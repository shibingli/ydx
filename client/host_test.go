package client

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"net/url"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

func TestWeightedAndExclusion(t *testing.T) {
	hs, err := NewHostSet(
		Host{Name: "a", URL: mustURL("http://a"), Weight: 3},
		Host{Name: "b", URL: mustURL("http://b"), Weight: 1},
	)
	if err != nil {
		t.Fatal(err)
	}
	defer hs.Close()
	req := httptest.NewRequest(http.MethodGet, "http://svc/x", nil)
	counts := map[string]int{}
	for i := 0; i < 400; i++ {
		h, err := hs.Pick(req, nil)
		if err != nil {
			t.Fatal(err)
		}
		counts[h.Name]++
		hs.Release(h)
	}
	if counts["a"] < 250 || counts["b"] < 50 {
		t.Fatalf("distribution %v", counts)
	}
	h, err := hs.Pick(req, map[string]struct{}{"a": {}})
	if err != nil || h.Name != "b" {
		t.Fatalf("exclusion picked %v err %v", h, err)
	}
	hs.Release(h)
}

func TestCallerCancelDoesNotPoisonHost(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		select {
		case <-r.Context().Done():
		case <-time.After(200 * time.Millisecond):
			w.WriteHeader(http.StatusOK)
		}
	}))
	defer srv.Close()
	hs, err := NewHostSet(Host{Name: "a", URL: mustURL(srv.URL), Health: HealthPolicy{FailThreshold: 1}})
	if err != nil {
		t.Fatal(err)
	}
	c, err := New(WithHostSet(hs))
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Millisecond)
	defer cancel()
	if _, err := c.Get(ctx, srv.URL+"/x"); err == nil {
		t.Fatal("expected cancellation error")
	}
	stats := c.HostStats()
	if stats[0].Failures != 0 || !stats[0].Healthy {
		t.Fatalf("caller cancellation poisoned host: %+v", stats[0])
	}
}

func TestCooldownHalfOpen(t *testing.T) {
	now := time.Unix(0, 0)
	hs, err := NewHostSet(Host{
		Name:   "a",
		URL:    mustURL("http://a"),
		Health: HealthPolicy{FailThreshold: 1, Cooldown: time.Second},
	})
	if err != nil {
		t.Fatal(err)
	}
	defer hs.Close()
	hs.now = func() time.Time { return now }
	req := httptest.NewRequest(http.MethodGet, "http://svc/x", nil)

	h, err := hs.Pick(req, nil)
	if err != nil {
		t.Fatal(err)
	}
	hs.MarkFailure(h, context.DeadlineExceeded)

	h, err = hs.Pick(req, nil)
	if err != nil || h.Name != "a" {
		t.Fatalf("fail-open pick %v err %v", h, err)
	}
	if hs.failOpen.Load() == 0 {
		t.Fatal("fail-open counter not incremented")
	}
	hs.Release(h)

	now = now.Add(2 * time.Second)
	h, err = hs.Pick(req, nil)
	if err != nil {
		t.Fatal(err)
	}
	if !h.entry.halfOpen.Load() {
		t.Fatal("expected half-open probe")
	}
	hs.MarkSuccess(h)
	if hs.Stats()[0].Healthy != true {
		t.Fatal("success did not restore health")
	}
}

func TestReleasedHalfOpenProbeIsReclaimable(t *testing.T) {
	hs, err := NewHostSetWithOptions(HostSetOptions{Balance: BalanceOrdered},
		Host{Name: "a", URL: mustURL("http://a"), Health: HealthPolicy{FailThreshold: 1}},
		Host{Name: "b", URL: mustURL("http://b")},
	)
	if err != nil {
		t.Fatal(err)
	}
	defer hs.Close()
	entry := hs.entries[0]
	hs.MarkFailure(entry.host, errors.New("boom"))
	entry.cooldownUntil.Store(time.Now().Add(-time.Second).UnixNano())
	req := httptest.NewRequest(http.MethodGet, "http://svc/x", nil)
	host, err := hs.Pick(req, nil)
	if err != nil || host.Name != "a" {
		t.Fatalf("first probe: host=%v err=%v", host, err)
	}
	hs.Release(host)
	host, err = hs.Pick(req, nil)
	if err != nil || host.Name != "a" {
		t.Fatalf("probe was not reclaimable: host=%v err=%v", host, err)
	}
	hs.Release(host)
}

func TestNoHealthyWithExclude(t *testing.T) {
	hs, err := NewHostSet(Host{Name: "a", URL: mustURL("http://a"), Health: HealthPolicy{FailThreshold: 1}})
	if err != nil {
		t.Fatal(err)
	}
	defer hs.Close()
	req := httptest.NewRequest(http.MethodGet, "http://svc/x", nil)
	h, _ := hs.Pick(req, nil)
	hs.MarkFailure(h, context.DeadlineExceeded)
	if _, err := hs.Pick(req, map[string]struct{}{"a": {}}); !errors.Is(err, ErrNoHealthyHosts) {
		t.Fatalf("want ErrNoHealthyHosts, got %v", err)
	}
}

func TestHostSetValidation(t *testing.T) {
	if _, err := NewHostSet(); err != nil {
		t.Fatal(err)
	}
	hs, err := NewHostSet()
	if err != nil {
		t.Fatal(err)
	}
	if _, err := hs.Pick(httptest.NewRequest(http.MethodGet, "http://svc/x", nil), nil); !errors.Is(err, ErrNoHosts) {
		t.Fatalf("empty set: %v", err)
	}
	hs.Close()

	if _, err := NewHostSet(
		Host{Name: "a", URL: mustURL("http://a")},
		Host{Name: "a", URL: mustURL("http://b")},
	); !errors.Is(err, ErrDuplicateHost) {
		t.Fatalf("duplicate host: %v", err)
	}
	if _, err := NewHostSet(Host{Name: "a", URL: &url.URL{}}); !errors.Is(err, ErrInvalidConfig) {
		t.Fatalf("invalid URL: %v", err)
	}
}

func TestUpdateHosts(t *testing.T) {
	c, err := New(WithHosts("http://a.example"))
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	old := c.engine.hosts.Load()
	if old == nil {
		t.Fatal("no host set")
	}
	if err := c.UpdateHosts(Host{Name: "b", URL: mustURL("http://b.example")}); err != nil {
		t.Fatal(err)
	}
	next := c.engine.hosts.Load()
	if next == nil || next == old {
		t.Fatal("host set not replaced")
	}
	req := httptest.NewRequest(http.MethodGet, "http://svc/x", nil)
	h, err := next.Pick(req, nil)
	if err != nil || h.Name != "b" {
		t.Fatalf("new host %v err %v", h, err)
	}
	next.Release(h)
	if _, err := old.Pick(req, nil); !errors.Is(err, ErrClosed) {
		t.Fatalf("old set not closed: %v", err)
	}
}

func TestMaxInflightWaitsForSlot(t *testing.T) {
	hs, err := NewHostSetWithOptions(HostSetOptions{Wait: time.Second},
		Host{Name: "a", URL: mustURL("http://a"), MaxInflight: 1})
	if err != nil {
		t.Fatal(err)
	}
	defer hs.Close()
	req := httptest.NewRequest(http.MethodGet, "http://svc/x", nil)
	first, err := hs.Pick(req, nil)
	if err != nil {
		t.Fatal(err)
	}
	type result struct {
		host *Host
		err  error
	}
	done := make(chan result, 1)
	go func() {
		host, err := hs.Pick(req, nil)
		done <- result{host: host, err: err}
	}()
	time.Sleep(10 * time.Millisecond)
	hs.Release(first)
	select {
	case got := <-done:
		if got.err != nil || got.host == nil {
			t.Fatalf("waiting pick: host=%v err=%v", got.host, got.err)
		}
		hs.Release(got.host)
	case <-time.After(time.Second):
		t.Fatal("Pick did not wake after release")
	}

	held, err := hs.Pick(req, nil)
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Millisecond)
	defer cancel()
	if _, err := hs.Pick(req.WithContext(ctx), nil); !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("want deadline, got %v", err)
	}
	hs.Release(held)
}

func TestMaxInflightAtomicReservation(t *testing.T) {
	hs, err := NewHostSetWithOptions(HostSetOptions{Wait: -1},
		Host{Name: "a", URL: mustURL("http://a"), MaxInflight: 1})
	if err != nil {
		t.Fatal(err)
	}
	defer hs.Close()
	req := httptest.NewRequest(http.MethodGet, "http://svc/x", nil)
	var current, maxSeen atomic.Int32
	var wg sync.WaitGroup
	for i := 0; i < 200; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			host, err := hs.Pick(req, nil)
			if err != nil {
				return
			}
			value := current.Add(1)
			for {
				seen := maxSeen.Load()
				if value <= seen || maxSeen.CompareAndSwap(seen, value) {
					break
				}
			}
			time.Sleep(time.Millisecond)
			current.Add(-1)
			hs.Release(host)
		}()
	}
	wg.Wait()
	if maxSeen.Load() > 1 {
		t.Fatalf("MaxInflight exceeded: %d", maxSeen.Load())
	}
}

func TestRuleHostSetSharedWithDefaultFollowsUpdate(t *testing.T) {
	one := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte("one"))
	}))
	defer one.Close()
	two := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte("two"))
	}))
	defer two.Close()
	u1, _ := url.Parse(one.URL)
	shared, err := NewHostSet(Host{URL: u1})
	if err != nil {
		t.Fatal(err)
	}
	c, err := New(WithHostSet(shared), WithRule(Rule{Name: "r", Pattern: "/**", HostSet: shared}))
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	u2, _ := url.Parse(two.URL)
	if err := c.UpdateHosts(Host{URL: u2}); err != nil {
		t.Fatal(err)
	}
	resp, err := c.Get(context.Background(), "/x")
	if err != nil {
		t.Fatal(err)
	}
	data, err := resp.Bytes()
	if err != nil {
		t.Fatal(err)
	}
	if string(data) != "two" {
		t.Fatalf("body %q", data)
	}
}

func TestHotReloadRetriesHostPick(t *testing.T) {
	oldSrv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte("old"))
	}))
	defer oldSrv.Close()
	newSrv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte("new"))
	}))
	defer newSrv.Close()
	var c *Client
	var err error
	c, err = New(
		WithHosts(oldSrv.URL),
		WithCache(CachePolicy{TTL: time.Minute}),
		WithHooks(Hooks{OnCacheMiss: func(context.Context, *http.Request) {
			_ = c.UpdateHosts(Host{Name: "new", URL: mustURL(newSrv.URL)})
		}}),
		WithoutCookieJar(),
	)
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	resp, err := c.Get(context.Background(), "/x")
	if err != nil {
		t.Fatalf("request failed after hot reload: %v", err)
	}
	data, err := resp.Bytes()
	if err != nil {
		t.Fatal(err)
	}
	if string(data) != "new" {
		t.Fatalf("body %q", data)
	}
}

func TestUpdateHostsPreservesOptions(t *testing.T) {
	initial, err := NewHostSetWithOptions(HostSetOptions{Balance: BalanceOrdered},
		Host{Name: "a", URL: mustURL("http://a")},
	)
	if err != nil {
		t.Fatal(err)
	}
	c, err := New(WithHostSet(initial), WithoutCookieJar())
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	if err := c.UpdateHosts(Host{Name: "b", URL: mustURL("http://b")}); err != nil {
		t.Fatal(err)
	}
	next := c.engine.hosts.Load()
	if next == nil || next.balance != BalanceOrdered {
		t.Fatalf("balance after update %q", next.balance)
	}
}

func TestHostBaseURLQueryMerged(t *testing.T) {
	var got atomic.Value
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		got.Store(r.URL.RawQuery)
		_, _ = w.Write([]byte("ok"))
	}))
	defer srv.Close()
	c, err := New(WithHosts(srv.URL+"?key=K"), WithoutCookieJar())
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	resp, err := c.Get(context.Background(), "/x?q=1")
	if err != nil {
		t.Fatal(err)
	}
	_ = resp.Body.Close()
	if value := got.Load(); value != "key=K&q=1" {
		t.Fatalf("raw query %q", value)
	}
}

func TestHostSetClonesExpectStatus(t *testing.T) {
	expected := []int{http.StatusOK}
	hs, err := NewHostSet(Host{
		Name:   "a",
		URL:    mustURL("http://a"),
		Health: HealthPolicy{ExpectStatus: expected},
	})
	if err != nil {
		t.Fatal(err)
	}
	defer hs.Close()
	expected[0] = http.StatusInternalServerError
	if got := hs.entries[0].host.Health.ExpectStatus[0]; got != http.StatusOK {
		t.Fatalf("ExpectStatus aliased caller slice: %d", got)
	}
}

func TestHalfOpenProbeClaimsOnlySelectedHost(t *testing.T) {
	hs, err := NewHostSetWithOptions(HostSetOptions{Balance: BalanceOrdered},
		Host{Name: "a", URL: mustURL("http://a"), Health: HealthPolicy{FailThreshold: 1, Cooldown: time.Second}},
		Host{Name: "b", URL: mustURL("http://b"), Health: HealthPolicy{FailThreshold: 1, Cooldown: time.Second}},
	)
	if err != nil {
		t.Fatal(err)
	}
	defer hs.Close()
	past := time.Now().Add(-time.Second).UnixNano()
	for _, entry := range hs.entries {
		entry.healthy.Store(false)
		entry.cooldownUntil.Store(past)
	}
	req := httptest.NewRequest(http.MethodGet, "http://svc/x", nil)
	host, err := hs.Pick(req, nil)
	if err != nil {
		t.Fatal(err)
	}
	if host.Name != "a" {
		t.Fatalf("picked %q", host.Name)
	}
	if !hs.entries[0].halfOpen.Load() {
		t.Fatal("selected host did not claim a half-open probe")
	}
	if hs.entries[1].halfOpen.Load() {
		t.Fatal("unselected host kept a half-open claim")
	}
	hs.Release(host)
}
