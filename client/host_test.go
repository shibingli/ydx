package client

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"net/url"
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
