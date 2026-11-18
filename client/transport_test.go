package client

import (
	"context"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

func TestRuleRewriteAndHostBasePath(t *testing.T) {
	var gotPath string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotPath = r.URL.Path
	}))
	defer srv.Close()

	c, err := New(
		WithHosts(srv.URL+"/v1"),
		WithRule(Rule{
			Name:    "user",
			Pattern: "/api/user/{id}",
			Rewrite: &Rewrite{StripPrefix: "/api"},
		}),
	)
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	if _, err := c.Get(context.Background(), srv.URL+"/api/user/42"); err != nil {
		t.Fatal(err)
	}
	if gotPath != "/v1/user/42" {
		t.Fatalf("path %q", gotPath)
	}
}

func TestHostRewriteAndPreserveHost(t *testing.T) {
	targetHost := mustURL("http://placeholder").Host
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/target":
			if r.Host != targetHost {
				t.Errorf("default Host %q want %q", r.Host, targetHost)
			}
		case "/preserve":
			if r.Host != "logical.example" {
				t.Errorf("preserved Host %q", r.Host)
			}
		}
	}))
	defer srv.Close()
	targetHost = mustURL(srv.URL).Host

	c, err := New(
		WithHosts(srv.URL),
		WithRule(Rule{Name: "target", Pattern: "/target"}),
		WithRule(Rule{Name: "preserve", Pattern: "/preserve", PreserveHost: true}),
	)
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	req, _ := http.NewRequest(http.MethodGet, "http://logical.example/target", nil)
	if _, err := c.Do(req); err != nil {
		t.Fatal(err)
	}
	req, _ = http.NewRequest(http.MethodGet, "http://logical.example/preserve", nil)
	if _, err := c.Do(req); err != nil {
		t.Fatal(err)
	}
}

func TestDoWithMeta(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {}))
	defer srv.Close()

	c, err := New(
		WithHosts(srv.URL),
		WithRule(Rule{Name: "user", Pattern: "/api/user/{id}"}),
	)
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	req, _ := http.NewRequest(http.MethodGet, srv.URL+"/api/user/42", nil)
	resp, err := c.DoWithMeta(req)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	if resp.Meta.Rule == nil || resp.Meta.Rule.Name != "user" {
		t.Fatalf("rule %+v", resp.Meta.Rule)
	}
	if resp.Meta.Params.Get("id") != "42" {
		t.Fatalf("params %v", resp.Meta.Params.Values())
	}
	if resp.Meta.Host == nil || resp.Meta.Attempts != 1 || len(resp.Meta.Hops) != 1 {
		t.Fatalf("meta %+v", resp.Meta)
	}
}

func TestNoHostsPassthrough(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte("direct"))
	}))
	defer srv.Close()
	c, err := New()
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	resp, err := c.Get(context.Background(), srv.URL)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	data, _ := resp.Bytes()
	if string(data) != "direct" {
		t.Fatalf("body %q", data)
	}
}

func TestPoliciesDefaultOff(t *testing.T) {
	var hits atomic.Int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		hits.Add(1)
		time.Sleep(20 * time.Millisecond)
	}))
	defer srv.Close()
	c, err := New(WithHosts(srv.URL))
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()

	var wg sync.WaitGroup
	for i := 0; i < 10; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			resp, err := c.Get(context.Background(), srv.URL+"/x")
			if err != nil {
				t.Error(err)
				return
			}
			resp.Body.Close()
		}()
	}
	wg.Wait()
	if hits.Load() != 10 {
		t.Fatalf("cache/coalesce enabled by default: hits=%d", hits.Load())
	}
}

func TestRetryContextCancel(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusServiceUnavailable)
	}))
	defer srv.Close()
	c, err := New(WithHosts(srv.URL), WithRetry(RetryPolicy{
		MaxAttempts: 3,
		StatusCodes: []int{http.StatusServiceUnavailable},
		Backoff:     func(int) time.Duration { return time.Hour },
	}))
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Millisecond)
	defer cancel()
	_, err = c.Get(ctx, srv.URL+"/x")
	if !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("want deadline exceeded, got %v", err)
	}
}

type trackingBody struct {
	reader io.Reader
	closed atomic.Bool
}

func (b *trackingBody) Read(p []byte) (int, error) { return b.reader.Read(p) }
func (b *trackingBody) Close() error               { b.closed.Store(true); return nil }

func TestRoundTripClosesBodyOnGuardDeny(t *testing.T) {
	guard := GuardFunc(func(context.Context, *http.Request) (GuardDecision, error) {
		return GuardDecision{Allowed: false, Status: http.StatusForbidden}, nil
	})
	c, err := New(WithGuard(guard))
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	body := &trackingBody{reader: strings.NewReader("payload")}
	req, _ := http.NewRequest(http.MethodPost, "http://example.com/x", body)
	if _, err := c.Transport().RoundTrip(req); !errors.Is(err, ErrBlocked) {
		t.Fatalf("want ErrBlocked, got %v", err)
	}
	if !body.closed.Load() {
		t.Fatal("request body was not closed on guard denial")
	}
}

func TestRoundTripClosesBodyOnCacheHit(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte("cached"))
	}))
	defer srv.Close()
	c, err := New(WithHosts(srv.URL), WithCache(CachePolicy{TTL: time.Minute}))
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	resp, err := c.Get(context.Background(), srv.URL+"/x")
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	body := &trackingBody{reader: strings.NewReader("payload")}
	req, _ := http.NewRequest(http.MethodGet, srv.URL+"/x", body)
	if _, err := c.Transport().RoundTrip(req); err != nil {
		t.Fatal(err)
	}
	if !body.closed.Load() {
		t.Fatal("request body was not closed on cache hit")
	}
}

func TestSendClosesBodyOnResolveError(t *testing.T) {
	c, err := New()
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	body := &trackingBody{reader: strings.NewReader("payload")}
	if _, err := c.Send(context.Background(), http.MethodPost, "/relative", body); !errors.Is(err, ErrRelativeURL) {
		t.Fatalf("want ErrRelativeURL, got %v", err)
	}
	if !body.closed.Load() {
		t.Fatal("request body was not closed on resolve error")
	}
}
