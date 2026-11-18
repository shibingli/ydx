package client

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

func TestHooksOrderAndStats(t *testing.T) {
	var mu sync.Mutex
	var order []string
	record := func(name string) {
		mu.Lock()
		order = append(order, name)
		mu.Unlock()
	}
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {}))
	defer srv.Close()

	c, err := New(
		WithHosts(srv.URL),
		WithRewriteAll(true),
		WithRule(Rule{Name: "r", Pattern: "/x"}),
		WithHooks(Hooks{
			OnRequest: func(context.Context, *http.Request) error {
				record("request")
				return nil
			},
			OnRoute: func(context.Context, *http.Request, *Rule, Params) {
				record("route")
			},
			OnHost: func(context.Context, *http.Request, *Host) {
				record("host")
			},
			OnAttempt: func(context.Context, AttemptInfo) {
				record("attempt")
			},
			OnResponse: func(_ context.Context, resp *Response) error {
				if resp.StatusCode != http.StatusOK {
					t.Errorf("status %d", resp.StatusCode)
				}
				record("response")
				return nil
			},
			OnComplete: func(_ context.Context, meta *Meta) {
				if meta.Attempts != 1 {
					t.Errorf("attempts %d", meta.Attempts)
				}
				record("complete")
			},
		}),
	)
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	resp, err := c.Get(context.Background(), srv.URL+"/x")
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()

	mu.Lock()
	want := []string{"request", "route", "host", "attempt", "response", "complete"}
	if len(order) != len(want) {
		t.Fatalf("order %v", order)
	}
	for i := range want {
		if order[i] != want[i] {
			t.Fatalf("order %v want %v", order, want)
		}
	}
	mu.Unlock()

	stats := c.Stats()
	if stats.Requests != 1 || stats.Responses != 1 || stats.Errors != 0 {
		t.Fatalf("stats %+v", stats)
	}
}

func TestHookErrorsAndPanic(t *testing.T) {
	t.Run("request error", func(t *testing.T) {
		var hits atomic.Int32
		srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			hits.Add(1)
		}))
		defer srv.Close()
		c, err := New(WithHosts(srv.URL), WithHooks(Hooks{
			OnRequest: func(context.Context, *http.Request) error { return errors.New("stop") },
		}))
		if err != nil {
			t.Fatal(err)
		}
		defer c.Close()
		if _, err := c.Get(context.Background(), srv.URL+"/x"); err == nil {
			t.Fatal("expected error")
		}
		if hits.Load() != 0 {
			t.Fatalf("hits %d", hits.Load())
		}
	})

	t.Run("panic", func(t *testing.T) {
		c, err := New(WithHooks(Hooks{
			OnRequest: func(context.Context, *http.Request) error { panic("boom") },
		}))
		if err != nil {
			t.Fatal(err)
		}
		defer c.Close()
		if _, err := c.Get(context.Background(), "http://example.com/x"); !errors.Is(err, ErrHookPanic) {
			t.Fatalf("want ErrHookPanic, got %v", err)
		}
	})

	t.Run("response error", func(t *testing.T) {
		srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			_, _ = w.Write([]byte("body"))
		}))
		defer srv.Close()
		c, err := New(WithHosts(srv.URL), WithHooks(Hooks{
			OnResponse: func(context.Context, *Response) error { return errors.New("reject") },
		}))
		if err != nil {
			t.Fatal(err)
		}
		defer c.Close()
		if _, err := c.Get(context.Background(), srv.URL); err == nil {
			t.Fatal("expected error")
		}
	})
}

func TestHookRetryCacheAndBlocked(t *testing.T) {
	t.Run("retry", func(t *testing.T) {
		var hits atomic.Int32
		srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if hits.Add(1) == 1 {
				w.WriteHeader(http.StatusServiceUnavailable)
				return
			}
		}))
		defer srv.Close()
		var retries atomic.Int32
		c, err := New(
			WithHosts(srv.URL),
			WithRetry(RetryPolicy{
				MaxAttempts: 2,
				StatusCodes: []int{http.StatusServiceUnavailable},
				Backoff:     func(int) time.Duration { return time.Millisecond },
			}),
			WithHooks(Hooks{OnRetry: func(context.Context, RetryInfo) { retries.Add(1) }}),
		)
		if err != nil {
			t.Fatal(err)
		}
		defer c.Close()
		resp, err := c.Get(context.Background(), srv.URL+"/x")
		if err != nil {
			t.Fatal(err)
		}
		resp.Body.Close()
		if retries.Load() != 1 || c.Stats().Retries != 1 {
			t.Fatalf("retries hook=%d stats=%d", retries.Load(), c.Stats().Retries)
		}
	})

	t.Run("cache", func(t *testing.T) {
		srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {}))
		defer srv.Close()
		var hits, misses, stores atomic.Int32
		c, err := New(
			WithRule(Rule{Name: "r", Pattern: "/x", Cache: &CachePolicy{TTL: time.Minute}}),
			WithHooks(Hooks{
				OnCacheHit:   func(context.Context, *http.Request) { hits.Add(1) },
				OnCacheMiss:  func(context.Context, *http.Request) { misses.Add(1) },
				OnCacheStore: func(context.Context, *http.Request, int64) { stores.Add(1) },
			}),
		)
		if err != nil {
			t.Fatal(err)
		}
		defer c.Close()
		for i := 0; i < 2; i++ {
			resp, err := c.Get(context.Background(), srv.URL+"/x")
			if err != nil {
				t.Fatal(err)
			}
			resp.Body.Close()
		}
		if hits.Load() != 1 || misses.Load() != 1 || stores.Load() != 1 {
			t.Fatalf("cache hooks hit=%d miss=%d store=%d", hits.Load(), misses.Load(), stores.Load())
		}
	})

	t.Run("blocked", func(t *testing.T) {
		var blocked atomic.Int32
		c, err := New(
			WithGuard(GuardFunc(func(context.Context, *http.Request) (GuardDecision, error) {
				return GuardDecision{Allowed: false, Message: "no"}, nil
			})),
			WithHooks(Hooks{OnBlocked: func(context.Context, *http.Request, GuardDecision) { blocked.Add(1) }}),
		)
		if err != nil {
			t.Fatal(err)
		}
		defer c.Close()
		if _, err := c.Get(context.Background(), "http://example.com/x"); !errors.Is(err, ErrBlocked) {
			t.Fatalf("want ErrBlocked, got %v", err)
		}
		if blocked.Load() != 1 || c.Stats().Blocked != 1 {
			t.Fatalf("blocked hook=%d stats=%d", blocked.Load(), c.Stats().Blocked)
		}
	})
}

func TestHookMirror(t *testing.T) {
	mirror := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {}))
	defer mirror.Close()
	primary := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {}))
	defer primary.Close()
	var starts, dones atomic.Int32
	c, err := New(
		WithHosts(primary.URL),
		WithRule(Rule{
			Name:    "r",
			Pattern: "/x",
			Mirror: &MirrorPolicy{
				Targets: []string{mirror.URL},
				Percent: 100,
				Sync:    true,
				Wait:    time.Second,
				Timeout: time.Second,
			},
		}),
		WithHooks(Hooks{
			OnMirrorStart: func(context.Context, MirrorInfo) { starts.Add(1) },
			OnMirrorDone:  func(context.Context, MirrorInfo) { dones.Add(1) },
		}),
	)
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	resp, err := c.Get(context.Background(), primary.URL+"/x")
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	if starts.Load() != 1 || dones.Load() != 1 {
		t.Fatalf("mirror hooks start=%d done=%d", starts.Load(), dones.Load())
	}
	if c.Stats().Mirrors != 1 {
		t.Fatalf("mirrors %d", c.Stats().Mirrors)
	}
}
