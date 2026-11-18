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

func TestRetryFailover(t *testing.T) {
	var aHits, bHits atomic.Int32
	a := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		aHits.Add(1)
		w.WriteHeader(http.StatusServiceUnavailable)
	}))
	defer a.Close()
	b := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		bHits.Add(1)
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("b"))
	}))
	defer b.Close()

	c, err := New(
		WithHosts(a.URL, b.URL),
		WithRewriteAll(true),
		WithRetry(RetryPolicy{
			MaxAttempts: 2,
			StatusCodes: []int{http.StatusServiceUnavailable},
			Backoff:     func(int) time.Duration { return time.Millisecond },
		}),
	)
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()

	resp, err := c.Get(context.Background(), a.URL+"/x")
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("status %d", resp.StatusCode)
	}
	if aHits.Load() == 0 || bHits.Load() == 0 {
		t.Fatalf("hits a=%d b=%d", aHits.Load(), bHits.Load())
	}
}

func TestRetryPostDefaultOff(t *testing.T) {
	var hits atomic.Int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		hits.Add(1)
		w.WriteHeader(http.StatusServiceUnavailable)
	}))
	defer srv.Close()

	c, err := New(WithHosts(srv.URL))
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	resp, err := c.Post(context.Background(), srv.URL+"/x", strings.NewReader("body"))
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	if hits.Load() != 1 {
		t.Fatalf("POST retried: %d", hits.Load())
	}
}

func TestStreamingBodyNoSilentEmptyRetry(t *testing.T) {
	c, err := New(
		WithRetry(RetryPolicy{MaxAttempts: 3, NonIdempotent: true}),
		WithSpoolLimit(0),
	)
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	req := mustRequest(t, http.MethodPost, "http://127.0.0.1:1/x", "abc")
	req.GetBody = nil
	if _, err := c.Do(req); !errors.Is(err, ErrBodyNotReplayable) {
		t.Fatalf("want ErrBodyNotReplayable, got %v", err)
	}
}

func TestRetrySingleHostDefaultOff(t *testing.T) {
	var hits atomic.Int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		hits.Add(1)
		w.WriteHeader(http.StatusServiceUnavailable)
	}))
	defer srv.Close()

	c, err := New(WithHosts(srv.URL))
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	resp, err := c.Get(context.Background(), srv.URL+"/x")
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusServiceUnavailable || hits.Load() != 1 {
		t.Fatalf("status %d hits %d", resp.StatusCode, hits.Load())
	}
}

func TestRetryExhausted(t *testing.T) {
	t.Run("status", func(t *testing.T) {
		var hits atomic.Int32
		srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			hits.Add(1)
			w.WriteHeader(http.StatusServiceUnavailable)
		}))
		defer srv.Close()
		c, err := New(WithHosts(srv.URL), WithRetry(RetryPolicy{
			MaxAttempts: 2,
			StatusCodes: []int{http.StatusServiceUnavailable},
			Backoff:     func(int) time.Duration { return time.Millisecond },
		}))
		if err != nil {
			t.Fatal(err)
		}
		defer c.Close()
		resp, err := c.Get(context.Background(), srv.URL+"/x")
		if err != nil {
			t.Fatalf("final status must return a response, got %v", err)
		}
		resp.Body.Close()
		if resp.StatusCode != http.StatusServiceUnavailable || hits.Load() != 2 {
			t.Fatalf("status %d hits %d", resp.StatusCode, hits.Load())
		}
	})

	t.Run("network", func(t *testing.T) {
		srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {}))
		target := srv.URL
		srv.Close()
		c, err := New(WithHosts(target), WithRetry(RetryPolicy{
			MaxAttempts: 2,
			Backoff:     func(int) time.Duration { return time.Millisecond },
		}))
		if err != nil {
			t.Fatal(err)
		}
		defer c.Close()
		_, err = c.Get(context.Background(), target+"/x")
		if !errors.Is(err, ErrRetryExhausted) {
			t.Fatalf("want ErrRetryExhausted, got %v", err)
		}
		var clientErr *Error
		if !errors.As(err, &clientErr) {
			t.Fatalf("want *Error, got %T", err)
		}
	})
}

func TestTLSErrorsNotRetried(t *testing.T) {
	for _, err := range []error{ErrTLSPin, ErrTLS, ErrTLSConfig} {
		if retryableError(err, context.Background()) {
			t.Fatalf("%v must not be retried", err)
		}
	}
}

func TestIdempotencyKeyRetriesPOST(t *testing.T) {
	var hits atomic.Int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if hits.Add(1) == 1 {
			w.WriteHeader(http.StatusServiceUnavailable)
			return
		}
		_, _ = w.Write([]byte("ok"))
	}))
	defer srv.Close()
	c, err := New(
		WithHosts(srv.URL),
		WithRetry(RetryPolicy{
			MaxAttempts: 3,
			StatusCodes: []int{http.StatusServiceUnavailable},
			Backoff:     func(int) time.Duration { return time.Millisecond },
		}),
	)
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	resp, err := c.Post(context.Background(), srv.URL+"/x", []byte("payload"),
		WithRequestHeader("Idempotency-Key", "one"))
	if err != nil {
		t.Fatal(err)
	}
	data, _ := io.ReadAll(resp.Body)
	resp.Body.Close()
	if string(data) != "ok" || hits.Load() != 2 {
		t.Fatalf("body %q hits %d", data, hits.Load())
	}
}

func TestPerAttemptTimeout(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		select {
		case <-r.Context().Done():
		case <-time.After(200 * time.Millisecond):
		}
	}))
	defer srv.Close()
	c, err := New(
		WithHosts(srv.URL),
		WithRetry(RetryPolicy{
			MaxAttempts:       2,
			PerAttemptTimeout: 20 * time.Millisecond,
			Backoff:           func(int) time.Duration { return time.Millisecond },
		}),
	)
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	start := time.Now()
	if _, err := c.Get(context.Background(), srv.URL+"/slow"); err == nil {
		t.Fatal("expected per-attempt timeout")
	}
	if elapsed := time.Since(start); elapsed > 120*time.Millisecond {
		t.Fatalf("per-attempt timeout not enforced: %v", elapsed)
	}
}

func TestRetryBudgetRatio(t *testing.T) {
	c, err := New(WithRetry(RetryPolicy{Budget: 0.5}))
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	budget := c.engine.budgetFor(0.5)
	if budget == c.engine.budget {
		t.Fatal("custom budget reused the default bucket")
	}
	if budget.rate != 5 {
		t.Fatalf("budget rate %v, want 5", budget.rate)
	}
}

func TestBodySpoolReplay(t *testing.T) {
	var mu sync.Mutex
	var bodies []string
	var hits atomic.Int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		data, _ := io.ReadAll(r.Body)
		mu.Lock()
		bodies = append(bodies, string(data))
		mu.Unlock()
		if hits.Add(1) == 1 {
			w.WriteHeader(http.StatusServiceUnavailable)
			return
		}
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()

	c, err := New(
		WithHosts(srv.URL),
		WithRetry(RetryPolicy{
			MaxAttempts:   2,
			NonIdempotent: true,
			StatusCodes:   []int{http.StatusServiceUnavailable},
			Backoff:       func(int) time.Duration { return time.Millisecond },
		}),
		WithSpoolLimit(1<<20),
	)
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()

	body := struct{ io.Reader }{strings.NewReader("payload")}
	resp, err := c.Post(context.Background(), srv.URL+"/x", body)
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("status %d", resp.StatusCode)
	}
	mu.Lock()
	defer mu.Unlock()
	if len(bodies) != 2 || bodies[0] != "payload" || bodies[1] != "payload" {
		t.Fatalf("bodies %v", bodies)
	}
}

func TestRetryAfterDelay(t *testing.T) {
	max := time.Second
	if got := retryAfterDelay(http.Header{"Retry-After": {"2"}}, max); got != max {
		t.Fatalf("seconds cap = %v", got)
	}
	if got := retryAfterDelay(http.Header{"Retry-After": {"999999999999999999"}}, max); got != max {
		t.Fatalf("overflow cap = %v", got)
	}
	if got := retryAfterDelay(http.Header{"Retry-After": {"garbage"}}, max); got != 0 {
		t.Fatalf("invalid = %v", got)
	}
	past := time.Now().Add(-time.Hour).UTC().Format(http.TimeFormat)
	if got := retryAfterDelay(http.Header{"Retry-After": {past}}, max); got != 0 {
		t.Fatalf("past date = %v", got)
	}
	future := time.Now().Add(10 * time.Second).UTC().Format(http.TimeFormat)
	if got := retryAfterDelay(http.Header{"Retry-After": {future}}, max); got != max {
		t.Fatalf("future date cap = %v", got)
	}
}

func TestNegativeRuleRetryRejected(t *testing.T) {
	if _, err := CompileRules(Rule{Pattern: "/**", Retry: &RetryPolicy{MaxAttempts: -1}}); err == nil {
		t.Fatal("expected negative rule retry error")
	}
	if _, err := CompileRules(Rule{Pattern: "/**", Timeout: -time.Second}); err == nil {
		t.Fatal("expected negative rule timeout error")
	}
}

func TestCustomBackoffHonorsMaxBackoff(t *testing.T) {
	policy := RetryPolicy{Backoff: func(int) time.Duration { return time.Minute }, MaxBackoff: time.Second}
	if got := backoffDelay(policy, 1); got != time.Second {
		t.Fatalf("backoff = %v", got)
	}
}
