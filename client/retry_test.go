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
