package client

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

func TestCoalesceSingleUpstream(t *testing.T) {
	var hits atomic.Int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		hits.Add(1)
		time.Sleep(50 * time.Millisecond)
		_, _ = w.Write([]byte("shared"))
	}))
	defer srv.Close()

	c, err := New(WithRule(Rule{
		Name:     "r",
		Pattern:  "/x",
		Coalesce: &CoalescePolicy{MaxBodyBytes: 1 << 20},
	}))
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()

	var wg sync.WaitGroup
	for i := 0; i < 20; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			resp, err := c.Get(context.Background(), srv.URL+"/x")
			if err != nil {
				t.Error(err)
				return
			}
			data, _ := io.ReadAll(resp.Body)
			resp.Body.Close()
			if string(data) != "shared" {
				t.Errorf("body %q", data)
			}
		}()
	}
	wg.Wait()
	if hits.Load() != 1 {
		t.Fatalf("upstream hits %d", hits.Load())
	}
}

func TestCoalesceDoesNotShareRanges(t *testing.T) {
	var hits atomic.Int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		hits.Add(1)
		time.Sleep(30 * time.Millisecond)
		if r.Header.Get("Range") != "" {
			w.WriteHeader(http.StatusPartialContent)
			_, _ = w.Write([]byte("AAAAA"))
			return
		}
		_, _ = w.Write([]byte("0123456789"))
	}))
	defer srv.Close()

	c, err := New(WithRule(Rule{
		Name:     "r",
		Pattern:  "/x",
		Coalesce: &CoalescePolicy{MaxBodyBytes: 1 << 20},
	}))
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()

	type result struct {
		body string
		err  error
	}
	results := make(chan result, 2)
	var wg sync.WaitGroup
	for _, rangeHeader := range []string{"", "bytes=0-4"} {
		wg.Add(1)
		go func(rangeHeader string) {
			defer wg.Done()
			resp, err := c.Get(context.Background(), srv.URL+"/x", WithRequestHeader("Range", rangeHeader))
			if err != nil {
				results <- result{err: err}
				return
			}
			data, readErr := io.ReadAll(resp.Body)
			resp.Body.Close()
			results <- result{body: string(data), err: readErr}
		}(rangeHeader)
	}
	wg.Wait()
	close(results)
	seen := map[string]bool{}
	for result := range results {
		if result.err != nil {
			t.Fatal(result.err)
		}
		seen[result.body] = true
	}
	if !seen["0123456789"] || !seen["AAAAA"] {
		t.Fatalf("coalesced range results: %v", seen)
	}
	if hits.Load() != 2 {
		t.Fatalf("upstream hits %d, want 2", hits.Load())
	}
}

func TestCoalesceDoesNotBufferSSE(t *testing.T) {
	release := make(chan struct{})
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/event-stream")
		fmt.Fprint(w, "data: one\n\n")
		w.(http.Flusher).Flush()
		<-release
	}))
	defer srv.Close()
	defer close(release)
	c, err := New(WithRule(Rule{
		Name:     "r",
		Pattern:  "/events",
		Coalesce: &CoalescePolicy{MaxBodyBytes: 1 << 20},
	}))
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	ctx, cancel := context.WithTimeout(context.Background(), 200*time.Millisecond)
	defer cancel()
	resp, err := c.Get(ctx, srv.URL+"/events")
	if err != nil {
		t.Fatalf("SSE was buffered until timeout: %v", err)
	}
	defer resp.Body.Close()
	buf := make([]byte, 64)
	n, _ := resp.Body.Read(buf)
	if !strings.Contains(string(buf[:n]), "data: one") {
		t.Fatalf("event %q", buf[:n])
	}
}

func TestCoalesceSeparatesCustomHeaders(t *testing.T) {
	var hits atomic.Int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		hits.Add(1)
		time.Sleep(30 * time.Millisecond)
		_, _ = w.Write([]byte(r.Header.Get("X-Tenant")))
	}))
	defer srv.Close()
	c, err := New(WithRule(Rule{
		Name:     "r",
		Pattern:  "/x",
		Coalesce: &CoalescePolicy{MaxBodyBytes: 1 << 20},
	}))
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	results := make(chan string, 2)
	var wg sync.WaitGroup
	for _, tenant := range []string{"a", "b"} {
		wg.Add(1)
		go func(tenant string) {
			defer wg.Done()
			resp, err := c.Get(context.Background(), srv.URL+"/x", WithRequestHeader("X-Tenant", tenant))
			if err != nil {
				results <- "error:" + err.Error()
				return
			}
			data, _ := io.ReadAll(resp.Body)
			resp.Body.Close()
			results <- string(data)
		}(tenant)
	}
	wg.Wait()
	close(results)
	seen := map[string]bool{}
	for result := range results {
		seen[result] = true
	}
	if !seen["a"] || !seen["b"] || hits.Load() != 2 {
		t.Fatalf("results %v hits %d", seen, hits.Load())
	}
}

func TestCoalesceLeaderCancelFallback(t *testing.T) {
	var hits atomic.Int32
	release := make(chan struct{})
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if hits.Add(1) == 1 {
			<-release
		}
		_, _ = w.Write([]byte("ok"))
	}))
	defer srv.Close()

	c, err := New(WithRule(Rule{
		Name:     "r",
		Pattern:  "/x",
		Coalesce: &CoalescePolicy{MaxBodyBytes: 1 << 20},
	}))
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()

	leaderCtx, cancel := context.WithCancel(context.Background())
	leaderDone := make(chan error, 1)
	go func() {
		resp, err := c.Get(leaderCtx, srv.URL+"/x")
		if err == nil {
			resp.Body.Close()
		}
		leaderDone <- err
	}()
	waitFor(t, time.Second, func() bool { return hits.Load() == 1 })

	followerDone := make(chan error, 1)
	go func() {
		resp, err := c.Get(context.Background(), srv.URL+"/x")
		if err == nil {
			data, _ := resp.Bytes()
			if string(data) != "ok" {
				t.Errorf("follower body %q", data)
			}
		}
		followerDone <- err
	}()
	time.Sleep(20 * time.Millisecond)
	cancel()
	close(release)

	if err := <-leaderDone; !errors.Is(err, context.Canceled) {
		t.Fatalf("leader error %v", err)
	}
	if err := <-followerDone; err != nil {
		t.Fatalf("follower error %v", err)
	}
	if hits.Load() != 2 {
		t.Fatalf("hits %d, want 2", hits.Load())
	}
}

func TestCoalesceOversizeBypass(t *testing.T) {
	payload := make([]byte, 100)
	for i := range payload {
		payload[i] = 'x'
	}
	var hits atomic.Int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		hits.Add(1)
		time.Sleep(20 * time.Millisecond)
		_, _ = w.Write(payload)
	}))
	defer srv.Close()

	c, err := New(WithRule(Rule{
		Name:     "r",
		Pattern:  "/x",
		Coalesce: &CoalescePolicy{MaxBodyBytes: 10},
	}))
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()

	var wg sync.WaitGroup
	for i := 0; i < 2; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			resp, err := c.Get(context.Background(), srv.URL+"/x")
			if err != nil {
				t.Error(err)
				return
			}
			data, _ := resp.Bytes()
			if len(data) != 100 {
				t.Errorf("body length %d", len(data))
			}
		}()
	}
	wg.Wait()
	if hits.Load() != 2 {
		t.Fatalf("hits %d, want 2", hits.Load())
	}
}

func TestCoalescePostAndAuthKey(t *testing.T) {
	var hits atomic.Int32
	release := make(chan struct{})
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		hits.Add(1)
		if r.Header.Get("Authorization") == "slow" {
			<-release
		}
		_, _ = w.Write([]byte("ok"))
	}))
	defer srv.Close()

	c, err := New(WithRule(Rule{
		Name:     "r",
		Pattern:  "/x",
		Coalesce: &CoalescePolicy{MaxBodyBytes: 1 << 20},
	}))
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()

	var wg sync.WaitGroup
	for i := 0; i < 5; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			resp, err := c.Post(context.Background(), srv.URL+"/x", nil)
			if err != nil {
				t.Error(err)
				return
			}
			resp.Body.Close()
		}()
	}
	wg.Wait()
	if hits.Load() != 5 {
		t.Fatalf("POST coalesced: %d", hits.Load())
	}

	hits.Store(0)
	first := make(chan struct{})
	go func() {
		resp, err := c.Get(context.Background(), srv.URL+"/x", WithRequestHeader("Authorization", "slow"))
		if err == nil {
			resp.Body.Close()
		}
		close(first)
	}()
	waitFor(t, time.Second, func() bool { return hits.Load() == 1 })
	second := make(chan struct{})
	go func() {
		resp, err := c.Get(context.Background(), srv.URL+"/x", WithRequestHeader("Authorization", "other"))
		if err == nil {
			resp.Body.Close()
		}
		close(second)
	}()
	time.Sleep(20 * time.Millisecond)
	close(release)
	<-first
	<-second
	if hits.Load() != 2 {
		t.Fatalf("different auth coalesced: %d", hits.Load())
	}
}
