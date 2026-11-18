package client

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

func TestSSEForwardFlushAndMirror(t *testing.T) {
	var mirrorHits atomic.Int32
	mirror := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		mirrorHits.Add(1)
		w.Header().Set("Content-Type", "text/event-stream")
		fmt.Fprint(w, "data: shadow\n\n")
	}))
	defer mirror.Close()
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/event-stream")
		flusher := w.(http.Flusher)
		fmt.Fprint(w, "data: one\n\n")
		flusher.Flush()
		fmt.Fprint(w, "data: two\n\n")
		flusher.Flush()
	}))
	defer upstream.Close()

	c, err := New(
		WithHosts(upstream.URL),
		WithRule(Rule{Name: "sse", Pattern: "/events", Mirror: &MirrorPolicy{
			Targets: []string{mirror.URL},
			Percent: 100,
		}}),
	)
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()

	resp, err := http.Get(upstream.URL + "/events")
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	rec := httptest.NewRecorder()
	in := httptest.NewRequest(http.MethodGet, "/events", nil)
	if err := c.copySSE(context.Background(), rec, resp, in, ForwardOptions{}); err != nil {
		t.Fatal(err)
	}
	body := rec.Body.String()
	if !strings.Contains(body, "data: one") || !strings.Contains(body, "data: two") {
		t.Fatalf("body %q", body)
	}

	logical, _ := url.Parse(upstream.URL + "/events")
	c.mirrorSSE(context.Background(), in, logical, &MirrorPolicy{Targets: []string{mirror.URL}, Percent: 100})
	waitFor(t, time.Second, func() bool { return mirrorHits.Load() == 1 })
}

func TestSSEForwardIdleTimeout(t *testing.T) {
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/event-stream")
		fmt.Fprint(w, "data: one\n\n")
		w.(http.Flusher).Flush()
		<-r.Context().Done()
	}))
	defer upstream.Close()

	c, err := New()
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	resp, err := http.Get(upstream.URL + "/events")
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	rec := httptest.NewRecorder()
	in := httptest.NewRequest(http.MethodGet, "/events", nil)
	err = c.copySSE(context.Background(), rec, resp, in, ForwardOptions{SSEIdleTimeout: 20 * time.Millisecond})
	if !errors.Is(err, ErrSSEIdle) {
		t.Fatalf("want ErrSSEIdle, got %v", err)
	}
	if !strings.Contains(rec.Body.String(), "data: one") {
		t.Fatalf("body %q", rec.Body.String())
	}
}

func TestSSEForwardTeeSink(t *testing.T) {
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/event-stream")
		fmt.Fprint(w, "data: one\n\n")
	}))
	defer upstream.Close()

	var mu sync.Mutex
	var collected []byte
	sink := SinkFunc(func(ctx context.Context, chunk []byte) error {
		mu.Lock()
		collected = append(collected, chunk...)
		mu.Unlock()
		return nil
	})
	c, err := New(WithRule(Rule{
		Name:    "sse",
		Pattern: "/events",
		Mirror:  &MirrorPolicy{Mode: MirrorTee, TeeSinks: []Sink{sink}},
	}))
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	resp, err := http.Get(upstream.URL + "/events")
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	rec := httptest.NewRecorder()
	in := httptest.NewRequest(http.MethodGet, "/events", nil)
	if err := c.copySSE(context.Background(), rec, resp, in, ForwardOptions{}); err != nil {
		t.Fatal(err)
	}
	mu.Lock()
	defer mu.Unlock()
	if !bytesContains(collected, []byte("data: one")) {
		t.Fatalf("tee collected %q", collected)
	}
}

func TestSSEEventSink(t *testing.T) {
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/event-stream")
		fmt.Fprint(w, "event: tick\ndata: one\n\n")
		fmt.Fprint(w, "data: two\n\n")
	}))
	defer upstream.Close()

	var mu sync.Mutex
	var events []Event
	sink := EventSinkFunc(func(ctx context.Context, event Event) error {
		mu.Lock()
		events = append(events, event)
		mu.Unlock()
		return nil
	})
	c, err := New(WithRule(Rule{
		Name:    "sse",
		Pattern: "/events",
		Mirror:  &MirrorPolicy{Mode: MirrorTee, TeeEventSinks: []EventSink{sink}},
	}))
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	resp, err := http.Get(upstream.URL + "/events")
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	rec := httptest.NewRecorder()
	in := httptest.NewRequest(http.MethodGet, "/events", nil)
	if err := c.copySSE(context.Background(), rec, resp, in, ForwardOptions{}); err != nil {
		t.Fatal(err)
	}
	mu.Lock()
	defer mu.Unlock()
	if len(events) != 2 || events[0].Name != "tick" || string(events[0].Data) != "one" || string(events[1].Data) != "two" {
		t.Fatalf("events %+v", events)
	}
}

func TestSSEEventSinkOversizedDoesNotHang(t *testing.T) {
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/event-stream")
		_, _ = w.Write([]byte("data: "))
		_, _ = w.Write(bytes.Repeat([]byte("x"), 2<<20))
		_, _ = w.Write([]byte("\n\n"))
	}))
	defer upstream.Close()

	sink := EventSinkFunc(func(context.Context, Event) error { return nil })
	c, err := New(WithRule(Rule{
		Name:    "sse",
		Pattern: "/events",
		Mirror:  &MirrorPolicy{Mode: MirrorTee, TeeEventSinks: []EventSink{sink}},
	}))
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	resp, err := http.Get(upstream.URL + "/events")
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	rec := httptest.NewRecorder()
	in := httptest.NewRequest(http.MethodGet, "/events", nil)
	done := make(chan error, 1)
	go func() {
		done <- c.copySSE(context.Background(), rec, resp, in, ForwardOptions{})
	}()
	select {
	case err := <-done:
		if err != nil {
			t.Fatal(err)
		}
	case <-time.After(3 * time.Second):
		t.Fatal("oversized SSE event hung the event pump")
	}
}

func TestSSEForwardHeartbeat(t *testing.T) {
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/event-stream")
		fmt.Fprint(w, "data: one\n\n")
		w.(http.Flusher).Flush()
		<-r.Context().Done()
	}))
	defer upstream.Close()

	c, err := New()
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	resp, err := http.Get(upstream.URL + "/events")
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	rec := httptest.NewRecorder()
	in := httptest.NewRequest(http.MethodGet, "/events", nil)
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() {
		done <- c.copySSE(ctx, rec, resp, in, ForwardOptions{SSEHeartbeat: 10 * time.Millisecond})
	}()
	time.Sleep(60 * time.Millisecond)
	cancel()
	<-done
	if !strings.Contains(rec.Body.String(), ": ping") {
		t.Fatalf("heartbeat missing: %q", rec.Body.String())
	}
}

func TestMirrorSSE(t *testing.T) {
	var hits atomic.Int32
	mirror := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		hits.Add(1)
		w.Header().Set("Content-Type", "text/event-stream")
		fmt.Fprint(w, "data: shadow\n\n")
	}))
	defer mirror.Close()

	c, err := New()
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	in := httptest.NewRequest(http.MethodGet, "http://logical.example/events", nil)
	logical, _ := url.Parse("http://logical.example/events")
	c.mirrorSSE(context.Background(), in, logical, &MirrorPolicy{
		Targets: []string{mirror.URL},
		Percent: 100,
		Timeout: time.Second,
	})
	waitFor(t, time.Second, func() bool { return hits.Load() == 1 })
}

func bytesContains(haystack, needle []byte) bool {
	return strings.Contains(string(haystack), string(needle))
}
