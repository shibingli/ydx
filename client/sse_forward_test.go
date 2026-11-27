package client

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
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

func TestForwardSSETeeNotDuplicated(t *testing.T) {
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/event-stream")
		fmt.Fprint(w, "data: one\n\n")
	}))
	defer upstream.Close()
	var calls atomic.Int32
	sink := SinkFunc(func(context.Context, []byte) error {
		calls.Add(1)
		return nil
	})
	c, err := New(
		WithHosts(upstream.URL),
		WithRule(Rule{
			Name:    "sse",
			Pattern: "/events",
			Mirror:  &MirrorPolicy{Mode: MirrorTee, TeeSinks: []Sink{sink}},
		}),
	)
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	in := httptest.NewRequest(http.MethodGet, "/events", nil)
	rec := httptest.NewRecorder()
	c.Handler().ServeHTTP(rec, in)
	waitFor(t, time.Second, func() bool { return calls.Load() > 0 })
	time.Sleep(50 * time.Millisecond)
	if calls.Load() != 1 {
		t.Fatalf("tee called %d times, want 1", calls.Load())
	}
}

func TestForwardDirectSSETee(t *testing.T) {
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/event-stream")
		fmt.Fprint(w, "data: one\n\n")
	}))
	defer upstream.Close()
	var calls atomic.Int32
	sink := SinkFunc(func(context.Context, []byte) error {
		calls.Add(1)
		return nil
	})
	c, err := New(
		WithHosts(upstream.URL),
		WithRule(Rule{
			Name:    "sse",
			Pattern: "/events",
			Mirror:  &MirrorPolicy{Mode: MirrorTee, TeeSinks: []Sink{sink}},
		}),
	)
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	in := httptest.NewRequest(http.MethodGet, "/events", nil)
	resp, err := c.Forward(context.Background(), in)
	if err != nil {
		t.Fatal(err)
	}
	_, _ = io.Copy(io.Discard, resp.Body)
	resp.Body.Close()
	waitFor(t, time.Second, func() bool { return calls.Load() > 0 })
}

func TestForwardSSERuleTimeoutDoesNotCutBody(t *testing.T) {
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/event-stream")
		fmt.Fprint(w, "data: one\n\n")
		w.(http.Flusher).Flush()
		time.Sleep(100 * time.Millisecond)
		fmt.Fprint(w, "data: two\n\n")
	}))
	defer upstream.Close()
	c, err := New(
		WithHosts(upstream.URL),
		WithRule(Rule{Name: "sse", Pattern: "/events", Timeout: 30 * time.Millisecond}),
	)
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	in := httptest.NewRequest(http.MethodGet, "/events", nil)
	resp, err := c.Forward(context.Background(), in)
	if err != nil {
		t.Fatal(err)
	}
	rec := httptest.NewRecorder()
	if err := c.copySSE(context.Background(), rec, resp, in, ForwardOptions{}); err != nil {
		t.Fatal(err)
	}
	body := rec.Body.String()
	if !strings.Contains(body, "data: one") || !strings.Contains(body, "data: two") {
		t.Fatalf("rule timeout cut SSE body: %q", body)
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

// flushRecorder records the body and each flush instant. | flushRecorder 记录正文与每次刷新时刻。
type flushRecorder struct {
	mu      sync.Mutex
	body    bytes.Buffer
	flushes []time.Time
}

func (r *flushRecorder) Header() http.Header { return make(http.Header) }

func (r *flushRecorder) WriteHeader(int) {}

func (r *flushRecorder) Write(p []byte) (int, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	return r.body.Write(p)
}

func (r *flushRecorder) Flush() {
	r.mu.Lock()
	r.flushes = append(r.flushes, time.Now())
	r.mu.Unlock()
}

func (r *flushRecorder) snapshot() (string, int) {
	r.mu.Lock()
	defer r.mu.Unlock()
	return r.body.String(), len(r.flushes)
}

// TestSSEForwardFlushIntervalReachesSilentUpstream pins that a chunk written within the
// throttle interval is still flushed when the upstream then goes silent. Without the timer it
// would stay in the response buffer until the next chunk or EOF. |
// TestSSEForwardFlushIntervalReachesSilentUpstream 固定：在节流间隔内写入的块，即使上游随后
// 沉默也会被刷新。没有定时器时它会滞留在响应缓冲中，直到下一个块或 EOF。
func TestSSEForwardFlushIntervalReachesSilentUpstream(t *testing.T) {
	for _, loop := range []bool{false, true} {
		name := "fast"
		if loop {
			name = "loop"
		}
		t.Run(name, func(t *testing.T) {
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
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			req, err := http.NewRequestWithContext(ctx, http.MethodGet, upstream.URL+"/events", nil)
			if err != nil {
				t.Fatal(err)
			}
			resp, err := http.DefaultClient.Do(req)
			if err != nil {
				t.Fatal(err)
			}
			defer resp.Body.Close()

			rec := &flushRecorder{}
			in := httptest.NewRequest(http.MethodGet, "/events", nil)
			opts := ForwardOptions{FlushInterval: 80 * time.Millisecond}
			if loop {
				// Heartbeat/idle select loop instead of the pooled fast path. |
				// 用心跳/空闲 select 循环代替池化快路径。
				opts.SSEIdleTimeout = 5 * time.Second
			}
			done := make(chan error, 1)
			go func() {
				done <- c.copySSE(ctx, rec, resp, in, opts)
			}()
			waitFor(t, time.Second, func() bool {
				body, flushes := rec.snapshot()
				return strings.Contains(body, "data: one") && flushes >= 2
			})
			cancel()
			select {
			case <-done:
			case <-time.After(2 * time.Second):
				t.Fatal("copySSE did not return after cancel | 取消后 copySSE 未返回")
			}
		})
	}
}
