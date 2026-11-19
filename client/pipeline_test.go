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

func TestPipelineSerialParallel(t *testing.T) {
	var mu sync.Mutex
	var order []string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/login":
			_, _ = w.Write([]byte(`{"token":"T"}`))
		case "/a", "/b":
			mu.Lock()
			order = append(order, r.URL.Path)
			mu.Unlock()
			if r.Header.Get("Authorization") != "Bearer T" {
				t.Errorf("auth %q", r.Header.Get("Authorization"))
			}
			_, _ = w.Write([]byte(`{"ok":true}`))
		}
	}))
	defer srv.Close()
	c, err := New(WithHosts(srv.URL), WithBaseURL(srv.URL))
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	plan := NewPipeline(PipelineOptions{Timeout: 2 * time.Second},
		Step("login").POST("/login").ExtractJSON("token", "token"),
		Parallel(
			Step("a").GET("/a").HeaderFunc("Authorization", func(v *Vars) string { return "Bearer " + v.String("token") }),
			Step("b").GET("/b").HeaderFunc("Authorization", func(v *Vars) string { return "Bearer " + v.String("token") }),
		),
	)
	result, err := plan.Run(context.Background(), c)
	if err != nil {
		t.Fatal(err)
	}
	if result.Steps["login"].Status != http.StatusOK || result.Vars.String("token") != "T" {
		t.Fatalf("result %+v", result)
	}
	mu.Lock()
	defer mu.Unlock()
	if len(order) != 2 {
		t.Fatalf("order %v", order)
	}
}

func TestPipelineFailFastAndOptional(t *testing.T) {
	var afterHits atomic.Int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/fail":
			w.WriteHeader(http.StatusInternalServerError)
		case "/after":
			afterHits.Add(1)
		case "/slow":
			time.Sleep(50 * time.Millisecond)
		}
	}))
	defer srv.Close()
	c, err := New(WithHosts(srv.URL), WithBaseURL(srv.URL))
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()

	plan := NewPipeline(PipelineOptions{},
		Serial(
			Step("fail").GET("/fail"),
			Step("after").GET("/after"),
		),
	)
	if _, err := plan.Run(context.Background(), c); err == nil {
		t.Fatal("expected failure")
	}
	if afterHits.Load() != 0 {
		t.Fatalf("after ran %d", afterHits.Load())
	}

	optional := NewPipeline(PipelineOptions{ContinueOnError: true},
		Step("optional").GET("/fail").Required(false),
		Step("after").GET("/after"),
	)
	result, err := optional.Run(context.Background(), c)
	if err != nil {
		t.Fatalf("optional error propagated: %v", err)
	}
	if result.Steps["optional"].Err == nil {
		t.Fatal("optional error not recorded")
	}
	if afterHits.Load() != 1 {
		t.Fatalf("after hits %d", afterHits.Load())
	}
}

func TestPipelineWhenSkip(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {}))
	defer srv.Close()
	c, err := New(WithHosts(srv.URL), WithBaseURL(srv.URL))
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	var skipped atomic.Int32
	plan := NewPipeline(PipelineOptions{Hooks: PipelineHooks{
		OnSkip: func(context.Context, string) { skipped.Add(1) },
	}},
		Step("skip").GET("/x").When(func(*Vars) bool { return false }),
	)
	result, err := plan.Run(context.Background(), c)
	if err != nil {
		t.Fatal(err)
	}
	if !result.Steps["skip"].Skipped || skipped.Load() != 1 {
		t.Fatalf("skip result %+v hook %d", result.Steps["skip"], skipped.Load())
	}
}

func TestPipelineBodyLimitAndSSE(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/large":
			_, _ = w.Write([]byte("0123456789abcdef"))
		case "/sse":
			w.Header().Set("Content-Type", "text/event-stream")
			_, _ = w.Write([]byte("data: x\n\n"))
		}
	}))
	defer srv.Close()
	c, err := New(WithHosts(srv.URL), WithBaseURL(srv.URL))
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()

	large := NewPipeline(PipelineOptions{MaxBodyBytes: 4}, Step("large").GET("/large"))
	_, err = large.Run(context.Background(), c)
	if !errors.Is(err, ErrPipelineBodyTooLarge) {
		t.Fatalf("want ErrPipelineBodyTooLarge, got %v", err)
	}

	sse := NewPipeline(PipelineOptions{}, Step("sse").GET("/sse"))
	_, err = sse.Run(context.Background(), c)
	if !errors.Is(err, ErrPipelineStream) {
		t.Fatalf("want ErrPipelineStream, got %v", err)
	}
}

func TestPipelineDuplicateAndTimeout(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		time.Sleep(50 * time.Millisecond)
	}))
	defer srv.Close()
	c, err := New(WithHosts(srv.URL), WithBaseURL(srv.URL))
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()

	duplicate := NewPipeline(PipelineOptions{},
		Step("same").GET("/x"),
		Step("same").GET("/y"),
	)
	if _, err := duplicate.Run(context.Background(), c); !errors.Is(err, ErrPipelineStep) {
		t.Fatalf("want ErrPipelineStep, got %v", err)
	}

	timeout := NewPipeline(PipelineOptions{}, Step("slow").GET("/x").Timeout(10*time.Millisecond))
	if _, err := timeout.Run(context.Background(), c); err == nil {
		t.Fatal("expected timeout")
	}
}

func TestPipelineFuncAndHooks(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {}))
	defer srv.Close()
	c, err := New(WithHosts(srv.URL), WithBaseURL(srv.URL))
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	var started, done, complete atomic.Int32
	plan := NewPipeline(PipelineOptions{Hooks: PipelineHooks{
		OnStepStart: func(context.Context, string) { started.Add(1) },
		OnStepDone:  func(context.Context, *StepResult) { done.Add(1) },
		OnComplete:  func(context.Context, *PipelineResult) { complete.Add(1) },
	}},
		Func("set", func(ctx context.Context, vars *Vars) error {
			vars.Set("value", "ok")
			return nil
		}),
		Step("get").GET("/x"),
	)
	result, err := plan.Run(context.Background(), c)
	if err != nil {
		t.Fatal(err)
	}
	if result.Vars.String("value") != "ok" || started.Load() != 2 || done.Load() != 2 || complete.Load() != 1 {
		t.Fatalf("result %+v hooks start=%d done=%d complete=%d", result, started.Load(), done.Load(), complete.Load())
	}
}

func TestPipelineParallelFailFastCancelsSiblings(t *testing.T) {
	var slowCanceled atomic.Bool
	slowStarted := make(chan struct{})
	var slowOnce sync.Once
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/fail":
			// Wait until the sibling request is active so cancellation is observable. | 等待兄弟请求已启动，确保可观察取消。
			select {
			case <-slowStarted:
			case <-time.After(time.Second):
			}
			w.WriteHeader(http.StatusInternalServerError)
		case "/slow":
			slowOnce.Do(func() { close(slowStarted) })
			select {
			case <-r.Context().Done():
				slowCanceled.Store(true)
			case <-time.After(time.Second):
			}
		}
	}))
	defer srv.Close()
	c, err := New(WithHosts(srv.URL), WithBaseURL(srv.URL))
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	plan := NewPipeline(PipelineOptions{},
		Parallel(
			Step("fail").GET("/fail"),
			Step("slow").GET("/slow"),
		),
	)
	start := time.Now()
	if _, err := plan.Run(context.Background(), c); err == nil {
		t.Fatal("expected failure")
	}
	if time.Since(start) > 500*time.Millisecond {
		t.Fatal("fail-fast did not cancel the sibling")
	}
	waitFor(t, time.Second, func() bool { return slowCanceled.Load() })
}

func TestPipelineErrorsJoin(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprint(w, `{"ok":1}`)
	}))
	defer srv.Close()
	c, err := New(WithHosts(srv.URL), WithBaseURL(srv.URL))
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	plan := NewPipeline(PipelineOptions{},
		Step("bad").GET("/x").ExtractJSON("x", "missing"),
	)
	_, err = plan.Run(context.Background(), c)
	if !errors.Is(err, ErrExtract) {
		t.Fatalf("want ErrExtract, got %v", err)
	}
}

func TestPipelineRecoversUserPanics(t *testing.T) {
	c, err := New()
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	boom := func(context.Context, *Vars) error { panic("boom") }
	for _, node := range []Node{
		Func("boom", boom),
		Parallel(Func("boom", boom)),
	} {
		p := NewPipeline(PipelineOptions{}, node)
		if _, err := p.Run(context.Background(), c); err == nil {
			t.Fatal("panic was not converted to a pipeline error")
		}
	}
}

func TestPipelineHEADPreservesContentLength(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Length", "456")
	}))
	defer srv.Close()
	c, err := New(WithHosts(srv.URL))
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	p := NewPipeline(PipelineOptions{}, Step("head").HEAD(srv.URL+"/x"))
	result, err := p.Run(context.Background(), c)
	if err != nil {
		t.Fatal(err)
	}
	step := result.Steps["head"]
	if step == nil || step.Response.ContentLength != 456 || step.Response.Header.Get("Content-Length") != "456" {
		t.Fatalf("step %+v", step)
	}
}

func TestStepReleasesSlotOnSendPanic(t *testing.T) {
	c, err := New(
		WithTransport(roundTripFunc(func(*http.Request) (*http.Response, error) {
			panic("boom")
		})),
		WithoutCookieJar(),
	)
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	shared := &runShared{
		client:  c,
		vars:    NewVars(),
		results: make(map[string]*StepResult),
		limit:   make(chan struct{}, 1),
	}
	rs := &runState{ctx: context.Background(), shared: shared}
	step := Step("s").GET("http://example.com/x")
	func() {
		defer func() { _ = recover() }()
		_ = step.run(rs)
	}()
	if len(shared.limit) != 0 {
		t.Fatal("pipeline step leaked its concurrency slot")
	}
}

func TestStepBodySetterOrder(t *testing.T) {
	var got atomic.Value
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		data, _ := io.ReadAll(r.Body)
		got.Store(string(data))
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()
	c, err := New(WithoutCookieJar())
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	p := NewPipeline(PipelineOptions{},
		Step("s").POST(srv.URL+"/x").
			JSON(map[string]string{"a": "b"}).
			Body(strings.NewReader("raw")),
	)
	if _, err := p.Run(context.Background(), c); err != nil {
		t.Fatal(err)
	}
	if value := got.Load(); value != "raw" {
		t.Fatalf("body %q, want last setter to win", value)
	}
}
