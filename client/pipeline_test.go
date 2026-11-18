package client

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
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
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/fail":
			w.WriteHeader(http.StatusInternalServerError)
		case "/slow":
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
