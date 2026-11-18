package client

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

func TestGroupDynamic(t *testing.T) {
	var hits atomic.Int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		hits.Add(1)
		_, _ = w.Write([]byte(r.URL.Path))
	}))
	defer srv.Close()
	c, err := New(WithHosts(srv.URL), WithMaxParallel(4))
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	g := c.NewGroup(context.Background())
	for i := 0; i < 20; i++ {
		g.GoRequest(fmt.Sprintf("r%d", i), http.MethodGet, srv.URL+fmt.Sprintf("/%d", i), nil)
	}
	if err := g.Wait(); err != nil {
		t.Fatal(err)
	}
	if hits.Load() != 20 || len(g.Results()) != 20 {
		t.Fatalf("hits %d results %d", hits.Load(), len(g.Results()))
	}
	result, ok := g.Result("r3")
	if !ok || result.Status != http.StatusOK || string(result.Body) != "/3" {
		t.Fatalf("result %+v ok %v", result, ok)
	}
}

func TestGroupFuncAndErrors(t *testing.T) {
	c, err := New()
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	g := c.NewGroup(context.Background())
	var value atomic.Int32
	g.GoFunc("ok", func(ctx context.Context) error {
		value.Add(1)
		return nil
	})
	g.GoFunc("fail", func(ctx context.Context) error {
		return errors.New("boom")
	})
	if err := g.Wait(); err == nil {
		t.Fatal("expected error")
	}
	if value.Load() != 1 {
		t.Fatalf("func ran %d", value.Load())
	}
	result, ok := g.Result("fail")
	if !ok || result.Err == nil {
		t.Fatalf("fail result %+v", result)
	}
}

func TestGroupDuplicateName(t *testing.T) {
	c, err := New()
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	g := c.NewGroup(context.Background())
	first := g.GoFunc("same", func(context.Context) error { return nil })
	second := g.GoFunc("same", func(context.Context) error { return nil })
	if _, err := first.Wait(context.Background()); err != nil {
		t.Fatal(err)
	}
	if _, err := second.Wait(context.Background()); !errors.Is(err, ErrPipelineStep) {
		t.Fatalf("want ErrPipelineStep, got %v", err)
	}
	if err := g.Wait(); !errors.Is(err, ErrPipelineStep) {
		t.Fatalf("want ErrPipelineStep, got %v", err)
	}
}

func TestGroupCancel(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		<-r.Context().Done()
	}))
	defer srv.Close()
	c, err := New(WithHosts(srv.URL))
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	ctx, cancel := context.WithCancel(context.Background())
	g := c.NewGroup(ctx)
	g.GoRequest("slow", http.MethodGet, srv.URL, nil)
	time.Sleep(20 * time.Millisecond)
	cancel()
	if err := g.Wait(); err == nil {
		t.Fatal("expected cancellation error")
	}
}

func TestGroupLimit(t *testing.T) {
	var current, maxSeen atomic.Int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		now := current.Add(1)
		for {
			old := maxSeen.Load()
			if now <= old || maxSeen.CompareAndSwap(old, now) {
				break
			}
		}
		time.Sleep(10 * time.Millisecond)
		current.Add(-1)
	}))
	defer srv.Close()
	c, err := New(WithHosts(srv.URL), WithMaxParallel(8))
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	g := c.NewGroup(context.Background(), WithGroupMaxParallel(2))
	var wg sync.WaitGroup
	for i := 0; i < 10; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			g.GoRequest(fmt.Sprintf("r%d", i), http.MethodGet, srv.URL, nil)
		}(i)
	}
	wg.Wait()
	if err := g.Wait(); err != nil {
		t.Fatal(err)
	}
	if maxSeen.Load() > 2 {
		t.Fatalf("max concurrency %d", maxSeen.Load())
	}
}

func TestGroupWaitRejectsLateTask(t *testing.T) {
	c, err := New()
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	g := c.NewGroup(context.Background())
	first := g.GoFunc("first", func(context.Context) error { return nil })
	if _, err := first.Wait(context.Background()); err != nil {
		t.Fatal(err)
	}
	if err := g.Wait(); err != nil {
		t.Fatal(err)
	}
	late := g.GoRequest("late", http.MethodGet, "http://example.com/", nil)
	if _, err := late.Wait(context.Background()); !errors.Is(err, ErrPipelineStep) {
		t.Fatalf("late task error = %v", err)
	}
}

func TestGroupRejectsEventStream(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/event-stream")
		_, _ = io.WriteString(w, "data: one\n\n")
		w.(http.Flusher).Flush()
	}))
	defer srv.Close()
	c, err := New(WithHosts(srv.URL))
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	g := c.NewGroup(context.Background())
	task := g.GoRequest("sse", http.MethodGet, srv.URL+"/events", nil)
	if _, err := task.Wait(context.Background()); !errors.Is(err, ErrPipelineStream) {
		t.Fatalf("error %v", err)
	}
	if err := g.Wait(); !errors.Is(err, ErrPipelineStream) {
		t.Fatalf("wait error %v", err)
	}
}

func TestGroupHEADPreservesContentLength(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Length", "321")
	}))
	defer srv.Close()
	c, err := New(WithHosts(srv.URL))
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	g := c.NewGroup(context.Background())
	task := g.GoRequest("head", http.MethodHead, srv.URL+"/x", nil)
	result, err := task.Wait(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if result.Response.ContentLength != 321 || result.Response.Header.Get("Content-Length") != "321" {
		t.Fatalf("content length %d header %q", result.Response.ContentLength, result.Response.Header.Get("Content-Length"))
	}
}
