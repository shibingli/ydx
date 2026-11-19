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

func TestSubmitAndClose(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte("async"))
	}))
	defer srv.Close()
	c, err := New(WithHosts(srv.URL), WithMaxAsync(2))
	if err != nil {
		t.Fatal(err)
	}
	future := c.Submit(context.Background(), mustRequest(t, http.MethodGet, srv.URL, ""), nil)
	resp, err := future.Wait(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	data, _ := resp.Bytes()
	if string(data) != "async" {
		t.Fatalf("body %q", data)
	}
	if err := c.CloseContext(context.Background()); err != nil {
		t.Fatal(err)
	}
}

func TestSubmitCallbackAndBusy(t *testing.T) {
	release := make(chan struct{})
	var hits atomic.Int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if hits.Add(1) == 1 {
			<-release
		}
	}))
	defer srv.Close()
	c, err := New(WithHosts(srv.URL), WithMaxAsync(1))
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()

	callback := make(chan error, 1)
	first := c.Submit(context.Background(), mustRequest(t, http.MethodGet, srv.URL, ""), func(_ *Response, err error) {
		callback <- err
	})
	waitFor(t, time.Second, func() bool { return hits.Load() == 1 })
	second := c.Submit(context.Background(), mustRequest(t, http.MethodGet, srv.URL, ""), nil)
	if _, err := second.Wait(context.Background()); !errors.Is(err, ErrBusy) {
		t.Fatalf("want ErrBusy, got %v", err)
	}
	close(release)
	if _, err := first.Wait(context.Background()); err != nil {
		t.Fatal(err)
	}
	if err := <-callback; err != nil {
		t.Fatal(err)
	}
}

func TestCloseCancelsAsync(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		<-r.Context().Done()
	}))
	defer srv.Close()
	c, err := New(WithHosts(srv.URL))
	if err != nil {
		t.Fatal(err)
	}
	future := c.Submit(context.Background(), mustRequest(t, http.MethodGet, srv.URL, ""), nil)
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	if err := c.CloseContext(ctx); err != nil {
		t.Fatalf("close: %v", err)
	}
	if _, err := future.Wait(context.Background()); !errors.Is(err, context.Canceled) && !errors.Is(err, ErrClosed) {
		t.Fatalf("want context.Canceled or ErrClosed, got %v", err)
	}
}

func TestFutureWaitContext(t *testing.T) {
	release := make(chan struct{})
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		<-release
	}))
	defer srv.Close()
	c, err := New(WithHosts(srv.URL))
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	future := c.Submit(context.Background(), mustRequest(t, http.MethodGet, srv.URL, ""), nil)
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Millisecond)
	defer cancel()
	if _, err := future.Wait(ctx); !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("want deadline exceeded, got %v", err)
	}
	close(release)
	if _, err := future.Wait(context.Background()); err != nil {
		t.Fatal(err)
	}
}

func TestSubmitCloseRace(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		time.Sleep(5 * time.Millisecond)
	}))
	defer srv.Close()
	c, err := New(WithHosts(srv.URL), WithMaxAsync(1000), WithoutCookieJar())
	if err != nil {
		t.Fatal(err)
	}
	var wg sync.WaitGroup
	for i := 0; i < 100; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			future := c.Submit(context.Background(), mustRequest(t, http.MethodGet, srv.URL, ""), nil)
			_, _ = future.Wait(context.Background())
		}()
	}
	time.Sleep(time.Millisecond)
	_ = c.Close()
	wg.Wait()
}

func TestSubmitClosedClosesBody(t *testing.T) {
	var closed atomic.Bool
	c, err := New(WithoutCookieJar())
	if err != nil {
		t.Fatal(err)
	}
	_ = c.Close()
	req := mustRequest(t, http.MethodGet, "http://example.com/x", "")
	req.Body = closeTrackingBody{closed: &closed}
	req.GetBody = nil
	future := c.Submit(context.Background(), req, nil)
	if _, err := future.Wait(context.Background()); !errors.Is(err, ErrClosed) {
		t.Fatalf("wait error %v", err)
	}
	if !closed.Load() {
		t.Fatal("request body was not closed")
	}
}

func TestSubmitKeepsBodyAlive(t *testing.T) {
	release := make(chan struct{})
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Length", "5")
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("he"))
		w.(http.Flusher).Flush()
		<-release
		_, _ = w.Write([]byte("llo"))
	}))
	defer srv.Close()
	c, err := New(WithHosts(srv.URL), WithoutCookieJar())
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	future := c.Submit(context.Background(), mustRequest(t, http.MethodGet, srv.URL+"/x", ""), nil)
	resp, err := future.Wait(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	// Give the async goroutine time to finish and (before the fix) cancel the
	// request context while the body is still unread. | 给异步 goroutine 时间结束；
	// 修复前它会在正文未读完时取消请求 context。
	time.Sleep(20 * time.Millisecond)
	close(release)
	data, err := resp.Bytes()
	if err != nil {
		t.Fatalf("body read after async completion: %v", err)
	}
	if string(data) != "hello" {
		t.Fatalf("body %q", data)
	}
}

func TestSubmitCallbackCanClose(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte("ok"))
	}))
	defer srv.Close()
	c, err := New(WithHosts(srv.URL), WithoutCookieJar())
	if err != nil {
		t.Fatal(err)
	}
	done := make(chan struct{})
	future := c.Submit(context.Background(), mustRequest(t, http.MethodGet, srv.URL, ""), func(resp *Response, err error) {
		defer close(done)
		if err == nil {
			_ = resp.Discard()
		}
		_ = c.Close()
	})
	if _, err := future.Wait(context.Background()); err != nil {
		t.Fatal(err)
	}
	select {
	case <-done:
	case <-time.After(3 * time.Second):
		t.Fatal("callback did not finish")
	}
}
