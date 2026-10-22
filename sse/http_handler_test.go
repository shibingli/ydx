package sse

import (
	"bufio"
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

// TestHTTPHandlerStreamsEvents proves the plain net/http entry point establishes
// an event stream and delivers a published event. | TestHTTPHandlerStreamsEvents
// 证明原生 net/http 入口能建立事件流并送达已发布事件。
func TestHTTPHandlerStreamsEvents(t *testing.T) {
	b := NewBroker(BrokerOptions{})
	defer b.Close()

	srv := httptest.NewServer(HTTPHandler(b, "http-topic", Options{}))
	defer srv.Close()

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, srv.URL, nil)
	if err != nil {
		t.Fatal(err)
	}
	respCh := make(chan *http.Response, 1)
	errCh := make(chan error, 1)
	go func() {
		resp, err := http.DefaultClient.Do(req)
		if err != nil {
			errCh <- err
			return
		}
		respCh <- resp
	}()

	deadline := time.Now().Add(3 * time.Second)
	for b.Clients("http-topic") == 0 {
		if time.Now().After(deadline) {
			t.Fatal("handler did not subscribe to the broker")
		}
		time.Sleep(time.Millisecond)
	}
	b.Publish("http-topic", Event{Data: []byte("hello")})

	var resp *http.Response
	select {
	case err := <-errCh:
		t.Fatalf("request failed: %v", err)
	case resp = <-respCh:
	case <-ctx.Done():
		t.Fatal("request timed out")
	}
	defer resp.Body.Close()

	scanner := bufio.NewScanner(resp.Body)
	for scanner.Scan() {
		if strings.HasPrefix(scanner.Text(), "data: hello") {
			return
		}
	}
	if err := scanner.Err(); err != nil {
		t.Fatalf("read stream: %v", err)
	}
	t.Fatal("published event was not delivered")
}

// TestHTTPHandlerLastEventIDRequest proves the native helper reads the header
// without a router context. | TestHTTPHandlerLastEventIDRequest 证明原生辅助函数
// 无需路由上下文即可读取请求头。
func TestHTTPHandlerLastEventIDRequest(t *testing.T) {
	req := httptest.NewRequest(http.MethodGet, "/events", nil)
	req.Header.Set("Last-Event-ID", "42")
	if got := LastEventIDRequest(req); got != "42" {
		t.Fatalf("LastEventIDRequest = %q, want 42", got)
	}
	if got := LastEventIDRequest(nil); got != "" {
		t.Fatalf("nil request = %q, want empty", got)
	}
}
