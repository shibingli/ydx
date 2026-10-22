package websocket

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

// TestHtmxHTTPHandlerUpgradeAndEcho proves the native endpoint upgrades and
// echoes the htmx envelope exactly like HtmxHandler. | TestHtmxHTTPHandlerUpgradeAndEcho
// 证明原生端点能完成升级，并像 HtmxHandler 一样回显 htmx 信封。
func TestHtmxHTTPHandlerUpgradeAndEcho(t *testing.T) {
	srv := httptest.NewServer(HtmxHTTPHandler(HtmxOptions{}))
	defer srv.Close()

	url := "ws" + strings.TrimPrefix(srv.URL, "http")
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	conn, err := Dial(ctx, url, DialOptions{})
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	defer func() { _ = conn.CloseNow() }()

	if err := conn.WriteMessage(TextMessage, []byte(`{"message":"hi"}`)); err != nil {
		t.Fatalf("write: %v", err)
	}
	op, data, err := conn.ReadMessage()
	if err != nil {
		t.Fatalf("read: %v", err)
	}
	if op != TextMessage {
		t.Fatalf("opcode = %v, want text", op)
	}
	// The reply shape is the htmx 4 {"content":"…"} envelope. | 应答形态是 htmx 4 的
	// {"content":"…"} 信封。
	if !strings.Contains(string(data), `"content":"hi"`) {
		t.Fatalf("echo = %s, want a content envelope with hi", data)
	}
}

// TestHtmxHTTPHandlerRejectsPlainGET proves a non-upgrade request receives the
// same HTTP error response as the YD entry point. | TestHtmxHTTPHandlerRejectsPlainGET
// 证明非升级请求会得到与 YD 入口相同的 HTTP 错误响应。
func TestHtmxHTTPHandlerRejectsPlainGET(t *testing.T) {
	srv := httptest.NewServer(HtmxHTTPHandler(HtmxOptions{}))
	defer srv.Close()

	resp, err := http.Get(srv.URL)
	if err != nil {
		t.Fatalf("GET: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode == http.StatusSwitchingProtocols {
		t.Fatal("plain GET must not be upgraded")
	}
	if resp.StatusCode < 400 {
		t.Fatalf("status = %d, want an error", resp.StatusCode)
	}
}
