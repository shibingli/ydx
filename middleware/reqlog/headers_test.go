package reqlog

import (
	"net/http"
	"net/http/httptest"
	"testing"
)

// TestHeaderValueUsesCanonicalKey proves the fast lookup returns the first value
// and never canonicalizes the key itself. | TestHeaderValueUsesCanonicalKey 证明快速
// 查表返回首个值，且不会自行规范化键。
func TestHeaderValueUsesCanonicalKey(t *testing.T) {
	h := http.Header{"X-Test": {"a", "b"}}
	if got := HeaderValue(h, "X-Test"); got != "a" {
		t.Fatalf("HeaderValue = %q, want a", got)
	}
	if got := HeaderValue(h, "X-Missing"); got != "" {
		t.Fatalf("missing HeaderValue = %q, want empty", got)
	}
}

// TestAppendVaryDeduplicates proves values are appended once, case-insensitively. |
// TestAppendVaryDeduplicates 证明同一取值按大小写不敏感只追加一次。
func TestAppendVaryDeduplicates(t *testing.T) {
	h := http.Header{}
	AppendVary(h, "Origin")
	AppendVary(h, "origin")
	if got := h.Values("Vary"); len(got) != 1 || got[0] != "Origin" {
		t.Fatalf("Vary = %v, want [Origin]", got)
	}
	AppendVary(h, "Accept-Encoding")
	if got := h.Values("Vary"); len(got) != 2 {
		t.Fatalf("Vary = %v, want two values", got)
	}
}

// TestIsUpgradeRequestIncludesConnect pins CONNECT tunnels and RFC 8441/9220
// streams as long-lived requests. | TestIsUpgradeRequestIncludesConnect 把 CONNECT
// 隧道与 RFC 8441/9220 流固定为长连接请求。
func TestIsUpgradeRequestIncludesConnect(t *testing.T) {
	plain := httptest.NewRequest(http.MethodConnect, "/ws", nil)
	if !IsUpgradeRequest(plain) {
		t.Fatal("plain CONNECT was not recognized")
	}
	h2 := httptest.NewRequest(http.MethodConnect, "/ws", nil)
	h2.Header.Set(":protocol", "websocket")
	if !IsUpgradeRequest(h2) {
		t.Fatal("HTTP/2 extended CONNECT was not recognized")
	}
	h3 := httptest.NewRequest(http.MethodConnect, "/ws", nil)
	h3.ProtoMajor = 3
	h3.Proto = "websocket"
	if !IsUpgradeRequest(h3) {
		t.Fatal("HTTP/3 extended CONNECT was not recognized")
	}
	if IsUpgradeRequest(httptest.NewRequest(http.MethodGet, "/ws", nil)) {
		t.Fatal("plain GET was recognized as an upgrade")
	}
}
