package reqlog

import (
	"net/http"
	"net/netip"
	"strings"
)

// Options configures the request-logging capture shared by the access-log plugins. |
// Options 配置访问日志插件共享的请求日志捕获。
type Options struct {
	// TrustedProxies lists the reverse proxies whose X-Forwarded-For / X-Real-Ip may be
	// trusted, using the same model as router.Ctx.ClientIP. Empty means the peer address is
	// used and proxy headers are ignored, which is the safe default. | TrustedProxies 列出其
	// X-Forwarded-For / X-Real-Ip 可被信任的反向代理，信任模型与 router.Ctx.ClientIP 相同。为空
	// 表示使用对端地址并忽略代理头，这是安全默认值。
	TrustedProxies []netip.Prefix
}

// IsUpgradeRequest reports whether r is a long-lived request that must not be wrapped or
// compressed: an HTTP/1.1 Upgrade, a CONNECT tunnel, or an RFC 8441/9220 WebSocket
// extended CONNECT. | IsUpgradeRequest 报告 r 是否为不得被包装或压缩的长连接请求：
// HTTP/1.1 Upgrade、CONNECT 隧道，或 RFC 8441/9220 的 WebSocket extended CONNECT。
func IsUpgradeRequest(r *http.Request) bool {
	if r == nil {
		return false
	}
	// CONNECT has no Upgrade header; its body is a tunnel or a WebSocket byte stream, so
	// wrapping the writer would corrupt it. | CONNECT 没有 Upgrade 头；它的正文是隧道或
	// WebSocket 字节流，包装写入器会破坏它。
	if r.Method == http.MethodConnect {
		return true
	}
	if HeaderValue(r.Header, "Upgrade") != "" {
		return true
	}
	return strings.Contains(strings.ToLower(HeaderValue(r.Header, "Connection")), "upgrade")
}

// HeaderValue returns the first value of an already-canonical header key. | HeaderValue
// 返回已规范化头部键的首个值。
//
// http.Header.Get runs textproto.CanonicalMIMEHeaderKey on every call, which is a per-byte
// scan of the key; the middleware hot path performs several of these per request. A direct
// lookup with the canonical spelling is equivalent (Set/Add always store the canonical form)
// and skips the scan. | http.Header.Get 每次都会调用 textproto.CanonicalMIMEHeaderKey，对键
// 逐字节扫描；中间件热路径每个请求要做多次。用规范化拼写直接查表与之等价（Set/Add 总是存规范化
// 形式），并省掉这次扫描。
func HeaderValue(h http.Header, canonicalKey string) string {
	if v := h[canonicalKey]; len(v) > 0 {
		return v[0]
	}
	return ""
}

// AppendVary adds value to the Vary response header unless it is already listed. |
// AppendVary 把 value 追加到 Vary 响应头，若已列出则不做任何事。
func AppendVary(h http.Header, value string) {
	for _, existing := range h["Vary"] {
		for _, item := range strings.Split(existing, ",") {
			if strings.EqualFold(strings.TrimSpace(item), value) {
				return
			}
		}
	}
	h["Vary"] = append(h["Vary"], value)
}
