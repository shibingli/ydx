package protocol

import (
	"net/http"
	"os"
	"strings"
)

// IsExtendedConnect reports whether r is an RFC 8441 (HTTP/2) or RFC 9220
// (HTTP/3) WebSocket extended CONNECT request. | IsExtendedConnect 报告 r 是否为
// RFC 8441（HTTP/2）或 RFC 9220（HTTP/3）的 WebSocket Extended CONNECT 请求。
//
// HTTP/2 exposes the protocol token as the :protocol header; quic-go's HTTP/3
// server removes that header and puts the token in Request.Proto instead. | HTTP/2
// 通过 :protocol 头暴露协议 token；quic-go 的 HTTP/3 服务端会删除该头，把 token 放进
// Request.Proto。
func IsExtendedConnect(r *http.Request) bool {
	return IsExtendedConnectProtocol(r, "websocket")
}

// IsExtendedConnectProtocol reports whether r is an extended CONNECT request for
// the given protocol token, such as "websocket" (RFC 8441/9220) or
// "webtransport" (WebTransport over HTTP/3). | IsExtendedConnectProtocol 报告 r 是否为
// 指定协议 token 的 extended CONNECT 请求，例如 "websocket"（RFC 8441/9220）或
// "webtransport"（HTTP/3 上的 WebTransport）。
func IsExtendedConnectProtocol(r *http.Request, protocol string) bool {
	token := ExtendedConnectProtocol(r)
	return token != "" && strings.EqualFold(token, protocol)
}

// IsTunnelConnect reports whether r is any extended CONNECT request, regardless
// of the protocol token it carries. | IsTunnelConnect 报告 r 是否为任意 extended
// CONNECT 请求，不区分其携带的协议 token。
//
// Routers use it to send every tunnel to the GET route: plain CONNECT has no
// path and stays on its own method, while an extended CONNECT carries :path and
// is served by the same handler that would serve a GET. | 路由器用它把每一种隧道都送到
// GET 路由：普通 CONNECT 没有路径、保持自己的方法，而 extended CONNECT 带 :path，
// 由处理 GET 的同一个处理器服务。
func IsTunnelConnect(r *http.Request) bool {
	return ExtendedConnectProtocol(r) != ""
}

// ExtendedConnectProtocol returns the :protocol token of an extended CONNECT
// request, or "" when r is not one. | ExtendedConnectProtocol 返回 extended CONNECT
// 请求的 :protocol token；r 不是此类请求时返回空串。
//
// HTTP/2 keeps the token in the :protocol pseudo-header. quic-go's HTTP/3 server
// removes that header and stores the token in Request.Proto; an ordinary HTTP/3
// request keeps "HTTP/3.0" there, so only a CONNECT with a non-HTTP Proto value
// is read as extended CONNECT. | HTTP/2 把 token 放在 :protocol 伪头中。quic-go 的
// HTTP/3 服务端删除该头并把 token 存进 Request.Proto；普通 HTTP/3 请求在那里保留
// "HTTP/3.0"，因此只有带非 HTTP 取值的 CONNECT 才被读作 extended CONNECT。
func ExtendedConnectProtocol(r *http.Request) string {
	if r == nil || r.Method != http.MethodConnect {
		return ""
	}
	if p := r.Header.Get(":protocol"); p != "" {
		return p
	}
	if r.ProtoMajor == 3 && r.Proto != "" && !strings.HasPrefix(strings.ToUpper(r.Proto), "HTTP/") {
		return r.Proto
	}
	return ""
}

// H2ExtendedConnectEnabled reports whether the process was started with
// GODEBUG=http2xconnect=1. | H2ExtendedConnectEnabled 报告进程是否以
// GODEBUG=http2xconnect=1 启动。
//
// The check mirrors the standard library exactly: net/http's HTTP/2 package
// reads GODEBUG once in init and only then advertises
// SETTINGS_ENABLE_CONNECT_PROTOCOL. | 该判定与标准库完全一致：net/http 的 HTTP/2
// 包在 init 时只读取一次 GODEBUG，只有读到该项才会通告
// SETTINGS_ENABLE_CONNECT_PROTOCOL。
func H2ExtendedConnectEnabled() bool {
	return strings.Contains(os.Getenv("GODEBUG"), "http2xconnect=1")
}

// MergeGODEBUG returns godebug with setting appended unless it already contains
// that exact setting. | MergeGODEBUG 在 godebug 不含该精确设置时追加 setting，否则原样返回。
//
// Empty and comma-only values collapse to setting; existing settings are
// preserved verbatim, including surrounding whitespace. | 空值与仅含逗号的值会归并为
// setting；已有项原样保留，包括其两侧空白。
func MergeGODEBUG(godebug, setting string) string {
	for _, pair := range strings.Split(godebug, ",") {
		if strings.TrimSpace(pair) == setting {
			return godebug
		}
	}
	trimmed := strings.Trim(godebug, " ,")
	if trimmed == "" {
		return setting
	}
	return trimmed + "," + setting
}
