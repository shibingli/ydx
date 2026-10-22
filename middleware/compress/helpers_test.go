package compress

import (
	"bufio"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"

	"github.com/shibingli/ydx/errs"
	"github.com/shibingli/ydx/router"
)

// doReq runs one request through r with the given headers and body. | doReq 携带指定请求头与
// 请求体，把请求送入 r 执行一次。
func doReq(r *router.Router, method, target string, hdr map[string]string, body string) *httptest.ResponseRecorder {
	req := httptest.NewRequest(method, target, strings.NewReader(body))
	for k, v := range hdr {
		req.Header.Set(k, v)
	}
	rec := httptest.NewRecorder()
	r.ServeHTTP(rec, req)
	return rec
}

// newRecorder returns a fresh response recorder. | newRecorder 返回一个新的响应记录器。
func newRecorder() *httptest.ResponseRecorder { return httptest.NewRecorder() }

// errNoHijack is returned by the fake hijacker below. | errNoHijack 由下面的假 Hijacker 返回。
var errNoHijack = errs.New("hijack unsupported | 不支持 Hijack")

// hijackRecorder adds http.Hijacker to a response recorder. | hijackRecorder 为响应记录器补充
// http.Hijacker 能力。
type hijackRecorder struct {
	*httptest.ResponseRecorder
}

// Hijack implements http.Hijacker. | Hijack 实现 http.Hijacker。
func (h *hijackRecorder) Hijack() (net.Conn, *bufio.ReadWriter, error) {
	return nil, nil, errNoHijack
}

// newUpgradeRequest builds a WebSocket-style upgrade request. | newUpgradeRequest 构造一个
// WebSocket 风格的升级请求。
func newUpgradeRequest(target string) *http.Request {
	req := httptest.NewRequest(http.MethodGet, target, nil)
	req.Header.Set("Connection", "Upgrade")
	req.Header.Set("Upgrade", "websocket")
	return req
}
