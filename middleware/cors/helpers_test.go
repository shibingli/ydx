package cors

import (
	"net/http/httptest"
	"strings"

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
