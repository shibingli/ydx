package transport

import (
	"net/http"

	"github.com/shibingli/ydx/router"
)

// Bind registers the captcha endpoints on a YD router. | Bind 在 YD 路由上注册验证码端点。
//
// The same Handler also implements http.Handler, so the YD and native entries
// share one implementation. | 同一个 Handler 也实现 http.Handler，因此 YD 与原生入口共享
// 同一套实现。
func (h *Handler) Bind(r *router.Router) {
	if h == nil || r == nil {
		return
	}
	handle := func(c *router.Ctx) { h.ServeHTTP(c.Writer, c.Request) }
	r.Handle(http.MethodPost, h.prefix+"/challenge", handle)
	r.Handle(http.MethodPost, h.prefix+"/verify", handle)
	r.Handle(http.MethodPost, h.prefix+"/send", handle)
	r.Handle(http.MethodPost, h.prefix+"/token/consume", handle)
	r.GET(h.prefix+"/image/*key", handle)
	r.GET(h.prefix+"/assets/*file", handle)
	r.Handle(http.MethodOptions, h.prefix+"/*rest", handle)
}
