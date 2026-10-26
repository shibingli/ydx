// Package transport serves captcha over YD and plain net/http.
// | Package transport 通过 YD 与原生 net/http 提供验证码服务。
package transport

// NewHandler builds a native net/http handler for one manager. | NewHandler 为一个管理器构建原生 net/http 处理器。
func NewHandler(manager Manager, options HandlerOptions) *Handler {
	return newHandler(manager, options)
}
