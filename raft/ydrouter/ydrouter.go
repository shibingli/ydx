package ydrouter

import (
	"net/http"

	"github.com/shibingli/ydx/errs"
	"github.com/shibingli/ydx/raft"
	"github.com/shibingli/ydx/router"
)

// ErrInvalidArgument reports a nil router, transport or empty path. | ErrInvalidArgument
// 表示路由器、传输为空或路径为空。
var ErrInvalidArgument = errs.New("raft/ydrouter: invalid argument | raft/ydrouter：非法参数")

// Handler adapts a raft HTTP transport to a YD router raw handler. | Handler 将
// raft HTTP 传输适配为 YD 路由的原始处理器。
func Handler(transport *raft.HTTPTransport) router.HandlerFuncRaw {
	if transport == nil {
		return nil
	}
	h := transport.Handler()
	return h.ServeHTTP
}

// Mount registers the transport's POST endpoint on a YD router. The route shares
// the router's middleware chain and is the preferred integration for ydx
// services. | Mount 将传输的 POST 端点注册到 YD 路由。该路由共享路由器的中间件链，
// 是 ydx 服务的首选集成方式。
func Mount(r *router.Router, path string, transport *raft.HTTPTransport) error {
	if r == nil || transport == nil || path == "" {
		return ErrInvalidArgument
	}
	h := Handler(transport)
	if h == nil {
		return ErrInvalidArgument
	}
	r.HandleRaw(http.MethodPost, path, h)
	return nil
}
