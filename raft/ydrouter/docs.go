// Package ydrouter mounts a raft.HTTPTransport on ydx/router. | Package ydrouter 将
// raft.HTTPTransport 挂载到 ydx/router。
//
// The YD router is the first-class entry point for ydx services: Mount registers
// the transport as a POST route on an existing router, sharing its middleware
// chain, authentication and observability. The same HTTPTransport.Handler also
// remains a standard net/http handler, so applications outside the YD stack can
// mount it on http.ServeMux or any other router. | YD 路由是 ydx 服务的一等入口：
// Mount 将传输注册为现有路由器上的 POST 路由，共享其中间件链、认证与可观测性。同一个
// HTTPTransport.Handler 仍然是标准 net/http 处理器，因此 ydx 栈之外的应用也可以将它
// 挂载到 http.ServeMux 或任意其它路由器。
//
// Typical usage | 典型用法：
//
//	tr, _ := raft.NewHTTPTransport(raft.HTTPTransportOptions{
//		ID: 1, Path: "/raft/message",
//	})
//	r := router.New()
//	if err := ydrouter.Mount(r, "/raft/message", tr); err != nil {
//		// handle
//	}
//
//	// net/http compatibility | 兼容原生 net/http
//	http.Handle("/raft/message", tr.Handler())
package ydrouter
