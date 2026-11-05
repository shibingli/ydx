# ydx/raft/ydrouter — YD 路由优先的 Raft HTTP 传输适配

`github.com/shibingli/ydx/raft/ydrouter` 将 `raft.HTTPTransport` 挂载到
`ydx/router`。YD 路由是 ydx 服务的一等入口；原生 `net/http` 作为兼容入口保留。

## 快速开始

```go
tr, err := raft.NewHTTPTransport(raft.HTTPTransportOptions{
    ID:           1,
    Path:         "/raft/message",
    SharedSecret: secret,
})
if err != nil {
    return err
}

r := router.New()
// YD 路由（一等公民）：共享路由器的中间件、认证与观测链
if err := ydrouter.Mount(r, "/raft/message", tr); err != nil {
    return err
}

// 原生 net/http 兼容入口
http.Handle("/raft/message", tr.Handler())
```

对端地址使用基础 URL，例如 `http://192.168.2.2:23102`。TLS 由外层 HTTP
服务器/客户端提供，`SharedSecret` 负责消息认证。

## API

- `ydrouter.Mount(r *router.Router, path string, tr *raft.HTTPTransport) error`：
  注册 `POST path` 路由，使用 `tr.Handler()`。
- `ydrouter.Handler(tr *raft.HTTPTransport) router.HandlerFuncRaw`：返回 YD 路由
  原始处理器，便于自定义注册。

## 依赖与兼容

- `github.com/shibingli/ydx/raft`：Raft 核心与 HTTP 传输。
- `github.com/shibingli/ydx/router`：YD 路由。
- 不使用 YD 路由的应用只需依赖 `raft` 并直接使用 `HTTPTransport.Handler()`。
- 默认纯 Go，无 cgo。
