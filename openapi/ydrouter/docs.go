// Package ydrouter adapts ydx/router routes to the standalone ydx/openapi document model.
// | Package ydrouter 把 ydx/router 的路由适配到独立的 ydx/openapi 文档模型。
//
// The openapi module itself knows nothing about any router: it accepts converted
// openapi.Route values and serves standard net/http handlers. This package is the only
// bridge between the two, so applications that use net/http (or another router) can depend
// on openapi alone, while ydx projects get the router-aware conversion. | openapi 模块本身
// 不感知任何路由器：它接收转换后的 openapi.Route 并提供标准 net/http 处理器。本包是两者之间
// 唯一的桥梁，因此使用 net/http（或其它路由器）的应用只依赖 openapi，而 ydx 项目获得结合
// 路由表的转换能力。
package ydrouter
