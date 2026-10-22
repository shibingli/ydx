// Package sse implements a W3C Server-Sent Events (text/event-stream) writer and an
// in-process publish/subscribe broadcaster. | Package sse 实现 W3C Server-Sent Events
// （text/event-stream）写入器与进程内发布订阅广播器。
//
// The writer strictly follows the event stream format: one event consists of several
// field lines separated by LF, and the event ends with a blank line; the field line
// order is fixed as comment → id → event → retry → data. The data field may span
// several lines, and CR / CRLF / LF inside a value are all normalized into separate
// data lines. | 写入器严格遵循事件流格式：一个事件由若干字段行组成，字段行之间以 LF 分隔，
// 事件以空行结束；字段行顺序固定为 comment → id → event → retry → data。data 字段可跨多行，
// 值中的 CR / CRLF / LF 都会被规整为独立的数据行。
//
// Two endpoint forms are available: Handler returns a YD router.HandlerFunc, while
// HTTPHandler returns a plain http.Handler for projects that do not use the YD router.
// Both share the same serving core and the same event stream semantics. | 提供两种端点形态：
// Handler 返回 YD 的 router.HandlerFunc，HTTPHandler 返回原生 http.Handler，供不使用 YD
// 路由的项目直接挂载。两者共享同一份服务核心与事件流语义。
//
// Typical usage | 典型用法：
//
//	b := sse.NewBroker(sse.BrokerOptions{})
//	r.GET("/events", sse.Handler(b, "topic", sse.Options{}))
//
//	// plain net/http | 原生 net/http
//	mux.Handle("/events", sse.HTTPHandler(b, "topic", sse.Options{}))
package sse
