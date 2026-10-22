// Package protocol holds HTTP protocol predicates shared by the router, the
// WebSocket layer and middleware. | Package protocol 提供路由器、WebSocket 层与中间件共用的
// HTTP 协议判定。
//
// Keeping these checks in one place avoids three drifting copies of the same
// Extended CONNECT rules. | 把这些判定集中在一处，避免同一套 Extended CONNECT 规则出现三份实现并逐渐漂移。
//
// Typical usage | 典型用法：
//
//	if protocol.IsExtendedConnect(r) {
//		// RFC 8441/9220 WebSocket extended CONNECT | RFC 8441/9220 WebSocket 扩展 CONNECT
//	}
package protocol
