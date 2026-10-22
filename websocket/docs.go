// Package websocket is a WebSocket implementation covering RFC 6455, RFC 7692,
// RFC 7936, RFC 8441 and RFC 9220. | Package websocket 是覆盖 RFC 6455、7692、7936、8441 与 9220 的
// WebSocket 实现。
//
// Standards: | 标准：
//
//   - RFC 6455 is the core protocol: handshake, framing, masking, fragmentation,
//     control frames and close codes. | RFC 6455 是核心协议：握手、帧、掩码、分片、控制帧与关闭码。
//   - RFC 7692 adds opt-in permessage-deflate on both endpoints. | RFC 7692 在两端提供可选的
//     permessage-deflate。
//   - RFC 7936 requires subprotocol names to be compared case-sensitively. | RFC 7936 要求
//     子协议名按大小写敏感比较。
//   - RFC 8441 carries WebSocket over HTTP/2 extended CONNECT; RFC 9220 does the same
//     over HTTP/3. | RFC 8441 通过 HTTP/2 extended CONNECT 承载 WebSocket；RFC 9220 在
//     HTTP/3 上同理。
//
// Transports: HTTP/1.1 upgrades through http.Hijacker, HTTP/2 (including h2c) and
// HTTP/3 use extended CONNECT and adapt the request stream to net.Conn. On HTTP/1.1
// a handler may hand the Conn to another goroutine and return; on HTTP/2 and HTTP/3
// the handler must stay alive until the connection ends, because returning closes the
// stream. | 传输：HTTP/1.1 通过 http.Hijacker 升级；HTTP/2（含 h2c）与 HTTP/3 使用
// extended CONNECT，并把请求流适配成 net.Conn。HTTP/1.1 下处理器可以把 Conn 交给其它协程后
// 返回；HTTP/2 与 HTTP/3 下处理器必须阻塞到连接结束，因为返回即关闭流。
//
// The upgrade core (Upgrade / Dial) is native net/http. HtmxHandler is the YD router
// entry point, while HtmxHTTPHandler is the native http.Handler entry point sharing
// the same htmx loop. | 升级核心（Upgrade / Dial）本身就是原生 net/http。HtmxHandler
// 是 YD 路由入口，HtmxHTTPHandler 是共享同一 htmx 读循环的原生 http.Handler 入口。
//
// Typical usage | 典型用法：
//
//	r.GET("/ws", websocket.HtmxHandler(websocket.HtmxOptions{}))
//
//	// plain net/http | 原生 net/http
//	mux.Handle("/ws", websocket.HtmxHTTPHandler(websocket.HtmxOptions{}))
package websocket
