// Package webtransport is the framework's WebTransport layer: RFC 9297 sessions
// over HTTP/3, carried by the same QUIC listener that serves HTTP/3. | Package
// webtransport 是框架的 WebTransport 层：HTTP/3 上的 RFC 9297 会话，复用服务 HTTP/3 的
// 同一条 QUIC 监听。
//
// Responsibilities: | 职责边界：
//
//   - own one webtransport.Server over an *http3.Server, so a single UDP port
//     serves ordinary HTTP/3 requests, RFC 9220 WebSockets and WebTransport
//     sessions; | 在一个 *http3.Server 之上持有一个 webtransport.Server，使同一个 UDP
//     端口同时服务普通 HTTP/3 请求、RFC 9220 WebSocket 与 WebTransport 会话；
//   - upgrade extended CONNECT requests into Sessions and expose a framed
//     message Channel on the first bidirectional stream; | 把 extended CONNECT
//     请求升级为 Session，并在首条双向流上提供带长度前缀的消息 Channel；
//   - track live sessions so a lifecycle owner can terminate all of them at
//     once on shutdown; | 追踪活跃会话，使生命周期持有者能在退出时一次终止全部会话；
//   - keep datagrams and additional streams available for callers that need
//     them. | 为需要数据报与额外流的调用方保留对应入口。
//
// It does not implement HTTP/3 itself, does not own TLS certificates and does
// not decide routing: the application registers an ordinary handler and calls
// Server.Upgrade when the request is a WebTransport CONNECT. | 它不实现 HTTP/3 本身、
// 不拥有 TLS 证书，也不决定路由：应用注册普通处理器，在请求为 WebTransport CONNECT
// 时调用 Server.Upgrade。
//
// Typical usage | 典型用法：
//
//	srv, err := webtransport.New(webtransport.Options{TLSConfig: tlsConf})
//	if err != nil {
//		return err
//	}
//	h3 := srv.H3()
//	h3.Handler = http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
//		sess, err := srv.Upgrade(w, r)
//		if err != nil {
//			return
//		}
//		ch, err := sess.Accept(r.Context())
//		...
//	})
//	if err := srv.Serve(udpConn); err != nil {
//		return err
//	}
package webtransport
