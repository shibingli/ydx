// Package compress negotiates and applies brotli, zstd or gzip response compression. |
// Package compress 协商并应用 brotli、zstd 或 gzip 响应压缩。
//
// The encoding is chosen from Accept-Encoding by Negotiate, and only once a response is
// actually large enough to compress. HEAD requests, protocol upgrades, excluded prefixes,
// SSE responses, bodiless or already encoded responses, bodies below MinSize and responses
// carrying Cache-Control: no-transform are never wrapped. Encoder and pending-body buffers
// come from pools returned when the response finishes. | 编码由 Negotiate 依据 Accept-Encoding
// 选出，且只在响应确实大到值得压缩时才协商。HEAD 请求、协议升级、命中排除前缀、SSE 响应、
// 无正文或已编码的响应、小于 MinSize 的正文，以及带 Cache-Control: no-transform 的响应一律
// 不包装；编码器与待压缩正文缓冲均取自池，并在响应结束时归还。
//
// Both entry points share the same implementation: Compress returns a router.Middleware,
// Middleware returns the native net/http wrapper. | 两个入口共享同一份实现：Compress 返回
// router.Middleware，Middleware 返回原生 net/http 包装器。
//
// Typical usage | 典型用法：
//
//	r.Use(compress.Compress(compress.CompressOptions{}))
//
//	// plain net/http | 原生 net/http
//	handler := compress.Middleware(compress.CompressOptions{})(mux)
package compress
