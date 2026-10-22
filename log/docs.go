// Package logx is a zero-copy, zero-reflection structured logging system.
// | Package logx 是零拷贝、零反射的结构化日志系统。
//
// Design highlights: | 设计要点：
//
//   - Encoding appends directly onto byte buffers reused from sync.Pool (1KB
//     initially; buffers above 64KB are not returned to the pool), and every log
//     record calls io.Writer.Write exactly once, so concurrent writes never
//     interleave lines; | 编码直接在 sync.Pool 复用的字节缓冲（初始 1KB，超过 64KB
//     不回池）上 append，每条日志只调用一次 io.Writer.Write，因此并发写入不会产生交错行；
//   - Fields are carried in a union representation (Field); the hot path does no
//     boxing, no reflection and creates no intermediate strings; | 字段以联合表示（Field）
//     承载，热路径不装箱、不反射、不产生中间 string；
//   - Callers can hoist the level check with Enabled, avoiding field construction at
//     disabled levels; the disabled path allocates nothing; | 调用方可用 Enabled 把级别
//     判断前置，避免在禁用级别上构造字段；禁用路径零分配；
//   - Every record carries the process id and, when the platform reports one, the
//     host name, both captured once in New; | 每条记录都带进程号，平台能提供时还带主机名，
//     两者都在 New 时取一次并缓存；
//   - Times are always output as UTC; time.Duration is milliseconds in JSON and a
//     human-readable string in console; []byte is base64 (RFC 4648 standard); | 时间一律
//     按 UTC 输出；time.Duration 在 JSON 中为毫秒、在 console 中为人类可读字符串；
//     []byte 按 base64（RFC 4648 标准）输出；
//   - Async is opt-in: producers encode locally and a dedicated writer goroutine
//     coalesces whole records into batched writes, with a bounded queue and blocking
//     backpressure. | Async 为显式开启：生产者在本地完成编码，专用写协程把完整记录合并为
//     批量写，队列有界且采用阻塞背压。
//
// Basic usage | 基本用法：
//
//	log := logx.New(logx.Options{Service: "api", Level: logx.InfoLevel})
//	log.Info("server started | 服务器已启动", logx.Str("addr", ":8080"))
//	reqLog := log.With(logx.Str("request_id", id))
package logx
