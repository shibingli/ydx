package middleware

import (
	"net/netip"
	"time"

	"github.com/shibingli/ydx/log"
	"github.com/shibingli/ydx/middleware/accesslog"
	"github.com/shibingli/ydx/middleware/asyncafter"
	"github.com/shibingli/ydx/middleware/compress"
	"github.com/shibingli/ydx/middleware/cors"
	"github.com/shibingli/ydx/middleware/ratelimit"
	"github.com/shibingli/ydx/middleware/recovery"
	"github.com/shibingli/ydx/middleware/requestid"
	"github.com/shibingli/ydx/router"
)

// AccessLogOptions configures the access-log capture. | AccessLogOptions 配置访问日志采集。
type AccessLogOptions = accesslog.AccessLogOptions

// Algorithm identifies a supported content-encoding. | Algorithm 标识一种受支持的内容编码。
type Algorithm = compress.Algorithm

// Supported content encodings. | 受支持的内容编码。
const (
	Gzip   = compress.Gzip
	Brotli = compress.Brotli
	Zstd   = compress.Zstd
)

// AsyncAfter is the response-after worker pipeline. | AsyncAfter 是响应后 worker 管线。
type AsyncAfter = asyncafter.AsyncAfter

// AsyncOptions configures an AsyncAfter pipeline. | AsyncOptions 配置 AsyncAfter 管线。
type AsyncOptions = asyncafter.AsyncOptions

// Record is a value snapshot of one finished request. | Record 是一次已完成请求的值快照。
type Record = asyncafter.Record

// OverflowPolicy selects what Submit does when the queue is full. | OverflowPolicy 选择队列满时
// Submit 的行为。
type OverflowPolicy = asyncafter.OverflowPolicy

// Queue overflow policies. | 队列溢出策略。
const (
	OverflowBlock      = asyncafter.OverflowBlock
	OverflowDropNew    = asyncafter.OverflowDropNew
	OverflowDropOldest = asyncafter.OverflowDropOldest
)

// CORSOptions configures the CORS middleware. | CORSOptions 配置 CORS 中间件。
type CORSOptions = cors.CORSOptions

// CompressOptions configures the compression middleware. | CompressOptions 配置压缩中间件。
type CompressOptions = compress.CompressOptions

// RateLimitOptions configures the rate-limit middleware. | RateLimitOptions 配置限流中间件。
type RateLimitOptions = ratelimit.RateLimitOptions

// KeyFunc derives a rate-limit bucket key. | KeyFunc 派生限流桶键。
type KeyFunc = ratelimit.KeyFunc

// LimitStore is a token-bucket backend. | LimitStore 是令牌桶后端。
type LimitStore = ratelimit.LimitStore

// MemoryStore is the in-process token-bucket store. | MemoryStore 是进程内令牌桶存储。
type MemoryStore = ratelimit.MemoryStore

// RedisStore is the Redis token-bucket store. | RedisStore 是 Redis 令牌桶存储。
type RedisStore = ratelimit.RedisStore

// RedisStoreOptions configures RedisStore. | RedisStoreOptions 配置 RedisStore。
type RedisStoreOptions = ratelimit.RedisStoreOptions

// Decision is the outcome of one token acquisition. | Decision 是一次取令牌的结果。
type Decision = ratelimit.Decision

// Declared error values. | 声明的错误值。
var (
	// ErrCloseTimeout is returned by AsyncAfter.Close when its context expires first. | ErrCloseTimeout
	// 由 AsyncAfter.Close 在其上下文先到期时返回。
	ErrCloseTimeout = asyncafter.ErrCloseTimeout
	// ErrRedisStoreClient reports a Redis store built without a client. | ErrRedisStoreClient 表示
	// 未提供客户端的 Redis 存储。
	ErrRedisStoreClient = ratelimit.ErrRedisStoreClient
	// ErrStoreDecision reports a backend that returned an unparsable decision. | ErrStoreDecision
	// 表示后端返回了无法解析的决定。
	ErrStoreDecision = ratelimit.ErrStoreDecision
)

// RequestIDKey is the context key under which RequestID stores the id. | RequestIDKey 是
// RequestID 在上下文中保存 ID 使用的键。
const RequestIDKey = requestid.RequestIDKey

// AccessLog returns the synchronous access-log middleware. | AccessLog 返回同步访问日志中间件。
func AccessLog(l *log.Logger, opts ...AccessLogOptions) router.Middleware {
	return accesslog.AccessLog(l, opts...)
}

// AccessLogAsync returns the asynchronous access-log middleware. | AccessLogAsync 返回异步访问
// 日志中间件。
func AccessLogAsync(l *log.Logger, a *AsyncAfter, opts ...AccessLogOptions) router.Middleware {
	return asyncafter.AccessLogAsync(l, a, opts...)
}

// AccessLogHandler returns an AsyncOptions.Handler that writes one access-log record. |
// AccessLogHandler 返回把每条 Record 写成一条访问日志的 AsyncOptions.Handler。
func AccessLogHandler(l *log.Logger) func(Record) {
	return asyncafter.AccessLogHandler(l)
}

// CORS returns the CORS middleware. | CORS 返回 CORS 中间件。
func CORS(o CORSOptions) router.Middleware {
	return cors.CORS(o)
}

// Compress returns the response-compression middleware. | Compress 返回响应压缩中间件。
func Compress(o CompressOptions) router.Middleware {
	return compress.Compress(o)
}

// ParseAcceptEncoding parses Accept-Encoding into encoding → q-value pairs. | ParseAcceptEncoding
// 把 Accept-Encoding 解析为「编码 → q 值」映射。
func ParseAcceptEncoding(h string) map[string]float64 {
	return compress.ParseAcceptEncoding(h)
}

// Negotiate picks the best algorithm the client accepts. | Negotiate 选出客户端可接受的最优算法。
func Negotiate(acceptEncoding string, algos []Algorithm) (Algorithm, bool) {
	return compress.Negotiate(acceptEncoding, algos)
}

// RateLimit returns the rate-limit middleware. | RateLimit 返回限流中间件。
func RateLimit(o RateLimitOptions) router.Middleware {
	return ratelimit.RateLimit(o)
}

// Recover returns the panic-recovery middleware. | Recover 返回 panic 恢复中间件。
func Recover(l *log.Logger) router.Middleware {
	return recovery.Recover(l)
}

// RequestID returns the request-id middleware. | RequestID 返回请求 ID 中间件。
func RequestID(header string) router.Middleware {
	return requestid.RequestID(header)
}

// NewAsyncAfter creates an AsyncAfter pipeline and starts its workers. | NewAsyncAfter 创建
// AsyncAfter 管线并启动 worker。
func NewAsyncAfter(o AsyncOptions) *AsyncAfter {
	return asyncafter.NewAsyncAfter(o)
}

// NewMemoryStore creates an in-process token-bucket store. | NewMemoryStore 创建进程内令牌桶存储。
func NewMemoryStore(cleanupInterval time.Duration) *MemoryStore {
	return ratelimit.NewMemoryStore(cleanupInterval)
}

// NewRedisStore creates a Redis token-bucket store. | NewRedisStore 创建 Redis 令牌桶存储。
func NewRedisStore(o RedisStoreOptions) (*RedisStore, error) {
	return ratelimit.NewRedisStore(o)
}

// KeyBasicAuthUser derives a key from the Basic-Auth user name. | KeyBasicAuthUser 从 Basic-Auth
// 用户名派生键。
func KeyBasicAuthUser() KeyFunc { return ratelimit.KeyBasicAuthUser() }

// KeyFingerprint combines several key functions into one fingerprint. | KeyFingerprint 把多个键
// 函数组合为一个指纹。
func KeyFingerprint(parts ...KeyFunc) KeyFunc { return ratelimit.KeyFingerprint(parts...) }

// KeyHeader derives a key from the named header. | KeyHeader 从指定请求头派生键。
func KeyHeader(name string) KeyFunc { return ratelimit.KeyHeader(name) }

// KeyPath derives a key from the request path. | KeyPath 从请求路径派生键。
func KeyPath() KeyFunc { return ratelimit.KeyPath() }

// KeyQuery derives a key from the named query parameter. | KeyQuery 从指定查询参数派生键。
func KeyQuery(name string) KeyFunc { return ratelimit.KeyQuery(name) }

// KeyRemoteIP derives a key from the client address with an explicit trusted-proxy list. |
// KeyRemoteIP 从客户端地址派生键，并显式给出可信代理列表。
func KeyRemoteIP(trusted []netip.Prefix) KeyFunc { return ratelimit.KeyRemoteIP(trusted) }
