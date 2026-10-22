package middleware

import (
	"net/http"
	"net/netip"
	"time"

	"github.com/shibingli/ydx/log"
	"github.com/shibingli/ydx/router"
)

// Compile-time compatibility assertions for the public API of the former yd middleware
// package. | 旧 yd middleware 包公开 API 的编译期兼容断言。
var (
	_ func(*log.Logger, ...AccessLogOptions) router.Middleware        = AccessLog
	_ func(*log.Logger, *AsyncAfter, ...AccessLogOptions) router.Middleware = AccessLogAsync
	_ func(*log.Logger) func(Record)                                  = AccessLogHandler
	_ func(CORSOptions) router.Middleware                             = CORS
	_ func(CompressOptions) router.Middleware                         = Compress
	_ func(string) map[string]float64                                 = ParseAcceptEncoding
	_ func(string, []Algorithm) (Algorithm, bool)                     = Negotiate
	_ func(RateLimitOptions) router.Middleware                        = RateLimit
	_ func(*log.Logger) router.Middleware                             = Recover
	_ func(string) router.Middleware                                  = RequestID
	_ func(AsyncOptions) *AsyncAfter                                  = NewAsyncAfter
	_ func(time.Duration) *MemoryStore                                = NewMemoryStore
	_ func(RedisStoreOptions) (*RedisStore, error)                    = NewRedisStore
	_ func() KeyFunc                                                  = KeyBasicAuthUser
	_ func(...KeyFunc) KeyFunc                                        = KeyFingerprint
	_ func(string) KeyFunc                                            = KeyHeader
	_ func() KeyFunc                                                  = KeyPath
	_ func(string) KeyFunc                                            = KeyQuery
	_ func([]netip.Prefix) KeyFunc                                    = KeyRemoteIP
	_ func(...router.Middleware) router.Middleware                    = Chain
	_ func(http.Handler, ...router.Middleware) http.Handler           = Adapt

	_ AccessLogOptions
	_ Algorithm
	_ AsyncAfter
	_ AsyncOptions
	_ Record
	_ OverflowPolicy
	_ CORSOptions
	_ CompressOptions
	_ RateLimitOptions
	_ KeyFunc
	_ LimitStore
	_ MemoryStore
	_ RedisStore
	_ RedisStoreOptions
	_ Decision

	_ = Gzip
	_ = Brotli
	_ = Zstd
	_ = OverflowBlock
	_ = OverflowDropNew
	_ = OverflowDropOldest
	_ = RequestIDKey
	_ = ErrCloseTimeout
	_ = ErrRedisStoreClient
	_ = ErrStoreDecision
)
