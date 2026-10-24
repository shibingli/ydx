package ratelimit

import (
	"context"
	"io"
	"math"
	"net/http"
	"net/netip"
	"net/textproto"
	"strconv"
	"time"

	"github.com/shibingli/ydx/log"
	"github.com/shibingli/ydx/router"
)

// rateLimitHeaderKeys holds the canonical keys of the rate-limit headers, computed once. | rateLimitHeaderKeys 保存限流响应头的规范 key，只计算一次。
//
// The public spelling stays X-RateLimit-*; Go's canonical form lowercases the tail of each
// hyphenated word, and precomputing it avoids re-canonicalizing (and heap-copying) the three
// keys on every request. Lookups through http.Header remain case-insensitive. | 对外拼写仍是
// X-RateLimit-*；Go 的规范形式会把每个连字符词的尾部小写，预计算可避免每请求重新规范化
// （并堆复制）这三个 key。通过 http.Header 的读取仍然大小写不敏感。
var rateLimitHeaderKeys = [...]string{
	textproto.CanonicalMIMEHeaderKey("X-RateLimit-Limit"),
	textproto.CanonicalMIMEHeaderKey("X-RateLimit-Remaining"),
	textproto.CanonicalMIMEHeaderKey("X-RateLimit-Reset"),
}

// rateLimitRetryKey is the canonical Retry-After key. | rateLimitRetryKey 是 Retry-After 的规范 key。
var rateLimitRetryKey = textproto.CanonicalMIMEHeaderKey("Retry-After")

// RateLimitOptions configures the token-bucket rate limiter. | RateLimitOptions 配置令牌桶限流器。
type RateLimitOptions struct {
	// Store is the limiting backend; nil means a private MemoryStore. Share one store across
	// middlewares only together with distinct KeyPrefix values. | Store 是限流后端；nil 表示私有的
	// MemoryStore。跨中间件共享同一存储时必须配合不同的 KeyPrefix。
	Store LimitStore
	// KeyFunc derives the bucket key; nil means KeyRemoteIP with TrustedProxies. | KeyFunc 派生桶的键；nil 表示使用 TrustedProxies 的 KeyRemoteIP。
	KeyFunc KeyFunc
	// Logger, when non-nil, records every throttled request and every store failure. | Logger 非 nil 时记录每一次被限流的请求与每一次存储故障。
	Logger *log.Logger
	// KeyPrefix is prepended to every derived key, separating rules that share a store. | KeyPrefix
	// 会加到每个派生键之前，用于隔离共享同一存储的多条规则。
	KeyPrefix string
	// TrustedProxies lists the reverse proxies allowed to supply X-Forwarded-For. Empty means the
	// peer address is the client address and proxy headers are ignored. | TrustedProxies 列出允许提供
	// X-Forwarded-For 的反向代理；为空表示以对端地址作为客户端地址并忽略代理头。
	TrustedProxies []netip.Prefix
	// Rate is the number of tokens replenished per second. | Rate 是每秒补充的令牌数。
	Rate float64
	// Burst is the bucket capacity, i.e. how many requests may pass at once. | Burst 是桶容量，即一次性允许通过的请求数。
	Burst int
	// CleanupInterval is the minimum delay between two lazy sweeps of a private MemoryStore. | CleanupInterval 是私有 MemoryStore 两次惰性清理之间的最小间隔。
	CleanupInterval time.Duration
	// FailClosed rejects requests when the store fails; the default (false) fails open. | FailClosed 在存储故障时拒绝请求；默认（false）失败开放。
	//
	// Fail-open keeps a Redis outage from taking the whole service down; fail-closed is the choice
	// when the limit protects a scarce resource that must not be oversubscribed during an outage.
	// | 失败开放避免 Redis 故障拖垮整个服务；当限流保护的是故障期间绝不可超卖的资源时，选择失败关闭。
	FailClosed bool
}

// rateLimiter holds the normalized options shared by every request. | rateLimiter 持有每个请求共享的归一化选项。
type rateLimiter struct {
	store      LimitStore
	allow      func(context.Context, string, float64, int) (Decision, error)
	keyFunc    KeyFunc
	logger     *log.Logger
	limitValue string
	keyPrefix  string
	trusted    []netip.Prefix
	rate       float64
	burst      int
	failClosed bool
}

// newRateLimiter normalizes o into a usable limiter. | newRateLimiter 把 o 归一化为可用的限流器。
func newRateLimiter(o RateLimitOptions) *rateLimiter {
	rate, burst := normalizeLimit(o.Rate, o.Burst)
	store := o.Store
	if store == nil {
		store = NewMemoryStore(o.CleanupInterval)
	}
	keyFunc := o.KeyFunc
	if keyFunc == nil {
		keyFunc = KeyRemoteIP(o.TrustedProxies)
	}
	lim := &rateLimiter{
		rate:       rate,
		burst:      burst,
		store:      store,
		keyFunc:    keyFunc,
		logger:     o.Logger,
		trusted:    o.TrustedProxies,
		keyPrefix:  o.KeyPrefix,
		limitValue: strconv.Itoa(burst),
		failClosed: o.FailClosed,
	}
	lim.allow = store.Allow
	if ms, ok := store.(*MemoryStore); ok {
		// The middleware normalized the options once at wiring time and a memory bucket never
		// blocks, so the hot path skips per-request normalization and cancellation checks. |
		// 中间件在装配期已归一化选项，且内存桶从不阻塞，因此热路径跳过每请求的归一化与取消检查。
		lim.allow = func(_ context.Context, key string, rate float64, burst int) (Decision, error) {
			return ms.allowNormalized(key, rate, burst)
		}
	}
	return lim
}

// joinNumbers renders a and b into one string and returns the two halves. | joinNumbers 把 a 与 b
// 渲染进同一个字符串，并返回两半。
//
// Both returned strings share one allocation, which is why a pair of numeric header values costs
// a single formatter allocation. | 两个返回的字符串共享同一次分配，因此一对数值头部值只需一次
// 格式化分配。
func joinNumbers(a, b int64) (string, string) {
	var scratch [41]byte
	out := strconv.AppendInt(scratch[:0], a, 10)
	split := len(out)
	out = append(out, '|')
	out = strconv.AppendInt(out, b, 10)
	s := string(out)
	return s[:split], s[split+1:]
}

// writeHeaders writes the three X-RateLimit-* headers shared by every outcome. | writeHeaders
// 写出所有结果共有的三个 X-RateLimit-* 头部。
func (lim *rateLimiter) writeHeaders(h http.Header, dec Decision) {
	remaining := int64(dec.Remaining)
	reset := int64(0)
	if d := dec.ResetAfter; d > 0 {
		// Integer ceiling in seconds; math.Ceil(d.Seconds()) would go through float64 on every
		// request. | 以整数秒向上取整；math.Ceil(d.Seconds()) 会在每个请求上走一遍 float64。
		reset = int64((d + time.Second - 1) / time.Second)
	}
	remainingValue, resetValue := joinNumbers(remaining, reset)
	vals := new([3]string)
	vals[0], vals[1], vals[2] = lim.limitValue, remainingValue, resetValue
	h[rateLimitHeaderKeys[0]] = vals[0:1:1]
	h[rateLimitHeaderKeys[1]] = vals[1:2:2]
	h[rateLimitHeaderKeys[2]] = vals[2:3:3]
}

// RateLimit returns a middleware backed by the configured LimitStore. | RateLimit 返回由配置的 LimitStore 支撑的限流中间件。
//
// Over-limit requests are answered with 429 plus Retry-After and the X-RateLimit-Limit,
// X-RateLimit-Remaining and X-RateLimit-Reset headers. The same three headers are also set on
// allowed responses. A store failure follows FailClosed: by default the request is allowed and a
// warning is logged; with FailClosed it is answered with 503. | 超限请求返回 429，并带上 Retry-After
// 与 X-RateLimit-Limit、X-RateLimit-Remaining、X-RateLimit-Reset；被放行的响应同样携带这三个头部。
// 存储故障遵循 FailClosed：默认放行并记录告警；开启 FailClosed 时返回 503。
func RateLimit(o RateLimitOptions) router.Middleware {
	lim := newRateLimiter(o)
	return func(c *router.Ctx) {
		key := lim.keyFunc(c)
		if lim.keyPrefix != "" {
			key = lim.keyPrefix + key
		}
		dec, err := lim.allow(c.Request.Context(), key, lim.rate, lim.burst)
		if err != nil {
			lim.logStoreFailure(c, key, err)
			if lim.failClosed {
				c.Abort()
				_ = c.String(http.StatusServiceUnavailable, "rate limit store unavailable | 限流存储不可用")
				return
			}
			c.Next()
			return
		}

		lim.writeHeaders(c.Writer.Header(), dec)
		if dec.Allowed {
			c.Next()
			return
		}

		wait := int(math.Ceil(dec.RetryAfter.Seconds()))
		if wait < 1 {
			wait = 1
		}
		c.Writer.Header()[rateLimitRetryKey] = []string{strconv.Itoa(wait)}
		if lim.logger != nil {
			lim.logger.Warn("rate limit exceeded | 触发限流",
				log.Str("key", key),
				log.Int("limit", lim.burst),
				log.Float64("rate", lim.rate),
				log.Str("path", c.Request.URL.Path),
				log.Str("remote_ip", c.ClientIP(lim.trusted)),
			)
		}
		c.Abort()
		_ = c.String(http.StatusTooManyRequests, "too many requests | 请求过于频繁")
	}
}

// logStoreFailure records a backend failure without ever panicking. | logStoreFailure 记录后端故障，且绝不 panic。
func (lim *rateLimiter) logStoreFailure(c *router.Ctx, key string, err error) {
	if lim.logger == nil {
		return
	}
	lim.logger.Warn("rate limit store failed | 限流存储故障",
		log.Str("key", key),
		log.Str("path", c.Request.URL.Path),
		log.Str("remote_ip", c.ClientIP(lim.trusted)),
		log.Str("error", err.Error()),
	)
}

// logStoreFailureHTTP is the native net/http form of logStoreFailure. | logStoreFailureHTTP 是
// logStoreFailure 的原生 net/http 形态。
func (lim *rateLimiter) logStoreFailureHTTP(r *http.Request, key string, err error) {
	if lim.logger == nil {
		return
	}
	lim.logger.Warn("rate limit store failed | 限流存储故障",
		log.Str("key", key),
		log.Str("path", r.URL.Path),
		log.Str("remote_ip", clientIP(r, lim.trusted)),
		log.Str("error", err.Error()),
	)
}

// clientIP resolves the native request's client address through the router's trusted-proxy model.
// | clientIP 通过路由的可信代理模型解析原生请求的客户端地址。
//
// ClientIP reads only Ctx.Request, so a request-only context on the caller's stack applies the
// exact same trusted-proxy rules as the router path; escape analysis keeps it off the heap, which
// is cheaper than a pooled context's Get/Put pair. | ClientIP 只读取 Ctx.Request，因此只携带请求
// 的栈上上下文会应用与路由路径完全相同的可信代理规则；逃逸分析让它留在栈上，比池化上下文的
// Get/Put 更便宜。
func clientIP(r *http.Request, trusted []netip.Prefix) string {
	var c router.Ctx
	c.Request = r
	return c.ClientIP(trusted)
}

// writePlain writes a plain-text status response on the native path. | writePlain 在原生路径上
// 写出纯文本状态响应。
func writePlain(w http.ResponseWriter, status int, msg string) {
	w.Header()["Content-Type"] = []string{"text/plain; charset=utf-8"}
	w.WriteHeader(status)
	_, _ = io.WriteString(w, msg)
}

// Middleware returns the native net/http form of RateLimit. | Middleware 返回 RateLimit 的
// 原生 net/http 形态。
//
// With the default IP key the native path executes the limiter directly, avoiding the router
// adapter on every request. A custom KeyFunc operates on *router.Ctx, so that configuration
// keeps using the shared router adapter. | 使用默认 IP 键时，原生路径直接执行限流器，省去每请求的
// 路由适配器；自定义 KeyFunc 依赖 *router.Ctx，因此该配置继续复用路由适配器。
func Middleware(o RateLimitOptions) func(http.Handler) http.Handler {
	if o.KeyFunc != nil {
		mw := RateLimit(o)
		return func(next http.Handler) http.Handler {
			return router.Adapt(next, mw)
		}
	}
	lim := newRateLimiter(o)
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			key := clientIP(r, lim.trusted)
			if lim.keyPrefix != "" {
				key = lim.keyPrefix + key
			}
			dec, err := lim.allow(r.Context(), key, lim.rate, lim.burst)
			if err != nil {
				lim.logStoreFailureHTTP(r, key, err)
				if lim.failClosed {
					writePlain(w, http.StatusServiceUnavailable, "rate limit store unavailable | 限流存储不可用")
					return
				}
				next.ServeHTTP(w, r)
				return
			}

			lim.writeHeaders(w.Header(), dec)
			if dec.Allowed {
				next.ServeHTTP(w, r)
				return
			}

			wait := int(math.Ceil(dec.RetryAfter.Seconds()))
			if wait < 1 {
				wait = 1
			}
			w.Header()[rateLimitRetryKey] = []string{strconv.Itoa(wait)}
			if lim.logger != nil {
				lim.logger.Warn("rate limit exceeded | 触发限流",
					log.Str("key", key),
					log.Int("limit", lim.burst),
					log.Float64("rate", lim.rate),
					log.Str("path", r.URL.Path),
					log.Str("remote_ip", clientIP(r, lim.trusted)),
				)
			}
			writePlain(w, http.StatusTooManyRequests, "too many requests | 请求过于频繁")
		})
	}
}
