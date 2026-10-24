package middleware

import (
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"sync"
	"testing"

	chimw "github.com/go-chi/chi/v5/middleware"
	"github.com/klauspost/compress/gzhttp"
	rscors "github.com/rs/cors"
	"golang.org/x/time/rate"

	ydxcompress "github.com/shibingli/ydx/middleware/compress"
	ydxcors "github.com/shibingli/ydx/middleware/cors"
	ydxratelimit "github.com/shibingli/ydx/middleware/ratelimit"
	ydxrecovery "github.com/shibingli/ydx/middleware/recovery"
	ydxrequestid "github.com/shibingli/ydx/middleware/requestid"
)

// The comparison benchmarks wrap a plain http.Handler, not the YD router, so mainstream
// net/http middleware can be measured on the same request path. Every case uses the same
// terminal handler, request and sink writer; a check runs once before the timer to prove the
// middleware really executed. | 对比基准包装普通 http.Handler 而不是 YD 路由，使主流 net/http
// 中间件能在同一请求路径上测量。每个用例共用相同的终端处理器、请求与丢弃写入器；计时前执行一次
// 校验，证明中间件确实生效。

// benchRunMiddleware wraps one terminal handler and measures the request path. |
// benchRunMiddleware 包装一个终端处理器并测量请求路径。
func benchRunMiddleware(
	b *testing.B,
	body []byte,
	contentType string,
	req *http.Request,
	wrap func(http.Handler) http.Handler,
	setBytes bool,
	check func(*testing.B, *httptest.ResponseRecorder),
) {
	b.Helper()
	terminal := http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		if contentType != "" {
			w.Header().Set("Content-Type", contentType)
		}
		_, _ = w.Write(body)
	})
	var h http.Handler = terminal
	if wrap != nil {
		h = wrap(terminal)
	}
	if check != nil {
		rec := httptest.NewRecorder()
		h.ServeHTTP(rec, req)
		check(b, rec)
	}
	w := &benchSinkWriter{header: make(http.Header)}
	if setBytes {
		b.SetBytes(int64(len(body)))
	}
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		clear(w.header)
		h.ServeHTTP(w, req)
	}
}

// benchCheckBody returns a validator requiring the response body to equal want. |
// benchCheckBody 返回要求响应正文等于 want 的校验器。
func benchCheckBody(want []byte) func(*testing.B, *httptest.ResponseRecorder) {
	return func(b *testing.B, rec *httptest.ResponseRecorder) {
		b.Helper()
		if got := rec.Body.Bytes(); string(got) != string(want) {
			b.Fatalf("body = %q, want %q | 正文不符", got, want)
		}
	}
}

// benchCheckHeader returns a validator requiring a non-empty response header. |
// benchCheckHeader 返回要求响应头非空的校验器。
func benchCheckHeader(name, want string) func(*testing.B, *httptest.ResponseRecorder) {
	return func(b *testing.B, rec *httptest.ResponseRecorder) {
		b.Helper()
		got := rec.Header().Get(name)
		if want == "" {
			if got == "" {
				b.Fatalf("header %q is empty | 响应头 %q 为空", name, name)
			}
			return
		}
		if got != want {
			b.Fatalf("header %q = %q, want %q | 响应头不符", name, got, want)
		}
	}
}

// BenchmarkCORSCompare compares the ydx CORS middleware with rs/cors on a cross-origin GET. |
// BenchmarkCORSCompare 在跨源 GET 上对比 ydx CORS 中间件与 rs/cors。
func BenchmarkCORSCompare(b *testing.B) {
	body := []byte(benchSmallBody)
	req := benchRequest(map[string]string{"Origin": "https://example.com"})
	check := benchCheckHeader("Access-Control-Allow-Origin", "*")
	ydxWrap := ydxcors.Middleware(ydxcors.CORSOptions{
		AllowOrigins: []string{"*"},
		AllowMethods: []string{http.MethodGet},
	})
	rsWrap := rscors.New(rscors.Options{
		AllowedOrigins: []string{"*"},
		AllowedMethods: []string{http.MethodGet},
	}).Handler

	b.Run("none", func(b *testing.B) {
		benchRunMiddleware(b, body, "", req, nil, false, nil)
	})
	b.Run("ydx", func(b *testing.B) {
		benchRunMiddleware(b, body, "", req, ydxWrap, false, check)
	})
	b.Run("rs-cors", func(b *testing.B) {
		benchRunMiddleware(b, body, "", req, rsWrap, false, check)
	})
}

// BenchmarkRequestIDCompare compares the ydx request-ID middleware with chi's RequestID. |
// BenchmarkRequestIDCompare 对比 ydx 请求 ID 中间件与 chi 的 RequestID。
func BenchmarkRequestIDCompare(b *testing.B) {
	body := []byte(benchSmallBody)
	req := benchRequest(nil)
	check := benchCheckHeader("X-Request-Id", "")

	b.Run("none", func(b *testing.B) {
		benchRunMiddleware(b, body, "", req, nil, false, nil)
	})
	b.Run("ydx", func(b *testing.B) {
		benchRunMiddleware(b, body, "", req, ydxrequestid.Middleware("X-Request-Id"), false, check)
	})
	b.Run("chi", func(b *testing.B) {
		// chi's RequestID stores the generated ID in the request context but does not write a
		// response header. The adapter writes the header from the context so both cases produce
		// the same observable result. | chi 的 RequestID 只把生成的 ID 放进请求上下文，不写响应头。
		// 适配器从上下文取出 ID 写入响应头，使两个用例产生相同的可观测结果。
		chiWrap := func(next http.Handler) http.Handler {
			return chimw.RequestID(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				if id := chimw.GetReqID(r.Context()); id != "" {
					w.Header().Set("X-Request-Id", id)
				}
				next.ServeHTTP(w, r)
			}))
		}
		benchRunMiddleware(b, body, "", req, chiWrap, false, check)
	})
}

// BenchmarkRecoverCompare compares the ydx recovery middleware with chi's Recoverer on the
// normal (no-panic) path. | BenchmarkRecoverCompare 在常态（无 panic）路径上对比 ydx 恢复中间件
// 与 chi 的 Recoverer。
func BenchmarkRecoverCompare(b *testing.B) {
	body := []byte(benchSmallBody)
	req := benchRequest(nil)
	check := benchCheckBody(body)

	b.Run("none", func(b *testing.B) {
		benchRunMiddleware(b, body, "", req, nil, false, nil)
	})
	b.Run("ydx", func(b *testing.B) {
		benchRunMiddleware(b, body, "", req, ydxrecovery.Middleware(benchDiscardLogger()), false, check)
	})
	b.Run("chi", func(b *testing.B) {
		benchRunMiddleware(b, body, "", req, chimw.Recoverer, false, check)
	})
}

// BenchmarkRateLimitCompare compares the ydx token-bucket middleware with an x/time/rate
// wrapper on the allowed path. ydx also writes three X-RateLimit-* headers; the x/time wrapper
// does not, which is part of the measured difference. |
// BenchmarkRateLimitCompare 在放行路径上对比 ydx 令牌桶中间件与 x/time/rate 包装器。ydx 还会写
// 三个 X-RateLimit-* 响应头，而 x/time 包装器不写，这属于测量差异的一部分。
func BenchmarkRateLimitCompare(b *testing.B) {
	body := []byte(benchSmallBody)
	req := benchRequest(nil)
	check := benchCheckBody(body)

	limiter := rate.NewLimiter(rate.Limit(1e9), 1<<30)
	xtimeWrap := func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if !limiter.Allow() {
				http.Error(w, "rate limited | 请求过多", http.StatusTooManyRequests)
				return
			}
			next.ServeHTTP(w, r)
		})
	}
	ydxWrap := ydxratelimit.Middleware(ydxratelimit.RateLimitOptions{
		Rate:  1e9,
		Burst: 1 << 30,
	})
	// The ydx middleware writes three X-RateLimit-* headers on every response. This variant adds
	// the same observable headers to the x/time/rate path so the comparison does not attribute
	// ydx's extra contract to limiter cost. | ydx 中间件在每个响应上写三个 X-RateLimit-* 头部。
	// 该变体给 x/time/rate 路径补上相同的可观测头部，避免把 ydx 的额外契约算成限流器成本。
	limitValue := strconv.Itoa(1 << 30)
	xtimeHeadersWrap := func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if !limiter.Allow() {
				http.Error(w, "rate limited | 请求过多", http.StatusTooManyRequests)
				return
			}
			benchWriteRateHeaders(w.Header(), limitValue, (1<<30)-1, 1)
			next.ServeHTTP(w, r)
		})
	}
	perIP := newBenchIPLimiters()
	xtimePerIPHeadersWrap := func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			key := r.RemoteAddr
			if i := strings.LastIndexByte(key, ':'); i > 0 {
				key = key[:i]
			}
			if !perIP.allow(key) {
				http.Error(w, "rate limited | 请求过多", http.StatusTooManyRequests)
				return
			}
			benchWriteRateHeaders(w.Header(), limitValue, (1<<30)-1, 1)
			next.ServeHTTP(w, r)
		})
	}

	b.Run("none", func(b *testing.B) {
		benchRunMiddleware(b, body, "", req, nil, false, nil)
	})
	b.Run("ydx", func(b *testing.B) {
		benchRunMiddleware(b, body, "", req, ydxWrap, false, check)
	})
	b.Run("x-time-rate", func(b *testing.B) {
		benchRunMiddleware(b, body, "", req, xtimeWrap, false, check)
	})
	b.Run("x-time-rate+headers", func(b *testing.B) {
		benchRunMiddleware(b, body, "", req, xtimeHeadersWrap, false, check)
	})
	b.Run("x-time-rate+per-ip+headers", func(b *testing.B) {
		benchRunMiddleware(b, body, "", req, xtimePerIPHeadersWrap, false, check)
	})
}

// benchIPLimiters is a per-key x/time/rate limiter map, matching the ydx middleware's default
// per-IP bucketing. It includes the map lookup and lock that a global limiter does not pay. |
// benchIPLimiters 是按 key 分桶的 x/time/rate 限制器映射，与 ydx 中间件默认的按 IP 分桶对齐。
// 它包含全局 limiting 不支付的 map 查找与锁。
type benchIPLimiters struct {
	mu sync.Mutex
	m  map[string]*rate.Limiter
}

func newBenchIPLimiters() *benchIPLimiters {
	return &benchIPLimiters{m: make(map[string]*rate.Limiter)}
}

func (l *benchIPLimiters) allow(key string) bool {
	l.mu.Lock()
	limiter := l.m[key]
	if limiter == nil {
		limiter = rate.NewLimiter(rate.Limit(1e9), 1<<30)
		l.m[key] = limiter
	}
	l.mu.Unlock()
	return limiter.Allow()
}

// benchWriteRateHeaders writes the three X-RateLimit-* headers with the same formatting strategy
// as the ydx middleware, so the x/time/rate+headers variant is a like-for-like measurement. |
// benchWriteRateHeaders 用与 ydx 中间件相同的格式化策略写三个 X-RateLimit-* 头部，使
// x/time/rate+headers 变体成为同口径测量。
func benchWriteRateHeaders(h http.Header, limit string, remaining, reset int64) {
	var scratch [41]byte
	out := strconv.AppendInt(scratch[:0], remaining, 10)
	split := len(out)
	out = append(out, '|')
	out = strconv.AppendInt(out, reset, 10)
	s := string(out)
	vals := new([3]string)
	vals[0], vals[1], vals[2] = limit, s[:split], s[split+1:]
	h["X-RateLimit-Limit"] = vals[0:1:1]
	h["X-RateLimit-Remaining"] = vals[1:2:2]
	h["X-RateLimit-Reset"] = vals[2:3:3]
}

// BenchmarkCompressCompare compares ydx gzip compression with klauspost gzhttp on a 16 KiB
// HTML response. Both are checked to really emit Content-Encoding: gzip before timing. |
// BenchmarkCompressCompare 在 16 KiB HTML 响应上对比 ydx gzip 压缩与 klauspost gzhttp。计时前
// 校验两者确实输出 Content-Encoding: gzip。
func BenchmarkCompressCompare(b *testing.B) {
	body := []byte(benchHTMLPayload)
	req := benchRequest(map[string]string{"Accept-Encoding": "gzip"})
	check := benchCheckHeader("Content-Encoding", "gzip")
	ydxWrap := ydxcompress.Middleware(ydxcompress.CompressOptions{
		Algorithms: []ydxcompress.Algorithm{ydxcompress.Gzip},
	})
	gzWrap := func(next http.Handler) http.Handler {
		return gzhttp.GzipHandler(next)
	}

	b.Run("none", func(b *testing.B) {
		benchRunMiddleware(b, body, "text/html; charset=utf-8", req, nil, true, nil)
	})
	b.Run("ydx-gzip", func(b *testing.B) {
		benchRunMiddleware(b, body, "text/html; charset=utf-8", req, ydxWrap, true, check)
	})
	b.Run("gzhttp", func(b *testing.B) {
		benchRunMiddleware(b, body, "text/html; charset=utf-8", req, gzWrap, true, check)
	})
}
