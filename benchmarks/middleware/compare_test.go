package middleware

import (
	"net/http"
	"net/http/httptest"
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

	b.Run("none", func(b *testing.B) {
		benchRunMiddleware(b, body, "", req, nil, false, nil)
	})
	b.Run("ydx", func(b *testing.B) {
		benchRunMiddleware(b, body, "", req, ydxWrap, false, check)
	})
	b.Run("x-time-rate", func(b *testing.B) {
		benchRunMiddleware(b, body, "", req, xtimeWrap, false, check)
	})
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
