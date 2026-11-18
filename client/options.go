package client

import (
	"net/http"
	"net/url"
	"time"

	"github.com/shibingli/ydx/errs"
	"github.com/shibingli/ydx/log"
)

// options is the mutable accumulator behind functional options. | options 是函数式选项背后的可变累加器。
type options struct {
	Hooks             Hooks
	Transport         http.RoundTripper
	Jar               http.CookieJar
	CacheStore        Store
	Guard             Guard
	Logger            *log.Logger
	CheckRedirect     func(*http.Request, []*http.Request) error
	BaseURL           *url.URL
	HostSet           *HostSet
	Retry             *RetryPolicy
	Cache             *CachePolicy
	Coalesce          *CoalescePolicy
	Mirror            *MirrorPolicy
	AccessPolicy      *AccessPolicy
	TLSConfig         *TLSConfig
	HostTLS           map[string]TLSConfig
	UserAgent         *UAPolicy
	ConnMode          ConnMode
	Rules             []Rule
	Hosts             []Host
	Timeout           time.Duration
	MaxParallel       int
	SpoolLimit        int64
	SpoolMaxBytes     int64
	MaxMirrorInflight int
	MaxAsync          int
	SpoolToDisk       bool
	H2C               bool
	DisableCookieJar  bool
	Trace             bool
	RewriteAll        bool
}

// Option mutates the client configuration during New. | Option 在 New 期间修改客户端配置。
type Option func(*options) error

// defaultOptions returns the defaults used when New receives no option. | defaultOptions 返回 New 未收到选项时使用的默认值。
func defaultOptions() options {
	return options{
		MaxParallel:   32,
		SpoolLimit:    1 << 20,
		SpoolMaxBytes: 64 << 20,
		MaxAsync:      1024,
		ConnMode:      ConnLong,
	}
}

// WithTransport replaces the underlying RoundTripper. | WithTransport 替换底层 RoundTripper。
func WithTransport(rt http.RoundTripper) Option {
	return func(o *options) error {
		o.Transport = rt
		return nil
	}
}

// WithLogger enables structured logging through ydx/log. | WithLogger 启用 ydx/log 结构化日志。
func WithLogger(l *log.Logger) Option {
	return func(o *options) error {
		o.Logger = l
		return nil
	}
}

// WithTimeout sets the default total request timeout; zero disables it. | WithTimeout 设置默认请求总超时；0 表示不限制。
func WithTimeout(d time.Duration) Option {
	return func(o *options) error {
		if d < 0 {
			return errs.Detail(ErrInvalidConfig, "negative timeout | 超时为负")
		}
		o.Timeout = d
		return nil
	}
}

// WithMaxParallel bounds concurrent requests issued by pipelines and groups. | WithMaxParallel 限制编排与动态组的并发请求数。
func WithMaxParallel(n int) Option {
	return func(o *options) error {
		if n <= 0 {
			return errs.Detail(ErrInvalidConfig, "max parallel must be positive | 最大并发必须为正")
		}
		o.MaxParallel = n
		return nil
	}
}

// WithSpoolLimit sets the in-memory replay buffer limit; zero disables memory spooling. | WithSpoolLimit 设置内存重放缓冲上限；0 表示不启用内存暂存。
func WithSpoolLimit(n int64) Option {
	return func(o *options) error {
		if n < 0 {
			return errs.Detail(ErrInvalidConfig, "negative spool limit | 暂存上限为负")
		}
		o.SpoolLimit = n
		return nil
	}
}

// WithSpoolMaxBytes caps the total spooled body (memory or disk); <=0 means unlimited. | WithSpoolMaxBytes 限制暂存正文总量（内存或磁盘）；<=0 表示不限制。
func WithSpoolMaxBytes(n int64) Option {
	return func(o *options) error {
		o.SpoolMaxBytes = n
		return nil
	}
}

// WithSpoolToDisk allows oversized replay bodies to spill to a temporary file. | WithSpoolToDisk 允许超大重放正文落到临时文件。
func WithSpoolToDisk(ok bool) Option {
	return func(o *options) error {
		o.SpoolToDisk = ok
		return nil
	}
}

// WithCookieJar installs the cookie jar used by Do; nil disables the default
// jar. | WithCookieJar 安装 Do 使用的 Cookie 罐；nil 关闭默认 Cookie 罐。
func WithCookieJar(jar http.CookieJar) Option {
	return func(o *options) error {
		o.Jar = jar
		o.DisableCookieJar = jar == nil
		return nil
	}
}

// WithoutCookieJar disables the default in-memory cookie jar. | WithoutCookieJar 关闭默认内存 Cookie 罐。
func WithoutCookieJar() Option {
	return func(o *options) error {
		o.Jar = nil
		o.DisableCookieJar = true
		return nil
	}
}

// WithRewriteAll routes absolute URLs through the default host pool. | WithRewriteAll 让绝对 URL 也走默认 Host 池。
func WithRewriteAll(enabled bool) Option {
	return func(o *options) error {
		o.RewriteAll = enabled
		return nil
	}
}

// WithTrace enables httptrace timings in Meta.Timings. | WithTrace 启用 Meta.Timings 的 httptrace 计时。
func WithTrace(enabled bool) Option {
	return func(o *options) error {
		o.Trace = enabled
		return nil
	}
}

// WithCheckRedirect installs the redirect policy used by Do. | WithCheckRedirect 安装 Do 使用的重定向策略。
func WithCheckRedirect(fn func(*http.Request, []*http.Request) error) Option {
	return func(o *options) error {
		o.CheckRedirect = fn
		return nil
	}
}
