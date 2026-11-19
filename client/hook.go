package client

import (
	"context"
	"net/http"
	"time"

	"github.com/shibingli/ydx/errs"
)

// AttemptInfo describes one upstream attempt. | AttemptInfo 描述一次上游尝试。
type AttemptInfo struct {
	// Host is the selected host, when any. | Host 是选中的 Host（如有）。
	Host *Host
	// Method is the request method. | Method 是请求方法。
	Method string
	// URL is the logical request URL without query. | URL 是不含查询的逻辑请求 URL。
	URL string
	// Attempt is the 1-based attempt number. | Attempt 是从 1 开始的尝试序号。
	Attempt int
}

// RetryInfo describes one retry decision. | RetryInfo 描述一次重试决策。
type RetryInfo struct {
	// Reason is a short retry reason. | Reason 是简短重试原因。
	Reason string
	// Attempt is the attempt that just failed. | Attempt 是刚失败的尝试序号。
	Attempt int
	// Delay is the backoff before the next attempt. | Delay 是下一次尝试前的退避。
	Delay time.Duration
}

// MirrorInfo identifies one mirror target. | MirrorInfo 标识一个镜像目标。
type MirrorInfo struct {
	// Target is the shadow base URL. | Target 是影子 base URL。
	Target string
}

// empty reports whether no hook is configured. | empty 报告是否未配置任何钩子。
func (h Hooks) empty() bool {
	return h.OnRequest == nil && h.OnRoute == nil && h.OnHost == nil && h.OnAttempt == nil &&
		h.OnRetry == nil && h.OnResponse == nil && h.OnCacheHit == nil && h.OnCacheMiss == nil &&
		h.OnCacheStore == nil && h.OnCoalesce == nil && h.OnMirrorStart == nil && h.OnMirrorDone == nil &&
		h.OnMirrorDrop == nil && h.OnBlocked == nil && h.OnStreamStart == nil && h.OnStreamEvent == nil &&
		h.OnStreamEnd == nil && h.OnError == nil && h.OnComplete == nil
}

// Hooks is the ordered callback set; nil fields are free. Engine hooks run
// inside request goroutines; they must not call Client.Close or CloseContext
// synchronously, because Close waits for those goroutines. Use
// Client.CloseAsync or launch a goroutine instead. | Hooks 是有序回调集合；nil
// 字段零开销。引擎钩子在请求 goroutine 内运行；不得同步调用 Client.Close 或
// CloseContext，因为 Close 会等待这些 goroutine。请改用 Client.CloseAsync 或
// 在独立 goroutine 中关闭。
type Hooks struct {
	// OnRequest runs before routing; an error aborts the request. | OnRequest 在路由前运行；错误会中止请求。
	OnRequest func(context.Context, *http.Request) error
	// OnRoute runs after a rule match. | OnRoute 在规则命中后运行。
	OnRoute func(context.Context, *http.Request, *Rule, Params)
	// OnHost runs after host selection. | OnHost 在 Host 选择后运行。
	OnHost func(context.Context, *http.Request, *Host)
	// OnAttempt runs before each upstream attempt. | OnAttempt 在每次上游尝试前运行。
	OnAttempt func(context.Context, AttemptInfo)
	// OnRetry runs before retry backoff. | OnRetry 在重试退避前运行。
	OnRetry func(context.Context, RetryInfo)
	// OnResponse runs before a response is returned; an error closes it. | OnResponse 在返回响应前运行；错误会关闭响应。
	OnResponse func(context.Context, *Response) error
	// OnCacheHit runs when a cached response is served. | OnCacheHit 在缓存命中时运行。
	OnCacheHit func(context.Context, *http.Request)
	// OnCacheMiss runs when the cache has no usable entry. | OnCacheMiss 在缓存未命中时运行。
	OnCacheMiss func(context.Context, *http.Request)
	// OnCacheStore runs after a response is stored. | OnCacheStore 在响应写入缓存后运行。
	OnCacheStore func(context.Context, *http.Request, int64)
	// OnCoalesce reports whether the request joined a flight. | OnCoalesce 报告请求是否加入合并。
	OnCoalesce func(context.Context, *http.Request, bool)
	// OnMirrorStart runs when a shadow request is scheduled. | OnMirrorStart 在影子请求调度时运行。
	OnMirrorStart func(context.Context, MirrorInfo)
	// OnMirrorDone runs when a shadow request finishes. | OnMirrorDone 在影子请求完成时运行。
	OnMirrorDone func(context.Context, MirrorInfo)
	// OnMirrorDrop runs when a mirror or tee payload is dropped. | OnMirrorDrop 在镜像或 tee 载荷丢弃时运行。
	OnMirrorDrop func(context.Context, MirrorInfo, string)
	// OnBlocked runs when a guard rejects a request. | OnBlocked 在守卫拒绝请求时运行。
	OnBlocked func(context.Context, *http.Request, GuardDecision)
	// OnStreamStart runs after an SSE stream opens. | OnStreamStart 在 SSE 流打开后运行。
	OnStreamStart func(context.Context, *http.Request)
	// OnStreamEvent runs for each outbound SSE event. | OnStreamEvent 为每个出站 SSE 事件运行。
	OnStreamEvent func(context.Context, Event)
	// OnStreamEnd runs when an SSE stream closes. | OnStreamEnd 在 SSE 流关闭时运行。
	OnStreamEnd func(context.Context, error)
	// OnError runs for a final request error. | OnError 在最终请求错误时运行。
	OnError func(context.Context, *Error)
	// OnComplete runs after a Client convenience call completes. | OnComplete 在 Client 便捷调用完成后运行。
	OnComplete func(context.Context, *Meta)
}

// WithHooks sets the client-wide hooks. | WithHooks 设置客户端级钩子。
func WithHooks(hooks Hooks) Option {
	return func(o *options) error {
		o.Hooks = hooks
		return nil
	}
}

// callHook invokes one hook, converting a panic into ErrHookPanic. | callHook 调用单个钩子，把 panic 转为 ErrHookPanic。
func callHook(fn func() error) (err error) {
	if fn == nil {
		return nil
	}
	defer func() {
		if recovered := recover(); recovered != nil {
			err = errs.Detail(ErrHookPanic, "panic: %v | panic：%v", recovered, recovered)
		}
	}()
	return fn()
}

// safeCheckRedirect isolates panics in a user redirect callback. | safeCheckRedirect 隔离用户重定向回调中的 panic。
func safeCheckRedirect(fn func(*http.Request, []*http.Request) error) func(*http.Request, []*http.Request) error {
	if fn == nil {
		return nil
	}
	return func(req *http.Request, via []*http.Request) (err error) {
		defer func() {
			if recovered := recover(); recovered != nil {
				err = errs.Detail(ErrHookPanic, "check redirect panic: %v | 重定向检查 panic：%v", recovered, recovered)
			}
		}()
		return fn(req, via)
	}
}

// fireRequest runs OnRequest. | fireRequest 运行 OnRequest。
func (e *engine) fireRequest(ctx context.Context, req *http.Request) error {
	if e.hooks.OnRequest == nil {
		return nil
	}
	return callHook(func() error { return e.hooks.OnRequest(ctx, req) })
}

// fireRoute runs OnRoute. | fireRoute 运行 OnRoute。
func (e *engine) fireRoute(ctx context.Context, req *http.Request, rule *Rule, params Params) error {
	if e.hooks.OnRoute == nil {
		return nil
	}
	return callHook(func() error {
		e.hooks.OnRoute(ctx, req, rule, params)
		return nil
	})
}

// fireHost runs OnHost. | fireHost 运行 OnHost。
func (e *engine) fireHost(ctx context.Context, req *http.Request, host *Host) {
	if e.hooks.OnHost != nil {
		_ = callHook(func() error {
			e.hooks.OnHost(ctx, req, host)
			return nil
		})
	}
}

// fireAttempt runs OnAttempt. | fireAttempt 运行 OnAttempt。
func (e *engine) fireAttempt(ctx context.Context, info AttemptInfo) {
	if e.hooks.OnAttempt != nil {
		_ = callHook(func() error {
			e.hooks.OnAttempt(ctx, info)
			return nil
		})
	}
}

// fireRetry runs OnRetry. | fireRetry 运行 OnRetry。
func (e *engine) fireRetry(ctx context.Context, info RetryInfo) {
	if e.hooks.OnRetry != nil {
		_ = callHook(func() error {
			e.hooks.OnRetry(ctx, info)
			return nil
		})
	}
}

// fireResponse runs OnResponse and closes the body on failure. | fireResponse 运行 OnResponse，失败时关闭正文。
func (e *engine) fireResponse(ctx context.Context, resp *Response) error {
	if e.hooks.OnResponse == nil || resp == nil {
		return nil
	}
	return callHook(func() error { return e.hooks.OnResponse(ctx, resp) })
}

// fireComplete runs OnComplete. | fireComplete 运行 OnComplete。
func (e *engine) fireComplete(ctx context.Context, meta *Meta) {
	if e.hooks.OnComplete == nil || meta == nil {
		return
	}
	_ = callHook(func() error {
		e.hooks.OnComplete(ctx, meta)
		return nil
	})
}

// fireError runs OnError. | fireError 运行 OnError。
func (e *engine) fireError(ctx context.Context, err *Error) {
	if e.hooks.OnError != nil && err != nil {
		_ = callHook(func() error {
			e.hooks.OnError(ctx, err)
			return nil
		})
	}
}
