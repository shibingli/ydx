package client

import (
	"context"
	"crypto/tls"
	"errors"
	"io"
	"math/rand/v2"
	"net"
	"net/http"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/shibingli/ydx/errs"
)

// RetryPolicy controls attempt count, retry triggers and backoff. | RetryPolicy 控制尝试次数、重试触发条件与退避。
type RetryPolicy struct {
	// Backoff overrides the default exponential backoff. | Backoff 覆盖默认指数退避。
	Backoff func(attempt int) time.Duration
	// Methods lists retryable methods; nil means idempotent methods (or all when NonIdempotent). | Methods 列出可重试方法；nil 表示幂等方法（NonIdempotent 时表示全部）。
	Methods []string
	// StatusCodes lists retryable statuses; nil means 429/502/503/504. | StatusCodes 列出可重试状态码；nil 表示 429/502/503/504。
	StatusCodes []int
	// MaxAttempts is the total attempt count; <=0 derives it from the host count
	// and values above 10 are capped at 10. | MaxAttempts 是总尝试次数；<=0 时按 Host
	// 数推导，大于 10 时按 10 封顶。
	MaxAttempts int
	// MaxBackoff caps one backoff or Retry-After delay; <=0 means 1s. | MaxBackoff 限制单次退避或 Retry-After；<=0 表示 1s。
	MaxBackoff time.Duration
	// Budget is the retry token ratio; <=0 means 0.1. | Budget 是重试令牌比例；<=0 表示 0.1。
	Budget float64
	// PerAttemptTimeout bounds one attempt including its response body. | PerAttemptTimeout 限制单次尝试（含响应正文）。
	PerAttemptTimeout time.Duration
	// DisableNetworkRetry disables retries for transport errors. | DisableNetworkRetry 禁用传输错误重试。
	DisableNetworkRetry bool
	// NonIdempotent permits retrying POST/PATCH when their body is replayable. | NonIdempotent 允许在正文可重放时重试 POST/PATCH。
	NonIdempotent bool
	// DisableRetryAfter ignores the Retry-After response header. | DisableRetryAfter 忽略 Retry-After 响应头。
	DisableRetryAfter bool
}

// defaultRetryStatusCodes is shared by every default retry policy. | defaultRetryStatusCodes 由所有默认重试策略共享。
var defaultRetryStatusCodes = []int{
	http.StatusTooManyRequests,
	http.StatusBadGateway,
	http.StatusServiceUnavailable,
	http.StatusGatewayTimeout,
}

// withDefaults fills zero-value retry settings. | withDefaults 填充零值重试设置。
func (p RetryPolicy) withDefaults(hostCount int) RetryPolicy {
	if p.MaxAttempts <= 0 {
		if hostCount > 1 {
			p.MaxAttempts = 2
		} else {
			p.MaxAttempts = 1
		}
	}
	if p.MaxAttempts > 10 {
		p.MaxAttempts = 10
	}
	if p.StatusCodes == nil {
		p.StatusCodes = defaultRetryStatusCodes
	}
	if p.MaxBackoff <= 0 {
		p.MaxBackoff = time.Second
	}
	if p.Budget <= 0 {
		p.Budget = 0.1
	}
	return p
}

// defaultRetryPolicy returns the policy used when none is configured. | defaultRetryPolicy 返回未配置时使用的策略。
func defaultRetryPolicy(hostCount int) RetryPolicy {
	return RetryPolicy{}.withDefaults(hostCount)
}

// WithRetry sets the client-wide retry policy. | WithRetry 设置客户端级重试策略。
func WithRetry(policy RetryPolicy) Option {
	policy.Methods = cloneSlice(policy.Methods)
	policy.StatusCodes = cloneSlice(policy.StatusCodes)
	return func(o *options) error {
		if policy.MaxAttempts < 0 {
			return errs.Detail(ErrInvalidConfig, "negative max attempts | 最大尝试次数为负")
		}
		o.Retry = &policy
		return nil
	}
}

// retryableMethod reports whether method may be retried under policy. | retryableMethod 报告 method 在 policy 下是否可重试。
func retryableMethod(policy RetryPolicy, req *http.Request) bool {
	if req == nil {
		return false
	}
	method := req.Method
	if policy.Methods != nil {
		for _, candidate := range policy.Methods {
			if candidate == method {
				return true
			}
		}
		return false
	}
	if policy.NonIdempotent {
		return true
	}
	if (method == http.MethodPost || method == http.MethodPatch) && req.Header.Get("Idempotency-Key") != "" {
		return true
	}
	switch method {
	case http.MethodGet, http.MethodHead, http.MethodPut, http.MethodDelete, http.MethodOptions, http.MethodTrace:
		return true
	default:
		return false
	}
}

// retryStatus reports whether status is configured as retryable. | retryStatus 报告 status 是否配置为可重试。
func retryStatus(policy RetryPolicy, status int) bool {
	for _, candidate := range policy.StatusCodes {
		if candidate == status {
			return true
		}
	}
	return false
}

// retryableError reports whether a transport error may be retried. | retryableError 报告传输错误是否可重试。
func retryableError(err error, parent context.Context) bool {
	if err == nil {
		return false
	}
	if parent != nil && parent.Err() != nil {
		return false
	}
	var certErr *tls.CertificateVerificationError
	if errors.As(err, &certErr) {
		return false
	}
	if errors.Is(err, ErrTLSPin) || errors.Is(err, ErrTLS) || errors.Is(err, ErrTLSConfig) ||
		errors.Is(err, ErrRequestTooLarge) || errors.Is(err, ErrBlocked) || errors.Is(err, ErrGuard) ||
		errors.Is(err, ErrInvalidResponse) || errors.Is(err, ErrInvalidRequest) ||
		errors.Is(err, ErrInvalidConfig) || errors.Is(err, ErrEncodeBody) ||
		errors.Is(err, ErrBodyNotReplayable) {
		return false
	}
	var netErr net.Error
	if errors.As(err, &netErr) {
		return true
	}
	if errors.Is(err, io.EOF) || errors.Is(err, io.ErrUnexpectedEOF) {
		return true
	}
	return true
}

// backoffDelay returns a full-jitter delay for the next attempt. | backoffDelay 返回下一次尝试的 full-jitter 延迟。
func backoffDelay(policy RetryPolicy, attempt int) (delay time.Duration) {
	if policy.Backoff != nil {
		defer func() {
			if recover() != nil {
				delay = 0
			}
		}()
		delay = policy.Backoff(attempt)
		if delay < 0 {
			return 0
		}
		if policy.MaxBackoff > 0 && delay > policy.MaxBackoff {
			delay = policy.MaxBackoff
		}
		return delay
	}
	delay = 50 * time.Millisecond
	for i := 1; i < attempt; i++ {
		delay *= 2
		if delay >= policy.MaxBackoff {
			delay = policy.MaxBackoff
			break
		}
	}
	if delay > policy.MaxBackoff {
		delay = policy.MaxBackoff
	}
	if delay <= 0 {
		return 0
	}
	return time.Duration(rand.Int64N(int64(delay) + 1))
}

// retryAfterValue parses Retry-After seconds or HTTP-date and caps it at max. | retryAfterValue
// 解析 Retry-After 秒数或 HTTP 日期并以 max 为上限；ok 表示头部合法。
func retryAfterValue(header http.Header, max time.Duration) (delay time.Duration, ok bool) {
	value := strings.TrimSpace(header.Get("Retry-After"))
	if value == "" {
		return 0, false
	}
	if seconds, err := strconv.Atoi(value); err == nil && seconds >= 0 {
		if max > 0 && int64(seconds) > int64(max/time.Second) {
			return max, true
		}
		delay = time.Duration(seconds) * time.Second
		if max > 0 && delay > max {
			delay = max
		}
		return delay, true
	}
	if when, err := http.ParseTime(value); err == nil {
		delay = time.Until(when)
		if delay < 0 {
			delay = 0
		}
		if max > 0 && delay > max {
			delay = max
		}
		return delay, true
	}
	return 0, false
}

// retryAfterDelay returns the parsed Retry-After delay, or zero. | retryAfterDelay 返回解析后的 Retry-After 延迟，非法时为零。
func retryAfterDelay(header http.Header, max time.Duration) time.Duration {
	delay, _ := retryAfterValue(header, max)
	return delay
}

// sleepContext sleeps for d unless ctx ends first. | sleepContext 休眠 d，ctx 先结束则返回其错误。
func sleepContext(ctx context.Context, d time.Duration) error {
	if d <= 0 {
		return nil
	}
	timer := time.NewTimer(d)
	defer timer.Stop()
	select {
	case <-ctx.Done():
		return ctx.Err()
	case <-timer.C:
		return nil
	}
}

// retryBudget is a monotonic token bucket shared by one engine. | retryBudget 是一个引擎共享的单调令牌桶。
type retryBudget struct {
	last     time.Time
	tokens   float64
	capacity float64
	rate     float64
	mu       sync.Mutex
}

// attemptWithTimeout bounds one attempt including its response body. | attemptWithTimeout 限制单次尝试（含响应正文）。
func attemptWithTimeout(req *http.Request, timeout time.Duration) (*http.Request, context.CancelFunc) {
	if timeout <= 0 {
		return req, nil
	}
	ctx, cancel := context.WithTimeout(req.Context(), timeout)
	return req.WithContext(ctx), cancel
}

// finishAttempt cancels the attempt or ties cancellation to the body. | finishAttempt 取消尝试或把取消绑定到响应正文。
func finishAttempt(resp *http.Response, cancel context.CancelFunc, err error) {
	if cancel == nil {
		return
	}
	if err != nil || resp == nil || resp.Body == nil {
		closeResponseBody(resp)
		cancel()
		return
	}
	resp.Body = &cancelBody{body: resp.Body, cancel: cancel}
}

// budgetFor returns the token bucket for a retry ratio. | budgetFor 返回指定重试比例对应的令牌桶。
func (e *engine) budgetFor(ratio float64) *retryBudget {
	if ratio <= 0 {
		ratio = 0.1
	}
	if ratio == 0.1 {
		return e.budget
	}
	e.budgetMu.Lock()
	defer e.budgetMu.Unlock()
	if budget := e.budgets[ratio]; budget != nil {
		return budget
	}
	budget := newRetryBudget(ratio)
	e.budgets[ratio] = budget
	return budget
}

// newRetryBudget builds a budget from the configured retry ratio. | newRetryBudget 按配置的重试比例构建预算。
func newRetryBudget(ratio float64) *retryBudget {
	if ratio <= 0 {
		ratio = 0.1
	}
	rate := ratio * 10
	if rate < 1 {
		rate = 1
	}
	capacity := 50.0
	return &retryBudget{tokens: capacity, capacity: capacity, rate: rate, last: time.Now()}
}

// allow consumes one retry token when available. | allow 在令牌可用时消耗一个重试令牌。
func (b *retryBudget) allow() bool {
	if b == nil {
		return true
	}
	b.mu.Lock()
	defer b.mu.Unlock()
	now := time.Now()
	elapsed := now.Sub(b.last).Seconds()
	if elapsed > 0 {
		b.tokens += elapsed * b.rate
		if b.tokens > b.capacity {
			b.tokens = b.capacity
		}
		b.last = now
	}
	if b.tokens < 1 {
		return false
	}
	b.tokens--
	return true
}

// drainAndClose drains at most limit bytes and closes the body. | drainAndClose 最多排空 limit 字节并关闭正文。
func drainAndClose(body io.ReadCloser, limit int64) {
	if body == nil {
		return
	}
	_, _ = io.Copy(io.Discard, io.LimitReader(body, limit))
	_ = body.Close()
}
