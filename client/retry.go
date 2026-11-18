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
	"sync"
	"time"

	"github.com/shibingli/ydx/errs"
)

// RetryPolicy controls attempt count, retry triggers and backoff. | RetryPolicy 控制尝试次数、重试触发条件与退避。
type RetryPolicy struct {
	// MaxAttempts is the total attempt count; <=0 derives it from the host count. | MaxAttempts 是总尝试次数；<=0 时按 Host 数推导。
	MaxAttempts int
	// Methods lists retryable methods; nil means idempotent methods (or all when NonIdempotent). | Methods 列出可重试方法；nil 表示幂等方法（NonIdempotent 时表示全部）。
	Methods []string
	// StatusCodes lists retryable statuses; nil means 429/502/503/504. | StatusCodes 列出可重试状态码；nil 表示 429/502/503/504。
	StatusCodes []int
	// DisableNetworkRetry disables retries for transport errors. | DisableNetworkRetry 禁用传输错误重试。
	DisableNetworkRetry bool
	// NonIdempotent permits retrying POST/PATCH when their body is replayable. | NonIdempotent 允许在正文可重放时重试 POST/PATCH。
	NonIdempotent bool
	// Backoff overrides the default exponential backoff. | Backoff 覆盖默认指数退避。
	Backoff func(attempt int) time.Duration
	// MaxBackoff caps one backoff or Retry-After delay; <=0 means 1s. | MaxBackoff 限制单次退避或 Retry-After；<=0 表示 1s。
	MaxBackoff time.Duration
	// DisableRetryAfter ignores the Retry-After response header. | DisableRetryAfter 忽略 Retry-After 响应头。
	DisableRetryAfter bool
	// Budget is the retry token ratio; <=0 means 0.1. | Budget 是重试令牌比例；<=0 表示 0.1。
	Budget float64
	// PerAttemptTimeout bounds one attempt including its response body. | PerAttemptTimeout 限制单次尝试（含响应正文）。
	PerAttemptTimeout time.Duration
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
	return func(o *options) error {
		if policy.MaxAttempts < 0 {
			return errs.Detail(ErrInvalidConfig, "negative max attempts | 最大尝试次数为负")
		}
		o.Retry = &policy
		return nil
	}
}

// retryableMethod reports whether method may be retried under policy. | retryableMethod 报告 method 在 policy 下是否可重试。
func retryableMethod(policy RetryPolicy, method string) bool {
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
func backoffDelay(policy RetryPolicy, attempt int) time.Duration {
	if policy.Backoff != nil {
		delay := policy.Backoff(attempt)
		if delay < 0 {
			return 0
		}
		return delay
	}
	delay := 50 * time.Millisecond
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

// retryAfterDelay parses Retry-After seconds or HTTP-date and caps it at max. | retryAfterDelay 解析 Retry-After 的秒数或 HTTP 日期，并以 max 为上限。
func retryAfterDelay(header http.Header, max time.Duration) time.Duration {
	value := header.Get("Retry-After")
	if value == "" {
		return 0
	}
	if seconds, err := strconv.Atoi(value); err == nil && seconds >= 0 {
		delay := time.Duration(seconds) * time.Second
		if max > 0 && delay > max {
			delay = max
		}
		return delay
	}
	if when, err := http.ParseTime(value); err == nil {
		delay := time.Until(when)
		if delay < 0 {
			return 0
		}
		if max > 0 && delay > max {
			delay = max
		}
		return delay
	}
	return 0
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
	mu       sync.Mutex
	tokens   float64
	capacity float64
	rate     float64
	last     time.Time
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
