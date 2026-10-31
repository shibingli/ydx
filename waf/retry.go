package waf

import (
	"context"
	"errors"
	"math/rand/v2"
	"time"
)

// Default retry parameters. | 默认重试参数。
const (
	defaultRetryAttempts   = 5
	defaultInitialBackoff  = 250 * time.Millisecond
	defaultRetryMaxBackoff = 30 * time.Second
	defaultRetryMultiplier = 2.0
	defaultRetryJitter     = 0.2
)

// RetryPolicy configures source fetch retries with exponential backoff and jitter.
// | RetryPolicy 配置带指数退避与抖动的来源拉取重试。
type RetryPolicy struct {
	MaxAttempts    int
	InitialBackoff time.Duration
	MaxBackoff     time.Duration
	Multiplier     float64
	Jitter         float64
}

// normalized fills defaults and clamps invalid values. | normalized 填充默认值并收敛非法值。
func (p RetryPolicy) normalized() RetryPolicy {
	n := p
	if n.MaxAttempts <= 0 {
		n.MaxAttempts = defaultRetryAttempts
	}
	if n.InitialBackoff <= 0 {
		n.InitialBackoff = defaultInitialBackoff
	}
	if n.MaxBackoff <= 0 {
		n.MaxBackoff = defaultRetryMaxBackoff
	}
	if n.MaxBackoff < n.InitialBackoff {
		n.MaxBackoff = n.InitialBackoff
	}
	if n.Multiplier < 1 {
		n.Multiplier = defaultRetryMultiplier
	}
	if n.Jitter < 0 || n.Jitter > 1 {
		n.Jitter = defaultRetryJitter
	}
	return n
}

// do runs fn until it succeeds, returns ErrNotModified, exhausts attempts or ctx expires.
// | do 运行 fn 直到成功、返回 ErrNotModified、用完尝试次数或上下文到期。
func (p RetryPolicy) do(ctx context.Context, fn func(context.Context) error) error {
	p = p.normalized()
	backoff := p.InitialBackoff
	var last error
	for attempt := 1; attempt <= p.MaxAttempts; attempt++ {
		err := fn(ctx)
		if err == nil {
			return nil
		}
		if errors.Is(err, ErrNotModified) {
			return err
		}
		last = err
		if attempt == p.MaxAttempts {
			break
		}
		delay := jitterDuration(backoff, p.Jitter)
		timer := time.NewTimer(delay)
		select {
		case <-ctx.Done():
			timer.Stop()
			return errors.Join(last, ctx.Err())
		case <-timer.C:
		}
		next := time.Duration(float64(backoff) * p.Multiplier)
		if next > p.MaxBackoff {
			next = p.MaxBackoff
		}
		backoff = next
	}
	return last
}

// jitterDuration applies symmetric jitter to a duration. | jitterDuration 对时长施加对称抖动。
func jitterDuration(base time.Duration, jitter float64) time.Duration {
	if jitter <= 0 {
		return base
	}
	factor := 1 + jitter*(2*rand.Float64()-1)
	if factor < 0 {
		factor = 0
	}
	return time.Duration(float64(base) * factor)
}
