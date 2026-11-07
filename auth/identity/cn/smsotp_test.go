package cn

import (
	"context"
	"errors"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

// smsCall records one provider invocation. | smsCall 记录一次服务方调用。
type smsCall struct {
	mobile     string
	templateID string
	params     map[string]string
}

// recordingProvider is a test SMSProvider. | recordingProvider 是测试用 SMSProvider。
type recordingProvider struct {
	mu    sync.Mutex
	calls []smsCall
	err   error
}

// Send records the call. | Send 记录调用。
func (p *recordingProvider) Send(ctx context.Context, mobile, templateID string, params map[string]string) (string, error) {
	p.mu.Lock()
	defer p.mu.Unlock()
	copied := make(map[string]string, len(params))
	for key, value := range params {
		copied[key] = value
	}
	p.calls = append(p.calls, smsCall{mobile: mobile, templateID: templateID, params: copied})
	if p.err != nil {
		return "", p.err
	}
	return "provider-request", nil
}

// last returns the most recent call. | last 返回最近一次调用。
func (p *recordingProvider) last() (smsCall, bool) {
	p.mu.Lock()
	defer p.mu.Unlock()
	if len(p.calls) == 0 {
		return smsCall{}, false
	}
	return p.calls[len(p.calls)-1], true
}

// count returns the number of calls. | count 返回调用次数。
func (p *recordingProvider) count() int {
	p.mu.Lock()
	defer p.mu.Unlock()
	return len(p.calls)
}

// fakeClock is a manually advanced clock. | fakeClock 是手动推进的时钟。
type fakeClock struct {
	mu  sync.Mutex
	now time.Time
}

// Now returns the current fake time. | Now 返回当前假时间。
func (c *fakeClock) Now() time.Time {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.now
}

// Advance moves the clock forward. | Advance 向前推进时钟。
func (c *fakeClock) Advance(d time.Duration) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.now = c.now.Add(d)
}

// testClock returns a fake clock at a fixed instant. | testClock 返回固定时刻的假时钟。
func testClock() *fakeClock {
	return &fakeClock{now: time.Date(2026, time.January, 1, 0, 0, 0, 0, time.UTC)}
}

// newTestOTP builds an SMSOTP with test-friendly defaults. | newTestOTP 构建使用测试友好默认值的 SMSOTP。
func newTestOTP(provider SMSProvider, clock *fakeClock, mutate func(*SMSOTPConfig)) *SMSOTP {
	cfg := SMSOTPConfig{
		Provider:       provider,
		TemplateID:     "template-1",
		Now:            clock.Now,
		ResendInterval: time.Minute,
	}
	if mutate != nil {
		mutate(&cfg)
	}
	return NewSMSOTP(cfg)
}

func TestSMSOTPBasicFlow(t *testing.T) {
	t.Parallel()
	clock := testClock()
	provider := &recordingProvider{}
	otp := newTestOTP(provider, clock, nil)

	challengeID, err := otp.Send(context.Background(), "138 0013 8000")
	if err != nil {
		t.Fatalf("Send returned error: %v", err)
	}
	if challengeID == "" {
		t.Fatal("Send returned an empty challenge ID")
	}
	call, ok := provider.last()
	if !ok {
		t.Fatal("provider was not called")
	}
	if call.mobile != "+8613800138000" {
		t.Fatalf("provider mobile = %q, want E.164", call.mobile)
	}
	if call.templateID != "template-1" {
		t.Fatalf("provider template = %q", call.templateID)
	}
	code := call.params["code"]
	if len(code) != DefaultSMSOTPCodeLength || !validOTPCode(code, DefaultSMSOTPCodeLength) {
		t.Fatalf("provider code = %q, want %d digits", code, DefaultSMSOTPCodeLength)
	}

	if err := otp.Verify(context.Background(), challengeID, "000000"); !errors.Is(err, ErrOTPInvalid) {
		t.Fatalf("wrong code error = %v, want ErrOTPInvalid", err)
	}
	if err := otp.Verify(context.Background(), challengeID, code); err != nil {
		t.Fatalf("Verify returned error: %v", err)
	}
	if err := otp.Verify(context.Background(), challengeID, code); !errors.Is(err, ErrOTPUsed) {
		t.Fatalf("second Verify error = %v, want ErrOTPUsed", err)
	}
	stored := otp.challenges[challengeID]
	if stored == nil {
		t.Fatal("challenge disappeared before its TTL")
	}
	if string(stored.codeHash[:]) == code {
		t.Fatal("the raw code is stored instead of its hash")
	}
}

func TestSMSOTPExpiry(t *testing.T) {
	t.Parallel()
	clock := testClock()
	provider := &recordingProvider{}
	otp := newTestOTP(provider, clock, func(cfg *SMSOTPConfig) {
		cfg.TTL = time.Minute
	})
	challengeID, err := otp.Send(context.Background(), "13800138000")
	if err != nil {
		t.Fatalf("Send returned error: %v", err)
	}
	call, _ := provider.last()
	clock.Advance(2 * time.Minute)
	if err := otp.Verify(context.Background(), challengeID, call.params["code"]); !errors.Is(err, ErrOTPExpired) {
		t.Fatalf("expired Verify error = %v, want ErrOTPExpired", err)
	}
	if err := otp.Verify(context.Background(), challengeID, call.params["code"]); !errors.Is(err, ErrOTPNotFound) {
		t.Fatalf("second expired Verify error = %v, want ErrOTPNotFound", err)
	}
}

func TestSMSOTPAttempts(t *testing.T) {
	t.Parallel()
	clock := testClock()
	provider := &recordingProvider{}
	otp := newTestOTP(provider, clock, func(cfg *SMSOTPConfig) {
		cfg.MaxAttempts = 3
		cfg.ResendInterval = -1
	})
	challengeID, err := otp.Send(context.Background(), "13800138000")
	if err != nil {
		t.Fatalf("Send returned error: %v", err)
	}
	call, _ := provider.last()
	for i := 0; i < 2; i++ {
		if err := otp.Verify(context.Background(), challengeID, "999999"); !errors.Is(err, ErrOTPInvalid) {
			t.Fatalf("attempt %d error = %v, want ErrOTPInvalid", i+1, err)
		}
	}
	if err := otp.Verify(context.Background(), challengeID, "999999"); !errors.Is(err, ErrOTPAttemptsExceeded) {
		t.Fatalf("third attempt error = %v, want ErrOTPAttemptsExceeded", err)
	}
	if err := otp.Verify(context.Background(), challengeID, call.params["code"]); !errors.Is(err, ErrOTPAttemptsExceeded) {
		t.Fatalf("locked Verify error = %v, want ErrOTPAttemptsExceeded", err)
	}
}

func TestSMSOTPResendInterval(t *testing.T) {
	t.Parallel()
	clock := testClock()
	provider := &recordingProvider{}
	otp := newTestOTP(provider, clock, nil)

	first, err := otp.Send(context.Background(), "13800138000")
	if err != nil {
		t.Fatalf("first Send returned error: %v", err)
	}
	firstCall, _ := provider.last()
	if _, err := otp.Send(context.Background(), "13800138000"); !errors.Is(err, ErrOTPResendTooSoon) {
		t.Fatalf("immediate resend error = %v, want ErrOTPResendTooSoon", err)
	}
	clock.Advance(61 * time.Second)
	second, err := otp.Send(context.Background(), "13800138000")
	if err != nil {
		t.Fatalf("second Send returned error: %v", err)
	}
	if second == first {
		t.Fatal("resend reused the previous challenge ID")
	}
	if err := otp.Verify(context.Background(), first, firstCall.params["code"]); !errors.Is(err, ErrOTPNotFound) {
		t.Fatalf("old challenge error = %v, want ErrOTPNotFound", err)
	}
}

func TestSMSOTPResendDisabled(t *testing.T) {
	t.Parallel()
	clock := testClock()
	provider := &recordingProvider{}
	otp := newTestOTP(provider, clock, func(cfg *SMSOTPConfig) {
		cfg.ResendInterval = -1
	})
	if _, err := otp.Send(context.Background(), "13800138000"); err != nil {
		t.Fatalf("first Send returned error: %v", err)
	}
	if _, err := otp.Send(context.Background(), "13800138000"); err != nil {
		t.Fatalf("second Send with disabled interval returned error: %v", err)
	}
}

func TestSMSOTPRateLimiter(t *testing.T) {
	t.Parallel()
	clock := testClock()
	provider := &recordingProvider{}
	boom := errors.New("rate limited")
	limiter := &denyLimiter{err: boom}
	otp := newTestOTP(provider, clock, func(cfg *SMSOTPConfig) {
		cfg.RateLimiter = limiter
	})
	if _, err := otp.Send(context.Background(), "13800138000"); !errors.Is(err, boom) {
		t.Fatalf("Send error = %v, want the limiter error", err)
	}
	if provider.count() != 0 {
		t.Fatal("provider was called despite the limiter denial")
	}

	allow := &allowLimiter{}
	otp = newTestOTP(provider, clock, func(cfg *SMSOTPConfig) {
		cfg.RateLimiter = allow
	})
	if _, err := otp.Send(context.Background(), "13800138000"); err != nil {
		t.Fatalf("Send returned error: %v", err)
	}
	if allow.mobile != "+8613800138000" {
		t.Fatalf("limiter mobile = %q, want E.164", allow.mobile)
	}
}

// denyLimiter always denies. | denyLimiter 总是拒绝。
type denyLimiter struct{ err error }

// Allow denies. | Allow 拒绝。
func (l *denyLimiter) Allow(ctx context.Context, mobile string) error { return l.err }

// allowLimiter records the last mobile. | allowLimiter 记录最近一次手机号。
type allowLimiter struct{ mobile string }

// Allow allows. | Allow 允许。
func (l *allowLimiter) Allow(ctx context.Context, mobile string) error {
	l.mobile = mobile
	return nil
}

func TestSMSOTPProviderFailure(t *testing.T) {
	t.Parallel()
	clock := testClock()
	boom := errors.New("provider down")
	provider := &recordingProvider{err: boom}
	otp := newTestOTP(provider, clock, nil)
	if _, err := otp.Send(context.Background(), "13800138000"); !errors.Is(err, ErrSMSSend) || !errors.Is(err, boom) {
		t.Fatalf("Send error = %v, want ErrSMSSend and provider error", err)
	}
	if len(otp.challenges) != 0 {
		t.Fatal("a challenge was stored after a provider failure")
	}
	if _, err := otp.Send(context.Background(), "13800138000"); !errors.Is(err, ErrOTPResendTooSoon) {
		t.Fatalf("retry error = %v, want ErrOTPResendTooSoon", err)
	}
}

func TestSMSOTPInputValidation(t *testing.T) {
	t.Parallel()
	clock := testClock()
	provider := &recordingProvider{}
	otp := newTestOTP(provider, clock, nil)
	if _, err := otp.Send(context.Background(), "12345"); !errors.Is(err, ErrInvalidMobile) {
		t.Fatalf("invalid mobile error = %v, want ErrInvalidMobile", err)
	}

	missing := NewSMSOTP(SMSOTPConfig{})
	if _, err := missing.Send(context.Background(), "13800138000"); !errors.Is(err, ErrInvalidConfig) {
		t.Fatalf("nil provider error = %v, want ErrInvalidConfig", err)
	}
	var zero SMSOTP
	if _, err := zero.Send(context.Background(), "13800138000"); !errors.Is(err, ErrInvalidConfig) {
		t.Fatalf("zero SMSOTP error = %v, want ErrInvalidConfig", err)
	}
	if err := zero.Verify(context.Background(), "missing", "123456"); !errors.Is(err, ErrInvalidConfig) {
		t.Fatalf("zero SMSOTP Verify error = %v, want ErrInvalidConfig", err)
	}

	badLength := NewSMSOTP(SMSOTPConfig{Provider: provider, CodeLength: 3})
	if _, err := badLength.Send(context.Background(), "13800138000"); !errors.Is(err, ErrInvalidConfig) {
		t.Fatalf("bad code length error = %v, want ErrInvalidConfig", err)
	}
}

func TestSMSOTPCodeGenerator(t *testing.T) {
	t.Parallel()
	clock := testClock()
	provider := &recordingProvider{}
	otp := newTestOTP(provider, clock, func(cfg *SMSOTPConfig) {
		cfg.CodeGenerator = func() (string, error) { return "000123", nil }
	})
	challengeID, err := otp.Send(context.Background(), "13800138000")
	if err != nil {
		t.Fatalf("Send returned error: %v", err)
	}
	call, _ := provider.last()
	if call.params["code"] != "000123" {
		t.Fatalf("code = %q, want 000123", call.params["code"])
	}
	if err := otp.Verify(context.Background(), challengeID, "000123"); err != nil {
		t.Fatalf("Verify returned error: %v", err)
	}

	invalid := newTestOTP(provider, clock, func(cfg *SMSOTPConfig) {
		cfg.CodeGenerator = func() (string, error) { return "12", nil }
	})
	if _, err := invalid.Send(context.Background(), "13800138000"); !errors.Is(err, ErrOTPGenerate) {
		t.Fatalf("invalid generator error = %v, want ErrOTPGenerate", err)
	}
	failing := newTestOTP(provider, clock, func(cfg *SMSOTPConfig) {
		cfg.CodeGenerator = func() (string, error) { return "", errors.New("rand failure") }
	})
	if _, err := failing.Send(context.Background(), "13800138000"); !errors.Is(err, ErrOTPGenerate) {
		t.Fatalf("failing generator error = %v, want ErrOTPGenerate", err)
	}
}

func TestSMSOTPUnknownChallenge(t *testing.T) {
	t.Parallel()
	clock := testClock()
	otp := newTestOTP(&recordingProvider{}, clock, nil)
	if err := otp.Verify(context.Background(), "missing", "123456"); !errors.Is(err, ErrOTPNotFound) {
		t.Fatalf("unknown challenge error = %v, want ErrOTPNotFound", err)
	}
}

func TestSMSOTPDefaultsAndParamsCopy(t *testing.T) {
	t.Parallel()
	clock := testClock()
	provider := &recordingProvider{}
	params := map[string]string{"app": "ydx"}
	otp := newTestOTP(provider, clock, func(cfg *SMSOTPConfig) {
		cfg.Params = params
	})
	if otp.cfg.CodeLength != DefaultSMSOTPCodeLength ||
		otp.cfg.TTL != DefaultSMSOTPTTL ||
		otp.cfg.MaxAttempts != DefaultSMSOTPMaxAttempts ||
		otp.cfg.ResendInterval != DefaultSMSOTPResendInterval {
		t.Fatalf("defaults = %+v", otp.cfg)
	}
	params["app"] = "mutated"
	if _, err := otp.Send(context.Background(), "13800138000"); err != nil {
		t.Fatalf("Send returned error: %v", err)
	}
	call, _ := provider.last()
	if call.params["app"] != "ydx" {
		t.Fatalf("params were not copied: %v", call.params)
	}
}

func TestSMSOTPConcurrentSends(t *testing.T) {
	t.Parallel()
	clock := testClock()
	provider := &recordingProvider{}
	otp := newTestOTP(provider, clock, func(cfg *SMSOTPConfig) {
		cfg.ResendInterval = time.Hour
	})
	const goroutines = 32
	var successes atomic.Int32
	var tooSoon atomic.Int32
	var other atomic.Int32
	var wg sync.WaitGroup
	start := make(chan struct{})
	for i := 0; i < goroutines; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			<-start
			_, err := otp.Send(context.Background(), "13800138000")
			switch {
			case err == nil:
				successes.Add(1)
			case errors.Is(err, ErrOTPResendTooSoon):
				tooSoon.Add(1)
			default:
				other.Add(1)
			}
		}()
	}
	close(start)
	wg.Wait()
	if successes.Load() != 1 {
		t.Fatalf("successful sends = %d, want 1", successes.Load())
	}
	if tooSoon.Load() != goroutines-1 || other.Load() != 0 {
		t.Fatalf("tooSoon = %d, other = %d", tooSoon.Load(), other.Load())
	}
	if provider.count() != 1 {
		t.Fatalf("provider calls = %d, want 1", provider.count())
	}
}

func TestSMSOTPConcurrentVerifies(t *testing.T) {
	t.Parallel()
	clock := testClock()
	provider := &recordingProvider{}
	otp := newTestOTP(provider, clock, func(cfg *SMSOTPConfig) {
		cfg.MaxAttempts = 100
	})
	challengeID, err := otp.Send(context.Background(), "13800138000")
	if err != nil {
		t.Fatalf("Send returned error: %v", err)
	}
	const goroutines = 100
	var invalid atomic.Int32
	var locked atomic.Int32
	var other atomic.Int32
	var wg sync.WaitGroup
	start := make(chan struct{})
	for i := 0; i < goroutines; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			<-start
			err := otp.Verify(context.Background(), challengeID, "999999")
			switch {
			case errors.Is(err, ErrOTPInvalid):
				invalid.Add(1)
			case errors.Is(err, ErrOTPAttemptsExceeded):
				locked.Add(1)
			default:
				other.Add(1)
			}
		}()
	}
	close(start)
	wg.Wait()
	if other.Load() != 0 {
		t.Fatalf("unexpected verify outcomes = %d", other.Load())
	}
	if invalid.Load()+locked.Load() != goroutines {
		t.Fatalf("invalid = %d, locked = %d, want %d total", invalid.Load(), locked.Load(), goroutines)
	}
	if locked.Load() != 1 {
		t.Fatalf("locked = %d, want exactly 1", locked.Load())
	}
}
