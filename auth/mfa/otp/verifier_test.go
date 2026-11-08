package otp

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/shibingli/ydx/auth"
)

// totpCredential returns a TOTP credential for tests. | totpCredential 返回测试用 TOTP 凭据。
func totpCredential(secret string) *auth.Credential {
	return &auth.Credential{
		ID:     "credential-1",
		UserID: "user-1",
		Type:   auth.CredentialTOTP,
		Name:   "primary",
		Secret: secret,
	}
}

// differentCode returns a six-digit code guaranteed to differ from code. | differentCode 返回与 code 不同且保证不同的六位口令。
func differentCode(code string) string {
	digits := []byte(code)
	if digits[0] == '0' {
		digits[0] = '1'
	} else {
		digits[0] = '0'
	}
	return string(digits)
}

// TestVerifierTOTP checks a successful and unsuccessful TOTP verification. | TestVerifierTOTP 检查 TOTP 校验成功与失败。
func TestVerifierTOTP(t *testing.T) {
	t.Parallel()
	at := time.Unix(1234567890, 0).UTC()
	secret := testSecret("12345678901234567890")
	code, err := TOTP(secret, at, Config{})
	if err != nil {
		t.Fatalf("TOTP: %v", err)
	}
	user := &auth.User{ID: "user-1"}
	credential := totpCredential(secret)
	verifier := NewVerifier(WithVerifierClock(fixedClock(at)))

	ok, err := verifier.Verify(context.Background(), user, credential, code)
	if err != nil || !ok {
		t.Fatalf("Verify = (%v, %v), want (true, nil) | 校验应成功", ok, err)
	}
	ok, err = verifier.Verify(context.Background(), user, credential, differentCode(code))
	if err != nil || ok {
		t.Fatalf("Verify(wrong code) = (%v, %v), want (false, nil) | 错误口令应失败", ok, err)
	}
	ok, err = verifier.Verify(context.Background(), user, credential, "  "+code+"  ")
	if err != nil || !ok {
		t.Fatalf("Verify(padded code) = (%v, %v), want (true, nil) | 带空白口令应成功", ok, err)
	}
	ok, err = verifier.Verify(context.Background(), user, credential, "")
	if err != nil || ok {
		t.Fatalf("Verify(empty) = (%v, %v), want (false, nil) | 空口令应失败", ok, err)
	}
}

// TestVerifierRejections checks disabled, unsupported, missing and nil inputs. | TestVerifierRejections 检查禁用、不支持、缺失与 nil 输入。
func TestVerifierRejections(t *testing.T) {
	t.Parallel()
	secret := testSecret("12345678901234567890")
	at := time.Unix(1234567890, 0).UTC()
	verifier := NewVerifier(WithVerifierClock(fixedClock(at)))
	ctx := context.Background()

	disabled := totpCredential(secret)
	disabled.Disabled = true
	if ok, err := verifier.Verify(ctx, nil, disabled, "123456"); ok || !errors.Is(err, auth.ErrMFAInvalid) {
		t.Errorf("disabled Verify = (%v, %v), want (false, ErrMFAInvalid) | 禁用凭据未被拒绝", ok, err)
	}

	unsupported := totpCredential(secret)
	unsupported.Type = auth.CredentialPassword
	if ok, err := verifier.Verify(ctx, nil, unsupported, "123456"); ok || !errors.Is(err, auth.ErrMFAInvalid) {
		t.Errorf("unsupported Verify = (%v, %v), want (false, ErrMFAInvalid) | 不支持类型未被拒绝", ok, err)
	}

	if ok, err := verifier.Verify(ctx, nil, nil, "123456"); ok || !errors.Is(err, auth.ErrCredentialNotFound) {
		t.Errorf("nil credential Verify = (%v, %v), want ErrCredentialNotFound | nil 凭据未被拒绝", ok, err)
	}

	missing := totpCredential("")
	if ok, err := verifier.Verify(ctx, nil, missing, "123456"); ok || !errors.Is(err, auth.ErrMFAInvalid) {
		t.Errorf("missing secret Verify = (%v, %v), want ErrMFAInvalid | 缺失密钥未被拒绝", ok, err)
	}

	malformed := totpCredential("!!!!")
	if ok, err := verifier.Verify(ctx, nil, malformed, "123456"); ok || !errors.Is(err, auth.ErrMFAInvalid) || !errors.Is(err, ErrInvalidSecret) {
		t.Errorf("malformed secret Verify = (%v, %v), want ErrMFAInvalid/ErrInvalidSecret | 非法密钥未被拒绝", ok, err)
	}

	var nilVerifier *Verifier
	if ok, err := nilVerifier.Verify(ctx, nil, totpCredential(secret), "123456"); ok || !errors.Is(err, auth.ErrMFAInvalid) {
		t.Errorf("nil verifier Verify = (%v, %v), want ErrMFAInvalid | nil 校验器未被拒绝", ok, err)
	}
}

// TestVerifierUserBinding checks that a credential belonging to another user is rejected even when
// the code is valid. | TestVerifierUserBinding 检查即使口令有效，属于其他用户的凭据也会被拒绝。
func TestVerifierUserBinding(t *testing.T) {
	t.Parallel()
	secret := testSecret("12345678901234567890")
	at := time.Unix(1234567890, 0).UTC()
	code, err := TOTP(secret, at, Config{})
	if err != nil {
		t.Fatalf("TOTP: %v", err)
	}
	verifier := NewVerifier(WithVerifierClock(fixedClock(at)))
	ctx := context.Background()

	foreign := &auth.User{ID: "user-2"}
	ok, err := verifier.Verify(ctx, foreign, totpCredential(secret), code)
	if ok || !errors.Is(err, auth.ErrMFAInvalid) {
		t.Fatalf("Verify(foreign user) = (%v, %v), want (false, ErrMFAInvalid) | 其他用户凭据未被拒绝", ok, err)
	}

	for _, user := range []*auth.User{nil, {}, {ID: "user-1"}} {
		ok, err := verifier.Verify(ctx, user, totpCredential(secret), code)
		if err != nil || !ok {
			t.Errorf("Verify(user %+v) = (%v, %v), want (true, nil) | 空或匹配用户凭据应通过", user, ok, err)
		}
	}

	unbound := totpCredential(secret)
	unbound.UserID = ""
	if ok, err := verifier.Verify(ctx, foreign, unbound, code); err != nil || !ok {
		t.Errorf("Verify(unbound credential) = (%v, %v), want (true, nil) | 未绑定用户的凭据应通过", ok, err)
	}
}

// TestVerifierDataConfig checks per-credential settings and the skew window. | TestVerifierDataConfig 检查每凭据设置与容差窗口。
func TestVerifierDataConfig(t *testing.T) {
	t.Parallel()
	secret := testSecret("12345678901234567890")
	at := time.Unix(2000000000, 0).UTC()
	dataConfig := Config{Digits: 8, Algorithm: SHA256, Period: time.Minute, Skew: 1}
	code, err := TOTP(secret, at, dataConfig)
	if err != nil {
		t.Fatalf("TOTP: %v", err)
	}
	credential := totpCredential(secret)
	credential.Data = map[string]string{
		"digits":    "8",
		"algorithm": "SHA256",
		"period":    "60",
		"skew":      "1",
	}
	verifier := NewVerifier(WithVerifierClock(fixedClock(at)))
	if ok, err := verifier.Verify(context.Background(), nil, credential, code); err != nil || !ok {
		t.Fatalf("Verify = (%v, %v), want (true, nil) | Data 配置校验失败", ok, err)
	}
	// The ±1 skew accepts the code one step later.
	later := NewVerifier(WithVerifierClock(fixedClock(at.Add(time.Minute))))
	if ok, err := later.Verify(context.Background(), nil, credential, code); err != nil || !ok {
		t.Fatalf("Verify(skewed) = (%v, %v), want (true, nil) | 容差窗口校验失败", ok, err)
	}
	// A duration value is accepted for period.
	credential.Data["period"] = "1m"
	if ok, err := verifier.Verify(context.Background(), nil, credential, code); err != nil || !ok {
		t.Fatalf("Verify(duration period) = (%v, %v), want (true, nil) | 时长格式 period 校验失败", ok, err)
	}
	// Data keys are matched case-insensitively.
	credential.Data = map[string]string{"DIGITS": "8", "ALGORITHM": "sha256", "PERIOD": "60s", "SKEW": "1"}
	if ok, err := verifier.Verify(context.Background(), nil, credential, code); err != nil || !ok {
		t.Fatalf("Verify(case-insensitive data) = (%v, %v), want (true, nil) | 大小写不敏感 Data 校验失败", ok, err)
	}
}

// TestVerifierBaseConfig checks that the verifier base configuration is used. | TestVerifierBaseConfig 检查使用校验器基础配置。
func TestVerifierBaseConfig(t *testing.T) {
	t.Parallel()
	secret := testSecret("12345678901234567890")
	at := time.Unix(2000000000, 0).UTC()
	code, err := TOTP(secret, at, Config{Digits: 8, Algorithm: SHA512})
	if err != nil {
		t.Fatalf("TOTP: %v", err)
	}
	verifier := NewVerifier(
		WithVerifierConfig(Config{Digits: 8, Algorithm: SHA512}),
		WithVerifierClock(fixedClock(at)),
	)
	if ok, err := verifier.Verify(context.Background(), nil, totpCredential(secret), code); err != nil || !ok {
		t.Fatalf("Verify = (%v, %v), want (true, nil) | 基础配置校验失败", ok, err)
	}
	// credential.Data overrides the base configuration.
	credential := totpCredential(secret)
	credential.Data = map[string]string{"digits": "6", "algorithm": "SHA1"}
	if ok, err := verifier.Verify(context.Background(), nil, credential, code); err != nil || ok {
		t.Fatalf("Verify(overridden) = (%v, %v), want (false, nil) | Data 覆盖未生效", ok, err)
	}
}

// TestVerifierInvalidData checks malformed per-credential settings. | TestVerifierInvalidData 检查非法每凭据设置。
func TestVerifierInvalidData(t *testing.T) {
	t.Parallel()
	secret := testSecret("12345678901234567890")
	at := time.Unix(1234567890, 0).UTC()
	verifier := NewVerifier(WithVerifierClock(fixedClock(at)))
	tests := []struct {
		name string
		data map[string]string
	}{
		{"digits not a number", map[string]string{"digits": "abc"}},
		{"digits out of range", map[string]string{"digits": "5"}},
		{"period not a duration", map[string]string{"period": "abc"}},
		{"period sub-second", map[string]string{"period": "500ms"}},
		{"negative skew", map[string]string{"skew": "-1"}},
		{"skew not a number", map[string]string{"skew": "abc"}},
		{"unsupported algorithm", map[string]string{"algorithm": "MD5"}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			credential := totpCredential(secret)
			credential.Data = tt.data
			ok, err := verifier.Verify(context.Background(), nil, credential, "123456")
			if ok || !errors.Is(err, ErrInvalidConfig) {
				t.Errorf("Verify = (%v, %v), want (false, ErrInvalidConfig) | 非法 Data 未报错", ok, err)
			}
			if !errors.Is(err, auth.ErrMFAInvalid) {
				t.Errorf("error %v does not match auth.ErrMFAInvalid | 错误未匹配 auth.ErrMFAInvalid", err)
			}
		})
	}
}

// TestVerifierHOTP checks counter validation, advancement and resynchronization. | TestVerifierHOTP 检查计数器校验、推进与重同步。
func TestVerifierHOTP(t *testing.T) {
	t.Parallel()
	secret := testSecret("12345678901234567890")
	code, err := HOTP(secret, 0, Config{})
	if err != nil {
		t.Fatalf("HOTP: %v", err)
	}
	credential := &auth.Credential{
		ID:     "hotp-1",
		UserID: "user-1",
		Type:   auth.CredentialHOTP,
		Secret: secret,
		Data:   map[string]string{"counter": "0"},
	}
	verifier := NewVerifier()
	ctx := context.Background()
	if ok, err := verifier.Verify(ctx, nil, credential, code); err != nil || !ok {
		t.Fatalf("Verify = (%v, %v), want (true, nil) | HOTP 校验失败", ok, err)
	}
	if credential.Data["counter"] != "1" {
		t.Errorf("counter = %q, want 1 | 计数器未推进", credential.Data["counter"])
	}
	if ok, err := verifier.Verify(ctx, nil, credential, code); err != nil || ok {
		t.Fatalf("replayed Verify = (%v, %v), want (false, nil) | 已用计数器未被拒绝", ok, err)
	}

	// A stale counter is resynchronized inside the configured window.
	credential.Data = map[string]string{"counter": "2", "skew": "1"}
	target, err := HOTP(secret, 3, Config{})
	if err != nil {
		t.Fatalf("HOTP: %v", err)
	}
	if ok, err := verifier.Verify(ctx, nil, credential, target); err != nil || !ok {
		t.Fatalf("resync Verify = (%v, %v), want (true, nil) | 计数器重同步失败", ok, err)
	}
	if credential.Data["counter"] != "4" {
		t.Errorf("counter = %q, want 4 | 重同步后计数器未推进", credential.Data["counter"])
	}

	credential.Data = map[string]string{"counter": "abc"}
	if ok, err := verifier.Verify(ctx, nil, credential, code); ok || !errors.Is(err, ErrInvalidConfig) {
		t.Errorf("invalid counter Verify = (%v, %v), want ErrInvalidConfig | 非法计数器未报错", ok, err)
	}
}

// TestVerifierHOTPRejectsCounterRollback checks that a code matching a counter below the stored
// counter is rejected instead of rewinding the persisted counter. | TestVerifierHOTPRejectsCounterRollback
// 检查匹配已存计数器之前计数器的口令会被拒绝，而不是回退已持久化计数器。
func TestVerifierHOTPRejectsCounterRollback(t *testing.T) {
	t.Parallel()
	secret := testSecret("12345678901234567890")
	stale, err := HOTP(secret, 3, Config{})
	if err != nil {
		t.Fatalf("HOTP: %v", err)
	}
	credential := &auth.Credential{
		ID:     "hotp-rollback",
		UserID: "user-1",
		Type:   auth.CredentialHOTP,
		Secret: secret,
		Data:   map[string]string{"counter": "5", "skew": "2"},
	}
	verifier := NewVerifier()
	if ok, err := verifier.Verify(context.Background(), nil, credential, stale); err != nil || ok {
		t.Fatalf("Verify(stale code) = (%v, %v), want (false, nil) | 已用计数器口令未被拒绝", ok, err)
	}
	if got := credential.Data["counter"]; got != "5" {
		t.Errorf("counter = %q, want 5 | 计数器发生回退", got)
	}

	forward, err := HOTP(secret, 6, Config{})
	if err != nil {
		t.Fatalf("HOTP: %v", err)
	}
	if ok, err := verifier.Verify(context.Background(), nil, credential, forward); err != nil || !ok {
		t.Fatalf("Verify(forward code) = (%v, %v), want (true, nil) | 前向重同步应成功", ok, err)
	}
	if got := credential.Data["counter"]; got != "7" {
		t.Errorf("counter = %q, want 7 | 前向校验后计数器未推进", got)
	}
}

// TestVerifierReplayGuard checks TOTP replay protection and per-credential keys. | TestVerifierReplayGuard 检查 TOTP 重放保护与每凭据键。
func TestVerifierReplayGuard(t *testing.T) {
	t.Parallel()
	secret := testSecret("12345678901234567890")
	at := time.Unix(1234567890, 0).UTC()
	code, err := TOTP(secret, at, Config{})
	if err != nil {
		t.Fatalf("TOTP: %v", err)
	}
	verifier := NewVerifier(
		WithVerifierClock(fixedClock(at)),
		WithVerifierGuard(NewMemoryReplayGuard()),
	)
	ctx := context.Background()
	if ok, err := verifier.Verify(ctx, nil, totpCredential(secret), code); err != nil || !ok {
		t.Fatalf("first Verify = (%v, %v), want (true, nil) | 首次校验失败", ok, err)
	}
	if ok, err := verifier.Verify(ctx, nil, totpCredential(secret), code); ok || !errors.Is(err, ErrReplay) {
		t.Fatalf("replayed Verify = (%v, %v), want (false, ErrReplay) | 重放未被拒绝", ok, err)
	}
	second := totpCredential(secret)
	second.ID = "credential-2"
	if ok, err := verifier.Verify(ctx, nil, second, code); err != nil || !ok {
		t.Fatalf("second credential Verify = (%v, %v), want (true, nil) | 不同凭据被误判重放", ok, err)
	}
	// A credential without IDs falls back to the secret fingerprint.
	anonymous := &auth.Credential{Type: auth.CredentialTOTP, Secret: secret}
	fresh := NewVerifier(WithVerifierClock(fixedClock(at)), WithVerifierGuard(NewMemoryReplayGuard()))
	if ok, err := fresh.Verify(ctx, nil, anonymous, code); err != nil || !ok {
		t.Fatalf("anonymous Verify = (%v, %v), want (true, nil) | 无 ID 凭据首次校验失败", ok, err)
	}
	if ok, err := fresh.Verify(ctx, nil, anonymous, code); ok || !errors.Is(err, ErrReplay) {
		t.Errorf("anonymous replay = (%v, %v), want ErrReplay | 无 ID 凭据重放未被拒绝", ok, err)
	}
}
