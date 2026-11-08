package otp

import (
	"context"
	"strconv"
	"strings"
	"time"

	"github.com/shibingli/ydx/auth"
	"github.com/shibingli/ydx/errs"
)

// Verifier adapts this package to auth.MFAVerifier for auth.CredentialTOTP and
// auth.CredentialHOTP. It reads the base32 secret from credential.Secret and optional factor
// settings from credential.Data: "digits", "period" (integer seconds or a Go duration),
// "algorithm" and "skew". HOTP additionally reads and advances "counter". | Verifier 把本包适配为
// auth.CredentialTOTP 与 auth.CredentialHOTP 的 auth.MFAVerifier。它从 credential.Secret 读取
// base32 密钥，从 credential.Data 读取可选因素设置："digits"、"period"（整数秒或 Go 时长）、
// "algorithm" 与 "skew"。HOTP 还会读取并推进 "counter"。
//
// Verify mutates credential.Data["counter"] after a successful HOTP check so the caller can
// persist the advanced counter through auth.Service.UpdateCredential; callers must not share one
// *auth.Credential value across concurrent verifications. The HOTP counter only moves forward: a
// code matching a counter below the stored counter is treated as a replay and rejected. A
// configured ReplayGuard records TOTP steps and HOTP counters keyed by credential ID. | HOTP 校验
// 成功后 Verify 会修改 credential.Data["counter"]，以便调用方通过 auth.Service.UpdateCredential
// 持久化推进后的计数器；调用方不得在并发校验之间共享同一个 *auth.Credential 值。HOTP 计数器只会
// 前进：匹配低于已存计数器计数器的口令会被视为重放并拒绝。配置的 ReplayGuard 以凭据 ID 为键记录
// TOTP 时间步与 HOTP 计数器。
type Verifier struct {
	guard ReplayGuard
	now   func() time.Time
	cfg   Config
}

// VerifierOption configures a Verifier. | VerifierOption 配置 Verifier。
type VerifierOption func(*Verifier)

// The compile-time proof that Verifier implements auth.MFAVerifier. | 编译期证明 Verifier 实现了
// auth.MFAVerifier。
var _ auth.MFAVerifier = (*Verifier)(nil)

// NewVerifier returns a Verifier. Without options it uses package defaults and no replay
// protection. | NewVerifier 返回 Verifier。无选项时使用包默认值且不启用重放保护。
func NewVerifier(opts ...VerifierOption) *Verifier {
	verifier := &Verifier{now: func() time.Time { return time.Now().UTC() }}
	for _, opt := range opts {
		if opt != nil {
			opt(verifier)
		}
	}
	return verifier
}

// WithVerifierConfig sets the base configuration. Per-credential credential.Data values override
// it. | WithVerifierConfig 设置基础配置。每个凭据的 credential.Data 值会覆盖它。
func WithVerifierConfig(cfg Config) VerifierOption {
	return func(verifier *Verifier) { verifier.cfg = cfg }
}

// WithVerifierGuard installs guard. A nil guard disables replay protection. | WithVerifierGuard
// 安装 guard。nil 表示关闭重放保护。
func WithVerifierGuard(guard ReplayGuard) VerifierOption {
	return func(verifier *Verifier) { verifier.guard = guard }
}

// WithVerifierClock overrides the time source. A nil function is ignored. | WithVerifierClock
// 覆盖时间源。nil 函数会被忽略。
func WithVerifierClock(now func() time.Time) VerifierOption {
	return func(verifier *Verifier) {
		if now != nil {
			verifier.now = now
		}
	}
}

// Verify implements auth.MFAVerifier. It returns false with a nil error for a syntactically valid
// challenge that does not match, and false with an error for a disabled credential, an unsupported
// credential type, invalid factor settings or a replayed code. | Verify 实现 auth.MFAVerifier。
// 对格式合法但不匹配的挑战返回 false 且错误为空；对已禁用凭据、不支持的凭据类型、非法因素设置或
// 重放的口令返回 false 并附带错误。
func (v *Verifier) Verify(ctx context.Context, user *auth.User, credential *auth.Credential, response string) (bool, error) {
	if v == nil {
		return false, errs.Detail(auth.ErrMFAInvalid, "nil verifier | 校验器为空")
	}
	if credential == nil {
		return false, auth.ErrCredentialNotFound
	}
	if credential.Disabled {
		return false, errs.Detail(auth.ErrMFAInvalid,
			"credential %s is disabled | 凭据 %s 已禁用", credential.ID, credential.ID)
	}
	if user != nil && user.ID != "" && credential.UserID != "" && user.ID != credential.UserID {
		return false, errs.Detail(auth.ErrMFAInvalid,
			"credential %s does not belong to user %s | 凭据 %s 不属于用户 %s",
			credential.ID, user.ID, credential.ID, user.ID)
	}
	switch credential.Type {
	case auth.CredentialTOTP, auth.CredentialHOTP:
	default:
		return false, errs.Detail(auth.ErrMFAInvalid,
			"credential %s type %q is not an OTP factor | 凭据 %s 类型 %q 不是 OTP 因素",
			credential.ID, credential.Type, credential.ID, credential.Type)
	}
	response = strings.TrimSpace(response)
	if response == "" {
		return false, nil
	}
	if strings.TrimSpace(credential.Secret) == "" {
		return false, errs.Detail(auth.ErrMFAInvalid,
			"credential %s has no secret | 凭据 %s 没有密钥", credential.ID, credential.ID)
	}
	cfg, err := v.configFor(credential)
	if err != nil {
		return false, err
	}
	userID := ""
	if user != nil {
		userID = user.ID
	}
	key := credentialReplayKey(credential, userID)
	now := v.nowTime()

	switch credential.Type {
	case auth.CredentialTOTP:
		step, ok, err := ValidateTOTP(credential.Secret, response, now, cfg)
		if err != nil {
			return false, errs.WrapDetail(err, auth.ErrMFAInvalid, "credential %s | 凭据 %s", credential.ID, credential.ID)
		}
		if !ok {
			return false, nil
		}
		if v.guard != nil {
			accepted, err := v.guard.Accept(ctx, key, step, replayWindow(cfg))
			if err != nil {
				return false, errs.Wrap(err, ErrReplayStore)
			}
			if !accepted {
				return false, errs.Detail(ErrReplay,
					"credential %s time step %d was already used | 凭据 %s 时间步 %d 已被使用",
					credential.ID, step, credential.ID, step)
			}
		}
		return true, nil

	case auth.CredentialHOTP:
		counter, err := counterFromData(credential.Data, credential.ID)
		if err != nil {
			return false, errs.Wrap(err, auth.ErrMFAInvalid)
		}
		matched, ok, err := ValidateHOTP(credential.Secret, response, counter, cfg)
		if err != nil {
			return false, errs.WrapDetail(err, auth.ErrMFAInvalid, "credential %s | 凭据 %s", credential.ID, credential.ID)
		}
		if !ok {
			return false, nil
		}
		// A counter below the stored value was already used. Accepting it would replay an old
		// code and rewind the persisted counter, allowing every counter up to the stored value to
		// be replayed. | 低于已存值的计数器已被使用。接受它会重放旧口令并回退已持久化计数器，使
		// 已存值之前的每个计数器都可被重放。
		if matched < counter {
			return false, nil
		}
		if v.guard != nil {
			if matched > uint64(maxInt64) {
				return false, errs.Detail(ErrInvalidConfig,
					"credential %s counter %d exceeds the replay guard range | 凭据 %s 计数器 %d 超出重放保护范围",
					credential.ID, matched, credential.ID, matched)
			}
			accepted, err := v.guard.Accept(ctx, key, int64(matched), replayWindow(cfg))
			if err != nil {
				return false, errs.Wrap(err, ErrReplayStore)
			}
			if !accepted {
				return false, errs.Detail(ErrReplay,
					"credential %s counter %d was already used | 凭据 %s 计数器 %d 已被使用",
					credential.ID, matched, credential.ID, matched)
			}
		}
		advanceHOTPCounter(credential, counter, matched)
		return true, nil
	}
	return false, nil
}

// configFor merges the credential's Data settings over the verifier base configuration and
// validates the result. | configFor 把凭据的 Data 设置合并到校验器基础配置之上，并校验结果。
func (v *Verifier) configFor(credential *auth.Credential) (Config, error) {
	cfg := v.cfg
	if value, ok := dataValue(credential.Data, "digits"); ok && strings.TrimSpace(value) != "" {
		digits, err := strconv.Atoi(strings.TrimSpace(value))
		if err != nil {
			return Config{}, invalidCredentialConfig(credential.ID,
				"credential %s digits %q is not an integer | 凭据 %s 位数 %q 不是整数",
				credential.ID, value, credential.ID, value)
		}
		cfg.Digits = digits
	}
	if value, ok := dataValue(credential.Data, "period"); ok && strings.TrimSpace(value) != "" {
		period, ok := parseDurationSetting(value)
		if !ok {
			return Config{}, invalidCredentialConfig(credential.ID,
				"credential %s period %q is not a positive duration | 凭据 %s 时间步 %q 不是正时长",
				credential.ID, value, credential.ID, value)
		}
		cfg.Period = period
	}
	if value, ok := dataValue(credential.Data, "algorithm"); ok && strings.TrimSpace(value) != "" {
		cfg.Algorithm = Algorithm(value)
	}
	if value, ok := dataValue(credential.Data, "skew"); ok && strings.TrimSpace(value) != "" {
		skew, err := strconv.Atoi(strings.TrimSpace(value))
		if err != nil {
			return Config{}, invalidCredentialConfig(credential.ID,
				"credential %s skew %q is not an integer | 凭据 %s 容差 %q 不是整数",
				credential.ID, value, credential.ID, value)
		}
		cfg.Skew = skew
	}
	normalized, err := cfg.Normalize()
	if err != nil {
		return Config{}, errs.WrapDetail(err, auth.ErrMFAInvalid,
			"credential %s configuration is invalid | 凭据 %s 配置非法", credential.ID, credential.ID)
	}
	return normalized, nil
}

// invalidCredentialConfig returns an ErrInvalidConfig detail that also classifies as
// ErrMFAInvalid, so a service can skip a factor whose stored settings are broken. | invalidCredentialConfig
// 返回同时归类为 ErrMFAInvalid 的 ErrInvalidConfig 详情，使服务能跳过存储设置损坏的因素。
func invalidCredentialConfig(credentialID, format string, args ...any) error {
	return errs.WrapDetail(errs.Detail(ErrInvalidConfig, format, args...), auth.ErrMFAInvalid,
		"credential %s | 凭据 %s", credentialID, credentialID)
}

// nowTime returns the verifier clock in UTC. | nowTime 返回 UTC 的校验器时钟。
func (v *Verifier) nowTime() time.Time {
	if v.now == nil {
		return time.Now().UTC()
	}
	return v.now().UTC()
}

// dataValue looks up key exactly first, then case-insensitively with a deterministic choice.
// | dataValue 先精确查找 key，再以确定的大小写不敏感方式查找。
func dataValue(data map[string]string, key string) (string, bool) {
	if data == nil {
		return "", false
	}
	if value, ok := data[key]; ok {
		return value, true
	}
	matchedKey := ""
	found := false
	for candidate := range data {
		if !strings.EqualFold(candidate, key) {
			continue
		}
		if !found || candidate < matchedKey {
			matchedKey = candidate
			found = true
		}
	}
	if !found {
		return "", false
	}
	return data[matchedKey], true
}

// counterFromData returns the stored HOTP counter, defaulting to zero. | counterFromData 返回已存 HOTP 计数器，默认零。
func counterFromData(data map[string]string, credentialID string) (uint64, error) {
	value, ok := dataValue(data, "counter")
	if !ok || strings.TrimSpace(value) == "" {
		return 0, nil
	}
	counter, err := strconv.ParseUint(strings.TrimSpace(value), 10, 64)
	if err != nil {
		return 0, errs.Detail(ErrInvalidConfig,
			"credential %s counter %q is not an unsigned integer | 凭据 %s 计数器 %q 不是无符号整数",
			credentialID, value, credentialID, value)
	}
	return counter, nil
}

// advanceHOTPCounter records the next expected counter on the credential so a caller that
// persists the credential prevents counter reuse. The stored counter never moves backwards. |
// advanceHOTPCounter 在凭据上记录下一个期望计数器，使持久化凭据的调用方能够阻止计数器重用。
// 已存计数器绝不回退。
func advanceHOTPCounter(credential *auth.Credential, stored, matched uint64) {
	if credential.Data == nil {
		credential.Data = make(map[string]string, 1)
	}
	next := matched
	if matched < ^uint64(0) {
		next = matched + 1
	}
	if next < stored {
		next = stored
	}
	credential.Data["counter"] = strconv.FormatUint(next, 10)
}

// credentialReplayKey derives a stable replay key without exposing the shared secret. | credentialReplayKey 派生稳定的重放键且不暴露共享密钥。
func credentialReplayKey(credential *auth.Credential, userID string) string {
	if credential.ID != "" {
		return credential.ID
	}
	if credential.UserID != "" {
		return credential.UserID
	}
	if userID != "" {
		return userID
	}
	return secretFingerprint(credential.Secret)
}
