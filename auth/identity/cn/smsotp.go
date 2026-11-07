package cn

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/hex"
	"math/big"
	"strings"
	"sync"
	"time"

	"github.com/shibingli/ydx/errs"
)

// SMS one-time-password sentinels. | 短信一次性验证码哨兵错误。
var (
	// ErrSMSSend reports a failed provider send. | ErrSMSSend 表示服务方发送失败。
	ErrSMSSend = errs.New("cn: SMS send failed | cn：短信发送失败")
	// ErrOTPNotFound reports an unknown challenge identifier. | ErrOTPNotFound 表示挑战标识不存在。
	ErrOTPNotFound = errs.New("cn: OTP challenge not found | cn：验证码挑战不存在")
	// ErrOTPExpired reports a challenge past its TTL. | ErrOTPExpired 表示验证码挑战超过有效期。
	ErrOTPExpired = errs.New("cn: OTP code expired | cn：验证码已过期")
	// ErrOTPUsed reports a challenge already consumed. | ErrOTPUsed 表示验证码挑战已被使用。
	ErrOTPUsed = errs.New("cn: OTP code already used | cn：验证码已使用")
	// ErrOTPInvalid reports a mismatched code. | ErrOTPInvalid 表示验证码不匹配。
	ErrOTPInvalid = errs.New("cn: invalid OTP code | cn：验证码错误")
	// ErrOTPAttemptsExceeded reports a challenge that reached its attempt limit. | ErrOTPAttemptsExceeded 表示验证码挑战已达尝试次数上限。
	ErrOTPAttemptsExceeded = errs.New("cn: OTP attempt limit reached | cn：验证码尝试次数已达上限")
	// ErrOTPResendTooSoon reports a send inside the per-mobile resend interval. | ErrOTPResendTooSoon 表示在每手机号重发间隔内再次发送。
	ErrOTPResendTooSoon = errs.New("cn: OTP resend too soon | cn：验证码重发过于频繁")
	// ErrOTPGenerate reports a code or challenge identifier generation failure. | ErrOTPGenerate 表示验证码或挑战标识生成失败。
	ErrOTPGenerate = errs.New("cn: OTP generation failed | cn：验证码生成失败")
)

// Default SMS one-time-password settings. | 短信一次性验证码默认设置。
const (
	// DefaultSMSOTPCodeLength is the default number of code digits. | DefaultSMSOTPCodeLength 是默认验证码位数。
	DefaultSMSOTPCodeLength = 6
	// DefaultSMSOTPTTL is the default code lifetime. | DefaultSMSOTPTTL 是默认验证码有效期。
	DefaultSMSOTPTTL = 5 * time.Minute
	// DefaultSMSOTPMaxAttempts is the default number of verification attempts per challenge. | DefaultSMSOTPMaxAttempts 是每个挑战默认的验证尝试次数。
	DefaultSMSOTPMaxAttempts = 5
	// DefaultSMSOTPResendInterval is the default minimum interval between sends to one mobile number. | DefaultSMSOTPResendInterval 是对同一手机号两次发送之间的默认最小间隔。
	DefaultSMSOTPResendInterval = 60 * time.Second
)

// SMSProvider sends a templated SMS message. | SMSProvider 发送模板短信。
type SMSProvider interface {
	// Send delivers templateID with params to mobile and returns the provider's request identifier.
	// The mobile value is E.164 (for example "+8613800138000"); the params map always contains the
	// "code" key for OTP templates and must not be retained by the provider after Send returns. |
	// Send 把 templateID 与 params 发送到 mobile，并返回服务方的请求标识。mobile 为 E.164 形式
	// （例如 "+8613800138000"）；OTP 模板的 params 始终包含 "code" 键，服务方不得在 Send 返回后
	// 继续持有该 map。
	Send(ctx context.Context, mobile, templateID string, params map[string]string) (requestID string, err error)
}

// SMSRateLimiter is an optional distributed rate-limit hook for SMS sends. | SMSRateLimiter 是可选的短信发送分布式限流钩子。
type SMSRateLimiter interface {
	// Allow reports whether a send to mobile may proceed. A non-nil error blocks the send and is
	// returned to the caller unchanged, so a shared limiter can return its own sentinel. | Allow
	// 报告是否允许向 mobile 发送。非 nil 错误会阻止发送并原样返回给调用方，因此共享限流器可返回
	// 自己的哨兵错误。
	Allow(ctx context.Context, mobile string) error
}

// SMSOTPConfig configures an SMSOTP. | SMSOTPConfig 配置 SMSOTP。
type SMSOTPConfig struct {
	// Provider is the required SMS transport. | Provider 是必填的短信传输实现。
	Provider SMSProvider
	// TemplateID is passed to every provider send unchanged. | TemplateID 原样传给每次服务方发送。
	TemplateID string
	// CodeLength is the number of digits, defaulting to 6 and limited to 4 through 10. | CodeLength 是验证码位数，默认 6，允许 4 至 10。
	CodeLength int
	// TTL is the code lifetime, defaulting to 5 minutes. | TTL 是验证码有效期，默认 5 分钟。
	TTL time.Duration
	// MaxAttempts is the verification attempt limit per challenge, defaulting to 5. | MaxAttempts 是每个挑战的验证尝试上限，默认 5。
	MaxAttempts int
	// ResendInterval is the minimum interval between sends to one mobile number. Zero selects the
	// 60-second default; a negative value disables the interval. | ResendInterval 是对同一手机号两次
	// 发送之间的最小间隔。零值使用 60 秒默认值；负值禁用该间隔。
	ResendInterval time.Duration
	// Params are extra template parameters copied into every send. | Params 是复制进每次发送的额外模板参数。
	Params map[string]string
	// Now overrides the clock for tests; it defaults to time.Now().UTC. | Now 为测试覆盖时钟，默认 time.Now().UTC。
	Now func() time.Time
	// CodeGenerator overrides code generation for tests. It must return CodeLength ASCII digits. | CodeGenerator 为测试覆盖验证码生成，必须返回 CodeLength 位 ASCII 数字。
	CodeGenerator func() (string, error)
	// RateLimiter is an optional pre-send rate-limit hook. | RateLimiter 是可选的发送前限流钩子。
	RateLimiter SMSRateLimiter
}

// smsChallenge is the server-side state of one issued code. Only a salted hash of the code is stored. | smsChallenge 是一个已签发验证码的服务端状态，仅保存加盐哈希。
type smsChallenge struct {
	mobile    string
	codeHash  [sha256.Size]byte
	expiresAt time.Time
	attempts  int
	used      bool
	locked    bool
}

// SMSOTP issues and verifies SMS one-time passwords. | SMSOTP 签发并校验短信一次性验证码。
//
// A successful Send creates a random challenge identifier and a random numeric code. The code is
// stored only as SHA-256(challengeID + ":" + code), compared in constant time, and deleted from the
// active set once used, expired or locked. Concurrency is guarded by a sync.Mutex. | 成功的 Send 会
// 创建随机挑战标识与随机数字验证码。验证码仅以 SHA-256(challengeID + ":" + code) 形式保存，以
// 常量时间比较；使用、过期或锁定后从活动集合移除。并发由 sync.Mutex 保护。
type SMSOTP struct {
	cfg       SMSOTPConfig
	configErr error

	mu         sync.Mutex
	challenges map[string]*smsChallenge
	lastSent   map[string]time.Time
	latest     map[string]string
}

// NewSMSOTP applies defaults and returns an SMSOTP. | NewSMSOTP 应用默认值并返回 SMSOTP。
//
// Missing or out-of-range values are recorded and returned by Send and Verify as ErrInvalidConfig;
// a nil Provider is not defaulted. | 缺失或越界的值会被记录，并由 Send 与 Verify 以
// ErrInvalidConfig 返回；Provider 为 nil 时不会自动补全。
func NewSMSOTP(config SMSOTPConfig) *SMSOTP {
	s := &SMSOTP{
		cfg:        config,
		challenges: make(map[string]*smsChallenge),
		lastSent:   make(map[string]time.Time),
		latest:     make(map[string]string),
	}
	if config.Provider == nil {
		s.setConfigErr("SMS provider is required | 需要短信提供方")
	}
	switch {
	case config.CodeLength == 0:
		s.cfg.CodeLength = DefaultSMSOTPCodeLength
	case config.CodeLength < 4 || config.CodeLength > 10:
		s.setConfigErr("code length %d is outside 4..10 | 验证码位数 %d 不在 4..10 范围", config.CodeLength, config.CodeLength)
	}
	switch {
	case config.TTL == 0:
		s.cfg.TTL = DefaultSMSOTPTTL
	case config.TTL < 0:
		s.setConfigErr("TTL must not be negative | 有效期不得为负")
	}
	switch {
	case config.MaxAttempts == 0:
		s.cfg.MaxAttempts = DefaultSMSOTPMaxAttempts
	case config.MaxAttempts < 0:
		s.setConfigErr("max attempts must not be negative | 最大尝试次数不得为负")
	}
	if config.ResendInterval == 0 {
		s.cfg.ResendInterval = DefaultSMSOTPResendInterval
	}
	if config.Now == nil {
		s.cfg.Now = func() time.Time { return time.Now().UTC() }
	}
	if len(config.Params) > 0 {
		s.cfg.Params = make(map[string]string, len(config.Params))
		for key, value := range config.Params {
			s.cfg.Params[key] = value
		}
	}
	return s
}

// Send issues a code to mobile and returns its challenge identifier. | Send 向 mobile 签发验证码并返回挑战标识。
//
// The mobile number is normalized to E.164 and passed to the provider in that form. The provider
// receives the configured templateID and params plus the "code" key. A successful send invalidates
// any previous outstanding challenge for the same mobile. A failed provider call still counts toward
// the resend interval, because the provider may have accepted the message before failing. | 手机号会
// 规范化为 E.164 并以该形式传给服务方。服务方收到配置的 templateID、params 以及 "code" 键。成功
// 发送会使同一手机号此前未完成的挑战失效。服务方调用失败仍计入重发间隔，因为服务方可能在报错前
// 已接受消息。
func (s *SMSOTP) Send(ctx context.Context, mobile string) (string, error) {
	if err := s.ready(); err != nil {
		return "", err
	}
	if ctx == nil {
		ctx = context.Background()
	}
	e164, err := NormalizeMobile(mobile)
	if err != nil {
		return "", err
	}
	if s.cfg.RateLimiter != nil {
		if err := s.cfg.RateLimiter.Allow(ctx, e164); err != nil {
			return "", err
		}
	}

	now := s.now()
	s.mu.Lock()
	s.purgeLocked(now)
	if s.cfg.ResendInterval >= 0 {
		if last, ok := s.lastSent[e164]; ok && now.Sub(last) < s.cfg.ResendInterval {
			remaining := s.cfg.ResendInterval - now.Sub(last)
			s.mu.Unlock()
			return "", errs.Detail(ErrOTPResendTooSoon, "retry after %s | 请在 %s 后重试", remaining.Round(time.Second), remaining.Round(time.Second))
		}
	}
	s.lastSent[e164] = now
	s.mu.Unlock()

	code, err := s.generateCode()
	if err != nil {
		return "", err
	}
	challengeID, err := randomOTPID()
	if err != nil {
		return "", err
	}
	hash := hashOTPCode(challengeID, code)
	params := make(map[string]string, len(s.cfg.Params)+1)
	for key, value := range s.cfg.Params {
		params[key] = value
	}
	params["code"] = code
	if _, err := s.cfg.Provider.Send(ctx, e164, s.cfg.TemplateID, params); err != nil {
		return "", errs.Wrap(err, ErrSMSSend)
	}

	challenge := &smsChallenge{
		mobile:    e164,
		codeHash:  hash,
		expiresAt: now.Add(s.cfg.TTL),
	}
	s.mu.Lock()
	if previous := s.latest[e164]; previous != "" {
		delete(s.challenges, previous)
	}
	s.challenges[challengeID] = challenge
	s.latest[e164] = challengeID
	s.mu.Unlock()
	return challengeID, nil
}

// Verify checks code against the challenge identified by challengeID. | Verify 校验 code 是否匹配 challengeID 对应的挑战。
//
// A valid code may be used once. A wrong code consumes one attempt; reaching MaxAttempts locks the
// challenge until it expires, and further calls return ErrOTPAttemptsExceeded. Unknown, expired and
// consumed challenges return ErrOTPNotFound, ErrOTPExpired and ErrOTPUsed respectively. | 验证码只能
// 使用一次。错误验证码消耗一次尝试；达到 MaxAttempts 后挑战锁定至过期，后续调用返回
// ErrOTPAttemptsExceeded。未知、过期与已使用的挑战分别返回 ErrOTPNotFound、ErrOTPExpired 与
// ErrOTPUsed。
func (s *SMSOTP) Verify(ctx context.Context, challengeID, code string) error {
	if err := s.ready(); err != nil {
		return err
	}
	now := s.now()
	s.mu.Lock()
	defer s.mu.Unlock()

	challenge := s.challenges[challengeID]
	if challenge == nil {
		return errs.Detail(ErrOTPNotFound, "challenge identifier is unknown | 挑战标识不存在")
	}
	if !now.Before(challenge.expiresAt) {
		delete(s.challenges, challengeID)
		if s.latest[challenge.mobile] == challengeID {
			delete(s.latest, challenge.mobile)
		}
		return errs.Detail(ErrOTPExpired, "challenge expired | 挑战已过期")
	}
	if challenge.used {
		return errs.Detail(ErrOTPUsed, "challenge already used | 挑战已使用")
	}
	if challenge.locked {
		return errs.Detail(ErrOTPAttemptsExceeded, "challenge locked after too many attempts | 挑战因尝试次数过多而锁定")
	}

	candidate := hashOTPCode(challengeID, code)
	if subtle.ConstantTimeCompare(candidate[:], challenge.codeHash[:]) != 1 {
		challenge.attempts++
		if challenge.attempts >= s.cfg.MaxAttempts {
			challenge.locked = true
			return errs.Detail(ErrOTPAttemptsExceeded, "maximum attempts reached | 已达最大尝试次数")
		}
		return errs.Detail(ErrOTPInvalid, "code does not match | 验证码不匹配")
	}
	challenge.used = true
	if s.latest[challenge.mobile] == challengeID {
		delete(s.latest, challenge.mobile)
	}
	return nil
}

// ready reports whether the instance was created by NewSMSOTP with a valid configuration. | ready 报告实例是否由 NewSMSOTP 以合法配置创建。
func (s *SMSOTP) ready() error {
	if s == nil {
		return errs.Detail(ErrInvalidConfig, "SMSOTP is nil | SMSOTP 为空")
	}
	if s.configErr != nil {
		return s.configErr
	}
	if s.cfg.Provider == nil || s.cfg.CodeLength <= 0 || s.cfg.TTL <= 0 || s.cfg.MaxAttempts <= 0 ||
		s.challenges == nil || s.lastSent == nil || s.latest == nil {
		return errs.Detail(ErrInvalidConfig, "SMSOTP is not initialized; use NewSMSOTP | SMSOTP 未初始化，请使用 NewSMSOTP")
	}
	return nil
}

// setConfigErr records the first configuration error. | setConfigErr 记录第一个配置错误。
func (s *SMSOTP) setConfigErr(format string, args ...any) {
	if s.configErr == nil {
		s.configErr = errs.Detail(ErrInvalidConfig, format, args...)
	}
}

// now returns the configured clock time. | now 返回配置的时钟时间。
func (s *SMSOTP) now() time.Time {
	if s.cfg.Now == nil {
		return time.Now().UTC()
	}
	return s.cfg.Now()
}

// generateCode returns a configured or cryptographically random numeric code. | generateCode 返回配置的或密码学随机的数字验证码。
func (s *SMSOTP) generateCode() (string, error) {
	if s.cfg.CodeGenerator != nil {
		code, err := s.cfg.CodeGenerator()
		if err != nil {
			return "", errs.Wrap(err, ErrOTPGenerate)
		}
		if !validOTPCode(code, s.cfg.CodeLength) {
			return "", errs.Detail(ErrOTPGenerate, "generator did not return %d ASCII digits | 生成器未返回 %d 位 ASCII 数字", s.cfg.CodeLength, s.cfg.CodeLength)
		}
		return code, nil
	}
	limit := new(big.Int).Exp(big.NewInt(10), big.NewInt(int64(s.cfg.CodeLength)), nil)
	value, err := rand.Int(rand.Reader, limit)
	if err != nil {
		return "", errs.Wrap(err, ErrOTPGenerate)
	}
	code := value.String()
	if len(code) < s.cfg.CodeLength {
		code = strings.Repeat("0", s.cfg.CodeLength-len(code)) + code
	}
	return code, nil
}

// purgeLocked removes challenges and send timestamps that can no longer affect a decision. | purgeLocked 删除不再影响判定的挑战与发送时间戳。
func (s *SMSOTP) purgeLocked(now time.Time) {
	window := s.cfg.TTL
	if s.cfg.ResendInterval > window {
		window = s.cfg.ResendInterval
	}
	for id, challenge := range s.challenges {
		if !now.Before(challenge.expiresAt) {
			delete(s.challenges, id)
			if s.latest[challenge.mobile] == id {
				delete(s.latest, challenge.mobile)
			}
		}
	}
	for mobile, sentAt := range s.lastSent {
		if now.Sub(sentAt) > window {
			delete(s.lastSent, mobile)
		}
	}
}

// randomOTPID returns a 128-bit random challenge identifier in lower-case hexadecimal. | randomOTPID 返回 128 位随机挑战标识的小写十六进制表示。
func randomOTPID() (string, error) {
	var raw [16]byte
	if _, err := rand.Read(raw[:]); err != nil {
		return "", errs.Wrap(err, ErrOTPGenerate)
	}
	return hex.EncodeToString(raw[:]), nil
}

// hashOTPCode returns SHA-256(challengeID + ":" + code). | hashOTPCode 返回 SHA-256(challengeID + ":" + code)。
func hashOTPCode(challengeID, code string) [sha256.Size]byte {
	return sha256.Sum256([]byte(challengeID + ":" + code))
}

// validOTPCode reports whether code is exactly n ASCII digits. | validOTPCode 报告 code 是否恰好为 n 位 ASCII 数字。
func validOTPCode(code string, n int) bool {
	if len(code) != n {
		return false
	}
	for i := 0; i < len(code); i++ {
		if code[i] < '0' || code[i] > '9' {
			return false
		}
	}
	return true
}
