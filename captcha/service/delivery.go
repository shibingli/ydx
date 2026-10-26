package service

import (
	"context"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"math/big"
	"net/mail"
	"strconv"
	"strings"
	"time"
	"unicode"

	"github.com/shibingli/ydx/captcha/core"
	"github.com/shibingli/ydx/errs"
)

// codeDigits is the number of digits in a delivered one-time code. | codeDigits 是下发一次性验证码的位数。
const codeDigits = 6

// codeMaxValue is the exclusive upper bound of the random code. | codeMaxValue 是随机验证码的排他上界。
const codeMaxValue = 1000000

// SendCode creates a one-time code challenge and delivers it. | SendCode 创建一次性验证码挑战并下发。
//
// A SendRequest with Fallback true is accepted only when Options.Fallback is
// enabled for the same channel; it records capture_fallback and the supplied
// capture trigger in audit output. | 只有 Options.Fallback 已启用且通道一致时，
// SendRequest.Fallback 才会被接受；它会把 capture_fallback 与触发原因写入审计。
func (m *Manager) SendCode(ctx context.Context, req SendRequest) (*Challenge, error) {
	if err := m.enter(); err != nil {
		return nil, err
	}
	start := m.now()
	req.Meta = core.SanitizeMeta(req.Meta)
	req.Signals = core.SanitizeSignals(req.Signals)
	req.Locale = core.CleanMeta(req.Locale, 64)
	if !req.Channel.Valid() {
		return nil, ErrUnsupportedChannel
	}
	if err := m.checkOrigin(req.Meta.Origin); err != nil {
		return nil, err
	}
	if err := validateAction(req.Action); err != nil {
		return nil, err
	}
	target, err := normalizeTarget(req.Channel, req.Target, m.opts.SMSDefaultCountryCode)
	if err != nil {
		return nil, err
	}
	locale := m.localizer.Normalize(req.Locale)
	typ := TypeSMS
	if req.Channel == ChannelEmail {
		typ = TypeEmail
	}
	signals := req.Signals
	var fallbackReasons []string
	if req.Fallback {
		if !m.opts.Fallback.Enabled || req.Channel != m.opts.Fallback.Channel {
			m.auditSince(ctx, start, AuditEvent{RequestID: req.Meta.RequestID, Action: req.Action, Type: typ, Outcome: AuditBlocked, IP: req.Meta.IP, Target: MaskTarget(req.Channel, target), ErrorCode: core.ErrorCode(ErrFallbackDisabled)})
			return nil, ErrFallbackDisabled
		}
		// The capture signal is the reason for the downgrade, not a reason to
		// reject the downgraded flow. | 录屏信号是降级原因，不应反过来拒绝降级流程。
		signals.ScreenCapture = false
		signals.ScreenshotKey = false
		signals.PrintAttempt = false
		signals.PageHidden = false
		signals.FocusLoss = 0
		fallbackReasons = append(fallbackReasons, "capture_fallback")
		if kind := safeCaptureKind(req.CaptureKind); kind != "" {
			fallbackReasons = append(fallbackReasons, kind)
		}
	}
	sender := m.senders[req.Channel]
	if sender == nil {
		return nil, errs.Detail(ErrNoSender, "channel %q | 通道 %q", req.Channel, req.Channel)
	}
	assessment, err := m.assess(ctx, req.Meta, signals, req.Action, typ, phaseSend, target)
	if err != nil {
		m.auditSince(ctx, start, AuditEvent{RequestID: req.Meta.RequestID, Action: req.Action, Type: typ, Outcome: auditOutcome(err), IP: req.Meta.IP, Target: MaskTarget(req.Channel, target), Risk: assessment.Score, Reasons: appendReasons(assessment.Reasons, fallbackReasons), ErrorCode: core.ErrorCode(err)})
		return nil, err
	}
	auditReasons := appendReasons(assessment.Reasons, fallbackReasons)
	targetHash := m.keyedDigest(string(req.Channel) + ":" + target)
	release, err := m.reserveCooldown(ctx, req.Channel, targetHash)
	if err != nil {
		m.auditSince(ctx, start, AuditEvent{RequestID: req.Meta.RequestID, Action: req.Action, Type: typ, Outcome: AuditRateLimited, IP: req.Meta.IP, Target: MaskTarget(req.Channel, target), Risk: assessment.Score, Reasons: auditReasons, ErrorCode: core.ErrorCode(err)})
		return nil, err
	}
	reserved := true
	defer func() {
		if reserved {
			release()
		}
	}()
	id, err := randomID(18)
	if err != nil {
		return nil, err
	}
	code, err := randomCode()
	if err != nil {
		return nil, err
	}
	now := m.now()
	record := &Record{
		ID:          id,
		Type:        typ,
		Action:      req.Action,
		Locale:      locale,
		CreatedAt:   now,
		ExpiresAt:   now.Add(m.opts.ChallengeTTL),
		Attempts:    0,
		MaxAttempts: m.opts.MaxAttempts,
		Risk:        assessment.Score,
		RiskReasons: append([]string(nil), auditReasons...),
		Signals:     signals,
		Geo:         assessment.Geo,
		GeoAt:       now,
		Meta:        req.Meta,
		Channel:     req.Channel,
		Target:      MaskTarget(req.Channel, target),
		TargetHash:  targetHash,
		CodeHash:    m.codeDigest(id, code),
		CodeSentAt:  now,
		Fallback:    req.Fallback,
		CaptureKind: safeCaptureKind(req.CaptureKind),
	}
	payload, err := encodeRecord(record)
	if err != nil {
		return nil, err
	}
	if err := m.store.Put(ctx, m.recordKey(id), payload, m.opts.ChallengeTTL); err != nil {
		return nil, errs.Wrap(err, ErrStore)
	}
	msg := Message{
		Channel:   req.Channel,
		To:        target,
		Code:      code,
		Action:    req.Action,
		Locale:    locale,
		Template:  "captcha_code",
		ExpiresIn: m.opts.ChallengeTTL,
		Data: map[string]string{
			"action":  req.Action,
			"locale":  locale,
			"purpose": req.Action,
		},
	}
	if err := sender.Send(ctx, msg); err != nil {
		_ = m.store.Delete(context.Background(), m.recordKey(id))
		m.auditSince(ctx, start, AuditEvent{RequestID: req.Meta.RequestID, ChallengeID: id, Action: req.Action, Type: typ, Outcome: AuditError, IP: req.Meta.IP, Target: record.Target, Risk: assessment.Score, Reasons: auditReasons, ErrorCode: core.ErrorCode(ErrSendFailed)})
		return nil, errs.Wrap(err, ErrSendFailed)
	}
	reserved = false
	m.auditSince(ctx, start, AuditEvent{RequestID: req.Meta.RequestID, ChallengeID: id, Action: req.Action, Type: typ, Outcome: AuditSent, IP: req.Meta.IP, Country: assessment.Geo.Country, Target: record.Target, Risk: assessment.Score, Reasons: auditReasons})
	notice := ""
	if req.Fallback {
		fallback := "Screen capture detected; switched to SMS verification."
		if req.Channel == ChannelEmail {
			fallback = "Screen capture detected; switched to email verification."
		}
		notice = m.localizer.Localized(locale, "notice.fallback_"+string(req.Channel), fallback)
	}
	return &Challenge{
		ID:        id,
		Type:      typ,
		Action:    req.Action,
		Locale:    locale,
		Prompt:    m.codePrompt(locale, req.Channel),
		Notice:    notice,
		Channel:   req.Channel,
		Target:    record.Target,
		ExpiresIn: int64(m.opts.ChallengeTTL / time.Second),
	}, nil
}

// codeDigest returns the keyed digest of a delivered code. | codeDigest 返回已下发验证码的键控摘要。
func (m *Manager) codeDigest(id, code string) []byte {
	mac := hmac.New(sha256.New, m.digestKey)
	_, _ = mac.Write([]byte("code:" + id + ":" + code))
	return mac.Sum(nil)
}

// verifyCode checks a submitted code in constant time. | verifyCode 以常量时间校验提交的验证码。
func (m *Manager) verifyCode(record *Record, code string) bool {
	code = strings.TrimSpace(code)
	if len(code) != codeDigits {
		return false
	}
	for i := 0; i < len(code); i++ {
		if code[i] < '0' || code[i] > '9' {
			return false
		}
	}
	expected := m.codeDigest(record.ID, code)
	return hmac.Equal(expected, record.CodeHash)
}

// keyedDigest returns a keyed non-reversible identifier. | keyedDigest 返回键控不可逆标识。
func (m *Manager) keyedDigest(value string) string {
	mac := hmac.New(sha256.New, m.digestKey)
	_, _ = mac.Write([]byte(value))
	return hex.EncodeToString(mac.Sum(nil)[:16])
}

// randomCode returns a zero-padded numeric code. | randomCode 返回补零的数字验证码。
func randomCode() (string, error) {
	n, err := rand.Int(rand.Reader, big.NewInt(codeMaxValue))
	if err != nil {
		return "", errs.Wrap(err, ErrSendFailed)
	}
	value := strconv.FormatInt(n.Int64(), 10)
	if len(value) >= codeDigits {
		return value, nil
	}
	return strings.Repeat("0", codeDigits-len(value)) + value, nil
}

// normalizeTarget validates and canonicalizes a phone number or email address. | normalizeTarget 校验并规范化手机号或邮箱。
func normalizeTarget(channel Channel, target string, defaultCountryCode string) (string, error) {
	target = strings.TrimSpace(target)
	if target == "" || len(target) > 254 {
		return "", ErrInvalidTarget
	}
	switch channel {
	case ChannelSMS:
		return normalizePhone(target, defaultCountryCode)
	case ChannelEmail:
		parsed, err := mail.ParseAddress(target)
		if err != nil || parsed.Name != "" || parsed.Address != target {
			return "", ErrInvalidTarget
		}
		at := strings.LastIndexByte(parsed.Address, '@')
		if at <= 0 || at == len(parsed.Address)-1 {
			return "", ErrInvalidTarget
		}
		for _, r := range parsed.Address {
			if unicode.IsControl(r) || unicode.IsSpace(r) {
				return "", ErrInvalidTarget
			}
		}
		// Treat email addresses case-insensitively for cooldown and token binding; | 邮件地址按大小写不敏感处理，
		// providers and users routinely vary the local part. | 供应商与用户经常改变本地部分大小写。
		return strings.ToLower(parsed.Address), nil
	default:
		return "", ErrUnsupportedChannel
	}
}

// normalizePhone canonicalizes accepted phone forms to E.164. | normalizePhone 把接受的手机号形式规范化为 E.164。
func normalizePhone(target, defaultCountryCode string) (string, error) {
	var b strings.Builder
	b.Grow(len(target))
	plus := false
	for i, r := range target {
		switch {
		case r == '+' && i == 0:
			plus = true
		case r >= '0' && r <= '9':
			b.WriteRune(r)
		case r == ' ' || r == '-' || r == '(' || r == ')' || r == '.':
			continue
		default:
			return "", ErrInvalidTarget
		}
	}
	digits := b.String()
	if digits == "" {
		return "", ErrInvalidTarget
	}
	if plus {
		if len(digits) < 8 || len(digits) > 15 || digits[0] == '0' {
			return "", ErrInvalidTarget
		}
		return "+" + digits, nil
	}
	if strings.HasPrefix(digits, "00") {
		digits = digits[2:]
		if len(digits) < 8 || len(digits) > 15 || digits[0] == '0' {
			return "", ErrInvalidTarget
		}
		return "+" + digits, nil
	}
	digits = strings.TrimPrefix(digits, "0")
	if defaultCountryCode == "" {
		return "", ErrInvalidTarget
	}
	digits = defaultCountryCode + digits
	if len(digits) < 8 || len(digits) > 15 {
		return "", ErrInvalidTarget
	}
	return "+" + digits, nil
}

// MaskTarget masks a phone number or email address for audit output. | MaskTarget 为审计输出脱敏手机号或邮箱。
func MaskTarget(channel Channel, target string) string {
	if target == "" {
		return ""
	}
	switch channel {
	case ChannelSMS:
		if len(target) <= 7 {
			return strings.Repeat("*", len(target))
		}
		return target[:3] + strings.Repeat("*", len(target)-7) + target[len(target)-4:]
	case ChannelEmail:
		at := strings.LastIndexByte(target, '@')
		if at <= 0 {
			return "***"
		}
		local := target[:at]
		if len(local) <= 2 {
			local = "**"
		} else {
			local = local[:2] + "***"
		}
		return local + target[at:]
	default:
		return "***"
	}
}

// reserveCooldown atomically reserves the next send window for one target. | reserveCooldown 原子预占目标的下一次发送窗口。
//
// The reservation happens before delivery so concurrent requests cannot all
// pass the same check. A failed send calls release, which deletes the entry
// only when it still carries this request's token. | 预占发生在投递之前，避免并发请求
// 同时通过检查；发送失败时 release 仅在条目仍携带本请求令牌时删除。
func (m *Manager) reserveCooldown(ctx context.Context, channel Channel, targetHash string) (func(), error) {
	key := m.opts.KeyPrefix + "cd:" + string(channel) + ":" + targetHash
	token, err := randomID(12)
	if err != nil {
		return nil, err
	}
	payload := []byte(strconv.FormatInt(m.now().Add(m.opts.Cooldown).UnixMilli(), 10) + ":" + token)
	ok, err := m.store.PutIfAbsent(ctx, key, payload, m.opts.Cooldown)
	if err != nil {
		return nil, errs.Wrap(err, ErrStore)
	}
	if !ok {
		// The key may have expired between SET NX and GET; retry once so a
		// stale entry cannot block a request beyond its cooldown. | 键可能在
		// SET NX 与 GET 之间过期；重试一次，避免陈旧条目阻塞超过冷却期。
		current, found, getErr := m.store.Get(ctx, key)
		if getErr != nil {
			return nil, errs.Wrap(getErr, ErrStore)
		}
		if !found {
			ok, err = m.store.PutIfAbsent(ctx, key, payload, m.opts.Cooldown)
			if err != nil {
				return nil, errs.Wrap(err, ErrStore)
			}
			if !ok {
				current, found, getErr = m.store.Get(ctx, key)
				if getErr != nil {
					return nil, errs.Wrap(getErr, ErrStore)
				}
			}
		}
		if !ok {
			retryAfter := m.opts.Cooldown
			if found {
				if remaining, valid := cooldownRemaining(current, m.now()); valid {
					retryAfter = remaining
				}
			}
			if retryAfter <= 0 {
				retryAfter = time.Millisecond
			}
			return nil, &CooldownError{RetryAfter: retryAfter}
		}
	}
	return m.cooldownRelease(key, payload), nil
}

// cooldownRemaining parses the expiry stored with a reservation. | cooldownRemaining 解析预占中保存的到期时间。
func cooldownRemaining(payload []byte, now time.Time) (time.Duration, bool) {
	raw, _, ok := strings.Cut(string(payload), ":")
	if !ok {
		return 0, false
	}
	millis, err := strconv.ParseInt(raw, 10, 64)
	if err != nil {
		return 0, false
	}
	return time.UnixMilli(millis).Sub(now), true
}

// cooldownRelease returns a compare-and-delete release for one reservation. | cooldownRelease 返回单个预占的比较删除释放函数。
func (m *Manager) cooldownRelease(key string, value []byte) func() {
	return func() {
		if _, err := m.store.DeleteIf(context.Background(), key, value); err != nil {
			m.logWarn("captcha cooldown release failed | 验证码冷却释放失败", err)
		}
	}
}

// safeCaptureKind keeps only known capture trigger names in audit output. | safeCaptureKind 只保留已知的录屏触发原因进入审计。
func safeCaptureKind(kind string) string {
	switch kind {
	case "screen_capture", "screenshot_key", "print_attempt", "focus_loss", "page_hidden":
		return kind
	default:
		return ""
	}
}

// codePrompt returns the localized code entry instruction. | codePrompt 返回本地化的验证码输入提示。
func (m *Manager) codePrompt(locale string, channel Channel) Prompt {
	if channel == ChannelSMS {
		return m.localizer.Prompt(locale, "prompt.sms", "hint.sms", "Enter the SMS code", "6-digit code")
	}
	return m.localizer.Prompt(locale, "prompt.email", "hint.email", "Enter the email code", "6-digit code")
}

// validateAction rejects empty, overlong or control-containing actions. | validateAction 拒绝空、过长或含控制符的动作。
func validateAction(action string) error {
	action = strings.TrimSpace(action)
	if action == "" || len(action) > 128 {
		return errs.Detail(ErrInvalidOptions, "action must be 1-128 bytes | action 必须为 1-128 字节")
	}
	for _, r := range action {
		if unicode.IsControl(r) {
			return errs.Detail(ErrInvalidOptions, "action contains a control character | action 包含控制字符")
		}
	}
	return nil
}
