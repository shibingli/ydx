package service

import (
	"context"
	"errors"
	"net/netip"
	"strings"

	"github.com/shibingli/ydx/captcha/core"
	"github.com/shibingli/ydx/errs"
)

// Create builds a fresh visual challenge. | Create 构建新的视觉挑战。
func (m *Manager) Create(ctx context.Context, req CreateRequest) (*Challenge, error) {
	if err := m.enter(); err != nil {
		return nil, err
	}
	start := m.now()
	req.Meta = core.SanitizeMeta(req.Meta)
	req.Signals = core.SanitizeSignals(req.Signals)
	req.Locale = core.CleanMeta(req.Locale, 64)
	if err := m.checkOrigin(req.Meta.Origin); err != nil {
		return nil, err
	}
	if err := validateAction(req.Action); err != nil {
		return nil, err
	}
	typ := req.Type
	if typ != "" && typ.IsCode() {
		return nil, ErrInvalidType
	}
	if typ == "" {
		typ = m.defaultType()
	}
	if !m.typeEnabled(typ) {
		return nil, errs.Detail(ErrInvalidType, "type %q is disabled | 类型 %q 未启用", typ, typ)
	}
	assessment, err := m.assess(ctx, req.Meta, req.Signals, req.Action, typ, phaseCreate, "")
	if err != nil {
		m.auditSince(ctx, start, AuditEvent{RequestID: req.Meta.RequestID, Action: req.Action, Type: typ, Outcome: auditOutcome(err), IP: req.Meta.IP, Risk: assessment.Score, Reasons: assessment.Reasons, ErrorCode: core.ErrorCode(err)})
		return nil, err
	}
	if req.Type == "" {
		candidate := m.adaptiveType(assessment.Score)
		if candidate != typ {
			// A type-level deny must also apply to an adaptively selected type. | 类型级拒绝同样适用于自适应选出的类型。
			addr, _ := netip.ParseAddr(strings.TrimSpace(req.Meta.IP))
			if m.policy.Load().Evaluate(addr, assessment.Geo.Country, req.Action, candidate).Denied {
				candidate = typ
			}
		}
		typ = candidate
		if !m.typeEnabled(typ) {
			typ = m.defaultType()
		}
	}
	provider, ok := m.provider(typ)
	if !ok {
		return nil, errs.Detail(ErrInvalidType, "no provider for %q | 类型 %q 没有生成器", typ, typ)
	}
	locale := m.localizer.Normalize(req.Locale)
	generated, err := provider.Generate(ctx, GenerateRequest{
		Locale: locale,
		Action: req.Action,
		Width:  m.opts.Width,
		Height: m.opts.Height,
		Now:    m.now(),
		Translate: func(key string, args ...string) string {
			return m.localizer.Message(locale, key, args...)
		},
	})
	if err != nil {
		m.auditSince(ctx, start, AuditEvent{RequestID: req.Meta.RequestID, Action: req.Action, Type: typ, Outcome: AuditError, IP: req.Meta.IP, Risk: assessment.Score, Reasons: assessment.Reasons, ErrorCode: core.ErrorCode(ErrProvider)})
		return nil, errs.Wrap(err, ErrProvider)
	}
	if err := validateGenerated(generated); err != nil {
		m.auditSince(ctx, start, AuditEvent{RequestID: req.Meta.RequestID, Action: req.Action, Type: typ, Outcome: AuditError, IP: req.Meta.IP, Risk: assessment.Score, ErrorCode: core.ErrorCode(err)})
		return nil, err
	}
	id, err := randomID(18)
	if err != nil {
		return nil, err
	}
	records, images, err := m.storeImages(ctx, generated.Images)
	if err != nil {
		return nil, err
	}
	var pow *PoWChallenge
	requirePoW := m.requiresPoW(assessment.Score)
	if requirePoW {
		pow, err = m.newPoWChallenge(assessment.Score)
		if err != nil {
			m.deleteImageKeys(ctx, records)
			return nil, err
		}
	}
	now := m.now()
	record := &Record{
		ID:          id,
		Type:        typ,
		Action:      req.Action,
		Locale:      locale,
		Answer:      generated.Answer,
		Images:      records,
		CreatedAt:   now,
		ExpiresAt:   now.Add(m.opts.ChallengeTTL),
		MaxAttempts: m.opts.MaxAttempts,
		Risk:        assessment.Score,
		RiskReasons: append([]string(nil), assessment.Reasons...),
		Signals:     req.Signals,
		Geo:         assessment.Geo,
		GeoAt:       now,
		Meta:        req.Meta,
		PoW:         pow,
		RequirePoW:  requirePoW,
	}
	payload, err := encodeRecord(record)
	if err != nil {
		m.deleteImageKeys(ctx, records)
		return nil, err
	}
	if err := m.store.Put(ctx, m.recordKey(id), payload, m.opts.ChallengeTTL); err != nil {
		m.deleteImageKeys(ctx, records)
		return nil, errs.Wrap(err, ErrStore)
	}
	m.auditSince(ctx, start, AuditEvent{RequestID: req.Meta.RequestID, ChallengeID: id, Action: req.Action, Type: typ, Outcome: AuditCreated, IP: req.Meta.IP, Country: assessment.Geo.Country, Risk: assessment.Score, Reasons: assessment.Reasons})
	return &Challenge{
		ID:        id,
		Type:      typ,
		Action:    req.Action,
		Locale:    locale,
		Prompt:    generated.Prompt,
		Images:    images,
		PoW:       pow,
		ExpiresIn: secondsCeil(m.opts.ChallengeTTL),
	}, nil
}

// Verify checks one answer and issues a token on success. | Verify 校验一次答案，成功时签发令牌。
func (m *Manager) Verify(ctx context.Context, req VerifyRequest) (*VerifyResult, error) {
	if err := m.enter(); err != nil {
		return nil, err
	}
	start := m.now()
	req.Meta = core.SanitizeMeta(req.Meta)
	req.Signals = core.SanitizeSignals(req.Signals)
	if err := m.checkOrigin(req.Meta.Origin); err != nil {
		return nil, err
	}
	id := strings.TrimSpace(req.ID)
	if id == "" || len(id) > 128 {
		return nil, ErrNotFound
	}
	now := start
	payload, ok, err := m.store.Take(ctx, m.recordKey(id))
	if err != nil {
		return nil, errs.Wrap(err, ErrStore)
	}
	if !ok {
		return nil, ErrNotFound
	}
	record, err := decodeRecord(payload)
	if err != nil {
		return nil, err
	}
	if !record.ExpiresAt.After(now) {
		m.auditSince(ctx, start, AuditEvent{RequestID: req.Meta.RequestID, ChallengeID: id, Action: record.Action, Type: record.Type, Outcome: AuditError, IP: req.Meta.IP, Risk: record.Risk, ErrorCode: core.ErrorCode(ErrExpired)})
		return nil, ErrExpired
	}
	verifySignals := req.Signals
	if record.Fallback {
		// A fallback code challenge is the mitigation for the capture event; the
		// code verification must not be rejected by the same client signal. |
		// 降级验证码是录屏事件的缓解措施；验证码校验不应被同一客户端信号拒绝。
		verifySignals.ScreenCapture = false
		verifySignals.ScreenshotKey = false
		verifySignals.PrintAttempt = false
		verifySignals.PageHidden = false
		verifySignals.FocusLoss = 0
	}
	assessment, err := m.assess(ctx, req.Meta, verifySignals, record.Action, record.Type, phaseVerify, "")
	if err != nil {
		if isLimitError(err) || errors.Is(err, ErrStore) || errors.Is(err, context.Canceled) || errors.Is(err, context.DeadlineExceeded) {
			m.restoreRecord(record, now)
		}
		m.auditSince(ctx, start, AuditEvent{RequestID: req.Meta.RequestID, ChallengeID: id, Action: record.Action, Type: record.Type, Outcome: auditOutcome(err), IP: req.Meta.IP, Country: assessment.Geo.Country, Target: record.Target, Risk: assessment.Score, Reasons: assessment.Reasons, ErrorCode: core.ErrorCode(err)})
		return nil, err
	}
	if !assessment.Allowlisted {
		if err := m.checkGeoBinding(record, assessment); err != nil {
			m.deleteImages(ctx, record)
			m.auditSince(ctx, start, AuditEvent{RequestID: req.Meta.RequestID, ChallengeID: id, Action: record.Action, Type: record.Type, Outcome: AuditBlocked, IP: req.Meta.IP, Country: assessment.Geo.Country, Target: record.Target, Risk: assessment.Score, Reasons: append(assessment.Reasons, "geo_mismatch"), ErrorCode: core.ErrorCode(err)})
			return nil, err
		}
		if record.RequirePoW {
			if err := verifyPoW(record.PoW, req.PoW); err != nil {
				return nil, m.failRecord(ctx, record, now, req.Meta, err, "pow_invalid")
			}
		}
	}
	check := CheckResult{Passed: true}
	if record.Type.IsCode() {
		if !m.verifyCode(record, req.Answer.Code) {
			return nil, m.failRecord(ctx, record, now, req.Meta, ErrInvalidAnswer, "code_invalid")
		}
	} else {
		provider, ok := m.provider(record.Type)
		if !ok {
			m.restoreRecord(record, now)
			m.auditSince(ctx, start, AuditEvent{RequestID: req.Meta.RequestID, ChallengeID: id, Action: record.Action, Type: record.Type, Outcome: AuditError, IP: req.Meta.IP, Target: record.Target, ErrorCode: core.ErrorCode(ErrProvider)})
			return nil, errs.Detail(ErrProvider, "missing provider %q | 缺少生成器 %q", record.Type, record.Type)
		}
		check, err = provider.Verify(ctx, record, req.Answer)
		if err != nil {
			m.restoreRecord(record, now)
			m.auditSince(ctx, start, AuditEvent{RequestID: req.Meta.RequestID, ChallengeID: id, Action: record.Action, Type: record.Type, Outcome: AuditError, IP: req.Meta.IP, Target: record.Target, ErrorCode: core.ErrorCode(ErrProvider)})
			return nil, errs.Wrap(err, ErrProvider)
		}
		if !check.Passed {
			return nil, m.failRecord(ctx, record, now, req.Meta, ErrInvalidAnswer, check.Reasons...)
		}
	}
	// Creation and verification signals overlap heavily. Use the larger base
	// score instead of adding them twice, then add behavior risk once. | 创建期与验证期
	// 信号高度重叠，取较大基础分而不是重复相加，再加入一次行为风险。
	baseRisk := record.Risk
	if assessment.Score > baseRisk {
		baseRisk = assessment.Score
	}
	finalRisk := clampScore(baseRisk + check.BehaviorScore)
	if assessment.Allowlisted {
		finalRisk = 0
	}
	reasons := appendReasons(record.RiskReasons, assessment.Reasons, check.Reasons)
	if finalRisk >= m.opts.RiskRejectScore {
		m.deleteImages(ctx, record)
		m.auditSince(ctx, start, AuditEvent{RequestID: req.Meta.RequestID, ChallengeID: id, Action: record.Action, Type: record.Type, Outcome: AuditBlocked, IP: req.Meta.IP, Country: assessment.Geo.Country, Target: record.Target, Risk: finalRisk, Reasons: reasons, ErrorCode: core.ErrorCode(ErrRiskRejected)})
		return nil, ErrRiskRejected
	}
	m.deleteImages(ctx, record)
	token, err := m.signer.issue(ctx, TokenClaims{
		ChallengeID: record.ID,
		Action:      record.Action,
		Subject:     record.TargetHash,
		Risk:        finalRisk,
	})
	if err != nil {
		m.auditSince(ctx, start, AuditEvent{RequestID: req.Meta.RequestID, ChallengeID: id, Action: record.Action, Type: record.Type, Outcome: AuditError, IP: req.Meta.IP, Target: record.Target, Risk: finalRisk, Reasons: reasons, ErrorCode: core.ErrorCode(err)})
		return nil, err
	}
	m.auditSince(ctx, start, AuditEvent{RequestID: req.Meta.RequestID, ChallengeID: id, Action: record.Action, Type: record.Type, Outcome: AuditPassed, IP: req.Meta.IP, Country: assessment.Geo.Country, Target: record.Target, Risk: finalRisk, Reasons: reasons})
	return &VerifyResult{Token: token, ExpiresIn: secondsCeil(m.signer.ttl), Action: record.Action}, nil
}

// VerifyToken verifies a token without consuming its one-time marker. | VerifyToken 验证令牌但不消费一次性标记。
func (m *Manager) VerifyToken(ctx context.Context, token, action string) (*TokenClaims, error) {
	if err := m.enter(); err != nil {
		return nil, err
	}
	return m.signer.verify(ctx, token, action, false)
}

// ConsumeToken verifies and consumes a token's one-time marker. | ConsumeToken 验证并消费令牌的一次性标记。
func (m *Manager) ConsumeToken(ctx context.Context, token, action string) (*TokenClaims, error) {
	if err := m.enter(); err != nil {
		return nil, err
	}
	return m.signer.verify(ctx, token, action, true)
}

// Image returns a stored challenge image by its public key. | Image 按公开键返回已存储的挑战图片。
func (m *Manager) Image(ctx context.Context, key string) ([]byte, string, bool, error) {
	if err := m.enter(); err != nil {
		return nil, "", false, err
	}
	if key == "" || len(key) > 128 {
		return nil, "", false, nil
	}
	data, mime, ok, err := m.images.Get(ctx, m.opts.KeyPrefix+"img:"+key)
	if err != nil {
		return nil, "", false, errs.Wrap(err, ErrStore)
	}
	return data, mime, ok, nil
}
