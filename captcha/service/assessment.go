package service

import (
	"context"
	"net/netip"
	"strings"
	"time"

	"github.com/shibingli/ydx/captcha/core"
	"github.com/shibingli/ydx/errs"
)

// riskPhase selects the rate-limit bucket family. | riskPhase 选择限流桶族。
type riskPhase string

const (
	phaseCreate riskPhase = "create"
	phaseVerify riskPhase = "verify"
	phaseSend   riskPhase = "send"
)

// Assessment is the outcome of the risk layer. | Assessment 是风险层的评估结果。
type Assessment struct {
	// Reasons lists stable machine-readable reason codes. | Reasons 列出稳定的机器可读原因码。
	Reasons []string `json:"reasons,omitempty"`
	// Geo is the resolved location, possibly zero. | Geo 是解析出的位置，可能为零值。
	Geo Geo `json:"geo,omitempty"`
	// Score is the clamped 0-100 risk score. | Score 是限制在 0-100 的风险分。
	Score int `json:"score"`
	// Allowlisted reports that an allow rule bypassed risk checks. | Allowlisted 报告允许规则已跳过风险检查。
	Allowlisted bool `json:"allowlisted,omitempty"`
}

// assess evaluates policy, geo, rate limits and client hints. | assess 评估策略、地理、限流与客户端提示。
func (m *Manager) assess(ctx context.Context, meta Meta, signals Signals, action string, typ Type, phase riskPhase, target string) (Assessment, error) {
	a := Assessment{}
	if err := ctx.Err(); err != nil {
		return a, err
	}
	ipText := strings.TrimSpace(meta.IP)
	addr, addrErr := netip.ParseAddr(ipText)
	if addrErr != nil {
		a.add(5, "ip_unknown")
	}
	snapshot := m.policy.Load()
	if m.geo != nil {
		geo, err := m.geo.Resolve(ctx, ipText)
		if err != nil {
			a.add(10, "geo_unavailable")
			m.logWarn("captcha geo resolver failed | 验证码地理解析失败", err)
			if snapshot.HasCountry() {
				return a, ErrGeoBlocked
			}
		} else {
			a.Geo = core.NormalizeGeo(geo)
		}
	}
	decision := snapshot.Evaluate(addr, a.Geo.Country, action, typ)
	if snapshot.CountryDeny() && !decision.Allowed && a.Geo.Country == "" {
		return a, ErrGeoBlocked
	}
	if decision.Denied {
		if decision.DeniedCountry {
			return a, ErrGeoBlocked
		}
		return a, ErrForbidden
	}
	if decision.Allowed {
		a.Allowlisted = true
		a.Reasons = append(a.Reasons, "allowlisted")
		return a, nil
	}
	if err := m.checkRate(ctx, ipText, addr, target, phase, &a); err != nil {
		return a, err
	}
	if m.opts.CaptureMode == CaptureReject && (signals.ScreenCapture || signals.ScreenshotKey || signals.PrintAttempt) {
		a.add(100, "capture_detected")
		return a, ErrCaptureDetected
	}
	score, reasons := scoreSignals(meta, signals, m.opts.CaptureMode)
	for _, reason := range reasons {
		a.Reasons = append(a.Reasons, reason)
	}
	a.Score += score
	a.clamp()
	return a, nil
}

// checkRate applies the IP and target token buckets. | checkRate 应用 IP 与目标令牌桶。
func (m *Manager) checkRate(ctx context.Context, ipText string, addr netip.Addr, target string, phase riskPhase, a *Assessment) error {
	ipKey := ipText
	if addr.IsValid() {
		ipKey = addr.String()
	}
	if ipKey == "" {
		ipKey = "unknown"
	}
	var rule Rate
	var key string
	switch phase {
	case phaseCreate:
		rule = m.limits.Create
		key = m.opts.KeyPrefix + "create:ip:" + ipKey
	case phaseVerify:
		rule = m.limits.Verify
		key = m.opts.KeyPrefix + "verify:ip:" + ipKey
	case phaseSend:
		rule = m.limits.Send
		key = m.opts.KeyPrefix + "send:ip:" + ipKey
	default:
		return nil
	}
	if err := m.allowRate(ctx, key, rule, a); err != nil {
		return err
	}
	if phase == phaseSend && target != "" {
		targetRule := m.limits.SendTarget
		targetKey := m.opts.KeyPrefix + "send:target:" + m.keyedDigest("target:"+target)
		if err := m.allowRate(ctx, targetKey, targetRule, a); err != nil {
			return err
		}
	}
	return nil
}

// allowRate applies one token bucket and records backend degradation. | allowRate 应用一个令牌桶并记录后端降级。
func (m *Manager) allowRate(ctx context.Context, key string, rule Rate, a *Assessment) error {
	dec, err := m.limits.Store.Allow(ctx, key, rule.Rate, rule.Burst)
	if err != nil {
		if m.limits.FailClosed {
			return errs.Wrap(err, ErrStore)
		}
		a.add(10, "limiter_unavailable")
		m.logWarn("captcha rate-limit store failed | 验证码限流存储故障", err)
		return nil
	}
	if dec.Allowed {
		return nil
	}
	retry := dec.RetryAfter
	if retry <= 0 {
		retry = time.Second
	}
	return &LimitError{RetryAfter: retry}
}

// checkGeoBinding enforces the short-term location contract. | checkGeoBinding 执行短期地理约束。
func (m *Manager) checkGeoBinding(record *Record, current Assessment) error {
	if !m.opts.GeoBind {
		return nil
	}
	if record.Geo.Country == "" && !record.Geo.HasCoordinates {
		return nil
	}
	if current.Geo.Country == "" && !current.Geo.HasCoordinates {
		return ErrGeoMismatch
	}
	if !core.SameCountry(record.Geo, current.Geo) {
		return ErrGeoMismatch
	}
	if record.Geo.HasCoordinates && current.Geo.HasCoordinates {
		elapsed := m.now().Sub(record.GeoAt)
		if elapsed < time.Second {
			elapsed = time.Second
		}
		if elapsed > m.opts.GeoTTL {
			elapsed = m.opts.GeoTTL
		}
		allowed := m.opts.GeoMaxDistanceKM
		bySpeed := m.opts.GeoMaxSpeedKMH * elapsed.Hours()
		if bySpeed > allowed {
			allowed = bySpeed
		}
		if core.DistanceKM(record.Geo, current.Geo) > allowed {
			return ErrGeoMismatch
		}
	}
	return nil
}

// add appends a reason and score with clamping. | add 追加原因与分数并限制范围。
func (a *Assessment) add(score int, reason string) {
	a.Score += score
	a.Reasons = append(a.Reasons, reason)
	a.clamp()
}

// clamp limits the score to 0-100. | clamp 把分数限制在 0-100。
func (a *Assessment) clamp() {
	if a.Score < 0 {
		a.Score = 0
	}
	if a.Score > 100 {
		a.Score = 100
	}
}

// scoreSignals converts client hints into risk points. | scoreSignals 把客户端提示转换为风险分。
func scoreSignals(meta Meta, s Signals, captureMode CaptureMode) (int, []string) {
	score := 0
	var reasons []string
	add := func(points int, reason string) {
		score += points
		reasons = append(reasons, reason)
	}
	if captureMode != CaptureOff {
		if s.ScreenCapture {
			add(100, "screen_capture")
		}
		if s.PrintAttempt {
			add(80, "print_attempt")
		}
		if s.ScreenshotKey {
			add(60, "screenshot_key")
		}
		if s.PageHidden {
			add(20, "capture_page_hidden")
		}
		if s.FocusLoss > 0 {
			loss := s.FocusLoss
			if loss > 5 {
				loss = 5
			}
			add(loss*5, "focus_loss")
		}
	}
	if s.WebDriver {
		add(50, "webdriver")
	}
	if s.Headless {
		add(30, "headless_hint")
	}
	if meta.UserAgent != "" && s.UserAgent != "" && meta.UserAgent != s.UserAgent {
		add(20, "ua_mismatch")
	}
	ua := strings.ToLower(meta.UserAgent)
	mobile := strings.Contains(ua, "mobile") || strings.Contains(ua, "android") || strings.Contains(ua, "iphone") || strings.Contains(ua, "ipad")
	if mobile && !s.Touch {
		add(20, "mobile_without_touch")
	}
	if s.ScreenWidth <= 0 || s.ScreenHeight <= 0 {
		add(10, "screen_missing")
	}
	if s.Timezone == "" {
		add(10, "timezone_missing")
	}
	if s.Language == "" {
		add(5, "language_missing")
	}
	if s.Platform == "" {
		add(5, "platform_missing")
	}
	if !s.CookieEnabled {
		add(5, "cookies_disabled")
	}
	if s.Plugins == 0 {
		add(5, "no_plugins")
	}
	if s.Visibility == "hidden" {
		add(5, "page_hidden")
	}
	if score > 100 {
		score = 100
	}
	return score, reasons
}

// clampScore limits an arbitrary score to 0-100. | clampScore 把任意分数限制在 0-100。
func clampScore(score int) int {
	if score < 0 {
		return 0
	}
	if score > 100 {
		return 100
	}
	return score
}
