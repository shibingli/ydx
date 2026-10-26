package service

import (
	"context"
	"crypto/sha256"
	"errors"
	"net/netip"
	"sort"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/shibingli/ydx/captcha/challenge"
	"github.com/shibingli/ydx/captcha/core"
	"github.com/shibingli/ydx/errs"
	ydlog "github.com/shibingli/ydx/log"
)

// policyLoadTimeout bounds one PolicyProvider refresh. | policyLoadTimeout 限制一次策略提供器刷新。
const policyLoadTimeout = 5 * time.Second

// Manager owns challenge creation, verification, risk control and token issuance. | Manager 负责挑战创建、验证、风险控制与令牌签发。
//
// A Manager is safe for concurrent use. | Manager 可安全并发使用。
type Manager struct {
	store     Store
	images    ImageStore
	geo       GeoResolver
	signer    *tokenSigner
	senders   map[Channel]Sender
	providers map[Type]Provider
	localizer *Localizer
	policy    atomic.Pointer[PolicySnapshot]
	policyOff context.CancelFunc
	limits    Limits
	digestKey []byte
	opts      Options
	policyWG  sync.WaitGroup
	providerM sync.RWMutex
	closed    atomic.Bool
}

// newManager validates options and builds a Manager. | newManager 校验选项并构建 Manager。
func newManager(o Options) (*Manager, error) {
	o = o.Defaults()
	if err := o.Validate(); err != nil {
		return nil, err
	}
	o.Limits = o.Limits.Normalized()
	localizer, err := core.NewLocalizer(o)
	if err != nil {
		return nil, err
	}
	o.DefaultLocale = localizer.DefaultLocale()
	signer, err := newTokenSigner(o, o.Store, o.Now)
	if err != nil {
		return nil, err
	}
	digestKey := append([]byte(nil), o.DigestKey...)
	if len(digestKey) == 0 {
		if len(o.Secret) > 0 {
			digestKey = append([]byte(nil), o.Secret...)
		} else {
			digestKey = deriveDigestKey(signer.keys)
		}
	}
	snapshot, err := core.CompilePolicy(o.Policy)
	if err != nil {
		return nil, err
	}
	if snapshot.HasCountry() && o.GeoResolver == nil {
		return nil, errs.Detail(ErrInvalidOptions, "country policy requires a GeoResolver | 国家策略需要 GeoResolver")
	}
	m := &Manager{
		opts:      o,
		store:     o.Store,
		images:    o.ImageStore,
		signer:    signer,
		geo:       o.GeoResolver,
		limits:    o.Limits,
		digestKey: digestKey,
		senders:   o.Senders,
		providers: make(map[Type]Provider, 8),
		localizer: localizer,
	}
	m.policy.Store(snapshot)
	for _, provider := range o.Providers {
		if provider == nil {
			return nil, errs.Detail(ErrProvider, "nil provider | 生成器为 nil")
		}
		typ := provider.Type()
		if typ == "" || typ.IsCode() {
			return nil, errs.Detail(ErrInvalidType, "provider type %q is not visual | 生成器类型 %q 不是视觉挑战", typ, typ)
		}
		if !m.typeEnabled(typ) {
			m.opts.Types = append(m.opts.Types, typ)
		}
		m.providers[typ] = provider
	}
	for _, provider := range challenge.NewBuiltins(o) {
		if _, exists := m.providers[provider.Type()]; !exists {
			m.providers[provider.Type()] = provider
		}
	}
	if signer.ephemeral {
		m.logWarn("captcha token secret is ephemeral; configure Options.Secret for multi-instance use | 验证码令牌密钥为临时密钥；多机部署请配置 Options.Secret", nil)
	}
	if o.PolicyProvider != nil {
		loadCtx, loadCancel := context.WithTimeout(context.Background(), policyLoadTimeout)
		policy, err := o.PolicyProvider.LoadPolicy(loadCtx)
		loadCancel()
		if err != nil {
			return nil, errs.Wrap(err, ErrStore)
		}
		if err := m.SetPolicy(policy); err != nil {
			return nil, err
		}
		ctx, cancel := context.WithCancel(context.Background())
		m.policyOff = cancel
		m.policyWG.Add(1)
		go m.refreshPolicyLoop(ctx)
	}
	return m, nil
}

// deriveDigestKey derives a stable digest key from the whole key set. | deriveDigestKey 从完整密钥集合派生稳定摘要密钥。
//
// Hashing every key keeps target and cooldown digests stable when KeyID rotates
// but old verification keys remain configured. | 对所有密钥做散列，使 KeyID 轮换但旧
// 验证密钥仍保留时，目标与冷却摘要保持稳定。
func deriveDigestKey(keys map[string][]byte) []byte {
	ids := make([]string, 0, len(keys))
	for id := range keys {
		ids = append(ids, id)
	}
	sort.Strings(ids)
	hash := sha256.New()
	for _, id := range ids {
		_, _ = hash.Write([]byte(id))
		_, _ = hash.Write([]byte{0})
		_, _ = hash.Write(keys[id])
		_, _ = hash.Write([]byte{0})
	}
	return hash.Sum(nil)
}

// NormalizeLocale resolves an arbitrary tag to a supported catalog tag. | NormalizeLocale 把任意标签解析为支持的语言标签。
func (m *Manager) NormalizeLocale(locale string) string {
	if m == nil {
		return ""
	}
	return m.localizer.Normalize(locale)
}

// ErrorMessage localizes a public API error by its stable code. | ErrorMessage 按稳定错误码本地化公开 API 错误。
func (m *Manager) ErrorMessage(locale string, err error) string {
	if err == nil {
		return ""
	}
	code := core.ErrorCode(err)
	if message := m.localizer.Message(locale, core.ErrorMessageKey(code)); message != "" {
		return message
	}
	if message := m.localizer.Message(locale, "error.request_failed"); message != "" {
		return message
	}
	return err.Error()
}

// Locales returns supported locale tags. | Locales 返回支持的语言标签。
func (m *Manager) Locales() []string {
	if m == nil {
		return nil
	}
	return m.localizer.Locales()
}

// DefaultLocale returns the fallback locale tag. | DefaultLocale 返回回退语言标签。
func (m *Manager) DefaultLocale() string {
	if m == nil {
		return ""
	}
	return m.localizer.DefaultLocale()
}

// AllowedOrigins returns the configured browser Origin allowlist. | AllowedOrigins 返回配置的浏览器 Origin 允许列表。
func (m *Manager) AllowedOrigins() []string {
	if m == nil {
		return nil
	}
	return append([]string(nil), m.opts.AllowedOrigins...)
}

// TrustedProxies returns the configured trusted proxy prefixes. | TrustedProxies 返回配置的可信代理前缀。
func (m *Manager) TrustedProxies() []netip.Prefix {
	if m == nil {
		return nil
	}
	return append([]netip.Prefix(nil), m.opts.TrustedProxies...)
}

// Close stops the policy refresh goroutine. | Close 停止策略刷新协程。
func (m *Manager) Close() error {
	if m == nil || m.closed.Swap(true) {
		return nil
	}
	if m.policyOff != nil {
		m.policyOff()
	}
	m.policyWG.Wait()
	return nil
}

// SetPolicy compiles and atomically installs a dynamic policy. | SetPolicy 编译并原子安装动态策略。
func (m *Manager) SetPolicy(p *Policy) error {
	snapshot, err := core.CompilePolicy(core.ClonePolicy(p))
	if err != nil {
		return err
	}
	if snapshot.HasCountry() && m.geo == nil {
		return errs.Detail(ErrInvalidOptions, "country policy requires a GeoResolver | 国家策略需要 GeoResolver")
	}
	m.policy.Store(snapshot)
	return nil
}

// RegisterProvider registers or replaces a visual challenge provider. | RegisterProvider 注册或替换视觉挑战生成器。
func (m *Manager) RegisterProvider(provider Provider) error {
	if provider == nil {
		return ErrProvider
	}
	typ := provider.Type()
	if typ == "" || typ.IsCode() {
		return errs.Detail(ErrInvalidType, "provider type %q is not a visual challenge | 生成器类型 %q 不是视觉挑战", typ, typ)
	}
	m.providerM.Lock()
	m.providers[typ] = provider
	m.providerM.Unlock()
	return nil
}

// checkOrigin applies the manager-level Origin allowlist. | checkOrigin 应用管理器级 Origin 允许列表。
func (m *Manager) checkOrigin(origin string) error {
	if origin == "" || len(m.opts.AllowedOrigins) == 0 {
		return nil
	}
	if !originAllowed(origin, m.opts.AllowedOrigins) {
		return ErrOriginNotAllowed
	}
	return nil
}

// originAllowed reports whether origin is in the allowlist. | originAllowed 报告 origin 是否在允许列表中。
func originAllowed(origin string, allowed []string) bool {
	for _, candidate := range allowed {
		if candidate == "*" || candidate == origin {
			return true
		}
	}
	return false
}

// enter rejects calls after Close. | enter 拒绝 Close 后的调用。
func (m *Manager) enter() error {
	if m == nil {
		return ErrInvalidOptions
	}
	if m.closed.Load() {
		return ErrClosed
	}
	return nil
}

// now returns the configured clock. | now 返回配置的时钟。
func (m *Manager) now() time.Time { return m.opts.Now() }

// provider returns a registered provider. | provider 返回已注册的生成器。
func (m *Manager) provider(typ Type) (Provider, bool) {
	m.providerM.RLock()
	p, ok := m.providers[typ]
	m.providerM.RUnlock()
	return p, ok
}

// typeEnabled reports whether typ is in the configured visual type list. | typeEnabled 报告 typ 是否在配置的视觉类型列表中。
func (m *Manager) typeEnabled(typ Type) bool {
	for _, enabled := range m.opts.Types {
		if enabled == typ {
			return true
		}
	}
	return false
}

// loadPolicy performs one policy refresh. | loadPolicy 执行一次策略刷新。
func (m *Manager) loadPolicy(ctx context.Context) {
	p, err := m.opts.PolicyProvider.LoadPolicy(ctx)
	if err != nil {
		m.logWarn("captcha policy load failed | 验证码策略加载失败", err)
		return
	}
	if err := m.SetPolicy(p); err != nil {
		m.logWarn("captcha policy rejected | 验证码策略被拒绝", err)
	}
}

// refreshPolicyLoop refreshes the dynamic policy until Close. | refreshPolicyLoop 刷新动态策略直到 Close。
func (m *Manager) refreshPolicyLoop(parent context.Context) {
	defer m.policyWG.Done()
	ticker := time.NewTicker(m.opts.PolicyRefresh)
	defer ticker.Stop()
	for {
		select {
		case <-parent.Done():
			return
		case <-ticker.C:
			ctx, cancel := context.WithTimeout(parent, policyLoadTimeout)
			m.loadPolicy(ctx)
			cancel()
		}
	}
}

// audit emits one event when a sink is configured. | audit 在配置了接收器时发出一个事件。
func (m *Manager) audit(ctx context.Context, event AuditEvent) {
	if m.opts.Audit == nil {
		return
	}
	if event.Timestamp == 0 {
		event.Timestamp = m.now().UnixMilli()
	}
	event.Reasons = append([]string(nil), event.Reasons...)
	if err := m.opts.Audit.WriteAudit(ctx, event); err != nil {
		m.logWarn("captcha audit sink failed | 验证码审计接收器故障", err)
	}
}

// auditSince records an event with the elapsed server handling time. | auditSince 记录带服务端处理耗时的事件。
func (m *Manager) auditSince(ctx context.Context, start time.Time, event AuditEvent) {
	if !start.IsZero() {
		if elapsed := m.now().Sub(start); elapsed > 0 {
			event.DurationMS = elapsed.Milliseconds()
		}
	}
	m.audit(ctx, event)
}

// logWarn records an operational warning without ever failing the request. | logWarn 记录运行告警且绝不使请求失败。
func (m *Manager) logWarn(message string, err error) {
	if m.opts.Logger == nil {
		return
	}
	if err == nil {
		m.opts.Logger.Warn(message)
		return
	}
	m.opts.Logger.Warn(message, ydlog.Str("error", err.Error()))
}

// isLimitError reports whether err is a token-bucket rejection. | isLimitError 报告 err 是否为令牌桶拒绝。
func isLimitError(err error) bool {
	var target *LimitError
	return errors.As(err, &target)
}

// auditOutcome maps an error to an audit outcome. | auditOutcome 把错误映射为审计结果。
func auditOutcome(err error) string {
	switch {
	case isLimitError(err):
		return AuditRateLimited
	case errors.Is(err, ErrForbidden), errors.Is(err, ErrGeoBlocked), errors.Is(err, ErrGeoMismatch), errors.Is(err, ErrRiskRejected), errors.Is(err, ErrCaptureDetected), errors.Is(err, ErrFallbackDisabled), errors.Is(err, ErrUnsupportedMediaType):
		return AuditBlocked
	default:
		return AuditError
	}
}

// validateGenerated checks provider output before it reaches the store. | validateGenerated 在进入存储前检查生成器输出。
func validateGenerated(g *Generated) error {
	if g == nil || strings.TrimSpace(g.Prompt.Text) == "" {
		return errs.Detail(ErrProvider, "empty prompt | 空提示")
	}
	if len(g.Images) == 0 || len(g.Images) > 4 {
		return errs.Detail(ErrProvider, "image count %d outside [1,4] | 图片数量 %d 超出 [1,4]", len(g.Images), len(g.Images))
	}
	if len(g.Answer) == 0 {
		return errs.Detail(ErrProvider, "empty answer state | 空答案状态")
	}
	names := make(map[string]struct{}, len(g.Images))
	var total int
	for i := range g.Images {
		img := &g.Images[i]
		if img.Name == "" || img.Width <= 0 || img.Height <= 0 || len(img.Data) == 0 {
			return errs.Detail(ErrProvider, "invalid image %d | 非法图片 %d", i, i)
		}
		if _, exists := names[img.Name]; exists {
			return errs.Detail(ErrProvider, "duplicate image %q | 重复图片 %q", img.Name, img.Name)
		}
		names[img.Name] = struct{}{}
		if !strings.HasPrefix(img.MIME, "image/") {
			return errs.Detail(ErrProvider, "invalid MIME %q | 非法 MIME %q", img.MIME, img.MIME)
		}
		total += len(img.Data)
		if total > 4<<20 {
			return errs.Detail(ErrProvider, "images exceed 4 MiB | 图片超过 4 MiB")
		}
	}
	return nil
}

// appendReasons returns a de-duplicated union of reason lists. | appendReasons 返回去重后的原因并集。
func appendReasons(lists ...[]string) []string {
	seen := make(map[string]struct{})
	var out []string
	for _, list := range lists {
		for _, reason := range list {
			if reason == "" {
				continue
			}
			if _, ok := seen[reason]; ok {
				continue
			}
			seen[reason] = struct{}{}
			out = append(out, reason)
		}
	}
	sort.Strings(out)
	return out
}

// secondsCeil converts a duration to whole seconds, rounding up. | secondsCeil 把时长向上取整为秒。
func secondsCeil(d time.Duration) int64 {
	if d <= 0 {
		return 0
	}
	return int64((d + time.Second - 1) / time.Second)
}
