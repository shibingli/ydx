package core

import (
	"net/netip"
	"strings"
	"time"

	"github.com/shibingli/ydx/errs"
	ydlog "github.com/shibingli/ydx/log"
	"github.com/shibingli/ydx/middleware/ratelimit"
)

// Default manager values. | 管理器默认值。
const (
	// DefaultChallengeTTL is the default challenge lifetime. | DefaultChallengeTTL 是默认挑战存活时间。
	DefaultChallengeTTL = 2 * time.Minute
	// DefaultTokenTTL is the default verification-token lifetime. | DefaultTokenTTL 是默认验证令牌存活时间。
	DefaultTokenTTL = 5 * time.Minute
	// DefaultCooldown is the default code resend delay. | DefaultCooldown 是默认验证码重发间隔。
	DefaultCooldown = 60 * time.Second
	// DefaultMaxAttempts is the default per-challenge attempt budget. | DefaultMaxAttempts 是默认单挑战尝试次数。
	DefaultMaxAttempts = 3
	// DefaultTextLength is the default number of characters in a text challenge. | DefaultTextLength 是文本挑战的默认字符数。
	DefaultTextLength = 4
	// DefaultWidth is the default challenge image width. | DefaultWidth 是默认挑战图片宽度。
	DefaultWidth = 320
	// DefaultHeight is the default challenge image height. | DefaultHeight 是默认挑战图片高度。
	DefaultHeight = 200
	// DefaultPolicyRefresh is the default dynamic-policy refresh interval. | DefaultPolicyRefresh 是动态策略默认刷新间隔。
	DefaultPolicyRefresh = 30 * time.Second
	// DefaultGeoTTL is the default short-term geolocation binding window. | DefaultGeoTTL 是默认短期地理绑定窗口。
	DefaultGeoTTL = 2 * time.Minute
	// DefaultGeoMaxDistanceKM is the default allowed displacement inside GeoTTL. | DefaultGeoMaxDistanceKM 是 GeoTTL 内允许的默认位移。
	DefaultGeoMaxDistanceKM = 100
	// DefaultGeoMaxSpeedKMH is the default implied travel-speed ceiling. | DefaultGeoMaxSpeedKMH 是默认隐含移动速度上限。
	DefaultGeoMaxSpeedKMH = 900
	// DefaultRiskRejectScore is the risk score at which a correct answer is still rejected. | DefaultRiskRejectScore 是即使答案正确也会拒绝的风险分。
	DefaultRiskRejectScore = 90
	// DefaultKeyPrefix separates captcha keys in a shared Redis. | DefaultKeyPrefix 在共享 Redis 中隔离验证码键。
	DefaultKeyPrefix = "yd:captcha:"
)

// PoWMode selects when proof of work is required. | PoWMode 选择何时要求工作量证明。
type PoWMode string

// Supported proof-of-work modes. | 支持的工作量证明模式。
const (
	// PoWOff disables proof of work. | PoWOff 关闭工作量证明。
	PoWOff PoWMode = "off"
	// PoWAdaptive requires proof of work above the risk threshold. | PoWAdaptive 在风险阈值以上要求工作量证明。
	PoWAdaptive PoWMode = "adaptive"
	// PoWAlways requires proof of work for every visual challenge. | PoWAlways 对每个视觉挑战都要求工作量证明。
	PoWAlways PoWMode = "always"
)

// CaptureMode selects how client-reported capture signals are handled. | CaptureMode 选择如何处理客户端上报的录屏/截屏信号。
type CaptureMode string

// Supported capture policies. | 支持的录屏/截屏策略。
const (
	// CaptureOff ignores capture signals. | CaptureOff 忽略录屏/截屏信号。
	CaptureOff CaptureMode = "off"
	// CaptureRisk adds capture signals to the risk score. | CaptureRisk 把录屏/截屏信号计入风险分。
	CaptureRisk CaptureMode = "risk"
	// CaptureReject rejects explicit screen-capture, screenshot and print signals. | CaptureReject 直接拒绝明确的录屏、截屏与打印信号。
	CaptureReject CaptureMode = "reject"
)

// FallbackOptions enables SMS or email downgrade after capture detection. | FallbackOptions 启用录屏/截屏检测后的短信或邮件降级。
type FallbackOptions struct {
	// Channel is the allowed fallback channel. | Channel 是允许的降级通道。
	Channel Channel
	// Enabled allows fallback SendCode requests. | Enabled 允许降级 SendCode 请求。
	Enabled bool
}

// PoWOptions configures SHA-256 proof of work. | PoWOptions 配置 SHA-256 工作量证明。
type PoWOptions struct {
	// Mode selects off, adaptive or always. | Mode 选择 off、adaptive 或 always。
	Mode PoWMode
	// Difficulty is the base number of leading zero bits. | Difficulty 是基础前导零位数。
	Difficulty int
	// MaxDifficulty caps the adaptive difficulty. | MaxDifficulty 限制自适应难度上限。
	MaxDifficulty int
	// Threshold is the risk score at which adaptive mode enables PoW. | Threshold 是自适应模式启用 PoW 的风险分阈值。
	Threshold int
}

// Rate is one token-bucket rule. | Rate 是一条令牌桶规则。
type Rate struct {
	// Rate is tokens replenished per second. | Rate 是每秒补充的令牌数。
	Rate float64
	// Burst is the bucket capacity. | Burst 是桶容量。
	Burst int
}

// Limits configures the captcha token buckets. | Limits 配置验证码令牌桶。
type Limits struct {
	// Store is the limiting backend; nil means a private memory store. | Store 是限流后端；nil 表示私有内存存储。
	Store ratelimit.LimitStore
	// Create limits challenge creation per client IP. | Create 限制每客户端 IP 的挑战创建。
	Create Rate
	// Verify limits answer submissions per client IP. | Verify 限制每客户端 IP 的答案提交。
	Verify Rate
	// Send limits code sends per client IP. | Send 限制每客户端 IP 的验证码发送。
	Send Rate
	// SendTarget limits code sends per phone number or email address. | SendTarget 限制每手机号或邮箱的验证码发送。
	SendTarget Rate
	// FailClosed rejects on limiter store errors instead of failing open. | FailClosed 在限流存储故障时拒绝而不是放行。
	FailClosed bool
}

// Options configures a Manager. | Options 配置 Manager。
type Options struct {
	// Store is the session backend; nil means a private MemoryStore. | Store 是会话后端；nil 表示私有 MemoryStore。
	Store Store
	// ImageStore is the image backend; nil means a private MemoryImageStore. | ImageStore 是图片后端；nil 表示私有 MemoryImageStore。
	ImageStore ImageStore
	// Audit receives structured events; nil disables auditing. | Audit 接收结构化事件；nil 关闭审计。
	Audit AuditSink
	// PolicyProvider refreshes the policy snapshot when non-nil. | PolicyProvider 非空时定期刷新策略快照。
	PolicyProvider PolicyProvider
	// GeoResolver maps an IP address to a coarse location. | GeoResolver 把 IP 映射到粗略位置。
	GeoResolver GeoResolver
	// Logger receives operational warnings; nil means ydlog.Default(). | Logger 接收运行告警；nil 表示 ydlog.Default()。
	Logger *ydlog.Logger
	// Policy is the initial dynamic allow/deny snapshot. | Policy 是初始动态黑白名单快照。
	Policy *Policy
	// Senders registers code senders by channel. | Senders 按通道注册验证码发送器。
	Senders map[Channel]Sender
	// Keys supplies additional verification keys for rotation. | Keys 提供用于轮换的额外验证密钥。
	Keys map[string][]byte
	// Now is the clock; nil means time.Now. | Now 是时钟；nil 表示 time.Now。
	Now func() time.Time
	// KeyID is the active signing key identifier; empty means k1. | KeyID 是活动签名 key 标识；空值为 k1。
	KeyID string
	// Issuer is embedded in and checked against tokens. | Issuer 写入令牌并参与校验。
	Issuer string
	// DefaultLocale is the fallback prompt language; empty means zh-CN. | DefaultLocale 是回退提示语言；空值为 zh-CN。
	DefaultLocale string
	// Messages overrides or adds locale catalogs keyed by BCP 47 tag. | Messages 按 BCP 47 标签覆盖或新增语言目录。
	Messages map[string]map[string]string
	// Translate optionally resolves messages through a host i18n bundle. | Translate 可选地通过宿主 i18n 目录解析消息。
	//
	// It receives the normalized locale, a key such as "prompt.text" and
	// positional arguments. Return an empty string or the key itself to fall
	// back to the built-in catalog. | 它接收规范化语言、诸如 "prompt.text" 的键
	// 与位置参数；返回空字符串或键本身表示回退到内置目录。
	Translate func(locale, key string, args ...string) string
	// KeyPrefix isolates captcha keys in a shared store. | KeyPrefix 在共享存储中隔离验证码键。
	KeyPrefix string
	// Secret is the HMAC signing secret. | Secret 是 HMAC 签名密钥。
	Secret []byte
	// DigestKey is a stable key for target, cooldown and code digests; empty derives one from Secret. | DigestKey 是目标、冷却与验证码摘要的稳定密钥；空值从 Secret 派生。
	DigestKey []byte
	// Types enables visual challenge types; nil means all built-in visual types. | Types 启用视觉挑战类型；nil 表示全部内置视觉类型。
	Types []Type
	// Providers registers custom providers during construction. | Providers 在构造期间注册自定义生成器。
	Providers []Provider
	// AllowedOrigins is the browser Origin allowlist; empty disables the check. | AllowedOrigins 是浏览器 Origin 允许列表；空值关闭检查。
	AllowedOrigins []string
	// TrustedProxies lists reverse proxies allowed to supply client IP headers. | TrustedProxies 列出允许提供客户端 IP 头的反向代理。
	TrustedProxies []netip.Prefix
	// PoW configures proof of work. | PoW 配置工作量证明。
	PoW PoWOptions
	// CaptureMode handles client-reported screen-capture signals; default risk. | CaptureMode 处理客户端上报的录屏/截屏信号；默认 risk。
	CaptureMode CaptureMode
	// Fallback enables SMS/email verification after a capture signal. | Fallback 启用录屏/截屏信号后的短信/邮件验证。
	Fallback FallbackOptions
	// Limits configures the captcha token buckets. | Limits 配置验证码令牌桶。
	Limits Limits
	// PolicyRefresh is the minimum delay between policy refreshes. | PolicyRefresh 是策略两次刷新之间的最短间隔。
	PolicyRefresh time.Duration
	// GeoTTL is the short-term location binding window. | GeoTTL 是短期地理绑定窗口。
	GeoTTL time.Duration
	// GeoMaxDistanceKM is the allowed displacement within GeoTTL. | GeoMaxDistanceKM 是 GeoTTL 内允许的位移。
	GeoMaxDistanceKM float64
	// GeoMaxSpeedKMH is the implied travel-speed ceiling. | GeoMaxSpeedKMH 是隐含移动速度上限。
	GeoMaxSpeedKMH float64
	// ChallengeTTL is the challenge lifetime. | ChallengeTTL 是挑战存活时间。
	ChallengeTTL time.Duration
	// TokenTTL is the verification-token lifetime. | TokenTTL 是验证令牌存活时间。
	TokenTTL time.Duration
	// Cooldown is the minimum delay between code sends to one target. | Cooldown 是同一目标两次发送验证码的最短间隔。
	Cooldown time.Duration
	// SMSDefaultCountryCode is prepended to national phone numbers; default 86. | SMSDefaultCountryCode 会加到国内手机号前；默认 86。
	SMSDefaultCountryCode string
	// RiskRejectScore rejects even a correct answer at or above this score. | RiskRejectScore 在风险分达到该值时连正确答案也拒绝。
	RiskRejectScore int
	// MaxAttempts is the per-challenge attempt budget. | MaxAttempts 是单挑战尝试次数。
	MaxAttempts int
	// TextLength is the number of characters in a text challenge. | TextLength 是文本挑战字符数。
	TextLength int
	// Width is the challenge image width. | Width 是挑战图片宽度。
	Width int
	// Height is the challenge image height. | Height 是挑战图片高度。
	Height int
	// GeoBind rejects verification when the short-term location changes. | GeoBind 在地理位置短期变化时拒绝验证。
	GeoBind bool
	// TokenReusable allows ConsumeToken to accept a token more than once; default false. | TokenReusable 允许 ConsumeToken 多次接受同一令牌；默认 false。
	TokenReusable bool
}

// defaults fills every zero option with a safe default. | defaults 用安全默认值填充所有零值选项。
func (o Options) Defaults() Options {
	if o.Store == nil {
		o.Store = NewMemoryStore()
	}
	if o.ImageStore == nil {
		o.ImageStore = NewMemoryImageStore()
	}
	if o.Logger == nil {
		o.Logger = ydlog.Default()
	}
	if o.PolicyRefresh <= 0 {
		o.PolicyRefresh = DefaultPolicyRefresh
	}
	if o.GeoTTL <= 0 {
		o.GeoTTL = DefaultGeoTTL
	}
	if o.GeoMaxDistanceKM <= 0 {
		o.GeoMaxDistanceKM = DefaultGeoMaxDistanceKM
	}
	if o.GeoMaxSpeedKMH <= 0 {
		o.GeoMaxSpeedKMH = DefaultGeoMaxSpeedKMH
	}
	if o.ChallengeTTL <= 0 {
		o.ChallengeTTL = DefaultChallengeTTL
	}
	if o.TokenTTL <= 0 {
		o.TokenTTL = DefaultTokenTTL
	}
	if o.Cooldown <= 0 {
		o.Cooldown = DefaultCooldown
	}
	if o.DefaultLocale == "" {
		o.DefaultLocale = defaultMessageLocale
	} else {
		o.DefaultLocale = canonicalLocaleTag(o.DefaultLocale)
	}
	if len(o.DigestKey) > 0 {
		o.DigestKey = append([]byte(nil), o.DigestKey...)
	}
	if len(o.Messages) > 0 {
		messages := make(map[string]map[string]string, len(o.Messages))
		for locale, catalog := range o.Messages {
			copied := make(map[string]string, len(catalog))
			for key, value := range catalog {
				copied[key] = value
			}
			messages[locale] = copied
		}
		o.Messages = messages
	}
	o.SMSDefaultCountryCode = strings.TrimPrefix(strings.TrimPrefix(strings.TrimSpace(o.SMSDefaultCountryCode), "+"), "00")
	if o.SMSDefaultCountryCode == "" {
		o.SMSDefaultCountryCode = "86"
	}
	if o.RiskRejectScore <= 0 {
		o.RiskRejectScore = DefaultRiskRejectScore
	}
	if o.KeyPrefix == "" {
		o.KeyPrefix = DefaultKeyPrefix
	}
	if o.MaxAttempts <= 0 {
		o.MaxAttempts = DefaultMaxAttempts
	}
	if o.TextLength <= 0 {
		o.TextLength = DefaultTextLength
	}
	if o.Width <= 0 {
		o.Width = DefaultWidth
	}
	if o.Height <= 0 {
		o.Height = DefaultHeight
	}
	if o.Types == nil {
		o.Types = []Type{TypeText, TypeClickText, TypeClickIcon, TypeSlide, TypeScratch, TypeSemantic, TypeRotate}
	}
	if o.PoW.Mode == "" {
		o.PoW.Mode = PoWAdaptive
	}
	if o.CaptureMode == "" {
		o.CaptureMode = CaptureRisk
	}
	if o.PoW.Difficulty <= 0 {
		o.PoW.Difficulty = 16
	}
	if o.PoW.MaxDifficulty <= 0 {
		o.PoW.MaxDifficulty = 22
	}
	if o.PoW.Threshold <= 0 {
		o.PoW.Threshold = 50
	}
	if o.Now == nil {
		o.Now = time.Now
	}
	if len(o.Senders) > 0 {
		senders := make(map[Channel]Sender, len(o.Senders))
		for channel, sender := range o.Senders {
			senders[channel] = sender
		}
		o.Senders = senders
	}
	o.AllowedOrigins = normalizeOrigins(o.AllowedOrigins)
	o.TrustedProxies = append([]netip.Prefix(nil), o.TrustedProxies...)
	return o
}

// validate checks normalized options. | validate 校验归一化后的选项。
func (o Options) Validate() error {
	if o.Width < 120 || o.Width > 1024 {
		return errs.Detail(ErrInvalidOptions, "width %d outside [120,1024] | 宽度 %d 超出 [120,1024]", o.Width, o.Width)
	}
	if o.Height < 80 || o.Height > 768 {
		return errs.Detail(ErrInvalidOptions, "height %d outside [80,768] | 高度 %d 超出 [80,768]", o.Height, o.Height)
	}
	if o.TextLength < 3 || o.TextLength > 8 {
		return errs.Detail(ErrInvalidOptions, "text length %d outside [3,8] | 文本长度 %d 超出 [3,8]", o.TextLength, o.TextLength)
	}
	if o.MaxAttempts > 10 {
		return errs.Detail(ErrInvalidOptions, "max attempts %d exceeds 10 | 最大尝试次数 %d 超过 10", o.MaxAttempts, o.MaxAttempts)
	}
	if !validLocaleTag(o.DefaultLocale) {
		return errs.Detail(ErrInvalidOptions, "invalid default locale %q | 非法默认语言 %q", o.DefaultLocale, o.DefaultLocale)
	}
	if len(o.DigestKey) > 0 && len(o.DigestKey) < 16 {
		return errs.Detail(ErrInvalidOptions, "digest key is shorter than 16 bytes | 摘要密钥短于 16 字节")
	}
	countryCode := o.SMSDefaultCountryCode
	if countryCode == "" || len(countryCode) > 3 || countryCode[0] == '0' {
		return errs.Detail(ErrInvalidOptions, "invalid SMS default country code %q | 非法短信默认国家码 %q", o.SMSDefaultCountryCode, o.SMSDefaultCountryCode)
	}
	for i := 0; i < len(countryCode); i++ {
		if countryCode[i] < '0' || countryCode[i] > '9' {
			return errs.Detail(ErrInvalidOptions, "invalid SMS default country code %q | 非法短信默认国家码 %q", o.SMSDefaultCountryCode, o.SMSDefaultCountryCode)
		}
	}
	if o.RiskRejectScore < 50 || o.RiskRejectScore > 100 {
		return errs.Detail(ErrInvalidOptions, "risk reject score %d outside [50,100] | 风险拒绝分 %d 超出 [50,100]", o.RiskRejectScore, o.RiskRejectScore)
	}
	if strings.ContainsAny(o.KeyPrefix, "\r\n") {
		return errs.Detail(ErrInvalidOptions, "key prefix contains a control line break | key 前缀包含换行控制符")
	}
	switch o.PoW.Mode {
	case PoWOff, PoWAdaptive, PoWAlways:
	default:
		return errs.Detail(ErrInvalidOptions, "unknown proof-of-work mode %q | 未知工作量证明模式 %q", o.PoW.Mode, o.PoW.Mode)
	}
	switch o.CaptureMode {
	case CaptureOff, CaptureRisk, CaptureReject:
	default:
		return errs.Detail(ErrInvalidOptions, "unknown capture mode %q | 未知录屏/截屏策略 %q", o.CaptureMode, o.CaptureMode)
	}
	if o.Fallback.Enabled {
		if !o.Fallback.Channel.Valid() {
			return errs.Detail(ErrInvalidOptions, "fallback requires a valid sms or email channel | 降级需要合法的短信或邮件通道")
		}
		if o.Senders[o.Fallback.Channel] == nil {
			return errs.Detail(ErrNoSender, "fallback channel %q has no sender | 降级通道 %q 未配置发送器", o.Fallback.Channel, o.Fallback.Channel)
		}
	}
	if o.PoW.Difficulty < 8 || o.PoW.Difficulty > 28 {
		return errs.Detail(ErrInvalidOptions, "proof-of-work difficulty %d outside [8,28] | 工作量证明难度 %d 超出 [8,28]", o.PoW.Difficulty, o.PoW.Difficulty)
	}
	if o.PoW.MaxDifficulty < o.PoW.Difficulty || o.PoW.MaxDifficulty > 28 {
		return errs.Detail(ErrInvalidOptions, "proof-of-work max difficulty %d outside [%d,28] | 工作量证明最大难度 %d 超出 [%d,28]", o.PoW.MaxDifficulty, o.PoW.Difficulty, o.PoW.MaxDifficulty, o.PoW.Difficulty)
	}
	if o.PoW.Threshold > 100 {
		return errs.Detail(ErrInvalidOptions, "proof-of-work threshold %d exceeds 100 | 工作量证明阈值 %d 超过 100", o.PoW.Threshold, o.PoW.Threshold)
	}
	if o.GeoBind && o.GeoResolver == nil {
		return errs.Detail(ErrInvalidOptions, "geo binding requires a resolver | 地理绑定需要解析器")
	}
	if len(o.Types) == 0 {
		return errs.Detail(ErrInvalidOptions, "no visual types enabled | 未启用任何视觉类型")
	}
	for _, t := range o.Types {
		if t == "" || t.code() {
			return errs.Detail(ErrInvalidType, "type %q cannot be a visual challenge | 类型 %q 不能作为视觉挑战", t, t)
		}
	}
	for channel, sender := range o.Senders {
		if !channel.Valid() {
			return errs.Detail(ErrInvalidOptions, "invalid sender channel %q | 非法发送通道 %q", channel, channel)
		}
		if sender == nil {
			return errs.Detail(ErrInvalidOptions, "nil sender for channel %q | 通道 %q 的发送器为 nil", channel, channel)
		}
		if sender.Channel() != channel {
			return errs.Detail(ErrInvalidOptions, "sender channel mismatch for %q | 通道 %q 的发送器通道不匹配", channel, channel)
		}
	}
	limits := o.Limits.Normalized()
	if limits.Store == nil {
		return errs.Detail(ErrInvalidOptions, "nil rate-limit store | 限流存储为 nil")
	}
	o.Limits = limits
	return nil
}

// normalized returns Limits with defaults applied. | normalized 返回应用默认值后的 Limits。
func (l Limits) Normalized() Limits {
	if l.Store == nil {
		l.Store = ratelimit.NewMemoryStore(time.Minute)
	}
	l.Create = rateOrDefault(l.Create, Rate{Rate: 2, Burst: 20})
	l.Verify = rateOrDefault(l.Verify, Rate{Rate: 5, Burst: 40})
	l.Send = rateOrDefault(l.Send, Rate{Rate: 0.02, Burst: 3})
	l.SendTarget = rateOrDefault(l.SendTarget, Rate{Rate: 0.0033, Burst: 3})
	return l
}

// rateOrDefault replaces a non-positive rule with the fallback. | rateOrDefault 用回退规则替换非正规则。
func rateOrDefault(r, fallback Rate) Rate {
	if r.Rate <= 0 || r.Burst <= 0 {
		return fallback
	}
	return r
}

// normalizeOrigins trims and de-duplicates the origin allowlist. | normalizeOrigins 去空格并去重 Origin 允许列表。
func normalizeOrigins(origins []string) []string {
	if len(origins) == 0 {
		return nil
	}
	seen := make(map[string]struct{}, len(origins))
	out := make([]string, 0, len(origins))
	for _, origin := range origins {
		origin = strings.TrimSpace(origin)
		if origin == "" {
			continue
		}
		if _, ok := seen[origin]; ok {
			continue
		}
		seen[origin] = struct{}{}
		out = append(out, origin)
	}
	return out
}
