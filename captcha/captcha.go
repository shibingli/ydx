// Package captcha is the compatibility facade for the captcha service.
//
// Existing integrations keep importing github.com/shibingli/ydx/captcha and
// use Manager, Options and the public challenge types; implementations live in
// the core, challenge, risk, service, transport and plugin subpackages.
// | Package captcha 是验证码服务的兼容门面。既有集成继续导入本包并使用
// Manager、Options 与公开挑战类型；具体实现位于 core、challenge、risk、service、
// transport 与插件子包。
package captcha

import (
	"context"
	"io"
	"net/http"

	"github.com/shibingli/ydx/captcha/core"
	"github.com/shibingli/ydx/captcha/service"
	"github.com/shibingli/ydx/captcha/transport"
	"github.com/shibingli/ydx/router"
)

// Core type aliases. | Core 类型别名。
type (
	Options          = core.Options
	Type             = core.Type
	Channel          = core.Channel
	Signals          = core.Signals
	Meta             = core.Meta
	Prompt           = core.Prompt
	Image            = core.Image
	ImageData        = core.ImageData
	Challenge        = core.Challenge
	CreateRequest    = core.CreateRequest
	VerifyRequest    = core.VerifyRequest
	Answer           = core.Answer
	SendRequest      = core.SendRequest
	VerifyResult     = core.VerifyResult
	TokenClaims      = core.TokenClaims
	PoWChallenge     = core.PoWChallenge
	PoWProof         = core.PoWProof
	Track            = core.Track
	TrackPoint       = core.TrackPoint
	Point            = core.Point
	Record           = core.Record
	Provider         = core.Provider
	GenerateRequest  = core.GenerateRequest
	Generated        = core.Generated
	CheckResult      = core.CheckResult
	Message          = core.Message
	Sender           = core.Sender
	SenderFunc       = core.SenderFunc
	LimitError       = core.LimitError
	CooldownError    = core.CooldownError
	Policy           = core.Policy
	Rule             = core.Rule
	PolicyProvider   = core.PolicyProvider
	PolicyFunc       = core.PolicyFunc
	Geo              = core.Geo
	GeoResolver      = core.GeoResolver
	GeoResolverFunc  = core.GeoResolverFunc
	GeoEntry         = core.GeoEntry
	CIDRGeoResolver  = core.CIDRGeoResolver
	AuditEvent       = core.AuditEvent
	AuditSink        = core.AuditSink
	AuditFunc        = core.AuditFunc
	JSONAuditSink    = core.JSONAuditSink
	FallbackOptions  = core.FallbackOptions
	Rate             = core.Rate
	Limits           = core.Limits
	PoWOptions       = core.PoWOptions
	PoWMode          = core.PoWMode
	CaptureMode      = core.CaptureMode
	MemoryStore      = core.MemoryStore
	MemoryImageStore = core.MemoryImageStore
	Store            = core.Store
	ImageStore       = core.ImageStore
)

// Transport aliases. | Transport 别名。
type (
	Handler        = transport.Handler
	HandlerOptions = transport.HandlerOptions
	ProtectOptions = transport.ProtectOptions
	Assessment     = service.Assessment
)

// Challenge type and channel constants. | 挑战类型与通道常量。
const (
	TypeText      = core.TypeText
	TypeClickText = core.TypeClickText
	TypeClickIcon = core.TypeClickIcon
	TypeSlide     = core.TypeSlide
	TypeScratch   = core.TypeScratch
	TypeSemantic  = core.TypeSemantic
	TypeRotate    = core.TypeRotate
	TypeSMS       = core.TypeSMS
	TypeEmail     = core.TypeEmail
	ChannelSMS    = core.ChannelSMS
	ChannelEmail  = core.ChannelEmail
)

// Policy and proof-of-work constants. | 策略与工作量证明常量。
const (
	PoWOff        = core.PoWOff
	PoWAdaptive   = core.PoWAdaptive
	PoWAlways     = core.PoWAlways
	CaptureOff    = core.CaptureOff
	CaptureRisk   = core.CaptureRisk
	CaptureReject = core.CaptureReject
)

// Audit outcome constants. | 审计结果常量。
const (
	AuditCreated     = core.AuditCreated
	AuditSent        = core.AuditSent
	AuditPassed      = core.AuditPassed
	AuditFailed      = core.AuditFailed
	AuditBlocked     = core.AuditBlocked
	AuditRateLimited = core.AuditRateLimited
	AuditError       = core.AuditError
)

// Default values. | 默认值。
const (
	DefaultChallengeTTL     = core.DefaultChallengeTTL
	DefaultTokenTTL         = core.DefaultTokenTTL
	DefaultCooldown         = core.DefaultCooldown
	DefaultMaxAttempts      = core.DefaultMaxAttempts
	DefaultTextLength       = core.DefaultTextLength
	DefaultWidth            = core.DefaultWidth
	DefaultHeight           = core.DefaultHeight
	DefaultPolicyRefresh    = core.DefaultPolicyRefresh
	DefaultGeoTTL           = core.DefaultGeoTTL
	DefaultGeoMaxDistanceKM = core.DefaultGeoMaxDistanceKM
	DefaultGeoMaxSpeedKMH   = core.DefaultGeoMaxSpeedKMH
	DefaultRiskRejectScore  = core.DefaultRiskRejectScore
	DefaultKeyPrefix        = core.DefaultKeyPrefix
	DefaultHandlerPrefix    = transport.DefaultHandlerPrefix
	DefaultMaxBodyBytes     = transport.DefaultMaxBodyBytes
	TokenHeader             = transport.TokenHeader
)

// Sentinel errors. | 哨兵错误。
var (
	ErrInvalidOptions       = core.ErrInvalidOptions
	ErrInvalidType          = core.ErrInvalidType
	ErrInvalidRequest       = core.ErrInvalidRequest
	ErrRequestTooLarge      = core.ErrRequestTooLarge
	ErrNotFound             = core.ErrNotFound
	ErrExpired              = core.ErrExpired
	ErrTooManyAttempts      = core.ErrTooManyAttempts
	ErrForbidden            = core.ErrForbidden
	ErrRateLimited          = core.ErrRateLimited
	ErrInvalidAnswer        = core.ErrInvalidAnswer
	ErrRiskRejected         = core.ErrRiskRejected
	ErrGeoBlocked           = core.ErrGeoBlocked
	ErrGeoMismatch          = core.ErrGeoMismatch
	ErrPoWRequired          = core.ErrPoWRequired
	ErrPoWInvalid           = core.ErrPoWInvalid
	ErrStore                = core.ErrStore
	ErrTokenInvalid         = core.ErrTokenInvalid
	ErrTokenExpired         = core.ErrTokenExpired
	ErrTokenUsed            = core.ErrTokenUsed
	ErrOriginNotAllowed     = core.ErrOriginNotAllowed
	ErrCaptureDetected      = core.ErrCaptureDetected
	ErrFallbackDisabled     = core.ErrFallbackDisabled
	ErrUnsupportedMediaType = core.ErrUnsupportedMediaType
	ErrUnsupportedChannel   = core.ErrUnsupportedChannel
	ErrNoSender             = core.ErrNoSender
	ErrInvalidTarget        = core.ErrInvalidTarget
	ErrSendFailed           = core.ErrSendFailed
	ErrCooldown             = core.ErrCooldown
	ErrProvider             = core.ErrProvider
	ErrAssets               = core.ErrAssets
	ErrClosed               = core.ErrClosed
)

// Constructor shortcuts. | 构造函数快捷方式。
func NewMemoryStore() *MemoryStore { return core.NewMemoryStore() }

// NewMemoryImageStore builds a sharded in-memory image store. | NewMemoryImageStore 构建分片内存图片存储。
func NewMemoryImageStore() *MemoryImageStore { return core.NewMemoryImageStore() }

// NewCIDRGeoResolver validates and copies a prefix table. | NewCIDRGeoResolver 校验并复制前缀表。
func NewCIDRGeoResolver(entries []GeoEntry) (*CIDRGeoResolver, error) {
	return core.NewCIDRGeoResolver(entries)
}

// NewJSONAuditSink builds a newline-delimited JSON sink. | NewJSONAuditSink 构建按行 JSON 审计接收器。
func NewJSONAuditSink(w io.Writer) *JSONAuditSink { return core.NewJSONAuditSink(w) }

// TokenFromRequest returns a token from the default header or Bearer scheme. | TokenFromRequest 从默认头或 Bearer 方案返回令牌。
func TokenFromRequest(r *http.Request) string { return transport.TokenFromRequest(r) }

// ClaimsFromContext returns verified claims from a request context. | ClaimsFromContext 从请求上下文返回已验证载荷。
func ClaimsFromContext(ctx context.Context) (*TokenClaims, bool) {
	return transport.ClaimsFromContext(ctx)
}

// SDKScript returns the embedded browser SDK bytes. | SDKScript 返回嵌入的浏览器 SDK 字节。
func SDKScript() []byte { return transport.SDKScript() }

// SDKStyle returns the embedded browser SDK stylesheet bytes. | SDKStyle 返回嵌入的浏览器 SDK 样式表字节。
func SDKStyle() []byte { return transport.SDKStyle() }

// Manager wraps the service manager with HTTP and YD entry points. | Manager 包装服务管理器并提供 HTTP 与 YD 入口。
type Manager struct {
	*service.Manager
}

// New validates options and builds a Manager. | New 校验选项并构建 Manager。
func New(o Options) (*Manager, error) {
	manager, err := service.New(o)
	if err != nil {
		return nil, err
	}
	return &Manager{Manager: manager}, nil
}

// Handler returns a native net/http handler. | Handler 返回原生 net/http 处理器。
func (m *Manager) Handler(options HandlerOptions) *Handler {
	if m == nil {
		return nil
	}
	return transport.NewHandler(m.Manager, options)
}

// Protect returns YD middleware requiring a valid token for action. | Protect 返回要求 action 有效令牌的 YD 中间件。
func (m *Manager) Protect(action string) router.Middleware {
	return m.ProtectWith(action, ProtectOptions{})
}

// ProtectWith returns configurable YD token middleware. | ProtectWith 返回可配置的 YD 令牌中间件。
func (m *Manager) ProtectWith(action string, options ProtectOptions) router.Middleware {
	if m == nil {
		return func(c *router.Ctx) {}
	}
	return transport.NewProtect(m.Manager, action, options)
}

// HTTPMiddleware returns native net/http token middleware. | HTTPMiddleware 返回原生 net/http 令牌中间件。
func (m *Manager) HTTPMiddleware(action string) func(http.Handler) http.Handler {
	return m.HTTPMiddlewareWith(action, ProtectOptions{})
}

// HTTPMiddlewareWith returns configurable native token middleware. | HTTPMiddlewareWith 返回可配置的原生令牌中间件。
func (m *Manager) HTTPMiddlewareWith(action string, options ProtectOptions) func(http.Handler) http.Handler {
	if m == nil {
		return func(next http.Handler) http.Handler { return next }
	}
	return transport.NewHTTPMiddleware(m.Manager, action, options)
}

// MaskTarget masks a phone number or email address for audit output. | MaskTarget 为审计输出脱敏手机号或邮箱。
func MaskTarget(channel Channel, target string) string {
	return service.MaskTarget(channel, target)
}
