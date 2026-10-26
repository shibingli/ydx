package transport

import "github.com/shibingli/ydx/captcha/core"

// Core HTTP payload aliases. | Core HTTP 载荷别名。
type (
	CreateRequest = core.CreateRequest
	VerifyRequest = core.VerifyRequest
	SendRequest   = core.SendRequest
	Challenge     = core.Challenge
	VerifyResult  = core.VerifyResult
	TokenClaims   = core.TokenClaims
	Meta          = core.Meta
	LimitError    = core.LimitError
	CooldownError = core.CooldownError
)

// Core error aliases. | Core 错误别名。
var (
	ErrInvalidRequest       = core.ErrInvalidRequest
	ErrRequestTooLarge      = core.ErrRequestTooLarge
	ErrUnsupportedMediaType = core.ErrUnsupportedMediaType
	ErrOriginNotAllowed     = core.ErrOriginNotAllowed
	ErrTokenInvalid         = core.ErrTokenInvalid
	ErrTokenExpired         = core.ErrTokenExpired
	ErrTokenUsed            = core.ErrTokenUsed
	ErrForbidden            = core.ErrForbidden
	ErrGeoBlocked           = core.ErrGeoBlocked
	ErrGeoMismatch          = core.ErrGeoMismatch
	ErrRiskRejected         = core.ErrRiskRejected
	ErrCaptureDetected      = core.ErrCaptureDetected
	ErrFallbackDisabled     = core.ErrFallbackDisabled
	ErrNotFound             = core.ErrNotFound
	ErrExpired              = core.ErrExpired
	ErrTooManyAttempts      = core.ErrTooManyAttempts
	ErrRateLimited          = core.ErrRateLimited
	ErrCooldown             = core.ErrCooldown
	ErrNoSender             = core.ErrNoSender
	ErrSendFailed           = core.ErrSendFailed
	ErrProvider             = core.ErrProvider
	ErrStore                = core.ErrStore
	ErrClosed               = core.ErrClosed
	ErrInvalidType          = core.ErrInvalidType
	ErrInvalidAnswer        = core.ErrInvalidAnswer
	ErrInvalidTarget        = core.ErrInvalidTarget
	ErrUnsupportedChannel   = core.ErrUnsupportedChannel
	ErrPoWRequired          = core.ErrPoWRequired
	ErrPoWInvalid           = core.ErrPoWInvalid
	ErrInvalidOptions       = core.ErrInvalidOptions
)
