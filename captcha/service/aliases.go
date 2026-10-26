package service

import "github.com/shibingli/ydx/captcha/core"

// Core API aliases keep the service package readable. | Core API 别名让 service 包保持可读。
type (
	Options         = core.Options
	Type            = core.Type
	Channel         = core.Channel
	Signals         = core.Signals
	Meta            = core.Meta
	Prompt          = core.Prompt
	Image           = core.Image
	Challenge       = core.Challenge
	CreateRequest   = core.CreateRequest
	VerifyRequest   = core.VerifyRequest
	Answer          = core.Answer
	SendRequest     = core.SendRequest
	VerifyResult    = core.VerifyResult
	TokenClaims     = core.TokenClaims
	PoWChallenge    = core.PoWChallenge
	PoWProof        = core.PoWProof
	Track           = core.Track
	TrackPoint      = core.TrackPoint
	Point           = core.Point
	Record          = core.Record
	Store           = core.Store
	ImageStore      = core.ImageStore
	Provider        = core.Provider
	GenerateRequest = core.GenerateRequest
	Generated       = core.Generated
	ImageData       = core.ImageData
	CheckResult     = core.CheckResult
	Message         = core.Message
	Sender          = core.Sender
	SenderFunc      = core.SenderFunc
	LimitError      = core.LimitError
	CooldownError   = core.CooldownError
	Policy          = core.Policy
	Rule            = core.Rule
	PolicyProvider  = core.PolicyProvider
	PolicyFunc      = core.PolicyFunc
	Geo             = core.Geo
	GeoResolver     = core.GeoResolver
	GeoResolverFunc = core.GeoResolverFunc
	GeoEntry        = core.GeoEntry
	CIDRGeoResolver = core.CIDRGeoResolver
	AuditEvent      = core.AuditEvent
	AuditSink       = core.AuditSink
	AuditFunc       = core.AuditFunc
	JSONAuditSink   = core.JSONAuditSink
	FallbackOptions = core.FallbackOptions
	Rate            = core.Rate
	Limits          = core.Limits
	PoWOptions      = core.PoWOptions
	PoWMode         = core.PoWMode
	CaptureMode     = core.CaptureMode
	PolicySnapshot  = core.PolicySnapshot
	PolicyDecision  = core.Decision
	Localizer       = core.Localizer
)

// Challenge type and channel aliases. | 挑战类型与通道别名。
const (
	TypeText         = core.TypeText
	TypeClickText    = core.TypeClickText
	TypeClickIcon    = core.TypeClickIcon
	TypeSlide        = core.TypeSlide
	TypeScratch      = core.TypeScratch
	TypeSemantic     = core.TypeSemantic
	TypeRotate       = core.TypeRotate
	TypeSMS          = core.TypeSMS
	TypeEmail        = core.TypeEmail
	ChannelSMS       = core.ChannelSMS
	ChannelEmail     = core.ChannelEmail
	PoWOff           = core.PoWOff
	PoWAdaptive      = core.PoWAdaptive
	PoWAlways        = core.PoWAlways
	CaptureOff       = core.CaptureOff
	CaptureRisk      = core.CaptureRisk
	CaptureReject    = core.CaptureReject
	AuditCreated     = core.AuditCreated
	AuditSent        = core.AuditSent
	AuditPassed      = core.AuditPassed
	AuditFailed      = core.AuditFailed
	AuditBlocked     = core.AuditBlocked
	AuditRateLimited = core.AuditRateLimited
	AuditError       = core.AuditError
)

// Error aliases preserve errors.Is behavior. | 错误别名保持 errors.Is 行为。
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
	NewMemoryStore          = core.NewMemoryStore
	NewMemoryImageStore     = core.NewMemoryImageStore
	NewCIDRGeoResolver      = core.NewCIDRGeoResolver
	NewJSONAuditSink        = core.NewJSONAuditSink
)
