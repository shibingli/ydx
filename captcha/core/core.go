// Package core defines captcha public types, options, stores, tokens and message catalogs.
// | Package core 定义验证码公开类型、选项、存储、令牌与消息目录。
package core

import (
	"context"
	"time"

	"github.com/shibingli/ydx/errs"
)

// Package-level sentinel errors, testable with errors.Is. | 包级哨兵错误，可用 errors.Is 判定。
var (
	// ErrInvalidOptions indicates unusable manager or handler options. | ErrInvalidOptions 表示管理器或处理器选项不可用。
	ErrInvalidOptions = errs.New("captcha: invalid options | captcha：非法选项")
	// ErrInvalidType indicates a challenge type that is not registered or not enabled. | ErrInvalidType 表示挑战类型未注册或未启用。
	ErrInvalidType = errs.New("captcha: invalid challenge type | captcha：非法验证码类型")
	// ErrInvalidRequest indicates a malformed or oversized HTTP request. | ErrInvalidRequest 表示 HTTP 请求格式错误或过大。
	ErrInvalidRequest = errs.New("captcha: invalid request | captcha：非法请求")
	// ErrRequestTooLarge indicates an HTTP body above the handler limit. | ErrRequestTooLarge 表示 HTTP 正文超过处理器上限。
	ErrRequestTooLarge = errs.New("captcha: request body too large | captcha：请求正文过大")
	// ErrNotFound indicates an unknown or already consumed challenge. | ErrNotFound 表示挑战不存在或已被消费。
	ErrNotFound = errs.New("captcha: challenge not found | captcha：验证码不存在")
	// ErrExpired indicates a challenge or token past its lifetime. | ErrExpired 表示挑战或令牌已过期。
	ErrExpired = errs.New("captcha: challenge expired | captcha：验证码已过期")
	// ErrTooManyAttempts indicates the per-challenge attempt budget is exhausted. | ErrTooManyAttempts 表示单次挑战的尝试次数已耗尽。
	ErrTooManyAttempts = errs.New("captcha: too many attempts | captcha：尝试次数过多")
	// ErrForbidden indicates a request rejected by the dynamic policy. | ErrForbidden 表示请求被动态策略拒绝。
	ErrForbidden = errs.New("captcha: request forbidden | captcha：请求被禁止")
	// ErrRateLimited indicates a token-bucket rejection. | ErrRateLimited 表示令牌桶限流拒绝。
	ErrRateLimited = errs.New("captcha: rate limited | captcha：请求过于频繁")
	// ErrInvalidAnswer indicates an answer that does not satisfy the challenge. | ErrInvalidAnswer 表示答案不满足挑战要求。
	ErrInvalidAnswer = errs.New("captcha: invalid answer | captcha：答案错误")
	// ErrRiskRejected indicates that a correct answer was refused because the request is too risky. | ErrRiskRejected 表示答案正确但请求风险过高被拒绝。
	ErrRiskRejected = errs.New("captcha: risk rejected | captcha：风险过高")
	// ErrGeoBlocked indicates a country or region blocked by policy. | ErrGeoBlocked 表示国家或地区被策略拦截。
	ErrGeoBlocked = errs.New("captcha: geo blocked | captcha：地理位置被拦截")
	// ErrGeoMismatch indicates a short-term location change beyond the configured bound. | ErrGeoMismatch 表示短期地理位置变化超出允许范围。
	ErrGeoMismatch = errs.New("captcha: geo mismatch | captcha：地理位置不匹配")
	// ErrPoWRequired indicates a proof of work is required but missing. | ErrPoWRequired 表示需要工作量证明但请求未提供。
	ErrPoWRequired = errs.New("captcha: proof of work required | captcha：需要工作量证明")
	// ErrPoWInvalid indicates an invalid or expired proof of work. | ErrPoWInvalid 表示工作量证明无效或过期。
	ErrPoWInvalid = errs.New("captcha: invalid proof of work | captcha：工作量证明无效")
	// ErrStore indicates a session or image store failure. | ErrStore 表示会话或图片存储故障。
	ErrStore = errs.New("captcha: store failure | captcha：存储故障")
	// ErrTokenInvalid indicates a malformed, tampered or mismatched verification token. | ErrTokenInvalid 表示验证令牌格式错误、被篡改或与 action 不匹配。
	ErrTokenInvalid = errs.New("captcha: invalid token | captcha：令牌无效")
	// ErrTokenExpired indicates an expired verification token. | ErrTokenExpired 表示验证令牌已过期。
	ErrTokenExpired = errs.New("captcha: token expired | captcha：令牌已过期")
	// ErrTokenUsed indicates a one-time token that was already consumed. | ErrTokenUsed 表示一次性令牌已被消费。
	ErrTokenUsed = errs.New("captcha: token already used | captcha：令牌已被使用")
	// ErrOriginNotAllowed indicates an Origin outside the configured allowlist. | ErrOriginNotAllowed 表示 Origin 不在允许列表内。
	ErrOriginNotAllowed = errs.New("captcha: origin not allowed | captcha：来源不被允许")
	// ErrCaptureDetected indicates a screen-capture, screenshot or print signal under reject policy. | ErrCaptureDetected 表示严格策略下检测到录屏、截屏或打印信号。
	ErrCaptureDetected = errs.New("captcha: screen capture detected | captcha：检测到录屏或截屏")
	// ErrFallbackDisabled indicates a fallback code request that the host has not enabled. | ErrFallbackDisabled 表示宿主未启用降级验证码请求。
	ErrFallbackDisabled = errs.New("captcha: fallback verification is disabled | captcha：未启用降级验证")
	// ErrUnsupportedMediaType indicates a non-JSON request body. | ErrUnsupportedMediaType 表示非 JSON 请求正文。
	ErrUnsupportedMediaType = errs.New("captcha: unsupported media type | captcha：不支持的媒体类型")
	// ErrUnsupportedChannel indicates an unknown SMS or email channel. | ErrUnsupportedChannel 表示未知的短信或邮件通道。
	ErrUnsupportedChannel = errs.New("captcha: unsupported channel | captcha：不支持的通道")
	// ErrNoSender indicates that no sender plugin is registered for a channel. | ErrNoSender 表示通道未注册发送插件。
	ErrNoSender = errs.New("captcha: sender not configured | captcha：未配置发送插件")
	// ErrInvalidTarget indicates an invalid phone number or email address. | ErrInvalidTarget 表示手机号或邮箱地址非法。
	ErrInvalidTarget = errs.New("captcha: invalid target | captcha：目标地址非法")
	// ErrSendFailed indicates that the sender plugin failed to deliver a code. | ErrSendFailed 表示发送插件投递验证码失败。
	ErrSendFailed = errs.New("captcha: send failed | captcha：发送失败")
	// ErrCooldown indicates that a new code was requested before the resend delay elapsed. | ErrCooldown 表示重发冷却时间未到。
	ErrCooldown = errs.New("captcha: resend cooldown | captcha：重发冷却中")
	// ErrProvider indicates a visual challenge provider failure. | ErrProvider 表示视觉挑战生成器故障。
	ErrProvider = errs.New("captcha: provider failure | captcha：题目生成器故障")
	// ErrAssets indicates missing or corrupt embedded frontend or glyph assets. | ErrAssets 表示嵌入的前端或字形资源缺失或损坏。
	ErrAssets = errs.New("captcha: asset failure | captcha：资源加载失败")
	// ErrClosed indicates a manager that has been closed. | ErrClosed 表示管理器已关闭。
	ErrClosed = errs.New("captcha: manager closed | captcha：管理器已关闭")
)

// Type identifies a challenge family. | Type 标识验证码类型。
type Type string

// Built-in challenge types. | 内置验证码类型。
const (
	// TypeText asks the user to type the characters in a distorted image. | TypeText 要求用户输入扭曲图片中的字符。
	TypeText Type = "text"
	// TypeClickText asks the user to click rendered words in the given order. | TypeClickText 要求用户按给定顺序点击文字。
	TypeClickText Type = "click_text"
	// TypeClickIcon asks the user to click rendered icons in the given order. | TypeClickIcon 要求用户按给定顺序点击图标。
	TypeClickIcon Type = "click_icon"
	// TypeSlide asks the user to drag a puzzle piece into the gap. | TypeSlide 要求用户把拼图块拖到缺口。
	TypeSlide Type = "slide"
	// TypeScratch asks the user to scratch a coating and type the revealed characters. | TypeScratch 要求用户刮开涂层并输入显露的字符。
	TypeScratch Type = "scratch"
	// TypeSemantic asks the user to select every object matching a semantic prompt. | TypeSemantic 要求用户选择所有符合语义提示的对象。
	TypeSemantic Type = "semantic"
	// TypeRotate asks the user to rotate an image to its upright orientation. | TypeRotate 要求用户把图片旋转到正向。
	TypeRotate Type = "rotate"
	// TypeSMS delivers a one-time code over SMS. | TypeSMS 通过短信下发一次性验证码。
	TypeSMS Type = "sms"
	// TypeEmail delivers a one-time code over email. | TypeEmail 通过邮件下发一次性验证码。
	TypeEmail Type = "email"
)

// Valid reports whether t is a built-in challenge type. | Valid 报告 t 是否为内置验证码类型。
func (t Type) Valid() bool {
	switch t {
	case TypeText, TypeClickText, TypeClickIcon, TypeSlide, TypeScratch, TypeSemantic, TypeRotate, TypeSMS, TypeEmail:
		return true
	default:
		return false
	}
}

// visual reports whether t is rendered as an image challenge. | visual 报告 t 是否为图片挑战。
func (t Type) visual() bool {
	switch t {
	case TypeText, TypeClickText, TypeClickIcon, TypeSlide, TypeScratch, TypeSemantic, TypeRotate:
		return true
	default:
		return false
	}
}

// code reports whether t uses the SMS/email delivery path. | code 报告 t 是否走短信/邮件下发路径。
func (t Type) code() bool { return t.IsCode() }

// IsCode reports whether the type uses a delivered one-time code. | IsCode 报告类型是否使用下发的一次性验证码。
func (t Type) IsCode() bool { return t == TypeSMS || t == TypeEmail }

// Channel identifies a code delivery channel. | Channel 标识验证码下发通道。
type Channel string

// Supported delivery channels. | 支持的下发通道。
const (
	// ChannelSMS is the SMS delivery channel. | ChannelSMS 是短信下发通道。
	ChannelSMS Channel = "sms"
	// ChannelEmail is the email delivery channel. | ChannelEmail 是邮件下发通道。
	ChannelEmail Channel = "email"
)

// Valid reports whether c is a supported delivery channel. | Valid 报告 c 是否为支持的下发通道。
func (c Channel) Valid() bool { return c == ChannelSMS || c == ChannelEmail }

// Point is an image-space coordinate. | Point 是图片坐标系中的点。
type Point struct {
	// X is the horizontal pixel coordinate. | X 是水平像素坐标。
	X int `json:"x"`
	// Y is the vertical pixel coordinate. | Y 是垂直像素坐标。
	Y int `json:"y"`
}

// TrackPoint is one sampled pointer position. | TrackPoint 是一个采样指针位置。
type TrackPoint struct {
	// Kind is an optional event name such as down, move or up. | Kind 是可选事件名，例如 down、move 或 up。
	Kind string `json:"kind,omitempty"`
	// T is the client-relative millisecond timestamp. | T 是客户端相对毫秒时间戳。
	T int64 `json:"t"`
	// X is the horizontal pixel coordinate. | X 是水平像素坐标。
	X int `json:"x"`
	// Y is the vertical pixel coordinate. | Y 是垂直像素坐标。
	Y int `json:"y"`
}

// Track is the pointer trajectory submitted by the client. | Track 是客户端提交的指针轨迹。
type Track struct {
	// Points is the bounded sample list. | Points 是有界采样列表。
	Points []TrackPoint `json:"points,omitempty"`
	// StartedAt is the first client timestamp in milliseconds. | StartedAt 是首个客户端毫秒时间戳。
	StartedAt int64 `json:"started_at,omitempty"`
	// EndedAt is the last client timestamp in milliseconds. | EndedAt 是最后一个客户端毫秒时间戳。
	EndedAt int64 `json:"ended_at,omitempty"`
}

// Signals carries non-authoritative browser hints used for risk scoring. | Signals 保存用于风险评分的非权威浏览器提示。
//
// Every field is client supplied and may be forged. The server normally uses
// it only to raise the cost of automation; an explicit CaptureReject policy may
// reject a request from a capture signal, but that remains a client-reported
// deterrence rather than a trustworthy authorization input. | 所有字段均由客户端提供且
// 可伪造。服务端通常只用它提高自动化成本；显式的 CaptureReject 策略可根据录屏信号拒绝
// 请求，但这仍是客户端威慑而非可信授权依据。
type Signals struct {
	// UserAgent is navigator.userAgent as reported by JavaScript. | UserAgent 是 JavaScript 报告的 navigator.userAgent。
	UserAgent string `json:"user_agent,omitempty"`
	// Platform is navigator.platform. | Platform 是 navigator.platform。
	Platform string `json:"platform,omitempty"`
	// Language is navigator.language. | Language 是 navigator.language。
	Language string `json:"language,omitempty"`
	// Timezone is Intl.DateTimeFormat().resolvedOptions().timeZone. | Timezone 是浏览器解析出的时区。
	Timezone string `json:"timezone,omitempty"`
	// CanvasHash is a coarse canvas fingerprint digest. | CanvasHash 是粗略的 Canvas 指纹摘要。
	CanvasHash string `json:"canvas_hash,omitempty"`
	// WebGLHash is a coarse WebGL fingerprint digest. | WebGLHash 是粗略的 WebGL 指纹摘要。
	WebGLHash string `json:"webgl_hash,omitempty"`
	// AudioHash is a coarse audio fingerprint digest. | AudioHash 是粗略的音频指纹摘要。
	AudioHash string `json:"audio_hash,omitempty"`
	// DoNotTrack is navigator.doNotTrack. | DoNotTrack 是 navigator.doNotTrack。
	DoNotTrack string `json:"do_not_track,omitempty"`
	// Visibility is document.visibilityState at submission time. | Visibility 是提交时的 document.visibilityState。
	Visibility string `json:"visibility,omitempty"`
	// Languages is navigator.languages. | Languages 是 navigator.languages。
	Languages []string `json:"languages,omitempty"`
	// FocusLoss counts window blur events observed by the SDK. | FocusLoss 是 SDK 观察到的窗口失焦次数。
	FocusLoss int `json:"focus_loss,omitempty"`
	// ScreenWidth is screen.width. | ScreenWidth 是 screen.width。
	ScreenWidth int `json:"screen_width,omitempty"`
	// ScreenHeight is screen.height. | ScreenHeight 是 screen.height。
	ScreenHeight int `json:"screen_height,omitempty"`
	// ColorDepth is screen.colorDepth. | ColorDepth 是 screen.colorDepth。
	ColorDepth int `json:"color_depth,omitempty"`
	// DeviceMemory is navigator.deviceMemory. | DeviceMemory 是 navigator.deviceMemory。
	DeviceMemory float64 `json:"device_memory,omitempty"`
	// HardwareConcurrency is navigator.hardwareConcurrency. | HardwareConcurrency 是 navigator.hardwareConcurrency。
	HardwareConcurrency int `json:"hardware_concurrency,omitempty"`
	// Plugins is navigator.plugins.length. | Plugins 是 navigator.plugins.length。
	Plugins int `json:"plugins,omitempty"`
	// MouseEntropy is the SD of pointer movement angles observed by the SDK. | MouseEntropy 是 SDK 观察到的指针移动角度标准差。
	MouseEntropy float64 `json:"mouse_entropy,omitempty"`
	// KeyEntropy is the SD of key interval timings observed by the SDK. | KeyEntropy 是 SDK 观察到的按键间隔标准差。
	KeyEntropy float64 `json:"key_entropy,omitempty"`
	// ScreenCapture reports that the page attempted getDisplayMedia. | ScreenCapture 报告页面尝试调用 getDisplayMedia。
	ScreenCapture bool `json:"screen_capture,omitempty"`
	// ScreenshotKey reports an observed screenshot keyboard shortcut. | ScreenshotKey 报告观察到截屏快捷键。
	ScreenshotKey bool `json:"screenshot_key,omitempty"`
	// PrintAttempt reports a beforeprint/print attempt. | PrintAttempt 报告 beforeprint/print 尝试。
	PrintAttempt bool `json:"print_attempt,omitempty"`
	// PageHidden reports that the page was hidden during the challenge. | PageHidden 报告挑战期间页面曾被隐藏。
	PageHidden bool `json:"page_hidden,omitempty"`
	// Touch reports whether the device exposes touch points. | Touch 报告设备是否暴露触摸点。
	Touch bool `json:"touch,omitempty"`
	// WebDriver reports navigator.webdriver. | WebDriver 报告 navigator.webdriver。
	WebDriver bool `json:"webdriver,omitempty"`
	// Headless is a heuristic hint supplied by the SDK. | Headless 是 SDK 提供的无头浏览器启发式提示。
	Headless bool `json:"headless,omitempty"`
	// CookieEnabled is navigator.cookieEnabled. | CookieEnabled 是 navigator.cookieEnabled。
	CookieEnabled bool `json:"cookie_enabled,omitempty"`
}

// Meta is the transport context attached to a manager call. | Meta 是附加到管理器调用的传输上下文。
type Meta struct {
	// IP is the peer address after trusted-proxy resolution. | IP 是可信代理解析后的客户端地址。
	IP string `json:"ip,omitempty"`
	// UserAgent is the raw HTTP User-Agent header. | UserAgent 是原始 HTTP User-Agent 请求头。
	UserAgent string `json:"ua,omitempty"`
	// Origin is the HTTP Origin header. | Origin 是 HTTP Origin 请求头。
	Origin string `json:"origin,omitempty"`
	// RequestID is an optional host correlation identifier. | RequestID 是可选宿主关联标识。
	RequestID string `json:"rid,omitempty"`
}

// Prompt is the localized human instruction for a challenge. | Prompt 是验证码的本地化人工指令。
type Prompt struct {
	// Text is the main instruction. | Text 是主要指令。
	Text string `json:"text"`
	// Hint is an optional secondary hint. | Hint 是可选补充提示。
	Hint string `json:"hint,omitempty"`
	// Count is the number of clicks or characters required, when relevant. | Count 是需要的点击次数或字符数（如适用）。
	Count int `json:"count,omitempty"`
}

// Image describes one challenge image served by the manager. | Image 描述管理器提供的一张挑战图片。
type Image struct {
	// Name is the semantic image name such as challenge or piece. | Name 是语义图片名，例如 challenge 或 piece。
	Name string `json:"name"`
	// URL is relative to the captcha endpoint, for example image/abc. | URL 是相对于验证码端点的地址，例如 image/abc。
	URL string `json:"url"`
	// MIME is the image media type. | MIME 是图片媒体类型。
	MIME string `json:"mime"`
	// Width is the image width in pixels. | Width 是图片像素宽度。
	Width int `json:"width"`
	// Height is the image height in pixels. | Height 是图片像素高度。
	Height int `json:"height"`
}

// PoWChallenge is a SHA-256 proof-of-work request. | PoWChallenge 是 SHA-256 工作量证明请求。
type PoWChallenge struct {
	// Algorithm is always sha256 for built-in PoW. | Algorithm 在内置 PoW 中始终为 sha256。
	Algorithm string `json:"algorithm"`
	// Seed is a random hex string. | Seed 是随机十六进制字符串。
	Seed string `json:"seed"`
	// Difficulty is the number of required leading zero bits. | Difficulty 是要求的前导零位数。
	Difficulty int `json:"difficulty"`
}

// PoWProof is the client's proof-of-work answer. | PoWProof 是客户端的工作量证明答案。
type PoWProof struct {
	// Nonce is the integer appended to the seed. | Nonce 是追加到种子后的整数。
	Nonce uint64 `json:"nonce"`
}

// Challenge is the public challenge returned to the client. | Challenge 是返回给客户端的公开挑战。
//
// It never contains the expected answer, target coordinates or the server-side
// record. | 它绝不包含预期答案、目标坐标或服务端记录。
type Challenge struct {
	// PoW is present when proof of work is required. | 需要工作量证明时 PoW 非空。
	PoW *PoWChallenge `json:"pow,omitempty"`
	// ID is the opaque one-time challenge identifier. | ID 是不透明的一次性挑战标识。
	ID string `json:"id"`
	// Type is the challenge family. | Type 是验证码类型。
	Type Type `json:"type"`
	// Action is the host action this challenge is bound to. | Action 是挑战绑定的宿主动作。
	Action string `json:"action"`
	// Locale is the localized prompt language. | Locale 是提示语言。
	Locale string `json:"locale"`
	// Channel is set for SMS and email challenges. | Channel 在短信与邮件挑战中设置。
	Channel Channel `json:"channel,omitempty"`
	// Target is the masked phone number or email address. | Target 是脱敏后的手机号或邮箱。
	Target string `json:"target,omitempty"`
	// Prompt is the localized instruction. | Prompt 是本地化指令。
	Prompt Prompt `json:"prompt"`
	// Notice is a localized downgrade notice for fallback code challenges. | Notice 是降级验证码挑战的本地化提示。
	Notice string `json:"notice,omitempty"`
	// Images is the image list, empty for SMS and email. | Images 是图片列表；短信与邮件为空。
	Images []Image `json:"images,omitempty"`
	// ExpiresIn is the remaining lifetime in whole seconds. | ExpiresIn 是剩余有效时间（整秒）。
	ExpiresIn int64 `json:"expires_in"`
}

// CreateRequest asks the manager for a fresh visual challenge. | CreateRequest 向管理器请求新的视觉挑战。
type CreateRequest struct {
	// Meta carries transport context. | Meta 携带传输上下文。
	Meta Meta `json:"meta,omitempty"`
	// Type selects a challenge family; empty means adaptive selection. | Type 选择验证码类型；空值表示自适应选择。
	Type Type `json:"type,omitempty"`
	// Action binds the challenge and the resulting token to a host action. | Action 把挑战与结果令牌绑定到宿主动作。
	Action string `json:"action"`
	// Locale is the prompt language such as zh-CN or en. | Locale 是提示语言，例如 zh-CN 或 en。
	Locale string `json:"locale,omitempty"`
	// Signals carries client-side hints. | Signals 携带客户端提示。
	Signals Signals `json:"signals,omitempty"`
}

// VerifyRequest submits an answer for a challenge. | VerifyRequest 提交某个挑战的答案。
type VerifyRequest struct {
	// PoW is the optional proof of work. | PoW 是可选的工作量证明。
	PoW *PoWProof `json:"pow,omitempty"`
	// Meta carries transport context. | Meta 携带传输上下文。
	Meta Meta `json:"meta,omitempty"`
	// ID is the challenge identifier. | ID 是挑战标识。
	ID string `json:"id"`
	// Answer is the user answer and interaction track. | Answer 是用户答案与交互轨迹。
	Answer Answer `json:"answer"`
	// Signals carries client-side hints captured at submission. | Signals 携带提交时采集的客户端提示。
	Signals Signals `json:"signals,omitempty"`
}

// Answer is the union of answer shapes accepted by built-in providers. | Answer 是内置生成器接受的答案联合体。
type Answer struct {
	// Text is used by text and scratch challenges. | Text 用于文本与刮刮卡挑战。
	Text string `json:"text,omitempty"`
	// Code is used by SMS and email challenges. | Code 用于短信与邮件挑战。
	Code string `json:"code,omitempty"`
	// Points is used by click and semantic challenges. | Points 用于点选与语义挑战。
	Points []Point `json:"points,omitempty"`
	// Offset is the horizontal slide offset in pixels. | Offset 是滑动拼图的水平偏移像素。
	Offset *int `json:"offset,omitempty"`
	// OffsetY is the vertical slide offset in pixels. | OffsetY 是滑动拼图的垂直偏移像素。
	OffsetY *int `json:"offset_y,omitempty"`
	// Angle is the rotate angle in degrees. | Angle 是旋转验证码的角度（度）。
	Angle *int `json:"angle,omitempty"`
	// Track is the pointer trajectory. | Track 是指针轨迹。
	Track Track `json:"track,omitempty"`
}

// SendRequest asks the manager to deliver a one-time code. | SendRequest 请求管理器下发一次性验证码。
type SendRequest struct {
	// Meta carries transport context. | Meta 携带传输上下文。
	Meta Meta `json:"meta,omitempty"`
	// Channel selects SMS or email. | Channel 选择短信或邮件。
	Channel Channel `json:"channel"`
	// Target is the phone number or email address. | Target 是手机号或邮箱地址。
	Target string `json:"target"`
	// Action binds the code and the resulting token to a host action. | Action 把验证码与结果令牌绑定到宿主动作。
	Action string `json:"action"`
	// Locale is the prompt and message language. | Locale 是提示与消息语言。
	Locale string `json:"locale,omitempty"`
	// CaptureKind is the client-observed trigger such as screen_capture. | CaptureKind 是客户端观察到的触发原因，例如 screen_capture。
	CaptureKind string `json:"capture_kind,omitempty"`
	// Signals carries client-side hints. | Signals 携带客户端提示。
	Signals Signals `json:"signals,omitempty"`
	// Fallback reports that this send is a downgrade from a visual challenge. | Fallback 报告本次发送是视觉挑战的降级。
	Fallback bool `json:"fallback,omitempty"`
}

// VerifyResult is returned after a successful verification. | VerifyResult 在验证成功后返回。
type VerifyResult struct {
	// Token is the HMAC-signed verification token. | Token 是 HMAC 签名的验证令牌。
	Token string `json:"token"`
	// Action is the action bound into the token. | Action 是写入令牌的动作。
	Action string `json:"action"`
	// ExpiresIn is the token lifetime in whole seconds. | ExpiresIn 是令牌有效期（整秒）。
	ExpiresIn int64 `json:"expires_in"`
}

// TokenClaims is the verified payload of a captcha token. | TokenClaims 是验证通过的验证码令牌载荷。
type TokenClaims struct {
	// ChallengeID is the consumed challenge identifier. | ChallengeID 是已消费的挑战标识。
	ChallengeID string `json:"cid"`
	// Action is the action the token is valid for. | Action 是令牌适用的动作。
	Action string `json:"act"`
	// Subject is a keyed digest of the verified phone or email target. | Subject 是已验证手机或邮箱的键控摘要。
	Subject string `json:"sub,omitempty"`
	// Nonce is the unique token identifier. | Nonce 是令牌唯一标识。
	Nonce string `json:"jti"`
	// Issuer is the optional token issuer. | Issuer 是可选签发方。
	Issuer string `json:"iss,omitempty"`
	// IssuedAt is the Unix issue timestamp in seconds. | IssuedAt 是 Unix 签发时间（秒）。
	IssuedAt int64 `json:"iat"`
	// ExpiresAt is the Unix expiry timestamp in seconds. | ExpiresAt 是 Unix 过期时间（秒）。
	ExpiresAt int64 `json:"exp"`
	// Risk is the final risk score at issuance. | Risk 是签发时的最终风险分。
	Risk int `json:"risk"`
}

// Store is the byte-oriented session backend. | Store 是面向字节的会话后端。
//
// Implementations must be safe for concurrent use and must make Take,
// PutIfAbsent and DeleteIf atomic for a given key: concurrent calls may let at
// most one caller receive the value or win the reservation. Values are owned
// by the store after Put and must not be mutated by the caller. | 实现必须并发安全，
// 且保证同一 key 的 Take、PutIfAbsent 与 DeleteIf 原子：并发调用中至多一个调用方
// 拿到值或赢得预占。值在 Put 后归存储所有，调用方不得修改。
type Store interface {
	// Put stores value under key for ttl. | Put 在 ttl 内把 value 存到 key。
	Put(ctx context.Context, key string, value []byte, ttl time.Duration) error
	// PutIfAbsent atomically stores value only when key is absent or expired. | PutIfAbsent 仅在 key 不存在或已过期时原子写入。
	PutIfAbsent(ctx context.Context, key string, value []byte, ttl time.Duration) (bool, error)
	// DeleteIf atomically deletes key only when its current value equals value. | DeleteIf 仅在 key 当前值等于 value 时原子删除。
	DeleteIf(ctx context.Context, key string, value []byte) (bool, error)
	// Get returns a copy of the value when present. | Get 在存在时返回值的副本。
	Get(ctx context.Context, key string) ([]byte, bool, error)
	// Take atomically returns and deletes the value. | Take 原子地返回并删除值。
	Take(ctx context.Context, key string) ([]byte, bool, error)
	// Delete removes key. | Delete 删除 key。
	Delete(ctx context.Context, key string) error
}

// ImageStore stores rendered challenge images. | ImageStore 存储已渲染的挑战图片。
type ImageStore interface {
	// Put stores image bytes and returns no identifier; the caller supplies the key. | Put 存储图片字节；标识由调用方提供。
	Put(ctx context.Context, key string, data []byte, mime string, ttl time.Duration) error
	// Get returns the image bytes and media type when present. | Get 在存在时返回图片字节与媒体类型。
	Get(ctx context.Context, key string) ([]byte, string, bool, error)
	// Delete removes an image. | Delete 删除一张图片。
	Delete(ctx context.Context, key string) error
}

// LimitError reports a token-bucket rejection with a retry hint. | LimitError 报告带重试提示的令牌桶拒绝。
type LimitError struct {
	// RetryAfter is the minimum wait before the next attempt. | RetryAfter 是下次尝试前的最短等待。
	RetryAfter time.Duration
}

// Error implements error. | Error 实现 error。
func (e *LimitError) Error() string { return ErrRateLimited.Error() }

// Unwrap exposes ErrRateLimited to errors.Is. | Unwrap 暴露 ErrRateLimited 供 errors.Is 使用。
func (e *LimitError) Unwrap() error { return ErrRateLimited }

// CooldownError reports a resend before the cooldown elapsed. | CooldownError 报告冷却期内的重发。
type CooldownError struct {
	// RetryAfter is the remaining cooldown. | RetryAfter 是剩余冷却时间。
	RetryAfter time.Duration
}

// Error implements error. | Error 实现 error。
func (e *CooldownError) Error() string { return ErrCooldown.Error() }

// Unwrap exposes ErrCooldown to errors.Is. | Unwrap 暴露 ErrCooldown 供 errors.Is 使用。
func (e *CooldownError) Unwrap() error { return ErrCooldown }
