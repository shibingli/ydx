package core

import "time"

// Record is the server-side state of one challenge. | Record 是一个挑战的服务端状态。
//
// It is stored with a short TTL and never serialized into an HTTP response. | 它以短 TTL
// 存储，且绝不会序列化进 HTTP 响应。
type Record struct {
	// ID is the challenge identifier. | ID 是挑战标识。
	ID string `json:"id"`
	// Type is the challenge family. | Type 是验证码类型。
	Type Type `json:"type"`
	// Action is the bound host action. | Action 是绑定的宿主动作。
	Action string `json:"action"`
	// Locale is the requested locale. | Locale 是请求的语言。
	Locale string `json:"locale"`
	// Answer is the opaque provider answer state. | Answer 是不透明的生成器答案状态。
	Answer []byte `json:"answer,omitempty"`
	// Images lists image keys that must be deleted after success. | Images 列出成功后需删除的图片键。
	Images []string `json:"images,omitempty"`
	// CreatedAt is the server creation time. | CreatedAt 是服务端创建时间。
	CreatedAt time.Time `json:"created_at"`
	// ExpiresAt is the server expiry time. | ExpiresAt 是服务端过期时间。
	ExpiresAt time.Time `json:"expires_at"`
	// Attempts is the number of consumed verification attempts. | Attempts 是已消费的验证尝试次数。
	Attempts int `json:"attempts"`
	// MaxAttempts is the attempt budget. | MaxAttempts 是尝试次数预算。
	MaxAttempts int `json:"max_attempts"`
	// Risk is the creation-time risk score. | Risk 是创建时风险分。
	Risk int `json:"risk,omitempty"`
	// RiskReasons lists stable creation-time reason codes. | RiskReasons 列出创建时稳定原因码。
	RiskReasons []string `json:"risk_reasons,omitempty"`
	// Signals is the creation-time client hint set. | Signals 是创建时客户端提示集。
	Signals Signals `json:"signals,omitempty"`
	// Geo is the short-term location captured at creation. | Geo 是创建时捕获的短期位置。
	Geo Geo `json:"geo,omitempty"`
	// GeoAt is the creation geo timestamp. | GeoAt 是创建地理位置时间。
	GeoAt time.Time `json:"geo_at,omitempty"`
	// Meta is the creation transport context. | Meta 是创建时传输上下文。
	Meta Meta `json:"meta,omitempty"`
	// Channel is set for SMS and email records. | Channel 在短信与邮件记录中设置。
	Channel Channel `json:"channel,omitempty"`
	// Target is the masked delivery target. | Target 是脱敏后的下发目标。
	Target string `json:"target,omitempty"`
	// TargetHash is a keyed digest of the full target. | TargetHash 是完整目标的键控摘要。
	TargetHash string `json:"target_hash,omitempty"`
	// CodeHash is the keyed digest of the delivered code. | CodeHash 是已下发验证码的键控摘要。
	CodeHash []byte `json:"code_hash,omitempty"`
	// CodeSentAt is the last delivery time. | CodeSentAt 是最后下发时间。
	CodeSentAt time.Time `json:"code_sent_at,omitempty"`
	// PoW is the issued proof-of-work challenge. | PoW 是已签发的工作量证明挑战。
	PoW *PoWChallenge `json:"pow,omitempty"`
	// RequirePoW reports whether a proof is mandatory at verification. | RequirePoW 报告验证时是否强制要求证明。
	RequirePoW bool `json:"require_pow,omitempty"`
	// Fallback reports that this code challenge is a capture downgrade. | Fallback 报告该验证码挑战是录屏降级。
	Fallback bool `json:"fallback,omitempty"`
	// CaptureKind is the client-observed fallback trigger. | CaptureKind 是客户端观察到的降级触发原因。
	CaptureKind string `json:"capture_kind,omitempty"`
}
