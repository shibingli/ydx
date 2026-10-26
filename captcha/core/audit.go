package core

import (
	"context"
	"io"
	"sync"
	"time"

	"github.com/shibingli/ydx/json"
)

// Audit outcomes. | 审计结果。
const (
	// AuditCreated records a generated challenge. | AuditCreated 记录已生成的挑战。
	AuditCreated = "created"
	// AuditSent records a delivered SMS or email code. | AuditSent 记录已下发的短信或邮件验证码。
	AuditSent = "sent"
	// AuditPassed records a successful verification. | AuditPassed 记录验证成功。
	AuditPassed = "passed"
	// AuditFailed records a wrong answer. | AuditFailed 记录答案错误。
	AuditFailed = "failed"
	// AuditBlocked records a policy or geo block. | AuditBlocked 记录策略或地理拦截。
	AuditBlocked = "blocked"
	// AuditRateLimited records a token-bucket rejection. | AuditRateLimited 记录限流拒绝。
	AuditRateLimited = "rate_limited"
	// AuditError records an internal or sender failure. | AuditError 记录内部或发送器故障。
	AuditError = "error"
)

// AuditEvent is a redacted, host-recordable verification event. | AuditEvent 是脱敏、可供宿主记录的验证事件。
//
// It never contains a code, token, raw target, raw User-Agent or full request
// body. | 它绝不包含验证码、令牌、原始目标地址、原始 User-Agent 或完整请求体。
type AuditEvent struct {
	// RequestID is the optional host correlation identifier. | RequestID 是可选宿主关联标识。
	RequestID string `json:"request_id,omitempty"`
	// ChallengeID is the opaque challenge identifier. | ChallengeID 是不透明挑战标识。
	ChallengeID string `json:"challenge_id,omitempty"`
	// Action is the host action. | Action 是宿主动作。
	Action string `json:"action,omitempty"`
	// Type is the challenge type. | Type 是验证码类型。
	Type Type `json:"type,omitempty"`
	// Outcome is one of the Audit* constants. | Outcome 是 Audit* 常量之一。
	Outcome string `json:"outcome"`
	// IP is the resolved client address. | IP 是解析后的客户端地址。
	IP string `json:"ip,omitempty"`
	// Country is the ISO country code when known. | Country 是已知时的 ISO 国家代码。
	Country string `json:"country,omitempty"`
	// Target is the masked phone number or email address. | Target 是脱敏后的手机号或邮箱。
	Target string `json:"target,omitempty"`
	// ErrorCode is a stable public error code, never an internal message. | ErrorCode 是稳定公开错误码，绝不是内部消息。
	ErrorCode string `json:"error_code,omitempty"`
	// Reasons lists stable risk reason codes. | Reasons 列出稳定风险原因码。
	Reasons []string `json:"reasons,omitempty"`
	// Timestamp is the Unix millisecond event time. | Timestamp 是 Unix 毫秒事件时间。
	Timestamp int64 `json:"ts"`
	// Risk is the final risk score. | Risk 是最终风险分。
	Risk int `json:"risk,omitempty"`
	// DurationMS is the server-side handling duration. | DurationMS 是服务端处理耗时。
	DurationMS int64 `json:"duration_ms,omitempty"`
}

// AuditSink receives audit events. | AuditSink 接收审计事件。
//
// Implementations must be safe for concurrent use. A returned error is logged
// and never fails the user request. | 实现必须并发安全。返回的错误会被记录，但绝不会使
// 用户请求失败。
type AuditSink interface {
	// WriteAudit records one event. | WriteAudit 记录一个事件。
	WriteAudit(ctx context.Context, event AuditEvent) error
}

// AuditFunc adapts a function to AuditSink. | AuditFunc 把函数适配为 AuditSink。
type AuditFunc func(ctx context.Context, event AuditEvent) error

// WriteAudit implements AuditSink. | WriteAudit 实现 AuditSink。
func (f AuditFunc) WriteAudit(ctx context.Context, event AuditEvent) error {
	if f == nil {
		return nil
	}
	return f(ctx, event)
}

// JSONAuditSink writes one JSON object per line. | JSONAuditSink 每行写出一个 JSON 对象。
type JSONAuditSink struct {
	writer io.Writer
	mu     sync.Mutex
}

// NewJSONAuditSink builds a newline-delimited JSON sink. | NewJSONAuditSink 构建按行分隔的 JSON 审计。
func NewJSONAuditSink(w io.Writer) *JSONAuditSink {
	if w == nil {
		w = io.Discard
	}
	return &JSONAuditSink{writer: w}
}

// WriteAudit implements AuditSink. | WriteAudit 实现 AuditSink。
func (s *JSONAuditSink) WriteAudit(_ context.Context, event AuditEvent) error {
	if event.Timestamp == 0 {
		event.Timestamp = time.Now().UnixMilli()
	}
	payload, err := json.Marshal(event)
	if err != nil {
		return err
	}
	payload = append(payload, '\n')
	s.mu.Lock()
	defer s.mu.Unlock()
	_, err = s.writer.Write(payload)
	return err
}
