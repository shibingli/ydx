package kms

import (
	"context"
	"sort"
	"time"

	"github.com/shibingli/ydx/errs"
)

// Audit outcomes. | 审计结果。
const (
	// OutcomeSuccess marks a completed operation. | OutcomeSuccess 标记操作成功。
	OutcomeSuccess = "success"
	// OutcomeFailure marks a failed operation. | OutcomeFailure 标记操作失败。
	OutcomeFailure = "failure"
	// OutcomeDenied marks an operation refused by policy or authorization. | OutcomeDenied 标记被策略或授权拒绝的操作。
	OutcomeDenied = "denied"
)

// Audit operation names. | 审计操作名。
const (
	// OperationKeyCreate records CreateKey and ImportKey. | OperationKeyCreate 记录 CreateKey 与 ImportKey。
	OperationKeyCreate = "key.create"
	// OperationKeyImport records ImportKey. | OperationKeyImport 记录 ImportKey。
	OperationKeyImport = "key.import"
	// OperationKeyUpdate records metadata updates. | OperationKeyUpdate 记录元数据更新。
	OperationKeyUpdate = "key.update"
	// OperationKeyActivate records Activate. | OperationKeyActivate 记录 Activate。
	OperationKeyActivate = "key.activate"
	// OperationKeyDeactivate records Deactivate. | OperationKeyDeactivate 记录 Deactivate。
	OperationKeyDeactivate = "key.deactivate"
	// OperationKeyCompromise records Compromise. | OperationKeyCompromise 记录 Compromise。
	OperationKeyCompromise = "key.compromise"
	// OperationKeyDestroy records Destroy. | OperationKeyDestroy 记录 Destroy。
	OperationKeyDestroy = "key.destroy"
	// OperationKeyScheduleDelete records ScheduleDelete. | OperationKeyScheduleDelete 记录 ScheduleDelete。
	OperationKeyScheduleDelete = "key.schedule_delete"
	// OperationKeyRotate records Rotate and RotateAllDue. | OperationKeyRotate 记录 Rotate 与 RotateAllDue。
	OperationKeyRotate = "key.rotate"
	// OperationKeyExport records ExportKey. | OperationKeyExport 记录 ExportKey。
	OperationKeyExport = "key.export"
	// OperationEncrypt records Encrypt and EncryptEnvelope. | OperationEncrypt 记录 Encrypt 与 EncryptEnvelope。
	OperationEncrypt = "crypto.encrypt"
	// OperationDecrypt records Decrypt and DecryptEnvelope. | OperationDecrypt 记录 Decrypt 与 DecryptEnvelope。
	OperationDecrypt = "crypto.decrypt"
	// OperationSign records Sign. | OperationSign 记录 Sign。
	OperationSign = "crypto.sign"
	// OperationVerify records Verify. | OperationVerify 记录 Verify。
	OperationVerify = "crypto.verify"
	// OperationWrapKey records WrapKey. | OperationWrapKey 记录 WrapKey。
	OperationWrapKey = "crypto.wrap_key"
	// OperationUnwrapKey records UnwrapKey. | OperationUnwrapKey 记录 UnwrapKey。
	OperationUnwrapKey = "crypto.unwrap_key"
	// OperationGenerateDataKey records GenerateDataKey. | OperationGenerateDataKey 记录 GenerateDataKey。
	OperationGenerateDataKey = "crypto.generate_data_key"
	// OperationDeriveKey records DeriveKey. | OperationDeriveKey 记录 DeriveKey。
	OperationDeriveKey = "crypto.derive_key"
	// OperationRandom records GenerateRandom. | OperationRandom 记录 GenerateRandom。
	OperationRandom = "crypto.random"
)

// AuditEvent is one append-only security-relevant KMS event. | AuditEvent 是一个只追加的 KMS 安全相关事件。
//
// Detail holds scalar attributes such as key type, version and algorithm. It must never contain
// plaintext, key material, passphrases or wrapped DEKs; the service only records non-secret
// metadata. | Detail 保存密钥类型、版本与算法等标量属性。它绝不能包含明文、密钥材料、口令或
// 已包装 DEK；服务只记录非机密元数据。
type AuditEvent struct {
	// ID is the event identifier; the store assigns one when empty. | ID 是事件标识；为空时由存储分配。
	ID string `json:"id"`
	// Operation is a stable operation name such as "key.create". | Operation 是稳定操作名，例如 "key.create"。
	Operation string `json:"operation"`
	// Actor is the authenticated subject that caused the operation. | Actor 是触发操作的已认证主体。
	Actor string `json:"actor,omitempty"`
	// KeyID is the affected key, when any. | KeyID 是受影响的密钥（如有）。
	KeyID string `json:"keyId,omitempty"`
	// KeyVersion is the affected key version, when any. | KeyVersion 是受影响的密钥版本（如有）。
	KeyVersion uint32 `json:"keyVersion,omitempty"`
	// Outcome is OutcomeSuccess, OutcomeFailure or OutcomeDenied. | Outcome 取值为 OutcomeSuccess、OutcomeFailure 或 OutcomeDenied。
	Outcome string `json:"outcome"`
	// Detail holds non-secret scalar attributes. | Detail 保存非机密标量属性。
	Detail map[string]string `json:"detail,omitempty"`
	// At is the UTC event time. | At 是 UTC 事件时间。
	At time.Time `json:"at"`
}

// Clone returns a deep copy of e. | Clone 返回 e 的深拷贝。
func (e *AuditEvent) Clone() *AuditEvent {
	if e == nil {
		return nil
	}
	c := *e
	if len(e.Detail) > 0 {
		c.Detail = make(map[string]string, len(e.Detail))
		for key, value := range e.Detail {
			c.Detail[key] = value
		}
	}
	return &c
}

// AuditFilter filters ListAudit results. | AuditFilter 过滤 ListAudit 结果。
type AuditFilter struct {
	// Operation filters by operation name. | Operation 按操作名过滤。
	Operation string
	// KeyID filters by affected key. | KeyID 按受影响密钥过滤。
	KeyID string
	// Actor filters by actor. | Actor 按触发者过滤。
	Actor string
	// Outcome filters by outcome. | Outcome 按结果过滤。
	Outcome string
	// Since and Until bound At inclusively. | Since 与 Until 包含式限定 At。
	Since time.Time
	Until time.Time
	// Offset and Limit paginate; Limit 0 means no limit. | Offset 与 Limit 分页；Limit 为 0 表示不限。
	Offset int
	Limit  int
	// Descending reverses chronological order. | Descending 反转时间顺序。
	Descending bool
}

// matches reports whether e passes the filter. | matches 报告 e 是否通过过滤器。
func (f AuditFilter) matches(e *AuditEvent) bool {
	if e == nil {
		return false
	}
	if f.Operation != "" && e.Operation != f.Operation {
		return false
	}
	if f.KeyID != "" && e.KeyID != f.KeyID {
		return false
	}
	if f.Actor != "" && e.Actor != f.Actor {
		return false
	}
	if f.Outcome != "" && e.Outcome != f.Outcome {
		return false
	}
	if !f.Since.IsZero() && e.At.Before(f.Since) {
		return false
	}
	if !f.Until.IsZero() && e.At.After(f.Until) {
		return false
	}
	return true
}

// sortAudit orders events chronologically with a stable tie-break on ID. | sortAudit 按时间排序，并以 ID 稳定打破平局。
func sortAudit(events []*AuditEvent, descending bool) {
	sort.SliceStable(events, func(i, j int) bool {
		if events[i].At.Equal(events[j].At) {
			if descending {
				return events[i].ID > events[j].ID
			}
			return events[i].ID < events[j].ID
		}
		if descending {
			return events[i].At.After(events[j].At)
		}
		return events[i].At.Before(events[j].At)
	})
}

// AuditSink appends and lists audit events. | AuditSink 追加与列出审计事件。
type AuditSink interface {
	// AppendAudit stores one event and assigns ID and At when they are empty. | AppendAudit 保存一个事件，并在 ID 与 At 为空时赋值。
	AppendAudit(ctx context.Context, event *AuditEvent) error
	// ListAudit returns the matching events in the requested order. | ListAudit 按请求顺序返回匹配事件。
	ListAudit(ctx context.Context, filter AuditFilter) ([]*AuditEvent, error)
}

// actorKey is the context key of the audit actor. | actorKey 是审计触发者的上下文键。
type actorKey struct{}

// WithActor returns a child context carrying the audit actor. | WithActor 返回携带审计触发者的子上下文。
//
// HTTP servers populate it from auth.Principal; embedded callers may set any stable subject. | HTTP
// 服务端会从 auth.Principal 填充；嵌入式调用方可设置任意稳定主体。
func WithActor(ctx context.Context, actor string) context.Context {
	if ctx == nil {
		ctx = context.Background()
	}
	return context.WithValue(ctx, actorKey{}, actor)
}

// ActorFromContext returns the actor stored by WithActor. | ActorFromContext 返回 WithActor 存储的触发者。
func ActorFromContext(ctx context.Context) string {
	if ctx == nil {
		return ""
	}
	actor, _ := ctx.Value(actorKey{}).(string)
	return actor
}

// errAuditNilEvent is returned when a nil audit event is appended. | errAuditNilEvent 在追加空审计事件时返回。
var errAuditNilEvent = errs.New("kms: nil audit event | kms：审计事件为空")
