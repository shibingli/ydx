package kmip

import (
	"errors"
	"runtime"
	"time"

	"github.com/shibingli/ydx/errs"
)

// Version constants of the KMIP protocol versions implemented by this package. | 本包实现的 KMIP 协议版本常量。
const (
	// MajorVersion1 is the major number of the KMIP 1.x family. | MajorVersion1 是 KMIP 1.x 系列的主版本号。
	MajorVersion1 = 1
	// MajorVersion2 is the major number of the KMIP 2.x family. | MajorVersion2 是 KMIP 2.x 系列的主版本号。
	MajorVersion2 = 2
)

// Default protocol limits. | 默认协议限制。
const (
	// DefaultMaxMessageSize is the default maximum size of a single TTLV message (16 MiB). | DefaultMaxMessageSize 是单个 TTLV 消息的默认最大长度（16 MiB）。
	DefaultMaxMessageSize = 16 << 20
	// DefaultMaxDepth is the default maximum nesting depth of a TTLV item tree. | DefaultMaxDepth 是 TTLV 项树默认的最大嵌套深度。
	DefaultMaxDepth = 32
	// DefaultMaxItems is the default maximum number of items in one TTLV message. | DefaultMaxItems 是单个 TTLV 消息默认的最大项数量。
	DefaultMaxItems = 1 << 16
	// DefaultMaxBatchItems is the default maximum number of batch items in one message. | DefaultMaxBatchItems 是单个消息默认的最大批处理项数量。
	DefaultMaxBatchItems = 256
)

// ProtocolVersion is a KMIP protocol version. | ProtocolVersion 是 KMIP 协议版本。
//
// The zero value is not a valid KMIP version; use one of the declared values or ProtocolVersion{Major: 1, Minor: 4}. | 零值不是合法的 KMIP 版本；请使用已声明的值或 ProtocolVersion{Major: 1, Minor: 4}。
type ProtocolVersion struct {
	// Major is the major version number. | Major 是主版本号。
	Major int
	// Minor is the minor version number. | Minor 是次版本号。
	Minor int
}

// The KMIP protocol versions supported by this implementation. | 本实现支持的 KMIP 协议版本。
var (
	// ProtocolVersion10 is KMIP 1.0. It is declared for reference and rejected on the wire. |
	// ProtocolVersion10 是 KMIP 1.0；仅作参考声明，在线路上会被拒绝。
	ProtocolVersion10 = ProtocolVersion{Major: 1, Minor: 0}
	// ProtocolVersion11 is KMIP 1.1. It is declared for reference and rejected on the wire. |
	// ProtocolVersion11 是 KMIP 1.1；仅作参考声明，在线路上会被拒绝。
	ProtocolVersion11 = ProtocolVersion{Major: 1, Minor: 1}
	// ProtocolVersion12 is KMIP 1.2. It is declared for reference and rejected on the wire. |
	// ProtocolVersion12 是 KMIP 1.2；仅作参考声明，在线路上会被拒绝。
	ProtocolVersion12 = ProtocolVersion{Major: 1, Minor: 2}
	// ProtocolVersion13 is KMIP 1.3. It is declared for reference and rejected on the wire. |
	// ProtocolVersion13 是 KMIP 1.3；仅作参考声明，在线路上会被拒绝。
	ProtocolVersion13 = ProtocolVersion{Major: 1, Minor: 3}
	// ProtocolVersion14 is KMIP 1.4, the default version used by the client and server. | ProtocolVersion14 是 KMIP 1.4，也是客户端与服务器默认使用的版本。
	ProtocolVersion14 = ProtocolVersion{Major: 1, Minor: 4}
	// ProtocolVersion20 is KMIP 2.0. | ProtocolVersion20 是 KMIP 2.0。
	ProtocolVersion20 = ProtocolVersion{Major: 2, Minor: 0}
)

// DefaultProtocolVersion is the version used when a request does not state one explicitly. | DefaultProtocolVersion 是请求未显式声明版本时使用的版本。
var DefaultProtocolVersion = ProtocolVersion14

// String renders the version as "major.minor". | String 以 "major.minor" 形式渲染版本。
func (v ProtocolVersion) String() string {
	return itoa(v.Major) + "." + itoa(v.Minor)
}

// Compare compares two versions: it returns -1 when v is older, 0 when equal and 1 when newer. | Compare 比较两个版本：v 更旧返回 -1，相同返回 0，更新返回 1。
func (v ProtocolVersion) Compare(other ProtocolVersion) int {
	switch {
	case v.Major < other.Major:
		return -1
	case v.Major > other.Major:
		return 1
	case v.Minor < other.Minor:
		return -1
	case v.Minor > other.Minor:
		return 1
	default:
		return 0
	}
}

// Valid reports whether the version is a positive major/minor pair. | Valid 报告版本是否是正的主次版本号对。
func (v ProtocolVersion) Valid() bool {
	return v.Major > 0 && v.Minor >= 0
}

// Supported reports whether this package accepts the version on the wire. | Supported 报告本包是否在线路上接受该版本。
//
// Only KMIP 1.4 and 2.0 are accepted. Versions 1.0 through 1.3 are declared for reference but rejected with
// ErrUnsupported because this implementation does not carry their older payload variants. KMIP 1.4 uses the
// Template-Attribute payload structures; KMIP 2.0 uses the Attributes payload structures, including the Attributes,
// Common Attributes, Private Key Attributes, Public Key Attributes and Attribute Reference tags, selected from the
// request header version. | 仅接受 KMIP 1.4 与 2.0。1.0 至 1.3 仅作参考声明，因本实现不携带其更旧的负载变体而返回
// ErrUnsupported。KMIP 1.4 使用 Template-Attribute 负载结构；KMIP 2.0 使用 Attributes 负载结构，包括
// Attributes、Common Attributes、Private Key Attributes、Public Key Attributes 与 Attribute Reference 标签，
// 并按请求头版本选择。
func (v ProtocolVersion) Supported() bool {
	return v == ProtocolVersion14 || v == ProtocolVersion20
}

// SupportedProtocolVersions returns the protocol versions advertised by DiscoverVersions. | SupportedProtocolVersions
// 返回 DiscoverVersions 通告的协议版本。
//
// KMIP 2.0 and 1.4 are advertised. The returned slice is a fresh copy that callers may modify. | 通告 KMIP 2.0
// 与 1.4。返回的切片是全新副本，调用方可自由修改。
func SupportedProtocolVersions() []ProtocolVersion {
	return []ProtocolVersion{ProtocolVersion20, ProtocolVersion14}
}

// Limits bounds the resources a single TTLV message may consume. | Limits 限制单个 TTLV 消息可消耗的资源。
//
// Zero fields are replaced by the corresponding Default* constant when the limits are used. | 零值字段在使用时会被对应的 Default* 常量替换。
type Limits struct {
	// MaxSize is the maximum total encoded message size in bytes. | MaxSize 是消息编码后的最大总字节数。
	MaxSize int
	// MaxDepth is the maximum nesting depth of structures. | MaxDepth 是结构嵌套的最大深度。
	MaxDepth int
	// MaxItems is the maximum number of TTLV items (including children). | MaxItems 是 TTLV 项（含子项）的最大数量。
	MaxItems int
}

// DefaultLimits returns the package default resource limits. | DefaultLimits 返回本包的默认资源限制。
func DefaultLimits() Limits {
	return Limits{MaxSize: DefaultMaxMessageSize, MaxDepth: DefaultMaxDepth, MaxItems: DefaultMaxItems}
}

// normalized replaces zero or negative fields with defaults. | normalized 用默认值替换零值或负值字段。
func (l Limits) normalized() Limits {
	if l.MaxSize <= 0 {
		l.MaxSize = DefaultMaxMessageSize
	}
	if l.MaxDepth <= 0 {
		l.MaxDepth = DefaultMaxDepth
	}
	if l.MaxItems <= 0 {
		l.MaxItems = DefaultMaxItems
	}
	return l
}

// Clock is a source of the current time, injectable for tests. | Clock 是当前时间来源，可在测试中注入。
type Clock func() time.Time

// The sentinel errors of the kmip package. | kmip 包的哨兵错误。
//
// Every failure path returns one of them directly or through errs.Detail / errs.Wrap, and ResultError maps KMIP result
// reasons onto them, so callers can classify failures with errors.Is. | 所有失败路径都直接或经由 errs.Detail / errs.Wrap
// 返回其中之一；ResultError 把 KMIP 结果原因映射到这些哨兵，因此调用方可用 errors.Is 分类失败。
var (
	// ErrMalformed reports an invalid or truncated TTLV encoding, or a message that violates the KMIP framing rules. | ErrMalformed 表示 TTLV 编码非法或截断，或消息违反 KMIP 框架规则。
	ErrMalformed = errs.New("kmip: malformed message | kmip：消息格式非法")
	// ErrLimitExceeded reports a message that exceeds a size, depth or item-count limit. | ErrLimitExceeded 表示消息超出长度、深度或项数限制。
	ErrLimitExceeded = errs.New("kmip: protocol limit exceeded | kmip：超出协议限制")
	// ErrUnsupported reports an operation, algorithm, key format or feature that this implementation does not support. | ErrUnsupported 表示本实现不支持的操作、算法、密钥格式或特性。
	ErrUnsupported = errs.New("kmip: unsupported operation or feature | kmip：不支持的操作或特性")
	// ErrInvalidRequest reports a structurally valid message with missing or contradictory fields. | ErrInvalidRequest 表示结构合法但字段缺失或相互矛盾的请求。
	ErrInvalidRequest = errs.New("kmip: invalid request | kmip：请求非法")
	// ErrItemNotFound reports that the requested managed object does not exist. | ErrItemNotFound 表示请求的受管对象不存在。
	ErrItemNotFound = errs.New("kmip: item not found | kmip：对象不存在")
	// ErrPermissionDenied reports an authorization failure or a sensitive/non-extractable object. | ErrPermissionDenied 表示授权失败，或对象敏感/不可导出。
	ErrPermissionDenied = errs.New("kmip: permission denied | kmip：权限不足")
	// ErrIllegalOperation reports an operation that the object's state does not allow. | ErrIllegalOperation 表示对象状态不允许该操作。
	ErrIllegalOperation = errs.New("kmip: illegal operation for object state | kmip：对象状态不允许该操作")
	// ErrAuthenticationFailed reports failed client authentication. | ErrAuthenticationFailed 表示客户端认证失败。
	ErrAuthenticationFailed = errs.New("kmip: authentication failed | kmip：认证失败")
	// ErrCryptographic reports a cryptographic failure such as a bad ciphertext or a missing usage-mask bit. | ErrCryptographic 表示密码学失败，如密文损坏或缺少用法掩码位。
	ErrCryptographic = errs.New("kmip: cryptographic operation failed | kmip：密码学操作失败")
	// ErrState reports an invalid lifecycle transition. | ErrState 表示非法的生命周期状态迁移。
	ErrState = errs.New("kmip: invalid state transition | kmip：非法状态迁移")
	// ErrClosed reports an operation attempted on a closed client or server. | ErrClosed 表示在已关闭的客户端或服务器上尝试操作。
	ErrClosed = errs.New("kmip: client or server is closed | kmip：客户端或服务器已关闭")
	// ErrTransport reports a transport-level failure such as a failed dial or a read/write error. Context
	// cancellation and deadlines are returned as context.Canceled or context.DeadlineExceeded instead. | ErrTransport
	// 表示传输层失败，例如拨号失败或读写错误。上下文取消与截止时间改为返回 context.Canceled 或
	// context.DeadlineExceeded。
	ErrTransport = errs.New("kmip: transport failure | kmip：传输失败")
	// ErrTLSRequired reports a plaintext configuration on a path that requires TLS. | ErrTLSRequired 表示在要求 TLS 的路径上使用了明文配置。
	ErrTLSRequired = errs.New("kmip: TLS is required | kmip：必须使用 TLS")
	// ErrResponseTooLarge reports a response larger than the client's configured maximum. | ErrResponseTooLarge 表示响应超过客户端配置的最大长度。
	ErrResponseTooLarge = errs.New("kmip: response too large | kmip：响应过大")
	// ErrUsageMask reports that a key's cryptographic usage mask does not allow the requested operation. | ErrUsageMask 表示密钥的密码学用法掩码不允许所请求的操作。
	ErrUsageMask = errs.New("kmip: cryptographic usage mask does not allow the operation | kmip：密码学用法掩码不允许该操作")
	// ErrObjectExists reports a duplicate unique identifier. | ErrObjectExists 表示唯一标识符重复。
	ErrObjectExists = errs.New("kmip: object already exists | kmip：对象已存在")
)

// zeroize overwrites a byte slice with zeros. | zeroize 用零覆盖字节切片。
//
// The compiler is prevented from optimizing the loop away with runtime.KeepAlive. | 通过 runtime.KeepAlive 阻止编译器把循环优化掉。
func zeroize(b []byte) {
	for i := range b {
		b[i] = 0
	}
	runtime.KeepAlive(b)
}

// itoa converts a small non-negative integer to decimal without importing strconv in hot paths. | itoa 把较小的非负整数转为十进制，避免在热路径导入 strconv。
func itoa(v int) string {
	if v == 0 {
		return "0"
	}
	if v < 0 {
		return "-" + itoa(-v)
	}
	var buf [20]byte
	i := len(buf)
	for v > 0 {
		i--
		buf[i] = byte('0' + v%10)
		v /= 10
	}
	return string(buf[i:])
}

// resultErrorFor builds a ResultError. | resultErrorFor 构造 ResultError。
func resultErrorFor(status ResultStatus, reason ResultReason, message string) *ResultError {
	return &ResultError{Status: status, Reason: reason, Message: message}
}

// operationFailed builds an operation-failed result. | operationFailed 构造操作失败结果。
func operationFailed(reason ResultReason, message string) *ResultError {
	return resultErrorFor(ResultStatusOperationFailed, reason, message)
}

// ResultError is a KMIP batch-item failure. | ResultError 是 KMIP 批处理项失败。
//
// It implements error and supports errors.Is through its mapped sentinel; errors.As can recover the structured reason,
// status and message. | 它实现 error 并通过映射的哨兵支持 errors.Is；errors.As 可取回结构化的原因、状态与消息。
type ResultError struct {
	// Status is the result status, normally ResultStatusOperationFailed. | Status 是结果状态，通常为 ResultStatusOperationFailed。
	Status ResultStatus
	// Reason is the KMIP result reason. | Reason 是 KMIP 结果原因。
	Reason ResultReason
	// Message is a human-readable diagnostic that must never contain key material. | Message 是人类可读的诊断信息，绝不能包含密钥材料。
	Message string
}

// Error implements error. | Error 实现 error。
func (e *ResultError) Error() string {
	if e == nil {
		return "<nil>"
	}
	if e.Message != "" {
		return "kmip: " + e.Status.String() + " (" + e.Reason.String() + "): " + e.Message
	}
	return "kmip: " + e.Status.String() + " (" + e.Reason.String() + ")"
}

// Unwrap returns the sentinel error mapped from the result reason. | Unwrap 返回由结果原因映射的哨兵错误。
func (e *ResultError) Unwrap() error {
	if e == nil {
		return nil
	}
	return sentinelForReason(e.Reason)
}

// Is reports whether target is the generic ErrOperationFailed and this result failed, in addition to the sentinel
// reported by Unwrap. | Is 除 Unwrap 报告的哨兵外，还报告 target 为通用 ErrOperationFailed 且本结果失败。
func (e *ResultError) Is(target error) bool {
	if e == nil {
		return false
	}
	if target == ErrOperationFailed {
		return e.Status == ResultStatusOperationFailed
	}
	return false
}

// ErrOperationFailed is the generic sentinel matched by any failed ResultError through errors.Is. | ErrOperationFailed 是任何失败的 ResultError 经 errors.Is 匹配到的通用哨兵。
var ErrOperationFailed = errs.New("kmip: operation failed | kmip：操作失败")

// sentinelForReason maps a KMIP result reason onto a package sentinel. | sentinelForReason 把 KMIP 结果原因映射到包哨兵。
func sentinelForReason(reason ResultReason) error {
	switch reason {
	case ResultReasonItemNotFound:
		return ErrItemNotFound
	case ResultReasonAuthenticationNotSuccessful:
		return ErrAuthenticationFailed
	case ResultReasonInvalidMessage, ResultReasonInvalidField, ResultReasonMissingData:
		return ErrMalformed
	case ResultReasonOperationNotSupported, ResultReasonFeatureNotSupported,
		ResultReasonKeyFormatTypeNotSupported, ResultReasonKeyCompressionTypeNotSupported,
		ResultReasonEncodingOptionError, ResultReasonKeyWrapTypeNotSupported:
		return ErrUnsupported
	case ResultReasonIllegalOperation:
		return ErrIllegalOperation
	case ResultReasonPermissionDenied, ResultReasonSensitive, ResultReasonNotExtractable:
		return ErrPermissionDenied
	case ResultReasonCryptographicFailure, ResultReasonBadCryptographicParameters:
		return ErrCryptographic
	case ResultReasonIncompatibleCryptographicUsageMask:
		return ErrUsageMask
	case ResultReasonObjectAlreadyExists:
		return ErrObjectExists
	case ResultReasonGeneralFailure, ResultReasonInternalServerError:
		return ErrOperationFailed
	case ResultReasonResponseTooLarge:
		return ErrResponseTooLarge
	case ResultReasonInvalidObjectType, ResultReasonInvalidAttribute, ResultReasonInvalidAttributeValue,
		ResultReasonBadPassword, ResultReasonNumericRange, ResultReasonInvalidDataType:
		return ErrInvalidRequest
	default:
		return ErrOperationFailed
	}
}

// asResultError converts err into a *ResultError, defaulting to a general failure. | asResultError 把 err 转为 *ResultError，默认使用通用失败。
func asResultError(err error) *ResultError {
	var re *ResultError
	if errors.As(err, &re) {
		return re
	}
	switch {
	case errors.Is(err, ErrItemNotFound):
		return operationFailed(ResultReasonItemNotFound, err.Error())
	case errors.Is(err, ErrAuthenticationFailed):
		return operationFailed(ResultReasonAuthenticationNotSuccessful, err.Error())
	case errors.Is(err, ErrUnsupported):
		return operationFailed(ResultReasonOperationNotSupported, err.Error())
	case errors.Is(err, ErrIllegalOperation):
		return operationFailed(ResultReasonIllegalOperation, err.Error())
	case errors.Is(err, ErrPermissionDenied):
		return operationFailed(ResultReasonPermissionDenied, err.Error())
	case errors.Is(err, ErrCryptographic):
		return operationFailed(ResultReasonCryptographicFailure, err.Error())
	case errors.Is(err, ErrUsageMask):
		return operationFailed(ResultReasonIncompatibleCryptographicUsageMask, err.Error())
	case errors.Is(err, ErrState):
		return operationFailed(ResultReasonIllegalOperation, err.Error())
	case errors.Is(err, ErrObjectExists):
		return operationFailed(ResultReasonObjectAlreadyExists, err.Error())
	case errors.Is(err, ErrInvalidRequest), errors.Is(err, ErrMalformed), errors.Is(err, ErrLimitExceeded):
		return operationFailed(ResultReasonInvalidMessage, err.Error())
	case errors.Is(err, ErrClosed):
		return operationFailed(ResultReasonGeneralFailure, err.Error())
	default:
		return operationFailed(ResultReasonGeneralFailure, err.Error())
	}
}
