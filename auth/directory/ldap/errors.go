package ldap

import (
	"strconv"
	"strings"

	"github.com/shibingli/ydx/errs"
)

// The declared sentinels of the package. | 本包声明的哨兵错误。
//
// Every failure path returns one of these values directly or wraps it with
// errs.Detail / errs.Wrap, so callers classify failures with errors.Is instead
// of matching text. | 所有失败路径都直接返回其中之一，或通过 errs.Detail /
// errs.Wrap 包装，因此调用方用 errors.Is 分类错误而不是匹配文案。
var (
	// ErrInvalidConfig reports an unusable client configuration. | ErrInvalidConfig 表示客户端配置不可用。
	ErrInvalidConfig = errs.New("ldap: invalid configuration | ldap：配置非法")
	// ErrInvalidURL reports an endpoint that is not a valid ldap or ldaps URL. | ErrInvalidURL 表示不是合法的 ldap 或 ldaps 地址。
	ErrInvalidURL = errs.New("ldap: invalid URL | ldap：地址非法")
	// ErrInvalidFilter reports an RFC 4515 filter syntax error. | ErrInvalidFilter 表示 RFC 4515 过滤器语法错误。
	ErrInvalidFilter = errs.New("ldap: invalid filter | ldap：过滤器非法")
	// ErrInvalidMessage reports a malformed local protocol object. | ErrInvalidMessage 表示本地协议对象非法。
	ErrInvalidMessage = errs.New("ldap: invalid message | ldap：消息非法")
	// ErrInvalidResponse reports a malformed or unexpected server response. | ErrInvalidResponse 表示服务端响应畸形或不符合预期。
	ErrInvalidResponse = errs.New("ldap: invalid response | ldap：响应非法")
	// ErrInvalidMessageTooLarge reports a message above the configured limit. | ErrInvalidMessageTooLarge 表示消息超过配置上限。
	ErrInvalidMessageTooLarge = errs.New("ldap: message exceeds size limit | ldap：消息超过大小限制")
	// ErrUnexpectedResponse reports a response that does not match the request. | ErrUnexpectedResponse 表示响应与请求不匹配。
	ErrUnexpectedResponse = errs.New("ldap: unexpected response | ldap：响应不符合预期")
	// ErrProtocolError reports a BER or LDAP protocol violation. | ErrProtocolError 表示 BER 或 LDAP 协议违规。
	ErrProtocolError = errs.New("ldap: protocol error | ldap：协议错误")
	// ErrNetwork reports a transport failure. | ErrNetwork 表示传输层故障。
	ErrNetwork = errs.New("ldap: network error | ldap：网络错误")
	// ErrTimeout reports an operation deadline. | ErrTimeout 表示操作超时。
	ErrTimeout = errs.New("ldap: timeout | ldap：超时")
	// ErrClosed reports use of a closed client or pool. | ErrClosed 表示使用了已关闭的客户端或连接池。
	ErrClosed = errs.New("ldap: closed | ldap：已关闭")
	// ErrPoolClosed reports use of a closed pool. | ErrPoolClosed 表示使用了已关闭的连接池。
	ErrPoolClosed = errs.New("ldap: pool closed | ldap：连接池已关闭")
	// ErrTLSRequired reports an operation that only runs over TLS. | ErrTLSRequired 表示操作只能通过 TLS 执行。
	ErrTLSRequired = errs.New("ldap: TLS required | ldap：需要 TLS")
	// ErrEmptyPassword reports a password that must not be sent. | ErrEmptyPassword 表示不得发送的空口令。
	ErrEmptyPassword = errs.New("ldap: empty password rejected | ldap：已拒绝空口令")
	// ErrNotSupported reports a feature this client does not implement. | ErrNotSupported 表示客户端未实现该功能。
	ErrNotSupported = errs.New("ldap: not supported | ldap：不支持")
	// ErrSASL reports a SASL negotiation failure. | ErrSASL 表示 SASL 协商失败。
	ErrSASL = errs.New("ldap: SASL failure | ldap：SASL 失败")
	// ErrSCRAM reports a SCRAM protocol or verification failure. | ErrSCRAM 表示 SCRAM 协议或校验失败。
	ErrSCRAM = errs.New("ldap: SCRAM failure | ldap：SCRAM 失败")
	// ErrNTLM reports an NTLM or SPNEGO negotiation failure. | ErrNTLM 表示 NTLM 或
	// SPNEGO 协商失败。
	ErrNTLM = errs.New("ldap: NTLM failure | ldap：NTLM 失败")
	// ErrPagingUnsupported reports a missing paged results response control. | ErrPagingUnsupported 表示缺少分页结果响应控件。
	ErrPagingUnsupported = errs.New("ldap: server does not support paged results | ldap：服务端不支持分页结果")
	// ErrPagingLoop reports a paging cookie that repeats, which would otherwise loop forever. |
	// ErrPagingLoop 表示分页 cookie 重复，否则会无限循环。
	ErrPagingLoop = errs.New("ldap: paging cookie did not advance | ldap：分页 cookie 未前进")
	// ErrPagingLimit reports that automatic paging reached SearchOptions.MaxPages. |
	// ErrPagingLimit 表示自动分页达到 SearchOptions.MaxPages。
	ErrPagingLimit = errs.New("ldap: paging page limit exceeded | ldap：分页页数超过上限")
	// ErrAmbiguousUser reports a login that resolves to multiple directory entries. | ErrAmbiguousUser 表示登录名解析到多个目录条目。
	ErrAmbiguousUser = errs.New("ldap: ambiguous user | ldap：用户不唯一")
	// ErrServiceBindRequired reports an operation that needs configured service credentials. | ErrServiceBindRequired 表示操作需要已配置的服务账号。
	ErrServiceBindRequired = errs.New("ldap: service bind required | ldap：需要服务账号绑定")
	// ErrADDiscovery reports a failed Active Directory domain-controller lookup. | ErrADDiscovery 表示 Active Directory 域控发现失败。
	ErrADDiscovery = errs.New("ldap: Active Directory discovery failed | ldap：Active Directory 发现失败")

	// ErrOperationsError is LDAP result code 1. | ErrOperationsError 是 LDAP 结果码 1。
	ErrOperationsError = errs.New("ldap: operations error | ldap：操作错误")
	// ErrTimeLimitExceeded is LDAP result code 3. | ErrTimeLimitExceeded 是 LDAP 结果码 3。
	ErrTimeLimitExceeded = errs.New("ldap: time limit exceeded | ldap：超过时间限制")
	// ErrSizeLimitExceeded is LDAP result code 4. | ErrSizeLimitExceeded 是 LDAP 结果码 4。
	ErrSizeLimitExceeded = errs.New("ldap: size limit exceeded | ldap：超过大小限制")
	// ErrCompareFalse is LDAP result code 5. | ErrCompareFalse 是 LDAP 结果码 5。
	ErrCompareFalse = errs.New("ldap: compare false | ldap：比较结果为假")
	// ErrCompareTrue is LDAP result code 6. | ErrCompareTrue 是 LDAP 结果码 6。
	ErrCompareTrue = errs.New("ldap: compare true | ldap：比较结果为真")
	// ErrAuthMethodNotSupported is LDAP result code 7. | ErrAuthMethodNotSupported 是 LDAP 结果码 7。
	ErrAuthMethodNotSupported = errs.New("ldap: authentication method not supported | ldap：不支持该认证方式")
	// ErrStrongAuthRequired is LDAP result code 8. | ErrStrongAuthRequired 是 LDAP 结果码 8。
	ErrStrongAuthRequired = errs.New("ldap: stronger authentication required | ldap：需要更强认证")
	// ErrReferral is LDAP result code 10. | ErrReferral 是 LDAP 结果码 10。
	ErrReferral = errs.New("ldap: referral | ldap：转介")
	// ErrAdminLimitExceeded is LDAP result code 11. | ErrAdminLimitExceeded 是 LDAP 结果码 11。
	ErrAdminLimitExceeded = errs.New("ldap: administrative limit exceeded | ldap：超过管理限制")
	// ErrUnavailableCriticalExtension is LDAP result code 12. | ErrUnavailableCriticalExtension 是 LDAP 结果码 12。
	ErrUnavailableCriticalExtension = errs.New("ldap: unavailable critical extension | ldap：关键扩展不可用")
	// ErrConfidentialityRequired is LDAP result code 13. | ErrConfidentialityRequired 是 LDAP 结果码 13。
	ErrConfidentialityRequired = errs.New("ldap: confidentiality required | ldap：要求机密性保护")
	// ErrSASLBindInProgress is LDAP result code 14. | ErrSASLBindInProgress 是 LDAP 结果码 14。
	ErrSASLBindInProgress = errs.New("ldap: SASL bind in progress | ldap：SASL 绑定进行中")
	// ErrNoSuchAttribute is LDAP result code 16. | ErrNoSuchAttribute 是 LDAP 结果码 16。
	ErrNoSuchAttribute = errs.New("ldap: no such attribute | ldap：属性不存在")
	// ErrUndefinedAttributeType is LDAP result code 17. | ErrUndefinedAttributeType 是 LDAP 结果码 17。
	ErrUndefinedAttributeType = errs.New("ldap: undefined attribute type | ldap：属性类型未定义")
	// ErrConstraintViolation is LDAP result code 19. | ErrConstraintViolation 是 LDAP 结果码 19。
	ErrConstraintViolation = errs.New("ldap: constraint violation | ldap：违反约束")
	// ErrAttributeOrValueExists is LDAP result code 20. | ErrAttributeOrValueExists 是 LDAP 结果码 20。
	ErrAttributeOrValueExists = errs.New("ldap: attribute or value exists | ldap：属性或值已存在")
	// ErrInvalidAttributeSyntax is LDAP result code 21. | ErrInvalidAttributeSyntax 是 LDAP 结果码 21。
	ErrInvalidAttributeSyntax = errs.New("ldap: invalid attribute syntax | ldap：属性语法非法")
	// ErrNoSuchObject is LDAP result code 32. | ErrNoSuchObject 是 LDAP 结果码 32。
	ErrNoSuchObject = errs.New("ldap: no such object | ldap：对象不存在")
	// ErrAliasProblem is LDAP result code 33. | ErrAliasProblem 是 LDAP 结果码 33。
	ErrAliasProblem = errs.New("ldap: alias problem | ldap：别名问题")
	// ErrInvalidDNSyntax is LDAP result code 34. | ErrInvalidDNSyntax 是 LDAP 结果码 34。
	ErrInvalidDNSyntax = errs.New("ldap: invalid DN syntax | ldap：DN 语法非法")
	// ErrAliasDereferencingProblem is LDAP result code 36. | ErrAliasDereferencingProblem 是 LDAP 结果码 36。
	ErrAliasDereferencingProblem = errs.New("ldap: alias dereferencing problem | ldap：别名解引用问题")
	// ErrInappropriateAuthentication is LDAP result code 48. | ErrInappropriateAuthentication 是 LDAP 结果码 48。
	ErrInappropriateAuthentication = errs.New("ldap: inappropriate authentication | ldap：认证方式不适用")
	// ErrInvalidCredentials is LDAP result code 49. | ErrInvalidCredentials 是 LDAP 结果码 49。
	ErrInvalidCredentials = errs.New("ldap: invalid credentials | ldap：凭据无效")
	// ErrInsufficientAccess is LDAP result code 50. | ErrInsufficientAccess 是 LDAP 结果码 50。
	ErrInsufficientAccess = errs.New("ldap: insufficient access rights | ldap：权限不足")
	// ErrBusy is LDAP result code 51. | ErrBusy 是 LDAP 结果码 51。
	ErrBusy = errs.New("ldap: server busy | ldap：服务端繁忙")
	// ErrUnavailable is LDAP result code 52. | ErrUnavailable 是 LDAP 结果码 52。
	ErrUnavailable = errs.New("ldap: server unavailable | ldap：服务端不可用")
	// ErrUnwillingToPerform is LDAP result code 53. | ErrUnwillingToPerform 是 LDAP 结果码 53。
	ErrUnwillingToPerform = errs.New("ldap: unwilling to perform | ldap：服务端拒绝执行")
	// ErrLoopDetect is LDAP result code 54. | ErrLoopDetect 是 LDAP 结果码 54。
	ErrLoopDetect = errs.New("ldap: loop detected | ldap：检测到循环")
	// ErrSortControlMissing is LDAP result code 60. | ErrSortControlMissing 是 LDAP 结果码 60。
	ErrSortControlMissing = errs.New("ldap: sort control missing | ldap：缺少排序控件")
	// ErrOffsetRangeError is LDAP result code 61. | ErrOffsetRangeError 是 LDAP 结果码 61。
	ErrOffsetRangeError = errs.New("ldap: offset range error | ldap：偏移范围错误")
	// ErrNamingViolation is LDAP result code 64. | ErrNamingViolation 是 LDAP 结果码 64。
	ErrNamingViolation = errs.New("ldap: naming violation | ldap：命名违规")
	// ErrObjectClassViolation is LDAP result code 65. | ErrObjectClassViolation 是 LDAP 结果码 65。
	ErrObjectClassViolation = errs.New("ldap: object class violation | ldap：对象类违规")
	// ErrNotAllowedOnNonLeaf is LDAP result code 66. | ErrNotAllowedOnNonLeaf 是 LDAP 结果码 66。
	ErrNotAllowedOnNonLeaf = errs.New("ldap: not allowed on non-leaf | ldap：不允许在非叶子节点执行")
	// ErrNotAllowedOnRDN is LDAP result code 67. | ErrNotAllowedOnRDN 是 LDAP 结果码 67。
	ErrNotAllowedOnRDN = errs.New("ldap: not allowed on RDN | ldap：不允许在 RDN 上执行")
	// ErrEntryAlreadyExists is LDAP result code 68. | ErrEntryAlreadyExists 是 LDAP 结果码 68。
	ErrEntryAlreadyExists = errs.New("ldap: entry already exists | ldap：条目已存在")
	// ErrObjectClassModsProhibited is LDAP result code 69. | ErrObjectClassModsProhibited 是 LDAP 结果码 69。
	ErrObjectClassModsProhibited = errs.New("ldap: object class modifications prohibited | ldap：禁止修改对象类")
	// ErrResultsTooLarge is LDAP result code 70. | ErrResultsTooLarge 是 LDAP 结果码 70。
	ErrResultsTooLarge = errs.New("ldap: results too large | ldap：结果过大")
	// ErrAffectsMultipleDSAs is LDAP result code 71. | ErrAffectsMultipleDSAs 是 LDAP 结果码 71。
	ErrAffectsMultipleDSAs = errs.New("ldap: operation affects multiple DSAs | ldap：操作影响多个 DSA")
	// ErrVirtualListViewError is LDAP result code 76. | ErrVirtualListViewError 是 LDAP 结果码 76。
	ErrVirtualListViewError = errs.New("ldap: virtual list view error | ldap：虚拟列表视图错误")
	// ErrOther is any unlisted LDAP result code. | ErrOther 表示未列出的 LDAP 结果码。
	ErrOther = errs.New("ldap: other error | ldap：其它错误")
	// ErrCanceled is LDAP result code 118. | ErrCanceled 是 LDAP 结果码 118。
	ErrCanceled = errs.New("ldap: canceled | ldap：已取消")
	// ErrNoSuchOperation is LDAP result code 119. | ErrNoSuchOperation 是 LDAP 结果码 119。
	ErrNoSuchOperation = errs.New("ldap: no such operation | ldap：操作不存在")
	// ErrTooLate is LDAP result code 120. | ErrTooLate 是 LDAP 结果码 120。
	ErrTooLate = errs.New("ldap: too late | ldap：过晚")
	// ErrCannotCancel is LDAP result code 121. | ErrCannotCancel 是 LDAP 结果码 121。
	ErrCannotCancel = errs.New("ldap: cannot cancel | ldap：无法取消")
	// ErrAssertionFailed is LDAP result code 122. | ErrAssertionFailed 是 LDAP 结果码 122。
	ErrAssertionFailed = errs.New("ldap: assertion failed | ldap：断言失败")

	// ErrAccountDisabled reports an administratively disabled account. | ErrAccountDisabled 表示账号被管理员禁用。
	ErrAccountDisabled = errs.New("ldap: account disabled | ldap：账号已禁用")
	// ErrAccountLocked reports a temporarily locked account. | ErrAccountLocked 表示账号被临时锁定。
	ErrAccountLocked = errs.New("ldap: account locked | ldap：账号已锁定")
	// ErrAccountExpired reports an expired account. | ErrAccountExpired 表示账号已过期。
	ErrAccountExpired = errs.New("ldap: account expired | ldap：账号已过期")
	// ErrPasswordExpired reports an expired password. | ErrPasswordExpired 表示口令已过期。
	ErrPasswordExpired = errs.New("ldap: password expired | ldap：口令已过期")
	// ErrPasswordMustChange reports a password that must be changed before login. | ErrPasswordMustChange 表示登录前必须修改口令。
	ErrPasswordMustChange = errs.New("ldap: password must be changed | ldap：必须修改口令")
	// ErrAccountRestricted reports a logon-hour, workstation or similar restriction. | ErrAccountRestricted 表示登录时段、工作站等限制。
	ErrAccountRestricted = errs.New("ldap: account restricted | ldap：账号受限制")
	// ErrPasswordPolicy reports a password policy rejection. | ErrPasswordPolicy 表示口令策略拒绝。
	ErrPasswordPolicy = errs.New("ldap: password policy rejection | ldap：口令策略拒绝")
)

// ResultCode is an LDAP result code as defined by RFC 4511 and its extensions.
// | ResultCode 是 RFC 4511 及其扩展定义的 LDAP 结果码。
type ResultCode int

// The result codes used by this package. | 本包使用的 LDAP 结果码。
const (
	ResultSuccess                      ResultCode = 0
	ResultOperationsError              ResultCode = 1
	ResultProtocolError                ResultCode = 2
	ResultTimeLimitExceeded            ResultCode = 3
	ResultSizeLimitExceeded            ResultCode = 4
	ResultCompareFalse                 ResultCode = 5
	ResultCompareTrue                  ResultCode = 6
	ResultAuthMethodNotSupported       ResultCode = 7
	ResultStrongerAuthRequired         ResultCode = 8
	ResultReferral                     ResultCode = 10
	ResultAdminLimitExceeded           ResultCode = 11
	ResultUnavailableCriticalExtension ResultCode = 12
	ResultConfidentialityRequired      ResultCode = 13
	ResultSASLBindInProgress           ResultCode = 14
	ResultNoSuchAttribute              ResultCode = 16
	ResultUndefinedAttributeType       ResultCode = 17
	ResultConstraintViolation          ResultCode = 19
	ResultAttributeOrValueExists       ResultCode = 20
	ResultInvalidAttributeSyntax       ResultCode = 21
	ResultNoSuchObject                 ResultCode = 32
	ResultAliasProblem                 ResultCode = 33
	ResultInvalidDNSyntax              ResultCode = 34
	ResultAliasDereferencingProblem    ResultCode = 36
	ResultInappropriateAuthentication  ResultCode = 48
	ResultInvalidCredentials           ResultCode = 49
	ResultInsufficientAccess           ResultCode = 50
	ResultBusy                         ResultCode = 51
	ResultUnavailable                  ResultCode = 52
	ResultUnwillingToPerform           ResultCode = 53
	ResultLoopDetect                   ResultCode = 54
	ResultSortControlMissing           ResultCode = 60
	ResultOffsetRangeError             ResultCode = 61
	ResultNamingViolation              ResultCode = 64
	ResultObjectClassViolation         ResultCode = 65
	ResultNotAllowedOnNonLeaf          ResultCode = 66
	ResultNotAllowedOnRDN              ResultCode = 67
	ResultEntryAlreadyExists           ResultCode = 68
	ResultObjectClassModsProhibited    ResultCode = 69
	ResultResultsTooLarge              ResultCode = 70
	ResultAffectsMultipleDSAs          ResultCode = 71
	ResultVirtualListViewError         ResultCode = 76
	ResultOther                        ResultCode = 80
	ResultCanceled                     ResultCode = 118
	ResultNoSuchOperation              ResultCode = 119
	ResultTooLate                      ResultCode = 120
	ResultCannotCancel                 ResultCode = 121
	ResultAssertionFailed              ResultCode = 122
)

// String returns the RFC result name, for example "invalidCredentials". | String
// 返回 RFC 结果名，例如 "invalidCredentials"。
func (c ResultCode) String() string {
	switch c {
	case ResultSuccess:
		return "success"
	case ResultOperationsError:
		return "operationsError"
	case ResultProtocolError:
		return "protocolError"
	case ResultTimeLimitExceeded:
		return "timeLimitExceeded"
	case ResultSizeLimitExceeded:
		return "sizeLimitExceeded"
	case ResultCompareFalse:
		return "compareFalse"
	case ResultCompareTrue:
		return "compareTrue"
	case ResultAuthMethodNotSupported:
		return "authMethodNotSupported"
	case ResultStrongerAuthRequired:
		return "strongerAuthRequired"
	case ResultReferral:
		return "referral"
	case ResultAdminLimitExceeded:
		return "adminLimitExceeded"
	case ResultUnavailableCriticalExtension:
		return "unavailableCriticalExtension"
	case ResultConfidentialityRequired:
		return "confidentialityRequired"
	case ResultSASLBindInProgress:
		return "saslBindInProgress"
	case ResultNoSuchAttribute:
		return "noSuchAttribute"
	case ResultUndefinedAttributeType:
		return "undefinedAttributeType"
	case ResultConstraintViolation:
		return "constraintViolation"
	case ResultAttributeOrValueExists:
		return "attributeOrValueExists"
	case ResultInvalidAttributeSyntax:
		return "invalidAttributeSyntax"
	case ResultNoSuchObject:
		return "noSuchObject"
	case ResultAliasProblem:
		return "aliasProblem"
	case ResultInvalidDNSyntax:
		return "invalidDNSyntax"
	case ResultAliasDereferencingProblem:
		return "aliasDereferencingProblem"
	case ResultInappropriateAuthentication:
		return "inappropriateAuthentication"
	case ResultInvalidCredentials:
		return "invalidCredentials"
	case ResultInsufficientAccess:
		return "insufficientAccessRights"
	case ResultBusy:
		return "busy"
	case ResultUnavailable:
		return "unavailable"
	case ResultUnwillingToPerform:
		return "unwillingToPerform"
	case ResultLoopDetect:
		return "loopDetect"
	case ResultSortControlMissing:
		return "sortControlMissing"
	case ResultOffsetRangeError:
		return "offsetRangeError"
	case ResultNamingViolation:
		return "namingViolation"
	case ResultObjectClassViolation:
		return "objectClassViolation"
	case ResultNotAllowedOnNonLeaf:
		return "notAllowedOnNonLeaf"
	case ResultNotAllowedOnRDN:
		return "notAllowedOnRDN"
	case ResultEntryAlreadyExists:
		return "entryAlreadyExists"
	case ResultObjectClassModsProhibited:
		return "objectClassModsProhibited"
	case ResultResultsTooLarge:
		return "resultsTooLarge"
	case ResultAffectsMultipleDSAs:
		return "affectsMultipleDSAs"
	case ResultVirtualListViewError:
		return "virtualListViewError"
	case ResultOther:
		return "other"
	case ResultCanceled:
		return "canceled"
	case ResultNoSuchOperation:
		return "noSuchOperation"
	case ResultTooLate:
		return "tooLate"
	case ResultCannotCancel:
		return "cannotCancel"
	case ResultAssertionFailed:
		return "assertionFailed"
	default:
		return "unknown"
	}
}

// LDAPResult is the common result triple carried by every response. | LDAPResult
// 是每个响应都携带的公共结果三元组。
type LDAPResult struct {
	// Code is the protocol result code. | Code 是协议结果码。
	Code ResultCode
	// MatchedDN is the closest existing ancestor supplied by the server. | MatchedDN 是服务端给出的最近存在祖先。
	MatchedDN string
	// DiagnosticMessage is the server diagnostic text. | DiagnosticMessage 是服务端诊断文本。
	DiagnosticMessage string
	// Referrals holds referral URIs carried by the result. | Referrals 保存结果携带的转介 URI。
	Referrals []string
}

// Error is a failed LDAP operation result. It supports errors.Is against both
// other Errors with the same result code and the package sentinels. | Error 是
// 失败的 LDAP 操作结果，既可用 errors.Is 匹配相同结果码的 Error，也可匹配包级哨兵。
type Error struct {
	// Code is the LDAP result code. | Code 是 LDAP 结果码。
	Code ResultCode
	// MatchedDN is the matched DN returned by the server. | MatchedDN 是服务端返回的匹配 DN。
	MatchedDN string
	// DiagnosticMessage is the diagnostic text returned by the server. | DiagnosticMessage 是服务端返回的诊断文本。
	DiagnosticMessage string
	// Referrals holds referral URIs. | Referrals 保存转介 URI。
	Referrals []string
	// Operation names the request that failed when known. | Operation 在已知时标识失败的操作。
	Operation string
}

// newResultError converts a non-success LDAPResult into an *Error. | newResultError
// 把非成功的 LDAPResult 转换为 *Error。
func newResultError(operation string, result LDAPResult) error {
	if result.Code == ResultSuccess {
		return nil
	}
	return &Error{
		Code:              result.Code,
		MatchedDN:         result.MatchedDN,
		DiagnosticMessage: result.DiagnosticMessage,
		Referrals:         append([]string(nil), result.Referrals...),
		Operation:         operation,
	}
}

// Error implements error. It deliberately omits any request credentials and
// caps the echoed diagnostic text. | Error 实现 error。它刻意不包含请求凭据，并限制回显诊断文本长度。
func (e *Error) Error() string {
	if e == nil {
		return "<nil>"
	}
	var b strings.Builder
	b.WriteString("ldap")
	if e.Operation != "" {
		b.WriteString(" ")
		b.WriteString(e.Operation)
	}
	b.WriteString(": ")
	b.WriteString(e.Code.String())
	b.WriteString(" (")
	b.WriteString(strconv.Itoa(int(e.Code)))
	b.WriteByte(')')
	if e.MatchedDN != "" {
		b.WriteString(", matched DN ")
		b.WriteString(e.MatchedDN)
	}
	if e.DiagnosticMessage != "" {
		const maxDiagnostic = 512
		diag := e.DiagnosticMessage
		if len(diag) > maxDiagnostic {
			diag = diag[:maxDiagnostic] + "..."
		}
		b.WriteString(": ")
		b.WriteString(diag)
	}
	return b.String()
}

// Unwrap exposes the sentinel selected by the result code. | Unwrap 暴露结果码对应的哨兵。
func (e *Error) Unwrap() error {
	if e == nil {
		return nil
	}
	return sentinelForCode(e.Code)
}

// Is matches another *Error with the same result code. | Is 匹配结果码相同的另一个 *Error。
func (e *Error) Is(target error) bool {
	if e == nil || target == nil {
		return false
	}
	other, ok := target.(*Error)
	return ok && other != nil && other.Code == e.Code
}

// sentinelForCode maps an LDAP result code to a declared sentinel. | sentinelForCode
// 把 LDAP 结果码映射到已声明的哨兵。
func sentinelForCode(code ResultCode) error {
	switch code {
	case ResultSuccess:
		return nil
	case ResultOperationsError:
		return ErrOperationsError
	case ResultProtocolError:
		return ErrProtocolError
	case ResultTimeLimitExceeded:
		return ErrTimeLimitExceeded
	case ResultSizeLimitExceeded:
		return ErrSizeLimitExceeded
	case ResultCompareFalse:
		return ErrCompareFalse
	case ResultCompareTrue:
		return ErrCompareTrue
	case ResultAuthMethodNotSupported:
		return ErrAuthMethodNotSupported
	case ResultStrongerAuthRequired:
		return ErrStrongAuthRequired
	case ResultReferral:
		return ErrReferral
	case ResultAdminLimitExceeded:
		return ErrAdminLimitExceeded
	case ResultUnavailableCriticalExtension:
		return ErrUnavailableCriticalExtension
	case ResultConfidentialityRequired:
		return ErrConfidentialityRequired
	case ResultSASLBindInProgress:
		return ErrSASLBindInProgress
	case ResultNoSuchAttribute:
		return ErrNoSuchAttribute
	case ResultUndefinedAttributeType:
		return ErrUndefinedAttributeType
	case ResultConstraintViolation:
		return ErrConstraintViolation
	case ResultAttributeOrValueExists:
		return ErrAttributeOrValueExists
	case ResultInvalidAttributeSyntax:
		return ErrInvalidAttributeSyntax
	case ResultNoSuchObject:
		return ErrNoSuchObject
	case ResultAliasProblem:
		return ErrAliasProblem
	case ResultInvalidDNSyntax:
		return ErrInvalidDNSyntax
	case ResultAliasDereferencingProblem:
		return ErrAliasDereferencingProblem
	case ResultInappropriateAuthentication:
		return ErrInappropriateAuthentication
	case ResultInvalidCredentials:
		return ErrInvalidCredentials
	case ResultInsufficientAccess:
		return ErrInsufficientAccess
	case ResultBusy:
		return ErrBusy
	case ResultUnavailable:
		return ErrUnavailable
	case ResultUnwillingToPerform:
		return ErrUnwillingToPerform
	case ResultLoopDetect:
		return ErrLoopDetect
	case ResultSortControlMissing:
		return ErrSortControlMissing
	case ResultOffsetRangeError:
		return ErrOffsetRangeError
	case ResultNamingViolation:
		return ErrNamingViolation
	case ResultObjectClassViolation:
		return ErrObjectClassViolation
	case ResultNotAllowedOnNonLeaf:
		return ErrNotAllowedOnNonLeaf
	case ResultNotAllowedOnRDN:
		return ErrNotAllowedOnRDN
	case ResultEntryAlreadyExists:
		return ErrEntryAlreadyExists
	case ResultObjectClassModsProhibited:
		return ErrObjectClassModsProhibited
	case ResultResultsTooLarge:
		return ErrResultsTooLarge
	case ResultAffectsMultipleDSAs:
		return ErrAffectsMultipleDSAs
	case ResultVirtualListViewError:
		return ErrVirtualListViewError
	case ResultCanceled:
		return ErrCanceled
	case ResultNoSuchOperation:
		return ErrNoSuchOperation
	case ResultTooLate:
		return ErrTooLate
	case ResultCannotCancel:
		return ErrCannotCancel
	case ResultAssertionFailed:
		return ErrAssertionFailed
	default:
		return ErrOther
	}
}
