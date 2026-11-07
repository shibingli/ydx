package scim

import (
	"errors"
	"net/http"

	"github.com/shibingli/ydx/errs"
)

// Sentinels returned by the server, the stores and the client. | 服务端、存储与客户端返回的
// 哨兵错误。
//
// Every failure path returns one of them directly or through errs.Detail / errs.Wrap, so callers
// classify failures with errors.Is instead of matching message text. | 所有失败路径都直接返回其中
// 之一，或经由 errs.Detail / errs.Wrap 包装，因此调用方可用 errors.Is 分类失败而无需匹配文案。
var (
	// ErrInvalidConfig reports a missing or contradictory configuration. | ErrInvalidConfig 表示
	// 配置缺失或互相矛盾。
	ErrInvalidConfig = errs.New("scim: invalid configuration | scim：配置非法")
	// ErrInvalidRequest reports malformed request input. | ErrInvalidRequest 表示请求输入非法。
	ErrInvalidRequest = errs.New("scim: invalid request | scim：请求非法")
	// ErrInvalidSyntax reports JSON that cannot be decoded. | ErrInvalidSyntax 表示 JSON 无法解码。
	ErrInvalidSyntax = errs.New("scim: invalid syntax | scim：语法非法")
	// ErrInvalidFilter reports a filter that does not conform to RFC 7644. | ErrInvalidFilter 表示
	// 过滤器不符合 RFC 7644。
	ErrInvalidFilter = errs.New("scim: invalid filter | scim：过滤器非法")
	// ErrInvalidPath reports an attribute path that does not conform to RFC 7644. | ErrInvalidPath
	// 表示属性路径不符合 RFC 7644。
	ErrInvalidPath = errs.New("scim: invalid path | scim：路径非法")
	// ErrNoTarget reports a PATCH path that matches no attribute value. | ErrNoTarget 表示 PATCH
	// 路径没有匹配任何属性值。
	ErrNoTarget = errs.New("scim: no target | scim：没有目标")
	// ErrInvalidValue reports a value that violates the resource model. | ErrInvalidValue 表示取值
	// 违反资源模型。
	ErrInvalidValue = errs.New("scim: invalid value | scim：取值非法")
	// ErrBulkIDUnresolved reports a bulkId reference that names no bulkId created by an earlier
	// successful operation. | ErrBulkIDUnresolved 表示 bulkId 引用没有指向先前成功操作创建的
	// bulkId。
	ErrBulkIDUnresolved = errs.New("scim: unresolved bulkId reference | scim：未解析的 bulkId 引用")
	// ErrBulkIDDuplicate reports two bulk operations that define the same bulkId. |
	// ErrBulkIDDuplicate 表示两个批量操作定义了相同的 bulkId。
	ErrBulkIDDuplicate = errs.New("scim: duplicate bulkId | scim：重复 bulkId")
	// ErrBulkUndoLimit reports that the atomic bulk undo log would exceed its configured memory
	// bound. | ErrBulkUndoLimit 表示原子批量撤销日志将超过配置的内存上限。
	ErrBulkUndoLimit = errs.New("scim: bulk undo log limit exceeded | scim：批量撤销日志超出限制")
	// ErrBulkRollbackConflict reports that a resource changed concurrently, so the atomic bulk
	// rollback refuses to overwrite the newer state. | ErrBulkRollbackConflict 表示资源已被并发修改，
	// 因此原子批量回滚拒绝覆盖较新的状态。
	ErrBulkRollbackConflict = errs.New("scim: bulk rollback conflict | scim：批量回滚冲突")
	// ErrBulkRollbackFailed reports that the atomic bulk rollback could not restore prior state. |
	// ErrBulkRollbackFailed 表示原子批量回滚无法恢复先前状态。
	ErrBulkRollbackFailed = errs.New("scim: bulk rollback failed | scim：批量回滚失败")
	// ErrMutability reports a write to a read-only or immutable attribute. | ErrMutability 表示写入
	// 只读或不可变属性。
	ErrMutability = errs.New("scim: attribute is not mutable | scim：属性不可修改")
	// ErrUniqueness reports a duplicate unique attribute. | ErrUniqueness 表示唯一属性重复。
	ErrUniqueness = errs.New("scim: uniqueness violation | scim：唯一性冲突")
	// ErrTooMany reports a request that exceeds a configured limit. | ErrTooMany 表示请求超过配置
	// 的限制。
	ErrTooMany = errs.New("scim: too many results | scim：结果过多")
	// ErrInvalidVersion reports a failed If-Match or If-None-Match precondition. | ErrInvalidVersion
	// 表示 If-Match 或 If-None-Match 前置条件失败。
	ErrInvalidVersion = errs.New("scim: invalid resource version | scim：资源版本无效")
	// ErrUnauthorized reports a missing or rejected authentication context. | ErrUnauthorized 表示
	// 缺少或拒绝认证上下文。
	ErrUnauthorized = errs.New("scim: unauthorized | scim：未认证")
	// ErrForbidden reports an authenticated caller without the required permission. | ErrForbidden
	// 表示调用方已认证但缺少所需权限。
	ErrForbidden = errs.New("scim: forbidden | scim：禁止访问")
	// ErrNotFound reports an unknown resource. | ErrNotFound 表示资源不存在。
	ErrNotFound = errs.New("scim: resource not found | scim：资源不存在")
	// ErrConflict reports a duplicate identifier or unique attribute at the store layer. |
	// ErrConflict 表示存储层的标识或唯一属性重复。
	ErrConflict = errs.New("scim: resource conflict | scim：资源冲突")
	// ErrPreconditionFailed reports an HTTP 412 precondition failure. | ErrPreconditionFailed
	// 表示 HTTP 412 前置条件失败。
	ErrPreconditionFailed = errs.New("scim: precondition failed | scim：前置条件失败")
	// ErrNotModified reports an HTTP 304 response to If-None-Match. | ErrNotModified 表示
	// If-None-Match 得到的 HTTP 304 响应。
	ErrNotModified = errs.New("scim: not modified | scim：未修改")
	// ErrUnsupported reports an operation the implementation does not provide. | ErrUnsupported
	// 表示实现不提供的操作。
	ErrUnsupported = errs.New("scim: operation not supported | scim：操作不受支持")
	// ErrStoreUnavailable reports a backend failure. | ErrStoreUnavailable 表示后端故障。
	ErrStoreUnavailable = errs.New("scim: store unavailable | scim：存储不可用")
	// ErrInternal reports an unexpected server-side failure. | ErrInternal 表示意外的服务端故障。
	ErrInternal = errs.New("scim: internal error | scim：内部错误")
	// ErrNotConfigured reports an operation that needs a caller supplied hook. | ErrNotConfigured
	// 表示操作需要调用方提供的钩子。
	ErrNotConfigured = errs.New("scim: feature not configured | scim：功能未配置")
)

// scimError describes the HTTP status and scimType for an error. | scimError 描述错误的 HTTP 状态
// 与 scimType。
type scimError struct {
	// scimType is the RFC 7644 error type, empty when the status alone is enough. | scimType 是
	// RFC 7644 错误类型，仅状态码足够时为空。
	scimType string
	// status is the HTTP status code. | status 是 HTTP 状态码。
	status int
}

// classifyError maps an error to its HTTP status and scimType. | classifyError 把错误映射为 HTTP
// 状态与 scimType。
func classifyError(err error) scimError {
	switch {
	case err == nil:
		return scimError{status: http.StatusOK}
	case errors.Is(err, ErrBulkRollbackFailed):
		return scimError{status: http.StatusInternalServerError}
	case errors.Is(err, ErrBulkRollbackConflict):
		return scimError{status: http.StatusConflict}
	case errors.Is(err, ErrInvalidFilter):
		return scimError{status: http.StatusBadRequest, scimType: "invalidFilter"}
	case errors.Is(err, ErrInvalidPath):
		return scimError{status: http.StatusBadRequest, scimType: "invalidPath"}
	case errors.Is(err, ErrNoTarget):
		return scimError{status: http.StatusBadRequest, scimType: "noTarget"}
	case errors.Is(err, ErrMutability):
		return scimError{status: http.StatusBadRequest, scimType: "mutability"}
	case errors.Is(err, ErrUniqueness):
		return scimError{status: http.StatusConflict, scimType: "uniqueness"}
	case errors.Is(err, ErrConflict):
		return scimError{status: http.StatusConflict, scimType: "uniqueness"}
	case errors.Is(err, ErrTooMany), errors.Is(err, ErrBulkUndoLimit):
		return scimError{status: http.StatusBadRequest, scimType: "tooMany"}
	case errors.Is(err, ErrInvalidVersion), errors.Is(err, ErrPreconditionFailed):
		return scimError{status: http.StatusPreconditionFailed, scimType: "invalidVers"}
	case errors.Is(err, ErrInvalidSyntax), errors.Is(err, ErrInvalidRequest):
		return scimError{status: http.StatusBadRequest, scimType: "invalidSyntax"}
	case errors.Is(err, ErrInvalidValue), errors.Is(err, ErrNotConfigured),
		errors.Is(err, ErrBulkIDUnresolved), errors.Is(err, ErrBulkIDDuplicate):
		return scimError{status: http.StatusBadRequest, scimType: "invalidValue"}
	case errors.Is(err, ErrNotFound):
		return scimError{status: http.StatusNotFound}
	case errors.Is(err, ErrUnauthorized):
		return scimError{status: http.StatusUnauthorized}
	case errors.Is(err, ErrForbidden):
		return scimError{status: http.StatusForbidden}
	case errors.Is(err, ErrUnsupported):
		return scimError{status: http.StatusNotImplemented}
	case errors.Is(err, ErrStoreUnavailable), errors.Is(err, ErrInternal):
		return scimError{status: http.StatusInternalServerError}
	case errors.Is(err, ErrInvalidConfig):
		return scimError{status: http.StatusInternalServerError}
	default:
		return scimError{status: http.StatusInternalServerError}
	}
}

// sentinelForStatus returns the sentinel that best matches an HTTP status and scimType. It backs
// errors.Is on client side *Error responses. | sentinelForStatus 返回最匹配 HTTP 状态与 scimType
// 的哨兵。它为客户端 *Error 响应上的 errors.Is 提供支持。
func sentinelForStatus(status int, scimType string) error {
	switch scimType {
	case "invalidFilter":
		return ErrInvalidFilter
	case "invalidPath":
		return ErrInvalidPath
	case "noTarget":
		return ErrNoTarget
	case "mutability":
		return ErrMutability
	case "uniqueness":
		return ErrUniqueness
	case "tooMany":
		return ErrTooMany
	case "invalidVers":
		return ErrInvalidVersion
	case "invalidSyntax":
		return ErrInvalidSyntax
	case "invalidValue":
		return ErrInvalidValue
	}
	switch status {
	case http.StatusBadRequest:
		return ErrInvalidRequest
	case http.StatusUnauthorized:
		return ErrUnauthorized
	case http.StatusForbidden:
		return ErrForbidden
	case http.StatusNotFound:
		return ErrNotFound
	case http.StatusConflict:
		return ErrConflict
	case http.StatusPreconditionFailed:
		return ErrPreconditionFailed
	case http.StatusNotModified:
		return ErrNotModified
	case http.StatusNotImplemented:
		return ErrUnsupported
	}
	if status >= http.StatusInternalServerError {
		return ErrInternal
	}
	return ErrInvalidRequest
}
