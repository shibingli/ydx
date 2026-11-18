package client

import "github.com/shibingli/ydx/errs"

// Declared sentinel errors, testable with errors.Is. | 已声明的哨兵错误，可用 errors.Is 判定。
var (
	// ErrInvalidConfig indicates an unusable option or request shape. | ErrInvalidConfig 表示不可用的选项或请求形态。
	ErrInvalidConfig = errs.New("client: invalid configuration | client：非法配置")
	// ErrClosed indicates the client has been closed. | ErrClosed 表示客户端已关闭。
	ErrClosed = errs.New("client: client closed | client：客户端已关闭")
	// ErrRelativeURL indicates a relative URL where an absolute URL is required. | ErrRelativeURL 表示需要绝对 URL 却收到相对 URL。
	ErrRelativeURL = errs.New("client: relative URL requires a base URL | client：相对 URL 需要 base URL")
	// ErrInvalidRequest indicates a request that cannot be constructed. | ErrInvalidRequest 表示无法构造的请求。
	ErrInvalidRequest = errs.New("client: invalid request | client：非法请求")
	// ErrEncodeBody indicates a request body that could not be encoded. | ErrEncodeBody 表示无法编码的请求正文。
	ErrEncodeBody = errs.New("client: encode request body | client：编码请求正文失败")
	// ErrBodyNotReplayable indicates a request body that cannot be replayed. | ErrBodyNotReplayable 表示无法重放的请求正文。
	ErrBodyNotReplayable = errs.New("client: request body is not replayable | client：请求正文不可重放")
	// ErrBodyConsumed indicates the response body was already read or closed. | ErrBodyConsumed 表示响应正文已被读取或关闭。
	ErrBodyConsumed = errs.New("client: response body already consumed | client：响应正文已被消费")
	// ErrResponseTooLarge indicates a response body exceeded its configured cap. | ErrResponseTooLarge 表示响应正文超过配置上限。
	ErrResponseTooLarge = errs.New("client: response body too large | client：响应正文过大")
	// ErrBadPattern indicates an invalid path pattern. | ErrBadPattern 表示非法的路径模式。
	ErrBadPattern = errs.New("client: invalid path pattern | client：非法的路径模式")
	// ErrDuplicateParam indicates a duplicate parameter name. | ErrDuplicateParam 表示重复的参数名。
	ErrDuplicateParam = errs.New("client: duplicate path parameter | client：重复的路径参数")
	// ErrParamName indicates an invalid parameter name. | ErrParamName 表示非法的参数名。
	ErrParamName = errs.New("client: invalid path parameter name | client：非法的路径参数名")
	// ErrWildcardPosition indicates a catch-all not in the final segment. | ErrWildcardPosition 表示捕获通配符不在最后一段。
	ErrWildcardPosition = errs.New("client: wildcard must be in the last segment | client：通配符必须位于最后一段")
	// ErrEscapeSequence indicates an unsupported escape sequence. | ErrEscapeSequence 表示不支持的转义序列。
	ErrEscapeSequence = errs.New("client: unsupported escape sequence | client：不支持的转义序列")
	// ErrDanglingEscape indicates a trailing backslash. | ErrDanglingEscape 表示末尾悬空反斜杠。
	ErrDanglingEscape = errs.New("client: dangling escape at end of segment | client：段末尾存在悬空转义符")
	// ErrMissingParam indicates a missing value during Expand. | ErrMissingParam 表示 Expand 缺少参数值。
	ErrMissingParam = errs.New("client: missing path parameter | client：缺少路径参数")
	// ErrParamValue indicates a path parameter value rejected by its regex. | ErrParamValue 表示路径参数值未通过正则校验。
	ErrParamValue = errs.New("client: invalid path parameter value | client：非法的路径参数值")
)
