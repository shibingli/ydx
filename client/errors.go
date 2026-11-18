package client

import (
	"strconv"

	"github.com/shibingli/ydx/errs"
)

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
	// ErrNoHosts indicates an empty host pool. | ErrNoHosts 表示空的 Host 池。
	ErrNoHosts = errs.New("client: no hosts configured | client：未配置 Host")
	// ErrNoHealthyHosts indicates no host is currently selectable. | ErrNoHealthyHosts 表示当前没有可选择的 Host。
	ErrNoHealthyHosts = errs.New("client: no healthy hosts | client：没有健康的 Host")
	// ErrDuplicateHost indicates duplicate host names. | ErrDuplicateHost 表示重复的 Host 名。
	ErrDuplicateHost = errs.New("client: duplicate host name | client：重复的 Host 名")
	// ErrUnknownBalance indicates an unsupported Balance value. | ErrUnknownBalance 表示不支持的 Balance 值。
	ErrUnknownBalance = errs.New("client: unknown balance strategy | client：未知的负载均衡策略")
	// ErrHealthCheck indicates an active health check failure. | ErrHealthCheck 表示主动健康检查失败。
	ErrHealthCheck = errs.New("client: health check failed | client：健康检查失败")
	// ErrRetryExhausted indicates every retry attempt failed. | ErrRetryExhausted 表示全部重试尝试失败。
	ErrRetryExhausted = errs.New("client: retry attempts exhausted | client：重试次数耗尽")
	// ErrUpstreamStatus indicates a status configured as a host failure. | ErrUpstreamStatus 表示被配置为 Host 失败的状态码。
	ErrUpstreamStatus = errs.New("client: upstream status failure | client：上游状态失败")
	// ErrSSEProtocol indicates a malformed or non-SSE response. | ErrSSEProtocol 表示非法或非 SSE 响应。
	ErrSSEProtocol = errs.New("client: invalid event stream | client：非法的事件流")
	// ErrSSETooLarge indicates an event or line over the configured cap. | ErrSSETooLarge 表示事件或行超过配置上限。
	ErrSSETooLarge = errs.New("client: event stream payload too large | client：事件流载荷过大")
	// ErrSSEIdle indicates no event arrived within the idle timeout. | ErrSSEIdle 表示空闲超时内没有事件。
	ErrSSEIdle = errs.New("client: event stream idle timeout | client：事件流空闲超时")
	// ErrStreamMode indicates mixed Next and Raw calls on a stream. | ErrStreamMode 表示流上混用 Next 与 Raw。
	ErrStreamMode = errs.New("client: stream mode conflict | client：流模式冲突")
)

// Error wraps a client operation failure and preserves the cause chain. | Error 包装客户端操作失败并保留原因链。
type Error struct {
	// Op is the failed operation. | Op 是失败的操作。
	Op string
	// Method is the request method. | Method 是请求方法。
	Method string
	// URL is the logical request URL without query. | URL 是不含查询的逻辑请求 URL。
	URL string
	// Host is the selected host name, when known. | Host 是已选择的 Host 名（已知时）。
	Host string
	// Attempts is the number of attempted upstream calls. | Attempts 是已尝试的上游调用次数。
	Attempts int
	// Err is the underlying cause. | Err 是底层原因。
	Err error
}

// Error implements error. | Error 实现 error 接口。
func (e *Error) Error() string {
	if e == nil {
		return "<nil>"
	}
	message := "client: " + e.Op
	if e.Method != "" {
		message += " " + e.Method
	}
	if e.URL != "" {
		message += " " + e.URL
	}
	if e.Host != "" {
		message += " host=" + e.Host
	}
	if e.Attempts > 0 {
		message += " attempts=" + strconv.Itoa(e.Attempts)
	}
	if e.Err != nil {
		message += ": " + e.Err.Error()
	}
	return message
}

// Unwrap returns the underlying cause. | Unwrap 返回底层原因。
func (e *Error) Unwrap() error {
	if e == nil {
		return nil
	}
	return e.Err
}
