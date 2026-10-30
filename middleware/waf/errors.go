package waf

import "github.com/shibingli/ydx/errs"

// Declared error values. | 声明的错误值。
var (
	// ErrNoRules is returned when the configuration does not declare any rule. | ErrNoRules
	// 在配置未声明任何规则时返回。
	ErrNoRules = errs.New("waf: no rules configured | waf：未配置任何规则")
	// ErrInvalidMode is returned for an unknown engine mode. | ErrInvalidMode 在引擎模式未知时返回。
	ErrInvalidMode = errs.New("waf: invalid engine mode | waf：无效的引擎模式")
	// ErrInvalidLimit is returned for a negative or oversized body limit. | ErrInvalidLimit
	// 在正文上限为负数或超过 1 GiB 时返回。
	ErrInvalidLimit = errs.New("waf: invalid body limit | waf：无效的正文上限")
	// ErrInvalidMimeType is returned for a malformed response MIME type. | ErrInvalidMimeType
	// 在响应 MIME 类型格式非法时返回。
	ErrInvalidMimeType = errs.New("waf: invalid response MIME type | waf：无效的响应 MIME 类型")
	// ErrInvalidOption is returned for any other rejected option. | ErrInvalidOption
	// 在其他配置项被拒绝时返回。
	ErrInvalidOption = errs.New("waf: invalid option | waf：无效的配置项")
	// ErrBuild is returned when Coraza rejects the directives. | ErrBuild 在 Coraza 拒绝指令时返回。
	ErrBuild = errs.New("waf: failed to build engine | waf：构建引擎失败")
	// ErrRequestBody is returned when the request body cannot be buffered or replayed. | ErrRequestBody
	// 在请求正文无法缓冲或回放时返回。
	ErrRequestBody = errs.New("waf: failed to process request body | waf：处理请求正文失败")
	// ErrResponseBody is returned when the response body cannot be buffered or replayed. | ErrResponseBody
	// 在响应正文无法缓冲或回放时返回。
	ErrResponseBody = errs.New("waf: failed to process response body | waf：处理响应正文失败")
	// ErrClosed is returned by operations on a closed instance. | ErrClosed 在已关闭实例上调用操作时返回。
	ErrClosed = errs.New("waf: middleware is closed | waf：中间件已关闭")
	// ErrShutdownTimeout is returned when Shutdown cannot drain in-flight requests in time. | ErrShutdownTimeout
	// 在 Shutdown 未能在时限内排空在途请求时返回。
	ErrShutdownTimeout = errs.New("waf: shutdown timed out | waf：关闭超时")
)
