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
	// ErrBodyConsumed indicates the response body was already read or closed. | ErrBodyConsumed 表示响应正文已被读取或关闭。
	ErrBodyConsumed = errs.New("client: response body already consumed | client：响应正文已被消费")
	// ErrResponseTooLarge indicates a response body exceeded its configured cap. | ErrResponseTooLarge 表示响应正文超过配置上限。
	ErrResponseTooLarge = errs.New("client: response body too large | client：响应正文过大")
)
