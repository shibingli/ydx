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
)
