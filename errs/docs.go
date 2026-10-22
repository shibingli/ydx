// Package errx provides declared sentinel errors and context-preserving wrapping.
// | Package errx 提供声明式哨兵错误与保留上下文的包装。
//
// The repository forbids fmt.Errorf by default. Errors are declared once at
// package level and every failure path references one of those declarations,
// which keeps messages uniform, keeps them translatable, and makes errors.Is
// usable by callers without string matching. | 本仓库默认禁止 fmt.Errorf：错误在包级
// 声明一次，所有失败路径都引用这些声明，从而保证文案统一、可翻译，并让调用方
// 无需字符串匹配即可用 errors.Is 判定。
//
// Typical usage | 典型用法：
//
//	var ErrBadPattern = errx.New("invalid pattern | 非法的路由模式")
//
//	// add a formatted detail to a declared error | 为已声明错误附加格式化细节
//	return errx.Detail(ErrBadPattern, "%q must start with /", p)
//
//	// keep context while preserving the sentinel | 保留上下文同时保留哨兵
//	return errx.Wrap(err, ErrReadBody)
//
// The import path is github.com/shibingli/ydx/errs while the package identifier
// remains errx, so existing yd call sites only change their import path.
// | 导入路径是 github.com/shibingli/ydx/errs，包标识符仍是 errx，因此 yd 既有调用点
// 只需替换导入路径。
package errx
