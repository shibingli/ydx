// Package regexpx is the repository's single regular-expression entry point.
// | Package regexpx 是本仓唯一的正则表达式入口。
//
// It owns two engines behind one API and chooses per pattern: | 它在一个 API 背后持有两个引擎，
// 并按模式选择：
//
//   - A pattern that the standard library accepts runs on the RE2 engine: linear time,
//     no backtracking, zero allocations on the hot paths, and no timeout needed. This
//     is the path every ordinary pattern takes. | 标准库能接受的模式走 RE2 引擎：线性时间、
//     不回溯、热路径零分配、无需超时。所有普通模式都走这条路。
//   - A pattern that needs .NET constructs (lookaround, backreferences, named groups)
//     does not compile in the standard library, so it runs on
//     github.com/dlclark/regexp2 in RE2 compatibility mode, with a mandatory match
//     timeout. A match that exceeds MatchTimeout is reported as "no match", which makes
//     validation callers fail closed. | 需要 .NET 构造（环视、反向引用、命名分组）的模式
//     在标准库中无法编译，因此走 github.com/dlclark/regexp2 的 RE2 兼容模式，并强制匹配超时。
//     超过 MatchTimeout 的匹配按「未匹配」处理，使校验类调用失败关闭。
//
// The dual engine is a correctness requirement, not an optimization detail: regexp2's
// iterator re-converts the remaining input to runes on every FindNextMatch, so FindAll
// over a large file is quadratic and can silently truncate under a timeout. Bulk
// scanners therefore depend on the RE2 fast path. | 双引擎不是优化细节而是正确性要求：
// regexp2 的迭代器在每次 FindNextMatch 时都会把剩余输入重新转成符文，因此对大文件的 FindAll
// 是二次复杂度，并可能在超时后静默截断。批量扫描器因此依赖 RE2 快路径。
//
// Indices are always byte offsets, regardless of the engine. | 无论走哪个引擎，索引一律是字节偏移。
//
// Usage | 用法：
//
//	var nameRe = regexpx.MustCompile(`^[a-z][a-z0-9_-]*$`)
//	if nameRe.MatchString(name) { /* ... */ }
package regexpx
