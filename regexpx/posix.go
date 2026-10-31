package regexpx

import resyntax "regexp/syntax"

// validatePOSIX uses the standard library's POSIX parser as the syntax oracle. This keeps
// CompilePOSIX's accept/reject set aligned with regexp.CompilePOSIX, including escapes, classes and
// repetition edge cases; the repository parser then compiles the accepted pattern. | validatePOSIX
// 使用标准库 POSIX 解析器作为语法判定的 oracle，使 CompilePOSIX 的接受/拒绝集合与
// regexp.CompilePOSIX 对齐（包括转义、字符类与重复边界）；随后由本仓解析器编译已接受模式。
func validatePOSIX(expr string) error {
	_, err := resyntax.Parse(expr, resyntax.POSIX)
	return err
}
