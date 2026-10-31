package waf

import (
	"strings"

	"github.com/shibingli/ydx/errs"
)

// logicalLine is one source line after backslash continuation is joined. | logicalLine 是反斜杠
// 续行拼接后的一条源码行。
type logicalLine struct {
	text string
	line int
}

// splitLogicalLines joins continuation lines and records the first physical line number.
// | splitLogicalLines 拼接续行并记录首个物理行号。
func splitLogicalLines(src string) []logicalLine {
	raw := strings.Split(src, "\n")
	out := make([]logicalLine, 0, len(raw))
	var pending strings.Builder
	start := 0
	for i, line := range raw {
		line = strings.TrimSuffix(line, "\r")
		if start == 0 {
			start = i + 1
		}
		trimmed := strings.TrimRight(line, " \t")
		if strings.HasSuffix(trimmed, "\\") {
			pending.WriteString(strings.TrimSuffix(trimmed, "\\"))
			pending.WriteByte(' ')
			continue
		}
		pending.WriteString(line)
		out = append(out, logicalLine{text: pending.String(), line: start})
		pending.Reset()
		start = 0
	}
	if pending.Len() > 0 {
		out = append(out, logicalLine{text: pending.String(), line: start})
	}
	return out
}

// lexLine splits one logical line into whitespace-separated tokens. Double-quoted tokens process
// \" and \\ escapes; every other backslash sequence is preserved so regular expressions keep
// their meaning. A '#' outside quotes starts a comment when it follows whitespace or begins the
// line. | lexLine 把一条逻辑行拆分为空白分隔的标记。双引号标记处理 \" 与 \\ 转义，其余反斜杠
// 序列原样保留以维持正则语义。引号外、位于空白之后或行首的 '#' 开始注释。
func lexLine(line string) ([]string, error) {
	tokens := make([]string, 0, 6)
	i := 0
	for i < len(line) {
		for i < len(line) && (line[i] == ' ' || line[i] == '\t') {
			i++
		}
		if i >= len(line) {
			break
		}
		if line[i] == '#' {
			break
		}
		if line[i] == '"' || line[i] == '\'' {
			quote := line[i]
			i++
			var b strings.Builder
			closed := false
			for i < len(line) {
				c := line[i]
				if c == quote {
					closed = true
					i++
					break
				}
				if c == '\\' && i+1 < len(line) {
					next := line[i+1]
					if next == quote || next == '\\' {
						b.WriteByte(next)
						i += 2
						continue
					}
					b.WriteByte(c)
					i++
					continue
				}
				b.WriteByte(c)
				i++
			}
			if !closed {
				return nil, errs.Detail(ErrParse, "unterminated quote at column %d | 第 %d 列引号未闭合", i, i)
			}
			tokens = append(tokens, b.String())
			continue
		}
		start := i
		for i < len(line) {
			c := line[i]
			if c == ' ' || c == '\t' {
				break
			}
			if c == '#' && (i == start || line[i-1] == ' ' || line[i-1] == '\t') {
				break
			}
			i++
		}
		tokens = append(tokens, line[start:i])
		if i < len(line) && line[i] == '#' {
			break
		}
	}
	return tokens, nil
}
