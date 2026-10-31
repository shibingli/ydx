package regexpx

import (
	"io"
	stdregexp "regexp"
	"strings"
)

// Match reports whether the pattern matches b. It compiles the pattern first, mirroring
// regexp.Match. | Match 报告模式是否匹配 b。它先编译模式，与 regexp.Match 一致。
func Match(pattern string, b []byte) (matched bool, err error) {
	re, err := Compile(pattern)
	if err != nil {
		return false, err
	}
	return re.Match(b), nil
}

// MatchString reports whether the pattern matches s. | MatchString 报告模式是否匹配 s。
func MatchString(pattern string, s string) (matched bool, err error) {
	re, err := Compile(pattern)
	if err != nil {
		return false, err
	}
	return re.MatchString(s), nil
}

// MatchReader reports whether the pattern matches the runes read from r. The reader is consumed
// completely. | MatchReader 报告模式是否匹配从 r 读取的符文。r 会被完整读取。
func MatchReader(pattern string, r io.RuneReader) (matched bool, err error) {
	re, err := Compile(pattern)
	if err != nil {
		return false, err
	}
	return re.MatchReader(r), nil
}

// Longest switches future matches to leftmost-longest. Like regexp.Regexp.Longest, it is a
// configuration method and must not run concurrently with matching. | Longest 把后续匹配切换为最左
// 最长。与 regexp.Regexp.Longest 一样，它是配置方法，不得与匹配并发执行。
func (r *Regexp) Longest() { r.longest = true }

// LiteralPrefix returns the literal prefix shared by every match and whether the whole pattern is
// exactly that literal. | LiteralPrefix 返回每个匹配共享的字面量前缀，以及整个模式是否恰好等于
// 该字面量。
func (r *Regexp) LiteralPrefix() (prefix string, complete bool) {
	if r.compat == nil {
		return "", false
	}
	// Use the standard library as the compatibility oracle for patterns it accepts. The AST
	// fallback covers regexpx-only .NET constructs that regexp rejects. | 对标准库接受的模式，用
	// 标准库作为兼容性 oracle；regexpx 独有、regexp 拒绝的 .NET 构造使用 AST 回退。
	r.compat.literalOnce.Do(func() {
		if r.posix {
			if std, err := stdregexp.CompilePOSIX(r.src); err == nil {
				r.compat.literalPrefix, r.compat.literalComplete = std.LiteralPrefix()
			}
			return
		}
		if std, err := stdregexp.Compile(r.src); err == nil {
			r.compat.literalPrefix, r.compat.literalComplete = std.LiteralPrefix()
		}
	})
	return r.compat.literalPrefix, r.compat.literalComplete
}

// AppendText appends the textual form of the pattern to b. | AppendText 把模式的文本形式追加到 b。
func (r *Regexp) AppendText(b []byte) ([]byte, error) {
	return append(b, r.src...), nil
}

// MarshalText returns the textual form of the pattern. | MarshalText 返回模式的文本形式。
func (r *Regexp) MarshalText() ([]byte, error) {
	return []byte(r.src), nil
}

// UnmarshalText compiles text and replaces the receiver. On failure the receiver is unchanged. |
// UnmarshalText 编译 text 并替换接收者；失败时接收者保持不变。
func (r *Regexp) UnmarshalText(text []byte) error {
	compiled, err := Compile(string(text))
	if err != nil {
		return err
	}
	*r = *compiled
	return nil
}

// Copy returns an independent copy. Calling Longest on one copy does not affect the other. |
// Copy 返回独立副本。对其中一个调用 Longest 不会影响另一个。
func (r *Regexp) Copy() *Regexp {
	// All mutable synchronization state lives behind pointers, so a shallow copy is safe and
	// shares the immutable program, names and pools. The longest flag is copied by value, which is
	// what keeps configuration changes independent. | 所有可变同步状态都在指针后面，因此浅拷贝是
	// 安全的，并共享不可变的程序、名称与池。longest 标志按值复制，保证配置修改相互独立。
	clone := *r
	return &clone
}

// Expand appends the replacement template to dst using match, mirroring regexp.Regexp.Expand. |
// Expand 使用 match 把替换模板追加到 dst，与 regexp.Regexp.Expand 一致。
func (r *Regexp) Expand(dst []byte, template []byte, src []byte, match []int) []byte {
	return r.appendExpand(dst, bytesToString(template), src, "", match)
}

// ExpandString appends the replacement template to dst using match. | ExpandString 使用 match 把替换
// 模板追加到 dst。
func (r *Regexp) ExpandString(dst []byte, template string, src string, match []int) []byte {
	return r.appendExpand(dst, template, nil, src, match)
}

// MatchReader reports whether the runes read from r contain a match. Any read error is treated
// as end of input. | MatchReader 报告从 r 读取的符文是否包含匹配。任何读取错误按输入结束处理。
func (r *Regexp) MatchReader(reader io.RuneReader) bool {
	if reader == nil {
		return false
	}
	// Without end-of-text, line or word-boundary assertions and backtracking constructs, a match
	// found in a prefix remains valid after more input arrives. Testing every 4 KiB avoids reading
	// an unbounded stream when the match is early. | 没有文本结尾、行/词边界断言与回溯构造时，
	// 前缀中已成立的匹配在后续输入到达后仍然成立。每 4 KiB 测试一次，避免为早期匹配读完整个无界流。
	if r.prog.info.hasEndAssert || r.prog.info.hasWordBoundary || r.prog.info.hasLineAnchor || r.prog.info.hasBacktrack {
		stream, ok := readRuneStream(reader)
		return ok && r.MatchString(stream.text)
	}
	var b strings.Builder
	chunk := 0
	limit := 1
	for {
		ch, size, err := reader.ReadRune()
		if err != nil || size == 0 {
			break
		}
		b.WriteRune(ch)
		chunk++
		if chunk == limit {
			if r.MatchString(b.String()) {
				return true
			}
			chunk = 0
			if limit < 4096 {
				limit *= 2
			}
		}
	}
	return r.MatchString(b.String())
}

// FindReaderIndex returns the byte offsets of the first match in the runes read from r, using the
// byte sizes reported by ReadRune. | FindReaderIndex 返回从 r 读取的符文中首个匹配的字节偏移，使用
// ReadRune 上报的字节大小。
func (r *Regexp) FindReaderIndex(reader io.RuneReader) []int {
	if result, handled := r.findReaderFixed(reader, false); handled {
		return result
	}
	stream, ok := readRuneStream(reader)
	if !ok {
		return nil
	}
	return stream.mapIndex(r.FindStringIndex(stream.text))
}

// FindReaderSubmatchIndex returns the byte offsets of the first match and its submatches in the
// runes read from r, using the byte sizes reported by ReadRune. | FindReaderSubmatchIndex 返回从 r
// 读取的符文中首个匹配及其子匹配的字节偏移，使用 ReadRune 上报的字节大小。
func (r *Regexp) FindReaderSubmatchIndex(reader io.RuneReader) []int {
	if result, handled := r.findReaderFixed(reader, true); handled {
		return result
	}
	stream, ok := readRuneStream(reader)
	if !ok {
		return nil
	}
	return stream.mapIndex(r.FindStringSubmatchIndex(stream.text))
}

// ReplaceAllLiteralString replaces every match with repl without expanding $ references. |
// ReplaceAllLiteralString 用 repl 替换每个匹配，不展开 $ 引用。
func (r *Regexp) ReplaceAllLiteralString(src, repl string) string {
	if r.longest {
		if std := r.stdRegexp(); std != nil {
			return std.ReplaceAllLiteralString(src, repl)
		}
	}
	out := make([]byte, 0, len(src))
	last := 0
	matched := false
	err := r.forEachMatch(src, -1, 2, func(caps []int) bool {
		out = append(out, src[last:caps[0]]...)
		out = append(out, repl...)
		last = caps[1]
		matched = true
		return false
	})
	if err != nil || !matched {
		return src
	}
	out = append(out, src[last:]...)
	return string(out)
}

// ReplaceAllLiteral replaces every match in src with repl without expanding $ references. |
// ReplaceAllLiteral 用 repl 替换 src 中的每个匹配，不展开 $ 引用。
func (r *Regexp) ReplaceAllLiteral(src, repl []byte) []byte {
	if r.longest {
		if std := r.stdRegexp(); std != nil {
			return std.ReplaceAllLiteral(src, repl)
		}
	}
	out := make([]byte, 0, len(src))
	last := 0
	matched := false
	err := r.forEachMatch(bytesToString(src), -1, 2, func(caps []int) bool {
		out = append(out, src[last:caps[0]]...)
		out = append(out, repl...)
		last = caps[1]
		matched = true
		return false
	})
	if err != nil || !matched {
		return src
	}
	return append(out, src[last:]...)
}
