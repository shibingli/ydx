package regexpx

import (
	"unicode"
	"unicode/utf8"
)

// stdLiteralPrefix mirrors regexp.Regexp.LiteralPrefix. It reports the literal prefix shared by
// every match and whether the pattern is exactly that literal; leading ^ or \A and a trailing $
// or \z are allowed for the complete case, matching the standard library. | stdLiteralPrefix 镜像
// regexp.Regexp.LiteralPrefix：返回每个匹配共享的字面量前缀，以及模式是否恰好等于该字面量；完整
// 匹配允许前导 ^ 或 \A 与尾部 $ 或 \z，与标准库一致。
func stdLiteralPrefix(ast node) (string, bool) {
	prefix, ok := stdPrefix(ast, true)
	if !ok {
		return "", false
	}
	exact, leadBegin, trailEnd, exactOK := stdExactLiteral(ast)
	complete := exactOK
	if complete {
		if leadBegin != trailEnd {
			complete = false
		}
		if len(exact) == 0 && (leadBegin || trailEnd) {
			// ^$ and \A\z match only the empty string, but the standard library does not report
			// them as a complete literal. | ^$ 与 \A\z 只匹配空串，但标准库不把它们报告为完整
			// 字面量。
			complete = false
		}
	}
	return string(prefix), complete
}

// stdPrefix returns the literal prefix of n. allowLead permits skipping a leading begin-text
// assertion once. | stdPrefix 返回 n 的字面量前缀。allowLead 允许跳过一次前导的文本开头断言。
func stdPrefix(n node, allowLead bool) ([]rune, bool) {
	switch n := n.(type) {
	case nil, *nEmpty:
		return nil, true
	case *nLiteral:
		if n.r == utf8.RuneError || n.fold && hasFoldVariant(n.r) {
			return nil, false
		}
		return []rune{n.r}, true
	case *nString:
		out := make([]rune, 0, len(n.runes))
		for _, r := range n.runes {
			if r == utf8.RuneError || n.fold && hasFoldVariant(r) {
				break
			}
			out = append(out, r)
		}
		return out, len(out) > 0
	case *nClass:
		r, ok := n.c.singleRune()
		if !ok {
			return nil, false
		}
		return []rune{r}, true
	case *nCapture:
		return stdPrefix(n.sub, allowLead)
	case *nAtomic:
		return stdPrefix(n.sub, allowLead)
	case *nConcat:
		var out []rune
		leading := allowLead
		for _, sub := range n.sub {
			if _, empty := sub.(*nEmpty); empty {
				continue
			}
			if assert, ok := sub.(*nAssert); ok {
				if leading && len(out) == 0 && assert.kind == assertBeginText {
					leading = false
					continue
				}
				return out, len(out) > 0
			}
			if _, look := sub.(*nLook); look {
				return out, len(out) > 0
			}
			prefix, ok := stdPrefix(sub, leading && len(out) == 0)
			if !ok {
				return out, len(out) > 0
			}
			out = append(out, prefix...)
			leading = false
			if _, _, _, exact := stdExactLiteral(sub); !exact {
				// A non-exact child can match beyond the prefix (for example (a|ab)), so a
				// following sibling cannot extend the guaranteed prefix. | 非精确子节点可能匹配
				// 超出前缀的内容（例如 (a|ab)），因此后续兄弟节点不能扩展保证前缀。
				return out, len(out) > 0
			}
		}
		return out, len(out) > 0
	case *nAlt:
		if len(n.sub) == 0 {
			return nil, false
		}
		var common []rune
		for i, sub := range n.sub {
			prefix, ok := stdPrefix(sub, allowLead)
			if !ok || len(prefix) == 0 {
				return nil, false
			}
			if i == 0 {
				common = append([]rune(nil), prefix...)
				continue
			}
			common = commonPrefix(common, prefix)
			if len(common) == 0 {
				return nil, false
			}
		}
		return common, true
	case *nRepeat:
		if n.min == 0 && n.max == 0 {
			return nil, true
		}
		if n.min < 1 {
			return nil, false
		}
		prefix, ok := stdPrefix(n.sub, allowLead)
		if !ok || len(prefix) == 0 {
			return nil, false
		}
		if _, _, _, exact := stdExactLiteral(n.sub); exact {
			out := make([]rune, 0, len(prefix)*n.min)
			for i := 0; i < n.min; i++ {
				out = append(out, prefix...)
			}
			return out, true
		}
		return prefix, true
	}
	return nil, false
}

// stdExactLiteral reports whether n matches exactly one literal, allowing one leading begin-text
// assertion and one trailing end-text assertion. | stdExactLiteral 报告 n 是否恰好匹配一个字面量，
// 允许一个前导文本开头断言与一个尾部文本结尾断言。
func stdExactLiteral(n node) (literal []rune, leadBegin, trailEnd, ok bool) {
	switch n := n.(type) {
	case nil, *nEmpty:
		return nil, false, false, true
	case *nLiteral:
		if n.r == utf8.RuneError || n.fold && hasFoldVariant(n.r) {
			return nil, false, false, false
		}
		return []rune{n.r}, false, false, true
	case *nString:
		for _, r := range n.runes {
			if r == utf8.RuneError || n.fold && hasFoldVariant(r) {
				return nil, false, false, false
			}
		}
		return append([]rune(nil), n.runes...), false, false, true
	case *nClass:
		r, single := n.c.singleRune()
		if !single {
			return nil, false, false, false
		}
		return []rune{r}, false, false, true
	case *nCapture:
		return stdExactLiteral(n.sub)
	case *nAtomic:
		return stdExactLiteral(n.sub)
	case *nConcat:
		var out []rune
		leadBegin, trailEnd = false, false
		for i, sub := range n.sub {
			if _, empty := sub.(*nEmpty); empty {
				continue
			}
			if assert, isAssert := sub.(*nAssert); isAssert {
				switch {
				case i == 0 && assert.kind == assertBeginText:
					leadBegin = true
				case i == len(n.sub)-1 && isEndAssert(assert.kind):
					trailEnd = true
				default:
					return nil, false, false, false
				}
				continue
			}
			if _, look := sub.(*nLook); look {
				return nil, false, false, false
			}
			part, lead, trail, partOK := stdExactLiteral(sub)
			if !partOK {
				return nil, false, false, false
			}
			out = append(out, part...)
			leadBegin = leadBegin || lead
			trailEnd = trailEnd || trail
		}
		return out, leadBegin, trailEnd, true
	case *nAlt:
		var common []rune
		leadBegin, trailEnd = false, false
		for i, sub := range n.sub {
			part, lead, trail, partOK := stdExactLiteral(sub)
			if !partOK {
				return nil, false, false, false
			}
			if i == 0 {
				common = part
				leadBegin, trailEnd = lead, trail
				continue
			}
			if !runesEqual(common, part) || lead != leadBegin || trail != trailEnd {
				return nil, false, false, false
			}
		}
		return common, leadBegin, trailEnd, true
	case *nRepeat:
		if n.min == 0 && n.max == 0 {
			return nil, false, false, true
		}
		if n.min != n.max {
			return nil, false, false, false
		}
		part, leadBegin, trailEnd, ok := stdExactLiteral(n.sub)
		if !ok || leadBegin || trailEnd {
			return nil, false, false, false
		}
		out := make([]rune, 0, len(part)*n.min)
		for i := 0; i < n.min; i++ {
			out = append(out, part...)
		}
		return out, false, false, true
	case *nAssert:
		if n.kind == assertBeginText {
			return nil, true, false, true
		}
		if isEndAssert(n.kind) {
			return nil, false, true, true
		}
	}
	return nil, false, false, false
}

// isEndAssert reports whether kind is an end-of-text assertion. | isEndAssert 报告 kind 是否为文本
// 结尾断言。
func isEndAssert(kind assertKind) bool {
	return kind == assertEndText || kind == assertEndTextFinalNewline
}

// runesEqual reports whether a and b contain the same runes. | runesEqual 报告 a 与 b 是否包含相同的
// 符文序列。
func runesEqual(a, b []rune) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}

// hasFoldVariant reports whether simple case folding maps r to another rune. A folded literal
// with no variant is effectively case-sensitive, matching the standard library's prefix analysis. |
// hasFoldVariant 报告简单大小写折叠是否把 r 映射到另一个符文。没有变体的折叠字面量等价于区分
// 大小写，与标准库的前缀分析一致。
func hasFoldVariant(r rune) bool {
	return unicode.SimpleFold(r) != r
}
