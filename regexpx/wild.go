package regexpx

import "strings"

// wildInfo describes a pattern made of a literal surrounded by dot-all greedy wildcards, such as
// (?s).*Holmes.*. Such patterns reduce to one literal search, so a full NFA scan is unnecessary. |
// wildInfo 描述由 dot-all 贪婪通配符包围字面量的模式，例如 (?s).*Holmes.*。这类模式可归约为一次
// 字面量搜索，无需完整 NFA 扫描。
type wildInfo struct {
	literal     string
	leadingAny  bool
	trailingAny bool
}

// analyzeWild recognizes the wildcard-literal shapes. Lazy wildcards and folded literals are left to
// the general engines. | analyzeWild 识别通配字面量形态。惰性通配与折叠字面量留给通用引擎。
func analyzeWild(ast node) *wildInfo {
	concat, ok := ast.(*nConcat)
	if !ok {
		return nil
	}
	subs := concat.sub
	info := &wildInfo{}
	if len(subs) > 0 && isGreedyDotStar(subs[0]) {
		info.leadingAny = true
		subs = subs[1:]
	}
	if len(subs) > 0 && isGreedyDotStar(subs[len(subs)-1]) {
		info.trailingAny = true
		subs = subs[:len(subs)-1]
	}
	if !info.leadingAny && !info.trailingAny || len(subs) != 1 {
		return nil
	}
	switch lit := subs[0].(type) {
	case *nString:
		if lit.fold || len(lit.runes) == 0 {
			return nil
		}
		info.literal = string(lit.runes)
	case *nLiteral:
		if lit.fold {
			return nil
		}
		info.literal = string(lit.r)
	default:
		return nil
	}
	return info
}

// isGreedyDotStar reports whether n is a greedy unbounded repetition of dot-all any. |
// isGreedyDotStar 报告 n 是否为 dot-all 任意符文的贪婪无界重复。
func isGreedyDotStar(n node) bool {
	repeat, ok := n.(*nRepeat)
	if !ok || !repeat.greedy || repeat.min != 0 || repeat.max != -1 {
		return false
	}
	any, ok := repeat.sub.(*nAny)
	return ok && any.dotAll
}

// wildFind returns the leftmost match for the wildcard-literal shape. A negative startLimit means no
// bound. | wildFind 返回通配字面量形态的最左匹配。startLimit 为负表示无上界。
func (r *Regexp) wildFind(s string, start, startLimit int) (int, int, bool) {
	w := r.wild
	if start < 0 {
		start = 0
	}
	if start > len(s) {
		return 0, 0, false
	}
	if startLimit < 0 || startLimit > len(s)+1 {
		startLimit = len(s) + 1
	}
	var begin, end int
	if w.leadingAny {
		// The greedy wildcard makes the leftmost match start at the search start whenever the
		// literal occurs at or after it. Without a trailing wildcard the greedy prefix consumes as
		// much as possible while still allowing the literal, so the last occurrence wins. | 贪婪
		// 通配符使字面量出现在搜索起点及其后时，最左匹配从搜索起点开始。没有尾随通配符时，贪婪前缀会
		// 在仍允许字面量匹配的前提下尽可能多消费，因此最后一次出现获胜。
		begin = start
		if begin >= startLimit {
			return 0, 0, false
		}
		if w.trailingAny {
			if indexLiteral(s, w.literal, begin) < 0 {
				return 0, 0, false
			}
			return begin, len(s), true
		}
		offset := strings.LastIndex(s[begin:], w.literal)
		if offset < 0 {
			return 0, 0, false
		}
		return begin, begin + offset + len(w.literal), true
	}
	idx := indexLiteral(s, w.literal, start)
	if idx < 0 || idx >= startLimit {
		return 0, 0, false
	}
	begin = idx
	if w.trailingAny {
		end = len(s)
	} else {
		end = idx + len(w.literal)
	}
	return begin, end, true
}
