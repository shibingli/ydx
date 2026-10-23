package regexpx

import "unicode/utf8"

// runInfo describes a pattern that is one repeated single-rune matcher, optionally anchored at both
// ends. Such patterns need no NFA: a linear run scan finds every match. | runInfo 描述「单个单符文匹配器
// 的重复」模式，可选两端锚定。这类模式不需要 NFA：线性运行扫描即可找到每个匹配。
type runInfo struct {
	class       *charClass
	lit         rune
	hasLit      bool
	any         bool
	dotAll      bool
	fold        bool
	min         int
	max         int // -1 means unbounded | -1 表示无上限
	greedy      bool
	anchorStart bool
	anchorEnd   bool
}

// analyzeRun recognizes the single-run shape. Capturing patterns are excluded because the run scanner
// only returns group zero. | analyzeRun 识别单运行模式。捕获模式被排除，因为运行扫描器只返回分组 0。
func analyzeRun(ast node, numCap int) *runInfo {
	if numCap != 0 {
		return nil
	}
	body := ast
	info := &runInfo{}
	if concat, ok := body.(*nConcat); ok {
		subs := concat.sub
		if len(subs) > 0 {
			if a, ok := subs[0].(*nAssert); ok && a.kind == assertBeginText {
				info.anchorStart = true
				subs = subs[1:]
			}
		}
		if len(subs) > 0 {
			if a, ok := subs[len(subs)-1].(*nAssert); ok && a.kind == assertEndText {
				info.anchorEnd = true
				subs = subs[:len(subs)-1]
			}
		}
		if len(subs) != 1 {
			return nil
		}
		body = subs[0]
	}
	if repeat, ok := body.(*nRepeat); ok {
		if repeat.max == 0 {
			return nil
		}
		info.min, info.max, info.greedy = repeat.min, repeat.max, repeat.greedy
		body = repeat.sub
	} else {
		info.min, info.max, info.greedy = 1, 1, true
	}
	switch n := body.(type) {
	case *nClass:
		info.class = n.c
	case *nLiteral:
		info.lit, info.hasLit, info.fold = n.r, true, n.fold
	case *nAny:
		info.any, info.dotAll = true, n.dotAll
	default:
		return nil
	}
	return info
}

// matchRune reports whether r belongs to the repeated matcher. | matchRune 报告 r 是否属于被重复的匹配器。
func (ri *runInfo) matchRune(r rune) bool {
	switch {
	case ri.class != nil:
		return ri.class.match(r)
	case ri.hasLit:
		if ri.fold {
			return equalFoldRune(r, ri.lit)
		}
		return r == ri.lit
	default:
		return ri.dotAll || r != '\n'
	}
}

// runFind returns the leftmost run match starting in [start, startLimit). A negative startLimit means
// no bound. | runFind 返回起点位于 [start, startLimit) 的最左运行匹配。startLimit 为负表示无上界。
func (r *Regexp) runFind(s string, start, startLimit int) (int, int, bool) {
	ri := r.run
	if start < 0 {
		start = 0
	}
	if start > len(s) {
		return 0, 0, false
	}
	if startLimit < 0 || startLimit > len(s)+1 {
		startLimit = len(s) + 1
	}
	if ri.anchorStart {
		if start != 0 || startLimit <= 0 {
			return 0, 0, false
		}
		return ri.findAt(s, 0)
	}
	pos := start
	for pos <= len(s) {
		if pos >= startLimit {
			return 0, 0, false
		}
		b, e, ok := ri.findAt(s, pos)
		if ok {
			return b, e, true
		}
		if pos == len(s) {
			break
		}
		_, size := utf8.DecodeRuneInString(s[pos:])
		pos += size
	}
	return 0, 0, false
}

// findAt attempts a run match whose start is exactly pos. | findAt 尝试起点恰为 pos 的运行匹配。
func (ri *runInfo) findAt(s string, pos int) (int, int, bool) {
	if ri.min > 0 {
		// Check the minimum prefix first. | 先检查最少重复前缀。
		scan := pos
		for count := 0; count < ri.min; count++ {
			if scan >= len(s) {
				return 0, 0, false
			}
			r, size := utf8.DecodeRuneInString(s[scan:])
			if !ri.matchRune(r) {
				return 0, 0, false
			}
			scan += size
		}
	}
	if !ri.greedy {
		end := pos
		for count := 0; count < ri.min; count++ {
			_, size := utf8.DecodeRuneInString(s[end:])
			end += size
		}
		if ri.anchorEnd && end != len(s) {
			return 0, 0, false
		}
		return pos, end, true
	}
	// Greedy: extend up to max. | 贪婪：扩展到上限。
	end := pos
	count := 0
	for end < len(s) && (ri.max < 0 || count < ri.max) {
		r, size := utf8.DecodeRuneInString(s[end:])
		if !ri.matchRune(r) {
			break
		}
		end += size
		count++
	}
	if count < ri.min {
		return 0, 0, false
	}
	if ri.anchorEnd && end != len(s) {
		return 0, 0, false
	}
	return pos, end, true
}
