package regexpx

// exactInfo describes a pattern that is a single literal, optionally anchored at both ends. |
// exactInfo 描述单个字面量模式，可选两端锚定。
type exactInfo struct {
	literal     string
	anchorStart bool
	anchorEnd   bool
}

// analyzeExact recognizes the whole-pattern literal shape. Folded literals and captures fall back to
// the prefix path. | analyzeExact 识别整模式字面量形态。折叠字面量与捕获回退到前缀路径。
func analyzeExact(ast node, numCap int) *exactInfo {
	if numCap != 0 {
		return nil
	}
	info := &exactInfo{}
	subs := []node{ast}
	if concat, ok := ast.(*nConcat); ok {
		subs = concat.sub
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
	}
	if len(subs) != 1 {
		return nil
	}
	switch n := subs[0].(type) {
	case *nLiteral:
		if n.fold {
			return nil
		}
		info.literal = string(n.r)
	case *nString:
		if n.fold {
			return nil
		}
		info.literal = string(n.runes)
	default:
		return nil
	}
	if info.literal == "" {
		return nil
	}
	return info
}

// exactFind returns the leftmost literal match starting in [start, startLimit). |
// exactFind 返回起点位于 [start, startLimit) 的最左字面量匹配。
func (r *Regexp) exactFind(s string, start, startLimit int) (int, int, bool) {
	ex := r.exact
	n := len(ex.literal)
	if start < 0 {
		start = 0
	}
	if startLimit < 0 || startLimit > len(s)+1 {
		startLimit = len(s) + 1
	}
	switch {
	case ex.anchorStart && ex.anchorEnd:
		if start != 0 || startLimit <= 0 || len(s) != n || s != ex.literal {
			return 0, 0, false
		}
		return 0, n, true
	case ex.anchorStart:
		if start != 0 || startLimit <= 0 || n > len(s) || s[:n] != ex.literal {
			return 0, 0, false
		}
		return 0, n, true
	case ex.anchorEnd:
		begin := len(s) - n
		if begin < start || begin < 0 || begin >= startLimit || s[begin:] != ex.literal {
			return 0, 0, false
		}
		return begin, len(s), true
	default:
		idx := indexLiteral(s, ex.literal, start)
		if idx < 0 || idx >= startLimit {
			return 0, 0, false
		}
		return idx, idx + n, true
	}
}
