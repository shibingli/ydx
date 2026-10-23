package regexpx

// emailInfo describes the common address shape class+ sep class+ dot class{min,}: a positive ASCII
// local run, one ASCII separator, a positive ASCII domain run, one ASCII dot, and a positive ASCII
// tail run. The shape can be searched from the separator instead of by NFA simulation. |
// emailInfo 描述常见的地址形态 class+ sep class+ dot class{min,}：正向 ASCII 局部串、一个 ASCII 分隔符、
// 正向 ASCII 域串、一个 ASCII 点号与正向 ASCII 尾串。该形态可以围绕分隔符搜索，而无需 NFA 模拟。
type emailInfo struct {
	local, domain, tail *charClass
	localMin            int
	domainMin           int
	tailMin             int
	sep                 rune
	dot                 rune
	anchorStart         bool
	anchorEnd           bool
}

// analyzeEmail recognizes the address shape. Captures, lookaround, alternation, lazy repeats and
// non-ASCII classes fall back to the general engines. | analyzeEmail 识别地址形态。捕获、环视、分支、
// 惰性重复与非 ASCII 字符类回退到通用引擎。
func analyzeEmail(ast node, numCap int) *emailInfo {
	if numCap != 0 {
		return nil
	}
	subs := []node{ast}
	if concat, ok := ast.(*nConcat); ok {
		subs = concat.sub
	}
	info := &emailInfo{}
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
	if len(subs) != 5 {
		return nil
	}
	localRepeat, ok := subs[0].(*nRepeat)
	if !ok || !localRepeat.greedy || localRepeat.min < 1 || localRepeat.max != -1 {
		return nil
	}
	localClass, ok := localRepeat.sub.(*nClass)
	if !ok || !asciiClassOK(localClass.c) {
		return nil
	}
	sepNode, ok := subs[1].(*nLiteral)
	if !ok || sepNode.fold || sepNode.r >= 128 {
		return nil
	}
	domainRepeat, ok := subs[2].(*nRepeat)
	if !ok || !domainRepeat.greedy || domainRepeat.min < 1 || domainRepeat.max != -1 {
		return nil
	}
	domainClass, ok := domainRepeat.sub.(*nClass)
	if !ok || !asciiClassOK(domainClass.c) {
		return nil
	}
	dotNode, ok := subs[3].(*nLiteral)
	if !ok || dotNode.fold || dotNode.r >= 128 {
		return nil
	}
	tailRepeat, ok := subs[4].(*nRepeat)
	if !ok || !tailRepeat.greedy || tailRepeat.min < 1 || tailRepeat.max != -1 {
		return nil
	}
	tailClass, ok := tailRepeat.sub.(*nClass)
	if !ok || !asciiClassOK(tailClass.c) {
		return nil
	}
	// The local run must stop at the separator, otherwise the first separator after a run is not
	// necessarily the one the pattern uses. | 局部串必须在分隔符处停止，否则运行之后的第一个分隔符不
	// 一定是模式使用的那个。
	if localClass.c.match(sepNode.r) {
		return nil
	}
	info.local = localClass.c
	info.domain = domainClass.c
	info.tail = tailClass.c
	info.localMin = localRepeat.min
	info.domainMin = domainRepeat.min
	info.tailMin = tailRepeat.min
	info.sep = sepNode.r
	info.dot = dotNode.r
	return info
}

// emailFind returns the leftmost address match starting in [start, startLimit). A negative
// startLimit means no bound. | emailFind 返回起点位于 [start, startLimit) 的最左地址匹配。startLimit
// 为负表示无上界。
func (r *Regexp) emailFind(s string, start, startLimit int) (int, int, bool) {
	info := r.email
	if start < 0 {
		start = 0
	}
	if start > len(s) {
		return 0, 0, false
	}
	if startLimit < 0 || startLimit > len(s)+1 {
		startLimit = len(s) + 1
	}
	if info.anchorStart && start != 0 {
		return 0, 0, false
	}
	sep := byte(info.sep)
	q := start
	for q < len(s) {
		idx := indexByte(s, sep, q)
		if idx < 0 {
			return 0, 0, false
		}
		q = idx
		p := q
		for p > start && info.local.match(rune(s[p-1])) {
			p--
		}
		if p >= startLimit {
			return 0, 0, false
		}
		if q-p >= info.localMin && (!info.anchorStart || p == 0) {
			if end, ok := info.matchDomain(s, q); ok {
				if !info.anchorEnd || end == len(s) {
					return p, end, true
				}
			}
		}
		if info.anchorStart {
			return 0, 0, false
		}
		q++
	}
	return 0, 0, false
}

// matchDomain matches the domain run, the dot and the tail run after the separator at q. |
// matchDomain 在 q 处的分隔符之后匹配域串、点号与尾串。
func (info *emailInfo) matchDomain(s string, q int) (int, bool) {
	dStart := q + 1
	dEnd := dStart
	for dEnd < len(s) && info.domain.match(rune(s[dEnd])) {
		dEnd++
	}
	if dEnd-dStart < info.domainMin {
		return 0, false
	}
	dot := byte(info.dot)
	d := dEnd
	if d >= len(s) {
		d = len(s) - 1
	}
	for ; d > dStart; d-- {
		if s[d] != dot {
			continue
		}
		if d-dStart < info.domainMin {
			break
		}
		t := d + 1
		for t < len(s) && info.tail.match(rune(s[t])) {
			t++
		}
		if t-(d+1) >= info.tailMin && (!info.anchorEnd || t == len(s)) {
			return t, true
		}
	}
	return 0, false
}
