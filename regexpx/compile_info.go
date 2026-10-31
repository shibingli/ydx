package regexpx

import (
	"math/bits"
	"unicode"
	"unicode/utf8"
)

// lengthBounds returns the minimum and maximum match length in runes; max is -1 when unbounded. |
// lengthBounds 返回匹配长度的最少与最多符文数；无上限时 max 为 -1。
func lengthBounds(n node) (min, max int) {
	switch n := n.(type) {
	case nil, *nEmpty, *nAssert, *nLook:
		return 0, 0
	case *nLiteral:
		return 1, 1
	case *nString:
		return len(n.runes), len(n.runes)
	case *nClass, *nAny:
		return 1, 1
	case *nConcat:
		for _, sub := range n.sub {
			lo, hi := lengthBounds(sub)
			min += lo
			if max >= 0 && hi >= 0 {
				max += hi
			} else {
				max = -1
			}
		}
		return min, max
	case *nAlt:
		min, max = -1, -1
		for i, sub := range n.sub {
			lo, hi := lengthBounds(sub)
			if min < 0 || lo < min {
				min = lo
			}
			if i == 0 {
				max = hi
				continue
			}
			if hi < 0 || max < 0 {
				max = -1
			} else if hi > max {
				max = hi
			}
		}
		return min, max
	case *nRepeat:
		lo, hi := lengthBounds(n.sub)
		min = lo * n.min
		if n.max < 0 || hi < 0 {
			max = -1
		} else {
			max = hi * n.max
		}
		return min, max
	case *nCapture:
		return lengthBounds(n.sub)
	case *nAtomic:
		return lengthBounds(n.sub)
	case *nBackref:
		return 0, -1
	}
	return 0, -1
}

// analyze derives prefilter, length and structural metadata from the AST. | analyze 从 AST 推导预过滤、
// 长度与结构元数据。
func analyze(ast node) progInfo {
	minLen, maxLen := lengthBounds(ast)
	info := progInfo{
		minLen:   minLen,
		maxLen:   maxLen,
		canEmpty: minLen == 0,
		anchored: anchoredStart(ast),
	}
	info.prefix, info.prefixFold, info.prefixOK = literalPrefix(ast)
	info.hasWordBoundary = containsAssert(ast, assertWordBoundary) || containsAssert(ast, assertNotWordBoundary)
	info.hasLineAnchor = containsAssert(ast, assertBeginLine) || containsAssert(ast, assertEndLine)
	info.hasBeginAssert = containsAssert(ast, assertBeginText)
	info.hasEndAssert = containsAssert(ast, assertEndText) || containsAssert(ast, assertEndTextFinalNewline)
	info.hasLookBehind = containsLookBehind(ast)
	if !info.canEmpty && !info.anchored {
		set, ok := firstByteSet(ast)
		if ok && set != allBytes() {
			info.firstBytes = set
			info.firstBytesOK = true
		}
	}
	if info.prefixOK && len(info.prefix) > 0 {
		// The literal prefix is strictly more precise than the byte set. | 字面量前缀比字节集更精确。
		info.firstBytes = prefixFirstBytes(info.prefix, info.prefixFold)
		info.firstBytesOK = true
	}
	if info.prefixOK {
		info.selectivePrefilter = true
	} else if info.firstBytesOK {
		info.selectivePrefilter = byteSetCount(info.firstBytes) <= 16
	}
	return info
}

// byteSetCount returns the number of bytes in the set. | byteSetCount 返回集合中的字节数量。
func byteSetCount(set byteSet) int {
	count := 0
	for _, word := range set {
		count += bits.OnesCount64(word)
	}
	return count
}

// containsAssert reports whether the AST contains the assertion kind. | containsAssert 报告 AST 是否包含
// 指定断言。
func containsAssert(n node, kind assertKind) bool {
	switch n := n.(type) {
	case *nAssert:
		return n.kind == kind
	case *nConcat:
		for _, sub := range n.sub {
			if containsAssert(sub, kind) {
				return true
			}
		}
	case *nAlt:
		for _, sub := range n.sub {
			if containsAssert(sub, kind) {
				return true
			}
		}
	case *nRepeat:
		return containsAssert(n.sub, kind)
	case *nCapture:
		return containsAssert(n.sub, kind)
	case *nLook:
		return containsAssert(n.sub, kind)
	case *nAtomic:
		return containsAssert(n.sub, kind)
	}
	return false
}

// containsLookBehind reports whether the AST contains a lookbehind. | containsLookBehind 报告 AST 是否
// 包含后行断言。
func containsLookBehind(n node) bool {
	switch n := n.(type) {
	case *nLook:
		return n.behind || containsLookBehind(n.sub)
	case *nConcat:
		for _, sub := range n.sub {
			if containsLookBehind(sub) {
				return true
			}
		}
	case *nAlt:
		for _, sub := range n.sub {
			if containsLookBehind(sub) {
				return true
			}
		}
	case *nRepeat:
		return containsLookBehind(n.sub)
	case *nCapture:
		return containsLookBehind(n.sub)
	case *nAtomic:
		return containsLookBehind(n.sub)
	}
	return false
}

// anchoredStart reports whether every match must start at offset zero. | anchoredStart 报告是否所有匹配
// 都必须从偏移 0 开始。
func anchoredStart(n node) bool {
	switch n := n.(type) {
	case *nAssert:
		return n.kind == assertBeginText
	case *nConcat:
		for _, sub := range n.sub {
			switch sub.(type) {
			case *nEmpty, *nLook:
				continue
			case *nAssert:
				if sub.(*nAssert).kind == assertBeginText {
					return true
				}
				return false
			}
			return anchoredStart(sub)
		}
		return false
	case *nAlt:
		if len(n.sub) == 0 {
			return false
		}
		for _, sub := range n.sub {
			if !anchoredStart(sub) {
				return false
			}
		}
		return true
	case *nCapture:
		return anchoredStart(n.sub)
	case *nRepeat:
		return n.min > 0 && anchoredStart(n.sub)
	}
	return false
}

// literalPrefix returns a literal rune sequence every match must start with. | literalPrefix 返回每个匹配
// 都必须以其开头的字面量符文序列。
func literalPrefix(n node) ([]rune, bool, bool) {
	switch n := n.(type) {
	case *nLiteral:
		return []rune{n.r}, n.fold, true
	case *nString:
		return n.runes, n.fold, true
	case *nCapture:
		return literalPrefix(n.sub)
	case *nAtomic:
		return literalPrefix(n.sub)
	case *nConcat:
		var out []rune
		fold := false
		for _, sub := range n.sub {
			switch sub.(type) {
			case *nEmpty, *nAssert, *nLook:
				continue
			}
			rs, f, ok := literalPrefix(sub)
			if !ok || len(rs) == 0 {
				break
			}
			if len(out) > 0 && f != fold {
				break
			}
			out = append(out, rs...)
			fold = f
			switch sub.(type) {
			case *nLiteral, *nString:
			default:
				return out, fold, len(out) > 0
			}
		}
		return out, fold, len(out) > 0
	case *nAlt:
		if len(n.sub) == 0 {
			return nil, false, false
		}
		var common []rune
		fold := false
		for i, sub := range n.sub {
			rs, f, ok := literalPrefix(sub)
			if !ok || len(rs) == 0 {
				return nil, false, false
			}
			if i == 0 {
				common, fold = append([]rune(nil), rs...), f
				continue
			}
			if f != fold {
				return nil, false, false
			}
			common = commonPrefix(common, rs)
			if len(common) == 0 {
				return nil, false, false
			}
		}
		return common, fold, len(common) > 0
	case *nRepeat:
		if n.min >= 1 {
			return literalPrefix(n.sub)
		}
	}
	return nil, false, false
}

// commonPrefix returns the longest common prefix of a and b. | commonPrefix 返回 a 与 b 的最长公共前缀。
func commonPrefix(a, b []rune) []rune {
	n := len(a)
	if len(b) < n {
		n = len(b)
	}
	i := 0
	for i < n && a[i] == b[i] {
		i++
	}
	return a[:i]
}

// firstByteSet returns a sound superset of the first bytes of any non-empty match. | firstByteSet 返回
// 任意非空匹配首字节的可靠超集。
func firstByteSet(n node) (byteSet, bool) {
	var set byteSet
	ok := true
	collectFirstBytes(n, &set, &ok)
	return set, ok
}

// collectFirstBytes accumulates the first-byte set of n into set. | collectFirstBytes 把 n 的首字节集
// 累积到 set。
func collectFirstBytes(n node, set *byteSet, ok *bool) {
	switch n := n.(type) {
	case nil, *nEmpty, *nAssert:
		return
	case *nLook:
		return
	case *nLiteral:
		addRuneFirstBytes(set, n.r, n.fold)
	case *nString:
		if len(n.runes) > 0 {
			addRuneFirstBytes(set, n.runes[0], n.fold)
		}
	case *nClass:
		set.union(n.c.firstBytes())
	case *nAny:
		*ok = false
	case *nCapture:
		collectFirstBytes(n.sub, set, ok)
	case *nAtomic:
		collectFirstBytes(n.sub, set, ok)
	case *nConcat:
		for _, sub := range n.sub {
			lo, _ := lengthBounds(sub)
			collectFirstBytes(sub, set, ok)
			if lo > 0 {
				return
			}
		}
	case *nAlt:
		for _, sub := range n.sub {
			collectFirstBytes(sub, set, ok)
		}
	case *nRepeat:
		collectFirstBytes(n.sub, set, ok)
	case *nBackref:
		*ok = false
	}
}

// addRuneFirstBytes adds the UTF-8 lead bytes of r and of every rune in its simple-fold orbit. Adding
// the orbit's own lead bytes is what keeps a folded ASCII pattern such as (?i)k sound: it also matches
// the Kelvin sign, whose first byte is E2. | addRuneFirstBytes 添加 r 及其简单折叠轨道中每个符文的 UTF-8
// 首字节。添加轨道自身的首字节使 (?i)k 这类折叠 ASCII 模式保持可靠：它也能匹配首字节为 E2 的开尔文
// 符号。
func addRuneFirstBytes(set *byteSet, r rune, fold bool) {
	addLeadByte(set, r)
	if !fold {
		return
	}
	for f := unicode.SimpleFold(r); f != r; f = unicode.SimpleFold(f) {
		addLeadByte(set, f)
	}
}

// addLeadByte adds the first UTF-8 byte of r. | addLeadByte 添加 r 的 UTF-8 首字节。
func addLeadByte(set *byteSet, r rune) {
	if r < utf8.RuneSelf {
		set.addByte(byte(r))
		return
	}
	switch n := utf8.RuneLen(r); n {
	case 2:
		set.addByte(byte(0xC0 | (r >> 6)))
	case 3:
		set.addByte(byte(0xE0 | (r >> 12)))
	case 4:
		set.addByte(byte(0xF0 | (r >> 18)))
	}
}

// prefixFirstBytes returns the first-byte set of a literal prefix. | prefixFirstBytes 返回字面量前缀的
// 首字节集。
func prefixFirstBytes(prefix []rune, fold bool) byteSet {
	var set byteSet
	addRuneFirstBytes(&set, prefix[0], fold)
	return set
}
