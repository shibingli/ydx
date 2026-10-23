package regexpx

// linAtom is one ASCII matcher in a linear pattern. Fixed atoms consume min==max bytes, optional
// atoms consume zero or one byte, and the trailing atom (max == -1) consumes a byte run to the end of
// the match. | linAtom 是线性模式中的一个 ASCII 匹配器。固定原子消费 min==max 个字节，可选原子消费零
// 或一个字节，末尾原子（max == -1）消费一段字节运行。
type linAtom struct {
	class  *charClass
	lit    rune
	hasLit bool
	any    bool
	dotAll bool
	min    int
	max    int // -1 only for the trailing atom | 仅末尾原子为 -1
	greedy bool
}

// linInfo describes a concatenation of fixed, optional and one trailing ASCII matcher. It has no
// alternation, no captures and at most one unbounded repeat, which ends the pattern. Matching is a
// small deterministic backtracking walk with a step budget; inputs containing non-ASCII bytes fall
// back to the general engine. | linInfo 描述由固定、可选与一个末尾 ASCII 匹配器组成的连接。它没有
// 分支与捕获，至多一个无界重复且位于模式末尾。匹配是一次带步数预算的小型确定性回溯；包含非 ASCII
// 字节的输入回退到通用引擎。
type linInfo struct {
	atoms       []linAtom
	length      int // fixed byte length when variable is false | variable 为 false 时的固定字节长度
	variable    bool
	anchorStart bool
	anchorEnd   bool
	// anchorOff, anchorByte and anchorOK describe a punctuation literal at a fixed offset. Searching
	// for that literal produces far fewer candidates than scanning the first-byte set, for example
	// the '-' in \d{4}-\d{2}-\d{2}. | anchorOff、anchorByte 与 anchorOK 描述固定偏移处的标点字面量。
	// 搜索该字面量比扫描首字节集合产生更少的候选，例如 \d{4}-\d{2}-\d{2} 中的 '-'。
	anchorOff  int
	anchorByte byte
	anchorOK   bool
}

// analyzeLinear recognizes the fixed/optional/trailing-run ASCII shape. Multiple unbounded repeats,
// alternation, captures, lazy trailing runs and non-ASCII literals fall back to the general engines.
// | analyzeLinear 识别固定/可选/尾运行 ASCII 形态。多个无界重复、分支、捕获、惰性尾运行与非 ASCII
// 字面量回退到通用引擎。
func analyzeLinear(ast node, numCap int) *linInfo {
	if numCap != 0 {
		return nil
	}
	info := &linInfo{}
	subs := []node{ast}
	if concat, ok := ast.(*nConcat); ok {
		subs = concat.sub
	}
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
	for i, sub := range subs {
		last := i == len(subs)-1
		switch n := sub.(type) {
		case *nEmpty:
		case *nLiteral:
			if clear, ok := asciiLinLiteral(n.r, n.fold); ok {
				info.atoms = append(info.atoms, linAtom{lit: clear, hasLit: true, min: 1, max: 1, greedy: true})
				info.length++
				continue
			}
			return nil
		case *nString:
			if n.fold {
				return nil
			}
			for _, r := range n.runes {
				if clear, ok := asciiLinLiteral(r, false); ok {
					info.atoms = append(info.atoms, linAtom{lit: clear, hasLit: true, min: 1, max: 1, greedy: true})
					info.length++
					continue
				}
				return nil
			}
		case *nClass:
			info.atoms = append(info.atoms, linAtom{class: n.c, min: 1, max: 1, greedy: true})
			info.length++
		case *nAny:
			info.atoms = append(info.atoms, linAtom{any: true, dotAll: n.dotAll, min: 1, max: 1, greedy: true})
			info.length++
		case *nRepeat:
			atom, ok := linRepeatAtom(n, last)
			if !ok {
				return nil
			}
			info.atoms = append(info.atoms, atom)
			if atom.max < 0 {
				info.variable = true
			} else if atom.min != atom.max {
				info.variable = true
			} else {
				info.length += atom.min
			}
		default:
			return nil
		}
	}
	if len(info.atoms) == 0 {
		return nil
	}
	// A fixed pattern can be searched by a punctuation literal instead of its first byte. Only
	// single-byte literals are anchors; punctuation is less frequent than digits or letters in
	// typical text. | 固定模式可用标点字面量代替首字节进行搜索。只有单字节字面量可作为锚点；在
	// 常见文本中标点比数字或字母更稀疏。
	if !info.variable {
		off := 0
		for i := range info.atoms {
			atom := &info.atoms[i]
			if atom.min == 1 && atom.max == 1 && atom.hasLit && anchorLiteral(byte(atom.lit)) {
				info.anchorOff, info.anchorByte, info.anchorOK = off, byte(atom.lit), true
				break
			}
			off += atom.min
		}
	}
	return info
}

// anchorLiteral reports whether b is printable punctuation rather than a letter, digit or space. |
// anchorLiteral 报告 b 是否是可打印标点而非字母、数字或空白。
func anchorLiteral(b byte) bool {
	if b <= ' ' || b >= 0x7F {
		return false
	}
	if b >= '0' && b <= '9' || b >= 'A' && b <= 'Z' || b >= 'a' && b <= 'z' {
		return false
	}
	return true
}

// asciiLinLiteral returns the literal when it can be matched byte by byte. | asciiLinLiteral 在字面量
// 可逐字节匹配时返回它。
func asciiLinLiteral(r rune, fold bool) (rune, bool) {
	if r >= 128 || fold {
		return 0, false
	}
	return r, true
}

// linRepeatAtom builds the atom for one repeat. Only fixed counts, a single optional byte and the
// final greedy unbounded run are supported. | linRepeatAtom 为一个重复构造原子。仅支持固定次数、单个
// 可选字节与末尾贪婪无界运行。
func linRepeatAtom(n *nRepeat, last bool) (linAtom, bool) {
	var atom linAtom
	switch body := n.sub.(type) {
	case *nLiteral:
		r, ok := asciiLinLiteral(body.r, body.fold)
		if !ok {
			return atom, false
		}
		atom.lit, atom.hasLit = r, true
	case *nClass:
		atom.class = body.c
	case *nAny:
		atom.any, atom.dotAll = true, body.dotAll
	default:
		return atom, false
	}
	switch {
	case n.max == -1:
		if !last || !n.greedy || n.min < 0 {
			return atom, false
		}
		atom.min, atom.max, atom.greedy = n.min, -1, n.greedy
	case n.min == n.max && n.min > 0:
		atom.min, atom.max, atom.greedy = n.min, n.min, n.greedy
	case n.min == 0 && n.max == 1:
		atom.min, atom.max, atom.greedy = 0, 1, n.greedy
	default:
		return atom, false
	}
	return atom, true
}

// matchByte reports whether the atom matches one ASCII byte. | matchByte 报告原子是否匹配一个 ASCII
// 字节。
func (a *linAtom) matchByte(b byte) bool {
	switch {
	case a.hasLit:
		return b == byte(a.lit)
	case a.class != nil:
		return a.class.match(rune(b))
	default:
		return a.dotAll || b != '\n'
	}
}

// linFind returns the leftmost linear match starting in [start, startLimit) and reports whether the
// input forced a fallback to the general engine. | linFind 返回起点位于 [start, startLimit) 的最左
// 线性匹配，并报告输入是否强制回退到通用引擎。
func (r *Regexp) linFind(s string, start, startLimit int) (int, int, bool, bool) {
	lin := r.lin
	if start < 0 {
		start = 0
	}
	if startLimit < 0 || startLimit > len(s)+1 {
		startLimit = len(s) + 1
	}
	if lin.anchorStart {
		if start != 0 || startLimit <= 0 {
			return 0, 0, false, false
		}
		return lin.matchAt(s, 0)
	}
	if lin.anchorEnd && !lin.variable {
		begin := len(s) - lin.length
		if begin < start || begin < 0 || begin >= startLimit {
			return 0, 0, false, false
		}
		return lin.matchAt(s, begin)
	}
	if !lin.variable && lin.anchorOK {
		from := start + lin.anchorOff
		if from < 0 {
			from = 0
		}
		for from < len(s) {
			at := indexByte(s, lin.anchorByte, from)
			if at < 0 {
				break
			}
			pos := at - lin.anchorOff
			if pos >= startLimit {
				break
			}
			if pos >= start {
				b, e, ok, fallback := lin.matchAt(s, pos)
				if fallback {
					return 0, 0, false, true
				}
				if ok {
					return b, e, true, false
				}
			}
			from = at + 1
		}
		return 0, 0, false, false
	}
	if !r.prog.info.firstBytesOK {
		// An anchored-end pattern may start with an optional or negated atom that admits every byte,
		// so there is no first-byte filter to scan. Leave the decision to the general engine instead
		// of reporting a false negative. | 锚定末尾的模式可能以放行所有字节的可选或否定原子开头，此时
		// 没有首字节过滤器可扫描。交由通用引擎判断，避免误报无匹配。
		return 0, 0, false, true
	}
	for cand := r.firstCandidate(s, start); cand >= 0; cand = r.firstCandidate(s, cand+1) {
		if cand >= startLimit {
			break
		}
		b, e, ok, fallback := lin.matchAt(s, cand)
		if fallback {
			return 0, 0, false, true
		}
		if ok {
			return b, e, true, false
		}
	}
	return 0, 0, false, false
}

// linStepLimit bounds the optional backtracking walk. Exceeding it falls back to the general engine
// instead of failing a valid match. | linStepLimit 限制可选回溯步数。超过后回退到通用引擎，而不是把
// 有效匹配判为失败。
const linStepLimit = 4096

// linMatcher is one linear match attempt. | linMatcher 是一次线性匹配尝试。
type linMatcher struct {
	info     *linInfo
	s        string
	steps    int
	fallback bool
}

// matchAt checks the linear program at pos and returns its end. | matchAt 在 pos 处检查线性程序并返回
// 结束位置。
func (lin *linInfo) matchAt(s string, pos int) (int, int, bool, bool) {
	m := linMatcher{info: lin, s: s}
	end, ok := m.match(0, pos)
	if m.fallback {
		return 0, 0, false, true
	}
	if !ok {
		return 0, 0, false, false
	}
	if lin.anchorEnd && end != len(s) {
		return 0, 0, false, false
	}
	return pos, end, true, false
}

// match walks atoms from index ai at pos. | match 从 pos 处、下标 ai 开始遍历原子。
func (m *linMatcher) match(ai, pos int) (int, bool) {
	m.steps++
	if m.steps > linStepLimit {
		m.fallback = true
		return 0, false
	}
	if ai == len(m.info.atoms) {
		return pos, true
	}
	atom := &m.info.atoms[ai]
	if atom.max == -1 {
		end := pos
		for end < len(m.s) {
			if m.s[end] >= 0x80 {
				m.fallback = true
				return 0, false
			}
			if !atom.matchByte(m.s[end]) {
				break
			}
			end++
		}
		if end-pos < atom.min {
			return 0, false
		}
		if m.info.anchorEnd && end != len(m.s) {
			return 0, false
		}
		return end, true
	}
	if atom.min == atom.max {
		for i := 0; i < atom.min; i++ {
			if pos >= len(m.s) {
				return 0, false
			}
			if m.s[pos] >= 0x80 {
				m.fallback = true
				return 0, false
			}
			if !atom.matchByte(m.s[pos]) {
				return 0, false
			}
			pos++
		}
		return m.match(ai+1, pos)
	}
	// Optional atom (min 0, max 1). | 可选原子（min 0，max 1）。
	if atom.greedy {
		if pos < len(m.s) {
			if m.s[pos] >= 0x80 {
				m.fallback = true
				return 0, false
			}
			if atom.matchByte(m.s[pos]) {
				if end, ok := m.match(ai+1, pos+1); ok || m.fallback {
					return end, ok
				}
			}
		}
		return m.match(ai+1, pos)
	}
	if end, ok := m.match(ai+1, pos); ok || m.fallback {
		return end, ok
	}
	if pos < len(m.s) {
		if m.s[pos] >= 0x80 {
			m.fallback = true
			return 0, false
		}
		if atom.matchByte(m.s[pos]) {
			return m.match(ai+1, pos+1)
		}
	}
	return 0, false
}

// asciiClassOK reports whether a class only matches ASCII bytes. It is used by the email shape, where
// byte classes must be exact without a rune fallback. | asciiClassOK 报告字符类是否只匹配 ASCII 字节。
// 邮件形态使用它，因为那里的字节类必须精确且没有符文回退。
func asciiClassOK(c *charClass) bool {
	if c.neg || c.fold || c.nonASCII || len(c.tables) > 0 {
		return false
	}
	for _, r := range c.ranges {
		if r.hi >= 128 {
			return false
		}
	}
	return true
}
