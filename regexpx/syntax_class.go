package regexpx

import (
	"slices"
	"unicode"
	"unicode/utf8"
)

// byteSet is a 256-bit membership bitmap over bytes. | byteSet 是字节的 256 位成员位图。
type byteSet [4]uint64

// runeRange is an inclusive rune interval. | runeRange 是闭区间符文范围。
type runeRange struct {
	lo, hi rune
}

// charClass is a compiled character class. The positive set is stored as an ASCII bitmap plus sorted
// non-ASCII ranges and Unicode range tables; negation and case folding are applied at match time so
// that folded negation follows the language semantics. | charClass 是编译后的字符类。正向集合以 ASCII
// 位图、有序非 ASCII 区间与 Unicode 区间表保存；取反与大小写折叠在匹配时应用，使折叠后的取反符合
// 语言语义。
type charClass struct {
	ascii     [4]uint64
	foldASCII [4]uint64
	ranges    []runeRange
	tables    []*unicode.RangeTable
	neg       bool
	fold      bool
	nonASCII  bool
}

// containsSlow checks the non-ASCII ranges and tables, and also handles ASCII when called from the
// folding orbit walk. | containsSlow 检查非 ASCII 区间与区间表，并在折叠轨道遍历中处理 ASCII。
func (c *charClass) containsSlow(r rune) bool {
	if r < 256 {
		return c.ascii[r>>6]&(uint64(1)<<(r&63)) != 0
	}
	lo, hi := 0, len(c.ranges)
	for lo < hi {
		mid := int(uint(lo+hi) >> 1)
		switch {
		case r < c.ranges[mid].lo:
			hi = mid
		case r > c.ranges[mid].hi:
			lo = mid + 1
		default:
			return true
		}
	}
	for _, table := range c.tables {
		if unicode.Is(table, r) {
			return true
		}
	}
	return false
}

// match reports whether r matches the class, applying folding before negation. | match 报告 r 是否匹配
// 该字符类，并在取反之前应用大小写折叠。
func (c *charClass) match(r rune) bool {
	var ok bool
	if r < 256 {
		word := r >> 6
		bit := uint64(1) << (r & 63)
		if c.fold {
			ok = c.foldASCII[word]&bit != 0
		} else {
			ok = c.ascii[word]&bit != 0
		}
		return ok != c.neg
	}
	ok = c.containsSlow(r)
	if !ok && c.fold {
		for f := unicode.SimpleFold(r); f != r; f = unicode.SimpleFold(f) {
			if c.containsSlow(f) {
				ok = true
				break
			}
		}
	}
	return ok != c.neg
}

// classBuilder accumulates ranges and Unicode tables before a class is normalized. | classBuilder 在
// 字符类规范化之前累积区间与 Unicode 表。
type classBuilder struct {
	ranges []runeRange
	tables []*unicode.RangeTable
}

// addRanges appends positive ranges. | addRanges 追加正向区间。
func (b *classBuilder) addRanges(rs []runeRange) {
	b.ranges = append(b.ranges, rs...)
}

// addTable appends a Unicode table. | addTable 追加 Unicode 区间表。
func (b *classBuilder) addTable(t *unicode.RangeTable) {
	if t == nil {
		b.addRanges([]runeRange{{0, unicode.MaxRune}})
		return
	}
	b.tables = append(b.tables, t)
}

// addTableComplement appends the complement of a Unicode table as explicit ranges. | addTableComplement
// 以显式区间追加 Unicode 区间表的补集。
func (b *classBuilder) addTableComplement(t *unicode.RangeTable) {
	if t == nil {
		return
	}
	b.addRanges(complementRanges(tableToRanges(t)))
}

// build normalizes the accumulated set and produces the compiled class. | build 规范化累积集合并生成
// 编译后的字符类。
func (b *classBuilder) build(neg, fold bool) *charClass {
	c := &charClass{neg: neg, fold: fold}
	c.ranges = normalizeRanges(b.ranges)
	c.tables = b.tables
	for _, r := range c.ranges {
		if r.hi >= 256 {
			c.nonASCII = true
		}
		lo, hi := r.lo, r.hi
		if hi > 255 {
			hi = 255
		}
		for v := lo; v <= hi; v++ {
			c.ascii[v>>6] |= uint64(1) << (v & 63)
		}
	}
	if len(c.tables) > 0 {
		for v := rune(0); v < 256; v++ {
			for _, table := range c.tables {
				if unicode.Is(table, v) {
					c.ascii[v>>6] |= uint64(1) << (v & 63)
					break
				}
			}
		}
		for _, table := range c.tables {
			if table.R32 != nil || table.R16 != nil {
				c.nonASCII = true
			}
		}
	}
	if fold {
		for v := rune(0); v < 256; v++ {
			if c.foldContains(v) {
				c.foldASCII[v>>6] |= uint64(1) << (v & 63)
				for f := unicode.SimpleFold(v); f != v; f = unicode.SimpleFold(f) {
					if f >= utf8.RuneSelf {
						// An ASCII member folds with a non-ASCII rune, so the first-byte
						// prefilter must admit non-ASCII lead bytes. | ASCII 成员与非 ASCII
						// 符文折叠，因此首字节预过滤必须接受非 ASCII 首字节。
						c.nonASCII = true
						break
					}
				}
			}
		}
	}
	return c
}

// foldContains reports whether any rune in v's simple-fold orbit belongs to the positive set. |
// foldContains 报告 v 的简单折叠轨道中是否有符文属于正向集合。
func (c *charClass) foldContains(v rune) bool {
	if c.containsSlow(v) {
		return true
	}
	for f := unicode.SimpleFold(v); f != v; f = unicode.SimpleFold(f) {
		if c.containsSlow(f) {
			return true
		}
	}
	return false
}

// asciiMatch reports whether a single ASCII byte matches the class after folding and negation. |
// asciiMatch 报告单个 ASCII 字节在折叠与取反后是否匹配该字符类。
func (c *charClass) asciiMatch(b byte) bool {
	r := rune(b)
	var ok bool
	if c.fold {
		ok = c.foldASCII[r>>6]&(uint64(1)<<(r&63)) != 0
	} else {
		ok = c.ascii[r>>6]&(uint64(1)<<(r&63)) != 0
	}
	return ok != c.neg
}

// firstBytes returns a sound superset of the first UTF-8 bytes of any rune the class can match. |
// firstBytes 返回该类可匹配的任意符文首字节的可靠超集。
func (c *charClass) firstBytes() byteSet {
	var bits byteSet
	if c.neg {
		return allBytes()
	}
	for v := rune(0); v < 256; v++ {
		if c.asciiMatch(byte(v)) {
			bits[v>>6] |= uint64(1) << (v & 63)
		}
	}
	if c.nonASCII {
		// Every valid non-ASCII lead byte is a sound superset; continuation bytes are excluded
		// because a match never starts at one. | 所有合法的非 ASCII 首字节构成可靠超集；续字节不会
		// 成为匹配起点，因此排除。
		for b := 0xC2; b <= 0xF4; b++ {
			bits[b>>6] |= uint64(1) << (b & 63)
		}
	}
	return bits
}

// allBytes returns a bitmap with every byte bit set. | allBytes 返回所有字节位均置位的位图。
func allBytes() byteSet {
	return byteSet{^uint64(0), ^uint64(0), ^uint64(0), ^uint64(0)}
}

// addByte sets one byte bit. | addByte 置位一个字节位。
func (b *byteSet) addByte(v byte) {
	b[v>>6] |= uint64(1) << (v & 63)
}

// union merges other into b. | union 把 other 合并到 b。
func (b *byteSet) union(other byteSet) {
	for i := range b {
		b[i] |= other[i]
	}
}

// has reports whether the byte bit is set. | has 报告字节位是否置位。
func (b *byteSet) has(v byte) bool {
	return b[v>>6]&(uint64(1)<<(v&63)) != 0
}

// normalizeRanges sorts and merges overlapping or adjacent intervals. | normalizeRanges 排序并合并重叠
// 或相邻区间。
func normalizeRanges(rs []runeRange) []runeRange {
	if len(rs) == 0 {
		return nil
	}
	slices.SortFunc(rs, func(a, b runeRange) int {
		switch {
		case a.lo < b.lo:
			return -1
		case a.lo > b.lo:
			return 1
		default:
			return 0
		}
	})
	out := rs[:0]
	for _, r := range rs {
		if r.lo > r.hi {
			continue
		}
		if len(out) == 0 || int64(r.lo) > int64(out[len(out)-1].hi)+1 {
			out = append(out, r)
			continue
		}
		if r.hi > out[len(out)-1].hi {
			out[len(out)-1].hi = r.hi
		}
	}
	return out
}

// complementRanges returns the complement of rs over the Unicode range. | complementRanges 返回 rs 在
// Unicode 范围内的补集。
func complementRanges(rs []runeRange) []runeRange {
	rs = normalizeRanges(rs)
	out := make([]runeRange, 0, len(rs)+1)
	next := int64(0)
	for _, r := range rs {
		if int64(r.lo) > next {
			out = append(out, runeRange{rune(next), r.lo - 1})
		}
		if int64(r.hi)+1 > next {
			next = int64(r.hi) + 1
		}
	}
	if next <= int64(unicode.MaxRune) {
		out = append(out, runeRange{rune(next), unicode.MaxRune})
	}
	return out
}

// tableToRanges expands a Unicode table into explicit intervals, splitting stride-based entries into
// individual runes. | tableToRanges 把 Unicode 区间表展开为显式区间，并把带步长的条目拆成单个符文。
func tableToRanges(t *unicode.RangeTable) []runeRange {
	var out []runeRange
	for _, r := range t.R16 {
		if r.Stride == 1 {
			out = append(out, runeRange{rune(r.Lo), rune(r.Hi)})
			continue
		}
		for v := int64(r.Lo); v <= int64(r.Hi); v += int64(r.Stride) {
			out = append(out, runeRange{rune(v), rune(v)})
		}
	}
	for _, r := range t.R32 {
		if r.Stride == 1 {
			out = append(out, runeRange{rune(r.Lo), rune(r.Hi)})
			continue
		}
		for v := int64(r.Lo); v <= int64(r.Hi); v += int64(r.Stride) {
			out = append(out, runeRange{rune(v), rune(v)})
		}
	}
	return out
}

// asciiDigit is the ASCII digit class. | asciiDigit 是 ASCII 数字类。
var asciiDigit = []runeRange{{'0', '9'}}

// asciiSpace is the ASCII whitespace class used by \s. | asciiSpace 是 \s 使用的 ASCII 空白类。
var asciiSpace = []runeRange{{'\t', '\r'}, {' ', ' '}}

// asciiWord is the ASCII word class used by \w. | asciiWord 是 \w 使用的 ASCII 单词类。
var asciiWord = []runeRange{{'0', '9'}, {'A', 'Z'}, {'_', '_'}, {'a', 'z'}}

// classNode builds a class node from positive ranges. | classNode 根据正向区间构造字符类节点。
func classNode(rs []runeRange, neg bool, flags flagSet) node {
	b := &classBuilder{}
	b.addRanges(rs)
	return &nClass{c: b.build(neg, flags&flagFold != 0)}
}

// posixClasses maps POSIX class names to their ASCII intervals. | posixClasses 把 POSIX 类名映射到
// 其 ASCII 区间。
var posixClasses = map[string][]runeRange{
	"alnum":  {{'0', '9'}, {'A', 'Z'}, {'a', 'z'}},
	"alpha":  {{'A', 'Z'}, {'a', 'z'}},
	"ascii":  {{0, 0x7F}},
	"blank":  {{'\t', '\t'}, {' ', ' '}},
	"cntrl":  {{0, 0x1F}, {0x7F, 0x7F}},
	"digit":  {{'0', '9'}},
	"graph":  {{'!', '~'}},
	"lower":  {{'a', 'z'}},
	"print":  {{' ', '~'}},
	"punct":  {{'!', '/'}, {':', '@'}, {'[', '`'}, {'{', '~'}},
	"space":  {{'\t', '\r'}, {' ', ' '}},
	"upper":  {{'A', 'Z'}},
	"word":   {{'0', '9'}, {'A', 'Z'}, {'_', '_'}, {'a', 'z'}},
	"xdigit": {{'0', '9'}, {'A', 'F'}, {'a', 'f'}},
}

// parseClass parses a bracketed character class. | parseClass 解析方括号字符类。
func (p *parser) parseClass(flags flagSet) node {
	p.pos++ // consume '['
	neg := false
	if p.peek() == '^' {
		neg = true
		p.pos++
	}
	b := &classBuilder{}
	first := true
	items := 0
	for {
		if p.err != nil {
			return nil
		}
		r := p.peek()
		if r == -1 {
			p.fail("missing closing ] | 缺少右方括号")
			return nil
		}
		if r == ']' && !first {
			p.pos++
			break
		}
		first = false

		if r == '[' && p.peekAt(1) == ':' {
			if rs, ok := p.parsePOSIX(); ok {
				b.addRanges(rs)
				items++
				if p.peek() == '-' && p.peekAt(1) != ']' {
					p.fail("invalid character class range | 非法的字符类范围")
					return nil
				}
				continue
			}
		}

		if r == '\\' && p.peekAt(1) == 'Q' {
			p.pos += 2
			for p.pos < len(p.runes) {
				if p.runes[p.pos] == '\\' && p.peekAt(1) == 'E' {
					p.pos += 2
					break
				}
				v := p.next()
				b.addRanges([]runeRange{{v, v}})
				items++
			}
			continue
		}

		lo, ok := p.parseClassLiteral(flags)
		if !ok {
			return nil
		}
		if lo.isClass {
			b.addRanges(lo.ranges)
			if lo.table != nil {
				b.addTable(lo.table)
			}
			items++
			if p.peek() == '-' && p.peekAt(1) != ']' {
				p.fail("invalid character class range | 非法的字符类范围")
				return nil
			}
			continue
		}
		if p.peek() == '-' && p.peekAt(1) != ']' && p.peekAt(1) != -1 {
			p.pos++
			hi, ok := p.parseClassLiteral(flags)
			if !ok {
				return nil
			}
			if hi.isClass {
				p.fail("invalid character class range | 非法的字符类范围")
				return nil
			}
			if hi.r < lo.r {
				p.fail("invalid character class range | 非法的字符类范围")
				return nil
			}
			b.addRanges([]runeRange{{lo.r, hi.r}})
		} else {
			b.addRanges([]runeRange{{lo.r, lo.r}})
		}
		items++
	}
	if neg && p.posix {
		// POSIX negated classes do not match newline (ClassNL is off), matching
		// regexp.CompilePOSIX. | POSIX 否定字符类不匹配换行（ClassNL 关闭），与
		// regexp.CompilePOSIX 一致。
		b.addRanges([]runeRange{{'\n', '\n'}})
	}
	if items == 0 {
		// [] is an empty class, and [^] is its complement. | [] 是空类，[^] 是其补集。
		return &nClass{c: b.build(neg, flags&flagFold != 0)}
	}
	return &nClass{c: b.build(neg, flags&flagFold != 0)}
}

// classLiteral is one parsed class element: either a single literal rune or a nested class item. |
// classLiteral 是一个解析后的字符类元素：单个字面量符文或嵌套类项。
type classLiteral struct {
	r       rune
	isClass bool
	ranges  []runeRange
	table   *unicode.RangeTable
}

// parseClassLiteral parses one literal or class escape inside a class. | parseClassLiteral 解析字符类
// 内的一个字面量或类转义。
func (p *parser) parseClassLiteral(flags flagSet) (classLiteral, bool) {
	r := p.peek()
	if r != '\\' {
		p.pos++
		return classLiteral{r: r}, true
	}
	p.pos++
	if p.pos >= len(p.runes) {
		p.fail("trailing backslash in character class | 字符类结尾反斜杠")
		return classLiteral{}, false
	}
	r = p.next()
	switch r {
	case 'a':
		return classLiteral{r: '\a'}, true
	case 'f':
		return classLiteral{r: '\f'}, true
	case 't':
		return classLiteral{r: '\t'}, true
	case 'n':
		return classLiteral{r: '\n'}, true
	case 'r':
		return classLiteral{r: '\r'}, true
	case 'v':
		return classLiteral{r: '\v'}, true
	case 'e':
		return classLiteral{r: 0x1B}, true
	case 'b':
		return classLiteral{r: '\b'}, true
	case 'c':
		node := p.parseControl(flags)
		lit, ok := node.(*nLiteral)
		if !ok {
			return classLiteral{}, false
		}
		return classLiteral{r: lit.r}, true
	case 'd':
		return classLiteral{isClass: true, ranges: asciiDigit}, true
	case 'D':
		return classLiteral{isClass: true, ranges: complementRanges(asciiDigit)}, true
	case 's':
		return classLiteral{isClass: true, ranges: asciiSpace}, true
	case 'S':
		return classLiteral{isClass: true, ranges: complementRanges(asciiSpace)}, true
	case 'w':
		return classLiteral{isClass: true, ranges: asciiWord}, true
	case 'W':
		return classLiteral{isClass: true, ranges: complementRanges(asciiWord)}, true
	case 'p', 'P':
		b := &classBuilder{}
		if !p.parseUnicodeClass(b, r == 'P') {
			return classLiteral{}, false
		}
		return classLiteral{isClass: true, ranges: b.ranges, table: firstTable(b.tables)}, true
	case 'x':
		value, ok := p.parseHex()
		if !ok {
			return classLiteral{}, false
		}
		return classLiteral{r: value}, true
	case '0', '1', '2', '3', '4', '5', '6', '7':
		value, ok := p.parseOctal(r)
		if !ok {
			return classLiteral{}, false
		}
		return classLiteral{r: value}, true
	case '8', '9':
		p.fail("invalid escape in character class | 字符类中的非法转义")
		return classLiteral{}, false
	}
	if isASCIIPunct(r) {
		return classLiteral{r: r}, true
	}
	p.failf("invalid escape sequence \\%c | 非法的转义序列 \\%c", r, r)
	return classLiteral{}, false
}

// firstTable returns the first table when there is exactly one, otherwise nil. Classes built from
// \p are the only ones that add a single table here. | firstTable 在恰好只有一张表时返回它，否则返回
// nil。这里只有 \p 构造的类会追加单张表。
func firstTable(tables []*unicode.RangeTable) *unicode.RangeTable {
	if len(tables) == 1 {
		return tables[0]
	}
	return nil
}

// parsePOSIX parses [:name:] or [:^name:] at the current position. It restores the position and
// reports false when the text is not a valid POSIX class, so '[' can become a literal. | parsePOSIX
// 解析当前位置的 [:name:] 或 [:^name:]。文本不是合法 POSIX 类时恢复位置并返回 false，使 '[' 可作为
// 字面量。
func (p *parser) parsePOSIX() ([]runeRange, bool) {
	save := p.pos
	if p.peek() != '[' || p.peekAt(1) != ':' {
		return nil, false
	}
	p.pos += 2
	neg := false
	if p.peek() == '^' {
		neg = true
		p.pos++
	}
	start := p.pos
	for p.pos < len(p.runes) {
		r := p.runes[p.pos]
		if (r >= 'a' && r <= 'z') || r == '_' {
			p.pos++
			continue
		}
		break
	}
	name := string(p.runes[start:p.pos])
	if p.peek() != ':' || p.peekAt(1) != ']' {
		p.pos = save
		return nil, false
	}
	p.pos += 2
	rs, ok := posixClasses[name]
	if !ok {
		p.failf("invalid POSIX class %q | 非法的 POSIX 类 %q", name, name)
		return nil, false
	}
	if neg {
		return complementRanges(rs), true
	}
	return rs, true
}

// singleRune reports whether the class matches exactly one rune without folding. It is used by
// LiteralPrefix to treat [a] as the literal a, matching the standard library. | singleRune 报告
// 字符类是否在不折叠的情况下恰好匹配一个符文。LiteralPrefix 用它把 [a] 当作字面量 a，与标准库一致。
func (c *charClass) singleRune() (rune, bool) {
	if c == nil || c.neg || c.fold || len(c.tables) > 0 {
		return 0, false
	}
	var r rune
	found := false
	for b := 0; b < 256; b++ {
		if c.ascii[b>>6]&(uint64(1)<<(b&63)) == 0 {
			continue
		}
		if found {
			return 0, false
		}
		r = rune(b)
		found = true
	}
	for _, rg := range c.ranges {
		if found && rg.lo == rg.hi && rune(rg.lo) == r {
			// The class constructor mirrors ASCII members into both the bitmap and the range
			// list; a duplicate of the rune already found is not a second member. | 字符类构造器
			// 会把 ASCII 成员同时写入位图与区间列表；与已发现符文相同的重复项不是第二个成员。
			continue
		}
		if rg.lo != rg.hi || found {
			return 0, false
		}
		r = rg.lo
		found = true
	}
	if !found || r == utf8.RuneError {
		return 0, false
	}
	return r, true
}
