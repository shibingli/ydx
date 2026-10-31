package waf

import (
	"math/bits"
	"sort"
	"strings"
	"unicode/utf8"
)

// Required-literal prefilter limits. | 必需字面量预过滤上限。
const (
	requiredNeedleGram  = 4
	maxRequiredShort    = 512
	maxRequiredNeedles  = 4096
	minNeedleBloomBits  = 1 << 10
	maxNeedleBloomBits  = 1 << 18
	maxNeedleParseDepth = 128
	maxNeedleMin        = 1 << 30
)

// needleNode is the small AST used only for required-literal analysis. It is intentionally
// independent from the regex engine AST; anything this parser cannot prove is treated as having
// no required literal. | needleNode 是仅用于必需字面量分析的小型 AST。它刻意独立于正则引擎 AST；
// 解析器无法证明的构造一律视为没有必需字面量。
type needleNode struct {
	lit     string
	sub     []*needleNode
	bytes   [4]uint64
	kind    uint8
	minLen  int
	hasByte bool
}

// Needle node kinds. | 字面量节点类型。
const (
	needleEmpty uint8 = iota
	needleLiteral
	needleConcat
	needleAlternation
)

// needleParser parses enough of the regex syntax to compute a sound required-literal set.
// | needleParser 解析足够的正则语法，以计算可靠的必需字面量集合。
type needleParser struct {
	src              string
	pos              int
	depth            int
	fold             bool
	nonASCIILiterals bool
	failed           bool
}

// needleSet is a non-empty set of literals where a match contains at least one of them.
// | needleSet 是一个非空字面量集合；命中值至少包含其中一个。
type needleSet struct {
	values []string
	ok     bool
}

// regexAnalysis is the legacy four-value view of analyzeRegex. | regexAnalysis 是 analyzeRegex 的
// 四返回值兼容视图。
func regexAnalysis(pattern string) (needles []string, fold, hasNeedles bool, minLen int) {
	analysis := analyzeRegex(pattern)
	return analysis.needles, analysis.fold, analysis.hasNeedles, analysis.minLen
}

// regexAnalysisResult carries all compile-time regex prefilters. | regexAnalysisResult 承载全部编译期
// 正则预过滤信息。
type regexAnalysisResult struct {
	needles    []string
	bytes      [4]uint64
	fold       bool
	hasNeedles bool
	hasBytes   bool
	minLen     int
}

// analyzeRegex parses a pattern once and returns its required literals, required byte set and a
// sound lower bound on the bytes a match can consume. | analyzeRegex 一次解析模式，返回必需字面量、
// 必需字节集以及匹配至少消耗字节数的可靠下界。
func analyzeRegex(pattern string) regexAnalysisResult {
	var result regexAnalysisResult
	if pattern == "" {
		return result
	}
	parser := &needleParser{src: pattern}
	node := parser.parseAlternation()
	if parser.failed || parser.pos != len(pattern) || node == nil {
		return result
	}
	result.minLen = node.minLen
	if parser.fold && parser.nonASCIILiterals {
		// Unicode case folding can turn a multi-byte literal into a shorter byte sequence. |
		// Unicode 大小写折叠可能把多字节字面量变成更短的字节序列。
		result.minLen = 0
	}
	if node.hasByte {
		result.bytes = node.bytes
		result.hasBytes = true
		if parser.fold {
			result.bytes = foldByteSet(result.bytes)
			result.fold = true
		}
	}
	set := requiredSet(node)
	if !set.ok || len(set.values) == 0 || len(set.values) > maxRequiredNeedles {
		result.fold = parser.fold
		return result
	}
	sort.Strings(set.values)
	if parser.fold {
		for _, needle := range set.values {
			if !asciiString(needle) {
				result.fold = parser.fold
				return result
			}
		}
	}
	result.needles = set.values
	result.hasNeedles = true
	result.fold = parser.fold
	return result
}

// regexRequiredNeedles returns just the required-literal part of regexAnalysis. |
// regexRequiredNeedles 只返回 regexAnalysis 的必需字面量部分。
func regexRequiredNeedles(pattern string) (needles []string, fold, ok bool) {
	needles, fold, ok, _ = regexAnalysis(pattern)
	return needles, fold, ok
}

// parseAlternation parses top-level alternation. | parseAlternation 解析顶层分支。
func (p *needleParser) parseAlternation() *needleNode {
	var branches []*needleNode
	for {
		branch := p.parseConcatenation()
		if p.failed {
			return nil
		}
		branches = append(branches, branch)
		if p.pos < len(p.src) && p.src[p.pos] == '|' {
			p.pos++
			continue
		}
		break
	}
	if len(branches) == 1 {
		return branches[0]
	}
	minimum := maxNeedleMin
	var set [4]uint64
	hasByte := true
	for _, branch := range branches {
		if branch.minLen < minimum {
			minimum = branch.minLen
		}
		if !branch.hasByte {
			hasByte = false
			continue
		}
		set = unionByteSets(set, branch.bytes)
	}
	return &needleNode{kind: needleAlternation, sub: branches, minLen: minimum, bytes: set, hasByte: hasByte}
}

// parseConcatenation parses a sequence of repeated atoms. | parseConcatenation 解析重复原子序列。
func (p *needleParser) parseConcatenation() *needleNode {
	var parts []*needleNode
	for p.pos < len(p.src) && p.src[p.pos] != '|' && p.src[p.pos] != ')' {
		part := p.parseRepeat()
		if p.failed {
			return nil
		}
		if part != nil {
			parts = append(parts, part)
		}
	}
	if len(parts) == 0 {
		return &needleNode{kind: needleEmpty}
	}
	if len(parts) == 1 {
		return parts[0]
	}
	minimum := 0
	var set [4]uint64
	hasByte := false
	bestCount := 0
	for _, part := range parts {
		minimum = addNeedleMin(minimum, part.minLen)
		if part.hasByte {
			count := byteSetCount(part.bytes)
			if count > 0 && (!hasByte || count < bestCount) {
				set = part.bytes
				bestCount = count
				hasByte = true
			}
		}
	}
	return &needleNode{kind: needleConcat, sub: parts, minLen: minimum, bytes: set, hasByte: hasByte}
}

// parseRepeat parses one atom and its quantifier. | parseRepeat 解析一个原子及其量词。
func (p *needleParser) parseRepeat() *needleNode {
	atom := p.parseAtom()
	if p.failed || atom == nil {
		return atom
	}
	minimum := 1
	if p.pos < len(p.src) {
		switch p.src[p.pos] {
		case '?':
			minimum = 0
			p.pos++
		case '*':
			minimum = 0
			p.pos++
		case '+':
			p.pos++
		case '{':
			value, good := p.parseBraceMinimum()
			if !good {
				p.failed = true
				return nil
			}
			minimum = value
		}
	}
	if p.pos < len(p.src) && (p.src[p.pos] == '?' || p.src[p.pos] == '+') {
		p.pos++
	}
	if minimum == 0 {
		return &needleNode{kind: needleEmpty}
	}
	atom.minLen = mulNeedleMin(atom.minLen, minimum)
	return atom
}

// parseBraceMinimum parses {m}, {m,} or {m,n}. | parseBraceMinimum 解析 {m}、{m,} 或 {m,n}。
func (p *needleParser) parseBraceMinimum() (int, bool) {
	if p.pos >= len(p.src) || p.src[p.pos] != '{' {
		return 0, false
	}
	index := p.pos + 1
	start := index
	for index < len(p.src) && p.src[index] >= '0' && p.src[index] <= '9' {
		index++
	}
	if index == start {
		return 0, false
	}
	minimum := 0
	for _, digit := range p.src[start:index] {
		if minimum > maxNeedleMin/10 {
			minimum = maxNeedleMin
			break
		}
		minimum = minimum*10 + int(digit-'0')
	}
	switch {
	case index < len(p.src) && p.src[index] == '}':
		p.pos = index + 1
		return minimum, true
	case index < len(p.src) && p.src[index] == ',':
		index++
		for index < len(p.src) && p.src[index] >= '0' && p.src[index] <= '9' {
			index++
		}
		if index < len(p.src) && p.src[index] == '}' {
			p.pos = index + 1
			return minimum, true
		}
	}
	return 0, false
}

// parseAtom parses one literal, group, class, assertion or unsupported token. | parseAtom 解析一个字面量、
// 分组、字符类、断言或不支持的标记。
func (p *needleParser) parseAtom() *needleNode {
	if p.pos >= len(p.src) {
		return &needleNode{kind: needleEmpty}
	}
	switch p.src[p.pos] {
	case '(':
		return p.parseGroup()
	case '[':
		next, set, hasByte, good := parseClassByteSet(p.src, p.pos, len(p.src))
		if !good {
			p.failed = true
			return nil
		}
		p.pos = next
		return &needleNode{kind: needleEmpty, minLen: 1, bytes: set, hasByte: hasByte}
	case '\\':
		return p.parseLiteralRun()
	case '.':
		p.pos++
		return &needleNode{kind: needleEmpty, minLen: 1}
	case '^', '$', '*', '+', '?', '{', '}', ']':
		p.pos++
		return &needleNode{kind: needleEmpty}
	case '|', ')':
		return &needleNode{kind: needleEmpty}
	default:
		return p.parseLiteralRun()
	}
}

// parseLiteralRun parses contiguous literal bytes, including simple escaped punctuation.
// | parseLiteralRun 解析连续的字面量字节，包括简单转义的标点。
func (p *needleParser) parseLiteralRun() *needleNode {
	var literal []byte
	minimum := 0
	for p.pos < len(p.src) {
		c := p.src[p.pos]
		if c == '\\' {
			value, isLiteral, next, good := parseRegexEscape(p.src, p.pos, len(p.src))
			if !good {
				p.failed = true
				return nil
			}
			if !isLiteral {
				minimum = addNeedleMin(minimum, escapeNeedleMin(p.src[p.pos+1]))
				p.pos = next
				break
			}
			literal = append(literal, value...)
			p.pos = next
			continue
		}
		if isRegexMetaByte(c) {
			break
		}
		literal = append(literal, c)
		p.pos++
	}
	if !asciiBytes(literal) {
		p.nonASCIILiterals = true
	}
	minimum = addNeedleMin(minimum, literalNeedleMin(literal, p.fold))
	var set [4]uint64
	for _, b := range literal {
		setByteBit(&set, b)
	}
	if len(literal) == 0 || p.fold && !asciiBytes(literal) {
		return &needleNode{kind: needleEmpty, minLen: minimum, bytes: set, hasByte: len(literal) > 0}
	}
	return &needleNode{kind: needleLiteral, lit: string(literal), minLen: minimum, bytes: set, hasByte: true}
}

// parseGroup parses a group, flags, lookaround or other parenthesized construct. | parseGroup 解析
// 分组、标志、环视或其它括号构造。
func (p *needleParser) parseGroup() *needleNode {
	p.depth++
	if p.depth > maxNeedleParseDepth {
		p.failed = true
		return nil
	}
	defer func() { p.depth-- }()
	start := p.pos
	p.pos++
	if p.pos >= len(p.src) || p.src[p.pos] == '*' {
		// PCRE verbs such as (*SKIP) are not literal groups. | (*SKIP) 等 PCRE 动词不是字面量分组。
		p.failed = true
		return nil
	}
	if p.src[p.pos] != '?' {
		inner := p.parseAlternation()
		if !p.closeGroup() {
			return nil
		}
		return inner
	}
	p.pos++
	if p.pos >= len(p.src) {
		p.failed = true
		return nil
	}
	switch p.src[p.pos] {
	case ':':
		p.pos++
		inner := p.parseAlternation()
		if !p.closeGroup() {
			return nil
		}
		return inner
	case '=', '!':
		p.pos = start
		if !p.skipGroup() {
			return nil
		}
		return &needleNode{kind: needleEmpty}
	case '<':
		if p.pos+1 < len(p.src) && (p.src[p.pos+1] == '=' || p.src[p.pos+1] == '!') {
			p.pos = start
			if !p.skipGroup() {
				return nil
			}
			return &needleNode{kind: needleEmpty}
		}
		p.pos++
		if !p.skipUntil('>') {
			return nil
		}
		inner := p.parseAlternation()
		if !p.closeGroup() {
			return nil
		}
		return inner
	case '\'':
		p.pos++
		if !p.skipUntil('\'') {
			return nil
		}
		inner := p.parseAlternation()
		if !p.closeGroup() {
			return nil
		}
		return inner
	case 'P':
		p.pos++
		if p.pos >= len(p.src) {
			p.failed = true
			return nil
		}
		if p.src[p.pos] == '=' {
			p.pos = start
			if !p.skipGroup() {
				return nil
			}
			return &needleNode{kind: needleEmpty}
		}
		if p.src[p.pos] != '<' {
			p.failed = true
			return nil
		}
		p.pos++
		if !p.skipUntil('>') {
			return nil
		}
		inner := p.parseAlternation()
		if !p.closeGroup() {
			return nil
		}
		return inner
	case '#':
		p.pos++
		for p.pos < len(p.src) {
			if p.src[p.pos] == '\\' {
				p.pos += 2
				continue
			}
			if p.src[p.pos] == ')' {
				p.pos++
				return &needleNode{kind: needleEmpty}
			}
			p.pos++
		}
		p.failed = true
		return nil
	case '>':
		p.pos++
		inner := p.parseAlternation()
		if !p.closeGroup() {
			return nil
		}
		return inner
	case '(':
		p.pos = start
		if !p.skipGroup() {
			return nil
		}
		return &needleNode{kind: needleEmpty}
	}
	if isFlagByte(p.src[p.pos]) {
		flagsStart := p.pos
		for p.pos < len(p.src) && isFlagByte(p.src[p.pos]) {
			p.pos++
		}
		flags := p.src[flagsStart:p.pos]
		if strings.ContainsRune(flags, 'x') {
			p.failed = true
			return nil
		}
		if strings.ContainsRune(flags, 'i') {
			p.fold = true
		}
		if p.pos >= len(p.src) {
			p.failed = true
			return nil
		}
		if p.src[p.pos] == ')' {
			p.pos++
			return &needleNode{kind: needleEmpty}
		}
		if p.src[p.pos] != ':' {
			p.failed = true
			return nil
		}
		p.pos++
		inner := p.parseAlternation()
		if !p.closeGroup() {
			return nil
		}
		return inner
	}
	p.pos = start
	if !p.skipGroup() {
		return nil
	}
	return &needleNode{kind: needleEmpty}
}

// closeGroup consumes a closing parenthesis. | closeGroup 消耗一个右括号。
func (p *needleParser) closeGroup() bool {
	if p.pos >= len(p.src) || p.src[p.pos] != ')' {
		p.failed = true
		return false
	}
	p.pos++
	return true
}

// skipUntil advances past the next unescaped delimiter. | skipUntil 前进到下一个未转义分隔符之后。
func (p *needleParser) skipUntil(delimiter byte) bool {
	for p.pos < len(p.src) {
		if p.src[p.pos] == '\\' {
			p.pos += 2
			continue
		}
		if p.src[p.pos] == delimiter {
			p.pos++
			return true
		}
		p.pos++
	}
	p.failed = true
	return false
}

// skipGroup skips one balanced parenthesized construct. | skipGroup 跳过一个平衡的括号构造。
func (p *needleParser) skipGroup() bool {
	if p.pos >= len(p.src) || p.src[p.pos] != '(' {
		p.failed = true
		return false
	}
	depth := 0
	for p.pos < len(p.src) {
		switch p.src[p.pos] {
		case '\\':
			p.pos += 2
			if p.pos > len(p.src) {
				p.failed = true
				return false
			}
		case '[':
			next, good := skipRegexClass(p.src, p.pos, len(p.src))
			if !good {
				p.failed = true
				return false
			}
			p.pos = next
		case '(':
			depth++
			p.pos++
		case ')':
			depth--
			p.pos++
			if depth == 0 {
				return true
			}
		default:
			p.pos++
		}
	}
	p.failed = true
	return false
}

// setByteBit adds one byte to a required byte set. | setByteBit 把一字节加入必需字节集。
func setByteBit(set *[4]uint64, b byte) {
	set[b>>6] |= 1 << (b & 63)
}

// unionByteSets returns the union of two byte sets. | unionByteSets 返回两个字节集的并集。
func unionByteSets(left, right [4]uint64) [4]uint64 {
	for i := range left {
		left[i] |= right[i]
	}
	return left
}

// foldByteSets adds the opposite ASCII case for every letter in the set. | foldByteSets 为集合中的
// 每个字母加入相反的 ASCII 大小写。
func foldByteSet(set [4]uint64) [4]uint64 {
	folded := set
	for b := byte('a'); b <= 'z'; b++ {
		if byteSetHas(set, b) || byteSetHas(set, b-'a'+'A') {
			setByteBit(&folded, b)
			setByteBit(&folded, b-'a'+'A')
		}
	}
	return folded
}

// byteSetHas reports whether b is in the set. | byteSetHas 报告 b 是否在集合中。
func byteSetHas(set [4]uint64, b byte) bool {
	return set[b>>6]&(1<<(b&63)) != 0
}

// byteSetCount returns the number of set bytes. | byteSetCount 返回集合中字节数量。
func byteSetCount(set [4]uint64) int {
	return bits.OnesCount64(set[0]) + bits.OnesCount64(set[1]) +
		bits.OnesCount64(set[2]) + bits.OnesCount64(set[3])
}

// addNeedleMin adds non-negative minimum lengths with saturation. | addNeedleMin 对非负最小长度做
// 饱和加法。
func addNeedleMin(left, right int) int {
	if left <= 0 {
		return right
	}
	if right <= 0 {
		return left
	}
	if left > maxNeedleMin-right {
		return maxNeedleMin
	}
	return left + right
}

// mulNeedleMin multiplies non-negative minimum lengths with saturation. | mulNeedleMin 对非负最小
// 长度做饱和乘法。
func mulNeedleMin(left, right int) int {
	if left == 0 || right == 0 {
		return 0
	}
	if left > maxNeedleMin/right {
		return maxNeedleMin
	}
	return left * right
}

// literalNeedleMin returns the minimum bytes a literal can consume. Under ASCII folding a match may
// use a different rune per byte, so rune count is the safe lower bound. | literalNeedleMin 返回字面量
// 至少消耗的字节数。ASCII 折叠下每个字节可能由不同符文匹配，因此以符文数为安全下界。
func literalNeedleMin(literal []byte, fold bool) int {
	if len(literal) == 0 {
		return 0
	}
	if fold {
		return utf8.RuneCount(literal)
	}
	return len(literal)
}

// escapeNeedleMin returns the minimum bytes one non-literal escape consumes. | escapeNeedleMin 返回
// 一个非字面量转义至少消耗的字节数。
func escapeNeedleMin(escaped byte) int {
	switch escaped {
	case 'b', 'B', 'A', 'z', 'Z', 'G', 'k', '1', '2', '3', '4', '5', '6', '7', '8', '9':
		return 0
	default:
		return 1
	}
}

// requiredSet computes the requirement of one AST node. | requiredSet 计算一个 AST 节点的需求。
func requiredSet(node *needleNode) needleSet {
	if node == nil {
		return needleSet{}
	}
	switch node.kind {
	case needleLiteral:
		if node.lit == "" {
			return needleSet{}
		}
		return needleSet{values: []string{node.lit}, ok: true}
	case needleConcat:
		var best needleSet
		for _, child := range node.sub {
			set := requiredSet(child)
			if set.ok && (!best.ok || betterNeedleSet(set, best)) {
				best = set
			}
		}
		return best
	case needleAlternation:
		var values []string
		for _, child := range node.sub {
			set := requiredSet(child)
			if !set.ok {
				return needleSet{}
			}
			values = append(values, set.values...)
		}
		values = dedupeNeedles(values)
		if len(values) == 0 {
			return needleSet{}
		}
		return needleSet{values: values, ok: true}
	default:
		return needleSet{}
	}
}

// betterNeedleSet prefers sets with longer minimum literals, then fewer alternatives.
// | betterNeedleSet 优先选择最短字面量更长的集合，其次选择分支更少的集合。
func betterNeedleSet(left, right needleSet) bool {
	leftMin, rightMin := minNeedleLength(left.values), minNeedleLength(right.values)
	if leftMin != rightMin {
		return leftMin > rightMin
	}
	return len(left.values) < len(right.values)
}

// minNeedleLength returns the shortest literal length in a set. | minNeedleLength 返回集合中最短字面量长度。
func minNeedleLength(values []string) int {
	minimum := 0
	for _, value := range values {
		if minimum == 0 || len(value) < minimum {
			minimum = len(value)
		}
	}
	return minimum
}

// dedupeNeedles removes duplicate literals while preserving order. | dedupeNeedles 去重并保持顺序。
func dedupeNeedles(values []string) []string {
	if len(values) < 2 {
		return values
	}
	seen := make(map[string]struct{}, len(values))
	out := values[:0]
	for _, value := range values {
		if _, ok := seen[value]; ok {
			continue
		}
		seen[value] = struct{}{}
		out = append(out, value)
	}
	return out
}

// needleFilter checks whether a value contains at least one required literal. Long literals are
// represented by a Bloom filter over their four-byte grams; a negative answer is exact and a
// positive answer may be a false positive. | needleFilter 检查取值是否包含至少一个必需字面量。
// 长字面量用其四字节 gram 的布隆过滤器表示；否定答案是精确的，肯定答案可能是误报。
type needleFilter struct {
	short []string
	bits  []uint64
	mask  uint64
	fold  bool
}

// newNeedleFilter builds a filter for the required-literal set. It returns nil when the set is
// empty or too fragmented to be worth checking. | newNeedleFilter 为必需字面量集合构建过滤器。集合为
// 空或过于零碎、不值得检查时返回 nil。
func newNeedleFilter(needles []string, fold bool) *needleFilter {
	unique := dedupeNeedles(append([]string(nil), needles...))
	if len(unique) == 0 {
		return nil
	}
	if fold {
		for _, needle := range unique {
			if !asciiString(needle) {
				return nil
			}
		}
	}
	for _, needle := range unique {
		// A single alphanumeric alternative occurs in almost every request value, so the filter
		// would pass everything and only add hashing cost. | 单个字母数字分支几乎出现在所有请求取值
		// 中，过滤器会全部放行并只增加哈希成本。
		if len(needle) == 1 && isASCIIAlphaNumeric(needle[0]) {
			return nil
		}
	}
	filter := &needleFilter{fold: fold}
	grams := 0
	for _, needle := range unique {
		if len(needle) < requiredNeedleGram {
			filter.short = append(filter.short, needle)
			if len(filter.short) > maxRequiredShort {
				return nil
			}
			continue
		}
		grams += len(needle) - requiredNeedleGram + 1
	}
	if grams > 0 {
		size := minNeedleBloomBits
		for size < grams*16 && size < maxNeedleBloomBits {
			size <<= 1
		}
		filter.bits = make([]uint64, size/64)
		filter.mask = uint64(size - 1)
		for _, needle := range unique {
			if len(needle) < requiredNeedleGram {
				continue
			}
			for index := 0; index+requiredNeedleGram <= len(needle); index++ {
				hash := needleGramHash(needle[index:index+requiredNeedleGram], fold)
				setBloomBit(filter.bits, filter.mask, hash)
				setBloomBit(filter.bits, filter.mask, mixNeedleHash(hash))
			}
		}
	}
	if len(filter.short) == 0 && len(filter.bits) == 0 {
		return nil
	}
	return filter
}

// match reports whether value may contain a required literal. | match 报告 value 是否可能包含必需字面量。
func (f *needleFilter) match(value string) bool {
	if f == nil {
		return true
	}
	if f.fold {
		for index := 0; index < len(value); index++ {
			if value[index] >= 0x80 {
				// Unicode case folding can match an ASCII literal through a non-ASCII rune. |
				// Unicode 大小写折叠可能通过非 ASCII 符文匹配 ASCII 字面量。
				return true
			}
		}
	}
	for _, needle := range f.short {
		if containsNeedle(value, needle, f.fold) {
			return true
		}
	}
	if len(f.bits) == 0 || len(value) < requiredNeedleGram {
		return false
	}
	for index := 0; index+requiredNeedleGram <= len(value); index++ {
		hash := needleGramHash(value[index:index+requiredNeedleGram], f.fold)
		if !bloomBit(f.bits, f.mask, hash) {
			continue
		}
		if bloomBit(f.bits, f.mask, mixNeedleHash(hash)) {
			return true
		}
	}
	return false
}

// needleGramHash hashes one four-byte gram. | needleGramHash 计算一个四字节 gram 的哈希。
func needleGramHash(gram string, fold bool) uint32 {
	var hash uint32 = 2166136261
	for index := 0; index < requiredNeedleGram; index++ {
		b := gram[index]
		if fold {
			b = lowerASCII(b)
		}
		hash ^= uint32(b)
		hash *= 16777619
	}
	return hash
}

// mixNeedleHash derives a second independent bit position from the first hash. | mixNeedleHash 从第一个
// 哈希派生第二个独立的位位置。
func mixNeedleHash(hash uint32) uint32 {
	return hash ^ (hash>>16)*0x7feb352d
}

// setBloomBit sets one bit in the Bloom filter. | setBloomBit 设置布隆过滤器的一位。
func setBloomBit(bits []uint64, mask uint64, hash uint32) {
	index := uint64(hash) & mask
	bits[index>>6] |= 1 << (index & 63)
}

// bloomBit reports whether one bit is set. | bloomBit 报告某一位是否已设置。
func bloomBit(bits []uint64, mask uint64, hash uint32) bool {
	index := uint64(hash) & mask
	return bits[index>>6]&(1<<(index&63)) != 0
}

// isRegexMetaByte reports whether c ends a literal run. | isRegexMetaByte 报告 c 是否结束字面量连续段。
func isRegexMetaByte(c byte) bool {
	switch c {
	case '\\', '.', '^', '$', '*', '+', '?', '(', ')', '[', ']', '{', '}', '|':
		return true
	default:
		return false
	}
}

// isFlagByte reports whether c can appear in an inline flag group. | isFlagByte 报告 c 是否可出现在
// 内联标志组中。
func isFlagByte(c byte) bool {
	return isASCIIAlpha(c) || c == '-'
}

// usefulNeedle reports whether a single literal is selective enough to check alone. | usefulNeedle
// 报告单个字面量是否足够有选择性、值得单独检查。
func usefulNeedle(needle string) bool {
	if needle == "" {
		return false
	}
	if len(needle) > 1 {
		return true
	}
	return !isASCIIAlphaNumeric(needle[0]) && !isSpaceByte(needle[0])
}

// asciiString reports whether every byte is ASCII. | asciiString 报告是否所有字节都是 ASCII。
func asciiString(value string) bool {
	for index := 0; index < len(value); index++ {
		if value[index] >= 0x80 {
			return false
		}
	}
	return true
}

// parseClassByteSet parses a simple ASCII character class and returns a superset of the bytes it
// can consume. Negated, POSIX, Unicode-property and general escape classes are rejected because a
// byte-level superset is not useful or not easy to prove. | parseClassByteSet 解析简单 ASCII 字符类，
// 返回其可能消耗字节的超集。否定、POSIX、Unicode 属性与通用转义类会被拒绝，因为字节级超集要么无用，
// 要么难以证明。
func parseClassByteSet(pattern string, index, end int) (next int, set [4]uint64, has, ok bool) {
	next, ok = skipRegexClass(pattern, index, end)
	if !ok {
		return 0, set, false, false
	}
	content := pattern[index+1 : next-1]
	if len(content) == 0 || content[0] == '^' {
		return next, set, false, true
	}
	for i := 0; i < len(content); {
		first, afterFirst, good := parseClassByte(content, i)
		if !good {
			return next, set, false, true
		}
		if afterFirst < len(content) && content[afterFirst] == '-' && afterFirst+1 < len(content) {
			second, afterSecond, rangeOK := parseClassByte(content, afterFirst+1)
			if !rangeOK || first > second {
				return next, set, false, true
			}
			for b := first; ; b++ {
				setByteBit(&set, b)
				if b == second {
					break
				}
			}
			i = afterSecond
			has = true
			continue
		}
		setByteBit(&set, first)
		has = true
		i = afterFirst
	}
	return next, set, has, true
}

// parseClassByte parses one byte-valued class item. | parseClassByte 解析一个单字节字符类项。
func parseClassByte(content string, index int) (value byte, next int, ok bool) {
	if index >= len(content) {
		return 0, index, false
	}
	c := content[index]
	if c != '\\' {
		if c == '[' && index+1 < len(content) &&
			(content[index+1] == ':' || content[index+1] == '.' || content[index+1] == '=') {
			return 0, index, false
		}
		if c >= 0x80 {
			return 0, index, false
		}
		return c, index + 1, true
	}
	if index+1 >= len(content) {
		return 0, index, false
	}
	escaped := content[index+1]
	switch escaped {
	case 'n':
		return '\n', index + 2, true
	case 'r':
		return '\r', index + 2, true
	case 't':
		return '\t', index + 2, true
	case 'f':
		return '\f', index + 2, true
	case 'v':
		return '\v', index + 2, true
	case 'a':
		return '\a', index + 2, true
	case 'e':
		return 0x1b, index + 2, true
	case 'x':
		if index+2 >= len(content) {
			return 0, index, false
		}
		if content[index+2] == '{' {
			close := strings.IndexByte(content[index+3:], '}')
			if close < 0 {
				return 0, index, false
			}
			value, valid := parseHex(content[index+3 : index+3+close])
			if !valid || value > 0xFF {
				return 0, index, false
			}
			return byte(value), index + 3 + close + 1, true
		}
		if index+3 >= len(content) {
			return 0, index, false
		}
		value, valid := parseHex(content[index+2 : index+4])
		if !valid {
			return 0, index, false
		}
		return byte(value), index + 4, true
	default:
		if isSimpleEscapedLiteral(escaped) {
			return escaped, index + 2, true
		}
		return 0, index, false
	}
}

// containsByteSet reports whether value contains any byte from the required set. When folding is
// enabled, non-ASCII input is never rejected because Unicode simple folding may match an ASCII
// byte through a multi-byte rune. | containsByteSet 报告 value 是否包含必需集合中的任一字节。启用
// 折叠时绝不拒绝非 ASCII 输入，因为 Unicode 简单折叠可能通过多字节符文匹配 ASCII 字节。
func containsByteSet(value string, set [4]uint64, fold bool) bool {
	if fold {
		for index := 0; index < len(value); index++ {
			if value[index] >= 0x80 {
				return true
			}
		}
	}
	for index := 0; index < len(value); index++ {
		if byteSetHas(set, value[index]) {
			return true
		}
	}
	return false
}
