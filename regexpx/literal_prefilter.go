package regexpx

import "strings"

// literalRequirement is a sound necessary condition: every match contains at least one of the
// literals. | literalRequirement 是命中的可靠必要条件：每个匹配至少包含其中一个字面量。
type literalRequirement struct {
	values []string
	fold   bool
	ok     bool
}

// analyzeRequiredLiterals extracts a conservative required-literal set from the AST. |
// analyzeRequiredLiterals 从 AST 提取保守的必需字面量集合。
func analyzeRequiredLiterals(n node) literalRequirement {
	switch n := n.(type) {
	case nil, *nEmpty, *nClass, *nAny, *nAssert, *nLook, *nBackref:
		return literalRequirement{}
	case *nLiteral:
		return literalFromRunes([]rune{n.r}, n.fold)
	case *nString:
		return literalFromRunes(n.runes, n.fold)
	case *nAmbig:
		return literalFromRunes([]rune{n.value}, n.fold)
	case *nCapture:
		return analyzeRequiredLiterals(n.sub)
	case *nAtomic:
		return analyzeRequiredLiterals(n.sub)
	case *nRepeat:
		if n.min <= 0 {
			return literalRequirement{}
		}
		return analyzeRequiredLiterals(n.sub)
	case *nAlt:
		return literalAlternation(n.sub)
	case *nConcat:
		return literalConcatenation(n.sub)
	default:
		return literalRequirement{}
	}
}

// literalFromRunes builds a requirement from a literal run. Folded non-ASCII literals are rejected
// because the gram matcher only performs ASCII folding. | literalFromRunes 从字面量序列构建需求。
// 折叠的非 ASCII 字面量会被拒绝，因为 gram 匹配器只做 ASCII 折叠。
func literalFromRunes(runes []rune, fold bool) literalRequirement {
	if len(runes) == 0 {
		return literalRequirement{}
	}
	if fold {
		for _, r := range runes {
			if r >= 0x80 {
				return literalRequirement{}
			}
		}
	}
	return literalRequirement{values: []string{string(runes)}, fold: fold, ok: true}
}

// literalAlternation unions branch requirements when every branch has one. | literalAlternation 在
// 每个分支都有需求时取并集。
func literalAlternation(subs []node) literalRequirement {
	if len(subs) == 0 {
		return literalRequirement{}
	}
	result := literalRequirement{ok: true}
	for _, sub := range subs {
		branch := analyzeRequiredLiterals(sub)
		if !branch.ok {
			return literalRequirement{}
		}
		result.values = append(result.values, branch.values...)
		result.fold = result.fold || branch.fold
	}
	result.values = dedupeLiteralValues(result.values)
	if len(result.values) == 0 || len(result.values) > maxRequiredLiterals {
		return literalRequirement{}
	}
	if result.fold {
		for _, value := range result.values {
			if !asciiString(value) {
				return literalRequirement{}
			}
		}
	}
	return result
}

// literalConcatenation chooses the strongest mandatory child requirement. | literalConcatenation
// 选择最强的必需子需求。
func literalConcatenation(subs []node) literalRequirement {
	var best literalRequirement
	for _, sub := range subs {
		child := analyzeRequiredLiterals(sub)
		if child.ok && (!best.ok || betterLiteralRequirement(child, best)) {
			best = child
		}
	}
	return best
}

// betterLiteralRequirement prefers longer minimum literals, then fewer alternatives. |
// betterLiteralRequirement 优先更长的最短字面量，其次选择更少的分支。
func betterLiteralRequirement(left, right literalRequirement) bool {
	leftMin, rightMin := minLiteralLength(left.values), minLiteralLength(right.values)
	if leftMin != rightMin {
		return leftMin > rightMin
	}
	return len(left.values) < len(right.values)
}

// minLiteralLength returns the shortest literal length. | minLiteralLength 返回最短字面量长度。
func minLiteralLength(values []string) int {
	minimum := 0
	for _, value := range values {
		if minimum == 0 || len(value) < minimum {
			minimum = len(value)
		}
	}
	return minimum
}

// dedupeLiteralValues removes duplicate literals. | dedupeLiteralValues 去重字面量。
func dedupeLiteralValues(values []string) []string {
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

// Required-literal filter limits. | 必需字面量过滤上限。
const (
	maxRequiredLiterals = 4096
	maxLiteralGramBits  = 1 << 18
	minLiteralGramBits  = 1 << 10
)

// requiredLiteralFilter checks whether a value may contain one of the required literals. Single
// literals use Contains; sets use Bloom filters over 1-4 byte grams, so a negative answer is exact
// and a positive answer may be a false positive. | requiredLiteralFilter 检查取值是否可能包含必需
// 字面量之一。单值使用 Contains；集合使用 1-4 字节 gram 布隆过滤器，因此否定答案精确，肯定答案
// 可能误报。
type requiredLiteralFilter struct {
	single string
	one    byteSet
	two    gramBloom
	three  gramBloom
	four   gramBloom
	fold   bool
	ok     bool
}

// gramBloom is a Bloom filter over fixed-width byte grams. | gramBloom 是固定宽度字节 gram 的布隆
// 过滤器。
type gramBloom struct {
	bits []uint64
	mask uint64
}

// buildRequiredLiteralFilter builds a filter, rejecting weak or excessively broad sets. |
// buildRequiredLiteralFilter 构建过滤器，拒绝过弱或过宽的字面量集合。
func buildRequiredLiteralFilter(req literalRequirement) requiredLiteralFilter {
	var filter requiredLiteralFilter
	if !req.ok || len(req.values) == 0 || len(req.values) > maxRequiredLiterals {
		return filter
	}
	if req.fold {
		for _, value := range req.values {
			if !asciiString(value) {
				return filter
			}
		}
	}
	for _, value := range req.values {
		if len(value) == 0 || len(value) == 1 && isASCIIAlphaNumeric(value[0]) {
			return requiredLiteralFilter{}
		}
	}
	if len(req.values) == 1 {
		filter.single = req.values[0]
		filter.fold = req.fold
		filter.ok = true
		return filter
	}
	counts := [5]int{}
	for _, value := range req.values {
		length := len(value)
		if length > 4 {
			length = 4
		}
		counts[length] += len(value) - length + 1
	}
	filter.one = byteSet{}
	filter.two = newGramBloom(counts[2])
	filter.three = newGramBloom(counts[3])
	filter.four = newGramBloom(counts[4])
	for _, value := range req.values {
		if len(value) == 1 {
			addLiteralByte(&filter.one, value[0])
			continue
		}
		if len(value) >= 2 {
			filter.two.addString(value, 2, req.fold)
		}
		if len(value) >= 3 {
			filter.three.addString(value, 3, req.fold)
		}
		if len(value) >= 4 {
			filter.four.addString(value, 4, req.fold)
		}
	}
	filter.fold = req.fold
	filter.ok = len(filter.two.bits) > 0 || len(filter.three.bits) > 0 ||
		len(filter.four.bits) > 0 || filter.one != (byteSet{})
	return filter
}

// matches reports whether value may contain a required literal. | matches 报告 value 是否可能包含
// 必需字面量。
func (f requiredLiteralFilter) matches(value string) bool {
	if !f.ok {
		return true
	}
	if f.single != "" {
		return containsLiteral(value, f.single, f.fold)
	}
	if f.fold {
		for i := 0; i < len(value); i++ {
			if value[i] >= 0x80 {
				return true
			}
		}
	}
	if f.one != (byteSet{}) {
		for i := 0; i < len(value); i++ {
			b := value[i]
			if b < 0x80 && f.one[0]&(uint64(1)<<uint(b&63)) != 0 {
				return true
			}
		}
	}
	return f.two.mayMatch(value, 2, f.fold) || f.three.mayMatch(value, 3, f.fold) ||
		f.four.mayMatch(value, 4, f.fold)
}

// newGramBloom sizes a Bloom filter for the expected number of grams. | newGramBloom 根据预期 gram
// 数量选择布隆过滤器大小。
func newGramBloom(grams int) gramBloom {
	if grams <= 0 {
		return gramBloom{}
	}
	size := minLiteralGramBits
	for size < grams*16 && size < maxLiteralGramBits {
		size <<= 1
	}
	return gramBloom{bits: make([]uint64, size/64), mask: uint64(size - 1)}
}

// addString inserts every width-byte gram of value. | addString 插入 value 的每个 width 字节 gram。
func (b *gramBloom) addString(value string, width int, fold bool) {
	if len(b.bits) == 0 || len(value) < width {
		return
	}
	for i := 0; i+width <= len(value); i++ {
		hash := gramHash(value[i:i+width], fold)
		setGramBit(b, hash)
		setGramBit(b, mixGramHash(hash))
	}
}

// mayMatch reports whether any width-byte gram of value may be in the set. | mayMatch 报告 value 的
// 任一 width 字节 gram 是否可能在集合中。
func (b gramBloom) mayMatch(value string, width int, fold bool) bool {
	if len(b.bits) == 0 || len(value) < width {
		return false
	}
	for i := 0; i+width <= len(value); i++ {
		hash := gramHash(value[i:i+width], fold)
		if hasGramBit(b, hash) && hasGramBit(b, mixGramHash(hash)) {
			return true
		}
	}
	return false
}

// gramHash hashes a short gram. | gramHash 计算短 gram 的哈希。
func gramHash(gram string, fold bool) uint32 {
	var hash uint32 = 2166136261
	for i := 0; i < len(gram); i++ {
		b := gram[i]
		if fold {
			b = lowerASCIIByte(b)
		}
		hash ^= uint32(b)
		hash *= 16777619
	}
	return hash
}

// mixGramHash derives a second bit position. | mixGramHash 派生第二个位位置。
func mixGramHash(hash uint32) uint32 {
	return hash ^ (hash>>16)*0x7feb352d
}

// setGramBit sets one Bloom bit. | setGramBit 设置一个布隆位。
func setGramBit(b *gramBloom, hash uint32) {
	index := uint64(hash) & b.mask
	b.bits[index>>6] |= 1 << (index & 63)
}

// hasGramBit reports whether one Bloom bit is set. | hasGramBit 报告一个布隆位是否设置。
func hasGramBit(b gramBloom, hash uint32) bool {
	index := uint64(hash) & b.mask
	return b.bits[index>>6]&(1<<(index&63)) != 0
}

// containsLiteral reports whether value contains literal, optionally under ASCII folding. |
// containsLiteral 报告 value 是否包含 literal，可选 ASCII 折叠。
func containsLiteral(value, literal string, fold bool) bool {
	if !fold {
		return strings.Contains(value, literal)
	}
	if len(literal) == 0 {
		return true
	}
	if len(literal) == 1 {
		want := lowerASCIIByte(literal[0])
		for i := 0; i < len(value); i++ {
			if value[i] >= 0x80 {
				return true
			}
			if lowerASCIIByte(value[i]) == want {
				return true
			}
		}
		return false
	}
	if len(value) < len(literal) {
		return false
	}
	for i := 0; i+len(literal) <= len(value); i++ {
		matched := true
		for j := 0; j < len(literal); j++ {
			b := value[i+j]
			if b >= 0x80 || lowerASCIIByte(b) != lowerASCIIByte(literal[j]) {
				matched = false
				break
			}
		}
		if matched {
			return true
		}
	}
	// Non-ASCII input may match through Unicode folding; never reject it. | 非 ASCII 输入可能通过
	// Unicode 折叠匹配，绝不拒绝。
	for i := 0; i < len(value); i++ {
		if value[i] >= 0x80 {
			return true
		}
	}
	return false
}

// addLiteralByte adds one ASCII byte to a set. | addLiteralByte 把一个 ASCII 字节加入集合。
func addLiteralByte(set *byteSet, b byte) {
	set[0] |= uint64(1) << uint(b&63)
}

// lowerASCIIByte lowercases one ASCII letter. | lowerASCIIByte 把一个 ASCII 字母转为小写。
func lowerASCIIByte(b byte) byte {
	if b >= 'A' && b <= 'Z' {
		return b + 'a' - 'A'
	}
	return b
}

// isASCIIAlphaNumeric reports whether b is an ASCII letter or digit. | isASCIIAlphaNumeric 报告 b
// 是否为 ASCII 字母或数字。
func isASCIIAlphaNumeric(b byte) bool {
	return isASCIILetter(b) || b >= '0' && b <= '9'
}

// asciiString reports whether every byte is ASCII. | asciiString 报告是否所有字节都是 ASCII。
func asciiString(value string) bool {
	for i := 0; i < len(value); i++ {
		if value[i] >= 0x80 {
			return false
		}
	}
	return true
}
