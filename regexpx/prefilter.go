package regexpx

import "math/bits"

// requiredBytes is a sound necessary condition for a match: the matched input contains at least
// minCount bytes that are either in ascii or, when anyHigh is set, have the high bit set. It is
// derived from the AST and is only used to reject input early; a rejected value can never match.
// | requiredBytes 是命中的可靠必要条件：匹配输入至少包含 minCount 个字节，这些字节属于 ascii，或在
// anyHigh 时最高位置位。它从 AST 推导，仅用于提前拒绝输入；被拒绝的取值绝不可能命中。
type requiredBytes struct {
	ascii    byteSet
	minCount int
	anyHigh  bool
	ok       bool
}

// Required-byte count caps. | 必需字节计数上限。
const (
	maxRequiredByteCount = 64
	maxRequiredByteSet   = 128
)

// analyzeRequiredBytes computes a conservative required-byte condition from n. | analyzeRequiredBytes
// 从 n 计算保守的必需字节条件。
func analyzeRequiredBytes(n node) requiredBytes {
	switch n := n.(type) {
	case nil, *nEmpty, *nAssert, *nLook, *nBackref, *nAny:
		return requiredBytes{}
	case *nLiteral:
		return requiredLiteralBytes([]rune{n.r}, n.fold)
	case *nString:
		return requiredLiteralBytes(n.runes, n.fold)
	case *nAmbig:
		return requiredLiteralBytes([]rune{n.value}, n.fold)
	case *nClass:
		return requiredClassBytes(n.c)
	case *nCapture:
		return analyzeRequiredBytes(n.sub)
	case *nAtomic:
		return analyzeRequiredBytes(n.sub)
	case *nRepeat:
		child := analyzeRequiredBytes(n.sub)
		if n.min <= 0 || !child.ok {
			return requiredBytes{}
		}
		child.minCount = saturatingByteCount(child.minCount, n.min)
		return child
	case *nAlt:
		return requiredAlternationBytes(n.sub)
	case *nConcat:
		return requiredConcatBytes(n.sub)
	default:
		return requiredBytes{}
	}
}

// requiredLiteralBytes returns the byte condition of a literal run. | requiredLiteralBytes 返回字面量
// 序列的字节条件。
func requiredLiteralBytes(runes []rune, fold bool) requiredBytes {
	if len(runes) == 0 {
		return requiredBytes{}
	}
	req := requiredBytes{minCount: saturatingByteCount(1, len(runes)), ok: true}
	for _, r := range runes {
		if r < 128 {
			addASCIIByte(&req.ascii, byte(r))
			if fold && isASCIILetter(byte(r)) {
				addASCIIByte(&req.ascii, byte(r)^0x20)
				req.anyHigh = true
			}
			continue
		}
		req.anyHigh = true
	}
	if fold {
		req.anyHigh = true
	}
	return finalizeRequiredBytes(req)
}

// requiredClassBytes returns the byte condition of a positive character class. | requiredClassBytes
// 返回正向字符类的字节条件。
func requiredClassBytes(class *charClass) requiredBytes {
	if class == nil || class.neg {
		return requiredBytes{}
	}
	req := requiredBytes{minCount: 1, ok: true}
	table := &class.ascii
	if class.fold {
		table = &class.foldASCII
		req.anyHigh = true
	}
	req.ascii[0] = table[0]
	req.ascii[1] = table[1]
	if class.nonASCII || len(class.tables) > 0 {
		req.anyHigh = true
	}
	for _, r := range class.ranges {
		if r.hi >= 0x80 {
			req.anyHigh = true
			break
		}
	}
	return finalizeRequiredBytes(req)
}

// requiredAlternationBytes unions every branch condition when all branches have one. | requiredAlternationBytes
// 在每个分支都有条件时取并集。
func requiredAlternationBytes(subs []node) requiredBytes {
	if len(subs) == 0 {
		return requiredBytes{}
	}
	var result requiredBytes
	minimum := maxRequiredByteCount
	for _, sub := range subs {
		branch := analyzeRequiredBytes(sub)
		if !branch.ok {
			return requiredBytes{}
		}
		result.ascii = unionByteSet(result.ascii, branch.ascii)
		result.anyHigh = result.anyHigh || branch.anyHigh
		if branch.minCount < minimum {
			minimum = branch.minCount
		}
	}
	result.minCount = minimum
	result.ok = true
	return finalizeRequiredBytes(result)
}

// requiredConcatBytes chooses the stronger of the best child condition and the union/sum of all
// mandatory children. | requiredConcatBytes 在最强子条件与所有必需子条件的并集/计数和之间选择更强的一个。
func requiredConcatBytes(subs []node) requiredBytes {
	var best requiredBytes
	var union requiredBytes
	union.ok = true
	for _, sub := range subs {
		child := analyzeRequiredBytes(sub)
		if !child.ok {
			continue
		}
		if !best.ok || betterRequiredBytes(child, best) {
			best = child
		}
		union.ascii = unionByteSet(union.ascii, child.ascii)
		union.anyHigh = union.anyHigh || child.anyHigh
		union.minCount = addByteCounts(union.minCount, child.minCount)
	}
	if !union.ok {
		return best
	}
	union = finalizeRequiredBytes(union)
	if best.ok && betterRequiredBytes(best, union) {
		return best
	}
	return union
}

// betterRequiredBytes prefers more required bytes, then a smaller set. | betterRequiredBytes 优先要求
// 更多字节，其次选择更小的集合。
func betterRequiredBytes(left, right requiredBytes) bool {
	if left.minCount != right.minCount {
		return left.minCount > right.minCount
	}
	return requiredByteSetSize(left) < requiredByteSetSize(right)
}

// finalizeRequiredBytes rejects empty or excessively broad conditions. | finalizeRequiredBytes 拒绝空或
// 过宽的条件。
func finalizeRequiredBytes(req requiredBytes) requiredBytes {
	if req.minCount <= 0 {
		return requiredBytes{}
	}
	size := requiredByteSetSize(req)
	if size == 0 || size > maxRequiredByteSet {
		return requiredBytes{}
	}
	if req.minCount < 2 && size > 32 {
		// A single common byte from a broad set rejects almost nothing. | 宽集合中的单个常见字节几乎
		// 拒绝不了任何输入。
		return requiredBytes{}
	}
	if req.minCount > maxRequiredByteCount {
		req.minCount = maxRequiredByteCount
	}
	req.ok = true
	return req
}

// requiredByteSetSize returns the number of possible criterion bytes. | requiredByteSetSize 返回条件
// 可能的字节数。
func requiredByteSetSize(req requiredBytes) int {
	size := bits.OnesCount64(req.ascii[0]) + bits.OnesCount64(req.ascii[1])
	if req.anyHigh {
		size++
	}
	return size
}

// matches reports whether s satisfies the required-byte condition. | matches 报告 s 是否满足必需字节
// 条件。
func (r requiredBytes) matches(s string) bool {
	if !r.ok || r.minCount <= 0 {
		return true
	}
	count := 0
	for index := 0; index < len(s); index++ {
		b := s[index]
		if b >= 0x80 {
			if r.anyHigh {
				count++
			}
		} else if r.ascii[b>>6]&(uint64(1)<<uint(b&63)) != 0 {
			count++
		}
		if count >= r.minCount {
			return true
		}
	}
	return false
}

// addASCIIByte adds an ASCII byte to a set. | addASCIIByte 把 ASCII 字节加入集合。
func addASCIIByte(set *byteSet, b byte) {
	set[b>>6] |= uint64(1) << uint(b&63)
}

// unionByteSet returns the union of two sets. | unionByteSet 返回两个集合的并集。
func unionByteSet(left, right byteSet) byteSet {
	left[0] |= right[0]
	left[1] |= right[1]
	left[2] |= right[2]
	left[3] |= right[3]
	return left
}

// addByteCounts adds counts with saturation. | addByteCounts 饱和相加计数。
func addByteCounts(left, right int) int {
	if left >= maxRequiredByteCount-right {
		return maxRequiredByteCount
	}
	return left + right
}

// saturatingByteCount multiplies a count with saturation. | saturatingByteCount 饱和相乘计数。
func saturatingByteCount(count, factor int) int {
	if count <= 0 || factor <= 0 {
		return 0
	}
	if count > maxRequiredByteCount/factor {
		return maxRequiredByteCount
	}
	return count * factor
}
