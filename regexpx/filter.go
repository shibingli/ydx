package regexpx

import "unicode/utf8"

// indexByteFn and indexByteSetFn are the prefilter kernels. Architecture-specific files replace
// them with SIMD implementations during init when the CPU supports the instructions. The block size
// tells the wrappers where the scalar tail begins. | indexByteFn 与 indexByteSetFn 是预过滤内核。
// 架构相关文件在 CPU 支持相应指令时于 init 中把它们替换为 SIMD 实现。块大小告诉包装函数标量尾部的
// 起点。
var (
	indexByteFn        = indexByteScalar
	indexByteBlock     = 1
	indexByteSetFn     = indexByteSetScalar
	indexByteSetBlock  = 1
	indexFoldPairFn    = indexFoldPairScalar
	indexFoldPairBlock = 1
)

// The scalar prefixes checked before a SIMD kernel absorb short scans, where setting up a vector
// block costs more than checking bytes directly. Candidate sets restart often and benefit from the
// longer set prefix, while a single-byte literal search is already cheap and keeps a short prefix.
// | 调用 SIMD 内核前检查的标量前缀用于吸收短扫描，此时建立向量块比直接检查字节更贵。候选集合频繁
// 重新开始，适合较长的集合前缀；单字节字面量搜索本身便宜，保持较短前缀。
const (
	simdBytePrefixLen = 8
	simdSetPrefixLen  = 32
	simdFoldPrefixLen = 32
)

// indexByte returns the first occurrence of c at or after from, or -1. | indexByte 返回 c 在 from 及其后
// 的首次出现，不存在时返回 -1。
func indexByte(s string, c byte, from int) int {
	if from < 0 {
		from = 0
	}
	if from >= len(s) {
		return -1
	}
	if indexByteBlock <= 1 {
		return indexByteScalar(s, c, from)
	}
	if end := from + simdBytePrefixLen; end < len(s) {
		for i := from; i < end; i++ {
			if s[i] == c {
				return i
			}
		}
		from = end
	} else {
		for i := from; i < len(s); i++ {
			if s[i] == c {
				return i
			}
		}
		return -1
	}
	full := from + (len(s)-from)/indexByteBlock*indexByteBlock
	if idx := indexByteFn(s, c, from); idx >= 0 {
		end := idx + indexByteBlock
		if end > full {
			end = full
		}
		for i := idx; i < end; i++ {
			if s[i] == c {
				return i
			}
		}
	}
	for i := full; i < len(s); i++ {
		if s[i] == c {
			return i
		}
	}
	return -1
}

// indexByteScalar is the portable byte scan. | indexByteScalar 是可移植的字节扫描。
func indexByteScalar(s string, c byte, from int) int {
	for i := from; i < len(s); i++ {
		if s[i] == c {
			return i
		}
	}
	return -1
}

// indexByteSet returns the first offset at or after from whose byte belongs to an ASCII table set,
// or -1. The tables encode only bytes below 0x80; callers use indexByteSetBitmap for wider sets. |
// indexByteSet 返回 from 及其后第一个属于 ASCII 表集合的字节偏移，不存在时返回 -1。表只编码小于 0x80
// 的字节；更宽的集合由调用方使用 indexByteSetBitmap。
func indexByteSet(s string, tables *[128]byte, from int) int {
	if from < 0 {
		from = 0
	}
	if from >= len(s) {
		return -1
	}
	if indexByteSetBlock <= 1 {
		return indexByteSetScalar(s, tables, from)
	}
	if end := from + simdSetPrefixLen; end < len(s) {
		for i := from; i < end; i++ {
			if tableSetHas(tables, s[i]) {
				return i
			}
		}
		from = end
	} else {
		return indexByteSetScalar(s, tables, from)
	}
	full := from + (len(s)-from)/indexByteSetBlock*indexByteSetBlock
	if idx := indexByteSetFn(s, tables, from); idx >= 0 {
		end := idx + indexByteSetBlock
		if end > full {
			end = full
		}
		for i := idx; i < end; i++ {
			if tableSetHas(tables, s[i]) {
				return i
			}
		}
	}
	for i := full; i < len(s); i++ {
		if tableSetHas(tables, s[i]) {
			return i
		}
	}
	return -1
}

// indexByteSetScalar is the portable set scan using the nibble tables. | indexByteSetScalar 是使用半字节
// 表的可移植集合扫描。
func indexByteSetScalar(s string, tables *[128]byte, from int) int {
	for i := from; i < len(s); i++ {
		if tableSetHas(tables, s[i]) {
			return i
		}
	}
	return -1
}

// indexByteSetBitmap scans a full 256-bit set without SIMD. | indexByteSetBitmap 在不使用 SIMD 的情况下
// 扫描完整的 256 位集合。
func indexByteSetBitmap(s string, set *byteSet, from int) int {
	for i := from; i < len(s); i++ {
		if set.has(s[i]) {
			return i
		}
	}
	return -1
}

// firstCandidate returns the next byte offset whose value can start a match. ASCII-only sets use the
// SIMD kernel; wider sets use the bitmap scan because the nibble tables encode only ASCII. |
// firstCandidate 返回下一个可能作为匹配起点的字节偏移。仅含 ASCII 的集合使用 SIMD 内核；更宽的集合
// 使用位图扫描，因为半字节表只编码 ASCII。
func (r *Regexp) firstCandidate(s string, from int) int {
	if r.firstASCIISet {
		return indexByteSet(s, &r.firstTables, from)
	}
	return indexByteSetBitmap(s, &r.prog.info.firstBytes, from)
}

// tableSetHas reports membership from the nibble tables. | tableSetHas 从半字节表报告成员关系。
func tableSetHas(tables *[128]byte, b byte) bool {
	return tables[b&0x0F]&tables[64+(b>>4)] != 0
}

// makeByteSetTables builds the nibble tables used by the SIMD set scan. The low table is stored four
// times at offset 0 and the high-nibble bit table four times at offset 64, so AVX2 loads 32 bytes and
// AVX-512 loads 64 bytes directly. The bit table maps high nibble h to 1<<h for h below 8 and to zero
// above, which makes the scan exact for ASCII-only sets and prevents non-ASCII input bytes from
// producing candidates. | makeByteSetTables 构建 SIMD 集合扫描使用的半字节表。低表在偏移 0 处存放
// 四份，高半字节位表在偏移 64 处存放四份，使 AVX2 直接加载 32 字节、AVX-512 直接加载 64 字节。位表
// 把高半字节 h 映射为 1<<h（h 小于 8），大于等于 8 时映射为 0，使扫描对仅含 ASCII 的集合精确，并避免
// 非 ASCII 输入字节产生候选。
func makeByteSetTables(set byteSet) (tables [128]byte, asciiOnly bool) {
	asciiOnly = set[2] == 0 && set[3] == 0
	for lo := 0; lo < 16; lo++ {
		var mask byte
		for hi := 0; hi < 8; hi++ {
			if set.has(byte(hi<<4 | lo)) {
				mask |= 1 << hi
			}
		}
		for copyIndex := 0; copyIndex < 4; copyIndex++ {
			tables[copyIndex*16+lo] = mask
		}
	}
	for hi := 0; hi < 16; hi++ {
		var bit byte
		if hi < 8 {
			bit = 1 << hi
		}
		for copyIndex := 0; copyIndex < 4; copyIndex++ {
			tables[64+copyIndex*16+hi] = bit
		}
	}
	return tables, asciiOnly
}

// indexLiteral returns the first occurrence of lit at or after from, or -1. It searches for the
// first byte with the SIMD kernel and verifies the full literal. | indexLiteral 返回 lit 在 from 及其后
// 的首次出现，不存在时返回 -1。它用 SIMD 内核搜索首字节并校验整个字面量。
func indexLiteral(s, lit string, from int) int {
	if lit == "" || from < 0 || from >= len(s) {
		return -1
	}
	if len(lit) == 1 {
		return indexByte(s, lit[0], from)
	}
	for from < len(s) {
		idx := indexByte(s, lit[0], from)
		if idx < 0 || idx+len(lit) > len(s) {
			return -1
		}
		if s[idx:idx+len(lit)] == lit {
			return idx
		}
		from = idx + 1
	}
	return -1
}

// indexFoldPair returns the first position at or after from where two consecutive ASCII letters match
// c0 and c1 under case folding. c0 and c1 must already be lowercase letters. | indexFoldPair 返回 from
// 及其后第一处连续两个 ASCII 字母在大小写折叠下匹配 c0 与 c1 的位置。c0 与 c1 必须已是小写字母。
func indexFoldPair(s string, c0, c1 byte, from int) int {
	if from < 0 {
		from = 0
	}
	if from+1 >= len(s) {
		return -1
	}
	if indexFoldPairBlock <= 1 {
		return indexFoldPairScalar(s, c0, c1, from)
	}
	if limit := len(s) - 1; from+simdFoldPrefixLen < limit {
		end := from + simdFoldPrefixLen
		for i := from; i < end; i++ {
			if foldPairAt(s, i, c0, c1) {
				return i
			}
		}
		from = end
	} else {
		for i := from; i < limit; i++ {
			if foldPairAt(s, i, c0, c1) {
				return i
			}
		}
		return -1
	}
	full := from + (len(s)-1-from)/indexFoldPairBlock*indexFoldPairBlock
	if idx := indexFoldPairFn(s, c0, c1, from); idx >= 0 {
		end := idx + indexFoldPairBlock
		if end > len(s)-1 {
			end = len(s) - 1
		}
		for i := idx; i < end; i++ {
			if foldPairAt(s, i, c0, c1) {
				return i
			}
		}
	}
	for i := full; i+1 < len(s); i++ {
		if foldPairAt(s, i, c0, c1) {
			return i
		}
	}
	return -1
}

// indexFoldPairScalar is the portable fold-pair scan. | indexFoldPairScalar 是可移植的折叠字节对扫描。
func indexFoldPairScalar(s string, c0, c1 byte, from int) int {
	for i := from; i+1 < len(s); i++ {
		if foldPairAt(s, i, c0, c1) {
			return i
		}
	}
	return -1
}

// foldPairAt reports whether two consecutive bytes fold to c0 and c1. | foldPairAt 报告连续两个字节是否
// 折叠为 c0 与 c1。
func foldPairAt(s string, i int, c0, c1 byte) bool {
	return s[i]|0x20 == c0 && s[i+1]|0x20 == c1
}

// isASCIILetter reports whether b is an ASCII letter. | isASCIILetter 报告 b 是否为 ASCII 字母。
func isASCIILetter(b byte) bool {
	lower := b | 0x20
	return lower >= 'a' && lower <= 'z'
}

// nextPrefix returns the next candidate start of the pattern's literal prefix at or after from. |
// nextPrefix 返回 from 及其后模式字面量前缀的下一个候选起点。
func (r *Regexp) nextPrefix(s string, from int) int {
	if !r.prog.info.prefixOK || len(r.prog.info.prefix) == 0 || from > len(s) {
		return -1
	}
	if !r.prog.info.prefixFold {
		return indexLiteral(s, r.prefixBytes, from)
	}
	if r.prefixFoldASCII && len(r.prefixBytes) >= 2 && indexFoldPairBlock > 1 &&
		isASCIILetter(r.prefixBytes[0]) && isASCIILetter(r.prefixBytes[1]) {
		c0 := byte(asciiLower(rune(r.prefixBytes[0])))
		c1 := byte(asciiLower(rune(r.prefixBytes[1])))
		for {
			idx := indexFoldPair(s, c0, c1, from)
			if idx < 0 {
				return -1
			}
			if r.prefixAt(s, idx) {
				return idx
			}
			from = idx + 1
		}
	}
	// Folded literals can have non-ASCII fold partners, so candidates come from the sound lead-byte
	// set and every candidate is verified with Unicode folding. | 折叠字面量可能有非 ASCII 折叠伙伴，
	// 因此候选来自可靠的引导字节集合，并用 Unicode 折叠逐一校验。
	second := byte(0)
	checkSecond := r.prefixFoldASCII && len(r.prefixBytes) >= 2
	if checkSecond {
		second = byte(asciiLower(rune(r.prefixBytes[1])))
	}
	for {
		idx := r.firstCandidate(s, from)
		if idx < 0 {
			return -1
		}
		if checkSecond {
			// Reject most candidates on the second byte before the full comparison. | 在完整比较之前
			// 用第二个字节排除大多数候选。
			if idx+1 >= len(s) || s[idx+1] >= 0x80 || byte(asciiLower(rune(s[idx+1]))) != second {
				from = idx + 1
				continue
			}
		}
		if r.prefixAt(s, idx) {
			return idx
		}
		from = idx + 1
	}
}

// prefixAt reports whether the folded prefix matches at pos. For an ASCII prefix whose fold orbit
// contains no non-ASCII rune, it compares bytes directly, which is the common case. |
// prefixAt 报告折叠前缀是否在 pos 处匹配。对于折叠轨道不含非 ASCII 符文的 ASCII 前缀，它直接比较
// 字节，这是最常见的情况。
func (r *Regexp) prefixAt(s string, pos int) bool {
	if r.prefixFoldASCII {
		if pos+len(r.prefixBytes) > len(s) {
			return false
		}
		for i := 0; i < len(r.prefixBytes); i++ {
			b := s[pos+i]
			if b >= 0x80 || asciiLower(rune(b)) != asciiLower(rune(r.prefixBytes[i])) {
				return false
			}
		}
		return true
	}
	for _, want := range r.prog.info.prefix {
		if pos >= len(s) {
			return false
		}
		got, size := utf8.DecodeRuneInString(s[pos:])
		if !equalFoldRune(got, want) {
			return false
		}
		pos += size
	}
	return true
}
