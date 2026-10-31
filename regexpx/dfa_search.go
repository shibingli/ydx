package regexpx

import (
	"encoding/binary"
	"math/bits"
	"slices"
	"sync"
	"sync/atomic"
)

// Lazy ASCII search DFA limits. The DFA is only a fast path for boolean matching on ASCII input;
// non-ASCII input falls back to the Pike VM. | 惰性 ASCII 搜索 DFA 的上限。该 DFA 仅用于 ASCII 输入上的
// 布尔匹配快路径；非 ASCII 输入回退到 Pike VM。
const (
	dfaSearchInstrCap = 8192
	dfaSearchStateCap = 1024
	dfaSearchMinInstr = 128
)

// Lazy DFA transition sentinels. | 惰性 DFA 转移哨兵值。
const (
	dfaSearchDead    int32 = -1
	dfaSearchAccept  int32 = -2
	dfaSearchUnknown int32 = -3
)

// searchDFAClass groups ASCII bytes with the same consuming-instruction signature and word flag. |
// searchDFAClass 对具有相同消费指令签名与单词标志的 ASCII 字节分组。
type searchDFAClass struct {
	rep  byte
	word bool
}

// searchDFAState is one position state before consuming the next byte. seeds are the unresolved
// successors after the previous byte plus the per-position start injection. | searchDFAState 是消费下
// 一字节前的位置状态。seeds 是上一字节后的未解析后继与本位置注入的起点。
type searchDFAState struct {
	seeds     []uint32
	row       []int32
	acceptEnd bool
	atStart   bool
	prevWord  bool
}

// searchDFA is a lazily populated deterministic automaton for unanchored existence testing. Rows are
// filled on demand under mu; completed cells are read atomically, so steady-state searches do not
// contend. | searchDFA 是用于未锚定存在性测试的惰性确定自动机。转移行在 mu 下按需填充；已完成的单元
// 以原子方式读取，因此稳态搜索没有锁竞争。
//
// states has a fixed length and is only written under mu. Readers index states by ids that were
// published through atomic row cells, so the slice header never races with growth. | states 长度固定，
// 且只在 mu 下写入。读取方只使用通过原子转移单元发布的状态下标，因此切片头不会与增长竞争。
type searchDFA struct {
	prog *program

	classes     []searchDFAClass
	classOf     [128]uint8
	consume     []uint32
	classMasks  [][2]uint64
	classMaskOK []bool
	runeMasks   [128][2]uint64
	runeMaskOK  [128]bool
	otherRunes  map[uint32][2]uint64

	mu       sync.Mutex
	states   []atomic.Pointer[searchDFAState]
	count    int
	index    map[string]int32
	seen     []uint32
	gen      uint32
	stack    []uint32
	pcs      []uint32
	seeds    []uint32
	start    int32
	overflow bool
}

// searchDFAEligible reports whether prog is large and broad enough that the lazy DFA is worth its
// one-time construction cost. | searchDFAEligible 报告 prog 是否足够大且首字节足够宽，使惰性 DFA 值得
// 其一次性构建成本。
func searchDFAEligible(prog *program) bool {
	if prog == nil || len(prog.insts) < dfaSearchMinInstr || len(prog.insts) > dfaSearchInstrCap {
		return false
	}
	if prog.info.hasBacktrack || prog.info.prefixOK || prog.info.selectivePrefilter {
		return false
	}
	for i := range prog.insts {
		if !searchDFAInstructionSupported(&prog.insts[i]) {
			return false
		}
	}
	return true
}

// searchDFA returns the lazily built search DFA, or nil when this pattern is not eligible. |
// searchDFA 返回惰性构建的搜索 DFA；模式不符合条件时返回 nil。
func (r *Regexp) searchDFA() *searchDFA {
	if !r.searchDFAEligible || r.compat == nil {
		return nil
	}
	r.compat.searchOnce.Do(func() {
		r.compat.searchDFA = newSearchDFA(r.prog)
	})
	return r.compat.searchDFA
}

// newSearchDFA builds an empty lazy DFA for prog, or nil when prog uses constructs the ASCII path
// cannot evaluate. | newSearchDFA 为 prog 构建空的惰性 DFA；当 prog 使用 ASCII 路径无法求值的构造时
// 返回 nil。
func newSearchDFA(prog *program) *searchDFA {
	if prog == nil || len(prog.insts) == 0 || len(prog.insts) > dfaSearchInstrCap {
		return nil
	}
	consume := make([]uint32, 0, 64)
	for i := range prog.insts {
		if !searchDFAInstructionSupported(&prog.insts[i]) {
			return nil
		}
		switch prog.insts[i].op {
		case opRune, opClass, opAny:
			consume = append(consume, uint32(i))
		}
	}
	d := &searchDFA{
		prog:        prog,
		states:      make([]atomic.Pointer[searchDFAState], dfaSearchStateCap),
		index:       make(map[string]int32),
		seen:        make([]uint32, len(prog.insts)),
		stack:       make([]uint32, 0, 64),
		pcs:         make([]uint32, 0, 64),
		seeds:       make([]uint32, 0, 64),
		consume:     consume,
		classMasks:  make([][2]uint64, len(prog.classes)),
		classMaskOK: make([]bool, len(prog.classes)),
		classOf:     [128]uint8{},
	}
	d.buildAlphabet()
	d.mu.Lock()
	d.start = d.internLocked([]uint32{prog.start}, true, false)
	overflow := d.overflow
	d.mu.Unlock()
	if overflow || d.start == dfaSearchUnknown {
		return nil
	}
	return d
}

// searchDFAInstructionSupported reports whether the ASCII search DFA can evaluate one instruction.
// | searchDFAInstructionSupported 报告 ASCII 搜索 DFA 能否求值一条指令。
func searchDFAInstructionSupported(in *inst) bool {
	switch in.op {
	case opAssert:
		switch assertKind(in.arg) {
		case assertBeginText, assertEndText, assertWordBoundary, assertNotWordBoundary:
			return true
		}
		return false
	case opLook, opBackref, opAtomic:
		return false
	}
	return true
}

// buildAlphabet partitions ASCII bytes by word flag and then refines the partition for every
// consuming instruction. Class membership is kept as a 128-bit mask, so each instruction splits
// classes in O(classes) bit operations instead of rescanning every byte. The result is exact: two
// bytes share a class only when every instruction matches them identically. | buildAlphabet 先按
// 单词标志划分 ASCII 字节，再按每条消费指令细化划分。分组成员使用 128 位掩码保存，因此每条指令以
// O(分组数) 位运算完成切分，无需重新扫描全部字节。结果精确：两个字节只有在每条指令的匹配结果都
// 相同时才属于同一分组。
func (d *searchDFA) buildAlphabet() {
	var nonWord, word [2]uint64
	for value := 0; value < 128; value++ {
		if isASCIIWordByte(byte(value)) {
			word[value>>6] |= uint64(1) << uint(value&63)
		} else {
			nonWord[value>>6] |= uint64(1) << uint(value&63)
		}
	}
	members := [][2]uint64{nonWord, word}
	words := []bool{false, true}
	for _, pc := range d.consume {
		mask := d.instructionMask(pc)
		existing := len(members)
		for classID := 0; classID < existing; classID++ {
			matched := [2]uint64{
				members[classID][0] & mask[0],
				members[classID][1] & mask[1],
			}
			unmatched := [2]uint64{
				members[classID][0] &^ mask[0],
				members[classID][1] &^ mask[1],
			}
			if matched[0]|matched[1] == 0 || unmatched[0]|unmatched[1] == 0 {
				continue
			}
			members = append(members, matched)
			words = append(words, words[classID])
			members[classID] = unmatched
		}
	}
	classes := make([]searchDFAClass, len(members))
	for classID := range members {
		classes[classID].word = words[classID]
		for wordIndex, set := range members[classID] {
			for set != 0 {
				low := set & -set
				value := wordIndex*64 + bits.TrailingZeros64(set)
				classes[classID].rep = byte(value)
				d.classOf[value] = uint8(classID)
				set &^= low
			}
		}
	}
	d.classes = classes
}

// instructionMask returns the ASCII bytes matched by one consuming instruction. The mask is cached
// per literal rune or character class so alphabet construction scans each distinct operand once
// instead of once per instruction. | instructionMask 返回一条消费指令匹配的 ASCII 字节。掩码按字面量
// 符文或字符类缓存，使字母表构建对每个不同操作数只扫描一次，而不是每条指令扫描一次。
func (d *searchDFA) instructionMask(pc uint32) [2]uint64 {
	in := &d.prog.insts[pc]
	switch in.op {
	case opRune:
		return d.runeMask(rune(in.arg), in.flags&instFold != 0)
	case opClass:
		return d.classMask(in.arg)
	case opAny:
		var mask [2]uint64
		mask[0], mask[1] = ^uint64(0), ^uint64(0)
		if in.flags&instDotAll == 0 {
			mask['\n'>>6] &^= uint64(1) << uint('\n'&63)
		}
		return mask
	default:
		return [2]uint64{}
	}
}

// runeMask returns the ASCII bytes matched by a literal rune, optionally under simple folding. |
// runeMask 返回字面量符文匹配的 ASCII 字节，可选简单折叠。
func (d *searchDFA) runeMask(want rune, fold bool) [2]uint64 {
	if !fold {
		var mask [2]uint64
		if want >= 0 && want < 128 {
			mask[want>>6] |= uint64(1) << uint(want&63)
		}
		return mask
	}
	if want >= 0 && want < 128 {
		index := int(want)
		if d.runeMaskOK[index] {
			return d.runeMasks[index]
		}
		mask := d.computeRuneMask(want)
		d.runeMasks[index] = mask
		d.runeMaskOK[index] = true
		return mask
	}
	if d.otherRunes != nil {
		if mask, ok := d.otherRunes[uint32(want)]; ok {
			return mask
		}
	} else {
		d.otherRunes = make(map[uint32][2]uint64, 4)
	}
	mask := d.computeRuneMask(want)
	d.otherRunes[uint32(want)] = mask
	return mask
}

// computeRuneMask scans ASCII bytes for a folded rune. | computeRuneMask 为折叠符文扫描 ASCII 字节。
func (d *searchDFA) computeRuneMask(want rune) [2]uint64 {
	var mask [2]uint64
	for value := 0; value < 128; value++ {
		if equalFoldRune(rune(value), want) {
			mask[value>>6] |= uint64(1) << uint(value&63)
		}
	}
	return mask
}

// classMask returns the ASCII bytes matched by a character class. | classMask 返回字符类匹配的 ASCII
// 字节。
func (d *searchDFA) classMask(index uint32) [2]uint64 {
	if int(index) >= len(d.classMasks) {
		return [2]uint64{}
	}
	if d.classMaskOK[index] {
		return d.classMasks[index]
	}
	var mask [2]uint64
	class := d.prog.classes[index]
	for value := 0; value < 128; value++ {
		if class.match(rune(value)) {
			mask[value>>6] |= uint64(1) << uint(value&63)
		}
	}
	d.classMasks[index] = mask
	d.classMaskOK[index] = true
	return mask
}

// matchesByte reports whether the consuming instruction at pc can consume an ASCII byte. |
// matchesByte 报告 pc 处的消费指令能否消费一个 ASCII 字节。
func (d *searchDFA) matchesByte(pc uint32, value byte) bool {
	if pc >= uint32(len(d.prog.insts)) {
		return false
	}
	in := &d.prog.insts[pc]
	switch in.op {
	case opRune:
		want := rune(in.arg)
		if in.flags&instFold != 0 {
			return equalFoldRune(rune(value), want)
		}
		return uint32(value) == in.arg
	case opClass:
		return d.prog.classes[in.arg].match(rune(value))
	case opAny:
		return in.flags&instDotAll != 0 || value != '\n'
	}
	return false
}

// match reports whether s contains a match and whether the DFA could decide it. known is false when
// the input contains a non-ASCII byte or the state budget overflowed; callers then use the Pike VM.
// | match 报告 s 是否包含匹配以及 DFA 是否能判定。输入含非 ASCII 字节或状态预算溢出时 known 为 false，
// 调用方随后使用 Pike VM。
func (d *searchDFA) match(s string) (matched, known bool) {
	state := d.start
	for i := 0; i < len(s); i++ {
		value := s[i]
		if value >= 0x80 {
			return false, false
		}
		next := d.step(state, d.classOf[value])
		switch next {
		case dfaSearchAccept:
			return true, true
		case dfaSearchUnknown:
			return false, false
		case dfaSearchDead:
			return false, true
		}
		state = next
	}
	st := d.states[state].Load()
	if st != nil && st.acceptEnd {
		return true, true
	}
	return false, true
}

// step returns the transition for one state and alphabet class, computing it on first use. |
// step 返回一个状态与一个字母表分组的转移，首次使用时计算。
func (d *searchDFA) step(state int32, class uint8) int32 {
	st := d.states[state].Load()
	if st == nil {
		return dfaSearchUnknown
	}
	if value := atomic.LoadInt32(&st.row[class]); value != dfaSearchUnknown {
		return value
	}
	d.mu.Lock()
	defer d.mu.Unlock()
	st = d.states[state].Load()
	if st == nil {
		return dfaSearchUnknown
	}
	if value := atomic.LoadInt32(&st.row[class]); value != dfaSearchUnknown {
		return value
	}
	if d.overflow {
		return dfaSearchUnknown
	}
	alphabet := d.classes[class]
	pcs, matched := d.closure(st.seeds, st.atStart, st.prevWord, alphabet.word, false)
	if d.overflow {
		return dfaSearchUnknown
	}
	if matched {
		atomic.StoreInt32(&st.row[class], dfaSearchAccept)
		return dfaSearchAccept
	}
	d.seeds = d.seeds[:0]
	for _, pc := range pcs {
		if d.matchesByte(pc, alphabet.rep) {
			d.seeds = append(d.seeds, pc+1)
		}
	}
	// Start injection for the next position keeps the search unanchored. | 下一位置的起点注入使搜索
	// 保持未锚定。
	d.seeds = append(d.seeds, d.prog.start)
	next := d.internLocked(d.seeds, false, alphabet.word)
	atomic.StoreInt32(&st.row[class], next)
	return next
}

// closure computes the epsilon closure of seeds at one position. Assertions use atStart, prevWord,
// nextWord and atEnd. The returned slice is valid until the next closure call. | closure 计算一个位置
// 上 seeds 的空转移闭包。断言使用 atStart、prevWord、nextWord 与 atEnd。返回切片在下次 closure 调用
// 前有效。
func (d *searchDFA) closure(seeds []uint32, atStart, prevWord, nextWord, atEnd bool) ([]uint32, bool) {
	d.gen++
	if d.gen == 0 {
		clear(d.seen)
		d.gen = 1
	}
	d.stack = append(d.stack[:0], seeds...)
	d.pcs = d.pcs[:0]
	matched := false
	for len(d.stack) > 0 {
		pc := d.stack[len(d.stack)-1]
		d.stack = d.stack[:len(d.stack)-1]
		if d.seen[pc] == d.gen {
			continue
		}
		d.seen[pc] = d.gen
		in := &d.prog.insts[pc]
		switch in.op {
		case opFail:
		case opJmp:
			d.stack = append(d.stack, in.x)
		case opSplit:
			d.stack = append(d.stack, in.y, in.x)
		case opSave:
			d.stack = append(d.stack, pc+1)
		case opAssert:
			ok := false
			switch assertKind(in.arg) {
			case assertBeginText:
				ok = atStart
			case assertEndText:
				ok = atEnd
			case assertWordBoundary:
				ok = prevWord != nextWord
			case assertNotWordBoundary:
				ok = prevWord == nextWord
			default:
				d.overflow = true
				return nil, false
			}
			if ok {
				d.stack = append(d.stack, pc+1)
			}
		case opMatch:
			matched = true
		case opRune, opClass, opAny:
			d.pcs = append(d.pcs, pc)
		default:
			d.overflow = true
			return nil, false
		}
	}
	return d.pcs, matched
}

// internLocked returns the state id for a seed set and context, creating the row on first use. The
// caller must hold d.mu. | internLocked 返回种子集合与上下文的状态下标，首次使用时创建转移行。调用方
// 必须持有 d.mu。
func (d *searchDFA) internLocked(seeds []uint32, atStart, prevWord bool) int32 {
	slices.Sort(seeds)
	seeds = slices.Compact(seeds)
	key := d.stateKey(seeds, atStart, prevWord)
	if id, ok := d.index[key]; ok {
		return id
	}
	if d.count >= dfaSearchStateCap {
		d.overflow = true
		return dfaSearchUnknown
	}
	_, matched := d.closure(seeds, atStart, prevWord, false, true)
	if d.overflow {
		return dfaSearchUnknown
	}
	row := make([]int32, len(d.classes))
	for i := range row {
		row[i] = dfaSearchUnknown
	}
	id := int32(d.count)
	d.index[key] = id
	d.states[id].Store(&searchDFAState{
		seeds:     append([]uint32(nil), seeds...),
		row:       row,
		acceptEnd: matched,
		atStart:   atStart,
		prevWord:  prevWord,
	})
	d.count++
	return id
}

// stateKey builds the map key for a state. | stateKey 构建状态映射键。
func (d *searchDFA) stateKey(seeds []uint32, atStart, prevWord bool) string {
	buf := make([]byte, 1+4*len(seeds))
	if atStart {
		buf[0] |= 1
	}
	if prevWord {
		buf[0] |= 2
	}
	offset := 1
	for _, pc := range seeds {
		binary.LittleEndian.PutUint32(buf[offset:], pc)
		offset += 4
	}
	return string(buf)
}

// isASCIIWordByte reports whether b is an ASCII word byte, matching the Pike VM's boundary rule. |
// isASCIIWordByte 报告 b 是否为 ASCII 单词字节，与 Pike VM 的边界规则一致。
func isASCIIWordByte(b byte) bool {
	return b == '_' || b >= '0' && b <= '9' || b >= 'A' && b <= 'Z' || b >= 'a' && b <= 'z'
}
