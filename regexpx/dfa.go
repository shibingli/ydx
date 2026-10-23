package regexpx

import "sort"

// asciiDFA is an eagerly built deterministic automaton for full-match validation patterns of the
// form ^body$ whose body only consumes positive ASCII literals and classes. Such patterns have a
// small state space, so the whole transition table is built at compile time; the execution path is
// one table lookup per byte and no allocations. | asciiDFA 是 ^body$ 形式全匹配校验模式的确定性
// 自动机，其主体只消费正向 ASCII 字面量与字符类。这类模式状态空间很小，因此整个转移表在编译期构建；
// 执行路径每字节一次查表且不分配。
type asciiDFA struct {
	trans  []int32 // len(states) * 256; -1 is dead | 长度为 状态数*256；-1 表示死状态
	accept []bool
	start  int32
}

// dfaStateCap bounds the state count so an unusual pattern falls back to the NFA instead of consuming
// compile time and memory. | dfaStateCap 限制状态数量，使异常模式回退到 NFA，而不是消耗编译时间与内存。
const dfaStateCap = 512

// dfaInstrCap bounds the program size eligible for DFA construction. | dfaInstrCap 限制可构建 DFA 的
// 程序大小。
const dfaInstrCap = 512

// dfaBuilder builds states by interning epsilon-closure results. Buffers are reused across closures so
// construction stays allocation-light. | dfaBuilder 通过驻留空转移闭包结果构建状态。闭包之间复用缓冲，
// 使构建保持低分配。
type dfaBuilder struct {
	prog   *program
	seen   []uint32
	gen    uint32
	states [][]uint32
	trans  []int32
	accept []bool

	hashKeys map[uint64][]int32
	flags    []uint8

	stackBuf    []uint32
	pcsBuf      []uint32
	seedBuf     []uint32
	acceptStack []uint32

	alphabetClasses [][]byte
	overflow        bool
}

// buildASCIIFullMatch builds the DFA for ast when it has the ^body$ shape and an ASCII-only body.
// | buildASCIIFullMatch 在 ast 具有 ^body$ 形状且主体仅含 ASCII 时构建 DFA。
func buildASCIIFullMatch(ast node, prog *program) *asciiDFA {
	body, ok := fullMatchBody(ast)
	if !ok || !asciiBodyOnly(body) || len(prog.insts) > dfaInstrCap {
		return nil
	}
	b := &dfaBuilder{
		prog:     prog,
		seen:     make([]uint32, len(prog.insts)),
		hashKeys: make(map[uint64][]int32),
	}
	b.collectAlphabet(prog)
	if len(b.alphabetClasses) == 0 {
		return nil
	}
	states, seeds, _ := b.closure([]uint32{prog.patternStart}, true, false)
	start := b.intern(states, seeds, true)
	if start < 0 {
		return nil
	}
	for next := 0; next < len(b.states); next++ {
		for _, class := range b.alphabetClasses {
			ch := class[0]
			b.seedBuf = b.seedBuf[:0]
			for _, pc := range b.states[next] {
				if b.matchesByte(pc, ch) {
					b.seedBuf = append(b.seedBuf, pc+1)
				}
			}
			if len(b.seedBuf) == 0 {
				continue
			}
			ns, sseeds, _ := b.closure(b.seedBuf, false, false)
			idx := b.intern(ns, sseeds, false)
			if idx < 0 {
				return nil
			}
			row := int(next) * 256
			for _, member := range class {
				b.trans[row+int(member)] = idx
			}
		}
	}
	return &asciiDFA{trans: b.trans, accept: b.accept, start: start}
}

// fullMatchBody recognizes Concat(BeginText, body, EndText) and returns the body. | fullMatchBody
// 识别 Concat(BeginText, body, EndText) 并返回主体。
func fullMatchBody(ast node) (node, bool) {
	concat, ok := ast.(*nConcat)
	if !ok {
		return nil, false
	}
	subs := concat.sub
	if len(subs) < 2 {
		return nil, false
	}
	if a, ok := subs[0].(*nAssert); !ok || a.kind != assertBeginText {
		return nil, false
	}
	if a, ok := subs[len(subs)-1].(*nAssert); !ok || a.kind != assertEndText {
		return nil, false
	}
	if len(subs) == 2 {
		return &nEmpty{}, true
	}
	return &nConcat{sub: subs[1 : len(subs)-1]}, true
}

// asciiBodyOnly reports whether every consuming instruction in n is a positive ASCII literal or
// class. | asciiBodyOnly 报告 n 中每条消费指令是否都是正向 ASCII 字面量或字符类。
func asciiBodyOnly(n node) bool {
	switch n := n.(type) {
	case *nEmpty:
		return true
	case *nLiteral:
		return n.r < 128 && !n.fold
	case *nString:
		if n.fold {
			return false
		}
		for _, r := range n.runes {
			if r >= 128 {
				return false
			}
		}
		return true
	case *nClass:
		c := n.c
		if c.neg || c.fold || c.nonASCII || len(c.tables) > 0 {
			return false
		}
		for _, r := range c.ranges {
			if r.hi >= 128 {
				return false
			}
		}
		return true
	case *nConcat:
		for _, sub := range n.sub {
			if !asciiBodyOnly(sub) {
				return false
			}
		}
		return true
	case *nAlt:
		for _, sub := range n.sub {
			if !asciiBodyOnly(sub) {
				return false
			}
		}
		return true
	case *nRepeat:
		return asciiBodyOnly(n.sub)
	case *nCapture:
		return asciiBodyOnly(n.sub)
	}
	return false
}

// collectAlphabet groups ASCII bytes by which consuming instructions they match. Bytes in one group
// have identical transitions from every DFA state, so the builder computes one transition per group
// instead of one per byte. | collectAlphabet 按「匹配哪些消费指令」对 ASCII 字节分组。同一组中的字节
// 从任何 DFA 状态出发都具有相同转移，因此构建器每组只计算一次转移，而不是每字节一次。
func (b *dfaBuilder) collectAlphabet(prog *program) {
	type signature [8]uint64 // 512 instruction bits | 512 个指令位
	groups := make(map[signature][]byte, 16)
	for v := 0; v < 128; v++ {
		var sig signature
		for i := range prog.insts {
			if b.matchesByte(uint32(i), byte(v)) {
				sig[i>>6] |= uint64(1) << (uint(i) & 63)
			}
		}
		if sig == (signature{}) {
			continue
		}
		groups[sig] = append(groups[sig], byte(v))
	}
	for _, class := range groups {
		b.alphabetClasses = append(b.alphabetClasses, class)
	}
	sort.Slice(b.alphabetClasses, func(i, j int) bool {
		return b.alphabetClasses[i][0] < b.alphabetClasses[j][0]
	})
}

// matchesByte reports whether the consuming instruction at pc matches the byte ch. |
// matchesByte 报告 pc 处的消费指令是否匹配字节 ch。
func (b *dfaBuilder) matchesByte(pc uint32, ch byte) bool {
	in := &b.prog.insts[pc]
	switch in.op {
	case opRune:
		return in.arg == uint32(ch) && in.flags&instFold == 0
	case opClass:
		return b.prog.classes[in.arg].match(rune(ch))
	}
	return false
}

// closure follows epsilon transitions under the given assertion context. It returns the consuming
// pcs, the raw seeds, and whether Match was reached. The returned slices are only valid until the next
// closure call. | closure 在给定断言上下文中跟踪空转移，返回消费指令、原始种子以及是否到达 Match。
// 返回的切片只在下一次闭包调用之前有效。
func (b *dfaBuilder) closure(seeds []uint32, atStart, atEnd bool) (pcs, rawSeeds []uint32, matched bool) {
	b.gen++
	if b.gen == 0 {
		clear(b.seen)
		b.gen = 1
	}
	b.stackBuf = append(b.stackBuf[:0], seeds...)
	b.seedBuf = append(b.seedBuf[:0], seeds...)
	b.pcsBuf = b.pcsBuf[:0]
	for len(b.stackBuf) > 0 {
		pc := b.stackBuf[len(b.stackBuf)-1]
		b.stackBuf = b.stackBuf[:len(b.stackBuf)-1]
		if b.seen[pc] == b.gen {
			continue
		}
		b.seen[pc] = b.gen
		in := &b.prog.insts[pc]
		switch in.op {
		case opFail:
		case opJmp:
			b.stackBuf = append(b.stackBuf, in.x)
		case opSplit:
			b.stackBuf = append(b.stackBuf, in.y, in.x)
		case opSave:
			b.stackBuf = append(b.stackBuf, pc+1)
		case opAssert:
			switch assertKind(in.arg) {
			case assertBeginText:
				if atStart {
					b.stackBuf = append(b.stackBuf, pc+1)
				}
			case assertEndText:
				if atEnd {
					b.stackBuf = append(b.stackBuf, pc+1)
				}
			default:
				b.overflow = true
			}
		case opMatch:
			matched = true
		case opRune, opClass, opAny:
			b.pcsBuf = append(b.pcsBuf, pc)
		default:
			b.overflow = true
		}
	}
	return b.pcsBuf, b.seedBuf, matched
}

// intern returns the state index for a closure result. The consuming pcs, start context and
// end-of-input acceptance form the state identity. | intern 返回闭包结果的状态下标。消费指令、起始上下文
// 与输入末尾接受性共同构成状态身份。
func (b *dfaBuilder) intern(pcs, seeds []uint32, atStart bool) int32 {
	if b.overflow {
		return -1
	}
	// Acceptance at end of input: close the seeds with the end assertion enabled. The result is part
	// of the state identity because two paths can reach the same consuming pcs with different
	// end-of-input outcomes. | 输入末尾的接受判定：启用末尾断言对种子做闭包。结果属于状态身份，因为
	// 两条路径可以到达相同的消费指令但输入末尾结果不同。
	matched := b.accepts(seeds, atStart)
	if b.overflow {
		return -1
	}
	flags := stateFlags(atStart, matched)
	hash := stateHash(pcs, atStart, matched)
	if candidates, ok := b.hashKeys[hash]; ok {
		for _, index := range candidates {
			if b.flags[index] == flags && equalPCs(b.states[index], pcs) {
				return index
			}
		}
	}
	pcCopy := append([]uint32(nil), pcs...)
	if len(b.states) >= dfaStateCap {
		b.overflow = true
		return -1
	}
	index := int32(len(b.states))
	b.hashKeys[hash] = append(b.hashKeys[hash], index)
	b.states = append(b.states, pcCopy)
	b.flags = append(b.flags, flags)
	b.accept = append(b.accept, matched)
	b.trans = append(b.trans, deadTransitions[:]...)
	return index
}

// accepts reports whether the seeds can reach Match with the end assertion enabled. It uses a
// dedicated stack so it can run between main closures without allocating. | accepts 报告种子在启用末尾
// 断言时能否到达 Match。它使用专用栈，因此可以在主闭包之间无分配地运行。
func (b *dfaBuilder) accepts(seeds []uint32, atStart bool) bool {
	b.gen++
	if b.gen == 0 {
		clear(b.seen)
		b.gen = 1
	}
	b.acceptStack = append(b.acceptStack[:0], seeds...)
	for len(b.acceptStack) > 0 {
		pc := b.acceptStack[len(b.acceptStack)-1]
		b.acceptStack = b.acceptStack[:len(b.acceptStack)-1]
		if b.seen[pc] == b.gen {
			continue
		}
		b.seen[pc] = b.gen
		in := &b.prog.insts[pc]
		switch in.op {
		case opFail:
		case opJmp:
			b.acceptStack = append(b.acceptStack, in.x)
		case opSplit:
			b.acceptStack = append(b.acceptStack, in.y, in.x)
		case opSave:
			b.acceptStack = append(b.acceptStack, pc+1)
		case opAssert:
			switch assertKind(in.arg) {
			case assertBeginText:
				if atStart {
					b.acceptStack = append(b.acceptStack, pc+1)
				}
			case assertEndText:
				b.acceptStack = append(b.acceptStack, pc+1)
			default:
				b.overflow = true
			}
		case opMatch:
			return true
		case opRune, opClass, opAny:
			// Consuming instructions cannot advance at end of input. | 消费指令在输入末尾无法前进。
		default:
			b.overflow = true
		}
	}
	return false
}

// deadTransitions is the initial dead-state transition row. | deadTransitions 是初始死状态转移行。
var deadTransitions = func() [256]int32 {
	var row [256]int32
	for i := range row {
		row[i] = -1
	}
	return row
}()

// stateHash hashes a state's pcs, start context and end-of-input acceptance. | stateHash 对状态的消费
// 指令、起始上下文与输入末尾接受性做哈希。
func stateHash(pcs []uint32, atStart, accept bool) uint64 {
	hash := uint64(1469598103934665603)
	if atStart {
		hash ^= 0x9E3779B97F4A7C15
		hash *= 1099511628211
	}
	if accept {
		hash ^= 0xD1B54A32D192ED03
		hash *= 1099511628211
	}
	for _, pc := range pcs {
		hash ^= uint64(pc)
		hash *= 1099511628211
	}
	return hash
}

// stateFlags encodes the start context and end-of-input acceptance. | stateFlags 编码起始上下文与输入
// 末尾接受性。
func stateFlags(atStart, accept bool) uint8 {
	var flags uint8
	if atStart {
		flags |= 1
	}
	if accept {
		flags |= 2
	}
	return flags
}

// equalPCs compares two sorted-or-identically-ordered pc slices. | equalPCs 比较两个顺序一致的消费指令
// 切片。
func equalPCs(a, b []uint32) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}

// match reports whether s matches the full anchored pattern. | match 报告 s 是否匹配该锚定全匹配模式。
func (d *asciiDFA) match(s string) bool {
	state := d.start
	for i := 0; i < len(s); i++ {
		ch := s[i]
		if ch >= 0x80 {
			return false
		}
		state = d.trans[int(state)*256+int(ch)]
		if state < 0 {
			return false
		}
	}
	return d.accept[state]
}
