package regexpx

import (
	"unicode"
	"unicode/utf8"
)

// pikeThread is one active NFA thread. Patterns that only need group zero keep its bounds in start
// and end, so the common Find and FindAll paths allocate no capture storage at all. |
// pikeThread 是一条活跃的 NFA 线程。只需要分组 0 的模式把其边界保存在 start 与 end 中，因此常见的
// Find 与 FindAll 路径完全不分配捕获存储。
type pikeThread struct {
	pc    uint32
	cap   []int
	start int
	end   int
}

// threadList is a priority-ordered, deduplicated thread list. Deduplication uses a generation-stamped
// stamp array, so resetting the list is O(1). | threadList 是按优先级排序并去重的线程列表。去重使用
// 代际标记数组，因此重置列表是 O(1)。
type threadList struct {
	dense []pikeThread
	stamp []uint32
	gen   uint32
}

// seen reports whether pc was already visited in this generation. | seen 报告本代际中是否已访问 pc。
func (l *threadList) seen(pc uint32) bool { return l.stamp[pc] == l.gen }

// mark records a visit to pc in this generation. | mark 记录本代际对 pc 的访问。
func (l *threadList) mark(pc uint32) { l.stamp[pc] = l.gen }

// addFrame is one pending epsilon closure item. A restore frame undoes a temporary capture write after
// the higher-priority branch has been explored. | addFrame 是一个待处理的空转移闭包项。恢复帧在更高
// 优先级分支探索完毕后撤销临时的捕获写入。
type addFrame struct {
	pc      uint32
	cap     []int
	start   int
	end     int
	restore bool
	slot    int
	old     int
}

// addSimpleFrame is the compact closure frame used when only group zero is tracked. |
// addSimpleFrame 是只跟踪分组 0 时使用的紧凑闭包帧。
type addSimpleFrame struct {
	pc    uint32
	start int
	end   int
}

// pikeMachine executes a Thompson program with the Pike VM algorithm. | pikeMachine 用 Pike VM 算法
// 执行 Thompson 程序。
type pikeMachine struct {
	prog     *program
	input    string
	capLen   int
	maxSlot  int
	lists    [2]threadList
	matched  bool
	matchcap []int
	stack    []addFrame
	simple   []addSimpleFrame
	capPool  [][]int

	// longest enables leftmost-longest selection; bestStart and bestEnd track the best match seen
	// so far. In first-match mode hasBest is only used to mirror the selected match. | longest
	// 启用最左最长选择；bestStart 与 bestEnd 记录目前最佳匹配。最左优先模式下 hasBest 只用于
	// 镜像已选匹配。
	longest   bool
	hasBest   bool
	bestStart int
	bestEnd   int

	// startSet gates unanchored start injection at positions that cannot begin a match. |
	// startSet 在不可能开始匹配的位置阻止未锚定起点注入。
	startSet     *byteSet
	startTables  *[128]byte
	startSetOK   bool
	startASCIIOK bool
}

// newPikeMachine builds a machine for p. | newPikeMachine 为 p 构造机器。
func newPikeMachine(p *program, maxSlot int) *pikeMachine {
	m := &pikeMachine{prog: p, maxSlot: maxSlot, capLen: maxSlot}
	for i := range m.lists {
		m.lists[i].stamp = make([]uint32, len(p.insts))
		m.lists[i].dense = make([]pikeThread, 0, 32)
	}
	m.stack = make([]addFrame, 0, 32)
	m.simple = make([]addSimpleFrame, 0, 64)
	m.capPool = make([][]int, 0, 64)
	return m
}

// canStartAt reports whether an unanchored match may start at pos according to the first-byte
// filter. | canStartAt 根据首字节过滤器报告未锚定匹配能否从 pos 开始。
func (m *pikeMachine) canStartAt(s string, pos int) bool {
	if !m.startSetOK || pos >= len(s) {
		return true
	}
	b := s[pos]
	if m.startASCIIOK {
		return tableSetHas(m.startTables, b)
	}
	return m.startSet.has(b)
}

// addSimple is the epsilon closure for patterns that track only group zero. It uses a compact frame
// and never touches capture slices. | addSimple 是只跟踪分组 0 的模式的空转移闭包。它使用紧凑帧且
// 不触碰捕获切片。
func (m *pikeMachine) addSimple(list *threadList, pc uint32, pos, start, end int) {
	stack := append(m.simple[:0], addSimpleFrame{pc: pc, start: start, end: end})
	insts := m.prog.insts
	stamp := list.stamp
	gen := list.gen
	input := m.input
	dense := list.dense
	for len(stack) > 0 {
		f := stack[len(stack)-1]
		stack = stack[:len(stack)-1]
		if stamp[f.pc] == gen {
			continue
		}
		stamp[f.pc] = gen
		in := &insts[f.pc]
		switch in.op {
		case opFail:
		case opJmp:
			stack = append(stack, addSimpleFrame{pc: in.x, start: f.start, end: f.end})
		case opSplit:
			stack = append(stack, addSimpleFrame{pc: in.y, start: f.start, end: f.end})
			stack = append(stack, addSimpleFrame{pc: in.x, start: f.start, end: f.end})
		case opSave:
			nstart, nend := f.start, f.end
			switch in.arg {
			case 0:
				nstart = pos
			case 1:
				nend = pos
			}
			stack = append(stack, addSimpleFrame{pc: f.pc + 1, start: nstart, end: nend})
		case opAssert:
			if assertHolds(assertKind(in.arg), input, pos) {
				stack = append(stack, addSimpleFrame{pc: f.pc + 1, start: f.start, end: f.end})
			}
		case opMatch, opRune, opClass, opAny:
			dense = append(dense, pikeThread{pc: f.pc, start: f.start, end: f.end})
		}
	}
	m.simple = stack[:0]
	list.dense = dense
}

// addThread dispatches to the compact or full closure. | addThread 分派到紧凑或完整闭包。
func (m *pikeMachine) addThread(list *threadList, pc uint32, pos int, cap []int, start, end int) {
	if m.capLen <= 2 {
		m.addSimple(list, pc, pos, start, end)
		return
	}
	m.add(list, pc, pos, cap, start, end)
}

// copyCap returns a private capture record, reusing a pooled buffer when possible. | copyCap 返回私有的
// 捕获记录，尽可能复用池化缓冲。
func (m *pikeMachine) copyCap(src []int) []int {
	if m.capLen == 0 {
		return nil
	}
	var out []int
	for len(m.capPool) > 0 {
		out = m.capPool[len(m.capPool)-1]
		m.capPool = m.capPool[:len(m.capPool)-1]
		if cap(out) >= m.capLen {
			out = out[:m.capLen]
			copy(out, src)
			return out
		}
	}
	out = make([]int, m.capLen)
	copy(out, src)
	return out
}

// releaseList returns every thread capture to the pool and starts a fresh dedup generation. |
// releaseList 把所有线程捕获归还池中并开启新的去重代际。
func (m *pikeMachine) releaseList(list *threadList) {
	if m.capLen > 2 {
		for i := range list.dense {
			if capSlice := list.dense[i].cap; capSlice != nil {
				m.capPool = append(m.capPool, capSlice)
			}
		}
	}
	list.dense = list.dense[:0]
	list.gen++
	if list.gen == 0 {
		clear(list.stamp)
		list.gen = 1
	}
}

// add follows the epsilon closure from pc and appends consuming and match threads to list in priority
// order. | add 从 pc 跟踪空转移闭包，并按优先级把消费线程与匹配线程追加到 list。
func (m *pikeMachine) add(list *threadList, pc uint32, pos int, cap []int, start, end int) {
	m.stack = append(m.stack[:0], addFrame{pc: pc, cap: cap, start: start, end: end})
	for len(m.stack) > 0 {
		f := m.stack[len(m.stack)-1]
		m.stack = m.stack[:len(m.stack)-1]
		if f.restore {
			f.cap[f.slot] = f.old
			continue
		}
		if list.seen(f.pc) {
			continue
		}
		list.mark(f.pc)
		in := &m.prog.insts[f.pc]
		switch in.op {
		case opFail:
			// Dead end. | 死路。
		case opJmp:
			m.stack = append(m.stack, addFrame{pc: in.x, cap: f.cap, start: f.start, end: f.end})
		case opSplit:
			// Push the lower-priority branch first so the higher-priority branch is popped first. |
			// 先压入低优先级分支，使高优先级分支先弹出。
			m.stack = append(m.stack, addFrame{pc: in.y, cap: f.cap, start: f.start, end: f.end})
			m.stack = append(m.stack, addFrame{pc: in.x, cap: f.cap, start: f.start, end: f.end})
		case opSave:
			slot := int(in.arg)
			switch {
			case m.capLen == 2:
				nstart, nend := f.start, f.end
				if slot == 0 {
					nstart = pos
				} else if slot == 1 {
					nend = pos
				}
				m.stack = append(m.stack, addFrame{pc: f.pc + 1, start: nstart, end: nend})
			case m.capLen > 2 && slot < m.maxSlot:
				// Temporarily write into the shared capture record and restore it after this
				// branch's subtree is explored, so sibling branches see the original value. |
				// 临时写入共享捕获记录，并在本分支子树探索完毕后恢复，使兄弟分支看到原值。
				m.stack = append(m.stack, addFrame{cap: f.cap, restore: true, slot: slot, old: f.cap[slot]})
				f.cap[slot] = pos
				m.stack = append(m.stack, addFrame{pc: f.pc + 1, cap: f.cap, start: f.start, end: f.end})
			default:
				m.stack = append(m.stack, addFrame{pc: f.pc + 1, cap: f.cap, start: f.start, end: f.end})
			}
		case opAssert:
			if assertHolds(assertKind(in.arg), m.input, pos) {
				m.stack = append(m.stack, addFrame{pc: f.pc + 1, cap: f.cap, start: f.start, end: f.end})
			}
		case opMatch, opRune, opClass, opAny:
			t := pikeThread{pc: f.pc, start: f.start, end: f.end}
			if m.capLen > 2 {
				t.cap = m.copyCap(f.cap)
			}
			list.dense = append(list.dense, t)
		default:
			// opBackref, opLook and opAtomic are handled by the backtracking machine. | opBackref、
			// opLook 与 opAtomic 由回溯机器处理。
		}
	}
}

// consumes reports whether the instruction at the thread can consume the rune r at pos. |
// consumes 报告线程所在指令能否在 pos 处消费符文 r。
func (m *pikeMachine) consumes(t *pikeThread, r rune) bool {
	in := &m.prog.insts[t.pc]
	switch in.op {
	case opRune:
		want := rune(in.arg)
		if in.flags&instFold != 0 {
			return equalFoldRune(r, want)
		}
		return r == want
	case opClass:
		return m.prog.classes[in.arg].match(r)
	case opAny:
		return in.flags&instDotAll != 0 || r != '\n'
	}
	return false
}

// step processes one input position. It records matches in priority order and cuts off every thread
// below the matching one. | step 处理一个输入位置。它按优先级记录匹配，并截断匹配线程之下的所有线程。
func (m *pikeMachine) step(runq, nextq *threadList, pos, nextPos int, r rune, width int) {
	if m.capLen <= 2 {
		m.stepSimple(runq, nextq, pos, nextPos, r, width)
		return
	}
	for j := 0; j < len(runq.dense); j++ {
		t := &runq.dense[j]
		in := &m.prog.insts[t.pc]
		if in.op == opMatch {
			m.recordMatch(t, pos)
			if !m.longest {
				// First-match mode: cut off all lower-priority threads. | 最左优先模式：截断所有
				// 更低优先级的线程。
				m.releaseList(runq)
				return
			}
			// Longest mode keeps lower-priority threads alive so a later-ending match can replace
			// the current best. | 最长模式保留更低优先级的线程，使结束更晚的匹配可以替换当前最佳。
			continue
		}
		if width == 0 || !m.consumes(t, r) {
			continue
		}
		m.addThread(nextq, t.pc+1, nextPos, t.cap, t.start, t.end)
	}
	m.releaseList(runq)
}

// stepSimple processes one input position when only group zero is tracked. It inlines instruction
// dispatch and consumption checks to keep the common no-capture path free of helper calls. |
// stepSimple 在只跟踪分组 0 时处理一个输入位置。它内联指令分派与消费检查，使常见的无捕获路径
// 不产生辅助函数调用。
func (m *pikeMachine) stepSimple(runq, nextq *threadList, pos, nextPos int, r rune, width int) {
	insts := m.prog.insts
	classes := m.prog.classes
	dense := runq.dense
	for j := range dense {
		t := &dense[j]
		in := &insts[t.pc]
		switch in.op {
		case opMatch:
			m.recordMatch(t, pos)
			if !m.longest {
				m.releaseList(runq)
				return
			}
		case opRune:
			if width == 0 {
				continue
			}
			want := rune(in.arg)
			if in.flags&instFold != 0 {
				if !equalFoldRune(r, want) {
					continue
				}
			} else if r != want {
				continue
			}
			m.addSimple(nextq, t.pc+1, nextPos, t.start, t.end)
		case opClass:
			if width == 0 || !classes[in.arg].match(r) {
				continue
			}
			m.addSimple(nextq, t.pc+1, nextPos, t.start, t.end)
		case opAny:
			if width == 0 || in.flags&instDotAll == 0 && r == '\n' {
				continue
			}
			m.addSimple(nextq, t.pc+1, nextPos, t.start, t.end)
		}
	}
	m.releaseList(runq)
}

// recordMatch records one match thread. In longest mode it keeps the match with the earliest start
// and, among equal starts, the furthest end; in first-match mode the caller immediately cuts off
// lower-priority threads, so the first record is the selected one. | recordMatch 记录一个匹配线程。
// 最长模式保留起点最早、起点相同时结束最晚的匹配；最左优先模式下调用方会立即截断更低优先级
// 线程，因此首次记录即为选中匹配。
func (m *pikeMachine) recordMatch(t *pikeThread, pos int) {
	start, end := t.start, pos
	if m.hasBest {
		if start > m.bestStart {
			return
		}
		if start == m.bestStart {
			if end < m.bestEnd {
				return
			}
			if end == m.bestEnd {
				// Same overall match: POSIX subexpression order prefers the earlier start and,
				// for equal starts, the longer end. | 整体匹配相同时，POSIX 子表达式顺序偏好更早的
				// 起点，以及起点相同时更晚的终点。
				if m.capLen <= 2 || t.cap == nil || !betterLongestCaptures(t.cap, m.matchcap) {
					return
				}
			}
		}
	}
	m.hasBest = true
	m.bestStart, m.bestEnd = start, end
	m.matched = true
	switch {
	case m.capLen == 2:
		m.matchcap[0], m.matchcap[1] = start, end
	case m.capLen > 2:
		copy(m.matchcap, t.cap)
		m.matchcap[0], m.matchcap[1] = start, end
	}
}

// betterLongestCaptures reports whether candidate is preferable to current under POSIX
// leftmost-longest subexpression order. Group zero has already been compared by the caller. |
// betterLongestCaptures 报告在 POSIX 最左最长子表达式顺序下 candidate 是否优于 current。调用方已
// 比较分组 0。
func betterLongestCaptures(candidate, current []int) bool {
	for i := 2; i+1 < len(candidate) && i+1 < len(current); i += 2 {
		candidateStart, candidateEnd := candidate[i], candidate[i+1]
		currentStart, currentEnd := current[i], current[i+1]
		candidateMatched := candidateStart >= 0
		currentMatched := currentStart >= 0
		if candidateMatched != currentMatched {
			return candidateMatched
		}
		if !candidateMatched {
			continue
		}
		if candidateStart != currentStart {
			return candidateStart < currentStart
		}
		if candidateEnd != currentEnd {
			return candidateEnd > currentEnd
		}
	}
	return false
}

// run executes the program from startPC at start. When allowNewStarts is true the pattern may start at
// every later position, implementing an unanchored search. | run 从 start 处的 startPC 开始执行程序。
// allowNewStarts 为 true 时模式可以在其后每个位置开始，实现未锚定搜索。
func (m *pikeMachine) run(s string, startPC uint32, start int, allowNewStarts bool) bool {
	m.input = s
	m.matched = false
	m.hasBest = false
	m.bestStart, m.bestEnd = 0, 0
	if m.capLen > 0 {
		if cap(m.matchcap) < m.capLen {
			m.matchcap = make([]int, m.capLen)
		} else {
			m.matchcap = m.matchcap[:m.capLen]
		}
		for i := range m.matchcap {
			m.matchcap[i] = -1
		}
	} else {
		m.matchcap = nil
	}
	m.releaseList(&m.lists[0])
	m.releaseList(&m.lists[1])
	// Positions advance by the decoded rune size, so every position here is one the standard
	// library would also consider, including each invalid byte. Do not skip continuation bytes:
	// an invalid byte decodes as RuneError with size one and is a valid match start. | 位置按解码
	// 出的符文长度前进，因此这里的每个位置（包括每个非法字节）都是标准库同样会考虑的位置。不要跳过
	// 续字节：非法字节解码为 RuneError 且长度为 1，是合法的匹配起点。
	pos := start
	if pos > len(s) {
		return false
	}
	runq, nextq := &m.lists[0], &m.lists[1]
	if m.capLen > 2 {
		m.matchcap[0] = pos
	}
	if !allowNewStarts || m.canStartAt(s, pos) {
		m.addThread(runq, startPC, pos, m.matchcap, pos, pos)
	}
	for {
		if len(runq.dense) == 0 && !allowNewStarts {
			// An anchored attempt with no live threads cannot match at a later position. | 没有活跃
			// 线程的锚定尝试不可能在后续位置匹配。
			break
		}
		var r rune
		var width int
		if pos < len(s) {
			r, width = utf8.DecodeRuneInString(s[pos:])
		}
		m.step(runq, nextq, pos, pos+width, r, width)
		if width == 0 {
			break
		}
		pos += width
		runq, nextq = nextq, runq
		if allowNewStarts && !m.matched && m.canStartAt(s, pos) {
			if m.capLen > 2 {
				m.matchcap[0] = pos
			}
			m.addThread(runq, startPC, pos, m.matchcap, pos, pos)
		}
		if len(runq.dense) == 0 && m.matched {
			break
		}
	}
	return m.matched
}

// search looks for a match at or after start. | search 在 start 及其后查找匹配。
func (m *pikeMachine) search(s string, start int) bool {
	return m.run(s, m.prog.start, start, true)
}

// matchAt reports whether a match starts exactly at start. | matchAt 报告是否有匹配恰好从 start 开始。
func (m *pikeMachine) matchAt(s string, start int) bool {
	return m.run(s, m.prog.patternStart, start, false)
}

// capsInto returns the most recent match captures, reusing dst when it has room. |
// capsInto 返回最近一次匹配的捕获，dst 有足够空间时复用。
func (m *pikeMachine) capsInto(dst []int) []int {
	if m.capLen == 0 {
		return nil
	}
	if dst != nil && cap(dst) >= m.capLen {
		dst = dst[:m.capLen]
		copy(dst, m.matchcap)
		return dst
	}
	return append([]int(nil), m.matchcap...)
}

// caps returns a private copy of the most recent match captures. | caps 返回最近一次匹配捕获的私有副本。
func (m *pikeMachine) caps() []int {
	if m.capLen == 0 {
		return nil
	}
	return append([]int(nil), m.matchcap...)
}

// equalFoldRune reports whether a and b are equal under Unicode simple case folding. | equalFoldRune
// 报告 a 与 b 在 Unicode 简单大小写折叠下是否相等。
func equalFoldRune(a, b rune) bool {
	if a == b {
		return true
	}
	if a < utf8.RuneSelf && b < utf8.RuneSelf {
		return asciiLower(a) == asciiLower(b)
	}
	for f := unicode.SimpleFold(a); f != a; f = unicode.SimpleFold(f) {
		if f == b {
			return true
		}
	}
	return false
}

// asciiLower lowercases an ASCII letter and leaves every other byte unchanged. | asciiLower 将 ASCII
// 字母转为小写，其他字节保持不变。
func asciiLower(r rune) rune {
	if r >= 'A' && r <= 'Z' {
		return r + ('a' - 'A')
	}
	return r
}

// assertHolds evaluates a zero-width assertion at pos. | assertHolds 在 pos 处求值零宽断言。
func assertHolds(kind assertKind, s string, pos int) bool {
	switch kind {
	case assertBeginText:
		return pos == 0
	case assertEndText:
		return pos == len(s)
	case assertBeginLine:
		return pos == 0 || s[pos-1] == '\n'
	case assertEndLine:
		return pos == len(s) || s[pos] == '\n'
	case assertWordBoundary:
		return isWordByteAt(s, pos-1) != isWordByteAt(s, pos)
	case assertNotWordBoundary:
		return isWordByteAt(s, pos-1) == isWordByteAt(s, pos)
	case assertEndTextFinalNewline:
		if pos == len(s) {
			return true
		}
		if pos == len(s)-1 && s[pos] == '\n' {
			return true
		}
		return pos == len(s)-2 && s[pos] == '\r' && s[pos+1] == '\n'
	}
	return false
}

// isWordByteAt reports whether the byte at index i is an ASCII word byte; out-of-range positions are
// non-word. | isWordByteAt 报告下标 i 的字节是否为 ASCII 单词字节；越界位置视为非单词字节。
func isWordByteAt(s string, i int) bool {
	if i < 0 || i >= len(s) {
		return false
	}
	b := s[i]
	return b == '_' || b >= '0' && b <= '9' || b >= 'A' && b <= 'Z' || b >= 'a' && b <= 'z'
}
