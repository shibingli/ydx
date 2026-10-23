package regexpx

import (
	"time"
	"unicode/utf8"

	"github.com/shibingli/ydx/errs"
)

// ErrMatchTimeout reports that a backtracking match exceeded its time or step budget. Callers that
// validate untrusted input should treat it as a non-match, which fails closed. | ErrMatchTimeout 表示
// 回溯匹配超出时间或步数预算。校验不可信输入的调用方应按未匹配处理，从而失败关闭。
var ErrMatchTimeout = errs.New("regular expression match timed out | 正则匹配超时")

// btStepLimit is the hard step ceiling for one match, independent of the wall clock. | btStepLimit 是
// 单次匹配的硬步数上限，与墙钟无关。
const btStepLimit = 64 << 20

// btFrame is one saved backtracking alternative. A frame may carry a loop guard for a backward
// branch that is only taken if a higher-priority branch fails. | btFrame 是一个保存的回溯备选。帧可以
// 携带循环保护，用于仅在更高优先级分支失败时才走的向后分支。
type btFrame struct {
	pc       uint32
	pos      int
	undo     int
	guard    uint32
	guardPos int
	hasGuard bool
}

// undoKind distinguishes capture and loop-guard undo records. | undoKind 区分捕获与循环保护的撤销记录。
type undoKind uint8

const (
	// undoCap restores one capture slot. | undoCap 恢复一个捕获槽。
	undoCap undoKind = iota
	// undoLoop restores one loop guard. | undoLoop 恢复一个循环保护。
	undoLoop
	// undoCapsAll restores an entire capture array used by atomic groups and lookarounds. |
	// undoCapsAll 恢复原子组与环视使用的整个捕获数组。
	undoCapsAll
)

// undoEntry is one reversible capture or guard change. | undoEntry 是一次可撤销的捕获或保护变更。
type undoEntry struct {
	kind undoKind
	idx  int
	old  int
	caps []int
}

// btMachine executes a program with an explicit-stack backtracking VM. | btMachine 用显式栈回溯 VM
// 执行程序。
type btMachine struct {
	prog      *program
	input     string
	caps      []int
	maxSlot   int
	loopGuard []int
	steps     int
	deadline  time.Time
}

// newBTMachine builds a backtracking machine. | newBTMachine 构造回溯机器。
func newBTMachine(p *program, maxSlot int) *btMachine {
	m := &btMachine{prog: p, maxSlot: maxSlot}
	if maxSlot > 0 {
		m.caps = make([]int, maxSlot)
	}
	m.loopGuard = make([]int, len(p.insts))
	for i := range m.loopGuard {
		m.loopGuard[i] = -1
	}
	return m
}

// errTimeout is the internal timeout signal. | errTimeout 是内部超时信号。
func errTimeout() error { return ErrMatchTimeout }

// checkBudget enforces the wall clock and hard step budget. | checkBudget 执行墙钟与硬步数预算。
func (m *btMachine) checkBudget() error {
	if m.steps > btStepLimit {
		return errTimeout()
	}
	if m.steps&0x3FF == 0 && !m.deadline.IsZero() && time.Now().After(m.deadline) {
		return errTimeout()
	}
	return nil
}

// clearState clears captures and loop guards before one match attempt while keeping the search-wide
// step count and deadline. | clearState 在一次匹配尝试前清空捕获与循环保护，同时保留整个搜索的步数与
// 截止时间。
func (m *btMachine) clearState() {
	for i := range m.caps {
		m.caps[i] = -1
	}
	for i := range m.loopGuard {
		m.loopGuard[i] = -1
	}
}

// run executes from startPC at startPos. When stopAt is non-negative, only a match ending exactly at
// stopAt is accepted; this implements lookbehind. | run 从 startPos 处的 startPC 开始执行。stopAt 非负
// 时只接受恰好结束于 stopAt 的匹配，用于实现后行断言。
func (m *btMachine) run(startPC uint32, startPos, stopAt int) (int, bool, error) {
	var stack []btFrame
	var undo []undoEntry
	pc, pos := startPC, startPos
	for {
		m.steps++
		if err := m.checkBudget(); err != nil {
			return 0, false, err
		}
		in := &m.prog.insts[pc]
		switch in.op {
		case opFail:
			if !m.backtrack(&stack, &undo, &pc, &pos) {
				return 0, false, nil
			}
		case opJmp:
			if in.x <= pc {
				if m.loopGuard[in.x] == pos {
					if !m.backtrack(&stack, &undo, &pc, &pos) {
						return 0, false, nil
					}
					continue
				}
				undo = append(undo, undoEntry{kind: undoLoop, idx: int(in.x), old: m.loopGuard[in.x]})
				m.loopGuard[in.x] = pos
			}
			pc = in.x
		case opSplit:
			// An empty loop can revisit the same split at the same position. The guard blocks the
			// backward branch after it has already been taken at this position. | 空循环可能在同一
			// 位置重复到达同一分支。保护机制在该位置的向后分支已被走过之后阻止再次进入。
			xBack := in.x <= pc
			yBack := in.y <= pc
			xBlocked := xBack && m.loopGuard[pc] == pos
			yBlocked := yBack && m.loopGuard[pc] == pos
			if xBlocked && yBlocked {
				if !m.backtrack(&stack, &undo, &pc, &pos) {
					return 0, false, nil
				}
				continue
			}
			if !xBlocked {
				if !yBlocked {
					frame := btFrame{pc: in.y, pos: pos, undo: len(undo)}
					if yBack {
						frame.hasGuard = true
						frame.guard = pc
						frame.guardPos = pos
					}
					stack = append(stack, frame)
				}
				if xBack {
					undo = append(undo, undoEntry{kind: undoLoop, idx: int(pc), old: m.loopGuard[pc]})
					m.loopGuard[pc] = pos
				}
				pc = in.x
				continue
			}
			if yBack {
				undo = append(undo, undoEntry{kind: undoLoop, idx: int(pc), old: m.loopGuard[pc]})
				m.loopGuard[pc] = pos
			}
			pc = in.y
		case opSave:
			slot := int(in.arg)
			if slot < m.maxSlot {
				undo = append(undo, undoEntry{kind: undoCap, idx: slot, old: m.caps[slot]})
				m.caps[slot] = pos
			}
			pc++
		case opAssert:
			if !assertHolds(assertKind(in.arg), m.input, pos) {
				if !m.backtrack(&stack, &undo, &pc, &pos) {
					return 0, false, nil
				}
				continue
			}
			pc++
		case opRune, opClass, opAny:
			next, ok := m.consumeRune(in, pos)
			if !ok {
				if !m.backtrack(&stack, &undo, &pc, &pos) {
					return 0, false, nil
				}
				continue
			}
			pos = next
			pc++
		case opBackref:
			next, ok := m.consumeBackref(in, pos)
			if !ok {
				if !m.backtrack(&stack, &undo, &pc, &pos) {
					return 0, false, nil
				}
				continue
			}
			pos = next
			pc++
		case opLook:
			ok, err := m.runLook(in, pos, &undo)
			if err != nil {
				return 0, false, err
			}
			if !ok {
				if !m.backtrack(&stack, &undo, &pc, &pos) {
					return 0, false, nil
				}
				continue
			}
			pc++
		case opAtomic:
			before := append([]int(nil), m.caps...)
			end, ok, err := m.run(in.arg, pos, -1)
			if err != nil {
				return 0, false, err
			}
			if !ok {
				if !m.backtrack(&stack, &undo, &pc, &pos) {
					return 0, false, nil
				}
				continue
			}
			undo = append(undo, undoEntry{kind: undoCapsAll, caps: before})
			pos = end
			pc++
		case opMatch:
			if stopAt >= 0 && pos != stopAt {
				if !m.backtrack(&stack, &undo, &pc, &pos) {
					return 0, false, nil
				}
				continue
			}
			m.unwindLoops(&undo)
			return pos, true, nil
		default:
			return 0, false, nil
		}
	}
}

// backtrack pops the next alternative and unwinds capture changes. | backtrack 弹出下一个备选并撤销
// 捕获变更。
func (m *btMachine) backtrack(stack *[]btFrame, undo *[]undoEntry, pc *uint32, pos *int) bool {
	if len(*stack) == 0 {
		m.unwindTo(undo, 0)
		return false
	}
	f := (*stack)[len(*stack)-1]
	*stack = (*stack)[:len(*stack)-1]
	if f.hasGuard && m.loopGuard[f.guard] == f.guardPos {
		// The backward alternative was already taken at this position. | 该向后分支已在此位置走过。
		return m.backtrack(stack, undo, pc, pos)
	}
	m.unwindTo(undo, f.undo)
	if f.hasGuard {
		*undo = append(*undo, undoEntry{kind: undoLoop, idx: int(f.guard), old: m.loopGuard[f.guard]})
		m.loopGuard[f.guard] = f.guardPos
	}
	*pc, *pos = f.pc, f.pos
	return true
}

// unwindTo restores undo entries down to mark. | unwindTo 恢复撤销记录直到 mark。
func (m *btMachine) unwindTo(undo *[]undoEntry, mark int) {
	u := *undo
	for i := len(u) - 1; i >= mark; i-- {
		e := u[i]
		switch e.kind {
		case undoCap:
			m.caps[e.idx] = e.old
		case undoLoop:
			m.loopGuard[e.idx] = e.old
		case undoCapsAll:
			copy(m.caps, e.caps)
		}
	}
	*undo = u[:mark]
}

// unwindLoops restores loop guards while keeping capture changes after a successful path. | unwindLoops
// 在成功路径之后恢复循环保护，同时保留捕获变更。
func (m *btMachine) unwindLoops(undo *[]undoEntry) {
	u := *undo
	kept := u[:0]
	for _, e := range u {
		if e.kind == undoLoop {
			m.loopGuard[e.idx] = e.old
			continue
		}
		kept = append(kept, e)
	}
	*undo = kept
}

// consumeRune advances over one rune for opRune, opClass and opAny. | consumeRune 为 opRune、opClass 与
// opAny 前进一个符文。
func (m *btMachine) consumeRune(in *inst, pos int) (int, bool) {
	if pos >= len(m.input) {
		return 0, false
	}
	r, size := utf8.DecodeRuneInString(m.input[pos:])
	switch in.op {
	case opRune:
		want := rune(in.arg)
		if in.flags&instFold != 0 {
			if !equalFoldRune(r, want) {
				return 0, false
			}
		} else if r != want {
			return 0, false
		}
	case opClass:
		if !m.prog.classes[in.arg].match(r) {
			return 0, false
		}
	case opAny:
		if in.flags&instDotAll == 0 && r == '\n' {
			return 0, false
		}
	}
	return pos + size, true
}

// consumeBackref matches the captured text at pos. | consumeBackref 在 pos 处匹配捕获文本。
func (m *btMachine) consumeBackref(in *inst, pos int) (int, bool) {
	group := int(in.arg)
	slot := 2 * group
	if slot+1 >= len(m.caps) {
		return 0, false
	}
	start, end := m.caps[slot], m.caps[slot+1]
	if start < 0 || end < start {
		return 0, false
	}
	n := end - start
	if pos+n > len(m.input) {
		return 0, false
	}
	if in.flags&instFold != 0 {
		if !equalFoldString(m.input[start:end], m.input[pos:pos+n]) {
			return 0, false
		}
	} else if m.input[start:end] != m.input[pos:pos+n] {
		return 0, false
	}
	return pos + n, true
}

// equalFoldString compares two strings under Unicode simple case folding. | equalFoldString 在 Unicode
// 简单大小写折叠下比较两个字符串。
func equalFoldString(a, b string) bool {
	for len(a) > 0 && len(b) > 0 {
		ra, sa := utf8.DecodeRuneInString(a)
		rb, sb := utf8.DecodeRuneInString(b)
		if !equalFoldRune(ra, rb) {
			return false
		}
		a, b = a[sa:], b[sb:]
	}
	return len(a) == 0 && len(b) == 0
}

// runLook executes a lookahead or lookbehind and reports whether the lookaround succeeded. |
// runLook 执行先行或后行断言，并报告环视是否成功。
func (m *btMachine) runLook(in *inst, pos int, undo *[]undoEntry) (bool, error) {
	behind := in.flags&instBehind != 0
	neg := in.flags&instNegative != 0
	before := append([]int(nil), m.caps...)
	ok, err := m.lookAt(in, pos, behind)
	if err != nil {
		return false, err
	}
	if neg {
		if ok {
			copy(m.caps, before)
			return false, nil
		}
		copy(m.caps, before)
		return true, nil
	}
	if !ok {
		copy(m.caps, before)
		return false, nil
	}
	// Captures made inside a successful positive lookaround persist, but must be undone when the
	// outer path backtracks past the lookaround. | 成功的正环视内的捕获会保留，但外层路径回溯越过
	// 该环视时必须撤销。
	*undo = append(*undo, undoEntry{kind: undoCapsAll, caps: before})
	return true, nil
}

// lookAt tests the lookaround sub-program. For lookbehind it walks start positions backwards and
// requires the sub-match to end exactly at pos. | lookAt 测试环视子程序。后行断言从 pos 向前遍历起点，
// 并要求子匹配恰好结束于 pos。
func (m *btMachine) lookAt(in *inst, pos int, behind bool) (bool, error) {
	if !behind {
		_, ok, err := m.run(in.arg, pos, -1)
		return ok, err
	}
	maxLen := -1
	if in.y != 0 {
		maxLen = int(in.y) - 1
	}
	lower := 0
	if maxLen >= 0 {
		lower = pos - 4*maxLen
		if lower < 0 {
			lower = 0
		}
	}
	for start := pos; start >= lower; {
		_, ok, err := m.run(in.arg, start, pos)
		if err != nil {
			return false, err
		}
		if ok {
			return true, nil
		}
		if start == 0 {
			break
		}
		_, size := utf8.DecodeLastRuneInString(m.input[:start])
		start -= size
	}
	return false, nil
}

// findFrom looks for the first match whose start lies in [start, startLimit), using the same prefix
// and first-byte filters as the linear engine. A negative startLimit means no bound. | findFrom 查找
// 起点位于 [start, startLimit) 的第一个匹配，并使用与线性引擎相同的前缀与首字节过滤。startLimit 为负
// 表示无上界。
func (m *btMachine) findFrom(re *Regexp, s string, start, startLimit int) ([]int, bool, error) {
	m.input = s
	if startLimit < 0 || startLimit > len(s)+1 {
		startLimit = len(s) + 1
	}
	if start < 0 {
		start = 0
	}
	if start > len(s) {
		return nil, false, nil
	}
	m.deadline = time.Now().Add(MatchTimeout)
	m.steps = 0
	try := func(pos int) ([]int, bool, error) {
		m.clearState()
		_, ok, err := m.run(m.prog.patternStart, pos, -1)
		if err != nil || !ok {
			return nil, false, err
		}
		return append([]int(nil), m.caps...), true, nil
	}
	if m.prog.info.anchored {
		if start != 0 || startLimit <= 0 {
			return nil, false, nil
		}
		return try(0)
	}
	if re != nil && re.prog.info.selectivePrefilter && re.prog.info.prefixOK {
		for candidate := re.nextPrefix(s, start); candidate >= 0; candidate = re.nextPrefix(s, candidate+1) {
			if candidate >= startLimit {
				break
			}
			if !utf8.RuneStart(s[candidate]) {
				continue
			}
			if caps, ok, err := try(candidate); err != nil || ok {
				return caps, ok, err
			}
		}
		return nil, false, nil
	}
	if re != nil && re.prog.info.selectivePrefilter && re.prog.info.firstBytesOK {
		for candidate := re.firstCandidate(s, start); candidate >= 0; candidate = re.firstCandidate(s, candidate+1) {
			if candidate >= startLimit {
				break
			}
			if !utf8.RuneStart(s[candidate]) {
				continue
			}
			if caps, ok, err := try(candidate); err != nil || ok {
				return caps, ok, err
			}
		}
		return nil, false, nil
	}
	for candidate := start; candidate < startLimit && candidate <= len(s); {
		if candidate == len(s) {
			// A zero-width match may start at end of input. | 零宽匹配可以从输入末尾开始。
			if caps, ok, err := try(candidate); err != nil || ok {
				return caps, ok, err
			}
			break
		}
		// Advance by the decoded size so invalid bytes are tried individually, matching the
		// standard library, while continuation bytes of valid runes are not. | 按解码长度前进，
		// 使非法字节逐个尝试（与标准库一致），同时不会尝试合法符文的续字节。
		if caps, ok, err := try(candidate); err != nil || ok {
			return caps, ok, err
		}
		_, size := utf8.DecodeRuneInString(s[candidate:])
		candidate += size
	}
	return nil, false, nil
}
