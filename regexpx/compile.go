package regexpx

import (
	"errors"

	"github.com/shibingli/ydx/errs"
)

// opcode enumerates the Thompson program instructions. The same program serves the Pike VM and the
// backtracking VM; the latter additionally understands opBackref, opLook and opAtomic. | opcode 枚举
// Thompson 程序指令。同一程序同时服务 Pike VM 与回溯 VM；后者额外理解 opBackref、opLook 与
// opAtomic。
type opcode uint8

const (
	// opFail always fails. | opFail 总是失败。
	opFail opcode = iota
	// opRune matches one literal rune in arg. | opRune 匹配 arg 中的一个字面量符文。
	opRune
	// opClass matches one rune from the class at index arg. | opClass 匹配下标 arg 处字符类的单个符文。
	opClass
	// opAny matches any rune; flag bit 0 includes newline. | opAny 匹配任意符文；标志位 0 表示包含换行。
	opAny
	// opSplit continues at x with higher priority and at y with lower priority. | opSplit 优先继续到 x，
	// 其次继续到 y。
	opSplit
	// opJmp continues at x. | opJmp 继续到 x。
	opJmp
	// opSave stores the current position in slot arg. | opSave 把当前位置存入槽 arg。
	opSave
	// opAssert checks the zero-width assertion in arg. | opAssert 检查 arg 处的零宽断言。
	opAssert
	// opBackref matches the text captured by group arg. | opBackref 匹配分组 arg 捕获的文本。
	opBackref
	// opLook runs the sub-program at arg as a lookaround; flag bit 0 is behind, bit 1 is negative. |
	// opLook 把 arg 处的子程序作为环视运行；标志位 0 表示后行，位 1 表示否定。
	opLook
	// opAtomic runs the sub-program at arg once and keeps its preferred match. | opAtomic 运行 arg 处
	// 的子程序一次并保留其首选匹配。
	opAtomic
	// opMatch reports a successful match. | opMatch 报告匹配成功。
	opMatch
)

const (
	// instFold marks case-insensitive rune/string/backreference matching. | instFold 标记大小写不敏感的
	// 符文、字符串或反向引用匹配。
	instFold uint8 = 1 << iota
	// instBehind marks a lookbehind. | instBehind 标记后行断言。
	instBehind
	// instNegative marks a negative lookaround. | instNegative 标记否定环视。
	instNegative
	// instDotAll marks a dot that also matches newline. | instDotAll 标记同时匹配换行的点号。
	instDotAll
)

// inst is one program instruction. | inst 是一条程序指令。
type inst struct {
	op    opcode
	flags uint8
	arg   uint32
	x     uint32
	y     uint32
}

// program is a compiled pattern. start points at the optional unanchored search prefix, while
// patternStart points at the pattern itself; anchored matching starts at patternStart. | program 是
// 编译后的模式。start 指向可选的未锚定搜索前缀，patternStart 指向模式本身；锚定匹配从 patternStart
// 开始。
type program struct {
	insts        []inst
	classes      []*charClass
	numCap       int
	start        uint32
	patternStart uint32
	info         progInfo
}

// progInfo holds the metadata shared by the execution engines and the prefilter. | progInfo 保存执行
// 引擎与预过滤器共享的元数据。
type progInfo struct {
	minLen   int
	maxLen   int // -1 means unbounded | -1 表示无上限
	canEmpty bool

	prefix     []rune
	prefixFold bool
	prefixOK   bool

	firstBytes   byteSet
	firstBytesOK bool
	// selectivePrefilter marks a literal prefix or a narrow first-byte set. Broad sets scan better
	// with the NFA's own start injection than with an anchored attempt at every candidate. |
	// selectivePrefilter 标记字面量前缀或较窄的首字节集。宽集合用 NFA 自身的起点注入比在每个候选处做
	// 锚定尝试更快。
	selectivePrefilter bool

	anchored        bool
	hasBacktrack    bool
	hasWordBoundary bool
	hasLineAnchor   bool
	hasLookBehind   bool
}

// compiler translates an AST into a Thompson program. | compiler 把 AST 翻译为 Thompson 程序。
type compiler struct {
	prog *program
	err  error
}

// compilePattern compiles an AST and its capture metadata. | compilePattern 编译 AST 及其捕获元数据。
func compilePattern(ast node, numCap int, names map[string]int) (*program, error) {
	var nameErr error
	resolveNamedBackrefs(ast, names, &nameErr)
	if nameErr != nil {
		return nil, errs.Wrap(nameErr, ErrCompile)
	}
	c := &compiler{prog: &program{numCap: numCap}}
	c.prog.patternStart = uint32(len(c.prog.insts))
	c.emit(opSave, 0, 0)
	c.compileNode(ast)
	c.emit(opSave, 0, 1)
	c.emit(opMatch, 0, 0)
	if c.err != nil {
		return nil, errs.Wrap(c.err, ErrCompile)
	}
	c.prog.info = analyze(ast)
	c.prog.info.hasBacktrack = hasBacktrackOnly(ast)
	return c.prog, nil
}

// emit appends one instruction and returns its index. | emit 追加一条指令并返回其下标。
func (c *compiler) emit(op opcode, flags uint8, arg uint32) int {
	c.prog.insts = append(c.prog.insts, inst{op: op, flags: flags, arg: arg})
	return len(c.prog.insts) - 1
}

// emitSplit appends a split with unresolved targets. | emitSplit 追加目标待定的分支指令。
func (c *compiler) emitSplit() int {
	return c.emit(opSplit, 0, 0)
}

// emitJmp appends a jump with an unresolved target. | emitJmp 追加目标待定的跳转指令。
func (c *compiler) emitJmp() int {
	return c.emit(opJmp, 0, 0)
}

// setTarget fills in a jump or split target. | setTarget 填充跳转或分支目标。
func (c *compiler) setTarget(index int, x, y uint32) {
	c.prog.insts[index].x = x
	c.prog.insts[index].y = y
}

// fail records the first compilation error. | fail 记录首个编译错误。
func (c *compiler) fail(err error) {
	if c.err == nil {
		c.err = err
	}
}

// compileNode emits the program for one AST node. | compileNode 为一个 AST 节点生成程序。
func (c *compiler) compileNode(n node) {
	if c.err != nil {
		return
	}
	switch n := n.(type) {
	case nil, *nEmpty:
	case *nLiteral:
		c.emit(opRune, foldFlagOf(n.fold), uint32(n.r))
	case *nString:
		for _, r := range n.runes {
			c.emit(opRune, foldFlagOf(n.fold), uint32(r))
		}
	case *nClass:
		c.prog.classes = append(c.prog.classes, n.c)
		c.emit(opClass, 0, uint32(len(c.prog.classes)-1))
	case *nAny:
		var flags uint8
		if n.dotAll {
			flags = instDotAll
		}
		c.emit(opAny, flags, 0)
	case *nConcat:
		for _, sub := range n.sub {
			c.compileNode(sub)
		}
	case *nAlt:
		c.compileAlt(n.sub)
	case *nRepeat:
		c.compileRepeat(n)
	case *nCapture:
		if n.index <= 0 || n.index > c.prog.numCap {
			c.fail(errors.New("invalid capture index | 非法的捕获下标"))
			return
		}
		c.emit(opSave, 0, uint32(2*n.index))
		c.compileNode(n.sub)
		c.emit(opSave, 0, uint32(2*n.index+1))
	case *nAssert:
		c.emit(opAssert, 0, uint32(n.kind))
	case *nLook:
		look := c.emit(opLook, lookFlags(n.behind, n.neg), 0)
		skip := c.emitJmp()
		subStart := uint32(len(c.prog.insts))
		c.compileNode(n.sub)
		c.emit(opMatch, 0, 0)
		c.prog.insts[look].arg = subStart
		_, maxLen := lengthBounds(n.sub)
		if maxLen >= 0 {
			c.prog.insts[look].y = uint32(maxLen + 1)
		}
		c.setTarget(skip, uint32(len(c.prog.insts)), 0)
	case *nAtomic:
		atomic := c.emit(opAtomic, 0, 0)
		skip := c.emitJmp()
		subStart := uint32(len(c.prog.insts))
		c.compileNode(n.sub)
		c.emit(opMatch, 0, 0)
		c.prog.insts[atomic].arg = subStart
		c.setTarget(skip, uint32(len(c.prog.insts)), 0)
	case *nBackref:
		if n.index <= 0 || n.index > c.prog.numCap {
			c.fail(errors.New("invalid backreference | 非法的反向引用"))
			return
		}
		c.emit(opBackref, foldFlagOf(n.fold), uint32(n.index))
	case *nAmbig:
		c.emit(opRune, 0, uint32(n.value))
	default:
		c.fail(errors.New("unsupported syntax node | 不支持的语法节点"))
	}
}

// compileAlt emits a priority-ordered alternation. | compileAlt 生成按优先级排序的分支。
func (c *compiler) compileAlt(subs []node) {
	if len(subs) == 0 {
		return
	}
	if len(subs) == 1 {
		c.compileNode(subs[0])
		return
	}
	var ends []int
	for i := 0; i < len(subs)-1; i++ {
		split := c.emitSplit()
		bodyStart := uint32(len(c.prog.insts))
		c.compileNode(subs[i])
		ends = append(ends, c.emitJmp())
		next := uint32(len(c.prog.insts))
		c.setTarget(split, bodyStart, next)
	}
	c.compileNode(subs[len(subs)-1])
	end := uint32(len(c.prog.insts))
	for _, j := range ends {
		c.prog.insts[j].x = end
	}
}

// compileRepeat emits a bounded or unbounded repetition. | compileRepeat 生成有界或无界重复。
func (c *compiler) compileRepeat(n *nRepeat) {
	if n.max == 0 || n.min < 0 {
		return
	}
	if n.max < 0 {
		if n.min == 0 {
			// Use distinct entry and loop splits, mirroring the standard library: an empty
			// iteration then reaches the loop split with its captures set and can win over the
			// entry split's lower-priority exit. A single split would deduplicate the revisit and
			// lose the empty iteration's captures. | 使用独立的入口与循环 split，与标准库一致：
			// 空迭代会带着捕获到达循环 split，并胜过入口 split 的低优先级出口。单一 split 会因
			// 去重丢掉空迭代的捕获。
			entry := c.emitSplit()
			bodyStart := uint32(len(c.prog.insts))
			c.compileNode(n.sub)
			loop := c.emitSplit()
			after := uint32(len(c.prog.insts))
			if n.greedy {
				c.setTarget(entry, bodyStart, after)
				c.setTarget(loop, bodyStart, after)
			} else {
				c.setTarget(entry, after, bodyStart)
				c.setTarget(loop, after, bodyStart)
			}
			return
		}
		for i := 0; i < n.min-1; i++ {
			c.compileNode(n.sub)
		}
		c.compilePlus(n)
		return
	}
	for i := 0; i < n.min; i++ {
		c.compileNode(n.sub)
	}
	for i := n.min; i < n.max; i++ {
		split := c.emitSplit()
		bodyStart := uint32(len(c.prog.insts))
		c.compileNode(n.sub)
		after := uint32(len(c.prog.insts))
		if n.greedy {
			c.setTarget(split, bodyStart, after)
		} else {
			c.setTarget(split, after, bodyStart)
		}
	}
}

// compilePlus emits the x+ form without duplicating the body. | compilePlus 在不复制主体的情况下生成
// x+ 形式。
func (c *compiler) compilePlus(n *nRepeat) {
	bodyStart := uint32(len(c.prog.insts))
	c.compileNode(n.sub)
	split := c.emitSplit()
	after := uint32(len(c.prog.insts))
	if n.greedy {
		c.setTarget(split, bodyStart, after)
	} else {
		c.setTarget(split, after, bodyStart)
	}
}

// foldFlagOf converts a fold boolean to instruction flags. | foldFlagOf 把折叠布尔值转换为指令标志。
func foldFlagOf(fold bool) uint8 {
	if fold {
		return instFold
	}
	return 0
}

// lookFlags builds the opLook flag byte. | lookFlags 构造 opLook 的标志字节。
func lookFlags(behind, neg bool) uint8 {
	var flags uint8
	if behind {
		flags |= instBehind
	}
	if neg {
		flags |= instNegative
	}
	return flags
}

// hasBacktrackOnly reports whether the AST contains a construct the Pike VM cannot execute. |
// hasBacktrackOnly 报告 AST 是否包含 Pike VM 无法执行的构造。
func hasBacktrackOnly(n node) bool {
	switch n := n.(type) {
	case *nBackref, *nLook, *nAtomic:
		return true
	case *nConcat:
		for _, sub := range n.sub {
			if hasBacktrackOnly(sub) {
				return true
			}
		}
	case *nAlt:
		for _, sub := range n.sub {
			if hasBacktrackOnly(sub) {
				return true
			}
		}
	case *nRepeat:
		return hasBacktrackOnly(n.sub)
	case *nCapture:
		return hasBacktrackOnly(n.sub)
	}
	return false
}
