package regexpx

import (
	"strings"
	"sync"
	"sync/atomic"
	"time"
	"unicode"
	"unicode/utf8"
	"unsafe"

	"github.com/shibingli/ydx/errs"
)

// MatchTimeout is the per-match wall-clock budget for the backtracking engine. The linear-time engine
// never needs a timeout: its cost is linear in the input. This budget only fires on catastrophic
// backtracking in patterns that need lookaround or backreferences. | MatchTimeout 是回溯引擎单次匹配的
// 实际耗时预算。线性时间引擎不需要超时：其代价与输入长度线性相关。该预算只会被需要环视或反向引用的
// 模式中的灾难性回溯触发。
const MatchTimeout = 100 * time.Millisecond

var (
	// ErrCompile reports that a pattern cannot be parsed or compiled. | ErrCompile 表示模式无法解析或
	// 编译。
	ErrCompile = errs.New("compile regular expression failed | 编译正则表达式失败")
)

// Regexp is a compiled pattern. It is safe for concurrent use and must not be copied after first use.
// | Regexp 是已编译的模式。它可安全并发使用，首次使用后不得复制。
type Regexp struct {
	src     string
	prog    *program
	exact   *exactInfo
	run     *runInfo
	wild    *wildInfo
	lin     *linInfo
	email   *emailInfo
	names   []string
	nameMap map[string]int

	prefixBytes     string
	prefixFoldASCII bool
	firstTables     [128]byte
	firstASCIISet   bool

	// The full-match DFA is built lazily on first use so package-level Compile stays cheap. |
	// 全匹配 DFA 在首次使用时惰性构建，使包级 Compile 保持廉价。
	dfaEligible bool
	dfaAST      node
	dfaOnce     sync.Once
	dfa         *asciiDFA

	pikePool sync.Pool
	btPool   sync.Pool

	// parallelSearches counts chunked searches for observability in tests. | parallelSearches 统计
	// 分块搜索次数，供测试观测。
	parallelSearches atomic.Int64
}

// Compile parses expr and returns a compiled pattern. | Compile 解析 expr 并返回已编译的模式。
//
// The syntax is RE2 plus the .NET constructs needed to replace regexp2: lookahead, lookbehind,
// backreferences, named groups, atomic groups and possessive quantifiers. A syntax error wraps
// ErrCompile so callers can test it with errors.Is. | 语法为 RE2 加上替换 regexp2 所需的 .NET 构造：
// 先行、后行、反向引用、命名分组、原子组与占有量词。语法错误包装 ErrCompile，调用方可用 errors.Is
// 判定。
func Compile(expr string) (*Regexp, error) {
	ast, numCap, names, err := parsePattern(expr)
	if err != nil {
		return nil, errs.WrapDetail(err, ErrCompile, "pattern %[1]q | 模式 %[1]q", expr)
	}
	prog, err := compilePattern(ast, numCap, names)
	if err != nil {
		return nil, errs.WrapDetail(err, ErrCompile, "pattern %[1]q | 模式 %[1]q", expr)
	}
	r := &Regexp{
		src:     expr,
		prog:    prog,
		names:   make([]string, numCap+1),
		nameMap: names,
	}
	for name, index := range names {
		r.names[index] = name
	}
	if prog.info.prefixOK {
		r.prefixBytes = string(prog.info.prefix)
		if prog.info.prefixFold {
			r.prefixFoldASCII = asciiFoldPrefix(prog.info.prefix)
		}
	}
	if prog.info.firstBytesOK {
		r.firstTables, r.firstASCIISet = makeByteSetTables(prog.info.firstBytes)
	}
	if body, ok := fullMatchBody(ast); ok && asciiBodyOnly(body) && len(prog.insts) <= dfaInstrCap {
		r.dfaEligible = true
		r.dfaAST = ast
	}
	r.exact = analyzeExact(ast, numCap)
	r.run = analyzeRun(ast, numCap)
	r.wild = analyzeWild(ast)
	r.lin = analyzeLinear(ast, numCap)
	r.email = analyzeEmail(ast, numCap)
	r.pikePool.New = func() any { return newPikeMachine(prog, 0) }
	r.btPool.New = func() any { return newBTMachine(prog, 0) }
	return r, nil
}

// MustCompile is like Compile but panics when expr is invalid. It is meant for package-level
// initialization, where an invalid pattern is a programming error, and mirrors the contract of the
// standard library's MustCompile. | MustCompile 与 Compile 相同，但 expr 非法时 panic。它用于包级
// 初始化：非法模式属于编程错误，与标准库 MustCompile 的约定一致。
func MustCompile(expr string) *Regexp {
	r, err := Compile(expr)
	if err != nil {
		panic(err)
	}
	return r
}

// QuoteMeta escapes every regular-expression metacharacter in s. | QuoteMeta 转义 s 中的全部正则元字符。
func QuoteMeta(s string) string {
	// A byte loop is correct because every metacharacter is ASCII; invalid UTF-8 bytes are copied
	// unchanged, matching the standard library. | 字节循环是正确的，因为所有元字符都是 ASCII；非法
	// UTF-8 字节原样复制，与标准库一致。
	i := 0
	for i < len(s) && !isMetaByte(s[i]) {
		i++
	}
	if i >= len(s) {
		return s
	}
	var b strings.Builder
	b.Grow(len(s) + 8)
	b.WriteString(s[:i])
	for ; i < len(s); i++ {
		if isMetaByte(s[i]) {
			b.WriteByte('\\')
		}
		b.WriteByte(s[i])
	}
	return b.String()
}

// isMetaByte reports whether b must be escaped by QuoteMeta. | isMetaByte 报告 QuoteMeta 是否必须转义 b。
func isMetaByte(b byte) bool {
	switch b {
	case '\\', '.', '+', '*', '?', '(', ')', '|', '[', ']', '{', '}', '^', '$':
		return true
	}
	return false
}

// String returns the source pattern. | String 返回模式原文。
func (r *Regexp) String() string { return r.src }

// NumSubexp returns the number of capturing groups, excluding the whole match. | NumSubexp 返回捕获分组
// 数量，不含整个匹配。
func (r *Regexp) NumSubexp() int { return len(r.names) - 1 }

// SubexpNames returns the group names; index zero is always empty. | SubexpNames 返回分组名；下标 0
// 始终为空。
func (r *Regexp) SubexpNames() []string {
	out := make([]string, len(r.names))
	copy(out, r.names)
	return out
}

// SubexpIndex returns the index of the named group, or -1. | SubexpIndex 返回命名分组的下标，不存在时
// 返回 -1。
func (r *Regexp) SubexpIndex(name string) int {
	if index, ok := r.nameMap[name]; ok {
		return index
	}
	return -1
}

// MatchString reports whether s contains a match. | MatchString 报告 s 中是否存在匹配。
//
// A backtracking match that exceeds MatchTimeout is reported as no match, so validation callers fail
// closed. | 超过 MatchTimeout 的回溯匹配按未匹配处理，因此校验类调用失败关闭。
func (r *Regexp) MatchString(s string) bool {
	_, ok, err := r.execute(s, 0, 0, -1, false)
	return ok && err == nil
}

// Match reports whether b contains a match. | Match 报告 b 中是否存在匹配。
func (r *Regexp) Match(b []byte) bool { return r.MatchString(bytesToString(b)) }

// findAll returns every non-overlapping match as capture rows. | findAll 以捕获行返回每个不重叠匹配。
func (r *Regexp) findAll(s string, n, maxSlot int) ([][]int, error) {
	if n == 0 {
		return nil, nil
	}
	var out [][]int
	pos := 0
	prevEnd := -1
	for pos <= len(s) {
		caps, ok, err := r.execute(s, pos, maxSlot, -1, true)
		if err != nil {
			return out, err
		}
		if !ok {
			break
		}
		start, end := caps[0], caps[1]
		accept := true
		if start == end && start == prevEnd {
			accept = false
		}
		if accept {
			out = append(out, caps)
			if n > 0 && len(out) >= n {
				break
			}
		}
		prevEnd = end
		if start == end {
			if end >= len(s) {
				break
			}
			_, size := utf8.DecodeRuneInString(s[end:])
			pos = end + size
		} else {
			pos = end
		}
	}
	return out, nil
}

// execute runs one search. maxSlot limits capture recording; startLimit is an exclusive bound on the
// match start, or negative for no bound. preferSearch selects the NFA's own start injection for broad
// first-byte sets, which is cheaper for full scans but more expensive for a single first match. |
// execute 执行一次搜索。maxSlot 限制捕获记录；startLimit 是匹配起点的排他上界，负数表示无上界。
// preferSearch 为宽首字节集选择 NFA 自身的起点注入：完整扫描更便宜，单次首匹配更昂贵。
func (r *Regexp) execute(s string, start, maxSlot, startLimit int, preferSearch bool) ([]int, bool, error) {
	if start < 0 {
		start = 0
	}
	if start > len(s) {
		return nil, false, nil
	}
	if startLimit >= 0 && startLimit > len(s)+1 {
		startLimit = len(s) + 1
	}
	if r.exact != nil && maxSlot <= 2 {
		b, e, ok := r.exactFind(s, start, startLimit)
		if !ok {
			return nil, false, nil
		}
		if maxSlot == 2 {
			return []int{b, e}, true, nil
		}
		return nil, true, nil
	}
	if r.run != nil && maxSlot <= 2 {
		b, e, ok := r.runFind(s, start, startLimit)
		if !ok {
			return nil, false, nil
		}
		if maxSlot == 2 {
			return []int{b, e}, true, nil
		}
		return nil, true, nil
	}
	if r.wild != nil && maxSlot <= 2 {
		b, e, ok := r.wildFind(s, start, startLimit)
		if !ok {
			return nil, false, nil
		}
		if maxSlot == 2 {
			return []int{b, e}, true, nil
		}
		return nil, true, nil
	}
	if r.email != nil && maxSlot <= 2 {
		b, e, ok := r.emailFind(s, start, startLimit)
		if !ok {
			return nil, false, nil
		}
		if maxSlot == 2 {
			return []int{b, e}, true, nil
		}
		return nil, true, nil
	}
	if r.lin != nil && maxSlot <= 2 && (r.lin.anchorStart || r.lin.anchorEnd || r.prog.info.firstBytesOK) {
		b, e, ok, fallback := r.linFind(s, start, startLimit)
		if !fallback {
			if !ok {
				return nil, false, nil
			}
			if maxSlot == 2 {
				return []int{b, e}, true, nil
			}
			return nil, true, nil
		}
		// Non-ASCII input or an unsupported walk: use the general engine. | 非 ASCII 输入或不支持的
		// 遍历：使用通用引擎。
	}
	if r.dfaEligible && maxSlot <= 2 {
		r.dfaOnce.Do(func() { r.dfa = buildASCIIFullMatch(r.dfaAST, r.prog) })
		// A ^body$ pattern can only match the whole input, so the DFA answers both the boolean and
		// the index question in one linear pass. | ^body$ 模式只能匹配整个输入，因此 DFA 一次线性扫描
		// 即可回答布尔与下标问题。
		if r.dfa != nil {
			if start != 0 || (startLimit >= 0 && startLimit <= 0) || !r.dfa.match(s) {
				return nil, false, nil
			}
			if maxSlot == 2 {
				return []int{0, len(s)}, true, nil
			}
			return nil, true, nil
		}
	}
	if r.prog.info.hasBacktrack {
		// Backreferences and lookarounds need every capture slot internally even when the caller
		// only asks whether a match exists. | 反向引用与环视即使调用方只判断是否匹配，也需要全部
		// 捕获槽。
		return r.executeBacktrack(s, start, len(r.names)*2, startLimit)
	}
	m := r.pikePool.Get().(*pikeMachine)
	m.maxSlot = maxSlot
	m.capLen = maxSlot
	m.startSet = &r.prog.info.firstBytes
	m.startTables = &r.firstTables
	m.startSetOK = r.prog.info.firstBytesOK
	m.startASCIIOK = r.firstASCIISet
	ok := false
	var caps []int
	switch {
	case r.prog.info.anchored:
		if start == 0 && (startLimit < 0 || startLimit > 0) {
			ok = m.matchAt(s, 0)
			caps = m.caps()
		}
	case r.prog.info.prefixOK && (r.prog.info.selectivePrefilter || !preferSearch):
		for cand := r.nextPrefix(s, start); cand >= 0; cand = r.nextPrefix(s, cand+1) {
			if startLimit >= 0 && cand >= startLimit {
				break
			}
			if !utf8.RuneStart(s[cand]) {
				continue
			}
			if m.matchAt(s, cand) {
				ok = true
				caps = m.caps()
				break
			}
		}
	case r.prog.info.firstBytesOK && (r.prog.info.selectivePrefilter || !preferSearch):
		for cand := r.firstCandidate(s, start); cand >= 0; cand = r.firstCandidate(s, cand+1) {
			if startLimit >= 0 && cand >= startLimit {
				break
			}
			if !utf8.RuneStart(s[cand]) {
				continue
			}
			if m.matchAt(s, cand) {
				ok = true
				caps = m.caps()
				break
			}
		}
	default:
		if startLimit < 0 {
			ok = m.search(s, start)
			caps = m.caps()
			break
		}
		for cand := start; cand < startLimit && cand <= len(s); {
			if utf8.RuneStart(s[cand]) && m.matchAt(s, cand) {
				ok = true
				caps = m.caps()
				break
			}
			if cand == len(s) {
				break
			}
			_, size := utf8.DecodeRuneInString(s[cand:])
			cand += size
		}
	}
	r.pikePool.Put(m)
	if !ok {
		return nil, false, nil
	}
	return caps, true, nil
}

// executeBacktrack runs one search on the backtracking engine. | executeBacktrack 在回溯引擎上执行一次
// 搜索。
func (r *Regexp) executeBacktrack(s string, start, maxSlot, startLimit int) ([]int, bool, error) {
	m := r.btPool.Get().(*btMachine)
	m.maxSlot = maxSlot
	if cap(m.caps) < maxSlot {
		m.caps = make([]int, maxSlot)
	} else {
		m.caps = m.caps[:maxSlot]
	}
	caps, ok, err := m.findFrom(r, s, start, startLimit)
	m.caps = m.caps[:0]
	r.btPool.Put(m)
	return caps, ok, err
}

// asciiFoldPrefix reports whether every prefix rune and every rune in its simple-fold orbit is ASCII.
// When true, folding can be checked byte by byte. | asciiFoldPrefix 报告前缀的每个符文及其简单折叠轨道
// 中的每个符文是否都是 ASCII。为 true 时可按字节检查折叠。
func asciiFoldPrefix(prefix []rune) bool {
	for _, r := range prefix {
		if r >= utf8.RuneSelf {
			return false
		}
		for f := unicode.SimpleFold(r); f != r; f = unicode.SimpleFold(f) {
			if f >= utf8.RuneSelf {
				return false
			}
		}
	}
	return true
}

// bytesToString views b as a string without copying. The result must not outlive b. | bytesToString 在
// 不复制的情况下把 b 视为字符串；结果不得比 b 存活更久。
func bytesToString(b []byte) string {
	if len(b) == 0 {
		return ""
	}
	return unsafe.String(unsafe.SliceData(b), len(b))
}
