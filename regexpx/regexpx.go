package regexpx

import (
	stdregexp "regexp"
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

// literalPrefixValue is the cached LiteralPrefix result. | literalPrefixValue 是缓存的
// LiteralPrefix 结果。
type literalPrefixValue struct {
	prefix   string
	complete bool
}

// compatCache holds lazily computed standard-library compatibility data shared by Regexp
// copies. | compatCache 保存 Regexp 副本共享的惰性标准库兼容数据。
type compatCache struct {
	literalOnce     sync.Once
	stdOnce         sync.Once
	dfaOnce         sync.Once
	literalResult   atomic.Pointer[literalPrefixValue]
	literalPrefix   string
	std             *stdregexp.Regexp
	dfa             *asciiDFA
	literalComplete bool
}

// Regexp is a compiled pattern. It is safe for concurrent use and must not be copied after first use.
// Configuration methods such as Longest must not run concurrently with matching. | Regexp 是已编译的
// 模式。它可安全并发使用，首次使用后不得复制。Longest 等配置方法不得与匹配并发执行。
type Regexp struct {
	prog    *program
	exact   *exactInfo
	run     *runInfo
	wild    *wildInfo
	lin     *linInfo
	email   *emailInfo
	names   []string
	nameMap map[string]int

	// compat holds lazily computed standard-library views shared by copies. | compat 保存副本共享的
	// 惰性标准库视图。
	compat *compatCache
	// longest selects leftmost-longest matching and is set by Longest and CompilePOSIX. | longest
	// 选择最左最长匹配，由 Longest 与 CompilePOSIX 设置。
	longest bool
	// posix records that the pattern was compiled with CompilePOSIX. | posix 记录模式由
	// CompilePOSIX 编译。
	posix bool

	prefixBytes     string
	prefixFoldASCII bool
	firstTables     *[128]byte
	firstASCIISet   bool

	// The full-match DFA is built lazily on first use so package-level Compile stays cheap. |
	// 全匹配 DFA 在首次使用时惰性构建，使包级 Compile 保持廉价。
	dfaEligible bool

	pikePool *sync.Pool
	btPool   *sync.Pool

	// parallelSearches counts chunked searches for observability in tests. | parallelSearches 统计
	// 分块搜索次数，供测试观测。
	parallelSearches *atomic.Int64
}

// Compile parses expr and returns a compiled pattern. | Compile 解析 expr 并返回已编译的模式。
//
// The syntax is RE2 plus the .NET constructs needed to replace regexp2: lookahead, lookbehind,
// backreferences, named groups, atomic groups and possessive quantifiers. A syntax error wraps
// ErrCompile so callers can test it with errors.Is. | 语法为 RE2 加上替换 regexp2 所需的 .NET 构造：
// 先行、后行、反向引用、命名分组、原子组与占有量词。语法错误包装 ErrCompile，调用方可用 errors.Is
// 判定。
func Compile(expr string) (*Regexp, error) {
	return compile(expr, false)
}

// CompilePOSIX is like Compile but selects leftmost-longest matching. The parser additionally
// rejects the non-POSIX escapes and groups that the standard library rejects in POSIX mode. |
// CompilePOSIX 与 Compile 相同，但选择最左最长匹配。解析器还会拒绝标准库在 POSIX 模式下拒绝的
// 非 POSIX 转义与分组。
func CompilePOSIX(expr string) (*Regexp, error) {
	return compile(expr, true)
}

// MustCompilePOSIX is like CompilePOSIX but panics when expr is invalid. | MustCompilePOSIX 与
// CompilePOSIX 相同，但 expr 非法时 panic。
func MustCompilePOSIX(expr string) *Regexp {
	r, err := CompilePOSIX(expr)
	if err != nil {
		panic(err)
	}
	return r
}

// compile parses and compiles expr. POSIX mode enables leftmost-longest matching and rejects
// syntax the standard library excludes from POSIX mode. | compile 解析并编译 expr。POSIX 模式开启
// 最左最长匹配，并拒绝标准库在 POSIX 模式下排除的语法。
func compile(expr string, posix bool) (*Regexp, error) {
	if posix {
		if err := validatePOSIX(expr); err != nil {
			return nil, errs.WrapDetail(err, ErrCompile, "pattern %[1]q | 模式 %[1]q", expr)
		}
	}
	ast, numCap, names, err := parsePatternWithMode(expr, posix)
	if err != nil {
		return nil, errs.WrapDetail(err, ErrCompile, "pattern %[1]q | 模式 %[1]q", expr)
	}
	prog, err := compilePattern(ast, numCap, names)
	if err != nil {
		return nil, errs.WrapDetail(err, ErrCompile, "pattern %[1]q | 模式 %[1]q", expr)
	}
	prog.src = expr
	r := &Regexp{
		prog:             prog,
		names:            make([]string, numCap+1),
		nameMap:          names,
		longest:          posix,
		posix:            posix,
		compat:           &compatCache{},
		pikePool:         &sync.Pool{},
		btPool:           &sync.Pool{},
		parallelSearches: &atomic.Int64{},
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
		tables, ascii := makeByteSetTables(prog.info.firstBytes)
		r.firstTables = &tables
		r.firstASCIISet = ascii
	}
	if body, ok := fullMatchBody(ast); ok && asciiBodyOnly(body) && len(prog.insts) <= dfaInstrCap {
		r.dfaEligible = true
		prog.dfaAST = ast
	}
	r.exact = analyzeExact(ast, numCap)
	r.run = analyzeRun(ast, numCap)
	r.wild = analyzeWild(ast)
	r.lin = analyzeLinear(ast, numCap)
	r.email = analyzeEmail(ast, numCap)
	r.compat.literalPrefix, r.compat.literalComplete = stdLiteralPrefix(ast)
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
func (r *Regexp) String() string { return r.prog.src }

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
	err := r.forEachMatch(s, n, maxSlot, func(caps []int) bool {
		out = append(out, append([]int(nil), caps...))
		return n > 0 && len(out) >= n
	})
	return out, err
}

// forEachMatch calls fn for every non-overlapping match. fn returns true to stop early. The empty
// match rule matches findAll: an empty match abutting the previous match is skipped. |
// forEachMatch 对每个不重叠匹配调用 fn；fn 返回 true 时提前停止。空匹配规则与 findAll 一致：
// 紧邻上一个匹配的空匹配会被跳过。
func (r *Regexp) forEachMatch(s string, n, maxSlot int, fn func(caps []int) bool) error {
	if n == 0 {
		return nil
	}
	var scratch []int
	if maxSlot > 0 && maxSlot <= 2 {
		scratch = make([]int, 2)
	}
	pos := 0
	prevEnd := -1
	count := 0
	for pos <= len(s) {
		caps, ok, err := r.executeInto(s, pos, maxSlot, -1, true, scratch)
		if err != nil {
			return err
		}
		if !ok {
			return nil
		}
		start, end := caps[0], caps[1]
		if start != end || start != prevEnd {
			count++
			if fn(caps) || (n > 0 && count >= n) {
				return nil
			}
		}
		prevEnd = end
		if start == end {
			if end >= len(s) {
				return nil
			}
			_, size := utf8.DecodeRuneInString(s[end:])
			pos = end + size
		} else {
			pos = end
		}
	}
	return nil
}

// fillCaps returns the group-zero capture pair, reusing dst when possible. | fillCaps 返回分组 0
// 的捕获对，尽可能复用 dst。
func fillCaps(dst []int, start, end, maxSlot int) []int {
	if maxSlot != 2 {
		return nil
	}
	if dst == nil {
		return []int{start, end}
	}
	dst[0], dst[1] = start, end
	return dst[:2]
}

// execute runs one search. maxSlot limits capture recording; startLimit is an exclusive bound on the
// match start, or negative for no bound. preferSearch selects the NFA's own start injection for broad
// first-byte sets, which is cheaper for full scans but more expensive for a single first match. |
// execute 执行一次搜索。maxSlot 限制捕获记录；startLimit 是匹配起点的排他上界，负数表示无上界。
// preferSearch 为宽首字节集选择 NFA 自身的起点注入：完整扫描更便宜，单次首匹配更昂贵。
func (r *Regexp) execute(s string, start, maxSlot, startLimit int, preferSearch bool) ([]int, bool, error) {
	return r.executeInto(s, start, maxSlot, startLimit, preferSearch, nil)
}

// executeInto is execute with an optional caller-provided capture buffer for maxSlot <= 2. When
// dst has room the result aliases dst, so callers must consume it before the next search. |
// executeInto 是带可选调用方捕获缓冲的 execute，适用于 maxSlot <= 2。dst 有足够空间时结果会
// 别名 dst，调用方必须在下次搜索前消费完毕。
func (r *Regexp) executeInto(s string, start, maxSlot, startLimit int, preferSearch bool, dst []int) ([]int, bool, error) {
	if start < 0 {
		start = 0
	}
	if start > len(s) {
		return nil, false, nil
	}
	if startLimit >= 0 && startLimit > len(s)+1 {
		startLimit = len(s) + 1
	}
	// Longest keeps only specialized paths whose result is inherently leftmost-longest: exact
	// literals, greedy runs, wildcard-literal shapes, fixed-length linear shapes and the anchored
	// full-match DFA. Email and lazy/variable shapes fall through to the general engine. |
	// 最长模式只保留结果天然是最左最长的专用路径：整字面量、贪婪运行、通配字面量形态、定长线性形态
	// 与锚定全匹配 DFA。邮箱与惰性/变长形态回退到通用引擎。
	if r.longest && r.prog.info.hasBacktrack {
		return r.executeBacktrackLongest(s, start, len(r.names)*2, startLimit)
	}
	{
		if r.exact != nil && maxSlot <= 2 {
			b, e, ok := r.exactFind(s, start, startLimit)
			if !ok {
				return nil, false, nil
			}
			if maxSlot == 2 {
				return fillCaps(dst, b, e, maxSlot), true, nil
			}
			return nil, true, nil
		}
		if r.run != nil && maxSlot <= 2 && (!r.longest || r.run.greedy) {
			b, e, ok := r.runFind(s, start, startLimit)
			if !ok {
				return nil, false, nil
			}
			if maxSlot == 2 {
				return fillCaps(dst, b, e, maxSlot), true, nil
			}
			return nil, true, nil
		}
		if r.wild != nil && maxSlot <= 2 {
			b, e, ok := r.wildFind(s, start, startLimit)
			if !ok {
				return nil, false, nil
			}
			if maxSlot == 2 {
				return fillCaps(dst, b, e, maxSlot), true, nil
			}
			return nil, true, nil
		}
		if r.email != nil && maxSlot <= 2 && !r.longest {
			b, e, ok := r.emailFind(s, start, startLimit)
			if !ok {
				return nil, false, nil
			}
			if maxSlot == 2 {
				return fillCaps(dst, b, e, maxSlot), true, nil
			}
			return nil, true, nil
		}
		if r.lin != nil && maxSlot <= 2 && (!r.longest || !r.lin.variable) && (r.lin.anchorStart || r.lin.anchorEnd || r.prog.info.firstBytesOK) {
			b, e, ok, fallback := r.linFind(s, start, startLimit)
			if !fallback {
				if !ok {
					return nil, false, nil
				}
				if maxSlot == 2 {
					return fillCaps(dst, b, e, maxSlot), true, nil
				}
				return nil, true, nil
			}
			// Non-ASCII input or an unsupported walk: use the general engine. | 非 ASCII 输入或不支持的
			// 遍历：使用通用引擎。
		}
		if r.dfaEligible && maxSlot <= 2 {
			r.compat.dfaOnce.Do(func() { r.compat.dfa = buildASCIIFullMatch(r.prog.dfaAST, r.prog) })
			// A ^body$ pattern can only match the whole input, so the DFA answers both the boolean and
			// the index question in one linear pass. | ^body$ 模式只能匹配整个输入，因此 DFA 一次线性扫描
			// 即可回答布尔与下标问题。
			if r.compat.dfa != nil {
				if start != 0 || (startLimit >= 0 && startLimit <= 0) || !r.compat.dfa.match(s) {
					return nil, false, nil
				}
				if maxSlot == 2 {
					return []int{0, len(s)}, true, nil
				}
				return nil, true, nil
			}
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
	m.startTables = r.firstTables
	m.startSetOK = r.prog.info.firstBytesOK
	m.startASCIIOK = r.firstASCIISet
	m.longest = r.longest
	ok := false
	var caps []int
	switch {
	case r.prog.info.anchored:
		if start == 0 && (startLimit < 0 || startLimit > 0) {
			ok = m.matchAt(s, 0)
			caps = m.capsInto(dst)
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
				caps = m.capsInto(dst)
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
				caps = m.capsInto(dst)
				break
			}
		}
	default:
		if startLimit < 0 {
			ok = m.search(s, start)
			caps = m.capsInto(dst)
			break
		}
		for cand := start; cand < startLimit && cand <= len(s); {
			if utf8.RuneStart(s[cand]) && m.matchAt(s, cand) {
				ok = true
				caps = m.capsInto(dst)
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

// executeBacktrackLongest runs one leftmost-longest search on the backtracking engine. Patterns
// with lookaround or backreferences cannot use the Pike VM, so each candidate end is tested from
// the longest down until one matches. | executeBacktrackLongest 在回溯引擎上执行一次最左最长搜索。
// 含环视或反向引用的模式无法使用 Pike VM，因此从最长的候选结束位置向下测试，直到某个位置匹配。
func (r *Regexp) executeBacktrackLongest(s string, start, maxSlot, startLimit int) ([]int, bool, error) {
	m := r.btPool.Get().(*btMachine)
	m.maxSlot = maxSlot
	if cap(m.caps) < maxSlot {
		m.caps = make([]int, maxSlot)
	} else {
		m.caps = m.caps[:maxSlot]
	}
	caps, ok, err := m.findFromLongest(r, s, start, startLimit)
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

// stdRegexp returns a lazily compiled standard-library view of the same pattern, or nil when the
// pattern uses regexpx-only constructs. Longest submatch and replacement methods use it as the
// compatibility oracle for POSIX subexpression semantics. | stdRegexp 返回同一模式的惰性标准库视图；
// 模式使用 regexpx 独有构造时返回 nil。Longest 的子匹配与替换方法用它作为 POSIX 子表达式语义的
// 兼容 oracle。
func (r *Regexp) stdRegexp() *stdregexp.Regexp {
	if r.compat == nil {
		return nil
	}
	r.compat.stdOnce.Do(func() {
		var re *stdregexp.Regexp
		var err error
		if r.posix {
			re, err = stdregexp.CompilePOSIX(r.prog.src)
		} else {
			re, err = stdregexp.Compile(r.prog.src)
		}
		if err == nil {
			re.Longest()
			r.compat.std = re
		}
	})
	return r.compat.std
}
