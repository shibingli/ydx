package waf

import (
	"io/fs"
	"os"
	"path"
	"strconv"
	"strings"
	"unicode/utf8"

	"github.com/shibingli/ydx/errs"
	"github.com/shibingli/ydx/regexpx"
)

// opKind enumerates built-in SecLang operators. | opKind 枚举内置 SecLang 算子。
type opKind uint8

// Built-in operator kinds. | 内置算子类型。
const (
	opRx opKind = iota
	opContains
	opContainsWord
	opBeginsWith
	opEndsWith
	opEq
	opNe
	opGt
	opGe
	opLt
	opLe
	opStrMatch
	opStrEq
	opWithin
	opUnconditional
	opNoMatch
	opPM
	opPMFromFile
	opIPMatch
	opIPMatchFromFile
	opValidateByteRange
	opValidateURLEncoding
	opValidateUTF8
	opDetectSQLi
	opDetectXSS
)

// operatorL1 caches the most recent negative operator result for one rule evaluation. Repeated
// values in a collection therefore skip the operator scan. Positive results are not cached because
// callers may need captures. | operatorL1 缓存单条规则求值中最近的否定算子结果。集合中的重复取值因此
// 跳过算子扫描。肯定结果不缓存，因为调用方可能需要捕获组。
type operatorL1 struct {
	input string
	hit   bool
	valid bool
}

// operator is one compiled SecLang operator. | operator 是一个编译后的 SecLang 算子。
type operator struct {
	re           *regexpx.Regexp
	prefilter    string
	needle       string
	matcher      *acMatcher
	needleFilter *needleFilter
	byteSet      [4]uint64
	ips          *ipMatcher
	argMacro     *macro
	name         string
	raw          string
	arg          string
	argNumber    float64
	ranges       byteRanges
	kind         opKind
	minLen       int
	argNumberOK  bool
	needleFold   bool
	byteSetFold  bool
	hasByteSet   bool
	negated      bool
}

// compileContext supplies filesystem and diagnostics to operator compilation. | compileContext
// 为算子编译提供文件系统与诊断。
type compileContext struct {
	fsys       fs.FS
	warn       func(string)
	baseDir    string
	regexCache map[string]*regexpx.Regexp
	strict     bool
}

// supportedOperators lists the operator names accepted by the engine. | supportedOperators 列出
// 引擎接受的算子名称。
var supportedOperators = map[string]opKind{
	"rx":                   opRx,
	"contains":             opContains,
	"containsword":         opContainsWord,
	"beginswith":           opBeginsWith,
	"endswith":             opEndsWith,
	"eq":                   opEq,
	"ne":                   opNe,
	"gt":                   opGt,
	"ge":                   opGe,
	"lt":                   opLt,
	"le":                   opLe,
	"strmatch":             opStrMatch,
	"streq":                opStrEq,
	"within":               opWithin,
	"unconditionalmatch":   opUnconditional,
	"nomatch":              opNoMatch,
	"pm":                   opPM,
	"pmfromfile":           opPMFromFile,
	"ipmatch":              opIPMatch,
	"ipmatchf":             opIPMatchFromFile,
	"ipmatchfromfile":      opIPMatchFromFile,
	"validatebyterange":    opValidateByteRange,
	"validateurlencoding":  opValidateURLEncoding,
	"validateutf8encoding": opValidateUTF8,
	"detectsqli":           opDetectSQLi,
	"detectxss":            opDetectXSS,
}

// compileOperator builds an operator from its SecLang name and argument. | compileOperator 从
// SecLang 名称与参数构建算子。
func compileOperator(negated bool, name, arg string, cc compileContext) (*operator, error) {
	trimmed := strings.TrimSpace(name)
	lower := strings.ToLower(strings.TrimPrefix(trimmed, "@"))
	kind, ok := supportedOperators[lower]
	if !ok {
		return nil, errs.Detail(ErrUnsupported, "unsupported operator %q | 不支持的算子 %q", name, name)
	}
	op := &operator{kind: kind, name: trimmed, raw: arg, negated: negated}
	switch kind {
	case opRx:
		if arg == "" {
			return nil, errs.Detail(ErrParse, "@rx requires a pattern | @rx 需要模式")
		}
		var compiled *regexpx.Regexp
		if cc.regexCache != nil {
			compiled = cc.regexCache[arg]
		}
		if compiled == nil {
			var err error
			compiled, err = regexpx.Compile(arg)
			if err != nil {
				return nil, errs.WrapDetail(err, ErrParse, "invalid @rx pattern | 非法的 @rx 模式")
			}
			if cc.regexCache != nil {
				cc.regexCache[arg] = compiled
			}
		}
		op.re = compiled
		// Every match begins with the literal prefix, so a value that does not contain it cannot
		// match. This skips the regex engine for most non-matching values. | 每个匹配都以该字面量
		// 前缀开始，因此不包含它的取值不可能匹配。这样大多数未命中的取值无需进入正则引擎。
		if prefix, _ := compiled.LiteralPrefix(); prefix != "" &&
			(!hasInlineCaseInsensitive(arg) || !hasASCIILetter(prefix)) {
			op.prefilter = prefix
		}
		// A mandatory required-literal set or trailing literal filters patterns whose prefix is
		// empty, which is the common case for the expensive generated CRS expressions. |
		// 必需的必需字面量集合或尾部字面量可以过滤前缀为空的模式，而这正是昂贵 CRS 生成表达式的常见情况。
		analysis := analyzeRegex(arg)
		op.minLen = analysis.minLen
		op.byteSet = analysis.bytes
		op.hasByteSet = analysis.hasBytes
		op.byteSetFold = analysis.fold && analysis.hasBytes
		if analysis.hasNeedles && len(analysis.needles) > 1 {
			op.needleFilter = newNeedleFilter(analysis.needles, analysis.fold)
		}
		suffix, suffixFold, suffixOK := regexSuffixNeedle(arg)
		if suffixOK && usefulNeedle(suffix) &&
			(!analysis.hasNeedles || len(analysis.needles) != 1 || len(suffix) >= len(analysis.needles[0])) {
			op.needle = suffix
			op.needleFold = suffixFold
		}
		if op.needle == "" && analysis.hasNeedles && len(analysis.needles) == 1 && usefulNeedle(analysis.needles[0]) {
			op.needle = analysis.needles[0]
			op.needleFold = analysis.fold
		}
	case opPM:
		patterns := strings.Fields(arg)
		if len(patterns) == 0 {
			return nil, errs.Detail(ErrParse, "@pm requires at least one pattern | @pm 至少需要一个模式")
		}
		op.matcher = newACMatcher(patterns)
	case opPMFromFile:
		lines, err := readOperatorFile(cc, arg)
		if err != nil {
			return nil, errs.WrapDetail(err, ErrParse, "cannot read @pmFromFile file | 无法读取 @pmFromFile 文件")
		}
		op.matcher = newACMatcher(lines)
	case opIPMatch:
		parsed, err := parseIPMatcher(strings.FieldsFunc(arg, func(r rune) bool { return r == ',' || r == ' ' || r == '\t' }))
		if err != nil {
			return nil, errs.Wrap(err, ErrParse)
		}
		op.ips = parsed
	case opIPMatchFromFile:
		lines, err := readOperatorFile(cc, arg)
		if err != nil {
			return nil, errs.WrapDetail(err, ErrParse, "cannot read @ipMatchFromFile file | 无法读取 @ipMatchFromFile 文件")
		}
		parsed, err := parseIPMatcher(lines)
		if err != nil {
			return nil, errs.Wrap(err, ErrParse)
		}
		op.ips = parsed
	case opValidateByteRange:
		ranges, err := parseByteRanges(arg)
		if err != nil {
			return nil, errs.Wrap(err, ErrParse)
		}
		op.ranges = ranges
	case opDetectSQLi, opDetectXSS, opValidateURLEncoding, opValidateUTF8, opUnconditional, opNoMatch:
		// These operators take no argument. | 这些算子不接受参数。
	case opContains, opContainsWord, opBeginsWith, opEndsWith, opEq, opNe, opGt, opGe, opLt, opLe, opStrMatch, opStrEq, opWithin:
		if arg == "" {
			return nil, errs.Detail(ErrParse, "operator %s requires an argument | 算子 %s 需要参数", name, name)
		}
		if strings.Contains(arg, "%{") {
			compiled, err := compileMacro(arg)
			if err != nil {
				return nil, err
			}
			op.argMacro = &compiled
		} else {
			op.arg = arg
			if kind >= opEq && kind <= opLe {
				op.argNumber, op.argNumberOK = parseOperatorNumber(arg)
			}
		}
	}
	return op, nil
}

// eval applies the operator to one value. capture selects whether regex submatches are
// materialized. | eval 对一个取值应用算子；capture 决定是否生成正则子匹配。
func (o *operator) eval(tx *transaction, value string, capture bool) (bool, []string) {
	return o.evalWithBuffer(tx, value, capture, false)
}

// evalWithBuffer is eval with optional reuse of the transaction capture buffer. Reuse is only
// enabled for a single, non-multiMatch regex result; the caller must consume or copy the returned
// groups before evaluating another value. | evalWithBuffer 是 eval 的变体，可选复用事务捕获缓冲区。
// 仅对单个、非 multiMatch 的正则结果启用；调用方必须在求值下一个取值前消费或复制返回的分组。
func (o *operator) evalWithBuffer(tx *transaction, value string, capture, reuse bool) (bool, []string) {
	matched, groups := o.match(tx, value, capture, reuse)
	if o.negated {
		return !matched, nil
	}
	return matched, groups
}

// match dispatches to the concrete operator implementation. | match 分派到具体算子实现。
func (o *operator) match(tx *transaction, value string, capture, reuse bool) (bool, []string) {
	switch o.kind {
	case opRx:
		if o.minLen > 0 && len(value) < o.minLen {
			return false, nil
		}
		if o.prefilter != "" && !strings.Contains(value, o.prefilter) {
			return false, nil
		}
		if o.needle != "" && !containsNeedle(value, o.needle, o.needleFold) {
			return false, nil
		}
		if o.needleFilter != nil && !o.needleFilter.match(value) {
			return false, nil
		}
		if o.hasByteSet && !containsByteSet(value, o.byteSet, o.byteSetFold) {
			return false, nil
		}
		if capture {
			if reuse && tx != nil && !tx.parallelEval {
				groups := o.re.FindStringSubmatchInto(tx.captureScratch[:0], value)
				if groups != nil {
					tx.captureScratch = groups
				}
				return len(groups) > 0, groups
			}
			groups := o.re.FindStringSubmatch(value)
			return len(groups) > 0, groups
		}
		return o.re.MatchString(value), nil
	case opContains:
		return strings.Contains(value, o.argument(tx)), nil
	case opContainsWord:
		return containsWord(value, o.argument(tx)), nil
	case opBeginsWith:
		return strings.HasPrefix(value, o.argument(tx)), nil
	case opEndsWith:
		return strings.HasSuffix(value, o.argument(tx)), nil
	case opEq, opNe, opGt, opGe, opLt, opLe:
		return o.compareNumeric(tx, value), nil
	case opStrMatch:
		return wildcardMatch(value, o.argument(tx)), nil
	case opStrEq:
		return value == o.argument(tx), nil
	case opWithin:
		return strings.Contains(o.argument(tx), value), nil
	case opUnconditional:
		return true, nil
	case opNoMatch:
		return false, nil
	case opPM, opPMFromFile:
		return o.matcher.match(value), nil
	case opIPMatch, opIPMatchFromFile:
		return o.ips.match(value), nil
	case opValidateByteRange:
		// Validation operators match on invalid input, matching ModSecurity/Coraza semantics.
		// | 校验类算子在输入非法时命中，与 ModSecurity/Coraza 语义一致。
		return !o.ranges.valid(value), nil
	case opValidateURLEncoding:
		return !validURLEncoding(value), nil
	case opValidateUTF8:
		return !utf8.ValidString(value), nil
	case opDetectSQLi:
		injected, fingerprint := detectSQLi(value)
		if injected {
			return true, []string{fingerprint}
		}
		return false, nil
	case opDetectXSS:
		return detectXSS(value), nil
	default:
		return false, nil
	}
}

// hasInlineCaseInsensitive reports whether a pattern enables the inline case-insensitive flag.
// The literal prefix probe is case-sensitive, so such patterns skip the prefilter rather than
// risk a false negative. | hasInlineCaseInsensitive 报告模式是否启用内联大小写不敏感标志。字面量
// 前缀探测区分大小写，因此这类模式跳过预过滤以避免漏报。
func hasInlineCaseInsensitive(pattern string) bool {
	return strings.Contains(pattern, "(?i")
}

// hasASCIILetter reports whether s contains an ASCII letter, which is the only class affected by
// the case-insensitive flag. | hasASCIILetter 报告 s 是否包含 ASCII 字母，即大小写标志唯一影响的
// 字符类。
func hasASCIILetter(s string) bool {
	for i := 0; i < len(s); i++ {
		c := s[i]
		if (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') {
			return true
		}
	}
	return false
}

// argument returns the operator argument, expanding macros when present. | argument 返回算子参数，
// 存在宏时展开。
func (o *operator) argument(tx *transaction) string {
	if o.argMacro != nil {
		return o.argMacro.expand(tx)
	}
	return o.arg
}

// containsWord reports whether value contains needle delimited by non-word bytes. | containsWord
// 报告 value 是否包含以非单词字节分隔的 needle。
func containsWord(value, needle string) bool {
	if needle == "" {
		return false
	}
	for offset := 0; ; {
		idx := strings.Index(value[offset:], needle)
		if idx < 0 {
			return false
		}
		start := offset + idx
		end := start + len(needle)
		leftOK := start == 0 || !isWordByte(value[start-1])
		rightOK := end == len(value) || !isWordByte(value[end])
		if leftOK && rightOK {
			return true
		}
		offset = start + 1
	}
}

// isWordByte reports whether c belongs to the ASCII word set. | isWordByte 报告 c 是否属于 ASCII
// 单词字符集。
func isWordByte(c byte) bool {
	return c == '_' || (c >= '0' && c <= '9') || (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z')
}

// compareNumeric compares one value with the operator argument. Literal arguments are parsed once
// at compile time; macro arguments are expanded and parsed per evaluation. | compareNumeric 比较一个
// 取值与算子参数。字面量参数在编译期解析一次；宏参数在每次求值时展开并解析。
func (o *operator) compareNumeric(tx *transaction, value string) bool {
	left, ok := parseOperatorNumber(value)
	if !ok {
		return false
	}
	right := o.argNumber
	if o.argMacro != nil {
		right, ok = parseOperatorNumber(o.argument(tx))
		if !ok {
			return false
		}
	} else if !o.argNumberOK {
		return false
	}
	switch o.kind {
	case opEq:
		return left == right
	case opNe:
		return left != right
	case opGt:
		return left > right
	case opGe:
		return left >= right
	case opLt:
		return left < right
	case opLe:
		return left <= right
	default:
		return false
	}
}

// parseOperatorNumber parses a SecLang numeric operand. | parseOperatorNumber 解析 SecLang 数值操作数。
func parseOperatorNumber(value string) (float64, bool) {
	value = strings.TrimSpace(value)
	if number, ok := parseSmallInteger(value); ok {
		return number, true
	}
	number, err := strconv.ParseFloat(value, 64)
	if err != nil {
		return 0, false
	}
	return number, true
}

// parseSmallInteger parses a short decimal integer without the general float parser. Fifteen
// digits fit exactly in a float64, so the result is identical to ParseFloat for this range. |
// parseSmallInteger 使用快速路径解析短十进制整数。十五位数字可精确表示在 float64 中，因此该范围
// 内结果与 ParseFloat 一致。
func parseSmallInteger(value string) (float64, bool) {
	if len(value) == 0 || len(value) > 15 {
		return 0, false
	}
	negative := false
	index := 0
	if value[0] == '-' {
		negative = true
		index = 1
		if index == len(value) {
			return 0, false
		}
	}
	var number int64
	for ; index < len(value); index++ {
		c := value[index]
		if c < '0' || c > '9' {
			return 0, false
		}
		number = number*10 + int64(c-'0')
	}
	if negative {
		number = -number
	}
	return float64(number), true
}

// wildcardMatch matches s against a pattern containing '*' and '?'. | wildcardMatch 用包含 '*' 与
// '?' 的模式匹配 s。
func wildcardMatch(s, pattern string) bool {
	if !strings.ContainsAny(pattern, "*?") {
		return s == pattern
	}
	si, pi := 0, 0
	star, mark := -1, 0
	for si < len(s) {
		if pi < len(pattern) && (pattern[pi] == '?' || pattern[pi] == s[si]) {
			si++
			pi++
			continue
		}
		if pi < len(pattern) && pattern[pi] == '*' {
			star = pi
			mark = si
			pi++
			continue
		}
		if star >= 0 {
			pi = star + 1
			mark++
			si = mark
			continue
		}
		return false
	}
	for pi < len(pattern) && pattern[pi] == '*' {
		pi++
	}
	return pi == len(pattern)
}

// validURLEncoding reports whether every percent escape is well formed and the decoded value is
// valid UTF-8. | validURLEncoding 报告每个百分号转义是否格式正确且解码后是合法 UTF-8。
func validURLEncoding(s string) bool {
	decoded := make([]byte, 0, len(s))
	for i := 0; i < len(s); i++ {
		if s[i] != '%' {
			decoded = append(decoded, s[i])
			continue
		}
		if i+2 >= len(s) {
			return false
		}
		value, ok := parseHex(s[i+1 : i+3])
		if !ok {
			return false
		}
		decoded = append(decoded, byte(value))
		i += 2
	}
	return utf8.Valid(decoded)
}

// readOperatorFile reads an operator data file from the configured filesystem. | readOperatorFile
// 从配置的文件系统读取算子数据文件。
func readOperatorFile(cc compileContext, name string) ([]string, error) {
	name = strings.TrimSpace(name)
	if name == "" {
		return nil, errs.Detail(ErrParse, "empty operator data file | 空的算子数据文件")
	}
	candidates := []string{name}
	if cc.baseDir != "" && !path.IsAbs(name) {
		candidates = append(candidates, path.Join(cc.baseDir, name))
	}
	var data []byte
	var err error
	for _, candidate := range candidates {
		if cc.fsys != nil {
			data, err = fs.ReadFile(cc.fsys, candidate)
		} else {
			data, err = os.ReadFile(candidate)
		}
		if err == nil {
			break
		}
	}
	if err != nil {
		return nil, errs.Wrap(err, ErrSource)
	}
	lines := make([]string, 0, 64)
	for _, line := range strings.Split(string(data), "\n") {
		line = strings.TrimSpace(strings.TrimSuffix(line, "\r"))
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		lines = append(lines, line)
	}
	if len(lines) == 0 {
		return nil, errs.Detail(ErrParse, "operator data file %q is empty | 算子数据文件 %q 为空", name, name)
	}
	return lines, nil
}
