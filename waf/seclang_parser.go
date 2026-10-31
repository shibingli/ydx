package waf

import (
	"strconv"
	"strings"

	"github.com/shibingli/ydx/errs"
)

// directiveKind classifies one parsed SecLang directive. | directiveKind 对一条已解析的 SecLang 指令分类。
type directiveKind uint8

// Directive kinds produced by the parser. | 解析器产生的指令类型。
const (
	dirRule directiveKind = iota
	dirAction
	dirMarker
	dirDefaultAction
	dirUpdateActionByID
	dirUpdateTargetByID
	dirUpdateTargetByTag
	dirUpdateTargetByMsg
	dirRemoveByID
	dirRemoveByTag
	dirRemoveByMsg
	dirRemoveTargetByID
	dirConfig
)

// parsedDirective is one parsed directive with source location. | parsedDirective 是带源码位置的一条
// 已解析指令。
type parsedDirective struct {
	Name string
	File string
	Raw  string
	Args []string
	Line int
	Kind directiveKind
}

// parseOptions controls parser strictness and warning collection. | parseOptions 控制解析器严格性与警告收集。
type parseOptions struct {
	Warn   func(string)
	Strict bool
}

// knownConfigDirectives lists SecLang configuration directives the engine accepts. Directives
// whose value does not affect inspection are parsed and ignored; the remainder are validated
// during compilation. | knownConfigDirectives 列出引擎接受的 SecLang 配置指令。不影响检测的指令
// 解析后忽略，其余在编译期校验。
var knownConfigDirectives = map[string]struct{}{
	"SecRuleEngine":                 {},
	"SecRequestBodyAccess":          {},
	"SecResponseBodyAccess":         {},
	"SecRequestBodyLimit":           {},
	"SecRequestBodyInMemoryLimit":   {},
	"SecRequestBodyNoFilesLimit":    {},
	"SecRequestBodyJsonDepthLimit":  {},
	"SecResponseBodyLimit":          {},
	"SecResponseBodyMimeType":       {},
	"SecRequestBodyLimitAction":     {},
	"SecResponseBodyLimitAction":    {},
	"SecArgumentsLimit":             {},
	"SecArgumentSeparator":          {},
	"SecCollectionTimeout":          {},
	"SecAuditEngine":                {},
	"SecAuditLog":                   {},
	"SecAuditLogParts":              {},
	"SecAuditLogType":               {},
	"SecAuditLogStorageDir":         {},
	"SecAuditLogRelevantStatus":     {},
	"SecDataDir":                    {},
	"SecTmpDir":                     {},
	"SecDebugLog":                   {},
	"SecDebugLogLevel":              {},
	"SecPcreMatchLimit":             {},
	"SecPcreMatchLimitRecursion":    {},
	"SecUnicodeMapFile":             {},
	"SecUnicodeCodePage":            {},
	"SecCookieFormat":               {},
	"SecComponentSignature":         {},
	"SecServerSignature":            {},
	"SecSensorId":                   {},
	"SecUploadDir":                  {},
	"SecUploadKeepFiles":            {},
	"SecUploadFileLimit":            {},
	"SecUploadFileMode":             {},
	"SecContentInjection":           {},
	"SecStreamInBodyInspection":     {},
	"SecRuleInheritance":            {},
	"SecConnReadStateLimit":         {},
	"SecConnWriteStateLimit":        {},
	"SecHashEngine":                 {},
	"SecHashKey":                    {},
	"SecHashMethodPm":               {},
	"SecHashMethodRx":               {},
	"SecRulePerfTime":               {},
	"SecDisableBackendCompression":  {},
	"SecCacheTransformations":       {},
	"SecResponseSingleContentType":  {},
	"SecXmlExternalEntity":          {},
	"SecAuditLogFormat":             {},
	"SecConnEngine":                 {},
	"SecGeoLookupDb":                {},
	"SecGsbLookupDb":                {},
	"SecVerifyDestination":          {},
	"SecStreamOutBodyInspection":    {},
	"SecRuleRemoveById":             {},
	"SecRuleRemoveByTag":            {},
	"SecRuleRemoveByMsg":            {},
	"SecRuleRemoveTargetById":       {},
	"SecRuleUpdateActionById":       {},
	"SecRuleUpdateTargetById":       {},
	"SecRuleUpdateTargetByTag":      {},
	"SecRuleUpdateTargetByMsg":      {},
	"SecMarker":                     {},
	"SecDefaultAction":              {},
	"SecAction":                     {},
	"SecRule":                       {},
	"Include":                       {},
	"IncludeOptional":               {},
	"SecRuleScript":                 {},
	"SecRuleUpdateTargetByMetaData": {},
}

// unsupportedDirectives are accepted syntactically but rejected in strict mode because ignoring
// them would silently weaken protection. | unsupportedDirectives 在语法上接受，但严格模式会拒绝，
// 因为忽略它们会悄悄削弱防护。
var unsupportedDirectives = map[string]struct{}{
	"SecRuleScript":                 {},
	"SecRuleUpdateTargetByMetaData": {},
	"SecRemoteRules":                {},
	"SecRemoteRulesFailAction":      {},
}

// parseSecLang parses a self-contained SecLang source. Include directives must already have
// been expanded by the loader. | parseSecLang 解析自包含的 SecLang 源码；Include 指令必须已由
// 加载器展开。
func parseSecLang(src, file string, opts parseOptions) ([]parsedDirective, error) {
	lines := splitLogicalLines(src)
	out := make([]parsedDirective, 0, len(lines))
	pendingFile := ""
	pendingLine := 0
	for _, ll := range lines {
		trimmed := strings.TrimSpace(ll.text)
		if strings.HasPrefix(trimmed, "#@ydx ") {
			marker := strings.TrimPrefix(trimmed, "#@ydx ")
			if idx := strings.LastIndexByte(marker, ':'); idx > 0 {
				pendingFile = marker[:idx]
				if parsed, err := strconv.Atoi(marker[idx+1:]); err == nil {
					pendingLine = parsed
				}
			}
			continue
		}
		tokens, err := lexLine(ll.text)
		if err != nil {
			return nil, errs.WrapDetail(err, ErrParse, "%s:%d", sourceFile(file, pendingFile), sourceLine(ll.line, pendingLine))
		}
		if len(tokens) == 0 {
			continue
		}
		directiveFile := sourceFile(file, pendingFile)
		directiveLine := sourceLine(ll.line, pendingLine)
		directive, err := buildDirective(tokens, directiveFile, directiveLine, trimmed, opts)
		pendingFile = ""
		pendingLine = 0
		if err != nil {
			return nil, errs.WrapDetail(err, ErrParse, "%s:%d", directiveFile, directiveLine)
		}
		if directive != nil {
			out = append(out, *directive)
		}
	}
	return out, nil
}

// sourceFile selects the marker file when present. | sourceFile 在存在标记时选择标记文件。
func sourceFile(fallback, marker string) string {
	if marker != "" {
		return marker
	}
	return fallback
}

// sourceLine selects the marker line when present. | sourceLine 在存在标记时选择标记行号。
func sourceLine(fallback, marker int) int {
	if marker > 0 {
		return marker
	}
	return fallback
}

// buildDirective converts one tokenized line into a directive. | buildDirective 把一条标记化后的行
// 转换为指令。
func buildDirective(tokens []string, file string, line int, raw string, opts parseOptions) (*parsedDirective, error) {
	name := tokens[0]
	args := tokens[1:]
	d := &parsedDirective{Name: name, Args: args, File: file, Line: line, Raw: raw}
	switch name {
	case "SecRule":
		if len(args) < 2 || len(args) > 3 {
			return nil, errs.Detail(ErrParse, "SecRule requires variables, operator and optional actions | SecRule 需要变量、算子与可选动作")
		}
		d.Kind = dirRule
	case "SecAction":
		if len(args) != 1 {
			return nil, errs.Detail(ErrParse, "SecAction requires one action list | SecAction 需要一个动作列表")
		}
		d.Kind = dirAction
	case "SecMarker":
		if len(args) != 1 {
			return nil, errs.Detail(ErrParse, "SecMarker requires one name | SecMarker 需要一个名称")
		}
		d.Kind = dirMarker
	case "SecDefaultAction":
		if len(args) != 1 {
			return nil, errs.Detail(ErrParse, "SecDefaultAction requires one action list | SecDefaultAction 需要一个动作列表")
		}
		d.Kind = dirDefaultAction
	case "SecRuleUpdateActionById":
		if len(args) != 2 {
			return nil, errs.Detail(ErrParse, "SecRuleUpdateActionById requires an id and actions | SecRuleUpdateActionById 需要 id 与动作")
		}
		d.Kind = dirUpdateActionByID
	case "SecRuleUpdateTargetById":
		if len(args) < 2 {
			return nil, errs.Detail(ErrParse, "SecRuleUpdateTargetById requires an id and targets | SecRuleUpdateTargetById 需要 id 与目标")
		}
		d.Kind = dirUpdateTargetByID
	case "SecRuleUpdateTargetByTag":
		if len(args) < 2 {
			return nil, errs.Detail(ErrParse, "SecRuleUpdateTargetByTag requires a tag and targets | SecRuleUpdateTargetByTag 需要标签与目标")
		}
		d.Kind = dirUpdateTargetByTag
	case "SecRuleUpdateTargetByMsg":
		if len(args) < 2 {
			return nil, errs.Detail(ErrParse, "SecRuleUpdateTargetByMsg requires a message and targets | SecRuleUpdateTargetByMsg 需要消息与目标")
		}
		d.Kind = dirUpdateTargetByMsg
	case "SecRuleRemoveById":
		if len(args) == 0 {
			return nil, errs.Detail(ErrParse, "SecRuleRemoveById requires at least one id | SecRuleRemoveById 至少需要一个 id")
		}
		d.Kind = dirRemoveByID
	case "SecRuleRemoveByTag":
		if len(args) == 0 {
			return nil, errs.Detail(ErrParse, "SecRuleRemoveByTag requires at least one tag | SecRuleRemoveByTag 至少需要一个标签")
		}
		d.Kind = dirRemoveByTag
	case "SecRuleRemoveByMsg":
		if len(args) == 0 {
			return nil, errs.Detail(ErrParse, "SecRuleRemoveByMsg requires at least one message | SecRuleRemoveByMsg 至少需要一个消息")
		}
		d.Kind = dirRemoveByMsg
	case "SecRuleRemoveTargetById":
		if len(args) < 2 {
			return nil, errs.Detail(ErrParse, "SecRuleRemoveTargetById requires an id and targets | SecRuleRemoveTargetById 需要 id 与目标")
		}
		d.Kind = dirRemoveTargetByID
	case "Include", "IncludeOptional":
		return nil, errs.Detail(ErrUnsupported, "internal: include must be expanded by the loader | 内部：Include 必须由加载器展开")
	default:
		if _, ok := knownConfigDirectives[name]; !ok {
			if opts.Strict {
				return nil, errs.Detail(ErrUnsupported, "unknown directive %q | 未知指令 %q", name, name)
			}
			if opts.Warn != nil {
				opts.Warn("unknown directive skipped: " + name + " | 已跳过未知指令：" + name)
			}
			return nil, nil
		}
		if _, unsupported := unsupportedDirectives[name]; unsupported {
			if opts.Strict {
				return nil, errs.Detail(ErrUnsupported, "directive %q is not supported | 不支持指令 %q", name, name)
			}
			if opts.Warn != nil {
				opts.Warn("unsupported directive skipped: " + name + " | 已跳过不支持的指令：" + name)
			}
			return nil, nil
		}
		d.Kind = dirConfig
	}
	return d, nil
}

// splitActionList splits a SecLang action list on commas outside quotes. | splitActionList 在引号外
// 按逗号切分 SecLang 动作列表。
func splitActionList(s string) []string {
	out := make([]string, 0, 8)
	start := 0
	var quote byte
	for i := 0; i < len(s); i++ {
		c := s[i]
		if quote != 0 {
			if c == '\\' && i+1 < len(s) {
				i++
				continue
			}
			if c == quote {
				quote = 0
			}
			continue
		}
		switch c {
		case '\'', '"':
			quote = c
		case ',':
			out = append(out, strings.TrimSpace(s[start:i]))
			start = i + 1
		}
	}
	if tail := strings.TrimSpace(s[start:]); tail != "" {
		out = append(out, tail)
	}
	return out
}

// splitVarList splits a variable list on '|' outside /regex/ selectors. A selector is treated as
// a key regex only when a slash after the colon is matched by a slash followed by the end of the
// selector or '|'; this keeps XML path selectors such as XML:/* and XML://@* intact.
// | splitVarList 在 /regex/ 选择器之外按 '|' 切分变量列表。仅当冒号后的斜杠由“后接选择器结尾
// 或 '|'”的斜杠闭合时才视为键正则；这样 XML 路径选择器（如 XML:/*、XML://@*）不会被拆坏。
func splitVarList(s string) []string {
	out := make([]string, 0, 4)
	start := 0
	for i := 0; i < len(s); i++ {
		c := s[i]
		if c == '\\' && i+1 < len(s) {
			i++
			continue
		}
		if c == ':' && i+1 < len(s) && s[i+1] == '/' {
			for j := i + 2; j < len(s); j++ {
				if s[j] == '\\' && j+1 < len(s) {
					j++
					continue
				}
				if s[j] == '|' && looksLikeSelectorStart(s[j+1:]) {
					// This is an XML path selector or another non-regex key followed by the next
					// selector. | 这是后接下一个选择器的 XML 路径选择器或其他非正则键。
					break
				}
				if s[j] == '/' && (j+1 == len(s) || s[j+1] == '|') {
					i = j
					break
				}
			}
			continue
		}
		if c == '|' {
			out = append(out, strings.TrimSpace(s[start:i]))
			start = i + 1
		}
	}
	if tail := strings.TrimSpace(s[start:]); tail != "" {
		out = append(out, tail)
	}
	return out
}

// looksLikeSelectorStart reports whether text begins with a known variable selector such as
// XML: or REQUEST_URI. It prevents a key regex scan from swallowing a following selector.
// | looksLikeSelectorStart 报告 text 是否以已知变量选择器（如 XML: 或 REQUEST_URI）开头，避免
// 键正则扫描吞掉后续选择器。
func looksLikeSelectorStart(text string) bool {
	text = strings.TrimPrefix(strings.TrimSpace(text), "!")
	end := 0
	for end < len(text) && (isWordByte(text[end]) || text[end] == '_') {
		end++
	}
	if end == 0 {
		return false
	}
	name := strings.ToUpper(text[:end])
	if _, ok := knownVariables[name]; !ok {
		return false
	}
	return end == len(text) || text[end] == ':'
}

// splitOperator parses the operator token into negation, name and argument. A bare pattern means
// @rx, matching SecLang. | splitOperator 把算子标记解析为取反、名称与参数；裸模式表示 @rx，与
// SecLang 一致。
func splitOperator(s string) (negated bool, name, arg string) {
	s = strings.TrimSpace(s)
	if strings.HasPrefix(s, "!") {
		negated = true
		s = strings.TrimSpace(s[1:])
	}
	if !strings.HasPrefix(s, "@") {
		return negated, "@rx", s
	}
	if idx := strings.IndexAny(s, " \t"); idx >= 0 {
		return negated, s[:idx], strings.TrimSpace(s[idx+1:])
	}
	return negated, s, ""
}

// unquoteActionValue removes one pair of matching quotes and unescapes the quote character.
// | unquoteActionValue 去掉一对外层引号并反转义引号字符。
func unquoteActionValue(s string) string {
	s = strings.TrimSpace(s)
	if len(s) < 2 {
		return s
	}
	q := s[0]
	if (q != '\'' && q != '"') || s[len(s)-1] != q {
		return s
	}
	inner := s[1 : len(s)-1]
	if !strings.ContainsRune(inner, '\\') {
		return inner
	}
	var b strings.Builder
	b.Grow(len(inner))
	for i := 0; i < len(inner); i++ {
		if inner[i] == '\\' && i+1 < len(inner) && (inner[i+1] == q || inner[i+1] == '\\') {
			b.WriteByte(inner[i+1])
			i++
			continue
		}
		b.WriteByte(inner[i])
	}
	return b.String()
}
