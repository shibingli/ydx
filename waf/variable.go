package waf

import (
	"net"
	"net/http"
	"path"
	"strconv"
	"strings"

	"github.com/shibingli/ydx/errs"
	"github.com/shibingli/ydx/regexpx"
)

// varValue is one value of a variable collection. | varValue 是变量集合中的一个取值。
type varValue struct {
	Name  string
	Key   string
	Value string
	Size  int64
}

// varSelector selects values from one transaction collection. | varSelector 从事务集合中选择取值。
type varSelector struct {
	Name             string
	Key              string
	KeyRe            *regexpx.Regexp
	Exclusions       []varSelector
	scalar           bool
	Count            bool
	exclusionsSelf   bool
	simpleCollection bool
	txHash           uint64
}

// knownVariables lists every variable the engine understands. Unknown variables are a compile
// error in strict mode. | knownVariables 列出引擎理解的全部变量；严格模式下未知变量是编译错误。
var knownVariables = map[string]struct{}{
	"ARGS": {}, "ARGS_NAMES": {}, "ARGS_GET": {}, "ARGS_GET_NAMES": {},
	"ARGS_POST": {}, "ARGS_POST_NAMES": {}, "ARGS_COMBINED_SIZE": {}, "FILES": {},
	"FILES_NAMES": {}, "FILES_SIZES": {}, "FILES_TMPNAMES": {}, "FILES_COMBINED_SIZE": {},
	"MULTIPART_PART_HEADERS": {}, "MULTIPART_PART_HEADERS_NAMES": {}, "REQUEST_HEADERS": {},
	"REQUEST_HEADERS_NAMES": {}, "REQUEST_COOKIES": {}, "REQUEST_COOKIES_NAMES": {},
	"REQUEST_URI": {}, "REQUEST_URI_RAW": {}, "REQUEST_LINE": {}, "REQUEST_FILENAME": {},
	"REQUEST_BASENAME": {}, "REQUEST_METHOD": {}, "REQUEST_PROTOCOL": {},
	"QUERY_STRING": {}, "REQUEST_BODY": {}, "REQUEST_BODY_LENGTH": {},
	"RESPONSE_BODY": {}, "RESPONSE_BODY_LENGTH": {}, "RESPONSE_HEADERS": {},
	"RESPONSE_HEADERS_NAMES": {}, "RESPONSE_STATUS": {}, "RESPONSE_PROTOCOL": {},
	"REMOTE_ADDR": {}, "REMOTE_HOST": {}, "REMOTE_PORT": {}, "SERVER_NAME": {},
	"SERVER_PORT": {}, "SERVER_ADDR": {}, "SERVER_PROTOCOL": {}, "UNIQUE_ID": {},
	"TX": {}, "IP": {}, "SESSION": {}, "USER": {}, "MATCHED_VAR": {},
	"MATCHED_VAR_NAME": {}, "MATCHED_VARS": {}, "MATCHED_VARS_NAMES": {},
	"RULE": {}, "ENGINE": {}, "DURATION": {}, "TIME": {}, "TIME_YEAR": {},
	"TIME_MON": {}, "TIME_DAY": {}, "TIME_HOUR": {}, "TIME_MIN": {}, "TIME_SEC": {},
	"TIME_WDAY": {}, "TIME_EPOCH": {}, "MULTIPART_STRICT_ERROR": {},
	"MULTIPART_UNMATCHED_BOUNDARY": {}, "URLENCODED_ERROR": {}, "REQBODY_ERROR": {},
	"REQBODY_ERROR_MSG": {}, "REQBODY_PROCESSOR": {}, "JSON": {}, "XML": {},
	"FULL_REQUEST": {}, "FULL_REQUEST_LENGTH": {}, "HIGHEST_SEVERITY": {},
}

// parseVarSelector parses one selector. It reports whether the selector was prefixed with '!'.
// | parseVarSelector 解析一个选择器，并报告其是否以 '!' 前缀表示排除。
func parseVarSelector(raw string) (varSelector, bool, error) {
	s := strings.TrimSpace(raw)
	exclude := false
	if strings.HasPrefix(s, "!") {
		exclude = true
		s = strings.TrimSpace(s[1:])
	}
	count := false
	if strings.HasPrefix(s, "&") {
		count = true
		s = strings.TrimSpace(s[1:])
	}
	if s == "" {
		return varSelector{}, false, errs.Detail(ErrParse, "empty variable selector | 空变量选择器")
	}
	name := s
	key := ""
	if idx := strings.IndexByte(s, ':'); idx >= 0 {
		name = s[:idx]
		key = s[idx+1:]
	}
	name = strings.ToUpper(strings.TrimSpace(name))
	if _, ok := knownVariables[name]; !ok {
		return varSelector{}, false, errs.Detail(ErrUnsupported, "unknown variable %q | 未知变量 %q", name, name)
	}
	selector := varSelector{Name: name, Key: key, Count: count}
	if len(key) >= 2 && key[0] == '/' && key[len(key)-1] == '/' {
		compiled, err := regexpx.Compile(key[1 : len(key)-1])
		if err != nil {
			return varSelector{}, false, errs.WrapDetail(err, ErrParse, "invalid variable key regex %q | 变量键正则无效 %q", key, key)
		}
		selector.KeyRe = compiled
		selector.Key = ""
	}
	return finishSelector(selector), exclude, nil
}

// finishSelector records compile-time selector properties that would otherwise require map or
// case-conversion work on every request. | finishSelector 记录选择器的编译期属性，避免每请求进行
// map 查找或大小写转换。
func finishSelector(selector varSelector) varSelector {
	if _, ok := scalarVariables[selector.Name]; ok {
		selector.scalar = true
	}
	selector.simpleCollection = selector.Key == "" && selector.KeyRe == nil && !selector.scalar &&
		!selector.Count && selector.Name != "ARGS_COMBINED_SIZE" && selector.Name != "FILES_COMBINED_SIZE"
	if selector.Name == "TX" && selector.Key != "" && selector.KeyRe == nil {
		selector.Key = strings.ToLower(selector.Key)
		selector.txHash = txNameHash(selector.Key)
	}
	return selector
}

// parseVarSelectors parses a rule's variable list and attaches exclusions. | parseVarSelectors 解析
// 规则的变量列表并附加排除项。
func parseVarSelectors(raw string) ([]varSelector, error) {
	parts := splitVarList(raw)
	selectors := make([]varSelector, 0, len(parts))
	exclusions := make([]varSelector, 0, 2)
	for _, part := range parts {
		selector, exclude, err := parseVarSelector(part)
		if err != nil {
			return nil, err
		}
		if exclude {
			exclusions = append(exclusions, selector)
			continue
		}
		selectors = append(selectors, selector)
	}
	if len(selectors) == 0 {
		return nil, errs.Detail(ErrParse, "rule has no positive variable | 规则没有正向变量")
	}
	for i := range selectors {
		selectors[i].Exclusions = exclusions
		selectors[i].exclusionsSelf = selectors[i].exclusionsTarget(selectors[i].Name)
	}
	return selectors, nil
}

// keyMatches reports whether the selector's key filter accepts key. | keyMatches 报告选择器的键
// 过滤是否接受 key。
func (s varSelector) keyMatches(key string) bool {
	if s.KeyRe != nil {
		return s.KeyRe.MatchString(key)
	}
	if s.Key == "" {
		return true
	}
	// Coraza XML path selectors address all elements or all attributes. Our flattened XML
	// collection keeps both in one namespace, so both wildcards accept every key.
	// | Coraza 的 XML 路径选择器分别指向全部元素或全部属性。我们的扁平 XML 集合把两者放在同一
	// 命名空间，因此两种通配符都接受所有键。
	if s.Name == "XML" && (s.Key == "/*" || s.Key == "//@*" || s.Key == "//*") {
		return true
	}
	switch s.Name {
	case "ARGS", "ARGS_GET", "ARGS_POST", "ARGS_NAMES", "ARGS_GET_NAMES", "ARGS_POST_NAMES":
		return s.Key == key
	default:
		return strings.EqualFold(s.Key, key)
	}
}

// isExcluded reports whether an exclusion selector rejects v. | isExcluded 报告排除选择器是否拒绝 v。
func (s varSelector) isExcluded(v varValue) bool {
	for i := range s.Exclusions {
		if s.Exclusions[i].matchesValue(v) {
			return true
		}
	}
	return false
}

// rejects reports whether the selector's exclusions or key filter reject v. | rejects 报告选择器的
// 排除项或键过滤是否拒绝 v。
func (s varSelector) rejects(v varValue) bool {
	if len(s.Exclusions) > 0 && s.isExcluded(v) {
		return true
	}
	if s.Key != "" || s.KeyRe != nil {
		return !s.keyMatches(v.Key)
	}
	return false
}

// exclusionsTarget reports whether an exclusion can name a value of the given variable.
// | exclusionsTarget 报告排除项是否可能指向给定变量的取值。
func (s varSelector) exclusionsTarget(name string) bool {
	for i := range s.Exclusions {
		target := s.Exclusions[i].Name
		if strings.EqualFold(target, name) {
			return true
		}
		switch {
		case (name == "ARGS_GET" || name == "ARGS_POST") && target == "ARGS":
			return true
		case (name == "ARGS_GET_NAMES" || name == "ARGS_POST_NAMES") && target == "ARGS_NAMES":
			return true
		}
	}
	return false
}

// matchesValue reports whether the selector names v and its key filter accepts v. | matchesValue
// 报告选择器是否指向 v 且键过滤接受 v。
func (s varSelector) matchesValue(v varValue) bool {
	name := v.Name
	switch {
	case s.Name == "ARGS" && (name == "ARGS_GET" || name == "ARGS_POST"):
		name = "ARGS"
	case s.Name == "ARGS_NAMES" && (name == "ARGS_GET_NAMES" || name == "ARGS_POST_NAMES"):
		name = "ARGS_NAMES"
	}
	if !strings.EqualFold(s.Name, name) {
		return false
	}
	return s.keyMatches(v.Key)
}

// collect gathers the values selected by s. | collect 收集 s 选中的取值。
func (s varSelector) collect(tx *transaction) []varValue {
	var values []varValue
	switch s.Name {
	case "ARGS":
		values = tx.collectArgs(true, true)
	case "ARGS_GET":
		values = tx.collectArgs(true, false)
	case "ARGS_POST":
		values = tx.collectArgs(false, true)
	case "ARGS_NAMES":
		values = tx.collectArgNames(true, true)
	case "ARGS_GET_NAMES":
		values = tx.collectArgNames(true, false)
	case "ARGS_POST_NAMES":
		values = tx.collectArgNames(false, true)
	case "REQUEST_HEADERS":
		values = tx.collectHeaders()
	case "REQUEST_HEADERS_NAMES":
		values = tx.collectHeaderNames()
	case "REQUEST_COOKIES":
		values = tx.collectCookies()
	case "REQUEST_COOKIES_NAMES":
		values = tx.collectCookieNames()
	case "RESPONSE_HEADERS":
		values = tx.collectResponseHeaders()
	case "RESPONSE_HEADERS_NAMES":
		values = tx.collectResponseHeaderNames()
	case "FILES":
		values = tx.collectFiles()
	case "FILES_NAMES":
		values = tx.collectFileNames()
	case "FILES_SIZES":
		values = tx.collectFileSizes()
	case "ARGS_COMBINED_SIZE":
		values = tx.collectArgsCombinedSize()
	case "FILES_COMBINED_SIZE":
		values = tx.collectFilesCombinedSize()
	case "MULTIPART_PART_HEADERS":
		tx.parsePostArgs()
		values = tx.multipartPartHeaders
	case "MULTIPART_PART_HEADERS_NAMES":
		tx.parsePostArgs()
		values = tx.multipartPartHeaderNames
	case "JSON":
		values = tx.collectJSON()
	case "XML":
		values = tx.collectXML()
	case "TX":
		values = tx.collectTX(s.txHash, s.Key, s.KeyRe)
	case "MATCHED_VARS":
		values = tx.matchedVars
	case "MATCHED_VARS_NAMES":
		values = make([]varValue, 0, len(tx.matchedVars))
		for _, v := range tx.matchedVars {
			values = append(values, varValue{Name: "MATCHED_VARS_NAMES", Value: qualifiedName(v.Name, v.Key)})
		}
	case "RULE":
		if s.Key != "" {
			values = []varValue{tx.ruleFieldValue(s.Key)}
		} else {
			values = []varValue{{Name: "RULE", Value: tx.ruleField("")}}
		}
	default:
		if single, ok := tx.singleValue(s.Name); ok {
			values = []varValue{single}
		}
	}
	if len(values) > 0 && (len(s.Exclusions) > 0 || s.Key != "" || s.KeyRe != nil) {
		// Never filter a cached collection in place: the same slice backs later selectors. Count the
		// survivors first so the common no-op and single-value cases avoid a copy.
		// | 绝不在缓存集合上原地过滤：同一底层切片会被后续选择器复用。先统计存活项，使常见的
		// 无变化与单值情形免于复制。
		kept := 0
		for i := range values {
			if !s.rejects(values[i]) {
				kept++
			}
		}
		switch kept {
		case 0:
			values = nil
		case len(values):
			// Every value survives: reuse the cached slice. | 全部保留：复用缓存切片。
		case 1:
			for i := range values {
				if !s.rejects(values[i]) {
					values = []varValue{values[i]}
					break
				}
			}
		default:
			filtered := make([]varValue, 0, kept)
			for i := range values {
				if !s.rejects(values[i]) {
					filtered = append(filtered, values[i])
				}
			}
			values = filtered
		}
	}
	if s.Count {
		return []varValue{{Name: s.Name, Value: strconv.Itoa(len(values))}}
	}
	return values
}

// scalarVariables are single-valued variables that can be evaluated without building a
// collection slice. | scalarVariables 是无需构建集合切片即可求值的单值变量。
var scalarVariables = map[string]struct{}{
	"REQUEST_URI": {}, "REQUEST_URI_RAW": {}, "REQUEST_LINE": {}, "REQUEST_FILENAME": {},
	"REQUEST_BASENAME": {}, "REQUEST_METHOD": {}, "REQUEST_PROTOCOL": {}, "QUERY_STRING": {},
	"REQUEST_BODY": {}, "REQUEST_BODY_LENGTH": {}, "RESPONSE_BODY": {}, "RESPONSE_BODY_LENGTH": {},
	"RESPONSE_STATUS": {}, "RESPONSE_PROTOCOL": {}, "REMOTE_ADDR": {}, "REMOTE_HOST": {},
	"REMOTE_PORT": {}, "SERVER_NAME": {}, "SERVER_PORT": {}, "SERVER_ADDR": {},
	"SERVER_PROTOCOL": {}, "UNIQUE_ID": {}, "ENGINE": {}, "DURATION": {}, "MATCHED_VAR": {},
	"MATCHED_VAR_NAME": {}, "RULE": {}, "REQBODY_PROCESSOR": {}, "REQBODY_ERROR": {},
	"REQBODY_ERROR_MSG": {}, "URLENCODED_ERROR": {}, "MULTIPART_STRICT_ERROR": {},
	"MULTIPART_UNMATCHED_BOUNDARY": {}, "FULL_REQUEST": {}, "FULL_REQUEST_LENGTH": {},
	"HIGHEST_SEVERITY": {}, "TIME": {}, "TIME_YEAR": {}, "TIME_MON": {}, "TIME_DAY": {},
	"TIME_HOUR": {}, "TIME_MIN": {}, "TIME_SEC": {}, "TIME_WDAY": {}, "TIME_EPOCH": {},
	"IP": {}, "SESSION": {}, "USER": {},
}

// fastValue evaluates common selectors without allocating a collection slice. handled is false
// when the selector needs the general collection path. | fastValue 在不分配集合切片的情况下
// 求值常见选择器；需要通用集合路径时 handled 为 false。
func (s varSelector) fastValue(tx *transaction) (value varValue, ok, handled bool) {
	if s.simpleCollection {
		return varValue{}, false, false
	}
	if s.scalar && s.Key == "" && s.KeyRe == nil && !s.Count && len(s.Exclusions) == 0 {
		value, found := tx.singleValue(s.Name)
		return value, found, true
	}
	if s.Key != "" && s.KeyRe == nil {
		if s.Count {
			if count, handled := s.fastKeyedCount(tx); handled {
				return varValue{Name: s.Name, Value: strconv.Itoa(count)}, true, true
			}
		} else if value, found, handled := s.fastKeyedValue(tx); handled {
			return value, found, true
		}
	}
	if s.exclusionsSelf {
		return varValue{}, false, false
	}
	if s.Count {
		if s.Name == "TX" && s.Key != "" && s.KeyRe == nil {
			count := 0
			if tx.hasTXHash(s.txHash, s.Key) {
				count = 1
			}
			return varValue{Name: "TX", Value: strconv.Itoa(count)}, true, true
		}
		return varValue{}, false, false
	}
	if s.Name == "TX" && s.Key != "" && s.KeyRe == nil {
		value, found := tx.exactTXHash(s.txHash, s.Key)
		return value, found, true
	}
	if s.Name == "RULE" && s.Key != "" {
		return tx.ruleFieldValue(s.Key), true, true
	}
	if s.Key != "" || s.KeyRe != nil {
		return varValue{}, false, false
	}
	switch s.Name {
	case "ARGS_COMBINED_SIZE":
		total := tx.argsCombinedSize()
		return varValue{Name: s.Name, Value: strconv.Itoa(total)}, true, true
	case "FILES_COMBINED_SIZE":
		tx.parsePostArgs()
		var total int64
		for _, file := range tx.files {
			total += file.Size
		}
		return varValue{Name: s.Name, Value: strconv.FormatInt(total, 10)}, true, true
	}
	if s.scalar {
		value, found := tx.singleValue(s.Name)
		return value, found, true
	}
	return varValue{}, false, false
}

// keyedCollection returns the collection scanned by an exact-key selector. handled is false for
// variables that are not collections. | keyedCollection 返回精确键选择器扫描的集合；非集合变量
// 的 handled 为 false。
func (s varSelector) keyedCollection(tx *transaction) ([]varValue, bool) {
	switch s.Name {
	case "ARGS":
		return tx.collectArgs(true, true), true
	case "ARGS_GET":
		return tx.collectArgs(true, false), true
	case "ARGS_POST":
		return tx.collectArgs(false, true), true
	case "ARGS_NAMES":
		return tx.collectArgNames(true, true), true
	case "ARGS_GET_NAMES":
		return tx.collectArgNames(true, false), true
	case "ARGS_POST_NAMES":
		return tx.collectArgNames(false, true), true
	case "REQUEST_HEADERS":
		return tx.collectHeaders(), true
	case "REQUEST_HEADERS_NAMES":
		return tx.collectHeaderNames(), true
	case "REQUEST_COOKIES":
		return tx.collectCookies(), true
	case "REQUEST_COOKIES_NAMES":
		return tx.collectCookieNames(), true
	case "RESPONSE_HEADERS":
		return tx.collectResponseHeaders(), true
	case "RESPONSE_HEADERS_NAMES":
		return tx.collectResponseHeaderNames(), true
	case "FILES":
		return tx.collectFiles(), true
	case "FILES_NAMES":
		return tx.collectFileNames(), true
	case "FILES_SIZES":
		return tx.collectFileSizes(), true
	case "MULTIPART_PART_HEADERS":
		tx.parsePostArgs()
		return tx.multipartPartHeaders, true
	case "MULTIPART_PART_HEADERS_NAMES":
		tx.parsePostArgs()
		return tx.multipartPartHeaderNames, true
	case "JSON":
		tx.parsePostArgs()
		return tx.jsonValues, true
	case "XML":
		return tx.collectXML(), true
	default:
		return nil, false
	}
}

// fastKeyedValue returns the only value selected by an exact-key selector without allocating.
// handled is false when the selector must use collect, which happens when several values match.
// | fastKeyedValue 在不分配的情况下返回精确键选择器选中的唯一取值；当多个取值命中而必须
// 使用 collect 时 handled 为 false。
func (s varSelector) fastKeyedValue(tx *transaction) (value varValue, found, handled bool) {
	values, handled := s.keyedCollection(tx)
	if !handled {
		return varValue{}, false, false
	}
	matches := 0
	for i := range values {
		if s.rejects(values[i]) {
			continue
		}
		matches++
		if matches > 1 {
			return varValue{}, false, false
		}
		value = values[i]
	}
	return value, matches == 1, true
}

// fastKeyedCount counts the values selected by an exact-key selector without allocating.
// | fastKeyedCount 在不分配的情况下统计精确键选择器选中的取值数。
func (s varSelector) fastKeyedCount(tx *transaction) (int, bool) {
	values, handled := s.keyedCollection(tx)
	if !handled {
		return 0, false
	}
	count := 0
	for i := range values {
		if !s.rejects(values[i]) {
			count++
		}
	}
	return count, true
}

// collectTX returns TX values matching an exact key or key regex. | collectTX 返回匹配精确键或键
// 正则的 TX 取值。
func (tx *transaction) collectTX(hash uint64, key string, keyRe *regexpx.Regexp) []varValue {
	if key == "" && keyRe == nil {
		return tx.txCollection()
	}
	if keyRe == nil {
		value, ok := tx.txLookup(hash, key)
		if !ok {
			return nil
		}
		if !value.expiry.IsZero() && timeNow().After(value.expiry) {
			return nil
		}
		if value.single {
			return []varValue{{Name: "TX", Key: key, Value: value.first}}
		}
		out := make([]varValue, 0, len(value.values))
		for _, item := range value.values {
			out = append(out, varValue{Name: "TX", Key: key, Value: item})
		}
		return out
	}
	var out []varValue
	for _, entry := range tx.tx {
		if !keyRe.MatchString(entry.key) {
			continue
		}
		value := entry.value
		if !value.expiry.IsZero() && timeNow().After(value.expiry) {
			continue
		}
		if value.single {
			out = append(out, varValue{Name: "TX", Key: entry.key, Value: value.first})
			continue
		}
		for _, item := range value.values {
			out = append(out, varValue{Name: "TX", Key: entry.key, Value: item})
		}
	}
	for name, value := range tx.txCollisions {
		if !keyRe.MatchString(name) {
			continue
		}
		if !value.expiry.IsZero() && timeNow().After(value.expiry) {
			continue
		}
		if value.single {
			out = append(out, varValue{Name: "TX", Key: name, Value: value.first})
			continue
		}
		for _, item := range value.values {
			out = append(out, varValue{Name: "TX", Key: name, Value: item})
		}
	}
	return out
}

// singleValue returns the value of a scalar variable. | singleValue 返回标量变量的取值。
func (tx *transaction) singleValue(name string) (varValue, bool) {
	r := tx.req
	switch name {
	case "REQUEST_URI":
		return varValue{Name: name, Value: tx.uriDecoded}, true
	case "REQUEST_URI_RAW":
		return varValue{Name: name, Value: tx.uriRaw}, true
	case "REQUEST_LINE":
		if r == nil {
			return varValue{Name: name}, true
		}
		return varValue{Name: name, Value: tx.requestLineValue()}, true
	case "REQUEST_FILENAME":
		if r == nil {
			return varValue{Name: name}, true
		}
		return varValue{Name: name, Value: r.URL.Path}, true
	case "REQUEST_BASENAME":
		if r == nil {
			return varValue{Name: name}, true
		}
		return varValue{Name: name, Value: path.Base(r.URL.Path)}, true
	case "REQUEST_METHOD":
		if r == nil {
			return varValue{Name: name}, true
		}
		return varValue{Name: name, Value: r.Method}, true
	case "REQUEST_PROTOCOL":
		if r == nil {
			return varValue{Name: name}, true
		}
		return varValue{Name: name, Value: r.Proto}, true
	case "QUERY_STRING":
		if r == nil {
			return varValue{Name: name}, true
		}
		return varValue{Name: name, Value: r.URL.RawQuery}, true
	case "REQUEST_BODY":
		return varValue{Name: name, Value: string(tx.requestBody)}, true
	case "REQUEST_BODY_LENGTH":
		return varValue{Name: name, Value: strconv.Itoa(len(tx.requestBody))}, true
	case "RESPONSE_BODY":
		return varValue{Name: name, Value: string(tx.responseBody)}, true
	case "RESPONSE_BODY_LENGTH":
		return varValue{Name: name, Value: strconv.Itoa(len(tx.responseBody))}, true
	case "RESPONSE_STATUS":
		return varValue{Name: name, Value: strconv.Itoa(tx.responseStatus)}, true
	case "RESPONSE_PROTOCOL":
		return varValue{Name: name, Value: tx.responseProto}, true
	case "REMOTE_ADDR", "REMOTE_HOST":
		return varValue{Name: name, Value: tx.clientIP}, true
	case "REMOTE_PORT":
		return varValue{Name: name, Value: tx.remotePort}, true
	case "SERVER_NAME":
		return varValue{Name: name, Value: serverHost(r)}, true
	case "SERVER_PORT":
		return varValue{Name: name, Value: serverPort(r)}, true
	case "SERVER_ADDR":
		return varValue{Name: name, Value: serverAddr(r)}, true
	case "SERVER_PROTOCOL":
		if r == nil {
			return varValue{Name: name}, true
		}
		return varValue{Name: name, Value: r.Proto}, true
	case "UNIQUE_ID":
		return varValue{Name: name, Value: tx.id}, true
	case "ENGINE":
		mode := tx.engineMode
		if mode == ModeDefault {
			mode = tx.defaultMode
		}
		return varValue{Name: name, Value: engineName(mode)}, true
	case "DURATION":
		return varValue{Name: name, Value: strconv.FormatInt(tx.durationMillis(), 10)}, true
	case "MATCHED_VAR":
		return varValue{Name: name, Value: tx.matchedValue}, true
	case "MATCHED_VAR_NAME":
		return varValue{Name: name, Value: qualifiedName(tx.matchedVar, tx.matchedKey)}, true
	case "RULE":
		return varValue{Name: name, Value: tx.ruleField("")}, true
	case "REQBODY_PROCESSOR":
		return varValue{Name: name, Value: tx.bodyProcessor}, true
	case "REQBODY_ERROR":
		if tx.bodyParseError {
			return varValue{Name: name, Value: "1"}, true
		}
		return varValue{Name: name, Value: "0"}, true
	case "REQBODY_ERROR_MSG":
		return varValue{Name: name, Value: tx.bodyErrorMessage}, true
	case "URLENCODED_ERROR":
		return varValue{Name: name, Value: boolString(tx.urlencodedError)}, true
	case "MULTIPART_STRICT_ERROR", "MULTIPART_UNMATCHED_BOUNDARY":
		return varValue{Name: name, Value: boolString(tx.multipartError)}, true
	case "FULL_REQUEST":
		return varValue{Name: name, Value: tx.fullRequest()}, true
	case "FULL_REQUEST_LENGTH":
		return varValue{Name: name, Value: strconv.Itoa(len(tx.fullRequest()))}, true
	case "HIGHEST_SEVERITY":
		return varValue{Name: name, Value: tx.highestSeverity()}, true
	case "TIME", "TIME_YEAR", "TIME_MON", "TIME_DAY", "TIME_HOUR", "TIME_MIN", "TIME_SEC", "TIME_WDAY", "TIME_EPOCH":
		return varValue{Name: name, Value: tx.timeValue(name)}, true
	case "IP", "SESSION", "USER":
		return varValue{Name: name, Value: tx.lastTX(name)}, true
	default:
		return varValue{}, false
	}
}

// requestLineValue returns the cached request line. | requestLineValue 返回缓存的请求行。
func (tx *transaction) requestLineValue() string {
	if tx.requestLine == "" && tx.req != nil {
		tx.requestLine = tx.req.Method + " " + tx.uriRaw + " " + tx.req.Proto
	}
	return tx.requestLine
}

// ruleField returns a RULE collection field for the current rule. | ruleField 返回当前规则的
// RULE 集合字段。
func (tx *transaction) ruleField(field string) string {
	rule := tx.currentRule
	if rule == nil || rule.meta == nil {
		return ""
	}
	meta := rule.meta
	switch strings.ToLower(field) {
	case "":
		return strconv.Itoa(meta.ID)
	case "id":
		return strconv.Itoa(meta.ID)
	case "rev":
		return meta.Rev
	case "ver":
		return meta.Ver
	case "msg":
		return meta.Msg
	case "severity":
		return meta.Severity
	case "logdata":
		return meta.LogData
	case "maturity":
		return strconv.Itoa(meta.Maturity)
	case "accuracy":
		return strconv.Itoa(meta.Accuracy)
	case "file":
		return meta.File
	case "line":
		return strconv.Itoa(meta.Line)
	case "tag":
		return strings.Join(meta.Tags, " ")
	default:
		return ""
	}
}

// ruleFieldValue supports RULE selectors with a key. | ruleFieldValue 支持带键的 RULE 选择器。
func (tx *transaction) ruleFieldValue(key string) varValue {
	return varValue{Name: "RULE", Key: strings.ToLower(key), Value: tx.ruleField(key)}
}

// timeValue renders one TIME variable. | timeValue 渲染一个 TIME 变量。
func (tx *transaction) timeValue(name string) string {
	now := tx.clock()
	switch name {
	case "TIME":
		return now.Format("15:04:05")
	case "TIME_YEAR":
		return strconv.Itoa(now.Year())
	case "TIME_MON":
		return strconv.Itoa(int(now.Month()))
	case "TIME_DAY":
		return strconv.Itoa(now.Day())
	case "TIME_HOUR":
		return strconv.Itoa(now.Hour())
	case "TIME_MIN":
		return strconv.Itoa(now.Minute())
	case "TIME_SEC":
		return strconv.Itoa(now.Second())
	case "TIME_WDAY":
		return strconv.Itoa(int(now.Weekday()))
	case "TIME_EPOCH":
		return strconv.FormatInt(now.Unix(), 10)
	default:
		return ""
	}
}

// highestSeverity returns the numerically lowest severity among matches. | highestSeverity 返回
// 命中规则中数值最低（最严重）的级别。
func (tx *transaction) highestSeverity() string {
	best := ""
	bestValue := 1 << 30
	for i := range tx.matches {
		value := severityValue(tx.matches[i].Severity)
		if value < bestValue {
			bestValue = value
			best = tx.matches[i].Severity
		}
	}
	return best
}

// fullRequest renders FULL_REQUEST. | fullRequest 渲染 FULL_REQUEST。
func (tx *transaction) fullRequest() string {
	r := tx.req
	if r == nil {
		return ""
	}
	var b strings.Builder
	b.Grow(256 + len(tx.requestBody))
	b.WriteString(r.Method)
	b.WriteByte(' ')
	b.WriteString(tx.uriRaw)
	b.WriteByte(' ')
	b.WriteString(r.Proto)
	b.WriteString("\r\n")
	names := tx.collectHeaderNames()
	for _, name := range names {
		for _, v := range tx.collectHeaders() {
			if strings.EqualFold(v.Key, name.Value) {
				b.WriteString(name.Value)
				b.WriteString(": ")
				b.WriteString(v.Value)
				b.WriteString("\r\n")
			}
		}
	}
	b.WriteString("\r\n")
	b.Write(tx.requestBody)
	return b.String()
}

// boolString renders a boolean as the SecLang 0/1 form. | boolString 把布尔值渲染为 SecLang 的 0/1 形式。
func boolString(b bool) string {
	if b {
		return "1"
	}
	return "0"
}

// engineName renders an engine mode as the SecRuleEngine value. | engineName 把引擎模式渲染为
// SecRuleEngine 取值。
func engineName(mode Mode) string {
	switch mode {
	case ModeDetection:
		return "DetectionOnly"
	case ModeOff:
		return "Off"
	default:
		return "On"
	}
}

// serverHost extracts the server host from the request. | serverHost 从请求中提取服务器主机。
func serverHost(r *http.Request) string {
	if r == nil {
		return ""
	}
	host, _, err := net.SplitHostPort(r.Host)
	if err == nil {
		return host
	}
	return r.Host
}

// serverPort extracts the server port from the request. | serverPort 从请求中提取服务器端口。
func serverPort(r *http.Request) string {
	if r == nil {
		return ""
	}
	if _, port, err := net.SplitHostPort(r.Host); err == nil {
		return port
	}
	if r.TLS != nil {
		return "443"
	}
	return "80"
}

// serverAddr extracts the local listener address. | serverAddr 提取本地监听地址。
func serverAddr(r *http.Request) string {
	if r == nil {
		return ""
	}
	if addr, ok := r.Context().Value(http.LocalAddrContextKey).(net.Addr); ok && addr != nil {
		host, _, err := net.SplitHostPort(addr.String())
		if err == nil {
			return host
		}
		return addr.String()
	}
	return ""
}
