package waf

import (
	"net/http"
	"sort"
	"strconv"
	"strings"
	"time"
)

// maxMatchedVars bounds the per-transaction MATCHED_VARS history so a rule with a huge
// collection cannot grow memory without limit. | maxMatchedVars 限制每事务的 MATCHED_VARS 历史，
// 避免巨大集合让内存无界增长。
const maxMatchedVars = 256

// maxEventMatches bounds logged event matches per transaction. Rules and arguments are already
// bounded, but a multiMatch rule over a large collection can still produce thousands of entries;
// the cap keeps event memory proportional to a small constant instead of the argument limit.
// | maxEventMatches 限制每事务记录的日志事件命中数。规则与参数本身已有上限，但多值规则在大集合
// 上仍可能产生数千条记录；该上限让事件内存保持为小常数，而不是随参数上限增长。
const maxEventMatches = 256

// txValue is one TX collection variable. | txValue 是一个 TX 集合变量。
type txValue struct {
	expiry time.Time
	values []string
	first  string
	single bool
}

// transaction carries all per-request state. It is owned by one goroutine and must not be
// shared. | transaction 承载全部请求级状态，由单个协程拥有，不得共享。
type transaction struct {
	start time.Time

	// Time snapshot used by TIME variables and DURATION. | TIME 变量与 DURATION 使用的时间快照。
	now time.Time
	req *http.Request

	tx             map[uint64]txEntry
	txCollisions   map[string]txValue
	transformCache map[transformCacheKey]string

	interruption *Interruption
	detected     *Interruption

	removedRules   map[int]struct{}
	removedTargets map[int][]varSelector
	rules          *ruleSet

	currentRule      *compiledRule
	id               string
	clientIP         string
	bodyProcessor    string
	bodyErrorMessage string
	uriDecoded       string
	uriRaw           string
	remoteHost       string
	remotePort       string
	matchedValue     string
	matchedVar       string
	matchedKey       string
	requestLine      string
	responseProto    string

	capture         []string
	captureScratch  []string
	matches         []Match
	matchedVars     []varValue
	parallelIndices []int
	parallelResults []ruleEval

	// Request collection caches. | 请求集合缓存。
	argsGet                  []varValue
	argsPost                 []varValue
	argsAll                  []varValue
	argNamesGet              []varValue
	argNamesPost             []varValue
	argNamesAll              []varValue
	headers                  []varValue
	cookies                  []varValue
	files                    []varValue
	argsGetNames             []string
	argsPostNames            []string
	headerNames              []varValue
	cookieNames              []varValue
	fileNames                []varValue
	fileSizes                []varValue
	jsonValues               []varValue
	xmlValues                []varValue
	multipartPartHeaders     []varValue
	multipartPartHeaderNames []varValue
	requestBody              []byte

	// Response collection caches. | 响应集合缓存。
	responseHeaders     []varValue
	responseHeaderNames []varValue
	responseBody        []byte
	responseJSON        []varValue

	responseStatus int

	// Configuration snapshot needed outside the engine. | 引擎之外需要的配置快照。
	argLimit          int
	bodyLimit         int
	responseBodyLimit int
	allow             bool

	engineMode  Mode
	defaultMode Mode

	bodyTooLarge         bool
	bodyRead             bool
	bodyParsed           bool
	argsAllReady         bool
	argsCombinedReady    bool
	argsCombined         int
	argNamesGetReady     bool
	argNamesPostReady    bool
	argNamesAllReady     bool
	queryParsed          bool
	headersParsed        bool
	cookiesParsed        bool
	filesParsed          bool
	jsonParsed           bool
	xmlParsed            bool
	forceBodyVar         bool
	bodyParseError       bool
	urlencodedError      bool
	multipartError       bool
	responseBodyTooLarge bool
	responseParsed       bool
	nowInit              bool
	parallelEval         bool

	argSep                  byte
	bodyLimitAction         LimitAction
	requestBodyAccess       bool
	responseBodyAccess      bool
	responseBodyLimitAction LimitAction
	auditEngine             bool
}

// resetTransaction prepares a pooled transaction for reuse. | resetTransaction 为复用准备池化事务。
func resetTransaction(tx *transaction) {
	tx.id = ""
	tx.req = nil
	tx.clientIP = ""
	tx.start = time.Time{}
	if tx.tx != nil {
		clear(tx.tx)
	}
	if tx.txCollisions != nil {
		clear(tx.txCollisions)
	}
	if tx.transformCache != nil {
		clear(tx.transformCache)
	}
	tx.parallelEval = false
	tx.requestLine = ""
	tx.capture = tx.capture[:0]
	clear(tx.captureScratch)
	tx.captureScratch = tx.captureScratch[:0]
	tx.matches = tx.matches[:0]
	tx.matchedVars = tx.matchedVars[:0]
	tx.parallelIndices = tx.parallelIndices[:0]
	tx.parallelResults = tx.parallelResults[:0]
	tx.interruption = nil
	tx.detected = nil
	tx.allow = false
	if tx.removedRules != nil {
		clear(tx.removedRules)
	}
	if tx.removedTargets != nil {
		clear(tx.removedTargets)
	}
	tx.rules = nil
	tx.engineMode = ModeDefault
	tx.defaultMode = ModeDefault
	tx.argsGet = tx.argsGet[:0]
	tx.argsPost = tx.argsPost[:0]
	tx.argsAll = tx.argsAll[:0]
	tx.argNamesGet = tx.argNamesGet[:0]
	tx.argNamesPost = tx.argNamesPost[:0]
	tx.argNamesAll = tx.argNamesAll[:0]
	tx.argsAllReady = false
	tx.argsCombinedReady = false
	tx.argsCombined = 0
	tx.argNamesGetReady = false
	tx.argNamesPostReady = false
	tx.argNamesAllReady = false
	tx.headers = tx.headers[:0]
	tx.cookies = tx.cookies[:0]
	tx.files = tx.files[:0]
	tx.argsGetNames = tx.argsGetNames[:0]
	tx.argsPostNames = tx.argsPostNames[:0]
	tx.headerNames = tx.headerNames[:0]
	tx.cookieNames = tx.cookieNames[:0]
	tx.fileNames = tx.fileNames[:0]
	tx.fileSizes = tx.fileSizes[:0]
	tx.jsonValues = tx.jsonValues[:0]
	tx.xmlValues = tx.xmlValues[:0]
	tx.multipartPartHeaders = tx.multipartPartHeaders[:0]
	tx.multipartPartHeaderNames = tx.multipartPartHeaderNames[:0]
	tx.requestBody = tx.requestBody[:0]
	tx.bodyTooLarge = false
	tx.bodyRead = false
	tx.bodyParsed = false
	tx.queryParsed = false
	tx.headersParsed = false
	tx.cookiesParsed = false
	tx.filesParsed = false
	tx.jsonParsed = false
	tx.xmlParsed = false
	tx.bodyProcessor = ""
	tx.forceBodyVar = false
	tx.bodyParseError = false
	tx.bodyErrorMessage = ""
	tx.urlencodedError = false
	tx.multipartError = false
	tx.uriDecoded = ""
	tx.uriRaw = ""
	tx.remoteHost = ""
	tx.remotePort = ""
	tx.matchedValue = ""
	tx.matchedVar = ""
	tx.matchedKey = ""
	tx.currentRule = nil
	tx.responseStatus = 0
	tx.responseProto = ""
	tx.responseHeaders = tx.responseHeaders[:0]
	tx.responseHeaderNames = tx.responseHeaderNames[:0]
	tx.responseBody = tx.responseBody[:0]
	tx.responseBodyTooLarge = false
	tx.responseParsed = false
	tx.responseJSON = tx.responseJSON[:0]
	tx.now = time.Time{}
	tx.nowInit = false
	tx.argLimit = 0
	tx.argSep = 0
	tx.bodyLimit = 0
	tx.bodyLimitAction = LimitDefault
	tx.requestBodyAccess = false
	tx.responseBodyAccess = false
	tx.responseBodyLimit = 0
	tx.responseBodyLimitAction = LimitDefault
	tx.auditEngine = false
}

// clock returns the transaction time snapshot used by TIME variables and DURATION. | clock 返回
// TIME 变量与 DURATION 使用的事务时间快照。
func (tx *transaction) clock() time.Time {
	if !tx.nowInit {
		tx.now = time.Now()
		tx.nowInit = true
	}
	return tx.now
}

// durationMillis returns the elapsed time in whole milliseconds. | durationMillis 返回整毫秒的耗时。
func (tx *transaction) durationMillis() int64 {
	if tx.start.IsZero() {
		return 0
	}
	return time.Since(tx.start).Milliseconds()
}

// txKey normalizes a TX variable name. Most compiled names are already lowercase, so the common
// path avoids strings.ToLower entirely. | txKey 归一化 TX 变量名。多数编译期名称已经小写，因此常见
// 路径完全避开 strings.ToLower。
func txKey(name string) string {
	for index := 0; index < len(name); index++ {
		c := name[index]
		if c >= 'A' && c <= 'Z' || c >= 0x80 {
			return strings.ToLower(name)
		}
	}
	return name
}

// txEntry is one keyed TX value in the primary hash table. | txEntry 是主哈希表中的一个键控 TX 取值。
type txEntry struct {
	key   string
	value txValue
}

// txNameHash hashes a normalized TX variable name. Precomputed hashes avoid re-hashing the same
// compile-time names on every rule evaluation. | txNameHash 对已归一化的 TX 变量名做哈希。预计算哈希
// 避免在每次规则求值时重复哈希相同的编译期名称。
func txNameHash(name string) uint64 {
	hash := uint64(1469598103934665603)
	for index := 0; index < len(name); index++ {
		hash ^= uint64(name[index])
		hash *= 1099511628211
	}
	return hash
}

// txKeyHash normalizes a TX name and returns it with its hash. | txKeyHash 归一化 TX 名称并返回名称与
// 哈希。
func txKeyHash(name string) (string, uint64) {
	key := txKey(name)
	return key, txNameHash(key)
}

// txLookup returns a TX value by precomputed hash and normalized key. Collisions are kept in a
// small secondary map; a 64-bit hash collision is rare, so the common path performs one map probe
// and one string comparison without hashing the key. | txLookup 按预计算哈希与归一化键返回 TX 取值。
// 碰撞保存在小型二级 map 中；64 位哈希碰撞很少，因此常见路径只做一次 map 探测与一次字符串比较，
// 不再哈希键。
func (tx *transaction) txLookup(hash uint64, key string) (txValue, bool) {
	if entry, ok := tx.tx[hash]; ok && entry.key == key {
		return entry.value, true
	}
	if tx.txCollisions != nil {
		value, ok := tx.txCollisions[key]
		return value, ok
	}
	return txValue{}, false
}

// txStore stores a TX value by precomputed hash and normalized key. | txStore 按预计算哈希与归一化键
// 保存 TX 取值。
func (tx *transaction) txStore(hash uint64, key string, value txValue) {
	if tx.tx == nil {
		tx.tx = make(map[uint64]txEntry, 8)
	}
	entry, ok := tx.tx[hash]
	if !ok || entry.key == key {
		if tx.txCollisions != nil {
			delete(tx.txCollisions, key)
		}
		tx.tx[hash] = txEntry{key: key, value: value}
		return
	}
	if tx.txCollisions == nil {
		tx.txCollisions = make(map[string]txValue, 1)
	}
	tx.txCollisions[key] = value
}

// txDelete removes a TX value by precomputed hash and normalized key. | txDelete 按预计算哈希与归一化
// 键删除 TX 取值。
func (tx *transaction) txDelete(hash uint64, key string) {
	if entry, ok := tx.tx[hash]; ok && entry.key == key {
		delete(tx.tx, hash)
		return
	}
	if tx.txCollisions != nil {
		delete(tx.txCollisions, key)
	}
}

// txEntries returns every stored TX entry for iteration. | txEntries 返回全部已存储 TX 条目以供遍历。
func (tx *transaction) txEntries() []txEntry {
	if len(tx.tx) == 0 && len(tx.txCollisions) == 0 {
		return nil
	}
	entries := make([]txEntry, 0, len(tx.tx)+len(tx.txCollisions))
	for _, entry := range tx.tx {
		entries = append(entries, entry)
	}
	for key, value := range tx.txCollisions {
		entries = append(entries, txEntry{key: key, value: value})
	}
	return entries
}

// setTX replaces a TX variable. A positive ttl marks the value as expiring. | setTX 替换 TX 变量；
// 正数 ttl 表示该值会过期。
func (tx *transaction) setTX(name string, values []string, ttl time.Duration) {
	key, hash := txKeyHash(name)
	tx.setTXHash(hash, key, values, ttl)
}

// setTXHash replaces a TX variable using a precomputed hash and normalized key. | setTXHash 使用预计算
// 哈希与归一化键替换 TX 变量。
func (tx *transaction) setTXHash(hash uint64, key string, values []string, ttl time.Duration) {
	if len(values) == 1 {
		tx.setTXValueHash(hash, key, values[0], ttl)
		return
	}
	current, _ := tx.txLookup(hash, key)
	current.values = append(current.values[:0], values...)
	current.first = ""
	current.single = false
	current.expiry = time.Time{}
	if ttl > 0 {
		current.expiry = time.Now().Add(ttl)
	}
	tx.txStore(hash, key, current)
}

// setTXValue replaces a TX variable with one scalar without allocating a slice. | setTXValue 用一个
// 标量替换 TX 变量，不分配切片。
func (tx *transaction) setTXValue(name, value string, ttl time.Duration) {
	key, hash := txKeyHash(name)
	tx.setTXValueHash(hash, key, value, ttl)
}

// setTXValueHash replaces a TX variable using a precomputed hash and normalized key. | setTXValueHash
// 使用预计算哈希与归一化键替换 TX 变量。
func (tx *transaction) setTXValueHash(hash uint64, key, value string, ttl time.Duration) {
	current, _ := tx.txLookup(hash, key)
	current.first = value
	current.single = true
	current.values = current.values[:0]
	current.expiry = time.Time{}
	if ttl > 0 {
		current.expiry = time.Now().Add(ttl)
	}
	tx.txStore(hash, key, current)
}

// addTX appends a value to a TX variable. | addTX 向 TX 变量追加一个值。
func (tx *transaction) addTX(name, value string, ttl time.Duration) {
	key, hash := txKeyHash(name)
	tx.addTXHash(hash, key, value, ttl)
}

// addTXHash appends a value using a precomputed hash and normalized key. | addTXHash 使用预计算哈希与
// 归一化键追加取值。
func (tx *transaction) addTXHash(hash uint64, key, value string, ttl time.Duration) {
	current, _ := tx.txLookup(hash, key)
	if !current.expiry.IsZero() && time.Now().After(current.expiry) {
		current = txValue{}
	}
	if current.single {
		current.values = append(current.values[:0], current.first, value)
		current.first = ""
		current.single = false
	} else {
		current.values = append(current.values, value)
	}
	if ttl > 0 {
		current.expiry = time.Now().Add(ttl)
	}
	tx.txStore(hash, key, current)
}

// deleteTX removes a TX variable. | deleteTX 删除 TX 变量。
func (tx *transaction) deleteTX(name string) {
	key, hash := txKeyHash(name)
	tx.deleteTXHash(hash, key)
}

// deleteTXHash removes a TX variable using a precomputed hash and normalized key. | deleteTXHash 使用
// 预计算哈希与归一化键删除 TX 变量。
func (tx *transaction) deleteTXHash(hash uint64, key string) {
	if tx.tx != nil {
		tx.txDelete(hash, key)
	}
}

// lastTX returns the last value of a TX variable. Expired values are removed lazily.
// | lastTX 返回 TX 变量的最后一个取值；过期值会被惰性删除。
func (tx *transaction) lastTX(name string) string {
	key, hash := txKeyHash(name)
	return tx.lastTXHash(hash, key)
}

// lastTXHash returns the last value using a precomputed hash and normalized key. | lastTXHash 使用预计算
// 哈希与归一化键返回最后一个取值。
func (tx *transaction) lastTXHash(hash uint64, key string) string {
	value, ok := tx.txLookup(hash, key)
	if !ok {
		return ""
	}
	if !value.expiry.IsZero() && time.Now().After(value.expiry) {
		// Do not delete during a read: parallel rule evaluation may read TX concurrently.
		// | 读取期间不删除：并行规则求值可能并发读取 TX。
		return ""
	}
	if value.single {
		return value.first
	}
	if len(value.values) == 0 {
		return ""
	}
	return value.values[len(value.values)-1]
}

// exactTX returns the current value of one TX variable without allocating. | exactTX 零分配地返回
// 一个 TX 变量的当前值。
func (tx *transaction) exactTX(name string) (varValue, bool) {
	key, hash := txKeyHash(name)
	return tx.exactTXHash(hash, key)
}

// exactTXHash returns the current TX value using a precomputed hash and normalized key. |
// exactTXHash 使用预计算哈希与归一化键返回当前 TX 取值。
func (tx *transaction) exactTXHash(hash uint64, key string) (varValue, bool) {
	value, ok := tx.txLookup(hash, key)
	if !ok {
		return varValue{}, false
	}
	if !value.expiry.IsZero() && time.Now().After(value.expiry) {
		return varValue{}, false
	}
	if value.single {
		return varValue{Name: "TX", Key: key, Value: value.first}, true
	}
	if len(value.values) == 0 {
		return varValue{}, false
	}
	return varValue{Name: "TX", Key: key, Value: value.values[len(value.values)-1]}, true
}

// hasTX reports whether a TX variable has a live value. | hasTX 报告 TX 变量是否有未过期的值。
func (tx *transaction) hasTX(name string) bool {
	key, hash := txKeyHash(name)
	return tx.hasTXHash(hash, key)
}

// hasTXHash reports whether a TX variable has a live value using a precomputed hash. | hasTXHash 使用
// 预计算哈希报告 TX 变量是否有未过期的值。
func (tx *transaction) hasTXHash(hash uint64, key string) bool {
	_, ok := tx.exactTXHash(hash, key)
	return ok
}

// txCollection returns every live TX variable sorted by name. | txCollection 按名称排序返回所有
// 未过期的 TX 变量。
func (tx *transaction) txCollection() []varValue {
	if len(tx.tx) == 0 && len(tx.txCollisions) == 0 {
		return nil
	}
	keys := make([]string, 0, len(tx.tx)+len(tx.txCollisions))
	for _, entry := range tx.tx {
		keys = append(keys, entry.key)
	}
	for key := range tx.txCollisions {
		keys = append(keys, key)
	}
	sort.Strings(keys)
	out := make([]varValue, 0, len(keys))
	for _, key := range keys {
		hash := txNameHash(key)
		value, ok := tx.txLookup(hash, key)
		if !ok {
			continue
		}
		if !value.expiry.IsZero() && time.Now().After(value.expiry) {
			continue
		}
		if value.single {
			out = append(out, varValue{Name: "TX", Key: key, Value: value.first})
			continue
		}
		for _, item := range value.values {
			out = append(out, varValue{Name: "TX", Key: key, Value: item})
		}
	}
	return out
}

// setCapture stores regex capture groups as TX.0 … TX.9. | setCapture 把正则捕获组保存为 TX.0 … TX.9。
func (tx *transaction) setCapture(groups []string) {
	if cap(tx.capture) < 10 {
		tx.capture = make([]string, 10)
	}
	tx.capture = tx.capture[:10]
	for i := range tx.capture {
		tx.capture[i] = ""
	}
	for i := 0; i < len(groups) && i < len(tx.capture); i++ {
		tx.capture[i] = groups[i]
		key := strconv.Itoa(i)
		tx.setTXValueHash(txNameHash(key), key, groups[i], 0)
	}
}

// setMatched records the current match for MATCHED_VAR macros without building a qualified name.
// | setMatched 为 MATCHED_VAR 宏记录当前命中，不构建限定名称。
func (tx *transaction) setMatched(v varValue) {
	tx.matchedValue = v.Value
	tx.matchedVar = v.Name
	tx.matchedKey = v.Key
	if len(tx.matchedVars) < maxMatchedVars {
		tx.matchedVars = append(tx.matchedVars, v)
	}
}

// appendMatch appends a logged event match up to maxEventMatches. | appendMatch 追加一条启用日志
// 的事件命中，最多保留 maxEventMatches 条。
func (tx *transaction) appendMatch(m Match) {
	if len(tx.matches) >= maxEventMatches {
		return
	}
	tx.matches = append(tx.matches, m)
}

// matchSnapshot returns a copy of the matches recorded so far. | matchSnapshot 返回目前已记录命中的副本。
func (tx *transaction) matchSnapshot() []Match {
	if len(tx.matches) == 0 {
		return nil
	}
	return append([]Match(nil), tx.matches...)
}

// qualifiedName renders a collection key as NAME:KEY. | qualifiedName 把集合键渲染为 NAME:KEY。
func qualifiedName(name, key string) string {
	if key == "" {
		return name
	}
	return name + ":" + key
}

// removeRule records a per-transaction ctl rule removal. | removeRule 记录事务级 ctl 规则移除。
func (tx *transaction) removeRule(id int) {
	if tx.removedRules == nil {
		tx.removedRules = make(map[int]struct{}, 4)
	}
	tx.removedRules[id] = struct{}{}
}

// removeTarget records a per-transaction ctl target removal. | removeTarget 记录事务级 ctl 目标移除。
func (tx *transaction) removeTarget(id int, selector varSelector) {
	if tx.removedTargets == nil {
		tx.removedTargets = make(map[int][]varSelector, 4)
	}
	tx.removedTargets[id] = append(tx.removedTargets[id], selector)
}

// ruleRemoved reports whether ctl removed a rule for this transaction. | ruleRemoved 报告 ctl 是否
// 为本事务移除了规则。
func (tx *transaction) ruleRemoved(id int) bool {
	_, removed := tx.removedRules[id]
	return removed
}

// targetRemoved reports whether ctl removed a selector from a rule. | targetRemoved 报告 ctl 是否为
// 规则移除了某个选择器。
func (tx *transaction) targetRemoved(id int, selector varSelector) bool {
	removed := tx.removedTargets[id]
	for i := range removed {
		if sameSelector(removed[i], selector) {
			return true
		}
	}
	return false
}

// sameSelector compares two selectors by name and key. | sameSelector 按名称与键比较两个选择器。
func sameSelector(a, b varSelector) bool {
	return strings.EqualFold(a.Name, b.Name) && strings.EqualFold(a.Key, b.Key)
}
