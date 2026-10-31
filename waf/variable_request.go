package waf

import (
	"bytes"
	"encoding/xml"
	"io"
	"mime"
	"mime/multipart"
	"net"
	"net/http"
	"net/url"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/shibingli/ydx/json"
)

// Collection mask bits used to prewarm caches before parallel rule evaluation.
// | 集合位掩码用于在并行规则求值前预热缓存。
const (
	collectQuery uint8 = 1 << iota
	collectPost
	collectHeaders
	collectCookies
	collectFiles
	collectJSON
	collectXML
)

// prewarm builds the collection caches required by a parallel rule run. It runs on the request
// goroutine before any worker starts, so workers only read immutable caches.
// | prewarm 构建并行规则段所需的集合缓存。它在任何工作协程启动之前于请求协程运行，因此工作
// 协程只读取不可变缓存。
func (tx *transaction) prewarm(mask uint8) {
	if mask&collectHeaders != 0 {
		tx.collectHeaders()
		tx.collectHeaderNames()
	}
	if mask&collectCookies != 0 {
		tx.collectCookies()
		tx.collectCookieNames()
	}
	if mask&collectQuery != 0 {
		tx.parseQueryArgs()
		tx.collectArgs(true, false)
		tx.collectArgNames(true, false)
	}
	if mask&collectPost != 0 {
		tx.parsePostArgs()
		tx.collectArgs(true, true)
		tx.collectArgNames(true, true)
	}
	if mask&collectFiles != 0 {
		tx.collectFiles()
		tx.collectFileNames()
		tx.collectFileSizes()
	}
	if mask&collectJSON != 0 {
		tx.collectJSON()
	}
	if mask&collectXML != 0 {
		tx.collectXML()
	}
}

// timeNow is replaceable in tests that need a stable clock. | timeNow 可由需要稳定时钟的测试替换。
var timeNow = time.Now

// initRequest fills the request-derived scalars used by scalar variables. | initRequest 填充标量
// 变量使用的请求派生值。
func (tx *transaction) initRequest() {
	r := tx.req
	if r == nil {
		return
	}
	if r.RequestURI != "" && r.RequestURI[0] == '/' {
		tx.uriRaw = r.RequestURI
	} else {
		tx.uriRaw = r.URL.RequestURI()
	}
	tx.uriDecoded = tx.uriRaw
	if host, port, err := net.SplitHostPort(r.RemoteAddr); err == nil {
		tx.remoteHost = host
		tx.remotePort = port
	} else {
		tx.remoteHost = r.RemoteAddr
	}
	if tx.clientIP == "" {
		tx.clientIP = tx.remoteHost
	}
}

// collectArgs returns GET and/or POST arguments. | collectArgs 返回 GET 与/或 POST 参数。
func (tx *transaction) collectArgs(get, post bool) []varValue {
	if get {
		tx.parseQueryArgs()
	}
	if post {
		tx.parsePostArgs()
	}
	switch {
	case get && post:
		if !tx.argsAllReady {
			tx.argsAll = append(tx.argsAll[:0], tx.argsGet...)
			tx.argsAll = append(tx.argsAll, tx.argsPost...)
			tx.argsAllReady = true
		}
		return tx.argsAll
	case get:
		return tx.argsGet
	default:
		return tx.argsPost
	}
}

// collectArgNames returns the names of GET and/or POST arguments. | collectArgNames 返回 GET 与/或
// POST 参数的名称。
func (tx *transaction) collectArgNames(get, post bool) []varValue {
	if get {
		tx.parseQueryArgs()
	}
	if post {
		tx.parsePostArgs()
	}
	switch {
	case get && post:
		if !tx.argNamesAllReady {
			tx.argNamesAll = tx.argNamesAll[:0]
			for _, name := range tx.argsGetNames {
				tx.argNamesAll = append(tx.argNamesAll, varValue{Name: "ARGS_GET_NAMES", Key: name, Value: name})
			}
			for _, name := range tx.argsPostNames {
				tx.argNamesAll = append(tx.argNamesAll, varValue{Name: "ARGS_POST_NAMES", Key: name, Value: name})
			}
			tx.argNamesAllReady = true
		}
		return tx.argNamesAll
	case get:
		if !tx.argNamesGetReady {
			tx.argNamesGet = tx.argNamesGet[:0]
			for _, name := range tx.argsGetNames {
				tx.argNamesGet = append(tx.argNamesGet, varValue{Name: "ARGS_GET_NAMES", Key: name, Value: name})
			}
			tx.argNamesGetReady = true
		}
		return tx.argNamesGet
	default:
		if !tx.argNamesPostReady {
			tx.argNamesPost = tx.argNamesPost[:0]
			for _, name := range tx.argsPostNames {
				tx.argNamesPost = append(tx.argNamesPost, varValue{Name: "ARGS_POST_NAMES", Key: name, Value: name})
			}
			tx.argNamesPostReady = true
		}
		return tx.argNamesPost
	}
}

// parseQueryArgs parses the query string once, applying the argument limit. | parseQueryArgs 解析
// 查询串一次，并应用参数上限。
func (tx *transaction) parseQueryArgs() {
	if tx.queryParsed {
		return
	}
	tx.queryParsed = true
	tx.argsCombinedReady = false
	if tx.req == nil {
		return
	}
	values, ok := parseArgumentValues(tx.req.URL.RawQuery, tx.argSep)
	if !ok {
		tx.urlencodedError = true
	}
	tx.appendArgs("ARGS_GET", values, &tx.argsGet, &tx.argsGetNames)
	tx.argsAllReady = false
	tx.argNamesGetReady = false
	tx.argNamesAllReady = false
}

// parsePostArgs parses the request body according to the selected body processor. | parsePostArgs
// 按选定的正文处理器解析请求正文。
func (tx *transaction) parsePostArgs() {
	if tx.bodyParsed || !tx.bodyRead {
		return
	}
	tx.bodyParsed = true
	tx.argsAllReady = false
	tx.argsCombinedReady = false
	tx.argNamesPostReady = false
	tx.argNamesAllReady = false
	if len(tx.requestBody) == 0 {
		return
	}
	processor := tx.bodyProcessor
	if processor == "" {
		processor = selectBodyProcessor(tx.req)
		tx.bodyProcessor = processor
	}
	switch processor {
	case "URLENCODED":
		tx.parseURLEncoded()
	case "MULTIPART":
		tx.parseMultipart()
	case "JSON":
		tx.parseJSON()
	case "XML":
		tx.parseXML()
	default:
		// RAW and unknown processors expose no arguments. | RAW 与未知处理器不暴露参数。
	}
}

// parseURLEncoded parses an application/x-www-form-urlencoded body. | parseURLEncoded 解析
// application/x-www-form-urlencoded 正文。
func (tx *transaction) parseURLEncoded() {
	values, ok := parseArgumentValues(string(tx.requestBody), tx.argSep)
	if !ok {
		tx.urlencodedError = true
	}
	tx.appendArgs("ARGS_POST", values, &tx.argsPost, &tx.argsPostNames)
	tx.argsAllReady = false
	tx.argNamesPostReady = false
	tx.argNamesAllReady = false
}

// parseMultipart parses a multipart body without writing anything to disk. | parseMultipart 解析
// multipart 正文，不向磁盘写入任何内容。
func (tx *transaction) parseMultipart() {
	if tx.req == nil {
		return
	}
	mediaType, params, err := mime.ParseMediaType(tx.req.Header.Get("Content-Type"))
	if err != nil || !strings.EqualFold(mediaType, "multipart/form-data") || params["boundary"] == "" {
		tx.multipartError = true
		tx.bodyParseError = true
		tx.bodyErrorMessage = "invalid multipart content type | 非法的 multipart 内容类型"
		return
	}
	reader := multipart.NewReader(bytes.NewReader(tx.requestBody), params["boundary"])
	for {
		part, err := reader.NextPart()
		if err == io.EOF {
			break
		}
		if err != nil {
			tx.multipartError = true
			tx.bodyParseError = true
			tx.bodyErrorMessage = "multipart parse failed | multipart 解析失败"
			return
		}
		for headerName, headerValues := range part.Header {
			key := strings.ToLower(headerName)
			for _, headerValue := range headerValues {
				tx.multipartPartHeaders = append(tx.multipartPartHeaders, varValue{
					Name: "MULTIPART_PART_HEADERS", Key: key, Value: headerValue,
				})
			}
			if !containsFold(tx.multipartPartHeaderNames, key) {
				tx.multipartPartHeaderNames = append(tx.multipartPartHeaderNames, varValue{
					Name: "MULTIPART_PART_HEADERS_NAMES", Key: key, Value: key,
				})
			}
		}
		name := part.FormName()
		if name == "" {
			_ = part.Close()
			continue
		}
		if filename := part.FileName(); filename != "" {
			size, copyErr := io.Copy(io.Discard, part)
			_ = part.Close()
			if copyErr != nil {
				tx.multipartError = true
			}
			tx.files = append(tx.files, varValue{Name: "FILES", Key: name, Value: filename, Size: size})
			tx.fileSizes = append(tx.fileSizes, varValue{Name: "FILES_SIZES", Key: name, Value: strconv.FormatInt(size, 10), Size: size})
			continue
		}
		value, readErr := io.ReadAll(io.LimitReader(part, 1<<20))
		_ = part.Close()
		if readErr != nil {
			tx.multipartError = true
			continue
		}
		if len(tx.argsPost) >= tx.argLimit {
			continue
		}
		tx.argsPost = append(tx.argsPost, varValue{Name: "ARGS_POST", Key: name, Value: string(value)})
		tx.argsPostNames = appendUniqueFold(tx.argsPostNames, name)
	}
	tx.filesParsed = true
}

// parseJSON parses a JSON body into flat ARGS_POST and JSON collections. | parseJSON 把 JSON 正文
// 解析为扁平的 ARGS_POST 与 JSON 集合。
func (tx *transaction) parseJSON() {
	var root any
	if err := json.Unmarshal(tx.requestBody, &root); err != nil {
		tx.bodyParseError = true
		tx.bodyErrorMessage = "invalid JSON body | 非法的 JSON 正文"
		return
	}
	tx.flattenJSON("", root, &tx.jsonValues, &tx.argsPost)
	tx.jsonParsed = true
	for _, value := range tx.jsonValues {
		tx.argsPostNames = appendUniqueFold(tx.argsPostNames, value.Key)
	}
	if len(tx.argsPostNames) > tx.argLimit {
		tx.argsPostNames = tx.argsPostNames[:tx.argLimit]
	}
}

// flattenJSON walks a decoded JSON value and appends scalar leaves to both collections.
// | flattenJSON 遍历解码后的 JSON 值，把标量叶子追加到两个集合。
func (tx *transaction) flattenJSON(prefix string, value any, jsonOut, argsOut *[]varValue) {
	switch v := value.(type) {
	case map[string]any:
		keys := make([]string, 0, len(v))
		for key := range v {
			keys = append(keys, key)
		}
		sort.Strings(keys)
		for _, key := range keys {
			tx.flattenJSON(joinPath(prefix, key), v[key], jsonOut, argsOut)
		}
	case []any:
		for i, item := range v {
			tx.flattenJSON(joinPath(prefix, strconv.Itoa(i)), item, jsonOut, argsOut)
		}
	case string:
		tx.appendJSONLeaf(prefix, v, jsonOut, argsOut)
	case bool:
		tx.appendJSONLeaf(prefix, strconv.FormatBool(v), jsonOut, argsOut)
	case float64:
		tx.appendJSONLeaf(prefix, strconv.FormatFloat(v, 'g', -1, 64), jsonOut, argsOut)
	case nil:
		tx.appendJSONLeaf(prefix, "", jsonOut, argsOut)
	default:
		tx.appendJSONLeaf(prefix, scalarString(v), jsonOut, argsOut)
	}
}

// appendJSONLeaf appends one flattened JSON leaf within the argument limit. | appendJSONLeaf 在参数
// 上限内追加一个扁平 JSON 叶子。
func (tx *transaction) appendJSONLeaf(key, value string, jsonOut, argsOut *[]varValue) {
	if len(tx.argsPost) >= tx.argLimit {
		return
	}
	*jsonOut = append(*jsonOut, varValue{Name: "JSON", Key: key, Value: value})
	*argsOut = append(*argsOut, varValue{Name: "ARGS_POST", Key: key, Value: value})
}

// parseXML parses an XML body into a flat best-effort collection. | parseXML 把 XML 正文解析为
// 尽力而为的扁平集合。
func (tx *transaction) parseXML() {
	decoder := xml.NewDecoder(bytes.NewReader(tx.requestBody))
	stack := make([]string, 0, 8)
	for {
		token, err := decoder.Token()
		if err == io.EOF {
			break
		}
		if err != nil {
			tx.bodyParseError = true
			tx.bodyErrorMessage = "invalid XML body | 非法的 XML 正文"
			return
		}
		switch t := token.(type) {
		case xml.StartElement:
			stack = append(stack, t.Name.Local)
			for _, attr := range t.Attr {
				key := joinPath(strings.Join(stack, "."), "@"+attr.Name.Local)
				tx.xmlValues = append(tx.xmlValues, varValue{Name: "XML", Key: key, Value: attr.Value})
			}
		case xml.EndElement:
			if len(stack) > 0 {
				stack = stack[:len(stack)-1]
			}
		case xml.CharData:
			value := strings.TrimSpace(string(t))
			if value == "" || len(stack) == 0 {
				continue
			}
			tx.xmlValues = append(tx.xmlValues, varValue{Name: "XML", Key: strings.Join(stack, "."), Value: value})
		}
	}
	tx.xmlParsed = true
}

// collectHeaders returns request header values sorted by header name. | collectHeaders 按头名称排序
// 返回请求头取值。
func (tx *transaction) collectHeaders() []varValue {
	if tx.headersParsed {
		return tx.headers
	}
	tx.headersParsed = true
	if tx.req == nil {
		return nil
	}
	names := make([]string, 0, len(tx.req.Header))
	for name := range tx.req.Header {
		names = append(names, name)
	}
	sort.Strings(names)
	for _, name := range names {
		for _, value := range tx.req.Header[name] {
			tx.headers = append(tx.headers, varValue{Name: "REQUEST_HEADERS", Key: name, Value: value})
		}
	}
	// net/http removes the Host header from Header and stores it in Request.Host. Rules such as
	// CRS 920280 require it to be visible as REQUEST_HEADERS:Host. | net/http 把 Host 从 Header
	// 移到 Request.Host；CRS 920280 等规则需要它以 REQUEST_HEADERS:Host 可见。
	if tx.req.Host != "" && !headerNamePresent(tx.req.Header, "Host") {
		tx.headers = append(tx.headers, varValue{Name: "REQUEST_HEADERS", Key: "Host", Value: tx.req.Host})
	}
	// net/http also moves Transfer-Encoding into Request.TransferEncoding. | net/http 还会把
	// Transfer-Encoding 移到 Request.TransferEncoding。
	if !headerNamePresent(tx.req.Header, "Transfer-Encoding") {
		for _, encoding := range tx.req.TransferEncoding {
			if encoding == "" {
				continue
			}
			tx.headers = append(tx.headers, varValue{Name: "REQUEST_HEADERS", Key: "Transfer-Encoding", Value: encoding})
		}
	}
	return tx.headers
}

// headerNamePresent reports whether header contains name, ignoring case. | headerNamePresent
// 报告 header 是否包含 name，忽略大小写。
func headerNamePresent(header http.Header, name string) bool {
	for key := range header {
		if strings.EqualFold(key, name) {
			return true
		}
	}
	return false
}

// collectHeaderNames returns request header names, sorted and unique. | collectHeaderNames 返回
// 排序去重的请求头名称。
func (tx *transaction) collectHeaderNames() []varValue {
	tx.collectHeaders()
	if tx.headerNames != nil {
		return tx.headerNames
	}
	tx.headerNames = make([]varValue, 0, len(tx.headers))
	for _, value := range tx.headers {
		if !containsFold(tx.headerNames, value.Key) {
			tx.headerNames = append(tx.headerNames, varValue{Name: "REQUEST_HEADERS_NAMES", Key: value.Key, Value: value.Key})
		}
	}
	return tx.headerNames
}

// collectCookies returns request cookie values. | collectCookies 返回请求 Cookie 取值。
func (tx *transaction) collectCookies() []varValue {
	if tx.cookiesParsed {
		return tx.cookies
	}
	tx.cookiesParsed = true
	if tx.req == nil {
		return nil
	}
	for _, header := range tx.req.Header.Values("Cookie") {
		for _, part := range strings.Split(header, ";") {
			name, value, ok := strings.Cut(strings.TrimSpace(part), "=")
			if !ok || name == "" {
				continue
			}
			tx.cookies = append(tx.cookies, varValue{Name: "REQUEST_COOKIES", Key: name, Value: value})
		}
	}
	return tx.cookies
}

// collectCookieNames returns request cookie names. | collectCookieNames 返回请求 Cookie 名称。
func (tx *transaction) collectCookieNames() []varValue {
	tx.collectCookies()
	if tx.cookieNames != nil {
		return tx.cookieNames
	}
	tx.cookieNames = make([]varValue, 0, len(tx.cookies))
	for _, value := range tx.cookies {
		if !containsFold(tx.cookieNames, value.Key) {
			tx.cookieNames = append(tx.cookieNames, varValue{Name: "REQUEST_COOKIES_NAMES", Key: value.Key, Value: value.Key})
		}
	}
	return tx.cookieNames
}

// collectFiles returns uploaded file names. | collectFiles 返回上传文件名。
func (tx *transaction) collectFiles() []varValue {
	tx.parsePostArgs()
	return tx.files
}

// collectFileNames returns uploaded form field names. | collectFileNames 返回上传表单字段名。
func (tx *transaction) collectFileNames() []varValue {
	tx.parsePostArgs()
	if tx.fileNames != nil {
		return tx.fileNames
	}
	tx.fileNames = make([]varValue, 0, len(tx.files))
	for _, value := range tx.files {
		if !containsFold(tx.fileNames, value.Key) {
			tx.fileNames = append(tx.fileNames, varValue{Name: "FILES_NAMES", Key: value.Key, Value: value.Key})
		}
	}
	return tx.fileNames
}

// collectFileSizes returns uploaded file sizes. | collectFileSizes 返回上传文件大小。
func (tx *transaction) collectFileSizes() []varValue {
	tx.parsePostArgs()
	return tx.fileSizes
}

// collectArgsCombinedSize returns the total key and value size of every argument.
// | collectArgsCombinedSize 返回所有参数的键与值总大小。
func (tx *transaction) collectArgsCombinedSize() []varValue {
	return []varValue{{Name: "ARGS_COMBINED_SIZE", Value: strconv.Itoa(tx.argsCombinedSize())}}
}

// argsCombinedSize returns the total key and value size of every argument. | argsCombinedSize 返回
// 所有参数的键与值总大小。
func (tx *transaction) argsCombinedSize() int {
	if tx.argsCombinedReady {
		return tx.argsCombined
	}
	values := tx.collectArgs(true, true)
	total := 0
	for _, value := range values {
		total += len(value.Key) + len(value.Value)
	}
	tx.argsCombined = total
	tx.argsCombinedReady = true
	return total
}

// collectFilesCombinedSize returns the total uploaded file size. | collectFilesCombinedSize 返回
// 上传文件总大小。
func (tx *transaction) collectFilesCombinedSize() []varValue {
	tx.parsePostArgs()
	var total int64
	for _, value := range tx.files {
		total += value.Size
	}
	return []varValue{{Name: "FILES_COMBINED_SIZE", Value: strconv.FormatInt(total, 10)}}
}

// collectJSON returns the flattened JSON body collection. | collectJSON 返回扁平 JSON 正文集合。
func (tx *transaction) collectJSON() []varValue {
	tx.parsePostArgs()
	return tx.jsonValues
}

// collectXML returns the flattened XML body collection. | collectXML 返回扁平 XML 正文集合。
func (tx *transaction) collectXML() []varValue {
	tx.parsePostArgs()
	return tx.xmlValues
}

// parseArgumentValues parses an argument string with the configured separator. It reports
// whether every escape decoded cleanly. | parseArgumentValues 用配置的分隔符解析参数字符串，并
// 报告每个转义是否成功解码。
func parseArgumentValues(raw string, separator byte) (map[string][]string, bool) {
	if separator == '&' || separator == 0 {
		values, err := url.ParseQuery(raw)
		return values, err == nil
	}
	values := make(map[string][]string, 8)
	valid := true
	for _, pair := range strings.Split(raw, string(separator)) {
		if pair == "" {
			continue
		}
		key, value, ok := strings.Cut(pair, "=")
		if !ok {
			value = ""
		}
		decodedKey, err := url.QueryUnescape(key)
		if err != nil {
			valid = false
			continue
		}
		decodedValue, err := url.QueryUnescape(value)
		if err != nil {
			valid = false
			continue
		}
		values[decodedKey] = append(values[decodedKey], decodedValue)
	}
	return values, valid
}

// appendArgs appends parsed values within the argument limit. | appendArgs 在参数上限内追加解析后的值。
func (tx *transaction) appendArgs(collection string, values url.Values, out *[]varValue, names *[]string) {
	keys := make([]string, 0, len(values))
	for key := range values {
		keys = append(keys, key)
	}
	sort.Strings(keys)
	for _, key := range keys {
		for _, value := range values[key] {
			if len(*out) >= tx.argLimit {
				return
			}
			*out = append(*out, varValue{Name: collection, Key: key, Value: value})
		}
		*names = append(*names, key)
	}
}

// appendUniqueFold appends name when it is not already present, ignoring case. | appendUniqueFold
// 在名称不存在时追加，忽略大小写。
func appendUniqueFold(values []string, name string) []string {
	for _, existing := range values {
		if strings.EqualFold(existing, name) {
			return values
		}
	}
	return append(values, name)
}

// containsFold reports whether values already contains name, ignoring case. | containsFold 报告
// values 是否已包含 name，忽略大小写。
func containsFold(values []varValue, name string) bool {
	for _, value := range values {
		if strings.EqualFold(value.Value, name) || strings.EqualFold(value.Key, name) {
			return true
		}
	}
	return false
}

// joinPath joins two JSON path segments. | joinPath 拼接两个 JSON 路径段。
func joinPath(prefix, key string) string {
	if prefix == "" {
		return key
	}
	return prefix + "." + key
}

// scalarString renders decoder scalar values the native JSON decoder may produce.
// | scalarString 渲染原生 JSON 解码器可能产生的标量值。
func scalarString(value any) string {
	switch v := value.(type) {
	case int:
		return strconv.Itoa(v)
	case int64:
		return strconv.FormatInt(v, 10)
	case uint64:
		return strconv.FormatUint(v, 10)
	case float32:
		return strconv.FormatFloat(float64(v), 'g', -1, 32)
	default:
		return ""
	}
}

// selectBodyProcessor maps a request Content-Type to a body processor name. | selectBodyProcessor
// 把请求 Content-Type 映射为正文处理器名称。
func selectBodyProcessor(r *http.Request) string {
	if r == nil {
		return "RAW"
	}
	contentType := r.Header.Get("Content-Type")
	mediaType, _, err := mime.ParseMediaType(contentType)
	if err != nil {
		mediaType = strings.TrimSpace(strings.Split(contentType, ";")[0])
	}
	mediaType = strings.ToLower(mediaType)
	switch {
	case mediaType == "application/json" || strings.HasSuffix(mediaType, "+json"):
		return "JSON"
	case mediaType == "application/xml" || mediaType == "text/xml" || strings.HasSuffix(mediaType, "+xml"):
		return "XML"
	case mediaType == "multipart/form-data":
		return "MULTIPART"
	case mediaType == "application/x-www-form-urlencoded":
		return "URLENCODED"
	case mediaType == "":
		return "URLENCODED"
	default:
		return "RAW"
	}
}
