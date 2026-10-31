package waf

import (
	"net/http"
	"sort"
	"strconv"
	"strings"
)

// setResponseHeaders captures the response headers and status for phase 3 and 5 rules.
// | setResponseHeaders 为 phase 3 与 5 规则捕获响应头与状态。
func (tx *transaction) setResponseHeaders(header http.Header, status int, proto string) {
	tx.responseStatus = status
	tx.responseProto = proto
	tx.responseHeaders = tx.responseHeaders[:0]
	tx.responseHeaderNames = tx.responseHeaderNames[:0]
	names := make([]string, 0, len(header))
	for name := range header {
		names = append(names, name)
	}
	sort.Strings(names)
	for _, name := range names {
		for _, value := range header[name] {
			tx.responseHeaders = append(tx.responseHeaders, varValue{Name: "RESPONSE_HEADERS", Key: name, Value: value})
		}
		if !containsFold(tx.responseHeaderNames, name) {
			tx.responseHeaderNames = append(tx.responseHeaderNames, varValue{Name: "RESPONSE_HEADERS_NAMES", Key: name, Value: name})
		}
	}
}

// setResponseBody captures the inspected response body. | setResponseBody 捕获被检测的响应正文。
func (tx *transaction) setResponseBody(body []byte) {
	tx.responseBody = append(tx.responseBody[:0], body...)
	tx.responseParsed = true
}

// collectResponseHeaders returns the captured response header values. | collectResponseHeaders
// 返回捕获的响应头取值。
func (tx *transaction) collectResponseHeaders() []varValue {
	return tx.responseHeaders
}

// collectResponseHeaderNames returns the captured response header names. | collectResponseHeaderNames
// 返回捕获的响应头名称。
func (tx *transaction) collectResponseHeaderNames() []varValue {
	return tx.responseHeaderNames
}

// severityValue maps a severity name or number to its ModSecurity numeric level. Unknown names
// map to the lowest severity (7). | severityValue 把严重级别名称或数字映射为 ModSecurity 数值级别；
// 未知名称映射为最低级别 7。
func severityValue(severity string) int {
	switch strings.ToUpper(strings.TrimSpace(severity)) {
	case "EMERGENCY":
		return 0
	case "ALERT":
		return 1
	case "CRITICAL":
		return 2
	case "ERROR":
		return 3
	case "WARNING":
		return 4
	case "NOTICE":
		return 5
	case "INFO":
		return 6
	case "DEBUG":
		return 7
	}
	if value, err := strconv.Atoi(strings.TrimSpace(severity)); err == nil && value >= 0 && value <= 7 {
		return value
	}
	return 7
}

// severityName maps a numeric severity to its canonical name. | severityName 把数值严重级别映射为规范名称。
func severityName(value int) string {
	switch value {
	case 0:
		return "EMERGENCY"
	case 1:
		return "ALERT"
	case 2:
		return "CRITICAL"
	case 3:
		return "ERROR"
	case 4:
		return "WARNING"
	case 5:
		return "NOTICE"
	case 6:
		return "INFO"
	default:
		return "DEBUG"
	}
}

// normalizeSeverity returns the canonical name for a severity token. | normalizeSeverity 返回严重
// 级别标记的规范名称。
func normalizeSeverity(severity string) string {
	severity = strings.TrimSpace(severity)
	if severity == "" {
		return "NOTICE"
	}
	if value, err := strconv.Atoi(severity); err == nil {
		return severityName(value)
	}
	return strings.ToUpper(severity)
}
