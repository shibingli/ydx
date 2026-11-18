package client

import (
	"bytes"
	"io"
	"mime"
	"net/http"
	"strconv"
	"strings"
)

// closeResponseBody releases a response body on a failed transport call. | closeResponseBody 在传输失败时释放响应正文。
func closeResponseBody(resp *http.Response) {
	if resp != nil && resp.Body != nil {
		_ = resp.Body.Close()
	}
}

// responseHasBody reports whether the method/status pair can carry a body. | responseHasBody
// 报告方法与状态码组合是否可能携带正文。
func responseHasBody(method string, status int) bool {
	return method != http.MethodHead && status != http.StatusNoContent &&
		status != http.StatusResetContent && status != http.StatusNotModified
}

// bufferedResponse materializes a buffered response without transfer-coding
// metadata that no longer applies. | bufferedResponse 生成已缓冲响应，并清理不再适用的传输编码元数据。
func bufferedResponse(resp *http.Response, method string, data []byte) *http.Response {
	copied := *resp
	copied.Header = resp.Header.Clone()
	if copied.Header == nil {
		copied.Header = make(http.Header)
	}
	copied.Body = io.NopCloser(bytes.NewReader(data))
	copied.ContentLength = bufferedContentLength(method, resp.StatusCode, resp.Header, len(data))
	copied.TransferEncoding = nil
	copied.Header.Del("Transfer-Encoding")
	return &copied
}

// bufferedContentLength keeps HEAD/304 metadata when a body is buffered. | bufferedContentLength
// 在正文被缓冲时保留 HEAD/304 的长度元数据。
func bufferedContentLength(method string, status int, header http.Header, bodyLen int) int64 {
	if method == http.MethodHead || status == http.StatusNotModified {
		if value := header.Get("Content-Length"); value != "" {
			if n, err := strconv.ParseInt(value, 10, 64); err == nil && n >= 0 {
				return n
			}
		}
	}
	return int64(bodyLen)
}

// headerValue joins all values of one header with NUL separators. | headerValue 用一个头部全部值并以 NUL 分隔。
func headerValue(header http.Header, key string) string {
	if header == nil {
		return ""
	}
	values := header.Values(key)
	if len(values) == 0 {
		return ""
	}
	if len(values) == 1 {
		return values[0]
	}
	return strings.Join(values, "\x00")
}

// defaultHopByHop is the immutable hop-by-hop header set. | defaultHopByHop 是不可变的逐跳头集合。
var defaultHopByHop = map[string]bool{
	"Connection":          true,
	"Proxy-Connection":    true,
	"Proxy-Authenticate":  true,
	"Proxy-Authorization": true,
	"Keep-Alive":          true,
	"Te":                  true,
	"Trailer":             true,
	"Transfer-Encoding":   true,
	"Upgrade":             true,
}

// hopByHopSet returns the hop-by-hop headers plus Connection-listed tokens. | hopByHopSet 返回逐跳头以及 Connection 列出的令牌。
func hopByHopSet(header http.Header) map[string]bool {
	connection := header.Values("Connection")
	if len(connection) == 0 {
		return defaultHopByHop
	}
	set := make(map[string]bool, len(defaultHopByHop)+len(connection))
	for key := range defaultHopByHop {
		set[key] = true
	}
	for _, value := range connection {
		for _, token := range strings.Split(value, ",") {
			token = strings.TrimSpace(token)
			if token != "" {
				set[http.CanonicalHeaderKey(token)] = true
			}
		}
	}
	return set
}

// isEventStream reports whether the header names an SSE response. | isEventStream 报告响应头是否表示 SSE。
func isEventStream(header http.Header) bool {
	if header == nil {
		return false
	}
	mediaType, _, err := mime.ParseMediaType(header.Get("Content-Type"))
	if err != nil {
		return false
	}
	return strings.EqualFold(mediaType, "text/event-stream")
}

// fnv64aString hashes a string with FNV-1a without allocations. | fnv64aString 用无分配的 FNV-1a 哈希字符串。
func fnv64aString(s string) uint64 {
	const offset = uint64(14695981039346656037)
	const prime = uint64(1099511628211)
	hash := offset
	for i := 0; i < len(s); i++ {
		hash ^= uint64(s[i])
		hash *= prime
	}
	return hash
}

// fnv32aString hashes a string with FNV-1a 32-bit without allocations. | fnv32aString 用无分配的 32 位 FNV-1a 哈希字符串。
func fnv32aString(s string) uint32 {
	return fnv32aUpdate(2166136261, s)
}

// fnv32aUpdate continues an FNV-1a 32-bit hash over s. | fnv32aUpdate 在 s 上继续 32 位 FNV-1a 哈希。
func fnv32aUpdate(hash uint32, s string) uint32 {
	const prime = uint32(16777619)
	for i := 0; i < len(s); i++ {
		hash ^= uint32(s[i])
		hash *= prime
	}
	return hash
}
