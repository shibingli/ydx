package client

import (
	"mime"
	"net/http"
	"strings"
)

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
