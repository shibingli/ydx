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
