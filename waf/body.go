package waf

import (
	"bytes"
	"io"
	"net/http"
)

// replayBody replays a buffered prefix and the unread remainder of the original body.
// | replayBody 回放已缓冲的前缀与原始正文的未读部分。
type replayBody struct {
	io.Reader
	closer io.Closer
}

// Close closes the original body. | Close 关闭原始正文。
func (b *replayBody) Close() error {
	if b.closer == nil {
		return nil
	}
	return b.closer.Close()
}

// captureRequestBody buffers a request body up to limit. When the body is larger and the action is
// ProcessPartial, the handler still receives the full body through a replay reader. The returned
// bool reports that the body exceeded the limit. | captureRequestBody 把请求正文缓冲到上限。正文
// 超限且动作为 ProcessPartial 时，处理器仍可通过回放读取器读取完整正文。返回的布尔值表示正文超限。
func captureRequestBody(r *http.Request, limit int, action LimitAction) ([]byte, bool, error) {
	if r == nil || r.Body == nil || r.Body == http.NoBody {
		return nil, false, nil
	}
	if r.Method == http.MethodGet || r.Method == http.MethodHead {
		if r.ContentLength == 0 {
			return nil, false, nil
		}
	}
	if limit <= 0 {
		limit = defaultRequestBodyLimit
	}
	if r.ContentLength > int64(limit) && action == LimitReject {
		_ = r.Body.Close()
		r.Body = http.NoBody
		r.ContentLength = 0
		return nil, true, nil
	}
	original := r.Body
	data, err := io.ReadAll(io.LimitReader(original, int64(limit)+1))
	if err != nil {
		_ = original.Close()
		r.Body = http.NoBody
		return nil, false, err
	}
	if len(data) > limit {
		prefix := append([]byte(nil), data[:limit]...)
		if action == LimitReject {
			_ = original.Close()
			r.Body = http.NoBody
			r.ContentLength = 0
			return prefix, true, nil
		}
		rest := io.MultiReader(bytes.NewReader(data[limit:]), original)
		r.Body = &replayBody{Reader: rest, closer: original}
		r.ContentLength = -1
		return prefix, true, nil
	}
	_ = original.Close()
	r.Body = io.NopCloser(bytes.NewReader(data))
	r.ContentLength = int64(len(data))
	return data, false, nil
}
