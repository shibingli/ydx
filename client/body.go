package client

import (
	"bytes"
	"io"
	"strings"

	"github.com/shibingli/ydx/errs"
	"github.com/shibingli/ydx/json"
)

// prepareBody classifies a request body into a reader, a replay function and an
// optional content type. | prepareBody 把请求正文归类为 reader、重放函数与可选 Content-Type。
func prepareBody(v any) (io.ReadCloser, func() (io.ReadCloser, error), string, error) {
	switch body := v.(type) {
	case nil:
		return nil, nil, "", nil
	case []byte:
		return bytesBody(body), bytesGetBody(body), "", nil
	case json.RawMessage:
		return bytesBody(body), bytesGetBody(body), "application/json", nil
	case string:
		return stringBody(body), stringGetBody(body), "", nil
	case *bytes.Buffer:
		data := body.Bytes()
		return bytesBody(data), bytesGetBody(data), "", nil
	case *strings.Reader:
		return io.NopCloser(body), func() (io.ReadCloser, error) {
			if _, err := body.Seek(0, io.SeekStart); err != nil {
				return nil, err
			}
			return io.NopCloser(body), nil
		}, "", nil
	case io.ReadSeeker:
		return io.NopCloser(body), func() (io.ReadCloser, error) {
			if _, err := body.Seek(0, io.SeekStart); err != nil {
				return nil, err
			}
			return io.NopCloser(body), nil
		}, "", nil
	case io.ReadCloser:
		return body, nil, "", nil
	case io.Reader:
		return io.NopCloser(body), nil, "", nil
	default:
		data, err := json.Marshal(v)
		if err != nil {
			return nil, nil, "", errs.Wrap(err, ErrEncodeBody)
		}
		return bytesBody(data), bytesGetBody(data), "application/json", nil
	}
}

// bytesBody wraps a byte slice in a reader without copying. | bytesBody 以不复制的方式把字节切片包装为 reader。
func bytesBody(b []byte) io.ReadCloser {
	return io.NopCloser(bytes.NewReader(b))
}

// bytesGetBody returns a replay function over the same byte slice. | bytesGetBody 返回同一字节切片上的重放函数。
func bytesGetBody(b []byte) func() (io.ReadCloser, error) {
	return func() (io.ReadCloser, error) {
		return io.NopCloser(bytes.NewReader(b)), nil
	}
}

// stringBody wraps a string in a reader without converting it to a byte slice. | stringBody 以不复制的方式把字符串包装为 reader。
func stringBody(s string) io.ReadCloser {
	return io.NopCloser(strings.NewReader(s))
}

// stringGetBody returns a replay function over the same string. | stringGetBody 返回同一字符串上的重放函数。
func stringGetBody(s string) func() (io.ReadCloser, error) {
	return func() (io.ReadCloser, error) {
		return io.NopCloser(strings.NewReader(s)), nil
	}
}
