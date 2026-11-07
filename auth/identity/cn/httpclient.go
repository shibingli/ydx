package cn

import (
	"io"
	"net/http"
	"time"

	"github.com/shibingli/ydx/errs"
)

// ErrProviderResponse reports a malformed, oversized or non-successful HTTP response. | ErrProviderResponse 表示 HTTP 响应格式非法、过大或状态非成功。
var ErrProviderResponse = errs.New("cn: invalid provider response | cn：服务方响应非法")

// defaultHTTPTimeout bounds a provider request when the caller does not supply a client. | defaultHTTPTimeout 在调用方未提供客户端时限制服务方请求时长。
const defaultHTTPTimeout = 10 * time.Second

// maxHTTPResponseBytes caps how much of a provider response is read. | maxHTTPResponseBytes 限制服务方响应的读取上限。
const maxHTTPResponseBytes = 64 << 10

// httpClientOrDefault returns client, or a client with the configured timeout. | httpClientOrDefault 返回 client，或带配置超时的新客户端。
func httpClientOrDefault(client *http.Client, timeout time.Duration) *http.Client {
	if client != nil {
		return client
	}
	if timeout <= 0 {
		timeout = defaultHTTPTimeout
	}
	return &http.Client{Timeout: timeout}
}

// applyHTTPHeaders sets each configured header on req. | applyHTTPHeaders 在 req 上设置每个配置的请求头。
func applyHTTPHeaders(req *http.Request, headers map[string]string) {
	for key, value := range headers {
		req.Header.Set(key, value)
	}
}

// readHTTPBody reads a provider response with a hard size cap. | readHTTPBody 在硬性大小上限内读取服务方响应。
func readHTTPBody(resp *http.Response) ([]byte, error) {
	if resp == nil || resp.Body == nil {
		return nil, errs.Detail(ErrProviderResponse, "empty response body | 响应体为空")
	}
	body, err := io.ReadAll(io.LimitReader(resp.Body, maxHTTPResponseBytes+1))
	if err != nil {
		return nil, errs.Wrap(err, ErrProviderResponse)
	}
	if len(body) > maxHTTPResponseBytes {
		return nil, errs.Detail(ErrProviderResponse, "response exceeds %d bytes | 响应超过 %d 字节", maxHTTPResponseBytes, maxHTTPResponseBytes)
	}
	return body, nil
}

// requireSuccessStatus rejects non-2xx provider responses without echoing the body. | requireSuccessStatus 拒绝非 2xx 服务方响应，且不回显响应体。
func requireSuccessStatus(resp *http.Response) error {
	if resp.StatusCode >= 200 && resp.StatusCode < 300 {
		return nil
	}
	return errs.Detail(ErrProviderResponse, "provider returned HTTP %d | 服务方返回 HTTP %d", resp.StatusCode, resp.StatusCode)
}
