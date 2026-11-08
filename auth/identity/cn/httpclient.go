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

// httpClientOrDefault returns client, or a client with the configured timeout that refuses redirects. | httpClientOrDefault
// 返回 client，或带配置超时且拒绝重定向的新客户端。
//
// The default client does not follow redirects: a provider redirect could forward static credential
// headers such as an API key to another host or turn the request into a cross-origin probe. A 3xx
// response is returned to the caller and rejected as non-success. | 默认客户端不跟随重定向：服务方
// 重定向可能把 API Key 等静态凭据请求头转发到另一主机，或把请求变成跨源探测。3xx 响应会返回调用方
// 并按非成功状态拒绝。
func httpClientOrDefault(client *http.Client, timeout time.Duration) *http.Client {
	if client != nil {
		return client
	}
	if timeout <= 0 {
		timeout = defaultHTTPTimeout
	}
	return &http.Client{
		Timeout: timeout,
		CheckRedirect: func(*http.Request, []*http.Request) error {
			return http.ErrUseLastResponse
		},
	}
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
