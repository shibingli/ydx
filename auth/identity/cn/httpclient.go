package cn

import (
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/shibingli/ydx/errs"
)

// ErrProviderResponse reports a malformed, oversized or non-successful HTTP response. | ErrProviderResponse 表示 HTTP 响应格式非法、过大或状态非成功。
var ErrProviderResponse = errs.New("cn: invalid provider response | cn：服务方响应非法")

// defaultHTTPTimeout bounds a provider request when the caller does not supply a client. | defaultHTTPTimeout 在调用方未提供客户端时限制服务方请求时长。
const defaultHTTPTimeout = 10 * time.Second

// maxHTTPResponseBytes caps how much of a provider response is read. | maxHTTPResponseBytes 限制服务方响应的读取上限。
const maxHTTPResponseBytes = 64 << 10

// maxProviderRedirects is the redirect-chain limit of the default client. Once the chain reaches
// the limit the client stops following and returns the last response. | maxProviderRedirects 是默认
// 客户端的重定向链上限；重定向链达到该上限后客户端停止跟随并返回最后一个响应。
const maxProviderRedirects = 10

// Provider response field caps. Oversized values are rejected instead of truncated so a provider
// cannot force unbounded result strings into downstream storage. | 服务方响应字段上限。超限值会被
// 拒绝而不是截断，避免服务方把无界结果字符串推入下游存储。
const (
	// maxProviderRequestIDLength caps requestId and messageId. | maxProviderRequestIDLength 限制
	// requestId 与 messageId。
	maxProviderRequestIDLength = 256
	// maxProviderMessageLength caps human-readable provider messages. | maxProviderMessageLength
	// 限制服务方人类可读消息。
	maxProviderMessageLength = 1024
	// maxProviderNameLength caps provider names. | maxProviderNameLength 限制服务方名称。
	maxProviderNameLength = 128
)

// httpClientOrDefault returns client, or a client with the configured timeout and a same-origin
// redirect policy. | httpClientOrDefault 返回 client，或带配置超时与同源重定向策略的新客户端。
//
// Static credential headers such as an API key are attached to the request, so the default client
// follows only redirects that keep the original host name and either preserve the effective port
// on the same scheme or upgrade HTTP to HTTPS (including the standard 80-to-443 upgrade).
// Cross-host redirects, HTTPS-to-HTTP downgrades and unrelated port changes are refused with
// http.ErrUseLastResponse, which returns the 3xx response to the caller for rejection as
// non-success. | API Key 等静态凭据请求头会附加到请求上，因此默认客户端只跟随保持原主机名且
// 在同一协议下保持有效端口，或把 HTTP 升级为 HTTPS（含标准 80 到 443 升级）的重定向。跨主机、
// HTTPS 降级到 HTTP 以及无关的端口变更会以 http.ErrUseLastResponse 拒绝，使 3xx 响应返回调用方
// 并按非成功状态处理。
func httpClientOrDefault(client *http.Client, timeout time.Duration) *http.Client {
	if client != nil {
		return client
	}
	if timeout <= 0 {
		timeout = defaultHTTPTimeout
	}
	return &http.Client{
		Timeout:       timeout,
		CheckRedirect: sameOriginRedirectPolicy,
	}
}

// sameOriginRedirectPolicy refuses redirects that could leak credential headers to another origin.
// | sameOriginRedirectPolicy 拒绝可能把凭据请求头泄露到其他来源的重定向。
func sameOriginRedirectPolicy(req *http.Request, via []*http.Request) error {
	if req == nil || req.URL == nil || len(via) == 0 || len(via) >= maxProviderRedirects {
		return http.ErrUseLastResponse
	}
	original := via[0].URL
	previous := via[len(via)-1].URL
	if original == nil || previous == nil || !strings.EqualFold(req.URL.Hostname(), original.Hostname()) {
		return http.ErrUseLastResponse
	}
	nextScheme := strings.ToLower(req.URL.Scheme)
	previousScheme := strings.ToLower(previous.Scheme)
	if nextScheme != "http" && nextScheme != "https" {
		return http.ErrUseLastResponse
	}
	if previousScheme == "https" && nextScheme == "http" {
		return http.ErrUseLastResponse
	}
	nextPort, ok := effectivePort(req.URL)
	if !ok {
		return http.ErrUseLastResponse
	}
	previousPort, ok := effectivePort(previous)
	if !ok {
		return http.ErrUseLastResponse
	}
	if nextScheme == previousScheme {
		if nextPort == previousPort {
			return nil
		}
		return http.ErrUseLastResponse
	}
	// Only HTTP-to-HTTPS reaches this point. Same-port in-place TLS and the standard default-port
	// upgrade preserve the intended service; any other port change could target a different
	// service on the same host. | 此处只剩 HTTP 到 HTTPS。同端口原地 TLS 与标准默认端口升级保持
	// 原定服务；其他端口变更可能指向同一主机上的另一服务。
	if nextPort == previousPort {
		return nil
	}
	if previousPort == "80" && nextPort == "443" {
		return nil
	}
	return http.ErrUseLastResponse
}

// effectivePort returns the explicit or scheme-default port of u. | effectivePort 返回 u 的显式端口
// 或协议默认端口。
func effectivePort(u *url.URL) (string, bool) {
	if u == nil {
		return "", false
	}
	if port := u.Port(); port != "" {
		return port, true
	}
	switch strings.ToLower(u.Scheme) {
	case "http":
		return "80", true
	case "https":
		return "443", true
	}
	return "", false
}

// checkProviderField rejects an oversized provider field without echoing its value. | checkProviderField
// 拒绝超限的服务方字段，且不回显其值。
func checkProviderField(field, value string, limit int) error {
	if len(value) > limit {
		return errs.Detail(ErrProviderResponse, "%s exceeds %d bytes | %s 超过 %d 字节", field, limit, field, limit)
	}
	return nil
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
