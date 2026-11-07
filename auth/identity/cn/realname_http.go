package cn

import (
	"bytes"
	"context"
	"net/http"
	"strings"
	"time"

	"github.com/shibingli/ydx/errs"
	"github.com/shibingli/ydx/json"
)

// HTTPVerifierConfig configures an HTTPVerifier. | HTTPVerifierConfig 配置 HTTPVerifier。
type HTTPVerifierConfig struct {
	// URL is the provider endpoint. It is required. | URL 是服务方端点，必填。
	URL string
	// Provider is the name stored in results when the response does not name one; it defaults to "http". | Provider 是响应未给出名称时写入结果的名称，默认 "http"。
	Provider string
	// Client, when set, is used as-is; otherwise a client with Timeout is created. | Client 非空时原样使用；否则创建带 Timeout 的客户端。
	Client *http.Client
	// Timeout bounds each request when Client is nil; it defaults to 10 seconds. | Timeout 在 Client 为空时限制每个请求，默认 10 秒。
	Timeout time.Duration
	// Headers are static request headers, for example an API key header. | Headers 是静态请求头，例如 API Key 请求头。
	Headers map[string]string
	// Sign, when set, runs after the body and headers are ready and may add authentication headers. | Sign 非空时在请求体与请求头就绪后运行，可添加认证请求头。
	Sign func(ctx context.Context, req *http.Request, body []byte) error
	// Decode, when set, replaces the default decoder. The body is already read and capped. | Decode 非空时替换默认解码器；响应体已读取并限制大小。
	Decode func(ctx context.Context, resp *http.Response, body []byte) (*RealNameResult, error)
}

// HTTPVerifier calls a configurable HTTP real-name verification endpoint. | HTTPVerifier 调用可配置的 HTTP 实名认证端点。
//
// The default request body is {"name":...,"idNumber":...,"mobile":...}; the default response body is
// {"verified":bool,"requestId":...,"message":...,"provider":...}. Vendors with different envelopes
// configure Decode, and vendors with request signing configure Sign; no credential is built in. |
// 默认请求体为 {"name":...,"idNumber":...,"mobile":...}，默认响应体为
// {"verified":bool,"requestId":...,"message":...,"provider":...}。报文格式不同的厂商配置 Decode，
// 需要请求签名的厂商配置 Sign；包内不内置任何凭据。
type HTTPVerifier struct {
	url      string
	provider string
	client   *http.Client
	headers  map[string]string
	sign     func(ctx context.Context, req *http.Request, body []byte) error
	decode   func(ctx context.Context, resp *http.Response, body []byte) (*RealNameResult, error)
}

// NewHTTPVerifier validates cfg and returns an HTTPVerifier. | NewHTTPVerifier 校验 cfg 并返回 HTTPVerifier。
func NewHTTPVerifier(cfg HTTPVerifierConfig) (*HTTPVerifier, error) {
	url := strings.TrimSpace(cfg.URL)
	if url == "" {
		return nil, errs.Detail(ErrInvalidConfig, "real-name endpoint URL is empty | 实名认证端点 URL 为空")
	}
	provider := strings.TrimSpace(cfg.Provider)
	if provider == "" {
		provider = "http"
	}
	headers := make(map[string]string, len(cfg.Headers))
	for key, value := range cfg.Headers {
		headers[key] = value
	}
	return &HTTPVerifier{
		url:      url,
		provider: provider,
		client:   httpClientOrDefault(cfg.Client, cfg.Timeout),
		headers:  headers,
		sign:     cfg.Sign,
		decode:   cfg.Decode,
	}, nil
}

// Verify sends req to the configured endpoint and decodes the result. | Verify 把 req 发送到配置的端点并解码结果。
//
// Name and IDNumber must be non-empty. Transport, signing, non-2xx and decoding failures wrap
// ErrRealNameProvider, or ErrProviderResponse for malformed responses; they never include the
// request values. | Name 与 IDNumber 必须非空。传输、签名、非 2xx 与解码失败包装
// ErrRealNameProvider，格式非法的响应包装 ErrProviderResponse；错误中不包含请求值。
func (v *HTTPVerifier) Verify(ctx context.Context, req RealNameRequest) (*RealNameResult, error) {
	if v == nil {
		return nil, errs.Detail(ErrInvalidConfig, "HTTP verifier is nil | HTTP 核验器为空")
	}
	if ctx == nil {
		ctx = context.Background()
	}
	name := strings.TrimSpace(req.Name)
	idNumber := strings.TrimSpace(req.IDNumber)
	if name == "" || idNumber == "" {
		return nil, errs.Detail(ErrInvalidRequest, "name and ID number are required | 姓名与身份证号必填")
	}

	payload, err := json.Marshal(realNameHTTPPayload{Name: name, IDNumber: idNumber, Mobile: strings.TrimSpace(req.Mobile)})
	if err != nil {
		return nil, errs.Wrap(err, ErrInvalidRequest)
	}
	httpReq, err := http.NewRequestWithContext(ctx, http.MethodPost, v.url, bytes.NewReader(payload))
	if err != nil {
		return nil, errs.Wrap(err, ErrRealNameProvider)
	}
	httpReq.Header.Set("Content-Type", "application/json")
	httpReq.Header.Set("Accept", "application/json")
	applyHTTPHeaders(httpReq, v.headers)
	if v.sign != nil {
		if err := v.sign(ctx, httpReq, payload); err != nil {
			return nil, errs.WrapDetail(err, ErrRealNameProvider, "sign request | 签名请求")
		}
	}

	resp, err := v.client.Do(httpReq)
	if err != nil {
		return nil, errs.WrapDetail(err, ErrRealNameProvider, "send request | 发送请求")
	}
	defer func() { _ = resp.Body.Close() }()
	body, err := readHTTPBody(resp)
	if err != nil {
		return nil, err
	}

	decode := v.decode
	if decode == nil {
		decode = decodeRealNameHTTPResponse
	}
	result, err := decode(ctx, resp, body)
	if err != nil {
		return nil, err
	}
	if result == nil {
		return nil, errs.Detail(ErrProviderResponse, "decoder returned no result | 解码器未返回结果")
	}
	if result.Provider == "" {
		result.Provider = v.provider
	}
	return result, nil
}

// realNameHTTPPayload is the default request envelope. | realNameHTTPPayload 是默认请求报文。
type realNameHTTPPayload struct {
	Name     string `json:"name"`
	IDNumber string `json:"idNumber"`
	Mobile   string `json:"mobile,omitempty"`
}

// realNameHTTPResponse is the default response envelope. | realNameHTTPResponse 是默认响应报文。
type realNameHTTPResponse struct {
	Verified  bool   `json:"verified"`
	RequestID string `json:"requestId"`
	Message   string `json:"message"`
	Provider  string `json:"provider"`
}

// decodeRealNameHTTPResponse is the default response decoder. | decodeRealNameHTTPResponse 是默认响应解码器。
func decodeRealNameHTTPResponse(ctx context.Context, resp *http.Response, body []byte) (*RealNameResult, error) {
	if err := requireSuccessStatus(resp); err != nil {
		return nil, errs.Wrap(err, ErrRealNameProvider)
	}
	var payload realNameHTTPResponse
	if err := json.Unmarshal(body, &payload); err != nil {
		return nil, errs.WrapDetail(err, ErrProviderResponse, "decode response | 解码响应")
	}
	return &RealNameResult{
		Verified:  payload.Verified,
		Provider:  payload.Provider,
		RequestID: payload.RequestID,
		Message:   payload.Message,
	}, nil
}
