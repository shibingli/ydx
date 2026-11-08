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

// HTTPProviderConfig configures an HTTPProvider. | HTTPProviderConfig 配置 HTTPProvider。
type HTTPProviderConfig struct {
	// URL is the SMS provider endpoint. It is required. | URL 是短信服务方端点，必填。
	URL string
	// Client, when set, is used as-is; otherwise a client with Timeout is created. | Client 非空时原样使用；否则创建带 Timeout 的客户端。
	Client *http.Client
	// Timeout bounds each request when Client is nil; it defaults to 10 seconds. | Timeout 在 Client 为空时限制每个请求，默认 10 秒。
	Timeout time.Duration
	// Headers are static request headers, for example an API key header. | Headers 是静态请求头，例如 API Key 请求头。
	Headers map[string]string
	// Sign, when set, runs after the body and headers are ready and may add authentication headers. | Sign 非空时在请求体与请求头就绪后运行，可添加认证请求头。
	Sign func(ctx context.Context, req *http.Request, body []byte) error
	// BuildRequest, when set, replaces the default request encoder. | BuildRequest 非空时替换默认请求编码器。
	BuildRequest func(ctx context.Context, mobile, templateID string, params map[string]string) ([]byte, error)
	// Decode, when set, replaces the default response decoder and returns the provider request ID. | Decode 非空时替换默认响应解码器并返回服务方请求标识。
	Decode func(ctx context.Context, resp *http.Response, body []byte) (string, error)
}

// HTTPProvider is a generic net/http implementation of SMSProvider. | HTTPProvider 是 SMSProvider 的通用 net/http 实现。
//
// The default request body is {"mobile":...,"templateId":...,"params":{...}} and the default response
// is {"requestId":"..."} (the alternative "messageId" field is also accepted). Vendors with different
// envelopes configure BuildRequest and Decode; credentials are supplied through Headers or Sign and
// are never hardcoded. | 默认请求体为 {"mobile":...,"templateId":...,"params":{...}}，默认响应为
// {"requestId":"..."}（也接受备用的 "messageId" 字段）。报文格式不同的厂商配置 BuildRequest 与
// Decode；凭据经 Headers 或 Sign 提供，绝不硬编码。
type HTTPProvider struct {
	url          string
	client       *http.Client
	headers      map[string]string
	sign         func(ctx context.Context, req *http.Request, body []byte) error
	buildRequest func(ctx context.Context, mobile, templateID string, params map[string]string) ([]byte, error)
	decode       func(ctx context.Context, resp *http.Response, body []byte) (string, error)
}

// NewHTTPProvider validates cfg and returns an HTTPProvider. | NewHTTPProvider 校验 cfg 并返回 HTTPProvider。
func NewHTTPProvider(cfg HTTPProviderConfig) (*HTTPProvider, error) {
	url := strings.TrimSpace(cfg.URL)
	if url == "" {
		return nil, errs.Detail(ErrInvalidConfig, "SMS endpoint URL is empty | 短信端点 URL 为空")
	}
	headers := make(map[string]string, len(cfg.Headers))
	for key, value := range cfg.Headers {
		headers[key] = value
	}
	return &HTTPProvider{
		url:          url,
		client:       httpClientOrDefault(cfg.Client, cfg.Timeout),
		headers:      headers,
		sign:         cfg.Sign,
		buildRequest: cfg.BuildRequest,
		decode:       cfg.Decode,
	}, nil
}

// Send delivers one templated SMS message. | Send 发送一条模板短信。
//
// A nil context is replaced by context.Background. Transport, signing, non-2xx and decoding failures
// wrap ErrSMSSend or ErrProviderResponse and never include the mobile number or template parameters. |
// nil 上下文会替换为 context.Background。传输、签名、非 2xx 与解码失败包装 ErrSMSSend 或
// ErrProviderResponse，且不包含手机号或模板参数。
func (p *HTTPProvider) Send(ctx context.Context, mobile, templateID string, params map[string]string) (string, error) {
	if p == nil {
		return "", errs.Detail(ErrInvalidConfig, "HTTP SMS provider is nil | HTTP 短信服务方为空")
	}
	if ctx == nil {
		ctx = context.Background()
	}
	body, err := p.build(ctx, mobile, templateID, params)
	if err != nil {
		return "", err
	}
	httpReq, err := http.NewRequestWithContext(ctx, http.MethodPost, p.url, bytes.NewReader(body))
	if err != nil {
		return "", errs.Wrap(err, ErrSMSSend)
	}
	httpReq.Header.Set("Content-Type", "application/json")
	httpReq.Header.Set("Accept", "application/json")
	applyHTTPHeaders(httpReq, p.headers)
	if p.sign != nil {
		if err := p.sign(ctx, httpReq, body); err != nil {
			return "", errs.WrapDetail(err, ErrSMSSend, "sign request | 签名请求")
		}
	}

	resp, err := p.client.Do(httpReq)
	if err != nil {
		return "", errs.WrapDetail(err, ErrSMSSend, "send request | 发送请求")
	}
	defer func() { _ = resp.Body.Close() }()
	responseBody, err := readHTTPBody(resp)
	if err != nil {
		return "", errs.Wrap(err, ErrSMSSend)
	}
	decode := p.decode
	if decode == nil {
		decode = decodeSMSHTTPResponse
	}
	return decode(ctx, resp, responseBody)
}

// build returns the default or configured request body. | build 返回默认或配置的请求体。
func (p *HTTPProvider) build(ctx context.Context, mobile, templateID string, params map[string]string) ([]byte, error) {
	if p.buildRequest != nil {
		body, err := p.buildRequest(ctx, mobile, templateID, params)
		if err != nil {
			return nil, errs.Wrap(err, ErrInvalidRequest)
		}
		return body, nil
	}
	body, err := json.Marshal(smsHTTPPayload{Mobile: mobile, TemplateID: templateID, Params: params})
	if err != nil {
		return nil, errs.Wrap(err, ErrInvalidRequest)
	}
	return body, nil
}

// smsHTTPPayload is the default request envelope. | smsHTTPPayload 是默认请求报文。
type smsHTTPPayload struct {
	// Mobile is the recipient phone number. | Mobile 是接收方手机号。
	Mobile string `json:"mobile"`
	// TemplateID is the provider template identifier. | TemplateID 是服务方模板标识。
	TemplateID string `json:"templateId"`
	// Params are the template parameters. | Params 是模板参数。
	Params map[string]string `json:"params,omitempty"`
}

// smsHTTPResponse is the default response envelope. | smsHTTPResponse 是默认响应报文。
type smsHTTPResponse struct {
	// RequestID is the provider request identifier. | RequestID 是服务方请求标识。
	RequestID string `json:"requestId"`
	// MessageID is the provider message identifier. | MessageID 是服务方消息标识。
	MessageID string `json:"messageId"`
}

// decodeSMSHTTPResponse is the default response decoder. | decodeSMSHTTPResponse 是默认响应解码器。
func decodeSMSHTTPResponse(ctx context.Context, resp *http.Response, body []byte) (string, error) {
	if err := requireSuccessStatus(resp); err != nil {
		return "", errs.Wrap(err, ErrSMSSend)
	}
	var payload smsHTTPResponse
	if err := json.Unmarshal(body, &payload); err != nil {
		// The decoder error may quote bytes from the provider body; replace it with a fixed message
		// so response content cannot reach logs or caller errors. | 解码错误可能引用响应体字节；
		// 用固定消息替换，避免响应内容进入日志或调用方错误。
		return "", errs.Detail(ErrProviderResponse, "decode response | 解码响应")
	}
	if payload.RequestID != "" {
		if err := checkProviderField("requestId", payload.RequestID, maxProviderRequestIDLength); err != nil {
			return "", err
		}
		return payload.RequestID, nil
	}
	if err := checkProviderField("messageId", payload.MessageID, maxProviderRequestIDLength); err != nil {
		return "", err
	}
	return payload.MessageID, nil
}
