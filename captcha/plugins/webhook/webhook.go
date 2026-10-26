// Package webhook bridges captcha codes to an HMAC-authenticated cloud SMS gateway.
// | Package webhook 通过 HMAC 认证的云短信网关桥接验证码。
//
// The signature header is hex(HMAC-SHA256(secret, timestamp + "." + body)); the
// timestamp header carries Unix seconds. | 签名头为
// hex(HMAC-SHA256(secret, timestamp + "." + body))，时间戳头携带 Unix 秒。
package webhook

import (
	"bytes"
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"

	"github.com/shibingli/ydx/captcha/core"
	"github.com/shibingli/ydx/errs"
	"github.com/shibingli/ydx/json"
)

var (
	// ErrInvalidOptions indicates unusable webhook options. | ErrInvalidOptions 表示 webhook 选项不可用。
	ErrInvalidOptions = errs.New("webhook: invalid options | webhook：非法选项")
	// ErrDelivery indicates a non-2xx gateway response. | ErrDelivery 表示网关返回非 2xx。
	ErrDelivery = errs.New("webhook: delivery failed | webhook：投递失败")
)

// Options configures the generic webhook sender. | Options 配置通用 webhook 发送器。
type Options struct {
	// Headers adds fixed gateway headers such as an API key. | Headers 添加固定网关头，例如 API key。
	Headers map[string]string
	// Client overrides the HTTP client. | Client 覆盖 HTTP 客户端。
	Client *http.Client
	// URL is the gateway endpoint. | URL 是网关端点。
	URL string
	// Channel is sms by default and may be email for a relay. | Channel 默认为 sms，也可设为 email 以对接中继。
	Channel core.Channel
	// SignatureHeader is the signature header name; empty means X-Captcha-Signature. | SignatureHeader 是签名头名；空值为 X-Captcha-Signature。
	SignatureHeader string
	// TimestampHeader is the timestamp header name; empty means X-Captcha-Timestamp. | TimestampHeader 是时间戳头名；空值为 X-Captcha-Timestamp。
	TimestampHeader string
	// Secret signs the request body and timestamp. | Secret 对请求正文与时间戳签名。
	Secret []byte
	// Timeout bounds one delivery. | Timeout 限制一次投递。
	Timeout time.Duration
	// AllowInsecureHTTP permits a plaintext http:// gateway for local development. | AllowInsecureHTTP 允许本地开发使用明文 http:// 网关。
	AllowInsecureHTTP bool
}

// Sender posts signed code messages to a gateway. | Sender 向网关发送签名验证码消息。
type Sender struct {
	client          *http.Client
	headers         map[string]string
	url             string
	channel         core.Channel
	signatureHeader string
	timestampHeader string
	secret          []byte
	timeout         time.Duration
}

// New validates options and builds a webhook sender. | New 校验选项并构建 webhook 发送器。
func New(o Options) (*Sender, error) {
	endpoint := strings.TrimSpace(o.URL)
	parsed, err := url.Parse(endpoint)
	if err != nil || parsed.Host == "" || (parsed.Scheme != "https" && parsed.Scheme != "http") {
		return nil, errs.Detail(ErrInvalidOptions, "URL must be absolute HTTP(S) | URL 必须是绝对 HTTP(S) 地址")
	}
	if parsed.Scheme != "https" && !o.AllowInsecureHTTP {
		return nil, errs.Detail(ErrInvalidOptions, "https is required unless AllowInsecureHTTP is set | 除非设置 AllowInsecureHTTP，否则必须使用 https")
	}
	if len(o.Secret) < 16 {
		return nil, errs.Detail(ErrInvalidOptions, "secret is shorter than 16 bytes | 密钥短于 16 字节")
	}
	channel := o.Channel
	if channel == "" {
		channel = core.ChannelSMS
	}
	if !channel.Valid() {
		return nil, errs.Detail(ErrInvalidOptions, "invalid channel %q | 非法通道 %q", channel, channel)
	}
	signatureHeader := strings.TrimSpace(o.SignatureHeader)
	if signatureHeader == "" {
		signatureHeader = "X-Captcha-Signature"
	}
	timestampHeader := strings.TrimSpace(o.TimestampHeader)
	if timestampHeader == "" {
		timestampHeader = "X-Captcha-Timestamp"
	}
	timeout := o.Timeout
	if timeout <= 0 {
		timeout = 10 * time.Second
	}
	client := o.Client
	if client == nil {
		client = &http.Client{Timeout: timeout, CheckRedirect: refuseRedirect}
	}
	headers := make(map[string]string, len(o.Headers))
	for key, value := range o.Headers {
		headers[key] = value
	}
	return &Sender{
		client:          client,
		url:             endpoint,
		channel:         channel,
		secret:          append([]byte(nil), o.Secret...),
		signatureHeader: signatureHeader,
		timestampHeader: timestampHeader,
		headers:         headers,
		timeout:         timeout,
	}, nil
}

// refuseRedirect prevents an API response from redirecting a signed request or code body. | refuseRedirect 防止 API 响应把签名请求或验证码正文重定向到别处。
func refuseRedirect(_ *http.Request, _ []*http.Request) error { return http.ErrUseLastResponse }

// Channel implements core.Sender. | Channel 实现 core.Sender。
func (s *Sender) Channel() core.Channel { return s.channel }

// wireMessage is the gateway request body. | wireMessage 是网关请求正文。
type wireMessage struct {
	Data      map[string]string `json:"data,omitempty"`
	Channel   core.Channel      `json:"channel"`
	To        string            `json:"to"`
	Code      string            `json:"code"`
	Action    string            `json:"action"`
	Locale    string            `json:"locale"`
	Template  string            `json:"template"`
	ExpiresIn int64             `json:"expires_in"`
}

// Send implements core.Sender. | Send 实现 core.Sender。
func (s *Sender) Send(ctx context.Context, msg core.Message) error {
	if s.timeout > 0 {
		var cancel context.CancelFunc
		ctx, cancel = context.WithTimeout(ctx, s.timeout)
		defer cancel()
	}
	payload, err := json.Marshal(wireMessage{
		Channel:   msg.Channel,
		To:        msg.To,
		Code:      msg.Code,
		Action:    msg.Action,
		Locale:    msg.Locale,
		Template:  msg.Template,
		Data:      msg.Data,
		ExpiresIn: int64(msg.ExpiresIn / time.Second),
	})
	if err != nil {
		return errs.Wrap(err, core.ErrSendFailed)
	}
	timestamp := strconv.FormatInt(time.Now().Unix(), 10)
	mac := hmac.New(sha256.New, s.secret)
	_, _ = mac.Write([]byte(timestamp))
	_, _ = mac.Write([]byte("."))
	_, _ = mac.Write(payload)
	signature := hex.EncodeToString(mac.Sum(nil))
	request, err := http.NewRequestWithContext(ctx, http.MethodPost, s.url, bytes.NewReader(payload))
	if err != nil {
		return errs.Wrap(err, core.ErrSendFailed)
	}
	request.Header.Set("Content-Type", "application/json")
	for key, value := range s.headers {
		request.Header.Set(key, value)
	}
	// Signature and timestamp are written last so custom headers cannot
	// accidentally override the authenticated values. | 最后写入签名与时间戳，
	// 避免自定义头覆盖已认证值。
	request.Header.Set(s.signatureHeader, signature)
	request.Header.Set(s.timestampHeader, timestamp)
	response, err := s.client.Do(request)
	if err != nil {
		return errs.Wrap(err, core.ErrSendFailed)
	}
	defer response.Body.Close()
	if response.StatusCode < 200 || response.StatusCode >= 300 {
		return errs.Detail(ErrDelivery, "gateway status %d | 网关状态 %d", response.StatusCode, response.StatusCode)
	}
	return nil
}
