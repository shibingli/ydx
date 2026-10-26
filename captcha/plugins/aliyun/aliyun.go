// Package aliyun delivers captcha codes through Alibaba Cloud Dysmsapi. | Package aliyun 通过阿里云 Dysmsapi 下发验证码。
package aliyun

import (
	"context"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha1"
	"encoding/hex"
	"net/http"
	"net/url"
	"sort"
	"strings"
	"time"

	"github.com/shibingli/ydx/base64"
	"github.com/shibingli/ydx/captcha/core"
	"github.com/shibingli/ydx/errs"
	"github.com/shibingli/ydx/json"
)

var (
	// ErrInvalidOptions indicates unusable Aliyun options. | ErrInvalidOptions 表示阿里云选项不可用。
	ErrInvalidOptions = errs.New("aliyun: invalid options | aliyun：非法选项")
	// ErrDelivery indicates a non-OK Dysmsapi response. | ErrDelivery 表示 Dysmsapi 返回非 OK。
	ErrDelivery = errs.New("aliyun: delivery failed | aliyun：投递失败")
)

// DefaultEndpoint is the public Dysmsapi RPC endpoint. | DefaultEndpoint 是公网 Dysmsapi RPC 端点。
const DefaultEndpoint = "https://dysmsapi.aliyuncs.com/"

// Options configures the Aliyun SMS sender. | Options 配置阿里云短信发送器。
type Options struct {
	// ExtraParams are additional template variables. | ExtraParams 是额外的模板变量。
	ExtraParams map[string]string
	// Client overrides the HTTP client. | Client 覆盖 HTTP 客户端。
	Client *http.Client
	// AccessKeyID is the RAM access key id. | AccessKeyID 是 RAM 访问密钥 ID。
	AccessKeyID string
	// AccessKeySecret is the RAM access key secret. | AccessKeySecret 是 RAM 访问密钥 Secret。
	AccessKeySecret string
	// SignName is the approved SMS signature. | SignName 是已审核短信签名。
	SignName string
	// TemplateCode is the approved template code. | TemplateCode 是已审核模板 Code。
	TemplateCode string
	// RegionID is the API region; empty means cn-hangzhou. | RegionID 是 API 地域；空值为 cn-hangzhou。
	RegionID string
	// Endpoint overrides the API endpoint. | Endpoint 覆盖 API 端点。
	Endpoint string
	// Timeout bounds one request. | Timeout 限制一次请求。
	Timeout time.Duration
	// AllowInsecureHTTP permits a plaintext http:// endpoint for local development. | AllowInsecureHTTP 允许本地开发使用明文 http:// 端点。
	AllowInsecureHTTP bool
}

// Sender is an Aliyun Dysmsapi captcha sender. | Sender 是阿里云 Dysmsapi 验证码发送器。
type Sender struct {
	client          *http.Client
	extraParams     map[string]string
	endpoint        string
	accessKeyID     string
	accessKeySecret string
	signName        string
	templateCode    string
	regionID        string
	timeout         time.Duration
}

// New validates options and builds a sender. | New 校验选项并构建发送器。
func New(o Options) (*Sender, error) {
	if strings.TrimSpace(o.AccessKeyID) == "" || strings.TrimSpace(o.AccessKeySecret) == "" {
		return nil, errs.Detail(ErrInvalidOptions, "missing access key | 缺少访问密钥")
	}
	if strings.TrimSpace(o.SignName) == "" || strings.TrimSpace(o.TemplateCode) == "" {
		return nil, errs.Detail(ErrInvalidOptions, "missing sign name or template code | 缺少签名或模板 Code")
	}
	endpoint := strings.TrimSpace(o.Endpoint)
	if endpoint == "" {
		endpoint = DefaultEndpoint
	}
	parsed, err := url.Parse(endpoint)
	if err != nil || parsed.Host == "" || (parsed.Scheme != "https" && parsed.Scheme != "http") {
		return nil, errs.Detail(ErrInvalidOptions, "invalid endpoint | 非法端点")
	}
	if parsed.Scheme != "https" && !o.AllowInsecureHTTP {
		return nil, errs.Detail(ErrInvalidOptions, "https is required unless AllowInsecureHTTP is set | 除非设置 AllowInsecureHTTP，否则必须使用 https")
	}
	region := strings.TrimSpace(o.RegionID)
	if region == "" {
		region = "cn-hangzhou"
	}
	timeout := o.Timeout
	if timeout <= 0 {
		timeout = 10 * time.Second
	}
	client := o.Client
	if client == nil {
		client = &http.Client{Timeout: timeout, CheckRedirect: refuseRedirect}
	}
	extraParams := make(map[string]string, len(o.ExtraParams))
	for key, value := range o.ExtraParams {
		extraParams[key] = value
	}
	return &Sender{
		client:          client,
		endpoint:        endpoint,
		accessKeyID:     o.AccessKeyID,
		accessKeySecret: o.AccessKeySecret,
		signName:        o.SignName,
		templateCode:    o.TemplateCode,
		regionID:        region,
		timeout:         timeout,
		extraParams:     extraParams,
	}, nil
}

// refuseRedirect prevents signed query parameters from being redirected to another origin. | refuseRedirect 防止签名查询参数被重定向到其他来源。
func refuseRedirect(_ *http.Request, _ []*http.Request) error { return http.ErrUseLastResponse }

// Channel implements core.Sender. | Channel 实现 core.Sender。
func (s *Sender) Channel() core.Channel { return core.ChannelSMS }

// response is the Dysmsapi JSON body. | response 是 Dysmsapi JSON 正文。
type response struct {
	Code      string `json:"Code"`
	Message   string `json:"Message"`
	RequestID string `json:"RequestId"`
	BizID     string `json:"BizId"`
}

// Send implements core.Sender. | Send 实现 core.Sender。
func (s *Sender) Send(ctx context.Context, msg core.Message) error {
	if s.timeout > 0 {
		var cancel context.CancelFunc
		ctx, cancel = context.WithTimeout(ctx, s.timeout)
		defer cancel()
	}
	templateData := make(map[string]string, len(s.extraParams)+1)
	for key, value := range s.extraParams {
		templateData[key] = value
	}
	templateData["code"] = msg.Code
	templateParam, err := json.Marshal(templateData)
	if err != nil {
		return errs.Wrap(err, core.ErrSendFailed)
	}
	nonce, err := signatureNonce()
	if err != nil {
		return errs.Wrap(err, core.ErrSendFailed)
	}
	params := map[string]string{
		"AccessKeyId":      s.accessKeyID,
		"Action":           "SendSms",
		"Format":           "JSON",
		"PhoneNumbers":     msg.To,
		"RegionId":         s.regionID,
		"SignName":         s.signName,
		"SignatureMethod":  "HMAC-SHA1",
		"SignatureNonce":   nonce,
		"SignatureVersion": "1.0",
		"TemplateCode":     s.templateCode,
		"TemplateParam":    string(templateParam),
		"Timestamp":        time.Now().UTC().Format("2006-01-02T15:04:05Z"),
		"Version":          "2017-05-25",
	}
	canonical := canonicalQuery(params)
	stringToSign := "POST&%2F&" + percentEncode(canonical)
	mac := hmac.New(sha1.New, []byte(s.accessKeySecret+"&"))
	_, _ = mac.Write([]byte(stringToSign))
	signature := base64.StdEncoding.EncodeToString(mac.Sum(nil))
	// Send signed parameters in the body so the plaintext code never reaches
	// proxy, gateway or APM access logs through a URL. | 把签名参数放在正文中，
	// 避免明文验证码通过 URL 进入代理、网关或 APM 访问日志。
	form := canonical + "&Signature=" + percentEncode(signature)
	request, err := http.NewRequestWithContext(ctx, http.MethodPost, strings.TrimSuffix(s.endpoint, "/"), strings.NewReader(form))
	if err != nil {
		return errs.Wrap(err, core.ErrSendFailed)
	}
	request.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	responseHTTP, err := s.client.Do(request)
	if err != nil {
		return errs.Wrap(err, core.ErrSendFailed)
	}
	defer responseHTTP.Body.Close()
	if responseHTTP.StatusCode < 200 || responseHTTP.StatusCode >= 300 {
		return errs.Detail(ErrDelivery, "http status %d | HTTP 状态 %d", responseHTTP.StatusCode, responseHTTP.StatusCode)
	}
	var body response
	if err := json.NewDecoder(responseHTTP.Body).Decode(&body); err != nil {
		return errs.Wrap(err, ErrDelivery)
	}
	if body.Code != "OK" {
		return errs.Detail(ErrDelivery, "provider code %q | 供应商错误码 %q", body.Code, body.Code)
	}
	return nil
}

// canonicalQuery builds Aliyun's sorted RFC3986 query string. | canonicalQuery 构建阿里云排序 RFC3986 查询串。
func canonicalQuery(params map[string]string) string {
	keys := make([]string, 0, len(params))
	for key := range params {
		keys = append(keys, key)
	}
	sort.Strings(keys)
	var b strings.Builder
	for i, key := range keys {
		if i > 0 {
			b.WriteByte('&')
		}
		b.WriteString(percentEncode(key))
		b.WriteByte('=')
		b.WriteString(percentEncode(params[key]))
	}
	return b.String()
}

// percentEncode applies Aliyun's RFC3986 encoding. | percentEncode 应用阿里云 RFC3986 编码。
func percentEncode(value string) string {
	encoded := url.QueryEscape(value)
	encoded = strings.ReplaceAll(encoded, "+", "%20")
	encoded = strings.ReplaceAll(encoded, "*", "%2A")
	encoded = strings.ReplaceAll(encoded, "%7E", "~")
	return encoded
}

// signatureNonce returns a random request nonce. | signatureNonce 返回随机请求 nonce。
func signatureNonce() (string, error) {
	var buf [16]byte
	if _, err := rand.Read(buf[:]); err != nil {
		return "", err
	}
	return hex.EncodeToString(buf[:]), nil
}
