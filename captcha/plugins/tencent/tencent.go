// Package tencent delivers captcha codes through Tencent Cloud SMS. | Package tencent 通过腾讯云短信下发验证码。
package tencent

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
	// ErrInvalidOptions indicates unusable Tencent Cloud options. | ErrInvalidOptions 表示腾讯云选项不可用。
	ErrInvalidOptions = errs.New("tencent: invalid options | tencent：非法选项")
	// ErrDelivery indicates a failed SendSms response. | ErrDelivery 表示 SendSms 返回失败。
	ErrDelivery = errs.New("tencent: delivery failed | tencent：投递失败")
)

// DefaultEndpoint is the public SMS API endpoint. | DefaultEndpoint 是公网短信 API 端点。
const DefaultEndpoint = "https://sms.tencentcloudapi.com"

// apiService and apiVersion identify the Tencent Cloud SMS API. | apiService 与 apiVersion 标识腾讯云短信 API。
const (
	apiService = "sms"
	apiVersion = "2021-01-11"
	apiAction  = "SendSms"
)

// Options configures the Tencent Cloud SMS sender. | Options 配置腾讯云短信发送器。
type Options struct {
	// Client overrides the HTTP client. | Client 覆盖 HTTP 客户端。
	Client *http.Client
	// SecretID is the CAM secret id. | SecretID 是 CAM 密钥 ID。
	SecretID string
	// SecretKey is the CAM secret key. | SecretKey 是 CAM 密钥。
	SecretKey string
	// SdkAppID is the SMS application id. | SdkAppID 是短信应用 ID。
	SdkAppID string
	// SignName is the approved SMS signature. | SignName 是已审核短信签名。
	SignName string
	// TemplateID is the approved template id. | TemplateID 是已审核模板 ID。
	TemplateID string
	// Region is the API region; empty means ap-guangzhou. | Region 是 API 地域；空值为 ap-guangzhou。
	Region string
	// Endpoint overrides the API endpoint. | Endpoint 覆盖 API 端点。
	Endpoint string
	// ExtraParams are appended after the code in TemplateParamSet. | ExtraParams 追加在验证码之后的模板参数。
	ExtraParams []string
	// Timeout bounds one request. | Timeout 限制一次请求。
	Timeout time.Duration
	// AllowInsecureHTTP permits a plaintext http:// endpoint for local development. | AllowInsecureHTTP 允许本地开发使用明文 http:// 端点。
	AllowInsecureHTTP bool
}

// Sender is a Tencent Cloud SMS captcha sender. | Sender 是腾讯云短信验证码发送器。
type Sender struct {
	client      *http.Client
	endpoint    string
	host        string
	secretID    string
	secretKey   string
	sdkAppID    string
	signName    string
	templateID  string
	region      string
	timeout     time.Duration
	extraParams []string
}

// New validates options and builds a sender. | New 校验选项并构建发送器。
func New(o Options) (*Sender, error) {
	if strings.TrimSpace(o.SecretID) == "" || strings.TrimSpace(o.SecretKey) == "" {
		return nil, errs.Detail(ErrInvalidOptions, "missing secret id or key | 缺少密钥 ID 或密钥")
	}
	if strings.TrimSpace(o.SdkAppID) == "" || strings.TrimSpace(o.SignName) == "" || strings.TrimSpace(o.TemplateID) == "" {
		return nil, errs.Detail(ErrInvalidOptions, "missing app id, sign name or template id | 缺少应用 ID、签名或模板 ID")
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
	region := strings.TrimSpace(o.Region)
	if region == "" {
		region = "ap-guangzhou"
	}
	timeout := o.Timeout
	if timeout <= 0 {
		timeout = 10 * time.Second
	}
	client := o.Client
	if client == nil {
		client = &http.Client{Timeout: timeout, CheckRedirect: refuseRedirect}
	}
	return &Sender{
		client:      client,
		endpoint:    endpoint,
		host:        parsed.Host,
		secretID:    o.SecretID,
		secretKey:   o.SecretKey,
		sdkAppID:    o.SdkAppID,
		signName:    o.SignName,
		templateID:  o.TemplateID,
		region:      region,
		timeout:     timeout,
		extraParams: append([]string(nil), o.ExtraParams...),
	}, nil
}

// refuseRedirect prevents signed requests from being redirected to another origin. | refuseRedirect 防止签名请求被重定向到其他来源。
func refuseRedirect(_ *http.Request, _ []*http.Request) error { return http.ErrUseLastResponse }

// Channel implements core.Sender. | Channel 实现 core.Sender。
func (s *Sender) Channel() core.Channel { return core.ChannelSMS }

// sendSmsRequest is the SendSms request body. | sendSmsRequest 是 SendSms 请求正文。
type sendSmsRequest struct {
	PhoneNumberSet   []string `json:"PhoneNumberSet"`
	SmsSdkAppID      string   `json:"SmsSdkAppId"`
	SignName         string   `json:"SignName"`
	TemplateID       string   `json:"TemplateId"`
	TemplateParamSet []string `json:"TemplateParamSet"`
}

// sendSmsResponse is the SendSms response body. | sendSmsResponse 是 SendSms 响应正文。
type sendSmsResponse struct {
	Response struct {
		Error *struct {
			Code    string `json:"Code"`
			Message string `json:"Message"`
		} `json:"Error"`
		RequestID     string `json:"RequestId"`
		SendStatusSet []struct {
			Code    string `json:"Code"`
			Message string `json:"Message"`
		} `json:"SendStatusSet"`
	} `json:"Response"`
}

// Send implements core.Sender. | Send 实现 core.Sender。
func (s *Sender) Send(ctx context.Context, msg core.Message) error {
	if s.timeout > 0 {
		var cancel context.CancelFunc
		ctx, cancel = context.WithTimeout(ctx, s.timeout)
		defer cancel()
	}
	params := make([]string, 0, 1+len(s.extraParams))
	params = append(params, msg.Code)
	params = append(params, s.extraParams...)
	payload, err := json.Marshal(sendSmsRequest{
		PhoneNumberSet:   []string{msg.To},
		SmsSdkAppID:      s.sdkAppID,
		SignName:         s.signName,
		TemplateID:       s.templateID,
		TemplateParamSet: params,
	})
	if err != nil {
		return errs.Wrap(err, core.ErrSendFailed)
	}
	timestamp := time.Now().Unix()
	date := time.Unix(timestamp, 0).UTC().Format("2006-01-02")
	authorization := s.authorization(payload, timestamp, date)
	request, err := http.NewRequestWithContext(ctx, http.MethodPost, s.endpoint, bytes.NewReader(payload))
	if err != nil {
		return errs.Wrap(err, core.ErrSendFailed)
	}
	request.Header.Set("Content-Type", "application/json; charset=utf-8")
	request.Host = s.host
	request.Header.Set("X-TC-Action", apiAction)
	request.Header.Set("X-TC-Version", apiVersion)
	request.Header.Set("X-TC-Timestamp", strconv.FormatInt(timestamp, 10))
	request.Header.Set("X-TC-Region", s.region)
	request.Header.Set("Authorization", authorization)
	responseHTTP, err := s.client.Do(request)
	if err != nil {
		return errs.Wrap(err, core.ErrSendFailed)
	}
	defer responseHTTP.Body.Close()
	if responseHTTP.StatusCode < 200 || responseHTTP.StatusCode >= 300 {
		return errs.Detail(ErrDelivery, "http status %d | HTTP 状态 %d", responseHTTP.StatusCode, responseHTTP.StatusCode)
	}
	var body sendSmsResponse
	if err := json.NewDecoder(responseHTTP.Body).Decode(&body); err != nil {
		return errs.Wrap(err, ErrDelivery)
	}
	if body.Response.Error != nil {
		return errs.Detail(ErrDelivery, "provider code %q | 供应商错误码 %q", body.Response.Error.Code, body.Response.Error.Code)
	}
	if len(body.Response.SendStatusSet) == 0 {
		return errs.Detail(ErrDelivery, "provider returned no delivery status | 供应商未返回投递状态")
	}
	for _, status := range body.Response.SendStatusSet {
		if status.Code != "" && status.Code != "Ok" {
			return errs.Detail(ErrDelivery, "provider code %q | 供应商错误码 %q", status.Code, status.Code)
		}
	}
	return nil
}

// authorization builds the TC3-HMAC-SHA256 Authorization header. | authorization 构建 TC3-HMAC-SHA256 Authorization 头。
func (s *Sender) authorization(payload []byte, timestamp int64, date string) string {
	canonicalHeaders := "content-type:application/json; charset=utf-8\nhost:" + s.host + "\n"
	signedHeaders := "content-type;host"
	hashedPayload := sha256Hex(payload)
	canonicalRequest := "POST\n/\n\n" + canonicalHeaders + "\n" + signedHeaders + "\n" + hashedPayload
	credentialScope := date + "/" + apiService + "/tc3_request"
	stringToSign := "TC3-HMAC-SHA256\n" + strconv.FormatInt(timestamp, 10) + "\n" + credentialScope + "\n" + sha256Hex([]byte(canonicalRequest))
	secretDate := hmacSHA256([]byte("TC3"+s.secretKey), date)
	secretService := hmacSHA256(secretDate, apiService)
	secretSigning := hmacSHA256(secretService, "tc3_request")
	signature := hex.EncodeToString(hmacSHA256(secretSigning, stringToSign))
	return "TC3-HMAC-SHA256 Credential=" + s.secretID + "/" + credentialScope + ", SignedHeaders=" + signedHeaders + ", Signature=" + signature
}

// sha256Hex returns the lowercase SHA-256 hex digest. | sha256Hex 返回小写 SHA-256 十六进制摘要。
func sha256Hex(data []byte) string {
	sum := sha256.Sum256(data)
	return hex.EncodeToString(sum[:])
}

// hmacSHA256 returns the raw HMAC-SHA256 digest. | hmacSHA256 返回原始 HMAC-SHA256 摘要。
func hmacSHA256(key []byte, data string) []byte {
	mac := hmac.New(sha256.New, key)
	_, _ = mac.Write([]byte(data))
	return mac.Sum(nil)
}
