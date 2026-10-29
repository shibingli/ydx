// Package notify provides the built-in workflow notification channels: a generic webhook that
// speaks the WeCom, DingTalk, Feishu and plain JSON dialects, an SMTP mail channel and a log
// channel for development. | Package notify 提供内置流程通知渠道：支持企业微信、钉钉、飞书与普通
// JSON 方言的通用 Webhook、SMTP 邮件渠道，以及开发用日志渠道。
package notify

import (
	"bytes"
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"io"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"

	"github.com/shibingli/ydx/base64"
	"github.com/shibingli/ydx/errs"
	"github.com/shibingli/ydx/json"
	"github.com/shibingli/ydx/workflow"
)

// Sentinel errors of the notification channels. | 通知渠道的哨兵错误。
var (
	// ErrInvalidOptions reports an unusable channel configuration. | ErrInvalidOptions 表示渠道配置不可用。
	ErrInvalidOptions = errs.New("invalid notification channel options | 非法的通知渠道配置")
	// ErrDelivery reports a non-2xx webhook response. | ErrDelivery 表示 Webhook 响应非 2xx。
	ErrDelivery = errs.New("notification delivery failed | 通知投递失败")
)

// Webhook kinds. | Webhook 方言。
const (
	// KindGeneric posts the notification fields as a plain JSON object. | KindGeneric 以普通 JSON 对象提交通知字段。
	KindGeneric = "generic"
	// KindWeCom posts a WeCom robot markdown message. | KindWeCom 提交企业微信机器人 markdown 消息。
	KindWeCom = "wecom"
	// KindDingTalk posts a DingTalk robot markdown message. | KindDingTalk 提交钉钉机器人 markdown 消息。
	KindDingTalk = "dingtalk"
	// KindFeishu posts a Feishu robot text message. | KindFeishu 提交飞书机器人文本消息。
	KindFeishu = "feishu"
)

// WebhookOptions configure one webhook channel. | WebhookOptions 配置一个 Webhook 渠道。
type WebhookOptions struct {
	// Client overrides the HTTP client for tests. | Client 覆盖测试用 HTTP 客户端。
	Client *http.Client
	// URL is the robot endpoint. | URL 是机器人端点。
	URL string
	// Kind selects the payload dialect. | Kind 选择载荷方言。
	Kind string
	// Secret signs DingTalk requests. | Secret 为钉钉请求签名。
	Secret string
	// Timeout bounds one request. | Timeout 限制单次请求。
	Timeout time.Duration
}

// Webhook is one HTTP notification channel. | Webhook 是一个 HTTP 通知渠道。
type Webhook struct {
	// client is the HTTP client. | client 是 HTTP 客户端。
	client *http.Client
	// url is the robot endpoint. | url 是机器人端点。
	url string
	// kind is the payload dialect. | kind 是载荷方言。
	kind string
	// secret signs DingTalk requests. | secret 为钉钉请求签名。
	secret string
	// timeout bounds one request. | timeout 限制单次请求。
	timeout time.Duration
}

// NewWebhook builds one webhook channel. | NewWebhook 构建一个 Webhook 渠道。
func NewWebhook(o WebhookOptions) (*Webhook, error) {
	target := strings.TrimSpace(o.URL)
	if target == "" {
		return nil, ErrInvalidOptions
	}
	parsed, err := url.Parse(target)
	if err != nil || (parsed.Scheme != "http" && parsed.Scheme != "https") || parsed.Host == "" {
		return nil, errs.Detail(ErrInvalidOptions, "webhook URL must be HTTP(S) | Webhook URL 必须是 HTTP(S)")
	}
	kind := strings.ToLower(strings.TrimSpace(o.Kind))
	if kind == "" {
		kind = KindGeneric
	}
	switch kind {
	case KindGeneric, KindWeCom, KindDingTalk, KindFeishu:
	default:
		return nil, errs.Detail(ErrInvalidOptions, "unknown webhook kind %[1]q | 未知的 Webhook 方言 %[1]q", kind)
	}
	if o.Timeout <= 0 {
		o.Timeout = 10 * time.Second
	}
	client := o.Client
	if client == nil {
		client = &http.Client{Timeout: o.Timeout}
	}
	return &Webhook{url: target, kind: kind, secret: strings.TrimSpace(o.Secret), timeout: o.Timeout, client: client}, nil
}

// Name returns the channel name. | Name 返回渠道名。
func (w *Webhook) Name() string { return "webhook" }

// Send posts one notification. | Send 提交一条通知。
func (w *Webhook) Send(ctx context.Context, note workflow.Notification) error {
	payload, err := w.payload(note)
	if err != nil {
		return err
	}
	target := w.url
	if w.kind == KindDingTalk && w.secret != "" {
		target = signDingTalk(target, w.secret, time.Now())
	}
	request, err := http.NewRequestWithContext(ctx, http.MethodPost, target, bytes.NewReader(payload))
	if err != nil {
		return errs.Wrap(err, ErrDelivery)
	}
	request.Header.Set("Content-Type", "application/json")
	response, err := w.client.Do(request)
	if err != nil {
		// The URL may embed a token; the summary never repeats it. | URL 可能带 token；摘要绝不重复它。
		return errs.Detail(ErrDelivery, "webhook request failed | Webhook 请求失败")
	}
	defer func() { _ = response.Body.Close() }()
	_, _ = io.Copy(io.Discard, io.LimitReader(response.Body, 64<<10))
	if response.StatusCode < 200 || response.StatusCode >= 300 {
		return errs.Detail(ErrDelivery, "webhook status %[1]d | Webhook 状态 %[1]d", response.StatusCode)
	}
	return nil
}

// payload renders the dialect-specific JSON body. | payload 渲染方言相关的 JSON 请求体。
func (w *Webhook) payload(note workflow.Notification) ([]byte, error) {
	text := note.Title
	if note.Body != "" {
		if text != "" {
			text += "\n"
		}
		text += note.Body
	}
	if note.URL != "" {
		text += "\n" + note.URL
	}
	var body any
	switch w.kind {
	case KindWeCom:
		body = map[string]any{
			"msgtype":  "markdown",
			"markdown": map[string]any{"content": text},
		}
	case KindDingTalk:
		body = map[string]any{
			"msgtype":  "markdown",
			"markdown": map[string]any{"title": note.Title, "text": text},
		}
	case KindFeishu:
		body = map[string]any{
			"msg_type": "text",
			"content":  map[string]any{"text": text},
		}
	default:
		body = map[string]any{
			"event":       note.Kind,
			"tenant_id":   note.TenantID,
			"instance_id": note.InstanceID,
			"task_id":     note.TaskID,
			"recipient":   note.RecipientID,
			"title":       note.Title,
			"body":        note.Body,
			"url":         note.URL,
		}
	}
	data, err := json.Marshal(body)
	if err != nil {
		return nil, errs.Wrap(err, ErrDelivery)
	}
	return data, nil
}

// signDingTalk appends the DingTalk timestamp and HMAC signature. | signDingTalk 追加钉钉时间戳与 HMAC 签名。
func signDingTalk(target, secret string, now time.Time) string {
	timestamp := now.UnixMilli()
	stringToSign := strconv.FormatInt(timestamp, 10) + "\n" + secret
	mac := hmac.New(sha256.New, []byte(secret))
	mac.Write([]byte(stringToSign))
	signature := url.QueryEscape(base64.StdEncoding.EncodeToString(mac.Sum(nil)))
	separator := "?"
	if strings.Contains(target, "?") {
		separator = "&"
	}
	return target + separator + "timestamp=" + strconv.FormatInt(timestamp, 10) + "&sign=" + signature
}
