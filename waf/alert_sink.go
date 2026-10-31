package waf

import (
	"bytes"
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"github.com/shibingli/ydx/errs"
	"github.com/shibingli/ydx/json"
)

// FileSink appends one JSON line per alert to a file. | FileSink 为每条报警向文件追加一行 JSON。
type FileSink struct {
	path string
	mu   sync.Mutex
}

// NewFileSink creates a JSON-lines alert sink. | NewFileSink 创建 JSON-lines 报警 Sink。
func NewFileSink(path string) *FileSink { return &FileSink{path: path} }

// Name returns the sink name. | Name 返回 Sink 名称。
func (s *FileSink) Name() string { return "file" }

// Send appends one alert line. | Send 追加一行报警。
func (s *FileSink) Send(ctx context.Context, alert Alert) error {
	if s == nil || strings.TrimSpace(s.path) == "" {
		return errs.Detail(ErrInvalidOption, "empty alert file path | 空的报警文件路径")
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	data, err := json.Marshal(alert)
	if err != nil {
		return errs.Wrap(err, ErrBuild)
	}
	line := make([]byte, 0, len(data)+1)
	line = append(line, data...)
	line = append(line, '\n')
	s.mu.Lock()
	defer s.mu.Unlock()
	if err := os.MkdirAll(filepath.Dir(s.path), 0o750); err != nil {
		return errs.Wrap(err, ErrSource)
	}
	file, err := os.OpenFile(s.path, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0o600)
	if err != nil {
		return errs.Wrap(err, ErrSource)
	}
	defer func() { _ = file.Close() }()
	if _, err := file.Write(line); err != nil {
		return errs.Wrap(err, ErrSource)
	}
	return nil
}

// Close implements AlertSink. | Close 实现 AlertSink。
func (s *FileSink) Close() error { return nil }

// WebhookConfig configures an HTTP alert sink. | WebhookConfig 配置 HTTP 报警 Sink。
type WebhookConfig struct {
	URL          string
	Client       *http.Client
	Headers      map[string]string
	SignatureKey []byte
	Timeout      time.Duration
}

// WebhookSink posts alerts as JSON to an HTTP endpoint. | WebhookSink 把报警以 JSON POST 到 HTTP 端点。
type WebhookSink struct {
	url    string
	client *http.Client
	config WebhookConfig
}

// NewWebhookSink creates a webhook sink. | NewWebhookSink 创建 webhook Sink。
func NewWebhookSink(config WebhookConfig) (*WebhookSink, error) {
	if strings.TrimSpace(config.URL) == "" {
		return nil, errs.Detail(ErrInvalidOption, "empty webhook URL | 空的 webhook URL")
	}
	client := config.Client
	if client == nil {
		timeout := config.Timeout
		if timeout <= 0 {
			timeout = defaultAlertSinkTimeout
		}
		client = &http.Client{Timeout: timeout}
	}
	return &WebhookSink{url: config.URL, client: client, config: config}, nil
}

// Name returns the sink name. | Name 返回 Sink 名称。
func (s *WebhookSink) Name() string { return "webhook" }

// Send posts one alert. | Send 投递一条报警。
func (s *WebhookSink) Send(ctx context.Context, alert Alert) error {
	data, err := json.Marshal(alert)
	if err != nil {
		return errs.Wrap(err, ErrBuild)
	}
	request, err := http.NewRequestWithContext(ctx, http.MethodPost, s.url, bytes.NewReader(data))
	if err != nil {
		return errs.Wrap(err, ErrSource)
	}
	request.Header.Set("Content-Type", "application/json")
	for name, value := range s.config.Headers {
		request.Header.Set(name, value)
	}
	if len(s.config.SignatureKey) > 0 {
		mac := hmac.New(sha256.New, s.config.SignatureKey)
		_, _ = mac.Write(data)
		request.Header.Set("X-YDX-WAF-Signature", hex.EncodeToString(mac.Sum(nil)))
	}
	response, err := s.client.Do(request)
	if err != nil {
		return errs.Wrap(err, ErrSource)
	}
	defer func() { _ = response.Body.Close() }()
	_, _ = io.Copy(io.Discard, io.LimitReader(response.Body, 4096))
	if response.StatusCode < 200 || response.StatusCode > 299 {
		return errs.Detail(ErrSource, "webhook returned status %d | webhook 返回状态 %d", response.StatusCode, response.StatusCode)
	}
	return nil
}

// Close implements AlertSink. | Close 实现 AlertSink。
func (s *WebhookSink) Close() error { return nil }

// SinkFunc adapts functions to AlertSink. | SinkFunc 把函数适配为 AlertSink。
type SinkFunc struct {
	Fn       func(context.Context, Alert) error
	CloseFn  func() error
	SinkName string
}

// Name returns the sink name. | Name 返回 Sink 名称。
func (s SinkFunc) Name() string {
	if s.SinkName == "" {
		return "sink"
	}
	return s.SinkName
}

// Send calls the function. | Send 调用函数。
func (s SinkFunc) Send(ctx context.Context, alert Alert) error {
	if s.Fn == nil {
		return nil
	}
	return s.Fn(ctx, alert)
}

// Close calls the close function. | Close 调用关闭函数。
func (s SinkFunc) Close() error {
	if s.CloseFn == nil {
		return nil
	}
	return s.CloseFn()
}
