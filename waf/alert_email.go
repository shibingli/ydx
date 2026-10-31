package waf

import (
	"context"
	"crypto/tls"
	"mime"
	"net"
	"net/mail"
	"net/smtp"
	"strconv"
	"strings"
	"time"

	"github.com/shibingli/ydx/errs"
)

// EmailConfig configures the built-in SMTP alert sink. | EmailConfig 配置内置 SMTP 报警 Sink。
type EmailConfig struct {
	// Host is the SMTP server host. | Host 是 SMTP 服务器主机。
	Host string
	// Username and Password authenticate with PLAIN when set. | Username 与 Password 非空时使用
	// PLAIN 认证。
	Username string
	Password string
	// From is the envelope and header sender, optionally with a display name.
	// | From 是信封与头部发件人，可带显示名。
	From string
	// SubjectPrefix prefixes every subject; default "[ydx-waf]". | SubjectPrefix 为每个主题加前缀；
	// 默认 "[ydx-waf]"。
	SubjectPrefix string
	// ClientName is the EHLO name; default "localhost". | ClientName 是 EHLO 名称；默认 "localhost"。
	ClientName string
	// To lists recipients. | To 列出收件人。
	To []string
	// Port is the SMTP port; defaults to 465 with ImplicitTLS and 587 otherwise.
	// | Port 是 SMTP 端口；ImplicitTLS 时默认 465，否则 587。
	Port int
	// Timeout bounds the SMTP conversation; default 10 seconds. | Timeout 限制 SMTP 会话；默认 10 秒。
	Timeout time.Duration
	// ImplicitTLS dials TLS directly, as port 465 requires. | ImplicitTLS 直接建立 TLS，465 端口需要。
	ImplicitTLS bool
	// StartTLS upgrades a plaintext connection. It defaults to true unless ImplicitTLS is set;
	// set DisableStartTLS to opt out. | StartTLS 升级明文连接。除 ImplicitTLS 外默认 true；可用
	// DisableStartTLS 关闭。
	StartTLS bool
	// DisableStartTLS explicitly keeps the connection plaintext. | DisableStartTLS 显式保持明文连接。
	DisableStartTLS bool
}

// EmailSink delivers alerts over SMTP. | EmailSink 通过 SMTP 投递报警。
type EmailSink struct {
	from     *mail.Address
	fromAddr string
	to       []*mail.Address
	toAddr   []string
	config   EmailConfig
}

// NewEmailSink validates the configuration and builds the sink. | NewEmailSink 校验配置并构建 Sink。
func NewEmailSink(config EmailConfig) (*EmailSink, error) {
	if strings.TrimSpace(config.Host) == "" {
		return nil, errs.Detail(ErrInvalidOption, "empty SMTP host | 空的 SMTP 主机")
	}
	from, err := mail.ParseAddress(strings.TrimSpace(config.From))
	if err != nil {
		return nil, errs.Detail(ErrInvalidOption, "invalid SMTP sender | 非法的 SMTP 发件人")
	}
	if len(config.To) == 0 {
		return nil, errs.Detail(ErrInvalidOption, "SMTP sink has no recipients | SMTP Sink 没有收件人")
	}
	recipients := make([]*mail.Address, 0, len(config.To))
	addresses := make([]string, 0, len(config.To))
	for _, value := range config.To {
		parsed, err := mail.ParseAddress(strings.TrimSpace(value))
		if err != nil {
			return nil, errs.Detail(ErrInvalidOption, "invalid SMTP recipient | 非法的 SMTP 收件人")
		}
		recipients = append(recipients, parsed)
		addresses = append(addresses, parsed.Address)
	}
	if config.Port == 0 {
		if config.ImplicitTLS {
			config.Port = 465
		} else {
			config.Port = 587
		}
	}
	if config.Port < 1 || config.Port > 65535 {
		return nil, errs.Detail(ErrInvalidOption, "invalid SMTP port | 非法的 SMTP 端口")
	}
	if config.SubjectPrefix == "" {
		config.SubjectPrefix = "[ydx-waf]"
	}
	if config.Timeout <= 0 {
		config.Timeout = defaultAlertSinkTimeout
	}
	if config.ClientName == "" {
		config.ClientName = "localhost"
	}
	if !config.ImplicitTLS && !config.DisableStartTLS {
		config.StartTLS = true
	}
	if !config.ImplicitTLS && !config.StartTLS && config.Username != "" {
		return nil, errs.Detail(ErrInvalidOption, "SMTP authentication requires TLS | SMTP 认证要求 TLS")
	}
	return &EmailSink{
		config:   config,
		from:     from,
		to:       recipients,
		fromAddr: from.Address,
		toAddr:   addresses,
	}, nil
}

// Name returns the sink name. | Name 返回 Sink 名称。
func (s *EmailSink) Name() string { return "email" }

// Send delivers one alert over SMTP. | Send 通过 SMTP 投递一条报警。
func (s *EmailSink) Send(ctx context.Context, alert Alert) error {
	if s == nil {
		return errs.Detail(ErrInvalidOption, "nil email sink | 空的邮件 Sink")
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	message := s.render(alert)
	address := net.JoinHostPort(s.config.Host, strconv.Itoa(s.config.Port))
	deadline := time.Now().Add(s.config.Timeout)
	if ctxDeadline, ok := ctx.Deadline(); ok && ctxDeadline.Before(deadline) {
		deadline = ctxDeadline
	}
	dialer := &net.Dialer{Timeout: s.config.Timeout}
	var connection net.Conn
	var err error
	if s.config.ImplicitTLS {
		connection, err = tls.DialWithDialer(dialer, "tcp", address, &tls.Config{
			ServerName: s.config.Host,
			MinVersion: tls.VersionTLS12,
		})
	} else {
		connection, err = dialer.DialContext(ctx, "tcp", address)
	}
	if err != nil {
		return errs.Wrap(err, ErrSource)
	}
	_ = connection.SetDeadline(deadline)
	client, err := smtp.NewClient(connection, s.config.Host)
	if err != nil {
		_ = connection.Close()
		return errs.Wrap(err, ErrSource)
	}
	defer func() {
		_ = client.Close()
		_ = connection.Close()
	}()
	if s.config.ClientName != "" {
		if err := client.Hello(s.config.ClientName); err != nil {
			return errs.Wrap(err, ErrSource)
		}
	}
	if !s.config.ImplicitTLS && s.config.StartTLS {
		if err := client.StartTLS(&tls.Config{
			ServerName: s.config.Host,
			MinVersion: tls.VersionTLS12,
		}); err != nil {
			return errs.Wrap(err, ErrSource)
		}
	}
	if s.config.Username != "" {
		if err := client.Auth(smtp.PlainAuth("", s.config.Username, s.config.Password, s.config.Host)); err != nil {
			return errs.Wrap(err, ErrSource)
		}
	}
	if err := client.Mail(s.fromAddr); err != nil {
		return errs.Wrap(err, ErrSource)
	}
	for _, recipient := range s.toAddr {
		if err := client.Rcpt(recipient); err != nil {
			return errs.Wrap(err, ErrSource)
		}
	}
	writer, err := client.Data()
	if err != nil {
		return errs.Wrap(err, ErrSource)
	}
	if _, err := writer.Write(message); err != nil {
		_ = writer.Close()
		return errs.Wrap(err, ErrSource)
	}
	if err := writer.Close(); err != nil {
		return errs.Wrap(err, ErrSource)
	}
	if err := client.Quit(); err != nil {
		return errs.Wrap(err, ErrSource)
	}
	return nil
}

// render builds the RFC 5322 message. | render 构建 RFC 5322 消息。
func (s *EmailSink) render(alert Alert) []byte {
	subject := s.subject(alert)
	var b strings.Builder
	b.Grow(1024)
	writeHeader := func(name, value string) {
		value = strings.ReplaceAll(value, "\r", "")
		value = strings.ReplaceAll(value, "\n", "")
		b.WriteString(name)
		b.WriteString(": ")
		b.WriteString(value)
		b.WriteString("\r\n")
	}
	writeHeader("From", s.from.String())
	to := make([]string, 0, len(s.to))
	for _, recipient := range s.to {
		to = append(to, recipient.String())
	}
	writeHeader("To", strings.Join(to, ", "))
	writeHeader("Subject", mime.QEncoding.Encode("UTF-8", subject))
	writeHeader("MIME-Version", "1.0")
	writeHeader("Content-Type", "text/plain; charset=UTF-8")
	writeHeader("Content-Transfer-Encoding", "8bit")
	b.WriteString("\r\n")
	b.WriteString("ydx WAF alert | ydx WAF 报警\r\n\r\n")
	appendField := func(name, value string) {
		if value == "" {
			return
		}
		value = strings.ReplaceAll(value, "\r", "")
		value = strings.ReplaceAll(value, "\n", " ")
		b.WriteString(name)
		b.WriteString(": ")
		b.WriteString(value)
		b.WriteString("\r\n")
	}
	appendField("Time", alert.Time.UTC().Format(time.RFC3339))
	appendField("Node", alert.NodeID)
	appendField("Rule", strconv.Itoa(alert.RuleID))
	appendField("Severity", alert.Severity)
	appendField("Action", alert.Action)
	appendField("Status", strconv.Itoa(alert.Status))
	appendField("Client", alert.ClientIP)
	appendField("Method", alert.Method)
	appendField("Path", alert.Path)
	appendField("Count", strconv.Itoa(alert.Count))
	appendField("Window", strconv.FormatInt(alert.WindowSeconds, 10)+"s")
	appendField("Message", alert.Message)
	appendField("Tags", strings.Join(alert.Tags, ", "))
	appendField("RuleVersion", alert.RuleVersion)
	appendField("Error", alert.Error)
	return []byte(b.String())
}

// subject renders the mail subject, including the aggregated count. | subject 渲染邮件主题，包含
// 聚合数量。
func (s *EmailSink) subject(alert Alert) string {
	prefix := strings.TrimSpace(s.config.SubjectPrefix)
	action := alert.Action
	if action == "" {
		action = "detected"
	}
	var b strings.Builder
	if prefix != "" {
		b.WriteString(prefix)
		b.WriteByte(' ')
	}
	b.WriteByte('[')
	b.WriteString(alert.Severity)
	b.WriteString("] rule ")
	b.WriteString(strconv.Itoa(alert.RuleID))
	b.WriteByte(' ')
	b.WriteString(action)
	b.WriteString(" x")
	b.WriteString(strconv.Itoa(alert.Count))
	if alert.ClientIP != "" {
		b.WriteString(" from ")
		b.WriteString(alert.ClientIP)
	}
	return b.String()
}

// Close implements AlertSink. | Close 实现 AlertSink。
func (s *EmailSink) Close() error { return nil }
