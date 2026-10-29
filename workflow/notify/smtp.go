package notify

import (
	"bytes"
	"context"
	"crypto/tls"
	"mime"
	"net"
	"net/smtp"
	"strconv"
	"strings"
	"time"

	"github.com/shibingli/ydx/errs"
	ydlog "github.com/shibingli/ydx/log"
	"github.com/shibingli/ydx/workflow"
)

// SMTPOptions configure the mail channel. | SMTPOptions 配置邮件渠道。
type SMTPOptions struct {
	// Host is the SMTP server. | Host 是 SMTP 服务器。
	Host string
	// Username and Password authenticate the client; empty skips AUTH. | Username 与 Password
	// 认证客户端；为空则跳过 AUTH。
	Username string
	Password string
	// From is the envelope and header sender. | From 是信封与头部发件人。
	From string
	// FromName is the display name of the sender. | FromName 是发件人展示名。
	FromName string
	// Port is the SMTP port; 465 uses implicit TLS, 587 usually uses STARTTLS. | Port 是 SMTP 端口；
	// 465 使用隐式 TLS，587 通常使用 STARTTLS。
	Port int
	// Timeout bounds one delivery. | Timeout 限制单次投递。
	Timeout time.Duration
	// TLS enables TLS: implicit on port 465, STARTTLS elsewhere. | TLS 开启 TLS：465 端口隐式，其它端口 STARTTLS。
	TLS bool
}

// SMTP is the mail notification channel. | SMTP 是邮件通知渠道。
type SMTP struct {
	// host is the SMTP server. | host 是 SMTP 服务器。
	host string
	// username and password authenticate the client. | username 与 password 认证客户端。
	username string
	password string
	// from is the envelope sender. | from 是信封发件人。
	from string
	// fromName is the display name. | fromName 是展示名。
	fromName string
	// port is the SMTP port. | port 是 SMTP 端口。
	port int
	// timeout bounds one delivery. | timeout 限制单次投递。
	timeout time.Duration
	// tls enables transport security. | tls 开启传输安全。
	tls bool
}

// NewSMTP builds the mail channel. | NewSMTP 构建邮件渠道。
func NewSMTP(o SMTPOptions) (*SMTP, error) {
	host := strings.TrimSpace(o.Host)
	from := strings.TrimSpace(o.From)
	if host == "" || from == "" || strings.ContainsAny(from, "\r\n") {
		return nil, ErrInvalidOptions
	}
	if o.Port <= 0 || o.Port > 65535 {
		o.Port = 587
	}
	if o.Timeout <= 0 {
		o.Timeout = 15 * time.Second
	}
	return &SMTP{
		host:     host,
		port:     o.Port,
		username: strings.TrimSpace(o.Username),
		password: o.Password,
		from:     from,
		fromName: strings.TrimSpace(o.FromName),
		tls:      o.TLS,
		timeout:  o.Timeout,
	}, nil
}

// Name returns the channel name. | Name 返回渠道名。
func (s *SMTP) Name() string { return "smtp" }

// Send delivers one mail. | Send 投递一封邮件。
func (s *SMTP) Send(ctx context.Context, note workflow.Notification) error {
	to := strings.TrimSpace(note.RecipientAddress)
	if to == "" || strings.ContainsAny(to, "\r\n") {
		return errs.Detail(ErrDelivery, "recipient %[1]q has no usable e-mail address | 接收人 %[1]q 没有可用邮箱", note.RecipientID)
	}
	subject := note.Title
	if subject == "" {
		subject = note.Kind
	}
	body := note.Body
	if note.URL != "" {
		if body != "" {
			body += "\r\n\r\n"
		}
		body += note.URL
	}
	message := buildMessage(s.from, s.fromName, to, subject, body)
	dialer := &net.Dialer{Timeout: s.timeout}
	address := net.JoinHostPort(s.host, strconv.Itoa(s.port))
	var conn net.Conn
	var err error
	if s.tls && s.port == 465 {
		conn, err = tls.DialWithDialer(dialer, "tcp", address, &tls.Config{ServerName: s.host, MinVersion: tls.VersionTLS12})
	} else {
		conn, err = dialer.DialContext(ctx, "tcp", address)
	}
	if err != nil {
		return errs.Detail(ErrDelivery, "smtp connect failed | SMTP 连接失败")
	}
	defer func() { _ = conn.Close() }()
	client, err := smtp.NewClient(conn, s.host)
	if err != nil {
		return errs.Detail(ErrDelivery, "smtp handshake failed | SMTP 握手失败")
	}
	defer func() { _ = client.Close() }()
	if s.tls && s.port != 465 {
		if ok, _ := client.Extension("STARTTLS"); ok {
			if err := client.StartTLS(&tls.Config{ServerName: s.host, MinVersion: tls.VersionTLS12}); err != nil {
				return errs.Detail(ErrDelivery, "smtp starttls failed | SMTP STARTTLS 失败")
			}
		}
	}
	if s.username != "" {
		auth := smtp.PlainAuth("", s.username, s.password, s.host)
		if err := client.Auth(auth); err != nil {
			return errs.Detail(ErrDelivery, "smtp authentication failed | SMTP 认证失败")
		}
	}
	if err := client.Mail(s.from); err != nil {
		return errs.Detail(ErrDelivery, "smtp sender rejected | SMTP 拒绝发件人")
	}
	if err := client.Rcpt(to); err != nil {
		return errs.Detail(ErrDelivery, "smtp recipient rejected | SMTP 拒绝收件人")
	}
	writer, err := client.Data()
	if err != nil {
		return errs.Detail(ErrDelivery, "smtp data failed | SMTP 数据阶段失败")
	}
	if _, err := writer.Write(message); err != nil {
		_ = writer.Close()
		return errs.Detail(ErrDelivery, "smtp write failed | SMTP 写入失败")
	}
	if err := writer.Close(); err != nil {
		return errs.Detail(ErrDelivery, "smtp finalise failed | SMTP 收尾失败")
	}
	_ = client.Quit()
	return nil
}

// buildMessage renders a UTF-8 plain-text message with printable headers. | buildMessage
// 渲染带可打印头部的 UTF-8 纯文本邮件。
func buildMessage(from, fromName, to, subject, body string) []byte {
	var b bytes.Buffer
	display := from
	if fromName != "" {
		display = mime.QEncoding.Encode("UTF-8", fromName) + " <" + from + ">"
	}
	b.WriteString("From: " + display + "\r\n")
	b.WriteString("To: " + to + "\r\n")
	b.WriteString("Subject: " + mime.QEncoding.Encode("UTF-8", subject) + "\r\n")
	b.WriteString("Date: " + time.Now().UTC().Format(time.RFC1123Z) + "\r\n")
	b.WriteString("MIME-Version: 1.0\r\n")
	b.WriteString("Content-Type: text/plain; charset=UTF-8\r\n")
	b.WriteString("Content-Transfer-Encoding: 8bit\r\n\r\n")
	b.WriteString(strings.ReplaceAll(body, "\n", "\r\n"))
	b.WriteString("\r\n")
	return b.Bytes()
}

// LogChannel writes notifications to the framework logger. It is intended for development and
// for verifying the notification pipeline without an external transport. | LogChannel 把通知写入框架日志。
// 它用于开发环境，以及在没有外部传输时验证通知链路。
type LogChannel struct {
	// Logger receives the lines. | Logger 接收日志行。
	Logger *ydlog.Logger
}

// Name returns the channel name. | Name 返回渠道名。
func (l *LogChannel) Name() string { return "log" }

// Send logs one notification. | Send 记录一条通知。
func (l *LogChannel) Send(ctx context.Context, note workflow.Notification) error {
	logger := l.Logger
	if logger == nil {
		logger = ydlog.Default()
	}
	logger.Info("workflow notification | 流程通知",
		ydlog.Str("kind", note.Kind),
		ydlog.Str("recipient", note.RecipientID),
		ydlog.Str("title", note.Title),
	)
	return nil
}
