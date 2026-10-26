// Package smtp delivers captcha codes through a self-hosted SMTP server. | Package smtp 通过自研 SMTP 服务下发验证码。
package smtp

import (
	"context"
	"crypto/tls"
	"mime"
	"net"
	"net/mail"
	"net/smtp"
	"strings"
	"time"

	"github.com/shibingli/ydx/base64"
	"github.com/shibingli/ydx/captcha/core"
	"github.com/shibingli/ydx/errs"
)

var (
	// ErrInvalidOptions indicates unusable SMTP options. | ErrInvalidOptions 表示 SMTP 选项不可用。
	ErrInvalidOptions = errs.New("smtp: invalid options | smtp：非法选项")
	// ErrPlaintext indicates a server without TLS while plaintext is disabled. | ErrPlaintext 表示服务器不支持 TLS 且明文被禁用。
	ErrPlaintext = errs.New("smtp: plaintext transport is disabled | smtp：明文传输已被禁用")
)

// Options configures the SMTP sender. | Options 配置 SMTP 发送器。
type Options struct {
	// Addr is the SMTP host:port. | Addr 是 SMTP host:port。
	Addr string
	// Host is the TLS server name; empty derives it from Addr. | Host 是 TLS 服务器名；空值从 Addr 推导。
	Host string
	// Username is the SMTP auth user; empty disables auth. | Username 是 SMTP 认证用户；空值关闭认证。
	Username string
	// Password is the SMTP auth password. | Password 是 SMTP 认证口令。
	Password string
	// From is the envelope and header sender address. | From 是信封与头部发件人地址。
	From string
	// TLS enables implicit TLS such as port 465. | TLS 启用隐式 TLS（如 465 端口）。
	TLS bool
	// AllowPlaintext permits a server without STARTTLS. | AllowPlaintext 允许不支持 STARTTLS 的服务器。
	AllowPlaintext bool
	// Timeout bounds connection, TLS and SMTP operations. | Timeout 限制连接、TLS 与 SMTP 操作。
	Timeout time.Duration
}

// Sender is a captcha email sender backed by SMTP. | Sender 是由 SMTP 支撑的验证码邮件发送器。
type Sender struct {
	from           *mail.Address
	host           string
	addr           string
	username       string
	password       string
	timeout        time.Duration
	implicitTLS    bool
	allowPlaintext bool
}

// New validates options and builds a sender. | New 校验选项并构建发送器。
func New(o Options) (*Sender, error) {
	addr := strings.TrimSpace(o.Addr)
	if addr == "" {
		return nil, errs.Detail(ErrInvalidOptions, "empty address | 空地址")
	}
	host := strings.TrimSpace(o.Host)
	if host == "" {
		host, _, _ = net.SplitHostPort(addr)
	}
	if host == "" {
		return nil, errs.Detail(ErrInvalidOptions, "cannot derive host from %q | 无法从 %q 推导主机名", addr, addr)
	}
	from, err := mail.ParseAddress(strings.TrimSpace(o.From))
	if err != nil || from.Name != "" {
		return nil, errs.Detail(ErrInvalidOptions, "invalid from address | 非法发件人地址")
	}
	timeout := o.Timeout
	if timeout <= 0 {
		timeout = 10 * time.Second
	}
	return &Sender{
		from:           from,
		host:           host,
		addr:           addr,
		username:       o.Username,
		password:       o.Password,
		timeout:        timeout,
		implicitTLS:    o.TLS,
		allowPlaintext: o.AllowPlaintext,
	}, nil
}

// Channel implements core.Sender. | Channel 实现 core.Sender。
func (s *Sender) Channel() core.Channel { return core.ChannelEmail }

// Send implements core.Sender. | Send 实现 core.Sender。
func (s *Sender) Send(ctx context.Context, msg core.Message) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	payload, err := s.message(msg)
	if err != nil {
		return err
	}
	conn, err := s.dial(ctx)
	if err != nil {
		return errs.Wrap(err, core.ErrSendFailed)
	}
	defer conn.Close()
	deadline := time.Now().Add(s.timeout)
	if ctxDeadline, ok := ctx.Deadline(); ok && ctxDeadline.Before(deadline) {
		deadline = ctxDeadline
	}
	_ = conn.SetDeadline(deadline)
	client, err := smtp.NewClient(conn, s.host)
	if err != nil {
		return errs.Wrap(err, core.ErrSendFailed)
	}
	defer client.Close()
	if !s.implicitTLS {
		if ok, _ := client.Extension("STARTTLS"); ok {
			if err := client.StartTLS(&tls.Config{ServerName: s.host, MinVersion: tls.VersionTLS12}); err != nil {
				return errs.Wrap(err, core.ErrSendFailed)
			}
		} else if !s.allowPlaintext {
			return ErrPlaintext
		}
	}
	if s.username != "" {
		if err := client.Auth(smtp.PlainAuth("", s.username, s.password, s.host)); err != nil {
			return errs.Wrap(err, core.ErrSendFailed)
		}
	}
	if err := client.Mail(s.from.Address); err != nil {
		return errs.Wrap(err, core.ErrSendFailed)
	}
	if err := client.Rcpt(msg.To); err != nil {
		return errs.Wrap(err, core.ErrSendFailed)
	}
	writer, err := client.Data()
	if err != nil {
		return errs.Wrap(err, core.ErrSendFailed)
	}
	if _, err := writer.Write(payload); err != nil {
		_ = writer.Close()
		return errs.Wrap(err, core.ErrSendFailed)
	}
	if err := writer.Close(); err != nil {
		return errs.Wrap(err, core.ErrSendFailed)
	}
	_ = client.Quit()
	return nil
}

// dial opens either an implicit-TLS or plaintext connection. | dial 打开隐式 TLS 或明文连接。
func (s *Sender) dial(ctx context.Context) (net.Conn, error) {
	dialer := &net.Dialer{Timeout: s.timeout}
	if s.implicitTLS {
		return tls.DialWithDialer(dialer, "tcp", s.addr, &tls.Config{ServerName: s.host, MinVersion: tls.VersionTLS12})
	}
	return dialer.DialContext(ctx, "tcp", s.addr)
}

// message builds a UTF-8 MIME message with a base64 body. | message 构建 UTF-8 MIME 消息与 Base64 正文。
func (s *Sender) message(msg core.Message) ([]byte, error) {
	if msg.To == "" || msg.Code == "" || strings.ContainsAny(msg.To, "\r\n") {
		return nil, errs.Detail(ErrInvalidOptions, "invalid recipient or code | 非法收件人或验证码")
	}
	subject := "Your verification code | 您的验证码"
	if strings.HasPrefix(msg.Locale, "zh") {
		subject = "您的验证码"
	}
	body := "Your verification code is: " + msg.Code + "\r\n" +
		"It expires in " + durationMinutes(msg.ExpiresIn) + " minutes.\r\n"
	if strings.HasPrefix(msg.Locale, "zh") {
		body = "您的验证码是：" + msg.Code + "\r\n" +
			"有效期 " + durationMinutes(msg.ExpiresIn) + " 分钟。\r\n"
	}
	var b strings.Builder
	b.WriteString("From: " + s.from.String() + "\r\n")
	b.WriteString("To: " + msg.To + "\r\n")
	b.WriteString("Subject: " + mime.QEncoding.Encode("UTF-8", subject) + "\r\n")
	b.WriteString("Date: " + time.Now().Format(time.RFC1123Z) + "\r\n")
	b.WriteString("MIME-Version: 1.0\r\n")
	b.WriteString("Content-Type: text/plain; charset=UTF-8\r\n")
	b.WriteString("Content-Transfer-Encoding: base64\r\n")
	b.WriteString("\r\n")
	encoded := base64.StdEncoding.EncodeToString([]byte(body))
	for len(encoded) > 76 {
		b.WriteString(encoded[:76])
		b.WriteString("\r\n")
		encoded = encoded[76:]
	}
	b.WriteString(encoded)
	b.WriteString("\r\n")
	return []byte(b.String()), nil
}

// durationMinutes renders a positive minute count. | durationMinutes 渲染正分钟数。
func durationMinutes(d time.Duration) string {
	minutes := int(d / time.Minute)
	if minutes < 1 {
		minutes = 1
	}
	return strconvItoa(minutes)
}

// strconvItoa avoids pulling formatting into the hot path. | strconvItoa 避免在热路径引入格式化。
func strconvItoa(v int) string {
	if v == 0 {
		return "0"
	}
	var buf [20]byte
	i := len(buf)
	for v > 0 {
		i--
		buf[i] = byte('0' + v%10)
		v /= 10
	}
	return string(buf[i:])
}
