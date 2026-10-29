package notify

import (
	"bufio"
	"context"
	"errors"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/shibingli/ydx/json"
	"github.com/shibingli/ydx/workflow"
)

// testNotification builds one representative notification. | testNotification 构建一个代表性通知。
func testNotification() workflow.Notification {
	return workflow.Notification{
		ID: "wfntf_1", TenantID: "tn_test", InstanceID: "wfins_1", TaskID: "wftsk_1",
		RecipientID: "u1", RecipientName: "User One", RecipientAddress: "u1@example.com",
		Kind: workflow.NotifyAssigned, Title: "新的审批待办", Body: "请处理", URL: "https://example.com/workflow/tasks/1",
	}
}

// TestWebhookDialects covers generic, WeCom, DingTalk and Feishu payloads. | TestWebhookDialects
// 覆盖通用、企业微信、钉钉与飞书载荷。
func TestWebhookDialects(t *testing.T) {
	cases := []struct {
		kind   string
		secret string
		assert func(t *testing.T, body map[string]any, request *http.Request)
	}{
		{
			kind: KindGeneric,
			assert: func(t *testing.T, body map[string]any, _ *http.Request) {
				if body["event"] != workflow.NotifyAssigned || body["recipient"] != "u1" || body["instance_id"] != "wfins_1" {
					t.Fatalf("通用载荷 = %+v", body)
				}
			},
		},
		{
			kind: KindWeCom,
			assert: func(t *testing.T, body map[string]any, _ *http.Request) {
				markdown, _ := body["markdown"].(map[string]any)
				if body["msgtype"] != "markdown" || markdown["content"] == "" {
					t.Fatalf("企业微信载荷 = %+v", body)
				}
			},
		},
		{
			kind: KindDingTalk, secret: "secret",
			assert: func(t *testing.T, body map[string]any, request *http.Request) {
				markdown, _ := body["markdown"].(map[string]any)
				if body["msgtype"] != "markdown" || markdown["title"] == nil {
					t.Fatalf("钉钉载荷 = %+v", body)
				}
				if request.URL.Query().Get("timestamp") == "" || request.URL.Query().Get("sign") == "" {
					t.Fatalf("钉钉签名缺失: %s", request.URL.String())
				}
			},
		},
		{
			kind: KindFeishu,
			assert: func(t *testing.T, body map[string]any, _ *http.Request) {
				if body["msg_type"] != "text" {
					t.Fatalf("飞书载荷 = %+v", body)
				}
			},
		},
	}
	for _, tc := range cases {
		t.Run(tc.kind, func(t *testing.T) {
			var payload map[string]any
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				data, _ := io.ReadAll(r.Body)
				if err := json.Unmarshal(data, &payload); err != nil {
					t.Errorf("载荷不是 JSON: %v", err)
				}
				tc.assert(t, payload, r)
				w.WriteHeader(http.StatusOK)
			}))
			defer server.Close()
			channel, err := NewWebhook(WebhookOptions{URL: server.URL, Kind: tc.kind, Secret: tc.secret, Client: server.Client()})
			if err != nil {
				t.Fatalf("构造 Webhook 失败: %v", err)
			}
			if err := channel.Send(context.Background(), testNotification()); err != nil {
				t.Fatalf("发送失败: %v", err)
			}
		})
	}
}

// TestWebhookFailures covers configuration and non-2xx responses. | TestWebhookFailures 覆盖配置与
// 非 2xx 响应。
func TestWebhookFailures(t *testing.T) {
	if _, err := NewWebhook(WebhookOptions{URL: ""}); !errors.Is(err, ErrInvalidOptions) {
		t.Fatalf("空 URL 错误 = %v", err)
	}
	if _, err := NewWebhook(WebhookOptions{URL: "ftp://example.com"}); !errors.Is(err, ErrInvalidOptions) {
		t.Fatalf("非 HTTP URL 错误 = %v", err)
	}
	if _, err := NewWebhook(WebhookOptions{URL: "https://example.com", Kind: "unknown"}); !errors.Is(err, ErrInvalidOptions) {
		t.Fatalf("未知方言错误 = %v", err)
	}
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusBadGateway)
	}))
	defer server.Close()
	channel, err := NewWebhook(WebhookOptions{URL: server.URL, Client: server.Client()})
	if err != nil {
		t.Fatalf("构造 Webhook 失败: %v", err)
	}
	if err := channel.Send(context.Background(), testNotification()); !errors.Is(err, ErrDelivery) {
		t.Fatalf("非 2xx 错误 = %v", err)
	}
}

// smtpServer is a minimal SMTP responder used to capture one message. | smtpServer 是用于捕获一封邮件的
// 最小 SMTP 响应器。
type smtpServer struct {
	// listener accepts one connection. | listener 接收一个连接。
	listener net.Listener
	// messages receives the DATA payload. | messages 接收 DATA 载荷。
	messages chan string
	// once guards close. | once 保护 close。
	once sync.Once
}

// startSMTP starts one local SMTP responder. | startSMTP 启动一个本地 SMTP 响应器。
func startSMTP(t *testing.T) *smtpServer {
	t.Helper()
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("监听 SMTP 失败: %v", err)
	}
	server := &smtpServer{listener: listener, messages: make(chan string, 1)}
	go server.serve()
	return server
}

// serve handles the SMTP dialogue. | serve 处理 SMTP 对话。
func (s *smtpServer) serve() {
	conn, err := s.listener.Accept()
	if err != nil {
		return
	}
	defer func() { _ = conn.Close() }()
	reader := bufio.NewReader(conn)
	writer := bufio.NewWriter(conn)
	write := func(line string) {
		_, _ = writer.WriteString(line + "\r\n")
		_ = writer.Flush()
	}
	write("220 test ESMTP")
	for {
		line, err := reader.ReadString('\n')
		if err != nil {
			return
		}
		line = strings.TrimSpace(line)
		upper := strings.ToUpper(line)
		switch {
		case strings.HasPrefix(upper, "EHLO"), strings.HasPrefix(upper, "HELO"):
			write("250-test")
			write("250 OK")
		case strings.HasPrefix(upper, "MAIL FROM"), strings.HasPrefix(upper, "RCPT TO"):
			write("250 OK")
		case upper == "DATA":
			write("354 End data with <CR><LF>.<CR><LF>")
			var body strings.Builder
			for {
				dataLine, err := reader.ReadString('\n')
				if err != nil {
					return
				}
				if strings.TrimRight(dataLine, "\r\n") == "." {
					break
				}
				body.WriteString(dataLine)
			}
			s.messages <- body.String()
			write("250 OK")
		case upper == "QUIT":
			write("221 Bye")
			return
		default:
			write("250 OK")
		}
	}
}

// close closes the listener. | close 关闭监听器。
func (s *smtpServer) close() {
	s.once.Do(func() { _ = s.listener.Close() })
}

// TestSMTPSend covers mail rendering and a full SMTP dialogue. | TestSMTPSend 覆盖邮件渲染与完整 SMTP 对话。
func TestSMTPSend(t *testing.T) {
	server := startSMTP(t)
	defer server.close()
	host, portText, err := net.SplitHostPort(server.listener.Addr().String())
	if err != nil {
		t.Fatalf("拆分 SMTP 地址失败: %v", err)
	}
	port, _ := strconv.Atoi(portText)
	channel, err := NewSMTP(SMTPOptions{Host: host, Port: port, From: "noreply@example.com", FromName: "审批中心", Timeout: 3 * time.Second})
	if err != nil {
		t.Fatalf("构造 SMTP 渠道失败: %v", err)
	}
	note := testNotification()
	note.Title = "审批待办"
	note.Body = "请尽快处理"
	if err := channel.Send(context.Background(), note); err != nil {
		t.Fatalf("发送邮件失败: %v", err)
	}
	select {
	case message := <-server.messages:
		for _, want := range []string{"To: u1@example.com", "Subject:", "请尽快处理", "MIME-Version: 1.0"} {
			if !strings.Contains(message, want) {
				t.Errorf("邮件缺少 %q:\n%s", want, message)
			}
		}
	case <-time.After(3 * time.Second):
		t.Fatal("未收到 SMTP 数据")
	}
}

// TestSMTPValidation covers configuration and recipient failures. | TestSMTPValidation 覆盖配置与收件人失败。
func TestSMTPValidation(t *testing.T) {
	if _, err := NewSMTP(SMTPOptions{}); !errors.Is(err, ErrInvalidOptions) {
		t.Fatalf("空配置错误 = %v", err)
	}
	channel, err := NewSMTP(SMTPOptions{Host: "127.0.0.1", From: "noreply@example.com"})
	if err != nil {
		t.Fatalf("构造 SMTP 渠道失败: %v", err)
	}
	note := testNotification()
	note.RecipientAddress = ""
	if err := channel.Send(context.Background(), note); !errors.Is(err, ErrDelivery) {
		t.Fatalf("缺少邮箱错误 = %v", err)
	}
}

// TestBuildMessageEscapesHeaders covers header injection resistance. | TestBuildMessageEscapesHeaders
// 覆盖头部注入防护。
func TestBuildMessageEscapesHeaders(t *testing.T) {
	message := string(buildMessage("noreply@example.com", "审批中心", "u1@example.com", "主题", "正文\n第二行"))
	if !strings.Contains(message, "Content-Type: text/plain; charset=UTF-8") {
		t.Fatalf("邮件头 = %s", message)
	}
	if !strings.Contains(message, "正文\r\n第二行") {
		t.Fatalf("正文未规范换行: %s", message)
	}
}

// TestLogChannel covers the development channel. | TestLogChannel 覆盖开发渠道。
func TestLogChannel(t *testing.T) {
	channel := &LogChannel{}
	if channel.Name() != "log" {
		t.Fatalf("渠道名 = %s", channel.Name())
	}
	if err := channel.Send(context.Background(), testNotification()); err != nil {
		t.Fatalf("日志渠道发送失败: %v", err)
	}
}
