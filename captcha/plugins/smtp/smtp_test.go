package smtp

import (
	"bufio"
	"context"
	"encoding/base64"
	"net"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/shibingli/ydx/captcha/core"
)

func TestSenderDeliversOverPlaintextWhenAllowed(t *testing.T) {
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer listener.Close()
	var mu sync.Mutex
	var body string
	done := make(chan struct{})
	go func() {
		defer close(done)
		conn, err := listener.Accept()
		if err != nil {
			return
		}
		defer conn.Close()
		reader := bufio.NewReader(conn)
		writer := bufio.NewWriter(conn)
		_, _ = writer.WriteString("220 localhost ESMTP\r\n")
		_ = writer.Flush()
		for {
			line, err := reader.ReadString('\n')
			if err != nil {
				return
			}
			command := strings.ToUpper(strings.TrimSpace(line))
			switch {
			case strings.HasPrefix(command, "EHLO"):
				_, _ = writer.WriteString("250-localhost\r\n250 OK\r\n")
				_ = writer.Flush()
			case strings.HasPrefix(command, "MAIL"), strings.HasPrefix(command, "RCPT"):
				_, _ = writer.WriteString("250 OK\r\n")
				_ = writer.Flush()
			case command == "DATA":
				_, _ = writer.WriteString("354 End data\r\n")
				_ = writer.Flush()
				var data strings.Builder
				for {
					dataLine, readErr := reader.ReadString('\n')
					if readErr != nil {
						return
					}
					if dataLine == ".\r\n" {
						break
					}
					data.WriteString(dataLine)
				}
				mu.Lock()
				body = data.String()
				mu.Unlock()
				_, _ = writer.WriteString("250 OK\r\n")
				_ = writer.Flush()
			case command == "QUIT":
				_, _ = writer.WriteString("221 Bye\r\n")
				_ = writer.Flush()
				return
			default:
				_, _ = writer.WriteString("250 OK\r\n")
				_ = writer.Flush()
			}
		}
	}()
	sender, err := New(Options{
		Addr:           listener.Addr().String(),
		From:           "no-reply@example.com",
		AllowPlaintext: true,
		Timeout:        5 * time.Second,
	})
	if err != nil {
		t.Fatal(err)
	}
	if err := sender.Send(context.Background(), core.Message{To: "user@example.com", Code: "123456", Locale: "en", ExpiresIn: 5 * time.Minute}); err != nil {
		t.Fatal(err)
	}
	<-done
	mu.Lock()
	got := body
	mu.Unlock()
	if !strings.Contains(got, "Content-Transfer-Encoding: base64") {
		t.Fatalf("missing MIME header: %s", got)
	}
	parts := strings.SplitN(got, "\r\n\r\n", 2)
	if len(parts) != 2 {
		t.Fatalf("missing body: %s", got)
	}
	decoded, err := base64.StdEncoding.DecodeString(strings.ReplaceAll(parts[1], "\r\n", ""))
	if err != nil {
		t.Fatalf("decode body: %v", err)
	}
	if !strings.Contains(string(decoded), "123456") {
		t.Fatalf("body missing code: %s", decoded)
	}
}

func TestNewValidation(t *testing.T) {
	if _, err := New(Options{Addr: "localhost:25", From: "bad"}); err == nil {
		t.Fatal("expected invalid from")
	}
	if _, err := New(Options{Addr: "", From: "a@example.com"}); err == nil {
		t.Fatal("expected empty address")
	}
}

func TestMessageRejectsHeaderInjection(t *testing.T) {
	sender, err := New(Options{Addr: "localhost:25", From: "no-reply@example.com", AllowPlaintext: true})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := sender.message(core.Message{To: "user@example.com\r\nBcc: evil@example.com", Code: "123456"}); err == nil {
		t.Fatal("expected header injection rejection")
	}
}
