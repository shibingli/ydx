package websocket

import (
	"context"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	. "github.com/shibingli/ydx/websocket"
)

// newEchoServer starts a real WebSocket echo endpoint and dials it once. The
// benchmark loop then measures per-message round trips over the public API. |
// newEchoServer 启动真实 WebSocket 回显端点并建立一次连接；基准循环随后经公开 API 测量
// 每条消息的往返。
func newEchoServer(b *testing.B, compress bool) *Conn {
	b.Helper()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		conn, err := Upgrade(w, r, Options{EnableCompression: compress})
		if err != nil {
			return
		}
		defer func() { _ = conn.CloseNow() }()
		for {
			op, data, err := conn.ReadMessage()
			if err != nil {
				return
			}
			if err := conn.WriteMessage(op, data); err != nil {
				return
			}
		}
	}))
	b.Cleanup(srv.Close)

	url := "ws" + strings.TrimPrefix(srv.URL, "http")
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	conn, err := Dial(ctx, url, DialOptions{EnableWriteCompression: compress})
	if err != nil {
		b.Fatalf("dial: %v", err)
	}
	b.Cleanup(func() { _ = conn.CloseNow() })
	return conn
}

// newSinkServer starts an endpoint that reads and discards every message. |
// newSinkServer 启动只读取并丢弃消息的端点。
func newSinkServer(b *testing.B) *Conn {
	b.Helper()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		conn, err := Upgrade(w, r, Options{})
		if err != nil {
			return
		}
		defer func() { _ = conn.CloseNow() }()
		for {
			if _, _, err := conn.ReadMessage(); err != nil {
				return
			}
		}
	}))
	b.Cleanup(srv.Close)

	url := "ws" + strings.TrimPrefix(srv.URL, "http")
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	conn, err := Dial(ctx, url, DialOptions{})
	if err != nil {
		b.Fatalf("dial: %v", err)
	}
	b.Cleanup(func() { _ = conn.CloseNow() })
	return conn
}

// BenchmarkMessageRoundTrip measures a 32-byte client-to-server message and its
// echo over a real WebSocket connection. | BenchmarkMessageRoundTrip 测量真实 WebSocket
// 连接上 32 字节客户端到服务端消息及其回显。
func BenchmarkMessageRoundTrip(b *testing.B) {
	conn := newEchoServer(b, false)
	payload := []byte(strings.Repeat("x", 32))
	b.SetBytes(int64(len(payload)))
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		if err := conn.WriteMessage(TextMessage, payload); err != nil {
			b.Fatalf("write: %v", err)
		}
		op, data, err := conn.ReadMessage()
		if err != nil {
			b.Fatalf("read: %v", err)
		}
		if op != TextMessage || len(data) != len(payload) {
			b.Fatalf("unexpected echo: op=%v len=%d", op, len(data))
		}
	}
}

// BenchmarkWriteBatch measures client-side batched writes over a real connection
// whose peer discards the messages. | BenchmarkWriteBatch 测量客户端经真实连接批量写、
// 对端丢弃消息时的开销。
func BenchmarkWriteBatch(b *testing.B) {
	conn := newSinkServer(b)
	payload := []byte(strings.Repeat("b", 1<<10))
	for _, batch := range []int{1, 4, 16, 64} {
		b.Run(fmt.Sprintf("batch=%d", batch), func(b *testing.B) {
			msgs := make([]Message, batch)
			for i := range msgs {
				msgs[i] = Message{Op: BinaryMessage, Payload: payload}
			}
			b.SetBytes(int64(batch * len(payload)))
			b.ReportAllocs()
			b.ResetTimer()
			for i := 0; i < b.N; i++ {
				if err := conn.WriteBatch(msgs); err != nil {
					b.Fatalf("WriteBatch: %v", err)
				}
			}
		})
	}
}

// BenchmarkCompressedRoundTrip measures a 4 KiB permessage-deflate round trip
// over a real connection. | BenchmarkCompressedRoundTrip 测量真实连接上 4 KiB
// permessage-deflate 往返。
func BenchmarkCompressedRoundTrip(b *testing.B) {
	const size = 4 << 10
	conn := newEchoServer(b, true)
	unit := `{"id":12345,"name":"bench-user","active":true,"score":98.5},`
	payload := []byte(strings.Repeat(unit, size/len(unit)+1))[:size]
	b.SetBytes(int64(size))
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		if err := conn.WriteMessage(TextMessage, payload); err != nil {
			b.Fatalf("write: %v", err)
		}
		op, data, err := conn.ReadMessage()
		if err != nil {
			b.Fatalf("read: %v", err)
		}
		if op != TextMessage || len(data) != size || data[0] != payload[0] || data[size-1] != payload[size-1] {
			b.Fatalf("unexpected echo: op=%v len=%d", op, len(data))
		}
	}
}
