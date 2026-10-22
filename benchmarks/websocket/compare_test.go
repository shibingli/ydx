package websocket

import (
	"context"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	coder "github.com/coder/websocket"
	gorilla "github.com/gorilla/websocket"

	. "github.com/shibingli/ydx/websocket"
)

// The comparison benchmarks use real loopback connections for every implementation. ydx reuses
// the helpers in bench_test.go; gorilla and coder get equivalent echo and sink servers here. |
// 对比基准为每个实现使用真实的回环连接。ydx 复用 bench_test.go 中的辅助函数；gorilla 与 coder
// 在此获得等价的回显与丢弃服务端。

// newGorillaEcho starts a gorilla echo server and dials it. | newGorillaEcho 启动 gorilla 回显服务端并建立连接。
func newGorillaEcho(b *testing.B) *gorilla.Conn {
	b.Helper()
	upgrader := gorilla.Upgrader{}
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		conn, err := upgrader.Upgrade(w, r, nil)
		if err != nil {
			return
		}
		defer func() { _ = conn.Close() }()
		for {
			mt, data, err := conn.ReadMessage()
			if err != nil {
				return
			}
			if err := conn.WriteMessage(mt, data); err != nil {
				return
			}
		}
	}))
	b.Cleanup(srv.Close)

	url := "ws" + strings.TrimPrefix(srv.URL, "http")
	conn, resp, err := gorilla.DefaultDialer.Dial(url, nil)
	if err != nil {
		b.Fatalf("dial: %v (response: %v) | 连接失败", err, resp)
	}
	b.Cleanup(func() { _ = conn.Close() })
	return conn
}

// newGorillaSink starts a gorilla server that reads and discards messages. |
// newGorillaSink 启动只读取并丢弃消息的 gorilla 服务端。
func newGorillaSink(b *testing.B) *gorilla.Conn {
	b.Helper()
	upgrader := gorilla.Upgrader{}
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		conn, err := upgrader.Upgrade(w, r, nil)
		if err != nil {
			return
		}
		defer func() { _ = conn.Close() }()
		for {
			if _, _, err := conn.ReadMessage(); err != nil {
				return
			}
		}
	}))
	b.Cleanup(srv.Close)

	url := "ws" + strings.TrimPrefix(srv.URL, "http")
	conn, resp, err := gorilla.DefaultDialer.Dial(url, nil)
	if err != nil {
		b.Fatalf("dial: %v (response: %v) | 连接失败", err, resp)
	}
	b.Cleanup(func() { _ = conn.Close() })
	return conn
}

// newCoderEcho starts a coder/websocket echo server and dials it. | newCoderEcho 启动 coder/websocket 回显服务端并建立连接。
func newCoderEcho(b *testing.B) *coder.Conn {
	b.Helper()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		conn, err := coder.Accept(w, r, nil)
		if err != nil {
			return
		}
		defer func() { _ = conn.CloseNow() }()
		ctx := context.Background()
		for {
			typ, data, err := conn.Read(ctx)
			if err != nil {
				return
			}
			if err := conn.Write(ctx, typ, data); err != nil {
				return
			}
		}
	}))
	b.Cleanup(srv.Close)

	url := "ws" + strings.TrimPrefix(srv.URL, "http")
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	conn, resp, err := coder.Dial(ctx, url, nil)
	if err != nil {
		b.Fatalf("dial: %v (response: %v) | 连接失败", err, resp)
	}
	b.Cleanup(func() { _ = conn.CloseNow() })
	return conn
}

// newCoderSink starts a coder server that reads and discards messages. |
// newCoderSink 启动只读取并丢弃消息的 coder 服务端。
func newCoderSink(b *testing.B) *coder.Conn {
	b.Helper()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		conn, err := coder.Accept(w, r, nil)
		if err != nil {
			return
		}
		defer func() { _ = conn.CloseNow() }()
		ctx := context.Background()
		for {
			if _, _, err := conn.Read(ctx); err != nil {
				return
			}
		}
	}))
	b.Cleanup(srv.Close)

	url := "ws" + strings.TrimPrefix(srv.URL, "http")
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	conn, resp, err := coder.Dial(ctx, url, nil)
	if err != nil {
		b.Fatalf("dial: %v (response: %v) | 连接失败", err, resp)
	}
	b.Cleanup(func() { _ = conn.CloseNow() })
	return conn
}

// BenchmarkMessageRoundTripCompare measures a 32-byte echo round trip over ydx, gorilla and coder.
// Each case warms up one round trip before the timer starts. |
// BenchmarkMessageRoundTripCompare 测量 ydx、gorilla 与 coder 上 32 字节消息的回显往返。每个用例
// 在计时前预热一次往返。
func BenchmarkMessageRoundTripCompare(b *testing.B) {
	payload := []byte(strings.Repeat("x", 32))

	b.Run("ydx", func(b *testing.B) {
		conn := newEchoServer(b, false)
		if err := conn.WriteMessage(TextMessage, payload); err != nil {
			b.Fatalf("warm-up write: %v | 预热写入失败", err)
		}
		if _, _, err := conn.ReadMessage(); err != nil {
			b.Fatalf("warm-up read: %v | 预热读取失败", err)
		}
		b.SetBytes(int64(len(payload)))
		b.ReportAllocs()
		b.ResetTimer()
		for i := 0; i < b.N; i++ {
			if err := conn.WriteMessage(TextMessage, payload); err != nil {
				b.Fatalf("write: %v | 写入失败", err)
			}
			op, data, err := conn.ReadMessage()
			if err != nil {
				b.Fatalf("read: %v | 读取失败", err)
			}
			if op != TextMessage || len(data) != len(payload) {
				b.Fatalf("unexpected echo: op=%v len=%d | 回显不符", op, len(data))
			}
		}
	})

	b.Run("gorilla", func(b *testing.B) {
		conn := newGorillaEcho(b)
		if err := conn.WriteMessage(gorilla.TextMessage, payload); err != nil {
			b.Fatalf("warm-up write: %v | 预热写入失败", err)
		}
		if _, _, err := conn.ReadMessage(); err != nil {
			b.Fatalf("warm-up read: %v | 预热读取失败", err)
		}
		b.SetBytes(int64(len(payload)))
		b.ReportAllocs()
		b.ResetTimer()
		for i := 0; i < b.N; i++ {
			if err := conn.WriteMessage(gorilla.TextMessage, payload); err != nil {
				b.Fatalf("write: %v | 写入失败", err)
			}
			op, data, err := conn.ReadMessage()
			if err != nil {
				b.Fatalf("read: %v | 读取失败", err)
			}
			if op != gorilla.TextMessage || len(data) != len(payload) {
				b.Fatalf("unexpected echo: op=%v len=%d | 回显不符", op, len(data))
			}
		}
	})

	b.Run("coder", func(b *testing.B) {
		conn := newCoderEcho(b)
		ctx := context.Background()
		if err := conn.Write(ctx, coder.MessageText, payload); err != nil {
			b.Fatalf("warm-up write: %v | 预热写入失败", err)
		}
		if _, _, err := conn.Read(ctx); err != nil {
			b.Fatalf("warm-up read: %v | 预热读取失败", err)
		}
		b.SetBytes(int64(len(payload)))
		b.ReportAllocs()
		b.ResetTimer()
		for i := 0; i < b.N; i++ {
			if err := conn.Write(ctx, coder.MessageText, payload); err != nil {
				b.Fatalf("write: %v | 写入失败", err)
			}
			typ, data, err := conn.Read(ctx)
			if err != nil {
				b.Fatalf("read: %v | 读取失败", err)
			}
			if typ != coder.MessageText || len(data) != len(payload) {
				b.Fatalf("unexpected echo: type=%v len=%d | 回显不符", typ, len(data))
			}
		}
	})
}

// BenchmarkWriteBatchCompare measures client-side batched writes over a real connection whose
// peer discards every message. ydx uses the native WriteBatch; gorilla and coder have no batch
// API, so their cases issue one Write per message. |
// BenchmarkWriteBatchCompare 测量客户端在真实连接上的批量写入，对端丢弃所有消息。ydx 使用原生
// WriteBatch；gorilla 与 coder 没有批量 API，因此它们的用例逐条 Write。
func BenchmarkWriteBatchCompare(b *testing.B) {
	payload := []byte(strings.Repeat("b", 1<<10))

	for _, batch := range []int{1, 4, 16, 64} {
		b.Run(fmt.Sprintf("batch=%d/ydx", batch), func(b *testing.B) {
			conn := newSinkServer(b)
			msgs := make([]Message, batch)
			for i := range msgs {
				msgs[i] = Message{Op: BinaryMessage, Payload: payload}
			}
			if err := conn.WriteBatch(msgs); err != nil {
				b.Fatalf("warm-up WriteBatch: %v | 预热 WriteBatch 失败", err)
			}
			b.SetBytes(int64(batch * len(payload)))
			b.ReportAllocs()
			b.ResetTimer()
			for i := 0; i < b.N; i++ {
				if err := conn.WriteBatch(msgs); err != nil {
					b.Fatalf("WriteBatch: %v | WriteBatch 失败", err)
				}
			}
		})

		b.Run(fmt.Sprintf("batch=%d/gorilla", batch), func(b *testing.B) {
			conn := newGorillaSink(b)
			if err := writeGorillaBatch(conn, payload, batch); err != nil {
				b.Fatalf("warm-up write: %v | 预热写入失败", err)
			}
			b.SetBytes(int64(batch * len(payload)))
			b.ReportAllocs()
			b.ResetTimer()
			for i := 0; i < b.N; i++ {
				if err := writeGorillaBatch(conn, payload, batch); err != nil {
					b.Fatalf("write: %v | 写入失败", err)
				}
			}
		})

		b.Run(fmt.Sprintf("batch=%d/coder", batch), func(b *testing.B) {
			conn := newCoderSink(b)
			ctx := context.Background()
			if err := writeCoderBatch(ctx, conn, payload, batch); err != nil {
				b.Fatalf("warm-up write: %v | 预热写入失败", err)
			}
			b.SetBytes(int64(batch * len(payload)))
			b.ReportAllocs()
			b.ResetTimer()
			for i := 0; i < b.N; i++ {
				if err := writeCoderBatch(ctx, conn, payload, batch); err != nil {
					b.Fatalf("write: %v | 写入失败", err)
				}
			}
		})
	}
}

// writeGorillaBatch writes payload n times through gorilla's per-message API. |
// writeGorillaBatch 通过 gorilla 的逐消息 API 写入 n 次 payload。
func writeGorillaBatch(conn *gorilla.Conn, payload []byte, n int) error {
	for i := 0; i < n; i++ {
		if err := conn.WriteMessage(gorilla.BinaryMessage, payload); err != nil {
			return err
		}
	}
	return nil
}

// writeCoderBatch writes payload n times through coder's per-message API. |
// writeCoderBatch 通过 coder 的逐消息 API 写入 n 次 payload。
func writeCoderBatch(ctx context.Context, conn *coder.Conn, payload []byte, n int) error {
	for i := 0; i < n; i++ {
		if err := conn.Write(ctx, coder.MessageBinary, payload); err != nil {
			return err
		}
	}
	return nil
}
