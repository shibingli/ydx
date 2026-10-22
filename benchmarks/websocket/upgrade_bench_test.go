package websocket

import (
	"bufio"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/shibingli/ydx/websocket"
)

// benchUpgradeConn discards writes and reports EOF on reads; the upgrade benchmark uses it as a
// minimal net.Conn. | benchUpgradeConn 丢弃写入并在读取时返回 EOF；升级基准用它作为最小 net.Conn。
type benchUpgradeConn struct {
	written int
}

// Read reports EOF. | Read 返回 EOF。
func (c *benchUpgradeConn) Read([]byte) (int, error) { return 0, io.EOF }

// Write discards p and counts its bytes. | Write 丢弃 p 并统计字节数。
func (c *benchUpgradeConn) Write(p []byte) (int, error) { c.written += len(p); return len(p), nil }

// Close is a no-op. | Close 为空操作。
func (c *benchUpgradeConn) Close() error { return nil }

// LocalAddr returns nil. | LocalAddr 返回 nil。
func (c *benchUpgradeConn) LocalAddr() net.Addr { return nil }

// RemoteAddr returns nil. | RemoteAddr 返回 nil。
func (c *benchUpgradeConn) RemoteAddr() net.Addr { return nil }

// SetDeadline is a no-op. | SetDeadline 为空操作。
func (c *benchUpgradeConn) SetDeadline(time.Time) error { return nil }

// SetReadDeadline is a no-op. | SetReadDeadline 为空操作。
func (c *benchUpgradeConn) SetReadDeadline(time.Time) error { return nil }

// SetWriteDeadline is a no-op. | SetWriteDeadline 为空操作。
func (c *benchUpgradeConn) SetWriteDeadline(time.Time) error { return nil }

// benchHijackWriter is a ResponseWriter+Hijacker backed by a sink connection. |
// benchHijackWriter 是由丢弃连接支撑的 ResponseWriter+Hijacker。
type benchHijackWriter struct {
	header http.Header
	conn   net.Conn
	brw    *bufio.ReadWriter
}

// Header returns the response header map. | Header 返回响应头映射。
func (w *benchHijackWriter) Header() http.Header { return w.header }

// Write discards the response bytes. | Write 丢弃响应字节。
func (w *benchHijackWriter) Write(p []byte) (int, error) { return len(p), nil }

// WriteHeader is a no-op. | WriteHeader 为空操作。
func (w *benchHijackWriter) WriteHeader(int) {}

// Hijack returns the pre-built connection and buffers. | Hijack 返回预构造的连接与缓冲。
func (w *benchHijackWriter) Hijack() (net.Conn, *bufio.ReadWriter, error) {
	return w.conn, w.brw, nil
}

// BenchmarkUpgrade measures a full HTTP/1.1 upgrade with reusable hijack buffers, isolating
// handshake allocation and CPU cost. | BenchmarkUpgrade 测量使用可复用劫持缓冲的完整
// HTTP/1.1 升级，隔离握手分配与 CPU 开销。
func BenchmarkUpgrade(b *testing.B) {
	nc := &benchUpgradeConn{}
	brw := bufio.NewReadWriter(
		bufio.NewReaderSize(nc, 4<<10),
		bufio.NewWriterSize(nc, 4<<10),
	)
	w := &benchHijackWriter{header: make(http.Header), conn: nc, brw: brw}
	r := httptest.NewRequest(http.MethodGet, "/ws", nil)
	r.Header.Set("Connection", "Upgrade")
	r.Header.Set("Upgrade", "websocket")
	r.Header.Set("Sec-WebSocket-Version", "13")
	r.Header.Set("Sec-WebSocket-Key", "dGhlIHNhbXBsZSBub25jZQ==")

	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		conn, err := websocket.Upgrade(w, r, websocket.Options{})
		if err != nil {
			b.Fatalf("Upgrade: %v | Upgrade：%v", err, err)
		}
		_ = conn.CloseNow()
	}
}
