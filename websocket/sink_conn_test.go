package websocket

import (
	"io"
	"net"
	"time"
)

// sinkConn discards writes and reports EOF on reads; the handshake tests use it as a
// minimal net.Conn. | sinkConn 丢弃写入并在读取时返回 EOF；握手测试用它作为最小 net.Conn。
type sinkConn struct{ written int }

func (c *sinkConn) Read([]byte) (int, error) { return 0, io.EOF }

func (c *sinkConn) Write(p []byte) (int, error) { c.written += len(p); return len(p), nil }

func (c *sinkConn) Close() error { return nil }

func (c *sinkConn) LocalAddr() net.Addr { return nil }

func (c *sinkConn) RemoteAddr() net.Addr { return nil }

func (c *sinkConn) SetDeadline(time.Time) error { return nil }

func (c *sinkConn) SetReadDeadline(time.Time) error { return nil }

func (c *sinkConn) SetWriteDeadline(time.Time) error { return nil }
