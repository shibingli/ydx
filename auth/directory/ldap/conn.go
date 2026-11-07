package ldap

import (
	"bufio"
	"context"
	"crypto/tls"
	"io"
	"net"
	"time"

	"github.com/shibingli/ydx/errs"
)

// conn is one framed LDAP transport. It is not safe for concurrent use; the
// owning Client serializes every exchange. | conn 是一个分帧 LDAP 传输。它不支持
// 并发使用；所属 Client 串行化每次交换。
type conn struct {
	netConn  net.Conn
	reader   *bufio.Reader
	secure   bool
	tlsState tls.ConnectionState
	maxSize  int
	nextID   int
}

// newConn wraps netConn. | newConn 包装 netConn。
func newConn(netConn net.Conn, secure bool, state tls.ConnectionState, maxSize int) *conn {
	if maxSize <= 0 {
		maxSize = DefaultMaxMessageSize
	}
	return &conn{
		netConn:  netConn,
		reader:   bufio.NewReaderSize(netConn, 16<<10),
		secure:   secure,
		tlsState: state,
		maxSize:  maxSize,
	}
}

// close closes the transport. | close 关闭传输。
func (c *conn) close() error {
	if c == nil || c.netConn == nil {
		return nil
	}
	return c.netConn.Close()
}

// nextMessageID returns the next positive 31-bit message identifier. | nextMessageID
// 返回下一个正的 31 位消息标识。
func (c *conn) nextMessageID() int {
	c.nextID++
	if c.nextID <= 0 || c.nextID > 2147483647 {
		c.nextID = 1
	}
	return c.nextID
}

// setDeadline applies the earlier of the context deadline and now+timeout. | setDeadline
// 应用上下文期限与 now+timeout 中较早者。
func (c *conn) setDeadline(ctx context.Context, timeout time.Duration) error {
	var deadline time.Time
	if timeout > 0 {
		deadline = time.Now().Add(timeout)
	}
	if ctx != nil {
		if d, ok := ctx.Deadline(); ok && (deadline.IsZero() || d.Before(deadline)) {
			deadline = d
		}
	}
	return c.netConn.SetDeadline(deadline)
}

// clearDeadline removes transport deadlines. | clearDeadline 移除传输期限。
func (c *conn) clearDeadline() error {
	return c.netConn.SetDeadline(time.Time{})
}

// writeMessage encodes and writes one LDAP message. | writeMessage 编码并写入一条 LDAP 消息。
func (c *conn) writeMessage(message *LDAPMessage) error {
	data, err := encodeLDAPMessage(message)
	if err != nil {
		return err
	}
	if len(data) > c.maxSize {
		return errs.Detail(ErrInvalidMessageTooLarge, "%d bytes exceed %d | %d 字节超过 %d", len(data), c.maxSize, len(data), c.maxSize)
	}
	for len(data) > 0 {
		n, err := c.netConn.Write(data)
		if err != nil {
			return err
		}
		if n <= 0 {
			return io.ErrUnexpectedEOF
		}
		data = data[n:]
	}
	return nil
}

// readMessage reads and decodes one framed LDAP message. | readMessage 读取并解码一条
// 分帧 LDAP 消息。
func (c *conn) readMessage() (*LDAPMessage, error) {
	packet, err := c.readPacket()
	if err != nil {
		return nil, err
	}
	return decodeLDAPMessage(packet)
}

// readPacket reads one top-level SEQUENCE packet without trusting its length. |
// readPacket 在不信任其长度的前提下读取一个顶层 SEQUENCE 报文。
func (c *conn) readPacket() ([]byte, error) {
	first, err := c.reader.ReadByte()
	if err != nil {
		return nil, err
	}
	if first != 0x30 {
		return nil, errs.Detail(ErrInvalidResponse, "top-level tag 0x%02x is not SEQUENCE | 顶层标签 0x%02x 不是 SEQUENCE", first, first)
	}
	firstLength, err := c.reader.ReadByte()
	if err != nil {
		return nil, err
	}
	var lengthBytes [8]byte
	headerLen := 2
	var length uint64
	if firstLength < 0x80 {
		length = uint64(firstLength)
	} else {
		count := int(firstLength & 0x7f)
		if count == 0 {
			return nil, errs.Detail(ErrInvalidResponse, "indefinite LDAP message length | LDAP 消息长度为不定长")
		}
		if count > 8 {
			return nil, errs.Detail(ErrInvalidResponse, "LDAP length uses %d octets | LDAP 长度占用 %d 字节", count, count)
		}
		if _, err := io.ReadFull(c.reader, lengthBytes[:count]); err != nil {
			return nil, err
		}
		if count == 1 && lengthBytes[0] < 0x80 {
			return nil, errs.Detail(ErrInvalidResponse, "non-minimal LDAP length | 非最小 LDAP 长度")
		}
		if count > 1 && lengthBytes[0] == 0 {
			return nil, errs.Detail(ErrInvalidResponse, "non-minimal LDAP length | 非最小 LDAP 长度")
		}
		for i := 0; i < count; i++ {
			length = length<<8 | uint64(lengthBytes[i])
		}
		headerLen += count
	}
	if headerLen > c.maxSize {
		return nil, errs.Detail(ErrInvalidMessageTooLarge, "LDAP message header %d exceeds %d | LDAP 消息头 %d 超过 %d", headerLen, c.maxSize, headerLen, c.maxSize)
	}
	if length > uint64(c.maxSize-headerLen) {
		return nil, errs.Detail(ErrInvalidMessageTooLarge, "LDAP message length %d exceeds %d | LDAP 消息长度 %d 超过 %d", length, c.maxSize, length, c.maxSize)
	}
	packet := make([]byte, headerLen+int(length))
	packet[0] = first
	packet[1] = firstLength
	copy(packet[2:], lengthBytes[:headerLen-2])
	if length > 0 {
		if _, err := io.ReadFull(c.reader, packet[headerLen:]); err != nil {
			return nil, err
		}
	}
	return packet, nil
}

// bufferedBytes reports bytes already prefetched by the frame reader. | bufferedBytes
// 返回分帧读取器已预读的字节数。
func (c *conn) bufferedBytes() int { return c.reader.Buffered() }

// dialTransport establishes a TCP connection and performs an immediate TLS
// handshake for ldaps. StartTLS is layered later by the client. | dialTransport
// 建立 TCP 连接，并为 ldaps 立即执行 TLS 握手。StartTLS 由客户端稍后叠加。
func dialTransport(ctx context.Context, cfg normalizedConfig) (*conn, error) {
	dialer := &net.Dialer{
		Timeout:   cfg.DialTimeout,
		KeepAlive: 30 * time.Second,
	}
	netConn, err := dialer.DialContext(ctx, "tcp", cfg.endpoint.address)
	if err != nil {
		return nil, err
	}
	if cfg.endpoint.secure {
		tlsConn := tls.Client(netConn, cfg.tls)
		if err := tlsConn.SetDeadline(time.Now().Add(cfg.DialTimeout)); err != nil {
			_ = netConn.Close()
			return nil, err
		}
		if err := tlsConn.HandshakeContext(ctx); err != nil {
			_ = netConn.Close()
			return nil, err
		}
		if err := tlsConn.SetDeadline(time.Time{}); err != nil {
			_ = tlsConn.Close()
			return nil, err
		}
		return newConn(tlsConn, true, tlsConn.ConnectionState(), cfg.MaxMessageSize), nil
	}
	return newConn(netConn, false, tls.ConnectionState{}, cfg.MaxMessageSize), nil
}

// upgradeTLS wraps the existing transport in TLS after a successful StartTLS
// extended response. | upgradeTLS 在 StartTLS 扩展响应成功后把现有传输包装为 TLS。
func upgradeTLS(ctx context.Context, current *conn, cfg normalizedConfig) (*conn, error) {
	if current == nil || current.netConn == nil {
		return nil, ErrClosed
	}
	if current.secure {
		return current, nil
	}
	if current.bufferedBytes() != 0 {
		return nil, errs.Detail(ErrProtocolError, "buffered bytes before TLS handshake | TLS 握手前存在缓冲字节")
	}
	tlsConn := tls.Client(current.netConn, cfg.tls)
	if err := tlsConn.SetDeadline(time.Now().Add(cfg.DialTimeout)); err != nil {
		return nil, err
	}
	if err := tlsConn.HandshakeContext(ctx); err != nil {
		return nil, err
	}
	if err := tlsConn.SetDeadline(time.Time{}); err != nil {
		_ = tlsConn.Close()
		return nil, err
	}
	upgraded := newConn(tlsConn, true, tlsConn.ConnectionState(), current.maxSize)
	upgraded.nextID = current.nextID
	return upgraded, nil
}
