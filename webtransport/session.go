package webtransport

import (
	"context"
	"encoding/binary"
	"io"
	"net"
	"sync"

	wtgo "github.com/quic-go/webtransport-go"

	"github.com/shibingli/ydx/errs"
)

// frameHeaderSize is the big-endian uint32 length prefix of one message. |
// frameHeaderSize 是一条消息的大端 uint32 长度前缀。
const frameHeaderSize = 4

// appendFrame appends one length-prefixed message to dst. | appendFrame 把一条带长度
// 前缀的消息追加到 dst。
func appendFrame(dst, p []byte) []byte {
	var hdr [frameHeaderSize]byte
	binary.BigEndian.PutUint32(hdr[:], uint32(len(p)))
	dst = append(dst, hdr[:]...)
	return append(dst, p...)
}

// readFrame reads one length-prefixed message from r, appending it to dst. |
// readFrame 从 r 读取一条带长度前缀的消息并追加到 dst。
//
// A zero-length frame is a heartbeat: it opens the stream (the peer's presence
// is what makes the stream visible to AcceptStream) and keeps NAT bindings
// alive, so it is skipped. A frame larger than max is rejected before any
// payload is read, so a corrupted frame cannot allocate an unbounded buffer. |
// 零长度帧是心跳：它打开流（对端正是凭借这次写入才让流对 AcceptStream 可见），并保持 NAT
// 绑定，因此被跳过。超过 max 的帧在任何载荷被读取之前就被拒绝，损坏的帧因此无法分配无界
// 缓冲。
func readFrame(r io.Reader, dst []byte, max int) ([]byte, error) {
	var hdr [frameHeaderSize]byte
	for {
		if _, err := io.ReadFull(r, hdr[:]); err != nil {
			return dst, err
		}
		n := binary.BigEndian.Uint32(hdr[:])
		if n == 0 {
			continue
		}
		if int64(n) > int64(max) {
			return dst, errs.Detail(ErrMessageTooLarge, "length %d exceeds %d | 长度 %d 超过 %d", n, max, n, max)
		}
		start := len(dst)
		dst = append(dst, make([]byte, int(n))...)
		if _, err := io.ReadFull(r, dst[start:]); err != nil {
			return dst[:start], err
		}
		return dst, nil
	}
}

// Session is one WebTransport session. | Session 是一个 WebTransport 会话。
//
// A session carries any number of streams and datagrams; the framework's framed
// message Channel lives on one bidirectional stream, opened by the client and
// accepted by the server. | 会话可承载任意数量的流与数据报；框架的带帧消息 Channel
// 位于一条双向流上，由客户端打开、服务端接受。
type Session struct {
	sess    *wtgo.Session
	close   sync.Once
	max     int
	untrack func()
	// untrackMu guards untrack and closed: Track can hand the session to a
	// lifecycle owner before wrap stores the untrack function, so Close may race
	// with that store; an already closed session unregisters immediately. |
	// untrackMu 保护 untrack 与 closed：Track 可能在 wrap 保存取消登记函数之前就把会话交给
	// 生命周期持有者，因此 Close 可能与该写入并发；已关闭的会话会立刻取消登记。
	untrackMu sync.Mutex
	closed    bool
}

// Accept waits for the client to open the framed message channel and returns it. |
// Accept 等待客户端打开带帧消息通道并返回。
func (s *Session) Accept(ctx context.Context) (*Channel, error) {
	if ctx == nil {
		ctx = context.Background()
	}
	str, err := s.sess.AcceptStream(ctx)
	if err != nil {
		return nil, errs.Wrap(err, ErrClosed)
	}
	return &Channel{str: str, max: s.max}, nil
}

// Open opens a bidirectional stream and wraps it as a framed message channel,
// which is the client-side counterpart of Accept. | Open 打开一条双向流并包装为带帧消息
// 通道，是 Accept 的客户端对应物。
func (s *Session) Open(ctx context.Context) (*Channel, error) {
	if ctx == nil {
		ctx = context.Background()
	}
	str, err := s.sess.OpenStreamSync(ctx)
	if err != nil {
		return nil, errs.Wrap(err, ErrClosed)
	}
	ch := &Channel{str: str, max: s.max}
	// The stream only becomes visible to the server's AcceptStream once it has
	// carried at least one write, so opening the channel sends a heartbeat frame.
	// | 流只有写出过至少一次才对服务端的 AcceptStream 可见，因此打开通道时先发一帧心跳。
	if err := ch.Ping(); err != nil {
		_ = ch.Close()
		return nil, err
	}
	return ch, nil
}

// SendDatagram sends one unreliable datagram. | SendDatagram 发送一条不可靠数据报。
func (s *Session) SendDatagram(p []byte) error {
	if err := s.sess.SendDatagram(p); err != nil {
		return errs.Wrap(err, ErrClosed)
	}
	return nil
}

// ReceiveDatagram waits for one datagram. | ReceiveDatagram 等待一条数据报。
func (s *Session) ReceiveDatagram(ctx context.Context) ([]byte, error) {
	p, err := s.sess.ReceiveDatagram(ctx)
	if err != nil {
		return nil, errs.Wrap(err, ErrClosed)
	}
	return p, nil
}

// Context is done when the session ends. | Context 在会话结束时关闭。
func (s *Session) Context() context.Context { return s.sess.Context() }

// LocalAddr returns the local QUIC address. | LocalAddr 返回本地 QUIC 地址。
func (s *Session) LocalAddr() net.Addr { return s.sess.LocalAddr() }

// RemoteAddr returns the peer QUIC address. | RemoteAddr 返回对端 QUIC 地址。
func (s *Session) RemoteAddr() net.Addr { return s.sess.RemoteAddr() }

// Close terminates the session with the given application error code and
// reason, and unregisters it from the tracker. | Close 以给定应用错误码与原因终止会话，
// 并从 Tracker 注销。
func (s *Session) Close(code uint32, reason string) error {
	err := s.sess.CloseWithError(wtgo.SessionErrorCode(code), reason)
	s.close.Do(func() {
		s.untrackMu.Lock()
		s.closed = true
		untrack := s.untrack
		s.untrack = nil
		s.untrackMu.Unlock()
		if untrack != nil {
			untrack()
		}
	})
	return err
}

// setUntrack stores the tracker's untrack function. A session that was already
// closed unregisters at once, closing the window between Track and this call. |
// setUntrack 保存 Tracker 的取消登记函数。已关闭的会话会立刻取消登记，从而封住 Track
// 与本调用之间的窗口。
func (s *Session) setUntrack(fn func()) {
	s.untrackMu.Lock()
	if s.closed {
		s.untrackMu.Unlock()
		if fn != nil {
			fn()
		}
		return
	}
	s.untrack = fn
	s.untrackMu.Unlock()
}

// Channel is a framed message channel over one bidirectional stream. | Channel 是一条
// 双向流上的带帧消息通道。
//
// Send is safe for concurrent use; Receive must not be called concurrently with
// itself. | Send 可安全并发调用；Receive 不得与自身并发调用。
type Channel struct {
	str *wtgo.Stream
	max int
	wmu sync.Mutex
}

// Send writes one message as a length-prefixed frame. | Send 把一条消息写成带长度前缀的帧。
func (c *Channel) Send(p []byte) error {
	if len(p) == 0 {
		return ErrEmptyMessage
	}
	buf := appendFrame(make([]byte, 0, frameHeaderSize+len(p)), p)
	c.wmu.Lock()
	defer c.wmu.Unlock()
	if _, err := c.str.Write(buf); err != nil {
		return errs.Wrap(err, ErrClosed)
	}
	return nil
}

// Ping writes one heartbeat frame, which also opens the stream on first use. |
// Ping 写一帧心跳，首次使用时同时打开流。
func (c *Channel) Ping() error {
	var hdr [frameHeaderSize]byte
	c.wmu.Lock()
	defer c.wmu.Unlock()
	if _, err := c.str.Write(hdr[:]); err != nil {
		return errs.Wrap(err, ErrClosed)
	}
	return nil
}

// Receive reads the next message into a new buffer. | Receive 把下一条消息读进新缓冲。
func (c *Channel) Receive() ([]byte, error) {
	return c.ReceiveAppend(nil)
}

// ReceiveAppend reads the next message, appending it to dst. | ReceiveAppend 读取下一条
// 消息并追加到 dst。
func (c *Channel) ReceiveAppend(dst []byte) ([]byte, error) {
	return readFrame(c.str, dst, c.max)
}

// Context is done when the stream ends. | Context 在流结束时关闭。
func (c *Channel) Context() context.Context { return c.str.Context() }

// Close closes the stream. | Close 关闭流。
func (c *Channel) Close() error { return c.str.Close() }
