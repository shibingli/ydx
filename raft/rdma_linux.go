//go:build linux && cgo && rdma

package raft

import (
	"context"
	"errors"
	"io"

	"github.com/shibingli/ydx/errs"
	"github.com/smallnest/gordma"
	"github.com/smallnest/gordma/rdmanet"
)

// RDMAAvailable reports whether this build links a working RDMA provider.
// | RDMAAvailable 报告当前构建是否链接了可用的 RDMA 实现。
func RDMAAvailable() bool { return gordma.Supported() }

// NewRDMATransport binds an RDMA CM listener and returns a stream-framed
// transport. Every peer must serve on its own ListenAddr. | NewRDMATransport 绑定
// RDMA CM 监听并返回流式帧传输。每个对端都必须在其 ListenAddr 上服务。
func NewRDMATransport(opts RDMATransportOptions) (*RDMATransport, error) {
	if !gordma.Supported() {
		return nil, errs.Detail(ErrUnsupported, "gordma build has no libibverbs/librdmacm support")
	}
	if opts.ListenAddr == "" {
		return nil, errs.Detail(ErrInvalidConfig, "RDMA ListenAddr is required")
	}
	backend := &rdmaBackend{opts: opts}
	st, err := newStreamTransport(backend, opts.ListenAddr, opts.SharedSecret, opts.Queue, opts.MaxFrameBytes, opts.DialTimeout)
	if err != nil {
		return nil, err
	}
	return &RDMATransport{streamTransport: st}, nil
}

// rdmaBackend implements streamBackend over rdmanet. | rdmaBackend 基于 rdmanet
// 实现 streamBackend。
type rdmaBackend struct {
	opts RDMATransportOptions
}

// options converts transport options to rdmanet options. | options 将传输配置转换为
// rdmanet 选项。
func (b *rdmaBackend) options() []rdmanet.Option {
	out := make([]rdmanet.Option, 0, 7)
	if b.opts.Device != "" {
		out = append(out, rdmanet.WithDevice(b.opts.Device))
	}
	if b.opts.GIDIndex > 0 {
		out = append(out, rdmanet.WithGIDIndex(b.opts.GIDIndex))
	}
	if b.opts.DevicePort > 0 {
		out = append(out, rdmanet.WithPort(b.opts.DevicePort))
	}
	if b.opts.QueueDepth > 0 {
		out = append(out, rdmanet.WithQueueDepth(b.opts.QueueDepth))
	}
	if b.opts.BufferSize > 0 {
		out = append(out, rdmanet.WithBufferSize(b.opts.BufferSize))
	}
	if b.opts.BusyPoll {
		out = append(out, rdmanet.WithPollMode(rdmanet.PollBusy))
	}
	if b.opts.UseHandshake {
		out = append(out, rdmanet.WithHandshake())
	}
	return out
}

// listen implements streamBackend. | listen 实现 streamBackend。
func (b *rdmaBackend) listen(addr string) (streamListener, error) {
	l, err := rdmanet.Listen(addr, b.options()...)
	if err != nil {
		if errors.Is(err, gordma.ErrNotSupported) {
			return nil, errs.Wrap(err, ErrUnsupported)
		}
		return nil, errs.Wrap(err, ErrStorage)
	}
	return &rdmaListener{l: l}, nil
}

// rdmaMessageConn uses RDMA message boundaries for frame exchange. | rdmaMessageConn
// 使用 RDMA 消息边界交换帧。
type rdmaMessageConn struct {
	c *rdmanet.Conn
}

// Read implements io.Reader. It is not used by the message path. | Read 实现
// io.Reader，消息路径不使用它。
func (c *rdmaMessageConn) Read(p []byte) (int, error) { return c.c.Read(p) }

// Write implements io.Writer. It is not used by the message path. | Write 实现
// io.Writer，消息路径不使用它。
func (c *rdmaMessageConn) Write(p []byte) (int, error) { return c.c.Write(p) }

// Close implements io.Closer. | Close 实现 io.Closer。
func (c *rdmaMessageConn) Close() error { return c.c.Close() }

// sendFrame sends one whole RDMA message. | sendFrame 发送一条完整 RDMA 消息。
func (c *rdmaMessageConn) sendFrame(frame []byte) error { return c.c.SendMsg(frame) }

// recvFrame receives one whole RDMA message. | recvFrame 接收一条完整 RDMA 消息。
func (c *rdmaMessageConn) recvFrame(max int) ([]byte, error) {
	msg, err := c.c.RecvMsg()
	if err != nil {
		return nil, err
	}
	if max > 0 && len(msg) > max {
		return nil, errs.Detail(ErrTooLarge, "RDMA frame %d bytes", len(msg))
	}
	return msg, nil
}

// dial implements streamBackend. | dial 实现 streamBackend。
func (b *rdmaBackend) dial(_ context.Context, addr string) (io.ReadWriteCloser, error) {
	timeout := b.opts.DialTimeout
	if timeout <= 0 {
		timeout = defaultDialTimeout
	}
	c, err := rdmanet.DialTimeout(addr, timeout, b.options()...)
	if err != nil {
		if errors.Is(err, gordma.ErrNotSupported) {
			return nil, errs.Wrap(err, ErrUnsupported)
		}
		return nil, err
	}
	return &rdmaMessageConn{c: c}, nil
}

// rdmaListener adapts rdmanet.Listener. | rdmaListener 适配 rdmanet.Listener。
type rdmaListener struct {
	l *rdmanet.Listener
}

// accept implements streamListener. | accept 实现 streamListener。
func (l *rdmaListener) accept() (io.ReadWriteCloser, error) {
	c, err := l.l.Accept()
	if err != nil {
		return nil, err
	}
	return &rdmaMessageConn{c: c}, nil
}

// close implements streamListener. | close 实现 streamListener。
func (l *rdmaListener) close() error { return l.l.Close() }

// addr implements streamListener. | addr 实现 streamListener。
func (l *rdmaListener) addr() string { return l.l.Addr() }
