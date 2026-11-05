//go:build linux && rdma && (amd64 || arm64)

package raft

import (
	"context"
	"errors"
	"io"
	"time"

	"github.com/shibingli/ydx/errs"
	ydxrdma "github.com/shibingli/ydx/rdma"
)

// RDMA message tuning. A frame is chunked into one registered slot at a time;
// the defaults keep per-connection registration small while amortizing chunk
// headers over useful payload. | RDMA 消息调优。帧按一个注册槽位分块；默认值让
// 每连接注册内存保持较小，同时用有效负载摊薄分块头。
const (
	defaultRDMASlots    = 64
	defaultRDMASlotSize = 64 << 10
	maxRDMASlots        = 512
	rdmaSendBatch       = 32
)

// RDMAAvailable reports whether libibverbs can be loaded in this build. | RDMAAvailable
// 报告当前构建能否加载 libibverbs。
func RDMAAvailable() bool { return ydxrdma.Supported() }

// NewRDMATransport binds an RDMA message listener and returns a stream-framed
// transport. It requires Linux/amd64 or Linux/arm64 with -tags rdma; ydx/rdma is
// pure Go and does not require cgo. Every peer must serve on its own
// ListenAddr. | NewRDMATransport 绑定 RDMA 消息监听并返回流式帧传输。它需要
// Linux/amd64 或 Linux/arm64 与 -tags rdma；ydx/rdma 为纯 Go，不需要 cgo。每个
// 对端都必须在其 ListenAddr 上服务。
func NewRDMATransport(opts RDMATransportOptions) (*RDMATransport, error) {
	if opts.ListenAddr == "" {
		return nil, errs.Detail(ErrInvalidConfig, "RDMA ListenAddr is required")
	}
	if !RDMAAvailable() {
		return nil, errs.Detail(ErrUnsupported, "libibverbs is not available | libibverbs 不可用")
	}
	backend := &rdmaBackend{opts: opts}
	st, err := newStreamTransport(backend, opts.ListenAddr, opts.SharedSecret, opts.Queue, opts.MaxFrameBytes, opts.DialTimeout)
	if err != nil {
		return nil, err
	}
	return &RDMATransport{streamTransport: st}, nil
}

// rdmaBackend implements streamBackend over ydx/rdma message connections.
// | rdmaBackend 基于 ydx/rdma 消息连接实现 streamBackend。
type rdmaBackend struct {
	opts RDMATransportOptions
}

// connConfig converts transport options to a ydx/rdma connection configuration.
// The returned chunk size is the payload capacity of one chunk. | connConfig 将
// 传输配置转换为 ydx/rdma 连接配置。返回的分块大小是单个分块的有效负载容量。
func (b *rdmaBackend) connConfig() (ydxrdma.ConnConfig, int, error) {
	cfg := ydxrdma.DefaultConnConfig()
	cfg.Device = b.opts.Device
	if b.opts.DevicePort > 0 {
		cfg.Port = b.opts.DevicePort
	}
	if b.opts.GIDIndex > 0 {
		cfg.GIDIndex = b.opts.GIDIndex
	}
	slots := b.opts.QueueDepth
	if slots <= 0 {
		slots = defaultRDMASlots
	}
	if slots > maxRDMASlots {
		slots = maxRDMASlots
	}
	slotSize := b.opts.BufferSize
	if slotSize <= 0 {
		slotSize = defaultRDMASlotSize
	}
	if slotSize < 4096 {
		slotSize = 4096
	}
	if slotSize > 1<<20 {
		slotSize = 1 << 20
	}
	slotSize = (slotSize + 63) &^ 63
	cfg.Slots = slots
	cfg.SlotSize = slotSize
	cfg.QueueDepth = slots
	cfg.CQDepth = slots * 2
	cfg.HugePages = true
	cfg.SendTimeout = 5 * time.Second
	cfg.RecvTimeout = -1
	cfg.MaxBatch = rdmaSendBatch
	if b.opts.DialTimeout > 0 {
		cfg.HandshakeTimeout = b.opts.DialTimeout
	}
	chunk := slotSize - rdmaChunkHeaderLen
	if chunk <= 0 {
		return ydxrdma.ConnConfig{}, 0, errs.Detail(ErrInvalidConfig, "RDMA slot size %d", slotSize)
	}
	return cfg, chunk, nil
}

// mapRDMAError classifies a ydx/rdma error. | mapRDMAError 归类 ydx/rdma 错误。
func mapRDMAError(err error) error {
	if err == nil {
		return nil
	}
	switch {
	case errors.Is(err, ydxrdma.ErrUnsupported), errors.Is(err, ydxrdma.ErrNoDevice),
		errors.Is(err, ydxrdma.ErrNoGID):
		return errs.Wrap(err, ErrUnsupported)
	case errors.Is(err, ydxrdma.ErrInvalidConfig):
		return errs.Wrap(err, ErrInvalidConfig)
	case errors.Is(err, ydxrdma.ErrMessageTooLarge):
		return errs.Wrap(err, ErrTooLarge)
	case errors.Is(err, ydxrdma.ErrTimeout):
		return errs.Wrap(err, ErrTimeout)
	default:
		return errs.Wrap(err, ErrNetwork)
	}
}

// listen implements streamBackend. | listen 实现 streamBackend。
func (b *rdmaBackend) listen(addr string) (streamListener, error) {
	cfg, chunk, err := b.connConfig()
	if err != nil {
		return nil, err
	}
	l, err := ydxrdma.Listen(addr, cfg)
	if err != nil {
		return nil, mapRDMAError(err)
	}
	return &rdmaListener{l: l, chunk: chunk}, nil
}

// dial implements streamBackend. | dial 实现 streamBackend。
func (b *rdmaBackend) dial(ctx context.Context, addr string) (io.ReadWriteCloser, error) {
	cfg, chunk, err := b.connConfig()
	if err != nil {
		return nil, err
	}
	timeout := b.opts.DialTimeout
	if timeout <= 0 {
		timeout = defaultDialTimeout
	}
	if deadline, ok := ctx.Deadline(); ok {
		remaining := time.Until(deadline)
		if remaining <= 0 {
			return nil, context.DeadlineExceeded
		}
		if remaining < timeout {
			timeout = remaining
		}
	}
	cfg.HandshakeTimeout = timeout
	c, err := ydxrdma.Dial(addr, cfg)
	if err != nil {
		return nil, mapRDMAError(err)
	}
	return &rdmaFrameConn{c: c, chunk: chunk}, nil
}

// rdmaFrameConn exchanges one complete stream frame as a sequence of RDMA
// messages. Outbound connections are used only by the peer's writer goroutine
// and inbound connections only by its reader goroutine, which matches
// ydx/rdma's single-goroutine Conn model. | rdmaFrameConn 将完整流帧作为一串
// RDMA 消息交换。出站连接只由对端写协程使用，入站连接只由读协程使用，符合
// ydx/rdma 的单协程 Conn 模型。
type rdmaFrameConn struct {
	c     *ydxrdma.Conn
	chunk int
}

// Read implements io.Reader. RDMA uses message mode. | Read 实现 io.Reader。RDMA
// 使用消息模式。
func (c *rdmaFrameConn) Read([]byte) (int, error) {
	return 0, errs.Detail(ErrUnsupported, "RDMA transport uses message frames | RDMA 传输使用消息帧")
}

// Write implements io.Writer. RDMA uses message mode. | Write 实现 io.Writer。RDMA
// 使用消息模式。
func (c *rdmaFrameConn) Write([]byte) (int, error) {
	return 0, errs.Detail(ErrUnsupported, "RDMA transport uses message frames | RDMA 传输使用消息帧")
}

// Close implements io.Closer. | Close 实现 io.Closer。
func (c *rdmaFrameConn) Close() error { return c.c.Close() }

// sendFrame sends one frame as consecutive chunk messages. It batches chunks to
// amortize doorbells while keeping each message within one registered slot.
// | sendFrame 将一帧作为连续分块消息发送。它批量提交以摊薄门铃开销，同时让每条
// 消息不超过一个注册槽位。
func (c *rdmaFrameConn) sendFrame(frame []byte) error {
	total := len(frame)
	if total == 0 {
		return errs.Detail(ErrInvalidConfig, "empty RDMA frame")
	}
	if uint64(total) > uint64(^uint32(0)) {
		return errs.Detail(ErrTooLarge, "RDMA frame %d bytes", total)
	}
	bufs := make([]*ydxrdma.Buffer, 0, rdmaSendBatch)
	lens := make([]int, 0, rdmaSendBatch)
	flush := func() error {
		if len(bufs) == 0 {
			return nil
		}
		want := len(bufs)
		posted, err := c.c.SendBatchBuffers(bufs, lens)
		bufs = bufs[:0]
		lens = lens[:0]
		if err != nil {
			return mapRDMAError(err)
		}
		if posted != want {
			return errs.Detail(ErrNetwork, "RDMA posted %d/%d chunks", posted, want)
		}
		return nil
	}
	for offset := 0; offset < total; {
		n := total - offset
		if n > c.chunk {
			n = c.chunk
		}
		b, err := c.c.Alloc(rdmaChunkHeaderLen + n)
		if err != nil {
			for _, held := range bufs {
				held.Release()
			}
			return mapRDMAError(err)
		}
		encodeRDMAChunkHeader(b.Bytes()[:rdmaChunkHeaderLen], uint32(total), uint32(offset))
		copy(b.Bytes()[rdmaChunkHeaderLen:rdmaChunkHeaderLen+n], frame[offset:offset+n])
		bufs = append(bufs, b)
		lens = append(lens, rdmaChunkHeaderLen+n)
		offset += n
		if len(bufs) >= rdmaSendBatch {
			if err := flush(); err != nil {
				return err
			}
		}
	}
	return flush()
}

// recvFrame reassembles one frame from consecutive chunk messages. | recvFrame
// 从连续分块消息重组一个帧。
func (c *rdmaFrameConn) recvFrame(max int) ([]byte, error) {
	var frame []byte
	var total, expected uint32
	for {
		b, n, err := c.c.RecvBuffer()
		if err != nil {
			return nil, mapRDMAError(err)
		}
		if n < rdmaChunkHeaderLen {
			_ = c.c.Release(b)
			return nil, errs.Detail(ErrCorrupt, "RDMA chunk %d bytes", n)
		}
		chunkTotal, offset, err := decodeRDMAChunkHeader(b.Bytes()[:n], max)
		if err != nil {
			_ = c.c.Release(b)
			return nil, err
		}
		if total == 0 {
			total = chunkTotal
			frame = make([]byte, total)
		}
		if chunkTotal != total || offset != expected {
			_ = c.c.Release(b)
			return nil, errs.Detail(ErrCorrupt, "RDMA chunk total=%d offset=%d want %d/%d",
				chunkTotal, offset, total, expected)
		}
		payload := n - rdmaChunkHeaderLen
		if payload <= 0 || uint64(offset)+uint64(payload) > uint64(total) {
			_ = c.c.Release(b)
			return nil, errs.Detail(ErrCorrupt, "RDMA chunk payload %d", payload)
		}
		copy(frame[offset:offset+uint32(payload)], b.Bytes()[rdmaChunkHeaderLen:n])
		if rerr := c.c.Release(b); rerr != nil {
			return nil, mapRDMAError(rerr)
		}
		expected += uint32(payload)
		if expected == total {
			return frame, nil
		}
	}
}

// rdmaListener adapts ydx/rdma.Listener. | rdmaListener 适配 ydx/rdma.Listener。
type rdmaListener struct {
	l     *ydxrdma.Listener
	chunk int
}

// accept implements streamListener. | accept 实现 streamListener。
func (l *rdmaListener) accept() (io.ReadWriteCloser, error) {
	c, err := l.l.Accept()
	if err != nil {
		return nil, mapRDMAError(err)
	}
	return &rdmaFrameConn{c: c, chunk: l.chunk}, nil
}

// close implements streamListener. | close 实现 streamListener。
func (l *rdmaListener) close() error { return l.l.Close() }

// addr implements streamListener. | addr 实现 streamListener。
func (l *rdmaListener) addr() string { return l.l.Addr().String() }
