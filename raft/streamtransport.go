package raft

import (
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"crypto/tls"
	"encoding/binary"
	"io"
	"net"
	"sync"
	"sync/atomic"
	"time"

	"github.com/shibingli/ydx/errs"
)

// defaultDialTimeout bounds stream connection establishment. | defaultDialTimeout
// 限制流式连接建立时间。
const defaultDialTimeout = 5 * time.Second

// tcpNetwork is the network name for plain TCP listeners and dialers. |
// tcpNetwork 是纯 TCP 监听与拨号的网络名。
const tcpNetwork = "tcp"

// defaultMaxConns bounds tracked inbound and outbound connections. | defaultMaxConns
// 限制跟踪的入站与出站连接数。
const defaultMaxConns = 256

// defaultReadTimeout closes a connection that sends no complete frame for this
// long, preventing stalled peers from pinning large read buffers. | defaultReadTimeout
// 关闭长时间收不到完整帧的连接，避免停滞对端长期占用大读取缓冲区。
const defaultReadTimeout = 60 * time.Second

// streamListener is a listener abstraction shared by TCP and RDMA. | streamListener
// 是 TCP 与 RDMA 共用的监听抽象。
type streamListener interface {
	accept() (io.ReadWriteCloser, error)
	close() error
	addr() string
}

// streamBackend supplies dial and listen primitives for one network technology.
// | streamBackend 为一种网络技术提供拨号与监听原语。
type streamBackend interface {
	listen(addr string) (streamListener, error)
	dial(ctx context.Context, addr string) (io.ReadWriteCloser, error)
}

// frameConn is an optional message-oriented connection. RDMA preserves message
// boundaries, so it can exchange one whole frame per SendMsg/RecvMsg instead of
// going through the byte-stream adapter. | frameConn 是可选的面向消息连接。RDMA
// 保留消息边界，因此每次 SendMsg/RecvMsg 可直接交换完整帧，而无需经过字节流适配器。
type frameConn interface {
	io.ReadWriteCloser
	sendFrame(frame []byte) error
	recvFrame(max int) ([]byte, error)
}

// writeFrame writes one frame using message mode when available. | writeFrame 在可用
// 时使用消息模式写入一个帧。
func writeFrame(conn io.ReadWriteCloser, frame []byte) error {
	if fc, ok := conn.(frameConn); ok {
		return fc.sendFrame(frame)
	}
	return writeFull(conn, frame)
}

// readFrame reads one frame using message mode when available. | readFrame 在可用时
// 使用消息模式读取一个帧。
func readFrame(conn io.ReadWriteCloser, secret []byte, maxFrame int) ([]Message, *frameAuth, error) {
	if fc, ok := conn.(frameConn); ok {
		frame, err := fc.recvFrame(maxFrame)
		if err != nil {
			return nil, nil, err
		}
		return decodeStreamFrame(frame, secret, maxFrame)
	}
	return readStreamFrame(conn, secret, maxFrame)
}

// streamTransport implements Transport over length-prefixed, optionally HMAC
// authenticated message frames. TCP and RDMA share it. | streamTransport 在带长度
// 前缀、可选 HMAC 认证的消息帧上实现 Transport；TCP 与 RDMA 共用该实现。
type streamTransport struct {
	backend  streamBackend
	listener streamListener
	peers    map[NodeID]*streamPeer
	conns    map[io.ReadWriteCloser]struct{}

	handler     atomic.Pointer[func(Message)]
	stopCh      chan struct{}
	secret      []byte
	wg          sync.WaitGroup
	queue       int
	maxFrame    int
	maxConns    int
	timeout     time.Duration
	readTTL     time.Duration
	frameMaxAge time.Duration
	authSeq     atomic.Uint64
	replay      *replayGuard

	drops atomic.Uint64

	mu        sync.RWMutex
	startOnce sync.Once
	closeOnce sync.Once
	stopped   atomic.Bool
	started   bool
}

// streamPeer owns the ordered outbound queues for one peer. Control traffic
// uses a separate lane so a large replication or snapshot batch cannot delay
// heartbeats and elections. Each lane preserves order; Raft tolerates
// cross-lane reordering. | streamPeer 持有一个对端的有序出站队列。控制流量使用
// 独立通道，避免大批复制或快照阻塞心跳与选举。各通道内部保序；Raft 容忍跨通道
// 重排。
type streamPeer struct {
	ctrl chan []Message
	data chan []Message
	stop chan struct{}
	addr string
	id   NodeID
}

// newStreamTransport binds the listener and returns a stopped-until-Start
// transport. maxConns zero uses defaultMaxConns, a negative value means
// unlimited. | newStreamTransport 绑定监听并返回在 Start 前不投递的传输。
// maxConns 为零时使用 defaultMaxConns，负值表示不限制。
func newStreamTransport(backend streamBackend, listenAddr string, secret []byte, queue, maxFrame, maxConns int, timeout, frameMaxAge time.Duration) (*streamTransport, error) {
	if queue <= 0 {
		queue = 64
	}
	if maxFrame <= 0 {
		maxFrame = 64 << 20
	}
	if timeout <= 0 {
		timeout = 5 * time.Second
	}
	if maxConns == 0 {
		maxConns = defaultMaxConns
	}
	if maxConns < 0 {
		maxConns = 0
	}
	if len(secret) > 0 && len(secret) < 16 {
		return nil, errs.Detail(ErrInvalidConfig, "shared secret must be at least 16 bytes")
	}
	var listener streamListener
	var err error
	if listenAddr != "" {
		listener, err = backend.listen(listenAddr)
		if err != nil {
			return nil, err
		}
	}
	return &streamTransport{
		backend:     backend,
		listener:    listener,
		secret:      append([]byte(nil), secret...),
		queue:       queue,
		maxFrame:    maxFrame,
		maxConns:    maxConns,
		timeout:     timeout,
		readTTL:     defaultReadTimeout,
		frameMaxAge: frameMaxAge,
		replay:      newReplayGuard(frameMaxAge),
		peers:       make(map[NodeID]*streamPeer),
		conns:       make(map[io.ReadWriteCloser]struct{}),
		stopCh:      make(chan struct{}),
	}, nil
}

// Start implements Transport. | Start 实现 Transport。
func (t *streamTransport) Start(handler func(Message)) error {
	if t.stopped.Load() {
		return ErrStopped
	}
	h := handler
	t.handler.Store(&h)
	t.startOnce.Do(func() {
		t.mu.Lock()
		t.started = true
		for _, p := range t.peers {
			t.wg.Add(1)
			go t.peerLoop(p)
		}
		t.mu.Unlock()
		if t.listener != nil {
			t.wg.Add(1)
			go t.acceptLoop()
		}
	})
	return nil
}

// UpdatePeer implements Transport. An address change takes effect on the next
// batch: peerLoop compares the dialed address with the current one before every
// write and reconnects immediately instead of waiting for an old connection to
// fail. | UpdatePeer 实现 Transport。地址变更在下一次发送时生效：peerLoop 每次
// 写入前比较已拨号地址与当前地址并立即重连，而不是等待旧连接失败。
func (t *streamTransport) UpdatePeer(id NodeID, addr string) {
	if id == 0 || addr == "" {
		return
	}
	t.mu.Lock()
	p := t.peers[id]
	if p == nil {
		ctrlQueue := t.queue / 4
		if ctrlQueue < 8 {
			ctrlQueue = 8
		}
		p = &streamPeer{
			id: id, addr: addr,
			ctrl: make(chan []Message, ctrlQueue),
			data: make(chan []Message, t.queue),
			stop: make(chan struct{}),
		}
		t.peers[id] = p
		if t.started {
			t.wg.Add(1)
			go t.peerLoop(p)
		}
	} else {
		p.addr = addr
	}
	t.mu.Unlock()
}

// RemovePeer implements PeerRemover. | RemovePeer 实现 PeerRemover。
func (t *streamTransport) RemovePeer(id NodeID) {
	if id == 0 {
		return
	}
	t.mu.Lock()
	p := t.peers[id]
	if p != nil {
		delete(t.peers, id)
		close(p.stop)
	}
	t.mu.Unlock()
}

// PeerAddress implements PeerDirectory. | PeerAddress 实现 PeerDirectory。
func (t *streamTransport) PeerAddress(id NodeID) (string, bool) {
	t.mu.RLock()
	defer t.mu.RUnlock()
	p := t.peers[id]
	if p == nil {
		return "", false
	}
	return p.addr, true
}

// RequiresPeerAddresses implements PeerAddressTransport. | RequiresPeerAddresses
// 实现 PeerAddressTransport。
func (t *streamTransport) RequiresPeerAddresses() bool { return true }

// Send implements Transport. | Send 实现 Transport。
func (t *streamTransport) Send(_ context.Context, msgs []Message) error {
	if t.stopped.Load() {
		return ErrStopped
	}
	if len(msgs) == 0 {
		return nil
	}
	groups := make(map[NodeID][]Message, 4)
	for i := range msgs {
		groups[msgs[i].To] = append(groups[msgs[i].To], msgs[i])
	}
	t.mu.RLock()
	defer t.mu.RUnlock()
	var firstErr error
	for id, batch := range groups {
		p := t.peers[id]
		if p == nil {
			if firstErr == nil {
				firstErr = errs.Detail(ErrUnknownNode, "stream peer %d has no address", id)
			}
			continue
		}
		control, data := splitTransportMessages(batch)
		if len(control) > 0 {
			select {
			case p.ctrl <- control:
			default:
				// A full control lane falls back to the data lane; losing an
				// election or acknowledgement message is worse than delaying it. |
				// 控制通道满时回退到数据通道；丢弃选举或确认消息比延迟它更糟。
				select {
				case p.data <- control:
				default:
					t.drops.Add(uint64(len(control)))
					if firstErr == nil {
						firstErr = errs.Detail(ErrProposalDropped, "stream queue for %d is full", id)
					}
				}
			}
		}
		if len(data) > 0 {
			select {
			case p.data <- data:
			default:
				t.drops.Add(uint64(len(data)))
				if firstErr == nil {
					firstErr = errs.Detail(ErrProposalDropped, "stream queue for %d is full", id)
				}
			}
		}
	}
	return firstErr
}

// SendImmediate implements ImmediateTransport. Send only groups and enqueues.
// | SendImmediate 实现 ImmediateTransport。Send 只做分组与入队。
func (t *streamTransport) SendImmediate() bool { return true }

// Addr returns the listener address, or "" for a client-only transport. | Addr
// 返回监听地址；仅客户端传输返回空串。
func (t *streamTransport) Addr() string {
	if t.listener == nil {
		return ""
	}
	return t.listener.addr()
}

// Drops returns frames or batches dropped by queue pressure or network errors.
// | Drops 返回因队列压力或网络错误丢弃的帧或批次。
func (t *streamTransport) Drops() uint64 { return t.drops.Load() }

// FrameLimit reports the maximum encoded frame accepted by this transport, or
// zero when unbounded. | FrameLimit 返回该传输可接受的最大编码帧；无限制时为
// 零。
func (t *streamTransport) FrameLimit() int64 { return int64(t.maxFrame) }

// Close implements Transport. | Close 实现 Transport。
func (t *streamTransport) Close() error {
	t.closeOnce.Do(func() {
		t.stopped.Store(true)
		close(t.stopCh)
		if t.listener != nil {
			_ = t.listener.close()
		}
		t.mu.Lock()
		conns := make([]io.ReadWriteCloser, 0, len(t.conns))
		for c := range t.conns {
			conns = append(conns, c)
		}
		t.mu.Unlock()
		for _, c := range conns {
			_ = c.Close()
		}
		t.wg.Wait()
	})
	return nil
}

// acceptLoop accepts inbound streams. | acceptLoop 接受入站流。
func (t *streamTransport) acceptLoop() {
	defer t.wg.Done()
	for {
		conn, err := t.listener.accept()
		if err != nil {
			if t.stopped.Load() {
				return
			}
			time.Sleep(10 * time.Millisecond)
			continue
		}
		if !t.track(conn) {
			_ = conn.Close()
			if t.stopped.Load() {
				return
			}
			time.Sleep(10 * time.Millisecond)
			continue
		}
		t.wg.Add(1)
		go t.readLoop(conn)
	}
}

// readLoop decodes frames from one inbound stream. | readLoop 从一条入站流解码帧。
func (t *streamTransport) readLoop(conn io.ReadWriteCloser) {
	defer t.wg.Done()
	defer t.untrack(conn)
	defer conn.Close()
	for {
		if dc, ok := conn.(interface{ SetReadDeadline(time.Time) error }); ok {
			_ = dc.SetReadDeadline(time.Now().Add(t.readTTL))
		}
		msgs, auth, err := readFrame(conn, t.secret, t.maxFrame)
		if err != nil {
			return
		}
		if t.frameMaxAge > 0 {
			if len(msgs) == 0 || !t.replay.accept(msgs[0].From, auth) {
				t.drops.Add(1)
				return
			}
			for i := 1; i < len(msgs); i++ {
				if msgs[i].From != msgs[0].From {
					t.drops.Add(1)
					return
				}
			}
		}
		h := t.handler.Load()
		if h == nil {
			continue
		}
		for i := range msgs {
			(*h)(msgs[i])
		}
	}
}

// peerLoop serializes writes to one peer and reconnects after failures or an
// address change. connAddr records the address the live connection was dialed
// for, so an UpdatePeer takes effect before the next write instead of waiting
// for the old connection to fail. | peerLoop 串行化发往一个对端的写入，并在失败或
// 地址变更后重连。connAddr 记录当前连接拨号时使用的地址，因此 UpdatePeer 会在下
// 一次写入前生效，而不是等待旧连接失败。
func (t *streamTransport) peerLoop(p *streamPeer) {
	defer t.wg.Done()
	var conn io.ReadWriteCloser
	var connAddr string
	defer func() {
		if conn != nil {
			t.untrack(conn)
			_ = conn.Close()
		}
	}()
	for {
		batch, control, ok := t.nextBatchClass(p)
		if !ok {
			return
		}
		select {
		case <-p.stop:
			return
		default:
		}
		batches := [][]Message{batch}
		total := len(batch)
		for len(batches) < maxCoalesceBatches && total < maxCoalesceMessages {
			more, ok := t.tryBatch(p, control)
			if !ok {
				break
			}
			batches = append(batches, more)
			total += len(more)
		}
		t.mu.RLock()
		addr := p.addr
		t.mu.RUnlock()
		if conn != nil && connAddr != addr {
			t.untrack(conn)
			_ = conn.Close()
			conn = nil
		}
		if conn == nil {
			ctx, cancel := context.WithTimeout(context.Background(), t.timeout)
			c, err := t.backend.dial(ctx, addr)
			cancel()
			if err != nil {
				t.drops.Add(uint64(total))
				continue
			}
			if !t.track(c) {
				_ = c.Close()
				if t.stopped.Load() {
					return
				}
				t.drops.Add(uint64(total))
				continue
			}
			conn = c
			connAddr = addr
		}
		merged := mergeBatches(batches)
		var auth *frameAuth
		if t.frameMaxAge > 0 {
			auth = &frameAuth{timestamp: time.Now().UnixNano(), counter: t.authSeq.Add(1)}
		}
		frame, err := encodeStreamFrame(merged, t.secret, t.maxFrame, auth)
		if err != nil {
			// A merged frame over the transport limit is split back into the
			// original batches; each batch still gets a chance to be written. |
			// 合并帧超过传输上限时拆回原始批次，每个批次仍有机会写出。
			for idx, one := range batches {
				var oneAuth *frameAuth
				if t.frameMaxAge > 0 {
					oneAuth = &frameAuth{timestamp: time.Now().UnixNano(), counter: t.authSeq.Add(1)}
				}
				frame, err := encodeStreamFrame(one, t.secret, t.maxFrame, oneAuth)
				if err != nil {
					t.drops.Add(uint64(len(one)))
					continue
				}
				if err := writeFrame(conn, frame); err != nil {
					t.untrack(conn)
					_ = conn.Close()
					conn = nil
					t.drops.Add(uint64(len(one)))
					for _, rest := range batches[idx+1:] {
						t.drops.Add(uint64(len(rest)))
					}
					break
				}
			}
			continue
		}
		if err := writeFrame(conn, frame); err != nil {
			t.untrack(conn)
			_ = conn.Close()
			conn = nil
			t.drops.Add(uint64(total))
		}
	}
}

// maxCoalesceBatches and maxCoalesceMessages bound one merged frame. Snapshot
// chunks and replication batches are capped by the transport frame limit; if a
// merged frame would exceed it, the sender falls back to the original batches.
// | maxCoalesceBatches 与 maxCoalesceMessages 限制单个合并帧。快照分块与复制批次
// 仍受传输帧上限约束；合并帧超限时回退为原始批次。
const (
	maxCoalesceBatches  = 8
	maxCoalesceMessages = 256
)

// nextBatchClass prefers the control lane and reports which lane supplied the
// batch, so coalescing never mixes a data batch ahead of a queued control batch.
// | nextBatchClass 优先控制通道并报告来源通道，避免合并时把数据批次排到已排队的
// 控制批次之前。
func (t *streamTransport) nextBatchClass(p *streamPeer) ([]Message, bool, bool) {
	select {
	case <-t.stopCh:
		return nil, false, false
	case <-p.stop:
		return nil, false, false
	case batch := <-p.ctrl:
		return batch, true, true
	default:
	}
	select {
	case <-t.stopCh:
		return nil, false, false
	case <-p.stop:
		return nil, false, false
	case batch := <-p.ctrl:
		return batch, true, true
	case batch := <-p.data:
		return batch, false, true
	}
}

// tryBatch drains one more batch from the same lane without blocking. |
// tryBatch 非阻塞地从同一通道再取一个批次。
func (t *streamTransport) tryBatch(p *streamPeer, control bool) ([]Message, bool) {
	ch := p.data
	if control {
		ch = p.ctrl
	}
	select {
	case batch := <-ch:
		return batch, true
	default:
		return nil, false
	}
}

// mergeBatches flattens queued batches while preserving their order. |
// mergeBatches 按顺序展平排队的批次。
func mergeBatches(batches [][]Message) []Message {
	total := 0
	for _, batch := range batches {
		total += len(batch)
	}
	out := make([]Message, 0, total)
	for _, batch := range batches {
		out = append(out, batch...)
	}
	return out
}

// track registers a live connection for shutdown. | track 注册活动连接以便关闭。
func (t *streamTransport) track(conn io.ReadWriteCloser) bool {
	t.mu.Lock()
	defer t.mu.Unlock()
	if t.stopped.Load() {
		return false
	}
	if t.maxConns > 0 && len(t.conns) >= t.maxConns {
		return false
	}
	t.conns[conn] = struct{}{}
	return true
}

// untrack removes a connection. | untrack 移除连接。
func (t *streamTransport) untrack(conn io.ReadWriteCloser) {
	t.mu.Lock()
	delete(t.conns, conn)
	t.mu.Unlock()
}

// writeFull writes the whole frame, handling short writes. | writeFull 写入完整帧并
// 处理短写。
func writeFull(w io.Writer, frame []byte) error {
	for len(frame) > 0 {
		n, err := w.Write(frame)
		if err != nil {
			return err
		}
		if n <= 0 {
			return io.ErrShortWrite
		}
		frame = frame[n:]
	}
	return nil
}

// encodeStreamFrame builds length-prefixed, CRC-checked, optionally HMAC-signed
// frame bytes. It encodes directly into the final buffer so a large snapshot
// image is not copied twice. | encodeStreamFrame 构建带长度前缀、CRC 校验与可选
// HMAC 签名的帧字节。它直接编码到最终缓冲区，避免大快照镜像被复制两次。
func encodeStreamFrame(msgs []Message, secret []byte, maxFrame int, auth *frameAuth) ([]byte, error) {
	macLen := 0
	if len(secret) > 0 {
		macLen = sha256.Size
	}
	out := make([]byte, 4, 4+256+macLen)
	var err error
	out, err = encodeHTTPFrameInto(out, msgs, auth)
	if err != nil {
		return nil, err
	}
	length := len(out) - 4 + macLen
	if length > maxMessageBytes || (maxFrame > 0 && 4+length > maxFrame) {
		return nil, errs.Detail(ErrTooLarge, "stream frame %d bytes", 4+length)
	}
	binary.BigEndian.PutUint32(out[:4], uint32(length))
	if macLen > 0 {
		mac := hmac.New(sha256.New, secret)
		_, _ = mac.Write(out[:4])
		_, _ = mac.Write(out[4:])
		out = append(out, mac.Sum(nil)...)
	}
	return out, nil
}

// readStreamFrame reads and authenticates one frame. | readStreamFrame 读取并认证
// 一个帧。
func readStreamFrame(r io.Reader, secret []byte, maxFrame int) ([]Message, *frameAuth, error) {
	var header [4]byte
	if _, err := io.ReadFull(r, header[:]); err != nil {
		return nil, nil, err
	}
	length := binary.BigEndian.Uint32(header[:])
	if length == 0 || uint64(length)+4 > uint64(maxMessageBytes) ||
		(maxFrame > 0 && uint64(length)+4 > uint64(maxFrame)) {
		return nil, nil, errs.Detail(ErrTooLarge, "stream frame length %d", length)
	}
	frame := make([]byte, 4+int(length))
	copy(frame, header[:])
	if _, err := io.ReadFull(r, frame[4:]); err != nil {
		return nil, nil, err
	}
	return decodeStreamFrame(frame, secret, maxFrame)
}

// decodeStreamFrame validates one complete frame, including its optional HMAC.
// | decodeStreamFrame 校验一个完整帧，包括可选 HMAC。
func decodeStreamFrame(frame, secret []byte, maxFrame int) ([]Message, *frameAuth, error) {
	if len(frame) < 4 {
		return nil, nil, errs.Detail(ErrCorrupt, "short stream frame")
	}
	length := binary.BigEndian.Uint32(frame[:4])
	if length == 0 || uint64(length) > uint64(maxMessageBytes) || int(length) != len(frame)-4 {
		return nil, nil, errs.Detail(ErrCorrupt, "stream frame length %d, got %d", length, len(frame)-4)
	}
	if maxFrame > 0 && len(frame) > maxFrame {
		return nil, nil, errs.Detail(ErrTooLarge, "stream frame %d bytes", len(frame))
	}
	macLen := 0
	if len(secret) > 0 {
		macLen = sha256.Size
	}
	body := frame[4:]
	if len(body) < macLen {
		return nil, nil, errs.Detail(ErrCorrupt, "short stream frame body")
	}
	payload := body[:len(body)-macLen]
	if macLen > 0 {
		mac := hmac.New(sha256.New, secret)
		_, _ = mac.Write(frame[:4])
		_, _ = mac.Write(payload)
		if !hmac.Equal(mac.Sum(nil), body[len(body)-macLen:]) {
			return nil, nil, errs.Detail(ErrCorrupt, "stream HMAC mismatch")
		}
	}
	return decodeHTTPFrameAuth(payload)
}

// TCPTransportOptions configures the TCP stream transport. | TCPTransportOptions
// 配置 TCP 流传输。
type TCPTransportOptions struct {
	// ListenAddr is the local bind address. Required. | ListenAddr 是本地绑定地址，
	// 必填。
	ListenAddr string
	// TLSConfig enables TLS when non-nil. The same config is used for listening
	// and dialing; set Certificates for the server and RootCAs for clients.
	// | TLSConfig 非空时启用 TLS。监听与拨号共用该配置；服务端设置 Certificates，
	// 客户端设置 RootCAs。
	TLSConfig *tls.Config
	// SharedSecret enables frame-level HMAC authentication. It is required unless
	// AllowInsecure is set. | SharedSecret 启用帧级 HMAC 认证。除非设置
	// AllowInsecure，否则必须提供。
	SharedSecret []byte
	// AllowInsecure permits an empty SharedSecret. Use it only on a trusted
	// network or when TLS/mTLS already authenticates both ends outside the
	// transport. | AllowInsecure 允许空的 SharedSecret。仅在可信网络或 TLS/mTLS
	// 已在传输之外双向认证时使用。
	AllowInsecure bool
	// Queue is the per-peer outbound queue length. Default 64. | Queue 是每对端出站
	// 队列长度，默认 64。
	Queue int
	// DialTimeout bounds connection establishment. Default 5s. | DialTimeout 限制
	// 建连时间，默认 5s。
	DialTimeout time.Duration
	// MaxFrameBytes caps one frame. Default 64 MiB. | MaxFrameBytes 限制单帧大小，
	// 默认 64 MiB。
	MaxFrameBytes int
	// MaxConns caps tracked inbound and outbound connections. Zero uses 256; a
	// negative value means unlimited. Each peer normally needs one connection in
	// each direction, so the default fits roughly 128 peers; raise it for larger
	// clusters. | MaxConns 限制跟踪的入站与出站连接总数。零值使用 256，负值表示
	// 不限制。每个对端通常需要一条各方向连接，默认值约可容纳 128 个对端；更大集群
	// 应提高该值。
	MaxConns int
	// FrameMaxAge enables HMAC-covered frame freshness and replay rejection.
	// Zero disables it. A positive value is the accepted clock window; frames
	// carry a timestamp and a sender-wide monotonic counter. SharedSecret is
	// required, and every peer must understand the auth frame flag; enable it
	// only after the whole cluster is upgraded. | FrameMaxAge 启用 HMAC 覆盖的帧
	// 新鲜度与重放拒绝。零值关闭；正值是接受的时钟窗口；帧携带时间戳与发送方全局
	// 单调计数器。必须配置 SharedSecret，且所有对端都要理解 auth 帧标志；请在全集群
	// 升级后再启用。
	FrameMaxAge time.Duration
}

// TCPTransport is a TCP implementation of Transport with optional TLS and HMAC.
// | TCPTransport 是支持可选 TLS 与 HMAC 的 TCP Transport 实现。
type TCPTransport struct {
	*streamTransport
}

// NewTCPTransport binds the listener and returns a transport. | NewTCPTransport
// 绑定监听并返回传输。
func NewTCPTransport(opts TCPTransportOptions) (*TCPTransport, error) {
	if opts.ListenAddr == "" {
		return nil, errs.Detail(ErrInvalidConfig, "TCP ListenAddr is required")
	}
	if len(opts.SharedSecret) == 0 && !opts.AllowInsecure {
		return nil, errs.Detail(ErrInvalidConfig, "shared secret is required unless AllowInsecure is set")
	}
	if opts.FrameMaxAge < 0 {
		return nil, errs.Detail(ErrInvalidConfig, "FrameMaxAge must not be negative")
	}
	if opts.FrameMaxAge > 0 && len(opts.SharedSecret) == 0 {
		return nil, errs.Detail(ErrInvalidConfig, "FrameMaxAge requires SharedSecret")
	}
	backend := &tcpBackend{tlsConfig: opts.TLSConfig, timeout: opts.DialTimeout}
	st, err := newStreamTransport(backend, opts.ListenAddr, opts.SharedSecret, opts.Queue, opts.MaxFrameBytes, opts.MaxConns, opts.DialTimeout, opts.FrameMaxAge)
	if err != nil {
		return nil, err
	}
	return &TCPTransport{streamTransport: st}, nil
}

// tcpBackend implements streamBackend over net.Conn. | tcpBackend 基于 net.Conn
// 实现 streamBackend。
type tcpBackend struct {
	tlsConfig *tls.Config
	timeout   time.Duration
}

// listen implements streamBackend. | listen 实现 streamBackend。
func (b *tcpBackend) listen(addr string) (streamListener, error) {
	ln, err := net.Listen(tcpNetwork, addr)
	if err != nil {
		return nil, errs.Wrap(err, ErrStorage)
	}
	if b.tlsConfig != nil {
		ln = tls.NewListener(ln, b.tlsConfig)
	}
	return &tcpListener{ln: ln}, nil
}

// dial implements streamBackend. | dial 实现 streamBackend。
func (b *tcpBackend) dial(ctx context.Context, addr string) (io.ReadWriteCloser, error) {
	d := net.Dialer{Timeout: b.timeout, KeepAlive: 30 * time.Second}
	raw, err := d.DialContext(ctx, tcpNetwork, addr)
	if err != nil {
		return nil, err
	}
	if b.tlsConfig == nil {
		return raw, nil
	}
	cfg := b.tlsConfig.Clone()
	if cfg.ServerName == "" {
		if host, _, err := net.SplitHostPort(addr); err == nil {
			cfg.ServerName = host
		}
	}
	conn := tls.Client(raw, cfg)
	if err := conn.HandshakeContext(ctx); err != nil {
		_ = raw.Close()
		return nil, err
	}
	return conn, nil
}

// tcpListener adapts net.Listener. | tcpListener 适配 net.Listener。
type tcpListener struct {
	ln net.Listener
}

// accept implements streamListener. | accept 实现 streamListener。
func (l *tcpListener) accept() (io.ReadWriteCloser, error) {
	conn, err := l.ln.Accept()
	if err != nil {
		return nil, err
	}
	return conn, nil
}

// close implements streamListener. | close 实现 streamListener。
func (l *tcpListener) close() error { return l.ln.Close() }

// addr implements streamListener. | addr 实现 streamListener。
func (l *tcpListener) addr() string { return l.ln.Addr().String() }
