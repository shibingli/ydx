package rdma

import (
	"errors"
	"math/rand/v2"
	"net"
	"runtime"
	"sync"
	"sync/atomic"
	"time"

	"github.com/shibingli/ydx/errs"
)

// txBit marks a completion as belonging to the transmit pool. | txBit 标记完成
// 事件属于发送池。
const txBit = uint64(1) << 63

// ConnConfig configures a message connection. Zero fields take tuned defaults.
// | ConnConfig 配置消息连接。零值字段使用调优默认值。
type ConnConfig struct {
	// Config configures the underlying device and queue pair. | Config 配置
	// 底层设备与队列对。
	Config
	// SlotSize is the zero-copy message slot size in bytes. Zero means 4096.
	// | SlotSize 是零拷贝消息槽位字节数；零表示 4096。
	SlotSize int
	// Slots is the number of send and receive slots. Zero means 1024. |
	// Slots 是发送与接收槽位数量；零表示 1024。
	Slots int
	// HugePages prefers 2 MiB huge pages for the registered pools. | HugePages
	// 让注册内存池优先使用 2 MiB 大页。
	HugePages bool
	// HandshakeTimeout bounds the TCP parameter exchange. Zero means 5s. |
	// HandshakeTimeout 限制 TCP 参数交换时间；零表示 5 秒。
	HandshakeTimeout time.Duration
	// SendTimeout bounds waiting for a free send slot. Zero means 5s; a
	// negative value waits forever. | SendTimeout 限制等待空闲发送槽位的时间；
	// 零表示 5 秒，负值表示永久等待。
	SendTimeout time.Duration
	// RecvTimeout bounds waiting for a message. Zero means 5s; a negative value
	// waits forever. | RecvTimeout 限制等待消息的时间；零表示 5 秒，负值表示
	// 永久等待。
	RecvTimeout time.Duration
	// MaxBatch caps one SendBatch or Process call. Zero means 64. | MaxBatch
	// 限制单次 SendBatch 或 Process 的数量；零表示 64。
	MaxBatch int
}

// DefaultConnConfig returns a tuned connection configuration. | DefaultConnConfig
// 返回调优后的连接配置。
func DefaultConnConfig() ConnConfig {
	return ConnConfig{
		Config:           DefaultConfig(),
		SlotSize:         4096,
		Slots:            1024,
		HugePages:        true,
		HandshakeTimeout: 5 * time.Second,
		SendTimeout:      5 * time.Second,
		RecvTimeout:      5 * time.Second,
		MaxBatch:         64,
	}
}

// normalize validates the configuration and fills defaults. | normalize 校验
// 配置并填充默认值。
func (c *ConnConfig) normalize() error {
	if err := c.Config.normalize(); err != nil {
		return err
	}
	if c.SlotSize == 0 {
		c.SlotSize = 4096
	}
	if c.SlotSize < 64 || c.SlotSize%64 != 0 {
		return errs.Detail(ErrInvalidConfig, "slot size %d must be a multiple of 64 | 槽位大小 %d 必须是 64 的倍数", c.SlotSize, c.SlotSize)
	}
	if c.Slots == 0 {
		c.Slots = 1024
	}
	if c.Slots < 2 {
		return errs.Detail(ErrInvalidConfig, "slots %d | 槽位数 %d", c.Slots, c.Slots)
	}
	if c.HandshakeTimeout == 0 {
		c.HandshakeTimeout = 5 * time.Second
	}
	if c.HandshakeTimeout < 0 {
		return errs.Detail(ErrInvalidConfig, "handshake timeout %v | 握手超时 %v", c.HandshakeTimeout, c.HandshakeTimeout)
	}
	if c.SendTimeout == 0 {
		c.SendTimeout = 5 * time.Second
	}
	if c.RecvTimeout == 0 {
		c.RecvTimeout = 5 * time.Second
	}
	if c.MaxBatch == 0 {
		c.MaxBatch = 64
	}
	if c.MaxBatch < 1 {
		return errs.Detail(ErrInvalidConfig, "max batch %d | 最大批量 %d", c.MaxBatch, c.MaxBatch)
	}
	return nil
}

// Conn is a zero-copy reliable connected message endpoint. A Conn must not be
// used from two goroutines at once; create one Conn per worker. | Conn 是零拷贝
// 可靠连接消息端点。同一个 Conn 不得被两个协程同时使用；每个工作协程使用独立
// Conn。
type Conn struct {
	dev         *Device
	qp          *QP
	cq          *CQ
	tx          *Pool
	rx          *Pool
	tcp         net.Conn
	cfg         ConnConfig
	txBufs      []*Buffer
	rxBufs      []*Buffer
	ring        *rxRing
	events      []Completion
	scratch     []SendWR
	scratchRecv []RecvWR
	oneSend     [1]SendWR
	oneRecv     [1]RecvWR

	ownsDevice bool
	listener   *Listener

	localAddr  net.Addr
	remoteAddr net.Addr

	closed atomic.Bool
	err    atomic.Pointer[error]

	sendSeq     uint64
	signalEvery uint64
}

// Listener accepts RDMA message connections over a TCP control channel. |
// Listener 通过 TCP 控制通道接受 RDMA 消息连接。
type Listener struct {
	ln     net.Listener
	dev    *Device
	cfg    ConnConfig
	mu     sync.Mutex
	conns  map[*Conn]struct{}
	closed atomic.Bool
}

// Listen binds a TCP control listener and opens the RDMA device. The RDMA
// data path uses the addresses exchanged over this listener. | Listen 绑定 TCP
// 控制监听并打开 RDMA 设备。RDMA 数据路径使用经该监听交换的地址。
func Listen(addr string, cfg ConnConfig) (*Listener, error) {
	if err := cfg.normalize(); err != nil {
		return nil, err
	}
	dev, err := Open(cfg.Config)
	if err != nil {
		return nil, err
	}
	ln, err := net.Listen("tcp", addr)
	if err != nil {
		_ = dev.Close()
		return nil, errs.Wrap(err, ErrNetwork)
	}
	return &Listener{ln: ln, dev: dev, cfg: cfg, conns: make(map[*Conn]struct{})}, nil
}

// Addr returns the TCP control address. | Addr 返回 TCP 控制地址。
func (l *Listener) Addr() net.Addr {
	if l == nil || l.ln == nil {
		return nil
	}
	return l.ln.Addr()
}

// Accept waits for one peer and returns a connected RDMA endpoint. | Accept
// 等待一个对端并返回已连接的 RDMA 端点。
func (l *Listener) Accept() (*Conn, error) {
	if l == nil || l.closed.Load() {
		return nil, ErrClosed
	}
	tcp, err := l.ln.Accept()
	if err != nil {
		if l.closed.Load() {
			return nil, ErrClosed
		}
		return nil, errs.Wrap(err, ErrNetwork)
	}
	c, err := newConn(l.dev, tcp, l.cfg, false)
	if err != nil {
		_ = tcp.Close()
		return nil, err
	}
	c.listener = l
	l.mu.Lock()
	l.conns[c] = struct{}{}
	l.mu.Unlock()
	return c, nil
}

// Close closes the listener and every connection it accepted, then releases
// the device. | Close 关闭监听及其接受的所有连接，然后释放设备。
func (l *Listener) Close() error {
	if l == nil || !l.closed.CompareAndSwap(false, true) {
		return nil
	}
	_ = l.ln.Close()
	l.mu.Lock()
	conns := make([]*Conn, 0, len(l.conns))
	for c := range l.conns {
		conns = append(conns, c)
	}
	l.mu.Unlock()
	for _, c := range conns {
		_ = c.Close()
	}
	return l.dev.Close()
}

// remove drops a closed connection from the listener. | remove 从监听中移除
// 已关闭连接。
func (l *Listener) remove(c *Conn) {
	l.mu.Lock()
	delete(l.conns, c)
	l.mu.Unlock()
}

// Dial connects to a TCP control listener and establishes the RDMA queue pair.
// | Dial 连接 TCP 控制监听并建立 RDMA 队列对。
func Dial(addr string, cfg ConnConfig) (*Conn, error) {
	if err := cfg.normalize(); err != nil {
		return nil, err
	}
	dev, err := Open(cfg.Config)
	if err != nil {
		return nil, err
	}
	tcp, err := net.DialTimeout("tcp", addr, cfg.HandshakeTimeout)
	if err != nil {
		_ = dev.Close()
		return nil, errs.Wrap(err, ErrNetwork)
	}
	c, err := newConn(dev, tcp, cfg, true)
	if err != nil {
		_ = tcp.Close()
		_ = dev.Close()
		return nil, err
	}
	return c, nil
}

// newConn creates the completion queue, pools and queue pair, exchanges the
// handshake and connects both sides. | newConn 创建完成队列、内存池与队列对，
// 交换握手并连接两端。
func newConn(dev *Device, tcp net.Conn, cfg ConnConfig, ownsDevice bool) (c *Conn, err error) {
	slots := cfg.Slots
	if maxWR := int(dev.Attr().MaxQPWR); maxWR > 0 && slots > maxWR {
		slots = maxWR
	}
	if slots < 2 {
		slots = 2
	}
	cq, err := dev.NewCQ(slots*2 + 16)
	if err != nil {
		return nil, err
	}
	tx, err := dev.NewPool(PoolConfig{Slots: slots, SlotSize: cfg.SlotSize, HugePages: cfg.HugePages, Access: AccessDefault})
	if err != nil {
		_ = cq.Close()
		return nil, err
	}
	rx, err := dev.NewPool(PoolConfig{Slots: slots, SlotSize: cfg.SlotSize, HugePages: cfg.HugePages, Access: AccessDefault})
	if err != nil {
		_ = tx.Close()
		_ = cq.Close()
		return nil, err
	}
	qp, err := dev.NewQP(QPConfig{
		Type: QPTypeRC, SendCQ: cq, RecvCQ: cq,
		MaxSendWR: slots, MaxRecvWR: slots,
		MaxSendSGE: 1, MaxRecvSGE: 1,
		MaxInline: cfg.MaxInline, SignalAll: false,
	})
	if err != nil {
		_ = rx.Close()
		_ = tx.Close()
		_ = cq.Close()
		return nil, err
	}
	signalEvery := uint64(slots / 2)
	if signalEvery < 1 {
		signalEvery = 1
	}
	conn := &Conn{
		dev: dev, qp: qp, cq: cq, tx: tx, rx: rx, tcp: tcp, cfg: cfg,
		txBufs: tx.Buffers(), rxBufs: make([]*Buffer, slots),
		ring: newRxRing(slots), events: make([]Completion, 256),
		ownsDevice: ownsDevice, signalEvery: signalEvery,
		localAddr: tcp.LocalAddr(), remoteAddr: tcp.RemoteAddr(),
	}
	success := false
	defer func() {
		if !success {
			_ = conn.closeResources()
		}
	}()
	recvs := make([]RecvWR, slots)
	for i := 0; i < slots; i++ {
		b, ok := rx.Acquire()
		if !ok {
			return nil, errs.Detail(ErrNoBuffer, "acquire receive slot %d | 获取接收槽位 %d 失败", i, i)
		}
		conn.rxBufs[i] = b
		recvs[i] = RecvWR{WRID: uint64(i), Addr: b.Addr(), Length: uint32(b.Len()), LKey: b.LKey()}
	}
	psn := rand.Uint32() & 0xffffff
	if psn == 0 {
		psn = 1
	}
	local := qp.LocalInfo(psn)
	info := qpInfo{
		QPN: local.QPN, PSN: local.PSN, GID: local.GID, LID: local.LID, MTU: uint16(local.MTU),
		MaxInline: uint32(qp.MaxInline()), RKey: rx.MR().RKey(), Addr: uint64(rx.MR().Addr()),
		SlotSize: uint32(rx.SlotSize()), Slots: uint32(slots),
	}
	remote, err := exchangeQPInfo(tcp, info, cfg.HandshakeTimeout)
	if err != nil {
		return nil, err
	}
	remoteInfo := ConnectInfo{
		QPN: remote.QPN, PSN: remote.PSN, GID: remote.GID, LID: remote.LID,
		MTU: int(remote.MTU), QKey: 0x11111111,
	}
	if remoteInfo.MTU == 0 {
		remoteInfo.MTU = cfg.MTU
	}
	if err := qp.Connect(local, remoteInfo); err != nil {
		return nil, err
	}
	// Receive requests are only accepted once the queue pair leaves RESET. |
	// 队列对离开 RESET 后才接受接收请求。
	if n, perr := qp.PostRecv(recvs); perr != nil || n != slots {
		return nil, errs.Detail(ErrDevice, "post receive slots %d/%d: %v | 提交接收槽位 %d/%d 失败", n, slots, perr, n, slots)
	}
	success = true
	return conn, nil
}

// rxRing is a single-consumer ring of received buffers. | rxRing 是单消费者
// 接收缓冲区环。
type rxRing struct {
	bufs  []*Buffer
	lens  []int
	head  int
	tail  int
	count int
}

// newRxRing creates a ring with the given capacity. | newRxRing 创建指定容量
// 的环。
func newRxRing(size int) *rxRing {
	return &rxRing{bufs: make([]*Buffer, size), lens: make([]int, size)}
}

// push appends one received buffer. | push 追加一个接收缓冲区。
func (r *rxRing) push(b *Buffer, n int) bool {
	if r.count == len(r.bufs) {
		return false
	}
	r.bufs[r.tail] = b
	r.lens[r.tail] = n
	r.tail = (r.tail + 1) % len(r.bufs)
	r.count++
	return true
}

// pop removes the oldest received buffer. | pop 取出最旧的接收缓冲区。
func (r *rxRing) pop() (*Buffer, int, bool) {
	if r.count == 0 {
		return nil, 0, false
	}
	b, n := r.bufs[r.head], r.lens[r.head]
	r.bufs[r.head] = nil
	r.lens[r.head] = 0
	r.head = (r.head + 1) % len(r.bufs)
	r.count--
	return b, n, true
}

// Device returns the underlying device. | Device 返回底层设备。
func (c *Conn) Device() *Device { return c.dev }

// QP returns the underlying queue pair. | QP 返回底层队列对。
func (c *Conn) QP() *QP { return c.qp }

// CQ returns the underlying completion queue. | CQ 返回底层完成队列。
func (c *Conn) CQ() *CQ { return c.cq }

// LocalAddr returns the local TCP control address. | LocalAddr 返回本地 TCP
// 控制地址。
func (c *Conn) LocalAddr() net.Addr { return c.localAddr }

// RemoteAddr returns the remote TCP control address. | RemoteAddr 返回远端
// TCP 控制地址。
func (c *Conn) RemoteAddr() net.Addr { return c.remoteAddr }

// setErr records the first fatal error. | setErr 记录首个致命错误。
func (c *Conn) setErr(err error) {
	if err == nil {
		return
	}
	ptr := &err
	c.err.CompareAndSwap(nil, ptr)
}

// lastErr returns the recorded fatal error. | lastErr 返回记录的致命错误。
func (c *Conn) lastErr() error {
	if p := c.err.Load(); p != nil {
		return *p
	}
	return nil
}

// check reports whether the connection is usable. | check 报告连接是否可用。
func (c *Conn) check() error {
	if c == nil || c.closed.Load() {
		return ErrClosed
	}
	return c.lastErr()
}

// Process polls up to budget completions, releases completed send buffers and
// queues received buffers. | Process 轮询至多 budget 个完成事件，释放已完成的
// 发送缓冲区并将接收缓冲区入队。
func (c *Conn) Process(budget int) (int, error) {
	if err := c.check(); err != nil {
		return 0, err
	}
	if budget <= 0 {
		budget = c.cfg.MaxBatch
	}
	if budget > len(c.events) {
		budget = len(c.events)
	}
	n, err := c.cq.Poll(c.events[:budget])
	if err != nil {
		c.setErr(err)
		return 0, err
	}
	var firstErr error
	for i := 0; i < n; i++ {
		wc := c.events[i]
		if wc.IsError() {
			if firstErr == nil {
				firstErr = errs.Detail(ErrConnReset, "completion %s status %s | 完成 %s 状态 %s",
					wc.Opcode, wc.Status, wc.Opcode, wc.Status)
			}
			continue
		}
		if wc.WRID&txBit != 0 {
			idx := int(wc.WRID &^ txBit)
			if idx >= 0 && idx < len(c.txBufs) {
				c.tx.Release(c.txBufs[idx])
			}
			continue
		}
		idx := int(wc.WRID)
		if idx < 0 || idx >= len(c.rxBufs) {
			if firstErr == nil {
				firstErr = errs.Detail(ErrDevice, "invalid receive wrid %d | 接收 WRID %d 非法", idx, idx)
			}
			continue
		}
		if !c.ring.push(c.rxBufs[idx], int(wc.Bytes)) {
			if firstErr == nil {
				firstErr = errs.Detail(ErrQueueFull, "receive ring full | 接收环已满")
			}
		}
	}
	if firstErr != nil {
		c.setErr(firstErr)
	}
	return n, firstErr
}

// Alloc acquires one zero-copy send slot. The caller writes into Bytes and
// passes the buffer to SendBuffer. | Alloc 获取一个零拷贝发送槽位。调用方写入
// Bytes 后将缓冲区交给 SendBuffer。
func (c *Conn) Alloc(size int) (*Buffer, error) {
	if err := c.check(); err != nil {
		return nil, err
	}
	if size < 0 || size > c.rx.SlotSize() {
		return nil, errs.Detail(ErrMessageTooLarge, "size %d exceeds slot %d | 大小 %d 超过槽位 %d",
			size, c.rx.SlotSize(), size, c.rx.SlotSize())
	}
	deadline := c.deadline(c.cfg.SendTimeout)
	spins := 0
	for {
		if b, ok := c.tx.Acquire(); ok {
			return b, nil
		}
		if _, err := c.Process(c.cfg.MaxBatch); err != nil {
			return nil, err
		}
		spins++
		if spins&1023 == 0 && !deadline.IsZero() && time.Now().After(deadline) {
			return nil, ErrTimeout
		}
		if spins >= 4096 {
			spins = 0
			runtime.Gosched()
		}
	}
}

// deadline converts a timeout to an absolute deadline; zero means no limit. |
// deadline 将超时转换为绝对截止时间；零表示不限。
func (c *Conn) deadline(timeout time.Duration) time.Time {
	if timeout < 0 {
		return time.Time{}
	}
	if timeout == 0 {
		return time.Now()
	}
	return time.Now().Add(timeout)
}

// SendBuffer posts a zero-copy send of the first n bytes of b. The buffer is
// released by Process when the completion arrives. | SendBuffer 零拷贝发送 b
// 的前 n 字节。完成事件到达后由 Process 释放缓冲区。
func (c *Conn) SendBuffer(b *Buffer, n int) error {
	if err := c.check(); err != nil {
		return err
	}
	if b == nil || b.owner != c.tx {
		return errs.Detail(ErrInvalidConfig, "buffer does not belong to the send pool | 缓冲区不属于发送池")
	}
	if n < 0 || n > b.Len() {
		return errs.Detail(ErrMessageTooLarge, "length %d | 长度 %d", n, n)
	}
	inline := n <= c.qp.MaxInline()
	signaled := !inline || c.sendSeq%c.signalEvery == 0
	flags := SendFlags(0)
	if inline {
		// Inline payloads are copied into the work request, so the buffer can
		// be recycled as soon as ibv_post_send returns. Periodic signaling is
		// still required so the provider can reclaim send queue space. |
		// 内联负载会复制进工作请求，ibv_post_send 返回后即可回收缓冲区；仍需
		// 周期性请求完成事件，以便提供方回收发送队列空间。
		flags |= SendInline
	}
	if signaled {
		flags |= SendSignaled
	}
	c.oneSend[0] = SendWR{
		WRID: txBit | uint64(b.index), Addr: b.Addr(), Length: uint32(n),
		LKey: b.LKey(), Opcode: OpSend, Flags: flags,
	}
	deadline := c.deadline(c.cfg.SendTimeout)
	spins := 0
	for {
		posted, err := c.qp.PostSend(c.oneSend[:])
		if err == nil {
			c.sendSeq++
			if inline && !signaled {
				c.tx.Release(b)
			}
			return nil
		}
		if !errors.Is(err, ErrQueueFull) || posted != 0 {
			c.tx.Release(b)
			c.setErr(err)
			return err
		}
		if _, perr := c.Process(c.cfg.MaxBatch); perr != nil {
			c.tx.Release(b)
			return perr
		}
		spins++
		if spins&1023 == 0 && !deadline.IsZero() && time.Now().After(deadline) {
			c.tx.Release(b)
			return ErrTimeout
		}
		if spins >= 4096 {
			spins = 0
			runtime.Gosched()
		}
	}
}

// Send copies msg into a send slot and posts it. | Send 将 msg 复制到发送槽位
// 并提交。
func (c *Conn) Send(msg []byte) error {
	b, err := c.Alloc(len(msg))
	if err != nil {
		return err
	}
	copy(b.Bytes(), msg)
	if err := c.SendBuffer(b, len(msg)); err != nil {
		b.Release()
		return err
	}
	return nil
}

// SendBatchBuffers posts several zero-copy buffers in one doorbell. It returns
// the number posted. Buffers after the posted prefix are released on failure.
// | SendBatchBuffers 以一次门铃提交多个零拷贝缓冲区，返回提交数量。失败时
// 会释放未提交的后续缓冲区。
func (c *Conn) SendBatchBuffers(bufs []*Buffer, lens []int) (int, error) {
	if err := c.check(); err != nil {
		return 0, err
	}
	if len(bufs) == 0 {
		return 0, nil
	}
	if len(lens) != len(bufs) {
		return 0, errs.Detail(ErrInvalidConfig, "buffer/length count mismatch | 缓冲区与长度数量不一致")
	}
	for i, b := range bufs {
		if b == nil || b.owner != c.tx || lens[i] < 0 || lens[i] > b.Len() {
			return 0, errs.Detail(ErrInvalidConfig, "invalid buffer at %d | 第 %d 个缓冲区非法", i, i)
		}
	}
	deadline := c.deadline(c.cfg.SendTimeout)
	spins := 0
	total := 0
	for total < len(bufs) {
		remaining := len(bufs) - total
		if remaining > c.cfg.MaxBatch {
			remaining = c.cfg.MaxBatch
		}
		if cap(c.scratch) < remaining {
			c.scratch = make([]SendWR, remaining)
		}
		wrs := c.scratch[:remaining]
		for i := 0; i < remaining; i++ {
			b, n := bufs[total+i], lens[total+i]
			inline := n <= c.qp.MaxInline()
			signaled := !inline || (c.sendSeq+uint64(i))%c.signalEvery == 0
			flags := SendFlags(0)
			if inline {
				flags |= SendInline
			}
			if signaled {
				flags |= SendSignaled
			}
			wrs[i] = SendWR{
				WRID: txBit | uint64(b.index), Addr: b.Addr(), Length: uint32(n),
				LKey: b.LKey(), Opcode: OpSend, Flags: flags,
			}
		}
		oldTotal := total
		posted, err := c.qp.PostSend(wrs)
		total += posted
		c.sendSeq += uint64(posted)
		// Inline buffers posted without a completion request are already copied
		// into their work requests and can be recycled now; the periodically
		// signaled ones and non-inline buffers stay in flight until their
		// completions arrive. | 未请求完成事件的内联缓冲区已复制进工作请求，
		// 可立即回收；周期性信号的内联缓冲区与非内联缓冲区保持到完成事件到达。
		for i := oldTotal; i < total; i++ {
			w := &wrs[i-oldTotal]
			if w.Flags&SendInline != 0 && w.Flags&SendSignaled == 0 {
				c.tx.Release(bufs[i])
			}
		}
		if err == nil {
			return total, nil
		}
		if !errors.Is(err, ErrQueueFull) {
			for i := total; i < len(bufs); i++ {
				c.tx.Release(bufs[i])
			}
			c.setErr(err)
			return total, err
		}
		// A partial post is normal under backpressure: the prefix is in flight
		// and the suffix is retried after draining completions. | 背压下部分提交
		// 属正常：前缀已在途，排空完成事件后重试后缀。
		if _, perr := c.Process(c.cfg.MaxBatch); perr != nil {
			for i := total; i < len(bufs); i++ {
				c.tx.Release(bufs[i])
			}
			return total, perr
		}
		spins++
		if spins&1023 == 0 && !deadline.IsZero() && time.Now().After(deadline) {
			for i := total; i < len(bufs); i++ {
				c.tx.Release(bufs[i])
			}
			return total, ErrTimeout
		}
		if spins >= 4096 {
			spins = 0
			runtime.Gosched()
		}
	}
	return total, nil
}

// SendBatch copies and posts several messages in one doorbell. | SendBatch
// 以一次门铃复制并提交多条消息。
func (c *Conn) SendBatch(msgs [][]byte) (int, error) {
	if err := c.check(); err != nil {
		return 0, err
	}
	if len(msgs) == 0 {
		return 0, nil
	}
	limit := c.cfg.MaxBatch
	if len(msgs) < limit {
		limit = len(msgs)
	}
	bufs := make([]*Buffer, 0, limit)
	lens := make([]int, 0, limit)
	for i := 0; i < limit; i++ {
		b, err := c.Alloc(len(msgs[i]))
		if err != nil {
			for _, held := range bufs {
				held.Release()
			}
			return 0, err
		}
		copy(b.Bytes(), msgs[i])
		bufs = append(bufs, b)
		lens = append(lens, len(msgs[i]))
	}
	return c.SendBatchBuffers(bufs, lens)
}

// RecvBuffer waits for one received buffer and its length. The caller must
// call Release when done; zero-copy consumers use it directly. | RecvBuffer
// 等待一个接收缓冲区及其长度。调用方完成后必须调用 Release；零拷贝消费方直接
// 使用该缓冲区。
func (c *Conn) RecvBuffer() (*Buffer, int, error) {
	if err := c.check(); err != nil {
		return nil, 0, err
	}
	deadline := c.deadline(c.cfg.RecvTimeout)
	spins := 0
	for {
		if b, n, ok := c.ring.pop(); ok {
			return b, n, nil
		}
		if _, err := c.Process(c.cfg.MaxBatch); err != nil {
			return nil, 0, err
		}
		spins++
		if spins&1023 == 0 && !deadline.IsZero() && time.Now().After(deadline) {
			return nil, 0, ErrTimeout
		}
		if spins >= 4096 {
			spins = 0
			runtime.Gosched()
		}
	}
}

// Recv waits for one message and copies it out. | Recv 等待一条消息并复制出来。
func (c *Conn) Recv() ([]byte, error) {
	b, n, err := c.RecvBuffer()
	if err != nil {
		return nil, err
	}
	out := make([]byte, n)
	copy(out, b.Bytes()[:n])
	if rerr := c.Release(b); rerr != nil {
		return nil, rerr
	}
	return out, nil
}

// RecvInto copies one message into dst and releases the receive buffer. | RecvInto
// 将一条消息复制到 dst 并释放接收缓冲区。
func (c *Conn) RecvInto(dst []byte) (int, error) {
	b, n, err := c.RecvBuffer()
	if err != nil {
		return 0, err
	}
	copied := copy(dst, b.Bytes()[:n])
	if rerr := c.Release(b); rerr != nil {
		return copied, rerr
	}
	if copied < n {
		return copied, errs.Detail(ErrMessageTooLarge, "destination %d < message %d | 目标 %d 小于消息 %d", len(dst), n, len(dst), n)
	}
	return copied, nil
}

// RecvBuffers drains up to len(dst) received buffers. When the receive ring is
// empty it polls once and then returns what is available; it never waits for a
// full batch. | RecvBuffers 取出至多 len(dst) 个接收缓冲区。接收环为空时先轮询
// 一次，然后返回可用数量；不会等待凑满一批。
func (c *Conn) RecvBuffers(dst []*Buffer, lens []int) (int, error) {
	if err := c.check(); err != nil {
		return 0, err
	}
	if len(dst) == 0 {
		return 0, nil
	}
	if len(lens) < len(dst) {
		return 0, errs.Detail(ErrInvalidConfig, "length slice too short | 长度切片过短")
	}
	n := 0
	for n < len(dst) {
		b, l, ok := c.ring.pop()
		if !ok {
			break
		}
		dst[n], lens[n] = b, l
		n++
	}
	if n > 0 {
		return n, nil
	}
	if _, err := c.Process(c.cfg.MaxBatch); err != nil {
		return 0, err
	}
	for n < len(dst) {
		b, l, ok := c.ring.pop()
		if !ok {
			break
		}
		dst[n], lens[n] = b, l
		n++
	}
	return n, nil
}

// ReleaseBatch re-posts several received buffers with one doorbell. | ReleaseBatch
// 以一次门铃重新提交多个接收缓冲区。
func (c *Conn) ReleaseBatch(bufs []*Buffer) error {
	if err := c.check(); err != nil {
		return err
	}
	if len(bufs) == 0 {
		return nil
	}
	if cap(c.scratchRecv) < len(bufs) {
		c.scratchRecv = make([]RecvWR, len(bufs))
	}
	wrs := c.scratchRecv[:len(bufs)]
	for i, b := range bufs {
		if b == nil || b.owner != c.rx {
			return errs.Detail(ErrInvalidConfig, "buffer %d does not belong to the receive pool | 第 %d 个缓冲区不属于接收池", i, i)
		}
		wrs[i] = RecvWR{WRID: uint64(b.index), Addr: b.Addr(), Length: uint32(b.Len()), LKey: b.LKey()}
	}
	if _, err := c.qp.PostRecv(wrs); err != nil {
		c.setErr(err)
		return err
	}
	return nil
}

// Release re-posts a received buffer to the receive queue. | Release 将接收
// 缓冲区重新提交到接收队列。
func (c *Conn) Release(b *Buffer) error {
	if err := c.check(); err != nil {
		return err
	}
	if b == nil || b.owner != c.rx {
		return errs.Detail(ErrInvalidConfig, "buffer does not belong to the receive pool | 缓冲区不属于接收池")
	}
	c.oneRecv[0] = RecvWR{WRID: uint64(b.index), Addr: b.Addr(), Length: uint32(b.Len()), LKey: b.LKey()}
	if _, err := c.qp.PostRecv(c.oneRecv[:]); err != nil {
		c.setErr(err)
		return err
	}
	return nil
}

// Close tears down the connection and its resources. | Close 拆除连接及其资源。
func (c *Conn) Close() error {
	if c == nil || !c.closed.CompareAndSwap(false, true) {
		return nil
	}
	return c.closeResources()
}

// closeResources releases the queue pair, completion queue, pools, TCP control
// channel and, when owned, the device. | closeResources 释放队列对、完成队列、
// 内存池、TCP 控制通道，并在拥有时释放设备。
func (c *Conn) closeResources() error {
	if c == nil {
		return nil
	}
	if c.qp != nil {
		_ = c.qp.Close()
	}
	if c.cq != nil {
		_ = c.cq.Close()
	}
	if c.tx != nil {
		_ = c.tx.Close()
	}
	if c.rx != nil {
		_ = c.rx.Close()
	}
	if c.tcp != nil {
		_ = c.tcp.Close()
	}
	if c.listener != nil {
		c.listener.remove(c)
	}
	if c.ownsDevice && c.dev != nil {
		return c.dev.Close()
	}
	return nil
}
