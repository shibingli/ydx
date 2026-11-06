package rdma

import (
	"math"
	"math/rand/v2"
	"net"
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
	// Slots is the requested send and receive slots. Zero means 1024. The
	// provider's granted depth and the completion-queue limit may reduce the
	// effective receive slots, and the send window is also capped by the peer's
	// advertised receive slots. | Slots 是请求的发送与接收槽位数量；零表示 1024。
	// 提供方授予的深度与完成队列上限可能降低有效接收槽位；发送窗口还受对端公布的
	// 接收槽位数限制。
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
	// RC message lengths are at most 2^31-1; larger slots would silently wrap
	// in the ibv_sge length field. | RC 消息长度最大为 2^31-1；更大的槽位会在
	// ibv_sge 长度字段中静默回绕。
	if c.SlotSize > math.MaxInt32 {
		return errs.Detail(ErrInvalidConfig, "slot size %d exceeds message limit | 槽位大小 %d 超过消息上限", c.SlotSize, c.SlotSize)
	}
	if c.Slots > (math.MaxInt-16)/2 {
		return errs.Detail(ErrInvalidConfig, "slots %d overflow completion queue depth | 槽位数 %d 导致完成队列深度溢出", c.Slots, c.Slots)
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
// used from two goroutines at once; create one Conn per worker. Close is the
// exception: it may be called concurrently with an operation and waits for the
// operation to observe the closed state before releasing resources. | Conn 是
// 零拷贝可靠连接消息端点。同一个 Conn 不得被两个协程同时使用；每个工作协程使用
// 独立 Conn。Close 是例外：它可以与操作并发调用，并在释放资源前等待操作观察到
// 关闭状态。
type Conn struct {
	tcp net.Conn

	localAddr  net.Addr
	remoteAddr net.Addr

	closeErr error

	dev      *Device
	qp       *QP
	cq       *CQ
	tx       *Pool
	rx       *Pool
	ring     *rxRing
	listener *Listener

	err     atomic.Pointer[error]
	opsCond *sync.Cond

	closeDone chan struct{}

	txBufs      []*Buffer
	rxBufs      []*Buffer
	events      []Completion
	scratch     []SendWR
	scratchRecv []RecvWR
	cfg         ConnConfig
	oneSend     [1]SendWR
	oneRecv     [1]RecvWR

	ops atomic.Int64

	sendSeq     uint64
	signalEvery uint64
	opsMu       sync.Mutex

	closed atomic.Bool

	ownsDevice bool
}

// Listener accepts RDMA message connections over a TCP control channel. |
// Listener 通过 TCP 控制通道接受 RDMA 消息连接。
type Listener struct {
	ln        net.Listener
	closeErr  error
	dev       *Device
	conns     map[*Conn]struct{}
	closeDone chan struct{}
	cfg       ConnConfig
	acceptWG  sync.WaitGroup
	mu        sync.Mutex
	closed    atomic.Bool
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
	return &Listener{ln: ln, dev: dev, cfg: cfg, conns: make(map[*Conn]struct{}),
		closeDone: make(chan struct{})}, nil
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
	if l == nil {
		return nil, ErrClosed
	}
	l.mu.Lock()
	if l.ln == nil || l.closed.Load() {
		l.mu.Unlock()
		return nil, ErrClosed
	}
	l.acceptWG.Add(1)
	l.mu.Unlock()
	defer l.acceptWG.Done()
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
	l.mu.Lock()
	if l.closed.Load() {
		l.mu.Unlock()
		_ = c.Close()
		return nil, ErrClosed
	}
	c.listener = l
	l.conns[c] = struct{}{}
	l.mu.Unlock()
	return c, nil
}

// Close closes the listener and every connection it accepted, then releases
// the device. | Close 关闭监听及其接受的所有连接，然后释放设备。
func (l *Listener) Close() error {
	if l == nil {
		return nil
	}
	l.mu.Lock()
	if l.closed.Load() {
		done := l.closeDone
		l.mu.Unlock()
		if done != nil {
			<-done
		}
		return l.closeErr
	}
	l.closed.Store(true)
	if l.ln != nil {
		_ = l.ln.Close()
	}
	l.mu.Unlock()
	// In-flight Accepts may still be creating a Conn on l.dev. Wait for them
	// before snapshotting connections and destroying the device. | 进行中的 Accept
	// 可能仍在 l.dev 上创建 Conn；在快照连接并销毁设备前等待它们结束。
	l.acceptWG.Wait()
	l.mu.Lock()
	conns := make([]*Conn, 0, len(l.conns))
	for c := range l.conns {
		conns = append(conns, c)
	}
	l.mu.Unlock()
	var first error
	for _, c := range conns {
		if err := c.Close(); err != nil && first == nil {
			first = err
		}
	}
	if l.dev != nil {
		if err := l.dev.Close(); err != nil && first == nil {
			first = err
		}
	}
	l.mu.Lock()
	l.closeErr = first
	if l.closeDone != nil {
		close(l.closeDone)
	}
	l.mu.Unlock()
	return first
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
	// NewCQ may clamp to the device's MaxCQE. Keep the pools and both queue
	// directions small enough that receive WRs plus in-flight sends cannot
	// overflow the CQ, which would drop completions and stall the connection.
	// | NewCQ 可能按设备 MaxCQE 截断。让内存池与收发队列足够小，确保接收 WR 加上
	// 在途发送不会溢出 CQ，否则完成事件会丢失并卡死连接。
	if depth := cq.Depth(); depth > 0 {
		if maxSlots := (depth - 16) / 2; slots > maxSlots {
			slots = maxSlots
		}
	}
	if slots < 2 {
		_ = cq.Close()
		return nil, errs.Detail(ErrInvalidConfig, "completion queue too small | 完成队列过小")
	}
	rx, err := dev.NewPool(PoolConfig{Slots: slots, SlotSize: cfg.SlotSize, HugePages: cfg.HugePages, Access: AccessLocalWrite})
	if err != nil {
		_ = cq.Close()
		return nil, err
	}
	qp, err := dev.NewQP(QPConfig{
		Type: QPTypeRC, SendCQ: cq, RecvCQ: cq,
		MaxSendWR: slots, MaxRecvWR: slots,
		MaxSendSGE: 1, MaxRecvSGE: 1,
		MaxInline: cfg.MaxInline, SignalAll: false, Access: AccessLocalWrite,
	})
	if err != nil {
		_ = rx.Close()
		_ = cq.Close()
		return nil, err
	}
	recvSlots := slots
	if granted := qp.RecvQueueDepth(); granted > 0 && granted < recvSlots {
		recvSlots = granted
	}
	conn := &Conn{
		dev: dev, qp: qp, cq: cq, rx: rx, tcp: tcp, cfg: cfg,
		rxBufs: make([]*Buffer, recvSlots),
		ring:   newRxRing(recvSlots), events: make([]Completion, 256),
		ownsDevice: ownsDevice,
		localAddr:  tcp.LocalAddr(), remoteAddr: tcp.RemoteAddr(),
	}
	conn.opsCond = sync.NewCond(&conn.opsMu)
	conn.closeDone = make(chan struct{})
	success := false
	defer func() {
		if !success {
			_ = conn.closeResources()
		}
	}()
	if recvSlots < 2 {
		return nil, errs.Detail(ErrInvalidConfig,
			"provider granted %d receive slots, need at least 2 | 提供方仅授予 %d 个接收槽位，至少需要 2 个",
			recvSlots, recvSlots)
	}
	recvs := make([]RecvWR, recvSlots)
	for i := 0; i < recvSlots; i++ {
		b, ok := rx.Acquire()
		if !ok {
			return nil, errs.Detail(ErrNoBuffer, "acquire receive slot %d | 获取接收槽位 %d 失败", i, i)
		}
		conn.rxBufs[i] = b
		b.rx = true
		b.posted.Store(true)
		recvs[i] = RecvWR{WRID: uint64(i), Addr: b.Addr(), Length: uint32(b.Len()), LKey: b.LKey()}
	}
	psn := cfg.PSN & 0xffffff
	if psn == 0 {
		psn = rand.Uint32() & 0xffffff
		if psn == 0 {
			psn = 1
		}
	}
	local := qp.LocalInfo(psn)
	info := qpInfo{
		QPN: local.QPN, PSN: local.PSN, GID: local.GID, LID: local.LID, MTU: uint16(local.MTU),
		MaxInline: uint32(qp.MaxInline()),
		// The Conn data path is SEND/RECV only; its pools are registered with
		// local-write access and no remote key is advertised. | Conn 数据路径只
		// 使用 SEND/RECV；其内存池仅注册本地写权限，不公布远端密钥。
		SlotSize: uint32(rx.SlotSize()), Slots: uint32(recvSlots),
	}
	remote, err := exchangeQPInfo(tcp, info, cfg.HandshakeTimeout)
	if err != nil {
		return nil, err
	}
	// SEND cannot exceed the receiver's posted slot length. A mismatched slot
	// size would make every large message fail at the remote end after the
	// handshake, so reject it before connecting. | SEND 不能超过接收方已提交的槽位
	// 长度。槽位大小不一致会让每条大消息在握手后于远端失败，因此应在连接前拒绝。
	if remote.SlotSize != uint32(conn.rx.SlotSize()) {
		return nil, errs.Detail(ErrInvalidConfig,
			"remote slot size %d differs from local %d | 远端槽位大小 %d 与本地 %d 不一致",
			remote.SlotSize, conn.rx.SlotSize(), remote.SlotSize, conn.rx.SlotSize())
	}
	if remote.Slots < 2 {
		return nil, errs.Detail(ErrHandshake, "remote slots %d | 远端槽位数 %d", remote.Slots, remote.Slots)
	}
	if remote.MTU > 4096 {
		return nil, errs.Detail(ErrHandshake, "remote MTU %d | 远端 MTU %d", remote.MTU, remote.MTU)
	}
	// Bound outstanding SENDs by the peer's posted receive queue. Without this,
	// an asymmetric configuration lets the sender outrun the receiver and turns
	// every excess message into RNR retries or a fatal RNR-exhaustion error.
	// | 按对端已提交的接收队列限制在途 SEND。否则不对称配置会让发送方超过接收方，
	// 把每条多余消息变成 RNR 重试，甚至触发 RNR 耗尽错误。
	txSlots := slots
	if int(remote.Slots) < txSlots {
		txSlots = int(remote.Slots)
	}
	if granted := qp.SendQueueDepth(); granted > 0 && granted < txSlots {
		txSlots = granted
	}
	tx, err := dev.NewPool(PoolConfig{Slots: txSlots, SlotSize: cfg.SlotSize, HugePages: cfg.HugePages, Access: AccessLocalWrite})
	if err != nil {
		return nil, err
	}
	conn.tx = tx
	conn.txBufs = tx.Buffers()
	conn.signalEvery = uint64(txSlots / 2)
	if conn.signalEvery < 1 {
		conn.signalEvery = 1
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
	if n, perr := qp.PostRecv(recvs); perr != nil || n != recvSlots {
		return nil, errs.Detail(ErrDevice, "post receive slots %d/%d: %v | 提交接收槽位 %d/%d 失败",
			n, recvSlots, perr, n, recvSlots)
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
	if c == nil || c.closed.Load() || c.qp == nil || c.cq == nil || c.tx == nil || c.rx == nil || c.ring == nil {
		return ErrClosed
	}
	return c.lastErr()
}

// enter registers one public operation so Close cannot free resources while it
// runs. | enter 登记一个公共操作，避免 Close 在操作运行期间释放资源。
func (c *Conn) enter() bool {
	if c == nil || c.closed.Load() {
		return false
	}
	c.ops.Add(1)
	if c.closed.Load() {
		c.leave()
		return false
	}
	return true
}

// leave completes one public operation and wakes a waiting Close. | leave 结束
// 一个公共操作并唤醒等待中的 Close。
func (c *Conn) leave() {
	if c.ops.Add(-1) == 0 && c.opsCond != nil {
		c.opsMu.Lock()
		c.opsCond.Broadcast()
		c.opsMu.Unlock()
	}
}

// Close tears down the connection and its resources. It waits for in-flight
// operations, but buffers already returned to the caller become invalid; the
// caller must finish consuming them and call Release before Close. | Close 拆除
// 连接及其资源。它会等待在途操作，但已返回给调用方的缓冲区会失效；调用方必须在
// Close 前消费完毕并调用 Release。
func (c *Conn) Close() error {
	if c == nil {
		return nil
	}
	if !c.closed.CompareAndSwap(false, true) {
		// A concurrent second Close (for example Listener.Close racing the
		// owning goroutine) must wait for the first one to finish before the
		// device can be destroyed. | 并发的第二次 Close（例如 Listener.Close
		// 与属主协程竞争）必须等待第一次完成，之后设备才能销毁。
		if c.closeDone != nil {
			<-c.closeDone
		}
		return c.closeErr
	}
	// Wait for operations that entered before the flag was set. Their loops
	// observe closed and return quickly; destroying QP/CQ/MRs underneath them
	// would be a use-after-free. | 等待在标志置位前进入的操作结束。它们的循环会
	// 观察到 closed 并快速返回；在其下方销毁 QP/CQ/MR 会造成释放后使用。
	c.opsMu.Lock()
	for c.ops.Load() != 0 && c.opsCond != nil {
		c.opsCond.Wait()
	}
	c.opsMu.Unlock()
	c.closeErr = c.closeResources()
	if c.closeDone != nil {
		close(c.closeDone)
	}
	return c.closeErr
}

// closeResources releases the queue pair, completion queue, pools, TCP control
// channel and, when owned, the device. | closeResources 释放队列对、完成队列、
// 内存池、TCP 控制通道，并在拥有时释放设备。
func (c *Conn) closeResources() error {
	if c == nil {
		return nil
	}
	var first error
	record := func(err error) {
		if err != nil && first == nil {
			first = err
		}
	}
	if c.qp != nil {
		record(c.qp.Close())
	}
	if c.cq != nil {
		record(c.cq.Close())
	}
	if c.tx != nil {
		record(c.tx.Close())
	}
	if c.rx != nil {
		record(c.rx.Close())
	}
	if c.tcp != nil {
		record(c.tcp.Close())
	}
	if c.listener != nil {
		c.listener.remove(c)
	}
	if c.ownsDevice && c.dev != nil {
		record(c.dev.Close())
	}
	return first
}
