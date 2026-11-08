package radius

import (
	"context"
	"crypto/tls"
	"encoding/binary"
	"io"
	"net"
	"sync"
	"time"

	"github.com/shibingli/ydx/errs"
)

// EAP TLS framing flag values shared by EAP-TLS, EAP-TTLS and PEAP version 0. | EAP-TLS、EAP-TTLS
// 与 PEAP 版本 0 共用的 EAP TLS 分帧标志值。
const (
	// EAPTLSFlagLength marks a four-octet total TLS message length. | EAPTLSFlagLength 标记四字节 TLS
	// 消息总长度。
	EAPTLSFlagLength byte = 0x80
	// EAPTLSFlagMore marks a non-final fragment. | EAPTLSFlagMore 标记非最终分片。
	EAPTLSFlagMore byte = 0x40
	// EAPTLSFlagStart marks the first server Request of a TLS tunnel. | EAPTLSFlagStart 标记 TLS
	// 隧道的首个服务器 Request。
	EAPTLSFlagStart byte = 0x20
)

// maxEAPTLSMessageLength bounds one reassembled inbound TLS message. It matches the largest EAP
// packet so an unauthenticated peer cannot announce a multi-gigabyte fragment length and force an
// unbounded allocation. | maxEAPTLSMessageLength 限制单个入站重组 TLS 消息，与最大 EAP 报文一致，
// 避免未认证对端声明数 GB 的分片长度并强制无界分配。
const maxEAPTLSMessageLength = MaxEAPPacketLength

// eapTLSEngine drives a crypto/tls server handshake and application data over an in-memory net.Conn
// whose reads are fed from EAP packets and whose writes become EAP packet data. | eapTLSEngine 在内存
// net.Conn 上驱动 crypto/tls 服务端握手与应用数据，其读取由 EAP 报文喂入，写入转为 EAP 报文数据。
type eapTLSEngine struct {
	conn      *eapTLSConn
	tlsConn   *tls.Conn
	done      chan struct{}
	appCh     chan []byte
	closed    chan struct{}
	closeOnce sync.Once

	mu          sync.Mutex
	err         error
	established bool
	appErr      error
}

// newEAPTLSEngine creates a TLS server engine and starts its handshake goroutine. The handshake blocks
// until inbound TLS bytes are supplied by processHandshake. | newEAPTLSEngine 创建 TLS 服务器引擎并
// 启动握手协程。握手会阻塞，直到 processHandshake 提供入站 TLS 字节。
func newEAPTLSEngine(config *tls.Config) (*eapTLSEngine, error) {
	if config == nil {
		return nil, errs.Detail(ErrInvalidConfig, "EAP TLS configuration is required")
	}
	conn := newEAPTLSEngineConn()
	engine := &eapTLSEngine{
		conn:    conn,
		tlsConn: tls.Server(conn, config.Clone()),
		done:    make(chan struct{}),
		appCh:   make(chan []byte, 16),
		closed:  make(chan struct{}),
	}
	go engine.runHandshake()
	return engine, nil
}

// runHandshake performs the TLS handshake once and publishes its outcome. | runHandshake 执行一次 TLS
// 握手并发布结果。
func (e *eapTLSEngine) runHandshake() {
	err := e.tlsConn.Handshake()
	e.mu.Lock()
	e.err = err
	e.established = err == nil
	e.mu.Unlock()
	close(e.done)
	if err == nil {
		go e.runApplicationRead()
	}
}

// runApplicationRead decrypts application data after the handshake and delivers it on appCh. |
// runApplicationRead 在握手后解密应用数据并通过 appCh 交付。
func (e *eapTLSEngine) runApplicationRead() {
	defer close(e.appCh)
	buffer := make([]byte, 32*1024)
	for {
		n, err := e.tlsConn.Read(buffer)
		if n > 0 {
			data := append([]byte(nil), buffer[:n]...)
			select {
			case e.appCh <- data:
			case <-e.closed:
				return
			}
		}
		if err != nil {
			e.mu.Lock()
			e.appErr = err
			e.mu.Unlock()
			_ = e.conn.Close()
			return
		}
	}
}

// status returns the handshake completion state, its error and whether the handshake succeeded. |
// status 返回握手完成状态、错误以及握手是否成功。
func (e *eapTLSEngine) status() (done bool, err error, established bool) {
	select {
	case <-e.done:
		e.mu.Lock()
		defer e.mu.Unlock()
		return true, e.err, e.established
	default:
		return false, nil, false
	}
}

// processHandshake feeds one inbound TLS flight, waits for the handshake goroutine to consume it and
// returns the outbound TLS flight, which may be empty. | processHandshake 喂入一个入站 TLS 飞行，等待
// 握手协程处理，并返回出站 TLS 飞行，可能为空。
func (e *eapTLSEngine) processHandshake(ctx context.Context, data []byte) ([]byte, error) {
	if err := e.conn.feed(data); err != nil {
		return nil, err
	}
	if err := e.conn.waitSettled(ctx, e.done); err != nil {
		return nil, err
	}
	return e.conn.takeOutput(), nil
}

// feedApplication supplies tunneled input after the handshake, waits for the application reader to
// consume it and returns any TLS output, such as an alert, produced while processing it. |
// feedApplication 在握手后提供隧道输入，等待应用读取协程消费，并返回处理期间产生的 TLS 输出（如告警）。
func (e *eapTLSEngine) feedApplication(ctx context.Context, data []byte) ([]byte, error) {
	if err := ctxErr(ctx); err != nil {
		return nil, err
	}
	if err := e.conn.feed(data); err != nil {
		return nil, err
	}
	if err := e.conn.waitReading(ctx); err != nil {
		return nil, err
	}
	return e.conn.takeOutput(), nil
}

// readApplication waits for one decrypted application message. | readApplication 等待一条已解密应用消息。
func (e *eapTLSEngine) readApplication(ctx context.Context) ([]byte, error) {
	select {
	case data, ok := <-e.appCh:
		if ok {
			return data, nil
		}
		e.mu.Lock()
		err := e.appErr
		e.mu.Unlock()
		if err == nil {
			err = io.EOF
		}
		return nil, errs.Wrap(err, ErrEAPState)
	case <-ctx.Done():
		return nil, contextError(ctx.Err())
	}
}

// writeApplication encrypts application data and returns the resulting TLS flight. | writeApplication
// 加密应用数据并返回生成的 TLS 飞行。
func (e *eapTLSEngine) writeApplication(ctx context.Context, data []byte) ([]byte, error) {
	done, _, established := e.status()
	if !done || !established {
		return nil, errs.Detail(ErrEAPState, "TLS tunnel is not established")
	}
	if err := ctxErr(ctx); err != nil {
		return nil, err
	}
	if _, err := e.tlsConn.Write(data); err != nil {
		return nil, errs.Wrap(err, ErrEAPState)
	}
	return e.conn.takeOutput(), nil
}

// connectionState returns the completed TLS connection state, or false before completion. |
// connectionState 返回已完成的 TLS 连接状态，完成前返回 false。
func (e *eapTLSEngine) connectionState() (tls.ConnectionState, bool) {
	done, err, established := e.status()
	if !done || err != nil || !established {
		return tls.ConnectionState{}, false
	}
	return e.tlsConn.ConnectionState(), true
}

// close tears down the TLS engine and unblocks its goroutines. | close 拆除 TLS 引擎并解除协程阻塞。
func (e *eapTLSEngine) close() {
	if e == nil {
		return
	}
	e.closeOnce.Do(func() {
		close(e.closed)
	})
	_ = e.tlsConn.Close()
	_ = e.conn.Close()
}

// eapTLSConn is an in-memory net.Conn bridging EAP packets and a crypto/tls server. Reads block until
// feed supplies bytes; writes append to an outbound buffer collected by the EAP layer. | eapTLSConn 是
// 在 EAP 报文与 crypto/tls 服务端之间架桥的内存 net.Conn。读取阻塞直到 feed 提供字节；写入追加到由
// EAP 层收集的出站缓冲区。
type eapTLSConn struct {
	cond   *sync.Cond
	events chan struct{}
	input  []byte
	output []byte
	local  net.Addr
	remote net.Addr

	readDeadline  time.Time
	writeDeadline time.Time

	mu      sync.Mutex
	reading bool
	closed  bool
}

// newEAPTLSEngineConn creates an unconnected in-memory connection. | newEAPTLSEngineConn 创建未连接的
// 内存连接。
func newEAPTLSEngineConn() *eapTLSConn {
	conn := &eapTLSConn{
		events: make(chan struct{}, 1),
		local:  eapTLSAddr("eap-tls-local"),
		remote: eapTLSAddr("eap-tls-peer"),
	}
	conn.cond = sync.NewCond(&conn.mu)
	return conn
}

// Read implements net.Conn. | Read 实现 net.Conn。
func (c *eapTLSConn) Read(p []byte) (int, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	for len(c.input) == 0 && !c.closed {
		c.reading = true
		c.signalLocked()
		c.cond.Wait()
	}
	c.reading = false
	c.signalLocked()
	if len(c.input) == 0 {
		return 0, io.EOF
	}
	n := copy(p, c.input)
	c.input = c.input[n:]
	if len(c.input) == 0 {
		c.input = nil
	}
	return n, nil
}

// Write implements net.Conn. | Write 实现 net.Conn。
func (c *eapTLSConn) Write(p []byte) (int, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.closed {
		return 0, io.ErrClosedPipe
	}
	c.output = append(c.output, p...)
	c.signalLocked()
	return len(p), nil
}

// Close implements net.Conn. | Close 实现 net.Conn。
func (c *eapTLSConn) Close() error {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.closed {
		return nil
	}
	c.closed = true
	c.cond.Broadcast()
	c.signalLocked()
	return nil
}

// LocalAddr implements net.Conn. | LocalAddr 实现 net.Conn。
func (c *eapTLSConn) LocalAddr() net.Addr { return c.local }

// RemoteAddr implements net.Conn. | RemoteAddr 实现 net.Conn。
func (c *eapTLSConn) RemoteAddr() net.Addr { return c.remote }

// SetDeadline implements net.Conn. Deadlines are not enforced because Close and context cancellation
// unblock every operation. | SetDeadline 实现 net.Conn。期限不由本连接强制执行，因为 Close 与上下文
// 取消会解除所有操作阻塞。
func (c *eapTLSConn) SetDeadline(t time.Time) error {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.readDeadline = t
	c.writeDeadline = t
	return nil
}

// SetReadDeadline implements net.Conn. | SetReadDeadline 实现 net.Conn。
func (c *eapTLSConn) SetReadDeadline(t time.Time) error {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.readDeadline = t
	return nil
}

// SetWriteDeadline implements net.Conn. | SetWriteDeadline 实现 net.Conn。
func (c *eapTLSConn) SetWriteDeadline(t time.Time) error {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.writeDeadline = t
	return nil
}

// feed appends inbound TLS bytes and wakes a blocked Read. | feed 追加入站 TLS 字节并唤醒阻塞的 Read。
func (c *eapTLSConn) feed(data []byte) error {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.closed {
		return errs.Detail(ErrEAPState, "TLS bridge is closed")
	}
	c.input = append(c.input, data...)
	// The reader is no longer settled: it has input to consume before it can block again. | 读取者不再
	// 处于稳定状态：它还有输入需要消费才能再次阻塞。
	c.reading = false
	c.cond.Broadcast()
	c.signalLocked()
	return nil
}

// takeOutput removes and returns every outbound TLS byte. | takeOutput 移除并返回全部出站 TLS 字节。
func (c *eapTLSConn) takeOutput() []byte {
	c.mu.Lock()
	defer c.mu.Unlock()
	if len(c.output) == 0 {
		return nil
	}
	out := append([]byte(nil), c.output...)
	c.output = nil
	c.signalLocked()
	return out
}

// waitSettled waits until the handshake goroutine is blocked reading again, or the handshake has
// completed. | waitSettled 等待握手协程再次阻塞于读取，或握手已完成。
//
// Output produced before the reader blocked is intentionally not part of the predicate: the
// handshake writes its flight and then waits for the next inbound flight, so a non-empty output
// buffer is the normal settled state. | 读取者阻塞前产生的输出不是判定条件的一部分：握手写入其飞行
// 后会等待下一个入站飞行，因此非空输出缓冲区正是正常的稳定状态。
func (c *eapTLSConn) waitSettled(ctx context.Context, done <-chan struct{}) error {
	for {
		c.mu.Lock()
		settled := c.closed || c.reading
		c.mu.Unlock()
		select {
		case <-done:
			return nil
		default:
		}
		if settled {
			return nil
		}
		select {
		case <-c.events:
		case <-done:
			return nil
		case <-ctx.Done():
			return contextError(ctx.Err())
		}
	}
}

// waitReading waits until the TLS reader is blocked waiting for input again. It is used after the
// handshake for tunneled application data. | waitReading 等待 TLS 读取者再次阻塞于等待输入。它在握手
// 完成后用于隧道应用数据。
func (c *eapTLSConn) waitReading(ctx context.Context) error {
	for {
		c.mu.Lock()
		settled := c.closed || c.reading
		c.mu.Unlock()
		if settled {
			return nil
		}
		select {
		case <-c.events:
		case <-ctx.Done():
			return contextError(ctx.Err())
		}
	}
}

// signalLocked wakes waitSettled. The caller must hold c.mu. | signalLocked 唤醒 waitSettled。调用方
// 必须持有 c.mu。
func (c *eapTLSConn) signalLocked() {
	select {
	case c.events <- struct{}{}:
	default:
	}
}

// eapTLSAddr is a synthetic net.Addr for the in-memory TLS bridge. | eapTLSAddr 是内存 TLS 桥接使用的
// 合成 net.Addr。
type eapTLSAddr string

// Network implements net.Addr. | Network 实现 net.Addr。
func (a eapTLSAddr) Network() string { return "eap" }

// String implements net.Addr. | String 实现 net.Addr。
func (a eapTLSAddr) String() string { return string(a) }

// eapTLSFragment describes one outbound EAP TLS method-data value. | eapTLSFragment 描述一个出站 EAP
// TLS 方法数据值。
type eapTLSFragment struct {
	payload []byte
	total   int
	flags   byte
}

// fragmentTLSData splits one TLS message into EAP-TLS, EAP-TTLS or PEAP fragments. | fragmentTLSData
// 将一条 TLS 消息拆分为 EAP-TLS、EAP-TTLS 或 PEAP 分片。
//
// maxData is the maximum number of TLS bytes per fragment. The first fragment carries the total
// length when the message is fragmented; start marks the first fragment as a tunnel Start. | maxData
// 是每片 TLS 字节上限。消息被分片时首片携带总长度；start 将首片标记为隧道 Start。
func fragmentTLSData(data []byte, maxData int, start bool) ([]eapTLSFragment, error) {
	if maxData < 1 {
		return nil, errs.Detail(ErrInvalidConfig, "EAP TLS fragment size %d must be positive", maxData)
	}
	if len(data) > MaxEAPPacketLength-EAPHeaderLength-1-5 {
		return nil, errs.Detail(ErrInvalidRequest, "TLS message length %d exceeds the EAP limit", len(data))
	}
	if len(data) == 0 {
		if start {
			return []eapTLSFragment{{flags: EAPTLSFlagStart}}, nil
		}
		return nil, nil
	}
	fragmented := len(data) > maxData
	var out []eapTLSFragment
	for offset := 0; offset < len(data); offset += maxData {
		end := offset + maxData
		if end > len(data) {
			end = len(data)
		}
		flags := byte(0)
		if offset == 0 {
			if start {
				flags |= EAPTLSFlagStart
			}
			if fragmented {
				flags |= EAPTLSFlagLength
			}
		}
		if end < len(data) {
			flags |= EAPTLSFlagMore
		}
		out = append(out, eapTLSFragment{
			flags:   flags,
			total:   len(data),
			payload: append([]byte(nil), data[offset:end]...),
		})
	}
	return out, nil
}

// bytes encodes the fragment as EAP method data. | bytes 将分片编码为 EAP 方法数据。
func (f eapTLSFragment) bytes() []byte {
	size := 1 + len(f.payload)
	if f.flags&EAPTLSFlagLength != 0 {
		size += 4
	}
	out := make([]byte, size)
	out[0] = f.flags
	offset := 1
	if f.flags&EAPTLSFlagLength != 0 {
		binary.BigEndian.PutUint32(out[1:5], uint32(f.total))
		offset = 5
	}
	copy(out[offset:], f.payload)
	return out
}

// parseTLSPayload parses EAP method data that carries TLS record bytes. It returns flags, the total
// length when announced (zero otherwise) and the payload. Start is only valid when allowStart. |
// parseTLSPayload 解析携带 TLS 记录字节的 EAP 方法数据，返回 flags、声明时的总长度（否则为零）与
// 负载。Start 仅在 allowStart 时合法。
func parseTLSPayload(data []byte, allowStart bool) (flags byte, total int, payload []byte, err error) {
	if len(data) < 1 {
		return 0, 0, nil, errs.Detail(ErrInvalidRequest, "EAP TLS data is empty")
	}
	flags = data[0]
	if flags&EAPTLSFlagStart != 0 && !allowStart {
		return 0, 0, nil, errs.Detail(ErrInvalidRequest, "EAP TLS response must not set the Start bit")
	}
	offset := 1
	if flags&EAPTLSFlagLength != 0 {
		if len(data) < 5 {
			return 0, 0, nil, errs.Detail(ErrInvalidRequest, "EAP TLS length flag needs four octets")
		}
		total = int(binary.BigEndian.Uint32(data[1:5]))
		offset = 5
		if total > maxEAPTLSMessageLength {
			return 0, 0, nil, errs.Detail(ErrInvalidRequest, "EAP TLS total length %d exceeds %d", total, maxEAPTLSMessageLength)
		}
		if total < len(data)-offset {
			return 0, 0, nil, errs.Detail(ErrInvalidRequest, "EAP TLS total length %d is below fragment length", total)
		}
	}
	payload = append([]byte(nil), data[offset:]...)
	return flags, total, payload, nil
}

// eapTLSReassembler accumulates inbound TLS fragments from peer responses. | eapTLSReassembler 累积来自
// 对端响应的入站 TLS 分片。
type eapTLSReassembler struct {
	buffer []byte
	total  int
	active bool
}

// add consumes one fragment and reports whether a complete message is available. | add 消费一个分片并
// 报告是否已获得完整消息。
func (r *eapTLSReassembler) add(flags byte, total int, payload []byte) (bool, []byte, error) {
	if flags&EAPTLSFlagLength != 0 {
		if total <= 0 || total > maxEAPTLSMessageLength {
			return false, nil, errs.Detail(ErrInvalidRequest, "EAP TLS total length %d is invalid", total)
		}
		if r.active {
			return false, nil, errs.Detail(ErrInvalidRequest, "EAP TLS restarted fragmentation before completion")
		}
		r.active = true
		r.total = total
		r.buffer = make([]byte, 0, total)
	} else if !r.active {
		if flags&EAPTLSFlagMore != 0 {
			return false, nil, errs.Detail(ErrInvalidRequest, "EAP TLS first fragment lacks a total length")
		}
		return true, append([]byte(nil), payload...), nil
	}
	r.buffer = append(r.buffer, payload...)
	if len(r.buffer) > r.total {
		return false, nil, errs.Detail(ErrInvalidRequest, "EAP TLS fragments exceed announced length %d", r.total)
	}
	if flags&EAPTLSFlagMore != 0 {
		return false, nil, nil
	}
	if len(r.buffer) != r.total {
		return false, nil, errs.Detail(ErrInvalidRequest, "EAP TLS fragments total %d want %d", len(r.buffer), r.total)
	}
	message := append([]byte(nil), r.buffer...)
	r.buffer = nil
	r.total = 0
	r.active = false
	return true, message, nil
}

// pending reports whether a fragmented message is incomplete. | pending 报告分片消息是否尚未完成。
func (r *eapTLSReassembler) pending() bool {
	return r != nil && r.active
}
