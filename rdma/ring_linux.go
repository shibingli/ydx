//go:build linux && rdma && (amd64 || arm64)

package rdma

import (
	"context"
	"crypto/rand"
	"encoding/binary"
	"net"
	"sync"
	"sync/atomic"
	"time"
)

// Ring is one end of a one-sided RDMA ring. The receiver owns a registered
// ring MR and exposes its RKey/address; the sender issues WRITE_WITH_IMM.
// Ring 是单边 RDMA Ring 的一端：接收端拥有预注册 Ring MR 并公布 RKey/地址，
// 发送端执行 WRITE_WITH_IMM。
type Ring struct {
	cfg    RingConfig
	role   string
	conn   net.Conn
	dev    *Device
	sendCQ *CQ
	recvCQ *CQ
	qp     *QP
	mr     *MR
	info   RingInfo
	remote RingInfo

	writeMu     sync.Mutex
	mu          sync.Mutex
	outstanding map[int]uint32
	ackCh       chan uint32
	seq         atomic.Uint32
	closed      atomic.Bool
}

// RingListener accepts one-sided ring connections. | RingListener 接受单边 Ring 连接。
type RingListener struct {
	cfg  RingConfig
	ln   net.Listener
	res  *ringResources
	used bool
}

type ringResources struct {
	dev *Device
	cq  *CQ
	qp  *QP
	mr  *MR
}

func newRingResources() (*ringResources, error) {
	dev, err := Open(DefaultConfig())
	if err != nil {
		return nil, err
	}
	cq, err := dev.NewCQ(64)
	if err != nil {
		_ = dev.Close()
		return nil, err
	}
	qp, err := dev.NewQP(QPConfig{Type: QPTypeRC, SendCQ: cq, RecvCQ: cq, MaxSendWR: 16, MaxRecvWR: 16, MaxSendSGE: 1, MaxRecvSGE: 1, Access: AccessLocalWrite | AccessRemoteWrite})
	if err != nil {
		_ = cq.Close()
		_ = dev.Close()
		return nil, err
	}
	mr, err := dev.NewMR(64<<10, AccessLocalWrite|AccessRemoteWrite)
	if err != nil {
		_ = qp.Close()
		_ = cq.Close()
		_ = dev.Close()
		return nil, err
	}
	return &ringResources{dev: dev, cq: cq, qp: qp, mr: mr}, nil
}

func (r *ringResources) Close() {
	if r == nil {
		return
	}
	if r.mr != nil {
		_ = r.mr.Close()
	}
	if r.qp != nil {
		_ = r.qp.Close()
	}
	if r.cq != nil {
		_ = r.cq.Close()
	}
	if r.dev != nil {
		_ = r.dev.Close()
	}
}

// ListenRing starts the TCP v2 handshake listener. | ListenRing 启动 TCP v2 握手监听。
func ListenRing(addr string, cfg RingConfig) (*RingListener, error) {
	cfg.Addr = addr
	cfg, err := normalizeRingConfig(cfg)
	if err != nil {
		return nil, err
	}
	res, err := newRingResources()
	if err != nil {
		return nil, err
	}
	ln, err := net.Listen("tcp", addr)
	if err != nil {
		res.Close()
		return nil, err
	}
	return &RingListener{cfg: cfg, ln: ln, res: res}, nil
}

// Addr returns the listener address. | Addr 返回监听地址。
func (l *RingListener) Addr() net.Addr {
	if l == nil || l.ln == nil {
		return nil
	}
	return l.ln.Addr()
}

// Close stops the listener. | Close 停止监听。
func (l *RingListener) Close() error {
	if l == nil || l.ln == nil {
		return nil
	}
	if l.res != nil {
		l.res.Close()
		l.res = nil
	}
	return l.ln.Close()
}

// Accept completes the handshake and returns the receiver ring.
// Accept 完成握手并返回接收端 Ring。
func (l *RingListener) Accept() (*Ring, error) {
	conn, err := l.ln.Accept()
	if err != nil {
		return nil, err
	}
	if l.used || l.res == nil {
		_ = conn.Close()
		return nil, ErrRingClosed
	}
	l.used = true
	res := l.res
	l.res = nil
	ring, err := newRing(l.cfg, conn, "recv", res)
	if err != nil {
		res.Close()
	}
	return ring, err
}

// DialRing connects to a listener and returns the sender ring.
// DialRing 连接监听端并返回发送端 Ring。
func DialRing(addr string, cfg RingConfig) (*Ring, error) {
	cfg.Addr = addr
	cfg, err := normalizeRingConfig(cfg)
	if err != nil {
		return nil, err
	}
	res, err := newRingResources()
	if err != nil {
		return nil, err
	}
	conn, err := net.DialTimeout("tcp", addr, cfg.Timeout)
	if err != nil {
		res.Close()
		return nil, err
	}
	ring, err := newRing(cfg, conn, "send", res)
	if err != nil {
		res.Close()
	}
	return ring, err
}

func newRing(cfg RingConfig, conn net.Conn, role string, res *ringResources) (*Ring, error) {
	_ = conn.SetDeadline(time.Now().Add(cfg.Timeout))
	dev, cq, qp, mr := res.dev, res.cq, res.qp, res.mr
	psn := uint32(123456)
	localInfo := qp.LocalInfo(psn)
	if localInfo.MTU == 0 {
		localInfo.MTU = 1024
	}
	info := RingInfo{QPN: localInfo.QPN, PSN: psn, GID: localInfo.GID, MTU: localInfo.MTU,
		Addr: uint64(mr.Addr()), RKey: mr.RKey(), SlotSize: cfg.SlotSize, Slots: cfg.Slots}
	if err := writeRingFrame(conn, cfg.Secret, ringHandshake{Info: info}); err != nil {
		res.Close()
		_ = conn.Close()
		return nil, err
	}
	var peer ringHandshake
	if err := readRingFrame(conn, cfg.Secret, &peer); err != nil {
		res.Close()
		_ = conn.Close()
		return nil, err
	}
	if peer.Info.SlotSize != cfg.SlotSize || peer.Info.Slots != cfg.Slots {
		res.Close()
		_ = conn.Close()
		return nil, ErrRingProtocol
	}
	if err := qp.Connect(localInfo, ConnectInfo{QPN: peer.Info.QPN, PSN: peer.Info.PSN, GID: peer.Info.GID, MTU: peer.Info.MTU}); err != nil {
		res.Close()
		_ = conn.Close()
		return nil, err
	}
	r := &Ring{cfg: cfg, role: role, conn: conn, dev: dev, sendCQ: cq, recvCQ: cq, qp: qp, mr: mr, info: info, remote: peer.Info,
		outstanding: map[int]uint32{}, ackCh: make(chan uint32, cfg.Slots*2)}
	if role == "recv" {
		wrs := make([]RecvWR, cfg.Slots)
		for i := 0; i < cfg.Slots; i++ {
			wrs[i] = RecvWR{WRID: uint64(i + 1), Addr: mr.Addr() + uintptr(i*cfg.SlotSize), Length: uint32(cfg.SlotSize), LKey: mr.LKey()}
		}
		if n, err := qp.PostRecv(wrs); err != nil || n != cfg.Slots {
			r.Close()
			return nil, err
		}
		if err := writeRingFrame(conn, cfg.Secret, map[string]uint32{"ready": 1}); err != nil {
			r.Close()
			return nil, err
		}
	} else {
		var ready map[string]uint32
		if err := readRingFrame(conn, cfg.Secret, &ready); err != nil {
			r.Close()
			return nil, err
		}
		if ready["ready"] != 1 {
			r.Close()
			return nil, ErrRingProtocol
		}
		go r.ackLoop()
	}
	_ = conn.SetDeadline(time.Time{})
	return r, nil
}

// LocalInfo returns this ring's handshake information. | LocalInfo 返回 Ring 握手信息。
func (r *Ring) LocalInfo() RingInfo {
	if r == nil {
		return RingInfo{}
	}
	return r.info
}

// WriteWithImm writes data into the next free remote slot with an immediate
// value and waits for the local send completion. Slot memory remains reserved
// until the receiver's ACK arrives. | WriteWithImm 将数据写入下一个空闲远端槽位
// 并携带立即数，等待本地发送完成；在收到接收端 ACK 前槽位保持占用。
func (r *Ring) WriteWithImm(ctx context.Context, data []byte, imm uint32) (uint32, error) {
	if r == nil || r.role != "send" {
		return 0, ErrInvalidConfig
	}
	if r.closed.Load() {
		return 0, ErrRingClosed
	}
	if len(data)+8 > r.cfg.SlotSize {
		return 0, ErrMessageTooLarge
	}
	slot, err := r.reserveSlot(ctx)
	if err != nil {
		return 0, err
	}
	seq := r.seq.Add(1)
	body := r.mr.Bytes()[slot*r.cfg.SlotSize:]
	binary.BigEndian.PutUint32(body[0:4], seq)
	binary.BigEndian.PutUint32(body[4:8], uint32(len(data)))
	copy(body[8:], data)
	wr := SendWR{WRID: 1, Addr: r.mr.Addr() + uintptr(slot*r.cfg.SlotSize), Length: uint32(8 + len(data)), LKey: r.mr.LKey(),
		RemoteAddr: r.remote.Addr + uint64(slot*r.cfg.SlotSize), RKey: r.remote.RKey, Opcode: OpRDMAWriteWithImm, Flags: SendSignaled, Imm: imm}
	if n, err := r.qp.PostSend([]SendWR{wr}); err != nil || n != 1 {
		r.releaseSlot(slot)
		if err != nil {
			return 0, err
		}
		return 0, ErrDevice
	}
	if err := r.waitSend(ctx); err != nil {
		r.releaseSlot(slot)
		return 0, err
	}
	r.mu.Lock()
	r.outstanding[slot] = seq
	r.mu.Unlock()
	return seq, nil
}

func (r *Ring) reserveSlot(ctx context.Context) (int, error) {
	deadline := time.Now().Add(r.cfg.Timeout)
	for {
		r.mu.Lock()
		for slot := 0; slot < r.cfg.Slots; slot++ {
			if _, used := r.outstanding[slot]; !used {
				r.outstanding[slot] = 0
				r.mu.Unlock()
				return slot, nil
			}
		}
		r.mu.Unlock()
		if time.Now().After(deadline) {
			return 0, ErrRingFull
		}
		select {
		case <-ctx.Done():
			return 0, ctx.Err()
		case <-time.After(time.Millisecond):
		}
	}
}

func (r *Ring) releaseSlot(slot int) {
	r.mu.Lock()
	delete(r.outstanding, slot)
	r.mu.Unlock()
}

func (r *Ring) waitSend(ctx context.Context) error {
	deadline := time.Now().Add(r.cfg.Timeout)
	events := make([]Completion, 8)
	for {
		n, err := r.sendCQ.Poll(events)
		if err != nil {
			return err
		}
		if n > 0 && events[0].IsError() {
			return ErrDevice
		}
		if n > 0 {
			return nil
		}
		if time.Now().After(deadline) {
			return ErrRingTimeout
		}
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-time.After(10 * time.Microsecond):
		}
	}
}

func (r *Ring) ackLoop() {
	for {
		seq, err := readRingAck(r.conn, r.cfg.Secret)
		if err != nil {
			return
		}
		r.mu.Lock()
		for slot, value := range r.outstanding {
			if value == seq {
				delete(r.outstanding, slot)
				break
			}
		}
		r.mu.Unlock()
		select {
		case r.ackCh <- seq:
		default:
		}
	}
}

// Poll returns completed one-sided writes. The caller must persist Data and
// then call Ack(seq) to release the sender's slot.
// Poll 返回已完成的单边写；调用方持久化 Data 后必须调用 Ack(seq) 释放发送端槽位。
func (r *Ring) Poll(ctx context.Context, max int) ([]RingMessage, error) {
	if r == nil || r.role != "recv" {
		return nil, ErrInvalidConfig
	}
	if max <= 0 || max > r.cfg.Slots {
		max = r.cfg.Slots
	}
	events := make([]Completion, max)
	n, err := r.recvCQ.Poll(events)
	if err != nil {
		return nil, err
	}
	out := make([]RingMessage, 0, n)
	for i := 0; i < n; i++ {
		event := events[i]
		slot := int(event.WRID) - 1
		if slot < 0 || slot >= r.cfg.Slots || event.IsError() {
			return out, ErrDevice
		}
		offset := slot * r.cfg.SlotSize
		body := r.mr.Bytes()[offset : offset+r.cfg.SlotSize]
		seq := binary.BigEndian.Uint32(body[0:4])
		length := int(binary.BigEndian.Uint32(body[4:8]))
		if length < 0 || length > r.cfg.SlotSize-8 {
			return out, ErrRingProtocol
		}
		out = append(out, RingMessage{Seq: seq, Slot: slot, Imm: event.Imm, Data: append([]byte(nil), body[8:8+length]...)})
		wr := RecvWR{WRID: uint64(slot + 1), Addr: r.mr.Addr() + uintptr(offset), Length: uint32(r.cfg.SlotSize), LKey: r.mr.LKey()}
		if m, err := r.qp.PostRecv([]RecvWR{wr}); err != nil || m != 1 {
			return out, ErrDevice
		}
	}
	return out, nil
}

func (r *Ring) Ack(ctx context.Context, seq uint32) error {
	if r == nil || r.role != "recv" {
		return ErrInvalidConfig
	}
	select {
	case <-ctx.Done():
		return ctx.Err()
	default:
	}
	r.writeMu.Lock()
	defer r.writeMu.Unlock()
	return writeRingAck(r.conn, r.cfg.Secret, seq)
}

// Close releases the ring resources. | Close 释放 Ring 资源。
func (r *Ring) Close() error {
	if r == nil || !r.closed.CompareAndSwap(false, true) {
		return nil
	}
	if r.conn != nil {
		_ = r.conn.Close()
	}
	if r.qp != nil {
		_ = r.qp.Close()
	}
	if r.mr != nil {
		_ = r.mr.Close()
	}
	if r.sendCQ != nil {
		_ = r.sendCQ.Close()
	}
	if r.recvCQ != nil && r.recvCQ != r.sendCQ {
		_ = r.recvCQ.Close()
	}
	if r.dev != nil {
		return r.dev.Close()
	}
	return nil
}

func randomPSN() uint32 {
	var raw [4]byte
	if _, err := rand.Read(raw[:]); err == nil {
		return binary.BigEndian.Uint32(raw[:]) & 0xffffff
	}
	return uint32(time.Now().UnixNano()) & 0xffffff
}
