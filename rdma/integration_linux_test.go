//go:build linux && rdma && (amd64 || arm64)

package rdma

import (
	"bytes"
	"encoding/binary"
	"errors"
	"testing"
	"time"
	"unsafe"
)

// openTestDevice opens the configured device with vendor-neutral defaults.
// YDX_RDMA_DEVICE and the other YDX_RDMA_* variables target specific hardware;
// without them the first active port and its best GID are selected. |
// openTestDevice 以厂商中立的默认配置打开设备。YDX_RDMA_DEVICE 等变量可用
// 于指定硬件；未设置时选择第一个活动端口及其最佳 GID。
func openTestDevice(t *testing.T) *Device {
	t.Helper()
	cfg := testConfig(t)
	d, err := Open(cfg)
	if err != nil {
		t.Fatalf("Open = %v | 打开设备失败", err)
	}
	t.Cleanup(func() { _ = d.Close() })
	return d
}

// newRCPair creates two reliable connected queue pairs on one device. | newRCPair
// 在同一设备上创建两个可靠连接队列对。
func newRCPair(t *testing.T, d *Device, depth int) (*CQ, *QP, *QP) {
	t.Helper()
	return newQPPair(t, d, depth, QPTypeRC)
}

// newQPPair creates and connects two queue pairs of the requested type. |
// newQPPair 创建并连接指定类型的两个队列对。
func newQPPair(t *testing.T, d *Device, depth int, typ QPType) (*CQ, *QP, *QP) {
	t.Helper()
	cq, err := d.NewCQ(depth * 2)
	if err != nil {
		t.Fatalf("NewCQ = %v | 创建 CQ 失败", err)
	}
	t.Cleanup(func() { _ = cq.Close() })
	cfg := DefaultQPConfig(cq)
	cfg.Type = typ
	cfg.MaxSendWR = depth
	cfg.MaxRecvWR = depth
	a, err := d.NewQP(cfg)
	if err != nil {
		t.Fatalf("NewQP(a) = %v | 创建 QP a 失败", err)
	}
	t.Cleanup(func() { _ = a.Close() })
	b, err := d.NewQP(cfg)
	if err != nil {
		t.Fatalf("NewQP(b) = %v | 创建 QP b 失败", err)
	}
	t.Cleanup(func() { _ = b.Close() })
	connectRC(t, d, a, b, 0x100, 0x200)
	return cq, a, b
}

// connectRC connects two queue pairs in loopback configuration through the
// public Connect API. | connectRC 通过公共 Connect API 连接两个环回队列对。
func connectRC(t *testing.T, d *Device, a, b *QP, psnA, psnB uint32) {
	t.Helper()
	infoA := a.LocalInfo(psnA)
	infoB := b.LocalInfo(psnB)
	if err := a.Connect(infoA, infoB); err != nil {
		t.Fatalf("Connect(a) = %v | 连接 a 失败", err)
	}
	if err := b.Connect(infoB, infoA); err != nil {
		t.Fatalf("Connect(b) = %v | 连接 b 失败", err)
	}
}

// pollUntil collects completions until want arrive or the deadline passes. |
// pollUntil 收集完成事件直到达到 want 或超时。
func pollUntil(t *testing.T, cq *CQ, want int, deadline time.Duration) []Completion {
	t.Helper()
	buf := make([]Completion, 16)
	var got []Completion
	end := time.Now().Add(deadline)
	for len(got) < want && time.Now().Before(end) {
		n, err := cq.Poll(buf)
		if err != nil {
			t.Fatalf("Poll = %v | 轮询失败", err)
		}
		for i := 0; i < n; i++ {
			if buf[i].IsError() {
				t.Fatalf("completion %+v failed | 完成事件失败", buf[i])
			}
			got = append(got, buf[i])
		}
	}
	if len(got) < want {
		t.Fatalf("completions = %d, want %d | 完成事件数量不足", len(got), want)
	}
	return got
}

// TestOpenDevice proves device, port and GID attributes are read through the
// purego bindings. | TestOpenDevice 证明设备、端口与 GID 属性可经 purego
// 绑定读取。
func TestOpenDevice(t *testing.T) {
	d := openTestDevice(t)
	if d.Name() == "" {
		t.Fatal("Name is empty | 设备名为空")
	}
	if d.GID().IsZero() {
		t.Fatal("selected GID is zero | 选中的 GID 为空")
	}
	if d.GID().Type == GIDTypeUnknown {
		// Some providers omit gid_attrs/types and use an unrecognised link
		// layer; the GID is still usable, so only log it. | 部分提供方缺少
		// gid_attrs/types 且链路层无法识别；GID 仍可用，仅记录。
		t.Logf("GID type is unknown | GID 类型未知")
	}
	if !d.PortAttr().State.Active() {
		t.Fatalf("port state = %v | 端口应为活动", d.PortAttr().State)
	}
	if d.PortAttr().ActiveMTU <= 0 {
		t.Fatalf("active mtu = %d | 活动 MTU 无效", d.PortAttr().ActiveMTU)
	}
	if d.Attr().MaxQPWR <= 0 || d.Attr().MaxCQE <= 0 {
		t.Fatalf("device attrs = %+v | 设备能力无效", d.Attr())
	}
}

// TestOpenRejectsMissingVerbsLibrary proves Config.VerbsLibrary overrides the
// automatic search and reports ErrUnsupported for a missing library. |
// TestOpenRejectsMissingVerbsLibrary 证明 Config.VerbsLibrary 覆盖自动查找，
// 并在库缺失时返回 ErrUnsupported。
func TestOpenRejectsMissingVerbsLibrary(t *testing.T) {
	cfg := testConfig(t)
	cfg.VerbsLibrary = "/nonexistent/libibverbs.so.1"
	_, err := Open(cfg)
	if !errors.Is(err, ErrUnsupported) {
		t.Fatalf("Open(missing library) = %v, want ErrUnsupported | 缺失库应返回 ErrUnsupported", err)
	}
}

// TestMemoryPool proves registered pools expose usable, distinct slots. |
// TestMemoryPool 证明注册内存池暴露可用且互不重叠的槽位。
func TestMemoryPool(t *testing.T) {
	d := openTestDevice(t)
	pool, err := d.NewPool(PoolConfig{Slots: 16, SlotSize: 4096, HugePages: true})
	if err != nil {
		t.Fatalf("NewPool = %v | 创建内存池失败", err)
	}
	defer pool.Close()
	if pool.Slots() < 16 {
		t.Fatalf("slots = %d, want >= 16 | 槽位不足", pool.Slots())
	}
	seen := make(map[uintptr]bool, 16)
	bufs := make([]*Buffer, 0, 16)
	for i := 0; i < 16; i++ {
		b, ok := pool.Acquire()
		if !ok {
			t.Fatalf("Acquire #%d failed | 获取槽位失败", i)
		}
		if len(b.Bytes()) != 4096 {
			t.Fatalf("slot len = %d | 槽位大小不符", len(b.Bytes()))
		}
		if seen[b.Addr()] {
			t.Fatalf("duplicate slot %#x | 槽位重复", b.Addr())
		}
		seen[b.Addr()] = true
		b.Bytes()[0] = byte(i)
		bufs = append(bufs, b)
	}
	for i, b := range bufs {
		if b.Bytes()[0] != byte(i) {
			t.Fatalf("slot %d content = %d | 槽位内容不符", i, b.Bytes()[0])
		}
		b.Release()
	}
	if pool.MR().LKey() == 0 || pool.MR().RKey() == 0 {
		t.Fatalf("lkey/rkey = %#x/%#x | 访问键为零", pool.MR().LKey(), pool.MR().RKey())
	}
}

// TestRCLoopbackSendRecv proves a zero-copy send/recv round trip completes on
// one device. | TestRCLoopbackSendRecv 证明单设备上的零拷贝收发往返可完成。
func TestRCLoopbackSendRecv(t *testing.T) {
	testLoopbackSendRecv(t, QPTypeRC)
}

// TestUCLoopbackSendRecv covers the unreliable-connected Connect path. |
// TestUCLoopbackSendRecv 覆盖不可靠连接类型的 Connect 路径。
func TestUCLoopbackSendRecv(t *testing.T) {
	testLoopbackSendRecv(t, QPTypeUC)
}

func testLoopbackSendRecv(t *testing.T, typ QPType) {
	t.Helper()
	d := openTestDevice(t)
	cq, qa, qb := newQPPair(t, d, 16, typ)
	pool, err := d.NewPool(PoolConfig{Slots: 16, SlotSize: 4096, HugePages: true})
	if err != nil {
		t.Fatalf("NewPool = %v | 创建内存池失败", err)
	}
	defer pool.Close()

	recvBufs := make([]*Buffer, 4)
	recvs := make([]RecvWR, 4)
	for i := range recvs {
		b, ok := pool.Acquire()
		if !ok {
			t.Fatal("Acquire recv failed | 获取接收槽位失败")
		}
		recvBufs[i] = b
		recvs[i] = RecvWR{WRID: uint64(i + 1), Addr: b.Addr(), Length: uint32(b.Len()), LKey: b.LKey()}
	}
	if n, err := qb.PostRecv(recvs); err != nil || n != 4 {
		t.Fatalf("PostRecv = %d/%v | 提交接收失败", n, err)
	}

	msg := []byte("hello rdma")
	tx, ok := pool.Acquire()
	if !ok {
		t.Fatal("Acquire tx failed | 获取发送槽位失败")
	}
	copy(tx.Bytes(), msg)
	if n, err := qa.PostSend([]SendWR{{
		WRID: 100, Addr: tx.Addr(), Length: uint32(len(msg)), LKey: tx.LKey(),
		Opcode: OpSend, Flags: SendSignaled,
	}}); err != nil || n != 1 {
		t.Fatalf("PostSend = %d/%v | 提交发送失败", n, err)
	}

	comps := pollUntil(t, cq, 2, 5*time.Second)
	var sawSend, sawRecv bool
	for _, c := range comps {
		switch {
		case c.WRID == 100 && c.Opcode == CompSend:
			sawSend = true
		case c.Opcode.IsRecv():
			sawRecv = true
			if c.WRID < 1 || c.WRID > 4 {
				t.Fatalf("recv wrid = %d | 接收 WRID 越界", c.WRID)
			}
			b := recvBufs[c.WRID-1]
			if c.Bytes != uint32(len(msg)) {
				t.Fatalf("recv bytes = %d, want %d | 接收字节数不符", c.Bytes, len(msg))
			}
			if !bytes.Equal(b.Bytes()[:c.Bytes], msg) {
				t.Fatalf("recv payload = %q | 接收负载不符", b.Bytes()[:c.Bytes])
			}
		}
	}
	if !sawSend || !sawRecv {
		t.Fatalf("send/recv = %v/%v | 缺少完成事件", sawSend, sawRecv)
	}
}

// TestInlineSendAtGrantedLimit proves a payload exactly at the provider-granted
// inline limit can be posted inline and received, so the automatic probe never
// over-estimates a vendor's limit. | TestInlineSendAtGrantedLimit 证明等于
// 提供方授予内联上限的负载可以内联提交并被接收，自动探测不会高估厂商上限。
func TestInlineSendAtGrantedLimit(t *testing.T) {
	d := openTestDevice(t)
	cq, qa, qb := newRCPair(t, d, 8)
	limit := qa.MaxInline()
	if limit <= 0 {
		t.Skip("provider grants no inline data | 提供方未授予内联能力")
	}
	pool, err := d.NewPool(PoolConfig{Slots: 4, SlotSize: 4096, HugePages: true})
	if err != nil {
		t.Fatalf("NewPool = %v | 创建内存池失败", err)
	}
	defer pool.Close()

	rx, ok := pool.Acquire()
	if !ok {
		t.Fatal("Acquire recv failed | 获取接收槽位失败")
	}
	if n, err := qb.PostRecv([]RecvWR{{
		WRID: 7, Addr: rx.Addr(), Length: uint32(rx.Len()), LKey: rx.LKey(),
	}}); err != nil || n != 1 {
		t.Fatalf("PostRecv = %d/%v | 提交接收失败", n, err)
	}
	tx, ok := pool.Acquire()
	if !ok {
		t.Fatal("Acquire tx failed | 获取发送槽位失败")
	}
	payload := tx.Bytes()[:limit]
	for i := range payload {
		payload[i] = byte(i * 7)
	}
	if n, err := qa.PostSend([]SendWR{{
		WRID: 8, Addr: tx.Addr(), Length: uint32(limit), LKey: tx.LKey(),
		Opcode: OpSend, Flags: SendSignaled | SendInline,
	}}); err != nil || n != 1 {
		t.Fatalf("PostSend inline = %d/%v | 提交内联发送失败", n, err)
	}
	comps := pollUntil(t, cq, 2, 5*time.Second)
	var sawSend, sawRecv bool
	for _, c := range comps {
		switch {
		case c.WRID == 8 && c.Opcode == CompSend:
			sawSend = true
		case c.WRID == 7 && c.Opcode.IsRecv():
			sawRecv = true
			if c.Bytes != uint32(limit) || !bytes.Equal(rx.Bytes()[:c.Bytes], payload) {
				t.Fatalf("recv = %d bytes | 内联接收负载不符", c.Bytes)
			}
		}
	}
	if !sawSend || !sawRecv {
		t.Fatalf("inline send/recv = %v/%v | 缺少内联完成事件", sawSend, sawRecv)
	}
}

// TestRCLoopbackWriteRead proves RDMA write and read reach the peer buffers. |
// TestRCLoopbackWriteRead 证明 RDMA 写与读可到达对端缓冲区。
func TestRCLoopbackWriteRead(t *testing.T) {
	d := openTestDevice(t)
	cq, qa, _ := newRCPair(t, d, 8)
	pool, err := d.NewPool(PoolConfig{Slots: 8, SlotSize: 4096, HugePages: true})
	if err != nil {
		t.Fatalf("NewPool = %v | 创建内存池失败", err)
	}
	defer pool.Close()
	remote, _ := pool.Acquire()
	local, _ := pool.Acquire()
	rkey := pool.MR().RKey()

	payload := []byte("rdma write payload")
	copy(local.Bytes(), payload)
	if _, err := qa.PostSend([]SendWR{{
		WRID: 1, Addr: local.Addr(), Length: uint32(len(payload)), LKey: local.LKey(),
		RemoteAddr: uint64(remote.Addr()), RKey: rkey,
		Opcode: OpRDMAWrite, Flags: SendSignaled,
	}}); err != nil {
		t.Fatalf("PostSend write = %v | 提交 RDMA 写失败", err)
	}
	pollUntil(t, cq, 1, 5*time.Second)
	if !bytes.Equal(remote.Bytes()[:len(payload)], payload) {
		t.Fatalf("remote payload = %q | 远端负载不符", remote.Bytes()[:len(payload)])
	}

	readBuf, _ := pool.Acquire()
	if _, err := qa.PostSend([]SendWR{{
		WRID: 2, Addr: readBuf.Addr(), Length: uint32(len(payload)), LKey: readBuf.LKey(),
		RemoteAddr: uint64(remote.Addr()), RKey: rkey,
		Opcode: OpRDMARead, Flags: SendSignaled,
	}}); err != nil {
		t.Fatalf("PostSend read = %v | 提交 RDMA 读失败", err)
	}
	pollUntil(t, cq, 1, 5*time.Second)
	if !bytes.Equal(readBuf.Bytes()[:len(payload)], payload) {
		t.Fatalf("read payload = %q | RDMA 读负载不符", readBuf.Bytes()[:len(payload)])
	}
}

// TestRCLoopbackAtomic proves fetch-and-add and compare-and-swap reach remote
// memory and return the original value. | TestRCLoopbackAtomic 证明取加与比较
// 交换可到达远端内存并返回原值。
func TestRCLoopbackAtomic(t *testing.T) {
	d := openTestDevice(t)
	cq, qa, _ := newRCPair(t, d, 8)
	pool, err := d.NewPool(PoolConfig{Slots: 8, SlotSize: 4096, HugePages: true})
	if err != nil {
		t.Fatalf("NewPool = %v | 创建内存池失败", err)
	}
	defer pool.Close()
	remote, _ := pool.Acquire()
	result, _ := pool.Acquire()
	rkey := pool.MR().RKey()
	*(*uint64)(unsafe.Pointer(&remote.Bytes()[0])) = 41

	if _, err := qa.PostSend([]SendWR{{
		WRID: 1, Addr: result.Addr(), Length: 8, LKey: result.LKey(),
		RemoteAddr: uint64(remote.Addr()), RKey: rkey,
		CompareAdd: 1, Opcode: OpAtomicFetchAdd, Flags: SendSignaled,
	}}); err != nil {
		t.Fatalf("PostSend fetch-add = %v | 提交取加失败", err)
	}
	pollUntil(t, cq, 1, 5*time.Second)
	if got := binary.BigEndian.Uint64(result.Bytes()[:8]); got != 41 {
		t.Fatalf("fetch-add result = %d, want 41 | 取加返回值不符", got)
	}
	if got := *(*uint64)(unsafe.Pointer(&remote.Bytes()[0])); got != 42 {
		t.Fatalf("remote = %d, want 42 | 远端值不符", got)
	}

	if _, err := qa.PostSend([]SendWR{{
		WRID: 2, Addr: result.Addr(), Length: 8, LKey: result.LKey(),
		RemoteAddr: uint64(remote.Addr()), RKey: rkey,
		CompareAdd: 42, Swap: 100, Opcode: OpAtomicCmpSwap, Flags: SendSignaled,
	}}); err != nil {
		t.Fatalf("PostSend cmp-swap = %v | 提交比较交换失败", err)
	}
	pollUntil(t, cq, 1, 5*time.Second)
	if got := binary.BigEndian.Uint64(result.Bytes()[:8]); got != 42 {
		t.Fatalf("cmp-swap result = %d, want 42 | 比较交换返回值不符", got)
	}
	if got := *(*uint64)(unsafe.Pointer(&remote.Bytes()[0])); got != 100 {
		t.Fatalf("remote = %d, want 100 | 远端值不符", got)
	}
}

// TestUDLoopback proves unreliable datagram send and receive on one device. |
// TestUDLoopback 证明单设备上的不可靠数据报收发。
func TestUDLoopback(t *testing.T) {
	d := openTestDevice(t)
	cq, err := d.NewCQ(64)
	if err != nil {
		t.Fatalf("NewCQ = %v | 创建 CQ 失败", err)
	}
	defer cq.Close()
	qpc := DefaultQPConfig(cq)
	qpc.Type = QPTypeUD
	qpc.MaxSendWR = 16
	qpc.MaxRecvWR = 16
	a, err := d.NewQP(qpc)
	if err != nil {
		t.Fatalf("NewQP(a) = %v | 创建 UD QP a 失败", err)
	}
	defer a.Close()
	b, err := d.NewQP(qpc)
	if err != nil {
		t.Fatalf("NewQP(b) = %v | 创建 UD QP b 失败", err)
	}
	defer b.Close()
	infoA := a.LocalInfo(0x100)
	infoB := b.LocalInfo(0x200)
	if err := a.Connect(infoA, infoB); err != nil {
		t.Fatalf("Connect(a) = %v | 连接 UD a 失败", err)
	}
	if err := b.Connect(infoB, infoA); err != nil {
		t.Fatalf("Connect(b) = %v | 连接 UD b 失败", err)
	}
	ah, err := d.NewAH(AHAttr{
		IsGlobal: true, GID: d.GID().Addr, SGIDIndex: uint8(d.Config().GIDIndex),
		HopLimit: 0xff, Port: uint8(d.Port()),
	})
	if err != nil {
		t.Fatalf("NewAH = %v | 创建地址句柄失败", err)
	}
	defer ah.Close()
	pool, err := d.NewPool(PoolConfig{Slots: 8, SlotSize: 4096})
	if err != nil {
		t.Fatalf("NewPool = %v | 创建内存池失败", err)
	}
	defer pool.Close()
	rx, _ := pool.Acquire()
	if _, err := b.PostRecv([]RecvWR{{
		WRID: 1, Addr: rx.Addr(), Length: uint32(rx.Len()), LKey: rx.LKey(),
	}}); err != nil {
		t.Fatalf("PostRecv = %v | 提交接收失败", err)
	}
	tx, _ := pool.Acquire()
	payload := []byte("ud datagram")
	copy(tx.Bytes(), payload)
	if _, err := a.PostSendUD([]SendWR{{
		WRID: 2, Addr: tx.Addr(), Length: uint32(len(payload)), LKey: tx.LKey(),
		Opcode: OpSend, Flags: SendSignaled, RemoteQPN: b.QPN(), RemoteQKey: 0x11111111,
	}}, ah); err != nil {
		t.Fatalf("PostSendUD = %v | 提交 UD 发送失败", err)
	}
	comps := pollUntil(t, cq, 2, 5*time.Second)
	var recv *Completion
	for i := range comps {
		if comps[i].Opcode.IsRecv() {
			recv = &comps[i]
		}
	}
	if recv == nil {
		t.Fatal("no receive completion | 缺少接收完成事件")
	}
	// UD receives prepend the 40-byte global routing header. | UD 接收会在前部
	// 附带 40 字节全局路由头。
	const grh = 40
	if recv.Bytes < grh+uint32(len(payload)) {
		t.Fatalf("recv bytes = %d | 接收字节数不足", recv.Bytes)
	}
	if !bytes.Equal(rx.Bytes()[grh:grh+len(payload)], payload) {
		t.Fatalf("ud payload = %q | UD 负载不符", rx.Bytes()[grh:grh+len(payload)])
	}
}

// TestSRQLoopback proves a shared receive queue serves a queue pair. |
// TestSRQLoopback 证明共享接收队列可为队列对服务。
func TestSRQLoopback(t *testing.T) {
	d := openTestDevice(t)
	cq, err := d.NewCQ(64)
	if err != nil {
		t.Fatalf("NewCQ = %v | 创建 CQ 失败", err)
	}
	defer cq.Close()
	qpc := DefaultQPConfig(cq)
	qpc.MaxSendWR = 8
	qpc.MaxRecvWR = 8
	qa, err := d.NewQP(qpc)
	if err != nil {
		t.Fatalf("NewQP(a) = %v | 创建 QP a 失败", err)
	}
	defer qa.Close()
	srq, err := d.NewSRQ(SRQConfig{MaxWR: 8, MaxSGE: 1})
	if err != nil {
		t.Fatalf("NewSRQ = %v | 创建共享接收队列失败", err)
	}
	defer srq.Close()
	qpb := DefaultQPConfig(cq)
	qpb.MaxSendWR = 8
	qpb.SRQ = srq
	qb, err := d.NewQP(qpb)
	if err != nil {
		t.Fatalf("NewQP(srq) = %v | 创建 SRQ QP 失败", err)
	}
	defer qb.Close()
	infoA := qa.LocalInfo(0x300)
	infoB := qb.LocalInfo(0x400)
	if err := qa.Connect(infoA, infoB); err != nil {
		t.Fatalf("Connect(a) = %v | 连接失败", err)
	}
	if err := qb.Connect(infoB, infoA); err != nil {
		t.Fatalf("Connect(b) = %v | 连接失败", err)
	}
	pool, err := d.NewPool(PoolConfig{Slots: 8, SlotSize: 4096})
	if err != nil {
		t.Fatalf("NewPool = %v | 创建内存池失败", err)
	}
	defer pool.Close()
	rx, _ := pool.Acquire()
	if _, err := srq.PostRecv([]RecvWR{{
		WRID: 7, Addr: rx.Addr(), Length: uint32(rx.Len()), LKey: rx.LKey(),
	}}); err != nil {
		t.Fatalf("SRQ.PostRecv = %v | 提交共享接收失败", err)
	}
	tx, _ := pool.Acquire()
	payload := []byte("srq payload")
	copy(tx.Bytes(), payload)
	if _, err := qa.PostSend([]SendWR{{
		WRID: 8, Addr: tx.Addr(), Length: uint32(len(payload)), LKey: tx.LKey(),
		Opcode: OpSend, Flags: SendSignaled,
	}}); err != nil {
		t.Fatalf("PostSend = %v | 发送失败", err)
	}
	comps := pollUntil(t, cq, 2, 5*time.Second)
	var got *Completion
	for i := range comps {
		if comps[i].Opcode.IsRecv() {
			got = &comps[i]
		}
	}
	if got == nil || got.WRID != 7 {
		t.Fatalf("srq completion = %+v | 共享接收完成事件不符", got)
	}
	if !bytes.Equal(rx.Bytes()[:got.Bytes], payload) {
		t.Fatalf("srq payload = %q | 共享接收负载不符", rx.Bytes()[:got.Bytes])
	}
}
