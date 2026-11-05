//go:build linux && rdma && (amd64 || arm64)

package rdma

import (
	"encoding/binary"
	"io"
	"net"
	"os"
	"testing"
	"time"

	ydx "github.com/shibingli/ydx/rdma"
)

// wireInfo is the fixed-size handshake record exchanged by the raw verbs
// benchmark. | wireInfo 是裸 verbs 基准交换的定长握手记录。
type wireInfo struct {
	QPN  uint32
	PSN  uint32
	GID  [16]byte
	LID  uint16
	MTU  uint16
	QKey uint32
}

// wireSize is the encoded handshake size. | wireSize 是握手编码长度。
const wireSize = 32

// writeWire writes one handshake record. | writeWire 写入一条握手记录。
func writeWire(w io.Writer, v wireInfo) error {
	var b [wireSize]byte
	binary.BigEndian.PutUint32(b[0:4], v.QPN)
	binary.BigEndian.PutUint32(b[4:8], v.PSN)
	copy(b[8:24], v.GID[:])
	binary.BigEndian.PutUint16(b[24:26], v.LID)
	binary.BigEndian.PutUint16(b[26:28], v.MTU)
	binary.BigEndian.PutUint32(b[28:32], v.QKey)
	_, err := w.Write(b[:])
	return err
}

// readWire reads one handshake record. | readWire 读取一条握手记录。
func readWire(r io.Reader) (wireInfo, error) {
	var b [wireSize]byte
	if _, err := io.ReadFull(r, b[:]); err != nil {
		return wireInfo{}, err
	}
	var v wireInfo
	v.QPN = binary.BigEndian.Uint32(b[0:4])
	v.PSN = binary.BigEndian.Uint32(b[4:8])
	copy(v.GID[:], b[8:24])
	v.LID = binary.BigEndian.Uint16(b[24:26])
	v.MTU = binary.BigEndian.Uint16(b[26:28])
	v.QKey = binary.BigEndian.Uint32(b[28:32])
	return v, nil
}

// exchangeWire writes and reads concurrently so unbuffered transports work. |
// exchangeWire 并发读写，兼容无缓冲传输。
func exchangeWire(conn net.Conn, local wireInfo, timeout time.Duration) (wireInfo, error) {
	if timeout > 0 {
		_ = conn.SetDeadline(time.Now().Add(timeout))
		defer conn.SetDeadline(time.Time{})
	}
	errCh := make(chan error, 1)
	go func() { errCh <- writeWire(conn, local) }()
	remote, err := readWire(conn)
	if werr := <-errCh; werr != nil && err == nil {
		err = werr
	}
	return remote, err
}

// pollMatch waits for one completion accepted by match. | pollMatch 等待一个
// 满足 match 的完成事件。
func pollMatch(t *testing.T, cq *ydx.CQ, match func(ydx.Completion) bool, deadline time.Duration) ydx.Completion {
	t.Helper()
	var buf [8]ydx.Completion
	end := time.Now().Add(deadline)
	for time.Now().Before(end) {
		n, err := cq.Poll(buf[:])
		if err != nil {
			t.Fatalf("Poll = %v | 轮询失败", err)
		}
		for i := 0; i < n; i++ {
			if buf[i].IsError() {
				t.Fatalf("completion %+v | 完成事件失败", buf[i])
			}
			if match(buf[i]) {
				return buf[i]
			}
		}
	}
	t.Fatal("poll timed out | 轮询超时")
	return ydx.Completion{}
}

// isRecvCompletion reports whether the completion consumed a receive. |
// isRecvCompletion 报告完成事件是否消费了接收。
func isRecvCompletion(c ydx.Completion) bool { return c.Opcode.IsRecv() }

// TestRawLatencyCrossHost measures the raw verbs round trip without the Conn
// layer. | TestRawLatencyCrossHost 在不使用 Conn 层的情况下测量裸 verbs 往返
// 延迟。
func TestRawLatencyCrossHost(t *testing.T) {
	role := os.Getenv("YDX_RDMA_ROLE")
	addr := os.Getenv("YDX_RDMA_ADDR")
	if role == "" || addr == "" {
		t.Skip("set YDX_RDMA_ROLE and YDX_RDMA_ADDR | 未设置跨主机测试变量")
	}
	cfg := benchConfig(t)
	d, err := ydx.Open(cfg)
	if err != nil {
		t.Fatalf("Open = %v | 打开设备失败", err)
	}
	defer d.Close()
	cq, err := d.NewCQ(128)
	if err != nil {
		t.Fatalf("NewCQ = %v | 创建 CQ 失败", err)
	}
	defer cq.Close()
	qpc := ydx.DefaultQPConfig(cq)
	qpc.MaxSendWR = 16
	qpc.MaxRecvWR = 16
	qp, err := d.NewQP(qpc)
	if err != nil {
		t.Fatalf("NewQP = %v | 创建 QP 失败", err)
	}
	defer qp.Close()
	pool, err := d.NewPool(ydx.PoolConfig{Slots: 8, SlotSize: 4096})
	if err != nil {
		t.Fatalf("NewPool = %v | 创建内存池失败", err)
	}
	defer pool.Close()
	tx, _ := pool.Acquire()
	rx, _ := pool.Acquire()

	var tcp net.Conn
	switch role {
	case "server":
		ln, lerr := net.Listen("tcp", addr)
		if lerr != nil {
			t.Fatalf("Listen = %v | 监听失败", lerr)
		}
		defer ln.Close()
		tcp, err = ln.Accept()
		if err != nil {
			t.Fatalf("Accept = %v | 接受失败", err)
		}
	case "client":
		tcp, err = net.DialTimeout("tcp", addr, 10*time.Second)
		if err != nil {
			t.Fatalf("Dial = %v | 拨号失败", err)
		}
	default:
		t.Fatalf("unknown role %q | 未知角色", role)
	}
	defer tcp.Close()
	local := qp.LocalInfo(0x1234)
	remote, err := exchangeWire(tcp, wireInfo{
		QPN: local.QPN, PSN: local.PSN, GID: local.GID, LID: local.LID,
		MTU: uint16(local.MTU), QKey: local.QKey,
	}, 10*time.Second)
	if err != nil {
		t.Fatalf("handshake = %v | 握手失败", err)
	}
	if err := qp.Connect(local, ydx.ConnectInfo{
		QPN: remote.QPN, PSN: remote.PSN, GID: remote.GID, LID: remote.LID,
		MTU: int(remote.MTU), QKey: remote.QKey,
	}); err != nil {
		t.Fatalf("Connect = %v | 连接失败", err)
	}
	t.Logf("raw inline=%d", qp.MaxInline())

	recvWR := ydx.RecvWR{WRID: 1, Addr: rx.Addr(), Length: uint32(rx.Len()), LKey: rx.LKey()}
	if _, err := qp.PostRecv([]ydx.RecvWR{recvWR}); err != nil {
		t.Fatalf("PostRecv = %v | 提交接收失败", err)
	}
	sendWR := ydx.SendWR{
		WRID: 2, Addr: tx.Addr(), Length: 18, LKey: tx.LKey(),
		Opcode: ydx.OpSend, Flags: ydx.SendSignaled | ydx.SendInline,
	}
	const iterations = 2000
	switch role {
	case "server":
		for i := 0; i < iterations; i++ {
			pollMatch(t, cq, isRecvCompletion, 10*time.Second)
			if _, err := qp.PostSend([]ydx.SendWR{sendWR}); err != nil {
				t.Fatalf("PostSend = %v | 提交发送失败", err)
			}
			if _, err := qp.PostRecv([]ydx.RecvWR{recvWR}); err != nil {
				t.Fatalf("PostRecv = %v | 重新提交接收失败", err)
			}
		}
	case "client":
		start := time.Now()
		for i := 0; i < iterations; i++ {
			if _, err := qp.PostSend([]ydx.SendWR{sendWR}); err != nil {
				t.Fatalf("PostSend = %v | 提交发送失败", err)
			}
			pollMatch(t, cq, isRecvCompletion, 10*time.Second)
			if _, err := qp.PostRecv([]ydx.RecvWR{recvWR}); err != nil {
				t.Fatalf("PostRecv = %v | 重新提交接收失败", err)
			}
		}
		elapsed := time.Since(start)
		t.Logf("raw round trip: %v (%d iterations) | 裸往返延迟", elapsed/iterations, iterations)
	}
}
