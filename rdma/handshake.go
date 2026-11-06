package rdma

import (
	"encoding/binary"
	"io"
	"net"
	"time"

	"github.com/shibingli/ydx/errs"
)

// Handshake wire constants. | 握手线格式常量。
const (
	// qpInfoMagic identifies a ydx RDMA queue pair descriptor. | qpInfoMagic 标识
	// ydx RDMA 队列对描述。
	qpInfoMagic uint32 = 0x59445244
	// qpInfoVersion is the current wire format version. | qpInfoVersion 是当前
	// 线格式版本。
	qpInfoVersion uint16 = 1
	// qpInfoWireSize is the fixed encoded descriptor size. | qpInfoWireSize 是
	// 固定编码长度。
	qpInfoWireSize = 60
)

// qpInfo carries the queue pair and memory parameters exchanged before a
// connection becomes usable. All peers must agree on the wire version. |
// qpInfo 携带连接可用前交换的队列对与内存参数；对端必须使用相同的线格式版本。
type qpInfo struct {
	// QPN is the local queue pair number. | QPN 是本地队列对号。
	QPN uint32
	// PSN is the local send packet sequence number; the peer uses it as its
	// receive PSN. | PSN 是本地发送报文序列号；对端将其作为接收 PSN。
	PSN uint32
	// GID is the local GID used for the connection. | GID 是连接使用的本地 GID。
	GID [16]byte
	// LID is the local InfiniBand LID; zero on RoCE. | LID 是本地 InfiniBand
	// LID；RoCE 上为零。
	LID uint16
	// MTU is the path MTU in bytes. | MTU 是路径 MTU（字节）。
	MTU uint16
	// MaxInline is the largest inline payload in bytes. | MaxInline 是最大内联
	// 负载字节数。
	MaxInline uint32
	// RKey is the remote access key of the advertised memory region. | RKey 是
	// 公布内存区的远端访问键。
	RKey uint32
	// Addr is the base address of the advertised memory region. | Addr 是公布
	// 内存区的基地址。
	Addr uint64
	// SlotSize is the size of one message slot in bytes. | SlotSize 是单个消息
	// 槽位的字节数。
	SlotSize uint32
	// Slots is the number of message slots. | Slots 是消息槽位数量。
	Slots uint32
}

// writeQPInfo encodes info and writes it to w. | writeQPInfo 编码 info 并写入 w。
func writeQPInfo(w io.Writer, info qpInfo) error {
	var buf [qpInfoWireSize]byte
	binary.BigEndian.PutUint32(buf[0:4], qpInfoMagic)
	binary.BigEndian.PutUint16(buf[4:6], qpInfoVersion)
	binary.BigEndian.PutUint16(buf[6:8], 0)
	binary.BigEndian.PutUint32(buf[8:12], info.QPN)
	binary.BigEndian.PutUint32(buf[12:16], info.PSN)
	copy(buf[16:32], info.GID[:])
	binary.BigEndian.PutUint16(buf[32:34], info.LID)
	binary.BigEndian.PutUint16(buf[34:36], info.MTU)
	binary.BigEndian.PutUint32(buf[36:40], info.MaxInline)
	binary.BigEndian.PutUint32(buf[40:44], info.RKey)
	binary.BigEndian.PutUint64(buf[44:52], info.Addr)
	binary.BigEndian.PutUint32(buf[52:56], info.SlotSize)
	binary.BigEndian.PutUint32(buf[56:60], info.Slots)
	if err := writeFull(w, buf[:]); err != nil {
		return errs.Wrap(err, ErrHandshake)
	}
	return nil
}

// readQPInfo reads and validates one descriptor from r. | readQPInfo 从 r 读取
// 并校验一个描述符。
func readQPInfo(r io.Reader) (qpInfo, error) {
	var buf [qpInfoWireSize]byte
	if _, err := io.ReadFull(r, buf[:]); err != nil {
		return qpInfo{}, errs.Wrap(err, ErrHandshake)
	}
	if magic := binary.BigEndian.Uint32(buf[0:4]); magic != qpInfoMagic {
		return qpInfo{}, errs.Detail(ErrHandshake, "bad magic %#x | 魔数错误 %#x", magic, magic)
	}
	if version := binary.BigEndian.Uint16(buf[4:6]); version != qpInfoVersion {
		return qpInfo{}, errs.Detail(ErrHandshake, "wire version %d | 线格式版本 %d", version, version)
	}
	var info qpInfo
	info.QPN = binary.BigEndian.Uint32(buf[8:12])
	info.PSN = binary.BigEndian.Uint32(buf[12:16])
	copy(info.GID[:], buf[16:32])
	info.LID = binary.BigEndian.Uint16(buf[32:34])
	info.MTU = binary.BigEndian.Uint16(buf[34:36])
	info.MaxInline = binary.BigEndian.Uint32(buf[36:40])
	info.RKey = binary.BigEndian.Uint32(buf[40:44])
	info.Addr = binary.BigEndian.Uint64(buf[44:52])
	info.SlotSize = binary.BigEndian.Uint32(buf[52:56])
	info.Slots = binary.BigEndian.Uint32(buf[56:60])
	return info, nil
}

// exchangeQPInfo writes the local descriptor and reads the remote one
// concurrently, so the exchange also works on unbuffered duplex streams. |
// exchangeQPInfo 并发写入本地描述并读取远端描述，因此在无缓冲双工流上也能工作。
func exchangeQPInfo(conn net.Conn, local qpInfo, timeout time.Duration) (qpInfo, error) {
	if timeout > 0 {
		if err := conn.SetDeadline(time.Now().Add(timeout)); err != nil {
			return qpInfo{}, errs.Wrap(err, ErrHandshake)
		}
		defer conn.SetDeadline(time.Time{})
	}
	writeErr := make(chan error, 1)
	go func() { writeErr <- writeQPInfo(conn, local) }()
	remote, err := readQPInfo(conn)
	if werr := <-writeErr; werr != nil && err == nil {
		err = werr
	}
	if err != nil {
		return qpInfo{}, err
	}
	if remote.QPN == 0 {
		return qpInfo{}, errs.Detail(ErrHandshake, "remote qpn is zero | 远端 QPN 为零")
	}
	if remote.SlotSize == 0 || remote.Slots == 0 {
		return qpInfo{}, errs.Detail(ErrHandshake, "remote slot geometry %d x %d | 远端槽位参数 %d x %d",
			remote.SlotSize, remote.Slots, remote.SlotSize, remote.Slots)
	}
	switch remote.MTU {
	case 256, 512, 1024, 2048, 4096:
	default:
		return qpInfo{}, errs.Detail(ErrHandshake, "remote MTU %d | 远端 MTU %d", remote.MTU, remote.MTU)
	}
	// RQPSN is a 24-bit field; reject values that cannot be represented rather
	// than silently truncating them in the provider. | RQPSN 是 24 位字段；拒绝
	// 无法表示的值，而不是由提供方静默截断。
	if remote.PSN > 0xffffff {
		return qpInfo{}, errs.Detail(ErrHandshake, "remote PSN %#x | 远端 PSN %#x", remote.PSN, remote.PSN)
	}
	return remote, nil
}

// writeFull writes all of p, tolerating short writes. | writeFull 写完全部 p，
// 容忍短写。
func writeFull(w io.Writer, p []byte) error {
	for len(p) > 0 {
		n, err := w.Write(p)
		if err != nil {
			return err
		}
		if n == 0 {
			return io.ErrShortWrite
		}
		p = p[n:]
	}
	return nil
}
