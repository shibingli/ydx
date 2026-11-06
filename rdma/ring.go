package rdma

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/binary"
	"encoding/json"
	"errors"
	"io"
	"time"
)

// Ring errors. | Ring 错误。
var (
	ErrRingFull     = errors.New("rdma: ring is full | rdma：Ring 已满")
	ErrRingTimeout  = errors.New("rdma: ring operation timed out | rdma：Ring 操作超时")
	ErrRingClosed   = errors.New("rdma: ring closed | rdma：Ring 已关闭")
	ErrRingProtocol = errors.New("rdma: ring protocol error | rdma：Ring 协议错误")
)

// RingConfig configures one one-sided RDMA ring. Addr is the TCP handshake
// address; the RDMA device is selected by Config. Secret is mandatory for the
// v2 handshake and ACK frames. | RingConfig 配置单边 RDMA Ring。Addr 是 TCP 握手
// 地址，RDMA 设备由 Config 选择；v2 握手与 ACK 帧必须配置 Secret。
type RingConfig struct {
	Config   Config
	Addr     string
	Secret   []byte
	SlotSize int
	Slots    int
	Timeout  time.Duration
}

// RingInfo is exchanged by the versioned v2 handshake. | RingInfo 由版本化 v2
// 握手交换。
type RingInfo struct {
	QPN      uint32 `json:"qpn"`
	PSN      uint32 `json:"psn"`
	GID      [16]byte
	MTU      int    `json:"mtu"`
	Addr     uint64 `json:"addr"`
	RKey     uint32 `json:"rkey"`
	SlotSize int    `json:"slot_size"`
	Slots    int    `json:"slots"`
}

// RingMessage is one received one-sided write. The caller must persist the
// payload and then call Ring.Ack(seq). | RingMessage 是一次收到的单边写；调用方
// 持久化后必须调用 Ring.Ack(seq)。
type RingMessage struct {
	Seq  uint32
	Slot int
	Imm  uint32
	Data []byte
}

const (
	ringHandshakeMagic = "FXR2"
	ringHandshakeLen   = 4 + 1 + 4 + 32
	ringMaxFrame       = 1 << 20
)

type ringHandshake struct {
	Info RingInfo `json:"info"`
}

func normalizeRingConfig(cfg RingConfig) (RingConfig, error) {
	if cfg.Addr == "" {
		return cfg, errors.New("rdma: ring address required | rdma：Ring 地址必填")
	}
	if len(cfg.Secret) < 16 {
		return cfg, errors.New("rdma: ring secret must be at least 16 bytes | rdma：Ring 密钥至少 16 字节")
	}
	if cfg.SlotSize <= 8 || cfg.SlotSize > 1<<20 {
		cfg.SlotSize = 64 << 10
	}
	if cfg.Slots <= 0 || cfg.Slots > 4096 {
		cfg.Slots = 64
	}
	if cfg.Timeout <= 0 {
		cfg.Timeout = 10 * time.Second
	}
	if cfg.Config.Port == 0 {
		cfg.Config = DefaultConfig()
	}
	if cfg.Config.CQDepth < cfg.Config.QueueDepth {
		cfg.Config.CQDepth = cfg.Config.QueueDepth
	}
	cfg.Config.CQDepth = cfg.Config.QueueDepth
	return cfg, nil
}

func writeRingFrame(w io.Writer, secret []byte, value any) error {
	payload, err := json.Marshal(value)
	if err != nil {
		return err
	}
	if len(payload) > ringMaxFrame {
		return ErrRingProtocol
	}
	frame := make([]byte, ringHandshakeLen+len(payload))
	copy(frame[0:4], ringHandshakeMagic)
	frame[4] = 2
	binary.BigEndian.PutUint32(frame[5:9], uint32(len(payload)))
	mac := hmac.New(sha256.New, secret)
	_, _ = mac.Write(frame[0:9])
	_, _ = mac.Write(payload)
	copy(frame[9:41], mac.Sum(nil))
	copy(frame[41:], payload)
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

func readRingFrame(r io.Reader, secret []byte, out any) error {
	header := make([]byte, 9)
	if _, err := io.ReadFull(r, header); err != nil {
		return err
	}
	if string(header[0:4]) != ringHandshakeMagic || header[4] != 2 {
		return ErrRingProtocol
	}
	size := int(binary.BigEndian.Uint32(header[5:9]))
	if size < 0 || size > ringMaxFrame {
		return ErrRingProtocol
	}
	body := make([]byte, 32+size)
	if _, err := io.ReadFull(r, body); err != nil {
		return err
	}
	mac := hmac.New(sha256.New, secret)
	_, _ = mac.Write(header)
	_, _ = mac.Write(body[32:])
	if !hmac.Equal(mac.Sum(nil), body[:32]) {
		return ErrRingProtocol
	}
	return json.Unmarshal(body[32:], out)
}

func writeRingAck(w io.Writer, secret []byte, seq uint32) error {
	return writeRingFrame(w, secret, map[string]uint32{"ack": seq})
}

func readRingAck(r io.Reader, secret []byte) (uint32, error) {
	var ack map[string]uint32
	if err := readRingFrame(r, secret, &ack); err != nil {
		return 0, err
	}
	seq, ok := ack["ack"]
	if !ok {
		return 0, ErrRingProtocol
	}
	return seq, nil
}
