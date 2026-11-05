package raft

import "time"

// RDMATransportOptions configures the optional RDMA transport. Real RDMA is
// compiled only on Linux with cgo and the "rdma" build tag; other builds return
// ErrUnsupported. | RDMATransportOptions 配置可选 RDMA 传输。真实 RDMA 仅在 Linux、
// cgo 与 "rdma" 构建标签下编译；其它构建返回 ErrUnsupported。
type RDMATransportOptions struct {
	// ListenAddr is the local RDMA CM address, for example "192.168.2.2:2030".
	// Required. | ListenAddr 是本地 RDMA CM 地址，例如 "192.168.2.2:2030"。必填。
	ListenAddr string
	// Device selects an RDMA device such as "mlx5_0". Empty lets rdmanet choose.
	// | Device 选择 RDMA 设备，例如 "mlx5_0"；为空时由 rdmanet 选择。
	Device string
	// GIDIndex selects a GID table entry when non-zero. | GIDIndex 非零时选择 GID
	// 表项。
	GIDIndex int
	// DevicePort selects the RDMA device port, normally 1. Zero uses the default.
	// | DevicePort 选择 RDMA 设备端口，通常为 1；零使用默认值。
	DevicePort int
	// QueueDepth overrides the queue pair depth when non-zero. | QueueDepth 非零时
	// 覆盖队列对深度。
	QueueDepth int
	// BufferSize overrides the per-slot buffer size when non-zero. | BufferSize 非零
	// 时覆盖每槽缓冲区大小。
	BufferSize int
	// BusyPoll spins on the completion queue for the lowest latency at the cost of
	// a busy core. | BusyPoll 自旋轮询完成队列以获得最低延迟，代价是占用一个核心。
	BusyPoll bool
	// UseHandshake switches from rdma_cm to the TCP out-of-band handshake. Both
	// peers must use the same mode. | UseHandshake 从 rdma_cm 切换为 TCP 带外握手；
	// 两端必须使用相同模式。
	UseHandshake bool
	// SharedSecret enables frame-level HMAC-SHA256 authentication. RDMA provides
	// reliable delivery, not encryption; use IPsec/MACsec for encryption. | SharedSecret
	// 启用帧级 HMAC-SHA256 认证。RDMA 提供可靠传输，不提供加密；加密请使用 IPsec/MACsec。
	SharedSecret []byte
	// Queue is the per-peer outbound queue length. Default 64. | Queue 是每对端出站
	// 队列长度，默认 64。
	Queue int
	// DialTimeout bounds connection establishment. Default 5s. | DialTimeout 限制
	// 建连时间，默认 5s。
	DialTimeout time.Duration
	// MaxFrameBytes caps one frame. Default 64 MiB. | MaxFrameBytes 限制单帧大小，
	// 默认 64 MiB。
	MaxFrameBytes int
}

// RDMATransport is the concrete RDMA transport. | RDMATransport 是具体 RDMA 传输。
type RDMATransport struct {
	*streamTransport
}
