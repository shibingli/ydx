package raft

import "time"

// RDMATransportOptions configures the optional RDMA transport. Real RDMA is
// compiled on Linux/amd64 or Linux/arm64 with the "rdma" build tag; other
// builds return ErrUnsupported. The transport uses ydx/rdma, which is pure Go
// (purego/dlfcn) and does not require cgo. | RDMATransportOptions 配置可选 RDMA
// 传输。真实 RDMA 仅在 Linux/amd64 或 Linux/arm64 与 "rdma" 构建标签下编译；其它
// 构建返回 ErrUnsupported。传输使用 ydx/rdma，它是纯 Go（purego/dlfcn），不需要
// cgo。
type RDMATransportOptions struct {
	// ListenAddr is the local TCP control and RDMA target address, for example
	// "192.168.2.2:2030". It should be on the RDMA-capable interface. Required.
	// | ListenAddr 是本地 TCP 控制与 RDMA 目标地址，例如 "192.168.2.2:2030"，
	// 应位于支持 RDMA 的网卡上。必填。
	ListenAddr string
	// Device selects an RDMA device such as "mlx5_0". Empty lets ydx/rdma choose
	// the first device with an active port. | Device 选择 RDMA 设备，例如 "mlx5_0"；
	// 为空时由 ydx/rdma 选择第一个存在活动端口的设备。
	Device string
	// SharedSecret enables frame-level HMAC-SHA256 authentication. RDMA provides
	// reliable delivery, not encryption; use IPsec/MACsec for encryption. | SharedSecret
	// 启用帧级 HMAC-SHA256 认证。RDMA 提供可靠传输，不提供加密；加密请使用 IPsec/MACsec。
	SharedSecret []byte
	// GIDIndex selects a GID table entry when positive. Zero lets ydx/rdma prefer
	// a routable RoCE v2 GID. | GIDIndex 为正时选择 GID 表项；零表示由 ydx/rdma
	// 优先选择可路由的 RoCE v2 GID。
	GIDIndex int
	// DevicePort selects the RDMA device port, normally 1. Zero uses the default.
	// | DevicePort 选择 RDMA 设备端口，通常为 1；零使用默认值。
	DevicePort int
	// QueueDepth is the number of registered send/receive slots per connection;
	// it is capped at 512. Zero uses 64. Memory per connection is roughly
	// 2*QueueDepth*BufferSize. | QueueDepth 是每连接注册的发送/接收槽位数，上限
	// 512；零使用 64。每连接内存约为 2*QueueDepth*BufferSize。
	QueueDepth int
	// BufferSize is the registered slot size and the maximum RDMA chunk payload
	// size; larger frames are split into chunks. Values below 4096 are raised to
	// 4096, values above 1 MiB are capped, and the result is rounded up to a
	// multiple of 64. Zero uses 64 KiB. All peers of a cluster must use the same
	// BufferSize and a QueueDepth large enough for one send batch (32 chunks);
	// an RDMA message cannot exceed the receiver's registered slot. | BufferSize
	// 是注册槽位大小及单个 RDMA 分块最大负载；更大的帧会被分块。小于 4096 提升到
	// 4096，大于 1 MiB 截断，并向上取整到 64 的倍数；零使用 64 KiB。同一集群的
	// 所有对端必须使用相同的 BufferSize，且 QueueDepth 足以容纳一个发送批次
	// （32 个分块）；RDMA 消息不能超过接收方注册的槽位。
	BufferSize int
	// Queue is the per-peer outbound queue length. Default 64. | Queue 是每对端出站
	// 队列长度，默认 64。
	Queue int
	// DialTimeout bounds connection establishment. Default 5s. | DialTimeout 限制
	// 建连时间，默认 5s。
	DialTimeout time.Duration
	// MaxFrameBytes caps one reassembled frame. Frames larger than one registered
	// slot are chunked, so this limit is independent of BufferSize. Default
	// 64 MiB. | MaxFrameBytes 限制重组后的单帧大小。超过一个注册槽位的帧会被分块，
	// 因此该限制与 BufferSize 独立。默认 64 MiB。
	MaxFrameBytes int
	// BusyPoll is retained for compatibility. ydx/rdma polls completion queues on
	// the hot path with a bounded spin before yielding. | BusyPoll 为兼容保留。
	// ydx/rdma 热路径轮询完成队列，并在有限自旋后让出处理器。
	BusyPoll bool
	// UseHandshake is retained for compatibility. ydx/rdma always exchanges queue
	// pair parameters over a TCP control connection; payloads use RDMA. |
	// UseHandshake 为兼容保留。ydx/rdma 始终通过 TCP 控制连接交换队列对参数，
	// 负载走 RDMA。
	UseHandshake bool
}

// RDMATransport is the concrete RDMA transport. | RDMATransport 是具体 RDMA 传输。
type RDMATransport struct {
	*streamTransport
}
