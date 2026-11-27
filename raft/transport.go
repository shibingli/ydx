package raft

import "context"

// Transport carries Raft messages between nodes. Implementations should
// preserve the per-sender order of Send calls within a traffic class; control
// messages (elections, heartbeats, acknowledgements, reads) may overtake large
// data batches (AppendEntries, snapshots) so a busy replication stream cannot
// delay liveness. Raft tolerates loss, duplication and reordering. | Transport
// 在节点之间传递 Raft 消息。实现应保持同一流量类别内每个发送者 Send 调用的顺序；
// 控制消息（选举、心跳、确认、读）可以越过大数据批次（AppendEntries、快照），
// 避免繁忙的复制流延迟活性。Raft 能容忍丢失、重复与乱序。
type Transport interface {
	// Start installs the inbound handler and starts any listeners. The handler
	// must be safe for concurrent calls. | Start 安装入站处理器并启动监听。处理器
	// 必须可并发调用。
	Start(handler func(Message)) error
	// Send delivers messages. It may return after enqueueing. | Send 投递消息，可在
	// 入队后返回。
	Send(ctx context.Context, msgs []Message) error
	// UpdatePeer installs or updates a peer address. | UpdatePeer 安装或更新对端地址。
	UpdatePeer(id NodeID, addr string)
	// Close stops listeners and releases resources. | Close 停止监听并释放资源。
	Close() error
}

// PeerRemover is an optional Transport extension that drops one peer address
// and releases the connection, queue and goroutine owned by it. Raft calls it
// after a removed member's final configuration commits on the leader and when a
// follower applies a configuration that no longer contains the member. |
// PeerRemover 是 Transport 的可选扩展，移除一个对端地址及其连接、队列与协程。
// 领导者在被移除成员的最终配置提交后调用；跟随者在应用不再包含该成员的配置时调用。
type PeerRemover interface {
	RemovePeer(id NodeID)
}

// PeerDirectory is an optional Transport extension that reports a known peer
// address. Startup seeds consult it and only fill missing entries, so a stale
// Config.Peers never overwrites an address installed explicitly through
// UpdatePeer or learned from another NodeHost group's membership. |
// PeerDirectory 是 Transport 的可选扩展，报告已知对端地址。启动种子会查询它并只
// 填补缺失项，因此过期的 Config.Peers 不会覆盖显式 UpdatePeer 或其它 NodeHost 组
// 从成员配置学到的地址。
type PeerDirectory interface {
	PeerAddress(id NodeID) (string, bool)
}

// PeerAddressTransport is an optional Transport extension for transports that
// deliver by address rather than by identifier. A Join node on such a transport
// needs Config.Peers seeds to answer the leader before its first configuration
// arrives; the node logs a warning when that list is empty. |
// PeerAddressTransport 是 Transport 的可选扩展，表示按地址而非标识投递的传输。
// 这类传输上的 Join 节点需要 Config.Peers 种子才能在首份配置到达前回复领导者；
// 种子列表为空时节点会记录告警。
type PeerAddressTransport interface {
	RequiresPeerAddresses() bool
}

// messageSink is implemented by in-process transports that can hand off a
// pooled message pointer without a value copy or per-message allocation. The
// sink takes ownership: it must enqueue the message or release it. |
// messageSink 由进程内传输实现，可直接移交池化消息指针，避免值复制与逐消息
// 分配。接收方取得所有权：必须入队或释放该消息。
type messageSink interface {
	StartSink(handler func(*Message)) error
}

// noopTransport is used for a single-voter cluster. | noopTransport 用于单投票成员
// 集群。
type noopTransport struct{}

// Start implements Transport. | Start 实现 Transport。
func (noopTransport) Start(func(Message)) error { return nil }

// Send implements Transport. | Send 实现 Transport。
func (noopTransport) Send(context.Context, []Message) error { return nil }

// SendImmediate implements ImmediateTransport. | SendImmediate 实现 ImmediateTransport。
func (noopTransport) SendImmediate() bool { return true }

// UpdatePeer implements Transport. | UpdatePeer 实现 Transport。
func (noopTransport) UpdatePeer(NodeID, string) {}

// RemovePeer implements PeerRemover. | RemovePeer 实现 PeerRemover。
func (noopTransport) RemovePeer(NodeID) {}

// RequiresPeerAddresses implements PeerAddressTransport. | RequiresPeerAddresses
// 实现 PeerAddressTransport。
func (noopTransport) RequiresPeerAddresses() bool { return false }

// Close implements Transport. | Close 实现 Transport。
func (noopTransport) Close() error { return nil }
