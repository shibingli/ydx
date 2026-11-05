package raft

import "context"

// Transport carries Raft messages between nodes. Implementations must preserve
// the per-sender order of Send calls; Raft itself tolerates loss, duplication
// and reordering, but ordered delivery keeps the pipeline efficient. | Transport
// 在节点之间传递 Raft 消息。实现必须保持每个发送者 Send 调用的顺序；Raft 本身能
// 容忍丢失、重复与乱序，但有序交付能让流水线更高效。
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

// Close implements Transport. | Close 实现 Transport。
func (noopTransport) Close() error { return nil }
