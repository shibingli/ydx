package raft

// MessageType identifies a Raft RPC. Values are part of the wire format. | MessageType
// 标识一种 Raft RPC；数值属于线格式。
type MessageType uint8

const (
	// MsgHup asks the local node to start an election. | MsgHup 请求本地节点发起选举。
	MsgHup MessageType = iota + 1
	// MsgPreVote probes an election without incrementing the term. | MsgPreVote
	// 在不提升任期的情况下探测选举。
	MsgPreVote
	// MsgPreVoteResp answers MsgPreVote. | MsgPreVoteResp 应答 MsgPreVote。
	MsgPreVoteResp
	// MsgVote requests a vote. | MsgVote 请求选票。
	MsgVote
	// MsgVoteResp answers MsgVote. | MsgVoteResp 应答 MsgVote。
	MsgVoteResp
	// MsgApp replicates log entries and carries the consistency check. | MsgApp
	// 复制日志项并携带一致性检查。
	MsgApp
	// MsgAppResp answers MsgApp. | MsgAppResp 应答 MsgApp。
	MsgAppResp
	// MsgHeartbeat carries the leader's commit index and lease probe. | MsgHeartbeat
	// 携带领导者提交索引与租约探测。
	MsgHeartbeat
	// MsgHeartbeatResp answers MsgHeartbeat. | MsgHeartbeatResp 应答 MsgHeartbeat。
	MsgHeartbeatResp
	// MsgSnap installs a snapshot. | MsgSnap 安装快照。
	MsgSnap
	// MsgSnapResp answers MsgSnap. | MsgSnapResp 应答 MsgSnap。
	MsgSnapResp
	// MsgTransferLeader asks a node to take over leadership. | MsgTransferLeader
	// 请求节点接管领导权。
	MsgTransferLeader
	// MsgTimeoutNow tells an up-to-date follower to campaign immediately.
	// | MsgTimeoutNow 通知已追平的跟随者立即竞选。
	MsgTimeoutNow
	// MsgReadIndex asks the leader to confirm a linearizable read index. | MsgReadIndex
	// 请求领导者确认线性一致读索引。
	MsgReadIndex
	// MsgReadIndexResp answers MsgReadIndex. | MsgReadIndexResp 应答 MsgReadIndex。
	MsgReadIndexResp
)

// maxMessageType is the largest valid wire type. | maxMessageType 是最大合法线类型。
const maxMessageType = MsgReadIndexResp

// String renders a stable RPC name. | String 输出稳定的 RPC 名称。
func (m MessageType) String() string {
	switch m {
	case MsgHup:
		return "hup"
	case MsgPreVote:
		return "prevote"
	case MsgPreVoteResp:
		return "prevote-resp"
	case MsgVote:
		return "vote"
	case MsgVoteResp:
		return "vote-resp"
	case MsgApp:
		return "append"
	case MsgAppResp:
		return "append-resp"
	case MsgHeartbeat:
		return "heartbeat"
	case MsgHeartbeatResp:
		return "heartbeat-resp"
	case MsgSnap:
		return "snapshot"
	case MsgSnapResp:
		return "snapshot-resp"
	case MsgTransferLeader:
		return "transfer-leader"
	case MsgTimeoutNow:
		return "timeout-now"
	case MsgReadIndex:
		return "read-index"
	case MsgReadIndexResp:
		return "read-index-resp"
	default:
		return "unknown"
	}
}

// Message is one Raft RPC. Entry data and snapshot data are immutable while a
// message is in flight. | Message 是一条 Raft RPC。消息在途期间日志项与快照数据
// 不可修改。
type Message struct {
	Type       MessageType
	From       NodeID
	To         NodeID
	Group      GroupID
	Term       uint64
	LogIndex   uint64
	LogTerm    uint64
	Index      uint64
	Commit     uint64
	RejectHint uint64
	RejectTerm uint64
	Context    []byte
	Entries    []Entry
	Snapshot   *Snapshot
	Reject     bool
}

// isControlMessage reports whether a message belongs on the high-priority
// queue. Elections, heartbeats, leadership transfer and snapshot delivery are
// small, rare and safety-critical; they must not queue behind a saturated
// replication backlog. A dropped snapshot is especially costly because it is
// the only way to recover a follower that fell behind the compacted log. | isControlMessage
// 报告消息是否属于高优先级队列。选举、心跳、领导权转移与快照投递消息小、罕见且关系
// 安全性，不能排在饱和的复制积压之后。快照尤其不能丢，因为它是落后于已压缩日志的
// 跟随者唯一的追赶途径。
func isControlMessage(t MessageType) bool {
	switch t {
	case MsgPreVote, MsgPreVoteResp, MsgVote, MsgVoteResp,
		MsgHeartbeat, MsgHeartbeatResp, MsgTransferLeader, MsgTimeoutNow,
		MsgSnap, MsgSnapResp:
		return true
	default:
		return false
	}
}

// isResponse reports whether the message answers a request. | isResponse 报告消息
// 是否应答请求。
func (m Message) isResponse() bool {
	switch m.Type {
	case MsgPreVoteResp, MsgVoteResp, MsgAppResp, MsgHeartbeatResp, MsgSnapResp, MsgReadIndexResp:
		return true
	default:
		return false
	}
}
