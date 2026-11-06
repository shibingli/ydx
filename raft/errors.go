package raft

import "github.com/shibingli/ydx/errs"

// Package-level sentinel errors. Callers use errors.Is to classify failures. |
// 包级哨兵错误。调用方使用 errors.Is 判定失败类别。
var (
	// ErrNotLeader reports that a write or linearizable read reached a follower.
	// | ErrNotLeader 表示写请求或线性一致读到达了跟随者。
	ErrNotLeader = errs.New("raft: not leader | raft：不是领导者")

	// ErrNoLeader reports that no leader is currently known. | ErrNoLeader 表示当前未知领导者。
	ErrNoLeader = errs.New("raft: no leader | raft：没有领导者")

	// ErrStopped reports that the node has been closed. | ErrStopped 表示节点已关闭。
	ErrStopped = errs.New("raft: node stopped | raft：节点已停止")

	// ErrProposalDropped reports that a proposal was discarded before it could
	// enter the log. Retrying is safe for idempotent commands. | ErrProposalDropped
	// 表示提案在进入日志前被丢弃。对幂等命令可安全重试。
	ErrProposalDropped = errs.New("raft: proposal dropped | raft：提案被丢弃")

	// ErrBusy reports that the bounded proposal intake is full. The caller
	// should apply backpressure and retry. | ErrBusy 表示有界提案入口已满，调用方
	// 应施加背压后重试。
	ErrBusy = errs.New("raft: proposal intake busy | raft：提案入口繁忙")

	// ErrLeadershipLost reports that leadership changed after a proposal entered
	// the log but before the outcome was known. The command may or may not have
	// committed. | ErrLeadershipLost 表示提案进入日志后、结果未知前领导权发生变化；
	// 命令可能已提交，也可能没有。
	ErrLeadershipLost = errs.New("raft: leadership lost | raft：领导权丢失")

	// ErrTransferInProgress reports that a leadership transfer blocks new
	// proposals. | ErrTransferInProgress 表示领导者转移进行中，暂时拒绝新提案。
	ErrTransferInProgress = errs.New("raft: leadership transfer in progress | raft：领导权转移进行中")

	// ErrConfChangeInProgress reports that another membership change is pending.
	// | ErrConfChangeInProgress 表示已有成员变更尚未完成。
	ErrConfChangeInProgress = errs.New("raft: membership change in progress | raft：成员变更进行中")

	// ErrUnknownNode reports that the peer is not part of the configuration.
	// | ErrUnknownNode 表示对端不在当前配置中。
	ErrUnknownNode = errs.New("raft: unknown node | raft：未知节点")

	// ErrInvalidConfig reports an unusable Config or membership change.
	// | ErrInvalidConfig 表示 Config 或成员变更不可用。
	ErrInvalidConfig = errs.New("raft: invalid configuration | raft：非法配置")

	// ErrCompacted reports that the requested log range has been compacted.
	// | ErrCompacted 表示请求的日志区间已被压缩。
	ErrCompacted = errs.New("raft: log compacted | raft：日志已压缩")

	// ErrUnavailable reports that the requested log index is not available.
	// | ErrUnavailable 表示请求的日志索引不可用。
	ErrUnavailable = errs.New("raft: log unavailable | raft：日志不可用")

	// ErrSnapshotOutOfDate reports that a snapshot is older than committed state.
	// | ErrSnapshotOutOfDate 表示快照落后于已提交状态。
	ErrSnapshotOutOfDate = errs.New("raft: snapshot out of date | raft：快照已过期")

	// ErrStorage reports a durable-storage failure. A node that observes this
	// error stops: continuing could violate Raft safety. | ErrStorage 表示持久化
	// 存储失败。观察到该错误的节点会停止，继续运行可能破坏 Raft 安全性。
	ErrStorage = errs.New("raft: storage failure | raft：存储失败")

	// ErrStorageLocked reports that another process already owns the storage
	// directory. Running two writers on one WAL can corrupt it. | ErrStorageLocked
	// 表示另一个进程已占用存储目录；两个写入者共用一份 WAL 会破坏数据。
	ErrStorageLocked = errs.New("raft: storage directory is locked | raft：存储目录已被占用")

	// ErrNetwork reports a transport connection or I/O failure. | ErrNetwork
	// 表示传输连接或 I/O 故障。
	ErrNetwork = errs.New("raft: network failure | raft：网络故障")

	// ErrCorrupt reports malformed wire data or a damaged WAL record.
	// | ErrCorrupt 表示网络数据格式错误或 WAL 记录损坏。
	ErrCorrupt = errs.New("raft: corrupt data | raft：数据损坏")

	// ErrFSMPanic reports that the user state machine panicked while applying.
	// | ErrFSMPanic 表示用户状态机在应用时发生 panic。
	ErrFSMPanic = errs.New("raft: state machine panic | raft：状态机 panic")

	// ErrTimeout reports that an operation did not finish before its deadline.
	// | ErrTimeout 表示操作未在期限内完成。
	ErrTimeout = errs.New("raft: timeout | raft：超时")

	// ErrTooLarge reports that a message, entry or snapshot exceeds a hard limit.
	// | ErrTooLarge 表示消息、日志项或快照超过硬限制。
	ErrTooLarge = errs.New("raft: payload too large | raft：负载过大")

	// ErrUnsupported reports a feature that was not compiled into this build,
	// such as RDMA without -tags rdma. | ErrUnsupported 表示当前构建未包含该特性，
	// 例如未使用 -tags rdma 的 RDMA。
	ErrUnsupported = errs.New("raft: unsupported feature | raft：不支持的特性")

	// ErrUnknownGroup reports a NodeHost group that is not running. | ErrUnknownGroup
	// 表示 NodeHost 组未运行。
	ErrUnknownGroup = errs.New("raft: unknown group | raft：未知组")
)
