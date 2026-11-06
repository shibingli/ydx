package raft

import (
	"time"

	"github.com/shibingli/ydx/errs"
	"github.com/shibingli/ydx/log"
)

// FSM is the replicated state machine. Apply is called by one goroutine in log
// order; Snapshot and Restore must not run concurrently with it. The returned
// value is delivered to the Future of a proposal. | FSM 是复制状态机。Apply 由单个
// 协程按日志顺序调用；Snapshot 与 Restore 不得与其并发。返回值会交给提案的 Future。
type FSM interface {
	// Apply applies one committed command. | Apply 应用一条已提交命令。
	Apply(index, term uint64, data []byte) any
	// Snapshot returns a consistent image of the state machine. | Snapshot 返回
	// 状态机的一致镜像。
	Snapshot() ([]byte, error)
	// Restore replaces the state machine with a snapshot image. | Restore 用快照
	// 镜像替换状态机。
	Restore(data []byte) error
}

// BatchFSM is an optional fast path that applies a contiguous batch at once.
// The returned slice must have exactly one value per entry. | BatchFSM 是可选的批量
// 快路径，一次性应用连续批次；返回切片必须与日志项一一对应。
type BatchFSM interface {
	FSM
	ApplyBatch(entries []Entry) []any
}

// Config configures a Node. The zero value is not usable: ID, Storage and FSM
// are required. Boolean safety features default to enabled. | Config 配置 Node。零值
// 不可用：ID、Storage 与 FSM 必填。布尔安全特性默认开启。
type Config struct {
	// Storage persists hard state, log entries and snapshots. Required. | Storage
	// 持久化硬状态、日志项与快照。必填。
	Storage Storage
	// FSM is the application state machine. Required. | FSM 是应用状态机。必填。
	FSM FSM
	// Transport carries messages between nodes. It may be nil only when the
	// cluster has exactly one voter, or when RDMA is enabled. | Transport 在节点
	// 间传递消息。仅当集群只有一个投票成员或启用 RDMA 时可以为 nil。
	Transport Transport
	// Logger receives rare lifecycle and error events. Nil disables logging.
	// | Logger 接收少量生命周期与错误事件；nil 表示关闭日志。
	Logger *log.Logger

	// OnConfChange observes membership transitions when they take effect, which
	// in Raft is when the entry enters the log. It is called from the Raft event
	// loop on every replica and must not call back into the Node. | OnConfChange
	// 观察生效的成员变更；按 Raft 规则，变更项进入日志即生效。它由 Raft 事件循环在
	// 每个副本上调用，且不得回调 Node。
	OnConfChange func(ConfState)
	// OnStateChange observes role changes. It is called from the Raft event loop
	// and must not call back into the Node. | OnStateChange 观察角色变化。它由 Raft
	// 事件循环调用，不得回调 Node。
	OnStateChange func(from, to State)
	// Peers seeds a brand-new cluster. It is ignored when Storage already holds
	// state. The local ID is added automatically when absent. | Peers 用于初始化全
	// 新集群；Storage 已有状态时忽略。本地 ID 缺失时会自动加入。
	Peers []Peer
	// RDMAOptions configures the built-in RDMA transport. | RDMAOptions 配置内置
	// RDMA 传输。
	RDMAOptions RDMATransportOptions
	// ID is the local member identifier and must be non-zero. | ID 是本地成员标识，
	// 必须非零。
	ID NodeID
	// Group identifies a NodeHost group. It is zero for a standalone Node and
	// non-zero for NodeHost-managed groups. | Group 标识 NodeHost 组。独立 Node 为
	// 零，NodeHost 管理的组非零。
	Group GroupID

	// TickInterval is the logical clock granularity. Default 100ms, matching the
	// usual etcd-style 100ms heartbeat / 1s election cadence. Lower it only when
	// the network and storage tail latency are known to be much smaller. | TickInterval
	// 是逻辑时钟粒度，默认 100ms，与常见的 etcd 风格 100ms 心跳 / 1s 选举节奏一致。
	// 只有在网络与存储尾延迟远低于该值时才应调低。
	TickInterval time.Duration
	// HeartbeatTicks is the heartbeat period in ticks. Default 1. | HeartbeatTicks
	// 是心跳周期（tick 数），默认 1。
	HeartbeatTicks int
	// ElectionTicks is the minimum election timeout in ticks. The actual timeout
	// is randomized in [ElectionTicks, 2*ElectionTicks). Default 10. | ElectionTicks
	// 是最小选举超时（tick 数）；实际超时在 [ElectionTicks, 2*ElectionTicks) 内随机。
	// 默认 10。
	ElectionTicks int
	// ElectionStagger adds a deterministic delay of rank * ElectionStagger to
	// the fine-grained election timeout, where rank is the zero-based position
	// of this node in the sorted voter-ID list. Lower IDs campaign first; this
	// reduces split votes in large clusters. Zero disables stagger and keeps
	// purely randomized timeouts. Keep the total stagger well below the election
	// timeout so a failed preferred node does not delay failover excessively.
	// | ElectionStagger 在细粒度选举超时上增加 rank * ElectionStagger 的确定性
	// 延迟，rank 是节点在 voter ID 升序列表中的零基位置。较小 ID 优先竞选，可减少
	// 大集群的分裂投票。零值关闭 stagger，保持纯随机超时。总 stagger 应明显小于
	// 选举超时，避免首选节点故障时过度拖慢故障转移。
	ElectionStagger time.Duration
	// PreVoteSubsetThreshold enables bounded pre-vote fanout once the voter set
	// is larger than this value. Zero uses 16. Small clusters always contact
	// every voter. | PreVoteSubsetThreshold 在投票成员数超过该值时启用有界
	// pre-vote 扇出；零表示 16。小集群始终联系所有投票成员。
	PreVoteSubsetThreshold int
	// PreVoteSubsetExtra is the number of extra voters contacted beyond the
	// quorum in the first bounded pre-vote wave. Zero uses 4. The remaining
	// voters are contacted if the first wave cannot reach a quorum or times out.
	// | PreVoteSubsetExtra 是首轮有界 pre-vote 在法定人数之外额外联系的投票成员
	// 数；零表示 4。首轮无法达到多数或超时后会联系其余成员。
	PreVoteSubsetExtra int

	// MaxBatchEntries caps entries in one AppendEntries message. Default 64.
	// | MaxBatchEntries 限制单条 AppendEntries 的日志项数量，默认 64。
	MaxBatchEntries int
	// MaxBatchBytes caps entries' payload bytes in one AppendEntries message.
	// Default 1 MiB. | MaxBatchBytes 限制单条 AppendEntries 的负载字节数，默认 1 MiB。
	MaxBatchBytes int
	// MaxProposalBytes rejects a single proposal larger than this before it
	// enters the log. Default 1 MiB. Keep it below the transport's frame/body
	// limit (TCP/HTTP MaxFrameBytes/MaxBodyBytes; RDMA chunking has no slot
	// limit) so an accepted entry can always be replicated. | MaxProposalBytes
	// 在单条提案进入日志前拒绝超过该值的负载。默认 1 MiB。应低于传输的帧/请求体
	// 上限（TCP/HTTP 的 MaxFrameBytes/MaxBodyBytes；RDMA 分块不受槽位限制），确保
	// 已接受的日志项总能被复制。
	MaxProposalBytes int
	// MaxInflightMsgs caps pipelined AppendEntries messages per follower.
	// Default 64. | MaxInflightMsgs 限制每个跟随者的流水线消息数，默认 64。
	MaxInflightMsgs int
	// MaxInflightBytes caps pipelined entry bytes per follower. Default 4 MiB.
	// | MaxInflightBytes 限制每个跟随者的流水线日志字节数，默认 4 MiB。
	MaxInflightBytes int
	// SnapshotEntries triggers an automatic snapshot after this many applied
	// entries since the last snapshot. Default 10000. | SnapshotEntries 表示距上次
	// 快照累计应用多少日志项后自动创建快照，默认 10000。
	SnapshotEntries uint64
	// SnapshotCatchUpEntries is retained in memory after compaction so a slightly
	// lagging follower can catch up without a full snapshot. The window is not
	// recovered after a restart, where a snapshot may be required. Default 256.
	// | SnapshotCatchUpEntries 是压缩后在内存中保留的日志项数量，使略微落后的
	// 跟随者无需完整快照即可追上。重启后该窗口不会恢复，此时可能仍需快照。默认 256。
	SnapshotCatchUpEntries uint64

	// PersistBatchDelay is a group-commit window for durable writes. The persist
	// goroutine waits up to this long after the first request to merge more
	// concurrent requests into one fsync. It never blocks the Raft event loop;
	// only commit acknowledgement is delayed. Zero disables the extra window and
	// relies on requests already queued. 50-200us is useful on storage whose
	// fsync latency dominates. | PersistBatchDelay 是持久写的组提交窗口。持久化
	// 协程在首个请求后最多等待该时长，把更多并发请求合并到一次 fsync。它不阻塞
	// Raft 事件循环，只延迟提交确认。零值关闭额外等待，仅合并已排队的请求。在
	// fsync 延迟占主导的存储上，50-200us 很有用。
	PersistBatchDelay time.Duration
	// ProposalQueue is the bounded proposal intake size. The intake is striped
	// across 64 locks; the limit is divided across stripes. A full stripe makes
	// Propose return ErrBusy so callers can apply backpressure. Default 4096.
	// | ProposalQueue 是有界提案入口大小。入口按 64 个锁分片；限额均分到各分片。
	// 分片满时 Propose 返回 ErrBusy，调用方可施加背压。默认 4096。
	ProposalQueue int
	// MessageQueue is the buffered inbound message channel size. Default 8192.
	// | MessageQueue 是入站消息通道缓冲区大小，默认 8192。
	MessageQueue int
	// OutboundQueue is the buffered outbound message channel size. Default 8192.
	// | OutboundQueue 是出站消息通道缓冲区大小，默认 8192。
	OutboundQueue int
	// MaxPendingReads bounds local and, separately, forwarded ReadIndex calls
	// parked until the new leader commits a current-term entry. Zero derives a
	// capacity from MessageQueue: max(256, min(4096, MessageQueue/8)). This is a
	// backpressure bound, not a parallelism target. | MaxPendingReads 分别限制
	// 本地与转发的 ReadIndex 在新领导者提交当前任期日志项前的暂存量。零值时根据
	// MessageQueue 推导：max(256, min(4096, MessageQueue/8))。这是背压上限，不是
	// 并行度目标。
	MaxPendingReads int

	// Join starts an empty node that waits to be added by a leader. | Join 启动一个
	// 空节点，等待领导者将其加入集群。
	Join bool
	// RDMA enables the built-in RDMA transport when Transport is nil. It requires
	// a Linux/amd64 or Linux/arm64 build with -tags rdma; other builds return
	// ErrUnsupported. ydx/rdma is pure Go (no cgo). An explicit Transport always
	// takes precedence. | RDMA 在 Transport 为 nil 时启用内置 RDMA 传输。需要
	// Linux/amd64 或 Linux/arm64 与 -tags rdma；其它构建返回 ErrUnsupported。
	// ydx/rdma 为纯 Go（不使用 cgo）。显式 Transport 始终优先。
	RDMA bool

	// DisablePreVote turns off the pre-vote probe. Pre-vote prevents a
	// partitioned member from disrupting a healthy leader; lease reads are also
	// disabled because their safety bound depends on it. | DisablePreVote 关闭
	// 预投票。预投票可避免被分区成员打扰健康领导者；租约读也随之一并禁用，因为其
	// 安全边界依赖预投票。
	DisablePreVote bool
	// DisableCheckQuorum turns off leader quorum checking. | DisableCheckQuorum
	// 关闭领导者法定人数检查。
	DisableCheckQuorum bool
	// DisableLeaseRead forces every linearizable read to confirm leadership with
	// a heartbeat round. | DisableLeaseRead 强制每次线性一致读都通过心跳轮次确认
	// 领导权。
	DisableLeaseRead bool
}

// defaults fills unset fields. | defaults 填充未设置的字段。
func (c *Config) defaults() {
	if c.TickInterval <= 0 {
		c.TickInterval = 100 * time.Millisecond
	}
	if c.HeartbeatTicks <= 0 {
		c.HeartbeatTicks = 1
	}
	if c.ElectionTicks <= 0 {
		c.ElectionTicks = 10
	}
	if c.ElectionStagger < 0 {
		c.ElectionStagger = 0
	}
	if c.PreVoteSubsetThreshold <= 0 {
		c.PreVoteSubsetThreshold = 16
	}
	if c.PreVoteSubsetExtra < 0 {
		c.PreVoteSubsetExtra = 0
	}
	if c.PreVoteSubsetExtra == 0 {
		c.PreVoteSubsetExtra = 4
	}
	if c.MaxBatchEntries <= 0 {
		c.MaxBatchEntries = 64
	}
	if c.MaxBatchBytes <= 0 {
		c.MaxBatchBytes = 1 << 20
	}
	if c.MaxProposalBytes <= 0 {
		c.MaxProposalBytes = 1 << 20
	}
	if c.MaxInflightMsgs <= 0 {
		c.MaxInflightMsgs = 64
	}
	if c.MaxInflightBytes <= 0 {
		c.MaxInflightBytes = 4 << 20
	}
	if c.SnapshotEntries == 0 {
		c.SnapshotEntries = 10_000
	}
	if c.SnapshotCatchUpEntries == 0 {
		c.SnapshotCatchUpEntries = 256
	}
	if c.ProposalQueue <= 0 {
		c.ProposalQueue = 4096
	}
	if c.MessageQueue <= 0 {
		c.MessageQueue = 8192
	}
	if c.OutboundQueue <= 0 {
		c.OutboundQueue = 8192
	}
}

// validate checks hard requirements. | validate 检查硬性要求。
func (c *Config) validate() error {
	if c.ID == 0 {
		return errs.Detail(ErrInvalidConfig, "ID must be non-zero")
	}
	if c.Storage == nil {
		return errs.Detail(ErrInvalidConfig, "Storage is required")
	}
	if c.FSM == nil {
		return errs.Detail(ErrInvalidConfig, "FSM is required")
	}
	if c.ElectionTicks <= c.HeartbeatTicks {
		return errs.Detail(ErrInvalidConfig, "ElectionTicks must exceed HeartbeatTicks")
	}
	if c.TickInterval <= 0 {
		return errs.Detail(ErrInvalidConfig, "TickInterval must be positive")
	}
	if c.MaxProposalBytes > maxEntryBytes {
		return errs.Detail(ErrInvalidConfig, "MaxProposalBytes %d exceeds wire entry limit %d",
			c.MaxProposalBytes, maxEntryBytes)
	}
	seenID := make(map[NodeID]struct{}, len(c.Peers)+1)
	seenAddr := make(map[string]struct{}, len(c.Peers))
	for _, p := range c.Peers {
		if p.ID == 0 {
			return errs.Detail(ErrInvalidConfig, "peer ID must be non-zero")
		}
		if _, ok := seenID[p.ID]; ok {
			return errs.Detail(ErrInvalidConfig, "duplicate peer ID %d", p.ID)
		}
		seenID[p.ID] = struct{}{}
		if p.Addr != "" {
			if _, ok := seenAddr[p.Addr]; ok && p.ID != c.ID {
				return errs.Detail(ErrInvalidConfig, "duplicate peer address %q", p.Addr)
			}
			seenAddr[p.Addr] = struct{}{}
		}
	}
	return nil
}

// electionTimeoutTicks draws a timeout in [ElectionTicks, 2*ElectionTicks).
// | electionTimeoutTicks 在 [ElectionTicks, 2*ElectionTicks) 内抽取超时。
func (c *Config) electionTimeoutTicks() int {
	return c.ElectionTicks + int(fastrand()%uint64(c.ElectionTicks))
}

// pendingReadLimit returns the configured or capacity-derived parked-read
// bound. | pendingReadLimit 返回配置的或按容量推导的暂存读上限。
func (c *Config) pendingReadLimit() int {
	if c.MaxPendingReads > 0 {
		return c.MaxPendingReads
	}
	limit := c.MessageQueue / 8
	if limit < 256 {
		limit = 256
	}
	if limit > 4096 {
		limit = 4096
	}
	return limit
}

// electionTimeout returns the current wall-clock timeout estimate. | electionTimeout
// 返回当前墙钟超时估计。
func (c *Config) electionTimeout() time.Duration {
	return time.Duration(c.ElectionTicks*2) * c.TickInterval
}
