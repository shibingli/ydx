package raft

import (
	"context"
	"slices"
	"sync"
	"sync/atomic"
	"time"

	"github.com/shibingli/ydx/errs"
	ydlog "github.com/shibingli/ydx/log"
)

// Node is one Raft replica. Create it with New; it starts immediately. All
// exported methods are safe for concurrent use except Close, which must not be
// called from a callback running on the Raft event loop. | Node 是一个 Raft 副本。
// 用 New 创建后立即启动。除 Close 外所有导出方法都可并发使用；Close 不得在 Raft
// 事件循环的回调中调用。
type Node struct {
	futurePool   sync.Pool
	proposalPool sync.Pool

	leaseUntil time.Time
	storage    Storage
	transport  Transport
	fsm        FSM
	closeErr   error
	fatalErr   error

	logger  *ydlog.Logger
	metrics *metrics
	futures *futureStore

	// Channels. Sizes come from Config. | 通道；大小来自 Config。
	recvCh          chan Message
	controlCh       chan Message
	proposals       *proposalQueue
	readCh          chan *readRequest
	tickCh          chan struct{}
	outCh           chan outboundBatch
	persistCh       chan *persistRequest
	persistAckCh    chan persistAck
	snapshotReadyCh chan snapshotReady
	snapshotFileCh  chan snapshotFileResult
	snapshotCh      chan *snapshotRequest
	campaignCh      chan *campaignRequest
	transferCh      chan *transferRequest
	statusCh        chan chan Status
	fatalCh         chan error
	stopCh          chan struct{}
	doneCh          chan struct{}
	closeDoneCh     chan struct{}
	applyQueue      *applyQueue
	applySnapshotCh chan *snapshotRequest
	applyDoneCh     chan struct{}
	snapshotDoneCh  chan struct{}

	appliedNotify     *appliedNotifier
	remoteReads       *remoteReadStore
	log               *raftLog
	conf              *membership
	confBase          *membership
	progress          map[NodeID]*progress
	votes             map[NodeID]bool
	preVotes          map[NodeID]bool
	preVoteSent       map[NodeID]struct{}
	preVotePending    map[NodeID]struct{}
	preVoteRemaining  []NodeID
	preVoteReq        Message
	preVoteExpandTick uint64
	pendingConf       *pendingConf
	latestSnapshot    *Snapshot
	activeSnapshotReq *snapshotRequest
	readRound         *readRound
	pendingReads      []*readRequest
	pendingRemoteRead []remoteReadResponse
	pendingReadLimit  int
	confHistory       []confVersion
	transferWaiters   []chan error
	pendingRemoval    []NodeID
	snapshotWaiters   []chan error
	pending           []deferredAction
	outBuf            []Message
	outCtrlBuf        []Message
	outDataBuf        []Message
	scratch           []uint64
	campaignWaiters   []chan error
	cfg               Config
	wg                sync.WaitGroup

	id               NodeID
	group            GroupID
	termAtomic       atomic.Uint64
	leaderAtomic     atomic.Uint64
	commitAtomic     atomic.Uint64
	applied          atomic.Uint64
	lastSnapshot     atomic.Uint64
	remoteReadSeq    atomic.Uint64
	remoteEpoch      uint64
	term             uint64
	vote             NodeID
	leader           NodeID
	committed        uint64
	sentApplied      uint64
	persistedIndex   uint64
	confBaseIndex    uint64
	jointIndex       uint64
	electionElapsed  int
	heartbeatElapsed int
	electionTimeout  int
	leadTransferee   NodeID
	transferElapsed  int
	leaveIndex       uint64
	readSeq          uint64
	tickCount        uint64
	termStartIndex   uint64
	appliedTerm      uint64
	persistSeq       uint64
	outControls      int

	// Config-derived hot fields. | 由配置导出的热字段。
	tickInterval     time.Duration
	heartbeatTicks   int
	electionTicks    int
	maxBatchEntries  int
	maxBatchBytes    int
	maxProposalBytes int
	maxInflightMsgs  int
	maxInflightBytes int
	snapshotEntries  uint64
	snapshotCatchUp  uint64
	closeOnce        sync.Once
	stopOnce         sync.Once
	fatalMu          sync.Mutex

	stopped atomic.Bool

	stateAtomic    atomic.Uint32
	transferActive atomic.Bool

	immediateStore     bool
	immediateTransport bool

	// Event-loop state. | 事件循环状态。
	electionTimer    *time.Timer
	electionRankConf *membership
	electionDeadline time.Time
	electionRank     int
	state            State
	transferSent     bool
	snapshotting     bool
	autoCampaign     bool
	selfVoteDurable  bool
}

// confVersion records the membership produced by one log entry. | confVersion 记录
// 一条日志项产生的成员配置。
type confVersion struct {
	conf       *membership
	index      uint64
	jointIndex uint64
}

// proposal is one client or internal write. | proposal 是一次客户端或内部写请求。
type proposal struct {
	conf   *ConfChange
	future *Future
	data   []byte
}

// readRequest asks for a linearizable read index. | readRequest 请求线性一致读索引。
type readRequest struct {
	done chan readResult
}

// readResult is the outcome of ReadIndex. | readResult 是 ReadIndex 的结果。
type readResult struct {
	err   error
	index uint64
}

// campaignRequest forces an election. | campaignRequest 强制发起选举。
type campaignRequest struct {
	done chan error
}

// transferRequest asks the leader to hand over to target. | transferRequest 请求领导
// 者将领导权交给 target。
type transferRequest struct {
	done   chan error
	target NodeID
}

// outboundBatch is handed to the sender goroutine. | outboundBatch 交给发送协程。
type outboundBatch struct {
	msgs []Message
}

// pendingConf tracks an in-flight membership change. | pendingConf 跟踪进行中的成员
// 变更。
type pendingConf struct {
	future       *Future
	change       ConfChange
	initialIndex uint64
	leaveIndex   uint64
	resolved     bool
}

// newProposal copies data and wraps it in a new future. | newProposal 复制数据并包装
// 成带新 Future 的提案。
func newProposal(data []byte, owned bool) *proposal {
	return newProposalWithFuture(data, owned, newFuture(0, 0))
}

// newProposalWithFuture copies data and wraps it with f. | newProposalWithFuture
// 复制数据并用 f 包装提案。
func newProposalWithFuture(data []byte, owned bool, f *Future) *proposal {
	if !owned && data != nil {
		data = append([]byte(nil), data...)
	}
	return &proposal{data: data, future: f}
}

// allocProposal returns a proposal, optionally from the synchronous-proposal
// pool. | allocProposal 返回提案，可选地从同步提案池中复用。
func (n *Node) allocProposal(data []byte, owned bool, f *Future, reuse bool) *proposal {
	var p *proposal
	if reuse {
		if v := n.proposalPool.Get(); v != nil {
			p = v.(*proposal)
		}
	}
	if p == nil {
		p = &proposal{}
	}
	if !owned && data != nil {
		data = append([]byte(nil), data...)
	}
	p.data = data
	p.conf = nil
	p.future = f
	return p
}

// releaseProposal clears and recycles a proposal whose outcome is known.
// | releaseProposal 清空并回收结果已知的提案。
func (n *Node) releaseProposal(p *proposal) {
	if p == nil {
		return
	}
	p.data = nil
	p.conf = nil
	p.future = nil
	n.proposalPool.Put(p)
}

// controlQueueSize returns the high-priority queue capacity. Control traffic is
// periodic and small; a fraction of the data queue keeps it independent of a
// saturated replication backlog. | controlQueueSize 返回高优先级队列容量。控制
// 流量周期性且很小；取数据队列的一部分即可让它在复制积压饱和时保持独立。
func controlQueueSize(messageQueue int) int {
	size := messageQueue / 8
	if size < 256 {
		size = 256
	}
	return size
}

// New creates and starts a node. Recovery, bootstrap and FSM restore happen
// before the first caller receives the node. | New 创建并启动节点。恢复、引导与 FSM
// 还原都在返回节点前完成。
func New(cfg Config) (*Node, error) {
	cfg.defaults()
	if err := cfg.validate(); err != nil {
		return nil, err
	}
	// Reject an obviously unusable multi-node transport before Load/recover can
	// bootstrap or mutate storage. Without this a failed New leaves a fresh
	// single-voter bootstrap behind. | 在 Load/recover 可能引导或修改存储前拒绝明显
	// 不可用的多节点传输；否则失败的 New 会留下一个全新的单投票成员引导状态。
	if cfg.Transport == nil && !cfg.RDMA && len(cfg.Peers) > 1 {
		return nil, errs.Detail(ErrInvalidConfig, "Transport is required for a multi-node cluster")
	}
	// Build the RDMA transport before Load/recover. Invalid RDMA options must not
	// leave a freshly bootstrapped log behind. | 在 Load/recover 前构建 RDMA 传输。
	// 无效的 RDMA 选项不得留下全新引导的日志。
	var builtTransport Transport
	if cfg.Transport == nil && cfg.RDMA {
		transport, err := NewRDMATransport(cfg.RDMAOptions)
		if err != nil {
			return nil, err
		}
		builtTransport = transport
		cfg.Transport = transport
	}
	rec, err := cfg.Storage.Load()
	if err != nil {
		if builtTransport != nil {
			_ = builtTransport.Close()
		}
		return nil, errs.Wrap(err, ErrStorage)
	}
	n := &Node{
		cfg:              cfg,
		id:               cfg.ID,
		group:            cfg.Group,
		storage:          cfg.Storage,
		fsm:              cfg.FSM,
		logger:           cfg.Logger,
		metrics:          newMetrics(),
		futures:          newFutureStore(),
		appliedNotify:    newAppliedNotifier(),
		remoteReads:      newRemoteReadStore(),
		remoteEpoch:      newRemoteReadEpoch(),
		recvCh:           make(chan Message, cfg.MessageQueue),
		controlCh:        make(chan Message, controlQueueSize(cfg.MessageQueue)),
		proposals:        newProposalQueue(cfg.ProposalQueue),
		readCh:           make(chan *readRequest, 256),
		tickCh:           make(chan struct{}, 1),
		outCh:            make(chan outboundBatch, cfg.OutboundQueue),
		persistCh:        make(chan *persistRequest, 128),
		persistAckCh:     make(chan persistAck, 256),
		snapshotReadyCh:  make(chan snapshotReady, 16),
		snapshotFileCh:   make(chan snapshotFileResult, 16),
		snapshotCh:       make(chan *snapshotRequest, 16),
		campaignCh:       make(chan *campaignRequest, 16),
		transferCh:       make(chan *transferRequest, 16),
		statusCh:         make(chan chan Status, 16),
		fatalCh:          make(chan error, 1),
		stopCh:           make(chan struct{}),
		doneCh:           make(chan struct{}),
		closeDoneCh:      make(chan struct{}),
		applySnapshotCh:  make(chan *snapshotRequest, 16),
		applyDoneCh:      make(chan struct{}),
		snapshotDoneCh:   make(chan struct{}, 1),
		progress:         make(map[NodeID]*progress),
		votes:            make(map[NodeID]bool),
		preVotes:         make(map[NodeID]bool),
		scratch:          make([]uint64, 0, 16),
		tickInterval:     cfg.TickInterval,
		heartbeatTicks:   cfg.HeartbeatTicks,
		electionTicks:    cfg.ElectionTicks,
		maxBatchEntries:  cfg.MaxBatchEntries,
		maxBatchBytes:    cfg.MaxBatchBytes,
		maxProposalBytes: cfg.MaxProposalBytes,
		maxInflightMsgs:  cfg.MaxInflightMsgs,
		maxInflightBytes: cfg.MaxInflightBytes,
		snapshotEntries:  cfg.SnapshotEntries,
		snapshotCatchUp:  cfg.SnapshotCatchUpEntries,
		pendingReadLimit: cfg.pendingReadLimit(),
	}
	n.applyQueue = newApplyQueue()
	n.autoCampaign = false
	// Recovery arms this timer for every path that has a membership; a Join
	// node with empty storage keeps it stopped until it is added. | 恢复会为所有
	// 有成员配置的路径启动该定时器；空存储的 Join 节点保持停止，直到被加入。
	n.electionTimer = time.NewTimer(time.Hour)
	n.electionTimer.Stop()
	success := false
	defer func() {
		if !success {
			n.stopElectionTimer()
		}
	}()
	if err := n.recover(rec); err != nil {
		_ = n.storage.Close()
		if builtTransport != nil {
			_ = builtTransport.Close()
		}
		return nil, err
	}
	if n.cfg.Transport == nil {
		if !n.singleVoter() {
			_ = n.storage.Close()
			return nil, errs.Detail(ErrInvalidConfig, "Transport is required for a multi-node cluster")
		}
		n.cfg.Transport = noopTransport{}
	}
	n.transport = n.cfg.Transport
	if st, ok := n.storage.(ImmediateStorage); ok && st.PersistImmediate() {
		n.immediateStore = true
	}
	if tr, ok := n.transport.(ImmediateTransport); ok && tr.SendImmediate() {
		n.immediateTransport = true
	}
	n.updatePeerAddresses()
	if err := n.transport.Start(n.Step); err != nil {
		_ = n.transport.Close()
		_ = n.storage.Close()
		return nil, errs.Wrap(err, ErrInvalidConfig)
	}
	n.autoCampaign = n.singleVoter() && !cfg.Join
	n.wg.Add(5)
	go n.applyLoop()
	go n.persistLoop()
	go n.senderLoop()
	go n.tickerLoop()
	success = true
	go n.run()
	return n, nil
}

// recover rebuilds the in-memory log and configuration. | recover 重建内存日志与配置。
func (n *Node) recover(rec Recovery) error {
	hasState := rec.Snapshot != nil || len(rec.Entries) > 0 || rec.HardState.Term > 0
	if !hasState && !n.cfg.Join {
		return n.bootstrap()
	}
	if !hasState {
		l, err := newLog(nil, nil)
		if err != nil {
			return err
		}
		n.log = l
		n.conf = newMembership(nil, nil, nil)
		n.confBase = n.conf
		n.term = 0
		n.applied.Store(0)
		n.sentApplied = 0
		return nil
	}
	var snap *Snapshot
	if rec.Snapshot != nil {
		// Storage.Load returns an immutable image owned by this recovery; keep it
		// without a full payload copy. | Storage.Load 返回的镜像不可变且归本次恢复
		// 所有；无需复制完整负载。
		snap = rec.Snapshot
		if err := n.fsm.Restore(snap.Data); err != nil {
			return errs.Wrap(err, ErrFSMPanic)
		}
	}
	// Storage.Load hands over fresh slices (see the Storage contract), so the
	// log can take ownership instead of deep-copying a potentially large tail.
	// | Storage.Load 移交全新的切片（见 Storage 契约），因此日志可直接接管，
	// 无需深拷贝可能很大的尾部。
	l, err := newLog(snap, rec.Entries)
	if err != nil {
		return err
	}
	n.log = l
	n.latestSnapshot = snap
	baseIndex := uint64(0)
	n.confBase = newMembership(nil, nil, nil)
	if snap != nil {
		n.confBase = newMembershipFromState(snap.ConfState)
		baseIndex = snap.Index
	}
	n.confBaseIndex = baseIndex
	n.conf = n.confBase
	if n.conf.joint() {
		n.jointIndex = baseIndex
	}
	if err := n.replayConfig(rec.Entries); err != nil {
		return err
	}
	hs := rec.HardState
	if snap != nil && hs.Term < snap.Term {
		hs.Term = snap.Term
	}
	n.term = hs.Term
	n.vote = hs.Vote
	n.termAtomic.Store(hs.Term)
	n.committed = hs.Commit
	if snap != nil && n.committed < snap.Index {
		n.committed = snap.Index
	}
	if n.committed > l.lastIndex {
		n.committed = l.lastIndex
	}
	n.commitAtomic.Store(n.committed)
	applied := uint64(0)
	if snap != nil {
		applied = snap.Index
	}
	n.applied.Store(applied)
	n.lastSnapshot.Store(applied)
	n.sentApplied = applied
	n.persistedIndex = l.lastIndex
	if snap != nil {
		n.appliedTerm = snap.Term
	}
	n.state = StateFollower
	n.stateAtomic.Store(uint32(StateFollower))
	n.resetElection()
	return nil
}

// bootstrap creates the initial configuration entry for a brand-new cluster.
// | bootstrap 为全新集群创建初始配置日志项。
func (n *Node) bootstrap() error {
	voters := []NodeID{n.id}
	addrs := make(map[NodeID]string, len(n.cfg.Peers))
	for _, p := range n.cfg.Peers {
		if p.ID != n.id {
			voters = append(voters, p.ID)
		}
		if p.Addr != "" {
			addrs[p.ID] = p.Addr
		}
	}
	slices.Sort(voters)
	voters = slices.Compact(voters)
	conf := newMembership(voters, nil, addrs)
	cs := conf.confState()
	entry := Entry{Index: 1, Term: 1, Type: EntryBootstrap, Data: appendConfState(nil, cs)}
	hs := HardState{Term: 1}
	batch := PersistBatch{HardState: &hs, Entries: []Entry{entry}}
	if err := n.storage.Persist(batch); err != nil {
		return errs.Wrap(err, ErrStorage)
	}
	l, err := newLog(nil, []Entry{entry})
	if err != nil {
		return err
	}
	n.log = l
	n.confBase = newMembership(nil, nil, nil)
	n.confBaseIndex = 0
	n.conf = conf
	n.confHistory = []confVersion{{index: 1, conf: conf}}
	n.term = 1
	n.termAtomic.Store(1)
	n.committed = 0
	n.applied.Store(0)
	n.lastSnapshot.Store(0)
	n.sentApplied = 0
	n.persistedIndex = 1
	n.state = StateFollower
	n.stateAtomic.Store(uint32(StateFollower))
	n.resetElection()
	return nil
}

// replayConfig replays bootstrap and membership entries after the snapshot base.
// | replayConfig 重放快照基点之后的引导与成员日志项。
func (n *Node) replayConfig(entries []Entry) error {
	conf := n.confBase
	jointIndex := n.jointIndex
	for i := range entries {
		e := &entries[i]
		switch e.Type {
		case EntryBootstrap:
			cs, err := decodeConfStateBytes(e.Data)
			if err != nil {
				return err
			}
			conf = newMembershipFromState(cs)
			jointIndex = 0
		case EntryConfChange:
			cc, err := decodeConfChange(e.Data)
			if err != nil {
				return err
			}
			next, err := conf.apply(cc)
			if err != nil {
				return errs.Wrap(err, ErrCorrupt)
			}
			if !conf.joint() && next.joint() {
				jointIndex = e.Index
			}
			if !next.joint() {
				jointIndex = 0
			}
			conf = next
		default:
			continue
		}
		n.confHistory = append(n.confHistory, confVersion{index: e.Index, conf: conf, jointIndex: jointIndex})
	}
	n.conf = conf
	n.jointIndex = jointIndex
	return nil
}

// configAt returns the configuration as of index. | configAt 返回截至 index 的配置。
func (n *Node) configAt(index uint64) *membership {
	conf := n.confBase
	for i := range n.confHistory {
		if n.confHistory[i].index > index {
			break
		}
		conf = n.confHistory[i].conf
	}
	return conf
}

// truncateConfig drops configuration versions at or after index and restores
// the configuration of the surviving log. | truncateConfig 删除 index 及之后的配置
// 版本，并恢复幸存日志对应的配置。
func (n *Node) truncateConfig(index uint64) {
	before := len(n.confHistory)
	cut := len(n.confHistory)
	for i := range n.confHistory {
		if n.confHistory[i].index >= index {
			cut = i
			break
		}
	}
	n.confHistory = n.confHistory[:cut]
	if cut == 0 {
		n.conf = n.confBase
		n.jointIndex = 0
	} else {
		v := n.confHistory[cut-1]
		n.conf = v.conf
		n.jointIndex = v.jointIndex
	}
	if n.conf.joint() && n.jointIndex == 0 {
		n.jointIndex = n.confBaseIndex
	}
	if cut < before && n.cfg.OnConfChange != nil {
		n.cfg.OnConfChange(n.conf.confState())
	}
}

// appendConfig applies membership entries that just entered the log. | appendConfig
// 应用刚刚进入日志的成员变更项。
func (n *Node) appendConfig(entries []Entry, from uint64) error {
	conf := n.conf
	jointIndex := n.jointIndex
	for i := range entries {
		e := &entries[i]
		if e.Index < from {
			continue
		}
		switch e.Type {
		case EntryBootstrap:
			cs, err := decodeConfStateBytes(e.Data)
			if err != nil {
				return err
			}
			conf = newMembershipFromState(cs)
			jointIndex = 0
		case EntryConfChange:
			cc, err := decodeConfChange(e.Data)
			if err != nil {
				return err
			}
			next, err := conf.apply(cc)
			if err != nil {
				return errs.Wrap(err, ErrCorrupt)
			}
			if !conf.joint() && next.joint() {
				jointIndex = e.Index
			}
			if !next.joint() {
				jointIndex = 0
			}
			conf = next
		default:
			continue
		}
		n.confHistory = append(n.confHistory, confVersion{index: e.Index, conf: conf, jointIndex: jointIndex})
	}
	n.conf = conf
	n.jointIndex = jointIndex
	n.updateProgressForConfig()
	n.updatePeerAddresses()
	if n.cfg.OnConfChange != nil {
		// Membership entries take effect as soon as they enter the log, on
		// followers as well as the leader. | 成员变更项进入日志即生效，跟随者与
		// 领导者同样如此。
		changed := false
		for i := range entries {
			if entries[i].Index >= from && (entries[i].Type == EntryBootstrap || entries[i].Type == EntryConfChange) {
				changed = true
				break
			}
		}
		if changed {
			n.cfg.OnConfChange(n.conf.confState())
		}
	}
	return nil
}

// updateProgressForConfig adds progress for new members and removes it for
// members that left the configuration. | updateProgressForConfig 为新成员添加进度，
// 并移除已离开配置成员的进度。
func (n *Node) updateProgressForConfig() {
	if n.state != StateLeader {
		return
	}
	live := make(map[NodeID]struct{}, len(n.conf.voters)+len(n.conf.learners)+len(n.conf.votersOut)+len(n.conf.learnersOut))
	for id := range n.conf.voters {
		live[id] = struct{}{}
	}
	for id := range n.conf.learners {
		live[id] = struct{}{}
	}
	for id := range n.conf.votersOut {
		live[id] = struct{}{}
	}
	for id := range n.conf.learnersOut {
		live[id] = struct{}{}
	}
	for _, id := range n.pendingRemoval {
		live[id] = struct{}{}
	}
	for id := range live {
		if _, ok := n.progress[id]; ok {
			continue
		}
		n.progress[id] = newProgress(n.log.lastIndex+1, n.maxInflightMsgs, n.maxInflightBytes)
	}
	for id := range n.progress {
		if _, ok := live[id]; ok {
			continue
		}
		if id == n.id {
			continue
		}
		delete(n.progress, id)
	}
}

// updatePeerAddresses pushes the current address directory into the transport.
// | updatePeerAddresses 将当前地址目录推送到传输层。
func (n *Node) updatePeerAddresses() {
	if n.transport == nil {
		return
	}
	for id, addr := range n.conf.addrs {
		if id == n.id || addr == "" {
			continue
		}
		n.transport.UpdatePeer(id, addr)
	}
}

// singleVoter reports whether this node is the only voter. | singleVoter 报告本节点
// 是否为唯一投票成员。
func (n *Node) singleVoter() bool {
	return len(n.conf.voters) == 1 && len(n.conf.votersOut) == 0 &&
		n.conf.isVoter(n.id) && len(n.conf.learners) == 0
}

// setState updates the role and notifies the observer. | setState 更新角色并通知观察者。
func (n *Node) setState(next State) {
	prev := n.state
	if prev == next {
		return
	}
	n.state = next
	n.stateAtomic.Store(uint32(next))
	if n.cfg.OnStateChange != nil {
		n.cfg.OnStateChange(prev, next)
	}
	if next != StateLeader {
		n.transferActive.Store(false)
	}
}

// setTerm updates the term and its atomic mirror. | setTerm 更新任期及其原子镜像。
func (n *Node) setTerm(term uint64) {
	if n.term != term {
		n.metrics.termChanges.Add(1)
	}
	n.term = term
	n.termAtomic.Store(term)
}

// setLeader updates the leader and its atomic mirror. | setLeader 更新领导者及其原子
// 镜像。
func (n *Node) setLeader(leader NodeID) {
	n.leader = leader
	n.leaderAtomic.Store(uint64(leader))
}

// setCommitted updates the commit index and its atomic mirror. | setCommitted 更新
// 提交索引及其原子镜像。
func (n *Node) setCommitted(index uint64) {
	if index > n.committed {
		n.committed = index
		n.commitAtomic.Store(index)
	}
}

// Step enqueues an inbound message. It is the Transport handler and is safe for
// concurrent use. Invalid messages are dropped. | Step 入站消息入队。它是 Transport
// 处理器且可并发调用；非法消息会被丢弃。
func (n *Node) Step(m Message) {
	if n.stopped.Load() || m.To != n.id || m.From == 0 || m.Group != n.group {
		return
	}
	if m.Type < MsgHup || m.Type > maxMessageType {
		return
	}
	// MsgHup is a local event, not a network message. Accepting it here would let
	// any peer that can reach the Raft port force elections and inflate terms.
	// Local campaigns use campaignCh. | MsgHup 是本地事件而非网络消息。在此接受它
	// 会让任何能访问 Raft 端口的对端强制发起选举并膨胀任期；本地竞选走 campaignCh。
	if m.Type == MsgHup {
		n.metrics.messagesDropped.Add(1)
		return
	}
	n.metrics.messagesIn.Add(1)
	if isControlMessage(m.Type) {
		select {
		case n.controlCh <- m:
		default:
			n.metrics.messagesDropped.Add(1)
		}
		return
	}
	select {
	case n.recvCh <- m:
	default:
		n.metrics.messagesDropped.Add(1)
	}
}

// State returns the current role. | State 返回当前角色。
func (n *Node) State() State { return State(n.stateAtomic.Load()) }

// Term returns the current term. | Term 返回当前任期。
func (n *Node) Term() uint64 { return n.termAtomic.Load() }

// Leader returns the current leader, or 0 when unknown. | Leader 返回当前领导者，
// 未知时为 0。
func (n *Node) Leader() NodeID { return NodeID(n.leaderAtomic.Load()) }

// Commit returns the highest committed log index. | Commit 返回最高已提交日志索引。
func (n *Node) Commit() uint64 { return n.commitAtomic.Load() }

// Applied returns the highest applied log index. | Applied 返回最高已应用日志索引。
func (n *Node) Applied() uint64 { return n.applied.Load() }

// Stats returns a snapshot of node counters. Transport-level drops are merged
// from transports that expose them. | Stats 返回节点计数器快照。暴露计数的传输层
// 会合并其丢弃计数。
func (n *Node) Stats() Stats {
	st := n.metrics.snapshot()
	if reporter, ok := n.transport.(interface{ Drops() uint64 }); ok {
		st.TransportDrops = reporter.Drops()
	}
	return st
}

// ID returns the local node identifier. | ID 返回本地节点标识。
func (n *Node) ID() NodeID { return n.id }

// logf emits a structured lifecycle log when a logger is configured. | logf 在配置
// 日志器时输出结构化生命周期日志。
func (n *Node) logf(level string, msg string, fields ...ydlog.Field) {
	if n.logger == nil {
		return
	}
	switch level {
	case "warn":
		n.logger.Warn(msg, fields...)
	case "error":
		n.logger.Error(msg, fields...)
	default:
		n.logger.Info(msg, fields...)
	}
}

// fatal records an unrecoverable error and wakes the event loop. | fatal 记录不可恢复
// 错误并唤醒事件循环。
func (n *Node) fatal(err error) {
	if err == nil {
		return
	}
	n.fatalMu.Lock()
	if n.fatalErr == nil {
		n.fatalErr = err
	}
	n.fatalMu.Unlock()
	select {
	case n.fatalCh <- err:
	default:
	}
}

// Err returns the unrecoverable error that stopped the node, if any. | Err 返回导致
// 节点停止的不可恢复错误（若有）。
func (n *Node) Err() error {
	n.fatalMu.Lock()
	defer n.fatalMu.Unlock()
	return n.fatalErr
}

// Close stops the node, closes its transport and storage, and waits for all
// internal goroutines. The FSM must not block Apply forever. | Close 停止节点，关闭
// 传输与存储，并等待所有内部协程。FSM 不得永久阻塞 Apply。
func (n *Node) Close() error {
	n.closeOnce.Do(func() {
		n.stopped.Store(true)
		n.stateAtomic.Store(uint32(StateShutdown))
		n.stop()
		<-n.doneCh
		_ = n.transport.Close()
		n.wg.Wait()
		n.closeErr = n.storage.Close()
		n.futures.failAll(ErrStopped)
		close(n.closeDoneCh)
	})
	<-n.closeDoneCh
	return n.closeErr
}

// WaitReady blocks until the node knows a leader or ctx expires. It is
// convenient for clients that start together with the cluster. | WaitReady 阻塞到
// 节点已知领导者或 ctx 到期，适用于与集群一同启动的客户端。
func (n *Node) WaitReady(ctx context.Context) error {
	for {
		if n.Leader() != 0 || n.State() == StateLeader {
			return nil
		}
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-n.stopCh:
			return ErrStopped
		case <-time.After(n.tickInterval):
		}
	}
}
