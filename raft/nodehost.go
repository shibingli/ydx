package raft

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/shibingli/ydx/errs"
	ydlog "github.com/shibingli/ydx/log"
)

// NodeHostConfig configures a multi-group NodeHost. | NodeHostConfig 配置多组
// NodeHost。
type NodeHostConfig struct {
	// Transport is the shared base transport. The host starts it with a group
	// multiplexer; do not start it yourself. | Transport 是共享基础传输。NodeHost
	// 会以组多路复用器启动它；请勿自行启动。
	Transport Transport
	// Storage creates the durable store for one group. | Storage 为一个组创建持久存储。
	Storage func(GroupID) (Storage, error)
	// FSM creates the state machine for one group. | FSM 为一个组创建状态机。
	FSM func(GroupID) (FSM, error)
	// Logger is shared by all groups. Nil disables lifecycle logging. | Logger 由
	// 所有组共享；nil 关闭生命周期日志。
	Logger *ydlog.Logger
	// ID is this host's member identifier; it is shared by every group. | ID 是本
	// 主机的成员标识，所有组共用。
	ID NodeID
}

// GroupConfig starts one Raft group. Zero tuning fields use Config defaults.
// | GroupConfig 启动一个 Raft 组。零值调优字段使用 Config 默认值。
type GroupConfig struct {
	Peers []Peer
	ID    GroupID

	TickInterval           time.Duration
	HeartbeatTicks         int
	ElectionTicks          int
	ElectionStagger        time.Duration
	PreVoteSubsetThreshold int
	PreVoteSubsetExtra     int
	MaxPendingReads        int
	MaxBatchEntries        int
	MaxBatchBytes          int
	MaxProposalBytes       int
	MaxInflightMsgs        int
	MaxInflightBytes       int
	SnapshotEntries        uint64
	SnapshotCatchUpEntries uint64
	SnapshotChunkBytes     int
	PersistBatchDelay      time.Duration
	ProposalQueue          int
	MessageQueue           int
	OutboundQueue          int
	Join                   bool
}

// groupNodeConfig converts GroupConfig into a Node Config template. | groupNodeConfig
// 将 GroupConfig 转换为 Node Config 模板。
func (g GroupConfig) groupNodeConfig(hostID NodeID, storage Storage, fsm FSM, transport Transport, logger *ydlog.Logger) Config {
	return Config{
		ID: hostID, Group: g.ID, Peers: g.Peers, Join: g.Join,
		Storage: storage, FSM: fsm, Transport: transport, Logger: logger,
		TickInterval:   g.TickInterval,
		HeartbeatTicks: g.HeartbeatTicks, ElectionTicks: g.ElectionTicks,
		ElectionStagger:        g.ElectionStagger,
		PreVoteSubsetThreshold: g.PreVoteSubsetThreshold,
		PreVoteSubsetExtra:     g.PreVoteSubsetExtra,
		MaxPendingReads:        g.MaxPendingReads,
		MaxBatchEntries:        g.MaxBatchEntries, MaxBatchBytes: g.MaxBatchBytes,
		MaxProposalBytes: g.MaxProposalBytes,
		MaxInflightMsgs:  g.MaxInflightMsgs, MaxInflightBytes: g.MaxInflightBytes,
		SnapshotEntries: g.SnapshotEntries, SnapshotCatchUpEntries: g.SnapshotCatchUpEntries,
		SnapshotChunkBytes: g.SnapshotChunkBytes,
		PersistBatchDelay:  g.PersistBatchDelay,
		ProposalQueue:      g.ProposalQueue, MessageQueue: g.MessageQueue,
		OutboundQueue: g.OutboundQueue,
	}
}

// Group is one running Raft group. | Group 是一个运行中的 Raft 组。
type Group struct {
	node      *Node
	transport *GroupTransport
	ID        GroupID
}

// Node returns the group's Raft node. | Node 返回该组的 Raft 节点。
func (g *Group) Node() *Node { return g.node }

// NodeHost runs many Raft groups on one member. All groups share the base
// transport and node identity, while each group has its own log, WAL, FSM,
// election state, snapshots and replication progress. | NodeHost 在一个成员上运行
// 多个 Raft 组。所有组共享基础传输与节点身份，但每个组拥有独立的日志、WAL、FSM、选举
// 状态、快照与复制进度。
type NodeHost struct {
	mux    *groupMux
	groups map[GroupID]*Group
	cfg    NodeHostConfig
	mu     sync.RWMutex
	closed bool
}

// NewNodeHost creates a host and starts the shared transport. | NewNodeHost 创建
// NodeHost 并启动共享传输。
func NewNodeHost(cfg NodeHostConfig) (*NodeHost, error) {
	if cfg.ID == 0 {
		return nil, errs.Detail(ErrInvalidConfig, "NodeHost ID must be non-zero")
	}
	if cfg.Transport == nil {
		return nil, errs.Detail(ErrInvalidConfig, "NodeHost Transport is required")
	}
	if cfg.Storage == nil || cfg.FSM == nil {
		return nil, errs.Detail(ErrInvalidConfig, "NodeHost Storage and FSM factories are required")
	}
	mux := newGroupMux(cfg.Transport)
	if err := cfg.Transport.Start(mux.dispatch); err != nil {
		_ = cfg.Transport.Close()
		return nil, errs.Wrap(err, ErrInvalidConfig)
	}
	return &NodeHost{cfg: cfg, mux: mux, groups: make(map[GroupID]*Group)}, nil
}

// StartGroup creates and starts one group. | StartGroup 创建并启动一个组。
func (h *NodeHost) StartGroup(cfg GroupConfig) (*Group, error) {
	if cfg.ID == 0 {
		return nil, errs.Detail(ErrInvalidConfig, "group ID must be non-zero")
	}
	h.mu.Lock()
	defer h.mu.Unlock()
	if h.closed {
		return nil, ErrStopped
	}
	if _, ok := h.groups[cfg.ID]; ok {
		return nil, errs.Detail(ErrInvalidConfig, "group %d already running", cfg.ID)
	}
	storage, err := h.cfg.Storage(cfg.ID)
	if err != nil {
		return nil, errs.Wrap(err, ErrStorage)
	}
	fsm, err := h.cfg.FSM(cfg.ID)
	if err != nil {
		_ = storage.Close()
		return nil, err
	}
	tr := &GroupTransport{mux: h.mux, group: cfg.ID}
	node, err := New(cfg.groupNodeConfig(h.cfg.ID, storage, fsm, tr, h.cfg.Logger))
	if err != nil {
		_ = tr.Close()
		_ = storage.Close()
		return nil, err
	}
	g := &Group{ID: cfg.ID, node: node, transport: tr}
	h.groups[cfg.ID] = g
	return g, nil
}

// StopGroup stops one group and closes its storage. The group entry is kept
// until Close completes so a concurrent StartGroup cannot open a second writer
// for the same storage. | StopGroup 停止一个组并关闭其存储。组条目保留到 Close
// 完成，避免并发 StartGroup 为同一存储打开第二个写入者。
func (h *NodeHost) StopGroup(id GroupID) error {
	h.mu.RLock()
	g := h.groups[id]
	h.mu.RUnlock()
	if g == nil {
		return errs.Detail(ErrUnknownGroup, "group %d", id)
	}
	err := g.node.Close()
	h.mu.Lock()
	if h.groups[id] == g {
		delete(h.groups, id)
	}
	h.mu.Unlock()
	return err
}

// Group returns a running group. | Group 返回运行中的组。
func (h *NodeHost) Group(id GroupID) (*Group, bool) {
	h.mu.RLock()
	g := h.groups[id]
	h.mu.RUnlock()
	return g, g != nil
}

// Groups returns the sorted running group IDs. | Groups 返回运行中的组 ID（有序）。
func (h *NodeHost) Groups() []GroupID {
	h.mu.RLock()
	out := make([]GroupID, 0, len(h.groups))
	for id := range h.groups {
		out = append(out, id)
	}
	h.mu.RUnlock()
	sort.Slice(out, func(i, j int) bool { return out[i] < out[j] })
	return out
}

// nodeFor resolves a group node. | nodeFor 解析组节点。
func (h *NodeHost) nodeFor(id GroupID) (*Node, error) {
	g, ok := h.Group(id)
	if !ok {
		return nil, errs.Detail(ErrUnknownGroup, "group %d", id)
	}
	return g.node, nil
}

// Propose appends a command to one group and waits for apply. | Propose 向一个组追加
// 命令并等待应用。
func (h *NodeHost) Propose(ctx context.Context, id GroupID, data []byte) (Result, error) {
	n, err := h.nodeFor(id)
	if err != nil {
		return Result{}, err
	}
	return n.Propose(ctx, data)
}

// ProposeAsync appends a command to one group. | ProposeAsync 向一个组追加命令。
func (h *NodeHost) ProposeAsync(ctx context.Context, id GroupID, data []byte) (*Future, error) {
	n, err := h.nodeFor(id)
	if err != nil {
		return nil, err
	}
	return n.ProposeAsync(ctx, data)
}

// ProposeOwned appends a command to one group without copying its data. | ProposeOwned
// 向一个组追加命令且不复制数据。
func (h *NodeHost) ProposeOwned(ctx context.Context, id GroupID, data []byte) (*Future, error) {
	n, err := h.nodeFor(id)
	if err != nil {
		return nil, err
	}
	return n.ProposeOwned(ctx, data)
}

// ReadIndex returns a linearizable read index for one group. | ReadIndex 返回一个组的
// 线性一致读索引。
func (h *NodeHost) ReadIndex(ctx context.Context, id GroupID) (uint64, error) {
	n, err := h.nodeFor(id)
	if err != nil {
		return 0, err
	}
	return n.ReadIndex(ctx)
}

// WaitApplied waits for one group's apply index. | WaitApplied 等待一个组的应用索引。
func (h *NodeHost) WaitApplied(ctx context.Context, id GroupID, index uint64) error {
	n, err := h.nodeFor(id)
	if err != nil {
		return err
	}
	return n.WaitApplied(ctx, index)
}

// Barrier performs a linearizable read barrier in one group. | Barrier 在一个组内执行
// 线性一致读屏障。
func (h *NodeHost) Barrier(ctx context.Context, id GroupID) error {
	n, err := h.nodeFor(id)
	if err != nil {
		return err
	}
	return n.Barrier(ctx)
}

// Status returns one group's status. | Status 返回一个组的状态。
func (h *NodeHost) Status(id GroupID) (Status, error) {
	n, err := h.nodeFor(id)
	if err != nil {
		return Status{}, err
	}
	return n.Status(), nil
}

// Stats returns one group's counters. | Stats 返回一个组的计数器。
func (h *NodeHost) Stats(id GroupID) (Stats, error) {
	n, err := h.nodeFor(id)
	if err != nil {
		return Stats{}, err
	}
	return n.Stats(), nil
}

// AddNode adds a voter to one group. | AddNode 向一个组增加投票成员。
func (h *NodeHost) AddNode(ctx context.Context, id GroupID, node NodeID, addr string) error {
	n, err := h.nodeFor(id)
	if err != nil {
		return err
	}
	return n.AddNode(ctx, node, addr)
}

// RemoveNode removes a member from one group. | RemoveNode 从一个组移除成员。
func (h *NodeHost) RemoveNode(ctx context.Context, id GroupID, node NodeID) error {
	n, err := h.nodeFor(id)
	if err != nil {
		return err
	}
	return n.RemoveNode(ctx, node)
}

// AddLearner adds a learner to one group. | AddLearner 向一个组增加学习者。
func (h *NodeHost) AddLearner(ctx context.Context, id GroupID, node NodeID, addr string) error {
	n, err := h.nodeFor(id)
	if err != nil {
		return err
	}
	return n.AddLearner(ctx, node, addr)
}

// Promote promotes a learner in one group. | Promote 在一个组内提升学习者。
func (h *NodeHost) Promote(ctx context.Context, id GroupID, node NodeID) error {
	n, err := h.nodeFor(id)
	if err != nil {
		return err
	}
	return n.Promote(ctx, node)
}

// TransferLeader transfers one group's leadership. | TransferLeader 转移一个组的
// 领导权。
func (h *NodeHost) TransferLeader(ctx context.Context, id GroupID, target NodeID) error {
	n, err := h.nodeFor(id)
	if err != nil {
		return err
	}
	return n.TransferLeader(ctx, target)
}

// Campaign forces one group to campaign. | Campaign 强制一个组竞选。
func (h *NodeHost) Campaign(ctx context.Context, id GroupID) error {
	n, err := h.nodeFor(id)
	if err != nil {
		return err
	}
	return n.Campaign(ctx)
}

// Snapshot captures one group's state machine. | Snapshot 捕获一个组的状态机。
func (h *NodeHost) Snapshot(ctx context.Context, id GroupID) error {
	n, err := h.nodeFor(id)
	if err != nil {
		return err
	}
	return n.Snapshot(ctx)
}

// Close stops every group and closes the shared transport. Close is idempotent.
// | Close 停止所有组并关闭共享传输。Close 幂等。
func (h *NodeHost) Close() error {
	h.mu.Lock()
	if h.closed {
		h.mu.Unlock()
		return nil
	}
	h.closed = true
	groups := make([]*Group, 0, len(h.groups))
	for _, g := range h.groups {
		groups = append(groups, g)
	}
	h.groups = make(map[GroupID]*Group)
	h.mu.Unlock()
	var joined []error
	for _, g := range groups {
		if err := g.node.Close(); err != nil {
			joined = append(joined, err)
		}
	}
	if err := h.cfg.Transport.Close(); err != nil {
		joined = append(joined, err)
	}
	return errors.Join(joined...)
}

// GroupDir returns the conventional directory for one group. | GroupDir 返回一个组的
// 约定目录。
func GroupDir(baseDir string, id GroupID) string {
	return filepath.Join(baseDir, "group-"+strconv.FormatUint(uint64(id), 10))
}

// FileStorageFactory creates one FileStorage per group below baseDir. | FileStorageFactory
// 在 baseDir 下为每个组创建 FileStorage。
func FileStorageFactory(baseDir string, opts FileStorageOptions) func(GroupID) (Storage, error) {
	return func(id GroupID) (Storage, error) {
		o := opts
		o.Dir = GroupDir(baseDir, id)
		return NewFileStorage(o)
	}
}

// ListGroups scans baseDir for group-<id> directories. It is used to recover
// every persisted group after a restart. | ListGroups 扫描 baseDir 下的 group-<id>
// 目录，用于重启后恢复所有已持久化组。
func ListGroups(baseDir string) ([]GroupID, error) {
	entries, err := os.ReadDir(baseDir)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return nil, nil
		}
		return nil, errs.Wrap(err, ErrStorage)
	}
	var ids []GroupID
	for _, entry := range entries {
		if !entry.IsDir() || !strings.HasPrefix(entry.Name(), "group-") {
			continue
		}
		raw := strings.TrimPrefix(entry.Name(), "group-")
		id, err := strconv.ParseUint(raw, 10, 64)
		if err != nil || id == 0 {
			continue
		}
		ids = append(ids, GroupID(id))
	}
	sort.Slice(ids, func(i, j int) bool { return ids[i] < ids[j] })
	return ids, nil
}
