package raft

import "strings"

// NodeID identifies a Raft member. Zero is reserved and never valid. | NodeID
// 标识一个 Raft 成员；零值保留，永远不合法。
type NodeID uint64

// String renders the numeric identifier. | String 输出数字标识。
func (id NodeID) String() string {
	return uint64String(uint64(id))
}

// GroupID identifies one Raft group on a NodeHost. Zero is reserved for a
// standalone Node; NodeHost groups must be non-zero. | GroupID 标识 NodeHost 上的
// 一个 Raft 组。零保留给独立 Node；NodeHost 组必须非零。
type GroupID uint64

// String renders the numeric group identifier. | String 输出数字组标识。
func (id GroupID) String() string { return uint64String(uint64(id)) }

// Peer is a member identifier together with its transport address. | Peer 是成员
// 标识与其传输地址的组合。
type Peer struct {
	ID   NodeID
	Addr string
}

// EntryType classifies a log entry. The numeric values are part of the wire
// format and must not change. | EntryType 对日志项分类；数值属于线格式，不得修改。
type EntryType uint8

const (
	// EntryNormal carries an application command. | EntryNormal 携带应用命令。
	EntryNormal EntryType = iota
	// EntryConfChange carries a membership change. | EntryConfChange 携带成员变更。
	EntryConfChange
	// EntryNoop is appended by a new leader to commit earlier terms safely.
	// | EntryNoop 由新领导者追加，用于安全提交更早任期的日志。
	EntryNoop
	// EntryBootstrap carries the initial configuration of a new cluster.
	// | EntryBootstrap 携带新集群的初始配置。
	EntryBootstrap
)

// Entry is one replicated log record. Data is owned by the node after it is
// proposed; callers must not mutate it. | Entry 是一条复制日志记录。提案后 Data
// 归节点所有，调用方不得再修改。
type Entry struct {
	Index uint64
	Term  uint64
	Type  EntryType
	Data  []byte
}

// clone returns a deep copy used at API and recovery boundaries. | clone 返回深拷贝，
// 用于 API 与恢复边界。
func (e Entry) clone() Entry {
	if e.Data != nil {
		e.Data = append([]byte(nil), e.Data...)
	}
	return e
}

// size returns the approximate heap footprint used for batching and flow control.
// | size 返回用于批处理与流控的近似内存占用。
func (e Entry) size() int {
	return len(e.Data) + 48
}

// HardState is the durable part of Raft state that must survive a crash. Commit
// is persisted opportunistically to shorten recovery; safety does not depend on
// it. | HardState 是必须在崩溃后保留的 Raft 持久状态。Commit 会被机会性地持久化以
// 缩短恢复时间，安全性不依赖它。
type HardState struct {
	Term   uint64
	Vote   NodeID
	Commit uint64
}

// ConfState is the serializable membership view stored in snapshots and
// bootstrap entries. Addresses is a directory for every identifier that appears
// in the four sets. | ConfState 是快照与引导日志项中可序列化的成员视图。Addresses
// 是四个集合中出现的所有标识的地址目录。
type ConfState struct {
	Voters           []NodeID
	Learners         []NodeID
	VotersOutgoing   []NodeID
	LearnersOutgoing []NodeID
	Addresses        []Peer
}

// peer looks up an address in the directory. | peer 在地址目录中查询地址。
func (c ConfState) peer(id NodeID) (string, bool) {
	for i := range c.Addresses {
		if c.Addresses[i].ID == id {
			return c.Addresses[i].Addr, c.Addresses[i].Addr != ""
		}
	}
	return "", false
}

// contains reports whether id appears in ids. | contains 报告 id 是否出现在 ids 中。
func contains(ids []NodeID, id NodeID) bool {
	for _, v := range ids {
		if v == id {
			return true
		}
	}
	return false
}

// Snapshot is a point-in-time state machine image and the configuration that
// produced it. | Snapshot 是某一时刻的状态机镜像及其对应的配置。
type Snapshot struct {
	Index     uint64
	Term      uint64
	ConfState ConfState
	Data      []byte
}

// clone returns a deep copy of the snapshot. | clone 返回快照的深拷贝。
func (s *Snapshot) clone() *Snapshot {
	if s == nil {
		return nil
	}
	out := *s
	if s.Data != nil {
		out.Data = append([]byte(nil), s.Data...)
	}
	out.ConfState = s.ConfState.clone()
	return &out
}

// clone returns a deep copy of the configuration state. | clone 返回配置状态的深拷贝。
func (c ConfState) clone() ConfState {
	out := ConfState{
		Voters:           append([]NodeID(nil), c.Voters...),
		Learners:         append([]NodeID(nil), c.Learners...),
		VotersOutgoing:   append([]NodeID(nil), c.VotersOutgoing...),
		LearnersOutgoing: append([]NodeID(nil), c.LearnersOutgoing...),
		Addresses:        append([]Peer(nil), c.Addresses...),
	}
	return out
}

// State is the externally visible Raft role. | State 是外部可见的 Raft 角色。
type State uint8

const (
	// StateFollower receives entries from a leader. | StateFollower 从领导者接收日志。
	StateFollower State = iota
	// StatePreCandidate probes whether an election can win without bumping the
	// term. | StatePreCandidate 在不提升任期的情况下探测选举能否获胜。
	StatePreCandidate
	// StateCandidate is collecting votes. | StateCandidate 正在收集选票。
	StateCandidate
	// StateLeader replicates entries and serves writes. | StateLeader 复制日志并处理写请求。
	StateLeader
	// StateShutdown is reported after the node stops. | StateShutdown 表示节点已停止。
	StateShutdown
)

// String renders a stable role name. | String 输出稳定的角色名。
func (s State) String() string {
	switch s {
	case StateFollower:
		return "follower"
	case StatePreCandidate:
		return "pre-candidate"
	case StateCandidate:
		return "candidate"
	case StateLeader:
		return "leader"
	case StateShutdown:
		return "shutdown"
	default:
		return "unknown"
	}
}

// uint64String converts without importing strconv at every call site. | uint64String
// 避免在每个调用点导入 strconv。
func uint64String(v uint64) string {
	if v == 0 {
		return "0"
	}
	var buf [20]byte
	i := len(buf)
	for v > 0 {
		i--
		buf[i] = byte('0' + v%10)
		v /= 10
	}
	return string(buf[i:])
}

// joinIDs renders a sorted id list for diagnostics and tests. | joinIDs 为诊断与测试
// 渲染有序 id 列表。
func joinIDs(ids []NodeID) string {
	var b strings.Builder
	for i, id := range ids {
		if i > 0 {
			b.WriteByte(',')
		}
		b.WriteString(id.String())
	}
	return b.String()
}
