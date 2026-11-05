package raft

import (
	"slices"

	"github.com/shibingli/ydx/errs"
)

// ConfChangeType identifies a membership operation. Values are part of the log
// format and must not change. | ConfChangeType 标识成员操作；数值属于日志格式，
// 不得修改。
type ConfChangeType uint8

const (
	// ConfChangeAddNode adds a voting member. | ConfChangeAddNode 增加投票成员。
	ConfChangeAddNode ConfChangeType = iota + 1
	// ConfChangeRemoveNode removes a member. | ConfChangeRemoveNode 移除成员。
	ConfChangeRemoveNode
	// ConfChangeAddLearner adds a non-voting member. | ConfChangeAddLearner 增加不投票成员。
	ConfChangeAddLearner
	// ConfChangePromote turns a learner into a voter. | ConfChangePromote 将学习者提升为投票成员。
	ConfChangePromote
	// ConfChangeLeaveJoint commits the new configuration of a joint transition.
	// | ConfChangeLeaveJoint 提交联合过渡的新配置。
	ConfChangeLeaveJoint
)

// ConfChange is the command stored in an EntryConfChange log entry. | ConfChange
// 是 EntryConfChange 日志项中存储的命令。
type ConfChange struct {
	Type   ConfChangeType
	NodeID NodeID
	Addr   string
}

// membership is an immutable view of the cluster configuration. Joint consensus
// is represented by non-empty outgoing sets. | membership 是集群配置的不可变视图。
// 非空的 outgoing 集合表示联合共识（joint consensus）。
type membership struct {
	voters      map[NodeID]struct{}
	learners    map[NodeID]struct{}
	votersOut   map[NodeID]struct{}
	learnersOut map[NodeID]struct{}
	addrs       map[NodeID]string
}

// newMembership builds an empty or explicit configuration. | newMembership 构建空配置或
// 显式配置。
func newMembership(voters, learners []NodeID, addrs map[NodeID]string) *membership {
	m := &membership{
		voters:      make(map[NodeID]struct{}, len(voters)),
		learners:    make(map[NodeID]struct{}, len(learners)),
		votersOut:   make(map[NodeID]struct{}),
		learnersOut: make(map[NodeID]struct{}),
		addrs:       make(map[NodeID]string, len(addrs)),
	}
	for _, id := range voters {
		m.voters[id] = struct{}{}
	}
	for _, id := range learners {
		m.learners[id] = struct{}{}
	}
	for id, addr := range addrs {
		if addr != "" {
			m.addrs[id] = addr
		}
	}
	return m
}

// newMembershipFromState rebuilds a membership from a serialized view. | newMembershipFromState
// 从序列化视图重建配置。
func newMembershipFromState(cs ConfState) *membership {
	addrs := make(map[NodeID]string, len(cs.Addresses))
	for _, p := range cs.Addresses {
		if p.Addr != "" {
			addrs[p.ID] = p.Addr
		}
	}
	m := &membership{
		voters:      make(map[NodeID]struct{}, len(cs.Voters)),
		learners:    make(map[NodeID]struct{}, len(cs.Learners)),
		votersOut:   make(map[NodeID]struct{}, len(cs.VotersOutgoing)),
		learnersOut: make(map[NodeID]struct{}, len(cs.LearnersOutgoing)),
		addrs:       addrs,
	}
	for _, id := range cs.Voters {
		m.voters[id] = struct{}{}
	}
	for _, id := range cs.Learners {
		m.learners[id] = struct{}{}
	}
	for _, id := range cs.VotersOutgoing {
		m.votersOut[id] = struct{}{}
	}
	for _, id := range cs.LearnersOutgoing {
		m.learnersOut[id] = struct{}{}
	}
	return m
}

// clone returns a mutable copy. Maps are never shared between configurations.
// | clone 返回可变副本；不同配置之间不共享 map。
func (m *membership) clone() *membership {
	if m == nil {
		return newMembership(nil, nil, nil)
	}
	out := &membership{
		voters:      make(map[NodeID]struct{}, len(m.voters)),
		learners:    make(map[NodeID]struct{}, len(m.learners)),
		votersOut:   make(map[NodeID]struct{}, len(m.votersOut)),
		learnersOut: make(map[NodeID]struct{}, len(m.learnersOut)),
		addrs:       make(map[NodeID]string, len(m.addrs)),
	}
	for id := range m.voters {
		out.voters[id] = struct{}{}
	}
	for id := range m.learners {
		out.learners[id] = struct{}{}
	}
	for id := range m.votersOut {
		out.votersOut[id] = struct{}{}
	}
	for id := range m.learnersOut {
		out.learnersOut[id] = struct{}{}
	}
	for id, addr := range m.addrs {
		out.addrs[id] = addr
	}
	return out
}

// joint reports whether a joint transition is in progress. | joint 报告是否处于联合过渡中。
func (m *membership) joint() bool {
	return len(m.votersOut) != 0 || len(m.learnersOut) != 0
}

// isVoter reports whether id votes in any active configuration. | isVoter 报告 id
// 是否在任意生效配置中拥有投票权。
func (m *membership) isVoter(id NodeID) bool {
	_, in := m.voters[id]
	_, out := m.votersOut[id]
	return in || out
}

// isLearner reports whether id is a non-voting member. | isLearner 报告 id 是否为
// 不投票成员。
func (m *membership) isLearner(id NodeID) bool {
	_, in := m.learners[id]
	_, out := m.learnersOut[id]
	return in || out
}

// isMember reports whether id belongs to the configuration at all. | isMember
// 报告 id 是否属于配置。
func (m *membership) isMember(id NodeID) bool {
	return m.isVoter(id) || m.isLearner(id)
}

// addr returns the transport address for id. | addr 返回 id 的传输地址。
func (m *membership) addr(id NodeID) string {
	return m.addrs[id]
}

// ids returns the sorted identifiers of one set. | ids 返回某个集合的有序标识。
func ids(set map[NodeID]struct{}) []NodeID {
	out := make([]NodeID, 0, len(set))
	for id := range set {
		out = append(out, id)
	}
	slices.Sort(out)
	return out
}

// confState serializes the configuration deterministically. | confState 确定性地
// 序列化配置。
func (m *membership) confState() ConfState {
	cs := ConfState{
		Voters:           ids(m.voters),
		Learners:         ids(m.learners),
		VotersOutgoing:   ids(m.votersOut),
		LearnersOutgoing: ids(m.learnersOut),
	}
	seen := make(map[NodeID]struct{}, len(m.addrs))
	for _, list := range [][]NodeID{cs.Voters, cs.Learners, cs.VotersOutgoing, cs.LearnersOutgoing} {
		for _, id := range list {
			if _, ok := seen[id]; ok {
				continue
			}
			seen[id] = struct{}{}
			if addr := m.addrs[id]; addr != "" {
				cs.Addresses = append(cs.Addresses, Peer{ID: id, Addr: addr})
			}
		}
	}
	slices.SortFunc(cs.Addresses, func(a, b Peer) int {
		switch {
		case a.ID < b.ID:
			return -1
		case a.ID > b.ID:
			return 1
		default:
			return 0
		}
	})
	return cs
}

// majority reports whether acked covers a strict majority of set. | majority 报告
// acked 是否覆盖 set 的严格多数。
func majority(set map[NodeID]struct{}, acked func(NodeID) bool) bool {
	if len(set) == 0 {
		return false
	}
	need := len(set)/2 + 1
	count := 0
	for id := range set {
		if acked(id) {
			count++
			if count >= need {
				return true
			}
		}
	}
	return false
}

// hasQuorum reports whether acked covers a majority of every active voter set.
// | hasQuorum 报告 acked 是否覆盖每个生效投票集合的多数。
func (m *membership) hasQuorum(acked func(NodeID) bool) bool {
	if !majority(m.voters, acked) {
		return false
	}
	if len(m.votersOut) > 0 && !majority(m.votersOut, acked) {
		return false
	}
	return true
}

// quorumMatch returns the highest index replicated on a majority of every active
// voter set. scratch must have capacity for the larger set and is reused to keep
// commit checks allocation-free. | quorumMatch 返回在每个生效投票集合的多数节点上
// 都已复制的最高索引。scratch 需容纳较大集合，用于让提交检查零分配。
func (m *membership) quorumMatch(progress map[NodeID]*progress, self NodeID, selfMatch uint64, scratch []uint64) uint64 {
	in := setQuorumIndex(m.voters, progress, self, selfMatch, scratch)
	if len(m.votersOut) == 0 {
		return in
	}
	out := setQuorumIndex(m.votersOut, progress, self, selfMatch, scratch)
	if out < in {
		return out
	}
	return in
}

// setQuorumIndex returns the majority-replicated index for one voter set.
// | setQuorumIndex 返回单个投票集合的多数已复制索引。
func setQuorumIndex(set map[NodeID]struct{}, progress map[NodeID]*progress, self NodeID, selfMatch uint64, scratch []uint64) uint64 {
	if len(set) == 0 {
		return 0
	}
	idx := scratch[:0]
	for id := range set {
		if id == self {
			idx = append(idx, selfMatch)
			continue
		}
		if pr := progress[id]; pr != nil {
			idx = append(idx, pr.match)
		} else {
			idx = append(idx, 0)
		}
	}
	slices.Sort(idx)
	return idx[len(idx)-(len(set)/2+1)]
}

// apply returns the configuration produced by cc. It never mutates the receiver.
// | apply 返回 cc 产生的配置，不会修改接收者。
func (m *membership) apply(cc ConfChange) (*membership, error) {
	next := m.clone()
	switch cc.Type {
	case ConfChangeAddNode:
		if next.isMember(cc.NodeID) {
			return nil, errs.Detail(ErrInvalidConfig, "node %d already a member", cc.NodeID)
		}
		if next.joint() {
			return nil, errs.Detail(ErrConfChangeInProgress, "joint configuration")
		}
		next.votersOut = cloneSet(next.voters)
		next.learnersOut = cloneSet(next.learners)
		next.voters[cc.NodeID] = struct{}{}
		if cc.Addr != "" {
			next.addrs[cc.NodeID] = cc.Addr
		}
	case ConfChangeRemoveNode:
		if !next.isMember(cc.NodeID) {
			return nil, errs.Detail(ErrUnknownNode, "node %d", cc.NodeID)
		}
		if _, voter := next.voters[cc.NodeID]; voter {
			if next.joint() {
				return nil, errs.Detail(ErrConfChangeInProgress, "joint configuration")
			}
			if len(next.voters) <= 1 {
				return nil, errs.Detail(ErrInvalidConfig, "cannot remove the last voter")
			}
			next.votersOut = cloneSet(next.voters)
			next.learnersOut = cloneSet(next.learners)
			delete(next.voters, cc.NodeID)
		} else {
			delete(next.learners, cc.NodeID)
		}
		delete(next.addrs, cc.NodeID)
	case ConfChangeAddLearner:
		if next.isMember(cc.NodeID) {
			return nil, errs.Detail(ErrInvalidConfig, "node %d already a member", cc.NodeID)
		}
		if next.joint() {
			return nil, errs.Detail(ErrConfChangeInProgress, "joint configuration")
		}
		next.learners[cc.NodeID] = struct{}{}
		if cc.Addr != "" {
			next.addrs[cc.NodeID] = cc.Addr
		}
	case ConfChangePromote:
		if _, ok := next.learners[cc.NodeID]; !ok {
			return nil, errs.Detail(ErrUnknownNode, "node %d is not a learner", cc.NodeID)
		}
		if next.joint() {
			return nil, errs.Detail(ErrConfChangeInProgress, "joint configuration")
		}
		next.votersOut = cloneSet(next.voters)
		next.learnersOut = cloneSet(next.learners)
		delete(next.learners, cc.NodeID)
		next.voters[cc.NodeID] = struct{}{}
	case ConfChangeLeaveJoint:
		if !next.joint() {
			return nil, errs.Detail(ErrInvalidConfig, "not in a joint configuration")
		}
		if len(next.voters) == 0 {
			return nil, errs.Detail(ErrInvalidConfig, "new configuration has no voters")
		}
		next.votersOut = make(map[NodeID]struct{})
		next.learnersOut = make(map[NodeID]struct{})
	default:
		return nil, errs.Detail(ErrInvalidConfig, "unknown change type %d", cc.Type)
	}
	return next, nil
}

// cloneSet copies a membership set. | cloneSet 复制成员集合。
func cloneSet(src map[NodeID]struct{}) map[NodeID]struct{} {
	out := make(map[NodeID]struct{}, len(src))
	for id := range src {
		out[id] = struct{}{}
	}
	return out
}
