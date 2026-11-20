package raft

import "math"

// maxCounter bounds every term and index accepted from a peer or persisted in a
// log. It stays well below the uint64 overflow point so term+1, index+1 and
// size conversions cannot wrap; no realistic Raft term or log index approaches
// it. | maxCounter 限制从对端接受或写入日志的每个任期与索引，远低于 uint64 溢出点，
// 使 term+1、index+1 与尺寸转换都不会回绕；现实中的 Raft 任期与日志索引远达不到该
// 值。
const maxCounter uint64 = math.MaxInt64

// isLeaderRequest reports whether only the leader of the message's term may send
// this type. | isLeaderRequest 报告该类型是否只允许该任期的领导者发送。
func isLeaderRequest(t MessageType) bool {
	switch t {
	case MsgApp, MsgHeartbeat, MsgSnap, MsgSnapChunk:
		return true
	default:
		return false
	}
}

// validInbound checks numeric bounds at the ingress boundary, before a message
// is queued or can reach a handler. Poisoned counters such as MaxUint64 and a
// snapshot term ahead of its carrying message are dropped here so no index,
// term or snapshot position can overflow or poison the log. | validInbound 在入口
// 边界、消息入队或到达处理器之前检查数值边界。MaxUint64 之类的毒化计数以及高于承载
// 消息任期的快照任期在此丢弃，任何索引、任期或快照位置都不会溢出或污染日志。
func validInbound(m *Message) bool {
	if m.Term > maxCounter || m.Index > maxCounter || m.LogIndex > maxCounter ||
		m.LogTerm > maxCounter || m.Commit > maxCounter ||
		m.RejectHint > maxCounter || m.RejectTerm > maxCounter {
		return false
	}
	if m.Type == MsgApp {
		// Entries must stay contiguous and inside the bounded range. The wire
		// decoder enforces this for encoded frames; custom in-process transports
		// can bypass it and would otherwise be able to inject gaps or poisoned
		// indexes. | 日志项必须连续且位于有界区间内。线格式解码器会为编码帧强制该约束；
		// 自定义进程内传输可绕过它，否则就能注入缺口或被毒化的索引。
		prev := m.LogIndex
		for i := range m.Entries {
			e := &m.Entries[i]
			if e.Index == 0 || e.Index > maxCounter || e.Term == 0 || e.Term > maxCounter ||
				e.Index != prev+1 {
				return false
			}
			prev = e.Index
		}
	}
	if s := m.Snapshot; s != nil {
		if s.Index == 0 || s.Index > maxCounter || s.Term == 0 || s.Term > maxCounter ||
			s.Term > m.Term {
			return false
		}
	}
	return true
}

// acceptSender validates the peer identity before a message can change local
// state. A sender must be a current member, and leader-only requests must come
// from the leader of their term; a lower term is stale and a second leader in
// the local leader's term is a protocol violation. A brand-new Join node has no
// configuration yet and must still accept the leader request that installs its
// first one. | acceptSender 在消息可改变本地状态前校验对端身份。发送者必须是当前
// 成员，且仅领导者可发送的请求必须来自其任期的领导者；更低任期已过期，与本地领导者同
// 任期的第二个领导者属于协议违规。全新 Join 节点尚无配置，仍需接受安装首份配置的
// 领导者请求。
func (n *Node) acceptSender(m *Message) bool {
	if m.From == n.id {
		// A node never sends to itself; a self-addressed frame is spoofing. |
		// 节点从不向自身发送消息；发往自身的帧属于伪造。
		return false
	}
	if !n.senderAllowed(m.From) {
		if n.conf == nil || !n.conf.empty() || !isLeaderRequest(m.Type) {
			return false
		}
	}
	if !isLeaderRequest(m.Type) {
		return true
	}
	if m.Term > n.term {
		// A higher term starts a new leadership epoch. The handler performs the
		// standard follower transition and installs the sender as leader. |
		// 更高任期开启新的领导纪元；处理器执行标准跟随者转换并安装发送者为领导者。
		return true
	}
	if m.Term < n.term {
		return false
	}
	if n.state == StateLeader {
		return false
	}
	// A follower or candidate that already knows the leader accepts only that
	// leader. With no known leader in this term, the request is the first contact
	// with the elected leader and must be accepted so the follower can learn it.
	// | 已知领导者的跟随者或候选者只接受该领导者。本任期尚无已知领导者时，该请求是与
	// 胜选者的首次接触，必须接受以便跟随者获知领导者。
	return n.leader == 0 || n.leader == m.From
}

// senderAllowed reports whether id is a current member. An injected
// Config.senderFilter takes precedence, letting tests exercise alternative
// membership views without a full cluster. | senderAllowed 报告 id 是否为当前成员。
// 注入的 Config.senderFilter 优先，使测试无需完整集群即可验证其他成员视图。
func (n *Node) senderAllowed(id NodeID) bool {
	if f := n.cfg.senderFilter; f != nil {
		return f(id)
	}
	return n.conf != nil && n.conf.isMember(id)
}

// validateAppendConfig simulates the membership transitions carried by one
// AppendEntries request. A peer-supplied bootstrap or ConfChange entry that
// cannot be decoded or applied is rejected before the term, log or configuration
// changes, so invalid input can never stop the node. | validateAppendConfig 模拟
// 一条 AppendEntries 请求携带的成员转换。无法解码或应用的对端引导/ConfChange 日志项
// 会在任期、日志或配置改变前被拒绝，非法输入因此永远不会让节点停机。
func (n *Node) validateAppendConfig(m *Message) error {
	if len(m.Entries) == 0 || n.conf == nil || n.log == nil {
		return nil
	}
	if m.LogIndex < n.log.snapshotIndex {
		// The log can no longer verify this predecessor; maybeAppend reports a
		// conflict without applying entries. | 日志已无法校验该前驱；maybeAppend 会
		// 报告冲突且不应用日志项。
		return nil
	}
	if m.LogIndex > n.log.lastIndex || n.log.mustTerm(m.LogIndex) != m.LogTerm {
		// The consistency check rejects this request before applying anything. |
		// 一致性检查会在应用任何日志项前拒绝该请求。
		return nil
	}
	// Find the first entry that would actually be applied. Earlier entries match
	// the local log and are skipped by appendConfig. | 找到第一条真正会被应用的日志
	// 项；更早的日志项与本地日志一致，appendConfig 会跳过。
	start := len(m.Entries)
	conflict := false
	for i := range m.Entries {
		e := &m.Entries[i]
		if e.Index <= n.log.lastIndex {
			if n.log.mustTerm(e.Index) == e.Term {
				continue
			}
			start = i
			conflict = true
			break
		}
		if e.Index != n.log.lastIndex+1 {
			// A gap cannot be applied; maybeAppend reports a conflict instead. |
			// 缺口无法应用；maybeAppend 会改为报告冲突。
			return nil
		}
		start = i
		break
	}
	if start == len(m.Entries) {
		return nil
	}
	conf := n.conf
	if conflict {
		// A conflicting suffix is truncated before its replacement is applied, so
		// validation must start from the configuration before the conflict. |
		// 冲突后缀会在替换项应用前被截断，因此校验必须从冲突位置之前的配置开始。
		if index := m.Entries[start].Index; index > 0 {
			conf = n.configAt(index - 1)
		}
	}
	if conf == nil {
		return nil
	}
	for i := start; i < len(m.Entries); i++ {
		e := &m.Entries[i]
		switch e.Type {
		case EntryBootstrap:
			cs, err := decodeConfStateBytes(e.Data)
			if err != nil {
				return err
			}
			if err := validateConfState(cs); err != nil {
				return err
			}
			conf = newMembershipFromState(cs)
		case EntryConfChange:
			cc, err := decodeConfChange(e.Data)
			if err != nil {
				return err
			}
			next, err := conf.apply(cc)
			if err != nil {
				return err
			}
			conf = next
		}
	}
	return nil
}
