package raft

// This file owns the transport address directory: startup seeds, membership
// updates, and reclamation of removed members. | 本文件负责传输层地址目录：启动
// 种子、成员地址更新与已移除成员的回收。

// seedPeerAddresses installs the configured peer list into the transport before
// any membership address. A Join node has an empty configuration, so without
// this seed it cannot answer the leader that is adding it: over a real transport
// every reply would fail with ErrUnknownNode and catch-up could never start.
// The seed is only a transport directory entry; it never makes the node a
// member, and later membership addresses take precedence because
// updatePeerAddresses runs immediately after it. A transport that implements
// PeerDirectory keeps addresses installed explicitly or by another NodeHost
// group: the seed only fills missing entries instead of overwriting them. |
// seedPeerAddresses 在任何成员地址之前把配置中的对端列表安装到传输层。Join 节点的
// 配置为空；若没有该种子，它无法回复正在添加它的领导者：在真实传输上每次回复都会
// 因 ErrUnknownNode 失败，追赶永远不会开始。该种子只是传输层目录项，不会使节点成为
// 成员；由于 updatePeerAddresses 紧随其后运行，之后的成员地址会覆盖它。实现
// PeerDirectory 的传输会保留显式安装的或其它 NodeHost 组学到的地址：种子只填补
// 缺失项，不覆盖已有地址。
func (n *Node) seedPeerAddresses() {
	if n.transport == nil {
		return
	}
	dir, _ := n.transport.(PeerDirectory)
	for _, p := range n.cfg.Peers {
		if p.ID == 0 || p.ID == n.id || p.Addr == "" {
			continue
		}
		if dir != nil {
			if _, ok := dir.PeerAddress(p.ID); ok {
				continue
			}
		}
		n.transport.UpdatePeer(p.ID, p.Addr)
	}
}

// removeTransportPeer releases one departed member's transport state. | removeTransportPeer
// 释放一个已离开成员的传输层状态。
func (n *Node) removeTransportPeer(id NodeID) {
	if n.transport == nil || id == n.id || id == 0 {
		return
	}
	if remover, ok := n.transport.(PeerRemover); ok {
		remover.RemovePeer(id)
	}
}

// removeDepartedPeers releases transport entries for members that disappeared
// between two configurations. Followers call it as soon as a configuration
// enters the log; the leader defers removals until the final configuration
// commits so a removed member can still learn that it left. | removeDepartedPeers
// 释放两份配置之间消失成员的传输条目。跟随者在配置进入日志时立即调用；领导者推迟到
// 最终配置提交后再移除，使被移除成员仍能得知自己已离开。
func (n *Node) removeDepartedPeers(old, next *membership) {
	if old == nil || next == nil {
		return
	}
	seen := make(map[NodeID]struct{}, len(old.voters)+len(old.learners))
	for _, set := range []map[NodeID]struct{}{old.voters, old.learners, old.votersOut, old.learnersOut} {
		for id := range set {
			if _, ok := seen[id]; ok {
				continue
			}
			seen[id] = struct{}{}
			if id == n.id || next.isMember(id) {
				continue
			}
			n.removeTransportPeer(id)
		}
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
