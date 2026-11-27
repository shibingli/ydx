package raft

import (
	"context"
	"sync"
	"sync/atomic"

	"github.com/shibingli/ydx/errs"
)

// groupMux multiplexes one base transport across Raft groups. Dispatch reads an
// immutable handler snapshot so the per-message path takes no lock; membership
// changes are rare and copy-on-write. | groupMux 将一条基础传输复用到多个 Raft 组。
// 分发读取不可变处理器快照，因此逐消息路径不加锁；成员变化很少，采用写时复制。
type groupMux struct {
	base     Transport
	handlers map[GroupID]func(Message)
	snapshot atomic.Pointer[map[GroupID]func(Message)]
	// refs records which groups still reference a peer address. The base
	// transport is host-scoped, so a peer is removed only after every group that
	// installed it has released it. | refs 记录仍引用某个对端地址的组。基础传输按
	// 主机共享，因此只有所有安装过该地址的组都释放后才移除对端。
	refs map[NodeID]map[GroupID]struct{}
	mu   sync.Mutex
}

// newGroupMux wraps a base transport. The caller must start base with dispatch as
// its inbound handler. | newGroupMux 包装基础传输。调用方必须以 dispatch 作为入站
// 处理器启动 base。
func newGroupMux(base Transport) *groupMux {
	m := &groupMux{
		base: base, handlers: make(map[GroupID]func(Message)),
		refs: make(map[NodeID]map[GroupID]struct{}),
	}
	m.publishLocked()
	return m
}

// updatePeer installs an address for one group and records its reference. |
// updatePeer 为一个组安装地址并记录引用。
func (m *groupMux) updatePeer(group GroupID, id NodeID, addr string) {
	if id == 0 || addr == "" {
		return
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	groups := m.refs[id]
	if groups == nil {
		groups = make(map[GroupID]struct{}, 2)
		m.refs[id] = groups
	}
	groups[group] = struct{}{}
	m.base.UpdatePeer(id, addr)
}

// removePeer releases one group's reference and removes the base peer only when
// no other group still uses it. | removePeer 释放一个组的引用；仅当没有其它组
// 仍使用该对端时才从基础传输移除。
func (m *groupMux) removePeer(group GroupID, id NodeID) {
	if id == 0 {
		return
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	groups := m.refs[id]
	if groups == nil {
		return
	}
	delete(groups, group)
	if len(groups) > 0 {
		return
	}
	delete(m.refs, id)
	if remover, ok := m.base.(PeerRemover); ok {
		remover.RemovePeer(id)
	}
}

// releaseGroupLocked drops every peer reference held by a stopped group. The
// caller must hold m.mu. | releaseGroupLocked 释放一个已停止组持有的全部对端引用；
// 调用方必须持有 m.mu。
func (m *groupMux) releaseGroupLocked(group GroupID) {
	for id, groups := range m.refs {
		delete(groups, group)
		if len(groups) > 0 {
			continue
		}
		delete(m.refs, id)
		if remover, ok := m.base.(PeerRemover); ok {
			remover.RemovePeer(id)
		}
	}
}

// publishLocked publishes an immutable copy of the handler map. | publishLocked
// 发布处理器映射的不可变副本。
func (m *groupMux) publishLocked() {
	next := make(map[GroupID]func(Message), len(m.handlers))
	for id, handler := range m.handlers {
		next[id] = handler
	}
	m.snapshot.Store(&next)
}

// dispatch routes one message to its group. | dispatch 将消息路由到所属组。
func (m *groupMux) dispatch(msg Message) {
	snapshot := m.snapshot.Load()
	if snapshot == nil {
		return
	}
	if h := (*snapshot)[msg.Group]; h != nil {
		h(msg)
	}
}

// register installs a group handler. | register 安装组处理器。
func (m *groupMux) register(id GroupID, handler func(Message)) error {
	if id == 0 || handler == nil {
		return errs.Detail(ErrInvalidConfig, "group ID and handler are required")
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	if _, ok := m.handlers[id]; ok {
		return errs.Detail(ErrInvalidConfig, "group %d already has a handler", id)
	}
	m.handlers[id] = handler
	m.publishLocked()
	return nil
}

// unregister removes a group handler. | unregister 移除组处理器。
func (m *groupMux) unregister(id GroupID) {
	m.mu.Lock()
	delete(m.handlers, id)
	m.releaseGroupLocked(id)
	m.publishLocked()
	m.mu.Unlock()
}

// GroupTransport is one group's view of a shared base transport. It stamps the
// group ID on outbound messages and registers an inbound handler with the mux.
// | GroupTransport 是某个组对共享基础传输的视图。它给发件打上组 ID，并向多路复用器
// 注册入站处理器。
type GroupTransport struct {
	mux   *groupMux
	group GroupID
}

// GroupID returns the group identifier. | GroupID 返回组标识。
func (t *GroupTransport) GroupID() GroupID { return t.group }

// Start implements Transport. | Start 实现 Transport。
func (t *GroupTransport) Start(handler func(Message)) error {
	return t.mux.register(t.group, handler)
}

// Send implements Transport. | Send 实现 Transport。
func (t *GroupTransport) Send(ctx context.Context, msgs []Message) error {
	for i := range msgs {
		msgs[i].Group = t.group
	}
	return t.mux.base.Send(ctx, msgs)
}

// SendImmediate implements ImmediateTransport. | SendImmediate 实现
// ImmediateTransport。
func (t *GroupTransport) SendImmediate() bool {
	if it, ok := t.mux.base.(ImmediateTransport); ok {
		return it.SendImmediate()
	}
	return false
}

// UpdatePeer implements Transport. Addresses are shared by all groups and
// reference-counted so one group's membership change cannot remove a host that
// another group still uses. | UpdatePeer 实现 Transport。地址由所有组共享，并按
// 引用计数管理，避免一个组的成员变更移除其它组仍在使用的对端。
func (t *GroupTransport) UpdatePeer(id NodeID, addr string) {
	t.mux.updatePeer(t.group, id, addr)
}

// RemovePeer implements PeerRemover. The shared base peer is removed only after
// every group releases it. | RemovePeer 实现 PeerRemover。只有所有组都释放后，
// 才从共享基础传输移除对端。
func (t *GroupTransport) RemovePeer(id NodeID) {
	t.mux.removePeer(t.group, id)
}

// PeerAddress implements PeerDirectory by forwarding to the shared base
// transport. | PeerAddress 通过共享基础传输实现 PeerDirectory。
func (t *GroupTransport) PeerAddress(id NodeID) (string, bool) {
	if dir, ok := t.mux.base.(PeerDirectory); ok {
		return dir.PeerAddress(id)
	}
	return "", false
}

// RequiresPeerAddresses implements PeerAddressTransport by forwarding to the
// shared base transport. | RequiresPeerAddresses 通过共享基础传输实现
// PeerAddressTransport。
func (t *GroupTransport) RequiresPeerAddresses() bool {
	if addr, ok := t.mux.base.(PeerAddressTransport); ok {
		return addr.RequiresPeerAddresses()
	}
	return false
}

// FrameLimit reports the shared transport's maximum encoded frame. | FrameLimit
// 返回共享传输的最大编码帧。
func (t *GroupTransport) FrameLimit() int64 {
	if limiter, ok := t.mux.base.(interface{ FrameLimit() int64 }); ok {
		return limiter.FrameLimit()
	}
	return 0
}

// Drops reports the shared transport's counted drops. | Drops 返回共享传输的丢弃
// 计数。
func (t *GroupTransport) Drops() uint64 {
	if reporter, ok := t.mux.base.(interface{ Drops() uint64 }); ok {
		return reporter.Drops()
	}
	return 0
}

// Close implements Transport. It only unregisters the group; the host owns the
// base transport. | Close 实现 Transport。它只注销组；基础传输由 NodeHost 持有。
func (t *GroupTransport) Close() error {
	t.mux.unregister(t.group)
	return nil
}
