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
	mu       sync.Mutex
	handlers map[GroupID]func(Message)
	snapshot atomic.Pointer[map[GroupID]func(Message)]
}

// newGroupMux wraps a base transport. The caller must start base with dispatch as
// its inbound handler. | newGroupMux 包装基础传输。调用方必须以 dispatch 作为入站
// 处理器启动 base。
func newGroupMux(base Transport) *groupMux {
	m := &groupMux{base: base, handlers: make(map[GroupID]func(Message))}
	m.publishLocked()
	return m
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

// UpdatePeer implements Transport. Addresses are shared by all groups. | UpdatePeer
// 实现 Transport。地址由所有组共享。
func (t *GroupTransport) UpdatePeer(id NodeID, addr string) {
	t.mux.base.UpdatePeer(id, addr)
}

// Close implements Transport. It only unregisters the group; the host owns the
// base transport. | Close 实现 Transport。它只注销组；基础传输由 NodeHost 持有。
func (t *GroupTransport) Close() error {
	t.mux.unregister(t.group)
	return nil
}
