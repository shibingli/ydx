package raft

import (
	"context"
	"sync"
	"sync/atomic"
	"time"

	"github.com/shibingli/ydx/errs"
)

// linkKey identifies one directed network link. | linkKey 标识一条有向网络链路。
type linkKey struct {
	from NodeID
	to   NodeID
}

// memRoute is an immutable routing view published for the delivery path. | memRoute
// 是发布给投递路径的不可变路由视图。
type memRoute struct {
	endpoints map[NodeID]*MemTransport
	blocked   map[linkKey]struct{}
	latency   time.Duration
	drop      func(from, to NodeID) bool
}

// MemNetwork is an in-process network for tests and benchmarks. It can drop,
// delay, partition and heal links without touching the Raft core. Routing uses
// an immutable snapshot so delivery takes no lock on the hot path. | MemNetwork
// 是用于测试与基准的进程内网络，可在不触碰 Raft 核心的情况下丢包、延迟、分区与恢复。
// 路由使用不可变快照，因此热路径投递不加锁。
type MemNetwork struct {
	mu        sync.Mutex
	endpoints map[NodeID]*MemTransport
	blocked   map[linkKey]struct{}
	latency   time.Duration
	drop      func(from, to NodeID) bool
	closed    bool
	route     atomic.Pointer[memRoute]
}

// NewMemNetwork returns an empty in-process network. | NewMemNetwork 返回空的进程内
// 网络。
func NewMemNetwork() *MemNetwork {
	n := &MemNetwork{
		endpoints: make(map[NodeID]*MemTransport),
		blocked:   make(map[linkKey]struct{}),
	}
	n.publishLocked()
	return n
}

// publishLocked publishes an immutable copy of the routing state. | publishLocked
// 发布路由状态的不可变副本。
func (n *MemNetwork) publishLocked() {
	route := &memRoute{
		endpoints: make(map[NodeID]*MemTransport, len(n.endpoints)),
		latency:   n.latency,
		drop:      n.drop,
	}
	for id, t := range n.endpoints {
		route.endpoints[id] = t
	}
	if len(n.blocked) > 0 {
		route.blocked = make(map[linkKey]struct{}, len(n.blocked))
		for key := range n.blocked {
			route.blocked[key] = struct{}{}
		}
	}
	n.route.Store(route)
}

// NewTransport registers and returns a transport for id. | NewTransport 注册并返回
// id 的传输。
func (n *MemNetwork) NewTransport(id NodeID) (*MemTransport, error) {
	if id == 0 {
		return nil, errs.Detail(ErrInvalidConfig, "transport ID must be non-zero")
	}
	n.mu.Lock()
	defer n.mu.Unlock()
	if n.closed {
		return nil, ErrStopped
	}
	if _, ok := n.endpoints[id]; ok {
		return nil, errs.Detail(ErrInvalidConfig, "transport %d already exists", id)
	}
	t := &MemTransport{
		id:    id,
		net:   n,
		inbox: make(chan Message, 16384),
		done:  make(chan struct{}),
	}
	n.endpoints[id] = t
	n.publishLocked()
	return t, nil
}

// SetLatency delays every delivered batch by d. Zero restores immediate delivery.
// | SetLatency 将每批投递延迟 d；零值恢复立即投递。
func (n *MemNetwork) SetLatency(d time.Duration) {
	n.mu.Lock()
	n.latency = d
	n.publishLocked()
	n.mu.Unlock()
}

// SetDropFunc installs a predicate evaluated for every message. It is intended
// for deterministic fault injection. | SetDropFunc 安装逐消息丢弃谓词，用于确定性
// 故障注入。
func (n *MemNetwork) SetDropFunc(fn func(from, to NodeID) bool) {
	n.mu.Lock()
	n.drop = fn
	n.publishLocked()
	n.mu.Unlock()
}

// Block drops every message from -> to. | Block 丢弃 from -> to 的所有消息。
func (n *MemNetwork) Block(from, to NodeID) {
	n.mu.Lock()
	n.blocked[linkKey{from: from, to: to}] = struct{}{}
	n.publishLocked()
	n.mu.Unlock()
}

// Unblock restores a blocked link. | Unblock 恢复被阻断的链路。
func (n *MemNetwork) Unblock(from, to NodeID) {
	n.mu.Lock()
	delete(n.blocked, linkKey{from: from, to: to})
	n.publishLocked()
	n.mu.Unlock()
}

// Partition splits the network into groups. Nodes in different groups cannot
// exchange messages; nodes omitted from every group are isolated. | Partition 将
// 网络分组。不同组之间不能通信；未出现在任何组中的节点被隔离。
func (n *MemNetwork) Partition(groups ...[]NodeID) {
	groupOf := make(map[NodeID]int)
	for i, group := range groups {
		for _, id := range group {
			groupOf[id] = i + 1
		}
	}
	n.mu.Lock()
	defer n.mu.Unlock()
	ids := make([]NodeID, 0, len(n.endpoints))
	for id := range n.endpoints {
		ids = append(ids, id)
	}
	for _, from := range ids {
		for _, to := range ids {
			if from == to {
				continue
			}
			gf, okf := groupOf[from]
			gt, okt := groupOf[to]
			if okf && okt && gf == gt {
				delete(n.blocked, linkKey{from: from, to: to})
				continue
			}
			n.blocked[linkKey{from: from, to: to}] = struct{}{}
		}
	}
	n.publishLocked()
}

// Heal restores every link. | Heal 恢复所有链路。
func (n *MemNetwork) Heal() {
	n.mu.Lock()
	n.blocked = make(map[linkKey]struct{})
	n.publishLocked()
	n.mu.Unlock()
}

// Close stops every transport on the network. | Close 停止网络中的所有传输。
func (n *MemNetwork) Close() {
	n.mu.Lock()
	if n.closed {
		n.mu.Unlock()
		return
	}
	n.closed = true
	list := make([]*MemTransport, 0, len(n.endpoints))
	for _, t := range n.endpoints {
		list = append(list, t)
	}
	n.endpoints = make(map[NodeID]*MemTransport)
	n.blocked = make(map[linkKey]struct{})
	n.publishLocked()
	n.mu.Unlock()
	for _, t := range list {
		t.close()
	}
}

// deliver routes one message, applying partition, drop and latency rules.
// | deliver 路由一条消息，并应用分区、丢弃与延迟规则。
func (n *MemNetwork) deliver(from NodeID, m Message) {
	route := n.route.Load()
	if route == nil {
		return
	}
	t := route.endpoints[m.To]
	if t == nil {
		return
	}
	if len(route.blocked) > 0 {
		if _, blocked := route.blocked[linkKey{from: from, to: m.To}]; blocked {
			return
		}
	}
	if drop := route.drop; drop != nil && drop(from, m.To) {
		return
	}
	if route.latency > 0 {
		time.AfterFunc(route.latency, func() { t.enqueue(m) })
		return
	}
	// Direct handoff removes one goroutine hop from the in-memory hot path.
	// The handler (Node.Step) only enqueues, so this cannot recurse into the
	// sender's event loop. Messages that arrived before Start still use the
	// inbox worker. | 直接交接移除内存热路径上的一次协程跳转。处理器（Node.Step）
	// 只入队，因此不会递归进入发送方事件循环。Start 之前到达的消息仍走收件箱
	// worker。
	if t.started.Load() {
		if h := t.handler.Load(); h != nil {
			(*h)(m)
			return
		}
	}
	t.enqueue(m)
}

// MemTransport is one endpoint on a MemNetwork. | MemTransport 是 MemNetwork 上的
// 一个端点。
type MemTransport struct {
	id      NodeID
	net     *MemNetwork
	inbox   chan Message
	done    chan struct{}
	handler atomic.Pointer[func(Message)]
	started atomic.Bool
	closed  atomic.Bool
	drops   atomic.Uint64
	once    sync.Once
}

// ID returns the endpoint identifier. | ID 返回端点标识。
func (t *MemTransport) ID() NodeID { return t.id }

// Start implements Transport. | Start 实现 Transport。
func (t *MemTransport) Start(handler func(Message)) error {
	if t.closed.Load() {
		return ErrStopped
	}
	h := handler
	t.handler.Store(&h)
	if t.started.CompareAndSwap(false, true) {
		go t.run()
	}
	return nil
}

// run delivers inbound messages to the handler. | run 将入站消息交给处理器。
func (t *MemTransport) run() {
	for {
		select {
		case <-t.done:
			return
		case m := <-t.inbox:
			if h := t.handler.Load(); h != nil {
				(*h)(m)
			}
		}
	}
}

// enqueue performs a non-blocking handoff. A full inbox is treated like packet
// loss; Raft retransmits. | enqueue 执行非阻塞交接。满队列视为丢包；Raft 会重传。
func (t *MemTransport) enqueue(m Message) {
	if t.closed.Load() {
		return
	}
	select {
	case t.inbox <- m:
	default:
		t.drops.Add(1)
	}
}

// Send implements Transport. | Send 实现 Transport。
func (t *MemTransport) Send(_ context.Context, msgs []Message) error {
	if t.closed.Load() {
		return ErrStopped
	}
	for i := range msgs {
		if msgs[i].To == 0 || msgs[i].To == t.id {
			continue
		}
		t.net.deliver(t.id, msgs[i])
	}
	return nil
}

// SendImmediate implements ImmediateTransport. | SendImmediate 实现
// ImmediateTransport。
func (t *MemTransport) SendImmediate() bool { return true }

// UpdatePeer implements Transport. Memory transports address by identifier.
// | UpdatePeer 实现 Transport。内存传输按标识寻址。
func (t *MemTransport) UpdatePeer(NodeID, string) {}

// Drops returns the number of messages dropped because the inbox was full.
// | Drops 返回因队列满而丢弃的消息数。
func (t *MemTransport) Drops() uint64 { return t.drops.Load() }

// Close implements Transport. | Close 实现 Transport。
func (t *MemTransport) Close() error {
	t.close()
	return nil
}

// close idempotently stops the endpoint. | close 幂等地停止端点。
func (t *MemTransport) close() {
	t.once.Do(func() {
		t.closed.Store(true)
		close(t.done)
		t.net.mu.Lock()
		if t.net.endpoints[t.id] == t {
			delete(t.net.endpoints, t.id)
		}
		t.net.mu.Unlock()
	})
}
