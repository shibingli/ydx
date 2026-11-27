package raft

import (
	"sync"
	"time"
)

// Frame freshness metadata is optional and HMAC-covered. A frame carries a
// wall-clock timestamp, a sender-wide monotonic counter and a random
// incarnation ID. The timestamp is clamped forward by the sender so a backward
// clock step does not stall a connection; the receiver uses the timestamp only
// for the freshness window and ordered counter per incarnation for replay
// rejection. Enabling it requires every peer to understand the auth flag; the
// default is off for wire compatibility. | 帧新鲜度元数据可选且由 HMAC 覆盖。帧携带
// 墙钟时间戳、发送方全局单调计数器与随机 incarnation ID。发送方将时间戳钳制向前，
// 避免时钟回拨卡住连接；接收方只用时间戳判断新鲜度，并用同一 incarnation 内的计数器
// 顺序拒绝重放。启用要求所有对端理解 auth 标志；为线格式兼容默认关闭。
type frameAuth struct {
	timestamp   int64
	counter     uint64
	incarnation uint64
}

const (
	// flagFrameAuth marks a frame whose payload starts with timestamp, counter
	// and incarnation fields. | flagFrameAuth 标记负载以时间戳、计数器与
	// incarnation 开头的帧。
	flagFrameAuth = 1 << 1
	// frameAuthLen is the encoded size of timestamp, counter and incarnation. |
	// frameAuthLen 是时间戳、计数器与 incarnation 的编码长度。
	frameAuthLen = 24
	// maxReplayPeers bounds guard state created by frames that spoofed sender
	// IDs. Only shared-secret holders can reach this path, but the bound keeps a
	// compromised peer from growing the map without limit. | maxReplayPeers 限制
	// 伪造发送方 ID 创建的守卫状态。只有共享密钥持有者能到达该路径，但上限可避免
	// 失陷对端无界增长 map。
	maxReplayPeers = 4096
	// maxRetiredInvocations bounds remembered old incarnation IDs per sender. |
	// maxRetiredInvocations 限制每个发送方记住的旧 incarnation 数。
	maxRetiredInvocations = 32
)

// frameWatermark is the highest accepted counter for one sender incarnation. |
// frameWatermark 是一个发送方 incarnation 已接受的最高计数器。
type frameWatermark struct {
	timestamp   int64
	counter     uint64
	incarnation uint64
	set         bool
}

// replayGuard enforces the freshness window and counter monotonicity per
// sender incarnation. State is O(1) per sender plus a small retired-incarnation
// ring, so a sender restart cannot be confused with a replay and a clock step
// can never lower the ordering watermark. | replayGuard 按发送方 incarnation 强制
// 新鲜度窗口与计数器单调性。每个发送方 O(1) 状态加一个小的旧 incarnation 环，使
// 发送方重启不会被误判为重放，时钟回拨也不会降低顺序水位。
type replayGuard struct {
	mu      sync.Mutex
	maxAge  time.Duration
	now     func() time.Time
	peers   map[NodeID]frameWatermark
	retired map[NodeID][]uint64
}

// newIncarnation returns a non-zero incarnation ID for a transport process. |
// newIncarnation 为传输进程返回非零 incarnation ID。
func newIncarnation() uint64 {
	v := fastrand()
	if v == 0 {
		v = 1
	}
	return v
}

// newReplayGuard returns a guard for a positive acceptance window. |
// newReplayGuard 为正值接受窗口返回守卫。
func newReplayGuard(maxAge time.Duration) *replayGuard {
	return &replayGuard{
		maxAge:  maxAge,
		now:     time.Now,
		peers:   make(map[NodeID]frameWatermark),
		retired: make(map[NodeID][]uint64),
	}
}

// accept reports whether a frame is fresh and newer than the sender's current
// incarnation watermark. | accept 报告帧是否新鲜且比发送方当前 incarnation 的水位
// 更新。
func (g *replayGuard) accept(id NodeID, auth *frameAuth) bool {
	if g == nil || g.maxAge <= 0 || auth == nil || id == 0 ||
		auth.timestamp <= 0 || auth.counter == 0 || auth.incarnation == 0 {
		return false
	}
	now := g.now().UnixNano()
	window := int64(g.maxAge)
	if auth.timestamp > now+window || auth.timestamp < now-window {
		return false
	}
	g.mu.Lock()
	defer g.mu.Unlock()
	last, exists := g.peers[id]
	if !exists {
		g.insertLocked(id, frameWatermark{
			timestamp: auth.timestamp, counter: auth.counter,
			incarnation: auth.incarnation, set: true,
		})
		return true
	}
	if auth.incarnation == last.incarnation {
		if auth.counter <= last.counter {
			return false
		}
		last.counter = auth.counter
		if auth.timestamp > last.timestamp {
			last.timestamp = auth.timestamp
		}
		g.peers[id] = last
		return true
	}
	if g.retiredLocked(id, auth.incarnation) {
		return false
	}
	g.rememberLocked(id, last.incarnation)
	g.peers[id] = frameWatermark{
		timestamp: auth.timestamp, counter: auth.counter,
		incarnation: auth.incarnation, set: true,
	}
	return true
}

// retiredLocked reports whether an incarnation was already superseded. |
// retiredLocked 报告 incarnation 是否已被取代。
func (g *replayGuard) retiredLocked(id NodeID, incarnation uint64) bool {
	for _, old := range g.retired[id] {
		if old == incarnation {
			return true
		}
	}
	return false
}

// rememberLocked records a superseded incarnation with a bounded ring. |
// rememberLocked 用有界环记录被取代的 incarnation。
func (g *replayGuard) rememberLocked(id NodeID, incarnation uint64) {
	old := g.retired[id]
	old = append(old, incarnation)
	if len(old) > maxRetiredInvocations {
		old = old[len(old)-maxRetiredInvocations:]
	}
	g.retired[id] = old
}

// insertLocked inserts a new sender and evicts one entry when the bound is
// reached. | insertLocked 插入新发送方，达到上限时淘汰一个条目。
func (g *replayGuard) insertLocked(id NodeID, mark frameWatermark) {
	if len(g.peers) >= maxReplayPeers {
		for key := range g.peers {
			delete(g.peers, key)
			delete(g.retired, key)
			break
		}
	}
	g.peers[id] = mark
}
