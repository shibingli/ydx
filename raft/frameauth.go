package raft

import (
	"sync"
	"time"
)

// Frame freshness metadata is optional and HMAC-covered. A frame carries a
// wall-clock timestamp and a sender-wide monotonic counter; the receiver
// accepts it only when it is within the allowed clock window and newer than the
// last frame from that sender. Enabling it requires every peer to run a version
// that understands the auth flag; the default is off for wire compatibility. |
// 帧新鲜度元数据是可选的，并由 HMAC 覆盖。帧携带墙钟时间戳与发送方全局单调计数器；
// 接收方仅在接受窗口内且比该发送方上一帧更新时接受。启用它要求所有对端运行理解
// auth 标志的版本；为线格式兼容默认关闭。
type frameAuth struct {
	timestamp int64
	counter   uint64
}

const (
	// flagFrameAuth marks a frame whose payload starts with timestamp and
	// counter fields. | flagFrameAuth 标记负载以时间戳与计数器开头的帧。
	flagFrameAuth = 1 << 1
	// frameAuthLen is the encoded size of timestamp plus counter. |
	// frameAuthLen 是时间戳与计数器的编码长度。
	frameAuthLen = 16
)

// frameWatermark is the highest accepted (timestamp, counter) per sender. |
// frameWatermark 是每个发送方已接受的最高（时间戳、计数器）。
type frameWatermark struct {
	timestamp int64
	counter   uint64
	set       bool
}

// replayGuard enforces the freshness window and strict counter monotonicity.
// State is O(1) per sender; frames are serialized per peer by the transports,
// so an older frame is a replay rather than harmless reordering. | replayGuard
// 强制新鲜度窗口与严格计数器单调性。每个发送方 O(1) 状态；传输层按对端串行发送帧，
// 因此更旧的帧属于重放而非无害乱序。
type replayGuard struct {
	mu     sync.Mutex
	maxAge time.Duration
	now    func() time.Time
	peers  map[NodeID]frameWatermark
}

// newReplayGuard returns a guard for a positive acceptance window. |
// newReplayGuard 为正值接受窗口返回守卫。
func newReplayGuard(maxAge time.Duration) *replayGuard {
	return &replayGuard{
		maxAge: maxAge,
		now:    time.Now,
		peers:  make(map[NodeID]frameWatermark),
	}
}

// accept reports whether a frame is fresh and newer than the sender's last
// accepted frame. | accept 报告帧是否新鲜且比该发送方上一接受帧更新。
func (g *replayGuard) accept(id NodeID, auth *frameAuth) bool {
	if g == nil || g.maxAge <= 0 || auth == nil || id == 0 ||
		auth.timestamp <= 0 || auth.counter == 0 {
		return false
	}
	now := g.now().UnixNano()
	window := int64(g.maxAge)
	if auth.timestamp > now+window || auth.timestamp < now-window {
		return false
	}
	g.mu.Lock()
	defer g.mu.Unlock()
	last := g.peers[id]
	if last.set && (auth.timestamp < last.timestamp ||
		(auth.timestamp == last.timestamp && auth.counter <= last.counter)) {
		return false
	}
	g.peers[id] = frameWatermark{
		timestamp: auth.timestamp, counter: auth.counter, set: true,
	}
	return true
}
