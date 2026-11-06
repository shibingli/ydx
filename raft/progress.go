package raft

import "time"

// progressState is the replication mode of one follower. | progressState 是单个
// 跟随者的复制模式。
type progressState uint8

const (
	// probe sends one AppendEntries at a time to find the match index. | probe
	// 每次只发送一条 AppendEntries 以探测匹配索引。
	probe progressState = iota
	// replicate streams pipelined AppendEntries. | replicate 流式发送流水线
	// AppendEntries。
	replicate
	// snapshot transfers a full state image. | snapshot 传输完整状态镜像。
	snapshot
)

// String renders a stable mode name. | String 输出稳定的模式名。
func (s progressState) String() string {
	switch s {
	case probe:
		return "probe"
	case replicate:
		return "replicate"
	case snapshot:
		return "snapshot"
	default:
		return "unknown"
	}
}

// inflight records one pipelined AppendEntries range. | inflight 记录一段流水线
// AppendEntries。
type inflight struct {
	index uint64
	bytes int
}

// inflights is a bounded FIFO of outstanding append ranges. | inflights 是有界的
// 未确认追加区间 FIFO。
type inflights struct {
	buf      []inflight
	start    int
	count    int
	bytes    int
	maxMsgs  int
	maxBytes int
}

// newInflights allocates a small ring that grows on demand. | newInflights 分配
// 一个小环形缓冲，按需增长。
func newInflights(maxMsgs, maxBytes int) *inflights {
	if maxMsgs <= 0 {
		maxMsgs = 64
	}
	if maxBytes <= 0 {
		maxBytes = 4 << 20
	}
	return &inflights{
		buf:      make([]inflight, 8),
		maxMsgs:  maxMsgs,
		maxBytes: maxBytes,
	}
}

// canAdd reports whether one more range of bytes fits. | canAdd 报告是否还能容纳
// 一段 bytes 字节的区间。
func (in *inflights) canAdd(bytes int) bool {
	if in.count >= in.maxMsgs {
		return false
	}
	if in.count > 0 && in.bytes+bytes > in.maxBytes {
		return false
	}
	return true
}

// add pushes a range. The caller must have checked canAdd. | add 压入区间；调用方
// 必须已检查 canAdd。
func (in *inflights) add(index uint64, bytes int) {
	if in.count == len(in.buf) {
		in.grow()
	}
	pos := (in.start + in.count) % len(in.buf)
	in.buf[pos] = inflight{index: index, bytes: bytes}
	in.count++
	in.bytes += bytes
}

// freeTo acknowledges every range ending at or before index. | freeTo 确认所有结束
// 索引不大于 index 的区间。
func (in *inflights) freeTo(index uint64) {
	for in.count > 0 {
		front := in.buf[in.start]
		if front.index > index {
			return
		}
		in.start = (in.start + 1) % len(in.buf)
		in.count--
		in.bytes -= front.bytes
	}
	in.start = 0
	in.bytes = 0
}

// reset forgets all outstanding ranges. | reset 忘记所有未确认区间。
func (in *inflights) reset() {
	in.start = 0
	in.count = 0
	in.bytes = 0
}

// grow doubles the ring and restores FIFO order. | grow 将环形缓冲翻倍并恢复 FIFO
// 顺序。
func (in *inflights) grow() {
	next := make([]inflight, len(in.buf)*2)
	for i := 0; i < in.count; i++ {
		next[i] = in.buf[(in.start+i)%len(in.buf)]
	}
	in.buf = next
	in.start = 0
}

// progress tracks replication state for one peer. | progress 跟踪一个对端的复制状态。
type progress struct {
	inflights        *inflights
	snapshotErr      error
	snapshotSentAt   time.Time
	match            uint64
	next             uint64
	pendingSnapshot  uint64
	snapshotOffset   uint64
	snapshotSize     uint64
	snapshotErrIndex uint64
	lastSnapshotTick uint64
	state            progressState
	recentActive     bool
	snapshotChunked  bool
	snapshotInFlight bool
}

// newProgress builds a follower starting at next. | newProgress 构建从 next 开始的
// 跟随者进度。
func newProgress(next uint64, maxMsgs, maxBytes int) *progress {
	return &progress{
		next:      next,
		state:     probe,
		inflights: newInflights(maxMsgs, maxBytes),
	}
}

// update records a successful append through match. | update 记录一次成功追加到
// match 的进度。
func (p *progress) update(match uint64) {
	if match > p.match {
		p.match = match
	}
	p.next = p.match + 1
	p.state = replicate
	p.inflights.freeTo(p.match)
}

// maybeDecrTo moves next back after a rejected append. hint is the leader's
// computed restart index; the method never moves below match+1 and always makes
// progress when next was beyond match. | maybeDecrTo 在追加被拒后回退 next。hint 是
// 领导者计算出的重启索引；结果不低于 match+1，且当 next 超过 match 时必定前进。
func (p *progress) maybeDecrTo(hint uint64) {
	if p.state == replicate {
		p.state = probe
	}
	if hint <= p.match {
		hint = p.match + 1
	}
	if hint >= p.next && p.next > p.match+1 {
		hint = p.next - 1
	}
	if hint < 1 {
		hint = 1
	}
	p.next = hint
	p.inflights.reset()
}

// becomesSnapshot switches to snapshot transfer. | becomesSnapshot 切换到快照传输。
func (p *progress) becomesSnapshot(index uint64) {
	p.state = snapshot
	p.pendingSnapshot = index
	p.inflights.reset()
}

// snapshotDone finishes snapshot transfer. | snapshotDone 结束快照传输。
func (p *progress) snapshotDone(index uint64) {
	p.update(index)
	p.pendingSnapshot = 0
	p.state = probe
	p.resetSnapshotChunks()
}

// resetSnapshotChunks clears chunk transfer state. | resetSnapshotChunks 清除分块
// 传输状态。
func (p *progress) resetSnapshotChunks() {
	p.snapshotChunked = false
	p.snapshotInFlight = false
	p.snapshotOffset = 0
	p.snapshotSize = 0
}
