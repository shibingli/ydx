package raft

import (
	"io"
	"os"
	"time"

	"github.com/shibingli/ydx/errs"
	ydlog "github.com/shibingli/ydx/log"
)

// incomingSnapshot reassembles one chunked snapshot from a leader. |
// incomingSnapshot 重组来自领导者的一个分块快照。
type incomingSnapshot struct {
	snap     *Snapshot
	from     NodeID
	term     uint64
	total    uint64
	received uint64
}

// snapshotSize returns the payload size of a snapshot. | snapshotSize 返回快照负载
// 大小。
func (n *Node) snapshotSize(snap *Snapshot) int64 {
	if snap == nil {
		return 0
	}
	if snap.Data != nil {
		return int64(len(snap.Data))
	}
	return snap.dataSize
}

// snapshotChunkLimit returns the payload bytes that fit one chunk, reduced for
// transports with a hard frame limit. Zero means chunking is unusable. |
// snapshotChunkLimit 返回单个分块可承载的负载字节数；对具有硬帧上限的传输会相应
// 缩小。零表示分块不可用。
func (n *Node) snapshotChunkLimit(snap *Snapshot) int {
	limit := n.snapshotChunkBytes
	if limit <= 0 {
		return 0
	}
	limiter, ok := n.transport.(interface{ FrameLimit() int64 })
	if !ok {
		return limit
	}
	frame := int(limiter.FrameLimit())
	if frame <= 0 {
		return limit
	}
	// Leave room for the message header, snapshot metadata, configuration and
	// framing. The estimate is deliberately conservative. | 为消息头、快照元数据、
	// 配置与帧格式预留空间；估算有意保守。
	overhead := 512 + len(appendConfState(nil, snap.ConfState))
	for _, p := range snap.ConfState.Addresses {
		overhead += len(p.Addr)
	}
	if frame-overhead < limit {
		limit = frame - overhead
	}
	return limit
}

// snapshotChunkData returns size payload bytes at offset from an in-memory or
// file-backed image. | snapshotChunkData 从内存或文件镜像返回 offset 处 size 字节
// 负载。
func (n *Node) snapshotChunkData(snap *Snapshot, offset uint64, size int) ([]byte, error) {
	if snap == nil {
		return nil, errs.Detail(ErrCorrupt, "nil snapshot")
	}
	total := uint64(n.snapshotSize(snap))
	if offset > total || uint64(size) > total-offset {
		return nil, errs.Detail(ErrCorrupt,
			"snapshot chunk offset %d size %d beyond %d | 快照分块越界", offset, size, total)
	}
	if size == 0 {
		return nil, nil
	}
	if snap.Data != nil {
		end := offset + uint64(size)
		return snap.Data[offset:end], nil
	}
	if snap.file == "" {
		return nil, errs.Detail(ErrCorrupt,
			"snapshot %d/%d has no image data | 快照缺少镜像数据", snap.Index, snap.Term)
	}
	f, err := os.Open(snap.file)
	if err != nil {
		return nil, errs.Wrap(err, ErrStorage)
	}
	defer f.Close()
	if _, err := f.Seek(snap.dataOffset+int64(offset), io.SeekStart); err != nil {
		return nil, errs.Wrap(err, ErrStorage)
	}
	buf := make([]byte, size)
	if _, err := io.ReadFull(f, buf); err != nil {
		return nil, errs.Wrap(err, ErrStorage)
	}
	return buf, nil
}

// startChunkedSnapshot begins an ack-gated chunk transfer. | startChunkedSnapshot
// 开始一个逐块确认的分块传输。
func (n *Node) startChunkedSnapshot(to NodeID, snap *Snapshot, total int64) {
	pr := n.progress[to]
	if pr == nil {
		return
	}
	pr.becomesSnapshot(snap.Index)
	pr.snapshotChunked = true
	pr.snapshotInFlight = false
	pr.snapshotOffset = 0
	pr.snapshotSize = uint64(total)
	pr.snapshotErr = nil
	pr.snapshotErrIndex = 0
	pr.lastSnapshotTick = n.tickCount
	pr.snapshotSentAt = n.now()
	n.logf("info", "raft sending chunked snapshot | raft 发送分块快照",
		ydlog.Uint64("node", uint64(n.id)), ydlog.Uint64("peer", uint64(to)),
		ydlog.Uint64("index", snap.Index), ydlog.Int64("bytes", total),
		ydlog.Int("chunk_bytes", n.snapshotChunkBytes))
	n.sendSnapshotChunk(to, snap)
}

// sendSnapshotChunk sends the current chunk or, when the payload is complete, a
// zero-length liveness probe for the install response. | sendSnapshotChunk 发送
// 当前分块；负载已完成时发送零长度存活探测以获取安装响应。
func (n *Node) sendSnapshotChunk(to NodeID, snap *Snapshot) {
	pr := n.progress[to]
	if pr == nil || !pr.snapshotChunked || snap == nil {
		return
	}
	limit := n.snapshotChunkLimit(snap)
	if limit <= 0 {
		pr.snapshotInFlight = false
		pr.snapshotErr = errs.Detail(ErrTooLarge,
			"snapshot chunk cannot fit transport frame limit | 快照分块无法适配传输帧上限")
		pr.snapshotErrIndex = snap.Index
		return
	}
	offset := pr.snapshotOffset
	total := pr.snapshotSize
	if offset > total {
		offset = total
	}
	size := 0
	if offset < total {
		size = limit
		if uint64(size) > total-offset {
			size = int(total - offset)
		}
	}
	data, err := n.snapshotChunkData(snap, offset, size)
	if err != nil {
		pr.snapshotInFlight = false
		pr.snapshotErr = err
		pr.snapshotErrIndex = snap.Index
		n.logf("error", "raft cannot read snapshot chunk | raft 无法读取快照分块",
			ydlog.Uint64("node", uint64(n.id)), ydlog.Uint64("peer", uint64(to)),
			ydlog.Uint64("snapshot", snap.Index), ydlog.Uint64("offset", offset),
			ydlog.Err(err))
		return
	}
	n.sendSolo(Message{
		Type: MsgSnapChunk, To: to, Term: n.term,
		LogIndex: offset, LogTerm: total,
		Snapshot: &Snapshot{
			Index: snap.Index, Term: snap.Term, ConfState: snap.ConfState, Data: data,
		},
	})
	pr.snapshotInFlight = true
	pr.snapshotSentAt = n.now()
	n.metrics.snapshotChunksOut.Add(1)
}

// handleSnapshotChunkResp advances a chunk transfer. | handleSnapshotChunkResp
// 推进分块传输。
func (n *Node) handleSnapshotChunkResp(m *Message) {
	if n.state != StateLeader {
		return
	}
	if m.Term > n.term {
		n.becomeFollower(m.Term, 0, true)
		return
	}
	if m.Term < n.term {
		return
	}
	pr := n.progress[m.From]
	if pr == nil || !pr.snapshotChunked || pr.state != snapshot {
		return
	}
	// A stale or reordered acknowledgment must not move the transfer backwards.
	// | 过期或乱序的确认不得让传输回退。
	if m.LogIndex != pr.snapshotOffset || m.Commit != pr.pendingSnapshot {
		return
	}
	pr.recentActive = true
	pr.snapshotInFlight = false
	snap := n.latestSnapshot
	if snap == nil || snap.Index != pr.pendingSnapshot {
		return
	}
	next := m.Index
	if next > pr.snapshotSize {
		next = pr.snapshotSize
	}
	pr.snapshotOffset = next
	if next >= pr.snapshotSize {
		// The final chunk is received. Wait for MsgSnapResp; heartbeat retries
		// send the liveness probe if the response was lost. | 最后一块已收到。等待
		// MsgSnapResp；若响应丢失，心跳重试会发送存活探测。
		pr.snapshotSentAt = n.now()
		return
	}
	n.sendSnapshotChunk(m.From, snap)
}

// handleSnapshotChunk accepts one chunk and installs the image when complete.
// | handleSnapshotChunk 接收一个分块，并在完整时安装镜像。
func (n *Node) handleSnapshotChunk(m *Message) {
	if m.Snapshot == nil {
		return
	}
	if m.Term < n.term {
		return
	}
	if m.Term > n.term {
		n.becomeFollower(m.Term, m.From, true)
	} else {
		if n.state != StateFollower {
			n.becomeFollower(n.term, m.From, false)
		}
		n.setLeader(m.From)
		n.resetElection()
	}
	snap := m.Snapshot
	if validateConfState(snap.ConfState) != nil {
		n.send(Message{Type: MsgSnapResp, To: m.From, Term: n.term, Reject: true,
			Index: n.committed, LogIndex: snap.Index})
		return
	}
	offset := m.LogIndex
	total := m.LogTerm
	if total > maxSnapshotBytes || offset > total {
		n.send(Message{Type: MsgSnapResp, To: m.From, Term: n.term, Reject: true,
			Index: n.committed, LogIndex: snap.Index})
		return
	}
	n.metrics.snapshotChunksIn.Add(1)
	if snap.Index <= n.committed {
		// The follower already has this base. If its image is still being
		// installed, report all bytes received so the leader waits for the
		// durable install response instead of restarting the whole transfer. |
		// 跟随者已拥有该基点。若镜像仍在安装，报告已收到全部字节，让领导者等待持久
		// 安装响应，而不是重传整个快照。
		if n.incomingSnapshot == nil && snap.Index <= n.lastSnapshot.Load() {
			n.sendSnapshotChunkResp(m.From, total, offset, snap.Index)
			return
		}
		n.send(Message{Type: MsgSnapResp, To: m.From, Term: n.term,
			Index: snap.Index, LogIndex: snap.Index})
		return
	}
	if offset == total && total > 0 && len(snap.Data) == 0 {
		// Liveness probe: the leader finished sending but did not see the install
		// response. Ask it to restart from what we are still missing. |
		// 存活探测：领导者已发送完毕但未看到安装响应。让它从仍缺失的位置重启。
		if inc := n.incomingSnapshot; inc != nil && inc.from == m.From && inc.term == m.Term &&
			inc.snap.Index == snap.Index && inc.snap.Term == snap.Term {
			n.sendSnapshotChunkResp(m.From, inc.received, offset, snap.Index)
		} else {
			n.sendSnapshotChunkResp(m.From, 0, offset, snap.Index)
		}
		return
	}
	inc := n.incomingSnapshot
	if inc == nil || inc.from != m.From || inc.term != m.Term ||
		inc.snap.Index != snap.Index || inc.snap.Term != snap.Term || inc.total != total {
		if offset != 0 {
			n.sendSnapshotChunkResp(m.From, 0, offset, snap.Index)
			return
		}
		inc = &incomingSnapshot{
			from: m.From, term: m.Term, total: total,
			snap: &Snapshot{
				Index:     snap.Index,
				Term:      snap.Term,
				ConfState: snap.ConfState.clone(),
				Data:      make([]byte, int(total)),
			},
		}
		n.incomingSnapshot = inc
	}
	if offset != inc.received {
		n.sendSnapshotChunkResp(m.From, inc.received, offset, snap.Index)
		return
	}
	if uint64(len(snap.Data)) > inc.total-inc.received {
		n.incomingSnapshot = nil
		n.sendSnapshotChunkResp(m.From, 0, offset, snap.Index)
		return
	}
	copy(inc.snap.Data[inc.received:], snap.Data)
	inc.received += uint64(len(snap.Data))
	n.sendSnapshotChunkResp(m.From, inc.received, offset, snap.Index)
	if inc.received == inc.total {
		complete := inc.snap
		n.incomingSnapshot = nil
		n.handleSnapshot(&Message{Type: MsgSnap, From: m.From, To: n.id,
			Term: m.Term, Snapshot: complete})
	}
}

// sendSnapshotChunkResp reports the next contiguous offset the follower needs.
// | sendSnapshotChunkResp 报告跟随者所需的下一连续偏移。
func (n *Node) sendSnapshotChunkResp(to NodeID, next, offset, index uint64) {
	n.send(Message{Type: MsgSnapChunkResp, To: to, Term: n.term,
		Index: next, LogIndex: offset, Commit: index})
}

// snapshotRetryInterval bounds how often a leader re-enqueues a snapshot whose
// response has not arrived. Re-sending every few ticks would multiply a large
// image in the outbound queues while a slow link is still transferring it.
// | snapshotRetryInterval 限制领导者重发尚未收到响应的快照。每隔几个 tick 重发会在
// 慢链路仍在传输时把大镜像在出站队列中复制多份。
const snapshotRetryInterval = 5 * time.Second

// sendSnapshot transfers the latest snapshot to a lagging follower. | sendSnapshot
// 将最新快照传输给落后跟随者。
func (n *Node) sendSnapshot(to NodeID) {
	if n.state != StateLeader {
		return
	}
	pr := n.progress[to]
	if pr == nil {
		return
	}
	if pr.state == snapshot && !pr.snapshotSentAt.IsZero() &&
		n.now().Sub(pr.snapshotSentAt) < snapshotRetryInterval {
		return
	}
	snap := n.latestSnapshot
	if snap == nil {
		n.logf("warn", "raft cannot send snapshot | raft 无法发送快照",
			ydlog.Uint64("node", uint64(n.id)), ydlog.Uint64("peer", uint64(to)))
		return
	}
	if snap.Index <= pr.match {
		// A follower can only have matched through this snapshot when it already
		// has a prefix consistent with the leader. If the leader has compacted
		// beyond that point but still exposes an older image, retrying would loop
		// between snapshot and append forever; wait for a newer image instead.
		// | 跟随者匹配到该快照时，其前缀必然与领导者一致。若领导者已压缩到更靠后的
		// 位置却仍暴露旧镜像，重试会在快照与追加之间无限循环；应等待更新的镜像。
		if pr.match < n.log.snapshotIndex {
			n.logf("warn", "raft snapshot is older than compacted log | raft 快照落后于已压缩日志",
				ydlog.Uint64("node", uint64(n.id)), ydlog.Uint64("peer", uint64(to)),
				ydlog.Uint64("snapshot", snap.Index), ydlog.Uint64("compacted", n.log.snapshotIndex))
			pr.state = snapshot
			pr.pendingSnapshot = 0
			pr.snapshotSentAt = n.now()
			pr.resetSnapshotChunks()
			return
		}
		pr.next = pr.match + 1
		pr.state = probe
		pr.snapshotErr = nil
		pr.snapshotErrIndex = 0
		pr.snapshotSentAt = time.Time{}
		pr.resetSnapshotChunks()
		n.maybeSendAppend(to)
		return
	}
	total := n.snapshotSize(snap)
	if pr.snapshotChunked && pr.pendingSnapshot != snap.Index {
		// A newer local snapshot superseded the image being transferred. |
		// 更新的本地快照取代了正在传输的镜像。
		pr.resetSnapshotChunks()
	}
	if pr.snapshotChunked && pr.pendingSnapshot == snap.Index {
		if pr.snapshotSize != uint64(total) {
			pr.resetSnapshotChunks()
		} else {
			pr.snapshotInFlight = false
			n.sendSnapshotChunk(to, snap)
			return
		}
	}
	overhead := int64(256 + len(appendConfState(nil, snap.ConfState)))
	for _, p := range snap.ConfState.Addresses {
		overhead += int64(len(p.Addr))
	}
	frameLimit := int64(0)
	if limiter, ok := n.transport.(interface{ FrameLimit() int64 }); ok {
		frameLimit = limiter.FrameLimit()
	}
	needsChunks := n.snapshotChunkBytes > 0 && total > 0 &&
		(total > int64(n.snapshotChunkBytes) ||
			(frameLimit > 0 && total+overhead > frameLimit-64))
	if needsChunks {
		if total > maxSnapshotBytes {
			pr.state = snapshot
			pr.pendingSnapshot = snap.Index
			pr.lastSnapshotTick = n.tickCount
			pr.snapshotSentAt = n.now()
			if pr.snapshotErr == nil || pr.snapshotErrIndex != snap.Index {
				pr.snapshotErr = errs.Detail(ErrTooLarge,
					"snapshot %d is %d bytes, chunk reassembly limit is %d",
					snap.Index, total, maxSnapshotBytes)
				pr.snapshotErrIndex = snap.Index
				n.logf("error", "raft snapshot exceeds chunk reassembly limit | raft 快照超过分块重组上限",
					ydlog.Uint64("node", uint64(n.id)), ydlog.Uint64("peer", uint64(to)),
					ydlog.Uint64("snapshot", snap.Index), ydlog.Int64("size", total))
			}
			return
		}
		if n.snapshotChunkLimit(snap) <= 0 {
			pr.state = snapshot
			pr.pendingSnapshot = snap.Index
			pr.lastSnapshotTick = n.tickCount
			pr.snapshotSentAt = n.now()
			if pr.snapshotErr == nil || pr.snapshotErrIndex != snap.Index {
				pr.snapshotErr = errs.Detail(ErrTooLarge,
					"snapshot chunk does not fit transport frame limit | 快照分块无法适配传输帧上限")
				pr.snapshotErrIndex = snap.Index
			}
			return
		}
		n.startChunkedSnapshot(to, snap, total)
		return
	}
	data, err := n.snapshotData(snap)
	if err != nil {
		pr.state = snapshot
		pr.pendingSnapshot = snap.Index
		pr.lastSnapshotTick = n.tickCount
		pr.snapshotSentAt = n.now()
		if pr.snapshotErr == nil || pr.snapshotErrIndex != snap.Index {
			pr.snapshotErr = err
			pr.snapshotErrIndex = snap.Index
			n.logf("error", "raft cannot load snapshot image | raft 无法加载快照镜像",
				ydlog.Uint64("node", uint64(n.id)), ydlog.Uint64("peer", uint64(to)),
				ydlog.Uint64("snapshot", snap.Index), ydlog.Err(err))
		}
		return
	}
	if frameLimit > 0 {
		size := int64(len(data)) + 256
		for _, p := range snap.ConfState.Addresses {
			size += int64(len(p.Addr))
		}
		if size > frameLimit-64 {
			// The transport would drop every attempt. Report the real cause
			// through Status and log it once per snapshot instead of silently
			// retrying an unsendable image. | 传输层会丢弃每次尝试。通过 Status
			// 报告真实原因，并对每张快照只记录一次日志，而不是静默重试无法发送的
			// 镜像。
			pr.state = snapshot
			pr.pendingSnapshot = snap.Index
			pr.lastSnapshotTick = n.tickCount
			pr.snapshotSentAt = n.now()
			if pr.snapshotErr == nil || pr.snapshotErrIndex != snap.Index {
				pr.snapshotErr = errs.Detail(ErrTooLarge,
					"snapshot %d is %d bytes, transport limit is %d", snap.Index, size, frameLimit)
				pr.snapshotErrIndex = snap.Index
				n.logf("error", "raft snapshot exceeds transport frame limit | raft 快照超过传输帧上限",
					ydlog.Uint64("node", uint64(n.id)), ydlog.Uint64("peer", uint64(to)),
					ydlog.Uint64("snapshot", snap.Index), ydlog.Int64("size", size),
					ydlog.Int64("limit", frameLimit))
			}
			return
		}
	}
	pr.becomesSnapshot(snap.Index)
	pr.resetSnapshotChunks()
	pr.lastSnapshotTick = n.tickCount
	pr.snapshotSentAt = n.now()
	pr.snapshotErr = nil
	pr.snapshotErrIndex = 0
	n.logf("info", "raft sending snapshot | raft 发送快照",
		ydlog.Uint64("node", uint64(n.id)), ydlog.Uint64("peer", uint64(to)),
		ydlog.Uint64("index", snap.Index))
	n.send(Message{Type: MsgSnap, To: to, Term: n.term, Snapshot: &Snapshot{
		Index: snap.Index, Term: snap.Term, ConfState: snap.ConfState, Data: data,
	}})
}
