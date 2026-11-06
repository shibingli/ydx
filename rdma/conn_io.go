package rdma

import (
	"errors"
	"runtime"
	"time"

	"github.com/shibingli/ydx/errs"
)

// Process polls up to budget completions. | Process 轮询至多 budget 个完成事件。
func (c *Conn) Process(budget int) (int, error) {
	if !c.enter() {
		return 0, ErrClosed
	}
	defer c.leave()
	return c.processLocked(budget)
}

// Alloc acquires one zero-copy send slot. | Alloc 获取一个零拷贝发送槽位。
func (c *Conn) Alloc(size int) (*Buffer, error) {
	if !c.enter() {
		return nil, ErrClosed
	}
	defer c.leave()
	return c.allocLocked(size)
}

// SendBuffer posts a zero-copy send. | SendBuffer 提交零拷贝发送。
func (c *Conn) SendBuffer(b *Buffer, n int) error {
	if !c.enter() {
		return ErrClosed
	}
	defer c.leave()
	return c.sendBufferLocked(b, n)
}

// Send copies and posts one message. | Send 复制并提交一条消息。
func (c *Conn) Send(msg []byte) error {
	if !c.enter() {
		return ErrClosed
	}
	defer c.leave()
	return c.sendLocked(msg)
}

// SendBatchBuffers posts a zero-copy batch. | SendBatchBuffers 提交零拷贝批次。
func (c *Conn) SendBatchBuffers(bufs []*Buffer, lens []int) (int, error) {
	if !c.enter() {
		return 0, ErrClosed
	}
	defer c.leave()
	return c.sendBatchBuffersLocked(bufs, lens)
}

// SendBatch copies and posts several messages. | SendBatch 复制并提交多条消息。
func (c *Conn) SendBatch(msgs [][]byte) (int, error) {
	if !c.enter() {
		return 0, ErrClosed
	}
	defer c.leave()
	return c.sendBatchLocked(msgs)
}

// RecvBuffer waits for one received buffer. | RecvBuffer 等待一个接收缓冲区。
func (c *Conn) RecvBuffer() (*Buffer, int, error) {
	if !c.enter() {
		return nil, 0, ErrClosed
	}
	defer c.leave()
	return c.recvBufferLocked()
}

// Recv waits for and copies one message. | Recv 等待并复制一条消息。
func (c *Conn) Recv() ([]byte, error) {
	if !c.enter() {
		return nil, ErrClosed
	}
	defer c.leave()
	return c.recvLocked()
}

// RecvInto copies one message into dst. | RecvInto 将一条消息复制到 dst。
func (c *Conn) RecvInto(dst []byte) (int, error) {
	if !c.enter() {
		return 0, ErrClosed
	}
	defer c.leave()
	return c.recvIntoLocked(dst)
}

// RecvBuffers drains received buffers. Every returned buffer must be returned
// with Conn.Release or Conn.ReleaseBatch. | RecvBuffers 取出接收缓冲区。每个返回
// 的缓冲区都必须通过 Conn.Release 或 Conn.ReleaseBatch 归还。
func (c *Conn) RecvBuffers(dst []*Buffer, lens []int) (int, error) {
	if !c.enter() {
		return 0, ErrClosed
	}
	defer c.leave()
	return c.recvBuffersLocked(dst, lens)
}

// ReleaseBatch re-posts received buffers. | ReleaseBatch 重新提交接收缓冲区。
func (c *Conn) ReleaseBatch(bufs []*Buffer) error {
	if !c.enter() {
		return ErrClosed
	}
	defer c.leave()
	return c.releaseBatchLocked(bufs)
}

// Release re-posts one received buffer. | Release 重新提交一个接收缓冲区。
func (c *Conn) Release(b *Buffer) error {
	if !c.enter() {
		return ErrClosed
	}
	defer c.leave()
	return c.releaseLocked(b)
}

// Process polls up to budget completions, releases completed send buffers and
// queues received buffers. | Process 轮询至多 budget 个完成事件，释放已完成的
// 发送缓冲区并将接收缓冲区入队。
func (c *Conn) processLocked(budget int) (int, error) {
	if err := c.check(); err != nil {
		return 0, err
	}
	if budget <= 0 {
		budget = c.cfg.MaxBatch
	}
	if budget > len(c.events) {
		budget = len(c.events)
	}
	n, pollErr := c.cq.Poll(c.events[:budget])
	var firstErr error
	for i := 0; i < n; i++ {
		wc := c.events[i]
		if wc.WRID&txBit != 0 {
			idx := int(wc.WRID &^ txBit)
			if idx < 0 || idx >= len(c.txBufs) {
				if firstErr == nil {
					firstErr = errs.Detail(ErrDevice, "invalid send wrid %d | 发送 WRID %d 非法", idx, idx)
				}
				continue
			}
			b := c.txBufs[idx]
			if !b.posted.Swap(false) {
				if firstErr == nil {
					firstErr = errs.Detail(ErrDevice, "send completion for unposted slot %d | 未提交槽位 %d 的发送完成", idx, idx)
				}
				continue
			}
			c.tx.Release(b)
			if wc.IsError() && firstErr == nil {
				firstErr = errs.Detail(ErrConnReset, "completion %s status %s | 完成 %s 状态 %s",
					wc.Opcode, wc.Status, wc.Opcode, wc.Status)
			}
			continue
		}
		if wc.IsError() {
			if firstErr == nil {
				firstErr = errs.Detail(ErrConnReset, "completion %s status %s | 完成 %s 状态 %s",
					wc.Opcode, wc.Status, wc.Opcode, wc.Status)
			}
			continue
		}
		idx := int(wc.WRID)
		if idx < 0 || idx >= len(c.rxBufs) {
			if firstErr == nil {
				firstErr = errs.Detail(ErrDevice, "invalid receive wrid %d | 接收 WRID %d 非法", idx, idx)
			}
			continue
		}
		b := c.rxBufs[idx]
		if !b.posted.Swap(false) {
			if firstErr == nil {
				firstErr = errs.Detail(ErrDevice, "receive completion for unposted slot %d | 未提交槽位 %d 的接收完成",
					idx, idx)
			}
			continue
		}
		n := int(wc.Bytes)
		if n < 0 || n > b.Len() {
			if firstErr == nil {
				firstErr = errs.Detail(ErrDevice, "receive length %d exceeds slot %d | 接收长度 %d 超过槽位 %d",
					n, b.Len(), n, b.Len())
			}
			continue
		}
		if !c.ring.push(b, n) {
			if firstErr == nil {
				firstErr = errs.Detail(ErrQueueFull, "receive ring full | 接收环已满")
			}
		}
	}
	if firstErr != nil {
		c.setErr(firstErr)
		return n, firstErr
	}
	if pollErr != nil {
		c.setErr(pollErr)
		return n, pollErr
	}
	return n, nil
}

// Alloc acquires one zero-copy send slot. The caller writes into Bytes and
// passes the buffer to SendBuffer. | Alloc 获取一个零拷贝发送槽位。调用方写入
// Bytes 后将缓冲区交给 SendBuffer。
func (c *Conn) allocLocked(size int) (*Buffer, error) {
	if err := c.check(); err != nil {
		return nil, err
	}
	if size < 0 || size > c.tx.SlotSize() {
		return nil, errs.Detail(ErrMessageTooLarge, "size %d exceeds slot %d | 大小 %d 超过槽位 %d",
			size, c.tx.SlotSize(), size, c.tx.SlotSize())
	}
	deadline := c.deadline(c.cfg.SendTimeout)
	spins := 0
	for {
		if b, ok := c.tx.Acquire(); ok {
			return b, nil
		}
		if _, err := c.processLocked(c.cfg.MaxBatch); err != nil {
			return nil, err
		}
		spins++
		if spins&1023 == 0 && !deadline.IsZero() && time.Now().After(deadline) {
			return nil, ErrTimeout
		}
		if spins >= 4096 {
			spins = 0
			runtime.Gosched()
		}
	}
}

// deadline converts a timeout to an absolute deadline; zero means no limit. |
// deadline 将超时转换为绝对截止时间；零表示不限。
func (c *Conn) deadline(timeout time.Duration) time.Time {
	if timeout < 0 {
		return time.Time{}
	}
	if timeout == 0 {
		return time.Now()
	}
	return time.Now().Add(timeout)
}

// SendBuffer posts a zero-copy send of the first n bytes of b. On success the
// buffer is owned by the connection and released by Process after completion
// (or immediately for an unsignaled inline send). On a post error an unposted
// buffer is released; on a validation error the caller still owns b. | SendBuffer
// 零拷贝发送 b 的前 n 字节。成功时缓冲区归连接所有，完成事件后由 Process 释放
// （未请求完成的内联发送立即释放）；提交错误时未提交的缓冲区会被释放，校验错误时
// 调用方仍拥有 b。
func (c *Conn) sendBufferLocked(b *Buffer, n int) error {
	if err := c.check(); err != nil {
		return err
	}
	if b == nil || b.owner != c.tx {
		return errs.Detail(ErrInvalidConfig, "buffer does not belong to the send pool | 缓冲区不属于发送池")
	}
	if n < 0 || n > b.Len() {
		return errs.Detail(ErrMessageTooLarge, "length %d | 长度 %d", n, n)
	}
	if !b.posted.CompareAndSwap(false, true) {
		return errs.Detail(ErrInvalidConfig, "buffer already posted | 缓冲区已提交")
	}
	inline := n <= c.qp.MaxInline()
	signaled := !inline || c.sendSeq%c.signalEvery == 0
	flags := SendFlags(0)
	if inline {
		// Inline payloads are copied into the work request, so the buffer can
		// be recycled as soon as ibv_post_send returns. Periodic signaling is
		// still required so the provider can reclaim send queue space. |
		// 内联负载会复制进工作请求，ibv_post_send 返回后即可回收缓冲区；仍需
		// 周期性请求完成事件，以便提供方回收发送队列空间。
		flags |= SendInline
	}
	if signaled {
		flags |= SendSignaled
	}
	c.oneSend[0] = SendWR{
		WRID: txBit | uint64(b.index), Addr: b.Addr(), Length: uint32(n),
		LKey: b.LKey(), Opcode: OpSend, Flags: flags,
	}
	deadline := c.deadline(c.cfg.SendTimeout)
	spins := 0
	for {
		posted, err := c.qp.PostSend(c.oneSend[:])
		if err == nil && posted != 1 {
			b.posted.Store(false)
			c.tx.Release(b)
			err = errs.Detail(ErrDevice, "provider posted %d/1 work requests | 提供方提交了 %d/1 个工作请求", posted, posted)
			c.setErr(err)
			return err
		}
		if err == nil {
			c.sendSeq++
			if inline && !signaled {
				b.posted.Store(false)
				c.tx.Release(b)
			}
			return nil
		}
		if !errors.Is(err, ErrQueueFull) || posted != 0 {
			if posted == 0 {
				b.posted.Store(false)
				c.tx.Release(b)
			}
			c.setErr(err)
			return err
		}
		if _, perr := c.processLocked(c.cfg.MaxBatch); perr != nil {
			b.posted.Store(false)
			c.tx.Release(b)
			return perr
		}
		spins++
		if spins&1023 == 0 && !deadline.IsZero() && time.Now().After(deadline) {
			b.posted.Store(false)
			c.tx.Release(b)
			return ErrTimeout
		}
		if spins >= 4096 {
			spins = 0
			runtime.Gosched()
		}
	}
}

// Send copies msg into a send slot and posts it. | Send 将 msg 复制到发送槽位
// 并提交。
func (c *Conn) sendLocked(msg []byte) error {
	b, err := c.allocLocked(len(msg))
	if err != nil {
		return err
	}
	copy(b.Bytes(), msg)
	if err := c.sendBufferLocked(b, len(msg)); err != nil {
		b.Release()
		return err
	}
	return nil
}

// SendBatchBuffers posts several zero-copy buffers in one or more doorbells and
// returns the number posted. Validation errors leave every buffer owned by the
// caller; after validation, unposted buffers are released on failure. |
// SendBatchBuffers 以一次或多次门铃提交多个零拷贝缓冲区并返回提交数量。校验错误
// 时所有缓冲区仍归调用方；通过校验后，失败时会释放未提交的缓冲区。
func (c *Conn) sendBatchBuffersLocked(bufs []*Buffer, lens []int) (int, error) {
	if err := c.check(); err != nil {
		return 0, err
	}
	if len(bufs) == 0 {
		return 0, nil
	}
	if len(lens) != len(bufs) {
		return 0, errs.Detail(ErrInvalidConfig, "buffer/length count mismatch | 缓冲区与长度数量不一致")
	}
	for i, b := range bufs {
		if b == nil || b.owner != c.tx || lens[i] < 0 || lens[i] > b.Len() {
			return 0, errs.Detail(ErrInvalidConfig, "invalid buffer at %d | 第 %d 个缓冲区非法", i, i)
		}
	}
	// Claim every buffer before posting anything. Duplicate or already in-flight
	// buffers would create two WQEs with the same WRID and corrupt the pool.
	// | 在提交前认领全部缓冲区。重复或已在途的缓冲区会产生同一 WRID 的两个 WQE，
	// 破坏内存池。
	claimed := 0
	for ; claimed < len(bufs); claimed++ {
		if !bufs[claimed].posted.CompareAndSwap(false, true) {
			for j := 0; j < claimed; j++ {
				bufs[j].posted.Store(false)
			}
			return 0, errs.Detail(ErrInvalidConfig, "buffer already posted at %d | 第 %d 个缓冲区已提交", claimed, claimed)
		}
	}
	deadline := c.deadline(c.cfg.SendTimeout)
	spins := 0
	total := 0
	for total < len(bufs) {
		remaining := len(bufs) - total
		if remaining > c.cfg.MaxBatch {
			remaining = c.cfg.MaxBatch
		}
		// Never request more WRs than the send queue can hold in one post. |
		// 单次提交不得请求超过发送队列容量的 WR。
		if remaining > len(c.txBufs) {
			remaining = len(c.txBufs)
		}
		if cap(c.scratch) < remaining {
			c.scratch = make([]SendWR, remaining)
		}
		wrs := c.scratch[:remaining]
		for i := 0; i < remaining; i++ {
			b, n := bufs[total+i], lens[total+i]
			inline := n <= c.qp.MaxInline()
			signaled := !inline || (c.sendSeq+uint64(i))%c.signalEvery == 0
			flags := SendFlags(0)
			if inline {
				flags |= SendInline
			}
			if signaled {
				flags |= SendSignaled
			}
			wrs[i] = SendWR{
				WRID: txBit | uint64(b.index), Addr: b.Addr(), Length: uint32(n),
				LKey: b.LKey(), Opcode: OpSend, Flags: flags,
			}
		}
		oldTotal := total
		posted, err := c.qp.PostSend(wrs)
		if err == nil && posted == 0 {
			err = errs.Detail(ErrDevice, "provider posted no work requests | 提供方未提交工作请求")
		}
		total += posted
		c.sendSeq += uint64(posted)
		// Inline buffers posted without a completion request are already copied
		// into their work requests and can be recycled now; the periodically
		// signaled ones and non-inline buffers stay in flight until their
		// completions arrive. | 未请求完成事件的内联缓冲区已复制进工作请求，
		// 可立即回收；周期性信号的内联缓冲区与非内联缓冲区保持到完成事件到达。
		for i := oldTotal; i < total; i++ {
			w := &wrs[i-oldTotal]
			if w.Flags&SendInline != 0 && w.Flags&SendSignaled == 0 {
				bufs[i].posted.Store(false)
				c.tx.Release(bufs[i])
			}
		}
		if err == nil {
			// Continue until the whole requested batch is posted; returning
			// after one chunk would silently drop and leak the suffix. | 继续
			// 提交直到整批完成；只提交一个分块会静默丢弃并泄漏后续缓冲区。
			continue
		}
		if !errors.Is(err, ErrQueueFull) {
			for i := total; i < len(bufs); i++ {
				bufs[i].posted.Store(false)
				c.tx.Release(bufs[i])
			}
			c.setErr(err)
			return total, err
		}
		// A partial post is normal under backpressure: the prefix is in flight
		// and the suffix is retried after draining completions. | 背压下部分提交
		// 属正常：前缀已在途，排空完成事件后重试后缀。
		if _, perr := c.processLocked(c.cfg.MaxBatch); perr != nil {
			for i := total; i < len(bufs); i++ {
				bufs[i].posted.Store(false)
				c.tx.Release(bufs[i])
			}
			return total, perr
		}
		spins++
		if spins&1023 == 0 && !deadline.IsZero() && time.Now().After(deadline) {
			for i := total; i < len(bufs); i++ {
				bufs[i].posted.Store(false)
				c.tx.Release(bufs[i])
			}
			return total, ErrTimeout
		}
		if spins >= 4096 {
			spins = 0
			runtime.Gosched()
		}
	}
	return total, nil
}

// SendBatch copies and posts every message, using several doorbells when the
// batch exceeds MaxBatch or the send queue depth. | SendBatch 复制并提交全部消息；
// 批次超过 MaxBatch 或发送队列深度时使用多次门铃。
func (c *Conn) sendBatchLocked(msgs [][]byte) (int, error) {
	if err := c.check(); err != nil {
		return 0, err
	}
	if len(msgs) == 0 {
		return 0, nil
	}
	total := 0
	for total < len(msgs) {
		limit := len(msgs) - total
		if limit > c.cfg.MaxBatch {
			limit = c.cfg.MaxBatch
		}
		if limit > len(c.txBufs) {
			limit = len(c.txBufs)
		}
		bufs := make([]*Buffer, 0, limit)
		lens := make([]int, 0, limit)
		for i := 0; i < limit; i++ {
			b, err := c.allocLocked(len(msgs[total+i]))
			if err != nil {
				for _, held := range bufs {
					held.Release()
				}
				return total, err
			}
			copy(b.Bytes(), msgs[total+i])
			bufs = append(bufs, b)
			lens = append(lens, len(msgs[total+i]))
		}
		posted, err := c.sendBatchBuffersLocked(bufs, lens)
		total += posted
		if err != nil {
			for _, b := range bufs {
				b.Release()
			}
			return total, err
		}
		if posted == 0 {
			for _, b := range bufs {
				b.Release()
			}
			return total, ErrTimeout
		}
	}
	return total, nil
}

// RecvBuffer waits for one received buffer and its length. The caller must
// return it with Conn.Release (not Buffer.Release) when done; zero-copy
// consumers use it directly. | RecvBuffer 等待一个接收缓冲区及其长度。调用方完成后
// 必须用 Conn.Release（而非 Buffer.Release）归还；零拷贝消费方直接使用该缓冲区。
func (c *Conn) recvBufferLocked() (*Buffer, int, error) {
	if err := c.check(); err != nil {
		return nil, 0, err
	}
	deadline := c.deadline(c.cfg.RecvTimeout)
	spins := 0
	for {
		if b, n, ok := c.ring.pop(); ok {
			return b, n, nil
		}
		if _, err := c.processLocked(c.cfg.MaxBatch); err != nil {
			return nil, 0, err
		}
		spins++
		if spins&1023 == 0 && !deadline.IsZero() && time.Now().After(deadline) {
			return nil, 0, ErrTimeout
		}
		if spins >= 4096 {
			spins = 0
			runtime.Gosched()
		}
	}
}

// Recv waits for one message and copies it out. | Recv 等待一条消息并复制出来。
func (c *Conn) recvLocked() ([]byte, error) {
	b, n, err := c.recvBufferLocked()
	if err != nil {
		return nil, err
	}
	out := make([]byte, n)
	copy(out, b.Bytes()[:n])
	if rerr := c.releaseLocked(b); rerr != nil {
		return nil, rerr
	}
	return out, nil
}

// RecvInto copies one message into dst and releases the receive buffer. | RecvInto
// 将一条消息复制到 dst 并释放接收缓冲区。
func (c *Conn) recvIntoLocked(dst []byte) (int, error) {
	b, n, err := c.recvBufferLocked()
	if err != nil {
		return 0, err
	}
	copied := copy(dst, b.Bytes()[:n])
	if rerr := c.releaseLocked(b); rerr != nil {
		return copied, rerr
	}
	if copied < n {
		return copied, errs.Detail(ErrMessageTooLarge, "destination %d < message %d | 目标 %d 小于消息 %d", len(dst), n, len(dst), n)
	}
	return copied, nil
}

// RecvBuffers drains up to len(dst) received buffers. When the receive ring is
// empty it polls once and then returns what is available; it never waits for a
// full batch. | RecvBuffers 取出至多 len(dst) 个接收缓冲区。接收环为空时先轮询
// 一次，然后返回可用数量；不会等待凑满一批。
func (c *Conn) recvBuffersLocked(dst []*Buffer, lens []int) (int, error) {
	if err := c.check(); err != nil {
		return 0, err
	}
	if len(dst) == 0 {
		return 0, nil
	}
	if len(lens) < len(dst) {
		return 0, errs.Detail(ErrInvalidConfig, "length slice too short | 长度切片过短")
	}
	n := 0
	for n < len(dst) {
		b, l, ok := c.ring.pop()
		if !ok {
			break
		}
		dst[n], lens[n] = b, l
		n++
	}
	if n > 0 {
		return n, nil
	}
	if _, err := c.processLocked(c.cfg.MaxBatch); err != nil {
		return 0, err
	}
	for n < len(dst) {
		b, l, ok := c.ring.pop()
		if !ok {
			break
		}
		dst[n], lens[n] = b, l
		n++
	}
	return n, nil
}

// ReleaseBatch re-posts several received buffers with one doorbell. | ReleaseBatch
// 以一次门铃重新提交多个接收缓冲区。
func (c *Conn) releaseBatchLocked(bufs []*Buffer) error {
	if err := c.check(); err != nil {
		return err
	}
	if len(bufs) == 0 {
		return nil
	}
	if cap(c.scratchRecv) < len(bufs) {
		c.scratchRecv = make([]RecvWR, len(bufs))
	}
	wrs := c.scratchRecv[:len(bufs)]
	for i, b := range bufs {
		if b == nil || b.owner != c.rx {
			return errs.Detail(ErrInvalidConfig, "buffer %d does not belong to the receive pool | 第 %d 个缓冲区不属于接收池", i, i)
		}
		if !b.posted.CompareAndSwap(false, true) {
			for j := 0; j < i; j++ {
				bufs[j].posted.Store(false)
			}
			return errs.Detail(ErrInvalidConfig, "receive buffer already posted at %d | 第 %d 个接收缓冲区已提交", i, i)
		}
		wrs[i] = RecvWR{WRID: uint64(b.index), Addr: b.Addr(), Length: uint32(b.Len()), LKey: b.LKey()}
	}
	posted, err := c.qp.PostRecv(wrs)
	if err != nil {
		// ibv_post_recv reports the first failing WR; WRs before it may already
		// be owned by the RQ. Keep that prefix marked posted and only recycle the
		// suffix, then fail the connection: the caller cannot safely retry a
		// partially posted batch. Clearing the prefix would let another owner
		// overwrite live DMA memory. | ibv_post_recv 报告首个失败的 WR；其之前的
		// WR 可能已归 RQ 所有。保留该前缀的已提交标记，仅回收后缀，然后使连接失败：
		// 调用方无法安全重试部分提交的批次。清除前缀会让其它所有者覆盖在途 DMA 内存。
		for i := posted; i < len(bufs); i++ {
			bufs[i].posted.Store(false)
		}
		c.setErr(err)
		return err
	}
	if posted != len(wrs) {
		for i := posted; i < len(wrs); i++ {
			bufs[i].posted.Store(false)
		}
		err := errs.Detail(ErrDevice, "re-posted %d/%d receive buffers | 重新提交接收缓冲区 %d/%d",
			posted, len(wrs), posted, len(wrs))
		c.setErr(err)
		return err
	}
	return nil
}

// Release re-posts a received buffer to the receive queue. It is the only valid
// way to return a buffer obtained from RecvBuffer or RecvBuffers. | Release 将
// 接收缓冲区重新提交到接收队列。它是归还 RecvBuffer 或 RecvBuffers 所得缓冲区的
// 唯一有效方式。
func (c *Conn) releaseLocked(b *Buffer) error {
	if err := c.check(); err != nil {
		return err
	}
	if b == nil || b.owner != c.rx {
		return errs.Detail(ErrInvalidConfig, "buffer does not belong to the receive pool | 缓冲区不属于接收池")
	}
	if !b.posted.CompareAndSwap(false, true) {
		return errs.Detail(ErrInvalidConfig, "receive buffer already posted | 接收缓冲区已提交")
	}
	c.oneRecv[0] = RecvWR{WRID: uint64(b.index), Addr: b.Addr(), Length: uint32(b.Len()), LKey: b.LKey()}
	posted, err := c.qp.PostRecv(c.oneRecv[:])
	if err != nil {
		// A provider error after accepting the WR leaves the slot in the RQ. |
		// 提供方接受 WR 后报错时，槽位仍留在 RQ 中。
		if posted == 0 {
			b.posted.Store(false)
		}
		c.setErr(err)
		return err
	}
	if posted != 1 {
		b.posted.Store(false)
		err := errs.Detail(ErrDevice, "re-posted %d/1 receive buffers | 重新提交接收缓冲区 %d/1", posted, posted)
		c.setErr(err)
		return err
	}
	return nil
}
