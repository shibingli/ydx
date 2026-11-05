//go:build linux && rdma && (amd64 || arm64)

package rdma

import (
	"math/bits"

	"github.com/shibingli/ydx/errs"
)

// Poll drains up to len(events) completions in batches of 64 and returns the
// number written. It returns zero when the queue is empty. | Poll 以 64 为批
// 取出至多 len(events) 个完成事件并返回写入数量。队列为空时返回零。
func (c *CQ) Poll(events []Completion) (int, error) {
	if c == nil || c.closed.Load() {
		return 0, ErrClosed
	}
	if len(events) == 0 {
		return 0, nil
	}
	total := 0
	for total < len(events) {
		batch := len(events) - total
		if batch > len(c.state.scratch) {
			batch = len(c.state.scratch)
		}
		n := int(c.dev.state.api.poll(c.dev.state.ctx, c.state.cq, int32(batch), &c.state.scratch[0]))
		if n < 0 {
			return total, errs.WrapDetail(errnoOf(-n), ErrDevice, "poll completion queue | 轮询完成队列")
		}
		if n == 0 {
			break
		}
		for i := 0; i < n; i++ {
			wc := &c.state.scratch[i]
			events[total] = Completion{
				WRID:      wc.WRID,
				Opcode:    CompletionOpcode(wc.Opcode),
				Status:    CompletionStatus(wc.Status),
				Bytes:     wc.ByteLen,
				QP:        wc.QPNum,
				Imm:       bits.ReverseBytes32(wc.ImmData),
				VendorErr: wc.VendorErr,
			}
			total++
		}
		if n < batch {
			break
		}
	}
	return total, nil
}

// Close destroys the completion queue. Queue pairs using it must be closed
// first. | Close 销毁完成队列。使用它的队列对必须先关闭。
func (c *CQ) Close() error {
	if c == nil || !c.closed.CompareAndSwap(false, true) {
		return nil
	}
	if c.state != nil && c.state.cq != nil {
		c.dev.state.api.removeCQ(c.state.cq)
		c.state.cq = nil
	}
	return nil
}
