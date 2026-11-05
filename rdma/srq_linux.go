//go:build linux && rdma && (amd64 || arm64)

package rdma

import (
	"unsafe"

	"github.com/shibingli/ydx/errs"
)

// PostRecv posts a batch of receive requests to the shared receive queue. |
// PostRecv 向共享接收队列提交一批接收请求。
func (s *SRQ) PostRecv(wrs []RecvWR) (int, error) {
	if s == nil || s.closed.Load() {
		return 0, ErrClosed
	}
	if len(wrs) == 0 {
		return 0, nil
	}
	if len(wrs) > s.state.cap {
		return 0, errs.Detail(ErrQueueFull, "batch %d exceeds shared receive queue %d | 批量 %d 超过共享接收队列 %d",
			len(wrs), s.state.cap, len(wrs), s.state.cap)
	}
	for i := range wrs {
		w := &wrs[i]
		r := &s.state.rwr[i]
		*r = ibvRecvWR{}
		r.WRID = w.WRID
		sges := s.state.rsge[i*MaxSGE : (i+1)*MaxSGE]
		r.SGList = &sges[0]
		nsge := int(w.NumSGE)
		if nsge == 0 {
			sges[0] = ibvSGE{Addr: uint64(w.Addr), Length: w.Length, LKey: w.LKey}
			nsge = 1
		} else {
			if nsge > MaxSGE {
				return i, errs.Detail(ErrInvalidConfig, "sge count %d exceeds %d | SGE 数量 %d 超过 %d",
					nsge, MaxSGE, nsge, MaxSGE)
			}
			for j := 0; j < nsge; j++ {
				sges[j] = ibvSGE{Addr: uint64(w.SGEs[j].Addr), Length: w.SGEs[j].Length, LKey: w.SGEs[j].LKey}
			}
		}
		r.NumSGE = int32(nsge)
		if i+1 < len(wrs) {
			r.Next = &s.state.rwr[i+1]
		}
	}
	rc, bad := s.dev.state.api.srqRecv(s.state.recvFn, s.state.srq, &s.state.rwr[0])
	if rc != 0 {
		idx := 0
		if bad != nil {
			idx = int((uintptr(unsafe.Pointer(bad)) - uintptr(unsafe.Pointer(&s.state.rwr[0]))) / unsafe.Sizeof(ibvRecvWR{}))
		}
		return idx, errnoError("post shared receive", rc)
	}
	return len(wrs), nil
}

// Close destroys the shared receive queue. | Close 销毁共享接收队列。
func (s *SRQ) Close() error {
	if s == nil || !s.closed.CompareAndSwap(false, true) {
		return nil
	}
	if s.state != nil && s.state.srq != nil {
		s.dev.state.api.removeSRQ(s.state.srq)
		s.state.srq = nil
	}
	return nil
}
