//go:build linux && rdma && (amd64 || arm64)

package rdma

import (
	"math/bits"
	"unsafe"

	"github.com/shibingli/ydx/errs"
)

// PostSend posts a batch of send work requests with one call into
// ibv_post_send and one doorbell. It returns the number posted and, on
// failure, the index of the first rejected request. | PostSend 以一次
// ibv_post_send 调用与一次门铃提交一批发送工作请求。成功返回提交数量；失败时
// 同时返回首个被拒绝请求的索引。
func (q *QP) PostSend(wrs []SendWR) (int, error) { return q.postSend(wrs, nil) }

// PostSendUD posts unreliable datagram work requests to the peer described by
// ah. | PostSendUD 向 ah 描述的对端提交不可靠数据报工作请求。
func (q *QP) PostSendUD(wrs []SendWR, ah *AH) (int, error) {
	if ah == nil || ah.closed.Load() || ah.state == nil || ah.state.ah == nil {
		return 0, errs.Detail(ErrInvalidConfig, "address handle is required | 必须提供地址句柄")
	}
	return q.postSend(wrs, ah)
}

// postSend encodes and posts one batch. | postSend 编码并提交一批请求。
func (q *QP) postSend(wrs []SendWR, ah *AH) (int, error) {
	if q == nil || q.closed.Load() {
		return 0, ErrClosed
	}
	if len(wrs) == 0 {
		return 0, nil
	}
	if len(wrs) > q.state.scap {
		return 0, errs.Detail(ErrQueueFull, "batch %d exceeds send queue %d | 批量 %d 超过发送队列 %d",
			len(wrs), q.state.scap, len(wrs), q.state.scap)
	}
	for i := range wrs {
		w := &wrs[i]
		s := &q.state.swr[i]
		*s = ibvSendWR{}
		s.WRID = w.WRID
		s.Opcode = uint32(w.Opcode)
		s.SendFlags = uint32(w.Flags)
		if w.Opcode == OpSendWithImm || w.Opcode == OpRDMAWriteWithImm {
			s.ImmData = bits.ReverseBytes32(w.Imm)
		}
		sges := q.state.ssge[i*MaxSGE : (i+1)*MaxSGE]
		s.SGList = &sges[0]
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
		s.NumSGE = int32(nsge)
		switch w.Opcode {
		case OpRDMAWrite, OpRDMAWriteWithImm, OpRDMARead:
			s.Union.RemoteAddr = w.RemoteAddr
			s.Union.Field8 = uint64(w.RKey)
		case OpAtomicCmpSwap, OpAtomicFetchAdd:
			s.Union.RemoteAddr = w.RemoteAddr
			s.Union.Field8 = w.CompareAdd
			s.Union.Swap = w.Swap
			s.Union.RKey = w.RKey
		}
		if ah != nil {
			s.Union.RemoteAddr = uint64(uintptr(unsafe.Pointer(ah.state.ah)))
			s.Union.Field8 = uint64(w.RemoteQPN) | uint64(w.RemoteQKey)<<32
		}
		if i+1 < len(wrs) {
			s.Next = &q.state.swr[i+1]
		}
	}
	rc, bad := q.dev.state.api.send(q.dev.state.ctx, q.state.qp, &q.state.swr[0])
	if rc != 0 {
		idx := 0
		if bad != nil {
			idx = int((uintptr(unsafe.Pointer(bad)) - uintptr(unsafe.Pointer(&q.state.swr[0]))) / unsafe.Sizeof(ibvSendWR{}))
		}
		return idx, errnoError("post send", rc)
	}
	return len(wrs), nil
}

// PostRecv posts a batch of receive work requests with one call into
// ibv_post_recv. | PostRecv 以一次 ibv_post_recv 调用提交一批接收工作请求。
func (q *QP) PostRecv(wrs []RecvWR) (int, error) {
	if q == nil || q.closed.Load() {
		return 0, ErrClosed
	}
	if len(wrs) == 0 {
		return 0, nil
	}
	if len(wrs) > q.state.rcap {
		return 0, errs.Detail(ErrQueueFull, "batch %d exceeds receive queue %d | 批量 %d 超过接收队列 %d",
			len(wrs), q.state.rcap, len(wrs), q.state.rcap)
	}
	for i := range wrs {
		w := &wrs[i]
		s := &q.state.rwr[i]
		*s = ibvRecvWR{}
		s.WRID = w.WRID
		sges := q.state.rsge[i*MaxSGE : (i+1)*MaxSGE]
		s.SGList = &sges[0]
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
		s.NumSGE = int32(nsge)
		if i+1 < len(wrs) {
			s.Next = &q.state.rwr[i+1]
		}
	}
	rc, bad := q.dev.state.api.recv(q.dev.state.ctx, q.state.qp, &q.state.rwr[0])
	if rc != 0 {
		idx := 0
		if bad != nil {
			idx = int((uintptr(unsafe.Pointer(bad)) - uintptr(unsafe.Pointer(&q.state.rwr[0]))) / unsafe.Sizeof(ibvRecvWR{}))
		}
		return idx, errnoError("post receive", rc)
	}
	return len(wrs), nil
}

// LocalInfo returns this queue pair's parameters for the out-of-band
// handshake. | LocalInfo 返回本队列对用于带外握手的参数。
func (q *QP) LocalInfo(psn uint32) ConnectInfo {
	if q == nil || q.dev == nil {
		return ConnectInfo{}
	}
	return ConnectInfo{
		QPN:  q.qpn,
		PSN:  psn & 0xffffff,
		GID:  q.dev.gid.Addr,
		LID:  q.dev.portAttr.LID,
		MTU:  q.dev.cfg.MTU,
		QKey: 0x11111111,
	}
}

// Connect moves the queue pair through INIT, RTR and RTS using the local and
// remote parameters. The remote MTU caps the path MTU. | Connect 使用本地与
// 远端参数将队列对推进到 INIT、RTR 与 RTS。远端 MTU 限制路径 MTU。
func (q *QP) Connect(local, remote ConnectInfo) error {
	if q == nil || q.closed.Load() {
		return ErrClosed
	}
	d := q.dev
	port := uint8(d.port)
	mtu := remote.MTU
	if mtu <= 0 {
		mtu = d.cfg.MTU
	}
	if d.cfg.MTU > 0 && mtu > d.cfg.MTU {
		mtu = d.cfg.MTU
	}
	qkey := remote.QKey
	if qkey == 0 {
		qkey = 0x11111111
	}
	initAttr := QPAttr{
		Mask:  QPAttrState | QPAttrPKeyIndex | QPAttrPort | QPAttrAccessFlags,
		State: QPStateInit, PKeyIndex: 0, Port: port, Access: AccessDefault,
	}
	if q.typ == QPTypeUD {
		// Unreliable datagram queue pairs reject access flags at INIT and use a
		// QKey instead. | 不可靠数据报队列对在 INIT 拒绝访问标志，改用 QKey。
		initAttr.Mask = QPAttrState | QPAttrPKeyIndex | QPAttrPort | QPAttrQKey
		initAttr.Access = 0
		initAttr.QKey = qkey
	}
	if err := q.Modify(initAttr); err != nil {
		return errs.WrapDetail(err, ErrInvalidConfig, "INIT | INIT")
	}
	ah := AHAttr{
		IsGlobal: true, GID: remote.GID, DLID: remote.LID,
		SGIDIndex: uint8(d.cfg.GIDIndex), HopLimit: 0xff, Port: port,
	}
	if q.typ == QPTypeUD {
		// UD sends carry their address handle per work request, so RTR only
		// needs the state transition; an address vector is rejected here. |
		// UD 发送在每次工作请求中携带地址句柄，因此 RTR 只需状态迁移；
		// 此处提交地址向量会被拒绝。
		if err := q.Modify(QPAttr{Mask: QPAttrState, State: QPStateRTR}); err != nil {
			return errs.WrapDetail(err, ErrInvalidConfig, "UD RTR | UD RTR")
		}
		if err := q.Modify(QPAttr{
			Mask: QPAttrState | QPAttrSQPSN, State: QPStateRTS, SQPSN: local.PSN,
		}); err != nil {
			return errs.WrapDetail(err, ErrInvalidConfig, "UD RTS | UD RTS")
		}
		return nil
	}
	if err := q.Modify(QPAttr{
		Mask: QPAttrState | QPAttrPathMTU | QPAttrDestQPN | QPAttrRQPSN |
			QPAttrAV | QPAttrMinRNRTimer | QPAttrMaxDestRDAtomic,
		State: QPStateRTR, PathMTU: mtu, DestQPN: remote.QPN, RQPSN: remote.PSN,
		MinRNRTimer: 12, MaxDestRDMAtomic: 16, AH: ah,
	}); err != nil {
		return errs.WrapDetail(err, ErrInvalidConfig, "RTR | RTR")
	}
	mask := QPAttrState | QPAttrSQPSN | QPAttrTimeout | QPAttrRetryCount | QPAttrRNRRetry
	if q.typ == QPTypeRC {
		mask |= QPAttrMaxQPRDAtomic
	}
	if err := q.Modify(QPAttr{
		Mask: mask, State: QPStateRTS, SQPSN: local.PSN,
		Timeout: d.cfg.Timeout, RetryCount: d.cfg.RetryCount, RNRRetry: d.cfg.RNRRetry,
		MaxRDMAtomic: d.cfg.MaxRDMAtomic,
	}); err != nil {
		return errs.WrapDetail(err, ErrInvalidConfig, "RTS | RTS")
	}
	return nil
}

// Modify applies queue pair attributes. | Modify 应用队列对属性。
func (q *QP) Modify(attr QPAttr) error {
	if q == nil || q.closed.Load() {
		return ErrClosed
	}
	var a ibvQPAttr
	a.QPState = uint32(attr.State)
	a.CurQPState = uint32(attr.CurState)
	a.PathMTU = mtuEnum(attr.PathMTU)
	a.PathMigState = attr.PathMigState
	a.QKey = attr.QKey
	a.RQPSN = attr.RQPSN
	a.SQPSN = attr.SQPSN
	a.DestQPN = attr.DestQPN
	a.QPAccessFlags = uint32(attr.Access)
	a.PKeyIndex = attr.PKeyIndex
	a.AltPKeyIndex = attr.AltPKeyIndex
	a.MaxRDAtomic = attr.MaxRDMAtomic
	a.MaxDestRDAtomic = attr.MaxDestRDMAtomic
	a.MinRNRTimer = attr.MinRNRTimer
	a.PortNum = attr.Port
	a.Timeout = attr.Timeout
	a.RetryCnt = attr.RetryCount
	a.RNRRetry = attr.RNRRetry
	a.AHAttr.IsGlobal = boolByte(attr.AH.IsGlobal)
	a.AHAttr.DLID = attr.AH.DLID
	a.AHAttr.SL = attr.AH.SL
	a.AHAttr.SrcPathBits = attr.AH.SrcPathBits
	a.AHAttr.StaticRate = attr.AH.StaticRate
	a.AHAttr.PortNum = attr.AH.Port
	a.AHAttr.GRH.DGID = attr.AH.GID
	a.AHAttr.GRH.FlowLabel = attr.AH.FlowLabel
	a.AHAttr.GRH.SGIDIndex = attr.AH.SGIDIndex
	a.AHAttr.GRH.HopLimit = attr.AH.HopLimit
	a.AHAttr.GRH.TrafficClass = attr.AH.TrafficClass
	if rc := q.dev.state.api.modify(q.state.qp, &a, attr.Mask); rc != 0 {
		return errnoError("modify queue pair", rc)
	}
	return nil
}

// State returns the current queue pair state. | State 返回当前队列对状态。
func (q *QP) State() (QPState, error) {
	if q == nil || q.closed.Load() {
		return QPStateErr, ErrClosed
	}
	state, rc := q.dev.state.api.state(q.state.qp)
	if rc != 0 {
		return QPStateErr, errnoError("query queue pair", rc)
	}
	return state, nil
}

// Close destroys the queue pair. Completion queues and memory regions must be
// closed after it. | Close 销毁队列对。完成队列与内存区必须在其后关闭。
func (q *QP) Close() error {
	if q == nil || !q.closed.CompareAndSwap(false, true) {
		return nil
	}
	if q.state != nil && q.state.qp != nil {
		q.dev.state.api.removeQP(q.state.qp)
		q.state.qp = nil
	}
	return nil
}
