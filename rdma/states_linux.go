//go:build linux && rdma && (amd64 || arm64)

package rdma

// Platform handles for the purego backend. | purego 后端的平台句柄。
type deviceOps struct {
	postSend    uintptr
	postRecv    uintptr
	pollCQ      uintptr
	postSRQRecv uintptr
}

type deviceState struct {
	api *verbsAPI
	ctx *ibvContext
	pd  *ibvPD
	ops deviceOps
}

type cqState struct {
	cq      *ibvCQ
	scratch []ibvWC
	pollFn  uintptr
}

type qpState struct {
	qp     *ibvQP
	swr    []ibvSendWR
	ssge   []ibvSGE
	rwr    []ibvRecvWR
	rsge   []ibvSGE
	scap   int
	rcap   int
	sendFn uintptr
	recvFn uintptr
}

type srqState struct {
	srq    *ibvSRQ
	rwr    []ibvRecvWR
	rsge   []ibvSGE
	cap    int
	recvFn uintptr
}

type ahState struct {
	api *verbsAPI
	ah  *ibvAH
}
