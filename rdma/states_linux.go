//go:build linux && rdma && (amd64 || arm64)

package rdma

// Platform handles for the purego backend. | purego 后端的平台句柄。
type deviceState struct {
	api *verbsAPI
	ctx *ibvContext
	pd  *ibvPD
}

type cqState struct {
	cq      *ibvCQ
	scratch []ibvWC
}

type qpState struct {
	qp   *ibvQP
	swr  []ibvSendWR
	ssge []ibvSGE
	rwr  []ibvRecvWR
	rsge []ibvSGE
	scap int
	rcap int
}

type srqState struct {
	srq  *ibvSRQ
	rwr  []ibvRecvWR
	rsge []ibvSGE
	cap  int
}

type ahState struct {
	api *verbsAPI
	ah  *ibvAH
}
