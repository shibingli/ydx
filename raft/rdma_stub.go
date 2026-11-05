//go:build !(linux && rdma && (amd64 || arm64))

package raft

import "github.com/shibingli/ydx/errs"

// RDMAAvailable reports whether this build can perform real RDMA. | RDMAAvailable
// 报告当前构建能否执行真实 RDMA。
func RDMAAvailable() bool { return false }

// NewRDMATransport returns ErrUnsupported unless built with -tags rdma on
// Linux/amd64 or Linux/arm64. ydx/rdma is pure Go; cgo is not required. | 只有在
// Linux/amd64 或 Linux/arm64 下以 -tags rdma 构建时，NewRDMATransport 才可用；
// ydx/rdma 为纯 Go，不需要 cgo。否则返回 ErrUnsupported。
func NewRDMATransport(opts RDMATransportOptions) (*RDMATransport, error) {
	_ = opts
	return nil, errs.Detail(ErrUnsupported, "build with -tags rdma on Linux amd64/arm64 with libibverbs")
}
