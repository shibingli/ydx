//go:build !(linux && cgo && rdma)

package raft

import "github.com/shibingli/ydx/errs"

// RDMAAvailable reports whether this build can perform real RDMA. | RDMAAvailable
// 报告当前构建能否执行真实 RDMA。
func RDMAAvailable() bool { return false }

// NewRDMATransport returns ErrUnsupported unless built with -tags rdma on Linux
// with cgo. | 只有在 Linux + cgo 下以 -tags rdma 构建时，NewRDMATransport 才可用；
// 否则返回 ErrUnsupported。
func NewRDMATransport(opts RDMATransportOptions) (*RDMATransport, error) {
	_ = opts
	return nil, errs.Detail(ErrUnsupported, "build with CGO_ENABLED=1 and -tags rdma on Linux with libibverbs/librdmacm")
}
