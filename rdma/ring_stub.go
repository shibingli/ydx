//go:build !(linux && rdma && (amd64 || arm64))

package rdma

import (
	"context"
	"net"
)

// Ring is unavailable without the rdma build tag. | 无 rdma 构建标签时 Ring 不可用。
type Ring struct{}

// RingListener is unavailable without the rdma build tag. | 无 rdma 构建标签时 RingListener 不可用。
type RingListener struct{}

// ListenRing returns ErrUnsupported without the rdma build tag.
// ListenRing 在无 rdma 构建标签时返回 ErrUnsupported。
func ListenRing(string, RingConfig) (*RingListener, error) { return nil, ErrUnsupported }

// DialRing returns ErrUnsupported without the rdma build tag.
// DialRing 在无 rdma 构建标签时返回 ErrUnsupported。
func DialRing(string, RingConfig) (*Ring, error) { return nil, ErrUnsupported }

func (l *RingListener) Addr() net.Addr         { return nil }
func (l *RingListener) Accept() (*Ring, error) { return nil, ErrUnsupported }
func (l *RingListener) Close() error           { return nil }

func (r *Ring) LocalInfo() RingInfo { return RingInfo{} }
func (r *Ring) WriteWithImm(context.Context, []byte, uint32) (uint32, error) {
	return 0, ErrUnsupported
}
func (r *Ring) Poll(context.Context, int) ([]RingMessage, error) { return nil, ErrUnsupported }
func (r *Ring) Ack(context.Context, uint32) error                { return ErrUnsupported }
func (r *Ring) Close() error                                     { return nil }
