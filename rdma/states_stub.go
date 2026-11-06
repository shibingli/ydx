//go:build !linux || !rdma || !(amd64 || arm64)

package rdma

// Platform handles are empty without the rdma build tag. | 没有 rdma 构建标签
// 时平台句柄为空。
type deviceState struct{}

type cqState struct{}

type qpState struct{}

type srqState struct{}

// SendQueueDepth returns zero without an RDMA backend. | SendQueueDepth 在无
// RDMA 后端时返回零。
func (q *QP) SendQueueDepth() int { return 0 }

// RecvQueueDepth returns zero without an RDMA backend. | RecvQueueDepth 在无
// RDMA 后端时返回零。
func (q *QP) RecvQueueDepth() int { return 0 }

type ahState struct{}
