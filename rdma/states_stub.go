//go:build !linux || !rdma || !(amd64 || arm64)

package rdma

// Platform handles are empty without the rdma build tag. | 没有 rdma 构建标签
// 时平台句柄为空。
type deviceState struct{}

type cqState struct{}

type qpState struct{}

type srqState struct{}

type ahState struct{}
