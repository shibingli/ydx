// Package raft contains benchmarks comparing ydx/raft with etcd raft and
// hashicorp/raft under the same in-memory storage and transport conditions.
// | Package raft 包含在相同内存存储与传输条件下，将 ydx/raft 与 etcd raft、
// hashicorp/raft 进行对比的基准。
//
// Every implementation uses one Raft group, in-memory persistence, an in-memory
// transport, the same 64-byte proposal payload, the same 100ms election cadence
// and waits for the proposal to be applied before the next operation. | 每个实现
// 都使用单组 Raft、内存持久化、内存传输、相同的 64 字节提案负载、相同的 100ms 选举
// 节奏，并在下一次操作前等待提案被应用。
//
// Run from this directory with a workspace that maps ydx/raft to the local
// module: | 在本目录使用将 ydx/raft 映射到本地模块的工作区运行：
//
//	GOWORK=/path/to/ydx-raft.work go test -bench . -benchmem -count=5
package raft
