//go:build !amd64 && !arm64

package wal

// detectCPU leaves portable defaults. | detectCPU 使用可移植默认值。
func detectCPU(*EngineInfo) {}
