//go:build amd64

package wal

import "golang.org/x/sys/cpu"

// detectCPU fills amd64 feature flags. | detectCPU 填充 amd64 特性标志。
func detectCPU(info *EngineInfo) {
	info.CRC32CHardware = cpu.X86.HasSSE42
	info.AESGCMHardware = cpu.X86.HasAES
	info.SM3Hardware = cpu.X86.HasAVX2
	info.SM4Hardware = cpu.X86.HasAES
}
