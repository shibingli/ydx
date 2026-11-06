//go:build arm64

package wal

import "golang.org/x/sys/cpu"

// detectCPU fills arm64 feature flags. | detectCPU 填充 arm64 特性标志。
func detectCPU(info *EngineInfo) {
	info.CRC32CHardware = cpu.ARM64.HasCRC32
	info.AESGCMHardware = cpu.ARM64.HasAES
	info.SM3Hardware = cpu.ARM64.HasSM3 || cpu.ARM64.HasSHA2
	info.SM4Hardware = cpu.ARM64.HasSM4 || cpu.ARM64.HasAES
}
