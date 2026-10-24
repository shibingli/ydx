package nodeid

import (
	"encoding/hex"
	"strings"
)

// hostSeedAllowed reports whether a platform seed may be used in this
// environment. Containers share the host's machine-id and SMBIOS values, so
// using them would give every replica the same identity. | hostSeedAllowed 报告当前环境
// 是否可以使用平台种子。容器共享宿主机的 machine-id 与 SMBIOS 值，使用它们会让每个副本得到同一
// 身份。
func hostSeedAllowed(env Environment, allowShared bool) bool {
	if env != EnvironmentContainer && env != EnvironmentKubernetes {
		return true
	}
	return allowShared
}

// validMachineID reports whether value is the 32-hex systemd machine id. |
// validMachineID 报告 value 是否为 32 位十六进制的 systemd machine-id。
func validMachineID(value string) bool {
	if len(value) != 32 {
		return false
	}
	_, err := hex.DecodeString(value)
	return err == nil
}

// validUUID reports whether value is a non-placeholder SMBIOS UUID. QEMU and
// some firmware report all-zero or fixed placeholder values that would make
// every virtual machine share one identity. | validUUID 报告 value 是否为非占位的 SMBIOS
// UUID。QEMU 与部分固件会报告全零或固定占位值，那会让所有虚机共享同一身份。
func validUUID(value string) bool {
	value = strings.ToLower(strings.TrimSpace(value))
	if len(value) != 36 {
		return false
	}
	compact := strings.ReplaceAll(value, "-", "")
	if len(compact) != 32 {
		return false
	}
	if _, err := hex.DecodeString(compact); err != nil {
		return false
	}
	switch value {
	case "00000000-0000-0000-0000-000000000000",
		"03000200-0400-0500-0006-000700080009":
		return false
	}
	return !strings.HasPrefix(value, "ffffffff-")
}

// cleanSerial rejects serial numbers that firmware uses as "not set". |
// cleanSerial 拒绝固件用来表示「未设置」的序列号。
func cleanSerial(value string) string {
	value = strings.TrimSpace(value)
	lower := strings.ToLower(value)
	switch lower {
	case "", "none", "not specified", "unknown", "default string",
		"to be filled by o.e.m.", "system serial number", "not applicable":
		return ""
	}
	for i := 0; i < len(lower); i++ {
		if lower[i] != '0' && lower[i] != ' ' && lower[i] != '-' && lower[i] != '.' {
			return value
		}
	}
	return ""
}
