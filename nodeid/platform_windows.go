//go:build windows

package nodeid

import (
	"strings"

	"golang.org/x/sys/windows/registry"
)

// Windows platform sources. MachineGuid is the per-installation identifier and
// survives reboots, driver changes and most hardware upgrades; a clean reinstall
// changes it, and the identity file is what carries the id across a reinstall. |
// Windows 平台来源。MachineGuid 是每次安装的标识，跨重启、驱动变更与多数硬件升级保持不变；
// 全新安装会改变它，跨安装保持身份靠的是身份文件。
const (
	machineGUIDKey   = `SOFTWARE\Microsoft\Cryptography`
	machineGUIDValue = "MachineGuid"
	biosKey          = `HARDWARE\DESCRIPTION\System\BIOS`
	biosVendorValue  = "SystemManufacturer"
	biosProductValue = "SystemProductName"
)

// platformFacts returns BIOS vendor and product names for VM detection. |
// platformFacts 返回用于虚机检测的 BIOS 厂商与产品名。
func platformFacts() (string, string) {
	return readRegistryString(biosKey, biosVendorValue), readRegistryString(biosKey, biosProductValue)
}

// platformSeed returns the Windows MachineGuid. Containers skip host-derived
// seeds unless allowShared is set. | platformSeed 返回 Windows MachineGuid。容器默认跳过
// 宿主相关的种子，除非 allowShared 为真。
func platformSeed(env Environment, allowShared bool) (Source, string, bool) {
	if !hostSeedAllowed(env, allowShared) {
		return "", "", false
	}
	value := strings.TrimSpace(readRegistryString(machineGUIDKey, machineGUIDValue))
	if len(value) < 16 || strings.ContainsAny(value, " \t\r\n") {
		return "", "", false
	}
	return SourcePlatform, strings.ToLower(value), true
}

// durablePath returns true on Windows; the common temporary-directory check in
// IsDurable still rejects %TEMP%. | durablePath 在 Windows 返回 true；IsDurable 中通用的
// 临时目录检查仍会拒绝 %TEMP%。
func durablePath(string) bool { return true }

// readRegistryString reads one string value, returning "" on any failure. |
// readRegistryString 读取一个字符串值，任何失败都返回空串。
func readRegistryString(path, name string) string {
	key, err := registry.OpenKey(registry.LOCAL_MACHINE, path, registry.QUERY_VALUE|registry.WOW64_64KEY)
	if err != nil {
		return ""
	}
	defer func() { _ = key.Close() }()
	value, _, err := key.GetStringValue(name)
	if err != nil {
		return ""
	}
	return strings.TrimSpace(value)
}
