//go:build linux

package nodeid

import (
	"os"
	"path/filepath"
	"strings"

	"golang.org/x/sys/unix"
)

// Linux platform sources and storage classification. | Linux 平台来源与存储判定。
var (
	machineIDPaths = []string{"/etc/machine-id", "/var/lib/dbus/machine-id"}
	dmiUUIDPath    = "/sys/class/dmi/id/product_uuid"
	dmiSerialPaths = []string{"/sys/class/dmi/id/product_serial", "/sys/class/dmi/id/board_serial"}
	dmiVendorPath  = "/sys/class/dmi/id/sys_vendor"
	dmiProductPath = "/sys/class/dmi/id/product_name"
)

// platformFacts returns DMI vendor and product names. | platformFacts 返回 DMI 厂商与产品名。
func platformFacts() (string, string) {
	return readTrim(dmiVendorPath), readTrim(dmiProductPath)
}

// platformSeed returns the best Linux seed. Containers skip host-derived seeds
// unless allowShared is set, because every container on the host sees the same
// machine-id and DMI values. | platformSeed 返回最佳的 Linux 种子。容器默认跳过宿主相关的
// 种子，因为宿主机上的每个容器都会看到相同的 machine-id 与 DMI 值。
func platformSeed(env Environment, allowShared bool) (Source, string, bool) {
	if !hostSeedAllowed(env, allowShared) {
		return "", "", false
	}
	for _, path := range machineIDPaths {
		if value := strings.ToLower(readTrim(path)); validMachineID(value) {
			return SourceMachineID, value, true
		}
	}
	if value := strings.ToLower(readTrim(dmiUUIDPath)); validUUID(value) {
		return SourceSMBIOS, value, true
	}
	for _, path := range dmiSerialPaths {
		if value := cleanSerial(readTrim(path)); value != "" {
			return SourceSMBIOS, value, true
		}
	}
	return "", "", false
}

// durablePath reports whether path lives on a filesystem that survives container
// recreation. | durablePath 报告 path 是否位于能跨容器重建存活的文件系统上。
func durablePath(path string) bool {
	existing := existingPath(path)
	var stat unix.Statfs_t
	if err := unix.Statfs(existing, &stat); err != nil {
		return true
	}
	switch stat.Type {
	case unix.OVERLAYFS_SUPER_MAGIC, unix.TMPFS_MAGIC, unix.RAMFS_MAGIC:
		return false
	default:
		return true
	}
}

// existingPath walks up until it finds an existing ancestor. | existingPath 向上查找，直到
// 找到存在的祖先路径。
func existingPath(path string) string {
	absolute, err := filepath.Abs(path)
	if err != nil {
		absolute = path
	}
	for {
		if _, err := os.Stat(absolute); err == nil {
			return absolute
		}
		parent := filepath.Dir(absolute)
		if parent == absolute {
			return absolute
		}
		absolute = parent
	}
}
