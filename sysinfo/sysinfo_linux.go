//go:build linux

package sysinfo

import (
	"os"
	"path"
	"strings"
)

// meminfo reads /proc/meminfo once per call. | meminfo 每次调用读取一次 /proc/meminfo。
func meminfo() map[string]uint64 {
	data, err := os.ReadFile("/proc/meminfo")
	if err != nil {
		return nil
	}
	return parseMeminfo(string(data))
}

func readTotalMemory() uint64 {
	return meminfo()["MemTotal"]
}

// pathWithin reports whether p is root or lies below it. | pathWithin 报告 p 是否等于 root
// 或位于其下。
func pathWithin(p, root string) bool {
	return p == root || strings.HasPrefix(p, root+"/")
}

// cgroupAncestorMemoryFiles returns the memory limit files from base up to and including mount,
// nearest first. In cgroup v2 the effective limit is the smallest memory.max along this path, so
// every ancestor must be consulted rather than only the leaf and the mount root. |
// cgroupAncestorMemoryFiles 返回从 base 到挂载根（含）的内存限额文件，由近及远。cgroup v2 的
// 有效上限是路径上最小的 memory.max，因此必须检查每一层祖先，而不是只看叶子与挂载根。
func cgroupAncestorMemoryFiles(base, mount, name string) []string {
	if !pathWithin(base, mount) {
		return nil
	}
	files := make([]string, 0, 8)
	for {
		files = append(files, path.Join(base, name))
		if base == mount {
			return files
		}
		parent := path.Dir(base)
		if parent == base || !pathWithin(parent, mount) {
			return files
		}
		base = parent
	}
}

// cgroupMemoryFiles returns the cgroup v2 and v1 memory limit/usage files for
// the current process, with the root fallbacks. | cgroupMemoryFiles 返回当前进程的
// cgroup v2/v1 内存限额与用量文件，并附带根目录回退。
func cgroupMemoryFiles() (limits, usages []string) {
	limits = []string{
		"/sys/fs/cgroup/memory.max",
		"/sys/fs/cgroup/memory/memory.limit_in_bytes",
	}
	usages = []string{
		"/sys/fs/cgroup/memory.current",
		"/sys/fs/cgroup/memory/memory.usage_in_bytes",
	}
	data, err := os.ReadFile("/proc/self/cgroup")
	if err != nil {
		return limits, usages
	}
	for _, line := range strings.Split(string(data), "\n") {
		parts := strings.SplitN(line, ":", 3)
		if len(parts) != 3 {
			continue
		}
		if parts[0] == "0" && parts[1] == "" {
			rel := strings.TrimPrefix(parts[2], "/")
			mount := "/sys/fs/cgroup"
			base := path.Join(mount, rel)
			if !pathWithin(base, mount) {
				continue
			}
			limits = append(cgroupAncestorMemoryFiles(base, mount, "memory.max"), limits...)
			usages = append([]string{path.Join(base, "memory.current")}, usages...)
			continue
		}
		// The controller list is comma-separated and often co-mounted, for example
		// "memory,cpu,cpuacct"; equality with "memory" misses those hosts and reports the host
		// total instead of the container limit. | 控制器列表以逗号分隔且常被共同挂载，例如
		// "memory,cpu,cpuacct"；与 "memory" 全等比较会漏掉这类主机，返回主机总量而不是容器上限。
		hasMemory := false
		for _, controller := range strings.Split(parts[1], ",") {
			if strings.TrimSpace(controller) == "memory" {
				hasMemory = true
				break
			}
		}
		if hasMemory {
			rel := strings.TrimPrefix(parts[2], "/")
			mount := "/sys/fs/cgroup/memory"
			base := path.Join(mount, rel)
			if !pathWithin(base, mount) {
				continue
			}
			limits = append(cgroupAncestorMemoryFiles(base, mount, "memory.limit_in_bytes"), limits...)
			usages = append([]string{path.Join(base, "memory.usage_in_bytes")}, usages...)
		}
	}
	return limits, usages
}

func readFileUint(path string) uint64 {
	data, err := os.ReadFile(path)
	if err != nil {
		return 0
	}
	return parseLimit(string(data))
}

func readMemoryLimit() uint64 {
	limits, _ := cgroupMemoryFiles()
	var cgroup uint64
	for _, p := range limits {
		n := readFileUint(p)
		if n == 0 {
			continue
		}
		// The effective cgroup v2 limit is the smallest numeric memory.max along the path;
		// a leaf may say "max" while an ancestor is stricter, and a parent may be smaller
		// than the leaf. | cgroup v2 的有效上限是路径上最小的数值 memory.max；叶子可能是
		// "max" 而祖先更严格，父级也可能小于叶子。
		if cgroup == 0 || n < cgroup {
			cgroup = n
		}
	}
	return clampLimit(cgroup, readTotalMemory())
}

func readAvailableMemory() uint64 {
	mi := meminfo()
	avail := mi["MemAvailable"]
	if avail == 0 {
		avail = mi["MemFree"]
	}
	limit := MemoryLimit()
	if limit == 0 {
		return avail
	}
	_, usages := cgroupMemoryFiles()
	var used uint64
	for _, p := range usages {
		if n := readFileUint(p); n != 0 {
			used = n
			break
		}
	}
	if used < limit {
		room := limit - used
		if avail == 0 || room < avail {
			return room
		}
	}
	return avail
}
