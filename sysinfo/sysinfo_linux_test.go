//go:build linux

package sysinfo

import (
	"reflect"
	"testing"
)

// TestCgroupAncestorMemoryFiles walks from the leaf to the mount root. |
// TestCgroupAncestorMemoryFiles 验证从叶子到挂载根的祖先遍历。
func TestCgroupAncestorMemoryFiles(t *testing.T) {
	got := cgroupAncestorMemoryFiles("/sys/fs/cgroup/kubepods/pod1/ctr1", "/sys/fs/cgroup", "memory.max")
	want := []string{
		"/sys/fs/cgroup/kubepods/pod1/ctr1/memory.max",
		"/sys/fs/cgroup/kubepods/pod1/memory.max",
		"/sys/fs/cgroup/kubepods/memory.max",
		"/sys/fs/cgroup/memory.max",
	}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("ancestors = %v, want %v | 祖先文件列表不符", got, want)
	}
	if got := cgroupAncestorMemoryFiles("/sys/fs/cgroup", "/sys/fs/cgroup", "memory.max"); !reflect.DeepEqual(got, []string{"/sys/fs/cgroup/memory.max"}) {
		t.Fatalf("root ancestors = %v | 挂载根文件列表不符", got)
	}
}

// TestCgroupAncestorMemoryFilesRejectsEscapes pins that a cgroup path leaving the mount root
// yields no files instead of reading unrelated host paths. |
// TestCgroupAncestorMemoryFilesRejectsEscapes 固定越过挂载根的 cgroup 路径不产生文件，避免读取
// 无关的主机路径。
func TestCgroupAncestorMemoryFilesRejectsEscapes(t *testing.T) {
	for _, base := range []string{"/sys/fs/cgroup2/a", "/sys/fs", "/"} {
		if got := cgroupAncestorMemoryFiles(base, "/sys/fs/cgroup", "memory.max"); got != nil {
			t.Fatalf("base %q: files = %v, want nil | 越界路径应返回空", base, got)
		}
	}
}
