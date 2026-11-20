package config_test

import (
	"errors"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"

	"github.com/spf13/afero"

	"github.com/shibingli/ydx/afs"
	"github.com/shibingli/ydx/config"
)

// TestWriteConfigAsUsesSecurePermissions asserts a written config file is
// created with owner-only permissions and that no temporary file is left
// behind. | TestWriteConfigAsUsesSecurePermissions 断言写出的配置文件使用仅属主
// 可读写的权限，且不残留临时文件。
func TestWriteConfigAsUsesSecurePermissions(t *testing.T) {
	dir := t.TempDir()
	base := filepath.Join(dir, "config.yaml")
	writeTestFile(t, base, "server:\n  port: 8080\n")

	c, err := config.Load(config.Options{
		Name:       "write-test",
		ConfigDir:  dir,
		ConfigName: "config",
		EnvPrefix:  "YDCONFIGWRITETEST",
		EnvFile:    filepath.Join(dir, "absent.env"),
	})
	if err != nil {
		t.Fatalf("config.Load 失败: %v", err)
	}
	c.Set("server.port", 9090)

	out := filepath.Join(dir, "written.yaml")
	if err := c.WriteConfigAs(out); err != nil {
		t.Fatalf("WriteConfigAs 失败: %v", err)
	}
	info, err := os.Stat(out)
	if err != nil {
		t.Fatalf("Stat 失败: %v", err)
	}
	// Windows reports synthesized permission bits (0666 for writable files), so
	// the mode assertion is only meaningful on the Unix targets. | Windows 对可写
	// 文件返回合成的 0666 权限位，因此权限断言只在 Unix 目标上有意义。
	if runtime.GOOS != "windows" {
		if perm := info.Mode().Perm(); perm != 0o600 {
			t.Fatalf("WriteConfigAs 权限 = %o, 期望 600", perm)
		}
	}
	data, err := os.ReadFile(out)
	if err != nil {
		t.Fatalf("ReadFile 失败: %v", err)
	}
	if !strings.Contains(string(data), "9090") {
		t.Fatalf("写出的配置缺少更新值: %q", data)
	}
	leftovers, err := filepath.Glob(filepath.Join(dir, ".written.yaml.tmp-*"))
	if err != nil {
		t.Fatalf("Glob 失败: %v", err)
	}
	if len(leftovers) != 0 {
		t.Fatalf("残留临时文件: %v", leftovers)
	}

	if err := c.SafeWriteConfigAs(out); !errors.Is(err, config.ErrConfigExists) {
		t.Fatalf("SafeWriteConfigAs 已存在文件错误 = %v, 期望 ErrConfigExists", err)
	}
}

// TestWriteConfigAsPermissionsOnMemoryFS asserts the writer requests mode 0600
// on a filesystem that preserves permission bits, independent of the host OS. |
// TestWriteConfigAsPermissionsOnMemoryFS 在保留权限位的文件系统上断言写入方请求
// 0600，且该断言与宿主 OS 无关。
func TestWriteConfigAsPermissionsOnMemoryFS(t *testing.T) {
	mem := afs.NewMem()
	if err := afero.WriteFile(mem, "config.yaml", []byte("server:\n  port: 8080\n"), 0o644); err != nil {
		t.Fatalf("写入夹具失败: %v", err)
	}
	c, err := config.Load(config.Options{
		Name:       "write-test",
		ConfigDir:  ".",
		ConfigName: "config",
		EnvPrefix:  "YDCONFIGWRITETEST",
		EnvFile:    "absent.env",
		FS:         mem,
	})
	if err != nil {
		t.Fatalf("config.Load 失败: %v", err)
	}
	if err := c.WriteConfigAs("written.yaml"); err != nil {
		t.Fatalf("WriteConfigAs 失败: %v", err)
	}
	info, err := mem.Stat("written.yaml")
	if err != nil {
		t.Fatalf("Stat 失败: %v", err)
	}
	if perm := info.Mode().Perm(); perm != 0o600 {
		t.Fatalf("WriteConfigAs 权限 = %o, 期望 600", perm)
	}
}

// TestWriteConfigUsesLoadedPath asserts WriteConfig rewrites the file it was
// loaded from with the same secure permissions. | TestWriteConfigUsesLoadedPath
// 断言 WriteConfig 以同样安全的权限重写已加载的文件。
func TestWriteConfigUsesLoadedPath(t *testing.T) {
	dir := t.TempDir()
	base := filepath.Join(dir, "config.yaml")
	writeTestFile(t, base, "server:\n  port: 8080\n")

	c, err := config.Load(config.Options{
		Name:       "write-test",
		ConfigDir:  dir,
		ConfigName: "config",
		EnvPrefix:  "YDCONFIGWRITETEST",
		EnvFile:    filepath.Join(dir, "absent.env"),
	})
	if err != nil {
		t.Fatalf("config.Load 失败: %v", err)
	}
	c.Set("server.port", 8081)
	if err := c.WriteConfig(); err != nil {
		t.Fatalf("WriteConfig 失败: %v", err)
	}
	info, err := os.Stat(base)
	if err != nil {
		t.Fatalf("Stat 失败: %v", err)
	}
	if runtime.GOOS != "windows" {
		if perm := info.Mode().Perm(); perm != 0o600 {
			t.Fatalf("WriteConfig 权限 = %o, 期望 600", perm)
		}
	}
	data, err := os.ReadFile(base)
	if err != nil {
		t.Fatalf("ReadFile 失败: %v", err)
	}
	if !strings.Contains(string(data), "8081") {
		t.Fatalf("写出的配置缺少更新值: %q", data)
	}
}
