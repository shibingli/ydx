package nodeid

import (
	"errors"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"time"

	"github.com/shibingli/ydx/errs"
)

// FileEnv overrides the identity file path without a config object. | FileEnv 在没有配置对象时
// 覆盖身份文件路径。
const FileEnv = "YD_NODE_ID_FILE"

// DefaultFile returns the identity file used when Options.File is empty. It
// honours FileEnv, then prefers %ProgramData%\yd\node-id on Windows and the
// per-user configuration directory elsewhere. The file is created only when
// Options.Create is set. | DefaultFile 返回 Options.File 为空时使用的身份文件。它优先读取
// FileEnv，其次在 Windows 使用 %ProgramData%\yd\node-id，其它平台使用用户配置目录。只有
// Options.Create 为真时才会创建该文件。
func DefaultFile() (string, error) {
	if value := strings.TrimSpace(os.Getenv(FileEnv)); value != "" {
		return value, nil
	}
	if runtime.GOOS == "windows" {
		if programData := strings.TrimSpace(os.Getenv("ProgramData")); programData != "" {
			return filepath.Join(programData, "yd", "node-id"), nil
		}
	}
	dir, err := os.UserConfigDir()
	if err != nil {
		return "", errs.Wrap(err, ErrIdentityFile)
	}
	return filepath.Join(dir, "yd", "node-id"), nil
}

// IsDurable reports whether path is on storage that is expected to survive a
// container or instance recreation. The temporary directory and Linux
// overlay/tmpfs/ramfs mounts are not durable. This is a best-effort signal: a
// bind mount into a container can look durable while still being a host path,
// which is exactly what a per-instance volume wants. | IsDurable 报告 path 是否位于预期
// 能跨容器/实例重建存活的存储上。临时目录以及 Linux overlay/tmpfs/ramfs 挂载不算持久。这是
// 尽力而为的信号：挂载进容器的 bind mount 可能看起来持久，但它实际上就是宿主机路径——这正是
// 每实例独立卷想要的效果。
func IsDurable(path string) bool {
	abs, err := filepath.Abs(path)
	if err != nil {
		return durablePath(path)
	}
	if tmp, tmpErr := filepath.Abs(os.TempDir()); tmpErr == nil {
		if rel, relErr := filepath.Rel(tmp, abs); relErr == nil {
			inside := rel == "." || (rel != ".." && !strings.HasPrefix(rel, ".."+string(os.PathSeparator)))
			if inside {
				return false
			}
		}
	}
	return durablePath(path)
}

// readIdentity reads and validates one id from path. | readIdentity 从 path 读取并校验一个 id。
func readIdentity(path string) (string, error) {
	f, err := os.Open(path)
	if err != nil {
		return "", err
	}
	defer func() { _ = f.Close() }()

	raw, err := io.ReadAll(io.LimitReader(f, MaxIDLength+2))
	if err != nil {
		return "", err
	}
	if len(raw) > MaxIDLength+1 {
		return "", errs.Detail(ErrCorrupt, "file %[1]q is longer than %[2]d bytes | 文件 %[1]q 超过 %[2]d 字节", path, MaxIDLength+1)
	}
	id := strings.TrimSpace(string(raw))
	if id == "" {
		return "", errs.Detail(ErrCorrupt, "file %[1]q is empty | 文件 %[1]q 为空", path)
	}
	if strings.ContainsAny(id, "\r\n") {
		return "", errs.Detail(ErrCorrupt, "file %[1]q contains multiple lines | 文件 %[1]q 含多行", path)
	}
	if err := Validate(id); err != nil {
		return "", errs.WrapDetail(err, ErrCorrupt, "file %[1]q | 文件 %[1]q", path)
	}
	return id, nil
}

// writeIdentity stores id at path without ever exposing a partial identity. It
// returns the id that won: another process may have created the file first. |
// writeIdentity 把 id 写入 path，且绝不暴露不完整的身份。它返回最终生效的 id：另一个进程可能
// 先创建了文件。
func writeIdentity(path, id string) (string, error) {
	dir := filepath.Dir(path)
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return "", err
	}

	tmp, err := os.CreateTemp(dir, ".node-id-*")
	if err != nil {
		return "", err
	}
	tmpName := tmp.Name()
	defer func() { _ = os.Remove(tmpName) }()

	if _, err := tmp.WriteString(id + "\n"); err != nil {
		_ = tmp.Close()
		return "", err
	}
	if err := tmp.Sync(); err != nil {
		_ = tmp.Close()
		return "", err
	}
	if err := tmp.Close(); err != nil {
		return "", err
	}
	if err := os.Chmod(tmpName, 0o600); err != nil {
		return "", err
	}

	// A hard link publishes the complete file atomically and fails if a racing
	// process already created it. | 硬链接原子发布完整文件，且会在竞争进程已创建时失败。
	linkErr := os.Link(tmpName, path)
	if linkErr == nil {
		return id, nil
	}
	if errors.Is(linkErr, fs.ErrExist) {
		return waitForIdentity(path)
	}

	// Filesystems without hard links fall back to an exclusive create. |
	// 不支持硬链接的文件系统回退到独占创建。
	f, err := os.OpenFile(path, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0o600)
	if err != nil {
		if errors.Is(err, fs.ErrExist) {
			return waitForIdentity(path)
		}
		return "", err
	}
	if _, err := f.WriteString(id + "\n"); err != nil {
		_ = f.Close()
		_ = os.Remove(path)
		return "", err
	}
	if err := f.Sync(); err != nil {
		_ = f.Close()
		_ = os.Remove(path)
		return "", err
	}
	if err := f.Close(); err != nil {
		return "", err
	}
	return id, nil
}

// waitForIdentity reads an id written by a racing process, allowing a short
// window for its write to become visible. | waitForIdentity 读取竞争进程写入的 id，并为其写入
// 可见留出短暂窗口。
func waitForIdentity(path string) (string, error) {
	deadline := time.Now().Add(2 * time.Second)
	for {
		id, err := readIdentity(path)
		if err == nil {
			return id, nil
		}
		if time.Now().After(deadline) {
			return "", err
		}
		time.Sleep(20 * time.Millisecond)
	}
}
