//go:build darwin

package nodeid

import (
	"context"
	"os/exec"
	"strings"
	"time"
)

// platformFacts returns no Darwin-specific facts; VM detection falls back to the
// generic container checks. | platformFacts 不返回 Darwin 专属事实；虚机检测退回到通用容器
// 检查。
func platformFacts() (string, string) { return "", "" }

// platformSeed reads IOPlatformUUID from ioreg. The command is bounded to two
// seconds and a missing tool simply disables the seed. | platformSeed 从 ioreg 读取
// IOPlatformUUID。命令限制在两秒内，工具缺失时只是禁用该种子。
func platformSeed(env Environment, allowShared bool) (Source, string, bool) {
	if !hostSeedAllowed(env, allowShared) {
		return "", "", false
	}
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	output, err := exec.CommandContext(ctx, "ioreg", "-rd1", "-c", "IOPlatformExpertDevice").Output()
	if err != nil {
		return "", "", false
	}
	for _, line := range strings.Split(string(output), "\n") {
		if !strings.Contains(line, "IOPlatformUUID") {
			continue
		}
		parts := strings.Split(line, `"`)
		if len(parts) >= 4 {
			if value := strings.TrimSpace(parts[3]); value != "" {
				return SourcePlatform, strings.ToLower(value), true
			}
		}
	}
	return "", "", false
}

// durablePath returns true on macOS; the common temporary-directory check still
// rejects TMPDIR. | durablePath 在 macOS 返回 true；通用临时目录检查仍会拒绝 TMPDIR。
func durablePath(string) bool { return true }
