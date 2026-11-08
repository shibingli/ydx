//go:build windows

package webauthn

import (
	"errors"
	"testing"
	"time"
)

// TestWindowsTPMRejectsInvalidCommands checks TBS command framing and closed-context handling without
// opening a TPM. | TestWindowsTPMRejectsInvalidCommands 在不打开 TPM 的情况下校验 TBS 命令框架与
// 已关闭上下文处理。
func TestWindowsTPMRejectsInvalidCommands(t *testing.T) {
	device := &windowsTPM{timeout: time.Second}
	if _, err := device.Execute(t.Context(), []byte{0x80}); !errors.Is(err, ErrTPMStructure) {
		t.Fatalf("malformed command error = %v, want ErrTPMStructure", err)
	}
	closed := &windowsTPM{timeout: time.Second, closed: true}
	if _, err := closed.Execute(t.Context(), testReadPublicCommand()); !errors.Is(err, ErrTPMTransport) {
		t.Fatalf("closed transport error = %v, want ErrTPMTransport", err)
	}
}
