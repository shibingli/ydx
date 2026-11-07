//go:build !linux || (!amd64 && !arm64)

package uring

import (
	"errors"
	"os"
	"testing"
)

// TestStubAPI verifies the platform stub exposes the same contract and fails
// explicitly. | 验证平台桩暴露相同契约并显式失败。
func TestStubAPI(t *testing.T) {
	if Supported() {
		t.Fatal("stub reported io_uring support")
	}
	if _, err := New(); !errors.Is(err, ErrUnsupported) {
		t.Fatalf("New err = %v, want ErrUnsupported", err)
	}
	var e Engine
	f, err := os.CreateTemp(t.TempDir(), "stub")
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	if err := e.WriteAt(f, [][]byte{[]byte("x")}, 0, true); !errors.Is(err, ErrUnsupported) {
		t.Fatalf("WriteAt err = %v", err)
	}
	if _, err := e.ReadAt(f, make([]byte, 1), 0); !errors.Is(err, ErrUnsupported) {
		t.Fatalf("ReadAt err = %v", err)
	}
	if err := e.Sync(f); !errors.Is(err, ErrUnsupported) {
		t.Fatalf("Sync err = %v", err)
	}
	if err := e.Close(); err != nil {
		t.Fatalf("Close err = %v", err)
	}
}
