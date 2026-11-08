//go:build b64x_std

package base64

import "testing"

// TestBackendIsStdlib pins the backend name of the b64x_std build. | TestBackendIsStdlib
// 固定 b64x_std 构建的后端名称。
func TestBackendIsStdlib(t *testing.T) {
	if got := Backend(); got != "encoding/base64" {
		t.Fatalf("Backend() = %q, want encoding/base64 | Backend() = %q，期望 encoding/base64", got, got)
	}
}
