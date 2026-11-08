//go:build jsonx_std

package json

import "testing"

// TestBackendIsStdlib pins the backend name of the jsonx_std build. | TestBackendIsStdlib
// 固定 jsonx_std 构建的后端名称。
func TestBackendIsStdlib(t *testing.T) {
	if got := Backend(); got != "encoding/json" {
		t.Fatalf("Backend() = %q, want encoding/json | Backend() = %q，期望 encoding/json", got, got)
	}
}
