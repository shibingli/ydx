//go:build !b64x_std

package base64

import "testing"

// TestBackendIsYDNative pins the backend name of the default build. | TestBackendIsYDNative
// 固定默认构建的后端名称。
func TestBackendIsYDNative(t *testing.T) {
	if got := Backend(); got != "yd-native" {
		t.Fatalf("Backend() = %q, want yd-native | Backend() = %q，期望 yd-native", got, got)
	}
}
