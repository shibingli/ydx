//go:build !(linux && rdma && (amd64 || arm64))

package rdma

import (
	"errors"
	"testing"
)

func TestRingStubReturnsUnsupported(t *testing.T) {
	if _, err := DialRing("127.0.0.1:1", RingConfig{}); !errors.Is(err, ErrUnsupported) {
		t.Fatalf("DialRing err = %v", err)
	}
	if _, err := ListenRing("127.0.0.1:1", RingConfig{}); !errors.Is(err, ErrUnsupported) {
		t.Fatalf("ListenRing err = %v", err)
	}
}
