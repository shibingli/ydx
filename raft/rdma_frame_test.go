package raft

import (
	"errors"
	"testing"
)

// TestRDMAChunkHeader verifies chunk header round-trip and corruption checks.
// | TestRDMAChunkHeader 验证分块头往返与损坏检查。
func TestRDMAChunkHeader(t *testing.T) {
	var buf [rdmaChunkHeaderLen]byte
	encodeRDMAChunkHeader(buf[:], 1<<20, 64<<10)
	total, offset, err := decodeRDMAChunkHeader(buf[:], 1<<20)
	if err != nil {
		t.Fatal(err)
	}
	if total != 1<<20 || offset != 64<<10 {
		t.Fatalf("total=%d offset=%d", total, offset)
	}
	if _, _, err := decodeRDMAChunkHeader(buf[:], 1<<20-1); !errors.Is(err, ErrTooLarge) {
		t.Fatalf("max check error = %v", err)
	}
	bad := buf
	bad[0] ^= 0xff
	if _, _, err := decodeRDMAChunkHeader(bad[:], 0); !errors.Is(err, ErrCorrupt) {
		t.Fatalf("magic check error = %v", err)
	}
	bad = buf
	bad[4] = 9
	if _, _, err := decodeRDMAChunkHeader(bad[:], 0); !errors.Is(err, ErrCorrupt) {
		t.Fatalf("version check error = %v", err)
	}
	bad = buf
	encodeRDMAChunkHeader(bad[:], ^uint32(0), 0)
	if _, _, err := decodeRDMAChunkHeader(bad[:], 0); !errors.Is(err, ErrTooLarge) {
		t.Fatalf("huge frame length error = %v", err)
	}
	bad = buf
	encodeRDMAChunkHeader(bad[:], 100, 100)
	if _, _, err := decodeRDMAChunkHeader(bad[:], 0); !errors.Is(err, ErrCorrupt) {
		t.Fatalf("offset check error = %v", err)
	}
	if _, _, err := decodeRDMAChunkHeader(buf[:rdmaChunkHeaderLen-1], 0); !errors.Is(err, ErrCorrupt) {
		t.Fatalf("short header error = %v", err)
	}
}
