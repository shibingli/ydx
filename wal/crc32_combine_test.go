package wal

import (
	"hash/crc32"
	"math/rand"
	"testing"
)

// TestCRC32CombineMatchesDirect verifies combining per-part CRC values equals a
// single checksum over the concatenation. | TestCRC32CombineMatchesDirect 验证
// 合并分段 CRC 与对拼接结果直接校验一致。
func TestCRC32CombineMatchesDirect(t *testing.T) {
	table := crc32.MakeTable(crc32.Castagnoli)
	rng := rand.New(rand.NewSource(1))
	lengths := []int{0, 1, 2, 7, 31, 32, 33, 255, 256, 4097, 1 << 20}
	for _, alen := range lengths {
		for _, blen := range lengths {
			a := make([]byte, alen)
			b := make([]byte, blen)
			rng.Read(a)
			rng.Read(b)
			got := crc32Combine(crc32.Checksum(a, table), crc32.Checksum(b, table), int64(blen))
			want := crc32.Checksum(append(append([]byte(nil), a...), b...), table)
			if got != want {
				t.Fatalf("combine len=%d+%d: got %08x want %08x", alen, blen, got, want)
			}
		}
	}
}
