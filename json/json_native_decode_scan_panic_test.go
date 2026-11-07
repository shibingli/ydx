package json

import (
	"strings"
	"testing"
)

// TestCleanStringTailFallsBackWhenArenaIsFull guards the parser against an arena replacement
// between the word loop and the tail loop. A previous implementation reserved eight tail bytes
// with ensureArenaSpare, which replaces the arena with an empty slice when only seven bytes were
// free; the stale arena offset then produced a slice-bounds panic. |
// TestCleanStringTailFallsBackWhenArenaIsFull 防止解析器在字循环与尾部循环之间替换 arena。
// 旧实现用 ensureArenaSpare 预留八个尾部字节；当只剩七个字节时会用空切片替换 arena，
// 随后使用过期的 arena 偏移导致切片越界 panic。
func TestCleanStringTailFallsBackWhenArenaIsFull(t *testing.T) {
	value := strings.Repeat("a", 63)
	input := []byte(`{"a":"` + value + `"}`)
	for i := 0; i < 100; i++ {
		var decoded map[string]string
		if err := Unmarshal(input, &decoded); err != nil {
			t.Fatalf("unmarshal iteration %d: %v", i, err)
		}
		if decoded["a"] != value {
			t.Fatalf("decoded value length = %d, want %d", len(decoded["a"]), len(value))
		}
	}
}
