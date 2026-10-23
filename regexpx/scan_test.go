package regexpx

import (
	"math/rand"
	"runtime"
	"strings"
	"testing"
)

// TestByteSetTables proves that the nibble tables agree with the bitmap for every byte. |
// TestByteSetTables 证明半字节表对每个字节都与位图一致。
func TestByteSetTables(t *testing.T) {
	sets := []byteSet{
		{},
		allBytes(),
		{1, 0, 0, 0},
		{0, 1, 0, 0},
		{0, 0, 1, 0},
		{0, 0, 0, 1},
	}
	rng := rand.New(rand.NewSource(7))
	for i := 0; i < 32; i++ {
		var set byteSet
		for j := 0; j < 8; j++ {
			set[rng.Intn(4)] |= uint64(1) << rng.Intn(64)
		}
		sets = append(sets, set)
	}
	for _, set := range sets {
		tables, asciiOnly := makeByteSetTables(set)
		if !asciiOnly {
			continue
		}
		for b := 0; b < 128; b++ {
			if got, want := tableSetHas(&tables, byte(b)), set.has(byte(b)); got != want {
				t.Fatalf("tableSetHas(%#x) = %v, want %v", b, got, want)
			}
		}
		for b := 128; b < 256; b++ {
			if tableSetHas(&tables, byte(b)) {
				t.Fatalf("ASCII table matched non-ASCII byte %#x", b)
			}
		}
	}
	var wide byteSet
	wide[2] = 1
	if _, asciiOnly := makeByteSetTables(wide); asciiOnly {
		t.Fatal("wide set reported as ASCII-only")
	}
}

// TestIndexByteMatchesReference compares the byte kernel with strings.IndexByte at every offset. |
// TestIndexByteMatchesReference 在每个偏移处把字节内核与 strings.IndexByte 对比。
func TestIndexByteMatchesReference(t *testing.T) {
	inputs := []string{
		"",
		"a",
		"abc",
		strings.Repeat("x", 31) + "a",
		strings.Repeat("x", 32) + "a",
		strings.Repeat("x", 63) + "a",
		strings.Repeat("x", 64) + "a",
		strings.Repeat("x", 65) + "a",
		"前缀用户后缀",
		"\x00\xff\x80\x7f",
	}
	rng := rand.New(rand.NewSource(11))
	for i := 0; i < 64; i++ {
		b := make([]byte, rng.Intn(200))
		rng.Read(b)
		inputs = append(inputs, string(b))
	}
	for _, s := range inputs {
		for c := 0; c < 256; c++ {
			for from := 0; from <= len(s); from++ {
				want := strings.IndexByte(s[from:], byte(c))
				if want >= 0 {
					want += from
				}
				if got := indexByte(s, byte(c), from); got != want {
					t.Fatalf("indexByte(%q, %#x, %d) = %d, want %d", s, c, from, got, want)
				}
			}
		}
	}
}

// TestIndexByteSetMatchesReference compares the set kernel with a scalar scan. |
// TestIndexByteSetMatchesReference 把集合内核与标量扫描对比。
func TestIndexByteSetMatchesReference(t *testing.T) {
	inputs := []string{
		"",
		"abc123",
		strings.Repeat("x", 31) + "7",
		strings.Repeat("x", 32) + "7",
		strings.Repeat("x", 63) + "7",
		strings.Repeat("x", 64) + "7",
		"前缀用户后缀",
		"\x00\xff\x80\x7f",
	}
	rng := rand.New(rand.NewSource(13))
	for i := 0; i < 64; i++ {
		b := make([]byte, rng.Intn(200))
		rng.Read(b)
		inputs = append(inputs, string(b))
	}
	asciiSets := []byteSet{
		{0x7E, 0, 0, 0}, // 0x01..0x7E
		{0, 0, 0, 0},
		{^uint64(0), ^uint64(0), 0, 0},
	}
	wideSets := []byteSet{
		{0, 0, 1, 0},
		{0, 0, 0, 1},
		allBytes(),
	}
	for i := 0; i < 16; i++ {
		var set byteSet
		for j := 0; j < 6; j++ {
			set[rng.Intn(2)] |= uint64(1) << rng.Intn(64)
		}
		asciiSets = append(asciiSets, set)
	}
	for _, set := range asciiSets {
		tables, asciiOnly := makeByteSetTables(set)
		if !asciiOnly {
			t.Fatalf("ASCII set reported wide: %v", set)
		}
		for _, s := range inputs {
			for from := 0; from <= len(s); from++ {
				want := indexByteSetBitmap(s, &set, from)
				if got := indexByteSet(s, &tables, from); got != want {
					t.Fatalf("indexByteSet(%q, %d) = %d, want %d (set %v)", s, from, got, want, set)
				}
			}
		}
	}
	for _, set := range wideSets {
		for _, s := range inputs {
			for from := 0; from <= len(s); from++ {
				want := -1
				for i := from; i < len(s); i++ {
					if set.has(s[i]) {
						want = i
						break
					}
				}
				if got := indexByteSetBitmap(s, &set, from); got != want {
					t.Fatalf("indexByteSetBitmap(%q, %d) = %d, want %d (set %v)", s, from, got, want, set)
				}
			}
		}
	}
}

// TestIndexLiteralMatchesReference compares the literal kernel with strings.Index. |
// TestIndexLiteralMatchesReference 把字面量内核与 strings.Index 对比。
func TestIndexLiteralMatchesReference(t *testing.T) {
	inputs := []string{
		"",
		"abc",
		"Sherlock Holmes and Sherlock Holmes",
		strings.Repeat("x", 31) + "abc",
		strings.Repeat("x", 32) + "abc",
		strings.Repeat("x", 64) + "abc",
		"前缀用户后缀",
		"aaabaaab",
	}
	rng := rand.New(rand.NewSource(17))
	for i := 0; i < 48; i++ {
		b := make([]byte, rng.Intn(200))
		rng.Read(b)
		inputs = append(inputs, string(b))
	}
	lits := []string{"a", "ab", "abc", "aaab", "用户", "Sherlock", "\x00", "\xff\x80"}
	for _, s := range inputs {
		for _, lit := range lits {
			for from := 0; from <= len(s); from++ {
				want := strings.Index(s[from:], lit)
				if want >= 0 {
					want += from
				}
				if got := indexLiteral(s, lit, from); got != want {
					t.Fatalf("indexLiteral(%q, %q, %d) = %d, want %d", s, lit, from, got, want)
				}
			}
		}
	}
}

// TestSIMDKernelsInstalled proves that the architecture's kernels are installed when available. |
// TestSIMDKernelsInstalled 证明可用时已安装对应架构的内核。
func TestSIMDKernelsInstalled(t *testing.T) {
	switch runtime.GOARCH {
	case "amd64":
		if indexByteBlock != 1 && indexByteBlock != 16 && indexByteBlock != 32 && indexByteBlock != 64 {
			t.Fatalf("unexpected amd64 block size %d", indexByteBlock)
		}
	case "arm64":
		if indexByteBlock != 16 || indexByteSetBlock != 16 || indexFoldPairBlock != 16 {
			t.Fatalf("NEON block = %d/%d/%d, want 16/16/16", indexByteBlock, indexByteSetBlock, indexFoldPairBlock)
		}
	}
}

// TestIndexFoldPairMatchesReference compares the folded pair kernel with its scalar reference. |
// TestIndexFoldPairMatchesReference 把折叠字节对内核与标量参考实现对比。
func TestIndexFoldPairMatchesReference(t *testing.T) {
	inputs := []string{
		"", "e", "er", "ER", "eR", "Er", "error ERROR Error",
		"前缀用户后缀", "\xc3\xa9er", "er\x80", "xERx",
	}
	for n := 0; n < 80; n++ {
		inputs = append(inputs, strings.Repeat("x", n)+"er")
		inputs = append(inputs, strings.Repeat("Q", n)+"ER"+strings.Repeat("z", 3))
	}
	rng := rand.New(rand.NewSource(23))
	alphabet := []byte("abcABCerERxyz_- .@")
	for i := 0; i < 64; i++ {
		b := make([]byte, rng.Intn(160))
		for j := range b {
			b[j] = alphabet[rng.Intn(len(alphabet))]
		}
		inputs = append(inputs, string(b))
	}
	pairs := [][2]byte{{'e', 'r'}, {'o', 'r'}, {'s', 't'}, {'a', 'a'}, {'k', 'k'}, {'z', 'z'}}
	for _, s := range inputs {
		for _, pair := range pairs {
			for from := 0; from <= len(s); from++ {
				want := indexFoldPairScalar(s, pair[0], pair[1], from)
				if got := indexFoldPair(s, pair[0], pair[1], from); got != want {
					t.Fatalf("indexFoldPair(%q, %c%c, %d) = %d, want %d", s, pair[0], pair[1], from, got, want)
				}
			}
		}
	}
}
