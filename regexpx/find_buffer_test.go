package regexpx

import "testing"

// TestFindStringSubmatchIndexIntoReusesBuffer verifies the caller buffer aliasing contract. |
// TestFindStringSubmatchIndexIntoReusesBuffer 验证调用方缓冲区复用约定。
func TestFindStringSubmatchIndexIntoReusesBuffer(t *testing.T) {
	re := MustCompile(`([a-z]+)-([0-9]+)`)
	value := "abc-123"
	buf := make([]int, 0, 16)
	got := re.FindStringSubmatchIndexInto(buf, value)
	want := re.FindStringSubmatchIndex(value)
	if !equalInts(got, want) {
		t.Fatalf("index = %v, want %v", got, want)
	}
	if len(got) == 0 || &got[0] != &buf[:cap(buf)][0] {
		t.Fatal("index result does not reuse the caller buffer")
	}
	if got := re.FindStringSubmatchIndexInto(buf, "none"); got != nil {
		t.Fatalf("no-match index = %v, want nil", got)
	}
}

// TestFindStringSubmatchIntoReusesBuffer verifies string buffer reuse and unmatched groups. |
// TestFindStringSubmatchIntoReusesBuffer 验证字符串缓冲区复用与未匹配分组。
func TestFindStringSubmatchIntoReusesBuffer(t *testing.T) {
	re := MustCompile(`(?P<word>[a-z]*)(?:-([0-9]+))?`)
	buf := make([]string, 0, 8)
	got := re.FindStringSubmatchInto(buf, "abc")
	want := re.FindStringSubmatch("abc")
	if !equalStrings(got, want) {
		t.Fatalf("submatch = %q, want %q", got, want)
	}
	if len(got) == 0 || &got[0] != &buf[:cap(buf)][0] {
		t.Fatal("submatch result does not reuse the caller buffer")
	}
	if got := re.FindStringSubmatchInto(buf, ""); got == nil || got[0] != "" {
		t.Fatalf("empty match = %q, want one empty group", got)
	}
}

// TestFindSubmatchIntoBytes verifies the byte-slice variant. | TestFindSubmatchIntoBytes 验证字节切片
// 变体。
func TestFindSubmatchIntoBytes(t *testing.T) {
	re := MustCompile(`(a+)(b)`)
	value := []byte("xxaaabyy")
	indexBuf := make([]int, 0, 8)
	index := re.FindSubmatchIndexInto(indexBuf, value)
	wantIndex := re.FindSubmatchIndex(value)
	if !equalInts(index, wantIndex) {
		t.Fatalf("index = %v, want %v", index, wantIndex)
	}
	subBuf := make([][]byte, 0, 4)
	groups := re.FindSubmatchInto(subBuf, value)
	if len(groups) != 3 || string(groups[1]) != "aaa" || string(groups[2]) != "b" {
		t.Fatalf("groups = %q", groups)
	}
	if &groups[0] != &subBuf[:cap(subBuf)][0] {
		t.Fatal("byte submatch result does not reuse the caller buffer")
	}
}

// TestFindStringSubmatchIntoAllocations verifies that warm buffer API calls do not allocate. |
// TestFindStringSubmatchIntoAllocations 验证预热后的缓冲区 API 调用不分配内存。
func TestFindStringSubmatchIntoAllocations(t *testing.T) {
	if raceEnabled {
		t.Skip("allocation assertions are unstable under -race")
	}
	re := MustCompile(`([a-z]+)-([0-9]+)`)
	indexBuf := make([]int, 0, 8)
	stringBuf := make([]string, 0, 3)
	value := "abc-123"
	if allocs := testing.AllocsPerRun(200, func() {
		_ = re.FindStringSubmatchIndexInto(indexBuf, value)
	}); allocs != 0 {
		t.Fatalf("FindStringSubmatchIndexInto allocations = %v, want 0", allocs)
	}
	if allocs := testing.AllocsPerRun(200, func() {
		_ = re.FindStringSubmatchInto(stringBuf, value)
	}); allocs != 0 {
		t.Fatalf("FindStringSubmatchInto allocations = %v, want 0", allocs)
	}
}

// TestFindStringSubmatchIntoBacktracking verifies the buffer API through the backtracking engine. |
// TestFindStringSubmatchIntoBacktracking 验证回溯引擎下的缓冲区 API。
func TestFindStringSubmatchIntoBacktracking(t *testing.T) {
	re := MustCompile(`(?=(a+))a`)
	buf := make([]string, 0, 4)
	got := re.FindStringSubmatchInto(buf, "baaa")
	want := re.FindStringSubmatch("baaa")
	if !equalStrings(got, want) {
		t.Fatalf("submatch = %q, want %q", got, want)
	}
}

// TestFindStringSubmatchIntoLongest verifies the POSIX longest path copies into the caller buffer.
// | TestFindStringSubmatchIntoLongest 验证 POSIX 最左最长路径会写入调用方缓冲区。
func TestFindStringSubmatchIntoLongest(t *testing.T) {
	re := MustCompilePOSIX(`(a|ab)(b?)`)
	buf := make([]string, 0, 4)
	got := re.FindStringSubmatchInto(buf, "ab")
	want := re.FindStringSubmatch("ab")
	if !equalStrings(got, want) {
		t.Fatalf("submatch = %q, want %q", got, want)
	}
	if &got[0] != &buf[:cap(buf)][0] {
		t.Fatal("longest result does not reuse the caller buffer")
	}
}
