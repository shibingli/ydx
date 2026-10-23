package regexpx

import (
	stdregexp "regexp"
	"strings"
	"sync"
	"testing"
)

// buildLargeText builds a deterministic corpus with words, dates and emails. | buildLargeText 构造包含
// 单词、日期与邮箱的确定性语料。
func buildLargeText(lines int) string {
	line := "tenant-admin user123@example.com 2024-07-15 https://example.com/a?b=1 foo bar 世界 "
	var b strings.Builder
	b.Grow(lines * len(line))
	for i := 0; i < lines; i++ {
		b.WriteString(line)
	}
	return b.String()
}

// TestLargeTextLinearScan checks that bulk scans stay linear and match the standard library. |
// TestLargeTextLinearScan 检查批量扫描保持线性并与标准库一致。
func TestLargeTextLinearScan(t *testing.T) {
	text := buildLargeText(20000)
	for _, pattern := range []string{`\w+`, `\d{4}-\d{2}-\d{2}`, `[a-z]+`, `用户`, `(?s).*Holmes.*`, `https?://[^\s/$.?#].[^\s]*`, `[a-zA-Z0-9._%+\-]+@[a-zA-Z0-9.\-]+\.[a-zA-Z]{2,}`} {
		got := MustCompile(pattern).FindAllStringIndex(text, -1)
		want := stdregexp.MustCompile(pattern).FindAllStringIndex(text, -1)
		if !equalIntsMatrix(got, want) {
			t.Fatalf("%q: got %d matches, want %d", pattern, len(got), len(want))
		}
	}
}

// TestParallelLargeMatchesSequential compares chunked and sequential scans on a multi-megabyte input.
// | TestParallelLargeMatchesSequential 在多兆字节输入上对比分块与顺序扫描。
func TestParallelLargeMatchesSequential(t *testing.T) {
	text := buildLargeText(50000)
	for _, pattern := range []string{`\w+`, `\d{4}-\d{2}-\d{2}`, `[a-z]+`, `user123@example\.com`, `https?://[^\s/$.?#].[^\s]*`, `[a-zA-Z0-9._%+\-]+@[a-zA-Z0-9.\-]+\.[a-zA-Z]{2,}`} {
		re := MustCompile(pattern)
		seq := re.FindAllStringIndex(text, -1)
		par := re.FindAllStringIndexParallel(text, -1)
		if !equalIntsMatrix(seq, par) {
			t.Fatalf("%q: parallel result differs (seq %d, par %d)", pattern, len(seq), len(par))
		}
	}
}

// TestParallelLimitAndBoundaries checks the result limit and matches that cross chunk boundaries. |
// TestParallelLimitAndBoundaries 检查结果上限以及跨块边界的匹配。
func TestParallelLimitAndBoundaries(t *testing.T) {
	var b strings.Builder
	for i := 0; i < 40000; i++ {
		b.WriteString(strings.Repeat("a", i%97+1))
		b.WriteString("b ")
	}
	text := b.String()
	re := MustCompile(`a+b`)
	seq := re.FindAllStringIndex(text, -1)
	par := re.FindAllStringIndexParallel(text, -1)
	if !equalIntsMatrix(seq, par) {
		t.Fatalf("boundary pattern differs (seq %d, par %d)", len(seq), len(par))
	}
	for _, limit := range []int{1, 7, 100} {
		seq := re.FindAllStringIndex(text, limit)
		par := re.FindAllStringIndexParallel(text, limit)
		if !equalIntsMatrix(seq, par) {
			t.Fatalf("limit %d differs (seq %v, par %v)", limit, seq, par)
		}
	}
}

// TestParallelFallbacks proves that ineligible patterns return the sequential result. |
// TestParallelFallbacks 证明不适用分块的模式返回顺序结果。
func TestParallelFallbacks(t *testing.T) {
	text := buildLargeText(20000) + "tail"
	cases := []string{`^tenant`, `\w*`, `(a)\1`, `用户(?=后)`}
	for _, pattern := range cases {
		re := MustCompile(pattern)
		seq := re.FindAllStringIndex(text, -1)
		par := re.FindAllStringIndexParallel(text, -1)
		if !equalIntsMatrix(seq, par) {
			t.Fatalf("%q: fallback differs (seq %d, par %d)", pattern, len(seq), len(par))
		}
	}
}

// TestParallelConcurrentUse exercises chunked scanning from several goroutines under the race
// detector. | TestParallelConcurrentUse 在竞态检测器下从多个 goroutine 调用分块扫描。
func TestParallelConcurrentUse(t *testing.T) {
	text := buildLargeText(10000)
	re := MustCompile(`\w+`)
	want := re.FindAllStringIndex(text, -1)
	var wg sync.WaitGroup
	for i := 0; i < 8; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for j := 0; j < 4; j++ {
				if got := re.FindAllStringIndexParallel(text, -1); !equalIntsMatrix(got, want) {
					t.Errorf("concurrent parallel scan returned a different result")
					return
				}
				if !re.MatchString(text) {
					t.Errorf("concurrent match failed")
					return
				}
			}
		}()
	}
	wg.Wait()
}

// TestParallelEligibility pins which fast paths use chunked scanning. | TestParallelEligibility 钉住
// 哪些快速路径使用分块扫描。
func TestParallelEligibility(t *testing.T) {
	text := buildLargeText(20000)
	date := MustCompile(`\d{4}-\d{2}-\d{2}`)
	before := date.parallelSearches.Load()
	date.FindAllStringIndexParallel(text, -1)
	if date.parallelSearches.Load() == before {
		t.Fatal("bounded fixed-length pattern did not use chunked scanning")
	}
	for _, pattern := range []string{`\w+`, `[a-z]+`, `tenant`, `(?s).*tenant.*`, `\w+$`} {
		re := MustCompile(pattern)
		before := re.parallelSearches.Load()
		par := re.FindAllStringIndexParallel(text, -1)
		if re.parallelSearches.Load() != before {
			t.Errorf("%q unexpectedly used chunked scanning", pattern)
		}
		seq := re.FindAllStringIndex(text, -1)
		if !equalIntsMatrix(seq, par) {
			t.Errorf("%q: parallel fallback differs", pattern)
		}
	}
}
