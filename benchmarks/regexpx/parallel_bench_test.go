package regexpx

import (
	"strings"
	"testing"

	ydx "github.com/shibingli/ydx/regexpx"
)

// parallelText and parallelMixed are 4 MiB corpora for the chunked benchmark. | parallelText 与
// parallelMixed 是用于分块基准的 4 MiB 语料。
var (
	parallelText  = strings.Repeat(largeText, 16)
	parallelMixed = strings.Repeat(mixedText, 32)
)

// BenchmarkParallelFindAll compares sequential and chunked scans of the self-developed engine. |
// BenchmarkParallelFindAll 对比自研引擎的顺序扫描与分块扫描。
func BenchmarkParallelFindAll(b *testing.B) {
	cases := []struct {
		pattern string
		text    string
	}{
		{`\w+`, parallelText},
		{`\d{4}-\d{2}-\d{2}`, parallelText},
		{`[a-z]+`, parallelText},
		{`[a-zA-Z0-9._%+\-]+@[a-zA-Z0-9.\-]+\.[a-zA-Z]{2,}`, parallelText},
		{`\p{Han}+`, parallelMixed},
		{`\p{So}+`, parallelMixed},
	}
	for _, tc := range cases {
		re, err := ydx.Compile(tc.pattern)
		if err != nil {
			b.Fatalf("Compile(%q): %v", tc.pattern, err)
		}
		b.Run("sequential/"+tc.pattern, func(b *testing.B) {
			b.SetBytes(int64(len(tc.text)))
			b.ReportAllocs()
			b.ResetTimer()
			var out [][]int
			for i := 0; i < b.N; i++ {
				out = re.FindAllStringIndex(tc.text, -1)
			}
			_ = out
		})
		b.Run("parallel/"+tc.pattern, func(b *testing.B) {
			b.SetBytes(int64(len(tc.text)))
			b.ReportAllocs()
			b.ResetTimer()
			var out [][]int
			for i := 0; i < b.N; i++ {
				out = re.FindAllStringIndexParallel(tc.text, -1)
			}
			_ = out
		})
	}
}
