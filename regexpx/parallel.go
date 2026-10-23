package regexpx

import (
	"runtime"
	"sync"
	"unicode/utf8"
)

// parallelThreshold is the minimum input size for chunked scanning. Below it the coordination cost
// dominates. | parallelThreshold 是分块扫描的最小输入长度；低于它时协调开销占据主导。
const parallelThreshold = 64 << 10

// FindAllStringIndexParallel returns the byte offset pairs of every non-overlapping match, splitting
// large inputs across CPU cores. The result is identical to FindAllStringIndex. Patterns that can
// match empty, anchored patterns, and backtracking patterns run sequentially. | FindAllStringIndexParallel
// 返回每个不重叠匹配的字节偏移对，并把大输入拆分到多个 CPU 核心。结果与 FindAllStringIndex 相同。
// 可匹配空串的模式、锚定模式与回溯模式按顺序执行。
func (r *Regexp) FindAllStringIndexParallel(s string, n int) [][]int {
	if !r.parallelEligible(s, n) {
		return r.FindAllStringIndex(s, n)
	}
	return r.findAllParallel(s, n)
}

// FindAllStringParallel returns the text of every non-overlapping match, using chunked scanning for
// large inputs. | FindAllStringParallel 返回每个不重叠匹配的文本，大输入使用分块扫描。
func (r *Regexp) FindAllStringParallel(s string, n int) []string {
	rows := r.FindAllStringIndexParallel(s, n)
	out := make([]string, len(rows))
	for i, row := range rows {
		out[i] = s[row[0]:row[1]]
	}
	return out
}

// parallelEligible reports whether chunked scanning preserves the sequential contract. | parallelEligible
// 报告分块扫描是否保持顺序执行的约定。
func (r *Regexp) parallelEligible(s string, n int) bool {
	if n == 0 || len(s) < parallelThreshold {
		return false
	}
	// Chunk boundaries are aligned to valid UTF-8 rune starts; malformed input therefore uses the
	// sequential path, which handles each invalid byte exactly like the standard library. | 块边界
	// 对齐到合法 UTF-8 符文起点；因此非法输入走顺序路径，逐字节处理方式与标准库完全一致。
	if !utf8.ValidString(s) {
		return false
	}
	info := r.prog.info
	if info.hasBacktrack || info.anchored || info.canEmpty {
		return false
	}
	// Dense unbounded runs such as \w+ are already memory-bandwidth limited in one pass, and chunk
	// results add allocation and merge overhead, so only bounded runs are split. Fixed-length
	// patterns with few matches, such as dates, benefit the most. Anchored, whole-literal and
	// wildcard shapes do no useful work per chunk. General NFA scans need a sound and selective
	// start filter, because a broad first-byte set would make every chunk re-scan most of its
	// range. | \w+ 这类密集的无界运行在单遍中已受内存带宽限制，分块结果还会增加分配与合并开销，
	// 因此只拆分有界运行。匹配较少的定长模式（如日期）收益最大。锚定、整模式字面量与通配符形态在
	// 每个块中没有有效工作。通用 NFA 扫描需要可靠且具有选择性的起点过滤器，因为宽首字节集会让每个块
	// 重复扫描其大部分范围。
	if r.exact != nil || r.wild != nil {
		return false
	}
	if r.email != nil {
		return true
	}
	if r.run != nil {
		return r.run.max >= 0 && !r.run.anchorStart && !r.run.anchorEnd
	}
	if r.lin != nil {
		return !r.lin.anchorStart && !r.lin.anchorEnd
	}
	return info.selectivePrefilter
}

// findAllParallel runs the find-first-per-chunk algorithm and merges the chunks in order. | findAllParallel
// 运行「每块找首个匹配」算法并按顺序合并各块。
func (r *Regexp) findAllParallel(s string, n int) [][]int {
	workers := runtime.GOMAXPROCS(0)
	if workers < 2 {
		return r.FindAllStringIndex(s, n)
	}
	chunks := workers * 4
	if maxChunks := len(s) / 4096; chunks > maxChunks {
		chunks = maxChunks
	}
	if chunks < 2 {
		return r.FindAllStringIndex(s, n)
	}
	bounds := chunkBounds(s, chunks)
	r.parallelSearches.Add(1)

	type chunkResult struct {
		matches [][]int
		err     error
	}
	results := make([]chunkResult, len(bounds)-1)
	sem := make(chan struct{}, workers)
	var wg sync.WaitGroup
	for i := 0; i < len(results); i++ {
		wg.Add(1)
		sem <- struct{}{}
		go func(i int) {
			defer wg.Done()
			defer func() { <-sem }()
			results[i].matches, results[i].err = r.findAllInRange(s, bounds[i], bounds[i+1], 2)
		}(i)
	}
	wg.Wait()

	out := make([][]int, 0, 16)
	cursor := 0
	for i := range results {
		if results[i].err != nil {
			return out
		}
		matches := results[i].matches
		if len(matches) > 0 && matches[0][0] < cursor {
			// The previous match crossed into this chunk; rescan from the cursor so no start is
			// skipped because of the stale match. | 上一个匹配延伸进了本块；从 cursor 重新扫描，
			// 避免因过期匹配而漏掉起点。
			rescan, err := r.findAllInRange(s, cursor, bounds[i+1], 2)
			if err != nil {
				return out
			}
			matches = rescan
		}
		for _, match := range matches {
			if match[0] < cursor {
				continue
			}
			out = append(out, []int{match[0], match[1]})
			cursor = match[1]
			if n > 0 && len(out) >= n {
				return out
			}
		}
	}
	return out
}

// findAllInRange returns every non-overlapping match whose start lies in [lo, hi). |
// findAllInRange 返回起点位于 [lo, hi) 的每个不重叠匹配。
func (r *Regexp) findAllInRange(s string, lo, hi, maxSlot int) ([][]int, error) {
	var out [][]int
	pos := lo
	for pos < hi && pos <= len(s) {
		caps, ok, err := r.execute(s, pos, maxSlot, hi, false)
		if err != nil || !ok {
			return out, err
		}
		out = append(out, []int{caps[0], caps[1]})
		if caps[1] > pos {
			pos = caps[1]
			continue
		}
		if caps[1] >= len(s) {
			break
		}
		_, size := utf8.DecodeRuneInString(s[caps[1]:])
		pos = caps[1] + size
	}
	return out, nil
}

// chunkBounds splits s into approximately equal chunks aligned to rune boundaries. | chunkBounds 把 s
// 切分为近似相等且对齐符文边界的块。
func chunkBounds(s string, chunks int) []int {
	bounds := make([]int, 1, chunks+1)
	bounds[0] = 0
	for i := 1; i < chunks; i++ {
		pos := len(s) * i / chunks
		for pos < len(s) && !utf8.RuneStart(s[pos]) {
			pos++
		}
		if pos <= bounds[len(bounds)-1] {
			continue
		}
		bounds = append(bounds, pos)
	}
	if bounds[len(bounds)-1] != len(s) {
		bounds = append(bounds, len(s))
	}
	return bounds
}
