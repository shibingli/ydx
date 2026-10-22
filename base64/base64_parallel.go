package base64

import (
	"bytes"
	"sync"

	"github.com/shibingli/ydx/sysinfo"
)

// parallelMinBytes is the input size below which spawning workers costs more
// than it saves. | parallelMinBytes 是启用并行内核的最小输入；更小的载荷上，
// 启动协程的成本高于收益。
const parallelMinBytes = 256 << 10

// minParallelChunk is the smallest slice worth handing to one worker; the
// single-call path also caps workers at maxParallelWorkers because memory
// bandwidth saturates before a many-core host is fully occupied. Concurrent
// callers still use every core. | minParallelChunk 是交给单个协程的最小分块；
// 单次调用还把协程数限制在 maxParallelWorkers，因为内存带宽会在多核主机被占满
// 之前饱和。并发调用方仍可使用全部核心。
const (
	minParallelChunk   = 256 << 10
	maxParallelWorkers = 8
)

// parallelWorkers chooses the worker count from the current environment and
// the input size, never from a caller-supplied core count. | parallelWorkers 根据
// 当前环境与输入大小选择协程数，绝不依赖调用方指定核心数。
func parallelWorkers(n int) int {
	w := sysinfo.Parallelism()
	if w > maxParallelWorkers {
		w = maxParallelWorkers
	}
	if bySize := n / minParallelChunk; w > bySize {
		w = bySize
	}
	if w < 1 {
		w = 1
	}
	return w
}

// EncodeParallel encodes src into dst with a worker count taken automatically
// from sysinfo.Parallelism(), i.e. the current GOMAXPROCS (container-aware on
// Linux). A single-core environment or a small input falls back to Encode. | EncodeParallel
// 使用由 sysinfo.Parallelism() 自动取得的工作协程数把 src 编码到 dst，即当前
// GOMAXPROCS（Linux 上感知容器配额）。单核环境或小输入回退到 Encode。
func (e *Encoding) EncodeParallel(dst, src []byte) { e.encodeParallel(dst, src, 0) }

func (e *Encoding) encodeParallel(dst, src []byte, workers int) {
	if len(dst) < e.EncodedLen(len(src)) {
		return
	}
	groups := (len(src) + 2) / 3
	if len(src) < parallelMinBytes || groups < 2 {
		e.Encode(dst, src)
		return
	}
	if workers <= 0 {
		workers = parallelWorkers(len(src))
	}
	if workers > groups {
		workers = groups
	}
	if workers <= 1 {
		e.Encode(dst, src)
		return
	}
	per := (groups + workers - 1) / workers
	var wg sync.WaitGroup
	for off, out := 0, 0; off < len(src); {
		n := per * 3
		if n > len(src)-off {
			n = len(src) - off
		}
		outN := e.EncodedLen(n)
		wg.Add(1)
		go func(src, dst []byte) {
			defer wg.Done()
			e.Encode(dst, src)
		}(src[off:off+n], dst[out:out+outN])
		off += n
		out += outN
	}
	wg.Wait()
}

// DecodeParallel decodes src into dst with a worker count taken automatically
// from sysinfo.Parallelism(). Inputs containing CR/LF are decoded serially
// because line breaks do not align with 4-character groups; a single-core
// environment or a small input falls back to Decode. | DecodeParallel 使用由
// sysinfo.Parallelism() 自动取得的工作协程数把 src 解码到 dst。含 CR/LF 的输入
// 按单协程解码，因为换行不与 4 字符组对齐；单核环境或小输入回退到 Decode。
func (e *Encoding) DecodeParallel(dst, src []byte) (int, error) {
	return e.decodeParallel(dst, src, 0)
}

// decodeChunk is one source slice and its destination window in a parallel
// decode. | decodeChunk 是并行解码中的一个源切片及其目标窗口。
type decodeChunk struct {
	src []byte
	dst []byte
	out int
}

// planDecodeChunks splits src across workers and computes each chunk's
// destination window. It reports ok=false when the backend's DecodedLen
// reserves a per-call margin, so the per-chunk upper bounds do not fit the
// total destination; the caller must then decode serially instead of slicing
// past dst. | planDecodeChunks 把 src 分给多个协程并计算每个分块的目标窗口。
// 后端 DecodedLen 每次调用都预留余量、使各分块上界之和超出总目标时返回 ok=false，
// 调用方必须改走串行解码，避免越过 dst 切片。
func planDecodeChunks(src, dst []byte, workers int, decodedLen func(int) int) ([]decodeChunk, bool) {
	if len(src) == 0 {
		return nil, true
	}
	groups := (len(src) + 3) / 4
	if workers < 1 {
		workers = 1
	}
	if workers > groups {
		workers = groups
	}
	per := (groups + workers - 1) / workers
	chunks := make([]decodeChunk, 0, workers)
	out := 0
	for off := 0; off < len(src); {
		n := per * 4
		if n > len(src)-off {
			n = len(src) - off
		}
		outN := decodedLen(n)
		if outN < 0 || outN > len(dst)-out {
			return nil, false
		}
		chunks = append(chunks, decodeChunk{src: src[off : off+n], dst: dst[out : out+outN], out: outN})
		off += n
		out += outN
	}
	return chunks, true
}

func (e *Encoding) decodeParallel(dst, src []byte, workers int) (int, error) {
	if len(dst) < e.DecodedLen(len(src)) {
		return 0, ErrShortBuffer
	}
	if len(src) < parallelMinBytes {
		return e.Decode(dst, src)
	}
	groups := (len(src) + 3) / 4
	if groups < 2 {
		return e.Decode(dst, src)
	}
	if workers <= 0 {
		workers = parallelWorkers(len(src))
	}
	if workers > groups {
		workers = groups
	}
	if workers <= 1 {
		return e.Decode(dst, src)
	}
	chunks, ok := planDecodeChunks(src, dst, workers, e.DecodedLen)
	if !ok {
		// A backend whose DecodedLen adds a per-call margin cannot be split
		// without overrunning dst; serial decoding keeps the exact semantics.
		// | 后端 DecodedLen 每次调用都加余量时，分块会越过 dst；串行解码保持精确语义。
		return e.Decode(dst, src)
	}
	type result struct {
		err      error
		n        int
		fallback bool
	}
	results := make(chan result, workers+1)
	var wg sync.WaitGroup
	for _, c := range chunks {
		wg.Add(1)
		go func(src, dst []byte) {
			defer wg.Done()
			// CR/LF is checked inside the worker so the scan runs in parallel with
			// the other chunks; line-wrapped input must be decoded serially because
			// line breaks do not align with 4-character groups. | CR/LF 在协程内部
			// 检查，使扫描与其它分块并行；含换行的输入必须串行解码，因为换行不与
			// 4 字符组对齐。
			if bytes.IndexByte(src, '\r') >= 0 || bytes.IndexByte(src, '\n') >= 0 {
				results <- result{fallback: true}
				return
			}
			got, err := e.Decode(dst, src)
			results <- result{n: got, err: err}
		}(c.src, c.dst)
	}
	wg.Wait()
	close(results)
	total := 0
	var firstErr error
	fallback := false
	for r := range results {
		if r.fallback {
			fallback = true
			continue
		}
		if r.err != nil && firstErr == nil {
			firstErr = r.err
		}
		total += r.n
	}
	if fallback {
		return e.Decode(dst, src)
	}
	if firstErr != nil {
		return 0, firstErr
	}
	return total, nil
}
