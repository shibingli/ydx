package gc

import (
	"runtime/debug"
	"runtime/metrics"
	"sync"

	"github.com/shibingli/ydx/sysinfo"
)

// CPU class metrics, sorted as runtime/metrics.Read requires. Their difference is the
// CPU time the process actually consumed. | CPU 类别指标，按 runtime/metrics.Read 要求的
// 顺序排序；两者的差值就是进程真正消耗的 CPU 时间。
var cpuMetricNames = [...]string{
	"/cpu/classes/idle:cpu-seconds",
	"/cpu/classes/total:cpu-seconds",
}

// Heap and GC metrics, sorted as runtime/metrics.Read requires. | 堆与 GC 指标，按
// runtime/metrics.Read 要求的顺序排序。
var heapMetricNames = [...]string{
	"/gc/cycles/total:gc-cycles",
	"/memory/classes/heap/objects:bytes",
	"/memory/classes/heap/released:bytes",
	"/memory/classes/total:bytes",
}

// metricsAvailable reports whether the runtime publishes every named metric. Checking the
// catalogue keeps a future Go rename from panicking inside metrics.Read. | metricsAvailable
// 报告运行时是否发布了全部指定指标。检查目录可避免未来 Go 改名时在 metrics.Read 内 panic。
func metricsAvailable(names []string) bool {
	known := make(map[string]struct{}, len(names))
	for _, description := range metrics.All() {
		known[description.Name] = struct{}{}
	}
	for _, name := range names {
		if _, ok := known[name]; !ok {
			return false
		}
	}
	return true
}

// cpuProbe measures the process's CPU utilisation between two samples. | cpuProbe 测量两次
// 采样之间进程的 CPU 利用率。
//
// The denominator is the runtime's own "available CPU seconds" metric, which is
// GOMAXPROCS integrated over wall time, so the result is a percentage of the parallelism
// this process is allowed to use rather than a percentage of the host. | 分母是运行时自身的
// 「可用 CPU 秒数」指标，即 GOMAXPROCS 对墙钟时间的积分；因此结果是本进程可用并行度的
// 百分比，而不是宿主 CPU 的百分比。
type cpuProbe struct {
	readRaw func() (idle, total float64, ok bool)
	samples []metrics.Sample
	// prevTotal and prevIdle are the previous cumulative readings. | prevTotal 与 prevIdle
	// 是上一次的累计读数。
	prevTotal float64
	prevIdle  float64
	// mu guards the samples and the previous readings; RunOnce can sample concurrently
	// with the scheduler goroutine. | mu 保护采样缓冲与上次读数；RunOnce 可能与调度协程
	// 并发采样。
	mu sync.Mutex
	// have reports whether a baseline exists. | have 报告是否已有基线。
	have bool
}

// newCPUProbe builds the default probe over runtime/metrics. | newCPUProbe 在
// runtime/metrics 之上构建默认探针。
func newCPUProbe() *cpuProbe {
	p := &cpuProbe{}
	if !metricsAvailable(cpuMetricNames[:]) {
		return p
	}
	p.samples = make([]metrics.Sample, len(cpuMetricNames))
	for i, name := range cpuMetricNames {
		p.samples[i].Name = name
	}
	p.readRaw = p.readMetrics
	// Validate the kinds once at construction; a renamed or retyped metric degrades to
	// "unavailable" instead of failing on every later sample. | 在构造期校验一次类型；
	// 指标被改名或改类型时降级为「不可用」，而不是在后续每次采样时失败。
	if _, _, ok := p.readMetrics(); !ok {
		p.samples = nil
		p.readRaw = nil
	}
	return p
}

// available reports whether the probe can produce measurements. | available 报告探针能否产生读数。
func (p *cpuProbe) available() bool {
	return p != nil && p.readRaw != nil
}

// readMetrics reads the cumulative idle and total CPU seconds. | readMetrics 读取累计空闲与
// 总 CPU 秒数。
func (p *cpuProbe) readMetrics() (idle, total float64, ok bool) {
	metrics.Read(p.samples)
	if p.samples[0].Value.Kind() != metrics.KindFloat64 || p.samples[1].Value.Kind() != metrics.KindFloat64 {
		return 0, 0, false
	}
	return p.samples[0].Value.Float64(), p.samples[1].Value.Float64(), true
}

// sample returns the utilisation percentage and whether it reflects real activity. The
// first call only establishes a baseline and reports false. | sample 返回利用率百分比，以及它
// 是否反映真实活动；第一次调用只建立基线并返回 false。
func (p *cpuProbe) sample() (float64, bool) {
	if p == nil || p.readRaw == nil {
		return 0, false
	}

	p.mu.Lock()
	defer p.mu.Unlock()

	idle, total, ok := p.readRaw()
	if !ok {
		return 0, false
	}
	if !p.have {
		p.prevIdle, p.prevTotal, p.have = idle, total, true
		return 0, false
	}

	idleDelta := idle - p.prevIdle
	totalDelta := total - p.prevTotal
	p.prevIdle, p.prevTotal = idle, total
	if totalDelta <= 0 {
		return 0, false
	}
	if idleDelta < 0 {
		idleDelta = 0
	}
	if idleDelta > totalDelta {
		idleDelta = totalDelta
	}
	return (totalDelta - idleDelta) / totalDelta * 100, true
}

// heapReading is one heap and GC snapshot. | heapReading 是一次堆与 GC 快照。
type heapReading struct {
	// heapObjects is live plus not-yet-freed heap objects, i.e. MemStats.HeapAlloc. | heapObjects
	// 是存活对象与尚未释放的堆对象，即 MemStats.HeapAlloc。
	heapObjects uint64
	// mapped is runtime-mapped memory that has not been returned to the OS. | mapped 是尚未
	// 归还操作系统的运行时映射内存。
	mapped uint64
	// released is mapped but free memory already returned to the OS. | released 是已映射但
	// 已归还操作系统的空闲内存。
	released uint64
	// gcCycles is the number of completed GC cycles. | gcCycles 是已完成的 GC 轮数。
	gcCycles uint64
	// ok reports whether the reading is meaningful. | ok 报告读数是否有意义。
	ok bool
}

// heapReader samples heap gauges without the stop-the-world cost of runtime.ReadMemStats. | heapReader
// 采样堆指标，不付 runtime.ReadMemStats 的停止世界代价。
type heapReader struct {
	readRaw func() heapReading
	samples []metrics.Sample
	// mu guards samples; both the scheduler and a manual run can read. | mu 保护采样缓冲；
	// 调度器与手动执行都可能读取。
	mu sync.Mutex
}

// newHeapReader builds the default reader over runtime/metrics. | newHeapReader 在
// runtime/metrics 之上构建默认读取器。
func newHeapReader() *heapReader {
	r := &heapReader{}
	if !metricsAvailable(heapMetricNames[:]) {
		return r
	}
	r.samples = make([]metrics.Sample, len(heapMetricNames))
	for i, name := range heapMetricNames {
		r.samples[i].Name = name
	}
	r.readRaw = r.readMetrics
	// Validate the kinds once at construction, for the same reason as the CPU probe. | 与 CPU
	// 探针同理，在构造期校验一次类型。
	if !r.readMetrics().ok {
		r.samples = nil
		r.readRaw = nil
	}
	return r
}

// readMetrics reads the four heap gauges. | readMetrics 读取四个堆指标。
func (r *heapReader) readMetrics() heapReading {
	r.mu.Lock()
	defer r.mu.Unlock()

	metrics.Read(r.samples)
	for _, sample := range r.samples {
		if sample.Value.Kind() != metrics.KindUint64 {
			return heapReading{}
		}
	}
	released := r.samples[2].Value.Uint64()
	total := r.samples[3].Value.Uint64()
	mapped := uint64(0)
	if total > released {
		mapped = total - released
	}
	return heapReading{
		heapObjects: r.samples[1].Value.Uint64(),
		mapped:      mapped,
		released:    released,
		gcCycles:    r.samples[0].Value.Uint64(),
		ok:          true,
	}
}

// read returns the current snapshot, or a zero reading when metrics are unavailable. | read
// 返回当前快照；指标不可用时返回零读数。
func (r *heapReader) read() heapReading {
	if r == nil || r.readRaw == nil {
		return heapReading{}
	}
	return r.readRaw()
}

// effectiveMemoryLimit returns the tighter of the Go soft memory limit and the host or
// cgroup ceiling, or zero when neither is known. | effectiveMemoryLimit 返回 Go 软内存上限与
// 宿主/cgroup 上限中的较小者；两者都未知时返回零。
func effectiveMemoryLimit() uint64 {
	var limit uint64
	// A negative input only reads the current soft limit and never changes it. | 负数输入只读取
	// 当前软上限，绝不修改它。
	if n := debug.SetMemoryLimit(-1); n > 0 {
		limit = uint64(n)
	}
	if host := sysinfo.MemoryLimit(); host > 0 && (limit == 0 || host < limit) {
		limit = host
	}
	return limit
}
