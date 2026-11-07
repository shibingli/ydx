package wal

import (
	"math"
	"sync"
	"sync/atomic"
	"time"
)

// SizePolicyMode selects how the WAL chooses size-dependent write strategies.
// | SizePolicyMode 选择 WAL 如何选取与数据大小相关的写策略。
type SizePolicyMode uint8

const (
	// SizePolicyAuto derives the CRC-combination crossover from measured scan
	// and combination costs, adapts the staging-join threshold from observed
	// write latency, and can size the write buffer from the batch-size
	// distribution. Zero fields mean "learn"; negative CRC/staging values
	// disable that strategy. | SizePolicyAuto 根据实测扫描与合并成本推导 CRC 合并
	// 阈值，根据观测到的写延迟调整暂存合并阈值，并可按批次大小分布确定写缓冲大小。
	// 零值表示“学习”；负的 CRC/暂存值关闭对应策略。
	SizePolicyAuto SizePolicyMode = iota
	// SizePolicyManual uses the explicit thresholds verbatim. A zero
	// CRCCombineMinBytes combines for every record, a zero StagingJoinMaxBytes
	// disables staging, and a zero WriteBufferBytes disables buffering.
	// | SizePolicyManual 原样使用显式阈值。CRCCombineMinBytes 为零表示所有记录都用
	// 合并，StagingJoinMaxBytes 为零表示关闭暂存合并，WriteBufferBytes 为零表示关闭
	// 写缓冲。
	SizePolicyManual
)

// SizePolicy configures size-dependent WAL write paths. The zero value is Auto
// with every optimization learned and the write buffer disabled. |
// SizePolicy 配置 WAL 中与数据大小相关的写路径。零值表示自动学习全部优化且关闭写
// 缓冲。
type SizePolicy struct {
	// Mode selects auto learning or manual thresholds. | Mode 选择自动学习或手动阈值。
	Mode SizePolicyMode
	// CRCCombineMinBytes is the record size from which the segment checksum
	// reuses the record checksum instead of rescanning the bytes. | CRCCombineMinBytes
	// 是从该记录大小起，分段校验复用记录校验而不再重新扫描字节。
	CRCCombineMinBytes int
	// StagingJoinMaxBytes is the largest batch that is copied into one staging
	// buffer for a single write on platforms that cannot write vectors. | StagingJoinMaxBytes
	// 是在无法向量写的平台上，复制进单个暂存缓冲后一次写出的最大批次。
	StagingJoinMaxBytes int
	// WriteBufferBytes is the userspace append buffer: 0 disables it, a
	// positive value fixes its size, and a negative value sizes it from the
	// observed batch-size distribution. | WriteBufferBytes 是用户态追写缓冲：0 关闭，
	// 正数固定大小，负数按观测到的批次大小分布自动确定。
	WriteBufferBytes int
}

// Bounds for learned thresholds. Values outside these ranges are not useful:
// below the minimum the fixed costs dominate, above the maximum the alternative
// path is always better. | 学习阈值的边界。低于下限时固定成本占主导，高于上限时
// 替代路径总是更优。
const (
	minCRCCombineBytes      = 4 << 10
	maxCRCCombineBytes      = 1 << 20
	minStagingJoinBytes     = 8 << 10
	maxStagingJoinBytes     = 256 << 10
	minAdaptiveWriteBuffer  = 64 << 10
	maxAdaptiveWriteBuffer  = 4 << 20
	defaultStagingJoinBytes = 64 << 10
	defaultAdaptiveBuffer   = 256 << 10
	defaultCRCCombineBytes  = 64 << 10
	// defaultWriteLatencyNs is the initial per-write cost used until the
	// staging model observes real writes. | defaultWriteLatencyNs 是暂存模型观测到
	// 真实写入前的初始单次写成本。
	defaultWriteLatencyNs = 3000
	// Buffer batch cut-offs: below the floor, copying is always cheaper than the
	// write calls it replaces; above the ceiling, one direct write per batch is
	// already efficient. | 缓冲批次上下限：低于下限时复制总是比替代的写调用便宜；
	// 高于上限时每批直接写已经足够高效。
	minBufferBatchBytes = 128 << 10
	maxBufferBatchBytes = 1 << 20
)

// Write buffer modes. | 写缓冲模式。
const (
	writeBufferDisabled uint8 = iota
	writeBufferFixed
	writeBufferAdaptive
)

// sizePolicyState is the resolved policy plus the runtime learning state. |
// sizePolicyState 是解析后的策略与运行时学习状态。
type sizePolicyState struct {
	engine          IOEngine
	mode            SizePolicyMode
	crcMin          int
	stagingAdaptive bool
	writeBufferMode uint8
	stagingJoinMax  atomic.Int64
	writeBufMax     atomic.Int64
	writeLatencyNs  atomic.Int64
	latencySamples  atomic.Uint64
	batchSamples    uint64
	hist            sizeHistogram
}

// sizeHistogram is a logarithmic batch-size histogram with periodic decay so
// the learned distribution follows a changing workload. It is only touched
// under the commit-side write lock. | sizeHistogram 是对数批次大小直方图，周期性
// 衰减，使学习到的分布跟随工作负载变化。它只在提交侧写锁下访问。
type sizeHistogram struct {
	buckets [24]uint64
	total   uint64
}

// sizeHistogramDecayObservations is the observation count between halvings. |
// sizeHistogramDecayObservations 是两次减半之间的观测数。
const sizeHistogramDecayObservations = 1 << 16

// observe records one batch size. | observe 记录一个批次大小。
func (h *sizeHistogram) observe(n int) {
	if n <= 0 {
		n = 1
	}
	b := 0
	for v := n; v > 1; v >>= 1 {
		b++
	}
	if b >= len(h.buckets) {
		b = len(h.buckets) - 1
	}
	h.buckets[b]++
	h.total++
	if h.total >= sizeHistogramDecayObservations {
		for i := range h.buckets {
			h.buckets[i] >>= 1
		}
		h.total >>= 1
	}
}

// quantile returns the upper bound of the bucket containing the requested rank.
// | quantile 返回包含指定分位排名的桶的上界。
func (h *sizeHistogram) quantile(q float64) int {
	if h.total == 0 {
		return 0
	}
	rank := uint64(q * float64(h.total))
	if rank == 0 {
		rank = 1
	}
	var seen uint64
	for i, count := range h.buckets {
		seen += count
		if seen >= rank {
			if i == len(h.buckets)-1 {
				return 1 << (i + 1)
			}
			return 1 << (i + 1)
		}
	}
	return 1 << len(h.buckets)
}

// newSizePolicyState resolves a policy and starts from conservative defaults
// until enough samples have been observed. | newSizePolicyState 解析策略，并在观测
// 到足够样本前使用保守默认值。
func newSizePolicyState(p SizePolicy, writeBufferOverride int) *sizePolicyState {
	s := &sizePolicyState{mode: p.Mode}
	if s.mode > SizePolicyManual {
		s.mode = SizePolicyAuto
	}
	// CRC: manual zero means "always combine"; auto zero means "learn". |
	// CRC：手动零值表示“总是合并”；自动零值表示“学习”。
	crc := p.CRCCombineMinBytes
	if crc < 0 {
		s.crcMin = math.MaxInt32
	} else if s.mode == SizePolicyManual {
		s.crcMin = crc
	} else if crc > 0 {
		s.crcMin = crc
	} else {
		s.crcMin = calibratedCRCCombineMin()
	}
	// Staging: manual zero disables; auto zero learns from observed latency. |
	// 暂存：手动零值关闭；自动零值根据观测延迟学习。
	switch {
	case s.mode == SizePolicyManual:
		if p.StagingJoinMaxBytes > 0 {
			s.stagingJoinMax.Store(int64(p.StagingJoinMaxBytes))
		}
	case p.StagingJoinMaxBytes < 0:
		// Disabled. | 关闭。
	case p.StagingJoinMaxBytes > 0:
		s.stagingJoinMax.Store(int64(p.StagingJoinMaxBytes))
	default:
		s.stagingJoinMax.Store(defaultStagingJoinBytes)
		s.stagingAdaptive = true
	}
	// Write buffer: the legacy option overrides the policy field. | 写缓冲：旧选项
	// 覆盖策略字段。
	buf := p.WriteBufferBytes
	if writeBufferOverride != 0 {
		buf = writeBufferOverride
	}
	switch {
	case buf > 0:
		s.writeBufferMode = writeBufferFixed
		s.writeBufMax.Store(int64(buf))
	case buf < 0:
		s.writeBufferMode = writeBufferAdaptive
		s.writeBufMax.Store(defaultAdaptiveBuffer)
	}
	return s
}

// bindEngine publishes the staging threshold to the I/O engine. |
// bindEngine 把暂存阈值发布给 I/O 引擎。
func (s *sizePolicyState) bindEngine(e IOEngine) {
	s.engine = e
	if setter, ok := e.(interface{ SetStagingJoinMax(int) }); ok {
		setter.SetStagingJoinMax(int(s.stagingJoinMax.Load()))
	}
}

// setStaging clamps and publishes a new staging threshold. | setStaging 收敛并发布新的
// 暂存阈值。
func (s *sizePolicyState) setStaging(n int) {
	if n < minStagingJoinBytes {
		n = minStagingJoinBytes
	}
	if n > maxStagingJoinBytes {
		n = maxStagingJoinBytes
	}
	if s.stagingJoinMax.Load() == int64(n) {
		return
	}
	s.stagingJoinMax.Store(int64(n))
	if setter, ok := s.engine.(interface{ SetStagingJoinMax(int) }); ok {
		setter.SetStagingJoinMax(n)
	}
}

// clockTick estimates the platform timer granularity once. A sample below a
// few ticks can be pure quantization noise, so the writer only feeds the
// learning model durations above that floor. | clockTick 只估算一次平台计时器
// 粒度。低于数个 tick 的样本可能纯属量化噪声，因此写入方只把高于该下限的耗时输入
// 学习模型。
var (
	clockTickOnce sync.Once
	clockTickNs   int64
)

// clockTick returns the estimated timer granularity. | clockTick 返回估算的计时器粒度。
func clockTick() time.Duration {
	clockTickOnce.Do(func() {
		start := time.Now()
		for time.Since(start) == 0 {
		}
		tick := time.Since(start).Nanoseconds()
		if tick <= 0 {
			tick = 1
		}
		clockTickNs = tick
	})
	return time.Duration(clockTickNs)
}

// observeWriteLatency feeds one non-synchronized write duration into the
// staging model. Joining parts costs one copy of the batch and saves one
// syscall per extra part; the break-even size is the latency multiplied by the
// measured copy bandwidth. | observeWriteLatency 把一次未同步写的耗时输入暂存模型。
// 合并分片需要复制整个批次，但每多一个分片省去一次系统调用；平衡点等于延迟乘以
// 实测复制带宽。
func (s *sizePolicyState) observeWriteLatency(d time.Duration, parts int) {
	if !s.stagingAdaptive || parts < 2 {
		return
	}
	ns := d.Nanoseconds()
	if ns <= 0 || ns > int64(50*time.Millisecond) {
		return
	}
	for {
		cur := s.writeLatencyNs.Load()
		next := ns
		if cur > 0 {
			next = cur + (ns-cur)/8
		}
		if next < 1 {
			next = 1
		}
		if s.writeLatencyNs.CompareAndSwap(cur, next) {
			break
		}
	}
	if s.latencySamples.Add(1)%64 != 0 {
		return
	}
	bps := calibratedMemcpyBps()
	bytes := float64(s.writeLatencyNs.Load()) * float64(bps) / float64(time.Second)
	s.setStaging(int(bytes))
}

// observeBatchSize feeds the adaptive write-buffer model. The buffer targets
// eight times the observed p95 with a 256 KiB floor so a flush syscall is
// amortized across many batches, and grows to the 4 MiB ceiling for large
// batches. It is recomputed every 256 observations. | observeBatchSize 输入自适应
// 写缓冲模型。缓冲目标取观测 p95 的八倍，并以 256 KiB 为下限，使一次刷新系统调用
// 摊销到多个批次上；大批次时增长到 4 MiB 上限。每 256 次观测重算一次。
func (s *sizePolicyState) observeBatchSize(n int) {
	if s.writeBufferMode != writeBufferAdaptive {
		return
	}
	s.hist.observe(n)
	s.batchSamples++
	if s.batchSamples%256 != 0 {
		return
	}
	target := 8 * s.hist.quantile(0.95)
	if target < defaultAdaptiveBuffer {
		target = defaultAdaptiveBuffer
	}
	if target > maxAdaptiveWriteBuffer {
		target = maxAdaptiveWriteBuffer
	}
	s.writeBufMax.Store(int64(target))
}

// crcCombineMin returns the effective CRC-combination threshold. | crcCombineMin
// 返回生效的 CRC 合并阈值。
func (w *WAL) crcCombineMin() int {
	if w.policy == nil {
		return calibratedCRCCombineMin()
	}
	return w.policy.crcMin
}

// EffectiveSizePolicy reports the size thresholds currently in use. | EffectiveSizePolicy
// 报告当前使用的数据大小阈值。
func (w *WAL) EffectiveSizePolicy() SizePolicy {
	if w.policy == nil {
		return SizePolicy{Mode: SizePolicyAuto}
	}
	return SizePolicy{
		Mode:                w.policy.mode,
		CRCCombineMinBytes:  w.policy.crcMin,
		StagingJoinMaxBytes: int(w.policy.stagingJoinMax.Load()),
		WriteBufferBytes:    int(w.policy.writeBufMax.Load()),
	}
}

// writeBufferLimit returns the enabled write-buffer size, or zero. |
// writeBufferLimit 返回启用的写缓冲大小，未启用时为零。
func (w *WAL) writeBufferLimit() int {
	if w.policy == nil {
		return 0
	}
	return int(w.policy.writeBufMax.Load())
}

// writeBufferBatchMax returns the largest batch the userspace buffer should
// absorb. Copying is worthwhile only while it is cheaper than the write calls
// it replaces: one extra part costs one write call, and the copy budget is
// twice the per-write latency to stay clear of the break-even edge. |
// writeBufferBatchMax 返回用户态缓冲应吸收的最大批次。只有当复制比其替代的写调用
// 更便宜时才值得缓冲：每多一个分片省一次写调用；复制预算取单次写延迟的两倍，以远离
// 盈亏平衡点。
func (w *WAL) writeBufferBatchMax(parts int) int {
	if w.policy == nil {
		return 0
	}
	latency := w.policy.writeLatencyNs.Load()
	if latency <= 0 {
		latency = defaultWriteLatencyNs
	}
	saved := parts - 1
	if saved < 1 {
		saved = 1
	}
	bytes := int(float64(latency) * float64(calibratedMemcpyBps()) / 1e9)
	bytes *= saved * 2
	if bytes < minBufferBatchBytes {
		bytes = minBufferBatchBytes
	}
	if bytes > maxBufferBatchBytes {
		bytes = maxBufferBatchBytes
	}
	return bytes
}

// Package-level cost calibration is shared by every WAL in the process: it
// depends on the CPU and memory subsystem, not on a directory. | 进程级成本标定由
// 所有 WAL 共享：它取决于 CPU 与内存子系统，而非目录。
var (
	crcCalibrationOnce    sync.Once
	crcCalibrationMin     int
	memcpyCalibrationOnce sync.Once
	memcpyCalibrationBps  int64
)

// calibratedCRCCombineMin measures the scan rate and the fixed combination
// cost, then derives the record size above which reusing the record checksum
// is cheaper than a second scan. Both probes run for a bounded wall window so
// coarse platform timers still produce a usable ratio. | calibratedCRCCombineMin
// 测量扫描速率与合并固定成本，推导出复用记录校验比二次扫描更便宜的记录大小。两个
// 探针都在固定时间窗内运行，使粗糙的平台计时器也能给出可用比例。
func calibratedCRCCombineMin() int {
	crcCalibrationOnce.Do(func() {
		payload := make([]byte, 4<<20)
		for i := range payload {
			payload[i] = byte(i)
		}
		var sink uint32
		// Scan rate: direct CRC32C over a large buffer. | 扫描速率：对大缓冲做直接
		// CRC32C。
		const window = 10 * time.Millisecond
		start := time.Now()
		reps := 0
		for time.Since(start) < window {
			sink ^= measureScan(payload)
			reps++
		}
		elapsed := time.Since(start)
		scanBps := 0.0
		if reps > 0 && elapsed > 0 {
			scanBps = float64(len(payload)*reps) / elapsed.Seconds()
		}
		// Fixed cost of one GF(2) combination. A representative length has
		// half of its bits set; the cost is proportional to the set bits. |
		// 一次 GF(2) 合并的固定成本。代表性长度有一半比特置位；成本与置位数成正比。
		const combineLen = int64(0x5555555555555555)
		start = time.Now()
		combines := 0
		crc := uint32(1)
		for time.Since(start) < window {
			crc = crc32Combine(crc, uint32(combines), combineLen)
			combines++
		}
		elapsed = time.Since(start)
		_ = sink
		if scanBps <= 0 || combines == 0 || elapsed <= 0 {
			crcCalibrationMin = defaultCRCCombineBytes
			return
		}
		combineCost := elapsed.Seconds() / float64(combines)
		// Direct scans twice; the combine path scans once and performs three
		// O(1) combinations (record CRC, segment contribution, segment update).
		// | 直接路径扫描两次；合并路径扫描一次并执行三次 O(1) 合并（记录校验、分段
		// 贡献、分段更新）。
		derived := int(3 * combineCost * scanBps)
		if derived < minCRCCombineBytes {
			derived = minCRCCombineBytes
		}
		if derived > maxCRCCombineBytes {
			derived = maxCRCCombineBytes
		}
		crcCalibrationMin = derived
	})
	return crcCalibrationMin
}

// measureScan is an opaque scan so the calibration loop cannot fold the calls.
// | measureScan 是不可折叠的扫描探针。
//
//go:noinline
func measureScan(p []byte) uint32 { return checksum(p) }

// calibratedMemcpyBps measures the copy bandwidth once. | calibratedMemcpyBps
// 只测量一次复制带宽。
func calibratedMemcpyBps() int64 {
	memcpyCalibrationOnce.Do(func() {
		src := make([]byte, 64<<10)
		dst := make([]byte, len(src))
		for i := range src {
			src[i] = byte(i)
		}
		const reps = 1024
		start := time.Now()
		for i := 0; i < reps; i++ {
			measureCopy(dst, src)
		}
		seconds := time.Since(start).Seconds()
		bps := int64(1 << 30)
		if seconds > 0 {
			bps = int64(float64(len(src)*reps) / seconds)
		}
		if bps < 1<<20 {
			bps = 1 << 20
		}
		memcpyCalibrationBps = bps
	})
	return memcpyCalibrationBps
}

// measureCopy prevents dead-store elimination in the bandwidth probe. |
// measureCopy 在带宽探针中避免死存储消除。
//
//go:noinline
func measureCopy(dst, src []byte) {
	copy(dst, src)
}
