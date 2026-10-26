package gc

import (
	"math"
	"testing"
	"time"
)

func TestCPUProbeUtilisation(t *testing.T) {
	readings := []struct {
		idle  float64
		total float64
		ok    bool
	}{
		{10, 20, true},
		{15, 30, true},
	}
	index := 0
	p := &cpuProbe{readRaw: func() (float64, float64, bool) {
		r := readings[index]
		index++
		return r.idle, r.total, r.ok
	}}

	if _, known := p.sample(); known {
		t.Fatal("the first sample only establishes a baseline | 第一次采样只建立基线")
	}
	percent, known := p.sample()
	if !known {
		t.Fatal("the second sample must produce a measurement | 第二次采样必须给出读数")
	}
	if percent != 50 {
		t.Fatalf("utilisation = %v, want 50 | 利用率应为 50", percent)
	}
}

func TestCPUProbeNoProgress(t *testing.T) {
	p := &cpuProbe{readRaw: func() (float64, float64, bool) { return 5, 10, true }}
	if _, known := p.sample(); known {
		t.Fatal("the first sample must be unknown | 第一次采样应为未知")
	}
	if _, known := p.sample(); known {
		t.Fatal("a frozen counter must be unknown, not busy | 计数器不前进时应为未知而不是繁忙")
	}
}

func TestCPUProbeClampsOverflow(t *testing.T) {
	readings := []struct {
		idle  float64
		total float64
	}{{0, 10}, {-5, 20}}
	index := 0
	p := &cpuProbe{readRaw: func() (float64, float64, bool) {
		r := readings[index]
		index++
		return r.idle, r.total, true
	}}
	_, _ = p.sample()
	percent, known := p.sample()
	if !known || percent != 100 {
		t.Fatalf("percent = %v, known = %v; want 100, true | 空闲倒退应被夹到 100%%", percent, known)
	}
}

func TestCPUProbeUnavailable(t *testing.T) {
	var p *cpuProbe
	if _, known := p.sample(); known {
		t.Fatal("a nil probe must be unknown | nil 探针应为未知")
	}
	if _, known := (&cpuProbe{}).sample(); known {
		t.Fatal("a probe without a reader must be unknown | 没有读取器的探针应为未知")
	}
}

func TestHeapReaderFromRuntime(t *testing.T) {
	r := newHeapReader()
	if r.readRaw == nil {
		t.Skip("runtime/metrics heap classes are unavailable | 运行时未提供堆类别指标")
	}
	reading := r.read()
	if !reading.ok {
		t.Fatal("heap reading must be valid | 堆读数必须有效")
	}
	if reading.mapped == 0 && reading.heapObjects == 0 {
		t.Fatal("a running test process must report a non-zero heap | 运行中的测试进程应报告非零堆")
	}
	second := r.read()
	if second.gcCycles < reading.gcCycles {
		t.Fatalf("GC cycles went backwards: %d -> %d | GC 轮数倒退", reading.gcCycles, second.gcCycles)
	}
}

func TestHeapReaderUnavailable(t *testing.T) {
	var r *heapReader
	if reading := r.read(); reading.ok {
		t.Fatal("a nil reader must report unavailable | nil 读取器应报告不可用")
	}
	if reading := (&heapReader{}).read(); reading.ok {
		t.Fatal("a reader without metrics must report unavailable | 无指标的读取器应报告不可用")
	}
}

// TestGoSoftMemoryLimit treats the runtime's MaxInt64 default as "no limit"; otherwise
// platforms without a host memory ceiling would expose an implausible 8 EiB limit.
// | TestGoSoftMemoryLimit 把运行时的 MaxInt64 默认值视为“未设置”；否则没有宿主内存上限的
// 平台会暴露不合理的 8 EiB 上限。
func TestGoSoftMemoryLimit(t *testing.T) {
	tests := []struct {
		name string
		in   int64
		want uint64
	}{
		{"unset default", math.MaxInt64, 0},
		{"zero", 0, 0},
		{"negative", -1, 0},
		{"real limit", 1 << 30, 1 << 30},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			if got := goSoftMemoryLimit(tc.in); got != tc.want {
				t.Fatalf("goSoftMemoryLimit(%d) = %d, want %d | 转换结果不符", tc.in, got, tc.want)
			}
		})
	}
}

func TestEffectiveMemoryLimit(t *testing.T) {
	limit := effectiveMemoryLimit()
	if limit == 0 {
		t.Skip("the host exposes no memory ceiling | 宿主未提供内存上限")
	}
	if limit > 1<<62 {
		t.Fatalf("limit = %d, implausibly large | 内存上限过大", limit)
	}
}

// TestSubtractFloor covers the counter-underflow guard. | TestSubtractFloor 覆盖计数器下溢保护。
func TestSubtractFloor(t *testing.T) {
	cases := []struct {
		a, b, want uint64
	}{{10, 4, 6}, {4, 10, 0}, {7, 7, 0}}
	for _, tc := range cases {
		if got := subtractFloor(tc.a, tc.b); got != tc.want {
			t.Errorf("subtractFloor(%d, %d) = %d, want %d", tc.a, tc.b, got, tc.want)
		}
	}
}

// TestJitterBounds keeps randomised intervals inside the documented band. | TestJitterBounds
// 保证随机间隔落在文档给出的范围内。
func TestJitterBounds(t *testing.T) {
	s := &Scheduler{opts: Options{Jitter: 0.1}}
	base := time.Minute
	for i := 0; i < 1000; i++ {
		got := s.jitter(base)
		if got < 54*time.Second || got > 66*time.Second {
			t.Fatalf("jittered interval = %v, want within ±10%% of %v | 抖动后的间隔超出 ±10%%", got, base)
		}
	}
	if got := s.jitter(0); got != 0 {
		t.Fatalf("jitter(0) = %v, want 0", got)
	}
}
