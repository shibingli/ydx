package gc

import (
	"testing"
	"time"
)

// policyScheduler builds a scheduler for direct gate tests. | policyScheduler 构建用于
// 直接测试门的调度器。
func policyScheduler(t *testing.T, mutate func(*Options)) *Scheduler {
	t.Helper()
	o := Options{
		Enabled:        true,
		Interval:       time.Minute,
		MaxInterval:    time.Hour,
		SampleInterval: 10 * time.Second,
		QuietWindow:    30 * time.Second,
		LoadThreshold:  30,
		PressureRatio:  0.8,
		Logger:         discardLogger(),
	}
	if mutate != nil {
		mutate(&o)
	}
	s, err := New(o)
	if err != nil {
		t.Fatalf("New: %v | 构造调度器失败", err)
	}
	s.limit = func() uint64 { return 1000 }
	return s
}

func TestDecideMemoryPressureOverridesBusy(t *testing.T) {
	s := policyScheduler(t, func(o *Options) {
		o.Busy = func() bool { return true }
	})
	st := &gateState{}
	now := time.Unix(1000, 0)

	d := s.decide(now, now, st, 95, true, heapReading{heapObjects: 64 << 20, mapped: 800, ok: true})
	if d.action != actionCollect || !d.forced || !d.pressure {
		t.Fatalf("pressure decision = %+v | 内存压力必须强制回收并标记压力来源", d)
	}

	d = s.decide(now, now, st, 95, true, heapReading{heapObjects: 64 << 20, mapped: 799, ok: true})
	if d.action != actionWait || !d.busy || d.forced {
		t.Fatalf("below-pressure decision = %+v | 未达压力比例时应因繁忙等待", d)
	}
}

func TestDecideHeapFloor(t *testing.T) {
	s := policyScheduler(t, func(o *Options) {
		o.MinHeap = 100
		o.QuietWindow = 0
		o.PressureRatio = 0
	})
	st := &gateState{}
	now := time.Unix(1000, 0)

	if d := s.decide(now, now, st, 0, true, heapReading{heapObjects: 50, ok: true}); d.action != actionHeapSkip {
		t.Fatalf("small-heap decision = %+v | 低于堆下限应跳过", d)
	}
	if d := s.decide(now, now, st, 0, true, heapReading{heapObjects: 150, ok: true}); d.action != actionCollect {
		t.Fatalf("large-heap decision = %+v | 达到堆下限应回收", d)
	}
}

func TestDecideLoadThreshold(t *testing.T) {
	s := policyScheduler(t, nil)
	st := &gateState{}
	now := time.Unix(1000, 0)

	d := s.decide(now, now, st, 50, true, heapReading{ok: true})
	if d.action != actionWait || !d.busy || d.wait != s.opts.SampleInterval {
		t.Fatalf("busy decision = %+v | 超过阈值应等待一个采样间隔", d)
	}
}

func TestDecideQuietWindow(t *testing.T) {
	s := policyScheduler(t, nil)
	st := &gateState{}
	t0 := time.Unix(1000, 0)
	hp := heapReading{ok: true}

	for _, elapsed := range []time.Duration{0, 10 * time.Second, 20 * time.Second} {
		d := s.decide(t0.Add(elapsed), t0, st, 5, true, hp)
		if d.action != actionWait || d.busy {
			t.Fatalf("at +%v decision = %+v | 空闲窗口未满应继续等待", elapsed, d)
		}
	}
	if d := s.decide(t0.Add(30*time.Second), t0, st, 5, true, hp); d.action != actionCollect {
		t.Fatalf("at +30s decision = %+v | 空闲窗口已满应回收", d)
	}
}

func TestDecideBusyResetsQuietWindow(t *testing.T) {
	s := policyScheduler(t, nil)
	st := &gateState{}
	t0 := time.Unix(1000, 0)
	hp := heapReading{ok: true}

	_ = s.decide(t0, t0, st, 5, true, hp)
	_ = s.decide(t0.Add(10*time.Second), t0, st, 60, true, hp)
	if !st.quietSince.IsZero() {
		t.Fatal("a busy sample must reset the quiet window | 繁忙采样必须重置空闲窗口")
	}

	quietStart := t0.Add(20 * time.Second)
	if d := s.decide(quietStart, t0, st, 5, true, hp); d.action != actionWait {
		t.Fatalf("after busy decision = %+v | 重新空闲后应重新计时", d)
	}
	if d := s.decide(quietStart.Add(20*time.Second), t0, st, 5, true, hp); d.action != actionWait {
		t.Fatalf("partial window decision = %+v | 空闲窗口未满应继续等待", d)
	}
	if d := s.decide(quietStart.Add(30*time.Second), t0, st, 5, true, hp); d.action != actionCollect {
		t.Fatalf("full window decision = %+v | 空闲窗口已满应回收", d)
	}
}

func TestDecideMaxDeferForcesCollection(t *testing.T) {
	s := policyScheduler(t, func(o *Options) {
		o.Busy = func() bool { return true }
		o.MaxDefer = time.Minute
	})
	st := &gateState{}
	now := time.Unix(1000, 0)
	hp := heapReading{ok: true}

	if d := s.decide(now, now.Add(-30*time.Second), st, 95, true, hp); d.action != actionWait || !d.busy {
		t.Fatalf("within max-defer decision = %+v | 未到强制期限应继续推迟", d)
	}
	if d := s.decide(now, now.Add(-2*time.Minute), st, 95, true, hp); d.action != actionCollect || !d.forced {
		t.Fatalf("past max-defer decision = %+v | 超过强制期限应回收", d)
	}
}

func TestDecideUnknownLoadDegrades(t *testing.T) {
	s := policyScheduler(t, func(o *Options) {
		o.QuietWindow = 0
	})
	st := &gateState{}
	now := time.Unix(1000, 0)
	hp := heapReading{ok: true}

	for i := 1; i <= maxUnknownSamples; i++ {
		d := s.decide(now, now, st, 0, false, hp)
		if d.action != actionWait || !d.unknown {
			t.Fatalf("unknown sample %d = %+v | 缺少读数前应等待", i, d)
		}
	}
	if d := s.decide(now, now, st, 0, false, hp); !d.unknownExhausted || !d.busy {
		t.Fatalf("exhausted decision = %+v | 连续缺少读数应失败关闭（按繁忙处理）", d)
	}
	if d := s.decide(now, now, st, 0, false, hp); d.action != actionWait || !d.busy {
		t.Fatalf("degraded decision = %+v | 探针降级后仍应保持繁忙", d)
	}
	// A recovered probe clears the degraded state and lets the quiet window finish. | 探针恢复后
	// 清除降级状态，空闲窗口随即完成。
	if d := s.decide(now, now, st, 0, true, hp); d.action != actionCollect {
		t.Fatalf("recovered decision = %+v | 探针恢复后应恢复回收", d)
	}
}

func TestDecideUnavailableProbeDisablesLoadGate(t *testing.T) {
	s := policyScheduler(t, func(o *Options) {
		o.QuietWindow = 0
	})
	s.loadAvailable = false
	d := s.decide(time.Unix(1000, 0), time.Unix(1000, 0), &gateState{}, 0, false, heapReading{ok: true})
	if d.action != actionCollect {
		t.Fatalf("unavailable-probe decision = %+v | 静态不可用的探针应关闭负载门而不是永久推迟", d)
	}
}

func TestDecideBusyFuncWithoutLoad(t *testing.T) {
	s := policyScheduler(t, func(o *Options) {
		o.LoadThreshold = 0
		o.Busy = func() bool { return true }
	})
	d := s.decide(time.Unix(1000, 0), time.Unix(1000, 0), &gateState{}, 0, true, heapReading{ok: true})
	if d.action != actionWait || !d.busy {
		t.Fatalf("busy-func decision = %+v | 应用级硬门应生效", d)
	}
}

func TestDecideUnavailableHeapSkipsFloor(t *testing.T) {
	s := policyScheduler(t, func(o *Options) {
		o.MinHeap = 1 << 30
		o.QuietWindow = 0
	})
	d := s.decide(time.Unix(1000, 0), time.Unix(1000, 0), &gateState{}, 0, true, heapReading{})
	if d.action != actionCollect {
		t.Fatalf("unavailable-heap decision = %+v | 堆指标不可用时不得误跳过", d)
	}
}

func TestScheduleNextShortensAfterPressure(t *testing.T) {
	s := policyScheduler(t, nil)
	now := time.Unix(1000, 0)

	s.scheduleNext(now, false)
	if got := s.Stats().NextRun; !got.Equal(now.Add(s.opts.Interval)) {
		t.Fatalf("normal next run = %v, want %v | 常规间隔不符", got, now.Add(s.opts.Interval))
	}

	s.scheduleNext(now, true)
	if got := s.Stats().NextRun; !got.Equal(now.Add(pressureRecheck)) {
		t.Fatalf("pressure next run = %v, want %v | 压力后应在一分钟内复查", got, now.Add(pressureRecheck))
	}
}
