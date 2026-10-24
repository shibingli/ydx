package gc

import (
	"context"
	"errors"
	"testing"
	"time"
)

func TestSampleLoadRecoversPanic(t *testing.T) {
	s, err := New(Options{
		Interval: time.Minute,
		Load: func() (float64, bool) {
			panic("load probe boom")
		},
		Logger: discardLogger(),
	})
	if err != nil {
		t.Fatalf("New: %v", err)
	}

	if _, known := s.sampleLoad(); known {
		t.Fatal("a panicking load probe must be treated as unknown | 发生 panic 的负载探针必须按未知处理")
	}
	if got := s.Stats().Errors; got != 1 {
		t.Fatalf("errors = %d, want 1 | panic 必须计入错误计数", got)
	}
	if _, known := s.sampleLoad(); known {
		t.Fatal("the scheduler must keep treating later panics as unknown | 后续 panic 仍应按未知处理")
	}
	if got := s.Stats().Errors; got != 2 {
		t.Fatalf("errors = %d, want 2 | 每次 panic 都必须计数", got)
	}
}

func TestBusyGateRecoversPanic(t *testing.T) {
	s := policyScheduler(t, func(o *Options) {
		o.Busy = func() bool { panic("busy probe boom") }
	})
	d := s.decide(time.Unix(1000, 0), time.Unix(1000, 0), &gateState{}, 0, true, heapReading{ok: true})
	if !d.busy || d.action != actionWait {
		t.Fatalf("decision = %+v | 发生 panic 的繁忙门必须按繁忙处理（失败关闭）", d)
	}
	if s.Stats().Errors == 0 {
		t.Fatal("the panic must be counted | 繁忙门 panic 必须计数")
	}
}

func TestRunOnceRecoversCollectionPanic(t *testing.T) {
	c := &fakeCollector{}
	s := newFakeScheduler(t, fastOptions(), c, 64<<20, 64<<20)
	s.collect = func(Mode, heapReading) heapReading { panic("collector boom") }

	if _, err := s.RunOnce(context.Background()); !errors.Is(err, ErrPanic) {
		t.Fatalf("RunOnce error = %v, want ErrPanic | 手动回收的 panic 必须转为 ErrPanic", err)
	}
	if s.Stats().Errors != 1 {
		t.Fatalf("errors = %d, want 1 | 手动回收 panic 必须计数", s.Stats().Errors)
	}

	// The scheduler must remain usable after a recovered manual panic. | 手动 panic 恢复后，
	// 调度器必须仍然可用。
	s.collect = c.collect
	if _, err := s.RunOnce(context.Background()); err != nil {
		t.Fatalf("RunOnce after recovery: %v", err)
	}
}

func TestLoopSurvivesCollectionPanic(t *testing.T) {
	c := &fakeCollector{}
	s := newFakeScheduler(t, fastOptions(), c, 64<<20, 64<<20)
	s.heap = &heapReader{readRaw: func() heapReading { panic("heap reader boom") }}

	s.Start()
	waitFor(t, 3*time.Second, func() bool { return s.Stats().Errors >= 1 })

	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	if err := s.Stop(ctx); err != nil {
		t.Fatalf("Stop after recovered panic: %v | panic 恢复后必须能正常停止", err)
	}
	if c.starts.Load() != 0 {
		t.Fatal("the collector must not run when the heap probe panics | 堆探针 panic 时不得进入回收")
	}
}
