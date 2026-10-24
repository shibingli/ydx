package gc

import "time"

// Result describes one collection. | Result 描述一次回收。
type Result struct {
	// Started is when the collection began. | Started 是回收开始时刻。
	Started time.Time
	// Finished is when the collection returned. | Finished 是回收返回时刻。
	Finished time.Time
	// Mode is the collection mode that ran. | Mode 是实际执行的回收模式。
	Mode Mode
	// Duration is Finished minus Started. | Duration 是 Finished 减 Started。
	Duration time.Duration
	// HeapBefore is the heap object bytes observed before the collection. | HeapBefore 是
	// 回收前观察到的堆对象字节数。
	HeapBefore uint64
	// HeapAfter is the heap object bytes observed after the collection. | HeapAfter 是
	// 回收后观察到的堆对象字节数。
	HeapAfter uint64
	// MappedBefore is the runtime-mapped, not-yet-released bytes before the collection. | MappedBefore
	// 是回收前运行时映射且尚未归还的字节数。
	MappedBefore uint64
	// MappedAfter is the same reading after the collection. | MappedAfter 是回收后的同一读数。
	MappedAfter uint64
	// Reclaimed is HeapBefore minus HeapAfter, floored at zero. | Reclaimed 是 HeapBefore
	// 减 HeapAfter，下限为零。
	Reclaimed uint64
	// Released is the growth of heap memory returned to the OS. | Released 是归还操作系统的
	// 堆内存增量。
	Released uint64
	// GCCycles is the number of completed GC cycles during the collection. | GCCycles 是
	// 回收期间完成的 GC 轮数。
	GCCycles uint64
	// Forced reports that memory pressure or MaxDefer overrode the gates. | Forced 报告
	// 内存压力或 MaxDefer 压过了门。
	Forced bool
	// Manual reports that RunOnce performed the collection. | Manual 报告该回收由 RunOnce 执行。
	Manual bool
}

// Stats is one consistent view of the scheduler counters. | Stats 是调度器计数的一致视图。
type Stats struct {
	// Started is when the scheduler was last started. | Started 是调度器最近一次启动的时刻。
	Started time.Time
	// LastRun is when the last collection finished. | LastRun 是最近一次回收完成的时刻。
	LastRun time.Time
	// NextRun is the next scheduled deadline. | NextRun 是下次调度期限。
	NextRun time.Time
	// Last is the most recent collection result. | Last 是最近一次回收结果。
	Last Result
	// Interval is the current (possibly backed-off) interval. | Interval 是当前（可能已退避的）间隔。
	Interval time.Duration
	// Runs is the number of completed collections, manual and scheduled. | Runs 是已完成回收数，
	// 含手动与定时。
	Runs uint64
	// Deferred is the number of due cycles that observed a busy process. | Deferred 是观察到
	// 繁忙进程的到期周期数。
	Deferred uint64
	// SkippedHeap is the number of cycles skipped by the heap floor. | SkippedHeap 是因堆
	// 下限被跳过的周期数。
	SkippedHeap uint64
	// Forced is the number of collections forced by pressure or MaxDefer. | Forced 是因内存
	// 压力或 MaxDefer 强制执行的回收数。
	Forced uint64
	// Errors is the number of recovered panics from callbacks or the collection path. | Errors
	// 是从回调或回收路径恢复的 panic 次数。
	Errors uint64
}
