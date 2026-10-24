// Package gc schedules garbage collection during quiet periods instead of at a fixed
// wall-clock moment. | Package gc 在空闲时段调度垃圾回收，而不是在固定的墙钟时刻触发。
//
// The Go runtime already collects automatically; calling runtime.GC or
// debug.FreeOSMemory only decides *when* an extra cycle happens and whether memory is
// returned to the operating system immediately. Those calls are cheap when the process
// is idle and disruptive when it is not, which is exactly what this package optimises:
// it waits for a configurable quiet window, skips busy periods, and still forces a
// collection when the Go memory limit (or the host/cgroup ceiling) is approached. |
// Go 运行时本身会自动回收；调用 runtime.GC 或 debug.FreeOSMemory 只决定额外一轮回收发生在
// *何时*，以及是否立即把内存归还操作系统。进程空闲时这些调用很便宜，繁忙时却会干扰业务，
// 这正是本包要优化的事情：等待可配置的空闲窗口、跳过繁忙时段，并在接近 Go 内存上限
// （或宿主/cgroup 上限）时仍然强制执行一次回收。
//
// Policy | 策略：
//
//   - ModeSoft runs runtime.GC; ModeRelease runs debug.FreeOSMemory and returns free
//     pages to the operating system. | ModeSoft 执行 runtime.GC；ModeRelease 执行
//     debug.FreeOSMemory 并把空闲页归还操作系统。
//   - The load gate uses the process's own CPU utilisation by default (runtime/metrics,
//     relative to GOMAXPROCS). Options.Load replaces it, Options.Busy adds a hard gate
//     such as an in-flight request counter. A probe that panics or stops reporting fails
//     closed (treated as busy), so unknown state never triggers a peak-time collection. |
//     负载门默认使用进程自身的 CPU 利用率（runtime/metrics，相对 GOMAXPROCS）；
//     Options.Load 可替换该来源，Options.Busy 可追加业务门，例如在途请求数。发生 panic
//     或不再上报读数的探针按失败关闭（视为繁忙）处理，未知状态绝不会在高峰触发回收。
//   - A collection starts only after the load stayed below Options.LoadThreshold for
//     Options.QuietWindow. The heap floor avoids pointless cycles on a tiny heap. | 只有
//     负载连续 Options.QuietWindow 低于 Options.LoadThreshold 才会开始回收；堆下限避免
//     在小堆上空转。
//   - Memory pressure overrides the busy gate: when the mapped heap reaches
//     Options.PressureRatio of the effective memory ceiling, the scheduler collects
//     regardless of load, so an unattended process cannot grow without bound. The next
//     recheck after a pressure-forced cycle is capped at one minute. | 内存压力会压过繁忙门：
//     映射堆达到生效内存上限的 Options.PressureRatio 时，无论负载如何都会回收，使无人值守
//     的进程不会无限增长；压力强制回收后的下一次复查不超过一分钟。
//   - With Options.Adaptive, a cycle that reclaims too little doubles the next interval
//     up to Options.MaxInterval, so a fully live heap is not collected over and over. |
//     开启 Options.Adaptive 时，回收量过小会把下次间隔翻倍，直至 Options.MaxInterval，
//     避免对一个几乎全是存活对象的堆反复回收。
//
// Presets | 预设：
//
//	gentle      soft GC every ~30m, strictly idle only | 约 30 分钟一次软回收，只在严格空闲时执行
//	balanced    release GC every ~10m, the default       | 约 10 分钟一次释放式回收，默认值
//	aggressive  release GC every ~2m, tolerant of load   | 约 2 分钟一次释放式回收，对负载更宽容
//	off         scheduling disabled, manual runs allowed | 关闭调度，仍允许手动执行
//
// Typical usage | 典型用法：
//
//	s, err := gc.New(gc.Options{
//		Enabled:  true,
//		Interval: 10 * time.Minute,
//		Mode:     gc.ModeRelease,
//	})
//	if err != nil {
//		return err
//	}
//	s.Start()
//	defer func() { _ = s.Stop(context.Background()) }()
//
// Config-driven usage | 配置驱动用法：
//
//	opts, err := gc.OptionsFromConfig(cfg) // reads the gc.* section and strategy presets
//	if err != nil {
//		return err
//	}
//	s, err := gc.New(opts)
//
// The scheduler owns exactly one goroutine, started by Start and stopped by Stop. Stop
// waits for an in-flight collection, so callers bound it with a context; the goroutine
// never outlives Stop's success. | 调度器只拥有一个协程，由 Start 启动、Stop 停止。Stop 会
// 等待正在执行的回收，因此调用方用 context 限定等待；协程绝不会在 Stop 成功后继续存活。
package gc
