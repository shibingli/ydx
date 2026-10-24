package gc

import (
	"strings"
	"time"

	"github.com/shibingli/ydx/errs"
	"github.com/shibingli/ydx/log"
)

// Mode selects what one scheduled collection asks the runtime to do. | Mode 选择一次定时回收
// 要求运行时执行的动作。
type Mode string

// Collection modes. | 回收模式。
const (
	// ModeSoft runs runtime.GC and leaves memory release to the runtime's background
	// scavenger. | ModeSoft 执行 runtime.GC，把内存归还交给运行时的后台清扫器。
	ModeSoft Mode = "soft"
	// ModeRelease runs debug.FreeOSMemory: a full collection followed by returning free
	// pages to the operating system. | ModeRelease 执行 debug.FreeOSMemory：完整回收后把
	// 空闲页归还操作系统。
	ModeRelease Mode = "release"
)

// Strategy names accepted by Preset and the gc.strategy configuration key. | Preset 与
// gc.strategy 配置键接受的策略名。
const (
	// StrategyGentle collects rarely and only when the process is genuinely idle. | StrategyGentle
	// 很少回收，且只在进程真正空闲时执行。
	StrategyGentle = "gentle"
	// StrategyBalanced is the default: release memory after a quiet window. | StrategyBalanced
	// 是默认策略：空闲窗口后归还内存。
	StrategyBalanced = "balanced"
	// StrategyAggressive collects often and tolerates a busier process. | StrategyAggressive
	// 回收频繁，并容忍更繁忙的进程。
	StrategyAggressive = "aggressive"
	// StrategyOff disables scheduling while keeping manual runs available. | StrategyOff
	// 关闭调度，但仍允许手动执行。
	StrategyOff = "off"
)

// Default strategy values. They describe the balanced preset and are exported so that
// callers can compare or document what the framework does out of the box. | 默认策略值。
// 它们描述 balanced 预设，导出以便调用方比较或记录框架的开箱行为。
const (
	// DefaultStrategy is used when gc.strategy is absent. | DefaultStrategy 在缺少 gc.strategy 时使用。
	DefaultStrategy = StrategyBalanced
	// DefaultInterval is the balanced interval between collections. | DefaultInterval 是 balanced 策略的回收间隔。
	DefaultInterval = 10 * time.Minute
	// DefaultMaxInterval caps the adaptive backoff. | DefaultMaxInterval 是自适应退避的上限。
	DefaultMaxInterval = time.Hour
	// DefaultSampleInterval is how often the load gate is sampled while waiting. | DefaultSampleInterval
	// 是等待期间负载门的采样间隔。
	DefaultSampleInterval = 5 * time.Second
	// DefaultQuietWindow is how long the process must stay below the load threshold. | DefaultQuietWindow
	// 是进程必须持续低于负载阈值的时长。
	DefaultQuietWindow = 30 * time.Second
	// DefaultLoadThreshold is the balanced CPU utilisation ceiling in percent. | DefaultLoadThreshold
	// 是 balanced 策略的 CPU 利用率上限（百分比）。
	DefaultLoadThreshold = 30.0
	// DefaultMinHeap is the balanced heap floor in bytes. | DefaultMinHeap 是 balanced 策略的堆下限（字节）。
	DefaultMinHeap = 32 << 20
	// DefaultPressureRatio is the balanced fraction of the memory ceiling that forces a
	// collection even while busy. | DefaultPressureRatio 是 balanced 策略下触发强制回收的
	// 内存上限占比。
	DefaultPressureRatio = 0.85
	// DefaultJitter is the balanced relative jitter applied to every interval. | DefaultJitter
	// 是 balanced 策略施加到每个间隔上的相对抖动。
	DefaultJitter = 0.1
)

// Sentinel errors, declared once at package level. | 哨兵错误，在包级声明一次。
var (
	// ErrInvalidMode indicates an unknown collection mode. | ErrInvalidMode 表示未知的回收模式。
	ErrInvalidMode = errs.New("gc: invalid mode | gc：非法的回收模式")
	// ErrInvalidStrategy indicates an unknown strategy preset. | ErrInvalidStrategy 表示未知的策略预设。
	ErrInvalidStrategy = errs.New("gc: invalid strategy | gc：非法的策略预设")
	// ErrInvalidInterval indicates a non-positive interval, sample interval or a max
	// interval smaller than the base interval. | ErrInvalidInterval 表示非正数的间隔、采样间隔，
	// 或小于基础间隔的最大间隔。
	ErrInvalidInterval = errs.New("gc: invalid interval | gc：非法的间隔")
	// ErrInvalidThreshold indicates a load threshold outside [0, 100]. | ErrInvalidThreshold 表示
	// 负载阈值不在 [0, 100] 内。
	ErrInvalidThreshold = errs.New("gc: invalid load threshold | gc：非法的负载阈值")
	// ErrInvalidHeap indicates a negative heap floor. | ErrInvalidHeap 表示负数的堆下限。
	ErrInvalidHeap = errs.New("gc: invalid heap floor | gc：非法的堆下限")
	// ErrInvalidRatio indicates a jitter or pressure ratio outside its range. | ErrInvalidRatio
	// 表示抖动或压力比例超出取值范围。
	ErrInvalidRatio = errs.New("gc: invalid ratio | gc：非法的比例")
	// ErrStopTimeout indicates Stop did not observe the scheduler goroutine exit before
	// the caller's context expired. | ErrStopTimeout 表示 Stop 未在调用方上下文到期前观察到
	// 调度协程退出。
	ErrStopTimeout = errs.New("gc: scheduler did not stop before the deadline | gc：调度器未在期限内停止")
	// ErrPanic indicates that a manual collection panicked and was recovered. | ErrPanic 表示
	// 一次手动回收发生 panic 并已被恢复。
	ErrPanic = errs.New("gc: recovered from a panic | gc：已从 panic 恢复")
)

// LoadFunc reports how busy the process is, as a percentage. It is called only while a
// collection is due, never on a hot path. | LoadFunc 以百分比报告进程的繁忙程度。它只在
// 回收到期期间被调用，绝不位于热路径上。
//
// The callback must return quickly, must not block and must not call Scheduler.Stop or
// Scheduler.Stats. A panic inside it is recovered, counted in Stats.Errors and treated as
// an unknown reading; repeated unknown readings fail closed and defer collection. | 回调必须
// 快速返回、不得阻塞，也不得调用 Scheduler.Stop 或 Scheduler.Stats。其中的 panic 会被恢复、
// 计入 Stats.Errors 并按未知读数处理；连续未知读数会失败关闭并推迟回收。
//
// A negative or non-finite value is treated as unknown so that a buggy probe cannot turn
// into a busy signal that defers collection forever. | 负数或非有限值按未知处理，避免有缺陷的
// 探针变成永远推迟回收的繁忙信号。
type LoadFunc func() (percent float64, ok bool)

// Options configures a Scheduler. Use Preset or OptionsFromConfig to obtain a complete,
// valid set instead of filling every field by hand. | Options 配置 Scheduler。请使用 Preset
// 或 OptionsFromConfig 获得完整有效的取值，而不是手工填写每个字段。
type Options struct {
	// Logger receives lifecycle and collection records; nil uses log.Default(). | Logger
	// 接收生命周期与回收记录；nil 使用 log.Default()。
	Logger *log.Logger
	// Load replaces the default process CPU probe. | Load 替换默认的进程 CPU 探针。
	Load LoadFunc
	// Busy adds a hard application-level gate, for example an in-flight request counter.
	// It is evaluated together with the load threshold. The callback must return quickly,
	// must not block and must not call Scheduler.Stop or Scheduler.Stats; a panic inside
	// it is recovered, counted in Stats.Errors and treated as busy (fail closed). | Busy
	// 追加应用级硬门，例如在途请求计数器；它与负载阈值一起判定。回调必须快速返回、不得阻塞，
	// 也不得调用 Scheduler.Stop 或 Scheduler.Stats；其中的 panic 会被恢复、计入
	// Stats.Errors 并按繁忙处理（失败关闭）。
	Busy func() bool
	// Mode selects soft GC or OS release. | Mode 选择软回收或归还操作系统。
	Mode Mode
	// Interval is the base delay between scheduled collections. | Interval 是两次定时回收之间的基础间隔。
	Interval time.Duration
	// MaxInterval caps adaptive backoff. | MaxInterval 限制自适应退避的上限。
	MaxInterval time.Duration
	// SampleInterval is the polling interval used while waiting for a quiet window. | SampleInterval
	// 是等待空闲窗口期间的轮询间隔。
	SampleInterval time.Duration
	// QuietWindow is how long the process must stay below the threshold before collecting. | QuietWindow
	// 是进程必须持续低于阈值多久才执行回收。
	QuietWindow time.Duration
	// MaxDefer forces a collection after this long even while busy; zero defers
	// indefinitely (memory pressure can still force one). | MaxDefer 在繁忙状态下超过此时长后
	// 强制执行回收；零表示无限期推迟（内存压力仍可强制触发）。
	MaxDefer time.Duration
	// MinHeap is the heap floor in bytes; a smaller heap skips the cycle. Zero disables
	// the floor. | MinHeap 是堆下限（字节）；小于它时跳过本轮。零表示关闭下限。
	MinHeap uint64
	// LoadThreshold is the busy percentage in [0, 100]; zero disables the load gate. | LoadThreshold
	// 是繁忙百分比，取值 [0, 100]；零表示关闭负载门。
	LoadThreshold float64
	// PressureRatio forces a collection at this fraction of the effective memory ceiling;
	// zero disables the override. | PressureRatio 在达到生效内存上限的该比例时强制回收；
	// 零表示关闭该覆盖。
	PressureRatio float64
	// Jitter spreads intervals by ±Jitter to avoid synchronised collections across
	// replicas; it must be in [0, 1). | Jitter 把间隔按 ±Jitter 展开，避免多副本同时回收；
	// 取值必须在 [0, 1) 内。
	Jitter float64
	// Enabled turns the background scheduler on or off; manual runs still work when it
	// is false. | Enabled 打开或关闭后台调度；为 false 时手动执行仍然可用。
	Enabled bool
	// Adaptive grows the interval when a cycle reclaims little. | Adaptive 在回收量很小时增大间隔。
	Adaptive bool
}

// Preset returns a complete option set for the named strategy. An empty name selects
// DefaultStrategy; matching is case-insensitive and ignores surrounding blanks. | Preset
// 返回指定策略的完整选项集。空名称选择 DefaultStrategy；匹配忽略大小写与首尾空白。
func Preset(name string) (Options, error) {
	key := strings.ToLower(strings.TrimSpace(name))
	if key == "" {
		key = DefaultStrategy
	}
	switch key {
	case StrategyGentle:
		return Options{
			Enabled:        true,
			Mode:           ModeSoft,
			Interval:       30 * time.Minute,
			MaxInterval:    2 * time.Hour,
			SampleInterval: 10 * time.Second,
			QuietWindow:    60 * time.Second,
			MaxDefer:       0,
			MinHeap:        64 << 20,
			LoadThreshold:  20,
			PressureRatio:  0.9,
			Jitter:         0.15,
			Adaptive:       true,
		}, nil
	case StrategyBalanced:
		return Options{
			Enabled:        true,
			Mode:           ModeRelease,
			Interval:       DefaultInterval,
			MaxInterval:    DefaultMaxInterval,
			SampleInterval: DefaultSampleInterval,
			QuietWindow:    DefaultQuietWindow,
			MaxDefer:       0,
			MinHeap:        DefaultMinHeap,
			LoadThreshold:  DefaultLoadThreshold,
			PressureRatio:  DefaultPressureRatio,
			Jitter:         DefaultJitter,
			Adaptive:       true,
		}, nil
	case StrategyAggressive:
		return Options{
			Enabled:        true,
			Mode:           ModeRelease,
			Interval:       2 * time.Minute,
			MaxInterval:    30 * time.Minute,
			SampleInterval: 2 * time.Second,
			QuietWindow:    10 * time.Second,
			MaxDefer:       0,
			MinHeap:        8 << 20,
			LoadThreshold:  60,
			PressureRatio:  0.8,
			Jitter:         0.1,
			Adaptive:       true,
		}, nil
	case StrategyOff:
		o, err := Preset(StrategyBalanced)
		if err != nil {
			return Options{}, err
		}
		o.Enabled = false
		return o, nil
	default:
		return Options{}, errs.Detail(ErrInvalidStrategy, "strategy=%q | 策略=%q", name, name)
	}
}

// ParseMode normalises a mode name. An empty value selects ModeRelease. | ParseMode
// 归一化模式名；空值选择 ModeRelease。
func ParseMode(name string) (Mode, error) {
	key := strings.ToLower(strings.TrimSpace(name))
	switch key {
	case "":
		return ModeRelease, nil
	case string(ModeSoft):
		return ModeSoft, nil
	case string(ModeRelease):
		return ModeRelease, nil
	default:
		return "", errs.Detail(ErrInvalidMode, "mode=%q | 模式=%q", name, name)
	}
}

// normalize fills defaults that have no ambiguous zero meaning and validates the rest. | normalize
// 填充没有歧义零值的默认项，并校验其余字段。
func (o Options) normalize() (Options, error) {
	mode, err := ParseMode(string(o.Mode))
	if err != nil {
		return Options{}, err
	}
	o.Mode = mode

	if o.Interval <= 0 {
		return Options{}, errs.Detail(ErrInvalidInterval, "interval=%v | 间隔=%v", o.Interval, o.Interval)
	}
	if o.MaxInterval == 0 {
		o.MaxInterval = o.Interval
	}
	if o.MaxInterval < o.Interval {
		return Options{}, errs.Detail(ErrInvalidInterval,
			"max_interval=%v is smaller than interval=%v | max_interval=%v 小于 interval=%v",
			o.MaxInterval, o.Interval, o.MaxInterval, o.Interval)
	}
	if o.SampleInterval <= 0 {
		o.SampleInterval = min(o.Interval, DefaultSampleInterval)
	}
	if o.QuietWindow < 0 {
		return Options{}, errs.Detail(ErrInvalidInterval, "quiet_window=%v | quiet_window=%v", o.QuietWindow, o.QuietWindow)
	}
	if o.MaxDefer < 0 {
		return Options{}, errs.Detail(ErrInvalidInterval, "max_defer=%v | max_defer=%v", o.MaxDefer, o.MaxDefer)
	}
	if o.LoadThreshold < 0 || o.LoadThreshold > 100 {
		return Options{}, errs.Detail(ErrInvalidThreshold,
			"load_threshold=%v must be within [0, 100] | load_threshold=%v 必须在 [0, 100] 内",
			o.LoadThreshold, o.LoadThreshold)
	}
	if o.Jitter < 0 || o.Jitter >= 1 {
		return Options{}, errs.Detail(ErrInvalidRatio, "jitter=%v must be within [0, 1) | jitter=%v 必须在 [0, 1) 内", o.Jitter, o.Jitter)
	}
	if o.PressureRatio < 0 || o.PressureRatio > 1 {
		return Options{}, errs.Detail(ErrInvalidRatio,
			"pressure_ratio=%v must be within [0, 1] | pressure_ratio=%v 必须在 [0, 1] 内",
			o.PressureRatio, o.PressureRatio)
	}
	if o.Logger == nil {
		o.Logger = log.Default()
	}
	return o, nil
}
