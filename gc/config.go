package gc

import (
	"github.com/shibingli/ydx/config"
	"github.com/shibingli/ydx/errs"
)

// OptionsFromConfig resolves the gc.* configuration section into Scheduler options. | OptionsFromConfig
// 把 gc.* 配置段解析为调度器选项。
//
// Resolution order | 解析顺序：
//
//  1. gc.strategy selects a preset (gentle, balanced, aggressive, off); an absent or empty
//     value selects DefaultStrategy. | gc.strategy 选择预设（gentle、balanced、aggressive、
//     off）；缺失或为空时选择 DefaultStrategy。
//  2. Every gc.* key that is explicitly present in any configuration layer (file, env or
//     bound flag) overrides the preset field by field. | 任何配置层（文件、环境变量或绑定的
//     命令行参数）中显式出现的 gc.* 键都会逐字段覆盖预设。
//
// Preset values are not registered in config.Defaults, so IsSet reflects genuine user
// intent rather than a framework default. This is what makes presets and per-field
// overrides composable. | 预设值不注册到 config.Defaults，因此 IsSet 反映的是用户真实意图，
// 而不是框架默认值；这正是预设与逐字段覆盖可以组合的原因。
func OptionsFromConfig(c *config.Config) (Options, error) {
	if c == nil {
		return Preset(DefaultStrategy)
	}

	o, err := Preset(c.GetString("gc.strategy"))
	if err != nil {
		return Options{}, err
	}

	if c.IsSet("gc.enabled") {
		o.Enabled = c.GetBool("gc.enabled")
	}
	if c.IsSet("gc.mode") {
		mode, err := ParseMode(c.GetString("gc.mode"))
		if err != nil {
			return Options{}, err
		}
		o.Mode = mode
	}
	if c.IsSet("gc.interval") {
		o.Interval = c.GetDuration("gc.interval")
	}
	if c.IsSet("gc.max_interval") {
		o.MaxInterval = c.GetDuration("gc.max_interval")
	}
	if c.IsSet("gc.sample_interval") {
		o.SampleInterval = c.GetDuration("gc.sample_interval")
	}
	if c.IsSet("gc.quiet_window") {
		o.QuietWindow = c.GetDuration("gc.quiet_window")
	}
	if c.IsSet("gc.max_defer") {
		o.MaxDefer = c.GetDuration("gc.max_defer")
	}
	if c.IsSet("gc.min_heap") {
		n := c.GetInt64("gc.min_heap")
		if n < 0 {
			return Options{}, errs.Detail(ErrInvalidHeap, "min_heap=%d | min_heap=%d", n, n)
		}
		o.MinHeap = uint64(n)
	}
	if c.IsSet("gc.load_threshold") {
		o.LoadThreshold = c.GetFloat64("gc.load_threshold")
	}
	if c.IsSet("gc.pressure_ratio") {
		o.PressureRatio = c.GetFloat64("gc.pressure_ratio")
	}
	if c.IsSet("gc.jitter") {
		o.Jitter = c.GetFloat64("gc.jitter")
	}
	if c.IsSet("gc.adaptive") {
		o.Adaptive = c.GetBool("gc.adaptive")
	}

	return o, nil
}
