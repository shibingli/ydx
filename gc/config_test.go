package gc

import (
	"errors"
	"testing"
	"time"

	"github.com/spf13/afero"

	"github.com/shibingli/ydx/config"
)

// loadConfig builds a config from an in-memory fixture with a test-only env prefix. | loadConfig
// 使用测试专用环境前缀从内存夹具构建配置。
func loadConfig(t *testing.T, yaml string) *config.Config {
	t.Helper()
	mem := afero.NewMemMapFs()
	if yaml != "" {
		if err := afero.WriteFile(mem, "config.yaml", []byte(yaml), 0o644); err != nil {
			t.Fatalf("write fixture: %v | 写入夹具失败", err)
		}
	}
	c, err := config.Load(config.Options{
		Name:       "gctest",
		ConfigDir:  ".",
		ConfigName: "config",
		EnvPrefix:  "YGCFGTEST",
		EnvFile:    "absent.env",
		FS:         mem,
	})
	if err != nil {
		t.Fatalf("config.Load: %v | 加载配置失败", err)
	}
	return c
}

func TestOptionsFromConfigDefaultsToBalanced(t *testing.T) {
	o, err := OptionsFromConfig(loadConfig(t, ""))
	if err != nil {
		t.Fatalf("OptionsFromConfig error = %v", err)
	}
	want, _ := Preset(StrategyBalanced)
	if o.Enabled != want.Enabled || o.Mode != want.Mode || o.Interval != want.Interval ||
		o.QuietWindow != want.QuietWindow || o.LoadThreshold != want.LoadThreshold ||
		o.MinHeap != want.MinHeap || o.PressureRatio != want.PressureRatio || o.Jitter != want.Jitter {
		t.Fatalf("defaults = %+v, want %+v | 无配置时应得到 balanced 预设", o, want)
	}

	nilOptions, err := OptionsFromConfig(nil)
	if err != nil || nilOptions.Interval != want.Interval || nilOptions.Mode != want.Mode {
		t.Fatalf("nil config = %+v, %v | nil 配置应回退到 balanced", nilOptions, err)
	}
}

func TestOptionsFromConfigPresetAndOverrides(t *testing.T) {
	c := loadConfig(t, `
gc:
  strategy: gentle
  interval: 3m
  load_threshold: 55
  enabled: false
`)
	o, err := OptionsFromConfig(c)
	if err != nil {
		t.Fatalf("OptionsFromConfig error = %v", err)
	}

	preset, _ := Preset(StrategyGentle)
	if o.Mode != preset.Mode || o.QuietWindow != preset.QuietWindow || o.MinHeap != preset.MinHeap {
		t.Fatalf("non-overridden fields = %+v | 未覆盖字段应保留预设值", o)
	}
	if o.Interval != 3*time.Minute || o.LoadThreshold != 55 || o.Enabled {
		t.Fatalf("overrides = %+v | 显式键必须覆盖预设", o)
	}
}

func TestOptionsFromConfigOffWithExplicitEnable(t *testing.T) {
	c := loadConfig(t, `
gc:
  strategy: off
  enabled: true
`)
	o, err := OptionsFromConfig(c)
	if err != nil {
		t.Fatalf("OptionsFromConfig error = %v", err)
	}
	if !o.Enabled {
		t.Fatal("explicit gc.enabled must win over the off preset | 显式 gc.enabled 必须压过 off 预设")
	}
}

func TestOptionsFromConfigRejectsBadValues(t *testing.T) {
	c := loadConfig(t, `
gc:
  strategy: turbo
`)
	if _, err := OptionsFromConfig(c); !errors.Is(err, ErrInvalidStrategy) {
		t.Fatalf("error = %v, want ErrInvalidStrategy", err)
	}

	c = loadConfig(t, `
gc:
  min_heap: -1
`)
	if _, err := OptionsFromConfig(c); !errors.Is(err, ErrInvalidHeap) {
		t.Fatalf("error = %v, want ErrInvalidHeap", err)
	}

	c = loadConfig(t, `
gc:
  mode: fast
`)
	if _, err := OptionsFromConfig(c); !errors.Is(err, ErrInvalidMode) {
		t.Fatalf("error = %v, want ErrInvalidMode", err)
	}
}
