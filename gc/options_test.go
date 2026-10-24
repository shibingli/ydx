package gc

import (
	"errors"
	"io"
	"testing"
	"time"

	"github.com/shibingli/ydx/log"
)

// discardLogger returns a logger that keeps test output clean. | discardLogger 返回一个
// 保持测试输出整洁的日志器。
func discardLogger() *log.Logger {
	return log.New(log.Options{Writer: io.Discard})
}

func TestPresetBalancedDefaults(t *testing.T) {
	o, err := Preset("")
	if err != nil {
		t.Fatalf("Preset(\"\") error = %v | 空策略应返回默认预设", err)
	}
	if !o.Enabled || o.Mode != ModeRelease || o.Interval != DefaultInterval {
		t.Fatalf("balanced = %+v | balanced 预设不符", o)
	}
	if o.QuietWindow != DefaultQuietWindow || o.LoadThreshold != DefaultLoadThreshold ||
		o.MinHeap != DefaultMinHeap || o.PressureRatio != DefaultPressureRatio || o.Jitter != DefaultJitter {
		t.Fatalf("balanced defaults = %+v | balanced 默认值不符", o)
	}
	if !o.Adaptive || o.MaxInterval != DefaultMaxInterval {
		t.Fatalf("balanced adaptive = %+v | balanced 自适应设置不符", o)
	}
}

func TestPresetStrategies(t *testing.T) {
	gentle, err := Preset(StrategyGentle)
	if err != nil {
		t.Fatalf("gentle error = %v", err)
	}
	if gentle.Mode != ModeSoft || gentle.Interval <= DefaultInterval || gentle.LoadThreshold >= DefaultLoadThreshold {
		t.Fatalf("gentle = %+v | gentle 应更软、更慢、更严格", gentle)
	}

	aggressive, err := Preset("AGGRESSIVE")
	if err != nil {
		t.Fatalf("aggressive error = %v", err)
	}
	if aggressive.Mode != ModeRelease || aggressive.Interval >= DefaultInterval || aggressive.LoadThreshold <= DefaultLoadThreshold {
		t.Fatalf("aggressive = %+v | aggressive 应更快、更宽容", aggressive)
	}

	off, err := Preset(StrategyOff)
	if err != nil {
		t.Fatalf("off error = %v", err)
	}
	if off.Enabled {
		t.Fatalf("off.Enabled = true | off 必须关闭调度")
	}
}

func TestPresetUnknown(t *testing.T) {
	if _, err := Preset("turbo"); !errors.Is(err, ErrInvalidStrategy) {
		t.Fatalf("error = %v, want ErrInvalidStrategy | 未知策略应返回 ErrInvalidStrategy", err)
	}
}

func TestParseMode(t *testing.T) {
	cases := []struct {
		in   string
		want Mode
		err  error
	}{
		{"", ModeRelease, nil},
		{" SOFT ", ModeSoft, nil},
		{"release", ModeRelease, nil},
		{"fast", "", ErrInvalidMode},
	}
	for _, tc := range cases {
		got, err := ParseMode(tc.in)
		if tc.err != nil {
			if !errors.Is(err, tc.err) {
				t.Errorf("ParseMode(%q) error = %v, want %v", tc.in, err, tc.err)
			}
			continue
		}
		if err != nil || got != tc.want {
			t.Errorf("ParseMode(%q) = %q, %v; want %q", tc.in, got, err, tc.want)
		}
	}
}

func TestNewFillsAndValidates(t *testing.T) {
	s, err := New(Options{
		Interval:      time.Minute,
		QuietWindow:   time.Second,
		LoadThreshold: 30,
		Logger:        discardLogger(),
	})
	if err != nil {
		t.Fatalf("New error = %v | 合法选项不应失败", err)
	}
	if s.opts.Mode != ModeRelease || s.opts.SampleInterval != DefaultSampleInterval || s.opts.MaxInterval != time.Minute {
		t.Fatalf("normalised = %+v | 归一化默认值不符", s.opts)
	}

	cases := []struct {
		name string
		opts Options
		want error
	}{
		{"zero interval", Options{Logger: discardLogger()}, ErrInvalidInterval},
		{"negative quiet", Options{Interval: time.Minute, QuietWindow: -time.Second, Logger: discardLogger()}, ErrInvalidInterval},
		{"max below interval", Options{Interval: time.Minute, MaxInterval: time.Second, Logger: discardLogger()}, ErrInvalidInterval},
		{"bad threshold", Options{Interval: time.Minute, LoadThreshold: 101, Logger: discardLogger()}, ErrInvalidThreshold},
		{"bad jitter", Options{Interval: time.Minute, Jitter: 1, Logger: discardLogger()}, ErrInvalidRatio},
		{"bad pressure", Options{Interval: time.Minute, PressureRatio: 1.5, Logger: discardLogger()}, ErrInvalidRatio},
		{"bad mode", Options{Interval: time.Minute, Mode: "fast", Logger: discardLogger()}, ErrInvalidMode},
		{"bad max defer", Options{Interval: time.Minute, MaxDefer: -time.Second, Logger: discardLogger()}, ErrInvalidInterval},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if _, err := New(tc.opts); !errors.Is(err, tc.want) {
				t.Fatalf("New error = %v, want %v", err, tc.want)
			}
		})
	}
}

func TestNewDefaultsLogger(t *testing.T) {
	s, err := New(Options{Interval: time.Minute})
	if err != nil {
		t.Fatalf("New error = %v", err)
	}
	if s.logger == nil {
		t.Fatal("logger must never be nil | 日志器不得为 nil")
	}
}
