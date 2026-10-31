package waf

import (
	"errors"
	"io"
	"net/http"
	"sync/atomic"
	"testing"

	"github.com/shibingli/ydx/log"
)

func TestPluginErrorReachesHook(t *testing.T) {
	var reported atomic.Int32
	hook := HookFunc{
		HookName:   "plugin-error",
		HookPoints: []HookPoint{HookPluginError},
		Fn: func(ctx *HookContext) error {
			if ctx.Err != nil {
				reported.Add(1)
			}
			return nil
		},
	}
	plugin := PluginFunc{
		PluginName: "failing",
		HookFn:     func(*HookContext) error { return errors.New("plugin boom") },
	}
	instance, err := New(Options{
		Directives: []string{`SecRule REQUEST_URI "@contains x" "id:9401,phase:1,pass,nolog"`},
		Logger:     log.New(log.Options{Writer: io.Discard, Level: log.ErrorLevel}),
		Hooks:      []Hook{hook},
		Plugins:    []Plugin{plugin},
	})
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	defer func() { _ = instance.Close() }()
	serveTest(t, instance, httptestNewRequest("/x"))
	if reported.Load() == 0 {
		t.Fatal("HookPluginError was not delivered")
	}
}

func TestNativePluginLifecycleAndHook(t *testing.T) {
	var initialized atomic.Bool
	var hooked atomic.Int32
	var closed atomic.Bool
	plugin := PluginFunc{
		PluginName: "native-test",
		InitFn: func(ctx *PluginContext) error {
			if ctx.Logger == nil {
				t.Error("plugin context has no logger")
			}
			initialized.Store(true)
			return nil
		},
		HookFn: func(ctx *HookContext) error {
			hooked.Add(1)
			if ctx.Point == HookRuleMatch && ctx.Match != nil && ctx.Match.RuleID == 9400 {
				ctx.Deny(http.StatusForbidden, "plugin denied")
			}
			return nil
		},
		CloseFn: func() error {
			closed.Store(true)
			return nil
		},
	}
	instance, err := New(Options{
		Directives: []string{
			`SecRule REQUEST_URI "@contains plugin" "id:9400,phase:1,pass,nolog"`,
		},
		Logger:  log.New(log.Options{Writer: io.Discard, Level: log.ErrorLevel}),
		Plugins: []Plugin{plugin},
	})
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	if !initialized.Load() {
		t.Fatal("plugin was not initialized")
	}
	response := serveTest(t, instance, httptestNewRequest("/plugin"))
	if response.Code != http.StatusForbidden {
		t.Fatalf("status = %d", response.Code)
	}
	if hooked.Load() == 0 {
		t.Fatal("plugin hook was not called")
	}
	if err := instance.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}
	if !closed.Load() {
		t.Fatal("plugin was not closed")
	}
}
