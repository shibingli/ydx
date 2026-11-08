package waf

import (
	"errors"
	"io"
	"net/http"
	"sync"
	"sync/atomic"
	"testing"

	"github.com/shibingli/ydx/log"
)

func TestPluginsReceiveReloadHook(t *testing.T) {
	var reloads atomic.Int32
	plugin := PluginFunc{
		PluginName: "reload-observer",
		HookPoints: []HookPoint{HookReload},
		HookFn: func(ctx *HookContext) error {
			if ctx.Point == HookReload {
				reloads.Add(1)
			}
			return nil
		},
	}
	instance, err := New(Options{
		Directives: []string{`SecRule REQUEST_URI "@contains x" "id:9402,phase:1,pass,nolog"`},
		Logger:     log.New(log.Options{Writer: io.Discard, Level: log.ErrorLevel}),
		Plugins:    []Plugin{plugin},
	})
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	defer func() { _ = instance.Close() }()
	if err := instance.Reload(); err != nil {
		t.Fatalf("Reload: %v", err)
	}
	if reloads.Load() != 1 {
		t.Fatalf("reload hooks = %d, want 1", reloads.Load())
	}
}

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

func TestNativePluginLifecycleAcrossReload(t *testing.T) {
	var inits atomic.Int32
	var closes atomic.Int32
	var hooks atomic.Int32
	var closed atomic.Bool
	plugin := PluginFunc{
		PluginName: "reload-lifecycle",
		InitFn: func(*PluginContext) error {
			inits.Add(1)
			return nil
		},
		HookFn: func(*HookContext) error {
			if closed.Load() {
				t.Error("plugin hook ran after Close")
			}
			hooks.Add(1)
			return nil
		},
		CloseFn: func() error {
			closes.Add(1)
			closed.Store(true)
			return nil
		},
	}
	instance, err := New(Options{
		Directives: []string{`SecRule REQUEST_URI "@contains x" "id:9450,phase:1,pass,nolog"`},
		Logger:     log.New(log.Options{Writer: io.Discard, Level: log.ErrorLevel}),
		Plugins:    []Plugin{plugin},
	})
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	var wait sync.WaitGroup
	for index := 0; index < 16; index++ {
		wait.Add(1)
		go func() {
			defer wait.Done()
			serveTest(t, instance, httptestNewRequest("/x"))
		}()
	}
	for index := 0; index < 4; index++ {
		if err := instance.Reload(); err != nil {
			t.Errorf("Reload: %v", err)
		}
	}
	wait.Wait()
	if inits.Load() != 1 {
		t.Fatalf("plugin initialized %d times, want 1", inits.Load())
	}
	if hooks.Load() == 0 {
		t.Fatal("plugin hook never ran")
	}
	if closes.Load() != 0 {
		t.Fatalf("plugin closed %d times while the WAF was active", closes.Load())
	}
	if err := instance.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}
	if closes.Load() != 1 {
		t.Fatalf("plugin closed %d times, want 1", closes.Load())
	}
}

func TestReloadWithReplacesNativePluginGeneration(t *testing.T) {
	var firstClosed atomic.Int32
	var secondInitialized atomic.Int32
	var secondClosed atomic.Int32
	first := PluginFunc{
		PluginName: "first",
		CloseFn: func() error {
			firstClosed.Add(1)
			return nil
		},
	}
	second := PluginFunc{
		PluginName: "second",
		InitFn: func(*PluginContext) error {
			secondInitialized.Add(1)
			return nil
		},
		CloseFn: func() error {
			secondClosed.Add(1)
			return nil
		},
	}
	logger := log.New(log.Options{Writer: io.Discard, Level: log.ErrorLevel})
	directives := []string{`SecRule REQUEST_URI "@contains x" "id:9451,phase:1,pass,nolog"`}
	instance, err := New(Options{
		Directives: directives,
		Logger:     logger,
		Plugins:    []Plugin{first},
	})
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	if err := instance.ReloadWith(Options{
		Directives: directives,
		Logger:     logger,
		Plugins:    []Plugin{second},
	}); err != nil {
		t.Fatalf("ReloadWith: %v", err)
	}
	if secondInitialized.Load() != 1 {
		t.Fatalf("second plugin initialized %d times, want 1", secondInitialized.Load())
	}
	if firstClosed.Load() != 1 {
		t.Fatalf("first plugin closed %d times, want 1", firstClosed.Load())
	}
	if secondClosed.Load() != 0 {
		t.Fatalf("second plugin closed before WAF Close")
	}
	if err := instance.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}
	if secondClosed.Load() != 1 {
		t.Fatalf("second plugin closed %d times, want 1", secondClosed.Load())
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
