package waf

import (
	"errors"
	"net/http"
	"sync"
	"sync/atomic"
	"testing"
)

func TestHookRuleMatchDeny(t *testing.T) {
	instance := newTestWAF(t, []string{
		`SecRule REQUEST_URI "@contains hit" "id:9200,phase:1,pass,nolog"`,
	}, nil)
	err := instance.AddHook(HookFunc{
		HookName:     "deny-hit",
		HookPriority: 1,
		Fn: func(ctx *HookContext) error {
			if ctx.Point == HookRuleMatch && ctx.Match != nil && ctx.Match.RuleID == 9200 {
				ctx.Deny(http.StatusTeapot, "hook denied")
			}
			return nil
		},
	})
	if err != nil {
		t.Fatalf("AddHook: %v", err)
	}
	response := serveTest(t, instance, httptestNewRequest("/hit"))
	if response.Code != http.StatusTeapot {
		t.Fatalf("status = %d, want 418", response.Code)
	}
}

func TestHookOrderAndCompletion(t *testing.T) {
	instance := newTestWAF(t, []string{
		`SecRule REQUEST_URI "@contains x" "id:9201,phase:1,pass,nolog"`,
	}, nil)
	var mu sync.Mutex
	var order []string
	add := func(name string, priority int) {
		if err := instance.AddHook(HookFunc{
			HookName:     name,
			HookPriority: priority,
			Fn: func(ctx *HookContext) error {
				mu.Lock()
				order = append(order, name+":"+ctx.Point.String())
				mu.Unlock()
				return nil
			},
		}); err != nil {
			t.Fatalf("AddHook %s: %v", name, err)
		}
	}
	add("late", 20)
	add("early", 10)
	serveTest(t, instance, httptestNewRequest("/x"))
	mu.Lock()
	defer mu.Unlock()
	earlyIndex := -1
	lateIndex := -1
	for index, entry := range order {
		if entry == "early:before_phase" && earlyIndex < 0 {
			earlyIndex = index
		}
		if entry == "late:before_phase" && lateIndex < 0 {
			lateIndex = index
		}
	}
	if earlyIndex < 0 || lateIndex < 0 || earlyIndex > lateIndex {
		t.Fatalf("hook priority order wrong: %v", order)
	}
	completed := false
	for _, entry := range order {
		if entry == "late:request_complete" || entry == "early:request_complete" {
			completed = true
		}
	}
	if !completed {
		t.Fatalf("request_complete did not run: %v", order)
	}
}

func TestHookPanicAndErrorAreIsolated(t *testing.T) {
	instance := newTestWAF(t, []string{
		`SecRule REQUEST_URI "@contains x" "id:9202,phase:1,pass,nolog"`,
	}, nil)
	var calls atomic.Int32
	if err := instance.AddHook(HookFunc{
		HookName: "panic",
		Fn: func(ctx *HookContext) error {
			calls.Add(1)
			if ctx.Point == HookBeforePhase {
				panic("boom")
			}
			return errors.New("hook error")
		},
	}); err != nil {
		t.Fatalf("AddHook: %v", err)
	}
	response := serveTest(t, instance, httptestNewRequest("/x"))
	if response.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200", response.Code)
	}
	if calls.Load() < 2 {
		t.Fatalf("hook calls = %d", calls.Load())
	}
	if stats := instance.Stats(); stats.Errors < 2 {
		t.Fatalf("errors = %d, want >= 2", stats.Errors)
	}
}

func TestHookDuplicateAndRemove(t *testing.T) {
	instance := newTestWAF(t, []string{
		`SecRule REQUEST_URI "@contains x" "id:9203,phase:1,pass,nolog"`,
	}, nil)
	hook := HookFunc{HookName: "same", Fn: func(*HookContext) error { return nil }}
	if err := instance.AddHook(hook); err != nil {
		t.Fatalf("AddHook: %v", err)
	}
	if err := instance.AddHook(hook); err == nil {
		t.Fatal("duplicate hook accepted")
	}
	if !instance.RemoveHook("same") {
		t.Fatal("RemoveHook returned false")
	}
	if instance.RemoveHook("same") {
		t.Fatal("RemoveHook removed a missing hook")
	}
}

func TestHookWithoutPointsRunsEverywhere(t *testing.T) {
	instance := newTestWAF(t, []string{
		`SecRule REQUEST_URI "@contains x" "id:9204,phase:1,pass,nolog"`,
	}, nil)
	var points sync.Map
	if err := instance.AddHook(HookFunc{
		HookName: "all",
		Fn: func(ctx *HookContext) error {
			points.Store(ctx.Point, true)
			return nil
		},
	}); err != nil {
		t.Fatalf("AddHook: %v", err)
	}
	serveTest(t, instance, httptestNewRequest("/x"))
	if _, ok := points.Load(HookBeforePhase); !ok {
		t.Fatal("before_phase not delivered")
	}
	if _, ok := points.Load(HookRequestComplete); !ok {
		t.Fatal("request_complete not delivered")
	}
}
