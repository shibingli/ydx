package waf

import (
	"io"
	"net/http"
	"net/http/httptest"
	"sync"
	"sync/atomic"
	"testing"

	"github.com/shibingli/ydx/log"
)

// parallelRules returns four side-effect-free rules in source order. | parallelRules 按源码顺序返回
// 四条无副作用规则。
func parallelRules() []string {
	return []string{
		`SecRule REQUEST_URI "@contains a" "id:9801,phase:1,pass,log"`,
		`SecRule REQUEST_URI "@contains b" "id:9802,phase:1,pass,log"`,
		`SecRule REQUEST_URI "@contains c" "id:9803,phase:1,deny,status:403,log"`,
		`SecRule REQUEST_URI "@contains d" "id:9804,phase:1,pass,log"`,
	}
}

// observeMatches runs one request and returns the status and matched rule ids ordered by commit.
// | observeMatches 运行一个请求并返回状态与按提交顺序排列的命中规则 id。
func observeMatches(t *testing.T, directives []string, workers int, target string, detection bool) (int, []int) {
	t.Helper()
	var matches []int
	options := Options{
		Directives:      directives,
		ParallelWorkers: workers,
		Logger:          log.New(log.Options{Writer: io.Discard, Level: log.ErrorLevel}),
		Observer: func(event Event) {
			matches = matches[:0]
			for _, match := range event.Matches {
				matches = append(matches, match.RuleID)
			}
		},
	}
	if detection {
		options.Mode = ModeDetection
	}
	instance, err := New(options)
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	defer func() { _ = instance.Close() }()
	response := serveTest(t, instance, httptestNewRequest(target))
	return response.Code, matches
}

func TestParallelRulesMatchSequentialSemantics(t *testing.T) {
	for _, detection := range []bool{false, true} {
		sequentialStatus, sequentialMatches := observeMatches(t, parallelRules(), 1, "/abcd", detection)
		parallelStatus, parallelMatches := observeMatches(t, parallelRules(), 8, "/abcd", detection)
		if sequentialStatus != parallelStatus {
			t.Fatalf("detection=%v status sequential=%d parallel=%d", detection, sequentialStatus, parallelStatus)
		}
		if len(sequentialMatches) != len(parallelMatches) {
			t.Fatalf("detection=%v matches sequential=%v parallel=%v", detection, sequentialMatches, parallelMatches)
		}
		for index := range sequentialMatches {
			if sequentialMatches[index] != parallelMatches[index] {
				t.Fatalf("detection=%v match order sequential=%v parallel=%v", detection, sequentialMatches, parallelMatches)
			}
		}
	}
}

func TestParallelRespectsBarriers(t *testing.T) {
	directives := []string{
		`SecRule REQUEST_URI "@contains seq" "id:9810,phase:1,pass,nolog,setvar:tx.flag=1"`,
		`SecRule TX:flag "@eq 1" "id:9811,phase:1,deny,status:403,log"`,
		`SecRule REQUEST_URI "@contains seq" "id:9812,phase:1,pass,log"`,
		`SecRule REQUEST_URI "@contains seq" "id:9813,phase:1,pass,log"`,
		`SecRule REQUEST_URI "@contains seq" "id:9814,phase:1,pass,log"`,
	}
	status, matches := observeMatches(t, directives, 8, "/seq", false)
	if status != http.StatusForbidden {
		t.Fatalf("status = %d", status)
	}
	if len(matches) == 0 || matches[0] != 9811 {
		t.Fatalf("barrier order violated: %v", matches)
	}
}

func TestParallelCollectionsPrewarmed(t *testing.T) {
	directives := []string{
		`SecRule ARGS:q "@contains attack" "id:9820,phase:1,pass,log"`,
		`SecRule REQUEST_HEADERS:User-Agent "@contains Mozilla" "id:9821,phase:1,pass,log"`,
		`SecRule REQUEST_COOKIES:sid "@contains abc" "id:9822,phase:1,pass,log"`,
		`SecRule REQUEST_HEADERS:Host "@contains example.com" "id:9823,phase:1,deny,status:403,log"`,
	}
	request := httptest.NewRequest(http.MethodGet, "/?q=attack", nil)
	request.Header.Set("User-Agent", "Mozilla/5.0")
	request.Header.Set("Cookie", "sid=abc")
	var matches []int
	instance, err := New(Options{
		Directives:      directives,
		ParallelWorkers: 8,
		Logger:          log.New(log.Options{Writer: io.Discard, Level: log.ErrorLevel}),
		Observer: func(event Event) {
			for _, match := range event.Matches {
				matches = append(matches, match.RuleID)
			}
		},
	})
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	defer func() { _ = instance.Close() }()
	response := serveTest(t, instance, request)
	if response.Code != http.StatusForbidden {
		t.Fatalf("status = %d", response.Code)
	}
	if len(matches) != 4 {
		t.Fatalf("matches = %v", matches)
	}
}

func TestParallelTXMacro(t *testing.T) {
	directives := []string{
		`SecAction "id:9830,phase:1,pass,nolog,setvar:tx.needle=attack"`,
		`SecRule ARGS:q "@within %{tx.needle}" "id:9831,phase:1,pass,log"`,
		`SecRule ARGS:q "@within %{tx.needle}" "id:9832,phase:1,pass,log"`,
		`SecRule ARGS:q "@within %{tx.needle}" "id:9833,phase:1,pass,log"`,
		`SecRule ARGS:q "@within %{tx.needle}" "id:9834,phase:1,deny,status:403,log"`,
	}
	status, matches := observeMatches(t, directives, 8, "/?q=attack", false)
	if status != http.StatusForbidden {
		t.Fatalf("status = %d", status)
	}
	if len(matches) != 4 {
		t.Fatalf("matches = %v", matches)
	}
}

func TestParallelMatchHookDisablesParallelism(t *testing.T) {
	var hookCalls atomic.Int32
	instance, err := New(Options{
		Directives:      parallelRules(),
		ParallelWorkers: 8,
		Logger:          log.New(log.Options{Writer: io.Discard, Level: log.ErrorLevel}),
		Hooks: []Hook{HookFunc{
			HookName:   "match-hook",
			HookPoints: []HookPoint{HookRuleMatch},
			Fn: func(ctx *HookContext) error {
				hookCalls.Add(1)
				if ctx.Match != nil && ctx.Match.RuleID == 9803 {
					ctx.Deny(http.StatusTeapot, "hook override")
				}
				return nil
			},
		}},
	})
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	defer func() { _ = instance.Close() }()
	response := serveTest(t, instance, httptestNewRequest("/abcd"))
	if response.Code != http.StatusTeapot {
		t.Fatalf("status = %d", response.Code)
	}
	if hookCalls.Load() != 3 {
		t.Fatalf("hook calls = %d, want 3 (stop at interrupting match)", hookCalls.Load())
	}
}

func TestParallelConcurrentRequests(t *testing.T) {
	instance, err := New(Options{
		Directives:      parallelRules(),
		ParallelWorkers: 8,
		Logger:          log.New(log.Options{Writer: io.Discard, Level: log.ErrorLevel}),
	})
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	defer func() { _ = instance.Close() }()
	handler := instance.HTTPMiddleware(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	var wait sync.WaitGroup
	for index := 0; index < 32; index++ {
		wait.Add(1)
		go func() {
			defer wait.Done()
			recorder := httptest.NewRecorder()
			handler.ServeHTTP(recorder, httptest.NewRequest(http.MethodGet, "/abcd", nil))
			if recorder.Code != http.StatusForbidden {
				t.Errorf("status = %d", recorder.Code)
			}
		}()
	}
	wait.Wait()
}

// TestParallelIndependentCapture verifies capture/setvar actions of side-effecting rules are
// committed in source order after concurrent evaluation. | TestParallelIndependentCapture 验证有副作用
// 规则在并发求值后仍按源码顺序提交捕获与 setvar。
func TestParallelIndependentCapture(t *testing.T) {
	directives := []string{
		`SecRule ARGS:q "@contains never-a" "id:9840,phase:2,pass,nolog"`,
		`SecRule ARGS:q "@contains never-b" "id:9841,phase:2,pass,nolog"`,
		`SecRule ARGS:q "@contains never-c" "id:9842,phase:2,pass,nolog"`,
		`SecRule ARGS:q "@rx (attack)" "id:9843,phase:2,pass,capture,nolog,setvar:tx.captured=%{TX.1}"`,
		`SecRule TX:captured "@streq attack" "id:9844,phase:2,deny,status:403,log"`,
	}
	instance, err := New(Options{
		Directives:      directives,
		ParallelWorkers: 8,
		Logger:          log.New(log.Options{Writer: io.Discard, Level: log.ErrorLevel}),
	})
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	defer func() { _ = instance.Close() }()
	response := serveTest(t, instance, httptestNewRequest("/?q=attack"))
	if response.Code != http.StatusForbidden {
		t.Fatalf("status = %d", response.Code)
	}
}

// TestParallelIndependentSetVarOrder verifies setvar actions are applied in source order. |
// TestParallelIndependentSetVarOrder 验证 setvar 动作按源码顺序应用。
func TestParallelIndependentSetVarOrder(t *testing.T) {
	directives := []string{
		`SecRule ARGS:q "@contains x" "id:9850,phase:2,pass,nolog,setvar:tx.order=1"`,
		`SecRule ARGS:q "@contains x" "id:9851,phase:2,pass,nolog,setvar:tx.order=2"`,
		`SecRule ARGS:q "@contains x" "id:9852,phase:2,pass,nolog,setvar:tx.order=3"`,
		`SecRule ARGS:q "@contains x" "id:9853,phase:2,pass,nolog,setvar:tx.order=4"`,
		`SecRule TX:order "@eq 4" "id:9854,phase:2,deny,status:403,log"`,
	}
	instance, err := New(Options{
		Directives:      directives,
		ParallelWorkers: 8,
		Logger:          log.New(log.Options{Writer: io.Discard, Level: log.ErrorLevel}),
	})
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	defer func() { _ = instance.Close() }()
	response := serveTest(t, instance, httptestNewRequest("/?q=x"))
	if response.Code != http.StatusForbidden {
		t.Fatalf("status = %d", response.Code)
	}
}
