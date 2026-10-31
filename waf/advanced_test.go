package waf

import (
	"context"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"
)

func TestCtlRuleRemoveById(t *testing.T) {
	instance := newTestWAF(t, []string{
		`SecRule REQUEST_URI "@contains disarm" "id:9600,phase:1,pass,nolog,ctl:ruleRemoveById=9601"`,
		`SecRule REQUEST_URI "@contains disarm" "id:9601,phase:1,deny,status:403"`,
	}, nil)
	if response := serveTest(t, instance, httptestNewRequest("/disarm")); response.Code != 200 {
		t.Fatalf("status = %d, want 200", response.Code)
	}
}

func TestCtlRuleRemoveTargetById(t *testing.T) {
	instance := newTestWAF(t, []string{
		`SecRule REQUEST_URI "@contains disarm" "id:9602,phase:1,pass,nolog,ctl:ruleRemoveTargetById=9603;ARGS:q"`,
		`SecRule ARGS:q "@contains attack" "id:9603,phase:2,deny,status:403"`,
	}, nil)
	if response := serveTest(t, instance, httptestNewRequest("/disarm?q=attack")); response.Code != 200 {
		t.Fatalf("status = %d, want 200", response.Code)
	}
}

func TestCtlRequestBodyProcessor(t *testing.T) {
	instance := newTestWAF(t, []string{
		`SecRule REQUEST_URI "@contains json" "id:9604,phase:1,pass,nolog,ctl:requestBodyProcessor=JSON"`,
		`SecRule ARGS_POST:user "@contains admin" "id:9605,phase:2,deny,status:403"`,
	}, nil)
	request := httptest.NewRequest(http.MethodPost, "/json", strings.NewReader(`{"user":"admin"}`))
	request.Header.Set("Content-Type", "text/plain")
	response := serveTest(t, instance, request)
	if response.Code != http.StatusForbidden {
		t.Fatalf("status = %d, want 403", response.Code)
	}
}

func TestCtlRuleEngineDetectionOnly(t *testing.T) {
	instance := newTestWAF(t, []string{
		`SecRule REQUEST_URI "@contains detect" "id:9606,phase:1,pass,nolog,ctl:ruleEngine=DetectionOnly"`,
		`SecRule REQUEST_URI "@contains detect" "id:9607,phase:1,deny,status:403"`,
	}, nil)
	response := serveTest(t, instance, httptestNewRequest("/detect"))
	if response.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200", response.Code)
	}
	if stats := instance.Stats(); stats.Detected != 1 || stats.Blocked != 0 {
		t.Fatalf("stats = %+v", stats)
	}
}

func TestSkipAction(t *testing.T) {
	instance := newTestWAF(t, []string{
		`SecRule REQUEST_URI "@contains skip" "id:9608,phase:1,pass,nolog,skip:1"`,
		`SecRule REQUEST_URI "@contains skip" "id:9609,phase:1,deny,status:403"`,
	}, nil)
	if response := serveTest(t, instance, httptestNewRequest("/skip")); response.Code != 200 {
		t.Fatalf("status = %d, want 200", response.Code)
	}
}

func TestCaptureMacro(t *testing.T) {
	instance := newTestWAF(t, []string{
		`SecRule ARGS:q "@rx ^user=(\w+)$" "id:9610,phase:1,capture,pass,nolog,setvar:tx.captured=%{tx.1}"`,
		`SecRule TX:captured "@contains admin" "id:9611,phase:1,deny,status:403"`,
	}, nil)
	if response := serveTest(t, instance, httptestNewRequest("/?q=user=admin")); response.Code != 403 {
		t.Fatalf("status = %d, want 403", response.Code)
	}
}

func TestInspectRequestBodyFalse(t *testing.T) {
	instance := newTestWAF(t, []string{
		`SecRule ARGS_POST:payload "@contains attack" "id:9612,phase:2,deny,status:403"`,
	}, func(options *Options) {
		options.InspectRequestBody = func(*http.Request) bool { return false }
	})
	payload := "payload=attack"
	recorder := httptest.NewRecorder()
	handler := instance.HTTPMiddleware(http.HandlerFunc(func(rw http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(r.Body)
		if string(body) != payload {
			t.Errorf("body = %q", body)
		}
		rw.WriteHeader(http.StatusOK)
	}))
	request := httptest.NewRequest(http.MethodPost, "/", strings.NewReader(payload))
	request.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	handler.ServeHTTP(recorder, request)
	if recorder.Code != http.StatusOK {
		t.Fatalf("status = %d", recorder.Code)
	}
}

func TestInspectResponseBodyFalse(t *testing.T) {
	instance := newTestWAF(t, []string{
		`SecRule RESPONSE_BODY "@contains secret" "id:9613,phase:4,deny,status:403"`,
	}, func(options *Options) {
		options.ResponseBodyAccess = true
		options.InspectResponseBody = func(*http.Request) bool { return false }
	})
	recorder := httptest.NewRecorder()
	handler := instance.HTTPMiddleware(http.HandlerFunc(func(rw http.ResponseWriter, r *http.Request) {
		rw.Header().Set("Content-Type", "text/plain")
		_, _ = io.WriteString(rw, "secret")
	}))
	handler.ServeHTTP(recorder, httptest.NewRequest(http.MethodGet, "/", nil))
	if recorder.Code != http.StatusOK {
		t.Fatalf("status = %d", recorder.Code)
	}
}

func TestTrustedProxyClientIP(t *testing.T) {
	rule := `SecRule REMOTE_ADDR "@ipMatch 203.0.113.5" "id:9614,phase:1,deny,status:403"`
	instance := newTestWAF(t, []string{rule}, func(options *Options) {
		options.TrustedProxies = []string{"10.0.0.0/8"}
	})
	request := httptest.NewRequest(http.MethodGet, "/", nil)
	request.RemoteAddr = "10.1.2.3:1234"
	request.Header.Set("X-Forwarded-For", "203.0.113.5, 10.2.2.2")
	if response := serveTest(t, instance, request); response.Code != 403 {
		t.Fatalf("trusted proxy status = %d", response.Code)
	}
	untrusted := newTestWAF(t, []string{rule}, nil)
	request = httptest.NewRequest(http.MethodGet, "/", nil)
	request.RemoteAddr = "10.1.2.3:1234"
	request.Header.Set("X-Forwarded-For", "203.0.113.5")
	if response := serveTest(t, untrusted, request); response.Code != 200 {
		t.Fatalf("untrusted status = %d", response.Code)
	}
}

func TestClientIPOverride(t *testing.T) {
	instance := newTestWAF(t, []string{
		`SecRule REMOTE_ADDR "@ipMatch 198.51.100.9" "id:9615,phase:1,deny,status:403"`,
	}, func(options *Options) {
		options.ClientIP = func(*http.Request) string { return "198.51.100.9" }
	})
	if response := serveTest(t, instance, httptestNewRequest("/")); response.Code != 403 {
		t.Fatalf("status = %d", response.Code)
	}
}

func TestArgumentSeparator(t *testing.T) {
	instance := newTestWAF(t, []string{
		`SecArgumentSeparator ;`,
		`SecRule ARGS:b "@contains attack" "id:9616,phase:1,deny,status:403"`,
	}, nil)
	if response := serveTest(t, instance, httptestNewRequest("/?a=1;b=attack")); response.Code != 403 {
		t.Fatalf("status = %d, want 403", response.Code)
	}
}

func TestReloadWithOptions(t *testing.T) {
	instance := newTestWAF(t, []string{
		`SecRule REQUEST_URI "@contains old" "id:9617,phase:1,deny,status:403"`,
	}, nil)
	err := instance.ReloadWith(Options{
		Directives: []string{
			`SecRule REQUEST_URI "@contains new" "id:9618,phase:1,deny,status:403"`,
		},
	})
	if err != nil {
		t.Fatalf("ReloadWith: %v", err)
	}
	if response := serveTest(t, instance, httptestNewRequest("/old")); response.Code != 200 {
		t.Fatalf("old status = %d", response.Code)
	}
	if response := serveTest(t, instance, httptestNewRequest("/new")); response.Code != 403 {
		t.Fatalf("new status = %d", response.Code)
	}
}

func TestShutdownWaitsForInflight(t *testing.T) {
	instance := newTestWAF(t, []string{
		`SecRule REQUEST_URI "@contains x" "id:9619,phase:1,pass,nolog"`,
	}, nil)
	entered := make(chan struct{})
	release := make(chan struct{})
	done := make(chan struct{})
	go func() {
		defer close(done)
		recorder := httptest.NewRecorder()
		instance.HTTPMiddleware(http.HandlerFunc(func(rw http.ResponseWriter, r *http.Request) {
			close(entered)
			<-release
			rw.WriteHeader(http.StatusOK)
		})).ServeHTTP(recorder, httptest.NewRequest(http.MethodGet, "/x", nil))
	}()
	<-entered
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Millisecond)
	defer cancel()
	err := instance.Shutdown(ctx)
	if !errors.Is(err, ErrShutdownTimeout) {
		t.Fatalf("Shutdown error = %v", err)
	}
	close(release)
	<-done
	_ = instance.Close()
}

func TestConnectSkipsResponsePhases(t *testing.T) {
	instance := newTestWAF(t, []string{
		`SecRule RESPONSE_HEADERS:Content-Type "@contains text/plain" "id:9620,phase:3,deny,status:403"`,
	}, nil)
	recorder := httptest.NewRecorder()
	called := false
	handler := instance.HTTPMiddleware(http.HandlerFunc(func(rw http.ResponseWriter, r *http.Request) {
		called = true
		rw.Header().Set("Content-Type", "text/plain")
		rw.WriteHeader(http.StatusOK)
	}))
	handler.ServeHTTP(recorder, httptest.NewRequest(http.MethodConnect, "/", nil))
	if !called {
		t.Fatal("CONNECT handler not called")
	}
	if recorder.Code != http.StatusOK {
		t.Fatalf("status = %d", recorder.Code)
	}
}

func TestModeOffBypasses(t *testing.T) {
	instance := newTestWAF(t, []string{
		`SecRule REQUEST_URI "@contains blocked" "id:9621,phase:1,deny,status:403"`,
	}, func(options *Options) { options.Mode = ModeOff })
	if response := serveTest(t, instance, httptestNewRequest("/blocked")); response.Code != 200 {
		t.Fatalf("status = %d", response.Code)
	}
	if stats := instance.Stats(); stats.Bypassed != 1 || stats.Inspected != 0 {
		t.Fatalf("stats = %+v", stats)
	}
}

func TestDisableRequestBodyAccess(t *testing.T) {
	instance := newTestWAF(t, []string{
		`SecRule ARGS_POST:payload "@contains attack" "id:9622,phase:2,deny,status:403"`,
	}, func(options *Options) { options.DisableRequestBodyAccess = true })
	request := httptest.NewRequest(http.MethodPost, "/", strings.NewReader("payload=attack"))
	request.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	if response := serveTest(t, instance, request); response.Code != 200 {
		t.Fatalf("status = %d", response.Code)
	}
}

func TestOptionsNormalizeErrors(t *testing.T) {
	if _, err := New(Options{Mode: Mode(99), Directives: []string{`SecAction "id:1,phase:1,pass"`}}); !errors.Is(err, ErrInvalidMode) {
		t.Fatalf("mode error = %v", err)
	}
	if _, err := New(Options{RequestBodyLimit: -1, Directives: []string{`SecAction "id:1,phase:1,pass"`}}); !errors.Is(err, ErrInvalidLimit) {
		t.Fatalf("limit error = %v", err)
	}
	if _, err := New(Options{TrustedProxies: []string{"nope"}, Directives: []string{`SecAction "id:1,phase:1,pass"`}}); !errors.Is(err, ErrInvalidOption) {
		t.Fatalf("proxy error = %v", err)
	}
}

func TestConcurrentHookRegistration(t *testing.T) {
	instance := newTestWAF(t, []string{
		`SecRule REQUEST_URI "@contains x" "id:9623,phase:1,pass,nolog"`,
	}, nil)
	var wait sync.WaitGroup
	for index := 0; index < 32; index++ {
		wait.Add(1)
		go func(index int) {
			defer wait.Done()
			_ = instance.AddHook(HookFunc{
				HookName: "hook-" + string(rune('a'+index%26)) + string(rune('a'+index/26)),
				Fn:       func(*HookContext) error { return nil },
			})
		}(index)
	}
	wait.Wait()
	serveTest(t, instance, httptestNewRequest("/x"))
}
