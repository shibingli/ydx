package waf

import (
	"errors"
	"io"
	"net/http"
	"strings"
	"sync/atomic"
	"testing"
)

const ruleArgCount = `SecRule &ARGS_POST "@gt 1" "id:1101,phase:2,deny,status:403,msg:'too many arguments'"`

func TestArgumentsLimitBoundsParsedArguments(t *testing.T) {
	headers := map[string]string{"Content-Type": "application/x-www-form-urlencoded"}
	limited := newWAF(t, Options{Directives: []string{ruleArgCount}, ArgumentsLimit: 1})
	if rec := doNative(limited, okHandler(), http.MethodPost, "/safe", "a=1&b=2", headers); rec.Code != http.StatusOK {
		t.Fatalf("限参请求状态 = %d，期望 200；正文 %q", rec.Code, rec.Body.String())
	}

	unlimited := newWAF(t, Options{Directives: []string{ruleArgCount}})
	if rec := doNative(unlimited, okHandler(), http.MethodPost, "/safe", "a=1&b=2", headers); rec.Code != http.StatusForbidden {
		t.Fatalf("未限参请求状态 = %d，期望 403", rec.Code)
	}

	if _, err := New(Options{Directives: []string{ruleURI}, ArgumentsLimit: -1}); !errors.Is(err, ErrInvalidLimit) {
		t.Fatalf("负数参数上限错误 = %v，期望 ErrInvalidLimit", err)
	}
}

func TestInspectRequestBodyPerRoute(t *testing.T) {
	w := newWAF(t, Options{
		Directives: []string{ruleReqBody},
		InspectRequestBody: func(r *http.Request) bool {
			return r.URL.Path != "/upload"
		},
	})
	headers := map[string]string{"Content-Type": "application/x-www-form-urlencoded"}
	rec := doNative(w, echoHandler(), http.MethodPost, "/upload", "x=attack-body", headers)
	if rec.Code != http.StatusOK || rec.Body.String() != "x=attack-body" {
		t.Fatalf("跳过正文检测: code=%d body=%q，期望原始正文", rec.Code, rec.Body.String())
	}
	if rec := doNative(w, okHandler(), http.MethodPost, "/check", "x=attack-body", headers); rec.Code != http.StatusForbidden {
		t.Fatalf("正文检测状态 = %d，期望 403", rec.Code)
	}
}

func TestInspectResponseBodyPerRoute(t *testing.T) {
	w := newWAF(t, Options{
		Directives:         []string{ruleResBody},
		ResponseBodyAccess: true,
		InspectResponseBody: func(r *http.Request) bool {
			return r.URL.Path != "/download"
		},
	})
	handler := http.HandlerFunc(func(rw http.ResponseWriter, _ *http.Request) {
		rw.Header().Set("Content-Type", "text/plain")
		_, _ = io.WriteString(rw, "response-secret")
	})
	rec := doNative(w, handler, http.MethodGet, "/download", "", nil)
	if rec.Code != http.StatusOK || rec.Body.String() != "response-secret" {
		t.Fatalf("跳过响应正文检测: code=%d body=%q", rec.Code, rec.Body.String())
	}
	if rec := doNative(w, handler, http.MethodGet, "/page", "", nil); rec.Code != http.StatusForbidden {
		t.Fatalf("响应正文检测状态 = %d，期望 403", rec.Code)
	}
}

func TestBodyCallbacksSkippedWhenNoBodyRules(t *testing.T) {
	var requestCalled, responseCalled atomic.Bool
	w := newWAF(t, Options{
		Directives: []string{ruleURI},
		InspectRequestBody: func(*http.Request) bool {
			requestCalled.Store(true)
			return false
		},
		InspectResponseBody: func(*http.Request) bool {
			responseCalled.Store(true)
			return false
		},
	})
	rec := doNative(w, okHandler(), http.MethodGet, "/safe", "", nil)
	if rec.Code != http.StatusOK {
		t.Fatalf("状态 = %d，期望 200", rec.Code)
	}
	if requestCalled.Load() {
		t.Fatal("没有正文规则时不应调用 InspectRequestBody")
	}
	if responseCalled.Load() {
		t.Fatal("没有响应正文规则时不应调用 InspectResponseBody")
	}
}

func TestInspectRequestBodyKeepsHeaderRules(t *testing.T) {
	var handlerReached atomic.Bool
	w := newWAF(t, Options{
		Directives:         []string{ruleUA, ruleReqBody},
		InspectRequestBody: func(*http.Request) bool { return false },
	})
	handler := http.HandlerFunc(func(rw http.ResponseWriter, _ *http.Request) {
		handlerReached.Store(true)
		_, _ = io.WriteString(rw, "ok")
	})
	rec := doNative(w, handler, http.MethodPost, "/safe", "x=attack-body", map[string]string{
		"Content-Type": "application/x-www-form-urlencoded",
		"User-Agent":   "evil-bot/1.0",
	})
	if rec.Code != http.StatusForbidden {
		t.Fatalf("请求头规则状态 = %d，期望 403", rec.Code)
	}
	if handlerReached.Load() {
		t.Fatal("请求头命中后不应进入处理器")
	}
	if strings.Contains(rec.Body.String(), "attack-body") {
		t.Fatalf("响应泄漏了正文: %q", rec.Body.String())
	}
}
