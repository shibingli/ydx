package waf

import (
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestEvaluateDenyAndAllow(t *testing.T) {
	w, err := New(Options{Directives: []string{
		`SecRule REQUEST_URI "@contains /admin" "id:1,phase:1,deny,status:403"`,
	}})
	if err != nil {
		t.Fatal(err)
	}
	defer w.Close()

	decision, err := w.Evaluate(httptest.NewRequest(http.MethodGet, "http://x/admin", nil))
	if err != nil {
		t.Fatal(err)
	}
	if !decision.Blocked || decision.Allowed || decision.Status != http.StatusForbidden {
		t.Fatalf("blocked decision %+v", decision)
	}
	if decision.RuleID != 1 {
		t.Fatalf("rule id %d", decision.RuleID)
	}

	decision, err = w.Evaluate(httptest.NewRequest(http.MethodGet, "http://x/public", nil))
	if err != nil {
		t.Fatal(err)
	}
	if decision.Blocked || !decision.Allowed {
		t.Fatalf("allowed decision %+v", decision)
	}
}

func TestEvaluateDetectionMode(t *testing.T) {
	w, err := New(Options{
		Mode: ModeDetection,
		Directives: []string{
			`SecRule REQUEST_URI "@contains /admin" "id:1,phase:1,deny,status:403"`,
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	defer w.Close()
	decision, err := w.Evaluate(httptest.NewRequest(http.MethodGet, "http://x/admin", nil))
	if err != nil {
		t.Fatal(err)
	}
	if decision.Blocked || !decision.Allowed || !decision.Detected {
		t.Fatalf("detection decision %+v", decision)
	}
}

func TestEvaluateExclude(t *testing.T) {
	w, err := New(Options{
		Exclude: func(*http.Request) bool { return true },
		Directives: []string{
			`SecRule REQUEST_URI "@contains /admin" "id:1,phase:1,deny,status:403"`,
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	defer w.Close()
	decision, err := w.Evaluate(httptest.NewRequest(http.MethodGet, "http://x/admin", nil))
	if err != nil || decision.Blocked || !decision.Allowed {
		t.Fatalf("excluded decision %+v err %v", decision, err)
	}
}

func TestEvaluateBodyLimit(t *testing.T) {
	w, err := New(Options{
		RequestBodyLimit:       4,
		RequestBodyLimitAction: LimitReject,
		Directives: []string{
			`SecRequestBodyAccess On`,
			`SecRule REQUEST_BODY "@contains secret" "id:2,phase:2,deny,status:403"`,
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	defer w.Close()
	decision, err := w.Evaluate(httptest.NewRequest(http.MethodPost, "http://x/", strings.NewReader("12345")))
	if !decision.Blocked || decision.Status != http.StatusRequestEntityTooLarge {
		t.Fatalf("body limit decision %+v", decision)
	}
	if !errors.Is(err, ErrRequestBodyTooLarge) {
		t.Fatalf("want ErrRequestBodyTooLarge, got %v", err)
	}
}

// failingBodyReader always fails, simulating a truncated or broken request body. |
// failingBodyReader 总是失败，模拟被截断或损坏的请求正文。
type failingBodyReader struct{}

func (failingBodyReader) Read([]byte) (int, error) { return 0, errors.New("body read failed") }

// TestEvaluateBodyReadErrorFailsClosed pins that a read failure is reflected in the Decision,
// not only in the returned error: callers that inspect only Allowed must not be left open. |
// TestEvaluateBodyReadErrorFailsClosed 固化读取失败必须反映在 Decision 中，而不仅是返回的 error：
// 只检查 Allowed 的调用方不能被放行。
func TestEvaluateBodyReadErrorFailsClosed(t *testing.T) {
	w, err := New(Options{Directives: []string{
		`SecRule REQUEST_BODY "@contains attack" "id:1,phase:2,deny,status:403"`,
	}})
	if err != nil {
		t.Fatal(err)
	}
	defer w.Close()

	req := httptest.NewRequest(http.MethodPost, "http://x/", nil)
	req.Body = io.NopCloser(failingBodyReader{})
	req.ContentLength = 16
	decision, evalErr := w.Evaluate(req)
	if evalErr == nil {
		t.Fatal("expected a body read error")
	}
	if decision.Allowed || !decision.Blocked || decision.Status != http.StatusBadRequest {
		t.Fatalf("decision = %+v, 期望 Allowed=false Blocked=true Status=400 | want fail-closed decision", decision)
	}
}
