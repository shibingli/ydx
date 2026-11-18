package waf

import (
	"errors"
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
