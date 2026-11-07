package cn

import (
	"context"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"

	"github.com/shibingli/ydx/json"
)

func TestRealNameFunc(t *testing.T) {
	t.Parallel()
	want := &RealNameResult{Verified: true, Provider: "func", RequestID: "r1"}
	fn := RealNameFunc(func(ctx context.Context, req RealNameRequest) (*RealNameResult, error) {
		if req.Name != "张三" || req.IDNumber != "11010519491231002X" {
			t.Fatalf("unexpected request: %+v", req)
		}
		return want, nil
	})
	got, err := fn.Verify(context.Background(), RealNameRequest{Name: "张三", IDNumber: "11010519491231002X"})
	if err != nil {
		t.Fatalf("Verify returned error: %v", err)
	}
	if got != want {
		t.Fatalf("Verify result = %+v, want %+v", got, want)
	}

	var nilFunc RealNameFunc
	if _, err := nilFunc.Verify(context.Background(), RealNameRequest{}); !errors.Is(err, ErrInvalidConfig) {
		t.Fatalf("nil RealNameFunc error = %v, want ErrInvalidConfig", err)
	}
}

func TestStaticVerifier(t *testing.T) {
	t.Parallel()
	verifier := StaticVerifier{Result: RealNameResult{Verified: true, RequestID: "static-1"}}
	result, err := verifier.Verify(context.Background(), RealNameRequest{Name: "张三", IDNumber: "x"})
	if err != nil {
		t.Fatalf("Verify returned error: %v", err)
	}
	if !result.Verified || result.Provider != "static" || result.RequestID != "static-1" {
		t.Fatalf("unexpected result: %+v", result)
	}

	boom := errors.New("boom")
	failing := StaticVerifier{Err: boom}
	if _, err := failing.Verify(context.Background(), RealNameRequest{}); !errors.Is(err, boom) {
		t.Fatalf("Verify error = %v, want boom", err)
	}
}

func TestHTTPVerifier(t *testing.T) {
	t.Parallel()
	const (
		name     = "张三"
		idNumber = "11010519491231002X"
		mobile   = "13800138000"
	)
	var sawSignature atomic.Bool
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			t.Errorf("method = %s, want POST", r.Method)
		}
		if r.URL.Path != "/verify" {
			t.Errorf("path = %s, want /verify", r.URL.Path)
		}
		if r.Header.Get("X-API-Key") != "test-key" {
			t.Errorf("missing static header")
		}
		if r.Header.Get("X-Signature") == "signed" {
			sawSignature.Store(true)
		}
		body, _ := io.ReadAll(r.Body)
		var payload struct {
			Name     string `json:"name"`
			IDNumber string `json:"idNumber"`
			Mobile   string `json:"mobile"`
		}
		if err := json.Unmarshal(body, &payload); err != nil {
			t.Errorf("decode request: %v", err)
		}
		if payload.Name != name || payload.IDNumber != idNumber || payload.Mobile != mobile {
			t.Errorf("payload = %+v", payload)
		}
		w.Header().Set("Content-Type", "application/json")
		io.WriteString(w, `{"verified":true,"requestId":"req-1","message":"ok","provider":"mock"}`)
	}))
	defer srv.Close()

	verifier, err := NewHTTPVerifier(HTTPVerifierConfig{
		URL:     srv.URL + "/verify",
		Headers: map[string]string{"X-API-Key": "test-key"},
		Sign: func(ctx context.Context, req *http.Request, body []byte) error {
			if len(body) == 0 {
				t.Error("sign hook received an empty body")
			}
			req.Header.Set("X-Signature", "signed")
			return nil
		},
	})
	if err != nil {
		t.Fatalf("NewHTTPVerifier returned error: %v", err)
	}
	result, err := verifier.Verify(context.Background(), RealNameRequest{Name: name, IDNumber: idNumber, Mobile: mobile})
	if err != nil {
		t.Fatalf("Verify returned error: %v", err)
	}
	if !result.Verified || result.Provider != "mock" || result.RequestID != "req-1" || result.Message != "ok" {
		t.Fatalf("unexpected result: %+v", result)
	}
	if !sawSignature.Load() {
		t.Fatal("sign hook did not run")
	}
}

func TestHTTPVerifierProviderFallback(t *testing.T) {
	t.Parallel()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		io.WriteString(w, `{"verified":false,"requestId":"req-2","message":"no match"}`)
	}))
	defer srv.Close()

	verifier, err := NewHTTPVerifier(HTTPVerifierConfig{URL: srv.URL, Provider: "fallback"})
	if err != nil {
		t.Fatalf("NewHTTPVerifier returned error: %v", err)
	}
	result, err := verifier.Verify(context.Background(), RealNameRequest{Name: "张三", IDNumber: "11010519491231002X"})
	if err != nil {
		t.Fatalf("Verify returned error: %v", err)
	}
	if result.Verified || result.Provider != "fallback" {
		t.Fatalf("unexpected result: %+v", result)
	}
}

func TestHTTPVerifierDecodeHook(t *testing.T) {
	t.Parallel()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		io.WriteString(w, `{"ok":true,"trace":"trace-9"}`)
	}))
	defer srv.Close()

	verifier, err := NewHTTPVerifier(HTTPVerifierConfig{
		URL: srv.URL,
		Decode: func(ctx context.Context, resp *http.Response, body []byte) (*RealNameResult, error) {
			var payload struct {
				OK    bool   `json:"ok"`
				Trace string `json:"trace"`
			}
			if err := json.Unmarshal(body, &payload); err != nil {
				return nil, err
			}
			return &RealNameResult{Verified: payload.OK, RequestID: payload.Trace}, nil
		},
	})
	if err != nil {
		t.Fatalf("NewHTTPVerifier returned error: %v", err)
	}
	result, err := verifier.Verify(context.Background(), RealNameRequest{Name: "张三", IDNumber: "11010519491231002X"})
	if err != nil {
		t.Fatalf("Verify returned error: %v", err)
	}
	if !result.Verified || result.RequestID != "trace-9" || result.Provider != "http" {
		t.Fatalf("unexpected result: %+v", result)
	}
}

func TestHTTPVerifierFailuresDoNotLeakPII(t *testing.T) {
	t.Parallel()
	const (
		name     = "张三"
		idNumber = "11010519491231002X"
		mobile   = "13800138000"
	)
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
		io.WriteString(w, `{"error":"`+idNumber+` `+mobile+`"}`)
	}))
	defer srv.Close()

	verifier, err := NewHTTPVerifier(HTTPVerifierConfig{URL: srv.URL})
	if err != nil {
		t.Fatalf("NewHTTPVerifier returned error: %v", err)
	}
	_, err = verifier.Verify(context.Background(), RealNameRequest{Name: name, IDNumber: idNumber, Mobile: mobile})
	if err == nil {
		t.Fatal("Verify unexpectedly succeeded")
	}
	if !errors.Is(err, ErrRealNameProvider) {
		t.Fatalf("error = %v, want ErrRealNameProvider", err)
	}
	for _, secret := range []string{name, idNumber, mobile} {
		if strings.Contains(err.Error(), secret) {
			t.Fatalf("error %q leaks %q", err, secret)
		}
	}
}

func TestHTTPVerifierSignFailure(t *testing.T) {
	t.Parallel()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		t.Error("server must not be called when signing fails")
	}))
	defer srv.Close()

	boom := errors.New("sign failure")
	verifier, err := NewHTTPVerifier(HTTPVerifierConfig{
		URL: srv.URL,
		Sign: func(ctx context.Context, req *http.Request, body []byte) error {
			return boom
		},
	})
	if err != nil {
		t.Fatalf("NewHTTPVerifier returned error: %v", err)
	}
	_, err = verifier.Verify(context.Background(), RealNameRequest{Name: "张三", IDNumber: "11010519491231002X"})
	if !errors.Is(err, boom) || !errors.Is(err, ErrRealNameProvider) {
		t.Fatalf("error = %v, want sign failure and ErrRealNameProvider", err)
	}
}

func TestHTTPVerifierConfigurationAndInput(t *testing.T) {
	t.Parallel()
	if _, err := NewHTTPVerifier(HTTPVerifierConfig{}); !errors.Is(err, ErrInvalidConfig) {
		t.Fatalf("empty URL error = %v, want ErrInvalidConfig", err)
	}
	verifier, err := NewHTTPVerifier(HTTPVerifierConfig{URL: "http://example.invalid"})
	if err != nil {
		t.Fatalf("NewHTTPVerifier returned error: %v", err)
	}
	if _, err := verifier.Verify(context.Background(), RealNameRequest{Name: "张三"}); !errors.Is(err, ErrInvalidRequest) {
		t.Fatalf("missing ID error = %v, want ErrInvalidRequest", err)
	}
	if _, err := verifier.Verify(context.Background(), RealNameRequest{IDNumber: "11010519491231002X"}); !errors.Is(err, ErrInvalidRequest) {
		t.Fatalf("missing name error = %v, want ErrInvalidRequest", err)
	}
}

func TestHTTPVerifierInvalidResponse(t *testing.T) {
	t.Parallel()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		io.WriteString(w, `not json`)
	}))
	defer srv.Close()

	verifier, err := NewHTTPVerifier(HTTPVerifierConfig{URL: srv.URL})
	if err != nil {
		t.Fatalf("NewHTTPVerifier returned error: %v", err)
	}
	_, err = verifier.Verify(context.Background(), RealNameRequest{Name: "张三", IDNumber: "11010519491231002X"})
	if !errors.Is(err, ErrProviderResponse) {
		t.Fatalf("error = %v, want ErrProviderResponse", err)
	}
}
