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

func TestHTTPProviderSend(t *testing.T) {
	t.Parallel()
	const mobile = "+8613800138000"
	var sawSignature atomic.Bool
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			t.Errorf("method = %s, want POST", r.Method)
		}
		if r.Header.Get("X-API-Key") != "test-key" {
			t.Error("missing static header")
		}
		if r.Header.Get("X-Signature") == "signed" {
			sawSignature.Store(true)
		}
		body, _ := io.ReadAll(r.Body)
		var payload struct {
			Mobile     string            `json:"mobile"`
			TemplateID string            `json:"templateId"`
			Params     map[string]string `json:"params"`
		}
		if err := json.Unmarshal(body, &payload); err != nil {
			t.Errorf("decode request: %v", err)
		}
		if payload.Mobile != mobile || payload.TemplateID != "template-1" || payload.Params["code"] != "123456" {
			t.Errorf("payload = %+v", payload)
		}
		w.Header().Set("Content-Type", "application/json")
		io.WriteString(w, `{"requestId":"req-9"}`)
	}))
	defer srv.Close()

	provider, err := NewHTTPProvider(HTTPProviderConfig{
		URL:     srv.URL,
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
		t.Fatalf("NewHTTPProvider returned error: %v", err)
	}
	requestID, err := provider.Send(context.TODO(), mobile, "template-1", map[string]string{"code": "123456"})
	if err != nil {
		t.Fatalf("Send returned error: %v", err)
	}
	if requestID != "req-9" {
		t.Fatalf("request ID = %q, want req-9", requestID)
	}
	if !sawSignature.Load() {
		t.Fatal("sign hook did not run")
	}
}

func TestHTTPProviderMessageIDFallback(t *testing.T) {
	t.Parallel()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		io.WriteString(w, `{"messageId":"msg-7"}`)
	}))
	defer srv.Close()

	provider, err := NewHTTPProvider(HTTPProviderConfig{URL: srv.URL})
	if err != nil {
		t.Fatalf("NewHTTPProvider returned error: %v", err)
	}
	requestID, err := provider.Send(context.Background(), "+8613800138000", "t", nil)
	if err != nil {
		t.Fatalf("Send returned error: %v", err)
	}
	if requestID != "msg-7" {
		t.Fatalf("request ID = %q, want msg-7", requestID)
	}
}

func TestHTTPProviderHooks(t *testing.T) {
	t.Parallel()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(r.Body)
		if string(body) != "custom-body" {
			t.Errorf("body = %q, want custom-body", body)
		}
		io.WriteString(w, `{}`)
	}))
	defer srv.Close()

	provider, err := NewHTTPProvider(HTTPProviderConfig{
		URL: srv.URL,
		BuildRequest: func(ctx context.Context, mobile, templateID string, params map[string]string) ([]byte, error) {
			return []byte("custom-body"), nil
		},
		Decode: func(ctx context.Context, resp *http.Response, body []byte) (string, error) {
			return "hook-id", nil
		},
	})
	if err != nil {
		t.Fatalf("NewHTTPProvider returned error: %v", err)
	}
	requestID, err := provider.Send(context.Background(), "+8613800138000", "t", nil)
	if err != nil {
		t.Fatalf("Send returned error: %v", err)
	}
	if requestID != "hook-id" {
		t.Fatalf("request ID = %q, want hook-id", requestID)
	}
}

func TestHTTPProviderFailures(t *testing.T) {
	t.Parallel()
	if _, err := NewHTTPProvider(HTTPProviderConfig{}); !errors.Is(err, ErrInvalidConfig) {
		t.Fatalf("empty URL error = %v, want ErrInvalidConfig", err)
	}

	const mobile = "+8613800138000"
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusForbidden)
		io.WriteString(w, `{"error":"`+mobile+`"}`)
	}))
	defer srv.Close()

	provider, err := NewHTTPProvider(HTTPProviderConfig{URL: srv.URL})
	if err != nil {
		t.Fatalf("NewHTTPProvider returned error: %v", err)
	}
	_, err = provider.Send(context.Background(), mobile, "t", nil)
	if err == nil {
		t.Fatal("Send unexpectedly succeeded")
	}
	if !errors.Is(err, ErrSMSSend) {
		t.Fatalf("error = %v, want ErrSMSSend", err)
	}
	if strings.Contains(err.Error(), mobile) {
		t.Fatalf("error %q leaks the mobile number", err)
	}

	var nilProvider *HTTPProvider
	if _, err := nilProvider.Send(context.Background(), mobile, "t", nil); !errors.Is(err, ErrInvalidConfig) {
		t.Fatalf("nil provider error = %v, want ErrInvalidConfig", err)
	}
}

func TestHTTPProviderSignAndDecodeFailures(t *testing.T) {
	t.Parallel()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		io.WriteString(w, `not json`)
	}))
	defer srv.Close()

	boom := errors.New("sign failure")
	provider, err := NewHTTPProvider(HTTPProviderConfig{
		URL: srv.URL,
		Sign: func(ctx context.Context, req *http.Request, body []byte) error {
			return boom
		},
	})
	if err != nil {
		t.Fatalf("NewHTTPProvider returned error: %v", err)
	}
	if _, err := provider.Send(context.Background(), "+8613800138000", "t", nil); !errors.Is(err, boom) || !errors.Is(err, ErrSMSSend) {
		t.Fatalf("sign error = %v, want sign failure and ErrSMSSend", err)
	}

	decoding, err := NewHTTPProvider(HTTPProviderConfig{URL: srv.URL})
	if err != nil {
		t.Fatalf("NewHTTPProvider returned error: %v", err)
	}
	if _, err := decoding.Send(context.Background(), "+8613800138000", "t", nil); !errors.Is(err, ErrProviderResponse) {
		t.Fatalf("decode error = %v, want ErrProviderResponse", err)
	}
}
