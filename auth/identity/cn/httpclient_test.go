package cn

import (
	"context"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"sync/atomic"
	"testing"
	"time"
)

func TestHTTPClientOrDefaultRefusesRedirects(t *testing.T) {
	var targetHits int32
	target := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		atomic.AddInt32(&targetHits, 1)
		w.WriteHeader(http.StatusOK)
	}))
	defer target.Close()
	redirect := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, target.URL, http.StatusFound)
	}))
	defer redirect.Close()

	client := httpClientOrDefault(nil, time.Second)
	resp, err := client.Get(redirect.URL)
	if err != nil {
		t.Fatalf("get: %v", err)
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != http.StatusFound {
		t.Fatalf("status = %d, want the unfollowed 302", resp.StatusCode)
	}
	if got := atomic.LoadInt32(&targetHits); got != 0 {
		t.Fatalf("redirect target received %d requests", got)
	}
}

func TestHTTPProviderFollowsSameOriginRedirect(t *testing.T) {
	var targetHits int32
	var sawKey atomic.Bool
	mux := http.NewServeMux()
	mux.HandleFunc("/start", func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, "/target", http.StatusTemporaryRedirect)
	})
	mux.HandleFunc("/target", func(w http.ResponseWriter, r *http.Request) {
		atomic.AddInt32(&targetHits, 1)
		if r.Header.Get("X-API-Key") == "test-key" {
			sawKey.Store(true)
		}
		_, _ = io.WriteString(w, `{"requestId":"req-same-origin"}`)
	})
	srv := httptest.NewServer(mux)
	defer srv.Close()

	provider, err := NewHTTPProvider(HTTPProviderConfig{
		URL:     srv.URL + "/start",
		Headers: map[string]string{"X-API-Key": "test-key"},
	})
	if err != nil {
		t.Fatalf("NewHTTPProvider: %v", err)
	}
	requestID, err := provider.Send(context.Background(), "+8613800138000", "template", nil)
	if err != nil {
		t.Fatalf("Send: %v", err)
	}
	if requestID != "req-same-origin" {
		t.Fatalf("request ID = %q", requestID)
	}
	if atomic.LoadInt32(&targetHits) != 1 || !sawKey.Load() {
		t.Fatalf("target hits = %d, key seen = %v", targetHits, sawKey.Load())
	}
}

func TestSameOriginRedirectPolicy(t *testing.T) {
	parse := func(raw string) *http.Request {
		t.Helper()
		u, err := url.Parse(raw)
		if err != nil {
			t.Fatalf("parse %q: %v", raw, err)
		}
		return &http.Request{URL: u}
	}
	viaFor := func(raw string) []*http.Request {
		t.Helper()
		original := parse(raw)
		return []*http.Request{original, original}
	}
	cases := []struct {
		name    string
		next    string
		via     []*http.Request
		allowed bool
	}{
		{"same origin", "https://example.com/b", viaFor("https://example.com/a"), true},
		{"same effective port", "https://example.com/b", viaFor("https://example.com:443/a"), true},
		{"port change", "http://example.com:9090/b", viaFor("http://example.com:8080/a"), false},
		{"cross host", "https://other.example.com/b", viaFor("https://example.com/a"), false},
		{"https downgrade", "http://example.com/b", viaFor("https://example.com/a"), false},
		{"default upgrade", "https://example.com/b", viaFor("http://example.com/a"), true},
		{"explicit default upgrade", "https://example.com:443/b", viaFor("http://example.com:80/a"), true},
		{"same-port upgrade", "https://example.com:8443/b", viaFor("http://example.com:8443/a"), true},
		{"unrelated upgrade port", "https://example.com:9443/b", viaFor("http://example.com:8080/a"), false},
		{"invalid scheme", "ftp://example.com/b", viaFor("http://example.com/a"), false},
		{"missing via", "https://example.com/b", nil, false},
	}
	for _, tc := range cases {
		if got := sameOriginRedirectPolicy(parse(tc.next), tc.via) == nil; got != tc.allowed {
			t.Fatalf("%s: allowed = %v, want %v", tc.name, got, tc.allowed)
		}
	}
	original := parse("https://example.com/a")
	via := make([]*http.Request, maxProviderRedirects)
	for i := range via {
		via[i] = original
	}
	if sameOriginRedirectPolicy(parse("https://example.com/b"), via) == nil {
		t.Fatal("redirect chain beyond the limit was allowed")
	}
}

func TestHTTPVerifierDoesNotFollowProviderRedirect(t *testing.T) {
	var targetHits int32
	var leakedHeaders int32
	target := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		atomic.AddInt32(&targetHits, 1)
		if r.Header.Get("X-API-Key") != "" {
			atomic.AddInt32(&leakedHeaders, 1)
		}
		_, _ = io.WriteString(w, `{"verified":true}`)
	}))
	defer target.Close()
	redirect := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Location", target.URL)
		w.WriteHeader(http.StatusTemporaryRedirect)
	}))
	defer redirect.Close()

	verifier, err := NewHTTPVerifier(HTTPVerifierConfig{
		URL:     redirect.URL,
		Headers: map[string]string{"X-API-Key": "test-api-key"},
	})
	if err != nil {
		t.Fatalf("NewHTTPVerifier: %v", err)
	}
	_, err = verifier.Verify(context.Background(), RealNameRequest{
		Name:     "张三",
		IDNumber: "11010519491231002X",
	})
	if !errors.Is(err, ErrProviderResponse) {
		t.Fatalf("redirecting provider = %v, want ErrProviderResponse", err)
	}
	if got := atomic.LoadInt32(&targetHits); got != 0 {
		t.Fatalf("redirect target received %d requests", got)
	}
	if got := atomic.LoadInt32(&leakedHeaders); got != 0 {
		t.Fatalf("redirect target received the API key header %d times", got)
	}
}
