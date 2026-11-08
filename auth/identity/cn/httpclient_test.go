package cn

import (
	"context"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
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
