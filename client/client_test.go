package client

import (
	"context"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"
)

func mustURL(raw string) *url.URL {
	u, err := url.Parse(raw)
	if err != nil {
		panic(err)
	}
	return u
}

func waitFor(t *testing.T, d time.Duration, fn func() bool) {
	t.Helper()
	deadline := time.Now().Add(d)
	for time.Now().Before(deadline) {
		if fn() {
			return
		}
		time.Sleep(5 * time.Millisecond)
	}
	t.Fatal("condition not met before timeout")
}

func mustRequest(t *testing.T, method, rawURL, body string) *http.Request {
	t.Helper()
	var reader io.Reader
	if body != "" {
		reader = strings.NewReader(body)
	}
	req, err := http.NewRequestWithContext(context.Background(), method, rawURL, reader)
	if err != nil {
		t.Fatalf("new request: %v", err)
	}
	return req
}

func TestNewDefaults(t *testing.T) {
	c, err := New()
	if err != nil {
		t.Fatal(err)
	}
	if c.HTTPClient() == nil || c.Transport() == nil {
		t.Fatal("nil client or transport")
	}
	if err := c.Close(); err != nil {
		t.Fatal(err)
	}
	if err := c.Close(); err != nil {
		t.Fatalf("second Close: %v", err)
	}
}

func TestDoPassthrough(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("X-Test", r.Method)
		w.WriteHeader(http.StatusCreated)
		_, _ = w.Write([]byte("ok"))
	}))
	defer srv.Close()

	c, err := New()
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()

	resp, err := c.Do(mustRequest(t, http.MethodPost, srv.URL+"/x", "body"))
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusCreated || resp.Header.Get("X-Test") != http.MethodPost {
		t.Fatalf("got %d %q", resp.StatusCode, resp.Header.Get("X-Test"))
	}
	body, _ := io.ReadAll(resp.Body)
	if string(body) != "ok" {
		t.Fatalf("body %q", body)
	}
}

func TestDoTimeout(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		time.Sleep(100 * time.Millisecond)
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()

	c, err := New(WithTimeout(10 * time.Millisecond))
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	if _, err := c.Do(mustRequest(t, http.MethodGet, srv.URL, "")); !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("want deadline exceeded, got %v", err)
	}
}

func TestDoRejectsRelativeURL(t *testing.T) {
	c, err := New()
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	req, _ := http.NewRequest(http.MethodGet, "/relative", nil)
	if _, err := c.Do(req); err != ErrRelativeURL {
		t.Fatalf("want ErrRelativeURL, got %v", err)
	}
}
