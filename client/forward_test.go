package client

import (
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

func TestForwardHandler(t *testing.T) {
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Connection") != "" {
			t.Error("hop-by-hop header leaked")
		}
		if r.Header.Get("X-Forwarded-For") == "" {
			t.Error("missing X-Forwarded-For")
		}
		if r.URL.Path != "/x" || r.URL.Query().Get("q") != "1" {
			t.Errorf("path %q query %q", r.URL.Path, r.URL.RawQuery)
		}
		w.Header().Set("X-Up", "1")
		w.Header().Set("Connection", "keep-alive")
		w.WriteHeader(http.StatusAccepted)
		_, _ = w.Write([]byte("proxied"))
	}))
	defer upstream.Close()

	c, err := New(WithHosts(upstream.URL), WithBaseURL(upstream.URL))
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodPost, "http://svc/x?q=1", strings.NewReader("body"))
	req.Header.Set("Connection", "keep-alive")
	c.Handler().ServeHTTP(rec, req)
	if rec.Code != http.StatusAccepted || rec.Body.String() != "proxied" || rec.Header().Get("X-Up") != "1" {
		t.Fatalf("code %d body %q", rec.Code, rec.Body.String())
	}
	if rec.Header().Get("Connection") != "" {
		t.Fatalf("hop-by-hop response header leaked: %q", rec.Header().Get("Connection"))
	}
}

func TestForwardNoTarget(t *testing.T) {
	c, err := New()
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/x", nil)
	req.Host = ""
	req.URL.Host = ""
	c.Handler().ServeHTTP(rec, req)
	if rec.Code != http.StatusBadGateway {
		t.Fatalf("code %d", rec.Code)
	}
}

func TestForwardPreserveHost(t *testing.T) {
	var gotHost atomic.Value
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotHost.Store(r.Host)
	}))
	defer upstream.Close()

	c, err := New(WithHosts(upstream.URL))
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()

	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "http://svc.example/x", nil)
	c.Handler().ServeHTTP(rec, req)
	if gotHost.Load() != "svc.example" {
		t.Fatalf("preserved host %q", gotHost.Load())
	}

	rec = httptest.NewRecorder()
	req = httptest.NewRequest(http.MethodGet, "http://svc.example/x", nil)
	c.Handler(WithForwardPreserveHost(false)).ServeHTTP(rec, req)
	if gotHost.Load() == "svc.example" {
		t.Fatalf("host preserved despite option: %q", gotHost.Load())
	}
}

func TestForwardSSE(t *testing.T) {
	var mirrorHits atomic.Int32
	mirror := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		mirrorHits.Add(1)
		w.Header().Set("Content-Type", "text/event-stream")
		fmt.Fprint(w, "data: shadow\n\n")
	}))
	defer mirror.Close()
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/event-stream")
		fmt.Fprint(w, "data: one\n\n")
		w.(http.Flusher).Flush()
		fmt.Fprint(w, "data: two\n\n")
		w.(http.Flusher).Flush()
	}))
	defer upstream.Close()

	c, err := New(
		WithHosts(upstream.URL),
		WithRule(Rule{Name: "sse", Pattern: "/events", Mirror: &MirrorPolicy{
			Targets: []string{mirror.URL},
			Percent: 100,
			Timeout: time.Second,
		}}),
	)
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "http://svc/events", nil)
	c.Handler().ServeHTTP(rec, req)
	if rec.Code != http.StatusOK || !strings.Contains(rec.Body.String(), "data: one") ||
		!strings.Contains(rec.Body.String(), "data: two") {
		t.Fatalf("code %d body %q", rec.Code, rec.Body.String())
	}
	waitFor(t, time.Second, func() bool { return mirrorHits.Load() == 1 })
}

func TestForwardUpgradeUnsupported(t *testing.T) {
	c, err := New()
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "http://svc/x", nil)
	req.Header.Set("Upgrade", "websocket")
	c.Handler().ServeHTTP(rec, req)
	if rec.Code != http.StatusNotImplemented {
		t.Fatalf("code %d", rec.Code)
	}
}

func TestForwardUpstreamError(t *testing.T) {
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {}))
	target := upstream.URL
	upstream.Close()

	c, err := New(WithHosts(target))
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	rec := httptest.NewRecorder()
	c.Handler().ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "http://svc/x", nil))
	if rec.Code != http.StatusBadGateway {
		t.Fatalf("code %d", rec.Code)
	}
}
