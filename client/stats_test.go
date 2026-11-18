package client

import (
	"context"
	"fmt"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"
)

func TestStatsBasicAndHost(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {}))
	defer srv.Close()
	c, err := New(WithHosts(srv.URL), WithRewriteAll(true))
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	resp, err := c.Get(context.Background(), srv.URL+"/x")
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	stats := c.Stats()
	if stats.Requests != 1 || stats.Responses != 1 || stats.Errors != 0 || stats.Inflight != 0 {
		t.Fatalf("stats %+v", stats)
	}
	hosts := c.HostStats()
	if len(hosts) != 1 || hosts[0].Name == "" || hosts[0].Requests != 1 {
		t.Fatalf("host stats %+v", hosts)
	}
}

func TestStatsCache(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {}))
	defer srv.Close()
	c, err := New(WithRule(Rule{Name: "r", Pattern: "/x", Cache: &CachePolicy{TTL: time.Minute}}))
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	for i := 0; i < 2; i++ {
		resp, err := c.Get(context.Background(), srv.URL+"/x")
		if err != nil {
			t.Fatal(err)
		}
		resp.Body.Close()
	}
	stats := c.Stats()
	if stats.CacheHits != 1 || stats.CacheMisses != 1 || stats.CacheStores != 1 {
		t.Fatalf("cache stats %+v", stats)
	}
}

func TestStatsSSE(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/event-stream")
		fmt.Fprint(w, "data: one\n\n")
	}))
	defer srv.Close()
	c, err := New()
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	stream, err := c.OpenStream(context.Background(), mustRequest(t, http.MethodGet, srv.URL, ""))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := stream.Next(context.Background()); err != nil {
		t.Fatal(err)
	}
	stream.Close()
	stats := c.Stats()
	if stats.SSESessions != 1 || stats.SSEEvents != 1 {
		t.Fatalf("sse stats %+v", stats)
	}
}

func TestMetaTimings(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte("ok"))
	}))
	defer srv.Close()
	c, err := New(WithHosts(srv.URL), WithTrace(true))
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	resp, err := c.Get(context.Background(), srv.URL+"/x")
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	if resp.Meta.Timings.Total <= 0 || resp.Meta.Timings.TTFB <= 0 {
		t.Fatalf("timings %+v", resp.Meta.Timings)
	}
}
