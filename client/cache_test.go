package client

import (
	"context"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

func TestCacheTTLAndVary(t *testing.T) {
	var hits atomic.Int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		hits.Add(1)
		w.Header().Set("Vary", "Accept-Language")
		w.Header().Set("Cache-Control", "max-age=60")
		_, _ = w.Write([]byte("v:" + r.Header.Get("Accept-Language")))
	}))
	defer srv.Close()

	c, err := New(WithRule(Rule{Name: "r", Pattern: "/x", Cache: &CachePolicy{TTL: time.Minute}}))
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()

	get := func(lang string) string {
		req := mustRequest(t, http.MethodGet, srv.URL+"/x", "")
		req.Header.Set("Accept-Language", lang)
		resp, err := c.Do(req)
		if err != nil {
			t.Fatal(err)
		}
		data, _ := io.ReadAll(resp.Body)
		resp.Body.Close()
		return string(data)
	}
	if got := get("zh"); got != "v:zh" {
		t.Fatal(got)
	}
	if got := get("zh"); got != "v:zh" {
		t.Fatal(got)
	}
	if hits.Load() != 1 {
		t.Fatalf("cache miss count %d", hits.Load())
	}
	if got := get("en"); got != "v:en" {
		t.Fatal(got)
	}
	if hits.Load() != 2 {
		t.Fatalf("vary miss count %d", hits.Load())
	}
}

func TestCacheAllowSensitiveSeparatesCredentials(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte(r.Header.Get("Authorization")))
	}))
	defer srv.Close()
	c, err := New(
		WithHosts(srv.URL),
		WithCache(CachePolicy{TTL: time.Minute, AllowSensitive: true}),
	)
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	for _, credential := range []string{"Bearer alice", "Bearer bob"} {
		resp, err := c.Get(context.Background(), srv.URL+"/x", WithRequestHeader("Authorization", credential))
		if err != nil {
			t.Fatal(err)
		}
		data, _ := io.ReadAll(resp.Body)
		resp.Body.Close()
		if string(data) != credential {
			t.Fatalf("credential %q got %q", credential, data)
		}
	}
}

func TestCacheSeparatesAcceptEncoding(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Accept-Encoding") == "identity" {
			_, _ = w.Write([]byte("identity"))
			return
		}
		_, _ = w.Write([]byte("auto"))
	}))
	defer srv.Close()
	c, err := New(WithHosts(srv.URL), WithCache(CachePolicy{TTL: time.Minute}))
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	resp, err := c.Get(context.Background(), srv.URL+"/x", WithRequestHeader("Accept-Encoding", "identity"))
	if err != nil {
		t.Fatal(err)
	}
	first, _ := io.ReadAll(resp.Body)
	resp.Body.Close()
	resp, err = c.Get(context.Background(), srv.URL+"/x")
	if err != nil {
		t.Fatal(err)
	}
	second, _ := io.ReadAll(resp.Body)
	resp.Body.Close()
	if string(first) != "identity" || string(second) != "auto" {
		t.Fatalf("bodies %q %q", first, second)
	}
}

func TestCacheHeadContentLength(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Length", "1234")
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()
	c, err := New(
		WithHosts(srv.URL),
		WithCache(CachePolicy{TTL: time.Minute}),
	)
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	for i := 0; i < 2; i++ {
		resp, err := c.Head(context.Background(), srv.URL+"/x")
		if err != nil {
			t.Fatal(err)
		}
		resp.Body.Close()
		if resp.ContentLength != 1234 {
			t.Fatalf("attempt %d: content length %d", i, resp.ContentLength)
		}
	}
}

func TestCacheSkipsConditionalRequests(t *testing.T) {
	policy := CachePolicy{}.withDefaults()
	for _, header := range []string{"Range", "If-Range", "If-None-Match", "If-Modified-Since", "If-Match", "If-Unmodified-Since"} {
		req := httptest.NewRequest(http.MethodGet, "http://svc/x", nil)
		req.Header.Set(header, "value")
		if cacheReadable(req, policy) {
			t.Fatalf("%s request must not use the cache", header)
		}
	}
}

func TestCacheOversizeBypass(t *testing.T) {
	payload := strings.Repeat("x", 100)
	var hits atomic.Int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		hits.Add(1)
		_, _ = w.Write([]byte(payload))
	}))
	defer srv.Close()

	c, err := New(WithRule(Rule{Name: "r", Pattern: "/x", Cache: &CachePolicy{
		TTL:          time.Minute,
		MaxBodyBytes: 10,
	}}))
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	for i := 0; i < 2; i++ {
		resp, err := c.Get(context.Background(), srv.URL+"/x")
		if err != nil {
			t.Fatal(err)
		}
		data, _ := resp.Bytes()
		if string(data) != payload {
			t.Fatalf("body length %d", len(data))
		}
	}
	if hits.Load() != 2 {
		t.Fatalf("oversize cached: hits=%d", hits.Load())
	}
}

func TestCacheNoStoreAndAuth(t *testing.T) {
	t.Run("no-store", func(t *testing.T) {
		var hits atomic.Int32
		srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			hits.Add(1)
			w.Header().Set("Cache-Control", "no-store")
		}))
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
		if hits.Load() != 2 {
			t.Fatalf("no-store cached: %d", hits.Load())
		}
	})

	t.Run("auth", func(t *testing.T) {
		var hits atomic.Int32
		srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			hits.Add(1)
		}))
		defer srv.Close()
		c, err := New(WithRule(Rule{Name: "r", Pattern: "/x", Cache: &CachePolicy{TTL: time.Minute}}))
		if err != nil {
			t.Fatal(err)
		}
		defer c.Close()
		for i := 0; i < 2; i++ {
			resp, err := c.Get(context.Background(), srv.URL+"/x", WithRequestHeader("Authorization", "Bearer t"))
			if err != nil {
				t.Fatal(err)
			}
			resp.Body.Close()
		}
		if hits.Load() != 2 {
			t.Fatalf("authorized response cached: %d", hits.Load())
		}
	})
}

func TestCacheConcurrentAfterWarmup(t *testing.T) {
	var hits atomic.Int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		hits.Add(1)
		time.Sleep(10 * time.Millisecond)
		_, _ = w.Write([]byte("cached"))
	}))
	defer srv.Close()
	c, err := New(WithRule(Rule{Name: "r", Pattern: "/x", Cache: &CachePolicy{TTL: time.Minute}}))
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()

	first, err := c.Get(context.Background(), srv.URL+"/x")
	if err != nil {
		t.Fatal(err)
	}
	first.Body.Close()

	var wg sync.WaitGroup
	for i := 0; i < 20; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			resp, err := c.Get(context.Background(), srv.URL+"/x")
			if err != nil {
				t.Error(err)
				return
			}
			data, _ := resp.Bytes()
			if string(data) != "cached" {
				t.Errorf("body %q", data)
			}
		}()
	}
	wg.Wait()
	if hits.Load() != 1 {
		t.Fatalf("cache hits %d", hits.Load())
	}
}

func TestMemoryStoreLRUAndExpiry(t *testing.T) {
	store, err := NewMemoryStore(MemoryOptions{
		MaxBytes:        220,
		MaxEntryBytes:   120,
		Shards:          1,
		CleanupInterval: time.Hour,
	})
	if err != nil {
		t.Fatal(err)
	}
	defer store.Close()

	entry := func(body string) *CacheEntry {
		return &CacheEntry{
			Status:     "200 OK",
			StatusCode: http.StatusOK,
			Header:     make(http.Header),
			Body:       []byte(body),
			Expires:    time.Now().Add(time.Minute),
		}
	}
	store.Set("a", entry(strings.Repeat("a", 60)))
	store.Set("b", entry(strings.Repeat("b", 60)))
	if _, ok := store.Get("a"); !ok {
		t.Fatal("a missing")
	}
	store.Set("c", entry(strings.Repeat("c", 60)))
	if _, ok := store.Get("b"); ok {
		t.Fatal("b should be evicted")
	}
	if _, ok := store.Get("a"); !ok {
		t.Fatal("a should remain")
	}
	if _, ok := store.Get("c"); !ok {
		t.Fatal("c missing")
	}

	store.Set("short", &CacheEntry{
		Status: "200 OK", StatusCode: 200, Header: make(http.Header),
		Body: []byte("x"), Expires: time.Now().Add(10 * time.Millisecond),
	})
	time.Sleep(20 * time.Millisecond)
	if _, ok := store.Get("short"); ok {
		t.Fatal("expired entry served")
	}
}

func TestCacheVaryStarAndNoCacheRequest(t *testing.T) {
	var hits atomic.Int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		hits.Add(1)
		w.Header().Set("Vary", "*")
	}))
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
	if hits.Load() != 2 {
		t.Fatalf("Vary:* cached: %d", hits.Load())
	}

	req := mustRequest(t, http.MethodGet, srv.URL+"/x", "")
	req.Header.Set("Cache-Control", "no-cache")
	if _, err := c.Do(req); err != nil {
		t.Fatal(err)
	}
	if hits.Load() != 3 {
		t.Fatalf("no-cache request hit cache: %d", hits.Load())
	}
}

func TestCacheNoCacheRequestStillWrites(t *testing.T) {
	var hits atomic.Int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		hits.Add(1)
		_, _ = w.Write([]byte("cached"))
	}))
	defer srv.Close()
	c, err := New(WithHosts(srv.URL), WithCache(CachePolicy{TTL: time.Minute}))
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	resp, err := c.Get(context.Background(), srv.URL+"/x", WithRequestHeader("Cache-Control", "no-cache"))
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	resp, err = c.Get(context.Background(), srv.URL+"/x")
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	if hits.Load() != 1 || c.Stats().CacheHits != 1 {
		t.Fatalf("hits %d cacheHits %d", hits.Load(), c.Stats().CacheHits)
	}
}

func TestCacheSkipsRequestsWithBody(t *testing.T) {
	var hits atomic.Int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		hits.Add(1)
		w.Header().Set("Cache-Control", "max-age=60")
		_, _ = w.Write([]byte("ok"))
	}))
	defer srv.Close()
	c, err := New(WithCache(CachePolicy{TTL: time.Minute}), WithHosts(srv.URL), WithoutCookieJar())
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	if _, err := c.Get(context.Background(), srv.URL+"/x"); err != nil {
		t.Fatal(err)
	}
	resp, err := c.Send(context.Background(), http.MethodGet, srv.URL+"/x", strings.NewReader("body"))
	if err != nil {
		t.Fatal(err)
	}
	_ = resp.Body.Close()
	if hits.Load() != 2 {
		t.Fatalf("request with body used cache: hits=%d", hits.Load())
	}
}

func TestCacheSkipsURLUserinfo(t *testing.T) {
	var hits atomic.Int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		hits.Add(1)
		w.Header().Set("Cache-Control", "max-age=60")
		_, _ = w.Write([]byte("ok"))
	}))
	defer srv.Close()
	c, err := New(WithCache(CachePolicy{TTL: time.Minute}), WithHosts(srv.URL), WithoutCookieJar())
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	u := strings.Replace(srv.URL, "http://", "http://user:pass@", 1) + "/x"
	for i := 0; i < 2; i++ {
		resp, err := c.Get(context.Background(), u)
		if err != nil {
			t.Fatal(err)
		}
		_ = resp.Body.Close()
	}
	if hits.Load() != 2 {
		t.Fatalf("URL userinfo used cache: hits=%d", hits.Load())
	}
}
