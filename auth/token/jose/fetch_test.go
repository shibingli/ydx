package jose

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

// testJWKSBody builds a one-key JWKS document. | testJWKSBody 构造只含一个密钥的 JWKS 文档。
func testJWKSBody(t *testing.T, kid string) []byte {
	t.Helper()
	k := mustGenerate(t, "EdDSA").Public()
	k.Kid = kid
	body, err := (&KeySet{Keys: []*Key{k}}).Marshal()
	if err != nil {
		t.Fatalf("Marshal failed: %v", err)
	}
	return body
}

func TestFetcherConditionalRequests(t *testing.T) {
	body := testJWKSBody(t, "k1")
	var served, notModified int32
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("If-None-Match") == `"v1"` {
			atomic.AddInt32(&notModified, 1)
			w.WriteHeader(http.StatusNotModified)
			return
		}
		atomic.AddInt32(&served, 1)
		w.Header().Set("ETag", `"v1"`)
		w.Header().Set("Content-Type", "application/jwk-set+json")
		_, _ = w.Write(body)
	}))
	defer server.Close()

	now := time.Unix(1700000000, 0)
	f, err := NewFetcher(server.URL, FetcherOptions{
		Client:             server.Client(),
		CacheTTL:           time.Minute,
		MinRefreshInterval: time.Minute,
		Now:                func() time.Time { return now },
	})
	if err != nil {
		t.Fatalf("NewFetcher failed: %v", err)
	}
	if f.URL() != server.URL || f.Cache() == nil {
		t.Fatalf("URL/Cache = %q/%v", f.URL(), f.Cache())
	}
	ctx := context.Background()

	set, err := f.Fetch(ctx)
	if err != nil {
		t.Fatalf("Fetch failed: %v", err)
	}
	if len(set.Keys) != 1 || set.Keys[0].Kid != "k1" {
		t.Fatalf("fetched set = %+v", set)
	}
	if got := atomic.LoadInt32(&served); got != 1 {
		t.Fatalf("served = %d, want 1", got)
	}
	if _, err := f.Fetch(ctx); err != nil {
		t.Fatalf("cached Fetch failed: %v", err)
	}
	if got := atomic.LoadInt32(&served); got != 1 {
		t.Fatalf("fresh cache caused a fetch: served = %d", got)
	}

	now = now.Add(2 * time.Minute)
	set, err = f.Fetch(ctx)
	if err != nil {
		t.Fatalf("revalidating Fetch failed: %v", err)
	}
	if len(set.Keys) != 1 {
		t.Fatalf("revalidated set = %+v", set)
	}
	if got := atomic.LoadInt32(&notModified); got != 1 {
		t.Fatalf("notModified = %d, want 1", got)
	}
	if _, err := f.ForceRefresh(ctx); err != nil {
		t.Fatalf("ForceRefresh failed: %v", err)
	}
	if got := atomic.LoadInt32(&notModified); got != 2 {
		t.Fatalf("notModified after ForceRefresh = %d, want 2", got)
	}

	now = now.Add(10 * time.Minute)
	key, err := f.Key(ctx, "k1")
	if err != nil {
		t.Fatalf("Key(k1) failed: %v", err)
	}
	if key.Kid != "k1" {
		t.Fatalf("key kid = %q", key.Kid)
	}
	if got := atomic.LoadInt32(&notModified); got != 3 {
		t.Fatalf("stale known kid did not revalidate: notModified = %d", got)
	}
	if _, err := f.Key(ctx, "missing"); !errors.Is(err, ErrKeyNotFound) {
		t.Fatalf("Key(missing) error = %v, want ErrKeyNotFound", err)
	}
	if got := atomic.LoadInt32(&notModified); got != 3 {
		t.Fatalf("rate limit did not hold: notModified = %d", got)
	}
	now = now.Add(2 * time.Minute)
	if _, err := f.Key(ctx, "missing"); !errors.Is(err, ErrKeyNotFound) {
		t.Fatalf("Key(missing) error = %v, want ErrKeyNotFound", err)
	}
	if got := atomic.LoadInt32(&notModified); got != 4 {
		t.Fatalf("unknown kid did not refresh: notModified = %d", got)
	}
	if got := atomic.LoadInt32(&served); got != 1 {
		t.Fatalf("server served %d bodies, want 1", got)
	}

	header := Header{"kid": "k1"}
	resolved, err := f.Resolver().ResolveKey(ctx, header)
	if err != nil {
		t.Fatalf("Resolver failed: %v", err)
	}
	if resolved.Kid != "k1" {
		t.Fatalf("resolved kid = %q", resolved.Kid)
	}
}

func TestFetcherRotation(t *testing.T) {
	var body atomic.Value
	body.Store(testJWKSBody(t, "old"))
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("ETag", `"rotating"`)
		_, _ = w.Write(body.Load().([]byte))
	}))
	defer server.Close()

	f, err := NewFetcher(server.URL, FetcherOptions{Client: server.Client()})
	if err != nil {
		t.Fatalf("NewFetcher failed: %v", err)
	}
	ctx := context.Background()
	if _, err := f.Fetch(ctx); err != nil {
		t.Fatalf("Fetch failed: %v", err)
	}
	if _, err := f.Cache().Get("old"); err != nil {
		t.Fatalf("Get(old) failed: %v", err)
	}
	body.Store(testJWKSBody(t, "new"))
	if _, err := f.ForceRefresh(ctx); err != nil {
		t.Fatalf("ForceRefresh failed: %v", err)
	}
	if _, err := f.Cache().Get("new"); err != nil {
		t.Fatalf("Get(new) failed: %v", err)
	}
	if _, err := f.Cache().Get("old"); !errors.Is(err, ErrKeyNotFound) {
		t.Fatalf("Get(old) after rotation error = %v, want ErrKeyNotFound", err)
	}
}

func TestFetcherErrors(t *testing.T) {
	if _, err := NewFetcher("ftp://example.com/jwks.json", FetcherOptions{}); !errors.Is(err, ErrInvalidConfig) {
		t.Fatalf("ftp URL error = %v, want ErrInvalidConfig", err)
	}
	if _, err := NewFetcher("not a url", FetcherOptions{}); !errors.Is(err, ErrInvalidConfig) {
		t.Fatalf("relative URL error = %v, want ErrInvalidConfig", err)
	}

	tooLarge := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte(strings.Repeat("x", 1024)))
	}))
	defer tooLarge.Close()
	f, err := NewFetcher(tooLarge.URL, FetcherOptions{Client: tooLarge.Client(), MaxBodySize: 128})
	if err != nil {
		t.Fatalf("NewFetcher failed: %v", err)
	}
	if _, err := f.Fetch(context.Background()); !errors.Is(err, ErrResponseTooLarge) {
		t.Fatalf("oversized body error = %v, want ErrResponseTooLarge", err)
	}

	badBody := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte("not json"))
	}))
	defer badBody.Close()
	f, err = NewFetcher(badBody.URL, FetcherOptions{Client: badBody.Client()})
	if err != nil {
		t.Fatalf("NewFetcher failed: %v", err)
	}
	if _, err := f.Fetch(context.Background()); !errors.Is(err, ErrFetchFailed) {
		t.Fatalf("invalid body error = %v, want ErrFetchFailed", err)
	}

	always304 := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusNotModified)
	}))
	defer always304.Close()
	f, err = NewFetcher(always304.URL, FetcherOptions{Client: always304.Client()})
	if err != nil {
		t.Fatalf("NewFetcher failed: %v", err)
	}
	if _, err := f.Fetch(context.Background()); !errors.Is(err, ErrFetchFailed) {
		t.Fatalf("304 without cache error = %v, want ErrFetchFailed", err)
	}

	failing := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
	}))
	defer failing.Close()
	f, err = NewFetcher(failing.URL, FetcherOptions{Client: failing.Client()})
	if err != nil {
		t.Fatalf("NewFetcher failed: %v", err)
	}
	if _, err := f.Fetch(context.Background()); !errors.Is(err, ErrFetchFailed) {
		t.Fatalf("500 error = %v, want ErrFetchFailed", err)
	}
}
