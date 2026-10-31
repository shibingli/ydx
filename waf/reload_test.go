package waf

import (
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

// testBundle builds a sealed SecLang bundle. | testBundle 构建已封装的 SecLang 规则包。
func testBundle(t *testing.T, version, source string) *Bundle {
	t.Helper()
	bundle := &Bundle{Version: version, Data: []byte(source)}
	if err := bundle.seal(); err != nil {
		t.Fatalf("seal: %v", err)
	}
	return bundle
}

// sourceState is a mutable source for reload tests. | sourceState 是重载测试使用的可变来源。
type sourceState struct {
	mu     sync.Mutex
	bundle *Bundle
	err    error
	calls  atomic.Int32
}

func (s *sourceState) Load(context.Context) (*Bundle, error) {
	s.calls.Add(1)
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.err != nil {
		return nil, s.err
	}
	return s.bundle, nil
}

func (s *sourceState) set(bundle *Bundle, err error) {
	s.mu.Lock()
	s.bundle = bundle
	s.err = err
	s.mu.Unlock()
}

func TestReloadSwapsRules(t *testing.T) {
	source := &sourceState{bundle: testBundle(t, "v1",
		`SecRule REQUEST_URI "@contains old" "id:1,phase:1,deny,status:403"`)}
	instance, err := New(Options{Source: source, Retry: RetryPolicy{MaxAttempts: 1}})
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	defer func() { _ = instance.Close() }()
	if response := serveTest(t, instance, httptestNewRequest("/old")); response.Code != 403 {
		t.Fatalf("old rule did not block: %d", response.Code)
	}
	source.set(testBundle(t, "v2",
		`SecRule REQUEST_URI "@contains new" "id:2,phase:1,deny,status:403"`), nil)
	if err := instance.Reload(); err != nil {
		t.Fatalf("Reload: %v", err)
	}
	if response := serveTest(t, instance, httptestNewRequest("/old")); response.Code != 200 {
		t.Fatalf("old rule still active: %d", response.Code)
	}
	if response := serveTest(t, instance, httptestNewRequest("/new")); response.Code != 403 {
		t.Fatalf("new rule did not block: %d", response.Code)
	}
	if instance.RuleVersion() != "v2" {
		t.Fatalf("version = %q", instance.RuleVersion())
	}
	if stats := instance.Stats(); stats.Reloads != 1 {
		t.Fatalf("reloads = %d", stats.Reloads)
	}
}

func TestFailedReloadKeepsOldEngine(t *testing.T) {
	source := &sourceState{bundle: testBundle(t, "v1",
		`SecRule REQUEST_URI "@contains old" "id:1,phase:1,deny,status:403"`)}
	instance, err := New(Options{Source: source, Retry: RetryPolicy{MaxAttempts: 1}})
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	defer func() { _ = instance.Close() }()
	source.set(testBundle(t, "bad", `SecRule REQUEST_URI "@rx (" "id:2,phase:1,deny"`), nil)
	if err := instance.Reload(); err == nil {
		t.Fatal("invalid reload succeeded")
	}
	if instance.RuleVersion() != "v1" {
		t.Fatalf("version changed to %q", instance.RuleVersion())
	}
	if response := serveTest(t, instance, httptestNewRequest("/old")); response.Code != 403 {
		t.Fatalf("old engine not serving: %d", response.Code)
	}
	if stats := instance.Stats(); stats.Errors == 0 {
		t.Fatal("reload error not counted")
	}
}

func TestLastKnownGoodFallback(t *testing.T) {
	directory := t.TempDir()
	prefix := filepath.Join(directory, "rules")
	source := &sourceState{bundle: testBundle(t, "v1",
		`SecRule REQUEST_URI "@contains cached" "id:1,phase:1,deny,status:403"`)}
	first, err := New(Options{Source: source, LastKnownGood: prefix, Retry: RetryPolicy{MaxAttempts: 1}})
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	_ = first.Close()
	if _, err := os.Stat(prefix); err != nil {
		t.Fatalf("cache not written: %v", err)
	}
	failing := &sourceState{err: errors.New("source down")}
	second, err := New(Options{Source: failing, LastKnownGood: prefix, Retry: RetryPolicy{MaxAttempts: 1}})
	if err != nil {
		t.Fatalf("New with cache: %v", err)
	}
	defer func() { _ = second.Close() }()
	if second.RuleVersion() != "v1" {
		t.Fatalf("version = %q", second.RuleVersion())
	}
	if response := serveTest(t, second, httptestNewRequest("/cached")); response.Code != 403 {
		t.Fatalf("cached rule did not block: %d", response.Code)
	}
}

func TestApplyBundle(t *testing.T) {
	instance := newTestWAF(t, []string{
		`SecRule REQUEST_URI "@contains first" "id:1,phase:1,deny,status:403"`,
	}, nil)
	if err := instance.ApplyBundle(testBundle(t, "pushed",
		`SecRule REQUEST_URI "@contains second" "id:2,phase:1,deny,status:403"`)); err != nil {
		t.Fatalf("ApplyBundle: %v", err)
	}
	if response := serveTest(t, instance, httptestNewRequest("/first")); response.Code != 200 {
		t.Fatalf("old rule still active: %d", response.Code)
	}
	if response := serveTest(t, instance, httptestNewRequest("/second")); response.Code != 403 {
		t.Fatalf("pushed rule did not block: %d", response.Code)
	}
}

func TestWatcherReloads(t *testing.T) {
	source := &sourceState{bundle: testBundle(t, "v1",
		`SecRule REQUEST_URI "@contains first" "id:1,phase:1,deny,status:403"`)}
	instance, err := New(Options{
		Source:        source,
		WatchInterval: 10 * time.Millisecond,
		Retry:         RetryPolicy{MaxAttempts: 1},
	})
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	defer func() { _ = instance.Close() }()
	source.set(testBundle(t, "v2",
		`SecRule REQUEST_URI "@contains second" "id:2,phase:1,deny,status:403"`), nil)
	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		if instance.RuleVersion() == "v2" {
			break
		}
		time.Sleep(10 * time.Millisecond)
	}
	if instance.RuleVersion() != "v2" {
		t.Fatalf("watcher did not reload, version = %q", instance.RuleVersion())
	}
}

func TestHTTPSourceRetryAndNotModified(t *testing.T) {
	bundle := testBundle(t, "http-v1",
		`SecRule REQUEST_URI "@contains http" "id:1,phase:1,deny,status:403"`)
	var attempts atomic.Int32
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		attempt := attempts.Add(1)
		if attempt < 3 {
			w.WriteHeader(http.StatusInternalServerError)
			return
		}
		if r.Header.Get("If-None-Match") == `"v1"` {
			w.WriteHeader(http.StatusNotModified)
			return
		}
		w.Header().Set("ETag", `"v1"`)
		w.Header().Set("X-YDX-WAF-Version", bundle.Version)
		_, _ = w.Write(bundle.Data)
	}))
	defer server.Close()
	source := &HTTPSource{URL: server.URL}
	policy := RetryPolicy{MaxAttempts: 3, InitialBackoff: time.Millisecond, MaxBackoff: time.Millisecond}
	var loaded *Bundle
	err := policy.do(context.Background(), func(ctx context.Context) error {
		got, err := source.Load(ctx)
		if err != nil {
			return err
		}
		loaded = got
		return nil
	})
	if err != nil {
		t.Fatalf("load: %v", err)
	}
	if loaded.Version != "http-v1" {
		t.Fatalf("version = %q", loaded.Version)
	}
	if _, err := source.Load(context.Background()); !errors.Is(err, ErrNotModified) {
		t.Fatalf("second load error = %v, want ErrNotModified", err)
	}
}

func TestHTTPSourceSignature(t *testing.T) {
	bundle := testBundle(t, "signed", `SecRule REQUEST_URI "@contains signed" "id:1,phase:1,deny"`)
	key := []byte("test-signature-key")
	mac := hmac.New(sha256.New, key)
	_, _ = mac.Write(bundle.Data)
	signature := hex.EncodeToString(mac.Sum(nil))
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("X-YDX-WAF-Signature", signature)
		_, _ = w.Write(bundle.Data)
	}))
	defer server.Close()
	source := &HTTPSource{URL: server.URL, SignatureKey: key}
	if _, err := source.Load(context.Background()); err != nil {
		t.Fatalf("signed load: %v", err)
	}
	bad := &HTTPSource{URL: server.URL, SignatureKey: []byte("wrong")}
	if _, err := bad.Load(context.Background()); !errors.Is(err, ErrSignature) {
		t.Fatalf("bad signature error = %v", err)
	}
}

func TestJSONBundleFormat(t *testing.T) {
	jsonRules := []byte(`{
		"version":"json-v1",
		"mode":"on",
		"rules":[{
			"id":1,
			"phase":1,
			"variables":"REQUEST_URI",
			"operator":"@contains",
			"pattern":"/json-block",
			"actions":{"deny":true,"status":403,"msg":"json rule"}
		}]
	}`)
	bundle := &Bundle{Version: "json-v1", Format: FormatJSON, Data: jsonRules}
	if err := bundle.seal(); err != nil {
		t.Fatalf("seal: %v", err)
	}
	instance, err := New(Options{Source: FuncSource(func(context.Context) (*Bundle, error) {
		return bundle, nil
	}), Retry: RetryPolicy{MaxAttempts: 1}})
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	defer func() { _ = instance.Close() }()
	if response := serveTest(t, instance, httptestNewRequest("/json-block")); response.Code != 403 {
		t.Fatalf("json rule did not block: %d", response.Code)
	}
}

func TestStartupFailureWithoutFallback(t *testing.T) {
	source := FuncSource(func(context.Context) (*Bundle, error) {
		return nil, errors.New("down")
	})
	_, err := New(Options{Source: source, Retry: RetryPolicy{MaxAttempts: 1}})
	if err == nil {
		t.Fatal("startup succeeded without rules")
	}
}

func TestFileSource(t *testing.T) {
	source := FileSource{Paths: []string{"missing.conf"}}
	if _, err := source.Load(context.Background()); err == nil {
		t.Fatal("missing file accepted")
	}
}
