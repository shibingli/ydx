package waf

import (
	"context"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

func TestReloadWithSwapsRules(t *testing.T) {
	w := newWAF(t, Options{Directives: []string{`SecRule REQUEST_URI "@contains /old" "id:2001,phase:1,deny,status:403"`}})
	if rec := doNative(w, okHandler(), http.MethodGet, "/old", "", nil); rec.Code != http.StatusForbidden {
		t.Fatalf("初始规则未生效: %d", rec.Code)
	}
	err := w.ReloadWith(Options{Directives: []string{`SecRule REQUEST_URI "@contains /new" "id:2002,phase:1,deny,status:403"`}})
	if err != nil {
		t.Fatalf("ReloadWith() 失败: %v", err)
	}
	if rec := doNative(w, okHandler(), http.MethodGet, "/old", "", nil); rec.Code != http.StatusOK {
		t.Fatalf("旧规则仍生效: %d", rec.Code)
	}
	if rec := doNative(w, okHandler(), http.MethodGet, "/new", "", nil); rec.Code != http.StatusForbidden {
		t.Fatalf("新规则未生效: %d", rec.Code)
	}
	if got := w.Stats().Reloads; got != 1 {
		t.Fatalf("Reloads = %d，期望 1", got)
	}
	if got := w.RulesCount(); got != 1 {
		t.Fatalf("RulesCount = %d，期望 1", got)
	}
}

func TestReloadFailureKeepsOldEngine(t *testing.T) {
	w := newWAF(t, Options{Directives: []string{ruleURI}})
	err := w.ReloadWith(Options{Directives: []string{"SecRule BROKEN"}})
	if !errors.Is(err, ErrBuild) {
		t.Fatalf("ReloadWith() 错误 = %v，期望 ErrBuild", err)
	}
	if rec := doNative(w, okHandler(), http.MethodGet, "/attack", "", nil); rec.Code != http.StatusForbidden {
		t.Fatalf("失败重载后旧规则失效: %d", rec.Code)
	}
	if got := w.Stats().Reloads; got != 0 {
		t.Fatalf("Reloads = %d，期望 0", got)
	}
	if got := w.Stats().Errors; got != 1 {
		t.Fatalf("Errors = %d，期望 1", got)
	}
}

func TestReloadRereadsRuleFile(t *testing.T) {
	path := filepath.Join(t.TempDir(), "rules.conf")
	writeRuleFile(t, path, `SecRule REQUEST_URI "@contains /one" "id:2101,phase:1,deny,status:403"`)
	w := newWAF(t, Options{RuleFiles: []string{path}})
	if rec := doNative(w, okHandler(), http.MethodGet, "/one", "", nil); rec.Code != http.StatusForbidden {
		t.Fatalf("初始文件规则未生效: %d", rec.Code)
	}

	writeRuleFile(t, path, `SecRule REQUEST_URI "@contains /two" "id:2102,phase:1,deny,status:403"`)
	if err := w.Reload(); err != nil {
		t.Fatalf("Reload() 失败: %v", err)
	}
	if rec := doNative(w, okHandler(), http.MethodGet, "/one", "", nil); rec.Code != http.StatusOK {
		t.Fatalf("旧文件规则仍生效: %d", rec.Code)
	}
	if rec := doNative(w, okHandler(), http.MethodGet, "/two", "", nil); rec.Code != http.StatusForbidden {
		t.Fatalf("新文件规则未生效: %d", rec.Code)
	}
}

func writeRuleFile(t *testing.T, path, content string) {
	t.Helper()
	if err := os.WriteFile(path, []byte(content+"\n"), 0o600); err != nil {
		t.Fatalf("写入规则文件失败: %v", err)
	}
}

func TestCloseRejectsNewRequests(t *testing.T) {
	w := newWAF(t, Options{Directives: []string{ruleURI}})
	if err := w.Close(); err != nil {
		t.Fatalf("Close() 失败: %v", err)
	}
	rec := doNative(w, okHandler(), http.MethodGet, "/safe", "", nil)
	if rec.Code != http.StatusServiceUnavailable {
		t.Fatalf("关闭后状态 = %d，期望 503", rec.Code)
	}
	if got := w.Stats().Rejected; got != 1 {
		t.Fatalf("Rejected = %d，期望 1", got)
	}
	if err := w.Close(); err != nil {
		t.Fatalf("重复 Close() 失败: %v", err)
	}
	if got := w.RulesCount(); got != 0 {
		t.Fatalf("关闭后 RulesCount = %d，期望 0", got)
	}
}

func TestReloadAfterCloseFails(t *testing.T) {
	w := newWAF(t, Options{Directives: []string{ruleURI}})
	_ = w.Close()
	if err := w.Reload(); !errors.Is(err, ErrClosed) {
		t.Fatalf("Reload() 错误 = %v，期望 ErrClosed", err)
	}
	if err := w.ReloadWith(Options{Directives: []string{ruleURI}}); !errors.Is(err, ErrClosed) {
		t.Fatalf("ReloadWith() 错误 = %v，期望 ErrClosed", err)
	}
}

func TestShutdownWaitsForInflight(t *testing.T) {
	w := newWAF(t, Options{Directives: []string{ruleURI}})
	started := make(chan struct{})
	release := make(chan struct{})
	h := http.HandlerFunc(func(rw http.ResponseWriter, _ *http.Request) {
		close(started)
		<-release
		_, _ = io.WriteString(rw, "done")
	})
	mw := w.HTTPMiddleware(h)
	reqDone := make(chan *httptest.ResponseRecorder, 1)
	go func() {
		rec := httptest.NewRecorder()
		mw.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/slow", nil))
		reqDone <- rec
	}()
	<-started

	shutdownDone := make(chan error, 1)
	go func() {
		ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
		defer cancel()
		shutdownDone <- w.Shutdown(ctx)
	}()
	select {
	case err := <-shutdownDone:
		t.Fatalf("Shutdown 在请求完成前返回: %v", err)
	case <-time.After(100 * time.Millisecond):
	}
	close(release)
	if err := <-shutdownDone; err != nil {
		t.Fatalf("Shutdown() 失败: %v", err)
	}
	rec := <-reqDone
	if rec.Code != http.StatusOK || rec.Body.String() != "done" {
		t.Fatalf("在途请求结果异常: code=%d body=%q", rec.Code, rec.Body.String())
	}
	if got := w.Stats().InFlight; got != 0 {
		t.Fatalf("InFlight = %d，期望 0", got)
	}
	if rec := doNative(w, okHandler(), http.MethodGet, "/safe", "", nil); rec.Code != http.StatusServiceUnavailable {
		t.Fatalf("Shutdown 后新请求状态 = %d，期望 503", rec.Code)
	}
}

func TestShutdownTimeout(t *testing.T) {
	w := newWAF(t, Options{Directives: []string{ruleURI}})
	started := make(chan struct{})
	release := make(chan struct{})
	h := http.HandlerFunc(func(rw http.ResponseWriter, _ *http.Request) {
		close(started)
		<-release
		_, _ = io.WriteString(rw, "done")
	})
	mw := w.HTTPMiddleware(h)
	reqDone := make(chan struct{})
	go func() {
		mw.ServeHTTP(httptest.NewRecorder(), httptest.NewRequest(http.MethodGet, "/slow", nil))
		close(reqDone)
	}()
	<-started

	ctx, cancel := context.WithTimeout(context.Background(), 50*time.Millisecond)
	defer cancel()
	err := w.Shutdown(ctx)
	if !errors.Is(err, ErrShutdownTimeout) {
		t.Fatalf("Shutdown() 错误 = %v，期望 ErrShutdownTimeout", err)
	}
	if !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("Shutdown() 错误 = %v，期望保留 context.DeadlineExceeded", err)
	}
	close(release)
	<-reqDone
}

func TestConcurrentRequests(t *testing.T) {
	sink := &eventSink{}
	w := newWAF(t, Options{Directives: []string{ruleURI}, Observer: sink.observe})
	h := w.HTTPMiddleware(okHandler())
	const workers = 16
	const perWorker = 40
	var failures atomic.Int64
	var wg sync.WaitGroup
	for i := 0; i < workers; i++ {
		wg.Add(1)
		go func(worker int) {
			defer wg.Done()
			for j := 0; j < perWorker; j++ {
				target := "/safe"
				want := http.StatusOK
				if (worker+j)%2 == 0 {
					target = "/attack"
					want = http.StatusForbidden
				}
				rec := httptest.NewRecorder()
				h.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, target, nil))
				if rec.Code != want {
					failures.Add(1)
				}
			}
		}(i)
	}
	wg.Wait()
	if failures.Load() != 0 {
		t.Fatalf("%d 个并发请求结果错误", failures.Load())
	}
	stats := w.Stats()
	if stats.Inspected != workers*perWorker {
		t.Fatalf("Inspected = %d，期望 %d", stats.Inspected, workers*perWorker)
	}
	if stats.Blocked != workers*perWorker/2 {
		t.Fatalf("Blocked = %d，期望 %d", stats.Blocked, workers*perWorker/2)
	}
	if stats.InFlight != 0 {
		t.Fatalf("InFlight = %d，期望 0", stats.InFlight)
	}
	if got := sink.count(); got != workers*perWorker {
		t.Fatalf("Observer 事件数 = %d，期望 %d", got, workers*perWorker)
	}
}

func TestConcurrentReload(t *testing.T) {
	w := newWAF(t, Options{Directives: []string{ruleURI}})
	h := w.HTTPMiddleware(okHandler())
	var stop atomic.Bool
	var requestWG sync.WaitGroup
	for i := 0; i < 4; i++ {
		requestWG.Add(1)
		go func() {
			defer requestWG.Done()
			for !stop.Load() {
				rec := httptest.NewRecorder()
				h.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/safe", nil))
				if rec.Code != http.StatusOK {
					t.Errorf("并发重载期间正常请求状态 = %d", rec.Code)
					return
				}
			}
		}()
	}
	for i := 0; i < 20; i++ {
		if err := w.ReloadWith(Options{Directives: []string{ruleURI}}); err != nil {
			t.Fatalf("第 %d 次重载失败: %v", i, err)
		}
	}
	stop.Store(true)
	requestWG.Wait()
	if got := w.Stats().Reloads; got != 20 {
		t.Fatalf("Reloads = %d，期望 20", got)
	}
}

func TestShutdownWaitsForEngineRetiredByReload(t *testing.T) {
	w := newWAF(t, Options{Directives: []string{ruleURI}})
	started := make(chan struct{})
	release := make(chan struct{})
	reqDone := make(chan struct{})
	h := http.HandlerFunc(func(rw http.ResponseWriter, _ *http.Request) {
		close(started)
		<-release
		_, _ = io.WriteString(rw, "done")
	})
	mw := w.HTTPMiddleware(h)
	go func() {
		mw.ServeHTTP(httptest.NewRecorder(), httptest.NewRequest(http.MethodGet, "/slow", nil))
		close(reqDone)
	}()
	<-started

	if err := w.ReloadWith(Options{Directives: []string{ruleURI}}); err != nil {
		t.Fatalf("ReloadWith() 失败: %v", err)
	}

	shutdownDone := make(chan error, 1)
	go func() {
		ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
		defer cancel()
		shutdownDone <- w.Shutdown(ctx)
	}()
	select {
	case err := <-shutdownDone:
		t.Fatalf("Shutdown 未等待重载退休引擎上的在途请求: %v", err)
	case <-time.After(100 * time.Millisecond):
	}
	close(release)
	if err := <-shutdownDone; err != nil {
		t.Fatalf("Shutdown() 失败: %v", err)
	}
	<-reqDone
}

func TestShutdownDoesNotWaitForConnectTunnel(t *testing.T) {
	w := newWAF(t, Options{Directives: []string{ruleURI}})
	started := make(chan struct{})
	release := make(chan struct{})
	done := make(chan struct{})
	h := http.HandlerFunc(func(rw http.ResponseWriter, _ *http.Request) {
		close(started)
		<-release
		rw.WriteHeader(http.StatusOK)
	})
	mw := w.HTTPMiddleware(h)
	go func() {
		req := httptest.NewRequest(http.MethodConnect, "/tunnel", nil)
		mw.ServeHTTP(httptest.NewRecorder(), req)
		close(done)
	}()
	<-started

	ctx, cancel := context.WithTimeout(context.Background(), 200*time.Millisecond)
	defer cancel()
	if err := w.Shutdown(ctx); err != nil {
		t.Fatalf("Shutdown 不应等待 CONNECT 隧道: %v", err)
	}
	close(release)
	<-done
}

func TestShutdownIdempotent(t *testing.T) {
	w := newWAF(t, Options{Directives: []string{ruleURI}})
	ctx := context.Background()
	if err := w.Shutdown(ctx); err != nil {
		t.Fatalf("首次 Shutdown() 失败: %v", err)
	}
	if err := w.Shutdown(ctx); err != nil {
		t.Fatalf("重复 Shutdown() 失败: %v", err)
	}
}
