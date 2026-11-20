package client

import (
	"context"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

func TestRuleRewriteAndHostBasePath(t *testing.T) {
	var gotPath string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotPath = r.URL.Path
	}))
	defer srv.Close()

	c, err := New(
		WithHosts(srv.URL+"/v1"),
		WithRewriteAll(true),
		WithRule(Rule{
			Name:    "user",
			Pattern: "/api/user/{id}",
			Rewrite: &Rewrite{StripPrefix: "/api"},
		}),
	)
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	if _, err := c.Get(context.Background(), srv.URL+"/api/user/42"); err != nil {
		t.Fatal(err)
	}
	if gotPath != "/v1/user/42" {
		t.Fatalf("path %q", gotPath)
	}
}

func TestHostRewriteAndPreserveHost(t *testing.T) {
	targetHost := mustURL("http://placeholder").Host
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/target":
			if r.Host != targetHost {
				t.Errorf("default Host %q want %q", r.Host, targetHost)
			}
		case "/preserve":
			if r.Host != "logical.example" {
				t.Errorf("preserved Host %q", r.Host)
			}
		}
	}))
	defer srv.Close()
	targetHost = mustURL(srv.URL).Host

	c, err := New(
		WithHosts(srv.URL),
		WithRewriteAll(true),
		WithRule(Rule{Name: "target", Pattern: "/target"}),
		WithRule(Rule{Name: "preserve", Pattern: "/preserve", PreserveHost: true}),
	)
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	req, _ := http.NewRequest(http.MethodGet, "http://logical.example/target", nil)
	if _, err := c.Do(req); err != nil {
		t.Fatal(err)
	}
	req, _ = http.NewRequest(http.MethodGet, "http://logical.example/preserve", nil)
	if _, err := c.Do(req); err != nil {
		t.Fatal(err)
	}
}

func TestDoWithMeta(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {}))
	defer srv.Close()

	c, err := New(
		WithHosts(srv.URL),
		WithRewriteAll(true),
		WithRule(Rule{Name: "user", Pattern: "/api/user/{id}"}),
	)
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	req, _ := http.NewRequest(http.MethodGet, srv.URL+"/api/user/42", nil)
	resp, err := c.DoWithMeta(req)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	if resp.Meta.Rule == nil || resp.Meta.Rule.Name != "user" {
		t.Fatalf("rule %+v", resp.Meta.Rule)
	}
	if resp.Meta.Params.Get("id") != "42" {
		t.Fatalf("params %v", resp.Meta.Params.Values())
	}
	if resp.Meta.Host == nil || resp.Meta.Attempts != 1 || len(resp.Meta.Hops) != 1 {
		t.Fatalf("meta %+v", resp.Meta)
	}
}

func TestNoHostsPassthrough(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte("direct"))
	}))
	defer srv.Close()
	c, err := New()
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	resp, err := c.Get(context.Background(), srv.URL)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	data, _ := resp.Bytes()
	if string(data) != "direct" {
		t.Fatalf("body %q", data)
	}
}

func TestPoliciesDefaultOff(t *testing.T) {
	var hits atomic.Int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		hits.Add(1)
		time.Sleep(20 * time.Millisecond)
	}))
	defer srv.Close()
	c, err := New(WithHosts(srv.URL))
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()

	var wg sync.WaitGroup
	for i := 0; i < 10; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			resp, err := c.Get(context.Background(), srv.URL+"/x")
			if err != nil {
				t.Error(err)
				return
			}
			resp.Body.Close()
		}()
	}
	wg.Wait()
	if hits.Load() != 10 {
		t.Fatalf("cache/coalesce enabled by default: hits=%d", hits.Load())
	}
}

func TestRetryContextCancel(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusServiceUnavailable)
	}))
	defer srv.Close()
	c, err := New(WithHosts(srv.URL), WithRetry(RetryPolicy{
		MaxAttempts: 3,
		StatusCodes: []int{http.StatusServiceUnavailable},
		Backoff:     func(int) time.Duration { return time.Hour },
	}))
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Millisecond)
	defer cancel()
	_, err = c.Get(ctx, srv.URL+"/x")
	if !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("want deadline exceeded, got %v", err)
	}
}

type trackingBody struct {
	reader io.Reader
	closed atomic.Bool
}

func (b *trackingBody) Read(p []byte) (int, error) { return b.reader.Read(p) }
func (b *trackingBody) Close() error               { b.closed.Store(true); return nil }

func TestRoundTripClosesBodyOnGuardDeny(t *testing.T) {
	guard := GuardFunc(func(context.Context, *http.Request) (GuardDecision, error) {
		return GuardDecision{Allowed: false, Status: http.StatusForbidden}, nil
	})
	c, err := New(WithGuard(guard))
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	body := &trackingBody{reader: strings.NewReader("payload")}
	req, _ := http.NewRequest(http.MethodPost, "http://example.com/x", body)
	if _, err := c.Transport().RoundTrip(req); !errors.Is(err, ErrBlocked) {
		t.Fatalf("want ErrBlocked, got %v", err)
	}
	if !body.closed.Load() {
		t.Fatal("request body was not closed on guard denial")
	}
}

func TestRoundTripClosesBodyOnCacheHit(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte("cached"))
	}))
	defer srv.Close()
	c, err := New(WithHosts(srv.URL), WithCache(CachePolicy{TTL: time.Minute}))
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	resp, err := c.Get(context.Background(), srv.URL+"/x")
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	body := &trackingBody{reader: strings.NewReader("payload")}
	req, _ := http.NewRequest(http.MethodGet, srv.URL+"/x", body)
	if _, err := c.Transport().RoundTrip(req); err != nil {
		t.Fatal(err)
	}
	if !body.closed.Load() {
		t.Fatal("request body was not closed on cache hit")
	}
}

func TestSendClosesBodyOnResolveError(t *testing.T) {
	c, err := New()
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	body := &trackingBody{reader: strings.NewReader("payload")}
	if _, err := c.Send(context.Background(), http.MethodPost, "/relative", body); !errors.Is(err, ErrRelativeURL) {
		t.Fatalf("want ErrRelativeURL, got %v", err)
	}
	if !body.closed.Load() {
		t.Fatal("request body was not closed on resolve error")
	}
}

func TestAbsoluteURLBypassesDefaultHosts(t *testing.T) {
	var poolHits, directHits atomic.Int32
	pool := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		poolHits.Add(1)
		_, _ = w.Write([]byte("pool"))
	}))
	defer pool.Close()
	direct := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		directHits.Add(1)
		_, _ = w.Write([]byte("direct"))
	}))
	defer direct.Close()
	c, err := New(WithHosts(pool.URL))
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	resp, err := c.Get(context.Background(), direct.URL+"/x")
	if err != nil {
		t.Fatal(err)
	}
	data, _ := io.ReadAll(resp.Body)
	resp.Body.Close()
	if string(data) != "direct" || poolHits.Load() != 0 || directHits.Load() != 1 {
		t.Fatalf("body %q pool=%d direct=%d", data, poolHits.Load(), directHits.Load())
	}

	forced, err := New(WithHosts(pool.URL), WithRewriteAll(true))
	if err != nil {
		t.Fatal(err)
	}
	defer forced.Close()
	resp, err = forced.Get(context.Background(), direct.URL+"/x")
	if err != nil {
		t.Fatal(err)
	}
	data, _ = io.ReadAll(resp.Body)
	resp.Body.Close()
	if string(data) != "pool" || poolHits.Load() != 1 {
		t.Fatalf("rewrite-all body %q pool=%d", data, poolHits.Load())
	}
}

func TestHostBasePathRedirectMapping(t *testing.T) {
	var mu sync.Mutex
	var paths []string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		paths = append(paths, r.URL.Path)
		mu.Unlock()
		if r.URL.Path == "/base/start" {
			http.Redirect(w, r, "next", http.StatusFound)
			return
		}
		if r.URL.Path == "/base/next" {
			_, _ = w.Write([]byte("ok"))
		}
	}))
	defer srv.Close()
	c, err := New(WithHosts(srv.URL + "/base"))
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	resp, err := c.Get(context.Background(), "/start")
	if err != nil {
		t.Fatal(err)
	}
	data, _ := io.ReadAll(resp.Body)
	resp.Body.Close()
	if string(data) != "ok" {
		t.Fatalf("body %q", data)
	}
	mu.Lock()
	defer mu.Unlock()
	if len(paths) != 2 || paths[0] != "/base/start" || paths[1] != "/base/next" {
		t.Fatalf("paths %v", paths)
	}
}

func TestHostBasePathAndRewriteRedirect(t *testing.T) {
	var mu sync.Mutex
	var paths []string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		paths = append(paths, r.URL.Path)
		mu.Unlock()
		if r.URL.Path == "/v1/user/start" {
			http.Redirect(w, r, "next", http.StatusFound)
			return
		}
		if r.URL.Path == "/v1/user/next" {
			_, _ = w.Write([]byte("ok"))
		}
	}))
	defer srv.Close()
	c, err := New(
		WithHosts(srv.URL+"/v1"),
		WithRule(Rule{Name: "user", Pattern: "/api/user/{id}", Rewrite: &Rewrite{StripPrefix: "/api"}}),
	)
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	resp, err := c.Get(context.Background(), "/api/user/start")
	if err != nil {
		t.Fatal(err)
	}
	data, _ := io.ReadAll(resp.Body)
	resp.Body.Close()
	if string(data) != "ok" {
		t.Fatalf("body %q", data)
	}
	mu.Lock()
	defer mu.Unlock()
	if len(paths) != 2 || paths[0] != "/v1/user/start" || paths[1] != "/v1/user/next" {
		t.Fatalf("paths %v", paths)
	}
}

func TestRuleRewriteRedirectDirect(t *testing.T) {
	var mu sync.Mutex
	var paths []string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		paths = append(paths, r.URL.Path)
		mu.Unlock()
		if r.URL.Path == "/start" {
			http.Redirect(w, r, "next", http.StatusFound)
			return
		}
		_, _ = w.Write([]byte("ok"))
	}))
	defer srv.Close()
	c, err := New(
		WithBaseURL(srv.URL),
		WithRule(Rule{Name: "api", Pattern: "/api/{id}", Rewrite: &Rewrite{StripPrefix: "/api"}}),
	)
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	resp, err := c.Get(context.Background(), "/api/start")
	if err != nil {
		t.Fatal(err)
	}
	data, _ := io.ReadAll(resp.Body)
	resp.Body.Close()
	if string(data) != "ok" {
		t.Fatalf("body %q", data)
	}
	mu.Lock()
	defer mu.Unlock()
	if len(paths) != 2 || paths[0] != "/start" || paths[1] != "/next" {
		t.Fatalf("paths %v", paths)
	}
}

func TestBareHostFastPathMeta(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {}))
	defer srv.Close()
	c, err := New(WithHosts(srv.URL), WithoutCookieJar())
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	if !c.engine.bare.Load() {
		t.Fatal("single-host bare engine expected")
	}
	resp, err := c.Get(context.Background(), "/x")
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	if resp.Meta.Host == nil || resp.Meta.Attempts != 1 || len(resp.Meta.Hops) != 1 {
		t.Fatalf("meta %+v", resp.Meta)
	}
}

func TestBareStateRecomputedAfterUpdates(t *testing.T) {
	c, err := New(WithoutCookieJar())
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	if !c.engine.bare.Load() {
		t.Fatal("new client should use bare path")
	}
	root, _ := url.Parse("http://127.0.0.1:1/")
	if err := c.UpdateHosts(Host{URL: root}); err != nil {
		t.Fatal(err)
	}
	if !c.engine.bare.Load() {
		t.Fatal("simple single host should use bare path")
	}
	base, _ := url.Parse("http://127.0.0.1:1/api")
	if err := c.UpdateHosts(Host{URL: base}); err != nil {
		t.Fatal(err)
	}
	if c.engine.bare.Load() {
		t.Fatal("host base path must disable bare path")
	}
	if err := c.UpdateRules(Rule{Name: "r", Pattern: "/**"}); err != nil {
		t.Fatal(err)
	}
	if c.engine.bare.Load() {
		t.Fatal("rules must disable bare path")
	}
	if err := c.UpdateHosts(Host{URL: root}); err != nil {
		t.Fatal(err)
	}
	if c.engine.bare.Load() {
		t.Fatal("rules must still disable bare path")
	}
	if err := c.UpdateRules(); err != nil {
		t.Fatal(err)
	}
	if !c.engine.bare.Load() {
		t.Fatal("empty rules should restore bare path")
	}
}

func TestRelativeSendRedirectToOtherHostIsDirect(t *testing.T) {
	var finalHits atomic.Int32
	final := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		finalHits.Add(1)
		_, _ = w.Write([]byte("final"))
	}))
	defer final.Close()
	start := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, final.URL+"/final", http.StatusFound)
	}))
	defer start.Close()
	c, err := New(WithHosts(start.URL))
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	resp, err := c.Get(context.Background(), "/start")
	if err != nil {
		t.Fatal(err)
	}
	data, err := resp.Bytes()
	if err != nil {
		t.Fatal(err)
	}
	if string(data) != "final" || finalHits.Load() != 1 {
		t.Fatalf("body %q hits %d", data, finalHits.Load())
	}
}

func TestExplicitHostHeaderPreservedWithHostPool(t *testing.T) {
	var got string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		got = r.Host
	}))
	defer srv.Close()
	c, err := New(WithHosts(srv.URL), WithRetry(RetryPolicy{MaxAttempts: 1}), WithoutCookieJar())
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	resp, err := c.Get(context.Background(), "/x", WithRequestHeader("Host", "custom.example"))
	if err != nil {
		t.Fatal(err)
	}
	if err := resp.Discard(); err != nil {
		t.Fatal(err)
	}
	if got != "custom.example" {
		t.Fatalf("host %q", got)
	}
}

type nilResponseRT struct{ calls atomic.Int32 }

func (r *nilResponseRT) RoundTrip(*http.Request) (*http.Response, error) {
	r.calls.Add(1)
	return nil, nil
}

func TestNilTransportResponseIsError(t *testing.T) {
	for _, host := range []bool{false, true} {
		rt := &nilResponseRT{}
		opts := []Option{WithTransport(rt), WithoutCookieJar()}
		if host {
			opts = append(opts, WithHosts("http://example.com"))
		}
		c, err := New(opts...)
		if err != nil {
			t.Fatal(err)
		}
		_, err = c.Get(context.Background(), "http://example.com/x")
		c.Close()
		if !errors.Is(err, ErrInvalidResponse) {
			t.Fatalf("host=%t error %v", host, err)
		}
		if rt.calls.Load() != 1 {
			t.Fatalf("host=%t calls %d", host, rt.calls.Load())
		}
	}
}

func TestNilTransportResponseNotRetried(t *testing.T) {
	rt := &nilResponseRT{}
	c, err := New(WithTransport(rt), WithRetry(RetryPolicy{MaxAttempts: 3}), WithoutCookieJar())
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	if _, err := c.Get(context.Background(), "http://example.com/x"); !errors.Is(err, ErrInvalidResponse) {
		t.Fatalf("error %v", err)
	}
	if rt.calls.Load() != 1 {
		t.Fatalf("retried nil response %d times", rt.calls.Load())
	}
}

type errorResponseRT struct{ closed *atomic.Bool }

func (r errorResponseRT) RoundTrip(req *http.Request) (*http.Response, error) {
	return &http.Response{
		StatusCode: http.StatusBadGateway,
		Header:     make(http.Header),
		Body:       closeTrackingBody{closed: r.closed},
		Request:    req,
	}, io.ErrUnexpectedEOF
}

func TestTransportResponseAndErrorClosesBody(t *testing.T) {
	var closed atomic.Bool
	c, err := New(WithTransport(errorResponseRT{closed: &closed}), WithRetry(RetryPolicy{MaxAttempts: 1}), WithoutCookieJar())
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	if _, err := c.Get(context.Background(), "http://example.com/x"); err == nil {
		t.Fatal("expected error")
	}
	if !closed.Load() {
		t.Fatal("response body was not closed")
	}
}

type urlErrorRT struct{}

func (urlErrorRT) RoundTrip(req *http.Request) (*http.Response, error) {
	return nil, &url.Error{Op: "Get", URL: req.URL.String(), Err: errors.New("boom")}
}

func TestTransportErrorRedactsURL(t *testing.T) {
	c, err := New(WithTransport(urlErrorRT{}), WithoutCookieJar())
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	_, err = c.Get(context.Background(), "http://user:pass@127.0.0.1:1/path?token=secret")
	if err == nil {
		t.Fatal("expected error")
	}
	text := err.Error()
	for _, secret := range []string{"user:pass", "token=secret", "?token"} {
		if strings.Contains(text, secret) {
			t.Fatalf("error leaked %q: %s", secret, text)
		}
	}
	if !strings.Contains(text, "http://127.0.0.1:1/path") {
		t.Fatalf("safe URL missing: %s", text)
	}
	var urlErr *url.Error
	if !errors.As(err, &urlErr) {
		t.Fatalf("url.Error type lost: %T", err)
	}
}

func TestTargetURLRejectsBasePathEscapes(t *testing.T) {
	host := &Host{URL: mustURL("http://upstream/api")}
	if _, err := targetURL(mustURL("http://logical/../admin"), host, nil); !errors.Is(err, ErrAmbiguousPath) {
		t.Fatalf("dot-dot escape error = %v, want ErrAmbiguousPath", err)
	}
	target, err := targetURL(mustURL("http://logical/x/../admin"), host, nil)
	if err != nil {
		t.Fatalf("in-base dot-dot: %v", err)
	}
	if target.Path != "/api/admin" || target.RawPath != "/api/admin" {
		t.Fatalf("in-base dot-dot target = path %q raw %q, want /api/admin", target.Path, target.RawPath)
	}
	target, err = targetURL(mustURL("http://logical//x"), host, nil)
	if err != nil {
		t.Fatalf("duplicate slash: %v", err)
	}
	if target.Path != "/api/x" {
		t.Fatalf("duplicate slash target = %q, want /api/x", target.Path)
	}
	if _, err := targetURL(mustURL("http://logical/start"), host, &Rule{Rewrite: &Rewrite{AddPrefix: "/../admin"}}); !errors.Is(err, ErrAmbiguousPath) {
		t.Fatalf("rewrite escape error = %v, want ErrAmbiguousPath", err)
	}
	target, err = targetURL(mustURL("http://logical/start"), host, &Rule{Rewrite: &Rewrite{AddPrefix: "/v2"}})
	if err != nil {
		t.Fatalf("in-base rewrite: %v", err)
	}
	if target.Path != "/api/v2/start" {
		t.Fatalf("rewrite target = %q, want /api/v2/start", target.Path)
	}
	if _, err := directTarget(mustURL("http://logical/start"), &Rule{Rewrite: &Rewrite{AddPrefix: "/../admin"}}); !errors.Is(err, ErrAmbiguousPath) {
		t.Fatalf("direct rewrite escape error = %v, want ErrAmbiguousPath", err)
	}
}

func TestHostBasePathRedirectPathAbsolute(t *testing.T) {
	var paths []string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		paths = append(paths, r.URL.Path)
		switch r.URL.Path {
		case "/base/start":
			http.Redirect(w, r, "/base/next", http.StatusFound)
		case "/base/next":
			_, _ = w.Write([]byte("ok"))
		default:
			http.NotFound(w, r)
		}
	}))
	defer srv.Close()
	c, err := New(WithHosts(srv.URL+"/base"), WithoutCookieJar())
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	resp, err := c.Get(context.Background(), "/start")
	if err != nil {
		t.Fatal(err)
	}
	data, err := resp.Bytes()
	if err != nil {
		t.Fatal(err)
	}
	if string(data) != "ok" {
		t.Fatalf("body %q paths %v", data, paths)
	}
}
