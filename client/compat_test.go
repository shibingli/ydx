package client

import (
	"compress/gzip"
	"context"
	"crypto/x509"
	"errors"
	"io"
	"net/http"
	"net/http/cookiejar"
	"net/http/httptest"
	"net/url"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

func TestRedirectSemantics(t *testing.T) {
	type seen struct {
		method string
		body   string
	}
	var mu sync.Mutex
	var got []seen
	var target string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/target" {
			body, _ := io.ReadAll(r.Body)
			mu.Lock()
			got = append(got, seen{method: r.Method, body: string(body)})
			mu.Unlock()
			return
		}
		w.Header().Set("Location", target)
		w.WriteHeader(http.StatusFound)
	}))
	defer srv.Close()
	target = srv.URL + "/target"

	c, err := New(WithHosts(srv.URL))
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	resp, err := c.Post(context.Background(), srv.URL+"/start", []byte("payload"))
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	mu.Lock()
	first := got[0]
	mu.Unlock()
	if first.method != http.MethodGet || first.body != "" {
		t.Fatalf("302 POST became %s %q", first.method, first.body)
	}

	srv307 := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/target" {
			body, _ := io.ReadAll(r.Body)
			mu.Lock()
			got = append(got, seen{method: r.Method, body: string(body)})
			mu.Unlock()
			return
		}
		w.Header().Set("Location", "/target")
		w.WriteHeader(http.StatusTemporaryRedirect)
	}))
	defer srv307.Close()
	c307, err := New(WithHosts(srv307.URL))
	if err != nil {
		t.Fatal(err)
	}
	defer c307.Close()
	resp, err = c307.Post(context.Background(), srv307.URL+"/start", []byte("payload"))
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	mu.Lock()
	last := got[len(got)-1]
	mu.Unlock()
	if last.method != http.MethodPost || last.body != "payload" {
		t.Fatalf("307 POST became %s %q", last.method, last.body)
	}
}

func TestCookieJarAndCheckRedirect(t *testing.T) {
	jar, err := cookiejar.New(nil)
	if err != nil {
		t.Fatal(err)
	}
	var mu sync.Mutex
	var cookies []string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		cookies = append(cookies, r.Header.Get("Cookie"))
		mu.Unlock()
		http.SetCookie(w, &http.Cookie{Name: "session", Value: "abc", Path: "/"})
		if r.URL.Path == "/redirect" {
			http.Redirect(w, r, "/final", http.StatusFound)
		}
	}))
	defer srv.Close()
	c, err := New(WithHosts(srv.URL), WithCookieJar(jar))
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	if _, err := c.Get(context.Background(), srv.URL+"/set"); err != nil {
		t.Fatal(err)
	}
	if _, err := c.Get(context.Background(), srv.URL+"/redirect"); err != nil {
		t.Fatal(err)
	}
	mu.Lock()
	gotCookies := append([]string(nil), cookies...)
	mu.Unlock()
	if len(gotCookies) < 3 || !strings.Contains(gotCookies[1], "session=abc") {
		t.Fatalf("cookies %v", gotCookies)
	}

	stop := func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }
	cstop, err := New(WithHosts(srv.URL), WithCheckRedirect(stop), WithTimeout(5*time.Second))
	if err != nil {
		t.Fatal(err)
	}
	defer cstop.Close()
	resp, err := cstop.Get(context.Background(), srv.URL+"/redirect")
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusFound {
		t.Fatalf("status %d", resp.StatusCode)
	}
}

func TestRedirectCookieCarry(t *testing.T) {
	for _, status := range []int{301, 302, 303, 307, 308} {
		status := status
		t.Run(http.StatusText(status), func(t *testing.T) {
			jar, err := cookiejar.New(nil)
			if err != nil {
				t.Fatal(err)
			}
			var mu sync.Mutex
			var finalCookie, finalMethod string
			srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				switch r.URL.Path {
				case "/start":
					http.SetCookie(w, &http.Cookie{Name: "first", Value: "1", Path: "/"})
					w.Header().Set("Location", "/middle")
					w.WriteHeader(status)
				case "/middle":
					if !strings.Contains(r.Header.Get("Cookie"), "first=1") {
						t.Errorf("middle missing first cookie: %q", r.Header.Get("Cookie"))
					}
					http.SetCookie(w, &http.Cookie{Name: "second", Value: "2", Path: "/"})
					w.Header().Set("Location", "/final")
					w.WriteHeader(status)
				case "/final":
					mu.Lock()
					finalCookie = r.Header.Get("Cookie")
					finalMethod = r.Method
					mu.Unlock()
				}
			}))
			defer srv.Close()
			c, err := New(WithHosts(srv.URL), WithCookieJar(jar))
			if err != nil {
				t.Fatal(err)
			}
			defer c.Close()
			resp, err := c.Post(context.Background(), srv.URL+"/start", []byte("body"))
			if err != nil {
				t.Fatal(err)
			}
			resp.Body.Close()
			mu.Lock()
			cookie, method := finalCookie, finalMethod
			mu.Unlock()
			if !strings.Contains(cookie, "first=1") || !strings.Contains(cookie, "second=2") {
				t.Fatalf("final cookie %q", cookie)
			}
			wantMethod := http.MethodGet
			if status == http.StatusTemporaryRedirect || status == http.StatusPermanentRedirect {
				wantMethod = http.MethodPost
			}
			if method != wantMethod {
				t.Fatalf("final method %s, want %s", method, wantMethod)
			}
		})
	}
}

func TestDefaultCookieJarCarriesRedirectCookies(t *testing.T) {
	var mu sync.Mutex
	var finalCookie string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/start" {
			http.SetCookie(w, &http.Cookie{Name: "default", Value: "1", Path: "/"})
			w.Header().Set("Location", "/final")
			w.WriteHeader(http.StatusFound)
			return
		}
		mu.Lock()
		finalCookie = r.Header.Get("Cookie")
		mu.Unlock()
	}))
	defer srv.Close()
	c, err := New(WithHosts(srv.URL))
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	resp, err := c.Get(context.Background(), srv.URL+"/start")
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	mu.Lock()
	cookie := finalCookie
	mu.Unlock()
	if !strings.Contains(cookie, "default=1") {
		t.Fatalf("default jar did not carry cookie: %q", cookie)
	}

	mu.Lock()
	finalCookie = ""
	mu.Unlock()
	noJar, err := New(WithHosts(srv.URL), WithoutCookieJar())
	if err != nil {
		t.Fatal(err)
	}
	defer noJar.Close()
	resp, err = noJar.Get(context.Background(), srv.URL+"/start")
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	mu.Lock()
	cookie = finalCookie
	mu.Unlock()
	if strings.Contains(cookie, "default=1") {
		t.Fatalf("WithoutCookieJar carried cookie: %q", cookie)
	}
}

func TestDoNilHeaderWithJar(t *testing.T) {
	var got string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		got = r.Header.Get("Cookie")
	}))
	defer srv.Close()
	jar, _ := cookiejar.New(nil)
	u, _ := url.Parse(srv.URL)
	jar.SetCookies(u, []*http.Cookie{{Name: "x", Value: "1", Path: "/"}})
	c, err := New(WithHosts(srv.URL), WithCookieJar(jar))
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	req, _ := http.NewRequest(http.MethodGet, srv.URL, nil)
	req.Header = nil
	resp, err := c.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	if !strings.Contains(got, "x=1") {
		t.Fatalf("cookie %q", got)
	}
}

func TestRedirectMetaHops(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/start" {
			w.Header().Set("Location", "/final")
			w.WriteHeader(http.StatusFound)
		}
	}))
	defer srv.Close()
	c, err := New(WithHosts(srv.URL))
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	resp, err := c.Get(context.Background(), srv.URL+"/start")
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	if len(resp.Meta.Hops) != 2 {
		t.Fatalf("hops %+v", resp.Meta.Hops)
	}
	if resp.Meta.Hops[0].Status != http.StatusFound || resp.Meta.Hops[1].Status != http.StatusOK {
		t.Fatalf("hop statuses %+v", resp.Meta.Hops)
	}
}

func TestHTTP2(t *testing.T) {
	srv := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte(r.Proto))
	}))
	srv.EnableHTTP2 = true
	srv.StartTLS()
	defer srv.Close()
	pool := x509.NewCertPool()
	pool.AddCert(srv.Certificate())
	c, err := New(WithHosts(srv.URL), WithTLS(TLSConfig{RootCAs: pool, DisableSystemRoots: true}))
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	resp, err := c.Get(context.Background(), srv.URL)
	if err != nil {
		t.Fatal(err)
	}
	body, _ := io.ReadAll(resp.Body)
	resp.Body.Close()
	if resp.ProtoMajor != 2 || string(body) != "HTTP/2.0" {
		t.Fatalf("proto %s body %q", resp.Proto, body)
	}
}

func TestH2CDoesNotBreakHTTPS(t *testing.T) {
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte("ok"))
	}))
	defer srv.Close()
	pool := x509.NewCertPool()
	pool.AddCert(srv.Certificate())
	c, err := New(
		WithHosts(srv.URL),
		WithTLS(TLSConfig{RootCAs: pool, DisableSystemRoots: true}),
		WithH2C(true),
	)
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	resp, err := c.Get(context.Background(), srv.URL)
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
}

func TestGzipAutoDecodeAndCache(t *testing.T) {
	const payload = `{"ok":true}`
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.Header().Set("Content-Encoding", "gzip")
		gz := gzip.NewWriter(w)
		_, _ = gz.Write([]byte(payload))
		_ = gz.Close()
	}))
	defer srv.Close()
	c, err := New(WithHosts(srv.URL), WithCache(CachePolicy{TTL: time.Minute}))
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	for i := 0; i < 2; i++ {
		resp, err := c.Get(context.Background(), srv.URL+"/gzip")
		if err != nil {
			t.Fatal(err)
		}
		data, _ := io.ReadAll(resp.Body)
		resp.Body.Close()
		if string(data) != payload {
			t.Fatalf("attempt %d body %q", i, data)
		}
		if resp.Header.Get("Content-Encoding") != "" {
			t.Fatalf("attempt %d content-encoding %q", i, resp.Header.Get("Content-Encoding"))
		}
	}
}

func TestTrailersAndNoBody(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/empty" {
			w.WriteHeader(http.StatusNoContent)
			return
		}
		w.Header().Set("Trailer", "X-Checksum")
		_, _ = w.Write([]byte("body"))
		w.Header().Set("X-Checksum", "ok")
	}))
	defer srv.Close()
	c, err := New(WithHosts(srv.URL))
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	resp, err := c.Get(context.Background(), srv.URL+"/trailer")
	if err != nil {
		t.Fatal(err)
	}
	data, _ := io.ReadAll(resp.Body)
	resp.Body.Close()
	if string(data) != "body" || resp.Trailer.Get("X-Checksum") != "ok" {
		t.Fatalf("body %q trailer %v", data, resp.Trailer)
	}
	resp, err = c.Get(context.Background(), srv.URL+"/empty")
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	if resp.Body != http.NoBody || resp.ContentLength != 0 {
		t.Fatalf("204 body %T length %d", resp.Body, resp.ContentLength)
	}
}

type closeTrackingBody struct {
	closed *atomic.Bool
}

func (b closeTrackingBody) Read([]byte) (int, error) { return 0, io.EOF }
func (b closeTrackingBody) Close() error {
	b.closed.Store(true)
	return nil
}

func TestDoClosesBodyOnEarlyError(t *testing.T) {
	c, err := New(WithoutCookieJar())
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	var closed atomic.Bool
	req, err := http.NewRequest(http.MethodPost, "/relative", closeTrackingBody{closed: &closed})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := c.Do(req); !errors.Is(err, ErrRelativeURL) {
		t.Fatalf("error %v", err)
	}
	if !closed.Load() {
		t.Fatal("body was not closed")
	}
}

func TestRequestClosePreservedOnClone(t *testing.T) {
	var closed atomic.Bool
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		closed.Store(r.Close)
	}))
	defer srv.Close()
	c, err := New(WithHosts(srv.URL), WithRetry(RetryPolicy{MaxAttempts: 1}), WithoutCookieJar())
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	req, _ := http.NewRequest(http.MethodGet, srv.URL+"/x", nil)
	req.Close = true
	resp, err := c.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	_ = resp.Body.Close()
	if !closed.Load() {
		t.Fatal("request Close was not preserved")
	}
}

func TestCheckRedirectPanicIsolated(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, "/next", http.StatusFound)
	}))
	defer srv.Close()
	c, err := New(WithoutCookieJar(), WithCheckRedirect(func(*http.Request, []*http.Request) error {
		panic("boom")
	}))
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	if _, err := c.Get(context.Background(), srv.URL+"/start"); !errors.Is(err, ErrHookPanic) {
		t.Fatalf("error %v", err)
	}
}

func TestDefaultLazyJarRedirectCookies(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/start":
			http.SetCookie(w, &http.Cookie{Name: "session", Value: "lazy", Path: "/"})
			http.Redirect(w, r, "/final", http.StatusFound)
		case "/final":
			if !strings.Contains(r.Header.Get("Cookie"), "session=lazy") {
				t.Errorf("cookie missing: %q", r.Header.Get("Cookie"))
			}
			_, _ = w.Write([]byte("ok"))
		}
	}))
	defer srv.Close()
	c, err := New(WithHosts(srv.URL))
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	resp, err := c.Get(context.Background(), srv.URL+"/start")
	if err != nil {
		t.Fatal(err)
	}
	data, err := resp.Bytes()
	if err != nil {
		t.Fatal(err)
	}
	if string(data) != "ok" {
		t.Fatalf("body %q", data)
	}
}

func TestConnectMethodRealTransport(t *testing.T) {
	var gotMethod, gotHost string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotMethod, gotHost = r.Method, r.Host
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("tunnel"))
	}))
	defer srv.Close()
	c, err := New(WithHosts(srv.URL), WithRetry(RetryPolicy{MaxAttempts: 1}), WithoutCookieJar())
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	resp, err := c.Connect(context.Background(), srv.URL, nil)
	if err != nil {
		t.Fatal(err)
	}
	data, err := resp.Bytes()
	if err != nil {
		t.Fatal(err)
	}
	if gotMethod != http.MethodConnect || string(data) != "tunnel" {
		t.Fatalf("method %q body %q", gotMethod, data)
	}
	if gotHost == "" {
		t.Fatal("CONNECT authority missing")
	}
}

func TestRedirectErrorRedactsTargetURL(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, "/target?token=secret", http.StatusFound)
	}))
	defer srv.Close()
	c, err := New(WithoutCookieJar(), WithCheckRedirect(func(*http.Request, []*http.Request) error {
		return errors.New("stop")
	}))
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	if _, err := c.Get(context.Background(), srv.URL+"/start"); err == nil {
		t.Fatal("expected redirect error")
	} else if strings.Contains(err.Error(), "token=secret") {
		t.Fatalf("redirect target leaked: %s", err)
	}
}

func TestRuleHeadersNotReaddedOnCrossHostRedirect(t *testing.T) {
	var gotAuth atomic.Value
	target := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotAuth.Store(r.Header.Get("Authorization"))
		_, _ = w.Write([]byte("ok"))
	}))
	defer target.Close()
	origin := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, target.URL+"/steal", http.StatusFound)
	}))
	defer origin.Close()
	c, err := New(
		WithRule(Rule{
			Pattern: "/**",
			Headers: http.Header{"Authorization": {"Bearer secret"}},
		}),
		WithoutCookieJar(),
	)
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	resp, err := c.Get(context.Background(), origin.URL+"/start")
	if err != nil {
		t.Fatal(err)
	}
	_ = resp.Body.Close()
	if got := gotAuth.Load(); got != nil && got.(string) != "" {
		t.Fatalf("rule Authorization leaked to redirect target: %q", got)
	}
}

// TestRuleCredentialHeadersNotReaddedOnCrossOriginRedirect checks that every rule header, not
// only the standard sensitive ones, is dropped when a redirect changes origin. | TestRuleCredentialHeadersNotReaddedOnCrossOriginRedirect
// 校验跨源重定向丢弃全部规则头，而不只是标准敏感头。
func TestRuleCredentialHeadersNotReaddedOnCrossOriginRedirect(t *testing.T) {
	var gotAuth, gotKey atomic.Value
	target := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotAuth.Store(r.Header.Get("Authorization"))
		gotKey.Store(r.Header.Get("X-API-Key"))
		_, _ = w.Write([]byte("ok"))
	}))
	defer target.Close()
	origin := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, target.URL+"/steal", http.StatusFound)
	}))
	defer origin.Close()
	c, err := New(
		WithRule(Rule{
			Pattern: "/**",
			Headers: http.Header{
				"Authorization": {"Bearer secret"},
				"X-API-Key":     {"api-secret"},
			},
		}),
		WithoutCookieJar(),
	)
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	resp, err := c.Get(context.Background(), origin.URL+"/start")
	if err != nil {
		t.Fatal(err)
	}
	_ = resp.Body.Close()
	if got := gotAuth.Load(); got != nil && got.(string) != "" {
		t.Fatalf("rule Authorization leaked across origins: %q", got)
	}
	if got := gotKey.Load(); got != nil && got.(string) != "" {
		t.Fatalf("rule X-API-Key leaked across origins: %q", got)
	}
}

// schemeRedirectTransport simulates an https request redirected to plain http on the same host. |
// schemeRedirectTransport 模拟同主机 https 请求重定向到明文 http。
type schemeRedirectTransport struct {
	mu   sync.Mutex
	auth []string
	key  []string
}

// RoundTrip returns one redirect followed by a successful response. | RoundTrip 返回一次重定向与
// 一次成功响应。
func (rt *schemeRedirectTransport) RoundTrip(req *http.Request) (*http.Response, error) {
	rt.mu.Lock()
	first := len(rt.auth) == 0
	rt.auth = append(rt.auth, req.Header.Get("Authorization"))
	rt.key = append(rt.key, req.Header.Get("X-API-Key"))
	rt.mu.Unlock()
	header := make(http.Header)
	if first {
		header.Set("Location", "http://example.com/next")
		return &http.Response{StatusCode: http.StatusFound, Header: header, Body: http.NoBody, Request: req}, nil
	}
	header.Set("Content-Type", "text/plain")
	return &http.Response{StatusCode: http.StatusOK, Header: header, Body: http.NoBody, Request: req}, nil
}

// TestSchemeDowngradeRedirectDropsRuleCredentials checks that an https to http redirect on the
// same host does not re-add rule credentials. | TestSchemeDowngradeRedirectDropsRuleCredentials
// 校验同主机 https 到 http 的重定向不会重新注入规则凭据。
func TestSchemeDowngradeRedirectDropsRuleCredentials(t *testing.T) {
	rt := &schemeRedirectTransport{}
	c, err := New(
		WithTransport(rt),
		WithRule(Rule{
			Pattern: "/**",
			Headers: http.Header{
				"Authorization": {"Bearer secret"},
				"X-API-Key":     {"api-secret"},
			},
		}),
		WithoutCookieJar(),
	)
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	resp, err := c.Get(context.Background(), "https://example.com/start")
	if err != nil {
		t.Fatal(err)
	}
	_ = resp.Body.Close()
	if len(rt.auth) != 2 {
		t.Fatalf("redirect hops = %d, want 2", len(rt.auth))
	}
	if rt.auth[0] != "Bearer secret" || rt.key[0] != "api-secret" {
		t.Fatalf("first hop credentials = %q/%q, want rule injection", rt.auth[0], rt.key[0])
	}
	if rt.auth[1] != "" || rt.key[1] != "" {
		t.Fatalf("downgrade hop leaked credentials: auth=%q key=%q", rt.auth[1], rt.key[1])
	}
}
