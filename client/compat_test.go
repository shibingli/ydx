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
