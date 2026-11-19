package client

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
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

func TestForwardStripsProxyAuthorization(t *testing.T) {
	var got string
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		got = r.Header.Get("Proxy-Authorization")
	}))
	defer upstream.Close()
	c, err := New(WithHosts(upstream.URL))
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	in := httptest.NewRequest(http.MethodGet, upstream.URL+"/x", nil)
	in.Header.Set("Proxy-Authorization", "Basic c2VjcmV0")
	resp, err := c.Forward(context.Background(), in)
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	if got != "" {
		t.Fatalf("proxy credentials leaked: %q", got)
	}
}

func TestForwardTrailers(t *testing.T) {
	var trailer string
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = io.Copy(io.Discard, r.Body)
		trailer = r.Trailer.Get("X-Sum")
	}))
	defer upstream.Close()
	c, err := New(WithHosts(upstream.URL))
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	in := httptest.NewRequest(http.MethodPost, "/x", strings.NewReader("payload"))
	in.Header.Set("Trailer", "X-Sum")
	in.Trailer = http.Header{"X-Sum": {"42"}}
	in.ContentLength = -1
	rec := httptest.NewRecorder()
	c.Handler().ServeHTTP(rec, in)
	if rec.Code != http.StatusOK || trailer != "42" {
		t.Fatalf("status %d trailer %q", rec.Code, trailer)
	}
}

func TestForwardRelativeHostHeaderIsNotATarget(t *testing.T) {
	var hits atomic.Int32
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		hits.Add(1)
	}))
	defer upstream.Close()
	c, err := New()
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	req := httptest.NewRequest(http.MethodGet, "/x", nil)
	req.Host = strings.TrimPrefix(upstream.URL, "http://")
	if _, err := c.Forward(context.Background(), req); !errors.Is(err, ErrNoHosts) {
		t.Fatalf("want ErrNoHosts, got %v", err)
	}
	if hits.Load() != 0 {
		t.Fatal("inbound Host was used as a proxy target")
	}
}

func TestForwardLargeResponseDefaultUnlimited(t *testing.T) {
	payload := strings.Repeat("x", 9<<20)
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte(payload))
	}))
	defer upstream.Close()
	c, err := New(WithHosts(upstream.URL))
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	rec := httptest.NewRecorder()
	in := httptest.NewRequest(http.MethodGet, upstream.URL+"/x", nil)
	c.Handler().ServeHTTP(rec, in)
	if rec.Code != http.StatusOK || rec.Body.Len() != len(payload) {
		t.Fatalf("status %d size %d", rec.Code, rec.Body.Len())
	}
}

func TestForwardMaxBodyBytes(t *testing.T) {
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte(strings.Repeat("x", 100)))
	}))
	defer upstream.Close()
	c, err := New(WithHosts(upstream.URL))
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	in := httptest.NewRequest(http.MethodGet, upstream.URL+"/x", nil)
	if _, err := c.Forward(context.Background(), in, WithForwardMaxBodyBytes(10)); !errors.Is(err, ErrResponseTooLarge) {
		t.Fatalf("want ErrResponseTooLarge, got %v", err)
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

func TestForwardUnknownBodyLimit(t *testing.T) {
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/octet-stream")
		w.(http.Flusher).Flush()
		_, _ = w.Write(bytes.Repeat([]byte("x"), 100))
	}))
	defer upstream.Close()
	c, err := New()
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	req := httptest.NewRequest(http.MethodGet, upstream.URL+"/data", nil)
	resp, err := c.Forward(context.Background(), req,
		WithForwardMaxBodyBytes(10), WithForwardAllowAbsoluteURLs(true))
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	if resp.ContentLength >= 0 {
		t.Fatalf("expected unknown length, got %d", resp.ContentLength)
	}
	data, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Fatal(err)
	}
	if len(data) != 10 {
		t.Fatalf("body length %d", len(data))
	}
}

func TestForwardRuleHeaderTimeout(t *testing.T) {
	c, err := New(WithTransport(blockingRoundTripper{}), WithHosts("http://svc"), WithRule(Rule{
		Name: "/**", Pattern: "/**", Timeout: 20 * time.Millisecond,
	}))
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	rec := httptest.NewRecorder()
	start := time.Now()
	c.Handler().ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "http://svc/x", nil))
	if rec.Code != http.StatusGatewayTimeout {
		t.Fatalf("code %d body %q", rec.Code, rec.Body.String())
	}
	if elapsed := time.Since(start); elapsed > time.Second {
		t.Fatalf("header timeout took %v", elapsed)
	}
}

func TestForwardRuleTimeoutStopsAtHeaders(t *testing.T) {
	c, err := New(WithTransport(headerThenSlowBodyRoundTripper{}), WithHosts("http://svc"), WithRule(Rule{
		Name: "/**", Pattern: "/**", Timeout: 20 * time.Millisecond,
	}))
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	req := httptest.NewRequest(http.MethodGet, "http://svc/x", nil)
	resp, err := c.Forward(context.Background(), req)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	data, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Fatal(err)
	}
	if string(data) != "body" {
		t.Fatalf("body %q", data)
	}
}

type blockingRoundTripper struct{}

func (blockingRoundTripper) RoundTrip(req *http.Request) (*http.Response, error) {
	<-req.Context().Done()
	return nil, req.Context().Err()
}

type headerThenSlowBodyRoundTripper struct{}

func (headerThenSlowBodyRoundTripper) RoundTrip(req *http.Request) (*http.Response, error) {
	return &http.Response{
		Status:        "200 OK",
		StatusCode:    http.StatusOK,
		Proto:         "HTTP/1.1",
		ProtoMajor:    1,
		ProtoMinor:    1,
		Header:        make(http.Header),
		ContentLength: -1,
		Body:          &headerThenSlowBody{ctx: req.Context()},
		Request:       req,
	}, nil
}

type headerThenSlowBody struct {
	ctx  context.Context
	read bool
}

func (b *headerThenSlowBody) Read(p []byte) (int, error) {
	if !b.read {
		b.read = true
		time.Sleep(60 * time.Millisecond)
	}
	if err := b.ctx.Err(); err != nil {
		return 0, err
	}
	return copy(p, "body"), io.EOF
}

func (b *headerThenSlowBody) Close() error { return nil }

func TestForwardPreservesAllForwardedForValues(t *testing.T) {
	var got []string
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		got = append([]string(nil), r.Header.Values("X-Forwarded-For")...)
	}))
	defer upstream.Close()
	c, err := New(WithHosts(upstream.URL))
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	in := httptest.NewRequest(http.MethodGet, upstream.URL+"/x", nil)
	in.Header.Add("X-Forwarded-For", "198.51.100.1")
	in.Header.Add("X-Forwarded-For", "203.0.113.2")
	resp, err := c.Forward(context.Background(), in)
	if err != nil {
		t.Fatal(err)
	}
	_ = resp.Body.Close()
	if len(got) != 1 || !strings.Contains(got[0], "198.51.100.1") ||
		!strings.Contains(got[0], "203.0.113.2") || !strings.Contains(got[0], "192.0.2.1") {
		t.Fatalf("X-Forwarded-For %v", got)
	}
}

func TestForwardNetworkPathURL(t *testing.T) {
	var hit atomic.Int32
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		hit.Add(1)
		_, _ = w.Write([]byte("ok"))
	}))
	defer upstream.Close()
	target, _ := url.Parse(upstream.URL)
	c, err := New(WithoutCookieJar())
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	in := httptest.NewRequest(http.MethodGet, upstream.URL+"/x", nil)
	in.URL = &url.URL{Path: "/x", Host: target.Host}
	in.Host = ""
	resp, err := c.Forward(context.Background(), in, WithForwardAllowAbsoluteURLs(true))
	if err != nil {
		t.Fatal(err)
	}
	data, _ := io.ReadAll(resp.Body)
	_ = resp.Body.Close()
	if string(data) != "ok" || hit.Load() != 1 {
		t.Fatalf("body %q hits %d", data, hit.Load())
	}
}

func TestForwardRejectsAbsoluteTargetByDefault(t *testing.T) {
	var hits atomic.Int32
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		hits.Add(1)
	}))
	defer upstream.Close()
	c, err := New(WithoutCookieJar())
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	in := httptest.NewRequest(http.MethodGet, upstream.URL+"/x", nil)
	if _, err := c.Forward(context.Background(), in); !errors.Is(err, ErrAbsoluteTarget) {
		t.Fatalf("want ErrAbsoluteTarget, got %v", err)
	}
	if hits.Load() != 0 {
		t.Fatal("absolute target reached upstream without opt-in")
	}
	rec := httptest.NewRecorder()
	c.Handler().ServeHTTP(rec, httptest.NewRequest(http.MethodGet, upstream.URL+"/x", nil))
	if rec.Code != http.StatusForbidden {
		t.Fatalf("handler status %d", rec.Code)
	}
}

func TestForwardAllowsAbsoluteTargetWithOption(t *testing.T) {
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte("ok"))
	}))
	defer upstream.Close()
	c, err := New(WithoutCookieJar())
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	in := httptest.NewRequest(http.MethodGet, upstream.URL+"/x", nil)
	resp, err := c.Forward(context.Background(), in, WithForwardAllowAbsoluteURLs(true))
	if err != nil {
		t.Fatal(err)
	}
	data, err := io.ReadAll(resp.Body)
	_ = resp.Body.Close()
	if err != nil {
		t.Fatal(err)
	}
	if string(data) != "ok" {
		t.Fatalf("body %q", data)
	}
}

func TestForwardDefaultDoesNotRetryAcrossHosts(t *testing.T) {
	var firstHits, secondHits atomic.Int32
	first := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		firstHits.Add(1)
		w.WriteHeader(http.StatusServiceUnavailable)
	}))
	defer first.Close()
	second := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		secondHits.Add(1)
		_, _ = w.Write([]byte("second"))
	}))
	defer second.Close()
	c, err := New(WithHosts(first.URL, second.URL))
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	in := httptest.NewRequest(http.MethodGet, first.URL+"/x", nil)
	resp, err := c.Forward(context.Background(), in)
	if err != nil {
		t.Fatal(err)
	}
	_ = resp.Body.Close()
	if resp.StatusCode != http.StatusServiceUnavailable {
		t.Fatalf("status %d", resp.StatusCode)
	}
	if firstHits.Load()+secondHits.Load() != 1 {
		t.Fatalf("default Forward retried: %d/%d", firstHits.Load(), secondHits.Load())
	}
}

type switchingRT struct{}

func (switchingRT) RoundTrip(req *http.Request) (*http.Response, error) {
	return &http.Response{
		Status:     "101 Switching Protocols",
		StatusCode: http.StatusSwitchingProtocols,
		Proto:      "HTTP/1.1",
		ProtoMajor: 1,
		ProtoMinor: 1,
		Header:     http.Header{"Upgrade": {"websocket"}},
		Body:       http.NoBody,
		Request:    req,
	}, nil
}

func TestForwardRejectsUpstream101(t *testing.T) {
	c, err := New(WithTransport(switchingRT{}), WithHosts("http://svc"), WithoutCookieJar())
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	in := httptest.NewRequest(http.MethodGet, "http://svc/x", nil)
	if _, err := c.Forward(context.Background(), in); !errors.Is(err, ErrUpgradeUnsupported) {
		t.Fatalf("error %v", err)
	}
	rec := httptest.NewRecorder()
	c.Handler().ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "http://svc/x", nil))
	if rec.Code != http.StatusNotImplemented {
		t.Fatalf("handler status %d", rec.Code)
	}
}

func TestForwardRelativeRejectsEmptyHostPool(t *testing.T) {
	empty, err := NewHostSet()
	if err != nil {
		t.Fatal(err)
	}
	c, err := New(WithHostSet(empty), WithoutCookieJar())
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	in := httptest.NewRequest(http.MethodGet, "/x", nil)
	in.Host = "svc"
	if _, err := c.Forward(context.Background(), in); !errors.Is(err, ErrNoHosts) {
		t.Fatalf("error %v", err)
	}
}

type notModifiedRT struct{}

func (notModifiedRT) RoundTrip(req *http.Request) (*http.Response, error) {
	return &http.Response{
		Status:        "304 Not Modified",
		StatusCode:    http.StatusNotModified,
		Proto:         "HTTP/1.1",
		ProtoMajor:    1,
		ProtoMinor:    1,
		Header:        http.Header{"Content-Length": {"999"}},
		ContentLength: 999,
		Body:          http.NoBody,
		Request:       req,
	}, nil
}

func TestForwardMaxBodyIgnoresNotModified(t *testing.T) {
	c, err := New(WithTransport(notModifiedRT{}), WithHosts("http://svc"), WithoutCookieJar())
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	in := httptest.NewRequest(http.MethodGet, "http://svc/x", nil)
	resp, err := c.Forward(context.Background(), in, WithForwardMaxBodyBytes(10))
	if err != nil {
		t.Fatal(err)
	}
	_ = resp.Body.Close()
	if resp.StatusCode != http.StatusNotModified {
		t.Fatalf("status %d", resp.StatusCode)
	}
}

func TestForwardUnannouncedTrailer(t *testing.T) {
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("body"))
		w.(http.Flusher).Flush()
		w.Header().Set(http.TrailerPrefix+"X-Foo", "bar")
	}))
	defer upstream.Close()
	c, err := New(WithHosts(upstream.URL), WithoutCookieJar())
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	down := httptest.NewServer(c.Handler())
	defer down.Close()
	resp, err := http.Get(down.URL + "/x")
	if err != nil {
		t.Fatal(err)
	}
	data, err := io.ReadAll(resp.Body)
	_ = resp.Body.Close()
	if err != nil {
		t.Fatal(err)
	}
	if string(data) != "body" {
		t.Fatalf("body %q", data)
	}
	if got := resp.Trailer.Get("X-Foo"); got != "bar" {
		t.Fatalf("trailer %q", got)
	}
}

func TestForwardSanitizesSpoofedForwardedHeaders(t *testing.T) {
	type forwarded struct {
		proto     string
		host      string
		forwarded string
	}
	seen := make(chan forwarded, 1)
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		seen <- forwarded{
			proto:     r.Header.Get("X-Forwarded-Proto"),
			host:      r.Header.Get("X-Forwarded-Host"),
			forwarded: r.Header.Get("Forwarded"),
		}
		w.WriteHeader(http.StatusNoContent)
	}))
	defer upstream.Close()
	c, err := New(WithHosts(upstream.URL), WithoutCookieJar())
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	in := httptest.NewRequest(http.MethodGet, "http://svc/x", nil)
	in.Host = "svc"
	in.Header.Set("X-Forwarded-Proto", "https")
	in.Header.Set("X-Forwarded-Host", "evil.example")
	in.Header.Set("Forwarded", "host=evil.example")
	resp, err := c.Forward(context.Background(), in)
	if err != nil {
		t.Fatal(err)
	}
	_ = resp.Body.Close()
	got := <-seen
	if got.proto != "http" {
		t.Fatalf("X-Forwarded-Proto %q", got.proto)
	}
	if got.host != "svc" {
		t.Fatalf("X-Forwarded-Host %q", got.host)
	}
	if got.forwarded != "" {
		t.Fatalf("Forwarded header leaked: %q", got.forwarded)
	}
}
