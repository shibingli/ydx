package client

import (
	"bytes"
	"context"
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

func TestMirrorUpstreamAsyncAndNoRecursion(t *testing.T) {
	var mirrorHits atomic.Int32
	mirror := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		mirrorHits.Add(1)
		w.WriteHeader(http.StatusOK)
	}))
	defer mirror.Close()
	primary := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	defer primary.Close()

	c, err := New(
		WithHosts(primary.URL),
		WithRule(Rule{
			Name:    "r",
			Pattern: "/x",
			Mirror: &MirrorPolicy{
				Targets: []string{mirror.URL},
				Percent: 100,
				Timeout: time.Second,
			},
		}),
	)
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()

	for i := 0; i < 5; i++ {
		resp, err := c.Get(context.Background(), primary.URL+"/x")
		if err != nil {
			t.Fatal(err)
		}
		resp.Body.Close()
	}
	waitFor(t, time.Second, func() bool { return mirrorHits.Load() == 5 })
	if mirrorHits.Load() != 5 {
		t.Fatalf("mirror hits %d", mirrorHits.Load())
	}
}

func TestMirrorUsesHostTLS(t *testing.T) {
	var hits atomic.Int32
	mirror, cert := newTestTLSServer(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		hits.Add(1)
	}))
	defer mirror.Close()
	primary := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {}))
	defer primary.Close()
	c, err := New(
		WithHosts(primary.URL),
		WithHostTLS(mirror.URL, TLSConfig{RootCAs: testCertPool(cert), DisableSystemRoots: true}),
		WithRule(Rule{
			Name:    "r",
			Pattern: "/x",
			Mirror:  &MirrorPolicy{Targets: []string{mirror.URL}, Percent: 100, Sync: true, Wait: time.Second},
		}),
	)
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	resp, err := c.Get(context.Background(), primary.URL+"/x")
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	if hits.Load() != 1 {
		t.Fatalf("mirror hits %d", hits.Load())
	}
	if c.Stats().MirrorErrors != 0 {
		t.Fatalf("mirror errors %d", c.Stats().MirrorErrors)
	}
}

func TestMirrorCloseRace(t *testing.T) {
	target := mustURL("http://127.0.0.1:1")
	policy := &MirrorPolicy{
		Mode:    MirrorUpstream,
		Percent: 100,
		Timeout: time.Millisecond,
		targets: []*url.URL{target},
	}
	m := newMirrorer(http.DefaultTransport, 4)
	req := httptest.NewRequest(http.MethodGet, "http://logical/x", nil)
	var wg sync.WaitGroup
	for i := 0; i < 50; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			m.submit(context.Background(), req, req.URL, nil, policy, nil)
		}()
	}
	m.Close()
	wg.Wait()
}

func TestMirrorSync(t *testing.T) {
	var mirrorHits atomic.Int32
	mirror := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		mirrorHits.Add(1)
	}))
	defer mirror.Close()
	primary := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {}))
	defer primary.Close()

	c, err := New(
		WithHosts(primary.URL),
		WithRule(Rule{
			Name:    "r",
			Pattern: "/x",
			Mirror: &MirrorPolicy{
				Targets: []string{mirror.URL},
				Percent: 100,
				Sync:    true,
				Wait:    time.Second,
				Timeout: time.Second,
			},
		}),
	)
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	resp, err := c.Get(context.Background(), primary.URL+"/x")
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	if mirrorHits.Load() != 1 {
		t.Fatalf("sync mirror hits %d", mirrorHits.Load())
	}
	if len(resp.Meta.Mirrors) != 1 || resp.Meta.Mirrors[0].Status != http.StatusOK ||
		resp.Meta.Mirrors[0].Target != mirror.URL {
		t.Fatalf("mirror results %+v", resp.Meta.Mirrors)
	}
}

func TestMirrorStripsSensitiveHeaders(t *testing.T) {
	var gotAuth, gotCookie atomic.Value
	mirror := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotAuth.Store(r.Header.Get("Authorization"))
		gotCookie.Store(r.Header.Get("Cookie"))
	}))
	defer mirror.Close()
	primary := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {}))
	defer primary.Close()

	c, err := New(
		WithHosts(primary.URL),
		WithRule(Rule{
			Name:    "r",
			Pattern: "/x",
			Mirror: &MirrorPolicy{
				Targets:      []string{mirror.URL},
				Percent:      100,
				Sync:         true,
				Wait:         time.Second,
				StripHeaders: []string{"X-Trace"},
			},
		}),
	)
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	resp, err := c.Get(context.Background(), primary.URL+"/x",
		WithRequestHeader("Authorization", "Bearer secret"),
		WithRequestHeader("Cookie", "session=secret"),
	)
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	if gotAuth.Load() != "" || gotCookie.Load() != "" {
		t.Fatalf("sensitive headers mirrored: auth=%q cookie=%q", gotAuth.Load(), gotCookie.Load())
	}
}

func TestMirrorSpoolsNonReplayableBody(t *testing.T) {
	var primaryBody, mirrorBody string
	primary := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		data, _ := io.ReadAll(r.Body)
		primaryBody = string(data)
	}))
	defer primary.Close()
	mirror := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		data, _ := io.ReadAll(r.Body)
		mirrorBody = string(data)
	}))
	defer mirror.Close()
	c, err := New(WithRule(Rule{
		Name:    "mirror",
		Pattern: "/x",
		Mirror: &MirrorPolicy{
			Targets: []string{mirror.URL},
			Percent: 100,
			Sync:    true,
			Wait:    time.Second,
			Timeout: time.Second,
		},
	}))
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	req, _ := http.NewRequest(http.MethodPost, primary.URL+"/x", io.NopCloser(strings.NewReader("payload")))
	req.ContentLength = -1
	resp, err := c.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	if primaryBody != "payload" || mirrorBody != "payload" {
		t.Fatalf("primary %q mirror %q", primaryBody, mirrorBody)
	}
}

func TestMirrorDoneHookCanClose(t *testing.T) {
	mirror := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	defer mirror.Close()
	primary := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte("ok"))
	}))
	defer primary.Close()
	var c *Client
	var err error
	c, err = New(
		WithHosts(primary.URL),
		WithMirror(MirrorPolicy{Targets: []string{mirror.URL}, Sync: true, Wait: time.Second}),
		WithHooks(Hooks{OnMirrorDone: func(context.Context, MirrorInfo) {
			_ = c.CloseContext(context.Background())
		}}),
		WithoutCookieJar(),
	)
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	done := make(chan struct{})
	go func() {
		defer close(done)
		resp, reqErr := c.Get(context.Background(), "/x")
		if reqErr == nil {
			_ = resp.Body.Close()
		}
	}()
	select {
	case <-done:
	case <-time.After(2 * time.Second):
		t.Fatal("OnMirrorDone blocked closing the client")
	}
}

func TestMirrorSpoolDoesNotMutateRequest(t *testing.T) {
	const size = 2 << 20
	var primarySize, mirrorSize atomic.Int64
	primary := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		n, _ := io.Copy(io.Discard, r.Body)
		primarySize.Store(n)
		w.WriteHeader(http.StatusOK)
	}))
	defer primary.Close()
	mirror := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		n, _ := io.Copy(io.Discard, r.Body)
		mirrorSize.Store(n)
		w.WriteHeader(http.StatusOK)
	}))
	defer mirror.Close()
	c, err := New(
		WithRule(Rule{
			Pattern: "/x",
			Mirror: &MirrorPolicy{
				Targets: []string{mirror.URL},
				Percent: 100,
				Sync:    true,
				Wait:    time.Second,
				Timeout: time.Second,
			},
		}),
		WithoutCookieJar(),
	)
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	req, err := http.NewRequest(http.MethodPost, primary.URL+"/x",
		io.LimitReader(bytes.NewReader(make([]byte, size)), size))
	if err != nil {
		t.Fatal(err)
	}
	req.ContentLength = -1
	if req.GetBody != nil {
		t.Fatal("test request unexpectedly replayable")
	}
	resp, err := c.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	_ = resp.Body.Close()
	if req.GetBody != nil {
		t.Fatal("mirror spool mutated caller GetBody")
	}
	if req.ContentLength != -1 {
		t.Fatalf("mirror spool mutated caller ContentLength: %d", req.ContentLength)
	}
	if primarySize.Load() != size || mirrorSize.Load() != size {
		t.Fatalf("primary=%d mirror=%d", primarySize.Load(), mirrorSize.Load())
	}
}

func TestAsyncMirrorResults(t *testing.T) {
	mirror := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		time.Sleep(20 * time.Millisecond)
	}))
	defer mirror.Close()
	primary := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {}))
	defer primary.Close()
	c, err := New(
		WithHosts(primary.URL),
		WithRule(Rule{Name: "r", Pattern: "/x", Mirror: &MirrorPolicy{
			Targets: []string{mirror.URL},
			Percent: 100,
			Timeout: time.Second,
		}}),
	)
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	resp, err := c.Get(context.Background(), primary.URL+"/x")
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	if resp.Meta.MirrorResults == nil {
		t.Fatal("nil async mirror tracker")
	}
	waitFor(t, time.Second, func() bool { return len(resp.Meta.MirrorResults.Snapshot()) == 1 })
	results := resp.Meta.MirrorResults.Snapshot()
	if results[0].Status != http.StatusOK || results[0].Target != mirror.URL {
		t.Fatalf("results %+v", results)
	}
}
