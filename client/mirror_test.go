package client

import (
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
	req.ContentLength = 7
	resp, err := c.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	if primaryBody != "payload" || mirrorBody != "payload" {
		t.Fatalf("primary %q mirror %q", primaryBody, mirrorBody)
	}
}
