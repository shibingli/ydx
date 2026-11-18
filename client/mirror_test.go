package client

import (
	"context"
	"net/http"
	"net/http/httptest"
	"net/url"
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
			m.submit(context.Background(), req, req.URL, nil, policy)
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
			Mirror:  &MirrorPolicy{Targets: []string{mirror.URL}, Percent: 100, Sync: true, Wait: time.Second},
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
