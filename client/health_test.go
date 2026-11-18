package client

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

func TestActiveHealth(t *testing.T) {
	var healthy atomic.Bool
	healthy.Store(true)
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if healthy.Load() {
			w.WriteHeader(http.StatusOK)
			return
		}
		w.WriteHeader(http.StatusServiceUnavailable)
	}))
	defer srv.Close()

	hs, err := NewHostSet(Host{
		Name: "a",
		URL:  mustURL(srv.URL),
		Health: HealthPolicy{
			Active:        true,
			Path:          "/health",
			Interval:      10 * time.Millisecond,
			Timeout:       100 * time.Millisecond,
			FailThreshold: 1,
			Cooldown:      20 * time.Millisecond,
			MaxCooldown:   100 * time.Millisecond,
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	defer hs.Close()

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	hs.StartHealth(ctx, &http.Transport{}, nil)

	healthy.Store(false)
	waitFor(t, 2*time.Second, func() bool { return !hs.Stats()[0].Healthy })

	healthy.Store(true)
	waitFor(t, 2*time.Second, func() bool { return hs.Stats()[0].Healthy })

	hs.Close()
	if _, err := hs.Pick(httptest.NewRequest(http.MethodGet, "http://svc/x", nil), nil); err != ErrClosed {
		t.Fatalf("pick after close: %v", err)
	}
}

func TestActiveHealthTLS(t *testing.T) {
	var hits atomic.Int32
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		hits.Add(1)
	}))
	defer srv.Close()
	hs, err := NewHostSet(Host{
		Name: "tls",
		URL:  mustURL(srv.URL),
		Health: HealthPolicy{
			Active:        true,
			Path:          "/health",
			Interval:      10 * time.Millisecond,
			Timeout:       100 * time.Millisecond,
			FailThreshold: 1,
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	c, err := New(
		WithHostSet(hs),
		WithTLS(TLSConfig{InsecureSkipVerify: true, DisableSystemRoots: true}),
	)
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	waitFor(t, 2*time.Second, func() bool { return hits.Load() > 0 })
}

func TestStartHealthNoActive(t *testing.T) {
	hs, err := NewHostSet(Host{Name: "a", URL: mustURL("http://a")})
	if err != nil {
		t.Fatal(err)
	}
	hs.StartHealth(context.Background(), &http.Transport{}, nil)
	if err := hs.Close(); err != nil {
		t.Fatal(err)
	}
}

type blockingTransport struct {
	release chan struct{}
	started chan struct{}
	once    sync.Once
}

func (b *blockingTransport) RoundTrip(req *http.Request) (*http.Response, error) {
	if b.started != nil {
		b.once.Do(func() { close(b.started) })
	}
	<-b.release
	return nil, context.Canceled
}

func TestCloseContextBoundsHealthWait(t *testing.T) {
	release := make(chan struct{})
	started := make(chan struct{})
	rt := &blockingTransport{release: release, started: started}
	hs, err := NewHostSet(Host{
		Name: "a",
		URL:  mustURL("http://127.0.0.1:1"),
		Health: HealthPolicy{
			Active:   true,
			Interval: 10 * time.Millisecond,
			Timeout:  time.Hour,
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	c, err := New(WithHostSet(hs), WithTransport(rt))
	if err != nil {
		t.Fatal(err)
	}
	select {
	case <-started:
	case <-time.After(time.Second):
		t.Fatal("health check did not start")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Millisecond)
	defer cancel()
	err = c.CloseContext(ctx)
	close(release)
	if !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("want deadline, got %v", err)
	}
}
