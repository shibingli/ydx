package client

import (
	"context"
	"net/http"
	"net/http/httptest"
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
