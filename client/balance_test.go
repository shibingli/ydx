package client

import (
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestLeastInflight(t *testing.T) {
	hs, err := NewHostSetWithOptions(HostSetOptions{Balance: BalanceLeastInflight},
		Host{Name: "a", URL: mustURL("http://a")},
		Host{Name: "b", URL: mustURL("http://b")},
	)
	if err != nil {
		t.Fatal(err)
	}
	defer hs.Close()
	req := httptest.NewRequest(http.MethodGet, "http://svc/x", nil)
	h1, err := hs.Pick(req, nil)
	if err != nil {
		t.Fatal(err)
	}
	h2, err := hs.Pick(req, nil)
	if err != nil {
		t.Fatal(err)
	}
	if h1.Name == h2.Name {
		t.Fatalf("least-inflight repeated %s", h1.Name)
	}
	hs.Release(h1)
	h3, err := hs.Pick(req, nil)
	if err != nil {
		t.Fatal(err)
	}
	if h3.Name != h1.Name {
		t.Fatalf("least-inflight picked %s, want %s", h3.Name, h1.Name)
	}
	hs.Release(h2)
	hs.Release(h3)
}

func TestBalanceHash(t *testing.T) {
	hs, err := NewHostSetWithOptions(HostSetOptions{
		Balance: BalanceHash,
		HashKey: func(r *http.Request) string { return r.URL.Path },
	},
		Host{Name: "a", URL: mustURL("http://a")},
		Host{Name: "b", URL: mustURL("http://b")},
	)
	if err != nil {
		t.Fatal(err)
	}
	defer hs.Close()
	req := httptest.NewRequest(http.MethodGet, "http://svc/stable", nil)
	h1, _ := hs.Pick(req, nil)
	hs.Release(h1)
	h2, _ := hs.Pick(req, nil)
	hs.Release(h2)
	if h1.Name != h2.Name {
		t.Fatalf("hash not stable: %s vs %s", h1.Name, h2.Name)
	}
}

func TestBalanceOrdered(t *testing.T) {
	hs, err := NewHostSetWithOptions(HostSetOptions{Balance: BalanceOrdered},
		Host{Name: "a", URL: mustURL("http://a")},
		Host{Name: "b", URL: mustURL("http://b")},
	)
	if err != nil {
		t.Fatal(err)
	}
	defer hs.Close()
	req := httptest.NewRequest(http.MethodGet, "http://svc/x", nil)
	for i := 0; i < 3; i++ {
		h, err := hs.Pick(req, nil)
		if err != nil {
			t.Fatal(err)
		}
		if h.Name != "a" {
			t.Fatalf("ordered picked %s", h.Name)
		}
		hs.Release(h)
	}
}

func TestBalanceRandom(t *testing.T) {
	hs, err := NewHostSetWithOptions(HostSetOptions{Balance: BalanceRandom},
		Host{Name: "a", URL: mustURL("http://a")},
		Host{Name: "b", URL: mustURL("http://b")},
	)
	if err != nil {
		t.Fatal(err)
	}
	defer hs.Close()
	req := httptest.NewRequest(http.MethodGet, "http://svc/x", nil)
	for i := 0; i < 20; i++ {
		h, err := hs.Pick(req, nil)
		if err != nil {
			t.Fatal(err)
		}
		hs.Release(h)
	}
}
