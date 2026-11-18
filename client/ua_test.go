package client

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
)

func TestUAModes(t *testing.T) {
	var mu sync.Mutex
	var got []string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		got = append(got, r.Header.Get("User-Agent"))
		mu.Unlock()
	}))
	defer srv.Close()

	c, err := New(WithHosts(srv.URL), WithUserAgent(UAPolicy{Mode: UARandom, Force: true}))
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	for i := 0; i < 10; i++ {
		resp, err := c.Get(context.Background(), srv.URL+"/x")
		if err != nil {
			t.Fatal(err)
		}
		resp.Body.Close()
	}
	mu.Lock()
	defer mu.Unlock()
	if len(got) != 10 || got[0] == "" {
		t.Fatalf("ua %v", got)
	}
}

func TestUAFixedForceAndRotate(t *testing.T) {
	var mu sync.Mutex
	var got []string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("User-Agent") == "custom-agent" && r.Header.Get("Accept-Language") != "zh-CN" {
			t.Errorf("companion header %q", r.Header.Get("Accept-Language"))
		}
		mu.Lock()
		got = append(got, r.Header.Get("User-Agent"))
		mu.Unlock()
	}))
	defer srv.Close()

	fixed, err := New(WithHosts(srv.URL), WithUserAgent(UAPolicy{
		Mode:  UAFixed,
		List:  []string{"custom-agent"},
		Force: true,
		Companion: http.Header{
			"Accept-Language": {"zh-CN"},
		},
	}))
	if err != nil {
		t.Fatal(err)
	}
	defer fixed.Close()
	resp, err := fixed.Get(context.Background(), srv.URL+"/x", WithRequestHeader("User-Agent", "explicit"))
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()

	noForce, err := New(WithHosts(srv.URL), WithUserAgent(UAPolicy{Mode: UAFixed, List: []string{"custom-agent"}}))
	if err != nil {
		t.Fatal(err)
	}
	defer noForce.Close()
	resp, err = noForce.Get(context.Background(), srv.URL+"/x", WithRequestHeader("User-Agent", "explicit"))
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()

	rotate, err := New(WithHosts(srv.URL), WithUserAgent(UAPolicy{
		Mode:  UARotate,
		List:  []string{"ua-1", "ua-2"},
		Force: true,
	}))
	if err != nil {
		t.Fatal(err)
	}
	defer rotate.Close()
	for i := 0; i < 4; i++ {
		resp, err := rotate.Get(context.Background(), srv.URL+"/x")
		if err != nil {
			t.Fatal(err)
		}
		resp.Body.Close()
	}

	mu.Lock()
	defer mu.Unlock()
	if got[0] != "custom-agent" {
		t.Fatalf("forced UA %q", got[0])
	}
	if got[1] != "explicit" {
		t.Fatalf("non-forced UA %q", got[1])
	}
	want := []string{"ua-1", "ua-2", "ua-1", "ua-2"}
	for i, value := range want {
		if got[2+i] != value {
			t.Fatalf("rotate %v", got[2:])
		}
	}
	if !strings.HasPrefix(got[0], "custom-agent") {
		t.Fatalf("companion UA %q", got[0])
	}
}

func TestUAWeightedAndBuiltin(t *testing.T) {
	var mu sync.Mutex
	var got []string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		got = append(got, r.Header.Get("User-Agent"))
		mu.Unlock()
	}))
	defer srv.Close()

	c, err := New(WithHosts(srv.URL), WithUserAgent(UAPolicy{
		Mode:    UAWeighted,
		List:    []string{"never", "always"},
		Weights: []int{0, 1},
		Force:   true,
	}))
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	for i := 0; i < 3; i++ {
		resp, err := c.Get(context.Background(), srv.URL+"/x")
		if err != nil {
			t.Fatal(err)
		}
		resp.Body.Close()
	}
	mu.Lock()
	for _, ua := range got {
		if ua != "always" {
			t.Fatalf("weighted UA %q", ua)
		}
	}
	mu.Unlock()

	builtin, err := New(WithHosts(srv.URL), WithUserAgent(UAPolicy{Mode: UAFixed, Force: true}))
	if err != nil {
		t.Fatal(err)
	}
	defer builtin.Close()
	resp, err := builtin.Get(context.Background(), srv.URL+"/x")
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	mu.Lock()
	defer mu.Unlock()
	if !strings.Contains(got[len(got)-1], "Mozilla") {
		t.Fatalf("builtin UA %q", got[len(got)-1])
	}
}

func TestUANilHeader(t *testing.T) {
	var got atomic.Value
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		got.Store(r.Header.Get("User-Agent"))
	}))
	defer srv.Close()
	c, err := New(WithHosts(srv.URL), WithUserAgent(UAPolicy{Mode: UAFixed, List: []string{"custom-agent"}, Force: true}))
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
	if got.Load() != "custom-agent" {
		t.Fatalf("ua %v", got.Load())
	}
}

func TestUAInvalidWeights(t *testing.T) {
	if _, err := New(WithUserAgent(UAPolicy{List: []string{"a"}, Weights: []int{1, 2}})); err == nil {
		t.Fatal("expected invalid weights error")
	}
}

func TestRuleUAOverride(t *testing.T) {
	var got atomic.Value
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		got.Store(r.Header.Get("User-Agent"))
	}))
	defer srv.Close()
	c, err := New(
		WithHosts(srv.URL),
		WithUserAgent(UAPolicy{Mode: UAFixed, List: []string{"global"}, Force: true}),
		WithRule(Rule{
			Name:    "ua",
			Pattern: "/x",
			UA:      &UAPolicy{Mode: UAFixed, List: []string{"rule"}, Force: true},
		}),
	)
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	resp, err := c.Get(context.Background(), srv.URL+"/x")
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	if got.Load() != "rule" {
		t.Fatalf("ua %v", got.Load())
	}
}
