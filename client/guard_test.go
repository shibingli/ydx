package client

import (
	"context"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

func TestAccessPolicy(t *testing.T) {
	p := &AccessPolicy{
		AllowSchemes: []string{"https"},
		AllowHosts:   []string{"*.example.com"},
		AllowMethods: []string{"GET"},
	}
	cases := []struct {
		method  string
		rawURL  string
		allowed bool
	}{
		{http.MethodGet, "https://api.example.com/x", true},
		{http.MethodPost, "https://api.example.com/x", false},
		{http.MethodGet, "http://api.example.com/x", false},
		{http.MethodGet, "https://evil.com/x", false},
	}
	for _, tc := range cases {
		req := mustRequest(t, tc.method, tc.rawURL, "")
		decision, err := p.Check(context.Background(), req)
		if err != nil {
			t.Fatal(err)
		}
		if decision.Allowed != tc.allowed {
			t.Fatalf("%s %s = %v", tc.method, tc.rawURL, decision.Allowed)
		}
	}
}

func TestAccessPolicyDenyCIDR(t *testing.T) {
	p := &AccessPolicy{AllowSchemes: []string{"https"}, DenyCIDRs: []string{"10.0.0.0/8"}}
	decision, err := p.Check(context.Background(), mustRequest(t, http.MethodGet, "https://10.0.0.1/x", ""))
	if err != nil || decision.Allowed {
		t.Fatalf("deny cidr: decision=%+v err=%v", decision, err)
	}
	decision, err = p.Check(context.Background(), mustRequest(t, http.MethodGet, "https://8.8.8.8/x", ""))
	if err != nil || !decision.Allowed {
		t.Fatalf("allow public: decision=%+v err=%v", decision, err)
	}
}

func TestAccessPolicyPrivateIP(t *testing.T) {
	p := &AccessPolicy{BlockPrivateIPs: true}
	for _, raw := range []string{
		"http://127.0.0.1/x",
		"http://10.1.2.3/x",
		"http://[::1]/x",
		"http://localhost/x",
	} {
		decision, err := p.Check(context.Background(), mustRequest(t, http.MethodGet, raw, ""))
		if err != nil {
			t.Fatal(err)
		}
		if decision.Allowed {
			t.Fatalf("%s allowed", raw)
		}
	}
	decision, err := p.Check(context.Background(), mustRequest(t, http.MethodGet, "http://8.8.8.8/x", ""))
	if err != nil || !decision.Allowed {
		t.Fatalf("public IP: %v %v", decision.Allowed, err)
	}
}

func TestAccessPolicyPortAndSize(t *testing.T) {
	p := &AccessPolicy{AllowPorts: []int{443}, MaxRequestBytes: 10}
	if decision, _ := p.Check(context.Background(), mustRequest(t, http.MethodGet, "https://example.com:443/x", "")); !decision.Allowed {
		t.Fatal("443 denied")
	}
	if decision, _ := p.Check(context.Background(), mustRequest(t, http.MethodGet, "http://example.com:80/x", "")); decision.Allowed {
		t.Fatal("80 allowed")
	}
	if decision, _ := p.Check(context.Background(), mustRequest(t, http.MethodPost, "https://example.com:443/x", "01234567890")); decision.Allowed {
		t.Fatal("oversize body allowed")
	}
}

func TestAccessPolicyInvalidCIDR(t *testing.T) {
	p := &AccessPolicy{AllowCIDRs: []string{"bad"}}
	_, err := p.Check(context.Background(), mustRequest(t, http.MethodGet, "http://example.com/x", ""))
	if !errors.Is(err, ErrInvalidConfig) {
		t.Fatalf("want ErrInvalidConfig, got %v", err)
	}
}

func TestGuardBlocksBeforeCache(t *testing.T) {
	var hits atomic.Int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		hits.Add(1)
	}))
	defer srv.Close()

	c, err := New(
		WithHosts(srv.URL),
		WithRule(Rule{Name: "r", Pattern: "/x", Cache: &CachePolicy{TTL: time.Minute}}),
		WithGuard(GuardFunc(func(context.Context, *http.Request) (GuardDecision, error) {
			return GuardDecision{Allowed: false, Message: "blocked by test"}, nil
		})),
	)
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	_, reqErr := c.Get(context.Background(), srv.URL+"/x")
	if !errors.Is(reqErr, ErrBlocked) {
		t.Fatalf("want ErrBlocked, got %v", reqErr)
	}
	if hits.Load() != 0 {
		t.Fatalf("upstream hit %d", hits.Load())
	}
	var clientErr *Error
	if !errors.As(reqErr, &clientErr) {
		t.Fatalf("want *Error, got %T", reqErr)
	}
}

func TestGuardChain(t *testing.T) {
	var allowCalls, denyCalls atomic.Int32
	allow := GuardFunc(func(context.Context, *http.Request) (GuardDecision, error) {
		allowCalls.Add(1)
		return GuardDecision{Allowed: true}, nil
	})
	deny := GuardFunc(func(context.Context, *http.Request) (GuardDecision, error) {
		denyCalls.Add(1)
		return GuardDecision{Allowed: false, Status: 403, Message: "no"}, nil
	})
	c, err := New(WithGuard(GuardChain{allow, deny}))
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	if _, err := c.Get(context.Background(), "http://example.com/x"); !errors.Is(err, ErrBlocked) {
		t.Fatalf("want ErrBlocked, got %v", err)
	}
	if allowCalls.Load() != 1 || denyCalls.Load() != 1 {
		t.Fatalf("calls allow=%d deny=%d", allowCalls.Load(), denyCalls.Load())
	}
}

func TestDialControl(t *testing.T) {
	p := &AccessPolicy{BlockPrivateIPs: true}
	if err := p.dialControl("tcp", "127.0.0.1:80", nil); !errors.Is(err, ErrBlocked) {
		t.Fatalf("loopback: %v", err)
	}
	if err := p.dialControl("tcp", "8.8.8.8:443", nil); err != nil {
		t.Fatalf("public: %v", err)
	}
}

func TestForwardGuard403(t *testing.T) {
	c, err := New(WithGuard(GuardFunc(func(context.Context, *http.Request) (GuardDecision, error) {
		return GuardDecision{Allowed: false, Message: "no"}, nil
	})))
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	rec := httptest.NewRecorder()
	c.Handler().ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "http://svc/x", nil))
	if rec.Code != http.StatusForbidden {
		t.Fatalf("code %d", rec.Code)
	}
}

func TestAccessPolicyCapsUnknownBody(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = io.Copy(io.Discard, r.Body)
	}))
	defer srv.Close()
	c, err := New(WithAccessPolicy(&AccessPolicy{MaxRequestBytes: 5}))
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	req, _ := http.NewRequest(http.MethodPost, srv.URL+"/x", io.NopCloser(strings.NewReader("0123456789")))
	req.ContentLength = -1
	if _, err := c.Do(req); !errors.Is(err, ErrRequestTooLarge) {
		t.Fatalf("want ErrRequestTooLarge, got %v", err)
	}
}
