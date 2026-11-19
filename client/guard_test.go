package client

import (
	"context"
	"errors"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"net/netip"
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

func TestGuardPanicFailsClosed(t *testing.T) {
	c, err := New(WithGuard(GuardFunc(func(context.Context, *http.Request) (GuardDecision, error) {
		panic("boom")
	})), WithoutCookieJar())
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	_, err = c.Get(context.Background(), "http://127.0.0.1:1/")
	if !errors.Is(err, ErrGuard) || !errors.Is(err, ErrHookPanic) {
		t.Fatalf("error %v", err)
	}
}

func TestAccessPolicyCachesDNS(t *testing.T) {
	var calls atomic.Int32
	p := &AccessPolicy{
		BlockPrivateIPs: true,
		DNSCacheTTL:     time.Minute,
		resolver: func(context.Context, string, string) ([]netip.Addr, error) {
			calls.Add(1)
			return []netip.Addr{netip.MustParseAddr("93.184.216.34")}, nil
		},
	}
	if err := p.prepare(); err != nil {
		t.Fatal(err)
	}
	req := mustRequest(t, http.MethodGet, "http://example.com/x", "")
	for i := 0; i < 2; i++ {
		decision, err := p.Check(context.Background(), req)
		if err != nil {
			t.Fatal(err)
		}
		if !decision.Allowed {
			t.Fatal("public address denied")
		}
	}
	if calls.Load() != 1 {
		t.Fatalf("resolver calls %d, want 1", calls.Load())
	}
}

func TestGuardedDialBlocksPrivateIP(t *testing.T) {
	policy := &AccessPolicy{BlockPrivateIPs: true}
	if err := policy.prepare(); err != nil {
		t.Fatal(err)
	}
	ctx := context.WithValue(context.Background(), dialPoliciesKey{}, []*AccessPolicy{policy})
	conn, err := guardedDialContext(&net.Dialer{Timeout: time.Second})(ctx, "tcp", "localhost:80")
	if conn != nil {
		_ = conn.Close()
	}
	if !errors.Is(err, ErrBlocked) {
		t.Fatalf("want ErrBlocked, got %v", err)
	}
}

func TestGuardedDialAllowsCIDR(t *testing.T) {
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer listener.Close()
	policy := &AccessPolicy{AllowCIDRs: []string{"127.0.0.0/8"}}
	if err := policy.prepare(); err != nil {
		t.Fatal(err)
	}
	ctx := context.WithValue(context.Background(), dialPoliciesKey{}, []*AccessPolicy{policy})
	_, port, err := net.SplitHostPort(listener.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	conn, err := guardedDialContext(&net.Dialer{Timeout: time.Second})(ctx, "tcp", "localhost:"+port)
	if err != nil {
		t.Fatalf("guarded dial: %v", err)
	}
	_ = conn.Close()
}

func TestNewRejectsIPGuardOnCustomTransport(t *testing.T) {
	custom := roundTripFunc(func(*http.Request) (*http.Response, error) {
		return &http.Response{StatusCode: http.StatusOK, Header: make(http.Header), Body: http.NoBody}, nil
	})
	if _, err := New(WithTransport(custom), WithAccessPolicy(&AccessPolicy{BlockPrivateIPs: true})); err == nil {
		t.Fatal("custom RoundTripper accepted with IP guard")
	}
	tr := &http.Transport{DialContext: (&net.Dialer{Timeout: time.Second}).DialContext}
	if _, err := New(WithTransport(tr), WithAccessPolicy(&AccessPolicy{BlockPrivateIPs: true})); err == nil {
		t.Fatal("custom DialContext accepted with IP guard")
	}
}

func TestUpdateRulesRejectsIPGuardOnCustomTransport(t *testing.T) {
	custom := roundTripFunc(func(*http.Request) (*http.Response, error) {
		return &http.Response{StatusCode: http.StatusOK, Header: make(http.Header), Body: http.NoBody}, nil
	})
	c, err := New(WithTransport(custom), WithoutCookieJar())
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	if err := c.UpdateRules(Rule{
		Pattern: "/**",
		Guard:   &AccessPolicy{BlockPrivateIPs: true},
	}); err == nil {
		t.Fatal("custom transport accepted a later IP-guard rule")
	}
}

func TestNewRejectsInvalidAccessPolicy(t *testing.T) {
	if _, err := New(WithAccessPolicy(&AccessPolicy{AllowCIDRs: []string{"bad"}})); err == nil {
		t.Fatal("invalid client access policy accepted")
	}
	if _, err := New(WithRule(Rule{
		Pattern: "/**",
		Guard:   &AccessPolicy{AllowCIDRs: []string{"bad"}},
	})); err == nil {
		t.Fatal("invalid rule access policy accepted")
	}
}

func TestAccessPolicyHostMatchStripsIPv6Zone(t *testing.T) {
	policy := &AccessPolicy{DenyHosts: []string{"fe80::1"}}
	req := mustRequest(t, http.MethodGet, "http://[fe80::1%25eth0]/x", "")
	decision, err := policy.Check(context.Background(), req)
	if err != nil {
		t.Fatal(err)
	}
	if decision.Allowed {
		t.Fatal("zoned IPv6 host bypassed deny host")
	}
}

func TestAccessPolicyCIDRStripsIPv6Zone(t *testing.T) {
	zoned := netip.MustParseAddr("2001:db8::1%eth0")
	deny := &AccessPolicy{DenyCIDRs: []string{"2001:db8::/32"}}
	if err := deny.prepare(); err != nil {
		t.Fatal(err)
	}
	if deny.allowIP(zoned) {
		t.Fatal("deny CIDR bypassed by IPv6 zone")
	}
	allow := &AccessPolicy{AllowCIDRs: []string{"2001:db8::/32"}}
	if err := allow.prepare(); err != nil {
		t.Fatal(err)
	}
	if !allow.allowIP(zoned) {
		t.Fatal("allow CIDR rejected zoned IPv6 address")
	}
}

func TestAccessPolicyCheckDeniesZonedIPv6CIDR(t *testing.T) {
	policy := &AccessPolicy{DenyCIDRs: []string{"2001:db8::/32"}}
	req := mustRequest(t, http.MethodGet, "http://[2001:db8::1%25eth0]/x", "")
	decision, err := policy.Check(context.Background(), req)
	if err != nil {
		t.Fatal(err)
	}
	if decision.Allowed {
		t.Fatal("zoned IPv6 bypassed deny CIDR in Check")
	}
}

func TestDialControlStripsIPv6Zone(t *testing.T) {
	policy := &AccessPolicy{DenyCIDRs: []string{"2001:db8::/32"}}
	if err := policy.prepare(); err != nil {
		t.Fatal(err)
	}
	err := policy.dialControl("tcp", "[2001:db8::1%eth0]:443", nil)
	if !errors.Is(err, ErrBlocked) {
		t.Fatalf("want ErrBlocked, got %v", err)
	}
}

func TestAccessPolicyDeniesIDNHost(t *testing.T) {
	p := &AccessPolicy{DenyHosts: []string{"metadata.google.internal"}}
	req := mustRequest(t, http.MethodGet, "http://ｍｅｔａｄａｔａ.google.internal/x", "")
	decision, err := p.Check(context.Background(), req)
	if err != nil {
		t.Fatal(err)
	}
	if decision.Allowed {
		t.Fatal("Unicode IDN host bypassed the deny list")
	}
}

func TestAccessPolicyIDNPattern(t *testing.T) {
	p := &AccessPolicy{DenyHosts: []string{"ｍｅｔａｄａｔａ.google.internal"}}
	req := mustRequest(t, http.MethodGet, "http://metadata.google.internal/x", "")
	decision, err := p.Check(context.Background(), req)
	if err != nil {
		t.Fatal(err)
	}
	if decision.Allowed {
		t.Fatal("Unicode deny pattern did not match the ASCII host")
	}
}

func TestAccessPolicyDeniesTrailingDotHost(t *testing.T) {
	p := &AccessPolicy{DenyHosts: []string{"metadata.google.internal"}}
	req := mustRequest(t, http.MethodGet, "http://metadata.google.internal./x", "")
	decision, err := p.Check(context.Background(), req)
	if err != nil {
		t.Fatal(err)
	}
	if decision.Allowed {
		t.Fatal("trailing-dot host bypassed the deny list")
	}
}

func TestBlockPrivateIPsBlocksThisNetwork(t *testing.T) {
	p := &AccessPolicy{BlockPrivateIPs: true}
	for _, raw := range []string{"http://0.0.0.1/x", "http://100.64.0.1/x"} {
		req := mustRequest(t, http.MethodGet, raw, "")
		decision, err := p.Check(context.Background(), req)
		if err != nil {
			t.Fatal(err)
		}
		if decision.Allowed {
			t.Fatalf("%s bypassed BlockPrivateIPs", raw)
		}
	}
}
