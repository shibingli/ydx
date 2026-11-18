package client

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"net/url"
	"testing"
	"time"
)

func TestRulePriorityAndRewrite(t *testing.T) {
	rs, err := CompileRules(
		Rule{Name: "param", Methods: []string{"GET"}, Pattern: "/api/user/{id}", Rewrite: &Rewrite{StripPrefix: "/api"}},
		Rule{Name: "static", Methods: []string{"GET"}, Pattern: "/api/user/me"},
		Rule{Name: "mixed", Methods: []string{"GET"}, Pattern: "/api/user/{id}.json"},
	)
	if err != nil {
		t.Fatal(err)
	}
	r, _, ok := rs.Match("GET", "/api/user/me")
	if !ok || r.Name != "static" {
		t.Fatalf("got %v %v", r, ok)
	}
	r, _, ok = rs.Match("GET", "/api/user/42")
	if !ok || r.Name != "param" {
		t.Fatalf("got %v", r)
	}
	if got := applyRewrite(r.Rewrite, "/api/user/42"); got != "/user/42" {
		t.Fatalf("rewrite %q", got)
	}
	if got := applyRewrite(&Rewrite{StripPrefix: "/api"}, "/apix"); got != "/apix" {
		t.Fatalf("boundary rewrite %q", got)
	}
	if _, _, ok := rs.Match("POST", "/api/user/42"); ok {
		t.Fatal("method must not match")
	}
}

func TestRuleSpecificity(t *testing.T) {
	rs, err := CompileRules(
		Rule{Name: "param", Pattern: "/a/{id}"},
		Rule{Name: "mixed", Pattern: "/a/{id}.json"},
		Rule{Name: "static", Pattern: "/a/b"},
		Rule{Name: "catchall", Pattern: "/a/*rest"},
	)
	if err != nil {
		t.Fatal(err)
	}
	cases := []struct{ path, want string }{
		{"/a/b", "static"},
		{"/a/b.json", "mixed"},
		{"/a/c", "param"},
		{"/a/c/d", "catchall"},
	}
	for _, tc := range cases {
		r, _, ok := rs.Match("GET", tc.path)
		if !ok || r.Name != tc.want {
			t.Fatalf("%s got %v %v want %s", tc.path, r, ok, tc.want)
		}
	}
}

func TestRuleCondition(t *testing.T) {
	rs, err := CompileRules(
		Rule{Name: "no", Pattern: "/x", Condition: func(*http.Request) bool { return false }},
		Rule{Name: "yes", Pattern: "/x"},
	)
	if err != nil {
		t.Fatal(err)
	}
	req := httptest.NewRequest(http.MethodGet, "http://svc/x", nil)
	r, _, ok := rs.MatchRequest(req)
	if !ok || r.Name != "yes" {
		t.Fatalf("got %v %v", r, ok)
	}
}

func TestRuleTimeout(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		time.Sleep(150 * time.Millisecond)
	}))
	defer srv.Close()
	c, err := New(
		WithHosts(srv.URL),
		WithRule(Rule{Name: "slow", Pattern: "/slow", Timeout: 20 * time.Millisecond}),
	)
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	start := time.Now()
	if _, err := c.Get(context.Background(), srv.URL+"/slow"); err == nil {
		t.Fatal("expected rule timeout")
	}
	if elapsed := time.Since(start); elapsed > 120*time.Millisecond {
		t.Fatalf("rule timeout not enforced: %v", elapsed)
	}
}

func TestRuleRewriteDirect(t *testing.T) {
	var gotPath string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotPath = r.URL.Path
	}))
	defer srv.Close()
	c, err := New(
		WithBaseURL(srv.URL),
		WithRule(Rule{Name: "api", Pattern: "/api/{id}", Rewrite: &Rewrite{StripPrefix: "/api"}}),
	)
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	resp, err := c.Get(context.Background(), "/api/42")
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	if gotPath != "/42" {
		t.Fatalf("upstream path %q, want /42", gotPath)
	}
}

func TestCompileRulesInvalid(t *testing.T) {
	cases := []struct {
		rule Rule
		want error
	}{
		{Rule{Pattern: ""}, ErrBadPattern},
		{Rule{Pattern: "/x", Rewrite: &Rewrite{StripPrefix: "api"}}, ErrBadPattern},
		{Rule{Pattern: "/x", Methods: []string{""}}, ErrInvalidConfig},
	}
	for _, tc := range cases {
		if _, err := CompileRules(tc.rule); !errors.Is(err, tc.want) {
			t.Fatalf("%+v: got %v want %v", tc.rule, err, tc.want)
		}
	}
}

func TestLogicalURL(t *testing.T) {
	base, _ := url.Parse("https://svc.example.com")
	got, err := resolveLogicalURL(base, "/api/user/42?x=1")
	if err != nil || got.Host != "svc.example.com" || got.Path != "/api/user/42" || got.RawQuery != "x=1" {
		t.Fatalf("got %v err %v", got, err)
	}
	abs, _ := url.Parse("https://other.example.com/y")
	got, err = resolveLogicalURL(base, abs.String())
	if err != nil || got.Host != "other.example.com" || got.Path != "/y" {
		t.Fatalf("absolute got %v err %v", got, err)
	}
	if _, err := resolveLogicalURL(nil, "/x"); !errors.Is(err, ErrRelativeURL) {
		t.Fatalf("want ErrRelativeURL, got %v", err)
	}
	withPath, _ := url.Parse("https://svc.example.com/api/")
	got, err = resolveLogicalURL(withPath, "user")
	if err != nil || got.Path != "/api/user" {
		t.Fatalf("join got %v err %v", got, err)
	}
}

func TestSendRelativeWithBaseURL(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/relative" {
			t.Errorf("path %q", r.URL.Path)
		}
	}))
	defer srv.Close()
	c, err := New(WithBaseURL(srv.URL))
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	if _, err := c.Get(context.Background(), "/relative"); err != nil {
		t.Fatal(err)
	}
}

func TestUpdateRules(t *testing.T) {
	c, err := New(WithRule(Rule{Name: "old", Pattern: "/old"}))
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	if r, _, ok := c.engine.rules.Load().Match("GET", "/old"); !ok || r.Name != "old" {
		t.Fatalf("initial rule %v %v", r, ok)
	}
	if err := c.UpdateRules(Rule{Name: "new", Pattern: "/new"}); err != nil {
		t.Fatal(err)
	}
	if _, _, ok := c.engine.rules.Load().Match("GET", "/old"); ok {
		t.Fatal("old rule still active")
	}
	if r, _, ok := c.engine.rules.Load().Match("GET", "/new"); !ok || r.Name != "new" {
		t.Fatalf("new rule %v %v", r, ok)
	}
}
