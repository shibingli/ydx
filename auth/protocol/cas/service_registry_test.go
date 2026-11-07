package cas

import (
	"context"
	"reflect"
	"testing"
)

func TestWildcardMatch(t *testing.T) {
	cases := []struct {
		pattern string
		value   string
		want    bool
	}{
		{"https://app.example.com/callback", "https://app.example.com/callback", true},
		{"https://app.example.com/callback", "https://app.example.com/other", false},
		{"https://*.example.com/*", "https://app.example.com/callback", true},
		{"https://*.example.com/*", "https://example.com/callback", false},
		{"*", "anything", true},
		{"", "", true},
		{"", "x", false},
		{"a*b*c", "abc", true},
		{"a*b*c", "axxbyyc", true},
		{"a*b*c", "axxbyy", false},
		{"https://app.example.com/*", "https://app.example.com/", true},
		{"https://app.example.com/*", "https://app.example.com", false},
	}
	for _, tc := range cases {
		if got := wildcardMatch(tc.pattern, tc.value); got != tc.want {
			t.Errorf("wildcardMatch(%q, %q) = %v, want %v", tc.pattern, tc.value, got, tc.want)
		}
	}
}

func TestStaticServiceRegistry(t *testing.T) {
	registry := NewStaticServiceRegistry(
		"https://app.example.com/callback",
		"https://*.example.org/*",
		"   ",
		"",
	)
	ctx := context.Background()
	if !registry.Allows(ctx, "https://app.example.com/callback") {
		t.Fatalf("exact service not allowed")
	}
	if !registry.Allows(ctx, "https://api.example.org/login") {
		t.Fatalf("wildcard service not allowed")
	}
	if registry.Allows(ctx, "https://evil.example.net/") {
		t.Fatalf("unregistered service allowed")
	}
	if registry.Allows(ctx, "") {
		t.Fatalf("empty service allowed")
	}
	if got := registry.Services(); !reflect.DeepEqual(got, []string{"https://app.example.com/callback", "https://*.example.org/*"}) {
		t.Fatalf("Services = %#v", got)
	}
	if !registry.Matches("https://app.example.com/callback", "https://app.example.com/callback") {
		t.Fatalf("exact match rejected")
	}
	if !registry.Matches("https://one.example.org/a", "https://two.example.org/b") {
		t.Fatalf("same-pattern match rejected")
	}
	if registry.Matches("https://one.example.org/a", "https://app.example.com/callback") {
		t.Fatalf("cross-pattern match accepted")
	}
	if registry.Matches("https://app.example.com/callback", "https://other.example.com/") {
		t.Fatalf("mismatched exact service accepted")
	}
}

func TestAllowAllServiceRegistry(t *testing.T) {
	registry := NewAllowAllServiceRegistry()
	ctx := context.Background()
	if !registry.Allows(ctx, "https://anything.example.com/") {
		t.Fatalf("allow-all registry rejected a service")
	}
	if registry.Allows(ctx, "") {
		t.Fatalf("allow-all registry accepted an empty service")
	}
	if !registry.Matches("https://a.example.com/", "https://a.example.com/") {
		t.Fatalf("exact match rejected")
	}
	if registry.Matches("https://a.example.com/", "https://b.example.com/") {
		t.Fatalf("allow-all registry accepted a mismatched service")
	}
	var nilRegistry *StaticServiceRegistry
	if !nilRegistry.Allows(ctx, "https://a.example.com/") {
		t.Fatalf("nil registry rejected a service")
	}
	if nilRegistry.Matches("https://a.example.com/", "https://b.example.com/") {
		t.Fatalf("nil registry accepted a mismatched service")
	}
}
