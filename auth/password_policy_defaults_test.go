package auth

import (
	"context"
	"errors"
	"strings"
	"testing"
)

func TestServicePasswordPolicyPartialMerge(t *testing.T) {
	harness := newTestService(t, func(config *Config) {
		config.Policy = PasswordPolicy{MinLength: 1}
	})
	policy := harness.service.Policy()
	if policy.MinLength != 1 || policy.MaxLength != 1024 || policy.CommonPasswords == nil {
		t.Fatalf("merged policy = %+v", policy)
	}
	if policy.DisallowUsername || policy.DisallowEmail {
		t.Fatalf("boolean rules were defaulted instead of kept literal: %+v", policy)
	}

	ctx := context.Background()
	if _, err := harness.service.Register(ctx, RegisterInput{
		Username: "shortpass", Email: "shortpass@example.com", Password: "x",
	}); err != nil {
		t.Fatalf("single-character password under MinLength 1: %v", err)
	}
	if _, err := harness.service.Register(ctx, RegisterInput{
		Username: "commonpass", Email: "commonpass@example.com", Password: "password",
	}); !errors.Is(err, ErrPasswordPolicy) {
		t.Fatalf("common password = %v, want ErrPasswordPolicy", err)
	}
	if _, err := harness.service.Register(ctx, RegisterInput{
		Username: "longpass", Email: "longpass@example.com", Password: strings.Repeat("a", 1025),
	}); !errors.Is(err, ErrPasswordPolicy) {
		t.Fatalf("oversized password = %v, want ErrPasswordPolicy", err)
	}
}

func TestServicePasswordPolicyZeroValueUsesDefaults(t *testing.T) {
	harness := newTestService(t, func(config *Config) {
		config.Policy = PasswordPolicy{}
	})
	policy := harness.service.Policy()
	defaults := DefaultPasswordPolicy()
	if policy.MinLength != defaults.MinLength || policy.MaxLength != defaults.MaxLength {
		t.Fatalf("zero policy lengths = %+v", policy)
	}
	if !policy.DisallowUsername || !policy.DisallowEmail || policy.CommonPasswords == nil {
		t.Fatalf("zero policy did not use full defaults: %+v", policy)
	}
	if _, err := harness.service.Register(context.Background(), RegisterInput{
		Username: "weak", Email: "weak@example.com", Password: "short",
	}); !errors.Is(err, ErrPasswordPolicy) {
		t.Fatalf("short password = %v, want ErrPasswordPolicy", err)
	}
}

func TestServicePasswordPolicyExplicitEmptyDenyList(t *testing.T) {
	harness := newTestService(t, func(config *Config) {
		config.Policy = PasswordPolicy{MinLength: 8, CommonPasswords: map[string]struct{}{}}
	})
	if len(harness.service.Policy().CommonPasswords) != 0 {
		t.Fatalf("explicit empty deny list was replaced: %+v", harness.service.Policy())
	}
	if harness.service.Policy().MaxLength != 1024 {
		t.Fatalf("MaxLength = %d, want 1024", harness.service.Policy().MaxLength)
	}
	if _, err := harness.service.Register(context.Background(), RegisterInput{
		Username: "empty-list", Email: "empty-list@example.com", Password: "password",
	}); err != nil {
		t.Fatalf("password rejected by a disabled deny list: %v", err)
	}
}
