package service

import (
	"context"
	"errors"
	"strings"
	"testing"
	"time"
)

func TestTokenLifecycle(t *testing.T) {
	current := time.Unix(1700000000, 0)
	m := newTestManager(t, func(o *Options) {
		o.Now = func() time.Time { return current }
		o.TokenTTL = time.Minute
	})
	token, err := m.signer.issue(context.Background(), TokenClaims{ChallengeID: "ch_1", Action: "login"})
	if err != nil {
		t.Fatal(err)
	}
	claims, err := m.VerifyToken(context.Background(), token, "login")
	if err != nil {
		t.Fatal(err)
	}
	if claims.ChallengeID != "ch_1" || claims.Issuer != "" {
		t.Fatalf("unexpected claims: %+v", claims)
	}
	if _, err := m.VerifyToken(context.Background(), token, "register"); !errors.Is(err, ErrTokenInvalid) {
		t.Fatalf("action mismatch: %v", err)
	}
	if _, err := m.ConsumeToken(context.Background(), token, "login"); err != nil {
		t.Fatalf("consume: %v", err)
	}
	if _, err := m.ConsumeToken(context.Background(), token, "login"); !errors.Is(err, ErrTokenUsed) {
		t.Fatalf("second consume: %v", err)
	}
}

func TestTokenExpiry(t *testing.T) {
	current := time.Unix(1700000000, 0)
	m := newTestManager(t, func(o *Options) {
		o.Now = func() time.Time { return current }
		o.TokenTTL = time.Second
	})
	token, err := m.signer.issue(context.Background(), TokenClaims{ChallengeID: "ch_1", Action: "login"})
	if err != nil {
		t.Fatal(err)
	}
	current = current.Add(2 * time.Second)
	if _, err := m.VerifyToken(context.Background(), token, "login"); !errors.Is(err, ErrTokenExpired) {
		t.Fatalf("expected expiry, got %v", err)
	}
}

func TestTokenTamperAndWrongKey(t *testing.T) {
	m := newTestManager(t, nil)
	token, err := m.signer.issue(context.Background(), TokenClaims{ChallengeID: "ch_1", Action: "login"})
	if err != nil {
		t.Fatal(err)
	}
	parts := strings.Split(token, ".")
	if len(parts) != tokenParts {
		t.Fatalf("token parts = %d", len(parts))
	}
	parts[2] = strings.Repeat("A", len(parts[2]))
	tampered := strings.Join(parts, ".")
	if _, err := m.VerifyToken(context.Background(), tampered, "login"); !errors.Is(err, ErrTokenInvalid) {
		t.Fatalf("tampered: %v", err)
	}
	other := newTestManager(t, func(o *Options) { o.Secret = []byte("abcdef0123456789abcdef0123456789") })
	if _, err := other.VerifyToken(context.Background(), token, "login"); !errors.Is(err, ErrTokenInvalid) {
		t.Fatalf("wrong key: %v", err)
	}
}
