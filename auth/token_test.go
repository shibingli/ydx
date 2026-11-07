package auth

import (
	"errors"
	"strings"
	"testing"
	"time"
)

func TestRandomToken(t *testing.T) {
	for _, length := range []int{0, -1, -100} {
		if _, err := RandomToken(length); !errors.Is(err, ErrInvalidRequest) {
			t.Fatalf("RandomToken(%d) error = %v, want ErrInvalidRequest", length, err)
		}
	}
	one, err := RandomToken(1)
	if err != nil || len(one) != 2 {
		t.Fatalf("RandomToken(1) = %q %v", one, err)
	}
	token, err := RandomToken(32)
	if err != nil {
		t.Fatalf("RandomToken(32): %v", err)
	}
	if len(token) != 43 {
		t.Fatalf("token length = %d, want 43", len(token))
	}
	for _, r := range token {
		if !strings.ContainsRune("ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_", r) {
			t.Fatalf("token contains non-URL-safe character %q", r)
		}
	}
	second, err := RandomToken(32)
	if err != nil || second == token {
		t.Fatalf("tokens not unique: %v", err)
	}
}

func TestHashTokenAndComparison(t *testing.T) {
	hash := HashToken("bearer-secret")
	if len(hash) != 43 || hash != HashToken("bearer-secret") {
		t.Fatalf("HashToken = %q", hash)
	}
	if hash == HashToken("other-secret") {
		t.Fatal("distinct tokens hashed equally")
	}
	if !TokenHashMatches(hash, "bearer-secret") {
		t.Fatal("matching token rejected")
	}
	if TokenHashMatches(hash, "wrong-secret") || TokenHashMatches("", "bearer-secret") || TokenHashMatches(hash, "") {
		t.Fatal("non-matching token accepted")
	}
	if !SecureEqual("same", "same") || SecureEqual("same", "other") || !SecureEqual("", "") {
		t.Fatal("SecureEqual behavior")
	}
}

func TestNewID(t *testing.T) {
	first := NewID("user")
	second := NewID("user")
	if !strings.HasPrefix(first, "user_") || len(first) != len("user_")+22 {
		t.Fatalf("NewID = %q", first)
	}
	if first == second {
		t.Fatal("IDs not unique")
	}
	plain := NewID("")
	if len(plain) != 22 || strings.HasPrefix(plain, "user_") {
		t.Fatalf("plain ID = %q", plain)
	}
}

func TestSanitizeIdentifier(t *testing.T) {
	cases := map[string]string{
		" Alice@Example.COM \t": "alice@example.com",
		"a b\tc\rd\ne":          "abcde",
		"":                      "",
		"用户":                    "用户",
		"MiXeD-123":             "mixed-123",
	}
	for input, want := range cases {
		if got := SanitizeIdentifier(input); got != want {
			t.Fatalf("SanitizeIdentifier(%q) = %q, want %q", input, got, want)
		}
	}
}

func TestNow(t *testing.T) {
	before := time.Now().Add(-time.Second)
	now := Now(nil)
	after := time.Now().Add(time.Second)
	if now.Before(before) || now.After(after) || now.Location() != time.UTC {
		t.Fatalf("Now(nil) = %v", now)
	}
	fixed := time.Date(2026, 8, 1, 12, 0, 0, 0, time.FixedZone("UTC+8", 8*3600))
	got := Now(func() time.Time { return fixed })
	if !got.Equal(fixed) || got.Location() != time.UTC || got.Hour() != 4 {
		t.Fatalf("Now(fixed) = %v", got)
	}
}
