package oauth2

import (
	"context"
	"testing"
	"time"

	"github.com/shibingli/ydx/auth/token/jose"
	"github.com/shibingli/ydx/json"
)

func TestJWTAccessTokenRoundTrip(t *testing.T) {
	key, err := jose.GenerateKey("ES256", 0)
	if err != nil {
		t.Fatalf("generate key: %v", err)
	}
	key.Kid = "at-1"
	key.Alg = "ES256"
	key.Use = "sig"
	keys := &jose.KeySet{}
	if err := keys.Add(key); err != nil {
		t.Fatalf("add key: %v", err)
	}
	issuer, err := NewJWTAccessTokenIssuer(key, "ES256")
	if err != nil {
		t.Fatalf("issuer: %v", err)
	}
	verifier, err := NewJWTAccessTokenVerifier(keys, "https://auth.example", "api")
	if err != nil {
		t.Fatalf("verifier: %v", err)
	}
	now := time.Now().UTC()
	token, err := issuer.SignAccessToken(context.Background(), &AccessTokenClaims{
		Issuer:    "https://auth.example",
		Subject:   "user-1",
		Audience:  []string{"api"},
		ExpiresAt: now.Add(time.Minute).Unix(),
		IssuedAt:  now.Unix(),
		JTI:       "jti-1",
		ClientID:  "web",
		Scope:     "api:read",
	})
	if err != nil {
		t.Fatalf("sign: %v", err)
	}
	claims, err := verifier.VerifyAccessToken(context.Background(), token)
	if err != nil {
		t.Fatalf("verify: %v", err)
	}
	if claims.Subject != "user-1" || claims.ClientID != "web" || claims.Scope != "api:read" {
		t.Fatalf("claims = %+v", claims)
	}
	if _, err := verifier.VerifyAccessToken(context.Background(), token+"x"); err == nil {
		t.Fatal("tampered token accepted")
	}
}

func TestDPoPProofVerifier(t *testing.T) {
	key, err := jose.GenerateKey("ES256", 0)
	if err != nil {
		t.Fatalf("generate key: %v", err)
	}
	key.Kid = "dpop-1"
	key.Alg = "ES256"
	key.Use = "sig"
	publicJSON, err := json.Marshal(key.Public())
	if err != nil {
		t.Fatal(err)
	}
	var jwk map[string]any
	if err := json.Unmarshal(publicJSON, &jwk); err != nil {
		t.Fatal(err)
	}
	makeProof := func(htu, jti string) string {
		payload, _ := json.Marshal(map[string]any{
			"jti": jti,
			"htm": "POST",
			"htu": htu,
			"iat": time.Now().Unix(),
		})
		proof, err := jose.Sign(payload, key, jose.SignOptions{
			Alg: "ES256",
			Kid: "dpop-1",
			Typ: "dpop+jwt",
			Extra: map[string]any{
				"jwk": jwk,
			},
		})
		if err != nil {
			t.Fatalf("sign proof: %v", err)
		}
		return proof
	}
	verifier := NewDPoPProofVerifier(DPoPVerifierConfig{})
	proof := makeProof("https://auth.example/token", "jti-1")
	jkt, err := verifier.VerifyProof(context.Background(), proof, "POST", "https://auth.example/token", "")
	if err != nil {
		t.Fatalf("verify proof: %v", err)
	}
	if jkt == "" {
		t.Fatal("empty jkt")
	}
	if _, err := verifier.VerifyProof(context.Background(), proof, "POST", "https://auth.example/token", ""); err == nil {
		t.Fatal("replayed proof accepted")
	}
	bad := makeProof("https://auth.example/other", "jti-2")
	if _, err := verifier.VerifyProof(context.Background(), bad, "POST", "https://auth.example/token", ""); err == nil {
		t.Fatal("wrong htu accepted")
	}
}
