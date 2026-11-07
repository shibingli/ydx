package oauth2

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"sync/atomic"
	"testing"
	"time"

	"github.com/shibingli/ydx/auth/token/jose"
	"github.com/shibingli/ydx/json"
)

// publicJWKS returns the JWK Set JSON for the public half of key. | publicJWKS 返回 key 公钥半部分的
// JWK Set JSON。
func publicJWKS(t *testing.T, key *jose.Key) []byte {
	t.Helper()
	set := &jose.KeySet{}
	if err := set.Add(key.Public()); err != nil {
		t.Fatalf("add public key: %v", err)
	}
	data, err := set.Marshal()
	if err != nil {
		t.Fatalf("marshal key set: %v", err)
	}
	return data
}

// signClaims signs claims with key. | signClaims 用 key 签发 claims。
func signClaims(t *testing.T, key *jose.Key, claims map[string]any) string {
	t.Helper()
	payload, err := json.Marshal(claims)
	if err != nil {
		t.Fatalf("marshal claims: %v", err)
	}
	token, err := jose.Sign(payload, key, jose.SignOptions{Alg: "ES256", Kid: key.Kid})
	if err != nil {
		t.Fatalf("sign claims: %v", err)
	}
	return token
}

// clientAssertionClaims returns a valid private_key_jwt claim set. | clientAssertionClaims 返回合法的
// private_key_jwt 声明集。
func clientAssertionClaims(clientID string, audience any, jti string, now time.Time) map[string]any {
	return map[string]any{
		"iss": clientID,
		"sub": clientID,
		"aud": audience,
		"exp": now.Add(time.Minute).Unix(),
		"iat": now.Unix(),
		"jti": jti,
	}
}

func TestPrivateKeyJWTVerifierInlineJWKS(t *testing.T) {
	key, _ := newTestJWTKey(t)
	now := time.Unix(1_700_000_000, 0).UTC()
	replay := NewMemoryDPoPReplayStore()
	replay.now = func() time.Time { return now }
	verifier := NewPrivateKeyJWTVerifier(PrivateKeyJWTConfig{Now: func() time.Time { return now }, Replay: replay})
	client := &Client{ID: "client-1", JWKS: publicJWKS(t, key)}
	ctx := context.Background()
	audience := "https://auth.example/token"

	if err := verifier.VerifyClientAssertion(ctx, nil, "x", audience); !errors.Is(err, ErrInvalidClient) {
		t.Fatalf("nil client = %v", err)
	}
	if err := verifier.VerifyClientAssertion(ctx, &Client{ID: "no-keys"}, "x", audience); !errors.Is(err, ErrInvalidClient) {
		t.Fatalf("missing keys = %v", err)
	}
	if err := verifier.VerifyClientAssertion(ctx, client, "not-a-jwt", audience); !errors.Is(err, ErrInvalidClient) {
		t.Fatalf("malformed assertion = %v", err)
	}
	assertion := signClaims(t, key, clientAssertionClaims("client-1", audience, "jti-1", now))
	if err := verifier.VerifyClientAssertion(ctx, client, assertion, audience); err != nil {
		t.Fatalf("valid assertion: %v", err)
	}
	if err := verifier.VerifyClientAssertion(ctx, client, assertion, audience); !errors.Is(err, ErrInvalidClient) {
		t.Fatalf("replayed assertion = %v", err)
	}

	// aud array encoding is accepted. | 接受 aud 数组编码。
	arrayClaims := clientAssertionClaims("client-1", []string{"other", audience}, "jti-array", now)
	if err := verifier.VerifyClientAssertion(ctx, client, signClaims(t, key, arrayClaims), audience); err != nil {
		t.Fatalf("array audience: %v", err)
	}
	// An empty expected audience skips the check. | 期望受众为空时跳过校验。
	if err := verifier.VerifyClientAssertion(ctx, client, signClaims(t, key, clientAssertionClaims("client-1", "any", "jti-noaud", now)), ""); err != nil {
		t.Fatalf("empty audience: %v", err)
	}

	badClaims := []map[string]any{
		{"iss": "other", "sub": "client-1", "aud": audience, "exp": now.Add(time.Minute).Unix(), "jti": "bad-iss"},
		{"iss": "client-1", "sub": "other", "aud": audience, "exp": now.Add(time.Minute).Unix(), "jti": "bad-sub"},
		{"iss": "client-1", "sub": "client-1", "aud": "https://other.example/token", "exp": now.Add(time.Minute).Unix(), "jti": "bad-aud"},
		{"iss": "client-1", "sub": "client-1", "aud": audience, "jti": "missing-exp"},
		{"iss": "client-1", "sub": "client-1", "aud": audience, "exp": now.Add(-time.Minute).Unix(), "jti": "expired"},
		{"iss": "client-1", "sub": "client-1", "aud": audience, "exp": now.Add(10 * time.Minute).Unix(), "jti": "long"},
		{"iss": "client-1", "sub": "client-1", "aud": audience, "exp": now.Add(time.Minute).Unix(), "iat": now.Add(time.Minute).Unix(), "jti": "future-iat"},
		{"iss": "client-1", "sub": "client-1", "aud": audience, "exp": now.Add(time.Minute).Unix()},
	}
	for _, claims := range badClaims {
		if err := verifier.VerifyClientAssertion(ctx, client, signClaims(t, key, claims), audience); !errors.Is(err, ErrInvalidClient) {
			t.Fatalf("claims %v = %v", claims, err)
		}
	}
	// An assertion signed by another key is rejected. | 其他密钥签发的断言会被拒绝。
	otherKey, _ := newTestJWTKey(t)
	otherKey.Kid = "other"
	if err := verifier.VerifyClientAssertion(ctx, client, signClaims(t, otherKey, clientAssertionClaims("client-1", audience, "jti-other", now)), audience); !errors.Is(err, ErrInvalidClient) {
		t.Fatalf("foreign signature = %v", err)
	}
}

func TestPrivateKeyJWTVerifierJWKSURI(t *testing.T) {
	key, _ := newTestJWTKey(t)
	now := time.Unix(1_700_000_000, 0).UTC()
	replay := NewMemoryDPoPReplayStore()
	replay.now = func() time.Time { return now }
	jwks := publicJWKS(t, key)
	var hits atomic.Int32
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		hits.Add(1)
		if r.URL.Path == "/bad" {
			w.WriteHeader(http.StatusInternalServerError)
			return
		}
		if r.URL.Path == "/garbage" {
			_, _ = w.Write([]byte("not a jwks"))
			return
		}
		_, _ = w.Write(jwks)
	}))
	defer server.Close()

	ctx := context.Background()
	audience := "https://auth.example/token"
	verifier := NewPrivateKeyJWTVerifier(PrivateKeyJWTConfig{Now: func() time.Time { return now }, Replay: replay})
	client := &Client{ID: "client-uri", JWKSURI: server.URL}
	for i := 0; i < 2; i++ {
		assertion := signClaims(t, key, clientAssertionClaims("client-uri", audience, "uri-jti-"+string(rune('a'+i)), now))
		if err := verifier.VerifyClientAssertion(ctx, client, assertion, audience); err != nil {
			t.Fatalf("verify %d: %v", i, err)
		}
	}
	if hits.Load() != 1 {
		t.Fatalf("jwks fetches = %d, want 1 (cached)", hits.Load())
	}

	// A negative cache TTL disables caching. | 负缓存时长禁用缓存。
	hits.Store(0)
	uncached := NewPrivateKeyJWTVerifier(PrivateKeyJWTConfig{Now: func() time.Time { return now }, JWKSCacheTTL: -1, Replay: NewMemoryDPoPReplayStore()})
	for i := 0; i < 2; i++ {
		assertion := signClaims(t, key, clientAssertionClaims("client-uri", audience, "uncached-jti-"+string(rune('a'+i)), now))
		if err := uncached.VerifyClientAssertion(ctx, client, assertion, audience); err != nil {
			t.Fatalf("uncached verify %d: %v", i, err)
		}
	}
	if hits.Load() != 2 {
		t.Fatalf("uncached jwks fetches = %d, want 2", hits.Load())
	}

	if err := verifier.VerifyClientAssertion(ctx, &Client{ID: "bad", JWKSURI: server.URL + "/bad"}, "x", audience); !errors.Is(err, ErrInvalidClient) {
		t.Fatalf("bad status = %v", err)
	}
	if err := verifier.VerifyClientAssertion(ctx, &Client{ID: "garbage", JWKSURI: server.URL + "/garbage"}, "x", audience); !errors.Is(err, ErrInvalidClient) {
		t.Fatalf("bad body = %v", err)
	}
	if err := verifier.VerifyClientAssertion(ctx, &Client{ID: "http", JWKSURI: "http://example.com/jwks"}, "x", audience); !errors.Is(err, ErrInvalidClient) {
		t.Fatalf("insecure jwks_uri = %v", err)
	}
	if err := verifier.VerifyClientAssertion(ctx, &Client{ID: "bad-url", JWKSURI: "://bad"}, "x", audience); !errors.Is(err, ErrInvalidClient) {
		t.Fatalf("malformed jwks_uri = %v", err)
	}
	// A loopback hostname such as localhost is allowed over plain HTTP. | localhost 等回环主机允许
	// 通过明文 HTTP 访问。
	loopback := &Client{ID: "loopback", JWKSURI: "http://localhost:1/jwks"}
	if err := verifier.VerifyClientAssertion(ctx, loopback, "x", audience); !errors.Is(err, ErrInvalidClient) {
		t.Fatalf("unreachable loopback = %v", err)
	}
}

func TestJWTAccessTokenIssuerAndVerifierErrors(t *testing.T) {
	key, err := jose.GenerateKey("ES256", 0)
	if err != nil {
		t.Fatal(err)
	}
	key.Kid = "at-key"
	key.Alg = "ES256"
	if _, err := NewJWTAccessTokenIssuer(nil, "ES256"); !errors.Is(err, ErrInvalidConfig) {
		t.Fatalf("nil key = %v", err)
	}
	noAlg := *key
	noAlg.Alg = ""
	if _, err := NewJWTAccessTokenIssuer(&noAlg, ""); !errors.Is(err, ErrInvalidConfig) {
		t.Fatalf("empty alg = %v", err)
	}
	issuer, err := NewJWTAccessTokenIssuer(key, "")
	if err != nil {
		t.Fatalf("default alg issuer: %v", err)
	}
	if _, err := issuer.SignAccessToken(context.Background(), nil); !errors.Is(err, ErrServerError) {
		t.Fatalf("nil claims = %v", err)
	}
	badAlg, err := NewJWTAccessTokenIssuer(key, "RS256")
	if err != nil {
		t.Fatalf("bad alg issuer: %v", err)
	}
	if _, err := badAlg.SignAccessToken(context.Background(), &AccessTokenClaims{Subject: "x"}); !errors.Is(err, ErrServerError) {
		t.Fatalf("mismatched alg = %v", err)
	}

	if _, err := NewJWTAccessTokenVerifier(nil, "https://auth.example", "api"); !errors.Is(err, ErrInvalidConfig) {
		t.Fatalf("nil key set = %v", err)
	}
	if _, err := NewJWTAccessTokenVerifier(&jose.KeySet{}, "", "api"); !errors.Is(err, ErrInvalidConfig) {
		t.Fatalf("empty issuer = %v", err)
	}

	now := time.Unix(1_700_000_000, 0).UTC()
	claims := &AccessTokenClaims{
		Issuer:    "https://auth.example",
		Subject:   "user-1",
		Audience:  []string{"api"},
		ExpiresAt: now.Add(time.Minute).Unix(),
		IssuedAt:  now.Unix(),
		JTI:       "jti-1",
		ClientID:  "web",
		Scope:     "api:read",
		CNF:       map[string]any{"jkt": "thumb", "x5t#S256": "cert"},
	}
	token, err := issuer.SignAccessToken(context.Background(), claims)
	if err != nil {
		t.Fatalf("sign: %v", err)
	}
	verifier, err := NewJWTAccessTokenVerifier(func() *jose.KeySet {
		set := &jose.KeySet{}
		_ = set.Add(key.Public())
		return set
	}(), "https://auth.example", "api")
	if err != nil {
		t.Fatal(err)
	}
	verifier.SetClock(func() time.Time { return now })
	got, err := verifier.VerifyAccessToken(context.Background(), token)
	if err != nil {
		t.Fatalf("verify: %v", err)
	}
	if got.Subject != "user-1" || got.JTI != "jti-1" {
		t.Fatalf("claims = %+v", got)
	}
	verifier.SetClock(func() time.Time { return now.Add(2 * time.Minute) })
	if _, err := verifier.VerifyAccessToken(context.Background(), token); !errors.Is(err, ErrInvalidGrant) {
		t.Fatalf("expired token = %v", err)
	}
	verifier.SetClock(func() time.Time { return now })

	wrongAudience, _ := NewJWTAccessTokenVerifier(func() *jose.KeySet {
		set := &jose.KeySet{}
		_ = set.Add(key.Public())
		return set
	}(), "https://auth.example", "other-api")
	wrongAudience.SetClock(func() time.Time { return now })
	if _, err := wrongAudience.VerifyAccessToken(context.Background(), token); !errors.Is(err, ErrInvalidGrant) {
		t.Fatalf("wrong audience = %v", err)
	}

	// A JWT with the wrong typ is rejected. | typ 错误的 JWT 会被拒绝。
	payload, _ := json.Marshal(claims)
	wrongTyp, err := jose.Sign(payload, key, jose.SignOptions{Alg: "ES256", Kid: key.Kid, Typ: "JWT"})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := verifier.VerifyAccessToken(context.Background(), wrongTyp); !errors.Is(err, ErrInvalidGrant) {
		t.Fatalf("wrong typ = %v", err)
	}
}

func TestDPoPProofVerifierEdges(t *testing.T) {
	key, err := jose.GenerateKey("ES256", 0)
	if err != nil {
		t.Fatal(err)
	}
	key.Kid = "dpop-edges"
	key.Alg = "ES256"
	publicJSON, _ := json.Marshal(key.Public())
	var publicJWK map[string]any
	if err := json.Unmarshal(publicJSON, &publicJWK); err != nil {
		t.Fatal(err)
	}
	privateJSON, _ := json.Marshal(key)
	var privateJWK map[string]any
	if err := json.Unmarshal(privateJSON, &privateJWK); err != nil {
		t.Fatal(err)
	}
	now := time.Unix(1_700_000_000, 0).UTC()
	makeProof := func(claims map[string]any, extra map[string]any, typ string) string {
		payload, _ := json.Marshal(claims)
		if extra == nil {
			extra = map[string]any{"jwk": publicJWK}
		}
		token, err := jose.Sign(payload, key, jose.SignOptions{Alg: "ES256", Kid: key.Kid, Typ: typ, Extra: extra})
		if err != nil {
			t.Fatalf("sign proof: %v", err)
		}
		return token
	}
	baseClaims := func() map[string]any {
		return map[string]any{
			"jti": "jti-edges",
			"htm": "POST",
			"htu": "https://auth.example/token",
			"iat": now.Unix(),
		}
	}
	verifier := NewDPoPProofVerifier(DPoPVerifierConfig{Now: func() time.Time { return now }})
	ctx := context.Background()

	if _, err := verifier.VerifyProof(ctx, "", "POST", "https://auth.example/token", ""); !errors.Is(err, ErrInvalidDPoPProof) {
		t.Fatalf("empty proof = %v", err)
	}
	if _, err := verifier.VerifyProof(ctx, "not-a-proof", "POST", "https://auth.example/token", ""); !errors.Is(err, ErrInvalidDPoPProof) {
		t.Fatalf("malformed proof = %v", err)
	}
	if _, err := verifier.VerifyProof(ctx, makeProof(baseClaims(), map[string]any{}, "dpop+jwt"), "POST", "https://auth.example/token", ""); !errors.Is(err, ErrInvalidDPoPProof) {
		t.Fatalf("missing jwk = %v", err)
	}
	if _, err := verifier.VerifyProof(ctx, makeProof(baseClaims(), map[string]any{"jwk": privateJWK}, "dpop+jwt"), "POST", "https://auth.example/token", ""); !errors.Is(err, ErrInvalidDPoPProof) {
		t.Fatalf("private jwk = %v", err)
	}
	if _, err := verifier.VerifyProof(ctx, makeProof(baseClaims(), nil, "JWT"), "POST", "https://auth.example/token", ""); !errors.Is(err, ErrInvalidDPoPProof) {
		t.Fatalf("wrong typ = %v", err)
	}

	method := baseClaims()
	method["htm"] = "GET"
	if _, err := verifier.VerifyProof(ctx, makeProof(method, nil, "dpop+jwt"), "POST", "https://auth.example/token", ""); !errors.Is(err, ErrInvalidDPoPProof) {
		t.Fatalf("htm mismatch = %v", err)
	}
	// Query strings are ignored when comparing htu. | 比较 htu 时忽略查询串。
	if _, err := verifier.VerifyProof(ctx, makeProof(baseClaims(), nil, "dpop+jwt"), "POST", "https://auth.example/token?x=1", ""); err != nil {
		t.Fatalf("htu query tolerance: %v", err)
	}

	missingIAT := baseClaims()
	delete(missingIAT, "iat")
	if _, err := verifier.VerifyProof(ctx, makeProof(missingIAT, nil, "dpop+jwt"), "POST", "https://auth.example/token", ""); !errors.Is(err, ErrInvalidDPoPProof) {
		t.Fatalf("missing iat = %v", err)
	}
	future := baseClaims()
	future["iat"] = now.Add(10 * time.Minute).Unix()
	if _, err := verifier.VerifyProof(ctx, makeProof(future, nil, "dpop+jwt"), "POST", "https://auth.example/token", ""); !errors.Is(err, ErrInvalidDPoPProof) {
		t.Fatalf("future iat = %v", err)
	}
	old := baseClaims()
	old["iat"] = now.Add(-10 * time.Minute).Unix()
	if _, err := verifier.VerifyProof(ctx, makeProof(old, nil, "dpop+jwt"), "POST", "https://auth.example/token", ""); !errors.Is(err, ErrInvalidDPoPProof) {
		t.Fatalf("old iat = %v", err)
	}
	missingJTI := baseClaims()
	delete(missingJTI, "jti")
	if _, err := verifier.VerifyProof(ctx, makeProof(missingJTI, nil, "dpop+jwt"), "POST", "https://auth.example/token", ""); !errors.Is(err, ErrInvalidDPoPProof) {
		t.Fatalf("missing jti = %v", err)
	}
	// ath must equal SHA-256(access token). | ath 必须等于访问令牌的 SHA-256。
	if _, err := verifier.VerifyProof(ctx, makeProof(baseClaims(), nil, "dpop+jwt"), "POST", "https://auth.example/token", "access-token"); !errors.Is(err, ErrInvalidDPoPProof) {
		t.Fatalf("missing ath = %v", err)
	}
	withATH := baseClaims()
	withATH["jti"] = "jti-ath"
	withATH["ath"] = "wrong"
	if _, err := verifier.VerifyProof(ctx, makeProof(withATH, nil, "dpop+jwt"), "POST", "https://auth.example/token", "access-token"); !errors.Is(err, ErrInvalidDPoPProof) {
		t.Fatalf("wrong ath = %v", err)
	}
}

// failingReplayStore always fails. | failingReplayStore 总是失败。
type failingReplayStore struct{}

func (failingReplayStore) Accept(context.Context, string, time.Time) (bool, error) {
	return false, errTest
}

func TestMemoryDPoPReplayStore(t *testing.T) {
	store := NewMemoryDPoPReplayStore()
	now := time.Unix(1_700_000_000, 0).UTC()
	store.now = func() time.Time { return now }
	ctx := context.Background()
	if fresh, err := store.Accept(ctx, "", now.Add(time.Minute)); !errors.Is(err, ErrInvalidDPoPProof) || fresh {
		t.Fatalf("empty jti = %v %v", fresh, err)
	}
	if fresh, err := store.Accept(ctx, "jti-1", now.Add(time.Minute)); err != nil || !fresh {
		t.Fatalf("first accept = %v %v", fresh, err)
	}
	if fresh, err := store.Accept(ctx, "jti-1", now.Add(time.Minute)); err != nil || fresh {
		t.Fatalf("replay accept = %v %v", fresh, err)
	}
	if fresh, err := store.Accept(ctx, "jti-2", now.Add(-time.Second)); err != nil || !fresh {
		t.Fatalf("expired accept = %v %v", fresh, err)
	}
	now = now.Add(2 * time.Minute)
	// The next Accept prunes replay entries whose deadline has passed. | 下一次 Accept 清理已过
	// 截止时间的重放条目。
	if fresh, err := store.Accept(ctx, "jti-1", now.Add(time.Minute)); err != nil || !fresh {
		t.Fatalf("expired jti-1 = %v %v", fresh, err)
	}
	if _, ok := store.seen["jti-2"]; ok {
		t.Fatal("expired replay entry not pruned")
	}
	if _, err := NewDPoPProofVerifier(DPoPVerifierConfig{Replay: failingReplayStore{}}).VerifyProof(
		ctx, "bad", "POST", "https://auth.example/token", ""); !errors.Is(err, ErrInvalidDPoPProof) {
		// A malformed proof fails before the replay store is consulted. | 畸形证明在访问重放存储前
		// 就已失败。
		t.Fatalf("failing replay store = %v", err)
	}
}

func TestAudienceClaimAndNumericClaim(t *testing.T) {
	var audience audienceClaim
	if err := json.Unmarshal([]byte(`"api"`), &audience); err != nil || !audience.Contains("api") || audience.Contains("other") {
		t.Fatalf("single audience = %v err=%v", audience, err)
	}
	if err := json.Unmarshal([]byte(`["api","other"]`), &audience); err != nil || len(audience) != 2 || !audience.Contains("other") {
		t.Fatalf("array audience = %v err=%v", audience, err)
	}
	if err := json.Unmarshal([]byte(`123`), &audience); err == nil {
		t.Fatal("numeric audience accepted")
	}
	if value, ok := numericClaim(float64(1)); !ok || value != 1 {
		t.Fatalf("float claim = %v %v", value, ok)
	}
	if value, ok := numericClaim(int64(2)); !ok || value != 2 {
		t.Fatalf("int64 claim = %v %v", value, ok)
	}
	if value, ok := numericClaim(3); !ok || value != 3 {
		t.Fatalf("int claim = %v %v", value, ok)
	}
	if _, ok := numericClaim("4"); ok {
		t.Fatal("string claim accepted")
	}
	if _, ok := numericClaim(nil); ok {
		t.Fatal("nil claim accepted")
	}
}
