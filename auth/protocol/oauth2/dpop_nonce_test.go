package oauth2

import (
	"context"
	"crypto/sha256"
	"errors"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/shibingli/ydx/auth"
	"github.com/shibingli/ydx/auth/token/jose"
	"github.com/shibingli/ydx/base64"
	"github.com/shibingli/ydx/json"
)

// dpopTestKey bundles a signing key with its public JWK header value. | dpopTestKey 把签名密钥与其
// 公钥 JWK 头部值组合在一起。
type dpopTestKey struct {
	key       *jose.Key
	publicJWK map[string]any
}

// newDPoPTestKey generates an ES256 key for proof tests. | newDPoPTestKey 为证明测试生成 ES256 密钥。
func newDPoPTestKey(t *testing.T) *dpopTestKey {
	t.Helper()
	key, err := jose.GenerateKey("ES256", 0)
	if err != nil {
		t.Fatalf("generate DPoP key: %v", err)
	}
	key.Kid = "dpop-test-key"
	key.Alg = "ES256"
	raw, err := json.Marshal(key.Public())
	if err != nil {
		t.Fatalf("marshal public JWK: %v", err)
	}
	var jwk map[string]any
	if err := json.Unmarshal(raw, &jwk); err != nil {
		t.Fatalf("decode public JWK: %v", err)
	}
	return &dpopTestKey{key: key, publicJWK: jwk}
}

// proof signs claims as a dpop+jwt with the public JWK header. | proof 把 claims 签为带公钥 JWK 头部的
// dpop+jwt。
func (k *dpopTestKey) proof(t *testing.T, claims map[string]any) string {
	t.Helper()
	payload, err := json.Marshal(claims)
	if err != nil {
		t.Fatalf("marshal proof claims: %v", err)
	}
	signed, err := jose.Sign(payload, k.key, jose.SignOptions{
		Alg:   "ES256",
		Kid:   k.key.Kid,
		Typ:   "dpop+jwt",
		Extra: map[string]any{"jwk": k.publicJWK},
	})
	if err != nil {
		t.Fatalf("sign DPoP proof: %v", err)
	}
	return signed
}

// thumbprint returns the RFC 7638 JWK thumbprint. | thumbprint 返回 RFC 7638 JWK 指纹。
func (k *dpopTestKey) thumbprint(t *testing.T) string {
	t.Helper()
	thumbprint, err := k.key.Public().Thumbprint()
	if err != nil {
		t.Fatalf("thumbprint: %v", err)
	}
	return thumbprint
}

// dpopProofClaims builds a proof claim set. | dpopProofClaims 构建证明声明集。
func dpopProofClaims(htm, htu, jti, nonce, ath string, iat time.Time) map[string]any {
	claims := map[string]any{
		"htm": htm,
		"htu": htu,
		"jti": jti,
		"iat": iat.Unix(),
	}
	if nonce != "" {
		claims["nonce"] = nonce
	}
	if ath != "" {
		claims["ath"] = ath
	}
	return claims
}

// rawDPoPTokenRequest performs a token request with a trusted forwarding header. |
// rawDPoPTokenRequest 使用可信转发头执行令牌请求。
func rawDPoPTokenRequest(t *testing.T, server *Server, form url.Values, client *Client, proof string) *httptest.ResponseRecorder {
	t.Helper()
	req := httptest.NewRequest(http.MethodPost, "https://auth.example/token", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Set("X-Forwarded-Proto", "https")
	req.SetBasicAuth(url.QueryEscape(client.ID), url.QueryEscape("super-secret"))
	if proof != "" {
		req.Header.Set("DPoP", proof)
	}
	w := httptest.NewRecorder()
	server.Token(w, req)
	return w
}

func TestMemoryDPoPNonceStore(t *testing.T) {
	ctx := context.Background()
	now := flowNow
	store := NewMemoryDPoPNonceStore()

	nonce, err := store.Issue(ctx, now, time.Minute)
	if err != nil || nonce == "" {
		t.Fatalf("issue = %q err=%v", nonce, err)
	}
	if ok, err := store.Accept(ctx, nonce, now); err != nil || !ok {
		t.Fatalf("accept = %v err=%v", ok, err)
	}
	// RFC 9449 nonces are time-window values, not single-use values. | RFC 9449 nonce 是时间窗取值，
	// 不是一次性值。
	if ok, err := store.Accept(ctx, nonce, now.Add(30*time.Second)); err != nil || !ok {
		t.Fatalf("nonce reuse = %v err=%v", ok, err)
	}
	if ok, err := store.Accept(ctx, "", now); err != nil || ok {
		t.Fatalf("empty nonce = %v err=%v", ok, err)
	}
	oversized := strings.Repeat("n", maxDPoPNonceLength+1)
	if ok, err := store.Accept(ctx, oversized, now); err != nil || ok {
		t.Fatalf("oversized nonce = %v err=%v", ok, err)
	}
	// The expiry instant itself is already expired. | 过期时刻本身即已过期。
	if ok, err := store.Accept(ctx, nonce, now.Add(time.Minute)); err != nil || ok {
		t.Fatalf("expired nonce = %v err=%v", ok, err)
	}
	if _, exists := store.nonces[nonce]; exists {
		t.Fatal("expired nonce was not pruned by Accept")
	}

	// A zero TTL uses the documented five-minute default. | 零寿命使用文档约定的 5 分钟默认值。
	short, err := store.Issue(ctx, now, 0)
	if err != nil || short == "" {
		t.Fatalf("default TTL issue = %q err=%v", short, err)
	}
	if ok, _ := store.Accept(ctx, short, now.Add(4*time.Minute)); !ok {
		t.Fatal("default TTL nonce expired too early")
	}
	store.Prune(now.Add(defaultDPoPNonceTTL))
	if len(store.nonces) != 0 {
		t.Fatalf("prune left %d nonces", len(store.nonces))
	}

	// The capacity bound evicts an arbitrary nonce instead of growing without limit. | 容量上限会淘汰
	// 任意 nonce，而不是无限增长。
	for i := 0; i < memoryDPoPNonceCapacity+8; i++ {
		if _, err := store.Issue(ctx, now, time.Minute); err != nil {
			t.Fatalf("capacity issue %d: %v", i, err)
		}
	}
	if len(store.nonces) > memoryDPoPNonceCapacity {
		t.Fatalf("nonce store size = %d, want <= %d", len(store.nonces), memoryDPoPNonceCapacity)
	}

	var nilStore *MemoryDPoPNonceStore
	if _, err := nilStore.Issue(ctx, now, time.Minute); !errors.Is(err, ErrServerError) {
		t.Fatalf("nil issue = %v", err)
	}
	if ok, err := nilStore.Accept(ctx, nonce, now); ok || !errors.Is(err, ErrServerError) {
		t.Fatalf("nil accept = %v %v", ok, err)
	}
	nilStore.Prune(now)
}

func TestDPoPProofVerifierNonceMode(t *testing.T) {
	key := newDPoPTestKey(t)
	now := flowNow
	verifier := NewDPoPProofVerifier(DPoPVerifierConfig{
		Now:          func() time.Time { return now },
		RequireNonce: true,
		NonceTTL:     time.Minute,
	})
	ctx := context.Background()
	target := "https://auth.example/token"

	_, err := verifier.VerifyProof(ctx, key.proof(t, dpopProofClaims("POST", target, "nonce-jti-1", "", "", now)), "POST", target, "")
	var challenge *DPoPNonceRequiredError
	if !errors.As(err, &challenge) || challenge.Nonce == "" || !errors.Is(err, ErrDPoPNonceRequired) {
		t.Fatalf("first challenge = %v", err)
	}
	if errors.Is(err, ErrInvalidDPoPProof) {
		t.Fatalf("nonce challenge also classified as invalid proof: %v", err)
	}
	nonce := challenge.Nonce

	// A proof carrying the nonce succeeds, and the nonce stays usable until expiry. | 携带 nonce 的证明
	// 成功，且该 nonce 在过期前一直可用。
	if _, err := verifier.VerifyProof(ctx, key.proof(t, dpopProofClaims("POST", target, "nonce-jti-2", nonce, "", now)), "POST", target, ""); err != nil {
		t.Fatalf("proof with nonce: %v", err)
	}
	if _, err := verifier.VerifyProof(ctx, key.proof(t, dpopProofClaims("POST", target, "nonce-jti-3", nonce, "", now)), "POST", target, ""); err != nil {
		t.Fatalf("nonce reuse: %v", err)
	}

	// jti replay stays an invalid proof, not a nonce challenge. | jti 重放仍是无效证明，而不是 nonce
	// 挑战。
	replay := key.proof(t, dpopProofClaims("POST", target, "nonce-jti-4", nonce, "", now))
	if _, err := verifier.VerifyProof(ctx, replay, "POST", target, ""); err != nil {
		t.Fatalf("first replay-proof use: %v", err)
	}
	_, err = verifier.VerifyProof(ctx, replay, "POST", target, "")
	if !errors.Is(err, ErrInvalidDPoPProof) {
		t.Fatalf("replayed proof = %v", err)
	}
	if errors.As(err, &challenge) {
		t.Fatalf("replayed proof produced a nonce challenge: %v", err)
	}

	// Unknown nonces produce a challenge with a usable fresh nonce. | 未知 nonce 会生成带可用新 nonce 的
	// 挑战。
	_, err = verifier.VerifyProof(ctx, key.proof(t, dpopProofClaims("POST", target, "nonce-jti-5", "not-issued", "", now)), "POST", target, "")
	if !errors.As(err, &challenge) || challenge.Nonce == "" {
		t.Fatalf("unknown nonce = %v", err)
	}
	fresh := challenge.Nonce
	if _, err := verifier.VerifyProof(ctx, key.proof(t, dpopProofClaims("POST", target, "nonce-jti-6", fresh, "", now)), "POST", target, ""); err != nil {
		t.Fatalf("fresh nonce: %v", err)
	}

	// htm, htu and ath are still validated in nonce mode and never become nonce challenges. | nonce
	// 模式下仍校验 htm、htu 与 ath，且不会变成 nonce 挑战。
	wrongHTM := key.proof(t, dpopProofClaims("GET", target, "nonce-jti-7", fresh, "", now))
	if _, err := verifier.VerifyProof(ctx, wrongHTM, "POST", target, ""); !errors.Is(err, ErrInvalidDPoPProof) {
		t.Fatalf("htm mismatch = %v", err)
	}
	wrongHTU := key.proof(t, dpopProofClaims("POST", target+"/other", "nonce-jti-8", fresh, "", now))
	if _, err := verifier.VerifyProof(ctx, wrongHTU, "POST", target, ""); !errors.Is(err, ErrInvalidDPoPProof) {
		t.Fatalf("htu mismatch = %v", err)
	}
	missingATH := key.proof(t, dpopProofClaims("POST", target, "nonce-jti-9", fresh, "", now))
	if _, err := verifier.VerifyProof(ctx, missingATH, "POST", target, "access-token"); !errors.Is(err, ErrInvalidDPoPProof) {
		t.Fatalf("missing ath = %v", err)
	}

	// Expired nonces are challenged again, and the replacement is valid at the new instant. | 过期
	// nonce 会再次触发挑战，替换值在新时刻有效。
	expiring, err := verifier.IssueDPoPNonce(ctx, now)
	if err != nil || expiring == "" {
		t.Fatalf("issue expiring nonce = %q err=%v", expiring, err)
	}
	now = now.Add(2 * time.Minute)
	_, err = verifier.VerifyProof(ctx, key.proof(t, dpopProofClaims("POST", target, "nonce-jti-10", expiring, "", now)), "POST", target, "")
	if !errors.As(err, &challenge) || challenge.Nonce == "" {
		t.Fatalf("expired nonce = %v", err)
	}
	if _, err := verifier.VerifyProof(ctx, key.proof(t, dpopProofClaims("POST", target, "nonce-jti-11", challenge.Nonce, "", now)), "POST", target, ""); err != nil {
		t.Fatalf("replacement nonce: %v", err)
	}

	store, ok := verifier.config.Nonces.(*MemoryDPoPNonceStore)
	if !ok {
		t.Fatalf("verifier nonce store = %T", verifier.config.Nonces)
	}
	verifier.PruneDPoPNonces(now.Add(10 * time.Minute))
	if len(store.nonces) != 0 {
		t.Fatalf("verifier prune left %d nonces", len(store.nonces))
	}

	// Without nonce mode no nonce is issued. | 未启用 nonce 模式时不签发 nonce。
	plain := NewDPoPProofVerifier(DPoPVerifierConfig{Now: func() time.Time { return now }})
	if nonce, err := plain.IssueDPoPNonce(ctx, now); err != nil || nonce != "" {
		t.Fatalf("disabled nonce issue = %q err=%v", nonce, err)
	}
	var nilVerifier *DPoPProofVerifier
	if nonce, err := nilVerifier.IssueDPoPNonce(ctx, now); err != nil || nonce != "" {
		t.Fatalf("nil verifier issue = %q err=%v", nonce, err)
	}
	nilVerifier.PruneDPoPNonces(now)
}

func TestServerDPoPNonceTokenEndpoint(t *testing.T) {
	key := newDPoPTestKey(t)
	now := flowNow
	verifier := NewDPoPProofVerifier(DPoPVerifierConfig{
		Now:          func() time.Time { return now },
		RequireNonce: true,
	})
	server, client := grantServer(t, func(config *ServerConfig) {
		config.DPoPVerifier = verifier
		config.DPoPRequired = true
		config.Clock = func() time.Time { return now }
	})
	target := "https://auth.example/token"
	form := url.Values{
		"grant_type": {GrantClientCredentials},
		"scope":      {"api:read"},
	}

	first := rawDPoPTokenRequest(t, server, form, client, key.proof(t, dpopProofClaims("POST", target, "token-jti-1", "", "", now)))
	requireErrorCode(t, first, http.StatusBadRequest, ErrorUseDPoPNonce)
	if challenge := first.Header().Get("WWW-Authenticate"); !strings.Contains(challenge, `error="use_dpop_nonce"`) {
		t.Fatalf("challenge header = %q", challenge)
	}
	nonce := first.Header().Get(DPoPNonceHeader)
	if nonce == "" {
		t.Fatal("challenge is missing DPoP-Nonce")
	}

	second := rawDPoPTokenRequest(t, server, form, client, key.proof(t, dpopProofClaims("POST", target, "token-jti-2", nonce, "", now)))
	if second.Code != http.StatusOK {
		t.Fatalf("retry status = %d body=%s", second.Code, second.Body.String())
	}
	var token TokenResponse
	if err := json.Unmarshal(second.Body.Bytes(), &token); err != nil {
		t.Fatalf("decode token response: %v", err)
	}
	if token.TokenType != TokenTypeDPoP || token.AccessToken == "" {
		t.Fatalf("token response = %+v", token)
	}
	if served := second.Header().Get(DPoPNonceHeader); served == "" {
		t.Fatal("successful DPoP response is missing DPoP-Nonce")
	}
	access, err := server.ValidateAccessToken(context.Background(), token.AccessToken)
	if err != nil || access.DPoPJKT != key.thumbprint(t) {
		t.Fatalf("access token binding = %+v err=%v", access, err)
	}

	// The consumed proof cannot be replayed even though its nonce is still valid. | 即使 nonce 仍有效，
	// 已使用的证明也不能重放。
	replay := rawDPoPTokenRequest(t, server, form, client, key.proof(t, dpopProofClaims("POST", target, "token-jti-2", nonce, "", now)))
	requireErrorCode(t, replay, http.StatusBadRequest, ErrorInvalidDPoPProof)

	unknown := rawDPoPTokenRequest(t, server, form, client, key.proof(t, dpopProofClaims("POST", target, "token-jti-3", "unknown-nonce", "", now)))
	requireErrorCode(t, unknown, http.StatusBadRequest, ErrorUseDPoPNonce)
	if unknown.Header().Get(DPoPNonceHeader) == "" {
		t.Fatal("unknown nonce challenge is missing DPoP-Nonce")
	}

	missing := rawDPoPTokenRequest(t, server, form, client, "")
	requireErrorCode(t, missing, http.StatusBadRequest, ErrorInvalidDPoPProof)

	// A Bearer response never carries a DPoP nonce. | Bearer 响应绝不携带 DPoP nonce。
	bearerServer, bearerClient := grantServer(t, func(config *ServerConfig) {
		config.DPoPVerifier = NewDPoPProofVerifier(DPoPVerifierConfig{
			Now:          func() time.Time { return now },
			RequireNonce: true,
		})
	})
	bearer := rawDPoPTokenRequest(t, bearerServer, form, bearerClient, "")
	if bearer.Code != http.StatusOK {
		t.Fatalf("bearer status = %d body=%s", bearer.Code, bearer.Body.String())
	}
	if header := bearer.Header().Get(DPoPNonceHeader); header != "" {
		t.Fatalf("bearer response DPoP-Nonce = %q", header)
	}
	body := decodeMap(t, bearer)
	if body["token_type"] != TokenTypeBearer {
		t.Fatalf("bearer token_type = %v", body["token_type"])
	}
}

func TestAuthorizationCodeDPoPNonceRetryPreservesCode(t *testing.T) {
	key := newDPoPTestKey(t)
	now := flowNow
	verifier := NewDPoPProofVerifier(DPoPVerifierConfig{
		Now:          func() time.Time { return now },
		RequireNonce: true,
	})
	server, client := grantServer(t, func(config *ServerConfig) {
		config.DPoPVerifier = verifier
		config.DPoPRequired = true
		config.Clock = func() time.Time { return now }
	})
	ctx := context.Background()
	if err := server.config.Store.SaveAuthorizationCode(ctx, &AuthorizationCode{
		CodeHash:  auth.HashToken("nonce-code"),
		ClientID:  client.ID,
		UserID:    "user-1",
		Subject:   "user-1",
		Scopes:    []string{"api:read"},
		CreatedAt: now,
		ExpiresAt: now.Add(time.Hour),
	}); err != nil {
		t.Fatalf("save authorization code: %v", err)
	}
	target := "https://auth.example/token"
	form := url.Values{
		"grant_type": {GrantAuthorizationCode},
		"code":       {"nonce-code"},
	}

	// A missing proof fails before the code is consumed. | 缺少证明会在消费授权码之前失败。
	missing := rawDPoPTokenRequest(t, server, form, client, "")
	requireErrorCode(t, missing, http.StatusBadRequest, ErrorInvalidDPoPProof)

	// The nonce challenge must not consume the authorization code. | nonce 挑战不得消费授权码。
	first := rawDPoPTokenRequest(t, server, form, client, key.proof(t, dpopProofClaims("POST", target, "code-jti-1", "", "", now)))
	requireErrorCode(t, first, http.StatusBadRequest, ErrorUseDPoPNonce)
	nonce := first.Header().Get(DPoPNonceHeader)
	if nonce == "" {
		t.Fatal("challenge is missing DPoP-Nonce")
	}

	second := rawDPoPTokenRequest(t, server, form, client, key.proof(t, dpopProofClaims("POST", target, "code-jti-2", nonce, "", now)))
	if second.Code != http.StatusOK {
		t.Fatalf("retry status = %d body=%s", second.Code, second.Body.String())
	}
	var token TokenResponse
	if err := json.Unmarshal(second.Body.Bytes(), &token); err != nil {
		t.Fatalf("decode token response: %v", err)
	}
	if token.TokenType != TokenTypeDPoP {
		t.Fatalf("token type = %q", token.TokenType)
	}

	// Only the successful exchange consumes the code. | 只有成功的兑换才会消费授权码。
	third := rawDPoPTokenRequest(t, server, form, client, key.proof(t, dpopProofClaims("POST", target, "code-jti-3", nonce, "", now)))
	requireErrorCode(t, third, http.StatusBadRequest, ErrorInvalidGrant)
}

func TestDPoPNonceResourceServerChallenge(t *testing.T) {
	key := newDPoPTestKey(t)
	thumbprint := key.thumbprint(t)
	now := flowNow
	verifier := NewDPoPProofVerifier(DPoPVerifierConfig{
		Now:          func() time.Time { return now },
		RequireNonce: true,
	})
	server, client := grantServer(t, func(config *ServerConfig) {
		config.DPoPVerifier = verifier
		config.Clock = func() time.Time { return now }
	})
	ctx := context.Background()
	rawAccess := "resource-access-token"
	if err := server.config.Store.SaveAccessToken(ctx, &AccessToken{
		TokenHash: auth.HashToken(rawAccess),
		ClientID:  client.ID,
		Subject:   "user-1",
		Scopes:    []string{"api:read"},
		IssuedAt:  now,
		ExpiresAt: now.Add(time.Hour),
		DPoPJKT:   thumbprint,
	}); err != nil {
		t.Fatalf("save access token: %v", err)
	}
	target := "https://auth.example/resource"
	resourceRequest := func(proof string) *http.Request {
		req := httptest.NewRequest(http.MethodGet, target, nil)
		req.Header.Set("X-Forwarded-Proto", "https")
		if proof != "" {
			req.Header.Set("DPoP", proof)
		}
		return req
	}

	sum := sha256.Sum256([]byte(rawAccess))
	ath := base64.RawURLEncoding.EncodeToString(sum[:])
	_, err := server.ValidateAccessTokenRequest(ctx, resourceRequest(key.proof(t, dpopProofClaims("GET", target, "rs-jti-1", "", ath, now))), rawAccess)
	var challenge *DPoPNonceRequiredError
	if !errors.As(err, &challenge) || challenge.Nonce == "" {
		t.Fatalf("resource challenge = %v", err)
	}
	recorder := httptest.NewRecorder()
	if !WriteDPoPChallenge(recorder, err) {
		t.Fatal("nonce challenge was not handled")
	}
	if recorder.Code != http.StatusUnauthorized {
		t.Fatalf("challenge status = %d", recorder.Code)
	}
	if header := recorder.Header().Get("WWW-Authenticate"); !strings.Contains(header, `error="use_dpop_nonce"`) {
		t.Fatalf("challenge header = %q", header)
	}
	nonce := recorder.Header().Get(DPoPNonceHeader)
	if nonce == "" {
		t.Fatal("resource challenge is missing DPoP-Nonce")
	}

	token, err := server.ValidateAccessTokenRequest(ctx, resourceRequest(key.proof(t, dpopProofClaims("GET", target, "rs-jti-2", nonce, ath, now))), rawAccess)
	if err != nil || token.DPoPJKT != thumbprint {
		t.Fatalf("resource retry = %+v err=%v", token, err)
	}

	wrongATH := key.proof(t, dpopProofClaims("GET", target, "rs-jti-3", nonce, "wrong-ath", now))
	_, err = server.ValidateAccessTokenRequest(ctx, resourceRequest(wrongATH), rawAccess)
	if !errors.Is(err, ErrInvalidDPoPProof) {
		t.Fatalf("wrong ath = %v", err)
	}
	proofRecorder := httptest.NewRecorder()
	if !WriteDPoPChallenge(proofRecorder, err) {
		t.Fatal("invalid proof challenge was not handled")
	}
	if proofRecorder.Code != http.StatusUnauthorized {
		t.Fatalf("invalid proof status = %d", proofRecorder.Code)
	}
	if header := proofRecorder.Header().Get("WWW-Authenticate"); !strings.Contains(header, `error="invalid_dpop_proof"`) {
		t.Fatalf("invalid proof header = %q", header)
	}
	if header := proofRecorder.Header().Get(DPoPNonceHeader); header != "" {
		t.Fatalf("invalid proof carried DPoP-Nonce %q", header)
	}

	if WriteDPoPChallenge(httptest.NewRecorder(), nil) {
		t.Fatal("nil error was handled as a challenge")
	}
	if WriteDPoPChallenge(httptest.NewRecorder(), errTest) {
		t.Fatal("unrelated error was handled as a challenge")
	}
}

func TestRefreshTokenDPoPBinding(t *testing.T) {
	bindingKey := newDPoPTestKey(t)
	thumbprint := bindingKey.thumbprint(t)
	now := flowNow
	accessKey, err := jose.GenerateKey("ES256", 0)
	if err != nil {
		t.Fatalf("generate access-token key: %v", err)
	}
	accessKey.Kid = "access-token-key"
	accessKey.Alg = "ES256"
	accessIssuer, err := NewJWTAccessTokenIssuer(accessKey, "ES256")
	if err != nil {
		t.Fatalf("access-token issuer: %v", err)
	}
	accessKeys := &jose.KeySet{}
	if err := accessKeys.Add(accessKey.Public()); err != nil {
		t.Fatalf("add access-token key: %v", err)
	}
	accessVerifier, err := NewJWTAccessTokenVerifier(accessKeys, "https://auth.example", "")
	if err != nil {
		t.Fatalf("access-token verifier: %v", err)
	}
	accessVerifier.SetClock(func() time.Time { return now })
	server, client := grantServer(t, func(config *ServerConfig) {
		config.DPoPVerifier = NewDPoPProofVerifier(DPoPVerifierConfig{Now: func() time.Time { return now }})
		config.TokenFormat = TokenFormatJWT
		config.AccessTokenIssuer = accessIssuer
		config.AccessTokenVerifier = accessVerifier
		config.Clock = func() time.Time { return now }
	})
	ctx := context.Background()
	rawRefresh := "bound-refresh-token"
	if err := server.config.Store.SaveRefreshToken(ctx, &RefreshToken{
		TokenHash: auth.HashToken(rawRefresh),
		FamilyID:  "family-bound",
		ClientID:  client.ID,
		UserID:    "user-1",
		Subject:   "user-1",
		Scopes:    []string{"api:read"},
		DPoPJKT:   thumbprint,
		CreatedAt: now,
		ExpiresAt: now.Add(time.Hour),
	}); err != nil {
		t.Fatalf("save refresh token: %v", err)
	}
	target := "https://auth.example/token"
	form := url.Values{
		"grant_type":    {GrantRefreshToken},
		"refresh_token": {rawRefresh},
	}

	missingProof := rawDPoPTokenRequest(t, server, form, client, "")
	requireErrorCode(t, missingProof, http.StatusBadRequest, ErrorInvalidDPoPProof)

	otherKey := newDPoPTestKey(t)
	mismatched := rawDPoPTokenRequest(t, server, form, client, otherKey.proof(t, dpopProofClaims("POST", target, "refresh-jti-1", "", "", now)))
	requireErrorCode(t, mismatched, http.StatusBadRequest, ErrorInvalidDPoPProof)

	matched := rawDPoPTokenRequest(t, server, form, client, bindingKey.proof(t, dpopProofClaims("POST", target, "refresh-jti-2", "", "", now)))
	if matched.Code != http.StatusOK {
		t.Fatalf("refresh status = %d body=%s", matched.Code, matched.Body.String())
	}
	var token TokenResponse
	if err := json.Unmarshal(matched.Body.Bytes(), &token); err != nil {
		t.Fatalf("decode refresh response: %v", err)
	}
	if token.TokenType != TokenTypeDPoP || token.RefreshToken == "" {
		t.Fatalf("refresh response = %+v", token)
	}
	access, err := server.ValidateAccessToken(ctx, token.AccessToken)
	if err != nil || access.DPoPJKT != thumbprint {
		t.Fatalf("JWT cnf.jkt = %+v err=%v", access, err)
	}
	rotated, err := server.config.Store.GetRefreshToken(ctx, auth.HashToken(token.RefreshToken))
	if err != nil || rotated.DPoPJKT != thumbprint {
		t.Fatalf("rotated refresh binding = %+v err=%v", rotated, err)
	}
}

// integrationDPoPSigner signs real proofs for a client integration test and records the nonces the
// client supplied. | integrationDPoPSigner 为客户端集成测试签发真实证明并记录客户端提供的 nonce。
type integrationDPoPSigner struct {
	key     *dpopTestKey
	now     func() time.Time
	mu      sync.Mutex
	counter int
	nonces  []string
}

func (s *integrationDPoPSigner) SignDPoP(method, target, accessToken string) (string, error) {
	return s.sign(method, target, accessToken, "")
}

func (s *integrationDPoPSigner) SignDPoPWithNonce(method, target, accessToken, nonce string) (string, error) {
	return s.sign(method, target, accessToken, nonce)
}

func (s *integrationDPoPSigner) Thumbprint() (string, error) {
	return s.key.key.Public().Thumbprint()
}

func (s *integrationDPoPSigner) sign(method, target, accessToken, nonce string) (string, error) {
	s.mu.Lock()
	s.counter++
	jti := "integration-jti-" + strconv.Itoa(s.counter)
	s.nonces = append(s.nonces, nonce)
	s.mu.Unlock()
	ath := ""
	if accessToken != "" {
		sum := sha256.Sum256([]byte(accessToken))
		ath = base64.RawURLEncoding.EncodeToString(sum[:])
	}
	payload, err := json.Marshal(dpopProofClaims(method, target, jti, nonce, ath, s.now()))
	if err != nil {
		return "", err
	}
	return jose.Sign(payload, s.key.key, jose.SignOptions{
		Alg:   "ES256",
		Kid:   s.key.key.Kid,
		Typ:   "dpop+jwt",
		Extra: map[string]any{"jwk": s.key.publicJWK},
	})
}

func (s *integrationDPoPSigner) recordedNonces() []string {
	s.mu.Lock()
	defer s.mu.Unlock()
	return append([]string(nil), s.nonces...)
}

func TestClientAuthorizationCodeNonceRetryIntegration(t *testing.T) {
	now := flowNow
	verifier := NewDPoPProofVerifier(DPoPVerifierConfig{
		Now:          func() time.Time { return now },
		RequireNonce: true,
	})
	server, client := grantServer(t, func(config *ServerConfig) {
		config.DPoPVerifier = verifier
		config.DPoPRequired = true
		config.Clock = func() time.Time { return now }
	})
	ctx := context.Background()
	if err := server.config.Store.SaveAuthorizationCode(ctx, &AuthorizationCode{
		CodeHash:  auth.HashToken("integration-code"),
		ClientID:  client.ID,
		UserID:    "user-1",
		Subject:   "user-1",
		Scopes:    []string{"api:read"},
		CreatedAt: now,
		ExpiresAt: now.Add(time.Hour),
	}); err != nil {
		t.Fatalf("save authorization code: %v", err)
	}
	httpServer := httptest.NewServer(http.HandlerFunc(server.Token))
	defer httpServer.Close()
	signer := &integrationDPoPSigner{key: newDPoPTestKey(t), now: func() time.Time { return now }}
	// The query exercises RFC 9449 htu normalization; it is not part of the signed target. | 查询串
	// 用于验证 RFC 9449 htu 规范化；它不属于签名目标。
	oauthClient, err := NewClient(ClientConfig{
		ClientID:     client.ID,
		ClientSecret: "super-secret",
		Endpoint:     Endpoint{TokenURL: httpServer.URL + "/token?tenant=acme"},
		DPoPKey:      signer,
	})
	if err != nil {
		t.Fatalf("new client: %v", err)
	}
	token, err := oauthClient.Exchange(ctx, "integration-code")
	if err != nil {
		t.Fatalf("exchange: %v", err)
	}
	if token.TokenType != TokenTypeDPoP || token.AccessToken == "" {
		t.Fatalf("token = %+v", token)
	}
	nonces := signer.recordedNonces()
	if len(nonces) != 2 || nonces[0] != "" || nonces[1] == "" {
		t.Fatalf("client nonces = %v", nonces)
	}
	if got := oauthClient.DPoPNonce(); got == "" {
		t.Fatal("client did not remember the successful response nonce")
	}
}

// nonceSignerStub records nonces passed to SignDPoPWithNonce. | nonceSignerStub 记录传给
// SignDPoPWithNonce 的 nonce。
type nonceSignerStub struct {
	mu     sync.Mutex
	nonces []string
}

func (s *nonceSignerStub) SignDPoP(string, string, string) (string, error) {
	return s.record("")
}

func (s *nonceSignerStub) SignDPoPWithNonce(_, _, _, nonce string) (string, error) {
	return s.record(nonce)
}

func (s *nonceSignerStub) Thumbprint() (string, error) { return "thumb", nil }

func (s *nonceSignerStub) record(nonce string) (string, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.nonces = append(s.nonces, nonce)
	return "proof:" + nonce, nil
}

func (s *nonceSignerStub) recorded() []string {
	s.mu.Lock()
	defer s.mu.Unlock()
	return append([]string(nil), s.nonces...)
}

func TestClientDPoPNonceRetry(t *testing.T) {
	var requests atomic.Int32
	var proofs sync.Map
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		index := int(requests.Add(1))
		proofs.Store(index, r.Header.Get("DPoP"))
		w.Header().Set("Content-Type", "application/json")
		if index == 1 {
			w.Header().Set(DPoPNonceHeader, "nonce-1")
			w.Header().Set("WWW-Authenticate", `DPoP error="use_dpop_nonce"`)
			w.WriteHeader(http.StatusBadRequest)
			_, _ = w.Write([]byte(`{"error":"use_dpop_nonce"}`))
			return
		}
		_, _ = w.Write([]byte(`{"access_token":"at-1","token_type":"DPoP","expires_in":60}`))
	}))
	defer server.Close()
	signer := &nonceSignerStub{}
	client, err := NewClient(ClientConfig{
		ClientID:     "web",
		ClientSecret: "s3cret",
		Endpoint:     Endpoint{TokenURL: server.URL + "/token"},
		DPoPKey:      signer,
	})
	if err != nil {
		t.Fatalf("new client: %v", err)
	}
	token, err := client.ClientCredentials(context.Background())
	if err != nil {
		t.Fatalf("client credentials: %v", err)
	}
	if token.TokenType != TokenTypeDPoP || requests.Load() != 2 {
		t.Fatalf("token = %+v requests = %d", token, requests.Load())
	}
	first, _ := proofs.Load(1)
	second, _ := proofs.Load(2)
	if first != "proof:" || second != "proof:nonce-1" {
		t.Fatalf("proofs = %v %v", first, second)
	}
	if got := client.DPoPNonce(); got != "nonce-1" {
		t.Fatalf("remembered nonce = %q", got)
	}
	if recorded := signer.recorded(); len(recorded) != 2 || recorded[0] != "" || recorded[1] != "nonce-1" {
		t.Fatalf("signer nonces = %v", recorded)
	}

	// A signer that cannot embed a nonce never retries. | 无法嵌入 nonce 的签名器绝不重试。
	var plainRequests atomic.Int32
	plainServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		plainRequests.Add(1)
		w.Header().Set(DPoPNonceHeader, "nonce-plain")
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusBadRequest)
		_, _ = w.Write([]byte(`{"error":"use_dpop_nonce"}`))
	}))
	defer plainServer.Close()
	plainClient, err := NewClient(ClientConfig{
		ClientID:     "web",
		ClientSecret: "s3cret",
		Endpoint:     Endpoint{TokenURL: plainServer.URL + "/token"},
		DPoPKey:      dpoPSignerStub{proof: "proof-1"},
	})
	if err != nil {
		t.Fatalf("plain client: %v", err)
	}
	if _, err := plainClient.ClientCredentials(context.Background()); !errors.Is(err, ErrDPoPNonceRequired) {
		t.Fatalf("plain signer error = %v", err)
	}
	if plainRequests.Load() != 1 {
		t.Fatalf("plain signer requests = %d, want 1", plainRequests.Load())
	}

	// A server that keeps challenging is retried exactly once. | 持续挑战的服务器只会被重试一次。
	var alwaysRequests atomic.Int32
	alwaysServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		index := alwaysRequests.Add(1)
		w.Header().Set(DPoPNonceHeader, "nonce-"+string(rune('0'+index)))
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusBadRequest)
		_, _ = w.Write([]byte(`{"error":"use_dpop_nonce"}`))
	}))
	defer alwaysServer.Close()
	alwaysClient, err := NewClient(ClientConfig{
		ClientID:     "web",
		ClientSecret: "s3cret",
		Endpoint:     Endpoint{TokenURL: alwaysServer.URL + "/token"},
		DPoPKey:      &nonceSignerStub{},
	})
	if err != nil {
		t.Fatalf("always client: %v", err)
	}
	if _, err := alwaysClient.ClientCredentials(context.Background()); !errors.Is(err, ErrDPoPNonceRequired) {
		t.Fatalf("always challenge error = %v", err)
	}
	if alwaysRequests.Load() != 2 {
		t.Fatalf("always challenge requests = %d, want 2", alwaysRequests.Load())
	}
}
