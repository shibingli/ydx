package jwt_test

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"testing"
	"time"

	golangjwt "github.com/golang-jwt/jwt/v5"
	ydjwt "github.com/shibingli/ydx/auth/token/jwt"
)

// jwtClaims returns the shared claim set. | jwtClaims 返回共享声明集。
func jwtClaims(now time.Time) map[string]any {
	return map[string]any{
		"sub": "user-42",
		"iss": "yd-bench",
		"aud": "api",
		"iat": now.Unix(),
		"exp": now.Add(time.Hour).Unix(),
	}
}

// TestJWTInteropWithGolangJWT checks both token directions for HS256 and ES256. |
// TestJWTInteropWithGolangJWT 检查 HS256 与 ES256 的双向令牌兼容性。
func TestJWTInteropWithGolangJWT(t *testing.T) {
	now := time.Now()
	claims := jwtClaims(now)
	parseOptions := ydjwt.ParseOptions{
		ValidAlgs:  []ydjwt.Alg{ydjwt.HS256, ydjwt.ES256},
		Issuer:     "yd-bench",
		Audience:   "api",
		RequireExp: true,
		Now:        func() time.Time { return now },
	}

	hmacKey := []byte("ydx-jwt-interop-hmac-secret-0123456789")
	ecKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("GenerateKey: %v", err)
	}
	var hmacAny any = hmacKey
	var ecAny any = &ecKey.PublicKey
	ydKeyFunc := func(ydjwt.Header) (any, error) { return hmacAny, nil }
	ydECKeyFunc := func(ydjwt.Header) (any, error) { return ecAny, nil }

	t.Run("ydx-to-golang-jwt-hs256", func(t *testing.T) {
		token, err := ydjwt.Sign(claims, hmacKey, ydjwt.HS256, ydjwt.SignOptions{Kid: "k1"})
		if err != nil {
			t.Fatalf("ydx Sign: %v", err)
		}
		parsed, err := golangjwt.Parse(token, func(*golangjwt.Token) (any, error) { return hmacKey, nil },
			golangjwt.WithValidMethods([]string{"HS256"}), golangjwt.WithIssuer("yd-bench"),
			golangjwt.WithAudience("api"), golangjwt.WithExpirationRequired())
		if err != nil || !parsed.Valid {
			t.Fatalf("golang-jwt rejected ydx token: valid=%v err=%v", parsed != nil && parsed.Valid, err)
		}
	})
	t.Run("golang-jwt-to-ydx-hs256", func(t *testing.T) {
		token, err := golangjwt.NewWithClaims(golangjwt.SigningMethodHS256, golangjwt.MapClaims(claims)).SignedString(hmacKey)
		if err != nil {
			t.Fatalf("golang-jwt Sign: %v", err)
		}
		if _, err := ydjwt.Parse(token, ydKeyFunc, parseOptions); err != nil {
			t.Fatalf("ydx rejected golang-jwt HS256 token: %v", err)
		}
	})
	t.Run("ydx-to-golang-jwt-es256", func(t *testing.T) {
		token, err := ydjwt.Sign(claims, ecKey, ydjwt.ES256, ydjwt.SignOptions{Kid: "k2"})
		if err != nil {
			t.Fatalf("ydx Sign: %v", err)
		}
		parsed, err := golangjwt.Parse(token, func(*golangjwt.Token) (any, error) { return &ecKey.PublicKey, nil },
			golangjwt.WithValidMethods([]string{"ES256"}), golangjwt.WithIssuer("yd-bench"),
			golangjwt.WithAudience("api"), golangjwt.WithExpirationRequired())
		if err != nil || !parsed.Valid {
			t.Fatalf("golang-jwt rejected ydx ES256 token: valid=%v err=%v", parsed != nil && parsed.Valid, err)
		}
	})
	t.Run("golang-jwt-to-ydx-es256", func(t *testing.T) {
		claimsWithExp := golangjwt.MapClaims(claims)
		token, err := golangjwt.NewWithClaims(golangjwt.SigningMethodES256, claimsWithExp).SignedString(ecKey)
		if err != nil {
			t.Fatalf("golang-jwt Sign: %v", err)
		}
		if _, err := ydjwt.Parse(token, ydECKeyFunc, parseOptions); err != nil {
			t.Fatalf("ydx rejected golang-jwt ES256 token: %v", err)
		}
	})
}
