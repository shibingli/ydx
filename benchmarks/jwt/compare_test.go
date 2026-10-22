package jwt

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	stdjson "encoding/json"
	"slices"
	"testing"
	"time"

	jose "github.com/go-jose/go-jose/v4"
	golangjwt "github.com/golang-jwt/jwt/v5"
	"github.com/lestrrat-go/jwx/v4/jwa"
	jwxjwt "github.com/lestrrat-go/jwx/v4/jwt"

	"github.com/shibingli/ydx/errs"
	ydxjwt "github.com/shibingli/ydx/jwt"
)

// benchCompareToken is the output slot for signing benchmarks. | benchCompareToken 是签发基准的输出槽位。
var benchCompareToken string

// errJoseClaims is returned when go-jose verified a signature but the claims failed the same
// checks the JWT libraries apply. | errJoseClaims 表示 go-jose 验签成功但声明未通过其它 JWT 库
// 所执行的同等校验。
var errJoseClaims = errs.New("benchmark: jose claims mismatch | benchmark：jose 声明不匹配")

// compareClaims returns the canonical six-claim payload. The audience is an array so every
// implementation accepts the same wire form. | compareClaims 返回规范的六项声明载荷。受众使用
// 数组形式，使所有实现接受相同的线上格式。
func compareClaims(now time.Time) map[string]any {
	return map[string]any{
		"sub": "user-42",
		"iss": "yd-bench",
		"aud": []string{"api"},
		"iat": now.Unix(),
		"exp": now.Add(time.Hour).Unix(),
		"jti": "7f3c1a9e-42",
	}
}

// newJwxToken builds a jwx token carrying compareClaims. | newJwxToken 构造携带 compareClaims 的 jwx token。
func newJwxToken(now time.Time) (jwxjwt.Token, error) {
	tok := jwxjwt.New()
	for k, v := range compareClaims(now) {
		if err := tok.Set(k, v); err != nil {
			return nil, err
		}
	}
	return tok, nil
}

// joseClaims is the subset go-jose callers must validate themselves. | joseClaims 是 go-jose 调用方
// 必须自行校验的声明子集。
type joseClaims struct {
	Issuer   string   `json:"iss"`
	Audience []string `json:"aud"`
	Expires  int64    `json:"exp"`
}

// verifyJoseToken parses, verifies and validates a token with go-jose. The library verifies the
// signature only; issuer, audience and expiry are checked here to match the other implementations. |
// verifyJoseToken 用 go-jose 解析、验签并校验 token。该库只验证签名；这里补上签发者、受众与过期
// 检查，使对比与其它实现等价。
func verifyJoseToken(token string, algs []jose.SignatureAlgorithm, key any) ([]byte, error) {
	obj, err := jose.ParseSigned(token, algs)
	if err != nil {
		return nil, err
	}
	payload, err := obj.Verify(key)
	if err != nil {
		return nil, err
	}
	var claims joseClaims
	if err := stdjson.Unmarshal(payload, &claims); err != nil {
		return nil, err
	}
	if claims.Issuer != "yd-bench" || !slices.Contains(claims.Audience, "api") || time.Now().Unix() >= claims.Expires {
		return nil, errJoseClaims
	}
	return payload, nil
}

// BenchmarkSignHS256Compare compares HS256 token creation across ydx, golang-jwt, jwx and go-jose.
// Every implementation serializes the same six claims and includes the signature. |
// BenchmarkSignHS256Compare 对比 ydx、golang-jwt、jwx 与 go-jose 的 HS256 签发。每个实现都序列化
// 相同的六项声明并生成签名。
func BenchmarkSignHS256Compare(b *testing.B) {
	now := time.Now()
	claims := compareClaims(now)
	jwxTok, err := newJwxToken(now)
	if err != nil {
		b.Fatalf("jwx token setup failed | jwx token 准备失败: %v", err)
	}
	golangTok := golangjwt.NewWithClaims(golangjwt.SigningMethodHS256, golangjwt.MapClaims(compareClaims(now)))
	golangTok.Header["kid"] = "k1"
	joseSigner, err := jose.NewSigner(jose.SigningKey{Algorithm: jose.HS256, Key: benchKey}, nil)
	if err != nil {
		b.Fatalf("go-jose signer setup failed | go-jose 签名器准备失败: %v", err)
	}

	b.Run("ydx", func(b *testing.B) {
		b.ReportAllocs()
		b.ResetTimer()
		for i := 0; i < b.N; i++ {
			tok, signErr := ydxjwt.Sign(claims, benchKey, ydxjwt.HS256, ydxjwt.SignOptions{Kid: "k1"})
			if signErr != nil {
				b.Fatalf("Sign failed | Sign 失败: %v", signErr)
			}
			benchCompareToken = tok
		}
	})
	b.Run("golang-jwt", func(b *testing.B) {
		b.ReportAllocs()
		b.ResetTimer()
		for i := 0; i < b.N; i++ {
			tok, signErr := golangTok.SignedString(benchKey)
			if signErr != nil {
				b.Fatalf("Sign failed | Sign 失败: %v", signErr)
			}
			benchCompareToken = tok
		}
	})
	b.Run("jwx", func(b *testing.B) {
		b.ReportAllocs()
		b.ResetTimer()
		for i := 0; i < b.N; i++ {
			tok, signErr := jwxjwt.Sign(jwxTok, jwxjwt.WithKey(jwa.HS256(), benchKey))
			if signErr != nil {
				b.Fatalf("Sign failed | Sign 失败: %v", signErr)
			}
			benchCompareToken = string(tok)
		}
	})
	b.Run("go-jose", func(b *testing.B) {
		b.ReportAllocs()
		b.ResetTimer()
		for i := 0; i < b.N; i++ {
			payload, marshalErr := stdjson.Marshal(claims)
			if marshalErr != nil {
				b.Fatalf("Marshal failed | Marshal 失败: %v", marshalErr)
			}
			obj, signErr := joseSigner.Sign(payload)
			if signErr != nil {
				b.Fatalf("Sign failed | Sign 失败: %v", signErr)
			}
			tok, serializeErr := obj.CompactSerialize()
			if serializeErr != nil {
				b.Fatalf("CompactSerialize failed | CompactSerialize 失败: %v", serializeErr)
			}
			benchCompareToken = tok
		}
	})
}

// BenchmarkSignES256Compare compares ES256 token creation across the same implementations. |
// BenchmarkSignES256Compare 对相同的实现对比 ES256 签发。
func BenchmarkSignES256Compare(b *testing.B) {
	priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		b.Fatalf("GenerateKey failed | GenerateKey 失败: %v", err)
	}
	now := time.Now()
	claims := compareClaims(now)
	jwxTok, err := newJwxToken(now)
	if err != nil {
		b.Fatalf("jwx token setup failed | jwx token 准备失败: %v", err)
	}
	golangTok := golangjwt.NewWithClaims(golangjwt.SigningMethodES256, golangjwt.MapClaims(compareClaims(now)))
	golangTok.Header["kid"] = "k1"
	joseSigner, err := jose.NewSigner(jose.SigningKey{Algorithm: jose.ES256, Key: priv}, nil)
	if err != nil {
		b.Fatalf("go-jose signer setup failed | go-jose 签名器准备失败: %v", err)
	}

	b.Run("ydx", func(b *testing.B) {
		b.ReportAllocs()
		b.ResetTimer()
		for i := 0; i < b.N; i++ {
			tok, signErr := ydxjwt.Sign(claims, priv, ydxjwt.ES256, ydxjwt.SignOptions{Kid: "k1"})
			if signErr != nil {
				b.Fatalf("Sign failed | Sign 失败: %v", signErr)
			}
			benchCompareToken = tok
		}
	})
	b.Run("golang-jwt", func(b *testing.B) {
		b.ReportAllocs()
		b.ResetTimer()
		for i := 0; i < b.N; i++ {
			tok, signErr := golangTok.SignedString(priv)
			if signErr != nil {
				b.Fatalf("Sign failed | Sign 失败: %v", signErr)
			}
			benchCompareToken = tok
		}
	})
	b.Run("jwx", func(b *testing.B) {
		b.ReportAllocs()
		b.ResetTimer()
		for i := 0; i < b.N; i++ {
			tok, signErr := jwxjwt.Sign(jwxTok, jwxjwt.WithKey(jwa.ES256(), priv))
			if signErr != nil {
				b.Fatalf("Sign failed | Sign 失败: %v", signErr)
			}
			benchCompareToken = string(tok)
		}
	})
	b.Run("go-jose", func(b *testing.B) {
		b.ReportAllocs()
		b.ResetTimer()
		for i := 0; i < b.N; i++ {
			payload, marshalErr := stdjson.Marshal(claims)
			if marshalErr != nil {
				b.Fatalf("Marshal failed | Marshal 失败: %v", marshalErr)
			}
			obj, signErr := joseSigner.Sign(payload)
			if signErr != nil {
				b.Fatalf("Sign failed | Sign 失败: %v", signErr)
			}
			tok, serializeErr := obj.CompactSerialize()
			if serializeErr != nil {
				b.Fatalf("CompactSerialize failed | CompactSerialize 失败: %v", serializeErr)
			}
			benchCompareToken = tok
		}
	})
}

// BenchmarkParseHS256Compare compares HS256 verification and claim validation on one canonical
// token produced by ydx, so every parser reads identical bytes. |
// BenchmarkParseHS256Compare 在 ydx 生成的同一份规范 token 上对比 HS256 验签与声明校验，使每个
// 解析器读取完全相同的字节。
func BenchmarkParseHS256Compare(b *testing.B) {
	now := time.Now()
	token, err := ydxjwt.Sign(compareClaims(now), benchKey, ydxjwt.HS256, ydxjwt.SignOptions{Kid: "k1"})
	if err != nil {
		b.Fatalf("token setup failed | token 准备失败: %v", err)
	}

	var keyAny any = benchKey
	ydxOpts := ydxjwt.ParseOptions{
		ValidAlgs:  []ydxjwt.Alg{ydxjwt.HS256},
		Issuer:     "yd-bench",
		Audience:   "api",
		RequireExp: true,
	}
	ydxKeyFn := func(ydxjwt.Header) (any, error) { return keyAny, nil }
	golangOpts := []golangjwt.ParserOption{
		golangjwt.WithValidMethods([]string{"HS256"}),
		golangjwt.WithIssuer("yd-bench"),
		golangjwt.WithAudience("api"),
		golangjwt.WithExpirationRequired(),
	}
	golangKeyFn := func(*golangjwt.Token) (any, error) { return keyAny, nil }
	jwxOpts := []jwxjwt.ParseOption{
		jwxjwt.WithKey(jwa.HS256(), keyAny),
		jwxjwt.WithIssuer("yd-bench"),
		jwxjwt.WithAudience("api"),
	}
	joseAlgs := []jose.SignatureAlgorithm{jose.HS256}

	b.Run("ydx", func(b *testing.B) {
		b.ReportAllocs()
		b.ResetTimer()
		for i := 0; i < b.N; i++ {
			tok, parseErr := ydxjwt.Parse(token, ydxKeyFn, ydxOpts)
			if parseErr != nil {
				b.Fatalf("Parse failed | Parse 失败: %v", parseErr)
			}
			_ = tok
		}
	})
	b.Run("golang-jwt", func(b *testing.B) {
		b.ReportAllocs()
		b.ResetTimer()
		for i := 0; i < b.N; i++ {
			tok, parseErr := golangjwt.Parse(token, golangKeyFn, golangOpts...)
			if parseErr != nil {
				b.Fatalf("Parse failed | Parse 失败: %v", parseErr)
			}
			_ = tok
		}
	})
	b.Run("jwx", func(b *testing.B) {
		b.ReportAllocs()
		b.ResetTimer()
		for i := 0; i < b.N; i++ {
			tok, parseErr := jwxjwt.Parse([]byte(token), jwxOpts...)
			if parseErr != nil {
				b.Fatalf("Parse failed | Parse 失败: %v", parseErr)
			}
			_ = tok
		}
	})
	b.Run("go-jose", func(b *testing.B) {
		b.ReportAllocs()
		b.ResetTimer()
		for i := 0; i < b.N; i++ {
			payload, verifyErr := verifyJoseToken(token, joseAlgs, benchKey)
			if verifyErr != nil {
				b.Fatalf("Verify failed | Verify 失败: %v", verifyErr)
			}
			_ = payload
		}
	})
}

// BenchmarkParseES256Compare compares ES256 verification on one canonical token produced by ydx. |
// BenchmarkParseES256Compare 在 ydx 生成的同一份规范 token 上对比 ES256 验签。
func BenchmarkParseES256Compare(b *testing.B) {
	priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		b.Fatalf("GenerateKey failed | GenerateKey 失败: %v", err)
	}
	now := time.Now()
	token, err := ydxjwt.Sign(compareClaims(now), priv, ydxjwt.ES256, ydxjwt.SignOptions{Kid: "k1"})
	if err != nil {
		b.Fatalf("token setup failed | token 准备失败: %v", err)
	}
	pub := &priv.PublicKey
	var pubAny any = pub

	ydxOpts := ydxjwt.ParseOptions{
		ValidAlgs:  []ydxjwt.Alg{ydxjwt.ES256},
		Issuer:     "yd-bench",
		Audience:   "api",
		RequireExp: true,
	}
	ydxKeyFn := func(ydxjwt.Header) (any, error) { return pubAny, nil }
	golangOpts := []golangjwt.ParserOption{
		golangjwt.WithValidMethods([]string{"ES256"}),
		golangjwt.WithIssuer("yd-bench"),
		golangjwt.WithAudience("api"),
		golangjwt.WithExpirationRequired(),
	}
	golangKeyFn := func(*golangjwt.Token) (any, error) { return pubAny, nil }
	jwxOpts := []jwxjwt.ParseOption{
		jwxjwt.WithKey(jwa.ES256(), pubAny),
		jwxjwt.WithIssuer("yd-bench"),
		jwxjwt.WithAudience("api"),
	}
	joseAlgs := []jose.SignatureAlgorithm{jose.ES256}

	b.Run("ydx", func(b *testing.B) {
		b.ReportAllocs()
		b.ResetTimer()
		for i := 0; i < b.N; i++ {
			tok, parseErr := ydxjwt.Parse(token, ydxKeyFn, ydxOpts)
			if parseErr != nil {
				b.Fatalf("Parse failed | Parse 失败: %v", parseErr)
			}
			_ = tok
		}
	})
	b.Run("golang-jwt", func(b *testing.B) {
		b.ReportAllocs()
		b.ResetTimer()
		for i := 0; i < b.N; i++ {
			tok, parseErr := golangjwt.Parse(token, golangKeyFn, golangOpts...)
			if parseErr != nil {
				b.Fatalf("Parse failed | Parse 失败: %v", parseErr)
			}
			_ = tok
		}
	})
	b.Run("jwx", func(b *testing.B) {
		b.ReportAllocs()
		b.ResetTimer()
		for i := 0; i < b.N; i++ {
			tok, parseErr := jwxjwt.Parse([]byte(token), jwxOpts...)
			if parseErr != nil {
				b.Fatalf("Parse failed | Parse 失败: %v", parseErr)
			}
			_ = tok
		}
	})
	b.Run("go-jose", func(b *testing.B) {
		b.ReportAllocs()
		b.ResetTimer()
		for i := 0; i < b.N; i++ {
			payload, verifyErr := verifyJoseToken(token, joseAlgs, pubAny)
			if verifyErr != nil {
				b.Fatalf("Verify failed | Verify 失败: %v", verifyErr)
			}
			_ = payload
		}
	})
}

// BenchmarkParseHS256ParallelCompare compares concurrent HS256 verification on the canonical
// token. The token is validated once before the timer; per-iteration errors are not surfaced from
// the parallel goroutines. | BenchmarkParseHS256ParallelCompare 在规范 token 上对比并发 HS256 验签。
// token 在计时前已完成一次校验；并行协程中的逐次错误不会向上报告。
func BenchmarkParseHS256ParallelCompare(b *testing.B) {
	now := time.Now()
	token, err := ydxjwt.Sign(compareClaims(now), benchKey, ydxjwt.HS256, ydxjwt.SignOptions{Kid: "k1"})
	if err != nil {
		b.Fatalf("token setup failed | token 准备失败: %v", err)
	}

	var keyAny any = benchKey
	ydxOpts := ydxjwt.ParseOptions{
		ValidAlgs:  []ydxjwt.Alg{ydxjwt.HS256},
		Issuer:     "yd-bench",
		Audience:   "api",
		RequireExp: true,
	}
	ydxKeyFn := func(ydxjwt.Header) (any, error) { return keyAny, nil }
	golangOpts := []golangjwt.ParserOption{
		golangjwt.WithValidMethods([]string{"HS256"}),
		golangjwt.WithIssuer("yd-bench"),
		golangjwt.WithAudience("api"),
		golangjwt.WithExpirationRequired(),
	}
	golangKeyFn := func(*golangjwt.Token) (any, error) { return keyAny, nil }
	jwxOpts := []jwxjwt.ParseOption{
		jwxjwt.WithKey(jwa.HS256(), keyAny),
		jwxjwt.WithIssuer("yd-bench"),
		jwxjwt.WithAudience("api"),
	}
	joseAlgs := []jose.SignatureAlgorithm{jose.HS256}

	if _, err := ydxjwt.Parse(token, ydxKeyFn, ydxOpts); err != nil {
		b.Fatalf("ydx setup validation failed | ydx 预校验失败: %v", err)
	}
	if _, err := golangjwt.Parse(token, golangKeyFn, golangOpts...); err != nil {
		b.Fatalf("golang-jwt setup validation failed | golang-jwt 预校验失败: %v", err)
	}
	if _, err := jwxjwt.Parse([]byte(token), jwxOpts...); err != nil {
		b.Fatalf("jwx setup validation failed | jwx 预校验失败: %v", err)
	}
	if _, err := verifyJoseToken(token, joseAlgs, benchKey); err != nil {
		b.Fatalf("go-jose setup validation failed | go-jose 预校验失败: %v", err)
	}

	b.Run("ydx", func(b *testing.B) {
		b.ReportAllocs()
		b.ResetTimer()
		b.RunParallel(func(pb *testing.PB) {
			for pb.Next() {
				_, _ = ydxjwt.Parse(token, ydxKeyFn, ydxOpts)
			}
		})
	})
	b.Run("golang-jwt", func(b *testing.B) {
		b.ReportAllocs()
		b.ResetTimer()
		b.RunParallel(func(pb *testing.PB) {
			for pb.Next() {
				_, _ = golangjwt.Parse(token, golangKeyFn, golangOpts...)
			}
		})
	})
	b.Run("jwx", func(b *testing.B) {
		b.ReportAllocs()
		b.ResetTimer()
		b.RunParallel(func(pb *testing.PB) {
			for pb.Next() {
				_, _ = jwxjwt.Parse([]byte(token), jwxOpts...)
			}
		})
	})
	b.Run("go-jose", func(b *testing.B) {
		b.ReportAllocs()
		b.ResetTimer()
		b.RunParallel(func(pb *testing.PB) {
			for pb.Next() {
				_, _ = verifyJoseToken(token, joseAlgs, benchKey)
			}
		})
	})
}
