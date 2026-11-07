package auth

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"testing"

	gojose "github.com/go-jose/go-jose/v4"
	"github.com/lestrrat-go/jwx/v4/jwa"
	"github.com/lestrrat-go/jwx/v4/jws"
	ydjose "github.com/shibingli/ydx/auth/token/jose"
)

// josePayload is a typical JWT-shaped JWS payload. | josePayload 是典型 JWT 形状的 JWS 载荷。
var josePayload = []byte(`{"iss":"https://ydx.example","sub":"alice","aud":"api","exp":1893456000,"iat":1577836800}`)

// joseHMACSecret is a fixed test secret. | joseHMACSecret 是固定测试密钥。
var joseHMACSecret = []byte("ydx-benchmark-hmac-secret-0123456789abcdef")

// newES256Key returns a fresh P-256 private key. | newES256Key 返回新的 P-256 私钥。
func newES256Key(b testing.TB) *ecdsa.PrivateKey {
	b.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		b.Fatalf("GenerateKey: %v", err)
	}
	return key
}

// BenchmarkJOSESignHS256 compares compact JWS signing with go-jose and jwx. |
// BenchmarkJOSESignHS256 对比紧凑 JWS 签名与 go-jose、jwx。
func BenchmarkJOSESignHS256(b *testing.B) {
	key, err := ydjose.FromHMAC("bench", joseHMACSecret)
	if err != nil {
		b.Fatal(err)
	}
	signer, err := gojose.NewSigner(gojose.SigningKey{Algorithm: gojose.HS256, Key: joseHMACSecret}, nil)
	if err != nil {
		b.Fatal(err)
	}
	b.Run("ydx", func(b *testing.B) {
		b.ReportAllocs()
		for i := 0; i < b.N; i++ {
			if _, err := ydjose.Sign(josePayload, key, ydjose.SignOptions{Alg: "HS256", Typ: "JWT"}); err != nil {
				b.Fatal(err)
			}
		}
	})
	b.Run("go-jose", func(b *testing.B) {
		b.ReportAllocs()
		for i := 0; i < b.N; i++ {
			object, err := signer.Sign(josePayload)
			if err != nil {
				b.Fatal(err)
			}
			if _, err := object.CompactSerialize(); err != nil {
				b.Fatal(err)
			}
		}
	})
	b.Run("jwx", func(b *testing.B) {
		b.ReportAllocs()
		for i := 0; i < b.N; i++ {
			if _, err := jws.Sign(josePayload, jws.WithKey(jwa.HS256(), joseHMACSecret)); err != nil {
				b.Fatal(err)
			}
		}
	})
}

// BenchmarkJOSEVerifyHS256 compares verification of the same ydx-signed token. |
// BenchmarkJOSEVerifyHS256 对比同一份 ydx 签发令牌的验签。
func BenchmarkJOSEVerifyHS256(b *testing.B) {
	key, err := ydjose.FromHMAC("bench", joseHMACSecret)
	if err != nil {
		b.Fatal(err)
	}
	token, err := ydjose.Sign(josePayload, key, ydjose.SignOptions{Alg: "HS256", Typ: "JWT"})
	if err != nil {
		b.Fatal(err)
	}
	resolver := ydjose.KeySetResolver(&ydjose.KeySet{Keys: []*ydjose.Key{key.Public()}})
	parsed, err := gojose.ParseSigned(token, []gojose.SignatureAlgorithm{gojose.HS256})
	if err != nil {
		b.Fatal(err)
	}
	b.Run("ydx", func(b *testing.B) {
		b.ReportAllocs()
		for i := 0; i < b.N; i++ {
			if _, err := ydjose.Verify(token, resolver, ydjose.VerifyOptions{ValidAlgs: []string{"HS256"}}); err != nil {
				b.Fatal(err)
			}
		}
	})
	b.Run("go-jose", func(b *testing.B) {
		b.ReportAllocs()
		for i := 0; i < b.N; i++ {
			if _, err := parsed.Verify(joseHMACSecret); err != nil {
				b.Fatal(err)
			}
		}
	})
	b.Run("jwx", func(b *testing.B) {
		b.ReportAllocs()
		for i := 0; i < b.N; i++ {
			if _, err := jws.Verify([]byte(token), jws.WithKey(jwa.HS256(), joseHMACSecret)); err != nil {
				b.Fatal(err)
			}
		}
	})
}

// BenchmarkJOSESignES256 compares ES256 signing. | BenchmarkJOSESignES256 对比 ES256 签名。
func BenchmarkJOSESignES256(b *testing.B) {
	priv := newES256Key(b)
	key, err := ydjose.FromPrivateKey("bench", priv)
	if err != nil {
		b.Fatal(err)
	}
	signer, err := gojose.NewSigner(gojose.SigningKey{Algorithm: gojose.ES256, Key: priv}, nil)
	if err != nil {
		b.Fatal(err)
	}
	b.Run("ydx", func(b *testing.B) {
		b.ReportAllocs()
		for i := 0; i < b.N; i++ {
			if _, err := ydjose.Sign(josePayload, key, ydjose.SignOptions{Alg: "ES256", Typ: "JWT"}); err != nil {
				b.Fatal(err)
			}
		}
	})
	b.Run("go-jose", func(b *testing.B) {
		b.ReportAllocs()
		for i := 0; i < b.N; i++ {
			object, err := signer.Sign(josePayload)
			if err != nil {
				b.Fatal(err)
			}
			if _, err := object.CompactSerialize(); err != nil {
				b.Fatal(err)
			}
		}
	})
	b.Run("jwx", func(b *testing.B) {
		b.ReportAllocs()
		for i := 0; i < b.N; i++ {
			if _, err := jws.Sign(josePayload, jws.WithKey(jwa.ES256(), priv)); err != nil {
				b.Fatal(err)
			}
		}
	})
}

// BenchmarkJOSEVerifyES256 compares ES256 verification of the same ydx-signed token. |
// BenchmarkJOSEVerifyES256 对比同一份 ydx 签发令牌的 ES256 验签。
func BenchmarkJOSEVerifyES256(b *testing.B) {
	priv := newES256Key(b)
	key, err := ydjose.FromPrivateKey("bench", priv)
	if err != nil {
		b.Fatal(err)
	}
	token, err := ydjose.Sign(josePayload, key, ydjose.SignOptions{Alg: "ES256", Typ: "JWT"})
	if err != nil {
		b.Fatal(err)
	}
	pub, err := key.PublicKey()
	if err != nil {
		b.Fatal(err)
	}
	resolver := ydjose.KeySetResolver(&ydjose.KeySet{Keys: []*ydjose.Key{key.Public()}})
	parsed, err := gojose.ParseSigned(token, []gojose.SignatureAlgorithm{gojose.ES256})
	if err != nil {
		b.Fatal(err)
	}
	b.Run("ydx", func(b *testing.B) {
		b.ReportAllocs()
		for i := 0; i < b.N; i++ {
			if _, err := ydjose.Verify(token, resolver, ydjose.VerifyOptions{ValidAlgs: []string{"ES256"}}); err != nil {
				b.Fatal(err)
			}
		}
	})
	b.Run("go-jose", func(b *testing.B) {
		b.ReportAllocs()
		for i := 0; i < b.N; i++ {
			if _, err := parsed.Verify(pub); err != nil {
				b.Fatal(err)
			}
		}
	})
	b.Run("jwx", func(b *testing.B) {
		b.ReportAllocs()
		for i := 0; i < b.N; i++ {
			if _, err := jws.Verify([]byte(token), jws.WithKey(jwa.ES256(), pub)); err != nil {
				b.Fatal(err)
			}
		}
	})
}

// TestJOSEInterop checks that ydx, go-jose and jwx accept each other's HS256 and ES256 tokens. |
// TestJOSEInterop 检查 ydx、go-jose 与 jwx 互相接受对方的 HS256 与 ES256 令牌。
func TestJOSEInterop(t *testing.T) {
	priv := newES256Key(t)
	ydHMAC, err := ydjose.FromHMAC("bench", joseHMACSecret)
	if err != nil {
		t.Fatal(err)
	}
	ydES, err := ydjose.FromPrivateKey("bench", priv)
	if err != nil {
		t.Fatal(err)
	}
	hmacResolver := ydjose.KeyResolverFunc(func(context.Context, ydjose.Header) (*ydjose.Key, error) {
		return ydHMAC.Public(), nil
	})
	esResolver := ydjose.KeyResolverFunc(func(context.Context, ydjose.Header) (*ydjose.Key, error) {
		return ydES.Public(), nil
	})
	hmacSigner, err := gojose.NewSigner(gojose.SigningKey{Algorithm: gojose.HS256, Key: joseHMACSecret}, nil)
	if err != nil {
		t.Fatal(err)
	}
	esSigner, err := gojose.NewSigner(gojose.SigningKey{Algorithm: gojose.ES256, Key: priv}, nil)
	if err != nil {
		t.Fatal(err)
	}
	pub, err := ydES.PublicKey()
	if err != nil {
		t.Fatal(err)
	}
	cases := []struct {
		name     string
		alg      string
		token    string
		verifyFn func(string) error
	}{
		{
			name: "ydx-hs256", alg: "HS256",
			token: mustSign(t, ydHMAC, "HS256"),
			verifyFn: func(token string) error {
				_, err := gojose.ParseSigned(token, []gojose.SignatureAlgorithm{gojose.HS256})
				return err
			},
		},
		{
			name: "go-jose-hs256", alg: "HS256",
			token: mustCompact(t, hmacSigner),
			verifyFn: func(token string) error {
				_, err := jws.Verify([]byte(token), jws.WithKey(jwa.HS256(), joseHMACSecret))
				return err
			},
		},
		{
			name: "jwx-hs256", alg: "HS256",
			token: string(mustJWXSign(t, jwa.HS256(), joseHMACSecret)),
			verifyFn: func(token string) error {
				_, err := gojose.ParseSigned(token, []gojose.SignatureAlgorithm{gojose.HS256})
				return err
			},
		},
		{
			name: "ydx-es256", alg: "ES256",
			token: mustSign(t, ydES, "ES256"),
			verifyFn: func(token string) error {
				parsed, err := gojose.ParseSigned(token, []gojose.SignatureAlgorithm{gojose.ES256})
				if err != nil {
					return err
				}
				_, err = parsed.Verify(pub)
				return err
			},
		},
		{
			name: "go-jose-es256", alg: "ES256",
			token: mustCompact(t, esSigner),
			verifyFn: func(token string) error {
				_, err := jws.Verify([]byte(token), jws.WithKey(jwa.ES256(), pub))
				return err
			},
		},
		{
			name: "jwx-es256", alg: "ES256",
			token: string(mustJWXSign(t, jwa.ES256(), priv)),
			verifyFn: func(token string) error {
				parsed, err := gojose.ParseSigned(token, []gojose.SignatureAlgorithm{gojose.ES256})
				if err != nil {
					return err
				}
				_, err = parsed.Verify(pub)
				return err
			},
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			resolver := hmacResolver
			if tc.alg == "ES256" {
				resolver = esResolver
			}
			if _, err := ydjose.Verify(tc.token, resolver, ydjose.VerifyOptions{ValidAlgs: []string{tc.alg}}); err != nil {
				t.Fatalf("ydx rejected token: %v", err)
			}
			if err := tc.verifyFn(tc.token); err != nil {
				t.Fatalf("comparison implementation rejected token: %v", err)
			}
		})
	}
}

// mustSign signs the benchmark payload with ydx and fails on error. | mustSign 用 ydx 签发基准载荷，
// 出错时终止测试。
func mustSign(t testing.TB, key *ydjose.Key, alg string) string {
	t.Helper()
	token, err := ydjose.Sign(josePayload, key, ydjose.SignOptions{Alg: alg, Typ: "JWT"})
	if err != nil {
		t.Fatalf("ydx Sign: %v", err)
	}
	return token
}

// mustCompact serializes a go-jose signature compactly. | mustCompact 紧凑序列化 go-jose 签名。
func mustCompact(t testing.TB, signer gojose.Signer) string {
	t.Helper()
	object, err := signer.Sign(josePayload)
	if err != nil {
		t.Fatalf("go-jose Sign: %v", err)
	}
	token, err := object.CompactSerialize()
	if err != nil {
		t.Fatalf("go-jose CompactSerialize: %v", err)
	}
	return token
}

// mustJWXSign signs the payload with jwx. | mustJWXSign 用 jwx 签发载荷。
func mustJWXSign(t testing.TB, alg jwa.SignatureAlgorithm, key any) []byte {
	t.Helper()
	token, err := jws.Sign(josePayload, jws.WithKey(alg, key))
	if err != nil {
		t.Fatalf("jwx Sign: %v", err)
	}
	return token
}
