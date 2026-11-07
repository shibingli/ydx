package jwt

import (
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"errors"
	"testing"
	"time"
)

// signClaims is the minimal claim set of the verification-key tests. | signClaims 是验签密钥测试使用的
// 最小声明集。
func signClaims() map[string]any {
	return map[string]any{"sub": "u-key", "exp": fixedNow.Add(time.Hour).Unix()}
}

// fixedClock is the deterministic clock of these tests. | fixedClock 是这些测试使用的确定性时钟。
func fixedClock() time.Time { return fixedNow }

func TestParseAcceptsPrivateKeysFromKeyFunc(t *testing.T) {
	rsaKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("生成 RSA 密钥失败: %v", err)
	}
	ecKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("生成 ECDSA 密钥失败: %v", err)
	}
	_, edPriv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("生成 Ed25519 密钥失败: %v", err)
	}

	cases := []struct {
		name string
		alg  Alg
		key  any // the same private key value serves Sign and Parse | 同一个私钥取值同时用于 Sign 与 Parse
	}{
		{"RS256", RS256, rsaKey},
		{"PS256", PS256, rsaKey},
		{"ES256", ES256, ecKey},
		{"EdDSA", EdDSA, edPriv},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			raw := mustSign(t, signClaims(), tc.key, tc.alg, SignOptions{Kid: "priv-key"})
			tok, err := Parse(raw, func(h Header) (any, error) {
				if h.Kid != "priv-key" {
					t.Errorf("KeyFunc 收到 Kid = %q，期望 %q", h.Kid, "priv-key")
				}
				return tc.key, nil
			}, ParseOptions{ValidAlgs: []Alg{tc.alg}, Now: fixedClock})
			if err != nil {
				t.Fatalf("Parse 用匹配的私钥验签失败: %v", err)
			}
			if got := tok.Claims.Subject(); got != "u-key" {
				t.Errorf("Claims.Subject() = %q，期望 %q", got, "u-key")
			}
			tok.Release()
		})
	}
}

func TestParseRejectsWrongPrivateKey(t *testing.T) {
	rsaKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("生成 RSA 密钥失败: %v", err)
	}
	otherRSA, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("生成备用 RSA 密钥失败: %v", err)
	}
	ecKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("生成 ECDSA 密钥失败: %v", err)
	}
	otherEC, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("生成备用 ECDSA 密钥失败: %v", err)
	}
	p384Key, err := ecdsa.GenerateKey(elliptic.P384(), rand.Reader)
	if err != nil {
		t.Fatalf("生成 P-384 密钥失败: %v", err)
	}
	_, edPriv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("生成 Ed25519 密钥失败: %v", err)
	}
	_, otherEd, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("生成备用 Ed25519 密钥失败: %v", err)
	}

	cases := []struct {
		name    string
		alg     Alg
		signKey any
		badKey  any
	}{
		{"RS256", RS256, rsaKey, otherRSA},
		{"PS384", PS384, rsaKey, otherRSA},
		{"ES256", ES256, ecKey, otherEC},
		// A private key on the wrong curve must not take the place of the required one. | 曲线不符的
		// 私钥不得顶替要求的曲线。
		{"ES384", ES384, p384Key, ecKey},
		{"EdDSA", EdDSA, edPriv, otherEd},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			raw := mustSign(t, signClaims(), tc.signKey, tc.alg, SignOptions{})
			_, err := Parse(raw, func(Header) (any, error) { return tc.badKey, nil }, ParseOptions{
				ValidAlgs: []Alg{tc.alg},
				Now:       fixedClock,
			})
			if !errors.Is(err, ErrSignatureInvalid) {
				t.Errorf("错误私钥的 err = %v，期望 ErrSignatureInvalid", err)
			}
		})
	}
}

func TestParsePrivateKeyNilAndEmptyNeverPanic(t *testing.T) {
	rsaKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("生成 RSA 密钥失败: %v", err)
	}
	ecKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("生成 ECDSA 密钥失败: %v", err)
	}
	_, edPriv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("生成 Ed25519 密钥失败: %v", err)
	}

	var nilRSA *rsa.PrivateKey
	var nilEC *ecdsa.PrivateKey
	var nilEd ed25519.PrivateKey
	shortEd := ed25519.PrivateKey(make([]byte, ed25519.PrivateKeySize-1))

	cases := []struct {
		name    string
		alg     Alg
		signKey any
		badKey  any
	}{
		{"RS256 nil", RS256, rsaKey, nilRSA},
		{"PS256 zero", PS256, rsaKey, &rsa.PrivateKey{}},
		{"ES256 nil", ES256, ecKey, nilEC},
		{"ES256 zero", ES256, ecKey, &ecdsa.PrivateKey{}},
		{"EdDSA nil", EdDSA, edPriv, nilEd},
		{"EdDSA short", EdDSA, edPriv, shortEd},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			raw := mustSign(t, signClaims(), tc.signKey, tc.alg, SignOptions{})
			_, err := Parse(raw, func(Header) (any, error) { return tc.badKey, nil }, ParseOptions{
				ValidAlgs: []Alg{tc.alg},
				Now:       fixedClock,
			})
			if !errors.Is(err, ErrSignatureInvalid) {
				t.Errorf("不可用私钥的 err = %v，期望 ErrSignatureInvalid", err)
			}
		})
	}
}

// TestAlgorithmConfusionWithPrivateKeysRejected proves that accepting private keys does not reopen
// algorithm confusion: an asymmetric private key returned for an HMAC algorithm is still refused. |
// TestAlgorithmConfusionWithPrivateKeysRejected 证明接受私钥不会重新打开算法混淆：为 HMAC 算法返回
// 非对称私钥依然被拒绝。
func TestAlgorithmConfusionWithPrivateKeysRejected(t *testing.T) {
	rsaKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("生成 RSA 密钥失败: %v", err)
	}
	ecKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("生成 ECDSA 密钥失败: %v", err)
	}
	_, edPriv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("生成 Ed25519 密钥失败: %v", err)
	}

	raw := mustSign(t, signClaims(), testSecret, HS256, SignOptions{})
	for _, key := range []any{rsaKey, ecKey, edPriv, &rsaKey.PublicKey, &ecKey.PublicKey} {
		if _, err := Parse(raw, func(Header) (any, error) { return key, nil }, ParseOptions{
			ValidAlgs: []Alg{HS256},
			Now:       fixedClock,
		}); !errors.Is(err, ErrSignatureInvalid) {
			t.Errorf("HMAC 算法配合 %T 的 err = %v，期望 ErrSignatureInvalid", key, err)
		}
	}
}
