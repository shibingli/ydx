package jose

import (
	"crypto"
	"crypto/hmac"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"errors"
	"strings"
	"testing"
	"time"

	ydjwt "github.com/shibingli/ydx/auth/token/jwt"
)

// jwsTestKey returns a signing key for alg. RSA is shared because generation is expensive. |
// jwsTestKey 返回 alg 的签名密钥。RSA 生成开销大，因此共享。
func jwsTestKey(t *testing.T, alg string) *Key {
	t.Helper()
	switch alg {
	case "RS256", "RS384", "RS512", "PS256", "PS384", "PS512":
		return testUnboundRSAKey(t)
	default:
		k, err := GenerateKey(alg, 0)
		if err != nil {
			t.Fatalf("GenerateKey(%q) failed: %v", alg, err)
		}
		return k
	}
}

// resolverFor returns a resolver that publishes the public half of k under kid. | resolverFor 返回
// 以 kid 发布 k 公钥部分的解析器。
func resolverFor(k *Key, kid string) KeyResolver {
	pub := k.Public()
	pub.Kid = kid
	return KeySetResolver(&KeySet{Keys: []*Key{pub}})
}

func mustSign(t *testing.T, payload []byte, key *Key, opts SignOptions) string {
	t.Helper()
	token, err := Sign(payload, key, opts)
	if err != nil {
		t.Fatalf("Sign failed: %v", err)
	}
	return token
}

func mustVerify(t *testing.T, token string, resolver KeyResolver, opts VerifyOptions) *Verified {
	t.Helper()
	v, err := Verify(token, resolver, opts)
	if err != nil {
		t.Fatalf("Verify failed: %v", err)
	}
	return v
}

// tamperSegment decodes seg, flips its last byte and re-encodes it. | tamperSegment 解码 seg，
// 翻转最后一个字节后重新编码。
func tamperSegment(t *testing.T, seg string) string {
	t.Helper()
	raw, err := DecodeSegment(seg)
	if err != nil {
		t.Fatalf("DecodeSegment failed: %v", err)
	}
	if len(raw) == 0 {
		t.Fatalf("segment is empty")
	}
	raw[len(raw)-1] ^= 0x01
	return EncodeSegment(raw)
}

// manualHS256 builds a compact JWS with an arbitrary protected header. | manualHS256 使用任意受保护
// 头部构造紧凑 JWS。
func manualHS256(header, payload string, secret []byte) string {
	head := EncodeSegment([]byte(header))
	body := EncodeSegment([]byte(payload))
	input := head + "." + body
	mac := hmac.New(sha256.New, secret)
	_, _ = mac.Write([]byte(input))
	return input + "." + EncodeSegment(mac.Sum(nil))
}

func TestSignVerifyAllAlgorithms(t *testing.T) {
	algs := []string{
		"HS256", "HS384", "HS512",
		"RS256", "RS384", "RS512",
		"PS256", "PS384", "PS512",
		"ES256", "ES384", "ES512",
		"EdDSA",
	}
	payload := []byte(`{"sub":"alice","scope":"read"}`)
	for _, alg := range algs {
		alg := alg
		for _, direct := range []bool{false, true} {
			name := alg
			typ := "JWT"
			opts := VerifyOptions{ValidAlgs: []string{alg}, Typ: typ}
			if direct {
				name += "/direct"
				typ = ""
				opts = VerifyOptions{ValidAlgs: []string{alg}}
			}
			t.Run(name, func(t *testing.T) {
				key := jwsTestKey(t, alg)
				kid := "kid-" + alg
				token := mustSign(t, payload, key, SignOptions{Alg: alg, Kid: kid, Typ: typ})
				resolver := resolverFor(key, kid)
				v := mustVerify(t, token, resolver, opts)
				if v.Header.Alg != alg {
					t.Fatalf("header alg = %q, want %q", v.Header.Alg, alg)
				}
				if v.Header.Kid != kid {
					t.Fatalf("header kid = %q, want %q", v.Header.Kid, kid)
				}
				if string(v.Payload) != string(payload) {
					t.Fatalf("payload = %q, want %q", v.Payload, payload)
				}
				if !v.IsJSON() || string(v.Claims) != string(payload) {
					t.Fatalf("claims = %q, want payload", v.Claims)
				}
				if len(v.Signature) == 0 {
					t.Fatal("signature is empty")
				}
			})
		}
	}
}

func TestSignArbitraryPayload(t *testing.T) {
	payload := []byte{0x00, 0xFF, 0x01, 0xFE, '\n', '{', '}'}
	algs := []string{"HS256", "RS256", "ES256", "EdDSA"}
	for _, alg := range algs {
		t.Run(alg, func(t *testing.T) {
			key := jwsTestKey(t, alg)
			token := mustSign(t, payload, key, SignOptions{Alg: alg, Kid: "k"})
			v := mustVerify(t, token, resolverFor(key, "k"), VerifyOptions{ValidAlgs: []string{alg}})
			if string(v.Payload) != string(payload) {
				t.Fatalf("payload = %x, want %x", v.Payload, payload)
			}
			if v.Claims != nil || v.IsJSON() {
				t.Fatal("binary payload was treated as JSON")
			}
		})
	}
}

func TestVerifyRejectsTampering(t *testing.T) {
	key := jwsTestKey(t, "HS256")
	token := mustSign(t, []byte(`{"sub":"alice"}`), key, SignOptions{Alg: "HS256", Typ: "JWT"})
	parts := strings.Split(token, ".")
	if len(parts) != 3 {
		t.Fatalf("token has %d segments, want 3", len(parts))
	}
	resolver := resolverFor(key, "")

	t.Run("signature", func(t *testing.T) {
		tampered := parts[0] + "." + parts[1] + "." + tamperSegment(t, parts[2])
		_, err := Verify(tampered, resolver, VerifyOptions{})
		if !errors.Is(err, ErrSignatureInvalid) {
			t.Fatalf("error = %v, want ErrSignatureInvalid", err)
		}
	})
	t.Run("payload", func(t *testing.T) {
		tampered := parts[0] + "." + tamperSegment(t, parts[1]) + "." + parts[2]
		_, err := Verify(tampered, resolver, VerifyOptions{})
		if !errors.Is(err, ErrSignatureInvalid) {
			t.Fatalf("error = %v, want ErrSignatureInvalid", err)
		}
	})
	t.Run("wrong key", func(t *testing.T) {
		other, err := FromHMAC("", bytesRepeat(0x11, 32))
		if err != nil {
			t.Fatalf("FromHMAC failed: %v", err)
		}
		_, err = Verify(token, resolverFor(other, ""), VerifyOptions{})
		if !errors.Is(err, ErrSignatureInvalid) {
			t.Fatalf("error = %v, want ErrSignatureInvalid", err)
		}
	})
}

func TestVerifyRejectsAlgorithmAbuse(t *testing.T) {
	key := jwsTestKey(t, "HS256")
	secret, err := key.PrivateKey()
	if err != nil {
		t.Fatalf("PrivateKey failed: %v", err)
	}
	secretBytes := secret.([]byte)
	resolver := resolverFor(key, "")

	t.Run("none", func(t *testing.T) {
		token := EncodeSegment([]byte(`{"alg":"none"}`)) + "." +
			EncodeSegment([]byte(`{"sub":"x"}`)) + "." + EncodeSegment([]byte{0x01})
		_, err := Verify(token, resolver, VerifyOptions{})
		if !errors.Is(err, ErrAlgNotAllowed) {
			t.Fatalf("error = %v, want ErrAlgNotAllowed", err)
		}
	})
	t.Run("allow list", func(t *testing.T) {
		token := mustSign(t, []byte(`{"sub":"x"}`), key, SignOptions{Alg: "HS256"})
		_, err := Verify(token, resolver, VerifyOptions{ValidAlgs: []string{"HS512"}})
		if !errors.Is(err, ErrAlgNotAllowed) {
			t.Fatalf("error = %v, want ErrAlgNotAllowed", err)
		}
	})
	t.Run("algorithm confusion", func(t *testing.T) {
		token := mustSign(t, []byte(`{"sub":"x"}`), key, SignOptions{Alg: "HS256"})
		rsaKey := testUnboundRSAKey(t)
		_, err := Verify(token, KeySetResolver(&KeySet{Keys: []*Key{rsaKey.Public()}}), VerifyOptions{})
		if !errors.Is(err, ErrKeyTypeMismatch) {
			t.Fatalf("error = %v, want ErrKeyTypeMismatch", err)
		}
	})
	t.Run("key alg binding", func(t *testing.T) {
		token := mustSign(t, []byte(`{"sub":"x"}`), key, SignOptions{Alg: "HS256"})
		bound, err := GenerateKey("HS512", 0)
		if err != nil {
			t.Fatalf("GenerateKey failed: %v", err)
		}
		_, err = Verify(token, resolverFor(bound, ""), VerifyOptions{})
		if !errors.Is(err, ErrAlgNotAllowed) {
			t.Fatalf("error = %v, want ErrAlgNotAllowed", err)
		}
	})
	t.Run("crit", func(t *testing.T) {
		token := manualHS256(`{"alg":"HS256","crit":["exp"]}`, `{"sub":"x"}`, secretBytes)
		_, err := Verify(token, resolver, VerifyOptions{})
		if !errors.Is(err, ErrUnsupportedCrit) {
			t.Fatalf("error = %v, want ErrUnsupportedCrit", err)
		}
	})
	t.Run("duplicate header", func(t *testing.T) {
		token := manualHS256(`{"alg":"HS256","alg":"HS256"}`, `{"sub":"x"}`, secretBytes)
		_, err := Verify(token, resolver, VerifyOptions{})
		if !errors.Is(err, ErrInvalidHeader) {
			t.Fatalf("error = %v, want ErrInvalidHeader", err)
		}
	})
	t.Run("b64 extension", func(t *testing.T) {
		token := manualHS256(`{"alg":"HS256","b64":false}`, `{"sub":"x"}`, secretBytes)
		_, err := Verify(token, resolver, VerifyOptions{})
		if !errors.Is(err, ErrInvalidHeader) {
			t.Fatalf("error = %v, want ErrInvalidHeader", err)
		}
	})
	t.Run("typ mismatch", func(t *testing.T) {
		token := mustSign(t, []byte(`{"sub":"x"}`), key, SignOptions{Alg: "HS256", Typ: "JWT"})
		_, err := Verify(token, resolver, VerifyOptions{Typ: "at+jwt"})
		if !errors.Is(err, ErrInvalidHeader) {
			t.Fatalf("error = %v, want ErrInvalidHeader", err)
		}
	})
}

func TestSignRejects(t *testing.T) {
	key := mustGenerate(t, "HS256")
	if _, err := Sign([]byte(`{}`), key, SignOptions{Alg: "none"}); !errors.Is(err, ErrAlgNotAllowed) {
		t.Fatalf("none error = %v, want ErrAlgNotAllowed", err)
	}
	weak, err := FromHMAC("", bytesRepeat(0x22, 16))
	if err != nil {
		t.Fatalf("FromHMAC failed: %v", err)
	}
	if _, err := Sign([]byte(`{}`), weak, SignOptions{Alg: "HS256"}); !errors.Is(err, ErrWeakKey) {
		t.Fatalf("weak key error = %v, want ErrWeakKey", err)
	}
	if _, err := Sign([]byte(`{}`), key, SignOptions{Alg: "HS256", Crit: []string{"exp"}}); !errors.Is(err, ErrUnsupportedCrit) {
		t.Fatalf("crit error = %v, want ErrUnsupportedCrit", err)
	}
	if _, err := Sign([]byte(`{}`), key, SignOptions{Alg: "HS256", Extra: map[string]any{"alg": "RS256"}}); !errors.Is(err, ErrInvalidHeader) {
		t.Fatalf("reserved extra error = %v, want ErrInvalidHeader", err)
	}
	unbound := testUnboundRSAKey(t)
	if _, err := Sign([]byte(`{}`), unbound, SignOptions{}); !errors.Is(err, ErrAlgNotAllowed) {
		t.Fatalf("missing alg error = %v, want ErrAlgNotAllowed", err)
	}
	bound := mustGenerate(t, "HS512")
	if _, err := Sign([]byte(`{}`), bound, SignOptions{Alg: "HS256"}); !errors.Is(err, ErrAlgNotAllowed) {
		t.Fatalf("bound alg error = %v, want ErrAlgNotAllowed", err)
	}
	if _, err := Sign([]byte(`{}`), nil, SignOptions{}); !errors.Is(err, ErrInvalidKey) {
		t.Fatalf("nil key error = %v, want ErrInvalidKey", err)
	}
}

func TestVerifyMalformed(t *testing.T) {
	resolver := resolverFor(mustGenerate(t, "HS256"), "")
	cases := []string{
		"",
		"one.two",
		"one.two.three.four",
		"a.b.",
	}
	for _, token := range cases {
		if _, err := Verify(token, resolver, VerifyOptions{}); err == nil {
			t.Fatalf("Verify(%q) succeeded, want error", token)
		}
	}
	if _, err := Verify("a.b.c", nil, VerifyOptions{}); !errors.Is(err, ErrInvalidConfig) {
		t.Fatalf("nil resolver error = %v, want ErrInvalidConfig", err)
	}
}

func TestVerifyClaimsValidation(t *testing.T) {
	key := mustGenerate(t, "HS256")
	payload := []byte(`{"iss":"issuer","aud":"aud","sub":"alice","exp":1699999940,"nbf":1699999880}`)
	token := mustSign(t, payload, key, SignOptions{Alg: "HS256"})
	resolver := resolverFor(key, "")
	now := time.Unix(1700000000, 0)
	base := VerifyOptions{
		ValidateClaims: true,
		Now:            func() time.Time { return now },
		Issuer:         "issuer",
		Audience:       "aud",
	}
	if _, err := Verify(token, resolver, base); !errors.Is(err, ErrClaimsInvalid) || !errors.Is(err, ydjwt.ErrTokenExpired) {
		t.Fatalf("expired error = %v, want ErrClaimsInvalid wrapping ErrTokenExpired", err)
	}
	base.Leeway = 2 * time.Minute
	if _, err := Verify(token, resolver, base); err != nil {
		t.Fatalf("Verify with leeway failed: %v", err)
	}
	base.Leeway = 0
	base.Issuer = "other"
	if _, err := Verify(token, resolver, base); !errors.Is(err, ErrClaimsInvalid) {
		t.Fatalf("issuer mismatch error = %v, want ErrClaimsInvalid", err)
	}
	base.Issuer = "issuer"
	base.Audience = "other"
	if _, err := Verify(token, resolver, base); !errors.Is(err, ErrClaimsInvalid) {
		t.Fatalf("audience mismatch error = %v, want ErrClaimsInvalid", err)
	}
	noClaims := mustSign(t, []byte(`{"sub":"x"}`), key, SignOptions{Alg: "HS256"})
	if _, err := Verify(noClaims, resolver, VerifyOptions{}); err != nil {
		t.Fatalf("Verify without claim validation failed: %v", err)
	}
	requireExp := VerifyOptions{
		ValidateClaims: true,
		RequireExp:     true,
		Now:            func() time.Time { return now },
	}
	if _, err := Verify(noClaims, resolver, requireExp); !errors.Is(err, ErrClaimsInvalid) {
		t.Fatalf("missing exp error = %v, want ErrClaimsInvalid", err)
	}
	nonJSON := mustSign(t, []byte("not json"), key, SignOptions{Alg: "HS256"})
	if _, err := Verify(nonJSON, resolver, VerifyOptions{ValidateClaims: true}); !errors.Is(err, ErrClaimsInvalid) {
		t.Fatalf("non-JSON claims error = %v, want ErrClaimsInvalid", err)
	}
}

// TestVerifyRFC7515HS256 checks the worked example of RFC 7515 appendix A.1. | TestVerifyRFC7515HS256
// 校验 RFC 7515 附录 A.1 的示例。
func TestVerifyRFC7515HS256(t *testing.T) {
	const token = "eyJ0eXAiOiJKV1QiLA0KICJhbGciOiJIUzI1NiJ9." +
		"eyJpc3MiOiJqb2UiLA0KICJleHAiOjEzMDA4MTkzODAsDQogImh0dHA6Ly9leGFtcGxlLmNvbS9pc19yb290Ijp0cnVlfQ." +
		"dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk"
	const jwk = `{"kty":"oct","k":"AyM1SysPpbyDfgZld3umj1qzKObwVMkoqQ-EstJQLr_T-1qS0gZH75aKtMN3Yj0iPS4hcgUuTwjAzZr1Z9CAow"}`
	key, err := ParseKey([]byte(jwk))
	if err != nil {
		t.Fatalf("ParseKey failed: %v", err)
	}
	v, err := Verify(token, KeySetResolver(&KeySet{Keys: []*Key{key}}), VerifyOptions{ValidAlgs: []string{"HS256"}})
	if err != nil {
		t.Fatalf("Verify RFC 7515 vector failed: %v", err)
	}
	if v.Header.Typ != "JWT" || v.Header.Alg != "HS256" {
		t.Fatalf("header = %+v", v.Header)
	}
	if !strings.Contains(string(v.Payload), `"iss":"joe"`) {
		t.Fatalf("payload = %q", v.Payload)
	}
}

// mustGenerate is a shorthand for GenerateKey(alg, 0). | mustGenerate 是 GenerateKey(alg, 0) 的
// 简写。
func mustGenerate(t *testing.T, alg string) *Key {
	t.Helper()
	k, err := GenerateKey(alg, 0)
	if err != nil {
		t.Fatalf("GenerateKey(%q) failed: %v", alg, err)
	}
	return k
}

// bytesRepeat returns n copies of b. | bytesRepeat 返回 n 个 b 的副本。
func bytesRepeat(b byte, n int) []byte {
	out := make([]byte, n)
	for i := range out {
		out[i] = b
	}
	return out
}

// TestSignVerifyEnforceKeyUseAndOps pins that the optional use and key_ops JWK metadata is
// enforced at the operation boundary, so a key published for encryption cannot verify signatures
// and vice versa. | TestSignVerifyEnforceKeyUseAndOps 固定「在操作边界强制执行可选的 use 与
// key_ops JWK 元数据」，因此用于加密的密钥不能验签，反之亦然。
func TestSignVerifyEnforceKeyUseAndOps(t *testing.T) {
	signer := testOctSecretKey()
	token := mustSign(t, []byte(`{"sub":"x"}`), signer, SignOptions{Alg: "HS256"})
	okResolver := KeySetResolver(&KeySet{Keys: []*Key{signer.Public()}})
	if _, err := Verify(token, okResolver, VerifyOptions{}); err != nil {
		t.Fatalf("Verify with unbound key failed: %v", err)
	}

	wrongUse := signer.Public()
	wrongUse.Use = "enc"
	if _, err := Verify(token, KeySetResolver(&KeySet{Keys: []*Key{wrongUse}}), VerifyOptions{}); !errors.Is(err, ErrInvalidKey) {
		t.Errorf("Verify(use=enc) err = %v, want ErrInvalidKey", err)
	}
	if _, err := Sign([]byte(`{"sub":"x"}`), wrongUse, SignOptions{Alg: "HS256"}); !errors.Is(err, ErrInvalidKey) {
		t.Errorf("Sign(use=enc) err = %v, want ErrInvalidKey", err)
	}

	verifyOps := signer.Public()
	verifyOps.KeyOps = []string{"verify"}
	if _, err := Verify(token, KeySetResolver(&KeySet{Keys: []*Key{verifyOps}}), VerifyOptions{}); err != nil {
		t.Fatalf("Verify(key_ops=[verify]) failed: %v", err)
	}
	signOps := signer.Clone()
	signOps.KeyOps = []string{"sign"}
	if _, err := Sign([]byte(`{"sub":"x"}`), signOps, SignOptions{Alg: "HS256"}); err != nil {
		t.Fatalf("Sign(key_ops=[sign]) failed: %v", err)
	}
	if _, err := Verify(token, KeySetResolver(&KeySet{Keys: []*Key{verifyOps.Clone()}}), VerifyOptions{}); err != nil {
		// Clone keeps key_ops and drops the derived material; verification must still succeed. |
		// 克隆保留 key_ops 但丢弃派生材料；验签仍须成功。
		t.Fatalf("Verify(cloned key_ops=[verify]) failed: %v", err)
	}

	signOnly := signer.Public()
	signOnly.KeyOps = []string{"sign"}
	if _, err := Verify(token, KeySetResolver(&KeySet{Keys: []*Key{signOnly}}), VerifyOptions{}); !errors.Is(err, ErrInvalidKey) {
		t.Errorf("Verify(key_ops=[sign]) err = %v, want ErrInvalidKey", err)
	}
}

// TestJWSRSAWeakKeysRejected pins the RFC 7518 minimum modulus size on the JWS side as well: a
// 1024-bit RSA key cannot sign or verify RSxxx/PSxxx through a JWK. | TestJWSRSAWeakKeysRejected
// 固定 JWS 侧的 RFC 7518 最小模数要求：1024 位 RSA 密钥无法通过 JWK 进行 RSxxx/PSxxx 签名或验签。
func TestJWSRSAWeakKeysRejected(t *testing.T) {
	small, err := rsa.GenerateKey(rand.Reader, 1024)
	if err != nil {
		t.Fatalf("rsa.GenerateKey: %v", err)
	}
	key, err := FromPrivateKey("weak", small)
	if err != nil {
		t.Fatalf("FromPrivateKey: %v", err)
	}
	for _, alg := range []string{"RS256", "PS256"} {
		if _, err := Sign([]byte(`{"sub":"u"}`), key, SignOptions{Alg: alg}); !errors.Is(err, ErrWeakKey) {
			t.Errorf("Sign(%s) err = %v, want ErrWeakKey", alg, err)
		}
	}
	input := []byte(EncodeSegment([]byte(`{"alg":"RS256"}`)) + "." + EncodeSegment([]byte(`{"sub":"u"}`)))
	digest := sha256.Sum256(input)
	sig, err := rsa.SignPKCS1v15(rand.Reader, small, crypto.SHA256, digest[:])
	if err != nil {
		t.Fatalf("rsa.SignPKCS1v15: %v", err)
	}
	token := string(input) + "." + EncodeSegment(sig)
	if _, err := Verify(token, KeySetResolver(&KeySet{Keys: []*Key{key.Public()}}), VerifyOptions{}); !errors.Is(err, ErrWeakKey) {
		t.Errorf("Verify(1024-bit RSA) err = %v, want ErrWeakKey", err)
	}
	key.Alg = "RS256"
	if err := key.Validate(); !errors.Is(err, ErrWeakKey) {
		t.Errorf("Validate(1024-bit RS256 key) err = %v, want ErrWeakKey", err)
	}
}

// TestVerifyTokenSizeLimit covers the pre-decode input bound: the exact limit passes, one byte over
// fails with ErrTokenTooLarge, and a zero option selects DefaultMaxTokenSize. |
// TestVerifyTokenSizeLimit 覆盖解码前的输入上限：恰好等于上限通过，超出 1 字节返回
// ErrTokenTooLarge，选项为零时使用 DefaultMaxTokenSize。
func TestVerifyTokenSizeLimit(t *testing.T) {
	signKey := testOctSecretKey()
	verifyKey := testOctSecretKey()
	token := mustSign(t, []byte(`{"sub":"u"}`), signKey, SignOptions{Alg: "HS256"})
	resolver := KeySetResolver(&KeySet{Keys: []*Key{verifyKey}})

	if _, err := Verify(token, resolver, VerifyOptions{MaxTokenSize: len(token)}); err != nil {
		t.Fatalf("Verify at exact limit failed: %v", err)
	}
	if _, err := Verify(token, resolver, VerifyOptions{MaxTokenSize: len(token) - 1}); !errors.Is(err, ErrTokenTooLarge) {
		t.Fatalf("Verify one byte over limit err = %v, want ErrTokenTooLarge", err)
	}
	if _, err := Verify(token, resolver, VerifyOptions{}); err != nil {
		t.Fatalf("Verify under default limit failed: %v", err)
	}
	huge := strings.Repeat("A", DefaultMaxTokenSize+1)
	if _, err := Verify(huge, resolver, VerifyOptions{}); !errors.Is(err, ErrTokenTooLarge) {
		t.Fatalf("Verify over default limit err = %v, want ErrTokenTooLarge", err)
	}
}
