package jwt

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"errors"
	"math/big"
	"strings"
	"testing"
	"time"

	"github.com/shibingli/ydx/base64"
)

// iatClock returns a Now function offset by d from fixedNow. | iatClock 返回相对 fixedNow 偏移 d 的 Now 函数。
func iatClock(d time.Duration) func() time.Time {
	return func() time.Time { return fixedNow.Add(d) }
}

// TestIssuedAtValidation covers the opt-in iat window: past and boundary values pass, a future
// value beyond the leeway fails, absence is accepted by ValidateIssuedAt and refused by
// RequireIssuedAt, and a non-numeric iat is a structural error once validation is enabled. |
// TestIssuedAtValidation 覆盖可选的 iat 窗口：过去与边界值通过，超出容差的未来值失败，
// ValidateIssuedAt 接受缺失而 RequireIssuedAt 拒绝缺失，启用校验后非数字 iat 是结构错误。
func TestIssuedAtValidation(t *testing.T) {
	keyFn := hmacKeyFunc(testSecret)

	past := mustSign(t, map[string]any{"iat": fixedNow.Add(-time.Minute).Unix()}, testSecret, HS256, SignOptions{})
	if _, err := Parse(past, keyFn, ParseOptions{ValidateIssuedAt: true, Now: iatClock(0)}); err != nil {
		t.Fatalf("past iat should pass, err = %v", err)
	}

	future := mustSign(t, map[string]any{"iat": fixedNow.Add(time.Hour).Unix()}, testSecret, HS256, SignOptions{})
	if _, err := Parse(future, keyFn, ParseOptions{ValidateIssuedAt: true, Now: iatClock(0)}); !errors.Is(err, ErrTokenUsedBeforeIssued) {
		t.Fatalf("future iat err = %v, want ErrTokenUsedBeforeIssued", err)
	}
	// Without the option, a future iat stays informational. | 未启用选项时，未来 iat 仍属信息性声明。
	if _, err := Parse(future, keyFn, ParseOptions{Now: iatClock(0)}); err != nil {
		t.Fatalf("future iat without option should pass, err = %v", err)
	}

	// iat equal to now+leeway is the inclusive boundary. | iat 恰等于 now+leeway 是闭区间边界。
	boundary := mustSign(t, map[string]any{"iat": fixedNow.Add(time.Minute).Unix()}, testSecret, HS256, SignOptions{})
	if _, err := Parse(boundary, keyFn, ParseOptions{ValidateIssuedAt: true, Leeway: time.Minute, Now: iatClock(0)}); err != nil {
		t.Fatalf("iat == now+leeway should pass, err = %v", err)
	}
	// One second beyond the boundary is rejected. | 超出边界 1 秒即拒绝。
	if _, err := Parse(boundary, keyFn, ParseOptions{ValidateIssuedAt: true, Leeway: time.Minute - time.Second, Now: iatClock(0)}); !errors.Is(err, ErrTokenUsedBeforeIssued) {
		t.Fatalf("iat just past now+leeway err = %v, want ErrTokenUsedBeforeIssued", err)
	}

	// Missing iat: ValidateIssuedAt alone accepts, RequireIssuedAt rejects. | 缺少 iat：仅
	// ValidateIssuedAt 时通过，RequireIssuedAt 时拒绝。
	missing := mustSign(t, map[string]any{"sub": "u"}, testSecret, HS256, SignOptions{})
	if _, err := Parse(missing, keyFn, ParseOptions{ValidateIssuedAt: true, Now: iatClock(0)}); err != nil {
		t.Fatalf("missing iat with ValidateIssuedAt should pass, err = %v", err)
	}
	if _, err := Parse(missing, keyFn, ParseOptions{RequireIssuedAt: true, Now: iatClock(0)}); !errors.Is(err, ErrMissingIssuedAt) {
		t.Fatalf("missing iat with RequireIssuedAt err = %v, want ErrMissingIssuedAt", err)
	}

	// RequireIssuedAt implies the future window check. | RequireIssuedAt 隐含未来时间检查。
	if _, err := Parse(future, keyFn, ParseOptions{RequireIssuedAt: true, Now: iatClock(0)}); !errors.Is(err, ErrTokenUsedBeforeIssued) {
		t.Fatalf("future iat with RequireIssuedAt err = %v, want ErrTokenUsedBeforeIssued", err)
	}

	// A non-numeric iat is structural once validation is enabled. | 启用校验后，非数字 iat 属结构错误。
	bad := resign(t, b64(`{"alg":"HS256"}`), b64(`{"iat":"tomorrow"}`))
	if _, err := Parse(bad, keyFn, ParseOptions{ValidateIssuedAt: true}); !errors.Is(err, ErrMalformed) {
		t.Fatalf("string iat err = %v, want ErrMalformed", err)
	}
	if _, err := Parse(bad, keyFn, ParseOptions{RequireIssuedAt: true}); !errors.Is(err, ErrMalformed) {
		t.Fatalf("string iat with RequireIssuedAt err = %v, want ErrMalformed", err)
	}
	// The same token remains readable when the option is off. | 未启用选项时该 token 仍可读取。
	if _, err := Parse(bad, keyFn, ParseOptions{}); err != nil {
		t.Fatalf("string iat without option should pass, err = %v", err)
	}

	// Fractional iat uses the same window as integer values. | 小数 iat 与整数使用同一窗口。
	frac := resign(t, b64(`{"alg":"HS256"}`), b64(`{"iat":1700000000.5}`))
	if _, err := Parse(frac, keyFn, ParseOptions{ValidateIssuedAt: true, Now: iatClock(0)}); !errors.Is(err, ErrTokenUsedBeforeIssued) {
		t.Fatalf("fractional future iat err = %v, want ErrTokenUsedBeforeIssued", err)
	}
	if _, err := Parse(frac, keyFn, ParseOptions{ValidateIssuedAt: true, Now: func() time.Time {
		return time.Unix(1700000000, 600_000_000)
	}}); err != nil {
		t.Fatalf("fractional iat within leeway should pass, err = %v", err)
	}
}

// TestIssuerSets covers Issuers and its union with Issuer. | TestIssuerSets 覆盖 Issuers 及其与 Issuer 的并集语义。
func TestIssuerSets(t *testing.T) {
	keyFn := hmacKeyFunc(testSecret)
	token := mustSign(t, map[string]any{"iss": "b", "aud": []string{"a", "b"}}, testSecret, HS256, SignOptions{})
	noIss := mustSign(t, map[string]any{"sub": "u"}, testSecret, HS256, SignOptions{})

	if _, err := Parse(token, keyFn, ParseOptions{Issuers: []string{"a", "b"}}); err != nil {
		t.Fatalf("iss in Issuers should pass, err = %v", err)
	}
	if _, err := Parse(token, keyFn, ParseOptions{Issuers: []string{"a", "c"}}); !errors.Is(err, ErrIssuerMismatch) {
		t.Fatalf("iss outside Issuers err = %v, want ErrIssuerMismatch", err)
	}
	// Issuer and Issuers form one union. | Issuer 与 Issuers 构成同一个并集。
	if _, err := Parse(token, keyFn, ParseOptions{Issuer: "b", Issuers: []string{"c"}}); err != nil {
		t.Fatalf("Issuer hit with non-matching Issuers should pass, err = %v", err)
	}
	if _, err := Parse(token, keyFn, ParseOptions{Issuer: "a", Issuers: []string{"b"}}); err != nil {
		t.Fatalf("Issuers hit with non-matching Issuer should pass, err = %v", err)
	}
	if _, err := Parse(token, keyFn, ParseOptions{Issuer: "a", Issuers: []string{"c"}}); !errors.Is(err, ErrIssuerMismatch) {
		t.Fatalf("iss outside union err = %v, want ErrIssuerMismatch", err)
	}
	// Empty entries are ignored and impose no requirement. | 空条目被忽略，不构成要求。
	if _, err := Parse(noIss, keyFn, ParseOptions{Issuers: []string{"", ""}}); err != nil {
		t.Fatalf("all-empty Issuers should not require iss, err = %v", err)
	}
	if _, err := Parse(noIss, keyFn, ParseOptions{Issuers: []string{"", "b"}}); !errors.Is(err, ErrIssuerMismatch) {
		t.Fatalf("missing iss with non-empty Issuers err = %v, want ErrIssuerMismatch", err)
	}
	// A non-string iss never matches. | 非字符串 iss 绝不匹配。
	badIss := resign(t, b64(`{"alg":"HS256"}`), b64(`{"iss":7}`))
	if _, err := Parse(badIss, keyFn, ParseOptions{Issuers: []string{"7"}}); !errors.Is(err, ErrIssuerMismatch) {
		t.Fatalf("numeric iss err = %v, want ErrIssuerMismatch", err)
	}
}

// TestAudienceSets covers Audiences and its union with Audience, including the single-string aud
// form and the "at least one" semantics. | TestAudienceSets 覆盖 Audiences 及其与 Audience 的
// 并集语义，包括字符串形式的 aud 与「至少一个」语义。
func TestAudienceSets(t *testing.T) {
	keyFn := hmacKeyFunc(testSecret)
	token := mustSign(t, map[string]any{"iss": "b", "aud": []string{"a", "b"}}, testSecret, HS256, SignOptions{})
	single := mustSign(t, map[string]any{"aud": "b"}, testSecret, HS256, SignOptions{})
	noAud := mustSign(t, map[string]any{"sub": "u"}, testSecret, HS256, SignOptions{})

	if _, err := Parse(token, keyFn, ParseOptions{Audiences: []string{"x", "b"}}); err != nil {
		t.Fatalf("aud containing one Audiences entry should pass, err = %v", err)
	}
	if _, err := Parse(token, keyFn, ParseOptions{Audiences: []string{"x", "y"}}); !errors.Is(err, ErrAudienceMismatch) {
		t.Fatalf("aud containing no Audiences entry err = %v, want ErrAudienceMismatch", err)
	}
	// A single-string aud is matched against the set. | 字符串形式的 aud 也参与集合匹配。
	if _, err := Parse(single, keyFn, ParseOptions{Audiences: []string{"b", "x"}}); err != nil {
		t.Fatalf("single-string aud should pass, err = %v", err)
	}
	// Audience and Audiences form one union. | Audience 与 Audiences 构成同一个并集。
	if _, err := Parse(token, keyFn, ParseOptions{Audience: "a", Audiences: []string{"x"}}); err != nil {
		t.Fatalf("Audience hit with non-matching Audiences should pass, err = %v", err)
	}
	if _, err := Parse(token, keyFn, ParseOptions{Audience: "x", Audiences: []string{"b"}}); err != nil {
		t.Fatalf("Audiences hit with non-matching Audience should pass, err = %v", err)
	}
	if _, err := Parse(token, keyFn, ParseOptions{Audience: "x", Audiences: []string{"y"}}); !errors.Is(err, ErrAudienceMismatch) {
		t.Fatalf("aud outside union err = %v, want ErrAudienceMismatch", err)
	}
	// Empty entries are ignored. | 空条目被忽略。
	if _, err := Parse(noAud, keyFn, ParseOptions{Audiences: []string{"", ""}}); err != nil {
		t.Fatalf("all-empty Audiences should not require aud, err = %v", err)
	}
	if _, err := Parse(noAud, keyFn, ParseOptions{Audiences: []string{"b"}}); !errors.Is(err, ErrAudienceMismatch) {
		t.Fatalf("missing aud with Audiences err = %v, want ErrAudienceMismatch", err)
	}
}

// TestECDSALowS covers the opt-in low-S normalization on signing and the matching verification
// requirement, including a valid high-S alternative signature being rejected only when required. |
// TestECDSALowS 覆盖可选的 low-S 签发规范化与对应验签要求，包括仅在要求时才拒绝合法的高 S 替代签名。
func TestECDSALowS(t *testing.T) {
	priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("ecdsa.GenerateKey failed: %v", err)
	}
	pubKeyFn := func(Header) (any, error) { return &priv.PublicKey, nil }
	claims := map[string]any{"sub": "low-s"}

	low := mustSign(t, claims, priv, ES256, SignOptions{LowS: true})
	tok := mustParse(t, low, pubKeyFn, ParseOptions{ValidAlgs: []Alg{ES256}, RequireLowS: true})
	if len(tok.Signature) != 64 {
		t.Fatalf("len(signature) = %d, want 64", len(tok.Signature))
	}
	if !isLowS(elliptic.P256(), tok.Signature[32:]) {
		t.Fatal("SignOptions.LowS produced a high-S signature")
	}
	// The same signature passes without the requirement. | 同一签名在未要求时也通过。
	if _, err := Parse(low, pubKeyFn, ParseOptions{ValidAlgs: []Alg{ES256}}); err != nil {
		t.Fatalf("low-S token without RequireLowS failed: %v", err)
	}

	// (r, N-s) is an equally valid ECDSA signature; flipping the low half yields the high-S form. |
	// (r, N-s) 同样是合法的 ECDSA 签名；翻转低半值即可得到高 S 形式。
	parts := strings.Split(low, ".")
	sigRaw, err := base64.RawURLEncoding.DecodeString(parts[2])
	if err != nil {
		t.Fatalf("decode signature failed: %v", err)
	}
	s := new(big.Int).SetBytes(sigRaw[32:])
	high := new(big.Int).Sub(elliptic.P256().Params().N, s)
	highSig := make([]byte, 64)
	copy(highSig, sigRaw[:32])
	high.FillBytes(highSig[32:])
	highToken := buildSegments(parts[0], parts[1], base64.RawURLEncoding.EncodeToString(highSig))

	// The high-S form is mathematically valid, so it passes by default. | 高 S 形式在数学上合法，
	// 因此默认配置下通过。
	if _, err := Parse(highToken, pubKeyFn, ParseOptions{ValidAlgs: []Alg{ES256}}); err != nil {
		t.Fatalf("high-S token without RequireLowS failed: %v", err)
	}
	if _, err := Parse(highToken, pubKeyFn, ParseOptions{ValidAlgs: []Alg{ES256}, RequireLowS: true}); !errors.Is(err, ErrSignatureInvalid) {
		t.Fatalf("high-S token with RequireLowS err = %v, want ErrSignatureInvalid", err)
	}
}
