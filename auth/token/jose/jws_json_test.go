package jose

import (
	"crypto/elliptic"
	"errors"
	"math/big"
	"strings"
	"testing"
	"time"

	ydjwt "github.com/shibingli/ydx/auth/token/jwt"
)

// jsonString returns s as a JSON string literal. | jsonString 返回 s 的 JSON 字符串字面量。
func jsonString(s string) string {
	return string(appendJSONString(nil, s))
}

// rawSign signs input for alg and returns the base64url signature segment. | rawSign 按 alg 对
// input 签名并返回 base64url 签名段。
func rawSign(t *testing.T, alg string, key *Key, input string) string {
	t.Helper()
	sig, err := signJWS(alg, key, []byte(input))
	if err != nil {
		t.Fatalf("signJWS(%q) failed: %v", alg, err)
	}
	return EncodeSegment(sig)
}

// tamperJSONStringMember flips the first character of the named JSON string member. | tamperJSONStringMember
// 翻转指定 JSON 字符串成员的首个字符。
func tamperJSONStringMember(t *testing.T, doc, name string) string {
	t.Helper()
	marker := `"` + name + `":"`
	i := strings.Index(doc, marker)
	if i < 0 {
		t.Fatalf("member %q not found in %q", name, doc)
	}
	start := i + len(marker)
	if start >= len(doc) {
		t.Fatalf("member %q has no value in %q", name, doc)
	}
	repl := byte('A')
	if doc[start] == 'A' {
		repl = 'B'
	}
	return doc[:start] + string(repl) + doc[start+1:]
}

// flipSignatureS returns the (r, N-s) variant of a fixed-width ECDSA signature segment. | flipSignatureS
// 返回定宽 ECDSA 签名段的 (r, N-s) 变体。
func flipSignatureS(t *testing.T, sigSeg string) string {
	t.Helper()
	raw, err := DecodeSegment(sigSeg)
	if err != nil {
		t.Fatalf("DecodeSegment failed: %v", err)
	}
	if len(raw) != 64 {
		t.Fatalf("signature is %d bytes, want 64", len(raw))
	}
	n := elliptic.P256().Params().N
	s := new(big.Int).SetBytes(raw[32:])
	s.Sub(n, s)
	out := make([]byte, 64)
	copy(out, raw[:32])
	s.FillBytes(out[32:])
	return EncodeSegment(out)
}

// TestJWSJSONSerializations covers flattened and general signing and verification, auto-detection,
// explicit serialization pinning, and tampering of the payload and signature members. |
// TestJWSJSONSerializations 覆盖扁平与通用形式的签发与验签、自动识别、显式固定序列化形式，以及
// 对 payload 与 signature 成员的篡改。
func TestJWSJSONSerializations(t *testing.T) {
	payload := []byte(`{"sub":"alice"}`)
	for _, alg := range []string{"HS256", "RS256", "ES256", "EdDSA"} {
		key := jwsTestKey(t, alg)
		kid := "kid-" + alg
		resolver := resolverFor(key, kid)
		for _, ser := range []Serialization{SerializationFlattened, SerializationGeneral} {
			t.Run(alg+"/"+string(ser), func(t *testing.T) {
				token := mustSign(t, payload, key, SignOptions{Alg: alg, Kid: kid, Typ: "JWT", Serialization: ser})
				if !strings.HasPrefix(token, "{") {
					t.Fatalf("token = %q, want JSON serialization", token)
				}
				if ser == SerializationGeneral && !strings.Contains(token, `"signatures":[{`) {
					t.Fatalf("general token = %q", token)
				}
				if ser == SerializationFlattened && strings.Contains(token, `"signatures"`) {
					t.Fatalf("flattened token carries signatures = %q", token)
				}

				v := mustVerify(t, token, resolver, VerifyOptions{ValidAlgs: []string{alg}, Typ: "JWT"})
				if v.Header.Alg != alg || v.Header.Kid != kid {
					t.Fatalf("header = %+v", v.Header)
				}
				if string(v.Payload) != string(payload) || string(v.Claims) != string(payload) {
					t.Fatalf("payload = %q, claims = %q", v.Payload, v.Claims)
				}
				if _, err := Verify(token, resolver, VerifyOptions{ValidAlgs: []string{alg}, Serialization: ser}); err != nil {
					t.Fatalf("Verify with explicit serialization failed: %v", err)
				}
				other := SerializationFlattened
				if ser == SerializationFlattened {
					other = SerializationGeneral
				}
				if _, err := Verify(token, resolver, VerifyOptions{Serialization: other}); !errors.Is(err, ErrMalformed) {
					t.Fatalf("mismatched serialization err = %v, want ErrMalformed", err)
				}

				badSig := tamperJSONStringMember(t, token, "signature")
				if _, err := Verify(badSig, resolver, VerifyOptions{}); !errors.Is(err, ErrSignatureInvalid) {
					t.Fatalf("tampered signature err = %v, want ErrSignatureInvalid", err)
				}
				badPayload := tamperJSONStringMember(t, token, "payload")
				if _, err := Verify(badPayload, resolver, VerifyOptions{}); !errors.Is(err, ErrSignatureInvalid) {
					t.Fatalf("tampered payload err = %v, want ErrSignatureInvalid", err)
				}
			})
		}
	}
}

// TestJWSJSONStrictParsing covers the structural refusals of the JSON parser: duplicate members,
// mixed general and flattened members, empty or malformed signature arrays, non-string values,
// trailing data, and the permissive treatment of unknown extension members. |
// TestJWSJSONStrictParsing 覆盖 JSON 解析器的结构性拒绝：重复成员、通用与扁平成员混用、签名数组
// 为空或格式非法、非字符串取值、尾随数据，以及对未知扩展成员的宽容处理。
func TestJWSJSONStrictParsing(t *testing.T) {
	key := jwsTestKey(t, "HS256")
	resolver := resolverFor(key, "")
	p := EncodeSegment([]byte(`{"alg":"HS256"}`))
	pB64 := EncodeSegment([]byte(`{"alg":"HS256","b64":false}`))
	s := EncodeSegment([]byte{0x01, 0x02, 0x03})
	payloadSeg := EncodeSegment([]byte(`{"sub":"x"}`))
	valid := `{"payload":` + jsonString(payloadSeg) + `,"protected":` + jsonString(p) +
		`,"signature":` + jsonString(s) + `}`

	cases := []struct {
		name  string
		token string
		want  error
	}{
		{"not object", `[]`, ErrMalformed},
		{"duplicate payload", `{"payload":"e30","payload":"e30","protected":` + jsonString(p) + `,"signature":` + jsonString(s) + `}`, ErrInvalidHeader},
		{"mixed forms", `{"payload":"e30","protected":` + jsonString(p) + `,"signature":` + jsonString(s) + `,"signatures":[]}`, ErrMalformed},
		{"empty signatures", `{"payload":"e30","signatures":[]}`, ErrMalformed},
		{"signatures not array", `{"signatures":{}}`, ErrMalformed},
		{"entry missing signature", `{"signatures":[{"protected":"e30"}]}`, ErrMalformed},
		{"entry not object", `{"signatures":["x"]}`, ErrMalformed},
		{"header not object", `{"payload":"e30","protected":` + jsonString(p) + `,"header":"x","signature":` + jsonString(s) + `}`, ErrInvalidHeader},
		{"protected not string", `{"payload":"e30","protected":7,"signature":"e30"}`, ErrMalformed},
		{"protected b64 false", `{"payload":"e30","protected":` + jsonString(pB64) + `,"signature":` + jsonString(s) + `}`, ErrInvalidHeader},
		{"payload not string", `{"payload":7,"protected":` + jsonString(p) + `,"signature":` + jsonString(s) + `}`, ErrMalformed},
		{"payload not base64url", `{"payload":"!!","protected":` + jsonString(p) + `,"signature":` + jsonString(s) + `}`, ErrMalformed},
		{"trailing data", valid + `x`, ErrMalformed},
		{"no signature", `{"payload":"e30","protected":` + jsonString(p) + `}`, ErrMalformed},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if _, err := Verify(tc.token, resolver, VerifyOptions{}); !errors.Is(err, tc.want) {
				t.Fatalf("Verify(%q) err = %v, want %v", tc.token, err, tc.want)
			}
		})
	}

	t.Run("unknown member", func(t *testing.T) {
		token := mustSign(t, []byte(`{"sub":"x"}`), key, SignOptions{Alg: "HS256", Serialization: SerializationFlattened})
		if _, err := Verify(`{"tenant":"acme",`+token[1:], resolver, VerifyOptions{}); err != nil {
			t.Fatalf("unknown member should be ignored, err = %v", err)
		}
	})
}

// TestJWSDetachedPayload covers RFC 7515 Appendix F for compact, flattened and general forms:
// the serialization omits the payload, Verify refuses it, VerifyDetached accepts the exact bytes
// and refuses different bytes or a token that still carries a payload. | TestJWSDetachedPayload
// 覆盖紧凑、扁平与通用形式的 RFC 7515 附录 F：序列化省略载荷，Verify 拒绝，VerifyDetached 接受
// 完全一致的字节并拒绝不同字节或仍携带载荷的 token。
func TestJWSDetachedPayload(t *testing.T) {
	key := jwsTestKey(t, "HS256")
	payload := []byte(`{"sub":"detached"}`)
	resolver := resolverFor(key, "k")

	compact := mustSign(t, payload, key, SignOptions{Alg: "HS256", Kid: "k", Detached: true})
	if strings.Count(compact, ".") != 2 || !strings.Contains(compact, "..") {
		t.Fatalf("detached compact token = %q", compact)
	}
	if _, err := Verify(compact, resolver, VerifyOptions{}); !errors.Is(err, ErrSignatureInvalid) {
		t.Fatalf("Verify(detached compact) err = %v, want ErrSignatureInvalid", err)
	}
	v, err := VerifyDetached(compact, payload, resolver, VerifyOptions{})
	if err != nil {
		t.Fatalf("VerifyDetached(compact) failed: %v", err)
	}
	if string(v.Payload) != string(payload) || string(v.Claims) != string(payload) {
		t.Fatalf("payload = %q, claims = %q", v.Payload, v.Claims)
	}
	if _, err := VerifyDetached(compact, []byte("other"), resolver, VerifyOptions{}); !errors.Is(err, ErrSignatureInvalid) {
		t.Fatalf("wrong detached payload err = %v, want ErrSignatureInvalid", err)
	}
	withPayload := mustSign(t, payload, key, SignOptions{Alg: "HS256", Kid: "k"})
	if _, err := VerifyDetached(withPayload, payload, resolver, VerifyOptions{}); !errors.Is(err, ErrMalformed) {
		t.Fatalf("VerifyDetached(token with payload) err = %v, want ErrMalformed", err)
	}

	empty := mustSign(t, nil, key, SignOptions{Alg: "HS256", Kid: "k", Detached: true})
	if v, err := VerifyDetached(empty, nil, resolver, VerifyOptions{}); err != nil || len(v.Payload) != 0 {
		t.Fatalf("VerifyDetached(empty) = %v, %v", v, err)
	}
	if _, err := VerifyDetached(empty, []byte{0x00}, resolver, VerifyOptions{}); !errors.Is(err, ErrSignatureInvalid) {
		t.Fatalf("empty detached with non-empty payload err = %v, want ErrSignatureInvalid", err)
	}

	for _, ser := range []Serialization{SerializationFlattened, SerializationGeneral} {
		t.Run(string(ser), func(t *testing.T) {
			token := mustSign(t, payload, key, SignOptions{Alg: "HS256", Kid: "k", Serialization: ser, Detached: true})
			if strings.Contains(token, `"payload"`) {
				t.Fatalf("detached JSON retains payload: %q", token)
			}
			if _, err := Verify(token, resolver, VerifyOptions{}); !errors.Is(err, ErrMalformed) {
				t.Fatalf("Verify(detached JSON) err = %v, want ErrMalformed", err)
			}
			if _, err := VerifyDetached(token, payload, resolver, VerifyOptions{Serialization: ser}); err != nil {
				t.Fatalf("VerifyDetached(JSON) failed: %v", err)
			}
			if _, err := VerifyDetached(token, []byte("other"), resolver, VerifyOptions{}); !errors.Is(err, ErrSignatureInvalid) {
				t.Fatalf("wrong detached JSON payload err = %v, want ErrSignatureInvalid", err)
			}
			full := mustSign(t, payload, key, SignOptions{Alg: "HS256", Kid: "k", Serialization: ser})
			if _, err := VerifyDetached(full, payload, resolver, VerifyOptions{}); !errors.Is(err, ErrMalformed) {
				t.Fatalf("VerifyDetached(JSON with payload) err = %v, want ErrMalformed", err)
			}
		})
	}
}

// TestJWSJSONUnprotectedHeader covers merging the unprotected header into the resolver input and
// refusing protected/unprotected duplicates plus crit and b64 in the unprotected header. |
// TestJWSJSONUnprotectedHeader 覆盖把非保护头部合并进解析器输入，并拒绝受保护与非保护头部重复，
// 以及非保护头部中的 crit 与 b64。
func TestJWSJSONUnprotectedHeader(t *testing.T) {
	key := jwsTestKey(t, "HS256")
	payloadSeg := EncodeSegment([]byte(`{"sub":"u"}`))
	protected := EncodeSegment([]byte(`{"alg":"HS256"}`))
	sig := rawSign(t, "HS256", key, protected+"."+payloadSeg)
	resolver := resolverFor(key, "k")
	build := func(header string) string {
		return `{"payload":` + jsonString(payloadSeg) + `,"protected":` + jsonString(protected) +
			`,"header":` + header + `,"signature":` + jsonString(sig) + `}`
	}

	v, err := Verify(build(`{"kid":"k"}`), resolver, VerifyOptions{})
	if err != nil {
		t.Fatalf("unprotected kid failed: %v", err)
	}
	if v.Header.Kid != "" || v.RawHeader.String("kid") != "k" {
		t.Fatalf("merged header = %+v / %v", v.Header, v.RawHeader)
	}
	if _, err := Verify(build(`{"alg":"HS256"}`), resolver, VerifyOptions{}); !errors.Is(err, ErrInvalidHeader) {
		t.Fatalf("duplicate alg err = %v, want ErrInvalidHeader", err)
	}
	if _, err := Verify(build(`{"crit":["exp"]}`), resolver, VerifyOptions{}); !errors.Is(err, ErrUnsupportedCrit) {
		t.Fatalf("unprotected crit err = %v, want ErrUnsupportedCrit", err)
	}
	if _, err := Verify(build(`{"b64":false}`), resolver, VerifyOptions{}); !errors.Is(err, ErrInvalidHeader) {
		t.Fatalf("unprotected b64 err = %v, want ErrInvalidHeader", err)
	}
	if _, err := Verify(build(`"not an object"`), resolver, VerifyOptions{}); !errors.Is(err, ErrInvalidHeader) {
		t.Fatalf("non-object header err = %v, want ErrInvalidHeader", err)
	}

	// A signature without a protected header is refused even when alg sits in the unprotected
	// header. | 即使 alg 位于非保护头部，缺少受保护头部的签名也会被拒绝。
	noProtected := `{"payload":` + jsonString(payloadSeg) + `,"header":{"alg":"HS256","kid":"k"},"signature":` + jsonString(sig) + `}`
	if _, err := Verify(noProtected, resolver, VerifyOptions{}); !errors.Is(err, ErrInvalidHeader) {
		t.Fatalf("missing protected header err = %v, want ErrInvalidHeader", err)
	}
}

// TestJWSJSONMultiSignature covers general-form semantics: any signature that verifies makes the
// document valid, the successful signature's header is returned, and the first failure surfaces
// when none verifies. | TestJWSJSONMultiSignature 覆盖通用形式语义：任意一个签名通过即文档有效，
// 返回通过签名的头部；全部失败时返回第一个错误。
func TestJWSJSONMultiSignature(t *testing.T) {
	key1 := jwsTestKey(t, "HS256")
	key2 := jwsTestKey(t, "HS256")
	payloadSeg := EncodeSegment([]byte(`{"sub":"multi"}`))
	p1 := EncodeSegment([]byte(`{"alg":"HS256","kid":"one"}`))
	p2 := EncodeSegment([]byte(`{"alg":"HS256","kid":"two"}`))
	s1 := rawSign(t, "HS256", key1, p1+"."+payloadSeg)
	s2 := rawSign(t, "HS256", key2, p2+"."+payloadSeg)

	pub1, pub2 := key1.Public(), key2.Public()
	pub1.Kid, pub2.Kid = "one", "two"
	resolver := KeySetResolver(&KeySet{Keys: []*Key{pub1, pub2}})

	doc := func(sig1, sig2 string) string {
		return `{"payload":` + jsonString(payloadSeg) + `,"signatures":[` +
			`{"protected":` + jsonString(p1) + `,"signature":` + jsonString(sig1) + `},` +
			`{"protected":` + jsonString(p2) + `,"signature":` + jsonString(sig2) + `}]}`
	}

	v, err := Verify(doc(s1, s2), resolver, VerifyOptions{})
	if err != nil {
		t.Fatalf("Verify(two valid signatures) failed: %v", err)
	}
	if v.Header.Kid != "one" {
		t.Fatalf("header kid = %q, want first signature", v.Header.Kid)
	}

	bad1 := tamperSegment(t, s1)
	v, err = Verify(doc(bad1, s2), resolver, VerifyOptions{})
	if err != nil {
		t.Fatalf("Verify(second signature valid) failed: %v", err)
	}
	if v.Header.Kid != "two" {
		t.Fatalf("header kid = %q, want second signature", v.Header.Kid)
	}

	if _, err := Verify(doc(bad1, tamperSegment(t, s2)), resolver, VerifyOptions{}); !errors.Is(err, ErrSignatureInvalid) {
		t.Fatalf("all bad signatures err = %v, want ErrSignatureInvalid", err)
	}
}

// TestJWSJSONClaimsOptions covers claim validation over JSON serializations, including the new
// multi-issuer, multi-audience and iat options forwarded to ydx/auth/token/jwt. |
// TestJWSJSONClaimsOptions 覆盖 JSON 序列化上的声明校验，包括转发给 ydx/auth/token/jwt 的新增
// 多 issuer、多 audience 与 iat 选项。
func TestJWSJSONClaimsOptions(t *testing.T) {
	key := jwsTestKey(t, "HS256")
	resolver := resolverFor(key, "")
	now := time.Unix(1700000000, 0)
	payload := []byte(`{"iss":"b","aud":["a","b"],"iat":1700000000,"exp":1700000600}`)

	for _, ser := range []Serialization{SerializationFlattened, SerializationGeneral} {
		t.Run(string(ser), func(t *testing.T) {
			token := mustSign(t, payload, key, SignOptions{Alg: "HS256", Serialization: ser})
			base := VerifyOptions{
				ValidateClaims:   true,
				Now:              func() time.Time { return now },
				Issuers:          []string{"a", "b"},
				Audiences:        []string{"x", "b"},
				ValidateIssuedAt: true,
			}
			if _, err := Verify(token, resolver, base); err != nil {
				t.Fatalf("Verify with claim sets failed: %v", err)
			}
			base.Issuers = []string{"c"}
			if _, err := Verify(token, resolver, base); !errors.Is(err, ErrClaimsInvalid) || !errors.Is(err, ydjwt.ErrIssuerMismatch) {
				t.Fatalf("issuer mismatch err = %v", err)
			}
			base.Issuers = []string{"b"}
			base.Audiences = []string{"y"}
			if _, err := Verify(token, resolver, base); !errors.Is(err, ErrClaimsInvalid) || !errors.Is(err, ydjwt.ErrAudienceMismatch) {
				t.Fatalf("audience mismatch err = %v", err)
			}
			base.Audiences = []string{"b"}
			base.Now = func() time.Time { return time.Unix(1699999000, 0) }
			if _, err := Verify(token, resolver, base); !errors.Is(err, ErrClaimsInvalid) || !errors.Is(err, ydjwt.ErrTokenUsedBeforeIssued) {
				t.Fatalf("future iat err = %v", err)
			}
		})
	}

	noIat := mustSign(t, []byte(`{"exp":1700000600}`), key, SignOptions{Alg: "HS256", Serialization: SerializationFlattened})
	if _, err := Verify(noIat, resolver, VerifyOptions{
		ValidateClaims:  true,
		RequireIssuedAt: true,
		Now:             func() time.Time { return now },
	}); !errors.Is(err, ErrClaimsInvalid) || !errors.Is(err, ydjwt.ErrMissingIssuedAt) {
		t.Fatalf("missing iat err = %v", err)
	}
}

// TestJWSECDSALowS covers opt-in low-S signing and the RequireLowS verification option: the
// normalized signature passes, the equally valid high-S alternative passes by default and fails
// when low-S is required, for both compact and flattened serializations. |
// TestJWSECDSALowS 覆盖可选的 low-S 签发与 RequireLowS 验签选项：规范化签名通过，同样合法的高 S
// 替代签名默认通过、要求 low-S 时失败，紧凑与扁平序列化均如此。
func TestJWSECDSALowS(t *testing.T) {
	key := jwsTestKey(t, "ES256")
	resolver := resolverFor(key, "")
	payload := []byte(`{"sub":"s"}`)
	opts := VerifyOptions{ValidAlgs: []string{"ES256"}}

	compact := mustSign(t, payload, key, SignOptions{Alg: "ES256", LowS: true})
	parts := strings.Split(compact, ".")
	if len(parts) != 3 {
		t.Fatalf("compact token has %d segments", len(parts))
	}
	sigRaw, err := DecodeSegment(parts[2])
	if err != nil {
		t.Fatalf("DecodeSegment failed: %v", err)
	}
	if !isLowS(elliptic.P256(), sigRaw[32:]) {
		t.Fatal("LowS signing produced a high-S signature")
	}
	if _, err := Verify(compact, resolver, VerifyOptions{ValidAlgs: []string{"ES256"}, RequireLowS: true}); err != nil {
		t.Fatalf("Verify(low-S, require) failed: %v", err)
	}

	highSig := flipSignatureS(t, parts[2])
	highCompact := parts[0] + "." + parts[1] + "." + highSig
	if _, err := Verify(highCompact, resolver, opts); err != nil {
		t.Fatalf("high-S should verify by default: %v", err)
	}
	if _, err := Verify(highCompact, resolver, VerifyOptions{ValidAlgs: []string{"ES256"}, RequireLowS: true}); !errors.Is(err, ErrSignatureInvalid) {
		t.Fatalf("high-S with RequireLowS err = %v, want ErrSignatureInvalid", err)
	}

	highJSON := `{"payload":` + jsonString(parts[1]) + `,"protected":` + jsonString(parts[0]) +
		`,"signature":` + jsonString(highSig) + `}`
	if _, err := Verify(highJSON, resolver, opts); err != nil {
		t.Fatalf("high-S JSON should verify by default: %v", err)
	}
	if _, err := Verify(highJSON, resolver, VerifyOptions{ValidAlgs: []string{"ES256"}, RequireLowS: true}); !errors.Is(err, ErrSignatureInvalid) {
		t.Fatalf("high-S JSON with RequireLowS err = %v, want ErrSignatureInvalid", err)
	}
	lowJSON := mustSign(t, payload, key, SignOptions{Alg: "ES256", LowS: true, Serialization: SerializationFlattened})
	if _, err := Verify(lowJSON, resolver, VerifyOptions{ValidAlgs: []string{"ES256"}, RequireLowS: true}); err != nil {
		t.Fatalf("low-S JSON with RequireLowS failed: %v", err)
	}

	// LowS is a no-op for non-ECDSA algorithms. | LowS 对非 ECDSA 算法是空操作。
	hsKey := jwsTestKey(t, "HS256")
	hs := mustSign(t, payload, hsKey, SignOptions{Alg: "HS256", LowS: true})
	if _, err := Verify(hs, resolverFor(hsKey, ""), VerifyOptions{RequireLowS: true}); err != nil {
		t.Fatalf("RequireLowS with HS256 failed: %v", err)
	}
}

// TestJWSSerializationOptionErrors covers unknown serialization values on both signing and
// verification. | TestJWSSerializationOptionErrors 覆盖签名与验签两侧的未知序列化取值。
func TestJWSSerializationOptionErrors(t *testing.T) {
	key := jwsTestKey(t, "HS256")
	if _, err := Sign([]byte(`{}`), key, SignOptions{Alg: "HS256", Serialization: Serialization("bogus")}); !errors.Is(err, ErrInvalidConfig) {
		t.Fatalf("Sign unknown serialization err = %v, want ErrInvalidConfig", err)
	}
	if _, err := Sign([]byte(`{}`), key, SignOptions{Alg: "HS256", Detached: true, Extra: map[string]any{"b64": false}}); !errors.Is(err, ErrInvalidHeader) {
		t.Fatalf("Sign b64=false err = %v, want ErrInvalidHeader", err)
	}
	token := mustSign(t, []byte(`{}`), key, SignOptions{Alg: "HS256"})
	if _, err := Verify(token, resolverFor(key, ""), VerifyOptions{Serialization: Serialization("bogus")}); !errors.Is(err, ErrInvalidConfig) {
		t.Fatalf("Verify unknown serialization err = %v, want ErrInvalidConfig", err)
	}
}
