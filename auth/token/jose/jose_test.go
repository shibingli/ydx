package jose

import (
	"context"
	"crypto/ed25519"
	"errors"
	"strings"
	"testing"
	"time"
)

// testSecretBytes returns the deterministic HMAC secret of these tests. | testSecretBytes 返回这些
// 测试使用的确定性 HMAC 密钥。
func testSecretBytes() []byte { return bytesRepeat(0x5a, 32) }

// testOctSecretKey returns an unbound "oct" key holding testSecretBytes. | testOctSecretKey 返回持有
// testSecretBytes 的未绑定 "oct" 密钥。
func testOctSecretKey() *Key {
	return &Key{Kty: KeyTypeOct, K: EncodeSegment(testSecretBytes())}
}

// TestHeaderAccessors covers Header.String and Header.Has. | TestHeaderAccessors 覆盖 Header.String
// 与 Header.Has。
func TestHeaderAccessors(t *testing.T) {
	h := Header{"alg": "HS256", "kid": "k1", "num": float64(1)}
	if got := h.String("alg"); got != "HS256" {
		t.Errorf("String(alg) = %q，期望 HS256", got)
	}
	if got := h.String("num"); got != "" {
		t.Errorf("String(num) = %q，期望空串", got)
	}
	if got := h.String("missing"); got != "" {
		t.Errorf("String(missing) = %q，期望空串", got)
	}
	if !h.Has("kid") {
		t.Error("Has(kid) = false，期望 true")
	}
	if h.Has("missing") {
		t.Error("Has(missing) = true，期望 false")
	}
}

// TestDecodeRune covers every branch of the UTF-8 decoder. | TestDecodeRune 覆盖 UTF-8 解码器的
// 每个分支。
func TestDecodeRune(t *testing.T) {
	cases := []struct {
		name string
		in   string
		want rune
		size int
	}{
		{"empty", "", 0, 0},
		{"ascii", "A", 'A', 1},
		{"continuation-only", "\x80rest", '�', 1},
		{"two-byte", "é", 'é', 2},
		{"two-byte-truncated", "\xc3", '�', 1},
		{"two-byte-bad-continuation", "\xc3(", '�', 1},
		{"three-byte", "€", '€', 3},
		{"three-byte-truncated", "\xe2\x82", '�', 1},
		{"three-byte-bad-third", "\xe2\x82(", '�', 1},
		{"three-byte-overlong", "\xe0\x80\x80", '�', 1},
		{"four-byte", "😀", '😀', 4},
		{"four-byte-truncated", "\xf0\x9f\x98", '�', 1},
		{"four-byte-bad-second", "\xf0(", '�', 1},
		{"four-byte-below-range", "\xf0\x80\x80\x80", '�', 1},
		{"four-byte-above-range", "\xf4\x90\x80\x80", '�', 1},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			r, size := decodeRune(tc.in)
			if r != tc.want || size != tc.size {
				t.Errorf("decodeRune(%q) = (%q, %d)，期望 (%q, %d)", tc.in, r, size, tc.want, tc.size)
			}
		})
	}
}

// TestAppendJSONString covers escaping and the invalid-UTF-8 replacement rule. | TestAppendJSONString
// 覆盖转义与非法 UTF-8 替换规则。
func TestAppendJSONString(t *testing.T) {
	cases := []struct {
		name string
		in   string
		want string
	}{
		{"plain", "abc", `"abc"`},
		{"quote-and-backslash", `a"b\c`, `"a\"b\\c"`},
		{"controls", "\b\f\n\r\t", `"\b\f\n\r\t"`},
		{"low-control", "\x01", `"\u0001"`},
		{"utf8", "é€😀", "\"é€😀\""},
		{"invalid-byte", "a\xffb", "\"a�b\""},
		{"truncated-rune", "a\xe2\x82b", "\"a��b\""},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := string(appendJSONString(nil, tc.in)); got != tc.want {
				t.Errorf("appendJSONString(%q) = %s，期望 %s", tc.in, got, tc.want)
			}
		})
	}
}

// TestIsJSONObject covers the whitespace and non-object branches. | TestIsJSONObject 覆盖空白与
// 非对象分支。
func TestIsJSONObject(t *testing.T) {
	cases := []struct {
		in   string
		want bool
	}{
		{"", false},
		{"   ", false},
		{" \t\r\n{}", true},
		{`{"a":1}`, true},
		{`[]`, false},
		{`"x"`, false},
		{`{"a":}`, false},
	}
	for _, tc := range cases {
		if got := isJSONObject([]byte(tc.in)); got != tc.want {
			t.Errorf("isJSONObject(%q) = %v，期望 %v", tc.in, got, tc.want)
		}
	}
}

// TestHeaderJSON covers the fast path, the strict fallback and every rejection. | TestHeaderJSON
// 覆盖快速路径、严格回退与所有拒绝分支。
func TestHeaderJSON(t *testing.T) {
	okCases := []struct {
		name string
		raw  string
		alg  string
		kid  any
	}{
		{"empty object", `{}`, "", nil},
		{"fast path", ` { "alg" : "HS256" , "kid" : "k1" } `, "HS256", "k1"},
		{"non-string value falls back", `{"alg":"HS256","n":1}`, "HS256", nil},
		{"escaped string falls back", `{"alg":"HS256","kid":"a\tb"}`, "HS256", "a\tb"},
		{"non-ascii falls back", `{"alg":"HS256","kid":"名字"}`, "HS256", "名字"},
	}
	for _, tc := range okCases {
		t.Run(tc.name, func(t *testing.T) {
			m, err := headerJSON([]byte(tc.raw))
			if err != nil {
				t.Fatalf("headerJSON(%s) 失败: %v", tc.raw, err)
			}
			if got, _ := m["alg"].(string); got != tc.alg {
				t.Errorf("alg = %q，期望 %q", got, tc.alg)
			}
			if tc.kid != nil && m["kid"] != tc.kid {
				t.Errorf("kid = %v，期望 %v", m["kid"], tc.kid)
			}
		})
	}

	badCases := []struct {
		name string
		raw  string
	}{
		{"oversized", `{"alg":"` + strings.Repeat("a", maxHeaderBytes) + `"}`},
		{"not an object", `[]`},
		{"duplicate member", `{"alg":"HS256","alg":"RS256"}`},
		{"nested duplicate member", `{"alg":"HS256","x":{"a":1,"a":2}}`},
		{"trailing garbage", `{"alg":"HS256"}x`},
		{"unterminated", `{"alg":"HS256"`},
		{"missing colon", `{"alg" "HS256"}`},
		{"missing comma", `{"alg":"HS256" "kid":"k"}`},
	}
	for _, tc := range badCases {
		t.Run(tc.name, func(t *testing.T) {
			if _, err := headerJSON([]byte(tc.raw)); err == nil {
				t.Fatalf("headerJSON(%s) 未报错，期望失败", tc.raw)
			} else if !errors.Is(err, ErrInvalidHeader) {
				t.Errorf("err = %v，期望 ErrInvalidHeader", err)
			}
		})
	}
}

// TestScanJSONHelpers covers the scanner branches that headerJSON relies on. | TestScanJSONHelpers
// 覆盖 headerJSON 依赖的扫描器分支。
func TestScanJSONHelpers(t *testing.T) {
	if next, ok := scanCleanASCIIString([]byte(`"abc"`), 0); !ok || next != 5 {
		t.Errorf("scanCleanASCIIString clean = (%d, %v)，期望 (5, true)", next, ok)
	}
	badStrings := [][]byte{
		{'"', 'a', 0x5c, 'u', '0', '0', '6', '2', '"'}, // escaped member | 带转义的成员
		{'"', 'a', 0x01, '"'},                          // control byte | 控制字节
		{'"', 'a'},                                     // unterminated | 未闭合
		{'a', 'b', 'c'},                                // no opening quote | 无起始引号
	}
	for _, raw := range badStrings {
		if _, ok := scanCleanASCIIString(raw, 0); ok {
			t.Errorf("scanCleanASCIIString(%q) = true，期望 false", raw)
		}
	}
	if next, ok := scanJSONString([]byte(`"a\"b"tail`), 0); !ok || next != 6 {
		t.Errorf("scanJSONString escaped = (%d, %v)，期望 (6, true)", next, ok)
	}
	if _, ok := scanJSONString([]byte(`"abc`), 0); ok {
		t.Error("scanJSONString unterminated = true，期望 false")
	}
	if _, ok := scanJSONString([]byte(`x"abc"`), 0); ok {
		t.Error("scanJSONString without quote = true，期望 false")
	}

	numCases := []struct {
		in   string
		next int
		ok   bool
	}{
		{"123", 3, true},
		{"-1.5e+3", 7, true},
		{"", 0, false},
		{"x1", 0, false},
	}
	for _, tc := range numCases {
		next, ok, dup := scanJSONNumber([]byte(tc.in), 0)
		if next != tc.next || ok != tc.ok || dup {
			t.Errorf("scanJSONNumber(%q) = (%d, %v, %v)，期望 (%d, %v, false)", tc.in, next, ok, dup, tc.next, tc.ok)
		}
	}

	if _, ok, _ := scanJSONValue([]byte(""), 0, 0); ok {
		t.Error("scanJSONValue(empty) = true，期望 false")
	}
	if _, ok, _ := scanJSONValue([]byte("truthy"), 0, 0); ok {
		t.Error("scanJSONValue(bad literal) = true，期望 false")
	}
	if _, ok, _ := scanJSONValue([]byte(`[1,]`), 0, 0); !ok {
		t.Error("scanJSONValue(trailing array comma) = false，期望 true（严格性由 json.Valid 保证）")
	}
	if _, ok, _ := scanJSONValue([]byte(`{"a":1,}`), 0, 0); !ok {
		t.Error("scanJSONValue(trailing object comma) = false，期望 true（严格性由 json.Valid 保证）")
	}
	if _, ok, _ := scanJSONValue([]byte(`{"a"}`), 0, 0); ok {
		t.Error("scanJSONValue(object without value) = true，期望 false")
	}
	if _, ok, _ := scanJSONValue([]byte(`{1:2}`), 0, 0); ok {
		t.Error("scanJSONValue(non-string key) = true，期望 false")
	}
	if _, ok, _ := scanJSONValue([]byte(`[1 2]`), 0, 0); ok {
		t.Error("scanJSONValue(array without comma) = true，期望 false")
	}
	if _, ok, _ := scanJSONValue([]byte(`[`), 0, 0); ok {
		t.Error("scanJSONValue(unterminated array) = true，期望 false")
	}
	if _, ok, _ := scanJSONValue([]byte(`{"a":`), 0, 0); ok {
		t.Error("scanJSONValue(unterminated object) = true，期望 false")
	}
	if _, ok, _ := scanJSONValue([]byte(`{"a":1`), 0, 0); ok {
		t.Error("scanJSONValue(object without brace) = true，期望 false")
	}
	if _, ok, _ := scanJSONValue([]byte("\"x\""), 0, 0); !ok {
		t.Error("scanJSONValue(string) = false，期望 true")
	}
	if _, ok, _ := scanJSONValue([]byte(`[true,false,null,[],{}]`), 0, 0); !ok {
		t.Error("scanJSONValue(literals) = false，期望 true")
	}

	if !hasDuplicateKeys([]byte(`{"a":1,"a":2}`)) {
		t.Error("hasDuplicateKeys top-level = false，期望 true")
	}
	if !hasDuplicateKeys([]byte(`{"a":[{"b":1,"b":2}]}`)) {
		t.Error("hasDuplicateKeys nested = false，期望 true")
	}
	if hasDuplicateKeys([]byte(`{"a":"a","b":"b"}`)) {
		t.Error("hasDuplicateKeys distinct = true，期望 false")
	}
	if hasDuplicateKeys([]byte(`{"a":`)) {
		t.Error("hasDuplicateKeys malformed = true，期望 false")
	}
	deep := strings.Repeat("[", 66) + strings.Repeat("]", 66)
	if hasDuplicateKeys([]byte(deep)) {
		t.Error("hasDuplicateKeys depth limit = true，期望 false")
	}
}

// TestParseJWSHeaderBranches covers header validation beyond the happy path. | TestParseJWSHeaderBranches
// 覆盖成功路径之外的头部校验。
func TestParseJWSHeaderBranches(t *testing.T) {
	h, raw, err := parseJWSHeader([]byte(`{"alg":"HS256","kid":"k","typ":"JWT","cty":"json","x-custom":"v","num":1}`))
	if err != nil {
		t.Fatalf("parseJWSHeader 失败: %v", err)
	}
	if h.Alg != "HS256" || h.Kid != "k" || h.Typ != "JWT" || h.Cty != "json" {
		t.Errorf("字段解析错误: %+v", h)
	}
	if h.Extra["x-custom"] != "v" || h.Extra["num"] != float64(1) {
		t.Errorf("Extra = %+v，期望包含 x-custom 与 num", h.Extra)
	}
	if raw.String("x-custom") != "v" {
		t.Errorf("RawHeader x-custom = %q，期望 v", raw.String("x-custom"))
	}

	if h, _, err := parseJWSHeader([]byte(`{"alg":"HS256","crit":[]}`)); err != nil || len(h.Crit) != 0 {
		t.Errorf("空 crit = (%+v, %v)，期望成功且为空", h, err)
	}

	cases := []struct {
		name string
		raw  string
		want error
	}{
		{"crit present", `{"alg":"HS256","crit":["exp"]}`, ErrUnsupportedCrit},
		{"crit not an array", `{"alg":"HS256","crit":"exp"}`, ErrInvalidHeader},
		{"crit array holds non-string", `{"alg":"HS256","crit":[1]}`, ErrInvalidHeader},
		{"b64 present", `{"alg":"HS256","b64":false}`, ErrInvalidHeader},
		{"kid not a string", `{"alg":"HS256","kid":1}`, ErrInvalidHeader},
		{"typ not a string", `{"alg":"HS256","typ":true}`, ErrInvalidHeader},
		{"cty not a string", `{"alg":"HS256","cty":[]}`, ErrInvalidHeader},
		{"missing alg", `{"kid":"k"}`, ErrAlgNotAllowed},
		{"empty alg", `{"alg":""}`, ErrAlgNotAllowed},
		{"alg not a string", `{"alg":1}`, ErrAlgNotAllowed},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if _, _, err := parseJWSHeader([]byte(tc.raw)); !errors.Is(err, tc.want) {
				t.Errorf("err = %v，期望 %v", err, tc.want)
			}
		})
	}
}

// TestStringSlice covers both accepted shapes and the rejection branch. | TestStringSlice 覆盖两种
// 接受形态与拒绝分支。
func TestStringSlice(t *testing.T) {
	if got, ok := stringSlice([]any{"a", "b"}); !ok || len(got) != 2 || got[1] != "b" {
		t.Errorf("stringSlice([]any) = (%v, %v)", got, ok)
	}
	if got, ok := stringSlice([]string{"a"}); !ok || len(got) != 1 || got[0] != "a" {
		t.Errorf("stringSlice([]string) = (%v, %v)", got, ok)
	}
	if _, ok := stringSlice([]any{"a", 1}); ok {
		t.Error("stringSlice([]any{string,int}) = true，期望 false")
	}
	if _, ok := stringSlice("a"); ok {
		t.Error("stringSlice(string) = true，期望 false")
	}
}

// TestEncodeJWSHeaderBranches covers deterministic encoding and its rejections. | TestEncodeJWSHeaderBranches
// 覆盖确定性编码及其拒绝分支。
func TestEncodeJWSHeaderBranches(t *testing.T) {
	out, err := encodeJWSHeader(JWSHeader{
		Alg:   "HS256",
		Kid:   "k",
		Typ:   "JWT",
		Cty:   "json",
		Extra: map[string]any{"z": "last", "a": float64(1)},
	})
	if err != nil {
		t.Fatalf("encodeJWSHeader 失败: %v", err)
	}
	want := `{"alg":"HS256","typ":"JWT","cty":"json","kid":"k","a":1,"z":"last"}`
	if string(out) != want {
		t.Errorf("encodeJWSHeader = %s，期望 %s", out, want)
	}

	if _, err := encodeJWSHeader(JWSHeader{Alg: "none"}); !errors.Is(err, ErrAlgNotAllowed) {
		t.Errorf("alg=none err = %v，期望 ErrAlgNotAllowed", err)
	}
	if _, err := encodeJWSHeader(JWSHeader{Alg: "NOPE"}); !errors.Is(err, ErrAlgNotAllowed) {
		t.Errorf("unknown alg err = %v，期望 ErrAlgNotAllowed", err)
	}
	if _, err := encodeJWSHeader(JWSHeader{Alg: "HS256", Crit: []string{"exp"}}); !errors.Is(err, ErrUnsupportedCrit) {
		t.Errorf("crit err = %v，期望 ErrUnsupportedCrit", err)
	}
	for _, reserved := range []string{"alg", "kid", "typ", "cty", "crit", "b64"} {
		if _, err := encodeJWSHeader(JWSHeader{Alg: "HS256", Extra: map[string]any{reserved: "x"}}); !errors.Is(err, ErrInvalidHeader) {
			t.Errorf("保留名 %q err = %v，期望 ErrInvalidHeader", reserved, err)
		}
	}
	if _, err := encodeJWSHeader(JWSHeader{Alg: "HS256", Extra: map[string]any{"bad": make(chan int)}}); !errors.Is(err, ErrInvalidHeader) {
		t.Errorf("不可编码取值 err = %v，期望 ErrInvalidHeader", err)
	}
	if _, err := jsonValue(make(chan int)); !errors.Is(err, ErrInvalidHeader) {
		t.Errorf("jsonValue(chan) err = %v，期望 ErrInvalidHeader", err)
	}
	if _, err := jsonValue("ok"); err != nil {
		t.Errorf("jsonValue(string) err = %v，期望成功", err)
	}
}

// TestSignRejectsBranches covers Sign validation paths. | TestSignRejectsBranches 覆盖 Sign 的校验路径。
func TestSignRejectsBranches(t *testing.T) {
	key := testOctSecretKey()
	if _, err := Sign([]byte(`{}`), nil, SignOptions{}); !errors.Is(err, ErrInvalidKey) {
		t.Errorf("nil key err = %v，期望 ErrInvalidKey", err)
	}
	if _, err := Sign([]byte(`{}`), key, SignOptions{}); !errors.Is(err, ErrAlgNotAllowed) {
		t.Errorf("missing alg err = %v，期望 ErrAlgNotAllowed", err)
	}
	if _, err := Sign([]byte(`{}`), key, SignOptions{Alg: "none"}); !errors.Is(err, ErrAlgNotAllowed) {
		t.Errorf("alg none err = %v，期望 ErrAlgNotAllowed", err)
	}
	bound := testOctSecretKey()
	bound.Alg = "RS256"
	if _, err := Sign([]byte(`{}`), bound, SignOptions{Alg: "HS256"}); !errors.Is(err, ErrAlgNotAllowed) {
		t.Errorf("key alg mismatch err = %v，期望 ErrAlgNotAllowed", err)
	}
	if _, err := Sign([]byte(`{}`), key, SignOptions{Alg: "HS256", Crit: []string{"exp"}}); !errors.Is(err, ErrUnsupportedCrit) {
		t.Errorf("crit err = %v，期望 ErrUnsupportedCrit", err)
	}
	if _, err := Sign([]byte(`{}`), key, SignOptions{Alg: "ES256"}); !errors.Is(err, ErrKeyTypeMismatch) {
		t.Errorf("key type mismatch err = %v，期望 ErrKeyTypeMismatch", err)
	}
}

// TestSignJWSRejects covers the key-type and strength checks of signJWS. | TestSignJWSRejects 覆盖
// signJWS 的密钥类型与强度检查。
func TestSignJWSRejects(t *testing.T) {
	input := []byte("header.payload")
	oct := testOctSecretKey()
	weak := &Key{Kty: KeyTypeOct, K: EncodeSegment([]byte("short"))}
	edPub := mustGenerate(t, "EdDSA").Public()
	rsaKey := testUnboundRSAKey(t)

	cases := []struct {
		name string
		alg  string
		key  *Key
		want error
	}{
		{"unknown alg", "NOPE", oct, ErrAlgNotAllowed},
		{"eddsa public only", "EdDSA", edPub, ErrNotPrivateKey},
		{"eddsa oct key", "EdDSA", oct, ErrKeyTypeMismatch},
		{"hmac octets of rsa", "HS256", rsaKey, ErrKeyTypeMismatch},
		{"hmac weak", "HS256", weak, ErrWeakKey},
		{"rsa with oct", "RS256", oct, ErrKeyTypeMismatch},
		{"pss with oct", "PS256", oct, ErrKeyTypeMismatch},
		{"ecdsa with oct", "ES256", oct, ErrKeyTypeMismatch},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if _, err := signJWS(tc.alg, tc.key, input); !errors.Is(err, tc.want) {
				t.Errorf("signJWS err = %v，期望 %v", err, tc.want)
			}
		})
	}

	// A public-only RSA key is still usable for verification but must not sign. | 仅含公钥的 RSA 密钥
	// 可用于验签，但绝不能签名。
	if _, err := signJWS("RS256", testUnboundRSAKey(t).Public(), input); !errors.Is(err, ErrNotPrivateKey) {
		t.Errorf("RSA public sign err = %v，期望 ErrNotPrivateKey", err)
	}
}

// TestVerifyJWSRejects covers the key-type and signature checks of verifyJWS. | TestVerifyJWSRejects
// 覆盖 verifyJWS 的密钥类型与签名检查。
func TestVerifyJWSRejects(t *testing.T) {
	input := []byte("header.payload")
	oct := testOctSecretKey()
	weak := &Key{Kty: KeyTypeOct, K: EncodeSegment([]byte("short"))}
	rsaPub := testUnboundRSAKey(t).Public()
	edPub := mustGenerate(t, "EdDSA").Public()
	ecKey := mustGenerate(t, "ES256")

	cases := []struct {
		name string
		alg  string
		key  *Key
		sig  []byte
		want error
	}{
		{"unknown alg", "NOPE", oct, []byte("sig"), ErrAlgNotAllowed},
		{"eddsa with rsa", "EdDSA", rsaPub, []byte("sig"), ErrKeyTypeMismatch},
		{"eddsa with oct", "EdDSA", oct, []byte("sig"), ErrKeyTypeMismatch},
		{"eddsa bad signature", "EdDSA", edPub, make([]byte, ed25519.SignatureSize), ErrSignatureInvalid},
		{"hmac weak", "HS256", weak, []byte("sig"), ErrWeakKey},
		{"rsa with oct", "RS256", oct, []byte("sig"), ErrKeyTypeMismatch},
		{"pss with oct", "PS256", oct, []byte("sig"), ErrKeyTypeMismatch},
		{"ecdsa with oct", "ES256", oct, []byte("sig"), ErrKeyTypeMismatch},
		{"ecdsa short signature", "ES256", ecKey.Public(), []byte("sig"), ErrSignatureInvalid},
		{"ecdsa zero signature", "ES256", ecKey.Public(), make([]byte, 64), ErrSignatureInvalid},
		{"rsa bad signature", "RS256", rsaPub, make([]byte, 32), ErrSignatureInvalid},
		{"pss bad signature", "PS256", rsaPub, make([]byte, 32), ErrSignatureInvalid},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if err := verifyJWS(tc.alg, tc.key, input, tc.sig); !errors.Is(err, tc.want) {
				t.Errorf("verifyJWS err = %v，期望 %v", err, tc.want)
			}
		})
	}

	if got := curveWidth("NOPE"); got != 0 {
		t.Errorf("curveWidth(NOPE) = %d，期望 0", got)
	}
	if got := appendDERInteger(nil, nil); len(got) != 3 || got[0] != 0x02 || got[1] != 0x01 || got[2] != 0x00 {
		t.Errorf("appendDERInteger(nil) = % x，期望 02 01 00", got)
	}
}

// TestResolverConstructors covers the resolver helpers and nil handling. | TestResolverConstructors
// 覆盖解析器辅助函数与 nil 处理。
func TestResolverConstructors(t *testing.T) {
	if _, err := (KeyResolverFunc(nil)).ResolveKey(context.Background(), Header{}); !errors.Is(err, ErrInvalidConfig) {
		t.Errorf("nil KeyResolverFunc err = %v，期望 ErrInvalidConfig", err)
	}
	key := testOctSecretKey()
	key.Kid = "k1"
	set := &KeySet{Keys: []*Key{key.Public()}}
	if got, err := set.Resolver().ResolveKey(context.Background(), Header{"kid": "k1"}); err != nil || got == nil {
		t.Errorf("KeySet.Resolver 命中失败: %v", err)
	}
	if _, err := set.Resolver().ResolveKey(context.Background(), Header{"kid": "nope"}); !errors.Is(err, ErrKeyNotFound) {
		t.Errorf("KeySet.Resolver 未命中 err = %v，期望 ErrKeyNotFound", err)
	}

	if _, err := CacheResolver(nil).ResolveKey(context.Background(), Header{}); !errors.Is(err, ErrKeyNotFound) {
		t.Errorf("nil CacheResolver err = %v，期望 ErrKeyNotFound", err)
	}
	cache := NewCache(set)
	if got, err := cache.Resolver().ResolveKey(context.Background(), Header{"kid": "k1"}); err != nil || got == nil {
		t.Errorf("Cache.Resolver 命中失败: %v", err)
	}
	if _, err := cache.Resolver().ResolveKey(context.Background(), Header{"kid": "nope"}); !errors.Is(err, ErrKeyNotFound) {
		t.Errorf("Cache.Resolver 未命中 err = %v，期望 ErrKeyNotFound", err)
	}
}

// TestVerifyContextErrorBranches covers structural rejections and resolver failures. | TestVerifyContextErrorBranches
// 覆盖结构拒绝与解析器失败。
func TestVerifyContextErrorBranches(t *testing.T) {
	key := testOctSecretKey()
	resolver := KeyResolverFunc(func(context.Context, Header) (*Key, error) { return key, nil })

	if _, err := VerifyContext(context.Background(), "a.b.c", nil, VerifyOptions{}); !errors.Is(err, ErrInvalidConfig) {
		t.Errorf("nil resolver err = %v，期望 ErrInvalidConfig", err)
	}
	for _, token := range []string{"", "nodots", "one.dot", "a.b.c.d"} {
		if _, err := VerifyContext(context.Background(), token, resolver, VerifyOptions{}); !errors.Is(err, ErrMalformed) {
			t.Errorf("VerifyContext(%q) err = %v，期望 ErrMalformed", token, err)
		}
	}
	emptySig := EncodeSegment([]byte(`{"alg":"HS256"}`)) + "." + EncodeSegment([]byte(`{}`)) + "."
	if _, err := VerifyContext(context.Background(), emptySig, resolver, VerifyOptions{}); !errors.Is(err, ErrMalformed) {
		t.Errorf("empty signature err = %v，期望 ErrMalformed", err)
	}
	badHeader := "!!!" + "." + EncodeSegment([]byte(`{}`)) + "." + EncodeSegment([]byte("sig"))
	if _, err := VerifyContext(context.Background(), badHeader, resolver, VerifyOptions{}); !errors.Is(err, ErrMalformed) {
		t.Errorf("bad header err = %v，期望 ErrMalformed", err)
	}

	goodHeader := EncodeSegment([]byte(`{"alg":"HS256"}`))
	token := manualHS256(`{"alg":"HS256"}`, `{}`, testSecretBytes())

	badPayload := goodHeader + "." + "!!!" + "." + strings.Split(token, ".")[2]
	if _, err := VerifyContext(context.Background(), badPayload, resolver, VerifyOptions{}); !errors.Is(err, ErrMalformed) {
		t.Errorf("bad payload err = %v，期望 ErrMalformed", err)
	}
	badSig := goodHeader + "." + EncodeSegment([]byte(`{}`)) + "." + "!!!"
	if _, err := VerifyContext(context.Background(), badSig, resolver, VerifyOptions{}); !errors.Is(err, ErrMalformed) {
		t.Errorf("bad signature segment err = %v，期望 ErrMalformed", err)
	}

	if _, err := VerifyContext(context.Background(), token, KeyResolverFunc(func(context.Context, Header) (*Key, error) {
		return nil, nil
	}), VerifyOptions{}); !errors.Is(err, ErrKeyNotFound) {
		t.Errorf("nil resolved key err = %v，期望 ErrKeyNotFound", err)
	}
	sentinel := errors.New("resolver failed")
	if _, err := VerifyContext(context.Background(), token, KeyResolverFunc(func(context.Context, Header) (*Key, error) {
		return nil, sentinel
	}), VerifyOptions{}); !errors.Is(err, sentinel) {
		t.Errorf("resolver error err = %v，期望原样透出", err)
	}
	if _, err := VerifyContext(context.Background(), token, resolver, VerifyOptions{ValidAlgs: []string{"RS256"}}); !errors.Is(err, ErrAlgNotAllowed) {
		t.Errorf("allow list err = %v，期望 ErrAlgNotAllowed", err)
	}
	if _, err := VerifyContext(context.Background(), token, resolver, VerifyOptions{Typ: "at+jwt"}); !errors.Is(err, ErrInvalidHeader) {
		t.Errorf("typ mismatch err = %v，期望 ErrInvalidHeader", err)
	}
	bound := testOctSecretKey()
	bound.Alg = "RS256"
	if _, err := VerifyContext(context.Background(), token, KeyResolverFunc(func(context.Context, Header) (*Key, error) {
		return bound, nil
	}), VerifyOptions{}); !errors.Is(err, ErrAlgNotAllowed) {
		t.Errorf("key alg mismatch err = %v，期望 ErrAlgNotAllowed", err)
	}
	if _, err := VerifyContext(context.Background(), token, KeyResolverFunc(func(context.Context, Header) (*Key, error) {
		return &Key{Kty: KeyTypeRSA}, nil
	}), VerifyOptions{}); !errors.Is(err, ErrKeyTypeMismatch) {
		t.Errorf("key family mismatch err = %v，期望 ErrKeyTypeMismatch", err)
	}
	tampered := strings.Split(token, ".")
	tampered[2] = tamperSegment(t, tampered[2])
	if _, err := VerifyContext(context.Background(), strings.Join(tampered, "."), resolver, VerifyOptions{}); !errors.Is(err, ErrSignatureInvalid) {
		t.Errorf("tampered err = %v，期望 ErrSignatureInvalid", err)
	}

	noneToken := manualHS256(`{"alg":"none"}`, `{}`, testSecretBytes())
	if _, err := VerifyContext(context.Background(), noneToken, resolver, VerifyOptions{}); !errors.Is(err, ErrAlgNotAllowed) {
		t.Errorf("alg none err = %v，期望 ErrAlgNotAllowed", err)
	}

	// ValidateClaims on a payload that is not a JSON object. | 对非 JSON 对象载荷启用 ValidateClaims。
	nonJSON := mustSign(t, []byte("plain"), key, SignOptions{Alg: "HS256"})
	if _, err := Verify(nonJSON, KeySetResolver(&KeySet{Keys: []*Key{key.Public()}}), VerifyOptions{ValidateClaims: true}); !errors.Is(err, ErrClaimsInvalid) {
		t.Errorf("non-JSON claims err = %v，期望 ErrClaimsInvalid", err)
	}
}

// TestVerifyClaimsValidationErrors covers the claim sentinels surfaced through Verify. |
// TestVerifyClaimsValidationErrors 覆盖通过 Verify 暴露的声明哨兵。
func TestVerifyClaimsValidationErrors(t *testing.T) {
	key := testOctSecretKey()
	pub := &KeySet{Keys: []*Key{key.Public()}}
	past := time.Now().Add(-2 * time.Hour)
	payload := []byte(`{"sub":"u","exp":` + itoa(past.Unix()) + `}`)
	token := mustSign(t, payload, key, SignOptions{Alg: "HS256"})
	if _, err := Verify(token, KeySetResolver(pub), VerifyOptions{ValidateClaims: true}); !errors.Is(err, ErrClaimsInvalid) {
		t.Errorf("expired err = %v，期望 ErrClaimsInvalid", err)
	}
}

// itoa formats an int64 without importing strconv in the test body. | itoa 在不引入 strconv 的情况下
// 格式化 int64。
func itoa(v int64) string {
	if v == 0 {
		return "0"
	}
	var buf [20]byte
	i := len(buf)
	for v > 0 {
		i--
		buf[i] = byte('0' + v%10)
		v /= 10
	}
	return string(buf[i:])
}
