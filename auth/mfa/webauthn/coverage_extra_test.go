package webauthn

import (
	"context"
	"crypto"
	"errors"
	"math"
	"testing"
	"time"

	"github.com/shibingli/ydx/base64"
)

// TestCBORAccessorBranches covers nil, wrong-kind and missing-key accessors. |
// TestCBORAccessorBranches 覆盖空值、类型错误与缺失键的访问器。
func TestCBORAccessorBranches(t *testing.T) {
	var nilValue *Value
	if nilValue.IsNull() || NewNull().IsNull() != true || NewBool(false).IsNull() {
		t.Fatal("IsNull mismatch")
	}
	if NewBool(false).Simple != 20 || NewBool(true).Simple != 21 {
		t.Fatal("NewBool values mismatch")
	}
	if v, ok := nilValue.AsInt64(); ok || v != 0 {
		t.Fatal("nil AsInt64 succeeded")
	}
	if v, ok := NewInt(-3).AsInt64(); !ok || v != -3 {
		t.Fatalf("negative AsInt64 = %d, %v", v, ok)
	}
	if v, ok := NewInt(math.MinInt64).AsInt64(); !ok || v != math.MinInt64 {
		t.Fatalf("MinInt64 AsInt64 = %d, %v", v, ok)
	}
	if _, ok := NewUint(math.MaxUint64).AsInt64(); ok {
		t.Fatal("MaxUint64 AsInt64 succeeded")
	}
	if _, ok := (&Value{Kind: KindNegInt, Neg: math.MaxUint64}).AsInt64(); ok {
		t.Fatal("oversized negative AsInt64 succeeded")
	}
	if _, ok := NewText("x").AsInt64(); ok {
		t.Fatal("text AsInt64 succeeded")
	}
	if v, ok := NewUint(7).AsUint64(); !ok || v != 7 {
		t.Fatalf("AsUint64 = %d, %v", v, ok)
	}
	if _, ok := NewInt(-1).AsUint64(); ok {
		t.Fatal("signed AsUint64 succeeded")
	}
	if b, ok := NewBytes([]byte{1}).AsBytes(); !ok || len(b) != 1 {
		t.Fatalf("AsBytes = %v, %v", b, ok)
	}
	if _, ok := NewText("x").AsBytes(); ok {
		t.Fatal("text AsBytes succeeded")
	}
	if s, ok := NewText("hello").AsText(); !ok || s != "hello" {
		t.Fatalf("AsText = %q, %v", s, ok)
	}
	if _, ok := NewBytes(nil).AsText(); ok {
		t.Fatal("bytes AsText succeeded")
	}
	m := NewMap(
		Pair{Key: NewInt(1), Value: NewText("one")},
		Pair{Key: NewInt(-2), Value: NewText("minus")},
		Pair{Key: nil, Value: NewText("nil")},
	)
	if v, ok := m.MapGetInt(1); !ok || v.Text != "one" {
		t.Fatalf("positive MapGetInt = %+v, %v", v, ok)
	}
	if v, ok := m.MapGetInt(-2); !ok || v.Text != "minus" {
		t.Fatalf("negative MapGetInt = %+v, %v", v, ok)
	}
	if _, ok := m.MapGetInt(2); ok {
		t.Fatal("missing positive MapGetInt succeeded")
	}
	if _, ok := m.MapGetInt(-1); ok {
		t.Fatal("missing negative MapGetInt succeeded")
	}
	if _, ok := NewText("x").MapGetInt(1); ok {
		t.Fatal("non-map MapGetInt succeeded")
	}
	if _, ok := nilValue.MapGetInt(1); ok {
		t.Fatal("nil MapGetInt succeeded")
	}
}

// TestCBORHeadEncoding exercises every additional-information width. | TestCBORHeadEncoding 覆盖所有附加
// 信息宽度。
func TestCBORHeadEncoding(t *testing.T) {
	cases := []struct {
		value uint64
		head  []byte
	}{
		{23, []byte{0x17}},
		{24, []byte{0x18, 0x18}},
		{255, []byte{0x18, 0xff}},
		{256, []byte{0x19, 0x01, 0x00}},
		{65535, []byte{0x19, 0xff, 0xff}},
		{65536, []byte{0x1a, 0x00, 0x01, 0x00, 0x00}},
		{1 << 32, []byte{0x1b, 0, 0, 0, 1, 0, 0, 0, 0}},
		{math.MaxUint64, []byte{0x1b, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff}},
	}
	for _, c := range cases {
		data, err := Encode(NewUint(c.value))
		if err != nil {
			t.Fatalf("Encode(%d): %v", c.value, err)
		}
		if string(data) != string(c.head) {
			t.Fatalf("Encode(%d) = %x, want %x", c.value, data, c.head)
		}
	}
	bytes24 := make([]byte, 24)
	if data, err := Encode(NewBytes(bytes24)); err != nil || len(data) != 26 || data[0] != 0x58 || data[1] != 24 {
		t.Fatalf("24-byte header = %x, %v", data, err)
	}
	text256 := make([]byte, 256)
	for i := range text256 {
		text256[i] = 'a'
	}
	if data, err := Encode(NewText(string(text256))); err != nil || len(data) != 259 || data[0] != 0x79 || data[1] != 0x01 || data[2] != 0x00 {
		t.Fatalf("256-byte text header = %x, %v", data[:3], err)
	}
}

// TestFloatHalfEdgeCases covers half conversion boundaries and fallbacks. |
// TestFloatHalfEdgeCases 覆盖半精度转换边界与回退。
func TestFloatHalfEdgeCases(t *testing.T) {
	cases := []struct {
		value float64
		half  uint16
		ok    bool
	}{
		{math.NaN(), 0x7e00, true},
		{math.Inf(1), 0x7c00, true},
		{math.Inf(-1), 0xfc00, true},
		{65504, 0x7bff, true},
		{math.Copysign(0, -1), 0x8000, true},
		{math.Ldexp(1, -20), 0x0010, true},
		{math.Ldexp(1, -40), 0x0000, true},
		{-math.Ldexp(1, -40), 0x8000, true},
		{float64(math.SmallestNonzeroFloat32), 0x0000, true},
		{math.Ldexp(1, 16), 0, false},
		{0.1, 0, false},
	}
	for _, c := range cases {
		half, ok := float64ToHalf(c.value)
		if ok != c.ok || (ok && half != c.half) {
			t.Fatalf("float64ToHalf(%v) = %#x, %v; want %#x, %v", c.value, half, ok, c.half, c.ok)
		}
	}
	halves := []struct {
		half  uint16
		check func(float64) bool
	}{
		{0x0000, func(v float64) bool { return v == 0 && !math.Signbit(v) }},
		{0x8000, func(v float64) bool { return v == 0 && math.Signbit(v) }},
		{0x0001, func(v float64) bool { return v == math.Ldexp(1, -24) }},
		{0x8001, func(v float64) bool { return v == -math.Ldexp(1, -24) }},
		{0x7c00, func(v float64) bool { return math.IsInf(v, 1) }},
		{0xfc00, func(v float64) bool { return math.IsInf(v, -1) }},
		{0x7e01, func(v float64) bool { return math.IsNaN(v) }},
		{0x3c00, func(v float64) bool { return v == 1 }},
	}
	for _, c := range halves {
		if v := halfToFloat64(c.half); !c.check(v) {
			t.Fatalf("halfToFloat64(%#x) = %v", c.half, v)
		}
	}
	encoded := func(v float64) []byte {
		data, err := Encode(NewFloat(v))
		if err != nil {
			t.Fatalf("Encode(%v): %v", v, err)
		}
		return data
	}
	if got := encoded(math.Inf(1)); string(got) != string([]byte{0xf9, 0x7c, 0x00}) {
		t.Fatalf("+Inf encoding = %x", got)
	}
	if got := encoded(math.NaN()); string(got) != string([]byte{0xf9, 0x7e, 0x00}) {
		t.Fatalf("NaN encoding = %x", got)
	}
	if got := encoded(math.Ldexp(1, 17)); len(got) != 5 || got[0] != 0xfa {
		t.Fatalf("float32 encoding = %x", got)
	}
	if got := encoded(1e300); len(got) != 9 || got[0] != 0xfb {
		t.Fatalf("float64 encoding = %x", got)
	}
	if got := encoded(65520); len(got) == 0 {
		t.Fatal("65520 encoding empty")
	}
}

// TestAuthDataExtensionBranches covers boolean, string, name and credProtect helpers. |
// TestAuthDataExtensionBranches 覆盖布尔、字符串、名称与 credProtect 辅助函数。
func TestAuthDataExtensionBranches(t *testing.T) {
	var nilData *AuthenticatorData
	if _, ok := nilData.ExtensionBool("x"); ok {
		t.Fatal("nil data extension")
	}
	if names := nilData.ExtensionNames(); names != nil {
		t.Fatalf("nil names = %v", names)
	}
	if _, ok := nilData.CredentialProtection(); ok {
		t.Fatal("nil credProtect")
	}
	data := &AuthenticatorData{Extensions: NewMap(
		Pair{Key: NewText("credProtect"), Value: NewText("userVerificationRequired")},
		Pair{Key: NewText("uvm"), Value: NewBool(true)},
		Pair{Key: NewText("hmac-secret"), Value: NewBool(false)},
		Pair{Key: NewText("bad"), Value: NewSimpleForTest(22)},
		Pair{Key: NewText("text"), Value: NewInt(5)},
		Pair{Key: NewInt(1), Value: NewText("ignored")},
	)}
	if v, ok := data.ExtensionBool("uvm"); !ok || !v {
		t.Fatalf("uvm = %v, %v", v, ok)
	}
	if v, ok := data.ExtensionBool("hmac-secret"); !ok || v {
		t.Fatalf("hmac-secret = %v, %v", v, ok)
	}
	if _, ok := data.ExtensionBool("bad"); ok {
		t.Fatal("null bool accepted")
	}
	if _, ok := data.ExtensionBool("text"); ok {
		t.Fatal("int bool accepted")
	}
	if _, ok := data.ExtensionBool("missing"); ok {
		t.Fatal("missing bool accepted")
	}
	if v, ok := data.ExtensionString("credProtect"); !ok || v != "userVerificationRequired" {
		t.Fatalf("credProtect string = %q, %v", v, ok)
	}
	if _, ok := data.ExtensionString("text"); ok {
		t.Fatal("int string accepted")
	}
	if names := data.ExtensionNames(); len(names) != 5 || names[0] != "bad" || names[4] != "uvm" {
		t.Fatalf("names = %v", names)
	}
	if v, ok := data.CredentialProtection(); !ok || v != "userVerificationRequired" {
		t.Fatalf("credProtect = %q, %v", v, ok)
	}
	invalid := &AuthenticatorData{Extensions: NewMap(Pair{Key: NewText("credProtect"), Value: NewText("weak")})}
	if _, ok := invalid.CredentialProtection(); ok {
		t.Fatal("invalid credProtect accepted")
	}
	if data.AAGUIDIsZero() != true {
		t.Fatal("zero AAGUID")
	}
}

// NewSimpleForTest builds a simple CBOR value for helper tests. | NewSimpleForTest 为辅助测试构建
// 简单 CBOR 值。
func NewSimpleForTest(simple uint8) *Value { return &Value{Kind: KindSimple, Simple: simple} }

// TestCredentialProtectionPolicy covers policy ranking and enforcement. |
// TestCredentialProtectionPolicy 覆盖策略排序与强制。
func TestCredentialProtectionPolicy(t *testing.T) {
	for policy, want := range map[string]int{
		"userVerificationOptional":                     0,
		"userVerificationOptionalWithCredentialIDList": 1,
		"userVerificationRequired":                     2,
		"other":                                        -1,
	} {
		if got := credentialProtectionRank(policy); got != want {
			t.Fatalf("rank(%q) = %d, want %d", policy, got, want)
		}
	}
	if err := verifyCredentialProtection(&AuthenticatorData{}, nil); err != nil {
		t.Fatalf("nil extensions: %v", err)
	}
	if err := verifyCredentialProtection(&AuthenticatorData{}, &RegistrationExtensions{}); err != nil {
		t.Fatalf("empty policy: %v", err)
	}
	if err := verifyCredentialProtection(&AuthenticatorData{}, &RegistrationExtensions{CredentialProtectionPolicy: "userVerificationRequired"}); err != nil {
		t.Fatalf("unenforced missing extension: %v", err)
	}
	if err := verifyCredentialProtection(&AuthenticatorData{}, &RegistrationExtensions{
		CredentialProtectionPolicy:        "userVerificationRequired",
		EnforceCredentialProtectionPolicy: true,
	}); !errors.Is(err, ErrInvalidCredential) {
		t.Fatalf("enforced missing extension err = %v", err)
	}
	weak := &AuthenticatorData{Extensions: NewMap(Pair{Key: NewText("credProtect"), Value: NewText("userVerificationOptional")})}
	if err := verifyCredentialProtection(weak, &RegistrationExtensions{
		CredentialProtectionPolicy:        "userVerificationRequired",
		EnforceCredentialProtectionPolicy: true,
	}); !errors.Is(err, ErrInvalidCredential) {
		t.Fatalf("weak policy err = %v", err)
	}
	strong := &AuthenticatorData{Extensions: NewMap(Pair{Key: NewText("credProtect"), Value: NewText("userVerificationOptionalWithCredentialIDList")})}
	if err := verifyCredentialProtection(strong, &RegistrationExtensions{
		CredentialProtectionPolicy:        "userVerificationOptionalWithCredentialIDList",
		EnforceCredentialProtectionPolicy: true,
	}); err != nil {
		t.Fatalf("matching policy: %v", err)
	}
	if _, err := registrationExtensions(&RegistrationExtensions{CredentialProtectionPolicy: "invalid"}, false); !errors.Is(err, ErrInvalidRequest) {
		t.Fatalf("unknown policy err = %v", err)
	}
	if _, err := registrationExtensions(&RegistrationExtensions{EnforceCredentialProtectionPolicy: true}, false); !errors.Is(err, ErrInvalidRequest) {
		t.Fatalf("enforcement without policy err = %v", err)
	}
	original := &RegistrationExtensions{HMACCreateSecret: true}
	copied, err := registrationExtensions(original, true)
	if err != nil || copied == original || !copied.HMACCreateSecret || !copied.CredProps {
		t.Fatalf("copied extensions = %+v, %v", copied, err)
	}
	if original.CredProps {
		t.Fatal("original extensions mutated")
	}
	resident, err := registrationExtensions(nil, true)
	if err != nil || resident == nil || !resident.CredProps {
		t.Fatalf("resident extensions = %+v, %v", resident, err)
	}
}

// TestMergeExcludeCredentials covers deduplication and validation. |
// TestMergeExcludeCredentials 覆盖去重与校验。
func TestMergeExcludeCredentials(t *testing.T) {
	stored := []*Credential{
		nil,
		{ID: nil},
		{ID: []byte{1, 2}, Transports: []string{"usb", "USB"}},
		{ID: []byte{1, 2}, Transports: []string{"nfc"}},
	}
	extra := []CredentialDescriptor{
		{Type: "public-key", ID: base64.RawURLEncoding.EncodeToString([]byte{1, 2})},
		{Type: "", ID: base64.RawURLEncoding.EncodeToString([]byte{3}), Transports: []string{"hybrid"}},
	}
	out, ids, err := mergeExcludeCredentials(stored, extra)
	if err != nil {
		t.Fatalf("merge: %v", err)
	}
	if len(out) != 2 || len(ids) != 2 || len(out[0].Transports) != 1 || out[0].Transports[0] != "usb" {
		t.Fatalf("merged = %+v, %v", out, ids)
	}
	if out[1].Type != "public-key" || out[1].ID != base64.RawURLEncoding.EncodeToString([]byte{3}) {
		t.Fatalf("extra descriptor = %+v", out[1])
	}
	if _, _, err := mergeExcludeCredentials(nil, []CredentialDescriptor{{Type: "other", ID: "AQ"}}); !errors.Is(err, ErrInvalidRequest) {
		t.Fatalf("unsupported descriptor type err = %v", err)
	}
}

// TestCredentialHelperBranches covers ID, descriptor and decoding helpers. |
// TestCredentialHelperBranches 覆盖 ID、描述符与解码辅助函数。
func TestCredentialHelperBranches(t *testing.T) {
	var nilCredential *Credential
	if nilCredential.CredentialIDBase64() != "" {
		t.Fatal("nil credential ID")
	}
	if descriptor := nilCredential.Descriptor(); descriptor.Type != "" || descriptor.ID != "" || descriptor.Transports != nil {
		t.Fatalf("nil descriptor = %+v", descriptor)
	}
	credential := &Credential{ID: []byte{1, 2, 3}, Transports: []string{"usb"}}
	if credential.CredentialIDBase64() != "AQID" {
		t.Fatalf("credential ID = %q", credential.CredentialIDBase64())
	}
	descriptor := credential.Descriptor()
	if descriptor.Type != "public-key" || descriptor.ID != "AQID" || len(descriptor.Transports) != 1 {
		t.Fatalf("descriptor = %+v", descriptor)
	}
	credential.Transports[0] = "nfc"
	if descriptor.Transports[0] != "usb" {
		t.Fatal("descriptor aliases transports")
	}
	if _, err := decodeCredentialResponseID("", ""); !errors.Is(err, ErrInvalidRequest) {
		t.Fatalf("empty IDs err = %v", err)
	}
	if _, err := decodeCredentialResponseID("!!!", "AQID"); !errors.Is(err, ErrInvalidRequest) {
		t.Fatalf("bad id err = %v", err)
	}
	if _, err := decodeCredentialResponseID("AQID", "!!!"); !errors.Is(err, ErrInvalidRequest) {
		t.Fatalf("bad rawId err = %v", err)
	}
	if _, err := decodeCredentialResponseID("AQID", "AQIE"); !errors.Is(err, ErrCredentialIDMismatch) {
		t.Fatalf("mismatch err = %v", err)
	}
	if id, err := decodeCredentialResponseID("AQID", "AQID"); err != nil || len(id) != 3 {
		t.Fatalf("decoded ID = %v, %v", id, err)
	}
	longID := base64.RawURLEncoding.EncodeToString(make([]byte, maxCredentialIDLength+1))
	if _, err := decodeCredentialResponseID(longID, longID); !errors.Is(err, ErrInvalidRequest) {
		t.Fatalf("oversized ID err = %v", err)
	}
	if b, err := decodeBase64URLField("field", "", false); err != nil || b != nil {
		t.Fatalf("optional field = %v, %v", b, err)
	}
	if _, err := decodeBase64URLField("field", "", true); !errors.Is(err, ErrInvalidRequest) {
		t.Fatalf("required field err = %v", err)
	}
	if _, err := decodeBase64URLField("field", "***", false); !errors.Is(err, ErrInvalidRequest) {
		t.Fatalf("invalid field err = %v", err)
	}
	longToken := make([]byte, 33)
	for i := range longToken {
		longToken[i] = 'a'
	}
	transports := normalizeTransports([]string{" USB ", "usb", "", string(longToken), "bad token", "nfc"})
	if len(transports) != 2 || transports[0] != "usb" || transports[1] != "nfc" {
		t.Fatalf("transports = %v", transports)
	}
	many := append(make([]string, 0, 10), "a", "b", "c", "d", "e", "f", "g", "h", "i", "j")
	if got := normalizeTransports(many); len(got) != 8 {
		t.Fatalf("transport cap = %v", got)
	}
	descriptors, ids, err := normalizeDescriptors([]CredentialDescriptor{
		{ID: "AQID", Transports: []string{"usb"}},
		{Type: "public-key", ID: "AQID"},
	})
	if err != nil || len(descriptors) != 1 || len(ids) != 1 || descriptors[0].Type != "public-key" {
		t.Fatalf("normalized = %+v, %v, %v", descriptors, ids, err)
	}
	if _, _, err := normalizeDescriptors([]CredentialDescriptor{{ID: ""}}); !errors.Is(err, ErrInvalidRequest) {
		t.Fatalf("empty descriptor ID err = %v", err)
	}
	if !descriptorIDsEqual(ids, []byte{1, 2, 3}) || descriptorIDsEqual(ids, []byte{9}) {
		t.Fatal("descriptorIDsEqual mismatch")
	}
}

// TestVerifyHelperBranches covers flag policy and offered algorithm checks. |
// TestVerifyHelperBranches 覆盖标志策略与算法提供检查。
func TestVerifyHelperBranches(t *testing.T) {
	if !bytesEqual(nil, []byte{}) || bytesEqual([]byte{1}, []byte{2}) || !bytesEqual([]byte{1}, []byte{1}) {
		t.Fatal("bytesEqual mismatch")
	}
	if err := verifyFlagPolicy(nil, UserVerificationRequired); !errors.Is(err, ErrInvalidAuthenticatorData) {
		t.Fatalf("nil authData err = %v", err)
	}
	if err := verifyFlagPolicy(&AuthenticatorData{}, UserVerificationPreferred); !errors.Is(err, ErrUserPresenceRequired) {
		t.Fatalf("missing UP err = %v", err)
	}
	if err := verifyFlagPolicy(&AuthenticatorData{Flags: FlagUserPresent}, UserVerificationRequired); !errors.Is(err, ErrUserVerificationRequired) {
		t.Fatalf("missing UV err = %v", err)
	}
	if err := verifyFlagPolicy(&AuthenticatorData{Flags: FlagUserPresent | FlagUserVerified}, UserVerificationRequired); err != nil {
		t.Fatalf("UV present: %v", err)
	}
	if err := verifyFlagPolicy(&AuthenticatorData{Flags: FlagUserPresent}, UserVerificationPreferred); err != nil {
		t.Fatalf("preferred without UV: %v", err)
	}
	if err := verifyOfferedAlgorithm(nil, nil); !errors.Is(err, ErrInvalidCOSEKey) {
		t.Fatalf("nil key err = %v", err)
	}
	if err := verifyOfferedAlgorithm(&COSEKey{Alg: 0}, nil); !errors.Is(err, ErrUnsupportedAlgorithm) {
		t.Fatalf("unsupported algorithm err = %v", err)
	}
	if err := verifyOfferedAlgorithm(&COSEKey{Alg: AlgES256}, []int{AlgES384}); !errors.Is(err, ErrUnsupportedAlgorithm) {
		t.Fatalf("unoffered algorithm err = %v", err)
	}
	if err := verifyOfferedAlgorithm(&COSEKey{Alg: AlgES256}, []int{AlgES256}); err != nil {
		t.Fatalf("offered algorithm: %v", err)
	}
	names := map[int]string{
		AlgES256: "ES256", AlgES384: "ES384", AlgES512: "ES512",
		AlgRS256: "RS256", AlgRS384: "RS384", AlgRS512: "RS512",
		AlgPS256: "PS256", AlgPS384: "PS384", AlgPS512: "PS512",
		AlgEdDSA: "EdDSA",
	}
	for alg, want := range names {
		if got := AlgorithmName(alg); got != want {
			t.Fatalf("AlgorithmName(%d) = %q, want %q", alg, got, want)
		}
	}
	_ = AlgorithmName(12345)
}

// TestJWSAlgorithmMapping covers every SafetyNet JWS algorithm and the fallback. |
// TestJWSAlgorithmMapping 覆盖所有 SafetyNet JWS 算法与回退。
func TestJWSAlgorithmMapping(t *testing.T) {
	cases := map[string]int{
		"RS256": AlgRS256, "RS384": AlgRS384, "RS512": AlgRS512,
		"PS256": AlgPS256, "PS384": AlgPS384, "PS512": AlgPS512,
		"ES256": AlgES256, "ES384": AlgES384, "ES512": AlgES512,
	}
	for name, want := range cases {
		if got, ok := jwsAlgorithm(name); !ok || got != want {
			t.Fatalf("jwsAlgorithm(%q) = %d, %v", name, got, ok)
		}
	}
	if _, ok := jwsAlgorithm("HS256"); ok {
		t.Fatal("HMAC JWS algorithm accepted")
	}
}

// TestTPMReaderAndHashHelpers covers truncated reads and hash mapping. |
// TestTPMReaderAndHashHelpers 覆盖截断读取与哈希映射。
func TestTPMReaderAndHashHelpers(t *testing.T) {
	empty := &tpmReader{}
	if _, err := empty.u8(); err == nil {
		t.Fatal("empty u8 succeeded")
	}
	if _, err := empty.u16(); err == nil {
		t.Fatal("empty u16 succeeded")
	}
	if _, err := empty.u32(); err == nil {
		t.Fatal("empty u32 succeeded")
	}
	if _, err := empty.u64(); err == nil {
		t.Fatal("empty u64 succeeded")
	}
	if _, err := empty.sized(); err == nil {
		t.Fatal("empty sized succeeded")
	}
	if err := empty.skip(1); err == nil {
		t.Fatal("empty skip succeeded")
	}
	if _, err := empty.readN(-1); err == nil {
		t.Fatal("negative read succeeded")
	}
	reader := &tpmReader{data: []byte{0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f}}
	if v, err := reader.u8(); err != nil || v != 0x01 {
		t.Fatalf("u8 = %#x, %v", v, err)
	}
	if v, err := reader.u16(); err != nil || v != 0x0203 {
		t.Fatalf("u16 = %#x, %v", v, err)
	}
	if v, err := reader.u32(); err != nil || v != 0x04050607 {
		t.Fatalf("u32 = %#x, %v", v, err)
	}
	if v, err := reader.u64(); err != nil || v != 0x08090a0b0c0d0e0f {
		t.Fatalf("u64 = %#x, %v", v, err)
	}
	if !reader.done() {
		t.Fatal("reader not done")
	}
	if v, err := (&tpmReader{data: []byte{0x00, 0x02, 'a', 'b'}}).sized(); err != nil || string(v) != "ab" {
		t.Fatalf("sized = %q, %v", v, err)
	}
	if _, err := (&tpmReader{data: []byte{0x00, 0x05, 'a'}}).sized(); err == nil {
		t.Fatal("truncated sized succeeded")
	}
	if hash, ok := tpmHash(tpmAlgSHA384); !ok || hash != crypto.SHA384 {
		t.Fatalf("tpmHash SHA384 = %v, %v", hash, ok)
	}
	if hash, ok := tpmHash(tpmAlgSHA512); !ok || hash != crypto.SHA512 {
		t.Fatalf("tpmHash SHA512 = %v, %v", hash, ok)
	}
	if _, ok := tpmHash(0xffff); ok {
		t.Fatal("unknown tpmHash succeeded")
	}
	if alg, ok := tpmHashAlgorithm(crypto.SHA256); !ok || alg != tpmAlgSHA256 {
		t.Fatalf("tpmHashAlgorithm SHA256 = %#x, %v", alg, ok)
	}
	if alg, ok := tpmHashAlgorithm(crypto.SHA384); !ok || alg != tpmAlgSHA384 {
		t.Fatalf("tpmHashAlgorithm SHA384 = %#x, %v", alg, ok)
	}
	if alg, ok := tpmHashAlgorithm(crypto.SHA512); !ok || alg != tpmAlgSHA512 {
		t.Fatalf("tpmHashAlgorithm SHA512 = %#x, %v", alg, ok)
	}
	if _, ok := tpmHashAlgorithm(crypto.SHA1); ok {
		t.Fatal("SHA1 tpmHashAlgorithm succeeded")
	}
}

// TestChallengeStoreCancellationAndClock covers canceled stores and nil clocks. |
// TestChallengeStoreCancellationAndClock 覆盖取消上下文与空时钟。
func TestChallengeStoreCancellationAndClock(t *testing.T) {
	store := NewMemoryChallengeStoreWithClock(nil)
	canceled, cancel := context.WithCancel(context.Background())
	cancel()
	if err := store.Put(canceled, &Ceremony{Challenge: []byte{1}}); !errors.Is(err, context.Canceled) {
		t.Fatalf("canceled put err = %v", err)
	}
	if _, err := store.Consume(canceled, "AQ"); !errors.Is(err, context.Canceled) {
		t.Fatalf("canceled consume err = %v", err)
	}
	if err := store.Put(context.Background(), nil); !errors.Is(err, ErrInvalidRequest) {
		t.Fatalf("nil ceremony err = %v", err)
	}
	if err := store.Put(context.Background(), &Ceremony{}); !errors.Is(err, ErrInvalidRequest) {
		t.Fatalf("empty challenge err = %v", err)
	}
	fixed := time.Now()
	clocked := NewMemoryChallengeStoreWithClock(func() time.Time { return fixed })
	ceremony := &Ceremony{Challenge: []byte{1, 2, 3}, ExpiresAt: fixed.Add(-time.Second)}
	if err := clocked.Put(context.Background(), ceremony); err != nil {
		t.Fatalf("put: %v", err)
	}
	if _, err := clocked.Consume(context.Background(), base64.RawURLEncoding.EncodeToString(ceremony.Challenge)); !errors.Is(err, ErrChallengeExpired) {
		t.Fatalf("expired consume err = %v", err)
	}
	if clocked.Len() != 0 {
		t.Fatalf("expired entry retained: %d", clocked.Len())
	}
	fresh := &Ceremony{Challenge: []byte{4, 5, 6}, ExpiresAt: fixed.Add(time.Minute)}
	if err := clocked.Put(context.Background(), fresh); err != nil {
		t.Fatalf("put fresh: %v", err)
	}
	consumed, err := clocked.Consume(context.Background(), base64.RawURLEncoding.EncodeToString(fresh.Challenge))
	if err != nil || consumed == nil || len(consumed.Challenge) != 3 {
		t.Fatalf("consume fresh = %+v, %v", consumed, err)
	}
	if _, err := clocked.Consume(context.Background(), "missing"); !errors.Is(err, ErrChallengeNotFound) {
		t.Fatalf("missing consume err = %v", err)
	}
}
