package webauthn

import (
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"errors"
	"math/big"
	"testing"
	"time"

	"github.com/shibingli/ydx/base64"
)

// testConcat joins byte slices. | testConcat 连接字节切片。
func testConcat(parts ...[]byte) []byte {
	var out []byte
	for _, part := range parts {
		out = append(out, part...)
	}
	return out
}

// testDERElement encodes a single low-tag DER element with a short or long length. |
// testDERElement 编码单个低标签 DER 元素，长度使用短格式或长格式。
func testDERElement(tag byte, content []byte) []byte {
	out := []byte{tag}
	switch length := len(content); {
	case length < 0x80:
		out = append(out, byte(length))
	case length <= 0xff:
		out = append(out, 0x81, byte(length))
	default:
		out = append(out, 0x82, byte(length>>8), byte(length))
	}
	return append(out, content...)
}

// testDERSequence encodes a universal SEQUENCE. | testDERSequence 编码通用 SEQUENCE。
func testDERSequence(parts ...[]byte) []byte {
	return testDERElement(0x30, testConcat(parts...))
}

// testDERSet encodes a universal SET. | testDERSet 编码通用 SET。
func testDERSet(parts ...[]byte) []byte {
	return testDERElement(0x31, testConcat(parts...))
}

// testDEROctetString encodes a universal OCTET STRING. | testDEROctetString 编码通用 OCTET STRING。
func testDEROctetString(content []byte) []byte {
	return testDERElement(0x04, content)
}

// testDERInteger encodes a universal INTEGER with raw content. | testDERInteger 用原始内容编码通用 INTEGER。
func testDERInteger(content []byte) []byte {
	return testDERElement(0x02, content)
}

// testContextField encodes a context-specific field. | testContextField 编码上下文特定字段。
func testContextField(t *testing.T, tag int, constructed bool, content []byte) []byte {
	t.Helper()
	encoded, err := asn1.Marshal(asn1.RawValue{Class: derClassContext, Tag: tag, IsCompound: constructed, Bytes: content})
	if err != nil {
		t.Fatalf("marshal context field %d: %v", tag, err)
	}
	return encoded
}

// testAndroidPurposeField encodes the purpose context field. | testAndroidPurposeField 编码 purpose 上下文字段。
func testAndroidPurposeField(t *testing.T, purposes ...int) []byte {
	t.Helper()
	var entries [][]byte
	for _, purpose := range purposes {
		entries = append(entries, testDERInteger([]byte{byte(purpose)}))
	}
	return testContextField(t, androidTagPurpose, true, testDERSet(entries...))
}

// testAndroidOriginField encodes the origin context field. | testAndroidOriginField 编码 origin 上下文字段。
func testAndroidOriginField(t *testing.T, origin int) []byte {
	t.Helper()
	encoded, err := asn1.Marshal(asn1.RawValue{Class: derClassContext, Tag: androidTagOrigin, Bytes: []byte{byte(origin)}})
	if err != nil {
		t.Fatalf("marshal origin: %v", err)
	}
	return encoded
}

// androidApplicationIDDER encodes the AttestationApplicationId sequence. | androidApplicationIDDER 编码
// AttestationApplicationId 序列。
func androidApplicationIDDER(t *testing.T, packageName string) []byte {
	t.Helper()
	inner, err := asn1.Marshal(testAndroidApplicationID{
		Packages: []testAndroidPackageInfo{{Name: []byte(packageName), Version: 1}},
		Digests:  [][]byte{{1, 2, 3}},
	})
	if err != nil {
		t.Fatalf("marshal application ID: %v", err)
	}
	return inner
}

// TestParseDERPositiveInt covers every value class of parseDERPositiveInt. |
// TestParseDERPositiveInt 覆盖 parseDERPositiveInt 的各类取值。
func TestParseDERPositiveInt(t *testing.T) {
	cases := []struct {
		name    string
		content []byte
		want    int
		wantErr bool
	}{
		{name: "empty", wantErr: true},
		{name: "negative", content: []byte{0x80}, wantErr: true},
		{name: "too large", content: []byte{1, 0, 0, 0, 0, 0, 0, 0, 0}, wantErr: true},
		{name: "zero", content: []byte{0x00}},
		{name: "one byte", content: []byte{0x02}, want: 2},
		{name: "multi byte", content: []byte{0x01, 0x00}, want: 256},
	}
	for _, test := range cases {
		t.Run(test.name, func(t *testing.T) {
			got, err := parseDERPositiveInt(test.content)
			if test.wantErr {
				if !errors.Is(err, ErrInvalidAttestation) {
					t.Fatalf("error = %v, want ErrInvalidAttestation", err)
				}
				return
			}
			if err != nil {
				t.Fatalf("parseDERPositiveInt: %v", err)
			}
			if got != test.want {
				t.Fatalf("value = %d, want %d", got, test.want)
			}
		})
	}
}

// TestParseDERElementBranches covers malformed and extended DER encodings. |
// TestParseDERElementBranches 覆盖非法与扩展 DER 编码。
func TestParseDERElementBranches(t *testing.T) {
	cases := []struct {
		name    string
		data    []byte
		wantErr bool
		tag     int
		class   int
	}{
		{name: "too deep", data: []byte{0x04, 0x00}, wantErr: true},
		{name: "truncated element", data: []byte{0x04}, wantErr: true},
		{name: "truncated tag", data: []byte{0x1f}, wantErr: true},
		{name: "truncated continuation tag", data: []byte{0x1f, 0x81}, wantErr: true},
		{name: "tag too large", data: []byte{0x1f, 0xff, 0xff, 0xff, 0xff, 0x00}, wantErr: true},
		{name: "truncated length", data: []byte{0x1f, 0x81, 0x01}, wantErr: true},
		{name: "indefinite length", data: []byte{0x30, 0x80}, wantErr: true},
		{name: "length count too large", data: []byte{0x04, 0x85, 1, 2, 3, 4, 5}, wantErr: true},
		{name: "length bytes truncated", data: []byte{0x04, 0x82, 0x01}, wantErr: true},
		{name: "content truncated", data: []byte{0x04, 0x05, 0x01}, wantErr: true},
		{name: "long form", data: []byte{0x04, 0x81, 0x01, 0xaa}, tag: derTagOctetString, class: derClassUniversal},
		{name: "high tag", data: []byte{0xbf, 0x85, 0x45, 0x00}, tag: androidTagAttestationApplicationID, class: derClassContext},
	}
	for _, test := range cases {
		t.Run(test.name, func(t *testing.T) {
			depth := 0
			if test.name == "too deep" {
				depth = 17
			}
			element, _, err := parseDERElementDepth(test.data, depth)
			if test.wantErr {
				if err == nil {
					t.Fatalf("expected an error for %x", test.data)
				}
				return
			}
			if err != nil {
				t.Fatalf("parseDERElementDepth: %v", err)
			}
			if element.tag != test.tag || element.class != test.class {
				t.Fatalf("element = %+v, want tag %d class %d", element, test.tag, test.class)
			}
		})
	}
}

// TestParseAndroidPurposeField covers purpose SET parsing. | TestParseAndroidPurposeField 覆盖 purpose SET 解析。
func TestParseAndroidPurposeField(t *testing.T) {
	purposes, err := parseAndroidPurposes(testDERSet(testDERInteger([]byte{kmPurposeSign}), testDERInteger([]byte{4})))
	if err != nil {
		t.Fatalf("parseAndroidPurposes: %v", err)
	}
	if len(purposes) != 2 || purposes[0] != kmPurposeSign || purposes[1] != 4 {
		t.Fatalf("purposes = %v", purposes)
	}
	cases := []struct {
		name    string
		content []byte
	}{
		{name: "not a set", content: testDERInteger([]byte{1})},
		{name: "trailing data", content: testConcat(testDERSet(testDERInteger([]byte{1})), []byte{0x00})},
		{name: "malformed set", content: testDERElement(0x31, []byte{0x04})},
		{name: "non integer entry", content: testDERSet(testDEROctetString([]byte{1}))},
		{name: "negative entry", content: testDERSet(testDERInteger([]byte{0x80}))},
	}
	for _, test := range cases {
		t.Run(test.name, func(t *testing.T) {
			if _, err := parseAndroidPurposes(test.content); !errors.Is(err, ErrInvalidAttestation) {
				t.Fatalf("error = %v, want ErrInvalidAttestation", err)
			}
		})
	}
}

// rawAuthorizationList wraps AuthorizationList content the way asn1.Unmarshal presents it. |
// rawAuthorizationList 按 asn1.Unmarshal 的呈现方式包装 AuthorizationList 内容。
func rawAuthorizationList(t *testing.T, content []byte) asn1.RawValue {
	t.Helper()
	encoded, err := asn1.Marshal(asn1.RawValue{Class: derClassContext, Tag: 1, IsCompound: true, Bytes: content})
	if err != nil {
		t.Fatalf("marshal authorization list: %v", err)
	}
	var raw asn1.RawValue
	if _, err := asn1.Unmarshal(encoded, &raw); err != nil {
		t.Fatalf("unmarshal authorization list: %v", err)
	}
	return raw
}

// TestParseAndroidAuthorizationList covers each AuthorizationList tag. |
// TestParseAndroidAuthorizationList 覆盖各个 AuthorizationList 标签。
func TestParseAndroidAuthorizationList(t *testing.T) {
	valid := testConcat(
		testAndroidPurposeField(t, kmPurposeSign),
		testAndroidOriginField(t, kmOriginGenerated),
	)
	list, err := parseAndroidAuthorizationList(rawAuthorizationList(t, valid))
	if err != nil {
		t.Fatalf("parseAndroidAuthorizationList: %v", err)
	}
	if !containsInt(list.purposes, kmPurposeSign) || !list.hasOrigin || list.origin != kmOriginGenerated {
		t.Fatalf("list = %+v", list)
	}
	if list.hasAllApplications || list.hasApplicationID {
		t.Fatalf("unexpected flags in %+v", list)
	}

	withPackage := testConcat(valid, testContextField(t, androidTagAttestationApplicationID, true, androidApplicationIDDER(t, "com.example.app")))
	list, err = parseAndroidAuthorizationList(rawAuthorizationList(t, withPackage))
	if err != nil {
		t.Fatalf("parseAndroidAuthorizationList: %v", err)
	}
	if !list.hasApplicationID || len(list.packageNames) != 1 || list.packageNames[0] != "com.example.app" {
		t.Fatalf("application ID = %+v", list)
	}

	withAll := testConcat(valid, testContextField(t, androidTagAllApplications, false, nil))
	list, err = parseAndroidAuthorizationList(rawAuthorizationList(t, withAll))
	if err != nil {
		t.Fatalf("parseAndroidAuthorizationList: %v", err)
	}
	if !list.hasAllApplications {
		t.Fatal("allApplications was not recorded")
	}

	list, err = parseAndroidAuthorizationList(rawAuthorizationList(t, testDERInteger([]byte{1})))
	if err != nil {
		t.Fatalf("non-context element: %v", err)
	}
	if len(list.purposes) != 0 || list.hasOrigin {
		t.Fatalf("non-context element was recorded: %+v", list)
	}

	cases := []struct {
		name    string
		content []byte
	}{
		{name: "malformed list", content: []byte{0x04}},
		{name: "purpose not set", content: testContextField(t, androidTagPurpose, true, testDERInteger([]byte{1}))},
		{name: "origin negative", content: testContextField(t, androidTagOrigin, false, []byte{0x80})},
		{name: "origin empty", content: testContextField(t, androidTagOrigin, false, nil)},
		{name: "application ID malformed", content: testContextField(t, androidTagAttestationApplicationID, true, []byte{0x04})},
	}
	for _, test := range cases {
		t.Run(test.name, func(t *testing.T) {
			if _, err := parseAndroidAuthorizationList(rawAuthorizationList(t, test.content)); !errors.Is(err, ErrInvalidAttestation) {
				t.Fatalf("error = %v, want ErrInvalidAttestation", err)
			}
		})
	}

	if _, err := parseAndroidAuthorizationList(asn1.RawValue{}); err != nil {
		t.Fatalf("empty raw value: %v", err)
	}
}

// TestParseAndroidAttestationApplicationID covers valid and malformed package structures. |
// TestParseAndroidAttestationApplicationID 覆盖合法与非法包结构。
func TestParseAndroidAttestationApplicationID(t *testing.T) {
	onePackage := testDERSequence(
		testDERSequence(testDERSequence(testDEROctetString([]byte("com.example.app")), testDERInteger([]byte{1}))),
		testDERSequence(testDEROctetString([]byte{1, 2, 3})),
	)
	names, err := parseAndroidAttestationApplicationID(onePackage)
	if err != nil {
		t.Fatalf("parseAndroidAttestationApplicationID: %v", err)
	}
	if len(names) != 1 || names[0] != "com.example.app" {
		t.Fatalf("names = %v", names)
	}
	twoPackages := testDERSequence(
		testDERSequence(
			testDERSequence(testDEROctetString([]byte("com.example.app")), testDERInteger([]byte{1})),
			testDERSequence(testDEROctetString([]byte("com.example.other")), testDERInteger([]byte{2})),
		),
		testDERSequence(testDEROctetString([]byte{1})),
	)
	names, err = parseAndroidAttestationApplicationID(twoPackages)
	if err != nil {
		t.Fatalf("parseAndroidAttestationApplicationID: %v", err)
	}
	if len(names) != 2 || names[1] != "com.example.other" {
		t.Fatalf("names = %v", names)
	}

	cases := []struct {
		name    string
		content []byte
	}{
		{name: "not a sequence", content: testDEROctetString(onePackage)},
		{name: "trailing data", content: append(append([]byte(nil), onePackage...), 0x00)},
		{name: "truncated", content: []byte{0x30}},
		{name: "single field", content: testDERSequence(testDERSequence(testDERSequence(testDEROctetString([]byte("x")), testDERInteger([]byte{1}))))},
		{name: "fields not sequences", content: testDERSequence(testDEROctetString(nil), testDERSequence())},
		{name: "no package infos", content: testDERSequence(testDERSequence(), testDERSequence(testDEROctetString([]byte{1})))},
		{name: "package info not sequence", content: testDERSequence(testDERSequence(testDEROctetString([]byte("x"))), testDERSequence(testDEROctetString([]byte{1})))},
		{name: "package info malformed", content: testDERSequence(testDERSequence([]byte{0x04}), testDERSequence(testDEROctetString([]byte{1})))},
		{name: "missing version", content: testDERSequence(testDERSequence(testDERSequence(testDEROctetString([]byte("x")))), testDERSequence(testDEROctetString([]byte{1})))},
		{name: "name not octet string", content: testDERSequence(testDERSequence(testDERSequence(testDERInteger([]byte{1}), testDERInteger([]byte{1}))), testDERSequence(testDEROctetString([]byte{1})))},
		{name: "empty name", content: testDERSequence(testDERSequence(testDERSequence(testDEROctetString(nil), testDERInteger([]byte{1}))), testDERSequence(testDEROctetString([]byte{1})))},
		{name: "negative version", content: testDERSequence(testDERSequence(testDERSequence(testDEROctetString([]byte("x")), testDERInteger([]byte{0x80}))), testDERSequence(testDEROctetString([]byte{1})))},
		{name: "digests malformed", content: testDERSequence(testDERSequence(testDERSequence(testDEROctetString([]byte("x")), testDERInteger([]byte{1}))), testDERSequence([]byte{0x04}))},
		{name: "digest not octet string", content: testDERSequence(testDERSequence(testDERSequence(testDEROctetString([]byte("x")), testDERInteger([]byte{1}))), testDERSequence(testDERInteger([]byte{1})))},
		{name: "empty digest", content: testDERSequence(testDERSequence(testDERSequence(testDEROctetString([]byte("x")), testDERInteger([]byte{1}))), testDERSequence(testDEROctetString(nil)))},
	}
	for _, test := range cases {
		t.Run(test.name, func(t *testing.T) {
			if _, err := parseAndroidAttestationApplicationID(test.content); !errors.Is(err, ErrInvalidAttestation) {
				t.Fatalf("error = %v, want ErrInvalidAttestation", err)
			}
		})
	}
}

// TestParseSafetyNetJWSErrors covers malformed compact JWS inputs. |
// TestParseSafetyNetJWSErrors 覆盖非法紧凑 JWS 输入。
func TestParseSafetyNetJWSErrors(t *testing.T) {
	cert := newTestAttestationCert(t, newECSigner(t))
	goodHeader := b64(mustMarshal(t, struct {
		Alg string   `json:"alg"`
		X5C []string `json:"x5c"`
	}{Alg: "ES256", X5C: []string{base64.StdEncoding.EncodeToString(cert.Raw)}}))
	goodPayload := b64(mustMarshal(t, map[string]any{"nonce": "", "ctsProfileMatch": true}))
	manyCerts := make([]string, maxAttestationCertificates+1)
	for i := range manyCerts {
		manyCerts[i] = base64.StdEncoding.EncodeToString(cert.Raw)
	}
	tooManyHeader := b64(mustMarshal(t, struct {
		Alg string   `json:"alg"`
		X5C []string `json:"x5c"`
	}{Alg: "ES256", X5C: manyCerts}))

	cases := []struct {
		name     string
		response string
	}{
		{name: "not compact", response: "a.b"},
		{name: "header not base64url", response: "!!!." + goodPayload + ".eA"},
		{name: "header not JSON", response: b64([]byte("{")) + "." + goodPayload + ".eA"},
		{name: "missing alg", response: b64(mustMarshal(t, map[string]any{"x5c": []string{}})) + "." + goodPayload + ".eA"},
		{name: "payload not base64url", response: goodHeader + ".!!!.eA"},
		{name: "payload not JSON", response: goodHeader + "." + b64([]byte("{")) + ".eA"},
		{name: "signature not base64url", response: goodHeader + "." + goodPayload + ".!!!"},
		{name: "no certificates", response: b64(mustMarshal(t, map[string]any{"alg": "ES256", "x5c": []string{}})) + "." + goodPayload + ".eA"},
		{name: "too many certificates", response: tooManyHeader + "." + goodPayload + ".eA"},
		{name: "certificate not base64", response: b64(mustMarshal(t, map[string]any{"alg": "ES256", "x5c": []string{"!!!"}})) + "." + goodPayload + ".eA"},
		{name: "certificate not parseable", response: b64(mustMarshal(t, map[string]any{"alg": "ES256", "x5c": []string{base64.StdEncoding.EncodeToString([]byte{1, 2, 3})}})) + "." + goodPayload + ".eA"},
	}
	for _, test := range cases {
		t.Run(test.name, func(t *testing.T) {
			if _, err := parseSafetyNetJWS([]byte(test.response)); !errors.Is(err, ErrInvalidAttestation) {
				t.Fatalf("error = %v, want ErrInvalidAttestation", err)
			}
		})
	}
}

// TestVerifySafetyNetJWSErrors covers signature, nonce, and verdict failures. |
// TestVerifySafetyNetJWSErrors 覆盖签名、nonce 与判定失败。
func TestVerifySafetyNetJWSErrors(t *testing.T) {
	signer := newECSigner(t)
	cert := newTestAttestationCert(t, signer)
	if err := verifySafetyNetJWS(&safetyNetJWS{header: safetyNetHeader{Alg: "HS256"}}, make([]byte, 32)); !errors.Is(err, ErrUnsupportedAlgorithm) {
		t.Fatalf("unsupported algorithm error = %v, want ErrUnsupportedAlgorithm", err)
	}
	if err := verifySafetyNetJWS(&safetyNetJWS{
		header:      safetyNetHeader{Alg: "ES256"},
		certs:       []*x509.Certificate{cert},
		signedInput: []byte("signed"),
		signature:   []byte{1, 2, 3},
	}, make([]byte, 32)); !errors.Is(err, ErrSignatureInvalid) {
		t.Fatalf("invalid signature error = %v, want ErrSignatureInvalid", err)
	}

	nonce := make([]byte, 32)
	response := buildSafetyNetES256JWS(t, signer, []*x509.Certificate{cert}, nonce, 0, true, "com.example.app")
	jws, err := parseSafetyNetJWS(response)
	if err != nil {
		t.Fatalf("parseSafetyNetJWS: %v", err)
	}
	jws.payload.Nonce = "!!!"
	if err := verifySafetyNetJWS(jws, nonce); !errors.Is(err, ErrInvalidAttestation) {
		t.Fatalf("bad nonce encoding error = %v, want ErrInvalidAttestation", err)
	}
	jws.payload.Nonce = base64.StdEncoding.EncodeToString([]byte("different"))
	if err := verifySafetyNetJWS(jws, nonce); !errors.Is(err, ErrInvalidAttestation) {
		t.Fatalf("nonce mismatch error = %v, want ErrInvalidAttestation", err)
	}
}

// marshalAndroidKeyDescription encodes a KeyDescription with arbitrary AuthorizationLists. |
// marshalAndroidKeyDescription 编码携带任意 AuthorizationList 的 KeyDescription。
func marshalAndroidKeyDescription(t *testing.T, challenge, software, tee []byte) []byte {
	t.Helper()
	description := struct {
		AttestationVersion       int
		AttestationSecurityLevel asn1.Enumerated
		KeymasterVersion         int
		KeymasterSecurityLevel   asn1.Enumerated
		AttestationChallenge     []byte
		UniqueID                 []byte
		SoftwareEnforced         asn1.RawValue
		TEEEnforced              asn1.RawValue
	}{
		AttestationVersion:       3,
		AttestationSecurityLevel: 1,
		KeymasterVersion:         4,
		KeymasterSecurityLevel:   1,
		AttestationChallenge:     challenge,
		SoftwareEnforced: asn1.RawValue{
			Class:      derClassContext,
			Tag:        1,
			IsCompound: true,
			Bytes:      software,
		},
		TEEEnforced: asn1.RawValue{
			Class:      derClassContext,
			Tag:        1,
			IsCompound: true,
			Bytes:      tee,
		},
	}
	value, err := asn1.Marshal(description)
	if err != nil {
		t.Fatalf("marshal android key description: %v", err)
	}
	return value
}

// newAndroidExtensionCert returns a certificate carrying a raw Android key extension value. |
// newAndroidExtensionCert 返回携带原始 Android 密钥扩展值的证书。
func newAndroidExtensionCert(t *testing.T, value []byte) *x509.Certificate {
	t.Helper()
	signer := newECSigner(t)
	extension := pkix.Extension{Id: androidKeyAttestationOID, Value: value}
	template := &x509.Certificate{
		SerialNumber:          big.NewInt(150),
		Subject:               pkix.Name{CommonName: "Android Extension Test"},
		NotBefore:             testNow.Add(-time.Hour),
		NotAfter:              testNow.Add(time.Hour),
		KeyUsage:              x509.KeyUsageDigitalSignature,
		BasicConstraintsValid: true,
		ExtraExtensions:       []pkix.Extension{extension},
	}
	der, err := x509.CreateCertificate(rand.Reader, template, template, signer.key.Public(), signer.key)
	if err != nil {
		t.Fatalf("create certificate: %v", err)
	}
	cert, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatalf("parse certificate: %v", err)
	}
	return cert
}

// TestVerifyAndroidKeyExtension covers every extension validation branch. |
// TestVerifyAndroidKeyExtension 覆盖扩展校验的每个分支。
func TestVerifyAndroidKeyExtension(t *testing.T) {
	challenge := make([]byte, 32)
	challenge[0] = 0xaa
	goodSoftware := testConcat(
		testAndroidPurposeField(t, kmPurposeSign),
		testAndroidOriginField(t, kmOriginGenerated),
	)
	withPackage := func(packageName string) []byte {
		return testConcat(goodSoftware, testContextField(t, androidTagAttestationApplicationID, true, androidApplicationIDDER(t, packageName)))
	}
	goodValue := marshalAndroidKeyDescription(t, challenge, goodSoftware, nil)

	if err := verifyAndroidKeyExtension(newAndroidExtensionCert(t, goodValue), challenge, ""); err != nil {
		t.Fatalf("verifyAndroidKeyExtension: %v", err)
	}

	noExtension := newTestAttestationCert(t, newECSigner(t))
	if err := verifyAndroidKeyExtension(noExtension, challenge, ""); !errors.Is(err, ErrInvalidAttestation) {
		t.Fatalf("missing extension error = %v, want ErrInvalidAttestation", err)
	}
	if err := verifyAndroidKeyExtension(newAndroidExtensionCert(t, []byte{0x30, 0x80}), challenge, ""); !errors.Is(err, ErrInvalidAttestation) {
		t.Fatalf("malformed extension error = %v, want ErrInvalidAttestation", err)
	}
	trailing := append(append([]byte(nil), goodValue...), 0x00)
	if err := verifyAndroidKeyExtension(newAndroidExtensionCert(t, trailing), challenge, ""); !errors.Is(err, ErrInvalidAttestation) {
		t.Fatalf("trailing extension bytes error = %v, want ErrInvalidAttestation", err)
	}
	if err := verifyAndroidKeyExtension(newAndroidExtensionCert(t, goodValue), []byte{0xbb}, ""); !errors.Is(err, ErrInvalidAttestation) {
		t.Fatalf("challenge mismatch error = %v, want ErrInvalidAttestation", err)
	}
	if err := verifyAndroidKeyExtension(newAndroidExtensionCert(t, marshalAndroidKeyDescription(t, challenge, []byte{0x04}, nil)), challenge, ""); !errors.Is(err, ErrInvalidAttestation) {
		t.Fatalf("malformed software list error = %v, want ErrInvalidAttestation", err)
	}
	if err := verifyAndroidKeyExtension(newAndroidExtensionCert(t, marshalAndroidKeyDescription(t, challenge, goodSoftware, []byte{0x04})), challenge, ""); !errors.Is(err, ErrInvalidAttestation) {
		t.Fatalf("malformed TEE list error = %v, want ErrInvalidAttestation", err)
	}

	cases := []struct {
		name       string
		software   []byte
		tee        []byte
		wantErr    bool
		pkg        string
		wantErrPkg bool
	}{
		{name: "all applications", software: testConcat(goodSoftware, testContextField(t, androidTagAllApplications, false, nil)), wantErr: true},
		{name: "TEE all applications", software: goodSoftware, tee: testConcat(testContextField(t, androidTagAllApplications, false, nil), testAndroidOriginField(t, kmOriginGenerated)), wantErr: true},
		{name: "no origin", software: testAndroidPurposeField(t, kmPurposeSign), wantErr: true},
		{name: "software bad origin", software: testConcat(testAndroidPurposeField(t, kmPurposeSign), testAndroidOriginField(t, 1)), wantErr: true},
		{name: "TEE bad origin", software: testAndroidPurposeField(t, kmPurposeSign), tee: testConcat(testAndroidPurposeField(t, kmPurposeSign), testAndroidOriginField(t, 1)), wantErr: true},
		{name: "no signing purpose", software: testAndroidOriginField(t, kmOriginGenerated), wantErr: true},
		{name: "missing application ID", software: goodSoftware, pkg: "com.example.app", wantErrPkg: true},
		{name: "wrong application ID", software: withPackage("com.other.app"), pkg: "com.example.app", wantErrPkg: true},
		{name: "matching application ID", software: withPackage("com.example.app"), pkg: "com.example.app"},
		{name: "TEE matching application ID", software: goodSoftware, tee: testConcat(testAndroidPurposeField(t, kmPurposeSign), testAndroidOriginField(t, kmOriginGenerated), testContextField(t, androidTagAttestationApplicationID, true, androidApplicationIDDER(t, "com.example.app"))), pkg: "com.example.app"},
	}
	for _, test := range cases {
		t.Run(test.name, func(t *testing.T) {
			value := marshalAndroidKeyDescription(t, challenge, test.software, test.tee)
			err := verifyAndroidKeyExtension(newAndroidExtensionCert(t, value), challenge, test.pkg)
			if test.wantErr || test.wantErrPkg {
				if !errors.Is(err, ErrInvalidAttestation) {
					t.Fatalf("error = %v, want ErrInvalidAttestation", err)
				}
				return
			}
			if err != nil {
				t.Fatalf("verifyAndroidKeyExtension: %v", err)
			}
		})
	}

	if _, ok := certificateExtension(nil, androidKeyAttestationOID); ok {
		t.Fatal("nil certificate reported an extension")
	}
}
