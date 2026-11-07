package xmlsig

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"errors"
	"math/big"
	"testing"
	"time"

	"github.com/shibingli/ydx/base64"
)

// keyInfoDocument is the fixture signed by KeyInfo tests. | keyInfoDocument 是 KeyInfo 测试使用的
// 固定文档。
const keyInfoDocument = `<root><order ID="order-1"><amount>42</amount></order></root>`

// mustParseNode parses one XML document and returns its root node. | mustParseNode 解析一个 XML
// 文档并返回根节点。
func mustParseNode(t *testing.T, input string) *xmlNode {
	t.Helper()
	doc, err := parseXML([]byte(input))
	if err != nil {
		t.Fatalf("parseXML(%q): %v", input, err)
	}
	return doc.root
}

// testCertificateWithSubjectKeyID issues a self-signed certificate carrying a SubjectKeyId. |
// testCertificateWithSubjectKeyID 签发携带 SubjectKeyId 的自签名证书。
func testCertificateWithSubjectKeyID(t *testing.T, key *rsa.PrivateKey, ski []byte) *x509.Certificate {
	t.Helper()
	template := &x509.Certificate{
		SerialNumber: big.NewInt(424242),
		Subject:      pkix.Name{CommonName: "xmlsig selector test"},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(time.Hour),
		KeyUsage:     x509.KeyUsageDigitalSignature,
		SubjectKeyId: ski,
	}
	der, err := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
	if err != nil {
		t.Fatalf("x509.CreateCertificate: %v", err)
	}
	cert, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatalf("x509.ParseCertificate: %v", err)
	}
	return cert
}

// replaceX509Data substitutes the children of the first X509Data element. KeyInfo is outside
// SignedInfo, so this does not disturb the signature. | replaceX509Data 替换首个 X509Data 元素的
// 子节点。KeyInfo 位于 SignedInfo 之外，因此不会破坏签名。
func replaceX509Data(t *testing.T, signed []byte, inner string) []byte {
	t.Helper()
	const open, closeTag = "<X509Data>", "</X509Data>"
	start := bytes.Index(signed, []byte(open))
	end := bytes.Index(signed, []byte(closeTag))
	if start < 0 || end < start {
		t.Fatalf("X509Data not found in %s", signed)
	}
	var out bytes.Buffer
	out.Write(signed[:start])
	out.WriteString(open)
	out.WriteString(inner)
	out.WriteString(closeTag)
	out.Write(signed[end+len(closeTag):])
	return out.Bytes()
}

// TestEmbeddedRSAAndECKeyValues covers KeyValue generation, parsing and TrustKeyInfo. |
// TestEmbeddedRSAAndECKeyValues 覆盖 KeyValue 的生成、解析与 TrustKeyInfo。
func TestEmbeddedRSAAndECKeyValues(t *testing.T) {
	rsaKey := testRSAPrivateKey(t)
	signed, err := Sign([]byte(keyInfoDocument), SignOptions{PrivateKey: rsaKey, ID: "order-1", IncludeKeyInfo: true})
	if err != nil {
		t.Fatalf("Sign RSA: %v", err)
	}
	for _, marker := range []string{"<KeyValue>", "<RSAKeyValue>", "<Modulus>", "<Exponent>"} {
		if !bytes.Contains(signed, []byte(marker)) {
			t.Fatalf("RSA KeyInfo lacks %s: %s", marker, signed)
		}
	}
	result, err := VerifyElement(signed, "order-1", VerifyOptions{TrustKeyInfo: true})
	if err != nil {
		t.Fatalf("VerifyElement TrustKeyInfo: %v", err)
	}
	if _, ok := result.Signer.(*rsa.PublicKey); !ok {
		t.Fatalf("signer type = %T, want *rsa.PublicKey", result.Signer)
	}
	if _, err := VerifyElement(signed, "order-1", VerifyOptions{}); !errors.Is(err, ErrUntrustedKey) {
		t.Fatalf("untrusted KeyInfo error = %v, want ErrUntrustedKey", err)
	}
	roots := x509.NewCertPool()
	roots.AddCert(testCertificate(t, testRSAPrivateKey(t)))
	if _, err := VerifyElement(signed, "order-1", VerifyOptions{Roots: roots}); !errors.Is(err, ErrUntrustedKey) {
		t.Fatalf("Roots without certs error = %v, want ErrUntrustedKey", err)
	}
	wrongCert := testCertificate(t, testRSAPrivateKey(t))
	if _, err := VerifyElement(signed, "order-1", VerifyOptions{Certificates: []*x509.Certificate{wrongCert}}); !errors.Is(err, ErrSignatureInvalid) {
		t.Fatalf("wrong certificate error = %v, want ErrSignatureInvalid", err)
	}

	tampered := bytes.Replace(signed, []byte("<amount>42</amount>"), []byte("<amount>43</amount>"), 1)
	if _, err := VerifyElement(tampered, "order-1", VerifyOptions{TrustKeyInfo: true}); !errors.Is(err, ErrDigestMismatch) {
		t.Fatalf("tampered TrustKeyInfo error = %v, want ErrDigestMismatch", err)
	}

	curves := []struct {
		name string
		uri  string
		oid  string
		key  *ecdsa.PrivateKey
	}{
		{name: "p256", uri: "http://www.w3.org/2001/04/xmldsig-more#secp256r1", oid: "urn:oid:1.2.840.10045.3.1.7", key: testECDSAPrivateKey(t, elliptic.P256())},
		{name: "p384", uri: "http://www.w3.org/2001/04/xmldsig-more#secp384r1", oid: "urn:oid:1.3.132.0.34", key: testECDSAPrivateKey(t, elliptic.P384())},
		{name: "p521", uri: "http://www.w3.org/2001/04/xmldsig-more#secp521r1", oid: "urn:oid:1.3.132.0.35", key: testECDSAPrivateKey(t, elliptic.P521())},
	}
	for _, tc := range curves {
		t.Run("ec-"+tc.name, func(t *testing.T) {
			signed, err := Sign([]byte(keyInfoDocument), SignOptions{PrivateKey: tc.key, ID: "order-1", IncludeKeyInfo: true})
			if err != nil {
				t.Fatalf("Sign: %v", err)
			}
			if !bytes.Contains(signed, []byte("ECKeyValue")) || !bytes.Contains(signed, []byte(`URI="`+tc.uri+`"`)) {
				t.Fatalf("EC KeyInfo lacks curve URI: %s", signed)
			}
			result, err := VerifyElement(signed, "order-1", VerifyOptions{TrustKeyInfo: true})
			if err != nil {
				t.Fatalf("VerifyElement: %v", err)
			}
			pub, ok := result.Signer.(*ecdsa.PublicKey)
			if !ok || pub.Curve != tc.key.Curve {
				t.Fatalf("signer = %#v, want curve %v", result.Signer, tc.key.Curve)
			}
			withOID := bytes.Replace(signed, []byte(`URI="`+tc.uri+`"`), []byte(`URI="`+tc.oid+`"`), 1)
			if _, err := VerifyElement(withOID, "order-1", VerifyOptions{TrustKeyInfo: true}); err != nil {
				t.Fatalf("OID curve verification: %v", err)
			}
			badCurve := bytes.Replace(signed, []byte(`URI="`+tc.uri+`"`), []byte(`URI="urn:oid:1.2.3"`), 1)
			if _, err := Verify(badCurve, VerifyOptions{TrustKeyInfo: true}); !errors.Is(err, ErrUnsupported) {
				t.Fatalf("unsupported curve error = %v, want ErrUnsupported", err)
			}
			badPoint := bytes.Replace(signed, []byte(`URI="`+tc.uri+`"`), []byte(`URI="`+tc.oid+`"`), 1)
			badPoint = replaceElementText(t, badPoint, "dsig11:PublicKey", base64.StdEncoding.EncodeToString([]byte{1, 2, 3}))
			if _, err := Verify(badPoint, VerifyOptions{TrustKeyInfo: true}); !errors.Is(err, ErrKeyMismatch) {
				t.Fatalf("invalid EC point error = %v, want ErrKeyMismatch", err)
			}
		})
	}

	p224 := testECDSAPrivateKey(t, elliptic.P224())
	if _, err := buildECKeyValue("", p224.PublicKey); !errors.Is(err, ErrUnsupported) {
		t.Fatalf("buildECKeyValue P224 error = %v, want ErrUnsupported", err)
	}
	if curveURI(elliptic.P224()) != "" {
		t.Fatal("curveURI(P224) must be empty")
	}
	for uri, curve := range map[string]elliptic.Curve{
		"http://www.w3.org/2001/04/xmldsig-more#secp256r1": elliptic.P256(),
		"urn:oid:1.2.840.10045.3.1.7":                      elliptic.P256(),
		"http://www.w3.org/2001/04/xmldsig-more#secp384r1": elliptic.P384(),
		"urn:oid:1.3.132.0.34":                             elliptic.P384(),
		"http://www.w3.org/2001/04/xmldsig-more#secp521r1": elliptic.P521(),
		"urn:oid:1.3.132.0.35":                             elliptic.P521(),
	} {
		if got, ok := curveFromURI(uri); !ok || got != curve {
			t.Fatalf("curveFromURI(%q) = %v, %v", uri, got, ok)
		}
	}
	if curve, ok := curveFromURI("urn:oid:1.2.3"); ok || curve != nil {
		t.Fatal("curveFromURI accepted an unknown OID")
	}
}

// replaceElementText replaces the text of the first element with the given local name. |
// replaceElementText 替换首个指定本地名元素的文本。
func replaceElementText(t *testing.T, data []byte, local, text string) []byte {
	t.Helper()
	open := []byte("<" + local + ">")
	closeTag := []byte("</" + local + ">")
	start := bytes.Index(data, open)
	end := bytes.Index(data, closeTag)
	if start < 0 || end < start {
		t.Fatalf("element %s not found in %s", local, data)
	}
	var out bytes.Buffer
	out.Write(data[:start])
	out.Write(open)
	out.WriteString(text)
	out.Write(closeTag)
	out.Write(data[end+len(closeTag):])
	return out.Bytes()
}

// TestX509DataSelectors covers every X509Data selector identifier. |
// TestX509DataSelectors 覆盖所有 X509Data 选择器标识。
func TestX509DataSelectors(t *testing.T) {
	key := testRSAPrivateKey(t)
	ski := []byte{0x01, 0x02, 0x03, 0x04, 0x05}
	cert := testCertificateWithSubjectKeyID(t, key, ski)
	trusted := VerifyOptions{Certificates: []*x509.Certificate{cert}}
	signed, err := Sign([]byte(keyInfoDocument), SignOptions{PrivateKey: key, Certificate: cert, ID: "order-1", IncludeKeyInfo: true})
	if err != nil {
		t.Fatalf("Sign: %v", err)
	}
	digest := computeDigest(digestSpecs[digestSHA256URI], cert.Raw)
	issuerSerial := "<X509IssuerSerial><X509IssuerName>" + cert.Issuer.String() +
		"</X509IssuerName><X509SerialNumber>" + cert.SerialNumber.String() + "</X509SerialNumber></X509IssuerSerial>"
	cases := []struct {
		name string
		xml  string
		want error
	}{
		{name: "subject name", xml: "<X509SubjectName>" + cert.Subject.String() + "</X509SubjectName>"},
		{name: "issuer serial", xml: issuerSerial},
		{name: "ski", xml: "<X509SKI>" + base64.StdEncoding.EncodeToString(ski) + "</X509SKI>"},
		{name: "digest", xml: `<X509Digest Algorithm="` + digestSHA256URI + `">` + base64.StdEncoding.EncodeToString(digest) + "</X509Digest>"},
		{name: "multiple match", xml: "<X509SubjectName>CN=other</X509SubjectName>" + issuerSerial},
		{name: "wrong subject", xml: "<X509SubjectName>CN=evil</X509SubjectName>", want: ErrSignatureInvalid},
		{name: "wrong serial", xml: "<X509IssuerSerial><X509IssuerName>" + cert.Issuer.String() + "</X509IssuerName><X509SerialNumber>1</X509SerialNumber></X509IssuerSerial>", want: ErrSignatureInvalid},
		{name: "wrong ski", xml: "<X509SKI>" + base64.StdEncoding.EncodeToString([]byte{9, 9, 9}) + "</X509SKI>", want: ErrSignatureInvalid},
		{name: "unsupported digest", xml: `<X509Digest Algorithm="urn:digest:unknown">` + base64.StdEncoding.EncodeToString(digest) + "</X509Digest>", want: ErrUnsupported},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			document := replaceX509Data(t, signed, tc.xml)
			_, err := VerifyElement(document, "order-1", trusted)
			if tc.want == nil {
				if err != nil {
					t.Fatalf("VerifyElement: %v", err)
				}
				return
			}
			if !errors.Is(err, tc.want) {
				t.Fatalf("VerifyElement error = %v, want %v", err, tc.want)
			}
		})
	}

	// An embedded X509Certificate is a direct reference; selectors do not narrow it. | 内嵌
	// X509Certificate 本身就是直接引用，选择器不会缩小候选范围。
	embeddedAndWrong := replaceX509Data(t, signed,
		"<X509Certificate>"+base64.StdEncoding.EncodeToString(cert.Raw)+"</X509Certificate><X509SubjectName>CN=evil</X509SubjectName>")
	if _, err := VerifyElement(embeddedAndWrong, "order-1", trusted); err != nil {
		t.Fatalf("embedded certificate with selector: %v", err)
	}
}

// TestMatchesCertificateUnit covers parsedKeyInfo selector matching directly. |
// TestMatchesCertificateUnit 直接覆盖 parsedKeyInfo 的选择器匹配。
func TestMatchesCertificateUnit(t *testing.T) {
	key := testRSAPrivateKey(t)
	cert := testCertificateWithSubjectKeyID(t, key, []byte{7, 8, 9})
	digest := computeDigest(digestSpecs[digestSHA256URI], cert.Raw)
	var nilInfo *parsedKeyInfo
	if ok, err := nilInfo.matchesCertificate(cert); err != nil || !ok {
		t.Fatalf("nil parsedKeyInfo matchesCertificate = %v, %v", ok, err)
	}
	if nilInfo.hasSelectors() {
		t.Fatal("nil parsedKeyInfo reports selectors")
	}
	cases := []struct {
		name string
		info parsedKeyInfo
		want bool
	}{
		{name: "empty", info: parsedKeyInfo{}, want: true},
		{name: "subject", info: parsedKeyInfo{subjectNames: []string{cert.Subject.String()}}, want: true},
		{name: "issuer serial", info: parsedKeyInfo{issuerSerials: []issuerSerial{{issuer: cert.Issuer.String(), serial: cert.SerialNumber.String()}}}, want: true},
		{name: "key id", info: parsedKeyInfo{keyIDs: [][]byte{cert.SubjectKeyId}}, want: true},
		{name: "empty key id", info: parsedKeyInfo{keyIDs: [][]byte{{}}}, want: false},
		{name: "digest", info: parsedKeyInfo{digests: []x509Digest{{algorithm: digestSHA256URI, value: digest}}}, want: true},
		{name: "wrong digest", info: parsedKeyInfo{digests: []x509Digest{{algorithm: digestSHA256URI, value: bytes.Repeat([]byte{0}, len(digest))}}}, want: false},
		{name: "short digest", info: parsedKeyInfo{digests: []x509Digest{{algorithm: digestSHA256URI, value: digest[:8]}}}, want: false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got, err := tc.info.matchesCertificate(cert)
			if err != nil {
				t.Fatalf("matchesCertificate: %v", err)
			}
			if got != tc.want {
				t.Fatalf("matchesCertificate = %v, want %v", got, tc.want)
			}
		})
	}
	if (&parsedKeyInfo{}).hasSelectors() {
		t.Fatal("empty parsedKeyInfo reports selectors")
	}
	if !(&parsedKeyInfo{subjectNames: []string{"CN=x"}}).hasSelectors() {
		t.Fatal("subject selector not reported")
	}
	if _, err := (&parsedKeyInfo{digests: []x509Digest{{algorithm: "urn:unknown"}}}).matchesCertificate(cert); !errors.Is(err, ErrUnsupported) {
		t.Fatalf("unsupported digest error = %v, want ErrUnsupported", err)
	}
}

// TestParseKeyInfoRejections covers malformed KeyInfo and KeyValue structures. |
// TestParseKeyInfoRejections 覆盖畸形的 KeyInfo 与 KeyValue 结构。
func TestParseKeyInfoRejections(t *testing.T) {
	if _, err := parseKeyInfo(mustParseNode(t, "<KeyInfo><RetrievalMethod/></KeyInfo>")); !errors.Is(err, ErrUnsupported) {
		t.Fatalf("RetrievalMethod error = %v, want ErrUnsupported", err)
	}
	if _, err := parseKeyInfo(mustParseNode(t, "<KeyInfo><X509Data><X509Certificate>%%%</X509Certificate></X509Data></KeyInfo>")); !errors.Is(err, ErrMalformed) {
		t.Fatalf("invalid X509Certificate base64 error = %v, want ErrMalformed", err)
	}
	if _, err := parseKeyInfo(mustParseNode(t, "<KeyInfo><X509Data><X509Certificate>"+
		base64.StdEncoding.EncodeToString([]byte("not a certificate"))+"</X509Certificate></X509Data></KeyInfo>")); !errors.Is(err, ErrCertificateInvalid) {
		t.Fatalf("invalid X509Certificate DER error = %v, want ErrCertificateInvalid", err)
	}
	if _, err := parseKeyInfo(mustParseNode(t, "<KeyInfo><X509Data><X509IssuerSerial><X509IssuerName>CN=x</X509IssuerName></X509IssuerSerial></X509Data></KeyInfo>")); !errors.Is(err, ErrMalformed) {
		t.Fatalf("incomplete IssuerSerial error = %v, want ErrMalformed", err)
	}
	if _, err := parseKeyInfo(mustParseNode(t, "<KeyInfo><X509Data><X509Digest>AQID</X509Digest></X509Data></KeyInfo>")); !errors.Is(err, ErrMalformed) {
		t.Fatalf("X509Digest without Algorithm error = %v, want ErrMalformed", err)
	}
	if _, err := parseKeyInfo(mustParseNode(t, "<KeyInfo><X509Data><X509Digest Algorithm=\"urn:d\">%%%</X509Digest></X509Data></KeyInfo>")); !errors.Is(err, ErrMalformed) {
		t.Fatalf("X509Digest invalid base64 error = %v, want ErrMalformed", err)
	}
	key := testRSAPrivateKey(t)
	duplicateRSA := newElement("", "KeyInfo")
	duplicateRSA.appendChild(buildRSAKeyValue("", key.PublicKey))
	duplicateRSA.appendChild(buildRSAKeyValue("", key.PublicKey))
	if _, err := parseKeyInfo(duplicateRSA); !errors.Is(err, ErrMalformed) {
		t.Fatalf("duplicate RSAKeyValue error = %v, want ErrMalformed", err)
	}
	ecKey := testECDSAPrivateKey(t, elliptic.P256())
	duplicateEC := newElement("", "KeyInfo")
	first, err := buildECKeyValue("", ecKey.PublicKey)
	if err != nil {
		t.Fatalf("buildECKeyValue: %v", err)
	}
	second, err := buildECKeyValue("", ecKey.PublicKey)
	if err != nil {
		t.Fatalf("buildECKeyValue: %v", err)
	}
	duplicateEC.appendChild(first)
	duplicateEC.appendChild(second)
	if _, err := parseKeyInfo(duplicateEC); !errors.Is(err, ErrMalformed) {
		t.Fatalf("duplicate ECKeyValue error = %v, want ErrMalformed", err)
	}
	if _, err := parseKeyInfo(mustParseNode(t, "<KeyInfo><KeyName>  key-1 \n</KeyName></KeyInfo>")); err != nil {
		t.Fatalf("parse KeyName: %v", err)
	} else if got := mustParseKeyNames(t, "<KeyInfo><KeyName>  key-1 \n</KeyName></KeyInfo>"); len(got) != 1 || got[0] != "key-1" {
		t.Fatalf("KeyName = %q, want key-1", got)
	}
}

// mustParseKeyNames returns the parsed KeyName values of one KeyInfo document. |
// mustParseKeyNames 返回一个 KeyInfo 文档解析出的 KeyName 值。
func mustParseKeyNames(t *testing.T, input string) []string {
	t.Helper()
	info, err := parseKeyInfo(mustParseNode(t, input))
	if err != nil {
		t.Fatalf("parseKeyInfo: %v", err)
	}
	return info.keyNames
}

// TestParseRSAAndECKeyValues covers structural and range validation of KeyValue. |
// TestParseRSAAndECKeyValues 覆盖 KeyValue 的结构与范围校验。
func TestParseRSAAndECKeyValues(t *testing.T) {
	key := testRSAPrivateKey(t)
	validModulus := base64.StdEncoding.EncodeToString(key.N.Bytes())
	validExponent := base64.StdEncoding.EncodeToString(big.NewInt(int64(key.E)).Bytes())
	rsaCases := []struct {
		name string
		xml  string
		want error
	}{
		{name: "valid", xml: "<RSAKeyValue><Modulus>" + validModulus + "</Modulus><Exponent>" + validExponent + "</Exponent></RSAKeyValue>"},
		{name: "missing modulus", xml: "<RSAKeyValue><Exponent>AQAB</Exponent></RSAKeyValue>", want: ErrMalformed},
		{name: "missing exponent", xml: "<RSAKeyValue><Modulus>" + validModulus + "</Modulus></RSAKeyValue>", want: ErrMalformed},
		{name: "duplicate modulus", xml: "<RSAKeyValue><Modulus>" + validModulus + "</Modulus><Modulus>" + validModulus + "</Modulus><Exponent>AQAB</Exponent></RSAKeyValue>", want: ErrMalformed},
		{name: "invalid modulus base64", xml: "<RSAKeyValue><Modulus>%%%</Modulus><Exponent>AQAB</Exponent></RSAKeyValue>", want: ErrMalformed},
		{name: "empty exponent", xml: "<RSAKeyValue><Modulus>" + validModulus + "</Modulus><Exponent></Exponent></RSAKeyValue>", want: ErrMalformed},
		{name: "tiny modulus", xml: "<RSAKeyValue><Modulus>AQ==</Modulus><Exponent>AQAB</Exponent></RSAKeyValue>", want: ErrKeyMismatch},
		{name: "small exponent", xml: "<RSAKeyValue><Modulus>" + validModulus + "</Modulus><Exponent>Ag==</Exponent></RSAKeyValue>", want: ErrKeyMismatch},
		{name: "huge exponent", xml: "<RSAKeyValue><Modulus>" + validModulus + "</Modulus><Exponent>" + base64.StdEncoding.EncodeToString(big.NewInt(1<<32).Bytes()) + "</Exponent></RSAKeyValue>", want: ErrKeyMismatch},
	}
	for _, tc := range rsaCases {
		t.Run("rsa-"+tc.name, func(t *testing.T) {
			node := mustParseNode(t, tc.xml)
			pub, err := parseRSAKeyValue(node)
			if tc.want != nil {
				if !errors.Is(err, tc.want) {
					t.Fatalf("parseRSAKeyValue error = %v, want %v", err, tc.want)
				}
				return
			}
			if err != nil {
				t.Fatalf("parseRSAKeyValue: %v", err)
			}
			if pub.N.Cmp(key.N) != 0 || pub.E != key.E {
				t.Fatalf("parsed key = %+v", pub)
			}
		})
	}

	ecKey := testECDSAPrivateKey(t, elliptic.P256())
	built, err := buildECKeyValue("", ecKey.PublicKey)
	if err != nil {
		t.Fatalf("buildECKeyValue: %v", err)
	}
	if pub, err := parseECKeyValue(built.childByLocal("ECKeyValue")); err != nil {
		t.Fatalf("parseECKeyValue: %v", err)
	} else if pub.Curve != elliptic.P256() {
		t.Fatalf("parsed curve = %v", pub.Curve)
	}
	ecCases := []struct {
		name string
		xml  string
		want error
	}{
		{name: "missing curve", xml: "<ECKeyValue><PublicKey>AQID</PublicKey></ECKeyValue>", want: ErrMalformed},
		{name: "missing curve uri", xml: "<ECKeyValue><NamedCurve/><PublicKey>AQID</PublicKey></ECKeyValue>", want: ErrMalformed},
		{name: "unsupported curve", xml: `<ECKeyValue><NamedCurve URI="urn:oid:1.2.3"/><PublicKey>AQID</PublicKey></ECKeyValue>`, want: ErrUnsupported},
		{name: "invalid point", xml: `<ECKeyValue><NamedCurve URI="urn:oid:1.2.840.10045.3.1.7"/><PublicKey>AQID</PublicKey></ECKeyValue>`, want: ErrKeyMismatch},
		{name: "missing point", xml: `<ECKeyValue><NamedCurve URI="urn:oid:1.2.840.10045.3.1.7"/></ECKeyValue>`, want: ErrMalformed},
		{name: "invalid point base64", xml: `<ECKeyValue><NamedCurve URI="urn:oid:1.2.840.10045.3.1.7"/><PublicKey>%%%</PublicKey></ECKeyValue>`, want: ErrMalformed},
	}
	for _, tc := range ecCases {
		t.Run("ec-"+tc.name, func(t *testing.T) {
			if _, err := parseECKeyValue(mustParseNode(t, tc.xml)); !errors.Is(err, tc.want) {
				t.Fatalf("parseECKeyValue error = %v, want %v", err, tc.want)
			}
		})
	}
	empty := newElement("", "KeyValue")
	out := &parsedKeyInfo{}
	if err := parseKeyValue(empty, out); err != nil || out.rsaKey != nil || out.ecKey != nil {
		t.Fatalf("empty KeyValue = %+v, %v", out, err)
	}
}

// TestSigningHelpersAndKeyChecks covers key comparison, certificate matching and signing key
// validation. | TestSigningHelpersAndKeyChecks 覆盖密钥比较、证书匹配与签名密钥校验。
func TestSigningHelpersAndKeyChecks(t *testing.T) {
	rsaA := testRSAPrivateKey(t)
	rsaB := testRSAPrivateKey(t)
	ecA := testECDSAPrivateKey(t, elliptic.P256())
	ecB := testECDSAPrivateKey(t, elliptic.P256())
	edA := testEd25519PrivateKey(t)
	edB := testEd25519PrivateKey(t)
	sm2A := testSM2Key(t)
	sm2B := testSM2Key(t)
	equalCases := []struct {
		name string
		a, b any
		want bool
	}{
		{name: "rsa equal", a: &rsaA.PublicKey, b: &rsaA.PublicKey, want: true},
		{name: "rsa different", a: &rsaA.PublicKey, b: &rsaB.PublicKey},
		{name: "rsa wrong type", a: &rsaA.PublicKey, b: &ecA.PublicKey},
		{name: "ec equal", a: &ecA.PublicKey, b: &ecA.PublicKey, want: true},
		{name: "ec different", a: &ecA.PublicKey, b: &ecB.PublicKey},
		{name: "ec wrong type", a: &ecA.PublicKey, b: &rsaA.PublicKey},
		{name: "ed equal", a: edA.Public(), b: edA.Public(), want: true},
		{name: "ed different", a: edA.Public(), b: edB.Public()},
		{name: "ed wrong type", a: edA.Public(), b: &rsaA.PublicKey},
		{name: "sm2 equal", a: sm2A.Public(), b: sm2A.Public(), want: true},
		{name: "sm2 different", a: sm2A.Public(), b: sm2B.Public()},
		{name: "sm2 wrong type", a: sm2A.Public(), b: &rsaA.PublicKey},
		{name: "nil", a: nil, b: nil},
	}
	for _, tc := range equalCases {
		t.Run(tc.name, func(t *testing.T) {
			if got := publicKeysEqual(tc.a, tc.b); got != tc.want {
				t.Fatalf("publicKeysEqual = %v, want %v", got, tc.want)
			}
		})
	}

	certA := testCertificate(t, rsaA)
	if err := signingCertificateMatches(certA, rsaA); err != nil {
		t.Fatalf("matching certificate: %v", err)
	}
	if err := signingCertificateMatches(certA, rsaB); !errors.Is(err, ErrKeyMismatch) {
		t.Fatalf("mismatched certificate error = %v, want ErrKeyMismatch", err)
	}
	if err := signingCertificateMatches(certA, int(1)); err != nil {
		t.Fatalf("unsupported key type should be ignored: %v", err)
	}
	ecCert := testCertificate(t, ecA)
	if err := signingCertificateMatches(ecCert, ecA); err != nil {
		t.Fatalf("matching EC certificate: %v", err)
	}
	edCert := testCertificate(t, edA)
	if err := signingCertificateMatches(edCert, edA); err != nil {
		t.Fatalf("matching Ed25519 certificate: %v", err)
	}

	certs := signingCertificates(SignOptions{Certificate: certA, Certificates: []*x509.Certificate{certA, nil, testCertificate(t, rsaB)}})
	if len(certs) != 2 || certs[0] != certA {
		t.Fatalf("signingCertificates = %d entries, want 2 with first certificate preserved", len(certs))
	}

	// Further certificates are chain material and need not match the signing key. | 其余证书属于链
	// 材料，无需与签名密钥匹配。
	multi, err := Sign([]byte(keyInfoDocument), SignOptions{PrivateKey: rsaA, Certificate: certA, Certificates: []*x509.Certificate{certA, testCertificate(t, rsaB)}, ID: "order-1", IncludeKeyInfo: true, KeyName: "key-1"})
	if err != nil {
		t.Fatalf("Sign with certificates: %v", err)
	}
	if got := bytes.Count(multi, []byte("<X509Certificate>")); got != 2 {
		t.Fatalf("X509Certificate count = %d, want 2", got)
	}
	if !bytes.Contains(multi, []byte("<KeyName>key-1</KeyName>")) {
		t.Fatalf("KeyName missing: %s", multi)
	}
	if _, err := VerifyElement(multi, "order-1", VerifyOptions{Certificates: []*x509.Certificate{certA}}); err != nil {
		t.Fatalf("VerifyElement multiple certificates: %v", err)
	}

	badSigns := []struct {
		name string
		opts SignOptions
		want error
	}{
		{name: "no key", opts: SignOptions{}, want: ErrKeyRequired},
		{name: "two keys", opts: SignOptions{PrivateKey: rsaA, HMACKey: []byte("secret")}, want: ErrKeyRequired},
		{name: "unsupported key type", opts: SignOptions{PrivateKey: int(1)}, want: ErrKeyMismatch},
		{name: "rsa with ecdsa method", opts: SignOptions{PrivateKey: rsaA, SignatureMethod: sigECDSASHA256URI}, want: ErrKeyMismatch},
		{name: "ecdsa with rsa method", opts: SignOptions{PrivateKey: ecA, SignatureMethod: sigRSASHA256URI}, want: ErrKeyMismatch},
		{name: "ed25519 with ecdsa method", opts: SignOptions{PrivateKey: edA, SignatureMethod: sigECDSASHA256URI}, want: ErrKeyMismatch},
		{name: "rsa with hmac method", opts: SignOptions{PrivateKey: rsaA, SignatureMethod: sigHMACSHA256URI}, want: ErrKeyMismatch},
		{name: "hmac with rsa method", opts: SignOptions{HMACKey: []byte("secret"), SignatureMethod: sigRSASHA256URI}, want: ErrKeyMismatch},
		{name: "sm2 with rsa method", opts: SignOptions{SM2Key: sm2A, SignatureMethod: sigRSASHA256URI}, want: ErrKeyMismatch},
		{name: "rsa with sm2 method", opts: SignOptions{PrivateKey: rsaA, SignatureMethod: sigSM2SM3URI}, want: ErrKeyMismatch},
		{name: "rsa with ed25519 method", opts: SignOptions{PrivateKey: rsaA, SignatureMethod: sigEd25519URI}, want: ErrKeyMismatch},
		{name: "unsupported method", opts: SignOptions{PrivateKey: rsaA, SignatureMethod: "urn:sig:unknown"}, want: ErrUnsupported},
		{name: "unsupported digest", opts: SignOptions{PrivateKey: rsaA, DigestMethod: "urn:digest:unknown"}, want: ErrUnsupported},
		{name: "certificate mismatch", opts: SignOptions{PrivateKey: rsaA, Certificate: ecCert, IncludeKeyInfo: true}, want: ErrKeyMismatch},
	}
	for _, tc := range badSigns {
		t.Run(tc.name, func(t *testing.T) {
			if _, err := Sign([]byte(keyInfoDocument), tc.opts); !errors.Is(err, tc.want) {
				t.Fatalf("Sign error = %v, want %v", err, tc.want)
			}
		})
	}
	if _, err := Sign([]byte(keyInfoDocument), SignOptions{PrivateKey: rsaA, Prefix: "xml"}); !errors.Is(err, ErrInvalidOption) {
		t.Fatalf("reserved xml prefix error = %v, want ErrInvalidOption", err)
	}
	if _, err := Sign([]byte(keyInfoDocument), SignOptions{PrivateKey: rsaA, Prefix: "xmlns"}); !errors.Is(err, ErrInvalidOption) {
		t.Fatalf("reserved xmlns prefix error = %v, want ErrInvalidOption", err)
	}
	if _, err := Sign([]byte(keyInfoDocument), SignOptions{PrivateKey: rsaA, ID: "missing"}); !errors.Is(err, ErrReference) {
		t.Fatalf("unknown ID error = %v, want ErrReference", err)
	}
	if _, err := Sign([]byte("<root>"), SignOptions{PrivateKey: rsaA}); !errors.Is(err, ErrInvalidXML) {
		t.Fatalf("invalid XML error = %v, want ErrInvalidXML", err)
	}
	if _, err := Sign([]byte(`<root><a ID="x"/><b ID="x"/></root>`), SignOptions{PrivateKey: rsaA, ID: "x"}); !errors.Is(err, ErrDuplicateID) {
		t.Fatalf("duplicate ID error = %v, want ErrDuplicateID", err)
	}
}

// TestKeyInfoKeyNameOnlyRejected checks that a KeyName plus embedded public key is still untrusted
// key material. | TestKeyInfoKeyNameOnlyRejected 校验 KeyName 加内嵌公钥仍属于不可信密钥材料。
func TestKeyInfoKeyNameOnlyRejected(t *testing.T) {
	key := testRSAPrivateKey(t)
	signed, err := Sign([]byte(keyInfoDocument), SignOptions{PrivateKey: key, ID: "order-1", IncludeKeyInfo: true, KeyName: "signing-key"})
	if err != nil {
		t.Fatalf("Sign RSA: %v", err)
	}
	if !bytes.Contains(signed, []byte("<KeyName>signing-key</KeyName>")) {
		t.Fatalf("KeyName missing: %s", signed)
	}
	if _, err := VerifyElement(signed, "order-1", VerifyOptions{}); !errors.Is(err, ErrUntrustedKey) {
		t.Fatalf("KeyName-only error = %v, want ErrUntrustedKey", err)
	}
	if _, err := VerifyElement(signed, "order-1", VerifyOptions{TrustKeyInfo: true}); err != nil {
		t.Fatalf("TrustKeyInfo verification: %v", err)
	}

	secret := []byte("0123456789abcdef")
	hmacSigned, err := Sign([]byte(keyInfoDocument), SignOptions{HMACKey: secret, ID: "order-1", IncludeKeyInfo: true, KeyName: "hmac-key"})
	if err != nil {
		t.Fatalf("Sign HMAC: %v", err)
	}
	if _, err := VerifyElement(hmacSigned, "order-1", VerifyOptions{HMACKey: secret, AllowedSignatureMethods: []string{sigHMACSHA256URI}}); err != nil {
		t.Fatalf("HMAC verification: %v", err)
	}
}

// TestParseKeyInfoSelectorsDigestLength guards fixed-length selector comparison. |
// TestParseKeyInfoSelectorsDigestLength 防止长度不同的摘要选择器误匹配。
func TestParseKeyInfoSelectorsDigestLength(t *testing.T) {
	key := testRSAPrivateKey(t)
	cert := testCertificate(t, key)
	short := computeDigest(digestSpecs[digestSHA256URI], cert.Raw)[:16]
	info := &parsedKeyInfo{digests: []x509Digest{{algorithm: digestSHA256URI, value: short}}}
	if ok, err := info.matchesCertificate(cert); err != nil || ok {
		t.Fatalf("short digest matched: %v, %v", ok, err)
	}
}
