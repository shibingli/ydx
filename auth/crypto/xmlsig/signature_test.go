package xmlsig

import (
	"bytes"
	"crypto/elliptic"
	"crypto/x509"
	"errors"
	"testing"
	"time"
)

// testDocument is the fixture used by signing tests. | testDocument 是签名测试使用的固定文档。
const testDocument = `<root><order ID="order-1"><amount>42</amount></order><other>x</other></root>`

// TestSignVerifyRoundTrips signs and verifies one document with every key family. |
// TestSignVerifyRoundTrips 使用每种密钥族对同一文档执行签名与校验。
func TestSignVerifyRoundTrips(t *testing.T) {
	rsaKey := testRSAPrivateKey(t)
	rsaCert := testCertificate(t, rsaKey)
	ec256 := testECDSAPrivateKey(t, elliptic.P256())
	ec256Cert := testCertificate(t, ec256)
	ec384 := testECDSAPrivateKey(t, elliptic.P384())
	ec384Cert := testCertificate(t, ec384)
	ec521 := testECDSAPrivateKey(t, elliptic.P521())
	ec521Cert := testCertificate(t, ec521)
	edKey := testEd25519PrivateKey(t)
	edCert := testCertificate(t, edKey)
	hmacKey := []byte("0123456789abcdef0123456789abcdef")
	sm2Key := testSM2Key(t)

	cases := []struct {
		name   string
		sign   SignOptions
		verify VerifyOptions
	}{
		{
			name:   "rsa-pkcs1-sha256",
			sign:   SignOptions{PrivateKey: rsaKey, Certificate: rsaCert, ID: "order-1", IncludeKeyInfo: true},
			verify: VerifyOptions{Certificates: []*x509.Certificate{rsaCert}},
		},
		{
			name:   "rsa-pss-sha256",
			sign:   SignOptions{PrivateKey: rsaKey, Certificate: rsaCert, ID: "order-1", IncludeKeyInfo: true, SignatureMethod: sigRSAPSSSHA256URI},
			verify: VerifyOptions{Certificates: []*x509.Certificate{rsaCert}},
		},
		{
			name:   "ecdsa-p256",
			sign:   SignOptions{PrivateKey: ec256, Certificate: ec256Cert, ID: "order-1", IncludeKeyInfo: true},
			verify: VerifyOptions{Certificates: []*x509.Certificate{ec256Cert}},
		},
		{
			name:   "ecdsa-p384",
			sign:   SignOptions{PrivateKey: ec384, Certificate: ec384Cert, ID: "order-1", IncludeKeyInfo: true},
			verify: VerifyOptions{Certificates: []*x509.Certificate{ec384Cert}},
		},
		{
			name:   "ecdsa-p521",
			sign:   SignOptions{PrivateKey: ec521, Certificate: ec521Cert, ID: "order-1", IncludeKeyInfo: true},
			verify: VerifyOptions{Certificates: []*x509.Certificate{ec521Cert}},
		},
		{
			name:   "ed25519",
			sign:   SignOptions{PrivateKey: edKey, Certificate: edCert, ID: "order-1", IncludeKeyInfo: true},
			verify: VerifyOptions{Certificates: []*x509.Certificate{edCert}},
		},
		{
			name:   "hmac-sha256",
			sign:   SignOptions{HMACKey: hmacKey, ID: "order-1"},
			verify: VerifyOptions{HMACKey: hmacKey, AllowedSignatureMethods: []string{sigHMACSHA256URI}},
		},
		{
			name:   "sm2-sm3",
			sign:   SignOptions{SM2Key: sm2Key, ID: "order-1"},
			verify: VerifyOptions{SM2PublicKey: sm2Key.Public()},
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			signed, err := Sign([]byte(testDocument), tc.sign)
			if err != nil {
				t.Fatalf("Sign: %v", err)
			}
			result, err := VerifyElement(signed, "order-1", tc.verify)
			if err != nil {
				t.Fatalf("VerifyElement: %v", err)
			}
			if result.ReferenceURI != "#order-1" || result.SignedElementID != "order-1" {
				t.Fatalf("unexpected result: %+v", result)
			}
			if result.SignatureMethod == "" || result.DigestMethod == "" {
				t.Fatalf("missing algorithm metadata: %+v", result)
			}
			tampered := bytes.Replace(signed, []byte("<amount>42</amount>"), []byte("<amount>43</amount>"), 1)
			if _, err := VerifyElement(tampered, "order-1", tc.verify); !errors.Is(err, ErrDigestMismatch) {
				t.Fatalf("tampered verification error = %v, want ErrDigestMismatch", err)
			}
		})
	}
}

// TestSignVerifyRoot checks reference URI "" and root element binding. | TestSignVerifyRoot 校验
// 引用 URI "" 与根元素绑定。
func TestSignVerifyRoot(t *testing.T) {
	key := testRSAPrivateKey(t)
	cert := testCertificate(t, key)
	signed, err := Sign([]byte(`<root ID="r"><a/></root>`), SignOptions{PrivateKey: key, Certificate: cert, IncludeKeyInfo: true})
	if err != nil {
		t.Fatalf("Sign: %v", err)
	}
	result, err := Verify(signed, VerifyOptions{Certificates: []*x509.Certificate{cert}})
	if err != nil {
		t.Fatalf("Verify: %v", err)
	}
	if result.ReferenceURI != "" {
		t.Fatalf("ReferenceURI = %q, want empty", result.ReferenceURI)
	}
	if _, err := VerifyElement(signed, "r", VerifyOptions{Certificates: []*x509.Certificate{cert}}); err != nil {
		t.Fatalf("VerifyElement root: %v", err)
	}
}

// TestVerifyElementNestedSignatures is the SAML regression: a signed Assertion inside a signed
// Response must be verifiable by each ID without an ambiguity error. |
// TestVerifyElementNestedSignatures 是 SAML 回归：已签名 Response 中的已签名 Assertion 必须能按
// 各自 ID 独立校验，且不出现歧义错误。
func TestVerifyElementNestedSignatures(t *testing.T) {
	key := testRSAPrivateKey(t)
	cert := testCertificate(t, key)
	opts := VerifyOptions{Certificates: []*x509.Certificate{cert}}
	doc := []byte(`<Response ID="resp"><Assertion ID="assert"><Subject>alice</Subject></Assertion></Response>`)

	assertionSigned, err := Sign(doc, SignOptions{PrivateKey: key, Certificate: cert, ID: "assert", IncludeKeyInfo: true})
	if err != nil {
		t.Fatalf("Sign assertion: %v", err)
	}
	responseSigned, err := Sign(assertionSigned, SignOptions{PrivateKey: key, Certificate: cert, ID: "resp", IncludeKeyInfo: true})
	if err != nil {
		t.Fatalf("Sign response: %v", err)
	}
	if _, err := VerifyElement(responseSigned, "resp", opts); err != nil {
		t.Fatalf("VerifyElement response: %v", err)
	}
	if _, err := VerifyElement(responseSigned, "assert", opts); err != nil {
		t.Fatalf("VerifyElement assertion: %v", err)
	}
}

// TestDetachedSignature checks detached signing and verification after re-embedding the Signature
// outside the referenced subtree. | TestDetachedSignature 校验分离签名，并在把 Signature 重新嵌入
// 引用子树之外后执行验证。
func TestDetachedSignature(t *testing.T) {
	key := testRSAPrivateKey(t)
	cert := testCertificate(t, key)
	doc := []byte(`<root><order ID="order-1"><amount>42</amount></order><other>x</other></root>`)
	signature, err := Sign(doc, SignOptions{PrivateKey: key, Certificate: cert, ID: "order-1", Detached: true})
	if err != nil {
		t.Fatalf("Sign detached: %v", err)
	}
	if bytes.Contains(signature, []byte("<order")) || bytes.Contains(signature, []byte("<amount>")) {
		t.Fatalf("detached signature contains the input document: %s", signature)
	}
	marker := []byte("<other>")
	embedded := append(append([]byte(nil), signature...), marker...)
	combined := bytes.Replace(doc, marker, embedded, 1)
	result, err := VerifyElement(combined, "order-1", VerifyOptions{Certificates: []*x509.Certificate{cert}})
	if err != nil {
		t.Fatalf("VerifyElement detached: %v", err)
	}
	if result.ReferenceURI != "#order-1" {
		t.Fatalf("ReferenceURI = %q, want #order-1", result.ReferenceURI)
	}
	tampered := bytes.Replace(combined, []byte("<amount>42</amount>"), []byte("<amount>43</amount>"), 1)
	if _, err := VerifyElement(tampered, "order-1", VerifyOptions{Certificates: []*x509.Certificate{cert}}); !errors.Is(err, ErrDigestMismatch) {
		t.Fatalf("tampered detached document error = %v, want ErrDigestMismatch", err)
	}
}

// TestMultipleSignaturesRejected checks that two signatures bound to one element are rejected. |
// TestMultipleSignaturesRejected 校验绑定到同一元素的两个签名会被拒绝。
func TestMultipleSignaturesRejected(t *testing.T) {
	key := testRSAPrivateKey(t)
	cert := testCertificate(t, key)
	opts := VerifyOptions{Certificates: []*x509.Certificate{cert}}
	signed, err := Sign([]byte(testDocument), SignOptions{PrivateKey: key, ID: "order-1"})
	if err != nil {
		t.Fatalf("Sign: %v", err)
	}
	signed, err = Sign(signed, SignOptions{PrivateKey: key, ID: "order-1"})
	if err != nil {
		t.Fatalf("Sign again: %v", err)
	}
	if _, err := VerifyElement(signed, "order-1", opts); !errors.Is(err, ErrMultipleSignatures) {
		t.Fatalf("VerifyElement error = %v, want ErrMultipleSignatures", err)
	}
}

// TestDuplicateIDsRejected checks duplicate identifiers at signing and verification time. |
// TestDuplicateIDsRejected 校验签名与校验阶段的重复标识。
func TestDuplicateIDsRejected(t *testing.T) {
	key := testRSAPrivateKey(t)
	cert := testCertificate(t, key)
	duplicate := []byte(`<root><a ID="x"/><b ID="x"/></root>`)
	if _, err := Sign(duplicate, SignOptions{PrivateKey: key, ID: "x"}); !errors.Is(err, ErrDuplicateID) {
		t.Fatalf("Sign error = %v, want ErrDuplicateID", err)
	}
	signed, err := Sign([]byte(testDocument), SignOptions{PrivateKey: key, ID: "order-1"})
	if err != nil {
		t.Fatalf("Sign: %v", err)
	}
	wrapped := bytes.Replace(signed, []byte("</root>"), []byte(`<evil ID="order-1"/></root>`), 1)
	if _, err := VerifyElement(wrapped, "order-1", VerifyOptions{Certificates: []*x509.Certificate{cert}}); !errors.Is(err, ErrDuplicateID) {
		t.Fatalf("VerifyElement error = %v, want ErrDuplicateID", err)
	}
}

// TestUnsupportedTransformsAndReferences checks XPath and external reference rejection. |
// TestUnsupportedTransformsAndReferences 校验 XPath 与外部引用拒绝。
func TestUnsupportedTransformsAndReferences(t *testing.T) {
	key := testRSAPrivateKey(t)
	cert := testCertificate(t, key)
	opts := VerifyOptions{Certificates: []*x509.Certificate{cert}}
	signed, err := Sign([]byte(testDocument), SignOptions{PrivateKey: key, ID: "order-1"})
	if err != nil {
		t.Fatalf("Sign: %v", err)
	}
	xpath := bytes.Replace(signed, []byte(transformEnvelopedURI), []byte("http://www.w3.org/TR/1999/REC-xpath-19991116"), 1)
	if _, err := Verify(xpath, opts); !errors.Is(err, ErrUnsupported) {
		t.Fatalf("XPath transform error = %v, want ErrUnsupported", err)
	}
	external := bytes.Replace(signed, []byte(`URI="#order-1"`), []byte(`URI="http://example.com/order"`), 1)
	if _, err := Verify(external, opts); !errors.Is(err, ErrReference) {
		t.Fatalf("external reference error = %v, want ErrReference", err)
	}
}

// TestSHA1AndHMACOptIn checks that weak algorithms require explicit allowlists. |
// TestSHA1AndHMACOptIn 校验弱算法必须显式加入允许列表。
func TestSHA1AndHMACOptIn(t *testing.T) {
	key := testRSAPrivateKey(t)
	cert := testCertificate(t, key)
	signed, err := Sign([]byte(testDocument), SignOptions{PrivateKey: key, ID: "order-1", SignatureMethod: sigRSASHA1URI, DigestMethod: digestSHA1URI})
	if err != nil {
		t.Fatalf("Sign SHA-1: %v", err)
	}
	if _, err := VerifyElement(signed, "order-1", VerifyOptions{Certificates: []*x509.Certificate{cert}}); !errors.Is(err, ErrAlgorithmNotAllowed) {
		t.Fatalf("SHA-1 default error = %v, want ErrAlgorithmNotAllowed", err)
	}
	if _, err := VerifyElement(signed, "order-1", VerifyOptions{
		Certificates:            []*x509.Certificate{cert},
		AllowedSignatureMethods: []string{sigRSASHA1URI},
		AllowedDigestMethods:    []string{digestSHA1URI},
	}); err != nil {
		t.Fatalf("SHA-1 opt-in: %v", err)
	}

	secret := []byte("hmac-secret-for-xmlsig-tests-01")
	hmacSigned, err := Sign([]byte(testDocument), SignOptions{HMACKey: secret, ID: "order-1"})
	if err != nil {
		t.Fatalf("Sign HMAC: %v", err)
	}
	if _, err := VerifyElement(hmacSigned, "order-1", VerifyOptions{HMACKey: secret}); !errors.Is(err, ErrAlgorithmNotAllowed) {
		t.Fatalf("HMAC default error = %v, want ErrAlgorithmNotAllowed", err)
	}
	if _, err := VerifyElement(hmacSigned, "order-1", VerifyOptions{HMACKey: secret, AllowedSignatureMethods: []string{sigHMACSHA256URI}}); err != nil {
		t.Fatalf("HMAC opt-in: %v", err)
	}
}

// TestCertificateValidation checks expiry, key usage, trust and chain handling. |
// TestCertificateValidation 校验过期、密钥用途、信任与证书链处理。
func TestCertificateValidation(t *testing.T) {
	key := testRSAPrivateKey(t)
	expired := testCertificateWith(t, key, key, time.Now().Add(-2*time.Hour), time.Now().Add(-time.Hour), x509.KeyUsageDigitalSignature)
	expiredSigned, err := Sign([]byte(testDocument), SignOptions{PrivateKey: key, Certificate: expired, ID: "order-1", IncludeKeyInfo: true})
	if err != nil {
		t.Fatalf("Sign expired: %v", err)
	}
	if _, err := VerifyElement(expiredSigned, "order-1", VerifyOptions{Certificates: []*x509.Certificate{expired}}); !errors.Is(err, ErrCertificateInvalid) {
		t.Fatalf("expired certificate error = %v, want ErrCertificateInvalid", err)
	}

	badUsage := testCertificateWith(t, key, key, time.Now().Add(-time.Hour), time.Now().Add(time.Hour), x509.KeyUsageCertSign)
	badUsageSigned, err := Sign([]byte(testDocument), SignOptions{PrivateKey: key, Certificate: badUsage, ID: "order-1", IncludeKeyInfo: true})
	if err != nil {
		t.Fatalf("Sign bad usage: %v", err)
	}
	if _, err := VerifyElement(badUsageSigned, "order-1", VerifyOptions{Certificates: []*x509.Certificate{badUsage}}); !errors.Is(err, ErrCertificateInvalid) {
		t.Fatalf("key usage error = %v, want ErrCertificateInvalid", err)
	}

	caCert, leafCert := testCA(t, key)
	leafSigned, err := Sign([]byte(testDocument), SignOptions{PrivateKey: key, Certificate: leafCert, ID: "order-1", IncludeKeyInfo: true})
	if err != nil {
		t.Fatalf("Sign leaf: %v", err)
	}
	roots := x509.NewCertPool()
	roots.AddCert(caCert)
	if _, err := VerifyElement(leafSigned, "order-1", VerifyOptions{Roots: roots}); err != nil {
		t.Fatalf("chain verification: %v", err)
	}
	if _, err := VerifyElement(leafSigned, "order-1", VerifyOptions{}); !errors.Is(err, ErrUntrustedKey) {
		t.Fatalf("untrusted KeyInfo error = %v, want ErrUntrustedKey", err)
	}

	otherKey := testRSAPrivateKey(t)
	otherCert := testCertificate(t, otherKey)
	if _, err := VerifyElement(leafSigned, "order-1", VerifyOptions{Certificates: []*x509.Certificate{otherCert}}); !errors.Is(err, ErrSignatureInvalid) {
		t.Fatalf("wrong certificate error = %v, want ErrSignatureInvalid", err)
	}
}

// TestWrongKeyRejected checks that an unrelated RSA key fails verification. |
// TestWrongKeyRejected 校验无关 RSA 密钥无法通过验证。
func TestWrongKeyRejected(t *testing.T) {
	key := testRSAPrivateKey(t)
	signed, err := Sign([]byte(testDocument), SignOptions{PrivateKey: key, ID: "order-1"})
	if err != nil {
		t.Fatalf("Sign: %v", err)
	}
	other := testRSAPrivateKey(t)
	otherCert := testCertificate(t, other)
	if _, err := VerifyElement(signed, "order-1", VerifyOptions{Certificates: []*x509.Certificate{otherCert}}); !errors.Is(err, ErrSignatureInvalid) {
		t.Fatalf("wrong key error = %v, want ErrSignatureInvalid", err)
	}
}
