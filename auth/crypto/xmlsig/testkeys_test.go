package xmlsig

import (
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"math/big"
	"testing"
	"time"

	"github.com/shibingli/ydx/guomi"
)

// testRSAPrivateKey returns a fresh RSA private key. | testRSAPrivateKey 返回新的 RSA 私钥。
func testRSAPrivateKey(t *testing.T) *rsa.PrivateKey {
	t.Helper()
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("rsa.GenerateKey: %v", err)
	}
	return key
}

// testECDSAPrivateKey returns a fresh ECDSA private key on curve. | testECDSAPrivateKey 返回 curve
// 上的新 ECDSA 私钥。
func testECDSAPrivateKey(t *testing.T, curve elliptic.Curve) *ecdsa.PrivateKey {
	t.Helper()
	key, err := ecdsa.GenerateKey(curve, rand.Reader)
	if err != nil {
		t.Fatalf("ecdsa.GenerateKey: %v", err)
	}
	return key
}

// testEd25519PrivateKey returns a fresh Ed25519 private key. | testEd25519PrivateKey 返回新的
// Ed25519 私钥。
func testEd25519PrivateKey(t *testing.T) ed25519.PrivateKey {
	t.Helper()
	_, key, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("ed25519.GenerateKey: %v", err)
	}
	return key
}

// testCertificate issues a self-signed certificate for key. | testCertificate 为 key 签发自签名证书。
func testCertificate(t *testing.T, key any) *x509.Certificate {
	t.Helper()
	return testCertificateWith(t, key, key, time.Now().Add(-time.Hour), time.Now().Add(time.Hour), x509.KeyUsageDigitalSignature)
}

// testCertificateWith issues a certificate for subjectKey, signed by signerKey. |
// testCertificateWith 为 subjectKey 签发由 signerKey 签名的证书。
func testCertificateWith(t *testing.T, signerKey, subjectKey any, notBefore, notAfter time.Time, usage x509.KeyUsage) *x509.Certificate {
	t.Helper()
	template := &x509.Certificate{
		SerialNumber: big.NewInt(time.Now().UnixNano()),
		Subject:      pkix.Name{CommonName: "xmlsig test"},
		NotBefore:    notBefore,
		NotAfter:     notAfter,
		KeyUsage:     usage,
	}
	publicKey := subjectKey
	if signer, ok := subjectKey.(interface{ Public() any }); ok {
		publicKey = signer.Public()
	}
	switch k := subjectKey.(type) {
	case *rsa.PrivateKey:
		publicKey = &k.PublicKey
	case *ecdsa.PrivateKey:
		publicKey = &k.PublicKey
	case ed25519.PrivateKey:
		publicKey = k.Public()
	}
	der, err := x509.CreateCertificate(rand.Reader, template, template, publicKey, signerKey)
	if err != nil {
		t.Fatalf("x509.CreateCertificate: %v", err)
	}
	cert, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatalf("x509.ParseCertificate: %v", err)
	}
	return cert
}

// testCA issues a CA certificate and a leaf certificate for leafKey. | testCA 签发 CA 证书与
// leafKey 的叶证书。
func testCA(t *testing.T, leafKey any) (*x509.Certificate, *x509.Certificate) {
	t.Helper()
	caKey := testRSAPrivateKey(t)
	caTemplate := &x509.Certificate{
		SerialNumber:          big.NewInt(time.Now().UnixNano()),
		Subject:               pkix.Name{CommonName: "xmlsig test CA"},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(time.Hour),
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageCRLSign,
		BasicConstraintsValid: true,
		IsCA:                  true,
	}
	caDER, err := x509.CreateCertificate(rand.Reader, caTemplate, caTemplate, &caKey.PublicKey, caKey)
	if err != nil {
		t.Fatalf("x509.CreateCertificate CA: %v", err)
	}
	caCert, err := x509.ParseCertificate(caDER)
	if err != nil {
		t.Fatalf("x509.ParseCertificate CA: %v", err)
	}
	leafTemplate := &x509.Certificate{
		SerialNumber: big.NewInt(time.Now().UnixNano() + 1),
		Subject:      pkix.Name{CommonName: "xmlsig test leaf"},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(time.Hour),
		KeyUsage:     x509.KeyUsageDigitalSignature,
	}
	leafPublic := leafKey
	switch k := leafKey.(type) {
	case *rsa.PrivateKey:
		leafPublic = &k.PublicKey
	case *ecdsa.PrivateKey:
		leafPublic = &k.PublicKey
	}
	leafDER, err := x509.CreateCertificate(rand.Reader, leafTemplate, caCert, leafPublic, caKey)
	if err != nil {
		t.Fatalf("x509.CreateCertificate leaf: %v", err)
	}
	leafCert, err := x509.ParseCertificate(leafDER)
	if err != nil {
		t.Fatalf("x509.ParseCertificate leaf: %v", err)
	}
	return caCert, leafCert
}

// testSM2Key returns a fresh SM2 private key. | testSM2Key 返回新的 SM2 私钥。
func testSM2Key(t *testing.T) *guomi.PrivateKey {
	t.Helper()
	key, err := guomi.GenerateKey()
	if err != nil {
		t.Fatalf("guomi.GenerateKey: %v", err)
	}
	return key
}
