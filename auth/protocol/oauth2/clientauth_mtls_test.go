package oauth2

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"errors"
	"math/big"
	"net/http"
	"testing"
	"time"
)

// testClientCertificate returns a self-signed certificate for mTLS tests. | testClientCertificate
// 返回用于 mTLS 测试的自签名证书。
func testClientCertificate(t *testing.T, subject string, dns []string) *x509.Certificate {
	t.Helper()
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("GenerateKey: %v", err)
	}
	template := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: subject},
		DNSNames:              dns,
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(time.Hour),
		KeyUsage:              x509.KeyUsageDigitalSignature | x509.KeyUsageCertSign,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth},
		BasicConstraintsValid: true,
		IsCA:                  true,
	}
	der, err := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
	if err != nil {
		t.Fatalf("CreateCertificate: %v", err)
	}
	cert, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatalf("ParseCertificate: %v", err)
	}
	return cert
}

// testTLSRequest returns a request carrying peerCert as the client certificate. | testTLSRequest
// 返回携带 peerCert 作为客户端证书的请求。
func testTLSRequest(peerCert *x509.Certificate) *http.Request {
	req, _ := http.NewRequest(http.MethodPost, "/token", nil)
	req.TLS = &tls.ConnectionState{PeerCertificates: []*x509.Certificate{peerCert}}
	return req
}

// TestVerifyTLSClient covers RFC 8705 subject/SAN binding and self-signed mode. |
// TestVerifyTLSClient 覆盖 RFC 8705 主体/SAN 绑定与自签名模式。
func TestVerifyTLSClient(t *testing.T) {
	cert := testClientCertificate(t, "client.example", []string{"client.example"})
	subjectDN := cert.Subject.String()

	t.Run("subject-match", func(t *testing.T) {
		client := &Client{ID: "mtls", TLSClientAuthSubjectDN: subjectDN}
		if err := verifyTLSClient(testTLSRequest(cert), client, TLSClientAuth); err != nil {
			t.Fatalf("verifyTLSClient: %v", err)
		}
	})
	t.Run("san-match", func(t *testing.T) {
		client := &Client{ID: "mtls", TLSClientAuthSANs: []string{"client.example"}}
		if err := verifyTLSClient(testTLSRequest(cert), client, TLSClientAuth); err != nil {
			t.Fatalf("verifyTLSClient: %v", err)
		}
	})
	t.Run("self-signed", func(t *testing.T) {
		client := &Client{ID: "mtls", TLSClientAuthSANs: []string{"client.example"}}
		if err := verifyTLSClient(testTLSRequest(cert), client, SelfSignedTLSClientAuth); err != nil {
			t.Fatalf("verifyTLSClient: %v", err)
		}
	})
	t.Run("missing-certificate", func(t *testing.T) {
		req, _ := http.NewRequest(http.MethodPost, "/token", nil)
		if err := verifyTLSClient(req, &Client{ID: "mtls"}, TLSClientAuth); !errors.Is(err, ErrInvalidClient) {
			t.Fatalf("error = %v, want ErrInvalidClient", err)
		}
	})
	t.Run("subject-mismatch", func(t *testing.T) {
		client := &Client{ID: "mtls", TLSClientAuthSubjectDN: "CN=other"}
		if err := verifyTLSClient(testTLSRequest(cert), client, TLSClientAuth); !errors.Is(err, ErrInvalidClient) {
			t.Fatalf("error = %v, want ErrInvalidClient", err)
		}
	})
	t.Run("san-mismatch", func(t *testing.T) {
		client := &Client{ID: "mtls", TLSClientAuthSANs: []string{"other.example"}}
		if err := verifyTLSClient(testTLSRequest(cert), client, TLSClientAuth); !errors.Is(err, ErrInvalidClient) {
			t.Fatalf("error = %v, want ErrInvalidClient", err)
		}
	})
}
