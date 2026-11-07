package kmip

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"errors"
	"math/big"
	"net"
	"testing"
	"time"
)

// selfSignedCertificate returns a self-signed server or client certificate. |
// selfSignedCertificate 返回自签名的服务器或客户端证书。
func selfSignedCertificate(t *testing.T, commonName string, server bool) (tls.Certificate, *x509.Certificate) {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("generate certificate key: %v | 生成证书密钥失败：%v", err, err)
	}
	template := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: commonName},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(time.Hour),
		KeyUsage:              x509.KeyUsageDigitalSignature | x509.KeyUsageCertSign,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth},
		BasicConstraintsValid: true,
		IsCA:                  true,
	}
	if server {
		template.ExtKeyUsage = []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}
		template.IPAddresses = []net.IP{net.ParseIP("127.0.0.1")}
	}
	der, err := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
	if err != nil {
		t.Fatalf("create certificate: %v | 创建证书失败：%v", err, err)
	}
	keyDER, err := x509.MarshalECPrivateKey(key)
	if err != nil {
		t.Fatalf("marshal certificate key: %v | 序列化证书密钥失败：%v", err, err)
	}
	certificate, err := tls.X509KeyPair(
		pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}),
		pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: keyDER}),
	)
	if err != nil {
		t.Fatalf("load certificate: %v | 加载证书失败：%v", err, err)
	}
	parsed, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatalf("parse certificate: %v | 解析证书失败：%v", err, err)
	}
	return certificate, parsed
}

// startTLSTestServer starts a mutual-TLS server on an ephemeral loopback listener. |
// startTLSTestServer 在回环临时端口上启动双向 TLS 服务器。
func startTLSTestServer(t *testing.T, serverCertificate tls.Certificate, clientCAs *x509.CertPool) string {
	t.Helper()
	server, err := NewServer(ServerConfig{
		Store: NewMemoryStore(),
		TLSConfig: &tls.Config{
			Certificates: []tls.Certificate{serverCertificate},
			ClientAuth:   tls.RequireAndVerifyClientCert,
			ClientCAs:    clientCAs,
			MinVersion:   tls.VersionTLS12,
		},
	})
	if err != nil {
		t.Fatalf("NewServer: %v", err)
	}
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	tlsListener := tls.NewListener(listener, server.cfg.TLSConfig.Clone())
	done := make(chan struct{})
	go func() {
		defer close(done)
		_ = server.ServeListener(tlsListener)
	}()
	t.Cleanup(func() {
		_ = server.Close()
		select {
		case <-done:
		case <-time.After(5 * time.Second):
			t.Error("TLS server did not stop | TLS 服务器未停止")
		}
	})
	return listener.Addr().String()
}

// TestClientTLSAndMutualTLS covers a successful mutual-TLS request and handshake failures. |
// TestClientTLSAndMutualTLS 覆盖成功的双向 TLS 请求与握手失败。
func TestClientTLSAndMutualTLS(t *testing.T) {
	serverCertificate, serverParsed := selfSignedCertificate(t, "kmip.test", true)
	clientCertificate, clientParsed := selfSignedCertificate(t, "client.test", false)
	clientRoots := x509.NewCertPool()
	clientRoots.AddCert(serverParsed)
	serverRoots := x509.NewCertPool()
	serverRoots.AddCert(clientParsed)
	address := startTLSTestServer(t, serverCertificate, serverRoots)

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	client, err := DialContext(ctx, ClientConfig{
		Address: address,
		TLSConfig: &tls.Config{
			RootCAs:      clientRoots,
			ServerName:   "127.0.0.1",
			Certificates: []tls.Certificate{clientCertificate},
			MinVersion:   tls.VersionTLS12,
		},
	})
	if err != nil {
		t.Fatalf("mutual TLS DialContext: %v | 双向 TLS 拨号失败：%v", err, err)
	}
	defer func() { _ = client.Close() }()
	query, err := client.Query(ctx, QueryRequest{QueryFunctions: []QueryFunction{QueryFunctionOperations}})
	if err != nil || len(query.Operations) == 0 {
		t.Fatalf("mutual TLS Query = %+v, %v | 双向 TLS 查询 = %+v，%v", query, err, query, err)
	}

	noCertificate, err := DialContext(ctx, ClientConfig{
		Address:   address,
		TLSConfig: &tls.Config{RootCAs: clientRoots, ServerName: "127.0.0.1", MinVersion: tls.VersionTLS12},
	})
	if err == nil {
		// TLS 1.3 clients may complete the handshake before the server verifies the certificate, so
		// the rejection can surface on the first application read. | TLS 1.3 客户端可能在服务器校验证书前
		// 完成握手，因此拒绝可能要到首次应用读取时才显现。
		_, err = noCertificate.Query(ctx, QueryRequest{QueryFunctions: []QueryFunction{QueryFunctionOperations}})
		_ = noCertificate.Close()
	}
	if err == nil {
		t.Fatal("TLS without client certificate was accepted | 缺少客户端证书的 TLS 被接受")
	}
	if _, err := DialContext(ctx, ClientConfig{
		Address: address,
		TLSConfig: &tls.Config{
			RootCAs:      x509.NewCertPool(),
			ServerName:   "127.0.0.1",
			Certificates: []tls.Certificate{clientCertificate},
			MinVersion:   tls.VersionTLS12,
		},
	}); !errors.Is(err, ErrAuthenticationFailed) {
		t.Fatalf("TLS with unknown CA error = %v | 未知 CA 错误 = %v", err, err)
	}
}

// TestServerRejectsPlaintextConnections verifies TLS is enforced on Serve and ListenAndServe. |
// TestServerRejectsPlaintextConnections 验证 Serve 与 ListenAndServe 强制 TLS。
func TestServerRejectsPlaintextConnections(t *testing.T) {
	serverCertificate, _ := selfSignedCertificate(t, "kmip.test", true)
	server, err := NewServer(ServerConfig{TLSConfig: &tls.Config{Certificates: []tls.Certificate{serverCertificate}}})
	if err != nil {
		t.Fatalf("NewServer: %v", err)
	}
	defer func() { _ = server.Close() }()
	plain, peer := net.Pipe()
	defer func() { _ = peer.Close() }()
	if err := server.Serve(plain); !errors.Is(err, ErrTLSRequired) {
		t.Fatalf("Serve plaintext error = %v | Serve 明文错误 = %v", err, err)
	}
	plaintext, err := NewServer(ServerConfig{Address: "127.0.0.1:0"})
	if err != nil {
		t.Fatalf("NewServer plaintext: %v", err)
	}
	defer func() { _ = plaintext.Close() }()
	if err := plaintext.ListenAndServe(); !errors.Is(err, ErrTLSRequired) {
		t.Fatalf("ListenAndServe without TLS error = %v | 无 TLS 监听错误 = %v", err, err)
	}
}
