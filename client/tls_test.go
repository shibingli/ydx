package client

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"encoding/pem"
	"errors"
	"math/big"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"testing"
	"time"
)

func newTestTLSServer(t *testing.T, handler http.Handler) (*httptest.Server, *x509.Certificate) {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	template := &x509.Certificate{
		SerialNumber:          big.NewInt(time.Now().UnixNano()),
		Subject:               pkix.Name{CommonName: "ydx-test"},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(time.Hour),
		KeyUsage:              x509.KeyUsageDigitalSignature | x509.KeyUsageCertSign,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		BasicConstraintsValid: true,
		IsCA:                  true,
		IPAddresses:           []net.IP{net.IPv4(127, 0, 0, 1)},
		DNSNames:              []string{"example.com"},
	}
	der, err := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	leaf, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatal(err)
	}
	srv := httptest.NewUnstartedServer(handler)
	srv.TLS = &tls.Config{Certificates: []tls.Certificate{{
		Certificate: [][]byte{der},
		PrivateKey:  key,
		Leaf:        leaf,
	}}}
	srv.StartTLS()
	return srv, leaf
}

func testCertPool(cert *x509.Certificate) *x509.CertPool {
	pool := x509.NewCertPool()
	pool.AddCert(cert)
	return pool
}

func testPin(cert *x509.Certificate) string {
	sum := sha256.Sum256(cert.RawSubjectPublicKeyInfo)
	return base64.StdEncoding.EncodeToString(sum[:])
}

func writeCertPEM(t *testing.T, cert *x509.Certificate, path string) {
	t.Helper()
	data := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: cert.Raw})
	if err := os.WriteFile(path, data, 0o600); err != nil {
		t.Fatal(err)
	}
}

func TestTLSPrivateCAAndPinning(t *testing.T) {
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte("tls"))
	}))
	defer srv.Close()
	cert := srv.Certificate()

	c, err := New(WithTLS(TLSConfig{
		RootCAs:            testCertPool(cert),
		PinSHA256:          []string{testPin(cert)},
		DisableSystemRoots: true,
	}))
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	resp, err := c.Get(context.Background(), srv.URL)
	if err != nil {
		t.Fatal(err)
	}
	data, _ := resp.Bytes()
	if string(data) != "tls" {
		t.Fatalf("body %q", data)
	}

	badPin := base64.StdEncoding.EncodeToString(make([]byte, sha256.Size))
	bad, err := New(WithTLS(TLSConfig{
		RootCAs:            testCertPool(cert),
		PinSHA256:          []string{badPin},
		DisableSystemRoots: true,
	}))
	if err != nil {
		t.Fatal(err)
	}
	defer bad.Close()
	if _, err := bad.Get(context.Background(), srv.URL); !errors.Is(err, ErrTLSPin) {
		t.Fatalf("want ErrTLSPin, got %v", err)
	}
}

func TestTLSInsecureSkipVerify(t *testing.T) {
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {}))
	defer srv.Close()
	c, err := New(WithTLS(TLSConfig{InsecureSkipVerify: true, DisableSystemRoots: true}))
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	if _, err := c.Get(context.Background(), srv.URL); err != nil {
		t.Fatal(err)
	}
}

func TestTLSReload(t *testing.T) {
	srvA, certA := newTestTLSServer(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte("a"))
	}))
	defer srvA.Close()
	srvB, certB := newTestTLSServer(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte("b"))
	}))
	defer srvB.Close()

	rootFile := filepath.Join(t.TempDir(), "root.pem")
	writeCertPEM(t, certA, rootFile)
	c, err := New(
		WithHosts(srvA.URL),
		WithTLS(TLSConfig{RootCAFiles: []string{rootFile}, DisableSystemRoots: true}),
	)
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	if _, err := c.Get(context.Background(), srvA.URL); err != nil {
		t.Fatal(err)
	}

	writeCertPEM(t, certB, rootFile)
	if err := c.ReloadTLS(); err != nil {
		t.Fatal(err)
	}
	if err := c.UpdateHosts(Host{Name: "b", URL: mustURL(srvB.URL)}); err != nil {
		t.Fatal(err)
	}
	resp, err := c.Get(context.Background(), srvB.URL)
	if err != nil {
		t.Fatal(err)
	}
	data, _ := resp.Bytes()
	if string(data) != "b" {
		t.Fatalf("body %q", data)
	}
}

func TestTLSHostOverride(t *testing.T) {
	srvA, certA := newTestTLSServer(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {}))
	defer srvA.Close()
	srvB, certB := newTestTLSServer(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {}))
	defer srvB.Close()

	hostB := mustURL(srvB.URL).Host
	c, err := New(
		WithHosts(srvB.URL),
		WithTLS(TLSConfig{RootCAs: testCertPool(certA), DisableSystemRoots: true}),
		WithHostTLS(hostB, TLSConfig{RootCAs: testCertPool(certB), DisableSystemRoots: true}),
	)
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	if _, err := c.Get(context.Background(), srvB.URL); err != nil {
		t.Fatal(err)
	}

	wrong, err := New(
		WithHosts(srvB.URL),
		WithTLS(TLSConfig{RootCAs: testCertPool(certA), DisableSystemRoots: true}),
	)
	if err != nil {
		t.Fatal(err)
	}
	defer wrong.Close()
	if _, err := wrong.Get(context.Background(), srvB.URL); err == nil {
		t.Fatal("expected verification failure")
	}
}

func TestTLSDirectHostOverride(t *testing.T) {
	srv, cert := newTestTLSServer(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {}))
	defer srv.Close()
	c, err := New(WithHostTLS(srv.URL, TLSConfig{
		RootCAs:            testCertPool(cert),
		DisableSystemRoots: true,
	}))
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	if _, err := c.Get(context.Background(), srv.URL); err != nil {
		t.Fatal(err)
	}
}

func TestTLSHostnameMismatch(t *testing.T) {
	srv, cert := newTestTLSServer(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {}))
	defer srv.Close()
	c, err := New(WithTLS(TLSConfig{
		RootCAs:            testCertPool(cert),
		DisableSystemRoots: true,
	}))
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	logical := mustURL(srv.URL)
	logical.Host = "localhost:" + logical.Port()
	if _, err := c.Get(context.Background(), logical.String()); err == nil {
		t.Fatal("expected hostname mismatch")
	}
}

func TestTLSConfigInvalid(t *testing.T) {
	if _, err := New(WithTLS(TLSConfig{CertFile: "missing.pem", KeyFile: "missing.key"})); !errors.Is(err, ErrTLSConfig) {
		t.Fatalf("missing cert: %v", err)
	}
	if _, err := New(WithTLS(TLSConfig{PinSHA256: []string{"not-base64"}})); !errors.Is(err, ErrTLSConfig) {
		t.Fatalf("bad pin: %v", err)
	}
}

func TestTLSHostField(t *testing.T) {
	srvA, certA := newTestTLSServer(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {}))
	defer srvA.Close()
	srvB, certB := newTestTLSServer(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {}))
	defer srvB.Close()

	hs, err := NewHostSet(Host{
		Name: "b",
		URL:  mustURL(srvB.URL),
		TLS:  &TLSConfig{RootCAs: testCertPool(certB), DisableSystemRoots: true},
	})
	if err != nil {
		t.Fatal(err)
	}
	c, err := New(
		WithHostSet(hs),
		WithRewriteAll(true),
		WithTLS(TLSConfig{RootCAs: testCertPool(certA), DisableSystemRoots: true}),
	)
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	if _, err := c.Get(context.Background(), srvB.URL); err != nil {
		t.Fatal(err)
	}
}

func TestReloadTLSWithoutConfig(t *testing.T) {
	c, err := New()
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	if err := c.ReloadTLS(); err != nil {
		t.Fatal(err)
	}
}

func TestTLSInsecureCounter(t *testing.T) {
	c, err := New(WithTLS(TLSConfig{InsecureSkipVerify: true, DisableSystemRoots: true}))
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	if c.Stats().TLSInsecure != 1 {
		t.Fatalf("tls insecure %d", c.Stats().TLSInsecure)
	}
}

func TestPruneTLSOnUpdateHosts(t *testing.T) {
	cfg := &TLSConfig{InsecureSkipVerify: true, DisableSystemRoots: true}
	hs, err := NewHostSet(Host{Name: "a", URL: mustURL("https://a.example"), TLS: cfg})
	if err != nil {
		t.Fatal(err)
	}
	c, err := New(WithHostSet(hs), WithRewriteAll(true))
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	if _, err := c.engine.stateFor(cfg); err != nil {
		t.Fatal(err)
	}
	if len(c.engine.tlsByConfig) != 1 {
		t.Fatalf("tls states %d", len(c.engine.tlsByConfig))
	}
	if err := c.UpdateHosts(Host{Name: "b", URL: mustURL("http://b.example")}); err != nil {
		t.Fatal(err)
	}
	if len(c.engine.tlsByConfig) != 0 {
		t.Fatalf("tls state was not reclaimed: %d", len(c.engine.tlsByConfig))
	}
}

func TestTLSSessionCacheDisabled(t *testing.T) {
	state, err := newTLSState(TLSConfig{SessionCacheSize: -1}, &http.Transport{})
	if err != nil {
		t.Fatal(err)
	}
	tr := state.current()
	if tr == nil || tr.TLSClientConfig == nil || tr.TLSClientConfig.ClientSessionCache != nil {
		t.Fatal("session cache should be disabled")
	}
}

func TestTLSCallbacksPanicIsolated(t *testing.T) {
	state, err := newTLSState(TLSConfig{
		VerifyConnection: func(tls.ConnectionState) error { panic("verify") },
		GetClientCertificate: func(*tls.CertificateRequestInfo) (*tls.Certificate, error) {
			panic("cert")
		},
	}, &http.Transport{})
	if err != nil {
		t.Fatal(err)
	}
	cfg := state.current().TLSClientConfig
	if err := cfg.VerifyConnection(tls.ConnectionState{}); !errors.Is(err, ErrTLSConfig) {
		t.Fatalf("verify error %v", err)
	}
	if _, err := cfg.GetClientCertificate(&tls.CertificateRequestInfo{}); !errors.Is(err, ErrTLSConfig) {
		t.Fatalf("certificate error %v", err)
	}
}

func TestHostTLSDefaultPortOverride(t *testing.T) {
	c, err := New(WithHostTLS("example.com:443", TLSConfig{}), WithoutCookieJar())
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	state := c.engine.hostTLS["example.com:443"]
	if state == nil {
		t.Fatal("host TLS state missing")
	}
	got := c.engine.transportForURL(&url.URL{Scheme: "https", Host: "example.com"})
	if got != state.current() {
		t.Fatal("default-port host TLS override was not applied")
	}
}
