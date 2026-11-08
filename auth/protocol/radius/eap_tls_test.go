package radius

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"errors"
	"io"
	"math/big"
	"sync"
	"testing"
	"time"
)

// eapTestPKI holds a test CA and leaf certificates. | eapTestPKI 保存测试 CA 与叶子证书。
type eapTestPKI struct {
	roots      *x509.CertPool
	serverCert tls.Certificate
	clientCert tls.Certificate
	clientLeaf *x509.Certificate
}

// newEAPTestPKI creates a CA, a localhost server certificate and a client certificate. | newEAPTestPKI
// 创建 CA、localhost 服务器证书与客户端证书。
func newEAPTestPKI(t *testing.T) *eapTestPKI {
	t.Helper()
	caKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("generate CA key: %v", err)
	}
	now := time.Now()
	caTemplate := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: "ydx radius test CA"},
		NotBefore:             now.Add(-time.Hour),
		NotAfter:              now.Add(time.Hour),
		IsCA:                  true,
		BasicConstraintsValid: true,
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageDigitalSignature,
	}
	caDER, err := x509.CreateCertificate(rand.Reader, caTemplate, caTemplate, &caKey.PublicKey, caKey)
	if err != nil {
		t.Fatalf("create CA certificate: %v", err)
	}
	caCert, err := x509.ParseCertificate(caDER)
	if err != nil {
		t.Fatalf("parse CA certificate: %v", err)
	}
	roots := x509.NewCertPool()
	roots.AddCert(caCert)

	serverLeaf, serverKey := eapTestLeaf(t, caCert, caKey, 2, "localhost", true)
	clientLeaf, clientKey := eapTestLeaf(t, caCert, caKey, 3, "tls-client", false)
	return &eapTestPKI{
		roots:      roots,
		serverCert: tls.Certificate{Certificate: [][]byte{serverLeaf.Raw, caDER}, PrivateKey: serverKey, Leaf: serverLeaf},
		clientCert: tls.Certificate{Certificate: [][]byte{clientLeaf.Raw, caDER}, PrivateKey: clientKey, Leaf: clientLeaf},
		clientLeaf: clientLeaf,
	}
}

// eapTestLeaf issues one signed leaf certificate. | eapTestLeaf 签发一张签名叶子证书。
func eapTestLeaf(t *testing.T, ca *x509.Certificate, caKey *ecdsa.PrivateKey, serial int64, commonName string, server bool) (*x509.Certificate, *ecdsa.PrivateKey) {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("generate leaf key: %v", err)
	}
	usage := x509.ExtKeyUsageClientAuth
	dnsNames := []string(nil)
	if server {
		usage = x509.ExtKeyUsageServerAuth
		dnsNames = []string{"localhost"}
	}
	template := &x509.Certificate{
		SerialNumber: big.NewInt(serial),
		Subject:      pkix.Name{CommonName: commonName},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(time.Hour),
		KeyUsage:     x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{usage},
		DNSNames:     dnsNames,
	}
	der, err := x509.CreateCertificate(rand.Reader, template, ca, &key.PublicKey, caKey)
	if err != nil {
		t.Fatalf("create leaf certificate: %v", err)
	}
	leaf, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatalf("parse leaf certificate: %v", err)
	}
	return leaf, key
}

// eapTestTLSClient drives a crypto/tls client over the EAP TLS bridge. | eapTestTLSClient 在 EAP TLS
// 桥上驱动 crypto/tls 客户端。
type eapTestTLSClient struct {
	conn    *eapTLSConn
	tlsConn *tls.Conn
	done    chan struct{}
	appCh   chan []byte

	mu     sync.Mutex
	err    error
	appErr error
	appRun bool
}

// newEAPTestTLSClient starts a client handshake over an in-memory bridge. | newEAPTestTLSClient 在内存桥
// 上启动客户端握手。
func newEAPTestTLSClient(config *tls.Config) *eapTestTLSClient {
	conn := newEAPTLSEngineConn()
	client := &eapTestTLSClient{
		conn:    conn,
		tlsConn: tls.Client(conn, config),
		done:    make(chan struct{}),
	}
	go func() {
		err := client.tlsConn.Handshake()
		client.mu.Lock()
		client.err = err
		client.mu.Unlock()
		close(client.done)
	}()
	return client
}

// handshakeOutput waits for one client TLS flight and returns it. | handshakeOutput 等待一个客户端 TLS
// 飞行并返回。
func (c *eapTestTLSClient) handshakeOutput(t *testing.T) []byte {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	if err := c.conn.waitSettled(ctx, c.done); err != nil {
		t.Fatalf("client handshake settle: %v", err)
	}
	out := c.conn.takeOutput()
	if err := c.handshakeError(); err != nil {
		t.Fatalf("client handshake: %v", err)
	}
	return out
}

// process feeds one server TLS flight and returns the next client TLS flight. | process 喂入一个服务器
// TLS 飞行并返回下一个客户端 TLS 飞行。
func (c *eapTestTLSClient) process(t *testing.T, data []byte) []byte {
	t.Helper()
	if err := c.conn.feed(data); err != nil {
		t.Fatalf("client feed: %v", err)
	}
	out := c.handshakeOutput(t)
	if c.handshakeDone() {
		if err := c.handshakeError(); err != nil {
			t.Fatalf("client handshake after final flight: %v", err)
		}
	}
	return out
}

// handshakeDone reports whether the client handshake goroutine returned. | handshakeDone 报告客户端握手
// 协程是否已返回。
func (c *eapTestTLSClient) handshakeDone() bool {
	select {
	case <-c.done:
		return true
	default:
		return false
	}
}

// handshakeError returns the handshake error. | handshakeError 返回握手错误。
func (c *eapTestTLSClient) handshakeError() error {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.err
}

// startApplicationReader starts delivering decrypted application data. | startApplicationReader 开始交付
// 已解密应用数据。
func (c *eapTestTLSClient) startApplicationReader() {
	if c.appRun {
		return
	}
	c.appRun = true
	c.appCh = make(chan []byte, 16)
	go func() {
		buffer := make([]byte, 32*1024)
		for {
			n, err := c.tlsConn.Read(buffer)
			if n > 0 {
				c.appCh <- append([]byte(nil), buffer[:n]...)
			}
			if err != nil {
				c.mu.Lock()
				c.appErr = err
				c.mu.Unlock()
				close(c.appCh)
				return
			}
		}
	}()
}

// writeApplication encrypts one application message and returns its TLS records. | writeApplication
// 加密一条应用消息并返回其 TLS 记录。
func (c *eapTestTLSClient) writeApplication(t *testing.T, data []byte) []byte {
	t.Helper()
	if _, err := c.tlsConn.Write(data); err != nil {
		t.Fatalf("client application write: %v", err)
	}
	return c.conn.takeOutput()
}

// readApplication waits for one decrypted application message. | readApplication 等待一条已解密应用
// 消息。
func (c *eapTestTLSClient) readApplication(t *testing.T) []byte {
	t.Helper()
	select {
	case data, ok := <-c.appCh:
		if ok {
			return data
		}
		c.mu.Lock()
		err := c.appErr
		c.mu.Unlock()
		if err == nil {
			err = io.EOF
		}
		t.Fatalf("client application read: %v", err)
	case <-time.After(5 * time.Second):
		t.Fatal("timed out waiting for client application data")
	}
	return nil
}

// readApplicationAvailable returns one decrypted application message if one arrives within timeout.
// | readApplicationAvailable 若在超时内到达则返回一条已解密应用消息。
func (c *eapTestTLSClient) readApplicationAvailable(timeout time.Duration) ([]byte, bool, error) {
	select {
	case data, ok := <-c.appCh:
		if ok {
			return data, true, nil
		}
		c.mu.Lock()
		err := c.appErr
		c.mu.Unlock()
		if err == nil {
			err = io.EOF
		}
		return nil, false, err
	case <-time.After(timeout):
		return nil, false, nil
	}
}

// eapConversation drives one EAPServer through successive Responses. | eapConversation 驱动一个
// EAPServer 处理连续的 Response。
type eapConversation struct {
	t        *testing.T
	server   *EAPServer
	userName string
	state    []byte
	request  *EAPPacket
	result   *AccessServerResult
}

// newEAPConversation starts a conversation and returns the first Request. | newEAPConversation 开始交互
// 并返回首个 Request。
func newEAPConversation(t *testing.T, server *EAPServer, userName string) *eapConversation {
	t.Helper()
	request, state := eapStart(t, server, userName)
	return &eapConversation{t: t, server: server, userName: userName, state: state, request: request}
}

// send submits one Response and stores the server result. | send 提交一个 Response 并保存服务器结果。
func (c *eapConversation) send(response *EAPPacket) *AccessServerResult {
	c.t.Helper()
	result := eapContinue(c.t, c.server, c.state, c.userName, response)
	c.state = result.State
	c.result = result
	if result.Challenge {
		c.request = eapPacketFromResult(c.t, result)
	}
	return result
}

// identity answers the initial Identity Request. | identity 应答初始 Identity Request。
func (c *eapConversation) identity(identity string) *AccessServerResult {
	c.t.Helper()
	return c.send(eapResponse(c.request, EAPTypeIdentity, []byte(identity)))
}

// collectServerTLS reassembles one server TLS flight, acknowledging intermediate fragments. It returns
// the TLS bytes and the final Request whose identifier must be echoed. | collectServerTLS 重组一个服务器
// TLS 飞行，并确认中间分片。它返回 TLS 字节与必须回显标识符的最终 Request。
func (c *eapConversation) collectServerTLS(method EAPType) ([]byte, *EAPPacket) {
	c.t.Helper()
	var data []byte
	request := c.request
	for {
		flags, _, payload, err := parseTLSPayload(request.Data, true)
		if err != nil {
			c.t.Fatalf("parse server TLS payload: %v", err)
		}
		data = append(data, payload...)
		if flags&EAPTLSFlagMore == 0 {
			return data, request
		}
		result := c.send(eapResponse(request, method, []byte{0}))
		if !result.Challenge {
			c.t.Fatalf("server ended TLS flight with %+v", result)
		}
		request = c.request
	}
}

// eapTLSClientConfig returns a client TLS configuration trusting the test CA. | eapTLSClientConfig 返回
// 信任测试 CA 的客户端 TLS 配置。
func eapTLSClientConfig(pki *eapTestPKI, withClientCert bool, maxVersion uint16) *tls.Config {
	config := &tls.Config{
		RootCAs:    pki.roots,
		ServerName: "localhost",
		MinVersion: tls.VersionTLS12,
		MaxVersion: maxVersion,
	}
	if withClientCert {
		config.Certificates = []tls.Certificate{pki.clientCert}
	}
	return config
}

// runEAPTLSAuthentication performs a full EAP-TLS exchange and returns the final result. |
// runEAPTLSAuthentication 执行完整 EAP-TLS 交互并返回最终结果。
func runEAPTLSAuthentication(t *testing.T, server *EAPServer, client *eapTestTLSClient, outerIdentity string) *AccessServerResult {
	t.Helper()
	conversation := newEAPConversation(t, server, outerIdentity)
	result := conversation.identity(outerIdentity)
	if !result.Challenge {
		t.Fatalf("Identity result = %+v, want TLS Start challenge", result)
	}
	if conversation.request.Type != EAPTypeTLS {
		t.Fatalf("first method = %d, want EAP-TLS", conversation.request.Type)
	}
	if conversation.request.Data[0]&EAPTLSFlagStart == 0 {
		t.Fatalf("TLS Start flags = %x", conversation.request.Data[0])
	}
	clientFlight := client.handshakeOutput(t)
	for attempt := 0; attempt < 32; attempt++ {
		result = conversation.send(eapResponse(conversation.request, EAPTypeTLS, append([]byte{0}, clientFlight...)))
		if result.Accept || !result.Challenge {
			return result
		}
		serverFlight, finalRequest := conversation.collectServerTLS(EAPTypeTLS)
		clientFlight = client.process(t, serverFlight)
		if len(clientFlight) == 0 {
			result = conversation.send(eapResponse(finalRequest, EAPTypeTLS, []byte{0}))
			if result.Accept || !result.Challenge {
				return result
			}
			serverFlight, finalRequest = conversation.collectServerTLS(EAPTypeTLS)
			clientFlight = client.process(t, serverFlight)
			continue
		}
		conversation.request = finalRequest
	}
	t.Fatal("EAP-TLS exchange did not terminate")
	return nil
}

func TestEAPTLSAuthentication(t *testing.T) {
	for _, version := range []struct {
		name       string
		maxVersion uint16
	}{
		{name: "TLS1.2", maxVersion: tls.VersionTLS12},
		{name: "TLS1.3", maxVersion: tls.VersionTLS13},
	} {
		t.Run(version.name, func(t *testing.T) {
			pki := newEAPTestPKI(t)
			server := eapTestServer(t, EAPServerConfig{
				Password: testEAPPasswordLookup(map[string]string{"alice": "s3cret"}),
				TLSConfig: &tls.Config{
					Certificates: []tls.Certificate{pki.serverCert},
					ClientAuth:   tls.RequireAndVerifyClientCert,
					ClientCAs:    pki.roots,
					MinVersion:   tls.VersionTLS12,
					MaxVersion:   version.maxVersion,
				},
				Methods:                 []EAPType{EAPTypeTLS},
				IdentityFromCertificate: func(certificate *x509.Certificate) string { return certificate.Subject.CommonName },
			})
			client := newEAPTestTLSClient(eapTLSClientConfig(pki, true, version.maxVersion))
			result := runEAPTLSAuthentication(t, server, client, "outer-alice")
			if !result.Accept {
				t.Fatalf("EAP-TLS result = %+v", result)
			}
			if result.Identity != "tls-client" {
				t.Fatalf("EAP-TLS identity = %q, want tls-client", result.Identity)
			}
			if packet := eapPacketFromResult(t, result); packet.Code != EAPCodeSuccess {
				t.Fatalf("final EAP code = %d", packet.Code)
			}
		})
	}
}

func TestEAPTLSWithoutClientCertificate(t *testing.T) {
	pki := newEAPTestPKI(t)
	server := eapTestServer(t, EAPServerConfig{
		Password:                 testEAPPasswordLookup(map[string]string{"alice": "s3cret"}),
		TLSConfig:                &tls.Config{Certificates: []tls.Certificate{pki.serverCert}, MinVersion: tls.VersionTLS12},
		Methods:                  []EAPType{EAPTypeTLS},
		RequireClientCertificate: false,
	})
	client := newEAPTestTLSClient(eapTLSClientConfig(pki, false, tls.VersionTLS12))
	result := runEAPTLSAuthentication(t, server, client, "alice")
	if !result.Accept || result.Identity != "alice" {
		t.Fatalf("EAP-TLS result = %+v", result)
	}
}

func TestEAPTLSRequiresClientCertificate(t *testing.T) {
	pki := newEAPTestPKI(t)
	server := eapTestServer(t, EAPServerConfig{
		Password:                 testEAPPasswordLookup(map[string]string{"alice": "s3cret"}),
		TLSConfig:                &tls.Config{Certificates: []tls.Certificate{pki.serverCert}, MinVersion: tls.VersionTLS12},
		Methods:                  []EAPType{EAPTypeTLS},
		RequireClientCertificate: true,
	})
	client := newEAPTestTLSClient(eapTLSClientConfig(pki, false, tls.VersionTLS12))
	result := runEAPTLSAuthentication(t, server, client, "alice")
	if result.Accept {
		t.Fatalf("EAP-TLS without required certificate accepted: %+v", result)
	}
}

func TestEAPTLSCertificateValidationCallback(t *testing.T) {
	pki := newEAPTestPKI(t)
	rejected := errors.New("test callback rejected certificate")
	server := eapTestServer(t, EAPServerConfig{
		Password: testEAPPasswordLookup(map[string]string{"alice": "s3cret"}),
		TLSConfig: &tls.Config{
			Certificates: []tls.Certificate{pki.serverCert},
			MinVersion:   tls.VersionTLS12,
			ClientAuth:   tls.RequireAnyClientCert,
			VerifyPeerCertificate: func(rawCerts [][]byte, verifiedChains [][]*x509.Certificate) error {
				if len(rawCerts) == 0 {
					return rejected
				}
				return rejected
			},
		},
		Methods: []EAPType{EAPTypeTLS},
	})
	client := newEAPTestTLSClient(eapTLSClientConfig(pki, true, tls.VersionTLS12))
	result := runEAPTLSAuthentication(t, server, client, "alice")
	if result.Accept {
		t.Fatalf("certificate callback rejection accepted: %+v", result)
	}
}

func TestEAPTLSTransportFailure(t *testing.T) {
	pki := newEAPTestPKI(t)
	server := eapTestServer(t, EAPServerConfig{
		Password:  testEAPPasswordLookup(map[string]string{"alice": "s3cret"}),
		TLSConfig: &tls.Config{Certificates: []tls.Certificate{pki.serverCert}, MinVersion: tls.VersionTLS12},
		Methods:   []EAPType{EAPTypeTLS},
	})
	conversation := newEAPConversation(t, server, "alice")
	result := conversation.identity("alice")
	if !result.Challenge {
		t.Fatalf("identity result = %+v", result)
	}
	result = conversation.send(eapResponse(conversation.request, EAPTypeTLS, []byte{0x00, 0xde, 0xad, 0xbe, 0xef}))
	if result.Accept {
		t.Fatalf("malformed TLS accepted: %+v", result)
	}
}

func TestEAPTLSTLSClientProcess(t *testing.T) {
	// The helper itself is exercised by the tests above; this guards against accidentally returning
	// an error after a completed client handshake. | 该辅助函数已被上面的测试覆盖；此用例防止客户端
	// 握手完成后误报错误。
	pki := newEAPTestPKI(t)
	client := newEAPTestTLSClient(eapTLSClientConfig(pki, false, tls.VersionTLS12))
	if len(client.handshakeOutput(t)) == 0 {
		t.Fatal("client produced no ClientHello")
	}
	if bytes.Contains(client.conn.takeOutput(), []byte{0}) {
		t.Fatal("unexpected output")
	}
}

func TestEAPTLSPayloadLengthBound(t *testing.T) {
	oversized := []byte{byte(EAPTLSFlagLength), 0xff, 0xff, 0xff, 0xff, 0x00}
	if _, _, _, err := parseTLSPayload(oversized, false); !errors.Is(err, ErrInvalidRequest) {
		t.Fatalf("oversized total error = %v, want ErrInvalidRequest", err)
	}
	atLimit := []byte{byte(EAPTLSFlagLength), 0x00, 0x00, 0xff, 0xff, 0x07}
	flags, total, payload, err := parseTLSPayload(atLimit, false)
	if err != nil || flags != EAPTLSFlagLength || total != maxEAPTLSMessageLength || len(payload) != 1 || payload[0] != 0x07 {
		t.Fatalf("at-limit payload = flags %x total %d payload %x err %v", flags, total, payload, err)
	}
	var reassembler eapTLSReassembler
	if _, _, err := reassembler.add(EAPTLSFlagLength|EAPTLSFlagMore, maxEAPTLSMessageLength+1, []byte{0x01}); !errors.Is(err, ErrInvalidRequest) {
		t.Fatalf("oversized reassembly error = %v, want ErrInvalidRequest", err)
	}
	if reassembler.active || len(reassembler.buffer) != 0 {
		t.Fatalf("oversized fragment activated reassembly: active=%v buffer=%d", reassembler.active, len(reassembler.buffer))
	}
}
