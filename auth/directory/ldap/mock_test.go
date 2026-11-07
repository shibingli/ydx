package ldap

import (
	"bufio"
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
	"net"
	"sync"
	"testing"
	"time"
)

// errCloseMockConn asks the mock server to close one session. | errCloseMockConn
// 请求模拟服务端关闭单个会话。
var errCloseMockConn = errors.New("mock: close connection")

// mockHandler processes one request. | mockHandler 处理一条请求。
type mockHandler func(*mockSession, *LDAPMessage) error

// mockServer is a minimal LDAP listener for tests. | mockServer 是测试用的最小 LDAP 监听器。
type mockServer struct {
	t       *testing.T
	ln      net.Listener
	scheme  string
	handler mockHandler
	wg      sync.WaitGroup
	mu      sync.Mutex
	conns   map[net.Conn]struct{}
	closed  bool
}

// startMockServer starts a plain LDAP listener. | startMockServer 启动明文 LDAP 监听器。
func startMockServer(t *testing.T, handler mockHandler) *mockServer {
	t.Helper()
	return startMockServerTLS(t, nil, handler)
}

// startMockServerTLS starts an LDAP listener, optionally wrapped in TLS. |
// startMockServerTLS 启动 LDAP 监听器，可选地包裹 TLS。
func startMockServerTLS(t *testing.T, serverTLS *tls.Config, handler mockHandler) *mockServer {
	t.Helper()
	raw, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	ln := raw
	scheme := "ldap"
	if serverTLS != nil {
		ln = tls.NewListener(raw, serverTLS)
		scheme = "ldaps"
	}
	server := &mockServer{
		t:       t,
		ln:      ln,
		scheme:  scheme,
		handler: handler,
		conns:   make(map[net.Conn]struct{}),
	}
	t.Cleanup(server.Close)
	go server.acceptLoop()
	return server
}

// URL returns the listener URL. | URL 返回监听地址。
func (s *mockServer) URL() string {
	return s.scheme + "://" + s.ln.Addr().String()
}

// Addr returns the listener host:port. | Addr 返回监听 host:port。
func (s *mockServer) Addr() string {
	return s.ln.Addr().String()
}

// Close stops accepting and closes every live session. | Close 停止接受并关闭所有活动会话。
func (s *mockServer) Close() {
	if s == nil {
		return
	}
	s.mu.Lock()
	if s.closed {
		s.mu.Unlock()
		return
	}
	s.closed = true
	_ = s.ln.Close()
	for conn := range s.conns {
		_ = conn.Close()
	}
	s.mu.Unlock()
	s.wg.Wait()
}

// acceptLoop accepts sessions until the listener closes. | acceptLoop 接受会话直至监听器关闭。
func (s *mockServer) acceptLoop() {
	for {
		conn, err := s.ln.Accept()
		if err != nil {
			return
		}
		s.mu.Lock()
		if s.closed {
			s.mu.Unlock()
			_ = conn.Close()
			return
		}
		s.conns[conn] = struct{}{}
		s.wg.Add(1)
		s.mu.Unlock()
		go s.serve(conn)
	}
}

// serve handles one connection. | serve 处理一条连接。
func (s *mockServer) serve(raw net.Conn) {
	defer s.wg.Done()
	conn := raw
	defer func() {
		s.mu.Lock()
		delete(s.conns, conn)
		delete(s.conns, raw)
		s.mu.Unlock()
		_ = conn.Close()
		_ = raw.Close()
	}()
	reader := bufio.NewReader(conn)
	for {
		packet, err := readMockPacket(reader)
		if err != nil {
			return
		}
		message, err := decodeLDAPMessage(packet)
		if err != nil {
			s.reportError("decode request", err)
			return
		}
		session := &mockSession{server: s, conn: conn, reader: reader}
		if err := s.handler(session, message); err != nil {
			if !errors.Is(err, errCloseMockConn) {
				s.reportError("handler", err)
			}
			return
		}
		if session.upgradeTLS != nil {
			tlsConn := tls.Server(conn, session.upgradeTLS)
			_ = tlsConn.SetDeadline(time.Now().Add(5 * time.Second))
			if err := tlsConn.Handshake(); err != nil {
				// A peer rejecting the certificate is a valid test outcome. |
				// 对端拒绝证书是合法的测试结果。
				return
			}
			_ = tlsConn.SetDeadline(time.Time{})
			s.mu.Lock()
			delete(s.conns, conn)
			s.conns[tlsConn] = struct{}{}
			s.mu.Unlock()
			conn = tlsConn
			reader = bufio.NewReader(conn)
		}
	}
}

// reportError records a server-side failure unless the server is closing. | reportError
// 在服务端未关闭时记录服务端故障。
func (s *mockServer) reportError(operation string, err error) {
	s.mu.Lock()
	closed := s.closed
	s.mu.Unlock()
	if closed {
		return
	}
	s.t.Errorf("mock LDAP %s: %v", operation, err)
}

// mockSession is one mock server connection. | mockSession 是一条模拟服务端连接。
type mockSession struct {
	server     *mockServer
	conn       net.Conn
	reader     *bufio.Reader
	upgradeTLS *tls.Config
}

// Upgrade requests a TLS upgrade after the current response is written. | Upgrade
// 请求在写出当前响应后进行 TLS 升级。
func (s *mockSession) Upgrade(config *tls.Config) {
	s.upgradeTLS = config
}

// Write encodes and writes one LDAP message. | Write 编码并写出一条 LDAP 消息。
func (s *mockSession) Write(message *LDAPMessage) error {
	data, err := encodeLDAPMessage(message)
	if err != nil {
		return err
	}
	_, err = s.conn.Write(data)
	return err
}

// writeSimpleResult writes a response carrying only an LDAPResult. | writeSimpleResult
// 写出只携带 LDAPResult 的响应。
func (s *mockSession) writeSimpleResult(id int, op ProtocolOp) error {
	return s.Write(&LDAPMessage{MessageID: id, Op: op})
}

// writeEntry writes one search entry. | writeEntry 写出一个搜索条目。
func (s *mockSession) writeEntry(id int, dn string, attributes ...Attribute) error {
	return s.Write(&LDAPMessage{MessageID: id, Op: &Entry{DN: dn, Attributes: attributes}})
}

// writeSearchDone writes a SearchResultDone. | writeSearchDone 写出 SearchResultDone。
func (s *mockSession) writeSearchDone(id int, result LDAPResult, controls ...Control) error {
	return s.Write(&LDAPMessage{MessageID: id, Op: &SearchResultDone{Result: result}, Controls: controls})
}

// writeSearchReference writes search reference URIs. | writeSearchReference 写出搜索转介 URI。
func (s *mockSession) writeSearchReference(id int, uris ...string) error {
	return s.Write(&LDAPMessage{MessageID: id, Op: &SearchResultReference{URIs: uris}})
}

// readMockPacket reads one top-level LDAP SEQUENCE. | readMockPacket 读取一个顶层 LDAP
// SEQUENCE。
func readMockPacket(reader *bufio.Reader) ([]byte, error) {
	first, err := reader.ReadByte()
	if err != nil {
		return nil, err
	}
	if first != 0x30 {
		return nil, errors.New("mock: top-level tag is not SEQUENCE")
	}
	firstLength, err := reader.ReadByte()
	if err != nil {
		return nil, err
	}
	header := []byte{first, firstLength}
	var length int
	if firstLength < 0x80 {
		length = int(firstLength)
	} else {
		count := int(firstLength & 0x7f)
		if count == 0 || count > 8 {
			return nil, errors.New("mock: invalid length form")
		}
		lengthBytes := make([]byte, count)
		if _, err := io.ReadFull(reader, lengthBytes); err != nil {
			return nil, err
		}
		header = append(header, lengthBytes...)
		for _, b := range lengthBytes {
			length = length<<8 | int(b)
		}
	}
	packet := make([]byte, len(header)+length)
	copy(packet, header)
	if length > 0 {
		if _, err := io.ReadFull(reader, packet[len(header):]); err != nil {
			return nil, err
		}
	}
	return packet, nil
}

// testCertificate returns a self-signed localhost certificate and trust pool. |
// testCertificate 返回 localhost 自签名证书与信任池。
func testCertificate(t *testing.T) (tls.Certificate, *x509.CertPool) {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("generate key: %v", err)
	}
	serial, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 120))
	if err != nil {
		t.Fatalf("serial: %v", err)
	}
	template := &x509.Certificate{
		SerialNumber:          serial,
		Subject:               pkix.Name{CommonName: "localhost"},
		DNSNames:              []string{"localhost"},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(time.Hour),
		KeyUsage:              x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment | x509.KeyUsageCertSign,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		BasicConstraintsValid: true,
		IsCA:                  true,
	}
	der, err := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
	if err != nil {
		t.Fatalf("create certificate: %v", err)
	}
	leaf, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatalf("parse certificate: %v", err)
	}
	pool := x509.NewCertPool()
	pool.AddCert(leaf)
	return tls.Certificate{Certificate: [][]byte{der}, PrivateKey: key, Leaf: leaf}, pool
}

// testTLSConfig returns client TLS settings trusting the test certificate. |
// testTLSConfig 返回信任测试证书的客户端 TLS 配置。
func testTLSConfig(pool *x509.CertPool) *tls.Config {
	return &tls.Config{
		RootCAs:    pool,
		ServerName: "localhost",
		MinVersion: tls.VersionTLS12,
	}
}

// mustTimeoutContext returns a context bounded by d. | mustTimeoutContext 返回受 d 限制的上下文。
func mustTimeoutContext(t *testing.T, d time.Duration) context.Context {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), d)
	t.Cleanup(cancel)
	return ctx
}
