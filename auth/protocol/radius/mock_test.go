package radius

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/binary"
	"io"
	"math/big"
	"net"
	"sync"
	"testing"
	"time"

	"github.com/shibingli/ydx/errs"
)

// capturedRequest is one request observed by a mock server. | capturedRequest 是模拟服务器观察到的一次请求。
type capturedRequest struct {
	raw    []byte
	packet *Packet
}

// responderFunc produces the raw response for one request. Returning nil drops the request, which
// exercises client retransmission. | responderFunc 为一次请求生成原始响应。返回 nil 表示丢弃该请求，
// 用于测试客户端重传。
type responderFunc func(request *Packet, raw []byte) ([]byte, error)

// signedResponse builds and signs a server response with the Response Authenticator. | signedResponse
// 构建并签名带 Response Authenticator 的服务器响应。
func signedResponse(request *Packet, secret []byte, code Code, attributes Attributes) ([]byte, error) {
	packet := &Packet{
		Code:          code,
		Identifier:    request.Identifier,
		Authenticator: request.Authenticator,
		Attributes:    attributes.Clone(),
	}
	raw, err := MarshalPacket(packet)
	if err != nil {
		return nil, err
	}
	if err := applyResponseAuthenticator(raw, secret); err != nil {
		return nil, err
	}
	return raw, nil
}

// signedMessageResponse builds a response that carries and signs a Message-Authenticator. | signedMessageResponse
// 构建携带并签名 Message-Authenticator 的响应。
func signedMessageResponse(request *Packet, secret []byte, code Code, attributes Attributes) ([]byte, error) {
	attributes = append(attributes.Clone(), NewAttribute(AttrMessageAuthenticator, make([]byte, 16)))
	packet := &Packet{
		Code:          code,
		Identifier:    request.Identifier,
		Authenticator: request.Authenticator,
		Attributes:    attributes,
	}
	raw, err := MarshalPacket(packet)
	if err != nil {
		return nil, err
	}
	if err := signMessageAuthenticator(raw, secret, request.Authenticator); err != nil {
		return nil, err
	}
	if err := applyResponseAuthenticator(raw, secret); err != nil {
		return nil, err
	}
	return raw, nil
}

// udpMock is a minimal UDP RADIUS responder for tests. | udpMock 是测试用的最小 UDP RADIUS 响应器。
type udpMock struct {
	conn      net.PacketConn
	secret    []byte
	responder responderFunc
	requests  chan capturedRequest
	failures  chan error
	done      chan struct{}
	closeOnce sync.Once
	wg        sync.WaitGroup
}

// newUDPMock starts a UDP responder. | newUDPMock 启动 UDP 响应器。
func newUDPMock(t *testing.T, secret []byte, responder responderFunc) *udpMock {
	t.Helper()
	conn, err := net.ListenPacket("udp4", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen udp: %v", err)
	}
	mock := &udpMock{
		conn:      conn,
		secret:    append([]byte(nil), secret...),
		responder: responder,
		requests:  make(chan capturedRequest, 256),
		failures:  make(chan error, 16),
		done:      make(chan struct{}),
	}
	mock.wg.Add(1)
	go mock.serve()
	t.Cleanup(mock.Close)
	return mock
}

// Addr returns the server address. | Addr 返回服务器地址。
func (m *udpMock) Addr() string {
	return m.conn.LocalAddr().String()
}

// serve reads requests and writes responses. | serve 读取请求并写入响应。
func (m *udpMock) serve() {
	defer m.wg.Done()
	buf := make([]byte, MaxPacketLength)
	for {
		n, addr, err := m.conn.ReadFrom(buf)
		if err != nil {
			if m.stopped() {
				return
			}
			m.report(err)
			return
		}
		raw := append([]byte(nil), buf[:n]...)
		request, err := ParsePacket(raw)
		if err != nil {
			m.report(err)
			continue
		}
		m.record(capturedRequest{raw: raw, packet: request})
		response, err := m.responder(request, raw)
		if err != nil {
			m.report(err)
			continue
		}
		if response == nil {
			continue
		}
		if _, err := m.conn.WriteTo(response, addr); err != nil && !m.stopped() {
			m.report(err)
		}
	}
}

// record publishes a request without blocking the server. | record 以非阻塞方式发布请求。
func (m *udpMock) record(request capturedRequest) {
	select {
	case m.requests <- request:
	default:
	}
}

// report publishes a server failure without blocking. | report 以非阻塞方式发布服务器故障。
func (m *udpMock) report(err error) {
	select {
	case m.failures <- err:
	default:
	}
}

// stopped reports whether Close has been called. | stopped 报告是否已调用 Close。
func (m *udpMock) stopped() bool {
	select {
	case <-m.done:
		return true
	default:
		return false
	}
}

// Close stops the responder. | Close 停止响应器。
func (m *udpMock) Close() {
	m.closeOnce.Do(func() {
		close(m.done)
		_ = m.conn.Close()
		m.wg.Wait()
	})
}

// nextRequest returns the next recorded request or fails the test. | nextRequest 返回下一条记录的请求，
// 或在失败时终止测试。
func (m *udpMock) nextRequest(t *testing.T) capturedRequest {
	t.Helper()
	select {
	case request := <-m.requests:
		return request
	case err := <-m.failures:
		t.Fatalf("udp mock failure: %v", err)
	case <-time.After(5 * time.Second):
		t.Fatal("timed out waiting for a request")
	}
	return capturedRequest{}
}

// streamMock is a minimal single-packet TCP or TLS RADIUS responder for tests. | streamMock 是测试用的
// 最小单报文 TCP 或 TLS RADIUS 响应器。
type streamMock struct {
	listener  net.Listener
	secret    []byte
	responder responderFunc
	requests  chan capturedRequest
	failures  chan error
	done      chan struct{}
	closeOnce sync.Once
	wg        sync.WaitGroup
	connMu    sync.Mutex
	conns     map[net.Conn]struct{}
}

// newTCPMock starts a TCP responder. | newTCPMock 启动 TCP 响应器。
func newTCPMock(t *testing.T, secret []byte, responder responderFunc) *streamMock {
	t.Helper()
	listener, err := net.Listen("tcp4", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen tcp: %v", err)
	}
	return newStreamMock(t, listener, secret, responder)
}

// newTLSMock starts a TLS responder and returns a client certificate pool. | newTLSMock 启动 TLS
// 响应器并返回客户端证书池。
func newTLSMock(t *testing.T, secret []byte, responder responderFunc) (*streamMock, *x509.CertPool) {
	t.Helper()
	certificate, roots := testCertificate(t)
	listener, err := net.Listen("tcp4", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen tls: %v", err)
	}
	tlsListener := tls.NewListener(listener, &tls.Config{
		Certificates: []tls.Certificate{certificate},
		MinVersion:   tls.VersionTLS12,
	})
	return newStreamMock(t, tlsListener, secret, responder), roots
}

// newStreamMock starts serving one request per connection. | newStreamMock 启动按每连接一个请求提供服务。
func newStreamMock(t *testing.T, listener net.Listener, secret []byte, responder responderFunc) *streamMock {
	t.Helper()
	mock := &streamMock{
		listener:  listener,
		secret:    append([]byte(nil), secret...),
		responder: responder,
		requests:  make(chan capturedRequest, 64),
		failures:  make(chan error, 16),
		done:      make(chan struct{}),
		conns:     make(map[net.Conn]struct{}),
	}
	mock.wg.Add(1)
	go mock.accept()
	t.Cleanup(mock.Close)
	return mock
}

// Addr returns the server address. | Addr 返回服务器地址。
func (m *streamMock) Addr() string {
	return m.listener.Addr().String()
}

// accept accepts connections until Close. | accept 接受连接直到 Close。
func (m *streamMock) accept() {
	defer m.wg.Done()
	for {
		conn, err := m.listener.Accept()
		if err != nil {
			if m.stopped() {
				return
			}
			m.report(err)
			return
		}
		m.connMu.Lock()
		m.conns[conn] = struct{}{}
		m.connMu.Unlock()
		m.wg.Add(1)
		go func() {
			defer m.wg.Done()
			defer conn.Close()
			defer func() {
				m.connMu.Lock()
				delete(m.conns, conn)
				m.connMu.Unlock()
			}()
			m.handle(conn)
		}()
	}
}

// handle reads one request, records it and writes one response. | handle 读取一个请求、记录它并写入一个响应。
func (m *streamMock) handle(conn net.Conn) {
	_ = conn.SetDeadline(time.Now().Add(5 * time.Second))
	raw, err := readStreamRequest(conn)
	if err != nil {
		if !m.stopped() {
			m.report(err)
		}
		return
	}
	request, err := ParsePacket(raw)
	if err != nil {
		m.report(err)
		return
	}
	m.record(capturedRequest{raw: raw, packet: request})
	response, err := m.responder(request, raw)
	if err != nil {
		m.report(err)
		return
	}
	if response == nil {
		return
	}
	if _, err := conn.Write(response); err != nil && !m.stopped() {
		m.report(err)
	}
}

// readStreamRequest reads one length-delimited request. | readStreamRequest 读取一个按长度分帧的请求。
func readStreamRequest(conn net.Conn) ([]byte, error) {
	header := make([]byte, 4)
	if _, err := io.ReadFull(conn, header); err != nil {
		return nil, err
	}
	length := int(binary.BigEndian.Uint16(header[2:4]))
	if length < HeaderLength || length > MaxPacketLength {
		return nil, errs.Detail(ErrInvalidPacket, "declared length %d is invalid", length)
	}
	raw := make([]byte, length)
	copy(raw, header)
	if _, err := io.ReadFull(conn, raw[4:]); err != nil {
		return nil, err
	}
	return raw, nil
}

// record publishes a request without blocking the server. | record 以非阻塞方式发布请求。
func (m *streamMock) record(request capturedRequest) {
	select {
	case m.requests <- request:
	default:
	}
}

// report publishes a server failure without blocking. | report 以非阻塞方式发布服务器故障。
func (m *streamMock) report(err error) {
	select {
	case m.failures <- err:
	default:
	}
}

// stopped reports whether Close has been called. | stopped 报告是否已调用 Close。
func (m *streamMock) stopped() bool {
	select {
	case <-m.done:
		return true
	default:
		return false
	}
}

// Close stops the responder and closes active connections. | Close 停止响应器并关闭活动连接。
func (m *streamMock) Close() {
	m.closeOnce.Do(func() {
		close(m.done)
		_ = m.listener.Close()
		m.connMu.Lock()
		for conn := range m.conns {
			_ = conn.Close()
		}
		m.connMu.Unlock()
		m.wg.Wait()
	})
}

// nextRequest returns the next recorded request or fails the test. | nextRequest 返回下一条记录的请求，
// 或在失败时终止测试。
func (m *streamMock) nextRequest(t *testing.T) capturedRequest {
	t.Helper()
	select {
	case request := <-m.requests:
		return request
	case err := <-m.failures:
		t.Fatalf("stream mock failure: %v", err)
	case <-time.After(5 * time.Second):
		t.Fatal("timed out waiting for a request")
	}
	return capturedRequest{}
}

// testCertificate returns a self-signed server certificate and a pool that trusts it. | testCertificate
// 返回自签名服务器证书与信任它的证书池。
func testCertificate(t *testing.T) (tls.Certificate, *x509.CertPool) {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("generate key: %v", err)
	}
	template := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: "radius.test"},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(time.Hour),
		KeyUsage:              x509.KeyUsageDigitalSignature | x509.KeyUsageCertSign,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		BasicConstraintsValid: true,
		IsCA:                  true,
		DNSNames:              []string{"radius.test"},
		IPAddresses:           []net.IP{net.ParseIP("127.0.0.1")},
	}
	der, err := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
	if err != nil {
		t.Fatalf("create certificate: %v", err)
	}
	parsed, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatalf("parse certificate: %v", err)
	}
	pool := x509.NewCertPool()
	pool.AddCert(parsed)
	return tls.Certificate{Certificate: [][]byte{der}, PrivateKey: key}, pool
}

// newTestClient returns a client tuned for fast tests. | newTestClient 返回为快速测试调优的客户端。
func newTestClient(t *testing.T, config ClientConfig) *Client {
	t.Helper()
	if config.Timeout == 0 {
		config.Timeout = 250 * time.Millisecond
	}
	client, err := NewClient(config)
	if err != nil {
		t.Fatalf("NewClient: %v", err)
	}
	t.Cleanup(func() {
		_ = client.Close()
	})
	return client
}
