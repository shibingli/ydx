package radius

import (
	"context"
	"errors"
	"net"
	"testing"
	"time"
)

// testServer is the common lifecycle of an AccessServer and an AccountingServer. | testServer 是
// AccessServer 与 AccountingServer 的公共生命周期。
type testServer interface {
	Listen() (net.Addr, error)
	Serve(ctx context.Context) error
	Close() error
}

// startTestServer starts server in a goroutine and returns its bound address. |
// startTestServer 在协程中启动 server 并返回其绑定地址。
func startTestServer(t *testing.T, server testServer) net.Addr {
	t.Helper()
	address, err := server.Listen()
	if err != nil {
		t.Fatalf("Listen: %v", err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() {
		done <- server.Serve(ctx)
	}()
	waitForTransportServing(t, server)
	t.Cleanup(func() {
		cancel()
		select {
		case err := <-done:
			if err != nil && !errors.Is(err, ErrServerClosed) {
				t.Errorf("Serve: %v", err)
			}
		case <-time.After(5 * time.Second):
			t.Errorf("Serve did not return after context cancellation")
		}
	})
	return address
}

// startAccessServer constructs and starts an AccessServer. | startAccessServer 构造并启动 AccessServer。
func startAccessServer(t *testing.T, config AccessServerConfig) *AccessServer {
	t.Helper()
	server, err := NewAccessServer(config)
	if err != nil {
		t.Fatalf("NewAccessServer: %v", err)
	}
	t.Cleanup(func() {
		_ = server.Close()
	})
	startTestServer(t, server)
	return server
}

// startAccountingServer constructs and starts an AccountingServer. | startAccountingServer 构造并启动
// AccountingServer。
func startAccountingServer(t *testing.T, config AccountingServerConfig) *AccountingServer {
	t.Helper()
	server, err := NewAccountingServer(config)
	if err != nil {
		t.Fatalf("NewAccountingServer: %v", err)
	}
	t.Cleanup(func() {
		_ = server.Close()
	})
	startTestServer(t, server)
	return server
}

// waitForTransportServing waits until Serve has claimed the socket or listener. |
// waitForTransportServing 等待 Serve 接管套接字或监听器。
func waitForTransportServing(t *testing.T, server testServer) {
	t.Helper()
	var transport *serverTransport
	switch typed := server.(type) {
	case *AccessServer:
		transport = typed.transport
	case *AccountingServer:
		transport = typed.transport
	default:
		t.Fatalf("unsupported server type %T", server)
	}
	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		transport.mu.Lock()
		serving := transport.serving
		transport.mu.Unlock()
		if serving {
			return
		}
		time.Sleep(time.Millisecond)
	}
	t.Fatal("Serve did not start")
}

// exchangeUDP sends one datagram and returns the response. | exchangeUDP 发送一个数据报并返回响应。
func exchangeUDP(t *testing.T, address string, request []byte, timeout time.Duration) ([]byte, error) {
	t.Helper()
	conn, err := net.DialTimeout("udp4", address, timeout)
	if err != nil {
		t.Fatalf("dial %s: %v", address, err)
	}
	defer func() {
		_ = conn.Close()
	}()
	_ = conn.SetDeadline(time.Now().Add(timeout))
	if _, err := conn.Write(request); err != nil {
		return nil, err
	}
	buffer := make([]byte, MaxPacketLength)
	n, err := conn.Read(buffer)
	if err != nil {
		return nil, err
	}
	return append([]byte(nil), buffer[:n]...), nil
}

// requireUDPTimeout asserts that a request receives no response before the read deadline. |
// requireUDPTimeout 断言请求在读取截止时间前没有收到响应。
func requireUDPTimeout(t *testing.T, address string, request []byte) {
	t.Helper()
	response, err := exchangeUDP(t, address, request, 150*time.Millisecond)
	if err == nil {
		t.Fatalf("unexpected response: %x", response)
	}
	var netErr net.Error
	if !errors.As(err, &netErr) || !netErr.Timeout() {
		t.Fatalf("read error = %v, want timeout", err)
	}
}

// parseAndVerifyResponse parses a server response and verifies its Response Authenticator. |
// parseAndVerifyResponse 解析服务器响应并校验其 Response Authenticator。
func parseAndVerifyResponse(t *testing.T, raw []byte, requestAuthenticator [16]byte, secret []byte) *Packet {
	t.Helper()
	packet, err := ParsePacket(raw)
	if err != nil {
		t.Fatalf("ParsePacket: %v", err)
	}
	if err := verifyResponseAuthenticator(raw, secret, requestAuthenticator); err != nil {
		t.Fatalf("Response Authenticator: %v", err)
	}
	return packet
}

// rawAccessAuthenticator returns the fixed Request Authenticator used by raw Access tests. |
// rawAccessAuthenticator 返回原始 Access 测试使用的固定 Request Authenticator。
func rawAccessAuthenticator() [16]byte {
	var authenticator [16]byte
	for i := range authenticator {
		authenticator[i] = byte(i + 1)
	}
	return authenticator
}

// rawAccessRequest encodes an Access-Request. When messageAuthenticatorSecret is non-nil a
// Message-Authenticator is added and signed with that secret. | rawAccessRequest 编码 Access-Request。
// messageAuthenticatorSecret 非 nil 时添加 Message-Authenticator 并用该密钥签名。
func rawAccessRequest(t *testing.T, identifier uint8, authenticator [16]byte, attributes Attributes, messageAuthenticatorSecret []byte) []byte {
	t.Helper()
	attrs := attributes.Clone()
	if messageAuthenticatorSecret != nil {
		attrs.Add(AttrMessageAuthenticator, make([]byte, 16))
	}
	raw, err := MarshalPacket(&Packet{
		Code:          CodeAccessRequest,
		Identifier:    identifier,
		Authenticator: authenticator,
		Attributes:    attrs,
	})
	if err != nil {
		t.Fatalf("MarshalPacket: %v", err)
	}
	if messageAuthenticatorSecret != nil {
		if err := signMessageAuthenticator(raw, messageAuthenticatorSecret, authenticator); err != nil {
			t.Fatalf("signMessageAuthenticator: %v", err)
		}
	}
	return raw
}

// hiddenPassword returns the RFC 2865 User-Password ciphertext for a raw Access test. | hiddenPassword
// 返回原始 Access 测试使用的 RFC 2865 User-Password 密文。
func hiddenPassword(t *testing.T, secret []byte, authenticator [16]byte, password string) []byte {
	t.Helper()
	encrypted, err := EncryptUserPassword(secret, authenticator[:], []byte(password))
	if err != nil {
		t.Fatalf("EncryptUserPassword: %v", err)
	}
	return encrypted
}

// rawAccountingRequest encodes and signs an Accounting-Request with secret. | rawAccountingRequest
// 编码并用 secret 签名 Accounting-Request。
func rawAccountingRequest(t *testing.T, secret []byte, identifier uint8, attributes Attributes) []byte {
	t.Helper()
	raw, err := MarshalPacket(&Packet{
		Code:       CodeAccountingRequest,
		Identifier: identifier,
		Attributes: attributes.Clone(),
	})
	if err != nil {
		t.Fatalf("MarshalPacket: %v", err)
	}
	authenticator, err := accountingRequestAuthenticator(raw, secret)
	if err != nil {
		t.Fatalf("accountingRequestAuthenticator: %v", err)
	}
	copy(raw[4:HeaderLength], authenticator[:])
	return raw
}
