package radius

import (
	"bytes"
	"context"
	"encoding/binary"
	"errors"
	"io"
	"net"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/shibingli/ydx/log"
)

// testDynamicLogger returns a logger that discards every record. | testDynamicLogger 返回丢弃全部
// 记录的日志器。
func testDynamicLogger() *log.Logger {
	return log.New(log.Options{Writer: io.Discard, Level: log.ErrorLevel})
}

// runningDynamicServer is a DynamicServer serving on a loopback address. | runningDynamicServer 是
// 在回环地址上服务的 DynamicServer。
type runningDynamicServer struct {
	server   *DynamicServer
	addr     string
	cancel   context.CancelFunc
	done     chan struct{}
	serveErr error
}

// newRunningDynamicServer starts a server for a test and registers cleanup. | newRunningDynamicServer
// 为测试启动服务器并注册清理。
func newRunningDynamicServer(t *testing.T, config DynamicServerConfig) *runningDynamicServer {
	t.Helper()
	if config.Network == "" {
		config.Network = "udp4"
	}
	if config.Address == "" {
		config.Address = "127.0.0.1:0"
	}
	if config.Logger == nil {
		config.Logger = testDynamicLogger()
	}
	server, err := NewDynamicServer(config)
	if err != nil {
		t.Fatalf("NewDynamicServer: %v", err)
	}
	address, err := server.Listen()
	if err != nil {
		t.Fatalf("Listen: %v", err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	harness := &runningDynamicServer{
		server: server,
		addr:   address.String(),
		cancel: cancel,
		done:   make(chan struct{}),
	}
	go func() {
		harness.serveErr = server.Serve(ctx)
		close(harness.done)
	}()
	t.Cleanup(func() {
		cancel()
		_ = server.Close()
		select {
		case <-harness.done:
			if harness.serveErr != nil && !errors.Is(harness.serveErr, ErrServerClosed) && !errors.Is(harness.serveErr, ErrNetwork) {
				t.Errorf("Serve: %v", harness.serveErr)
			}
		case <-time.After(2 * time.Second):
			t.Errorf("dynamic server did not stop")
		}
	})
	return harness
}

// dialDynamic opens a connected UDP socket to the test server. | dialDynamic 打开到测试服务器的
// 已连接 UDP 套接字。
func dialDynamic(t *testing.T, address string) net.Conn {
	t.Helper()
	conn, err := net.Dial("udp4", address)
	if err != nil {
		t.Fatalf("dial %s: %v", address, err)
	}
	t.Cleanup(func() {
		_ = conn.Close()
	})
	return conn
}

// sendDynamicDatagram sends raw and reads one datagram. | sendDynamicDatagram 发送 raw 并读取一个
// 数据报。
func sendDynamicDatagram(t *testing.T, conn net.Conn, raw []byte, timeout time.Duration) ([]byte, error) {
	t.Helper()
	_ = conn.SetDeadline(time.Now().Add(timeout))
	if _, err := conn.Write(raw); err != nil {
		return nil, err
	}
	buffer := make([]byte, MaxPacketLength)
	n, err := conn.Read(buffer)
	if err != nil {
		return nil, err
	}
	out := make([]byte, n)
	copy(out, buffer[:n])
	return out, nil
}

// requireNoDynamicResponse asserts that raw produces no response. | requireNoDynamicResponse 断言
// raw 不会产生响应。
func requireNoDynamicResponse(t *testing.T, conn net.Conn, raw []byte) {
	t.Helper()
	buffer := make([]byte, MaxPacketLength)
	_ = conn.SetDeadline(time.Now().Add(200 * time.Millisecond))
	if _, err := conn.Write(raw); err != nil {
		t.Fatalf("write datagram: %v", err)
	}
	n, err := conn.Read(buffer)
	if err == nil {
		t.Fatalf("unexpected %d-byte response", n)
	}
	var netErr net.Error
	if !errors.As(err, &netErr) || !netErr.Timeout() {
		t.Fatalf("read error = %v, want a timeout", err)
	}
}

// buildDynamicTestRequest encodes and signs one request outside the Client. | buildDynamicTestRequest
// 在 Client 之外编码并签名一个请求。
func buildDynamicTestRequest(t *testing.T, code Code, identifier uint8, secret []byte, includeMessageAuthenticator bool, attributes Attributes) ([]byte, [16]byte) {
	t.Helper()
	if includeMessageAuthenticator {
		attributes = append(attributes.Clone(), NewAttribute(AttrMessageAuthenticator, make([]byte, 16)))
	}
	raw, err := MarshalPacket(&Packet{Code: code, Identifier: identifier, Attributes: attributes.Clone()})
	if err != nil {
		t.Fatalf("MarshalPacket: %v", err)
	}
	authenticator, err := signDynamicRequest(raw, secret, includeMessageAuthenticator)
	if err != nil {
		t.Fatalf("signDynamicRequest: %v", err)
	}
	return raw, authenticator
}

// dynamicTestAttributes returns representative request attributes. | dynamicTestAttributes 返回具有
// 代表性的请求属性。
func dynamicTestAttributes() Attributes {
	var port [4]byte
	binary.BigEndian.PutUint32(port[:], 9)
	var timestamp [4]byte
	binary.BigEndian.PutUint32(timestamp[:], 1_700_000_100)
	return Attributes{
		NewAttribute(AttrAcctSessionID, []byte("session-1")),
		NewAttribute(AttrUserName, []byte("alice")),
		NewAttribute(AttrNASIPAddress, []byte{192, 0, 2, 10}),
		NewAttribute(AttrNASIdentifier, []byte("nas-1")),
		NewAttribute(AttrNASPort, port[:]),
		NewAttribute(AttrEventTimestamp, timestamp[:]),
		NewAttribute(AttrProxyState, []byte("proxy-state-1")),
		NewAttribute(AttrFilterID, []byte("acl-1")),
	}
}

// verifyDynamicTestResponse parses raw and verifies both authenticators. | verifyDynamicTestResponse
// 解析 raw 并校验两个认证符。
func verifyDynamicTestResponse(t *testing.T, raw, secret []byte, requestAuthenticator [16]byte, wantMessageAuthenticator bool) *Packet {
	t.Helper()
	packet, err := ParsePacket(raw)
	if err != nil {
		t.Fatalf("ParsePacket: %v", err)
	}
	if err := verifyResponseAuthenticator(raw, secret, requestAuthenticator); err != nil {
		t.Fatalf("Response Authenticator: %v", err)
	}
	present, valid, err := verifyMessageAuthenticatorRaw(raw, secret, requestAuthenticator)
	if err != nil {
		t.Fatalf("verify Message-Authenticator: %v", err)
	}
	if wantMessageAuthenticator {
		if !present || !valid {
			t.Fatalf("Message-Authenticator = present %v valid %v, want a valid one", present, valid)
		}
	} else if present {
		t.Fatal("response carried an unexpected Message-Authenticator")
	}
	return packet
}

func TestDynamicServerACKEndToEnd(t *testing.T) {
	secret := []byte("testing-secret")
	requests := make(chan *DynamicAuthorizationPacket, 2)
	handler := DynamicRequestHandlerFunc(func(ctx context.Context, request *DynamicAuthorizationPacket) (*DynamicAuthorizationResult, error) {
		requests <- request
		return &DynamicAuthorizationResult{
			Accept:       true,
			ReplyMessage: "accepted",
			Attributes: Attributes{
				NewAttribute(AttrSessionTimeout, []byte{0, 0, 1, 44}),
			},
		}, nil
	})
	harness := newRunningDynamicServer(t, DynamicServerConfig{Secret: secret, Handler: handler})
	conn := dialDynamic(t, harness.addr)

	cases := []struct {
		code         Code
		responseCode Code
	}{
		{code: CodeCoARequest, responseCode: CodeCoAACK},
		{code: CodeDisconnectRequest, responseCode: CodeDisconnectACK},
	}
	for _, testCase := range cases {
		raw, requestAuthenticator := buildDynamicTestRequest(t, testCase.code, uint8(testCase.code), secret, false, dynamicTestAttributes())
		responseRaw, err := sendDynamicDatagram(t, conn, raw, 2*time.Second)
		if err != nil {
			t.Fatalf("code %d: %v", testCase.code, err)
		}
		packet := verifyDynamicTestResponse(t, responseRaw, secret, requestAuthenticator, false)
		if packet.Code != testCase.responseCode {
			t.Fatalf("response code = %d, want %d", packet.Code, testCase.responseCode)
		}
		if packet.Identifier != uint8(testCase.code) {
			t.Fatalf("response identifier = %d", packet.Identifier)
		}
		assertStringAttribute(t, packet.Attributes, AttrReplyMessage, "accepted")
		assertUint32Attribute(t, packet.Attributes, AttrSessionTimeout, 300)
		proxyStates := packet.Attributes.GetAll(AttrProxyState)
		if len(proxyStates) != 1 || proxyStates[0].String() != "proxy-state-1" {
			t.Fatalf("Proxy-State was not echoed: %+v", proxyStates)
		}

		var request *DynamicAuthorizationPacket
		select {
		case request = <-requests:
		case <-time.After(2 * time.Second):
			t.Fatal("handler was not invoked")
		}
		if request.Code != testCase.code || request.Identifier != uint8(testCase.code) {
			t.Fatalf("handler request header = %+v", request)
		}
		if request.SessionID != "session-1" || request.UserName != "alice" || request.NASIdentifier != "nas-1" {
			t.Fatalf("handler request identities = %+v", request)
		}
		if request.NASPort != 9 {
			t.Fatalf("NAS-Port = %d", request.NASPort)
		}
		if !request.HasEventTimestamp || request.EventTimestamp.Unix() != 1_700_000_100 {
			t.Fatalf("Event-Timestamp = %v, %v", request.EventTimestamp, request.HasEventTimestamp)
		}
		if !request.NASIPAddress.Equal(net.IPv4(192, 0, 2, 10)) {
			t.Fatalf("NAS-IP-Address = %v", request.NASIPAddress)
		}
		if request.RemoteAddr == nil {
			t.Fatal("handler request lacks RemoteAddr")
		}
		if request.HasMessageAuthenticator {
			t.Fatal("request reported a Message-Authenticator that was not sent")
		}
	}
}

func TestDynamicServerResultMapping(t *testing.T) {
	secret := []byte("testing-secret")
	handlerError := errors.New("boom-internal-detail")
	cases := []struct {
		name         string
		requestCode  Code
		result       *DynamicAuthorizationResult
		handlerErr   error
		responseCode Code
		errorCause   ErrorCause
		replyMessage string
	}{
		{
			name:         "nak with cause",
			requestCode:  CodeCoARequest,
			result:       &DynamicAuthorizationResult{ErrorCause: ErrorCauseSessionContextNotFound, ReplyMessage: "gone"},
			responseCode: CodeCoANAK,
			errorCause:   ErrorCauseSessionContextNotFound,
			replyMessage: "gone",
		},
		{
			name:         "nak without cause",
			requestCode:  CodeDisconnectRequest,
			result:       &DynamicAuthorizationResult{},
			responseCode: CodeDisconnectNAK,
		},
		{
			name:         "disconnect ack residual context",
			requestCode:  CodeDisconnectRequest,
			result:       &DynamicAuthorizationResult{Accept: true, ErrorCause: ErrorCauseResidualSessionContextRemoved},
			responseCode: CodeDisconnectACK,
			errorCause:   ErrorCauseResidualSessionContextRemoved,
		},
		{
			name:         "coa ack with residual cause is invalid",
			requestCode:  CodeCoARequest,
			result:       &DynamicAuthorizationResult{Accept: true, ErrorCause: ErrorCauseResidualSessionContextRemoved},
			responseCode: CodeCoANAK,
			errorCause:   ErrorCauseResourcesUnavailable,
		},
		{
			name:         "ack with client error cause is invalid",
			requestCode:  CodeCoARequest,
			result:       &DynamicAuthorizationResult{Accept: true, ErrorCause: ErrorCauseInvalidRequest},
			responseCode: CodeCoANAK,
			errorCause:   ErrorCauseResourcesUnavailable,
		},
		{
			name:         "nak with success cause is invalid",
			requestCode:  CodeCoARequest,
			result:       &DynamicAuthorizationResult{ErrorCause: ErrorCauseResidualSessionContextRemoved},
			responseCode: CodeCoANAK,
			errorCause:   ErrorCauseResourcesUnavailable,
		},
		{
			name:         "nil result",
			requestCode:  CodeCoARequest,
			responseCode: CodeCoANAK,
			errorCause:   ErrorCauseResourcesUnavailable,
		},
		{
			name:         "handler error",
			requestCode:  CodeDisconnectRequest,
			handlerErr:   handlerError,
			responseCode: CodeDisconnectNAK,
			errorCause:   ErrorCauseResourcesUnavailable,
		},
		{
			name:        "unencodable response attribute",
			requestCode: CodeCoARequest,
			result: &DynamicAuthorizationResult{Accept: true, Attributes: Attributes{
				NewAttribute(0, []byte("reserved")),
			}},
			responseCode: CodeCoANAK,
			errorCause:   ErrorCauseResourcesUnavailable,
		},
	}
	for _, testCase := range cases {
		t.Run(testCase.name, func(t *testing.T) {
			handler := DynamicRequestHandlerFunc(func(ctx context.Context, request *DynamicAuthorizationPacket) (*DynamicAuthorizationResult, error) {
				return testCase.result, testCase.handlerErr
			})
			harness := newRunningDynamicServer(t, DynamicServerConfig{Secret: secret, Handler: handler})
			conn := dialDynamic(t, harness.addr)
			raw, requestAuthenticator := buildDynamicTestRequest(t, testCase.requestCode, 3, secret, false, Attributes{
				NewAttribute(AttrAcctSessionID, []byte("session-1")),
			})
			responseRaw, err := sendDynamicDatagram(t, conn, raw, 2*time.Second)
			if err != nil {
				t.Fatalf("send: %v", err)
			}
			packet := verifyDynamicTestResponse(t, responseRaw, secret, requestAuthenticator, false)
			if packet.Code != testCase.responseCode {
				t.Fatalf("response code = %d, want %d", packet.Code, testCase.responseCode)
			}
			cause, hasCause := packet.Attributes.Uint32(AttrErrorCause)
			if testCase.errorCause == 0 {
				if hasCause {
					t.Fatalf("unexpected Error-Cause %d", cause)
				}
			} else if !hasCause || ErrorCause(cause) != testCase.errorCause {
				t.Fatalf("Error-Cause = %d, %v, want %d", cause, hasCause, testCase.errorCause)
			}
			message, hasMessage := packet.Attributes.Get(AttrReplyMessage)
			if testCase.replyMessage == "" {
				if hasMessage {
					t.Fatalf("unexpected Reply-Message %q", message.String())
				}
			} else if !hasMessage || message.String() != testCase.replyMessage {
				t.Fatalf("Reply-Message = %q, %v", message.String(), hasMessage)
			}
			if bytes.Contains(responseRaw, []byte(handlerError.Error())) {
				t.Fatal("response leaked the handler error text")
			}
		})
	}
}

func TestDynamicServerFiltersReservedResultAttributes(t *testing.T) {
	secret := []byte("testing-secret")
	handler := DynamicRequestHandlerFunc(func(ctx context.Context, request *DynamicAuthorizationPacket) (*DynamicAuthorizationResult, error) {
		return &DynamicAuthorizationResult{
			Accept:       true,
			ReplyMessage: "typed",
			Attributes: Attributes{
				errorCauseAttribute(ErrorCauseInvalidRequest),
				NewAttribute(AttrReplyMessage, []byte("attribute")),
				NewAttribute(AttrMessageAuthenticator, make([]byte, 16)),
				NewAttribute(AttrFilterID, []byte("acl-2")),
			},
		}, nil
	})
	harness := newRunningDynamicServer(t, DynamicServerConfig{Secret: secret, Handler: handler})
	conn := dialDynamic(t, harness.addr)
	raw, requestAuthenticator := buildDynamicTestRequest(t, CodeCoARequest, 4, secret, false, Attributes{
		NewAttribute(AttrAcctSessionID, []byte("session-1")),
	})
	responseRaw, err := sendDynamicDatagram(t, conn, raw, 2*time.Second)
	if err != nil {
		t.Fatalf("send: %v", err)
	}
	packet := verifyDynamicTestResponse(t, responseRaw, secret, requestAuthenticator, false)
	if packet.Code != CodeCoAACK {
		t.Fatalf("response code = %d", packet.Code)
	}
	if _, ok := packet.Attributes.Get(AttrErrorCause); ok {
		t.Fatal("handler-provided Error-Cause was not filtered")
	}
	assertStringAttribute(t, packet.Attributes, AttrReplyMessage, "typed")
	assertStringAttribute(t, packet.Attributes, AttrFilterID, "acl-2")
	if _, ok := packet.Attributes.Get(AttrMessageAuthenticator); ok {
		t.Fatal("handler-provided Message-Authenticator was not filtered")
	}
}

func TestDynamicServerMessageAuthenticator(t *testing.T) {
	secret := []byte("testing-secret")
	t.Run("present and signed", func(t *testing.T) {
		requests := make(chan *DynamicAuthorizationPacket, 1)
		handler := DynamicRequestHandlerFunc(func(ctx context.Context, request *DynamicAuthorizationPacket) (*DynamicAuthorizationResult, error) {
			requests <- request
			return &DynamicAuthorizationResult{Accept: true}, nil
		})
		harness := newRunningDynamicServer(t, DynamicServerConfig{Secret: secret, Handler: handler})
		conn := dialDynamic(t, harness.addr)
		raw, requestAuthenticator := buildDynamicTestRequest(t, CodeCoARequest, 5, secret, true, dynamicTestAttributes())
		responseRaw, err := sendDynamicDatagram(t, conn, raw, 2*time.Second)
		if err != nil {
			t.Fatalf("send: %v", err)
		}
		verifyDynamicTestResponse(t, responseRaw, secret, requestAuthenticator, true)
		request := <-requests
		if !request.HasMessageAuthenticator {
			t.Fatal("handler did not observe the verified Message-Authenticator")
		}
	})
	t.Run("absent stays absent", func(t *testing.T) {
		handler := DynamicRequestHandlerFunc(func(ctx context.Context, request *DynamicAuthorizationPacket) (*DynamicAuthorizationResult, error) {
			return &DynamicAuthorizationResult{Accept: true}, nil
		})
		harness := newRunningDynamicServer(t, DynamicServerConfig{Secret: secret, Handler: handler})
		conn := dialDynamic(t, harness.addr)
		raw, requestAuthenticator := buildDynamicTestRequest(t, CodeCoARequest, 6, secret, false, dynamicTestAttributes())
		responseRaw, err := sendDynamicDatagram(t, conn, raw, 2*time.Second)
		if err != nil {
			t.Fatalf("send: %v", err)
		}
		verifyDynamicTestResponse(t, responseRaw, secret, requestAuthenticator, false)
	})
	t.Run("required missing", func(t *testing.T) {
		var calls atomic.Int32
		handler := DynamicRequestHandlerFunc(func(ctx context.Context, request *DynamicAuthorizationPacket) (*DynamicAuthorizationResult, error) {
			calls.Add(1)
			return &DynamicAuthorizationResult{Accept: true}, nil
		})
		harness := newRunningDynamicServer(t, DynamicServerConfig{
			Secret:                      secret,
			Handler:                     handler,
			RequireMessageAuthenticator: true,
		})
		conn := dialDynamic(t, harness.addr)
		raw, _ := buildDynamicTestRequest(t, CodeCoARequest, 7, secret, false, dynamicTestAttributes())
		requireNoDynamicResponse(t, conn, raw)
		if calls.Load() != 0 {
			t.Fatal("handler ran for a request missing the required Message-Authenticator")
		}
	})
	t.Run("required valid", func(t *testing.T) {
		handler := DynamicRequestHandlerFunc(func(ctx context.Context, request *DynamicAuthorizationPacket) (*DynamicAuthorizationResult, error) {
			return &DynamicAuthorizationResult{Accept: true}, nil
		})
		harness := newRunningDynamicServer(t, DynamicServerConfig{
			Secret:                      secret,
			Handler:                     handler,
			RequireMessageAuthenticator: true,
		})
		conn := dialDynamic(t, harness.addr)
		raw, requestAuthenticator := buildDynamicTestRequest(t, CodeDisconnectRequest, 8, secret, true, dynamicTestAttributes())
		responseRaw, err := sendDynamicDatagram(t, conn, raw, 2*time.Second)
		if err != nil {
			t.Fatalf("send: %v", err)
		}
		verifyDynamicTestResponse(t, responseRaw, secret, requestAuthenticator, true)
	})
	t.Run("invalid", func(t *testing.T) {
		var calls atomic.Int32
		handler := DynamicRequestHandlerFunc(func(ctx context.Context, request *DynamicAuthorizationPacket) (*DynamicAuthorizationResult, error) {
			calls.Add(1)
			return &DynamicAuthorizationResult{Accept: true}, nil
		})
		harness := newRunningDynamicServer(t, DynamicServerConfig{Secret: secret, Handler: handler})
		conn := dialDynamic(t, harness.addr)
		raw, _ := buildDynamicTestRequest(t, CodeCoARequest, 9, secret, true, dynamicTestAttributes())
		offsets, err := messageAuthenticatorOffsets(raw)
		if err != nil || len(offsets) != 1 {
			t.Fatalf("messageAuthenticatorOffsets = %v, %v", offsets, err)
		}
		// Corrupt the Message-Authenticator and recompute only the Request Authenticator, so the
		// request reaches the Message-Authenticator check with a valid outer authenticator. |
		// 破坏 Message-Authenticator 后只重算 Request Authenticator，使请求以合法外层认证符进入
		// Message-Authenticator 校验。
		raw[offsets[0]] ^= 0xff
		authenticator, err := accountingRequestAuthenticator(raw, secret)
		if err != nil {
			t.Fatalf("accountingRequestAuthenticator: %v", err)
		}
		copy(raw[4:HeaderLength], authenticator[:])
		requireNoDynamicResponse(t, conn, raw)
		if calls.Load() != 0 {
			t.Fatal("handler ran for a request with an invalid Message-Authenticator")
		}
	})
}

func TestDynamicServerRejectsUnauthenticatedRequests(t *testing.T) {
	secret := []byte("testing-secret")
	var calls atomic.Int32
	handler := DynamicRequestHandlerFunc(func(ctx context.Context, request *DynamicAuthorizationPacket) (*DynamicAuthorizationResult, error) {
		calls.Add(1)
		return &DynamicAuthorizationResult{Accept: true}, nil
	})
	harness := newRunningDynamicServer(t, DynamicServerConfig{Secret: secret, Handler: handler})
	conn := dialDynamic(t, harness.addr)

	wrongSecretRaw, _ := buildDynamicTestRequest(t, CodeCoARequest, 10, []byte("other-secret"), false, dynamicTestAttributes())
	requireNoDynamicResponse(t, conn, wrongSecretRaw)

	corruptedRaw, _ := buildDynamicTestRequest(t, CodeCoARequest, 11, secret, false, dynamicTestAttributes())
	corruptedRaw[5] ^= 0xff
	requireNoDynamicResponse(t, conn, corruptedRaw)

	if calls.Load() != 0 {
		t.Fatalf("handler ran %d times for unauthenticated requests", calls.Load())
	}
}

func TestDynamicServerDropsMalformedAndOversizedPackets(t *testing.T) {
	secret := []byte("testing-secret")
	var calls atomic.Int32
	handler := DynamicRequestHandlerFunc(func(ctx context.Context, request *DynamicAuthorizationPacket) (*DynamicAuthorizationResult, error) {
		calls.Add(1)
		return &DynamicAuthorizationResult{Accept: true}, nil
	})
	harness := newRunningDynamicServer(t, DynamicServerConfig{
		Secret:        secret,
		Handler:       handler,
		MaxPacketSize: 128,
	})
	conn := dialDynamic(t, harness.addr)

	requireNoDynamicResponse(t, conn, []byte{byte(CodeCoARequest), 1, 0, 10})

	malformed := make([]byte, 22)
	malformed[0] = byte(CodeCoARequest)
	malformed[1] = 2
	binary.BigEndian.PutUint16(malformed[2:4], 22)
	malformed[20] = 0
	malformed[21] = 2
	requireNoDynamicResponse(t, conn, malformed)

	unknownCode, _ := buildDynamicTestRequest(t, CodeAccessRequest, 3, secret, false, nil)
	requireNoDynamicResponse(t, conn, unknownCode)

	oversized := make([]byte, 200)
	oversized[0] = byte(CodeCoARequest)
	oversized[1] = 4
	binary.BigEndian.PutUint16(oversized[2:4], 200)
	requireNoDynamicResponse(t, conn, oversized)

	raw, requestAuthenticator := buildDynamicTestRequest(t, CodeCoARequest, 5, secret, false, Attributes{
		NewAttribute(AttrAcctSessionID, []byte("session-1")),
	})
	responseRaw, err := sendDynamicDatagram(t, conn, raw, 2*time.Second)
	if err != nil {
		t.Fatalf("valid request after drops: %v", err)
	}
	verifyDynamicTestResponse(t, responseRaw, secret, requestAuthenticator, false)
	if calls.Load() != 1 {
		t.Fatalf("handler ran %d times, want 1", calls.Load())
	}
}

func TestDynamicServerDuplicateCacheReplay(t *testing.T) {
	secret := []byte("testing-secret")
	var calls atomic.Int32
	handler := DynamicRequestHandlerFunc(func(ctx context.Context, request *DynamicAuthorizationPacket) (*DynamicAuthorizationResult, error) {
		calls.Add(1)
		return &DynamicAuthorizationResult{Accept: true, ReplyMessage: "handled"}, nil
	})
	harness := newRunningDynamicServer(t, DynamicServerConfig{Secret: secret, Handler: handler})
	conn := dialDynamic(t, harness.addr)
	raw, requestAuthenticator := buildDynamicTestRequest(t, CodeCoARequest, 20, secret, true, dynamicTestAttributes())

	first, err := sendDynamicDatagram(t, conn, raw, 2*time.Second)
	if err != nil {
		t.Fatalf("first send: %v", err)
	}
	second, err := sendDynamicDatagram(t, conn, raw, 2*time.Second)
	if err != nil {
		t.Fatalf("duplicate send: %v", err)
	}
	if !bytes.Equal(first, second) {
		t.Fatal("duplicate request did not receive the byte-identical cached response")
	}
	if calls.Load() != 1 {
		t.Fatalf("handler ran %d times for a duplicate, want 1", calls.Load())
	}
	verifyDynamicTestResponse(t, first, secret, requestAuthenticator, true)

	otherRaw, _ := buildDynamicTestRequest(t, CodeCoARequest, 21, secret, true, dynamicTestAttributes())
	if _, err := sendDynamicDatagram(t, conn, otherRaw, 2*time.Second); err != nil {
		t.Fatalf("new identifier send: %v", err)
	}
	if calls.Load() != 2 {
		t.Fatalf("handler ran %d times, want 2 for a new identifier", calls.Load())
	}
}

func TestDynamicServerDuplicateCacheExpiry(t *testing.T) {
	secret := []byte("testing-secret")
	var clockNanos atomic.Int64
	clockNanos.Store(time.Unix(1_700_000_000, 0).UnixNano())
	cache, err := NewDynamicDuplicateCache(DynamicDuplicateCacheConfig{
		Capacity: 16,
		TTL:      10 * time.Second,
		Clock: func() time.Time {
			return time.Unix(0, clockNanos.Load()).UTC()
		},
	})
	if err != nil {
		t.Fatalf("NewDynamicDuplicateCache: %v", err)
	}
	var calls atomic.Int32
	handler := DynamicRequestHandlerFunc(func(ctx context.Context, request *DynamicAuthorizationPacket) (*DynamicAuthorizationResult, error) {
		calls.Add(1)
		return &DynamicAuthorizationResult{Accept: true}, nil
	})
	harness := newRunningDynamicServer(t, DynamicServerConfig{Secret: secret, Handler: handler, DuplicateCache: cache})
	conn := dialDynamic(t, harness.addr)
	raw, _ := buildDynamicTestRequest(t, CodeCoARequest, 22, secret, false, dynamicTestAttributes())

	if _, err := sendDynamicDatagram(t, conn, raw, 2*time.Second); err != nil {
		t.Fatalf("first send: %v", err)
	}
	if _, err := sendDynamicDatagram(t, conn, raw, 2*time.Second); err != nil {
		t.Fatalf("duplicate send: %v", err)
	}
	if calls.Load() != 1 {
		t.Fatalf("handler ran %d times before expiry, want 1", calls.Load())
	}

	clockNanos.Add(int64(11 * time.Second))
	if _, err := sendDynamicDatagram(t, conn, raw, 2*time.Second); err != nil {
		t.Fatalf("send after expiry: %v", err)
	}
	if calls.Load() != 2 {
		t.Fatalf("handler ran %d times after expiry, want 2", calls.Load())
	}
}

func TestDynamicServerConcurrentDuplicates(t *testing.T) {
	secret := []byte("testing-secret")
	var calls atomic.Int32
	handler := DynamicRequestHandlerFunc(func(ctx context.Context, request *DynamicAuthorizationPacket) (*DynamicAuthorizationResult, error) {
		calls.Add(1)
		time.Sleep(10 * time.Millisecond)
		return &DynamicAuthorizationResult{Accept: true, ReplyMessage: "once"}, nil
	})
	harness := newRunningDynamicServer(t, DynamicServerConfig{Secret: secret, Handler: handler})
	conn := dialDynamic(t, harness.addr)
	raw, requestAuthenticator := buildDynamicTestRequest(t, CodeDisconnectRequest, 23, secret, false, dynamicTestAttributes())

	const senders = 8
	var waitGroup sync.WaitGroup
	for i := 0; i < senders; i++ {
		waitGroup.Add(1)
		go func() {
			defer waitGroup.Done()
			if _, err := conn.Write(raw); err != nil {
				t.Errorf("concurrent write: %v", err)
			}
		}()
	}
	waitGroup.Wait()

	responses := make([][]byte, 0, senders)
	for i := 0; i < senders; i++ {
		_ = conn.SetReadDeadline(time.Now().Add(2 * time.Second))
		buffer := make([]byte, MaxPacketLength)
		n, err := conn.Read(buffer)
		if err != nil {
			t.Fatalf("read response %d: %v", i, err)
		}
		response := make([]byte, n)
		copy(response, buffer[:n])
		responses = append(responses, response)
	}
	for i := 1; i < len(responses); i++ {
		if !bytes.Equal(responses[0], responses[i]) {
			t.Fatalf("duplicate response %d differs from the first", i)
		}
	}
	if calls.Load() != 1 {
		t.Fatalf("handler ran %d times for concurrent duplicates, want 1", calls.Load())
	}
	verifyDynamicTestResponse(t, responses[0], secret, requestAuthenticator, false)
}

// TestDynamicServerDeduplicatesClientRetransmission crosses the real Client and DynamicServer: a
// handler slower than the client timeout forces a retransmission, and the duplicate cache must keep
// the handler count at one while the client still receives the original ACK. |
// TestDynamicServerDeduplicatesClientRetransmission 打通真实 Client 与 DynamicServer：慢于客户端超时的
// 处理器触发重传，重复缓存必须把处理器调用保持为一次，同时客户端仍收到原始 ACK。
func TestDynamicServerDeduplicatesClientRetransmission(t *testing.T) {
	secret := []byte("testing-secret")
	var calls atomic.Int32
	handler := DynamicRequestHandlerFunc(func(ctx context.Context, request *DynamicAuthorizationPacket) (*DynamicAuthorizationResult, error) {
		calls.Add(1)
		time.Sleep(150 * time.Millisecond)
		return &DynamicAuthorizationResult{Accept: true, ReplyMessage: "slow"}, nil
	})
	harness := newRunningDynamicServer(t, DynamicServerConfig{Secret: secret, Handler: handler})
	client := newTestClient(t, ClientConfig{
		Address: harness.addr,
		Secret:  secret,
		Timeout: 120 * time.Millisecond,
		Retries: 1,
	})
	response, err := client.SendCoA(context.Background(), &CoARequest{
		SessionID:                   "session-1",
		IncludeMessageAuthenticator: true,
	})
	if err != nil {
		t.Fatalf("SendCoA: %v", err)
	}
	if response.Code != CodeCoAACK || response.ReplyMessage != "slow" {
		t.Fatalf("response = %+v", response)
	}
	time.Sleep(300 * time.Millisecond)
	if calls.Load() != 1 {
		t.Fatalf("handler ran %d times for a retransmission, want 1", calls.Load())
	}
}

func TestDynamicServerContextShutdown(t *testing.T) {
	server, err := NewDynamicServer(DynamicServerConfig{
		Address: "127.0.0.1:0",
		Network: "udp4",
		Secret:  []byte("testing-secret"),
		Handler: DynamicRequestHandlerFunc(func(ctx context.Context, request *DynamicAuthorizationPacket) (*DynamicAuthorizationResult, error) {
			return &DynamicAuthorizationResult{Accept: true}, nil
		}),
		Logger: testDynamicLogger(),
	})
	if err != nil {
		t.Fatalf("NewDynamicServer: %v", err)
	}
	t.Cleanup(func() {
		_ = server.Close()
	})
	if _, err := server.Listen(); err != nil {
		t.Fatalf("Listen: %v", err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() {
		done <- server.Serve(ctx)
	}()
	cancel()
	select {
	case err := <-done:
		if err != nil {
			t.Fatalf("Serve after context cancellation = %v, want nil", err)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("Serve did not return after context cancellation")
	}
}

func TestDynamicServerClose(t *testing.T) {
	server, err := NewDynamicServer(DynamicServerConfig{
		Address: "127.0.0.1:0",
		Network: "udp4",
		Secret:  []byte("testing-secret"),
		Handler: DynamicRequestHandlerFunc(func(ctx context.Context, request *DynamicAuthorizationPacket) (*DynamicAuthorizationResult, error) {
			return &DynamicAuthorizationResult{Accept: true}, nil
		}),
		Logger: testDynamicLogger(),
	})
	if err != nil {
		t.Fatalf("NewDynamicServer: %v", err)
	}
	if err := server.Serve(context.Background()); !errors.Is(err, ErrInvalidConfig) {
		t.Fatalf("Serve before Listen = %v, want ErrInvalidConfig", err)
	}
	if _, err := server.Listen(); err != nil {
		t.Fatalf("Listen: %v", err)
	}
	done := make(chan error, 1)
	go func() {
		done <- server.Serve(context.Background())
	}()
	waitForDynamicServerServing(t, server)
	if err := server.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}
	select {
	case err := <-done:
		if !errors.Is(err, ErrServerClosed) {
			t.Fatalf("Serve after Close = %v, want ErrServerClosed", err)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("Serve did not return after Close")
	}
	if err := server.Close(); err != nil {
		t.Fatalf("second Close: %v", err)
	}
	if _, err := server.Listen(); !errors.Is(err, ErrServerClosed) {
		t.Fatalf("Listen after Close = %v, want ErrServerClosed", err)
	}
	if err := server.Serve(context.Background()); !errors.Is(err, ErrServerClosed) {
		t.Fatalf("Serve after Close = %v, want ErrServerClosed", err)
	}
}

func TestDynamicServerRejectsConcurrentServe(t *testing.T) {
	harness := newRunningDynamicServer(t, DynamicServerConfig{
		Secret: []byte("testing-secret"),
		Handler: DynamicRequestHandlerFunc(func(ctx context.Context, request *DynamicAuthorizationPacket) (*DynamicAuthorizationResult, error) {
			return &DynamicAuthorizationResult{Accept: true}, nil
		}),
	})
	waitForDynamicServerServing(t, harness.server)
	if err := harness.server.Serve(context.Background()); !errors.Is(err, ErrInvalidConfig) {
		t.Fatalf("second Serve = %v, want ErrInvalidConfig", err)
	}
}

// waitForDynamicServerServing waits until Serve has claimed the socket. | waitForDynamicServerServing
// 等待 Serve 接管套接字。
func waitForDynamicServerServing(t *testing.T, server *DynamicServer) {
	t.Helper()
	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		server.mu.RLock()
		serving := server.serving
		server.mu.RUnlock()
		if serving {
			return
		}
		time.Sleep(time.Millisecond)
	}
	t.Fatal("server did not start serving")
}

func TestDynamicServerListenAndServeCanceledContext(t *testing.T) {
	server, err := NewDynamicServer(DynamicServerConfig{
		Address: "127.0.0.1:0",
		Network: "udp4",
		Secret:  []byte("testing-secret"),
		Handler: DynamicRequestHandlerFunc(func(ctx context.Context, request *DynamicAuthorizationPacket) (*DynamicAuthorizationResult, error) {
			return &DynamicAuthorizationResult{Accept: true}, nil
		}),
		Logger: testDynamicLogger(),
	})
	if err != nil {
		t.Fatalf("NewDynamicServer: %v", err)
	}
	defer server.Close()
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if err := server.ListenAndServe(ctx); err != nil {
		t.Fatalf("ListenAndServe = %v, want nil", err)
	}
}

func TestDynamicServerListenFailure(t *testing.T) {
	first := newRunningDynamicServer(t, DynamicServerConfig{
		Secret: []byte("testing-secret"),
		Handler: DynamicRequestHandlerFunc(func(ctx context.Context, request *DynamicAuthorizationPacket) (*DynamicAuthorizationResult, error) {
			return &DynamicAuthorizationResult{Accept: true}, nil
		}),
	})
	second, err := NewDynamicServer(DynamicServerConfig{
		Address: first.addr,
		Network: "udp4",
		Secret:  []byte("testing-secret"),
		Handler: DynamicRequestHandlerFunc(func(ctx context.Context, request *DynamicAuthorizationPacket) (*DynamicAuthorizationResult, error) {
			return &DynamicAuthorizationResult{Accept: true}, nil
		}),
		Logger: testDynamicLogger(),
	})
	if err != nil {
		t.Fatalf("NewDynamicServer: %v", err)
	}
	defer second.Close()
	if _, err := second.Listen(); !errors.Is(err, ErrNetwork) {
		t.Fatalf("duplicate Listen = %v, want ErrNetwork", err)
	}
}

func TestDynamicServerHandlerContextTimeout(t *testing.T) {
	deadlineSeen := make(chan bool, 1)
	handler := DynamicRequestHandlerFunc(func(ctx context.Context, request *DynamicAuthorizationPacket) (*DynamicAuthorizationResult, error) {
		_, ok := ctx.Deadline()
		deadlineSeen <- ok
		return &DynamicAuthorizationResult{Accept: true}, nil
	})
	harness := newRunningDynamicServer(t, DynamicServerConfig{
		Secret:  []byte("testing-secret"),
		Handler: handler,
		Timeout: 250 * time.Millisecond,
	})
	conn := dialDynamic(t, harness.addr)
	raw, requestAuthenticator := buildDynamicTestRequest(t, CodeCoARequest, 30, []byte("testing-secret"), false, dynamicTestAttributes())
	responseRaw, err := sendDynamicDatagram(t, conn, raw, 2*time.Second)
	if err != nil {
		t.Fatalf("send: %v", err)
	}
	verifyDynamicTestResponse(t, responseRaw, harness.server.secret, requestAuthenticator, false)
	select {
	case ok := <-deadlineSeen:
		if !ok {
			t.Fatal("handler context carried no deadline")
		}
	case <-time.After(2 * time.Second):
		t.Fatal("handler was not invoked")
	}
}

func TestNewDynamicServerValidation(t *testing.T) {
	handler := DynamicRequestHandlerFunc(func(ctx context.Context, request *DynamicAuthorizationPacket) (*DynamicAuthorizationResult, error) {
		return &DynamicAuthorizationResult{Accept: true}, nil
	})
	base := DynamicServerConfig{Secret: []byte("testing-secret"), Handler: handler}
	cases := []struct {
		name   string
		config DynamicServerConfig
	}{
		{name: "missing secret", config: DynamicServerConfig{Handler: handler}},
		{name: "nil handler", config: DynamicServerConfig{Secret: []byte("testing-secret")}},
		{name: "tcp network", config: func() DynamicServerConfig {
			config := base
			config.Network = NetworkTCP
			return config
		}()},
		{name: "address without port", config: func() DynamicServerConfig {
			config := base
			config.Address = "127.0.0.1"
			return config
		}()},
		{name: "negative timeout", config: func() DynamicServerConfig {
			config := base
			config.Timeout = -time.Second
			return config
		}()},
		{name: "max packet below header", config: func() DynamicServerConfig {
			config := base
			config.MaxPacketSize = HeaderLength - 1
			return config
		}()},
		{name: "max packet above limit", config: func() DynamicServerConfig {
			config := base
			config.MaxPacketSize = MaxPacketLength + 1
			return config
		}()},
		{name: "negative duplicate ttl", config: func() DynamicServerConfig {
			config := base
			config.DuplicateTTL = -time.Second
			return config
		}()},
		{name: "negative duplicate capacity", config: func() DynamicServerConfig {
			config := base
			config.DuplicateCapacity = -1
			return config
		}()},
	}
	for _, testCase := range cases {
		t.Run(testCase.name, func(t *testing.T) {
			if _, err := NewDynamicServer(testCase.config); !errors.Is(err, ErrInvalidConfig) {
				t.Fatalf("error = %v, want ErrInvalidConfig", err)
			}
		})
	}

	server, err := NewDynamicServer(base)
	if err != nil {
		t.Fatalf("defaults: %v", err)
	}
	defer server.Close()
	if server.cfg.Network != NetworkUDP {
		t.Fatalf("default network = %q", server.cfg.Network)
	}
	if server.cfg.Address != DefaultDynamicServerAddress {
		t.Fatalf("default address = %q", server.cfg.Address)
	}
	if server.cfg.Timeout != DefaultTimeout {
		t.Fatalf("default timeout = %s", server.cfg.Timeout)
	}
	if server.cfg.MaxPacketSize != MaxPacketLength {
		t.Fatalf("default max packet size = %d", server.cfg.MaxPacketSize)
	}
	if server.cache == nil {
		t.Fatal("server did not create a duplicate cache")
	}
}

func TestNewDynamicServerUsesInjectedCache(t *testing.T) {
	cache, err := NewDynamicDuplicateCache(DynamicDuplicateCacheConfig{Capacity: 2})
	if err != nil {
		t.Fatalf("NewDynamicDuplicateCache: %v", err)
	}
	server, err := NewDynamicServer(DynamicServerConfig{
		Secret: []byte("testing-secret"),
		Handler: DynamicRequestHandlerFunc(func(ctx context.Context, request *DynamicAuthorizationPacket) (*DynamicAuthorizationResult, error) {
			return &DynamicAuthorizationResult{Accept: true}, nil
		}),
		DuplicateCache: cache,
	})
	if err != nil {
		t.Fatalf("NewDynamicServer: %v", err)
	}
	defer server.Close()
	if server.cache != cache {
		t.Fatal("server did not use the injected duplicate cache")
	}
	if server.Addr() != nil {
		t.Fatalf("Addr before Listen = %v", server.Addr())
	}
}

func TestDynamicRequestHandlerFuncNil(t *testing.T) {
	var handler DynamicRequestHandlerFunc
	if _, err := handler.HandleDynamicAuthorization(context.Background(), nil); !errors.Is(err, ErrInvalidRequest) {
		t.Fatalf("error = %v, want ErrInvalidRequest", err)
	}
}
