package radius

import (
	"context"
	"crypto/tls"
	"errors"
	"net"
	"testing"
	"time"
)

// accessCapture is a copy of one AccessServerRequest observed by a test authenticator. |
// accessCapture 是测试认证器观察到的一次 AccessServerRequest 副本。
type accessCapture struct {
	userName   string
	method     AuthMethod
	papOK      bool
	chapOK     bool
	hasMA      bool
	identifier uint8
	attributes Attributes
	remote     string
}

// captureAccess copies a request while its ephemeral password is still available. | captureAccess
// 在临时口令仍可用时复制请求。
func captureAccess(request *AccessServerRequest, expectedPassword string) accessCapture {
	return accessCapture{
		userName:   request.UserName,
		method:     request.CredentialMethod,
		papOK:      request.VerifyPAP([]byte(expectedPassword)),
		chapOK:     request.VerifyCHAP([]byte(expectedPassword)),
		hasMA:      request.HasMessageAuthenticator,
		identifier: request.Identifier,
		attributes: request.Attributes.Clone(),
		remote:     peerString(request.RemoteAddr),
	}
}

// nextAccessCapture returns the next authenticated request or fails the test. | nextAccessCapture
// 返回下一个已认证请求，或在失败时终止测试。
func nextAccessCapture(t *testing.T, captures <-chan accessCapture) accessCapture {
	t.Helper()
	select {
	case capture := <-captures:
		return capture
	case <-time.After(2 * time.Second):
		t.Fatal("timed out waiting for the access authenticator")
	}
	return accessCapture{}
}

// expectNoAccessCapture asserts that the authenticator was not invoked. | expectNoAccessCapture
// 断言认证器未被调用。
func expectNoAccessCapture(t *testing.T, captures <-chan accessCapture) {
	t.Helper()
	select {
	case capture := <-captures:
		t.Fatalf("access authenticator was invoked: %+v", capture)
	case <-time.After(100 * time.Millisecond):
	}
}

func TestAccessServerPAPAccept(t *testing.T) {
	secret := []byte("testing-secret")
	var resultAttributes Attributes
	resultAttributes.AddString(AttrFilterID, "acl-1")
	resultAttributes.AddUint32(AttrSessionTimeout, 60)
	captures := make(chan accessCapture, 4)
	authenticator := AccessAuthenticatorFunc(func(ctx context.Context, request *AccessServerRequest) (*AccessServerResult, error) {
		captures <- captureAccess(request, "s3cret")
		return &AccessServerResult{Accept: true, ReplyMessage: "welcome", Attributes: resultAttributes}, nil
	})
	server := startAccessServer(t, AccessServerConfig{
		Network:       "udp4",
		Address:       "127.0.0.1:0",
		Secret:        secret,
		Authenticator: authenticator,
		Timeout:       time.Second,
		Logger:        testDynamicLogger(),
	})
	var extra Attributes
	extra.AddString(AttrProxyState, "proxy-state-1")
	client := newTestClient(t, ClientConfig{Address: server.Addr().String(), Secret: secret})
	response, err := client.AccessRequest(context.Background(), &AccessRequest{
		UserName:   "alice",
		Password:   "s3cret",
		Attributes: extra,
	})
	if err != nil {
		t.Fatalf("AccessRequest: %v", err)
	}
	if !response.Accepted() {
		t.Fatalf("response = %+v, want Access-Accept", response)
	}
	if response.ReplyMessage != "welcome" || response.FilterID != "acl-1" || response.SessionTimeout != 60 {
		t.Fatalf("unexpected response attributes: %+v", response)
	}
	proxyStates := response.Attributes.GetAll(AttrProxyState)
	if len(proxyStates) != 1 || proxyStates[0].String() != "proxy-state-1" {
		t.Fatalf("Proxy-State = %v", proxyStates)
	}
	capture := nextAccessCapture(t, captures)
	if capture.userName != "alice" || capture.method != AuthPAP || !capture.papOK || capture.chapOK {
		t.Fatalf("unexpected request: %+v", capture)
	}
	if capture.hasMA {
		t.Fatal("PAP request unexpectedly reported a Message-Authenticator")
	}
	if capture.remote == "" {
		t.Fatal("RemoteAddr was not set")
	}
	if capture.identifier != response.Identifier {
		t.Fatalf("identifier = %d, response identifier = %d", capture.identifier, response.Identifier)
	}
}

func TestAccessServerPAPReject(t *testing.T) {
	secret := []byte("testing-secret")
	captures := make(chan accessCapture, 4)
	authenticator := AccessAuthenticatorFunc(func(ctx context.Context, request *AccessServerRequest) (*AccessServerResult, error) {
		captures <- captureAccess(request, "s3cret")
		return &AccessServerResult{}, nil
	})
	server := startAccessServer(t, AccessServerConfig{
		Network:       "udp4",
		Address:       "127.0.0.1:0",
		Secret:        secret,
		Authenticator: authenticator,
		Logger:        testDynamicLogger(),
	})
	client := newTestClient(t, ClientConfig{Address: server.Addr().String(), Secret: secret})
	response, err := client.AccessRequest(context.Background(), &AccessRequest{UserName: "alice", Password: "wrong"})
	if err != nil {
		t.Fatalf("AccessRequest: %v", err)
	}
	if !response.Rejected() {
		t.Fatalf("response = %+v, want Access-Reject", response)
	}
	capture := nextAccessCapture(t, captures)
	if capture.papOK {
		t.Fatal("VerifyPAP accepted the wrong password")
	}
}

func TestAccessServerCHAP(t *testing.T) {
	secret := []byte("testing-secret")
	captures := make(chan accessCapture, 4)
	authenticator := AccessAuthenticatorFunc(func(ctx context.Context, request *AccessServerRequest) (*AccessServerResult, error) {
		captures <- captureAccess(request, "chap-secret")
		result := &AccessServerResult{}
		if request.VerifyCHAP([]byte("chap-secret")) {
			result.Accept = true
		}
		return result, nil
	})
	server := startAccessServer(t, AccessServerConfig{
		Network:       "udp4",
		Address:       "127.0.0.1:0",
		Secret:        secret,
		Authenticator: authenticator,
		Logger:        testDynamicLogger(),
	})
	client := newTestClient(t, ClientConfig{Address: server.Addr().String(), Secret: secret})
	response, err := client.AccessRequest(context.Background(), &AccessRequest{
		UserName:      "alice",
		Method:        AuthCHAP,
		Password:      "chap-secret",
		CHAPChallenge: []byte("1234567890"),
	})
	if err != nil {
		t.Fatalf("AccessRequest: %v", err)
	}
	if !response.Accepted() {
		t.Fatalf("response = %+v, want Access-Accept", response)
	}
	capture := nextAccessCapture(t, captures)
	if capture.method != AuthCHAP || !capture.chapOK || capture.papOK {
		t.Fatalf("unexpected CHAP request: %+v", capture)
	}
	response, err = client.AccessRequest(context.Background(), &AccessRequest{
		UserName:      "alice",
		Method:        AuthCHAP,
		Password:      "wrong",
		CHAPChallenge: []byte("1234567890"),
	})
	if err != nil {
		t.Fatalf("AccessRequest wrong CHAP: %v", err)
	}
	if !response.Rejected() {
		t.Fatalf("response = %+v, want Access-Reject", response)
	}
	capture = nextAccessCapture(t, captures)
	if capture.chapOK {
		t.Fatal("VerifyCHAP accepted the wrong password")
	}
}

func TestAccessServerRequiresMessageAuthenticator(t *testing.T) {
	secret := []byte("testing-secret")
	captures := make(chan accessCapture, 4)
	authenticator := AccessAuthenticatorFunc(func(ctx context.Context, request *AccessServerRequest) (*AccessServerResult, error) {
		captures <- captureAccess(request, "s3cret")
		return &AccessServerResult{Accept: true}, nil
	})
	server := startAccessServer(t, AccessServerConfig{
		Network:                     "udp4",
		Address:                     "127.0.0.1:0",
		Secret:                      secret,
		Authenticator:               authenticator,
		RequireMessageAuthenticator: true,
		Timeout:                     time.Second,
		Logger:                      testDynamicLogger(),
	})

	t.Run("missing dropped", func(t *testing.T) {
		client := newTestClient(t, ClientConfig{
			Address: server.Addr().String(),
			Secret:  secret,
			Timeout: 80 * time.Millisecond,
		})
		_, err := client.AccessRequest(context.Background(), &AccessRequest{UserName: "alice", Password: "s3cret"})
		if !errors.Is(err, ErrTimeout) {
			t.Fatalf("error = %v, want ErrTimeout", err)
		}
		expectNoAccessCapture(t, captures)
	})

	t.Run("invalid dropped", func(t *testing.T) {
		authenticator := rawAccessAuthenticator()
		var attributes Attributes
		attributes.AddString(AttrUserName, "alice")
		attributes.Add(AttrUserPassword, hiddenPassword(t, secret, authenticator, "s3cret"))
		raw := rawAccessRequest(t, 9, authenticator, attributes, []byte("other-secret"))
		requireUDPTimeout(t, server.Addr().String(), raw)
		expectNoAccessCapture(t, captures)
	})

	t.Run("valid accepted", func(t *testing.T) {
		client := newTestClient(t, ClientConfig{Address: server.Addr().String(), Secret: secret})
		response, err := client.AccessRequest(context.Background(), &AccessRequest{
			UserName:                    "alice",
			Password:                    "s3cret",
			IncludeMessageAuthenticator: true,
		})
		if err != nil {
			t.Fatalf("AccessRequest: %v", err)
		}
		if !response.Accepted() {
			t.Fatalf("response = %+v, want Access-Accept", response)
		}
		capture := nextAccessCapture(t, captures)
		if !capture.hasMA {
			t.Fatal("request with Message-Authenticator was not marked")
		}
	})
}

func TestAccessServerEAPRequiresMessageAuthenticator(t *testing.T) {
	secret := []byte("testing-secret")
	captures := make(chan accessCapture, 4)
	server := startAccessServer(t, AccessServerConfig{
		Network: "udp4",
		Address: "127.0.0.1:0",
		Secret:  secret,
		Authenticator: AccessAuthenticatorFunc(func(ctx context.Context, request *AccessServerRequest) (*AccessServerResult, error) {
			captures <- captureAccess(request, "s3cret")
			return &AccessServerResult{Accept: true}, nil
		}),
		Logger: testDynamicLogger(),
	})
	authenticator := rawAccessAuthenticator()
	var attributes Attributes
	attributes.AddString(AttrUserName, "alice")
	attributes.Add(AttrEAPMessage, []byte{2, 1, 0, 5, 1})
	requireUDPTimeout(t, server.Addr().String(), rawAccessRequest(t, 24, authenticator, attributes, nil))
	expectNoAccessCapture(t, captures)
}

func TestAccessServerHandlerErrorRejects(t *testing.T) {
	secret := []byte("testing-secret")
	server := startAccessServer(t, AccessServerConfig{
		Network: "udp4",
		Address: "127.0.0.1:0",
		Secret:  secret,
		Authenticator: AccessAuthenticatorFunc(func(ctx context.Context, request *AccessServerRequest) (*AccessServerResult, error) {
			return nil, errors.New("backend unavailable")
		}),
		Logger: testDynamicLogger(),
	})
	client := newTestClient(t, ClientConfig{Address: server.Addr().String(), Secret: secret})
	response, err := client.AccessRequest(context.Background(), &AccessRequest{UserName: "alice", Password: "s3cret"})
	if err != nil {
		t.Fatalf("AccessRequest: %v", err)
	}
	if !response.Rejected() {
		t.Fatalf("response = %+v, want Access-Reject", response)
	}
}

func TestAccessServerClientLookup(t *testing.T) {
	secret := []byte("nas-secret")
	lookups := make(chan string, 4)
	lookup := ServerClientLookupFunc(func(ctx context.Context, remote net.Addr, attributes Attributes) (*ServerClient, error) {
		nas, _ := attributes.Get(AttrNASIdentifier)
		lookups <- nas.String()
		switch nas.String() {
		case "nas-1":
			return &ServerClient{Name: "nas-1", Secret: secret}, nil
		case "nas-error":
			return nil, errors.New("lookup failure")
		default:
			return nil, nil
		}
	})
	captures := make(chan accessCapture, 4)
	authenticator := AccessAuthenticatorFunc(func(ctx context.Context, request *AccessServerRequest) (*AccessServerResult, error) {
		captures <- captureAccess(request, "s3cret")
		return &AccessServerResult{Accept: true}, nil
	})
	server := startAccessServer(t, AccessServerConfig{
		Network:       "udp4",
		Address:       "127.0.0.1:0",
		ClientLookup:  lookup,
		Authenticator: authenticator,
		Logger:        testDynamicLogger(),
	})

	client := newTestClient(t, ClientConfig{
		Address:       server.Addr().String(),
		Secret:        secret,
		NASIdentifier: "nas-1",
	})
	response, err := client.AccessRequest(context.Background(), &AccessRequest{UserName: "alice", Password: "s3cret"})
	if err != nil {
		t.Fatalf("AccessRequest known client: %v", err)
	}
	if !response.Accepted() {
		t.Fatalf("response = %+v, want Access-Accept", response)
	}
	nextAccessCapture(t, captures)
	select {
	case nas := <-lookups:
		if nas != "nas-1" {
			t.Fatalf("lookup NAS-Identifier = %q", nas)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("client lookup was not called")
	}

	for _, testCase := range []struct {
		name string
		nas  string
	}{
		{name: "unknown client", nas: "nas-2"},
		{name: "lookup error", nas: "nas-error"},
	} {
		t.Run(testCase.name, func(t *testing.T) {
			client := newTestClient(t, ClientConfig{
				Address:       server.Addr().String(),
				Secret:        secret,
				NASIdentifier: testCase.nas,
				Timeout:       80 * time.Millisecond,
			})
			if _, err := client.AccessRequest(context.Background(), &AccessRequest{UserName: "alice", Password: "s3cret"}); !errors.Is(err, ErrTimeout) {
				t.Fatalf("error = %v, want ErrTimeout", err)
			}
			expectNoAccessCapture(t, captures)
			select {
			case nas := <-lookups:
				if nas != testCase.nas {
					t.Fatalf("lookup NAS-Identifier = %q", nas)
				}
			case <-time.After(2 * time.Second):
				t.Fatal("client lookup was not called")
			}
		})
	}
}

func TestAccessServerRejectsMalformedCredentials(t *testing.T) {
	secret := []byte("testing-secret")
	captures := make(chan accessCapture, 4)
	authenticator := AccessAuthenticatorFunc(func(ctx context.Context, request *AccessServerRequest) (*AccessServerResult, error) {
		captures <- captureAccess(request, "s3cret")
		return &AccessServerResult{Accept: true}, nil
	})
	server := startAccessServer(t, AccessServerConfig{
		Network:       "udp4",
		Address:       "127.0.0.1:0",
		Secret:        secret,
		Authenticator: authenticator,
		Logger:        testDynamicLogger(),
	})
	requestAuthenticator := rawAccessAuthenticator()

	t.Run("missing User-Name", func(t *testing.T) {
		var attributes Attributes
		attributes.Add(AttrUserPassword, hiddenPassword(t, secret, requestAuthenticator, "s3cret"))
		raw := rawAccessRequest(t, 21, requestAuthenticator, attributes, nil)
		response, err := exchangeUDP(t, server.Addr().String(), raw, 500*time.Millisecond)
		if err != nil {
			t.Fatalf("read response: %v", err)
		}
		packet := parseAndVerifyResponse(t, response, requestAuthenticator, secret)
		if packet.Code != CodeAccessReject {
			t.Fatalf("code = %d, want Access-Reject", packet.Code)
		}
		expectNoAccessCapture(t, captures)
	})

	t.Run("conflicting credentials", func(t *testing.T) {
		var attributes Attributes
		attributes.AddString(AttrUserName, "alice")
		attributes.Add(AttrUserPassword, hiddenPassword(t, secret, requestAuthenticator, "s3cret"))
		attributes.Add(AttrCHAPPassword, append([]byte{1}, make([]byte, 16)...))
		raw := rawAccessRequest(t, 22, requestAuthenticator, attributes, nil)
		response, err := exchangeUDP(t, server.Addr().String(), raw, 500*time.Millisecond)
		if err != nil {
			t.Fatalf("read response: %v", err)
		}
		packet := parseAndVerifyResponse(t, response, requestAuthenticator, secret)
		if packet.Code != CodeAccessReject {
			t.Fatalf("code = %d, want Access-Reject", packet.Code)
		}
		expectNoAccessCapture(t, captures)
	})

	t.Run("short packet", func(t *testing.T) {
		requireUDPTimeout(t, server.Addr().String(), make([]byte, 10))
		expectNoAccessCapture(t, captures)
	})

	t.Run("unexpected code", func(t *testing.T) {
		raw, err := MarshalPacket(&Packet{Code: CodeAccountingRequest, Identifier: 23})
		if err != nil {
			t.Fatalf("MarshalPacket: %v", err)
		}
		requireUDPTimeout(t, server.Addr().String(), raw)
		expectNoAccessCapture(t, captures)
	})
}

func TestAccessServerOverStreams(t *testing.T) {
	testCases := []struct {
		name    string
		network string
		useTLS  bool
	}{
		{name: "tcp", network: NetworkTCP},
		{name: "tls", network: NetworkTLS, useTLS: true},
	}
	for _, testCase := range testCases {
		t.Run(testCase.name, func(t *testing.T) {
			secret := []byte("testing-secret")
			captures := make(chan accessCapture, 4)
			config := AccessServerConfig{
				Network: testCase.network,
				Address: "127.0.0.1:0",
				Secret:  secret,
				Authenticator: AccessAuthenticatorFunc(func(ctx context.Context, request *AccessServerRequest) (*AccessServerResult, error) {
					captures <- captureAccess(request, "s3cret")
					return &AccessServerResult{Accept: true}, nil
				}),
				Timeout: time.Second,
				Logger:  testDynamicLogger(),
			}
			clientConfig := ClientConfig{Network: testCase.network, Secret: secret}
			if testCase.useTLS {
				certificate, roots := testCertificate(t)
				config.TLSConfig = &tls.Config{
					Certificates: []tls.Certificate{certificate},
					MinVersion:   tls.VersionTLS12,
				}
				clientConfig.TLSConfig = &tls.Config{
					RootCAs:    roots,
					ServerName: "radius.test",
				}
			}
			server := startAccessServer(t, config)
			clientConfig.Address = server.Addr().String()
			client := newTestClient(t, clientConfig)
			response, err := client.AccessRequest(context.Background(), &AccessRequest{UserName: "alice", Password: "s3cret"})
			if err != nil {
				t.Fatalf("AccessRequest: %v", err)
			}
			if !response.Accepted() {
				t.Fatalf("response = %+v, want Access-Accept", response)
			}
			capture := nextAccessCapture(t, captures)
			if capture.method != AuthPAP || !capture.papOK {
				t.Fatalf("unexpected request: %+v", capture)
			}
		})
	}
}

func TestStreamServerClosesOnInvalidMessageAuthenticator(t *testing.T) {
	secret := []byte("testing-secret")
	server := startAccessServer(t, AccessServerConfig{
		Network: "tcp4",
		Address: "127.0.0.1:0",
		Secret:  secret,
		Authenticator: AccessAuthenticatorFunc(func(ctx context.Context, request *AccessServerRequest) (*AccessServerResult, error) {
			return &AccessServerResult{Accept: true}, nil
		}),
		Logger: testDynamicLogger(),
	})
	conn, err := net.DialTimeout("tcp4", server.Addr().String(), time.Second)
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	defer func() {
		_ = conn.Close()
	}()
	authenticator := rawAccessAuthenticator()
	var attributes Attributes
	attributes.AddString(AttrUserName, "alice")
	raw := rawAccessRequest(t, 31, authenticator, attributes, []byte("other-secret"))
	if _, err := conn.Write(raw); err != nil {
		t.Fatalf("write: %v", err)
	}
	_ = conn.SetReadDeadline(time.Now().Add(2 * time.Second))
	_, err = conn.Read(make([]byte, 1))
	if err == nil {
		t.Fatal("server kept the stream connection open after an invalid Message-Authenticator")
	}
	var netErr net.Error
	if errors.As(err, &netErr) && netErr.Timeout() {
		t.Fatalf("connection stayed open: %v", err)
	}
}

func TestAccessServerRejectsInvalidOptionalMessageAuthenticator(t *testing.T) {
	secret := []byte("testing-secret")
	captures := make(chan accessCapture, 4)
	server := startAccessServer(t, AccessServerConfig{
		Network: "udp4",
		Address: "127.0.0.1:0",
		Secret:  secret,
		Authenticator: AccessAuthenticatorFunc(func(ctx context.Context, request *AccessServerRequest) (*AccessServerResult, error) {
			captures <- captureAccess(request, "s3cret")
			return &AccessServerResult{Accept: true}, nil
		}),
		Logger: testDynamicLogger(),
	})
	authenticator := rawAccessAuthenticator()
	var attributes Attributes
	attributes.AddString(AttrUserName, "alice")
	attributes.Add(AttrUserPassword, hiddenPassword(t, secret, authenticator, "s3cret"))
	requireUDPTimeout(t, server.Addr().String(), rawAccessRequest(t, 25, authenticator, attributes, []byte("other-secret")))
	expectNoAccessCapture(t, captures)
}

func TestStreamServerClosesOnOversizedFrame(t *testing.T) {
	secret := []byte("testing-secret")
	server := startAccessServer(t, AccessServerConfig{
		Network:       "tcp4",
		Address:       "127.0.0.1:0",
		Secret:        secret,
		MaxPacketSize: 64,
		Authenticator: AccessAuthenticatorFunc(func(ctx context.Context, request *AccessServerRequest) (*AccessServerResult, error) {
			return &AccessServerResult{Accept: true}, nil
		}),
		Logger: testDynamicLogger(),
	})
	conn, err := net.DialTimeout("tcp4", server.Addr().String(), time.Second)
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	defer func() {
		_ = conn.Close()
	}()
	header := []byte{byte(CodeAccessRequest), 1, 0, 100}
	if _, err := conn.Write(header); err != nil {
		t.Fatalf("write: %v", err)
	}
	_ = conn.SetReadDeadline(time.Now().Add(2 * time.Second))
	_, err = conn.Read(make([]byte, 1))
	if err == nil {
		t.Fatal("server kept the stream connection open after an oversized frame")
	}
	var netErr net.Error
	if errors.As(err, &netErr) && netErr.Timeout() {
		t.Fatalf("connection stayed open: %v", err)
	}
}

func TestAccessServerMaxPacketSize(t *testing.T) {
	secret := []byte("testing-secret")
	server := startAccessServer(t, AccessServerConfig{
		Network:       "udp4",
		Address:       "127.0.0.1:0",
		Secret:        secret,
		MaxPacketSize: 64,
		Authenticator: AccessAuthenticatorFunc(func(ctx context.Context, request *AccessServerRequest) (*AccessServerResult, error) {
			return &AccessServerResult{Accept: true}, nil
		}),
		Logger: testDynamicLogger(),
	})
	requireUDPTimeout(t, server.Addr().String(), make([]byte, 128))
	client := newTestClient(t, ClientConfig{Address: server.Addr().String(), Secret: secret})
	response, err := client.AccessRequest(context.Background(), &AccessRequest{UserName: "alice", Password: "s3cret"})
	if err != nil {
		t.Fatalf("AccessRequest after oversized datagram: %v", err)
	}
	if !response.Accepted() {
		t.Fatalf("response = %+v, want Access-Accept", response)
	}
}

func TestAccessServerConcurrencyLimit(t *testing.T) {
	secret := []byte("testing-secret")
	started := make(chan struct{}, 1)
	release := make(chan struct{})
	server := startAccessServer(t, AccessServerConfig{
		Network:       "udp4",
		Address:       "127.0.0.1:0",
		Secret:        secret,
		MaxConcurrent: 1,
		Timeout:       2 * time.Second,
		Authenticator: AccessAuthenticatorFunc(func(ctx context.Context, request *AccessServerRequest) (*AccessServerResult, error) {
			started <- struct{}{}
			select {
			case <-release:
				return &AccessServerResult{Accept: true}, nil
			case <-ctx.Done():
				return nil, ctx.Err()
			}
		}),
		Logger: testDynamicLogger(),
	})
	client := newTestClient(t, ClientConfig{Address: server.Addr().String(), Secret: secret, Timeout: 2 * time.Second})
	type result struct {
		response *AccessResponse
		err      error
	}
	first := make(chan result, 1)
	go func() {
		response, err := client.AccessRequest(context.Background(), &AccessRequest{UserName: "alice", Password: "s3cret"})
		first <- result{response: response, err: err}
	}()
	select {
	case <-started:
	case <-time.After(2 * time.Second):
		t.Fatal("handler did not start")
	}

	authenticator := rawAccessAuthenticator()
	var attributes Attributes
	attributes.AddString(AttrUserName, "bob")
	attributes.Add(AttrUserPassword, hiddenPassword(t, secret, authenticator, "s3cret"))
	requireUDPTimeout(t, server.Addr().String(), rawAccessRequest(t, 41, authenticator, attributes, nil))

	close(release)
	select {
	case got := <-first:
		if got.err != nil {
			t.Fatalf("first AccessRequest: %v", got.err)
		}
		if !got.response.Accepted() {
			t.Fatalf("first response = %+v, want Access-Accept", got.response)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("first AccessRequest did not finish")
	}
}

func TestAccessServerLifecycle(t *testing.T) {
	secret := []byte("testing-secret")
	server, err := NewAccessServer(AccessServerConfig{
		Network: "udp4",
		Address: "127.0.0.1:0",
		Secret:  secret,
		Authenticator: AccessAuthenticatorFunc(func(ctx context.Context, request *AccessServerRequest) (*AccessServerResult, error) {
			return &AccessServerResult{Accept: true}, nil
		}),
		Logger: testDynamicLogger(),
	})
	if err != nil {
		t.Fatalf("NewAccessServer: %v", err)
	}
	t.Cleanup(func() {
		_ = server.Close()
	})
	if err := server.Serve(context.Background()); !errors.Is(err, ErrInvalidConfig) {
		t.Fatalf("Serve before Listen = %v, want ErrInvalidConfig", err)
	}
	address, err := server.Listen()
	if err != nil {
		t.Fatalf("Listen: %v", err)
	}
	again, err := server.Listen()
	if err != nil {
		t.Fatalf("second Listen: %v", err)
	}
	if address.String() != again.String() {
		t.Fatalf("Listen addresses differ: %s and %s", address, again)
	}
	done := make(chan error, 1)
	go func() {
		done <- server.Serve(context.Background())
	}()
	waitForTransportServing(t, server)
	if err := server.Serve(context.Background()); !errors.Is(err, ErrInvalidConfig) {
		t.Fatalf("concurrent Serve = %v, want ErrInvalidConfig", err)
	}
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
	if err := server.ListenAndServe(context.Background()); !errors.Is(err, ErrServerClosed) {
		t.Fatalf("ListenAndServe after Close = %v, want ErrServerClosed", err)
	}
	if server.Addr() == nil {
		t.Fatal("Addr is nil after Serve returned")
	}
}

func TestAccessServerConfigValidation(t *testing.T) {
	secret := []byte("testing-secret")
	handler := AccessAuthenticatorFunc(func(ctx context.Context, request *AccessServerRequest) (*AccessServerResult, error) {
		return &AccessServerResult{}, nil
	})
	cases := []struct {
		name   string
		config AccessServerConfig
	}{
		{name: "missing authenticator", config: AccessServerConfig{Secret: secret}},
		{name: "missing secret", config: AccessServerConfig{Authenticator: handler}},
		{name: "bad network", config: AccessServerConfig{Network: "sctp", Secret: secret, Authenticator: handler}},
		{name: "bad address", config: AccessServerConfig{Address: "127.0.0.1", Secret: secret, Authenticator: handler}},
		{name: "tls without config", config: AccessServerConfig{Network: NetworkTLS, Secret: secret, Authenticator: handler}},
		{name: "packet too small", config: AccessServerConfig{Secret: secret, Authenticator: handler, MaxPacketSize: HeaderLength - 1}},
		{name: "packet too large", config: AccessServerConfig{Secret: secret, Authenticator: handler, MaxPacketSize: MaxPacketLength + 1}},
		{name: "negative concurrency", config: AccessServerConfig{Secret: secret, Authenticator: handler, MaxConcurrent: -1}},
		{name: "negative timeout", config: AccessServerConfig{Secret: secret, Authenticator: handler, Timeout: -time.Second}},
	}
	for _, testCase := range cases {
		t.Run(testCase.name, func(t *testing.T) {
			if _, err := NewAccessServer(testCase.config); !errors.Is(err, ErrInvalidConfig) {
				t.Fatalf("error = %v, want ErrInvalidConfig", err)
			}
		})
	}
}
