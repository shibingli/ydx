package radius

import (
	"context"
	"errors"
	"net"
	"sync"
	"testing"
	"time"
)

// waitForProxyServing waits until Serve has claimed the socket or listener. |
// waitForProxyServing 等待 Serve 接管套接字或监听器。
func waitForProxyServing(t *testing.T, server *ProxyServer) {
	t.Helper()
	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		server.transport.mu.Lock()
		serving := server.transport.serving
		server.transport.mu.Unlock()
		if serving {
			return
		}
		time.Sleep(time.Millisecond)
	}
	t.Fatal("Serve did not start")
}

// startProxyServer constructs and starts a ProxyServer. | startProxyServer 构造并启动 ProxyServer。
func startProxyServer(t *testing.T, config ProxyServerConfig) *ProxyServer {
	t.Helper()
	server, err := NewProxyServer(config)
	if err != nil {
		t.Fatalf("NewProxyServer: %v", err)
	}
	if _, err := server.Listen(); err != nil {
		t.Fatalf("Listen: %v", err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() {
		done <- server.Serve(ctx)
	}()
	waitForProxyServing(t, server)
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
		if err := server.Close(); err != nil {
			t.Errorf("Close: %v", err)
		}
	})
	return server
}

// proxyResponseCode returns the upstream response code for a request code. |
// proxyResponseCode 返回请求类型对应的上游响应类型。
func proxyResponseCode(code Code) Code {
	if code == CodeAccountingRequest {
		return CodeAccountingResponse
	}
	return CodeAccessAccept
}

// newProxyUpstream starts an upstream responder used by proxy tests. | newProxyUpstream 启动代理测试
// 使用的上游响应器。
func newProxyUpstream(t *testing.T, secret []byte, observations chan relayObservation) *udpMock {
	t.Helper()
	return newUDPMock(t, secret, func(request *Packet, raw []byte) ([]byte, error) {
		observation, err := observeRelayRequest(request.Code, request, raw, secret, "upstream")
		if err != nil {
			return nil, err
		}
		observations <- observation
		attributes := echoProxyStates(request, "proxied")
		if observation.maPresent {
			return signedMessageResponse(request, secret, proxyResponseCode(request.Code), attributes)
		}
		return signedResponse(request, secret, proxyResponseCode(request.Code), attributes)
	})
}

// proxyUDPAccessRequest builds a downstream Access-Request for proxy tests. |
// proxyUDPAccessRequest 为代理测试构建下游 Access-Request。
func proxyUDPAccessRequest(t *testing.T, secret []byte, identifier uint8, messageAuthenticator bool) ([]byte, [16]byte) {
	t.Helper()
	authenticator := rawAccessAuthenticator()
	authenticator[0] ^= identifier
	var attributes Attributes
	attributes.AddString(AttrUserName, "alice")
	attributes.AddString(AttrProxyState, "downstream-state")
	var maSecret []byte
	if messageAuthenticator {
		maSecret = secret
	}
	return rawAccessRequest(t, identifier, authenticator, attributes, maSecret), authenticator
}

// proxyUDPAccountingRequest builds a downstream Accounting-Request for proxy tests. |
// proxyUDPAccountingRequest 为代理测试构建下游 Accounting-Request。
func proxyUDPAccountingRequest(t *testing.T, secret []byte, identifier uint8, messageAuthenticator bool) ([]byte, [16]byte) {
	t.Helper()
	var attributes Attributes
	attributes.AddUint32(AttrAcctStatusType, uint32(AcctStatusStart))
	attributes.AddString(AttrAcctSessionID, "proxy-session")
	attributes.AddString(AttrNASIdentifier, "proxy-nas")
	attributes.AddString(AttrProxyState, "downstream-state")
	var raw []byte
	if messageAuthenticator {
		raw = accountingRequestWithMessageAuthenticator(t, secret, identifier, attributes)
	} else {
		raw = rawAccountingRequest(t, secret, identifier, attributes)
	}
	packet, err := ParsePacket(raw)
	if err != nil {
		t.Fatalf("ParsePacket: %v", err)
	}
	return raw, packet.Authenticator
}

func TestProxyServerForwardsAccessAndAccounting(t *testing.T) {
	nasSecret := []byte("proxy-nas-secret")
	upstreamSecret := []byte("proxy-upstream-secret")
	observations := make(chan relayObservation, 16)
	upstream := newProxyUpstream(t, upstreamSecret, observations)
	relay := newTestRelay(t, RelayConfig{
		Upstreams: []RelayUpstream{{
			Name:    "upstream",
			Network: "udp4",
			Address: upstream.Addr(),
			Secret:  upstreamSecret,
		}},
	})
	server := startProxyServer(t, ProxyServerConfig{
		Network:                     "udp4",
		Address:                     "127.0.0.1:0",
		Secret:                      nasSecret,
		Relay:                       relay,
		RequireMessageAuthenticator: true,
		Logger:                      testDynamicLogger(),
	})

	accessRaw, accessAuthenticator := proxyUDPAccessRequest(t, nasSecret, 0x21, true)
	accessResponse, err := exchangeUDP(t, server.Addr().String(), accessRaw, time.Second)
	if err != nil {
		t.Fatalf("access exchange: %v", err)
	}
	accessPacket := parseAndVerifyResponse(t, accessResponse, accessAuthenticator, nasSecret)
	if accessPacket.Code != CodeAccessAccept || accessPacket.Identifier != 0x21 {
		t.Fatalf("access response code=%d identifier=%d", accessPacket.Code, accessPacket.Identifier)
	}
	states := accessPacket.Attributes.GetAll(AttrProxyState)
	if len(states) != 1 || string(states[0].Value) != "downstream-state" {
		t.Fatalf("access response Proxy-State = %v", states)
	}
	present, valid, err := verifyMessageAuthenticatorRaw(accessResponse, nasSecret, accessAuthenticator)
	if err != nil || !present || !valid {
		t.Fatalf("access response Message-Authenticator present=%v valid=%v err=%v", present, valid, err)
	}

	accountingRaw, accountingAuthenticator := proxyUDPAccountingRequest(t, nasSecret, 0x31, true)
	accountingResponse, err := exchangeUDP(t, server.Addr().String(), accountingRaw, time.Second)
	if err != nil {
		t.Fatalf("accounting exchange: %v", err)
	}
	accountingPacket := parseAndVerifyResponse(t, accountingResponse, accountingAuthenticator, nasSecret)
	if accountingPacket.Code != CodeAccountingResponse || accountingPacket.Identifier != 0x31 {
		t.Fatalf("accounting response code=%d identifier=%d", accountingPacket.Code, accountingPacket.Identifier)
	}
	present, valid, err = verifyMessageAuthenticatorRaw(accountingResponse, nasSecret, accountingAuthenticator)
	if err != nil || !present || !valid {
		t.Fatalf("accounting response Message-Authenticator present=%v valid=%v err=%v", present, valid, err)
	}

	accessObservation := nextRelayObservation(t, observations)
	if accessObservation.packet.Code != CodeAccessRequest || !accessObservation.maValid {
		t.Fatalf("unexpected upstream access observation: code=%d MA=%v/%v", accessObservation.packet.Code, accessObservation.maPresent, accessObservation.maValid)
	}
	accountingObservation := nextRelayObservation(t, observations)
	if accountingObservation.packet.Code != CodeAccountingRequest || !accountingObservation.acctValid || !accountingObservation.maValid {
		t.Fatalf("unexpected upstream accounting observation: code=%d auth=%v MA=%v/%v",
			accountingObservation.packet.Code, accountingObservation.acctValid, accountingObservation.maPresent, accountingObservation.maValid)
	}
}

func TestProxyServerDropsUnauthenticatedRequests(t *testing.T) {
	nasSecret := []byte("proxy-nas-secret")
	upstreamSecret := []byte("proxy-upstream-secret")
	observations := make(chan relayObservation, 16)
	upstream := newProxyUpstream(t, upstreamSecret, observations)
	relay := newTestRelay(t, RelayConfig{
		Upstreams: []RelayUpstream{{
			Network: "udp4",
			Address: upstream.Addr(),
			Secret:  upstreamSecret,
		}},
	})
	server := startProxyServer(t, ProxyServerConfig{
		Network:                     "udp4",
		Address:                     "127.0.0.1:0",
		Secret:                      nasSecret,
		Relay:                       relay,
		RequireMessageAuthenticator: true,
		Logger:                      testDynamicLogger(),
	})
	address := server.Addr().String()

	missingMA, _ := proxyUDPAccessRequest(t, nasSecret, 0x41, false)
	requireUDPTimeout(t, address, missingMA)
	expectNoRelayObservation(t, observations)

	wrongMA, _ := proxyUDPAccessRequest(t, []byte("wrong-nas-secret"), 0x42, true)
	requireUDPTimeout(t, address, wrongMA)
	expectNoRelayObservation(t, observations)

	wrongSecret, _ := proxyUDPAccessRequest(t, []byte("wrong-nas-secret"), 0x43, false)
	requireUDPTimeout(t, address, wrongSecret)
	expectNoRelayObservation(t, observations)

	badAccounting, _ := proxyUDPAccountingRequest(t, []byte("wrong-nas-secret"), 0x44, true)
	requireUDPTimeout(t, address, badAccounting)
	expectNoRelayObservation(t, observations)

	valid, authenticator := proxyUDPAccessRequest(t, nasSecret, 0x45, true)
	response, err := exchangeUDP(t, address, valid, time.Second)
	if err != nil {
		t.Fatalf("valid exchange after drops: %v", err)
	}
	parseAndVerifyResponse(t, response, authenticator, nasSecret)
	nextRelayObservation(t, observations)
}

func TestProxyServerUpstreamFailureReturnsNoResponse(t *testing.T) {
	nasSecret := []byte("proxy-nas-secret")
	conn, err := net.ListenPacket("udp4", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	closedAddress := conn.LocalAddr().String()
	_ = conn.Close()
	relay := newTestRelay(t, RelayConfig{
		Upstreams: []RelayUpstream{{
			Network: "udp4",
			Address: closedAddress,
			Secret:  []byte("proxy-upstream-secret"),
			Timeout: 40 * time.Millisecond,
		}},
	})
	server := startProxyServer(t, ProxyServerConfig{
		Network:                     "udp4",
		Address:                     "127.0.0.1:0",
		Secret:                      nasSecret,
		Relay:                       relay,
		RequireMessageAuthenticator: true,
		Logger:                      testDynamicLogger(),
	})
	raw, _ := proxyUDPAccessRequest(t, nasSecret, 0x46, true)
	requireUDPTimeout(t, server.Addr().String(), raw)
}

func TestProxyServerStreamKeepsAuthenticatedConnections(t *testing.T) {
	nasSecret := []byte("proxy-nas-secret")
	upstreamSecret := []byte("proxy-upstream-secret")
	observations := make(chan relayObservation, 16)
	upstream := newProxyUpstream(t, upstreamSecret, observations)
	relay := newTestRelay(t, RelayConfig{
		Upstreams: []RelayUpstream{{
			Network: "udp4",
			Address: upstream.Addr(),
			Secret:  upstreamSecret,
		}},
	})
	server := startProxyServer(t, ProxyServerConfig{
		Network:                     "tcp4",
		Address:                     "127.0.0.1:0",
		Secret:                      nasSecret,
		Relay:                       relay,
		RequireMessageAuthenticator: true,
		Logger:                      testDynamicLogger(),
	})
	conn, err := net.DialTimeout("tcp4", server.Addr().String(), time.Second)
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	defer func() {
		_ = conn.Close()
	}()
	_ = conn.SetDeadline(time.Now().Add(5 * time.Second))

	accessRaw, accessAuthenticator := proxyUDPAccessRequest(t, nasSecret, 0x51, true)
	if _, err := conn.Write(accessRaw); err != nil {
		t.Fatalf("write access: %v", err)
	}
	accessResponse, err := readStreamResponse(conn, 0x51, nil)
	if err != nil {
		t.Fatalf("read access response: %v", err)
	}
	parseAndVerifyResponse(t, accessResponse, accessAuthenticator, nasSecret)

	accountingRaw, accountingAuthenticator := proxyUDPAccountingRequest(t, nasSecret, 0x52, true)
	if _, err := conn.Write(accountingRaw); err != nil {
		t.Fatalf("write accounting: %v", err)
	}
	accountingResponse, err := readStreamResponse(conn, 0x52, nil)
	if err != nil {
		t.Fatalf("read accounting response: %v", err)
	}
	parseAndVerifyResponse(t, accountingResponse, accountingAuthenticator, nasSecret)

	nextRelayObservation(t, observations)
	nextRelayObservation(t, observations)

	invalid, _ := proxyUDPAccessRequest(t, []byte("wrong-nas-secret"), 0x53, true)
	if _, err := conn.Write(invalid); err != nil {
		t.Fatalf("write invalid: %v", err)
	}
	_ = conn.SetReadDeadline(time.Now().Add(2 * time.Second))
	if _, err := readStreamResponse(conn, 0x53, nil); err == nil {
		t.Fatal("stream connection stayed open after an unauthenticated request")
	} else {
		var netErr net.Error
		if errors.As(err, &netErr) && netErr.Timeout() {
			t.Fatalf("stream connection was not closed after an unauthenticated request: %v", err)
		}
	}
}

func TestProxyServerConcurrentRequests(t *testing.T) {
	nasSecret := []byte("proxy-nas-secret")
	upstreamSecret := []byte("proxy-upstream-secret")
	observations := make(chan relayObservation, 64)
	upstream := newProxyUpstream(t, upstreamSecret, observations)
	relay := newTestRelay(t, RelayConfig{
		Upstreams: []RelayUpstream{{
			Network: "udp4",
			Address: upstream.Addr(),
			Secret:  upstreamSecret,
		}},
	})
	server := startProxyServer(t, ProxyServerConfig{
		Network:                     "udp4",
		Address:                     "127.0.0.1:0",
		Secret:                      nasSecret,
		Relay:                       relay,
		RequireMessageAuthenticator: true,
		Logger:                      testDynamicLogger(),
	})
	const requests = 6
	var wg sync.WaitGroup
	errsChannel := make(chan error, requests)
	for index := 0; index < requests; index++ {
		wg.Add(1)
		go func(index int) {
			defer wg.Done()
			raw, authenticator := proxyUDPAccessRequest(t, nasSecret, uint8(0x60+index), true)
			response, err := exchangeUDP(t, server.Addr().String(), raw, 2*time.Second)
			if err != nil {
				errsChannel <- err
				return
			}
			if err := verifyResponseAuthenticator(response, nasSecret, authenticator); err != nil {
				errsChannel <- err
			}
		}(index)
	}
	wg.Wait()
	close(errsChannel)
	for err := range errsChannel {
		t.Errorf("concurrent proxy exchange: %v", err)
	}
	for index := 0; index < requests; index++ {
		nextRelayObservation(t, observations)
	}
}

func TestProxyServerLifecycle(t *testing.T) {
	nasSecret := []byte("proxy-nas-secret")
	relay := newTestRelay(t, RelayConfig{
		Upstreams: []RelayUpstream{{
			Network: "udp4",
			Address: "127.0.0.1:1812",
			Secret:  []byte("proxy-upstream-secret"),
		}},
	})
	server, err := NewProxyServer(ProxyServerConfig{
		Network: "udp4",
		Address: "127.0.0.1:0",
		Secret:  nasSecret,
		Relay:   relay,
		Logger:  testDynamicLogger(),
	})
	if err != nil {
		t.Fatalf("NewProxyServer: %v", err)
	}
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
	waitForProxyServing(t, server)
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
	if err := server.ListenAndServe(context.Background()); !errors.Is(err, ErrServerClosed) {
		t.Fatalf("ListenAndServe after Close = %v, want ErrServerClosed", err)
	}
	if server.Addr() == nil {
		t.Fatal("Addr is nil after Serve returned")
	}
}

func TestProxyServerConfigValidation(t *testing.T) {
	nasSecret := []byte("proxy-nas-secret")
	relay := newTestRelay(t, RelayConfig{
		Upstreams: []RelayUpstream{{
			Network: "udp4",
			Address: "127.0.0.1:1812",
			Secret:  []byte("proxy-upstream-secret"),
		}},
	})
	cases := []struct {
		name   string
		config ProxyServerConfig
	}{
		{name: "missing relay", config: ProxyServerConfig{Secret: nasSecret}},
		{name: "missing secret", config: ProxyServerConfig{Relay: relay}},
		{name: "bad network", config: ProxyServerConfig{Network: "sctp", Secret: nasSecret, Relay: relay}},
		{name: "tls without config", config: ProxyServerConfig{Network: NetworkTLS, Secret: nasSecret, Relay: relay}},
		{name: "packet too small", config: ProxyServerConfig{Secret: nasSecret, Relay: relay, MaxPacketSize: HeaderLength - 1}},
		{name: "packet too large", config: ProxyServerConfig{Secret: nasSecret, Relay: relay, MaxPacketSize: MaxPacketLength + 1}},
		{name: "negative concurrency", config: ProxyServerConfig{Secret: nasSecret, Relay: relay, MaxConcurrent: -1}},
		{name: "negative timeout", config: ProxyServerConfig{Secret: nasSecret, Relay: relay, Timeout: -time.Second}},
	}
	for _, testCase := range cases {
		t.Run(testCase.name, func(t *testing.T) {
			if _, err := NewProxyServer(testCase.config); !errors.Is(err, ErrInvalidConfig) {
				t.Fatalf("error = %v, want ErrInvalidConfig", err)
			}
		})
	}
}

func TestProxyServerClientLookup(t *testing.T) {
	nasSecret := []byte("proxy-nas-secret")
	upstreamSecret := []byte("proxy-upstream-secret")
	observations := make(chan relayObservation, 8)
	upstream := newProxyUpstream(t, upstreamSecret, observations)
	relay := newTestRelay(t, RelayConfig{
		Upstreams: []RelayUpstream{{
			Network: "udp4",
			Address: upstream.Addr(),
			Secret:  upstreamSecret,
		}},
	})
	lookup := ServerClientLookupFunc(func(ctx context.Context, remote net.Addr, attributes Attributes) (*ServerClient, error) {
		identifier, _ := attributes.Get(AttrNASIdentifier)
		if identifier.String() == "known" {
			return &ServerClient{Name: "known", Secret: nasSecret}, nil
		}
		return nil, nil
	})
	server := startProxyServer(t, ProxyServerConfig{
		Network:                     "udp4",
		Address:                     "127.0.0.1:0",
		ClientLookup:                lookup,
		Relay:                       relay,
		RequireMessageAuthenticator: true,
		Logger:                      testDynamicLogger(),
	})
	address := server.Addr().String()

	knownAuthenticator := rawAccessAuthenticator()
	var known Attributes
	known.AddString(AttrUserName, "alice")
	known.AddString(AttrNASIdentifier, "known")
	knownRaw := rawAccessRequest(t, 0x71, knownAuthenticator, known, nasSecret)
	response, err := exchangeUDP(t, address, knownRaw, time.Second)
	if err != nil {
		t.Fatalf("known client exchange: %v", err)
	}
	parseAndVerifyResponse(t, response, knownAuthenticator, nasSecret)
	nextRelayObservation(t, observations)

	unknownAuthenticator := rawAccessAuthenticator()
	unknownAuthenticator[0] = 0x99
	var unknown Attributes
	unknown.AddString(AttrUserName, "alice")
	unknown.AddString(AttrNASIdentifier, "unknown")
	unknownRaw := rawAccessRequest(t, 0x72, unknownAuthenticator, unknown, nasSecret)
	requireUDPTimeout(t, address, unknownRaw)
	expectNoRelayObservation(t, observations)
}

func TestProxyServerBadFrames(t *testing.T) {
	nasSecret := []byte("proxy-nas-secret")
	upstreamSecret := []byte("proxy-upstream-secret")
	observations := make(chan relayObservation, 8)
	upstream := newProxyUpstream(t, upstreamSecret, observations)
	relay := newTestRelay(t, RelayConfig{
		Upstreams: []RelayUpstream{{
			Network: "udp4",
			Address: upstream.Addr(),
			Secret:  upstreamSecret,
		}},
	})
	server := startProxyServer(t, ProxyServerConfig{
		Network: "udp4",
		Address: "127.0.0.1:0",
		Secret:  nasSecret,
		Relay:   relay,
		Logger:  testDynamicLogger(),
	})
	requireUDPTimeout(t, server.Addr().String(), []byte{byte(CodeAccessRequest), 1, 0, 4})
	requireUDPTimeout(t, server.Addr().String(), []byte{byte(CodeAccessAccept), 1, 0, 20, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0})
	expectNoRelayObservation(t, observations)
}
