package radius

import (
	"bytes"
	"context"
	"crypto/tls"
	"errors"
	"net"
	"testing"
	"time"
)

// accountingCapture is a copy of one AccountingServerRequest observed by a test handler. |
// accountingCapture 是测试处理器观察到的一次 AccountingServerRequest 副本。
type accountingCapture struct {
	request AccountingServerRequest
}

// nextAccountingCapture returns the next authenticated request or fails the test. |
// nextAccountingCapture 返回下一个已认证请求，或在失败时终止测试。
func nextAccountingCapture(t *testing.T, captures <-chan accountingCapture) AccountingServerRequest {
	t.Helper()
	select {
	case capture := <-captures:
		return capture.request
	case <-time.After(2 * time.Second):
		t.Fatal("timed out waiting for the accounting handler")
	}
	return AccountingServerRequest{}
}

// expectNoAccountingCapture asserts that the handler was not invoked. | expectNoAccountingCapture
// 断言处理器未被调用。
func expectNoAccountingCapture(t *testing.T, captures <-chan accountingCapture) {
	t.Helper()
	select {
	case capture := <-captures:
		t.Fatalf("accounting handler was invoked: %+v", capture.request)
	case <-time.After(100 * time.Millisecond):
	}
}

// accountingServerSecret returns the shared secret used by accounting server tests. |
// accountingServerSecret 返回计费服务器测试使用的共享密钥。
func accountingServerSecret() []byte {
	return []byte("testing-secret")
}

func TestAccountingServerRecordsRequest(t *testing.T) {
	secret := accountingServerSecret()
	captures := make(chan accountingCapture, 4)
	var resultAttributes Attributes
	resultAttributes.AddUint32(AttrSessionTimeout, 30)
	server := startAccountingServer(t, AccountingServerConfig{
		Network: "udp4",
		Address: "127.0.0.1:0",
		Secret:  secret,
		Handler: AccountingHandlerFunc(func(ctx context.Context, request *AccountingServerRequest) (*AccountingServerResult, error) {
			captures <- accountingCapture{request: *request}
			return &AccountingServerResult{ReplyMessage: "recorded", Attributes: resultAttributes}, nil
		}),
		Logger: testDynamicLogger(),
	})
	var extra Attributes
	extra.AddString(AttrProxyState, "proxy-state-1")
	eventTimestamp := time.Unix(1_700_000_000, 0).UTC()
	client := newTestClient(t, ClientConfig{
		Address:       server.Addr().String(),
		Secret:        secret,
		NASIdentifier: "nas-1",
	})
	response, err := client.AccountRequest(context.Background(), &AccountingRequest{
		StatusType:       AcctStatusStart,
		SessionID:        "sess-1",
		UserName:         "alice",
		NASPort:          7,
		NASPortType:      NASPortTypeEthernet,
		Authentic:        AcctAuthenticRADIUS,
		InputOctets:      100,
		OutputOctets:     200,
		InputPackets:     3,
		OutputPackets:    4,
		SessionTime:      11,
		TerminateCause:   AcctTerminateUserRequest,
		EventTimestamp:   eventTimestamp,
		CallingStationID: "caller-1",
		CalledStationID:  "called-1",
		Class:            []byte{0xde, 0xad},
		Attributes:       extra,
	})
	if err != nil {
		t.Fatalf("AccountRequest: %v", err)
	}
	if response.Code != CodeAccountingResponse {
		t.Fatalf("code = %d, want Accounting-Response", response.Code)
	}
	if response.ReplyMessage != "recorded" {
		t.Fatalf("ReplyMessage = %q", response.ReplyMessage)
	}
	if timeout, ok := response.Attributes.Uint32(AttrSessionTimeout); !ok || timeout != 30 {
		t.Fatalf("Session-Timeout = %d (present %v), want 30", timeout, ok)
	}
	proxyStates := response.Attributes.GetAll(AttrProxyState)
	if len(proxyStates) != 1 || proxyStates[0].String() != "proxy-state-1" {
		t.Fatalf("Proxy-State = %v", proxyStates)
	}
	capture := nextAccountingCapture(t, captures)
	if capture.StatusType != AcctStatusStart || capture.SessionID != "sess-1" || capture.UserName != "alice" {
		t.Fatalf("unexpected capture: %+v", capture)
	}
	if capture.NASIdentifier != "nas-1" || capture.NASPort != 7 || capture.NASPortType != NASPortTypeEthernet {
		t.Fatalf("unexpected NAS fields: %+v", capture)
	}
	if capture.Authentic != AcctAuthenticRADIUS || capture.TerminateCause != AcctTerminateUserRequest {
		t.Fatalf("unexpected accounting fields: %+v", capture)
	}
	if capture.DelayTime != 0 {
		t.Fatalf("Acct-Delay-Time = %d, want 0", capture.DelayTime)
	}
	if capture.InputOctets != 100 || capture.OutputOctets != 200 || capture.InputPackets != 3 || capture.OutputPackets != 4 || capture.SessionTime != 11 {
		t.Fatalf("unexpected counters: %+v", capture)
	}
	if !capture.HasEventTimestamp || capture.EventTimestamp.Unix() != eventTimestamp.Unix() {
		t.Fatalf("Event-Timestamp = %v (present %v), want %v", capture.EventTimestamp, capture.HasEventTimestamp, eventTimestamp)
	}
	if capture.CallingStationID != "caller-1" || capture.CalledStationID != "called-1" {
		t.Fatalf("unexpected station IDs: %+v", capture)
	}
	if !bytes.Equal(capture.Class, []byte{0xde, 0xad}) {
		t.Fatalf("Class = %x", capture.Class)
	}
	if capture.Identifier != response.Identifier {
		t.Fatalf("identifier = %d, response identifier = %d", capture.Identifier, response.Identifier)
	}
	if capture.RemoteAddr == nil {
		t.Fatal("RemoteAddr was not set")
	}
}

func TestAccountingServerStatusTypes(t *testing.T) {
	secret := accountingServerSecret()
	captures := make(chan accountingCapture, 8)
	server := startAccountingServer(t, AccountingServerConfig{
		Network: "udp4",
		Address: "127.0.0.1:0",
		Secret:  secret,
		Handler: AccountingHandlerFunc(func(ctx context.Context, request *AccountingServerRequest) (*AccountingServerResult, error) {
			captures <- accountingCapture{request: *request}
			return &AccountingServerResult{}, nil
		}),
		Logger: testDynamicLogger(),
	})
	cases := []struct {
		name   string
		status AcctStatusType
	}{
		{name: "start", status: AcctStatusStart},
		{name: "stop", status: AcctStatusStop},
		{name: "interim-update", status: AcctStatusInterimUpdate},
		{name: "accounting-on", status: AcctStatusAccountingOn},
		{name: "accounting-off", status: AcctStatusAccountingOff},
	}
	for _, testCase := range cases {
		t.Run(testCase.name, func(t *testing.T) {
			request := &AccountingRequest{StatusType: testCase.status}
			if accountingSessionStatus(testCase.status) {
				request.SessionID = "sess-" + testCase.name
			}
			client := newTestClient(t, ClientConfig{
				Address:       server.Addr().String(),
				Secret:        secret,
				NASIdentifier: "nas-1",
			})
			if _, err := client.AccountRequest(context.Background(), request); err != nil {
				t.Fatalf("AccountRequest: %v", err)
			}
			capture := nextAccountingCapture(t, captures)
			if capture.StatusType != testCase.status {
				t.Fatalf("StatusType = %d, want %d", capture.StatusType, testCase.status)
			}
		})
	}
}

func TestAccountingServerRejectsBadAuthenticator(t *testing.T) {
	secret := accountingServerSecret()
	captures := make(chan accountingCapture, 4)
	server := startAccountingServer(t, AccountingServerConfig{
		Network: "udp4",
		Address: "127.0.0.1:0",
		Secret:  secret,
		Handler: AccountingHandlerFunc(func(ctx context.Context, request *AccountingServerRequest) (*AccountingServerResult, error) {
			captures <- accountingCapture{request: *request}
			return &AccountingServerResult{}, nil
		}),
		Logger: testDynamicLogger(),
	})
	var attributes Attributes
	attributes.AddUint32(AttrAcctStatusType, uint32(AcctStatusStart))
	attributes.AddString(AttrAcctSessionID, "sess-1")
	attributes.AddString(AttrNASIdentifier, "nas-1")
	requireUDPTimeout(t, server.Addr().String(), rawAccountingRequest(t, []byte("wrong-secret"), 51, attributes))
	expectNoAccountingCapture(t, captures)

	client := newTestClient(t, ClientConfig{
		Address:       server.Addr().String(),
		Secret:        secret,
		NASIdentifier: "nas-1",
	})
	if _, err := client.AccountRequest(context.Background(), &AccountingRequest{StatusType: AcctStatusStart, SessionID: "sess-1"}); err != nil {
		t.Fatalf("AccountRequest after bad authenticator: %v", err)
	}
	if capture := nextAccountingCapture(t, captures); capture.SessionID != "sess-1" {
		t.Fatalf("SessionID = %q", capture.SessionID)
	}
}

func TestAccountingServerRequiresMandatoryAttributes(t *testing.T) {
	secret := accountingServerSecret()
	captures := make(chan accountingCapture, 4)
	server := startAccountingServer(t, AccountingServerConfig{
		Network: "udp4",
		Address: "127.0.0.1:0",
		Secret:  secret,
		Handler: AccountingHandlerFunc(func(ctx context.Context, request *AccountingServerRequest) (*AccountingServerResult, error) {
			captures <- accountingCapture{request: *request}
			return &AccountingServerResult{}, nil
		}),
		Logger: testDynamicLogger(),
	})
	cases := []struct {
		name       string
		attributes func() Attributes
	}{
		{
			name: "missing status type",
			attributes: func() Attributes {
				var attributes Attributes
				attributes.AddString(AttrAcctSessionID, "sess-1")
				attributes.AddString(AttrNASIdentifier, "nas-1")
				return attributes
			},
		},
		{
			name: "unsupported status type",
			attributes: func() Attributes {
				var attributes Attributes
				attributes.AddUint32(AttrAcctStatusType, 9)
				attributes.AddString(AttrAcctSessionID, "sess-1")
				attributes.AddString(AttrNASIdentifier, "nas-1")
				return attributes
			},
		},
		{
			name: "missing session ID",
			attributes: func() Attributes {
				var attributes Attributes
				attributes.AddUint32(AttrAcctStatusType, uint32(AcctStatusStart))
				attributes.AddString(AttrNASIdentifier, "nas-1")
				return attributes
			},
		},
		{
			name: "missing NAS identity",
			attributes: func() Attributes {
				var attributes Attributes
				attributes.AddUint32(AttrAcctStatusType, uint32(AcctStatusStart))
				attributes.AddString(AttrAcctSessionID, "sess-1")
				return attributes
			},
		},
	}
	for _, testCase := range cases {
		t.Run(testCase.name, func(t *testing.T) {
			requireUDPTimeout(t, server.Addr().String(), rawAccountingRequest(t, secret, 51, testCase.attributes()))
			expectNoAccountingCapture(t, captures)
		})
	}
}

func TestAccountingServerHandlerError(t *testing.T) {
	secret := accountingServerSecret()
	captures := make(chan accountingCapture, 4)
	server := startAccountingServer(t, AccountingServerConfig{
		Network: "udp4",
		Address: "127.0.0.1:0",
		Secret:  secret,
		Handler: AccountingHandlerFunc(func(ctx context.Context, request *AccountingServerRequest) (*AccountingServerResult, error) {
			captures <- accountingCapture{request: *request}
			if request.UserName == "fail" {
				return nil, errors.New("storage unavailable")
			}
			return &AccountingServerResult{}, nil
		}),
		Logger: testDynamicLogger(),
	})
	client := newTestClient(t, ClientConfig{
		Address:       server.Addr().String(),
		Secret:        secret,
		NASIdentifier: "nas-1",
		Timeout:       80 * time.Millisecond,
	})
	if _, err := client.AccountRequest(context.Background(), &AccountingRequest{
		StatusType: AcctStatusStart,
		SessionID:  "sess-1",
		UserName:   "fail",
	}); !errors.Is(err, ErrTimeout) {
		t.Fatalf("error = %v, want ErrTimeout", err)
	}
	if capture := nextAccountingCapture(t, captures); capture.UserName != "fail" {
		t.Fatalf("UserName = %q", capture.UserName)
	}

	client = newTestClient(t, ClientConfig{
		Address:       server.Addr().String(),
		Secret:        secret,
		NASIdentifier: "nas-1",
	})
	if _, err := client.AccountRequest(context.Background(), &AccountingRequest{
		StatusType: AcctStatusStart,
		SessionID:  "sess-2",
		UserName:   "ok",
	}); err != nil {
		t.Fatalf("AccountRequest after handler error: %v", err)
	}
	if capture := nextAccountingCapture(t, captures); capture.SessionID != "sess-2" {
		t.Fatalf("SessionID = %q", capture.SessionID)
	}
}

func TestAccountingServerClientLookup(t *testing.T) {
	secret := accountingServerSecret()
	lookup := ServerClientLookupFunc(func(ctx context.Context, remote net.Addr, attributes Attributes) (*ServerClient, error) {
		nas, _ := attributes.Get(AttrNASIdentifier)
		if nas.String() == "nas-1" {
			return &ServerClient{Name: "nas-1", Secret: secret}, nil
		}
		return nil, nil
	})
	captures := make(chan accountingCapture, 4)
	server := startAccountingServer(t, AccountingServerConfig{
		Network:      "udp4",
		Address:      "127.0.0.1:0",
		ClientLookup: lookup,
		Handler: AccountingHandlerFunc(func(ctx context.Context, request *AccountingServerRequest) (*AccountingServerResult, error) {
			captures <- accountingCapture{request: *request}
			return &AccountingServerResult{}, nil
		}),
		Logger: testDynamicLogger(),
	})
	client := newTestClient(t, ClientConfig{
		Address:       server.Addr().String(),
		Secret:        secret,
		NASIdentifier: "nas-1",
	})
	if _, err := client.AccountRequest(context.Background(), &AccountingRequest{StatusType: AcctStatusStart, SessionID: "sess-1"}); err != nil {
		t.Fatalf("AccountRequest known client: %v", err)
	}
	if capture := nextAccountingCapture(t, captures); capture.SessionID != "sess-1" {
		t.Fatalf("SessionID = %q", capture.SessionID)
	}

	client = newTestClient(t, ClientConfig{
		Address:       server.Addr().String(),
		Secret:        secret,
		NASIdentifier: "nas-2",
		Timeout:       80 * time.Millisecond,
	})
	if _, err := client.AccountRequest(context.Background(), &AccountingRequest{StatusType: AcctStatusStart, SessionID: "sess-2"}); !errors.Is(err, ErrTimeout) {
		t.Fatalf("error = %v, want ErrTimeout", err)
	}
	expectNoAccountingCapture(t, captures)
}

func TestAccountingServerOverTLS(t *testing.T) {
	secret := accountingServerSecret()
	certificate, roots := testCertificate(t)
	captures := make(chan accountingCapture, 4)
	server := startAccountingServer(t, AccountingServerConfig{
		Network: NetworkTLS,
		Address: "127.0.0.1:0",
		Secret:  secret,
		Handler: AccountingHandlerFunc(func(ctx context.Context, request *AccountingServerRequest) (*AccountingServerResult, error) {
			captures <- accountingCapture{request: *request}
			return &AccountingServerResult{}, nil
		}),
		TLSConfig: &tls.Config{
			Certificates: []tls.Certificate{certificate},
			MinVersion:   tls.VersionTLS12,
		},
		Logger: testDynamicLogger(),
	})
	client := newTestClient(t, ClientConfig{
		Network:       NetworkTLS,
		Address:       server.Addr().String(),
		Secret:        secret,
		NASIdentifier: "nas-1",
		TLSConfig: &tls.Config{
			RootCAs:    roots,
			ServerName: "radius.test",
		},
	})
	response, err := client.AccountRequest(context.Background(), &AccountingRequest{StatusType: AcctStatusStart, SessionID: "sess-tls"})
	if err != nil {
		t.Fatalf("AccountRequest: %v", err)
	}
	if response.Code != CodeAccountingResponse {
		t.Fatalf("code = %d, want Accounting-Response", response.Code)
	}
	if capture := nextAccountingCapture(t, captures); capture.SessionID != "sess-tls" {
		t.Fatalf("SessionID = %q", capture.SessionID)
	}
}

func TestAccountingServerLifecycle(t *testing.T) {
	secret := accountingServerSecret()
	server, err := NewAccountingServer(AccountingServerConfig{
		Network: "udp4",
		Address: "127.0.0.1:0",
		Secret:  secret,
		Handler: AccountingHandlerFunc(func(ctx context.Context, request *AccountingServerRequest) (*AccountingServerResult, error) {
			return &AccountingServerResult{}, nil
		}),
		Logger: testDynamicLogger(),
	})
	if err != nil {
		t.Fatalf("NewAccountingServer: %v", err)
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
	if err := server.ListenAndServe(context.Background()); !errors.Is(err, ErrServerClosed) {
		t.Fatalf("ListenAndServe after Close = %v, want ErrServerClosed", err)
	}
	if server.Addr() == nil {
		t.Fatal("Addr is nil after Serve returned")
	}
}

func TestAccountingServerConfigValidation(t *testing.T) {
	secret := accountingServerSecret()
	handler := AccountingHandlerFunc(func(ctx context.Context, request *AccountingServerRequest) (*AccountingServerResult, error) {
		return &AccountingServerResult{}, nil
	})
	cases := []struct {
		name   string
		config AccountingServerConfig
	}{
		{name: "missing handler", config: AccountingServerConfig{Secret: secret}},
		{name: "missing secret", config: AccountingServerConfig{Handler: handler}},
		{name: "bad network", config: AccountingServerConfig{Network: "sctp", Secret: secret, Handler: handler}},
		{name: "bad address", config: AccountingServerConfig{Address: "127.0.0.1", Secret: secret, Handler: handler}},
		{name: "tls without config", config: AccountingServerConfig{Network: NetworkTLS, Secret: secret, Handler: handler}},
		{name: "packet too small", config: AccountingServerConfig{Secret: secret, Handler: handler, MaxPacketSize: HeaderLength - 1}},
		{name: "packet too large", config: AccountingServerConfig{Secret: secret, Handler: handler, MaxPacketSize: MaxPacketLength + 1}},
		{name: "negative concurrency", config: AccountingServerConfig{Secret: secret, Handler: handler, MaxConcurrent: -1}},
		{name: "negative timeout", config: AccountingServerConfig{Secret: secret, Handler: handler, Timeout: -time.Second}},
	}
	for _, testCase := range cases {
		t.Run(testCase.name, func(t *testing.T) {
			if _, err := NewAccountingServer(testCase.config); !errors.Is(err, ErrInvalidConfig) {
				t.Fatalf("error = %v, want ErrInvalidConfig", err)
			}
		})
	}
}

func TestServerDefaults(t *testing.T) {
	secret := []byte("testing-secret")
	authenticator := AccessAuthenticatorFunc(func(ctx context.Context, request *AccessServerRequest) (*AccessServerResult, error) {
		return &AccessServerResult{}, nil
	})
	accountingHandler := AccountingHandlerFunc(func(ctx context.Context, request *AccountingServerRequest) (*AccountingServerResult, error) {
		return &AccountingServerResult{}, nil
	})
	access, err := NewAccessServer(AccessServerConfig{Secret: secret, Authenticator: authenticator})
	if err != nil {
		t.Fatalf("NewAccessServer: %v", err)
	}
	t.Cleanup(func() {
		_ = access.Close()
	})
	accounting, err := NewAccountingServer(AccountingServerConfig{Secret: secret, Handler: accountingHandler})
	if err != nil {
		t.Fatalf("NewAccountingServer: %v", err)
	}
	t.Cleanup(func() {
		_ = accounting.Close()
	})
	certificate, _ := testCertificate(t)
	tlsAccess, err := NewAccessServer(AccessServerConfig{
		Network:       NetworkTLS,
		Secret:        secret,
		Authenticator: authenticator,
		TLSConfig:     &tls.Config{Certificates: []tls.Certificate{certificate}},
	})
	if err != nil {
		t.Fatalf("NewAccessServer TLS: %v", err)
	}
	t.Cleanup(func() {
		_ = tlsAccess.Close()
	})
	cases := []struct {
		name     string
		settings serverSettings
		address  string
		stream   bool
		useTLS   bool
	}{
		{name: "access udp", settings: access.transport.cfg.settings, address: DefaultAccessServerAddress},
		{name: "accounting udp", settings: accounting.transport.cfg.settings, address: DefaultAccountingServerAddress},
		{name: "access tls", settings: tlsAccess.transport.cfg.settings, address: DefaultServerTLSAddress, stream: true, useTLS: true},
	}
	for _, testCase := range cases {
		t.Run(testCase.name, func(t *testing.T) {
			if testCase.settings.address != testCase.address {
				t.Fatalf("address = %q, want %q", testCase.settings.address, testCase.address)
			}
			if testCase.settings.stream != testCase.stream || testCase.settings.useTLS != testCase.useTLS {
				t.Fatalf("stream = %v, TLS = %v", testCase.settings.stream, testCase.settings.useTLS)
			}
			if testCase.settings.maxPacketSize != MaxPacketLength {
				t.Fatalf("max packet size = %d, want %d", testCase.settings.maxPacketSize, MaxPacketLength)
			}
			if testCase.settings.maxConcurrent != DefaultMaxConcurrentRequests {
				t.Fatalf("max concurrent = %d, want %d", testCase.settings.maxConcurrent, DefaultMaxConcurrentRequests)
			}
			if testCase.settings.timeout != DefaultTimeout {
				t.Fatalf("timeout = %v, want %v", testCase.settings.timeout, DefaultTimeout)
			}
		})
	}
}

func TestServerAdaptersRejectNil(t *testing.T) {
	if _, err := ServerClientLookupFunc(nil).LookupServerClient(context.Background(), nil, nil); !errors.Is(err, ErrInvalidConfig) {
		t.Fatalf("nil ServerClientLookupFunc error = %v, want ErrInvalidConfig", err)
	}
	if _, err := AccessAuthenticatorFunc(nil).AuthenticateAccess(context.Background(), nil); !errors.Is(err, ErrInvalidRequest) {
		t.Fatalf("nil AccessAuthenticatorFunc error = %v, want ErrInvalidRequest", err)
	}
	if _, err := AccountingHandlerFunc(nil).HandleAccounting(context.Background(), nil); !errors.Is(err, ErrInvalidRequest) {
		t.Fatalf("nil AccountingHandlerFunc error = %v, want ErrInvalidRequest", err)
	}
	var request *AccessServerRequest
	if request.VerifyPAP([]byte("secret")) {
		t.Fatal("nil AccessServerRequest accepted a PAP password")
	}
	if request.VerifyCHAP([]byte("secret")) {
		t.Fatal("nil AccessServerRequest accepted a CHAP password")
	}
}
