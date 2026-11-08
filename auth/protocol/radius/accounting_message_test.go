package radius

import (
	"bytes"
	"context"
	"errors"
	"net"
	"sync/atomic"
	"testing"
	"time"
)

// exchangeUDPRepeat sends the same request several times over one UDP socket and returns each
// response. Reusing the socket exercises duplicate detection from one NAS peer. |
// exchangeUDPRepeat 通过同一个 UDP 套接字多次发送同一请求并返回每个响应。复用套接字可验证同一 NAS
// 对端的重复检测。
func exchangeUDPRepeat(t *testing.T, address string, request []byte, count int) [][]byte {
	t.Helper()
	conn, err := net.DialTimeout("udp4", address, time.Second)
	if err != nil {
		t.Fatalf("dial %s: %v", address, err)
	}
	defer func() {
		_ = conn.Close()
	}()
	_ = conn.SetDeadline(time.Now().Add(2 * time.Second))
	responses := make([][]byte, 0, count)
	buffer := make([]byte, MaxPacketLength)
	for index := 0; index < count; index++ {
		if _, err := conn.Write(request); err != nil {
			t.Fatalf("write %d: %v", index, err)
		}
		n, err := conn.Read(buffer)
		if err != nil {
			t.Fatalf("read %d: %v", index, err)
		}
		responses = append(responses, append([]byte(nil), buffer[:n]...))
	}
	return responses
}

// wrongOrderMessageAuthenticator builds an Accounting-Request whose Request Authenticator is valid
// but whose Message-Authenticator was signed with the accounting authenticator instead of the
// RFC 2866 zero vector. | wrongOrderMessageAuthenticator 构建 Request Authenticator 合法、但
// Message-Authenticator 使用计费认证符而非 RFC 2866 零向量签名的 Accounting-Request。
func wrongOrderMessageAuthenticator(t *testing.T, secret []byte, identifier uint8, attributes Attributes) []byte {
	t.Helper()
	attrs := attributes.Clone()
	attrs.Add(AttrMessageAuthenticator, make([]byte, 16))
	raw, err := MarshalPacket(&Packet{
		Code:       CodeAccountingRequest,
		Identifier: identifier,
		Attributes: attrs,
	})
	if err != nil {
		t.Fatalf("MarshalPacket: %v", err)
	}
	authenticator, err := accountingRequestAuthenticator(raw, secret)
	if err != nil {
		t.Fatalf("accountingRequestAuthenticator: %v", err)
	}
	copy(raw[4:HeaderLength], authenticator[:])
	if err := signMessageAuthenticator(raw, secret, authenticator); err != nil {
		t.Fatalf("signMessageAuthenticator: %v", err)
	}
	authenticator, err = accountingRequestAuthenticator(raw, secret)
	if err != nil {
		t.Fatalf("accountingRequestAuthenticator: %v", err)
	}
	copy(raw[4:HeaderLength], authenticator[:])
	return raw
}

// accountingMessageAttributes returns the mandatory attributes for an Accounting-Request. |
// accountingMessageAttributes 返回 Accounting-Request 的必选属性。
func accountingMessageAttributes(sessionID string) Attributes {
	var attributes Attributes
	attributes.AddUint32(AttrAcctStatusType, uint32(AcctStatusStart))
	attributes.AddString(AttrAcctSessionID, sessionID)
	attributes.AddString(AttrNASIdentifier, "nas-message")
	return attributes
}

func TestAccountingServerMessageAuthenticator(t *testing.T) {
	secret := accountingServerSecret()
	captures := make(chan accountingCapture, 16)
	handler := AccountingHandlerFunc(func(ctx context.Context, request *AccountingServerRequest) (*AccountingServerResult, error) {
		captures <- accountingCapture{request: *request}
		return &AccountingServerResult{ReplyMessage: "recorded"}, nil
	})
	optional := startAccountingServer(t, AccountingServerConfig{
		Network: "udp4",
		Address: "127.0.0.1:0",
		Secret:  secret,
		Handler: handler,
		Logger:  testDynamicLogger(),
	})
	address := optional.Addr().String()

	raw := accountingRequestWithMessageAuthenticator(t, secret, 0x11, accountingMessageAttributes("sess-ma"))
	request, err := ParsePacket(raw)
	if err != nil {
		t.Fatalf("ParsePacket: %v", err)
	}
	response, err := exchangeUDP(t, address, raw, time.Second)
	if err != nil {
		t.Fatalf("exchange with Message-Authenticator: %v", err)
	}
	packet := parseAndVerifyResponse(t, response, request.Authenticator, secret)
	if packet.Code != CodeAccountingResponse {
		t.Fatalf("response code = %d", packet.Code)
	}
	present, valid, err := verifyMessageAuthenticatorRaw(response, secret, request.Authenticator)
	if err != nil || !present || !valid {
		t.Fatalf("response Message-Authenticator present=%v valid=%v err=%v", present, valid, err)
	}
	capture := nextAccountingCapture(t, captures)
	if !capture.HasMessageAuthenticator {
		t.Fatal("HasMessageAuthenticator is false for a signed request")
	}

	raw = rawAccountingRequest(t, secret, 0x12, accountingMessageAttributes("sess-no-ma"))
	request, err = ParsePacket(raw)
	if err != nil {
		t.Fatalf("ParsePacket: %v", err)
	}
	response, err = exchangeUDP(t, address, raw, time.Second)
	if err != nil {
		t.Fatalf("exchange without Message-Authenticator: %v", err)
	}
	parseAndVerifyResponse(t, response, request.Authenticator, secret)
	if present, _, err := verifyMessageAuthenticatorRaw(response, secret, request.Authenticator); err != nil || present {
		t.Fatalf("unrequested response Message-Authenticator present=%v err=%v", present, err)
	}
	capture = nextAccountingCapture(t, captures)
	if capture.HasMessageAuthenticator {
		t.Fatal("HasMessageAuthenticator is true for an unsigned request")
	}

	invalid := wrongOrderMessageAuthenticator(t, secret, 0x13, accountingMessageAttributes("sess-invalid-ma"))
	requireUDPTimeout(t, address, invalid)
	expectNoAccountingCapture(t, captures)

	required := startAccountingServer(t, AccountingServerConfig{
		Network:                     "udp4",
		Address:                     "127.0.0.1:0",
		Secret:                      secret,
		Handler:                     handler,
		RequireMessageAuthenticator: true,
		Logger:                      testDynamicLogger(),
	})
	missing := rawAccountingRequest(t, secret, 0x14, accountingMessageAttributes("sess-required"))
	requireUDPTimeout(t, required.Addr().String(), missing)
	expectNoAccountingCapture(t, captures)

	validRaw := accountingRequestWithMessageAuthenticator(t, secret, 0x15, accountingMessageAttributes("sess-required-ma"))
	validRequest, err := ParsePacket(validRaw)
	if err != nil {
		t.Fatalf("ParsePacket: %v", err)
	}
	response, err = exchangeUDP(t, required.Addr().String(), validRaw, time.Second)
	if err != nil {
		t.Fatalf("required exchange: %v", err)
	}
	parseAndVerifyResponse(t, response, validRequest.Authenticator, secret)
	if capture := nextAccountingCapture(t, captures); !capture.HasMessageAuthenticator {
		t.Fatal("required request was accepted without HasMessageAuthenticator")
	}
}

func TestAccountingServerDuplicateSuppression(t *testing.T) {
	secret := accountingServerSecret()
	var calls atomic.Int64
	server := startAccountingServer(t, AccountingServerConfig{
		Network: "udp4",
		Address: "127.0.0.1:0",
		Secret:  secret,
		Handler: AccountingHandlerFunc(func(ctx context.Context, request *AccountingServerRequest) (*AccountingServerResult, error) {
			calls.Add(1)
			return &AccountingServerResult{ReplyMessage: "recorded"}, nil
		}),
		Logger: testDynamicLogger(),
	})
	raw := accountingRequestWithMessageAuthenticator(t, secret, 0x21, accountingMessageAttributes("sess-duplicate"))
	responses := exchangeUDPRepeat(t, server.Addr().String(), raw, 2)
	if !bytes.Equal(responses[0], responses[1]) {
		t.Fatal("duplicate retransmission did not replay the exact signed response")
	}
	if calls.Load() != 1 {
		t.Fatalf("handler calls = %d after duplicate, want 1", calls.Load())
	}
	other := accountingRequestWithMessageAuthenticator(t, secret, 0x22, accountingMessageAttributes("sess-other"))
	if _, err := exchangeUDP(t, server.Addr().String(), other, time.Second); err != nil {
		t.Fatalf("exchange distinct request: %v", err)
	}
	if calls.Load() != 2 {
		t.Fatalf("handler calls = %d after distinct request, want 2", calls.Load())
	}
}

func TestAccountingServerDuplicateExpiry(t *testing.T) {
	secret := accountingServerSecret()
	var calls atomic.Int64
	server := startAccountingServer(t, AccountingServerConfig{
		Network:         "udp4",
		Address:         "127.0.0.1:0",
		Secret:          secret,
		DuplicateWindow: 60 * time.Millisecond,
		Handler: AccountingHandlerFunc(func(ctx context.Context, request *AccountingServerRequest) (*AccountingServerResult, error) {
			calls.Add(1)
			return &AccountingServerResult{}, nil
		}),
		Logger: testDynamicLogger(),
	})
	raw := accountingRequestWithMessageAuthenticator(t, secret, 0x23, accountingMessageAttributes("sess-expiry"))
	if _, err := exchangeUDP(t, server.Addr().String(), raw, time.Second); err != nil {
		t.Fatalf("first exchange: %v", err)
	}
	if calls.Load() != 1 {
		t.Fatalf("handler calls = %d, want 1", calls.Load())
	}
	time.Sleep(120 * time.Millisecond)
	if _, err := exchangeUDP(t, server.Addr().String(), raw, time.Second); err != nil {
		t.Fatalf("second exchange: %v", err)
	}
	if calls.Load() != 2 {
		t.Fatalf("handler calls = %d after expiry, want 2", calls.Load())
	}
}

func TestAccountingServerDuplicateSuppressionDisabled(t *testing.T) {
	secret := accountingServerSecret()
	var calls atomic.Int64
	server := startAccountingServer(t, AccountingServerConfig{
		Network:         "udp4",
		Address:         "127.0.0.1:0",
		Secret:          secret,
		DuplicateWindow: -time.Second,
		Handler: AccountingHandlerFunc(func(ctx context.Context, request *AccountingServerRequest) (*AccountingServerResult, error) {
			calls.Add(1)
			return &AccountingServerResult{}, nil
		}),
		Logger: testDynamicLogger(),
	})
	if server.duplicates != nil {
		t.Fatal("duplicate cache is enabled for a negative window")
	}
	raw := accountingRequestWithMessageAuthenticator(t, secret, 0x24, accountingMessageAttributes("sess-disabled"))
	exchangeUDPRepeat(t, server.Addr().String(), raw, 2)
	if calls.Load() != 2 {
		t.Fatalf("handler calls = %d with suppression disabled, want 2", calls.Load())
	}
}

func TestAccountingServerDuplicateConfigValidation(t *testing.T) {
	secret := accountingServerSecret()
	handler := AccountingHandlerFunc(func(ctx context.Context, request *AccountingServerRequest) (*AccountingServerResult, error) {
		return &AccountingServerResult{}, nil
	})
	if _, err := NewAccountingServer(AccountingServerConfig{
		Secret:             secret,
		Handler:            handler,
		DuplicateCacheSize: -1,
	}); !errors.Is(err, ErrInvalidConfig) {
		t.Fatalf("negative cache size error = %v, want ErrInvalidConfig", err)
	}
	server, err := NewAccountingServer(AccountingServerConfig{
		Secret:             secret,
		Handler:            handler,
		DuplicateCacheSize: 2,
		DuplicateWindow:    -time.Second,
	})
	if err != nil {
		t.Fatalf("NewAccountingServer with suppression disabled: %v", err)
	}
	t.Cleanup(func() {
		_ = server.Close()
	})
	if server.duplicates != nil {
		t.Fatal("negative window did not disable duplicate suppression")
	}
	defaults, err := NewAccountingServer(AccountingServerConfig{Secret: secret, Handler: handler})
	if err != nil {
		t.Fatalf("NewAccountingServer defaults: %v", err)
	}
	t.Cleanup(func() {
		_ = defaults.Close()
	})
	if defaults.duplicates == nil || defaults.duplicates.max != DefaultAccountingDuplicateCacheSize ||
		defaults.duplicates.window != DefaultAccountingDuplicateWindow {
		t.Fatal("default duplicate cache settings were not applied")
	}
}

func TestAccountingDuplicateCache(t *testing.T) {
	remote := &net.UDPAddr{IP: net.ParseIP("192.0.2.10"), Port: 1234}
	otherPort := &net.UDPAddr{IP: net.ParseIP("192.0.2.10"), Port: 9999}
	otherHost := &net.UDPAddr{IP: net.ParseIP("192.0.2.11"), Port: 1234}
	cache := newAccountingDuplicateCache(2, time.Minute)
	now := time.Now()
	cache.store(remote, []byte("raw-a"), []byte("response-a"), now)
	if response, ok := cache.lookup(otherPort, []byte("raw-a"), now); !ok || string(response) != "response-a" {
		t.Fatalf("lookup from another source port = %q, %v; want a replay", response, ok)
	}
	if _, ok := cache.lookup(otherHost, []byte("raw-a"), now); ok {
		t.Fatal("lookup from another host matched a duplicate")
	}
	if _, ok := cache.lookup(remote, []byte("raw-b"), now); ok {
		t.Fatal("lookup for another request matched a duplicate")
	}
	if _, ok := cache.lookup(remote, []byte("raw-a"), now.Add(2*time.Minute)); ok {
		t.Fatal("expired entry was replayed")
	}
	cache.store(remote, []byte("raw-a"), []byte("response-a"), now)
	cache.store(remote, []byte("raw-b"), []byte("response-b"), now)
	cache.store(remote, []byte("raw-c"), []byte("response-c"), now)
	if _, ok := cache.lookup(remote, []byte("raw-a"), now); ok {
		t.Fatal("oldest entry was not evicted from a full cache")
	}
	if response, ok := cache.lookup(remote, []byte("raw-b"), now); !ok || string(response) != "response-b" {
		t.Fatalf("lookup after eviction = %q, %v", response, ok)
	}
	var nilCache *accountingDuplicateCache
	if _, ok := nilCache.lookup(remote, nil, now); ok {
		t.Fatal("nil cache replayed a response")
	}
	nilCache.store(remote, nil, nil, now)
}
