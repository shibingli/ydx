package radius

import (
	"bytes"
	"context"
	"errors"
	"net"
	"strings"
	"sync"
	"testing"
	"time"
)

// relayObservation captures one request observed by a relay test upstream. |
// relayObservation 保存中继测试上游观察到的一次请求。
type relayObservation struct {
	packet      *Packet
	raw         []byte
	password    []byte
	sendKey     []byte
	recvKey     []byte
	proxyStates []string
	chapChall   []byte
	name        string
	maPresent   bool
	maValid     bool
	acctValid   bool
}

// newTestRelay constructs a relay and closes it at test cleanup. | newTestRelay 构造中继并在测试清理时关闭。
func newTestRelay(t *testing.T, config RelayConfig) *Relay {
	t.Helper()
	relay, err := NewRelay(config)
	if err != nil {
		t.Fatalf("NewRelay: %v", err)
	}
	t.Cleanup(func() {
		_ = relay.Close()
	})
	return relay
}

// nextRelayObservation returns the next upstream observation or fails the test. |
// nextRelayObservation 返回下一条上游观察结果或在失败时终止测试。
func nextRelayObservation(t *testing.T, observations <-chan relayObservation) relayObservation {
	t.Helper()
	select {
	case observation := <-observations:
		return observation
	case <-time.After(2 * time.Second):
		t.Fatal("timed out waiting for an upstream request")
	}
	return relayObservation{}
}

// expectNoRelayObservation asserts that the upstream was not contacted. |
// expectNoRelayObservation 断言上游未被联系。
func expectNoRelayObservation(t *testing.T, observations <-chan relayObservation) {
	t.Helper()
	select {
	case observation := <-observations:
		t.Fatalf("unexpected upstream request: code %d", uint8(observation.packet.Code))
	case <-time.After(100 * time.Millisecond):
	}
}

// echoProxyStates returns every Proxy-State from request followed by a Reply-Message. |
// echoProxyStates 返回 request 的全部 Proxy-State，并追加 Reply-Message。
func echoProxyStates(request *Packet, message string) Attributes {
	var attributes Attributes
	for _, proxyState := range request.Attributes.GetAll(AttrProxyState) {
		attributes = append(attributes, Attributes{proxyState}.Clone()...)
	}
	if message != "" {
		attributes.AddString(AttrReplyMessage, message)
	}
	return attributes
}

// relayAccessRequest builds an Access-Request for relay tests. | relayAccessRequest 为 relay 测试构建
// Access-Request。
func relayAccessRequest(t *testing.T, secret []byte, identifier uint8, attributes Attributes, messageAuthenticator bool) ([]byte, [16]byte) {
	t.Helper()
	authenticator := rawAccessAuthenticator()
	authenticator[0] = identifier
	var maSecret []byte
	if messageAuthenticator {
		maSecret = secret
	}
	return rawAccessRequest(t, identifier, authenticator, attributes, maSecret), authenticator
}

// accountingRequestWithMessageAuthenticator encodes an Accounting-Request with the RFC 2866
// Message-Authenticator order: the HMAC is computed over a zero Request Authenticator before the
// accounting Request Authenticator is computed over the packet that already carries the
// Message-Authenticator. | accountingRequestWithMessageAuthenticator 按 RFC 2866 的
// Message-Authenticator 顺序编码 Accounting-Request：先用全零 Request Authenticator 计算 HMAC，再在
// 已包含 Message-Authenticator 的报文上计算计费 Request Authenticator。
func accountingRequestWithMessageAuthenticator(t *testing.T, secret []byte, identifier uint8, attributes Attributes) []byte {
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
	if err := signMessageAuthenticator(raw, secret, [16]byte{}); err != nil {
		t.Fatalf("signMessageAuthenticator: %v", err)
	}
	authenticator, err := accountingRequestAuthenticator(raw, secret)
	if err != nil {
		t.Fatalf("accountingRequestAuthenticator: %v", err)
	}
	copy(raw[4:HeaderLength], authenticator[:])
	return raw
}

// observeRelayRequest extracts credential material from an upstream request. |
// observeRelayRequest 从上游请求中提取凭据材料。
func observeRelayRequest(code Code, request *Packet, raw, secret []byte, name string) (relayObservation, error) {
	observation := relayObservation{
		packet: request,
		raw:    raw,
		name:   name,
	}
	for _, attribute := range request.Attributes {
		switch {
		case attribute.Type == AttrProxyState:
			observation.proxyStates = append(observation.proxyStates, string(attribute.Value))
		case attribute.Type == AttrCHAPChallenge:
			observation.chapChall = append([]byte(nil), attribute.Value...)
		case attribute.Type == AttrUserPassword:
			plain, err := DecryptUserPassword(secret, request.Authenticator[:], attribute.Value)
			if err != nil {
				return observation, err
			}
			observation.password = plain
		case attribute.Type == AttrVendorSpecific && attribute.VendorID == VendorMicrosoft &&
			attribute.VendorType == VendorMSMPPESendKey:
			plain, err := DecryptMSMPPEKey(secret, request.Authenticator[:], attribute.Value)
			if err != nil {
				return observation, err
			}
			observation.sendKey = plain
		case attribute.Type == AttrVendorSpecific && attribute.VendorID == VendorMicrosoft &&
			attribute.VendorType == VendorMSMPPERecvKey:
			plain, err := DecryptMSMPPEKey(secret, request.Authenticator[:], attribute.Value)
			if err != nil {
				return observation, err
			}
			observation.recvKey = plain
		}
	}
	present, valid, err := verifyInboundMessageAuthenticator(code, raw, secret, request.Authenticator)
	if err != nil {
		return observation, err
	}
	observation.maPresent = present
	observation.maValid = valid
	if code == CodeAccountingRequest {
		observation.acctValid = verifyAccountingRequestAuthenticator(raw, secret) == nil
	}
	return observation, nil
}

func TestRelayForwardsAccessWithTranslation(t *testing.T) {
	nasSecret := []byte("relay-nas-secret")
	upstreamSecret := []byte("relay-upstream-secret")
	observations := make(chan relayObservation, 4)
	upstream := newUDPMock(t, upstreamSecret, func(request *Packet, raw []byte) ([]byte, error) {
		observation, err := observeRelayRequest(CodeAccessRequest, request, raw, upstreamSecret, "primary")
		if err != nil {
			return nil, err
		}
		observations <- observation
		return signedMessageResponse(request, upstreamSecret, CodeAccessAccept, echoProxyStates(request, "accepted"))
	})
	relay := newTestRelay(t, RelayConfig{
		Upstreams: []RelayUpstream{{
			Name:    "primary",
			Network: "udp4",
			Address: upstream.Addr(),
			Secret:  upstreamSecret,
		}},
	})
	authenticator := rawAccessAuthenticator()
	var attributes Attributes
	attributes.AddString(AttrUserName, "alice")
	attributes.Add(AttrUserPassword, hiddenPassword(t, nasSecret, authenticator, "correct horse battery staple"))
	attributes.AddString(AttrProxyState, "state-1")
	attributes.AddString(AttrProxyState, "state-2")
	raw := rawAccessRequest(t, 0x21, authenticator, attributes, nasSecret)

	result, err := relay.ForwardAccess(context.Background(), raw, nasSecret)
	if err != nil {
		t.Fatalf("ForwardAccess: %v", err)
	}
	if result.Upstream != "primary" {
		t.Fatalf("Upstream = %q, want primary", result.Upstream)
	}
	response := parseAndVerifyResponse(t, result.Raw, authenticator, nasSecret)
	if response.Code != CodeAccessAccept {
		t.Fatalf("response code = %d, want Access-Accept", response.Code)
	}
	if response.Identifier != 0x21 {
		t.Fatalf("response identifier = %d, want 33", response.Identifier)
	}
	if message, ok := response.Attributes.Get(AttrReplyMessage); !ok || message.String() != "accepted" {
		t.Fatalf("Reply-Message = %v", response.Attributes.GetAll(AttrReplyMessage))
	}
	states := response.Attributes.GetAll(AttrProxyState)
	if len(states) != 2 || string(states[0].Value) != "state-1" || string(states[1].Value) != "state-2" {
		t.Fatalf("downstream Proxy-State = %v, want the two original values", states)
	}
	present, valid, err := verifyMessageAuthenticatorRaw(result.Raw, nasSecret, authenticator)
	if err != nil || !present || !valid {
		t.Fatalf("downstream Message-Authenticator present=%v valid=%v err=%v", present, valid, err)
	}

	observation := nextRelayObservation(t, observations)
	if !observation.maPresent || !observation.maValid {
		t.Fatalf("upstream Message-Authenticator present=%v valid=%v", observation.maPresent, observation.maValid)
	}
	if string(observation.password) != "correct horse battery staple" {
		t.Fatalf("upstream User-Password = %q", observation.password)
	}
	if len(observation.proxyStates) != 3 {
		t.Fatalf("upstream Proxy-State count = %d, want 3", len(observation.proxyStates))
	}
	if observation.proxyStates[0] != "state-1" || observation.proxyStates[1] != "state-2" {
		t.Fatalf("upstream Proxy-State = %v", observation.proxyStates)
	}
	marker := observation.proxyStates[2]
	if !strings.HasPrefix(marker, relayProxyStateMagic) {
		t.Fatalf("upstream relay marker = %q", marker)
	}
	if observation.packet.Identifier == 0 && response.Identifier == 0 {
		t.Fatal("unexpected zero identifiers")
	}
}

func TestRelayAccessFailoverAndRetries(t *testing.T) {
	nasSecret := []byte("relay-nas-secret")
	firstSecret := []byte("relay-first-secret")
	secondSecret := []byte("relay-second-secret")
	firstObservations := make(chan relayObservation, 4)
	secondObservations := make(chan relayObservation, 4)
	first := newUDPMock(t, firstSecret, func(request *Packet, raw []byte) ([]byte, error) {
		observation, err := observeRelayRequest(CodeAccessRequest, request, raw, firstSecret, "first")
		if err != nil {
			return nil, err
		}
		firstObservations <- observation
		return nil, nil
	})
	second := newUDPMock(t, secondSecret, func(request *Packet, raw []byte) ([]byte, error) {
		observation, err := observeRelayRequest(CodeAccessRequest, request, raw, secondSecret, "second")
		if err != nil {
			return nil, err
		}
		secondObservations <- observation
		return signedResponse(request, secondSecret, CodeAccessAccept, nil)
	})
	relay := newTestRelay(t, RelayConfig{
		Upstreams: []RelayUpstream{
			{Name: "first", Network: "udp4", Address: first.Addr(), Secret: firstSecret, Timeout: 30 * time.Millisecond, Retries: 1},
			{Name: "second", Network: "udp4", Address: second.Addr(), Secret: secondSecret},
		},
	})
	authenticator := rawAccessAuthenticator()
	var attributes Attributes
	attributes.AddString(AttrUserName, "alice")
	attributes.Add(AttrUserPassword, hiddenPassword(t, nasSecret, authenticator, "password"))
	raw := rawAccessRequest(t, 0x31, authenticator, attributes, nil)
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	result, err := relay.ForwardAccess(ctx, raw, nasSecret)
	if err != nil {
		t.Fatalf("ForwardAccess: %v", err)
	}
	if result.Upstream != "second" {
		t.Fatalf("Upstream = %q, want second", result.Upstream)
	}
	parseAndVerifyResponse(t, result.Raw, authenticator, nasSecret)
	nextRelayObservation(t, firstObservations)
	nextRelayObservation(t, firstObservations)
	nextRelayObservation(t, secondObservations)
	first.successes(t)
}

// successes is a helper that asserts no mock-side errors were reported. | successes 断言模拟端未报告错误。
func (m *udpMock) successes(t *testing.T) {
	t.Helper()
	select {
	case err := <-m.failures:
		t.Fatalf("udp mock failure: %v", err)
	default:
	}
}

func TestRelayRejectsProxyStateLoops(t *testing.T) {
	nasSecret := []byte("relay-nas-secret")
	upstreamSecret := []byte("relay-upstream-secret")
	observations := make(chan relayObservation, 4)
	upstream := newUDPMock(t, upstreamSecret, func(request *Packet, raw []byte) ([]byte, error) {
		observation, err := observeRelayRequest(CodeAccessRequest, request, raw, upstreamSecret, "primary")
		if err != nil {
			return nil, err
		}
		observations <- observation
		return signedResponse(request, upstreamSecret, CodeAccessAccept, nil)
	})
	relay := newTestRelay(t, RelayConfig{
		LoopToken: []byte("fixed-loop-token"),
		Upstreams: []RelayUpstream{{
			Network: "udp4",
			Address: upstream.Addr(),
			Secret:  upstreamSecret,
		}},
	})
	authenticator := rawAccessAuthenticator()
	var looped Attributes
	looped.AddString(AttrUserName, "alice")
	looped.Add(AttrProxyState, relay.proxyStateMarker(1))
	raw := rawAccessRequest(t, 0x41, authenticator, looped, nil)
	if _, err := relay.ForwardAccess(context.Background(), raw, nasSecret); !errors.Is(err, ErrRelayLoop) {
		t.Fatalf("loop error = %v, want ErrRelayLoop", err)
	}
	expectNoRelayObservation(t, observations)

	limited := newTestRelay(t, RelayConfig{
		MaxHops: 2,
		Upstreams: []RelayUpstream{{
			Network: "udp4",
			Address: upstream.Addr(),
			Secret:  upstreamSecret,
		}},
	})
	var hops Attributes
	hops.AddString(AttrUserName, "alice")
	hops.AddString(AttrProxyState, "one")
	hops.AddString(AttrProxyState, "two")
	raw = rawAccessRequest(t, 0x42, authenticator, hops, nil)
	if _, err := limited.ForwardAccess(context.Background(), raw, nasSecret); !errors.Is(err, ErrRelayLoop) {
		t.Fatalf("hop limit error = %v, want ErrRelayLoop", err)
	}
	expectNoRelayObservation(t, observations)
}

func TestRelayForwardsAccountingWithMessageAuthenticator(t *testing.T) {
	nasSecret := []byte("relay-nas-secret")
	upstreamSecret := []byte("relay-upstream-secret")
	observations := make(chan relayObservation, 4)
	upstream := newUDPMock(t, upstreamSecret, func(request *Packet, raw []byte) ([]byte, error) {
		observation, err := observeRelayRequest(CodeAccountingRequest, request, raw, upstreamSecret, "primary")
		if err != nil {
			return nil, err
		}
		observations <- observation
		attributes := echoProxyStates(request, "recorded")
		if observation.maPresent {
			return signedMessageResponse(request, upstreamSecret, CodeAccountingResponse, attributes)
		}
		return signedResponse(request, upstreamSecret, CodeAccountingResponse, attributes)
	})
	relay := newTestRelay(t, RelayConfig{
		Upstreams: []RelayUpstream{{
			Name:    "primary",
			Network: "udp4",
			Address: upstream.Addr(),
			Secret:  upstreamSecret,
		}},
	})
	var attributes Attributes
	attributes.AddUint32(AttrAcctStatusType, uint32(AcctStatusStart))
	attributes.AddString(AttrAcctSessionID, "sess-relay")
	attributes.AddString(AttrNASIdentifier, "nas-relay")
	attributes.AddString(AttrProxyState, "accounting-state")
	raw := accountingRequestWithMessageAuthenticator(t, nasSecret, 0x51, attributes)
	request, err := ParsePacket(raw)
	if err != nil {
		t.Fatalf("ParsePacket: %v", err)
	}

	result, err := relay.ForwardAccounting(context.Background(), raw, nasSecret)
	if err != nil {
		t.Fatalf("ForwardAccounting: %v", err)
	}
	response := parseAndVerifyResponse(t, result.Raw, request.Authenticator, nasSecret)
	if response.Code != CodeAccountingResponse {
		t.Fatalf("response code = %d, want Accounting-Response", response.Code)
	}
	if response.Identifier != 0x51 {
		t.Fatalf("response identifier = %d, want 81", response.Identifier)
	}
	states := response.Attributes.GetAll(AttrProxyState)
	if len(states) != 1 || string(states[0].Value) != "accounting-state" {
		t.Fatalf("downstream Proxy-State = %v", states)
	}
	present, valid, err := verifyMessageAuthenticatorRaw(result.Raw, nasSecret, request.Authenticator)
	if err != nil || !present || !valid {
		t.Fatalf("downstream Message-Authenticator present=%v valid=%v err=%v", present, valid, err)
	}
	observation := nextRelayObservation(t, observations)
	if !observation.acctValid {
		t.Fatal("relayed Accounting-Request authenticator is invalid")
	}
	if !observation.maPresent || !observation.maValid {
		t.Fatalf("relayed Accounting-Request Message-Authenticator present=%v valid=%v", observation.maPresent, observation.maValid)
	}
	if len(observation.proxyStates) != 2 || observation.proxyStates[0] != "accounting-state" {
		t.Fatalf("upstream Proxy-State = %v", observation.proxyStates)
	}

	rawWithoutMA := rawAccountingRequest(t, nasSecret, 0x52, attributes)
	requestWithoutMA, err := ParsePacket(rawWithoutMA)
	if err != nil {
		t.Fatalf("ParsePacket: %v", err)
	}
	result, err = relay.ForwardAccounting(context.Background(), rawWithoutMA, nasSecret)
	if err != nil {
		t.Fatalf("ForwardAccounting without Message-Authenticator: %v", err)
	}
	response = parseAndVerifyResponse(t, result.Raw, requestWithoutMA.Authenticator, nasSecret)
	if present, _, err := verifyMessageAuthenticatorRaw(result.Raw, nasSecret, requestWithoutMA.Authenticator); err != nil || present {
		t.Fatalf("downstream unrequested Message-Authenticator present=%v err=%v", present, err)
	}
	observation = nextRelayObservation(t, observations)
	if observation.maPresent {
		t.Fatal("relay added a Message-Authenticator to a request that had none")
	}
}

func TestRelayTranslatesMSMPPEKeys(t *testing.T) {
	nasSecret := []byte("relay-nas-secret")
	upstreamSecret := []byte("relay-upstream-secret")
	requestSendKey := bytes.Repeat([]byte{0x11}, 16)
	requestRecvKey := bytes.Repeat([]byte{0x22}, 16)
	responseSendKey := bytes.Repeat([]byte{0x33}, 16)
	responseRecvKey := bytes.Repeat([]byte{0x44}, 16)
	observations := make(chan relayObservation, 4)
	upstream := newUDPMock(t, upstreamSecret, func(request *Packet, raw []byte) ([]byte, error) {
		observation, err := observeRelayRequest(CodeAccessRequest, request, raw, upstreamSecret, "primary")
		if err != nil {
			return nil, err
		}
		observations <- observation
		sendValue, err := EncryptMSMPPEKey(upstreamSecret, request.Authenticator[:], responseSendKey)
		if err != nil {
			return nil, err
		}
		recvValue, err := EncryptMSMPPEKey(upstreamSecret, request.Authenticator[:], responseRecvKey)
		if err != nil {
			return nil, err
		}
		attributes := echoProxyStates(request, "")
		attributes = append(attributes, NewVendorAttribute(VendorMicrosoft, VendorMSMPPESendKey, sendValue))
		attributes = append(attributes, NewVendorAttribute(VendorMicrosoft, VendorMSMPPERecvKey, recvValue))
		return signedResponse(request, upstreamSecret, CodeAccessAccept, attributes)
	})
	relay := newTestRelay(t, RelayConfig{
		Upstreams: []RelayUpstream{{
			Network: "udp4",
			Address: upstream.Addr(),
			Secret:  upstreamSecret,
		}},
	})
	authenticator := rawAccessAuthenticator()
	sendValue, err := EncryptMSMPPEKey(nasSecret, authenticator[:], requestSendKey)
	if err != nil {
		t.Fatalf("EncryptMSMPPEKey send: %v", err)
	}
	recvValue, err := EncryptMSMPPEKey(nasSecret, authenticator[:], requestRecvKey)
	if err != nil {
		t.Fatalf("EncryptMSMPPEKey recv: %v", err)
	}
	var attributes Attributes
	attributes.AddString(AttrUserName, "alice")
	attributes = append(attributes, NewVendorAttribute(VendorMicrosoft, VendorMSMPPESendKey, sendValue))
	attributes = append(attributes, NewVendorAttribute(VendorMicrosoft, VendorMSMPPERecvKey, recvValue))
	raw := rawAccessRequest(t, 0x61, authenticator, attributes, nil)
	result, err := relay.ForwardAccess(context.Background(), raw, nasSecret)
	if err != nil {
		t.Fatalf("ForwardAccess: %v", err)
	}
	observation := nextRelayObservation(t, observations)
	if !bytes.Equal(observation.sendKey, requestSendKey) || !bytes.Equal(observation.recvKey, requestRecvKey) {
		t.Fatalf("upstream MPPE keys = %x / %x", observation.sendKey, observation.recvKey)
	}
	response := parseAndVerifyResponse(t, result.Raw, authenticator, nasSecret)
	sendAttributes := response.Attributes.VendorAll(VendorMicrosoft, VendorMSMPPESendKey)
	recvAttributes := response.Attributes.VendorAll(VendorMicrosoft, VendorMSMPPERecvKey)
	if len(sendAttributes) != 1 || len(recvAttributes) != 1 {
		t.Fatalf("response MPPE attributes = %d send / %d recv", len(sendAttributes), len(recvAttributes))
	}
	plainSend, err := DecryptMSMPPEKey(nasSecret, authenticator[:], sendAttributes[0].Value)
	if err != nil {
		t.Fatalf("DecryptMSMPPEKey send: %v", err)
	}
	plainRecv, err := DecryptMSMPPEKey(nasSecret, authenticator[:], recvAttributes[0].Value)
	if err != nil {
		t.Fatalf("DecryptMSMPPEKey recv: %v", err)
	}
	if !bytes.Equal(plainSend, responseSendKey) || !bytes.Equal(plainRecv, responseRecvKey) {
		t.Fatalf("downstream MPPE keys = %x / %x", plainSend, plainRecv)
	}
}

func TestRelayMaterializesCHAPChallenge(t *testing.T) {
	nasSecret := []byte("relay-nas-secret")
	upstreamSecret := []byte("relay-upstream-secret")
	observations := make(chan relayObservation, 4)
	upstream := newUDPMock(t, upstreamSecret, func(request *Packet, raw []byte) ([]byte, error) {
		observation, err := observeRelayRequest(CodeAccessRequest, request, raw, upstreamSecret, "primary")
		if err != nil {
			return nil, err
		}
		observations <- observation
		return signedResponse(request, upstreamSecret, CodeAccessAccept, nil)
	})
	relay := newTestRelay(t, RelayConfig{
		Upstreams: []RelayUpstream{{
			Network: "udp4",
			Address: upstream.Addr(),
			Secret:  upstreamSecret,
		}},
	})
	authenticator := rawAccessAuthenticator()
	var attributes Attributes
	attributes.AddString(AttrUserName, "alice")
	attributes.Add(AttrCHAPPassword, append([]byte{0x07}, bytes.Repeat([]byte{0xaa}, 16)...))
	raw := rawAccessRequest(t, 0x71, authenticator, attributes, nil)
	if _, err := relay.ForwardAccess(context.Background(), raw, nasSecret); err != nil {
		t.Fatalf("ForwardAccess: %v", err)
	}
	observation := nextRelayObservation(t, observations)
	if !bytes.Equal(observation.chapChall, authenticator[:]) {
		t.Fatalf("CHAP-Challenge = %x, want the original Request Authenticator %x", observation.chapChall, authenticator)
	}
	if _, ok := observation.packet.Attributes.Get(AttrCHAPChallenge); !ok {
		t.Fatal("relayed request lacks a materialized CHAP-Challenge")
	}
}

func TestRelayTCPUpstream(t *testing.T) {
	nasSecret := []byte("relay-nas-secret")
	upstreamSecret := []byte("relay-upstream-secret")
	observations := make(chan relayObservation, 4)
	upstream := newTCPMock(t, upstreamSecret, func(request *Packet, raw []byte) ([]byte, error) {
		observation, err := observeRelayRequest(CodeAccessRequest, request, raw, upstreamSecret, "tcp")
		if err != nil {
			return nil, err
		}
		observations <- observation
		return signedResponse(request, upstreamSecret, CodeAccessAccept, nil)
	})
	relay := newTestRelay(t, RelayConfig{
		Upstreams: []RelayUpstream{{
			Name:    "tcp",
			Network: "tcp4",
			Address: upstream.Addr(),
			Secret:  upstreamSecret,
		}},
	})
	authenticator := rawAccessAuthenticator()
	var attributes Attributes
	attributes.AddString(AttrUserName, "alice")
	raw := rawAccessRequest(t, 0x72, authenticator, attributes, nil)
	result, err := relay.ForwardAccess(context.Background(), raw, nasSecret)
	if err != nil {
		t.Fatalf("ForwardAccess over TCP: %v", err)
	}
	parseAndVerifyResponse(t, result.Raw, authenticator, nasSecret)
	nextRelayObservation(t, observations)
}

func TestRelayUnreachableAndClose(t *testing.T) {
	nasSecret := []byte("relay-nas-secret")
	conn, err := net.ListenPacket("udp4", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	closedAddress := conn.LocalAddr().String()
	_ = conn.Close()
	relay := newTestRelay(t, RelayConfig{
		Upstreams: []RelayUpstream{{
			Name:    "closed",
			Network: "udp4",
			Address: closedAddress,
			Secret:  []byte("relay-upstream-secret"),
			Timeout: 40 * time.Millisecond,
		}},
	})
	authenticator := rawAccessAuthenticator()
	var attributes Attributes
	attributes.AddString(AttrUserName, "alice")
	raw := rawAccessRequest(t, 0x73, authenticator, attributes, nil)
	if _, err := relay.ForwardAccess(context.Background(), raw, nasSecret); !errors.Is(err, ErrNoUpstream) {
		t.Fatalf("unreachable error = %v, want ErrNoUpstream", err)
	}
	if err := relay.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}
	if err := relay.Close(); err != nil {
		t.Fatalf("second Close: %v", err)
	}
	if _, err := relay.ForwardAccess(context.Background(), raw, nasSecret); !errors.Is(err, ErrClosed) {
		t.Fatalf("ForwardAccess after Close = %v, want ErrClosed", err)
	}
}

func TestRelayConfigValidation(t *testing.T) {
	secret := []byte("relay-upstream-secret")
	cases := []struct {
		name   string
		config RelayConfig
	}{
		{name: "no upstreams", config: RelayConfig{}},
		{name: "negative hops", config: RelayConfig{MaxHops: -1, Upstreams: []RelayUpstream{{Address: "127.0.0.1:1812", Secret: secret}}}},
		{name: "too many hops", config: RelayConfig{MaxHops: 256, Upstreams: []RelayUpstream{{Address: "127.0.0.1:1812", Secret: secret}}}},
		{name: "loop token too long", config: RelayConfig{LoopToken: make([]byte, MaxRelayLoopTokenLength+1), Upstreams: []RelayUpstream{{Address: "127.0.0.1:1812", Secret: secret}}}},
		{name: "bad network", config: RelayConfig{Upstreams: []RelayUpstream{{Network: "sctp", Address: "127.0.0.1:1812", Secret: secret}}}},
		{name: "missing address", config: RelayConfig{Upstreams: []RelayUpstream{{Network: "udp4", Secret: secret}}}},
		{name: "missing secret", config: RelayConfig{Upstreams: []RelayUpstream{{Network: "udp4", Address: "127.0.0.1:1812"}}}},
	}
	for _, testCase := range cases {
		t.Run(testCase.name, func(t *testing.T) {
			if _, err := NewRelay(testCase.config); !errors.Is(err, ErrInvalidConfig) {
				t.Fatalf("error = %v, want ErrInvalidConfig", err)
			}
		})
	}
}

func TestRelayBadDownstreamAuthenticator(t *testing.T) {
	nasSecret := []byte("relay-nas-secret")
	upstreamSecret := []byte("relay-upstream-secret")
	observations := make(chan relayObservation, 4)
	upstream := newUDPMock(t, upstreamSecret, func(request *Packet, raw []byte) ([]byte, error) {
		observation, err := observeRelayRequest(CodeAccessRequest, request, raw, upstreamSecret, "primary")
		if err != nil {
			return nil, err
		}
		observations <- observation
		return signedResponse(request, upstreamSecret, CodeAccessAccept, nil)
	})
	relay := newTestRelay(t, RelayConfig{
		Upstreams: []RelayUpstream{{
			Network: "udp4",
			Address: upstream.Addr(),
			Secret:  upstreamSecret,
		}},
	})
	authenticator := rawAccessAuthenticator()
	var attributes Attributes
	attributes.AddString(AttrUserName, "alice")
	raw := rawAccessRequest(t, 0x74, authenticator, attributes, []byte("wrong-nas-secret"))
	if _, err := relay.ForwardAccess(context.Background(), raw, nasSecret); !errors.Is(err, ErrMessageAuthenticator) {
		t.Fatalf("invalid Message-Authenticator error = %v, want ErrMessageAuthenticator", err)
	}
	expectNoRelayObservation(t, observations)

	raw = rawAccessRequest(t, 0x75, authenticator, attributes, nil)
	relay.requireMA = true
	if _, err := relay.ForwardAccess(context.Background(), raw, nasSecret); !errors.Is(err, ErrMessageAuthenticator) {
		t.Fatalf("missing required Message-Authenticator error = %v, want ErrMessageAuthenticator", err)
	}
	expectNoRelayObservation(t, observations)
}

func TestRelayConcurrentAccess(t *testing.T) {
	nasSecret := []byte("relay-nas-secret")
	upstreamSecret := []byte("relay-upstream-secret")
	observations := make(chan relayObservation, 64)
	upstream := newUDPMock(t, upstreamSecret, func(request *Packet, raw []byte) ([]byte, error) {
		observation, err := observeRelayRequest(CodeAccessRequest, request, raw, upstreamSecret, "primary")
		if err != nil {
			return nil, err
		}
		observations <- observation
		attributes := echoProxyStates(request, "")
		return signedMessageResponse(request, upstreamSecret, CodeAccessAccept, attributes)
	})
	relay := newTestRelay(t, RelayConfig{
		Upstreams: []RelayUpstream{{
			Network: "udp4",
			Address: upstream.Addr(),
			Secret:  upstreamSecret,
		}},
	})
	const requests = 8
	var wg sync.WaitGroup
	errsChannel := make(chan error, requests)
	for index := 0; index < requests; index++ {
		wg.Add(1)
		go func(index int) {
			defer wg.Done()
			authenticator := rawAccessAuthenticator()
			authenticator[15] = byte(index)
			var attributes Attributes
			attributes.AddString(AttrUserName, "user")
			raw := rawAccessRequest(t, uint8(0x80+index), authenticator, attributes, nasSecret)
			result, err := relay.ForwardAccess(context.Background(), raw, nasSecret)
			if err != nil {
				errsChannel <- err
				return
			}
			if _, err := ParsePacket(result.Raw); err != nil {
				errsChannel <- err
				return
			}
			if err := verifyResponseAuthenticator(result.Raw, nasSecret, authenticator); err != nil {
				errsChannel <- err
			}
		}(index)
	}
	wg.Wait()
	close(errsChannel)
	for err := range errsChannel {
		t.Errorf("concurrent ForwardAccess: %v", err)
	}
	for index := 0; index < requests; index++ {
		observation := nextRelayObservation(t, observations)
		if !observation.maPresent || !observation.maValid {
			t.Errorf("upstream request %d Message-Authenticator present=%v valid=%v", index, observation.maPresent, observation.maValid)
		}
	}
}

func TestRelayForwardAccessRejectsWrongCode(t *testing.T) {
	relay := newTestRelay(t, RelayConfig{
		Upstreams: []RelayUpstream{{
			Network: "udp4",
			Address: "127.0.0.1:1812",
			Secret:  []byte("relay-upstream-secret"),
		}},
	})
	var attributes Attributes
	attributes.AddUint32(AttrAcctStatusType, uint32(AcctStatusStart))
	attributes.AddString(AttrAcctSessionID, "sess")
	attributes.AddString(AttrNASIdentifier, "nas")
	raw := rawAccountingRequest(t, []byte("relay-nas-secret"), 1, attributes)
	if _, err := relay.ForwardAccess(context.Background(), raw, []byte("relay-nas-secret")); !errors.Is(err, ErrUnexpectedCode) {
		t.Fatalf("wrong code error = %v, want ErrUnexpectedCode", err)
	}
}
