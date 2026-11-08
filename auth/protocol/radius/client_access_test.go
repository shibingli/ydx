package radius

import (
	"bytes"
	"context"
	"errors"
	"net"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

func TestAccessAcceptPAP(t *testing.T) {
	secret := []byte("testing-secret")
	responseAttributes := Attributes{
		NewAttribute(AttrReplyMessage, []byte("welcome")),
		NewAttribute(AttrSessionTimeout, []byte{0, 0, 0, 60}),
		NewAttribute(AttrIdleTimeout, []byte{0, 0, 0, 10}),
		NewAttribute(AttrFilterID, []byte("corp-acl")),
		NewAttribute(AttrFramedIPAddress, []byte{203, 0, 113, 9}),
		NewAttribute(AttrTunnelType, []byte{1, 0, 0, 0, 13}),
		NewAttribute(AttrTunnelMediumType, []byte{1, 0, 0, 0, 1}),
		NewAttribute(AttrTunnelPrivateGroupID, []byte{1, 'v', 'l', 'a', 'n', '7'}),
		NewAttribute(AttrClass, []byte("class-1")),
	}
	server := newUDPMock(t, secret, func(request *Packet, raw []byte) ([]byte, error) {
		return signedResponse(request, secret, CodeAccessAccept, responseAttributes)
	})
	client := newTestClient(t, ClientConfig{
		Address:       server.Addr(),
		Secret:        secret,
		NASIdentifier: "nas-1",
		NASIPAddress:  net.IPv4(192, 0, 2, 20),
	})

	response, err := client.AccessRequest(context.Background(), &AccessRequest{
		UserName:         "alice",
		Password:         "s3cret",
		ServiceType:      ServiceTypeLogin,
		NASPort:          7,
		NASPortType:      NASPortTypeEthernet,
		CallingStationID: "00-11-22-33-44-55",
	})
	if err != nil {
		t.Fatalf("AccessRequest: %v", err)
	}
	if !response.Accepted() || response.Rejected() || response.Challenged() {
		t.Fatalf("unexpected code %d", response.Code)
	}
	if response.ReplyMessage != "welcome" || len(response.ReplyMessages) != 1 {
		t.Fatalf("ReplyMessage = %q, %v", response.ReplyMessage, response.ReplyMessages)
	}
	if response.SessionTimeout != 60 || response.IdleTimeout != 10 {
		t.Fatalf("timeouts = %d, %d", response.SessionTimeout, response.IdleTimeout)
	}
	if response.FilterID != "corp-acl" {
		t.Fatalf("FilterID = %q", response.FilterID)
	}
	if !response.FramedIPAddress.Equal(net.IPv4(203, 0, 113, 9)) {
		t.Fatalf("FramedIPAddress = %v", response.FramedIPAddress)
	}
	if len(response.TunnelTypes) != 1 || response.TunnelTypes[0] != TunnelTypeVLAN {
		t.Fatalf("TunnelTypes = %v", response.TunnelTypes)
	}
	if len(response.TunnelMediumTypes) != 1 || response.TunnelMediumTypes[0] != TunnelMediumIPv4 {
		t.Fatalf("TunnelMediumTypes = %v", response.TunnelMediumTypes)
	}
	if len(response.TunnelPrivateGroupIDs) != 1 || response.TunnelPrivateGroupIDs[0] != "vlan7" {
		t.Fatalf("TunnelPrivateGroupIDs = %v", response.TunnelPrivateGroupIDs)
	}
	if !bytes.Equal(response.State, nil) || !bytes.Equal(response.Class, []byte("class-1")) {
		t.Fatalf("State/Class = %x/%x", response.State, response.Class)
	}

	request := server.nextRequest(t)
	assertStringAttribute(t, request.packet.Attributes, AttrUserName, "alice")
	assertStringAttribute(t, request.packet.Attributes, AttrNASIdentifier, "nas-1")
	assertStringAttribute(t, request.packet.Attributes, AttrCallingStationID, "00-11-22-33-44-55")
	assertUint32Attribute(t, request.packet.Attributes, AttrNASPort, 7)
	assertUint32Attribute(t, request.packet.Attributes, AttrServiceType, uint32(ServiceTypeLogin))
	assertUint32Attribute(t, request.packet.Attributes, AttrNASPortType, uint32(NASPortTypeEthernet))
	assertIPAttribute(t, request.packet.Attributes, AttrNASIPAddress, net.IPv4(192, 0, 2, 20))
	password, ok := request.packet.Attributes.Get(AttrUserPassword)
	if !ok {
		t.Fatal("User-Password missing")
	}
	plaintext, err := DecryptUserPassword(secret, request.packet.Authenticator[:], password.Value)
	if err != nil {
		t.Fatalf("DecryptUserPassword: %v", err)
	}
	if string(plaintext) != "s3cret" {
		t.Fatalf("decrypted password = %q", plaintext)
	}
}

func TestAccessReject(t *testing.T) {
	secret := []byte("testing-secret")
	server := newUDPMock(t, secret, func(request *Packet, raw []byte) ([]byte, error) {
		return signedResponse(request, secret, CodeAccessReject, Attributes{
			NewAttribute(AttrReplyMessage, []byte("denied")),
		})
	})
	client := newTestClient(t, ClientConfig{Address: server.Addr(), Secret: secret})
	response, err := client.AccessRequest(context.Background(), &AccessRequest{UserName: "alice", Password: "wrong"})
	if err != nil {
		t.Fatalf("AccessRequest: %v", err)
	}
	if !response.Rejected() || response.Accepted() {
		t.Fatalf("unexpected code %d", response.Code)
	}
	if response.ReplyMessage != "denied" {
		t.Fatalf("ReplyMessage = %q", response.ReplyMessage)
	}
}

func TestAccessChallenge(t *testing.T) {
	secret := []byte("testing-secret")
	state := []byte("challenge-state")
	server := newUDPMock(t, secret, func(request *Packet, raw []byte) ([]byte, error) {
		return signedResponse(request, secret, CodeAccessChallenge, Attributes{
			NewAttribute(AttrState, state),
			NewAttribute(AttrReplyMessage, []byte("continue")),
		})
	})
	client := newTestClient(t, ClientConfig{Address: server.Addr(), Secret: secret})
	response, err := client.AccessRequest(context.Background(), &AccessRequest{UserName: "alice", Method: AuthNone})
	if err != nil {
		t.Fatalf("AccessRequest: %v", err)
	}
	if !response.Challenged() {
		t.Fatalf("unexpected code %d", response.Code)
	}
	if !bytes.Equal(response.State, state) {
		t.Fatalf("State = %q, want %q", response.State, state)
	}
}

func TestAccessCHAP(t *testing.T) {
	secret := []byte("testing-secret")
	cases := []struct {
		name       string
		challenge  []byte
		identifier uint8
	}{
		{name: "request authenticator challenge"},
		{name: "explicit challenge", challenge: []byte("explicit-challenge"), identifier: 0x33},
	}
	for _, testCase := range cases {
		t.Run(testCase.name, func(t *testing.T) {
			server := newUDPMock(t, secret, func(request *Packet, raw []byte) ([]byte, error) {
				return signedResponse(request, secret, CodeAccessAccept, nil)
			})
			client := newTestClient(t, ClientConfig{Address: server.Addr(), Secret: secret})
			response, err := client.AccessRequest(context.Background(), &AccessRequest{
				UserName:       "alice",
				Password:       "chap-secret",
				Method:         AuthCHAP,
				CHAPChallenge:  testCase.challenge,
				CHAPIdentifier: testCase.identifier,
			})
			if err != nil {
				t.Fatalf("AccessRequest: %v", err)
			}
			if !response.Accepted() {
				t.Fatalf("unexpected code %d", response.Code)
			}
			request := server.nextRequest(t)
			chapPassword, ok := request.packet.Attributes.Get(AttrCHAPPassword)
			if !ok || len(chapPassword.Value) != 17 {
				t.Fatalf("CHAP-Password = %x", chapPassword.Value)
			}
			identifier := chapPassword.Value[0]
			expectedIdentifier := testCase.identifier
			if expectedIdentifier == 0 {
				expectedIdentifier = request.packet.Identifier
			}
			if identifier != expectedIdentifier {
				t.Fatalf("CHAP identifier = %d, want %d", identifier, expectedIdentifier)
			}
			challenge := testCase.challenge
			if len(challenge) == 0 {
				challenge = request.packet.Authenticator[:]
			}
			if !VerifyCHAPResponse(identifier, []byte("chap-secret"), challenge, chapPassword.Value[1:]) {
				t.Fatal("CHAP-Password does not verify")
			}
			if len(testCase.challenge) != 0 {
				explicit, ok := request.packet.Attributes.Get(AttrCHAPChallenge)
				if !ok || !bytes.Equal(explicit.Value, testCase.challenge) {
					t.Fatalf("CHAP-Challenge = %x, want %x", explicit.Value, testCase.challenge)
				}
			}
		})
	}
}

func TestAccessRetransmissionRotatesIdentifiers(t *testing.T) {
	secret := []byte("testing-secret")
	var attempts atomic.Int32
	server := newUDPMock(t, secret, func(request *Packet, raw []byte) ([]byte, error) {
		if attempts.Add(1) == 1 {
			return nil, nil
		}
		return signedResponse(request, secret, CodeAccessAccept, nil)
	})
	client := newTestClient(t, ClientConfig{
		Address: server.Addr(),
		Secret:  secret,
		Timeout: 100 * time.Millisecond,
		Retries: 1,
	})
	start := time.Now()
	response, err := client.AccessRequest(context.Background(), &AccessRequest{UserName: "alice", Password: "s3cret"})
	elapsed := time.Since(start)
	if err != nil {
		t.Fatalf("AccessRequest: %v", err)
	}
	if !response.Accepted() {
		t.Fatalf("unexpected code %d", response.Code)
	}
	if elapsed < 80*time.Millisecond {
		t.Fatalf("retransmission returned after only %v", elapsed)
	}
	first := server.nextRequest(t)
	second := server.nextRequest(t)
	if first.packet.Identifier == second.packet.Identifier {
		t.Fatalf("retransmission reused identifier %d", first.packet.Identifier)
	}
	if first.packet.Authenticator == second.packet.Authenticator {
		t.Fatal("retransmission reused the Request Authenticator")
	}
}

func TestAccessDiscardsBadResponseAuthenticator(t *testing.T) {
	secret := []byte("testing-secret")
	t.Run("bad then good", func(t *testing.T) {
		server := newScriptedUDPServer(t, func(request *Packet) ([][]byte, error) {
			bad, err := signedResponse(request, []byte("other-secret"), CodeAccessAccept, nil)
			if err != nil {
				return nil, err
			}
			good, err := signedResponse(request, secret, CodeAccessAccept, nil)
			if err != nil {
				return nil, err
			}
			return [][]byte{bad, good}, nil
		})
		client := newTestClient(t, ClientConfig{
			Address: server.LocalAddr().String(),
			Secret:  secret,
			Timeout: 500 * time.Millisecond,
		})
		response, err := client.AccessRequest(context.Background(), &AccessRequest{UserName: "alice", Password: "s3cret"})
		if err != nil {
			t.Fatalf("AccessRequest: %v", err)
		}
		if !response.Accepted() {
			t.Fatalf("unexpected code %d", response.Code)
		}
	})
	t.Run("bad only times out", func(t *testing.T) {
		server := newUDPMock(t, secret, func(request *Packet, raw []byte) ([]byte, error) {
			return signedResponse(request, []byte("other-secret"), CodeAccessAccept, nil)
		})
		client := newTestClient(t, ClientConfig{
			Address: server.Addr(),
			Secret:  secret,
			Timeout: 80 * time.Millisecond,
			Retries: 1,
		})
		start := time.Now()
		_, err := client.AccessRequest(context.Background(), &AccessRequest{UserName: "alice", Password: "s3cret"})
		if !errors.Is(err, ErrTimeout) {
			t.Fatalf("error = %v, want ErrTimeout", err)
		}
		if elapsed := time.Since(start); elapsed < 100*time.Millisecond {
			t.Fatalf("bad response failed the exchange after only %v", elapsed)
		}
		if strings.Contains(err.Error(), string(secret)) || strings.Contains(err.Error(), "s3cret") {
			t.Fatalf("error leaks a secret: %v", err)
		}
	})
}

func TestAccessRejectsUnexpectedCode(t *testing.T) {
	secret := []byte("testing-secret")
	server := newUDPMock(t, secret, func(request *Packet, raw []byte) ([]byte, error) {
		return signedResponse(request, secret, CodeAccountingResponse, nil)
	})
	client := newTestClient(t, ClientConfig{Address: server.Addr(), Secret: secret})
	if _, err := client.AccessRequest(context.Background(), &AccessRequest{UserName: "alice"}); !errors.Is(err, ErrUnexpectedCode) {
		t.Fatalf("error = %v, want ErrUnexpectedCode", err)
	}
}

func TestAccessRejectsMalformedResponse(t *testing.T) {
	secret := []byte("testing-secret")
	server := newUDPMock(t, secret, func(request *Packet, raw []byte) ([]byte, error) {
		malformed := make([]byte, 10)
		malformed[0] = byte(CodeAccessAccept)
		malformed[1] = request.Identifier
		return malformed, nil
	})
	client := newTestClient(t, ClientConfig{Address: server.Addr(), Secret: secret})
	if _, err := client.AccessRequest(context.Background(), &AccessRequest{UserName: "alice"}); !errors.Is(err, ErrInvalidResponse) {
		t.Fatalf("error = %v, want ErrInvalidResponse", err)
	}
}

func TestAccessEAPMessageAuthenticator(t *testing.T) {
	secret := []byte("testing-secret")
	responseEAP := []byte{2, 1, 0, 5, 1}
	server := newUDPMock(t, secret, func(request *Packet, raw []byte) ([]byte, error) {
		return signedMessageResponse(request, secret, CodeAccessAccept, Attributes{
			NewAttribute(AttrEAPMessage, responseEAP),
		})
	})
	client := newTestClient(t, ClientConfig{Address: server.Addr(), Secret: secret})
	response, err := client.AccessRequest(context.Background(), &AccessRequest{
		UserName:    "alice",
		Method:      AuthEAP,
		EAPMessages: [][]byte{{2, 1, 0, 5}},
	})
	if err != nil {
		t.Fatalf("AccessRequest: %v", err)
	}
	if !response.Accepted() || len(response.EAPMessages) != 1 || !bytes.Equal(response.EAPMessages[0], responseEAP) {
		t.Fatalf("unexpected response: %+v", response)
	}
	request := server.nextRequest(t)
	messageAuthenticator, ok := request.packet.Attributes.Get(AttrMessageAuthenticator)
	if !ok {
		t.Fatal("request lacks Message-Authenticator")
	}
	present, valid, err := verifyMessageAuthenticatorRaw(request.raw, secret, request.packet.Authenticator)
	if err != nil || !present || !valid {
		t.Fatalf("request Message-Authenticator = %v, %v, %v", present, valid, err)
	}
	if bytes.Equal(messageAuthenticator.Value, make([]byte, 16)) {
		t.Fatal("request Message-Authenticator was not signed")
	}
	eapMessages := request.packet.Attributes.GetAll(AttrEAPMessage)
	if len(eapMessages) != 1 || !bytes.Equal(eapMessages[0].Value, []byte{2, 1, 0, 5}) {
		t.Fatalf("request EAP-Message = %+v", eapMessages)
	}
}

func TestAccessRequiresMessageAuthenticatorInResponse(t *testing.T) {
	secret := []byte("testing-secret")
	t.Run("missing", func(t *testing.T) {
		server := newUDPMock(t, secret, func(request *Packet, raw []byte) ([]byte, error) {
			return signedResponse(request, secret, CodeAccessAccept, nil)
		})
		client := newTestClient(t, ClientConfig{Address: server.Addr(), Secret: secret})
		_, err := client.AccessRequest(context.Background(), &AccessRequest{
			Method:      AuthEAP,
			EAPMessages: [][]byte{{1}},
		})
		if !errors.Is(err, ErrMessageAuthenticator) {
			t.Fatalf("error = %v, want ErrMessageAuthenticator", err)
		}
	})
	t.Run("invalid", func(t *testing.T) {
		server := newUDPMock(t, secret, func(request *Packet, raw []byte) ([]byte, error) {
			return signedResponse(request, secret, CodeAccessAccept, Attributes{
				NewAttribute(AttrMessageAuthenticator, make([]byte, 16)),
			})
		})
		client := newTestClient(t, ClientConfig{Address: server.Addr(), Secret: secret})
		_, err := client.AccessRequest(context.Background(), &AccessRequest{
			Method:      AuthEAP,
			EAPMessages: [][]byte{{1}},
		})
		if !errors.Is(err, ErrMessageAuthenticator) {
			t.Fatalf("error = %v, want ErrMessageAuthenticator", err)
		}
	})
	t.Run("extra EAP attribute", func(t *testing.T) {
		server := newUDPMock(t, secret, func(request *Packet, raw []byte) ([]byte, error) {
			return signedResponse(request, secret, CodeAccessAccept, nil)
		})
		client := newTestClient(t, ClientConfig{Address: server.Addr(), Secret: secret})
		_, err := client.AccessRequest(context.Background(), &AccessRequest{
			UserName:   "alice",
			Method:     AuthNone,
			Attributes: Attributes{NewAttribute(AttrEAPMessage, []byte{1})},
		})
		if !errors.Is(err, ErrMessageAuthenticator) {
			t.Fatalf("error = %v, want ErrMessageAuthenticator", err)
		}
		request := server.nextRequest(t)
		present, valid, err := verifyMessageAuthenticatorRaw(request.raw, secret, request.packet.Authenticator)
		if err != nil || !present || !valid {
			t.Fatalf("request Message-Authenticator = %v, %v, %v", present, valid, err)
		}
	})
	t.Run("non-EAP include message authenticator", func(t *testing.T) {
		server := newUDPMock(t, secret, func(request *Packet, raw []byte) ([]byte, error) {
			return signedResponse(request, secret, CodeAccessAccept, nil)
		})
		client := newTestClient(t, ClientConfig{Address: server.Addr(), Secret: secret})
		_, err := client.AccessRequest(context.Background(), &AccessRequest{
			UserName:                    "alice",
			Method:                      AuthPAP,
			Password:                    "secret",
			IncludeMessageAuthenticator: true,
		})
		if !errors.Is(err, ErrMessageAuthenticator) {
			t.Fatalf("error = %v, want ErrMessageAuthenticator", err)
		}
		request := server.nextRequest(t)
		present, valid, err := verifyMessageAuthenticatorRaw(request.raw, secret, request.packet.Authenticator)
		if err != nil || !present || !valid {
			t.Fatalf("request Message-Authenticator = %v, %v, %v", present, valid, err)
		}
	})
	t.Run("non-EAP signed response", func(t *testing.T) {
		server := newUDPMock(t, secret, func(request *Packet, raw []byte) ([]byte, error) {
			return signedMessageResponse(request, secret, CodeAccessAccept, nil)
		})
		client := newTestClient(t, ClientConfig{Address: server.Addr(), Secret: secret})
		response, err := client.AccessRequest(context.Background(), &AccessRequest{
			UserName:                    "alice",
			Method:                      AuthPAP,
			Password:                    "secret",
			IncludeMessageAuthenticator: true,
		})
		if err != nil || !response.Accepted() {
			t.Fatalf("AccessRequest = %+v, %v", response, err)
		}
	})
}

func TestAccessMSCHAPv2ChallengeExchange(t *testing.T) {
	secret := []byte("testing-secret")
	serverChallenge := decodeHex(t, "5b5d7c7d7b3f2f3e3c2c602132262628")
	state := []byte("mschap-state")
	var attempts atomic.Int32
	server := newUDPMock(t, secret, func(request *Packet, raw []byte) ([]byte, error) {
		if attempts.Add(1) == 1 {
			return signedResponse(request, secret, CodeAccessChallenge, Attributes{
				NewAttribute(AttrState, state),
				NewVendorAttribute(VendorMicrosoft, VendorMSCHAPChallenge, serverChallenge),
			})
		}
		return signedResponse(request, secret, CodeAccessAccept, Attributes{
			NewVendorAttribute(VendorMicrosoft, VendorMSCHAP2Success, []byte("S=success")),
		})
	})
	client := newTestClient(t, ClientConfig{Address: server.Addr(), Secret: secret})
	response, err := client.AuthenticateMSCHAPv2(context.Background(), "User", "clientPass", nil)
	if err != nil {
		t.Fatalf("AuthenticateMSCHAPv2: %v", err)
	}
	if !response.Accepted() || string(response.MSCHAPv2Success) != "S=success" {
		t.Fatalf("unexpected response: %+v", response)
	}

	probe := server.nextRequest(t)
	if _, ok := probe.packet.Attributes.Get(AttrUserPassword); ok {
		t.Fatal("probe carried a User-Password")
	}
	if _, ok := probe.packet.Attributes.Vendor(VendorMicrosoft, VendorMSCHAP2Response); ok {
		t.Fatal("probe carried an MS-CHAP2-Response")
	}
	assertStringAttribute(t, probe.packet.Attributes, AttrUserName, "User")

	second := server.nextRequest(t)
	stateAttribute, ok := second.packet.Attributes.Get(AttrState)
	if !ok || !bytes.Equal(stateAttribute.Value, state) {
		t.Fatalf("State = %x, want %x", stateAttribute.Value, state)
	}
	challenge, ok := second.packet.Attributes.Vendor(VendorMicrosoft, VendorMSCHAPChallenge)
	if !ok || !bytes.Equal(challenge.Value, serverChallenge) {
		t.Fatalf("MS-CHAP-Challenge = %x", challenge.Value)
	}
	mschapResponse, ok := second.packet.Attributes.Vendor(VendorMicrosoft, VendorMSCHAP2Response)
	if !ok || len(mschapResponse.Value) != msCHAPv2ResponseLength {
		t.Fatalf("MS-CHAP2-Response = %x", mschapResponse.Value)
	}
	valid, err := VerifyMSCHAPv2Response("User", "clientPass", serverChallenge, mschapResponse.Value)
	if err != nil || !valid {
		t.Fatalf("MS-CHAP2-Response does not verify: %v, %v", valid, err)
	}
}

func TestAccessInvalidRequests(t *testing.T) {
	secret := []byte("testing-secret")
	client := newTestClient(t, ClientConfig{Address: "127.0.0.1:1", Secret: secret})
	cases := []struct {
		name    string
		request *AccessRequest
	}{
		{name: "nil", request: nil},
		{name: "pap without user", request: &AccessRequest{Password: "x"}},
		{name: "chap without user", request: &AccessRequest{Method: AuthCHAP}},
		{name: "mschap without credentials", request: &AccessRequest{Method: AuthMSCHAPv2, UserName: "alice"}},
		{name: "mschap short challenge", request: &AccessRequest{Method: AuthMSCHAPv2, UserName: "alice", MSCHAPv2: &MSCHAPv2Credentials{Password: "x", Challenge: make([]byte, 8)}}},
		{name: "mschap precomputed response without challenge", request: &AccessRequest{Method: AuthMSCHAPv2, UserName: "alice", MSCHAPv2: &MSCHAPv2Credentials{Response: make([]byte, msCHAPv2ResponseLength)}}},
		{name: "eap without messages", request: &AccessRequest{Method: AuthEAP, UserName: "alice"}},
		{name: "eap empty message", request: &AccessRequest{Method: AuthEAP, EAPMessages: [][]byte{{}}}},
		{name: "pap with eap attribute", request: &AccessRequest{UserName: "alice", Attributes: Attributes{NewAttribute(AttrEAPMessage, []byte{1})}}},
		{name: "unknown method", request: &AccessRequest{Method: AuthMethod(99), UserName: "alice"}},
		{name: "invalid nas address", request: &AccessRequest{UserName: "alice", NASIPAddress: net.ParseIP("2001:db8::1")}},
	}
	for _, testCase := range cases {
		t.Run(testCase.name, func(t *testing.T) {
			if _, err := client.AccessRequest(context.Background(), testCase.request); !errors.Is(err, ErrInvalidRequest) {
				t.Fatalf("error = %v, want ErrInvalidRequest", err)
			}
		})
	}
}

func TestClientCloseZeroizesSecret(t *testing.T) {
	secret := []byte("testing-secret")
	client := newTestClient(t, ClientConfig{Address: "127.0.0.1:1", Secret: secret})
	if len(client.cfg.Secret) != 0 {
		t.Fatalf("client configuration retains %d secret octets", len(client.cfg.Secret))
	}
	if !bytes.Equal(client.secret, secret) {
		t.Fatalf("secret copy = %x, want %x", client.secret, secret)
	}
	if err := client.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}
	for i, value := range client.secret {
		if value != 0 {
			t.Fatalf("secret octet %d = %d after Close", i, value)
		}
	}
	if _, err := client.AccessRequest(context.Background(), &AccessRequest{UserName: "alice"}); !errors.Is(err, ErrClosed) {
		t.Fatalf("error after Close = %v, want ErrClosed", err)
	}
}

func assertStringAttribute(t *testing.T, attributes Attributes, attributeType AttributeType, expected string) {
	t.Helper()
	attribute, ok := attributes.Get(attributeType)
	if !ok || attribute.String() != expected {
		t.Fatalf("attribute %d = %q, %v, want %q", attributeType, attribute.String(), ok, expected)
	}
}

func assertUint32Attribute(t *testing.T, attributes Attributes, attributeType AttributeType, expected uint32) {
	t.Helper()
	value, ok := attributes.Uint32(attributeType)
	if !ok || value != expected {
		t.Fatalf("attribute %d = %d, %v, want %d", attributeType, value, ok, expected)
	}
}

func assertIPAttribute(t *testing.T, attributes Attributes, attributeType AttributeType, expected net.IP) {
	t.Helper()
	value, ok := attributes.IP(attributeType)
	if !ok || !value.Equal(expected) {
		t.Fatalf("attribute %d = %v, %v, want %v", attributeType, value, ok, expected)
	}
}
