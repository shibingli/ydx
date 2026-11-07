package radius

import (
	"context"
	"errors"
	"net"
	"testing"
	"time"
)

func TestAccountingStartAndStop(t *testing.T) {
	secret := []byte("testing-secret")
	server := newUDPMock(t, secret, func(request *Packet, raw []byte) ([]byte, error) {
		return signedResponse(request, secret, CodeAccountingResponse, Attributes{
			NewAttribute(AttrReplyMessage, []byte("recorded")),
		})
	})
	client := newTestClient(t, ClientConfig{
		Address:       server.Addr(),
		Secret:        secret,
		NASIdentifier: "nas-1",
		NASIPAddress:  net.IPv4(192, 0, 2, 30),
	})
	eventTime := time.Unix(1_700_000_000, 0).UTC()

	startResponse, err := client.AccountRequest(context.Background(), &AccountingRequest{
		StatusType:     AcctStatusStart,
		SessionID:      "session-1",
		UserName:       "alice",
		NASPort:        7,
		NASPortType:    NASPortTypeEthernet,
		Authentic:      AcctAuthenticRADIUS,
		InputOctets:    100,
		OutputOctets:   200,
		InputPackets:   1,
		OutputPackets:  2,
		EventTimestamp: eventTime,
	})
	if err != nil {
		t.Fatalf("AccountRequest start: %v", err)
	}
	if startResponse.Code != CodeAccountingResponse || startResponse.ReplyMessage != "recorded" {
		t.Fatalf("unexpected accounting response: %+v", startResponse)
	}

	start := server.nextRequest(t)
	if start.packet.Code != CodeAccountingRequest {
		t.Fatalf("request code = %d", start.packet.Code)
	}
	if err := verifyAccountingRequestAuthenticator(start.raw, secret); err != nil {
		t.Fatalf("accounting authenticator: %v", err)
	}
	assertUint32Attribute(t, start.packet.Attributes, AttrAcctStatusType, uint32(AcctStatusStart))
	assertUint32Attribute(t, start.packet.Attributes, AttrAcctInputOctets, 100)
	assertUint32Attribute(t, start.packet.Attributes, AttrAcctOutputOctets, 200)
	assertUint32Attribute(t, start.packet.Attributes, AttrAcctInputPackets, 1)
	assertUint32Attribute(t, start.packet.Attributes, AttrAcctOutputPackets, 2)
	assertUint32Attribute(t, start.packet.Attributes, AttrAcctSessionTime, 0)
	assertUint32Attribute(t, start.packet.Attributes, AttrAcctAuthentic, uint32(AcctAuthenticRADIUS))
	assertUint32Attribute(t, start.packet.Attributes, AttrNASPort, 7)
	assertUint32Attribute(t, start.packet.Attributes, AttrNASPortType, uint32(NASPortTypeEthernet))
	assertUint32Attribute(t, start.packet.Attributes, AttrEventTimestamp, uint32(eventTime.Unix()))
	assertStringAttribute(t, start.packet.Attributes, AttrAcctSessionID, "session-1")
	assertStringAttribute(t, start.packet.Attributes, AttrUserName, "alice")
	assertStringAttribute(t, start.packet.Attributes, AttrNASIdentifier, "nas-1")
	assertIPAttribute(t, start.packet.Attributes, AttrNASIPAddress, net.IPv4(192, 0, 2, 30))
	if _, ok := start.packet.Attributes.Uint32(AttrAcctDelayTime); !ok {
		t.Fatal("Acct-Delay-Time missing")
	}

	stopResponse, err := client.AccountRequest(context.Background(), &AccountingRequest{
		StatusType:     AcctStatusStop,
		SessionID:      "session-1",
		UserName:       "alice",
		InputOctets:    4096,
		OutputOctets:   8192,
		InputPackets:   10,
		OutputPackets:  20,
		SessionTime:    300,
		TerminateCause: AcctTerminateUserRequest,
		EventTimestamp: eventTime.Add(5 * time.Minute),
		Class:          []byte("class-1"),
	})
	if err != nil {
		t.Fatalf("AccountRequest stop: %v", err)
	}
	if stopResponse.Code != CodeAccountingResponse {
		t.Fatalf("unexpected accounting response: %+v", stopResponse)
	}
	stop := server.nextRequest(t)
	if err := verifyAccountingRequestAuthenticator(stop.raw, secret); err != nil {
		t.Fatalf("stop accounting authenticator: %v", err)
	}
	assertUint32Attribute(t, stop.packet.Attributes, AttrAcctStatusType, uint32(AcctStatusStop))
	assertUint32Attribute(t, stop.packet.Attributes, AttrAcctInputOctets, 4096)
	assertUint32Attribute(t, stop.packet.Attributes, AttrAcctOutputOctets, 8192)
	assertUint32Attribute(t, stop.packet.Attributes, AttrAcctSessionTime, 300)
	assertUint32Attribute(t, stop.packet.Attributes, AttrAcctTerminateCause, uint32(AcctTerminateUserRequest))
	class, ok := stop.packet.Attributes.Get(AttrClass)
	if !ok || string(class.Value) != "class-1" {
		t.Fatalf("Class = %x", class.Value)
	}
	if start.packet.Identifier == stop.packet.Identifier {
		t.Fatalf("accounting reused identifier %d", start.packet.Identifier)
	}
}

func TestAccountingServerStatus(t *testing.T) {
	secret := []byte("testing-secret")
	server := newUDPMock(t, secret, func(request *Packet, raw []byte) ([]byte, error) {
		return signedResponse(request, secret, CodeAccountingResponse, nil)
	})
	client := newTestClient(t, ClientConfig{Address: server.Addr(), Secret: secret})
	if _, err := client.AccountRequest(context.Background(), &AccountingRequest{StatusType: AcctStatusAccountingOn}); err != nil {
		t.Fatalf("AccountRequest Accounting-On: %v", err)
	}
	request := server.nextRequest(t)
	assertUint32Attribute(t, request.packet.Attributes, AttrAcctStatusType, uint32(AcctStatusAccountingOn))
	if _, ok := request.packet.Attributes.Get(AttrAcctInputOctets); ok {
		t.Fatal("Accounting-On carried Acct-Input-Octets")
	}
	if _, ok := request.packet.Attributes.Get(AttrAcctSessionID); ok {
		t.Fatal("Accounting-On carried Acct-Session-Id")
	}
}

func TestAccountingInvalidRequests(t *testing.T) {
	client := newTestClient(t, ClientConfig{Address: "127.0.0.1:1", Secret: []byte("testing-secret")})
	cases := []struct {
		name    string
		request *AccountingRequest
	}{
		{name: "nil", request: nil},
		{name: "start without session", request: &AccountingRequest{StatusType: AcctStatusStart}},
		{name: "stop without session", request: &AccountingRequest{StatusType: AcctStatusStop}},
		{name: "unsupported status", request: &AccountingRequest{StatusType: AcctStatusType(99)}},
		{name: "ipv6 nas", request: &AccountingRequest{StatusType: AcctStatusAccountingOn, NASIPAddress: net.ParseIP("2001:db8::1")}},
		{name: "event timestamp before epoch", request: &AccountingRequest{StatusType: AcctStatusAccountingOn, EventTimestamp: time.Unix(-1, 0)}},
		{name: "event timestamp after uint32", request: &AccountingRequest{StatusType: AcctStatusAccountingOn, EventTimestamp: time.Unix(1<<33, 0)}},
	}
	for _, testCase := range cases {
		t.Run(testCase.name, func(t *testing.T) {
			if _, err := client.AccountRequest(context.Background(), testCase.request); !errors.Is(err, ErrInvalidRequest) {
				t.Fatalf("error = %v, want ErrInvalidRequest", err)
			}
		})
	}
}

func TestAccountingRejectsBadResponseAuthenticator(t *testing.T) {
	secret := []byte("testing-secret")
	server := newUDPMock(t, secret, func(request *Packet, raw []byte) ([]byte, error) {
		return signedResponse(request, []byte("other-secret"), CodeAccountingResponse, nil)
	})
	client := newTestClient(t, ClientConfig{Address: server.Addr(), Secret: secret})
	_, err := client.AccountRequest(context.Background(), &AccountingRequest{
		StatusType: AcctStatusAccountingOn,
	})
	if !errors.Is(err, ErrAuthenticator) {
		t.Fatalf("error = %v, want ErrAuthenticator", err)
	}
}

func TestAccountingRejectsUnexpectedCode(t *testing.T) {
	secret := []byte("testing-secret")
	server := newUDPMock(t, secret, func(request *Packet, raw []byte) ([]byte, error) {
		return signedResponse(request, secret, CodeAccessAccept, nil)
	})
	client := newTestClient(t, ClientConfig{Address: server.Addr(), Secret: secret})
	_, err := client.AccountRequest(context.Background(), &AccountingRequest{
		StatusType: AcctStatusAccountingOn,
	})
	if !errors.Is(err, ErrUnexpectedCode) {
		t.Fatalf("error = %v, want ErrUnexpectedCode", err)
	}
}

func TestAccountingDelay(t *testing.T) {
	if delay := accountingDelay(5, time.Now()); delay != 5 {
		t.Fatalf("immediate delay = %d, want 5", delay)
	}
	if delay := accountingDelay(5, time.Now().Add(-3*time.Second)); delay < 8 || delay > 9 {
		t.Fatalf("elapsed delay = %d, want 8 or 9", delay)
	}
	if delay := accountingDelay(maxUint32Value-1, time.Now().Add(-10*time.Second)); delay != maxUint32Value {
		t.Fatalf("overflow delay = %d, want %d", delay, maxUint32Value)
	}
}
