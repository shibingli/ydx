package radius

import (
	"bytes"
	"context"
	"encoding/binary"
	"errors"
	"net"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

// errorCauseAttribute builds an Error-Cause attribute. | errorCauseAttribute 构建 Error-Cause 属性。
func errorCauseAttribute(cause ErrorCause) Attribute {
	var value [4]byte
	binary.BigEndian.PutUint32(value[:], uint32(cause))
	return NewAttribute(AttrErrorCause, value[:])
}

// sendDynamicFunc invokes one dynamic authorization method. | sendDynamicFunc 调用一个动态授权方法。
type sendDynamicFunc func(*Client, context.Context) error

func TestSendCoAACK(t *testing.T) {
	secret := []byte("testing-secret")
	eventTime := time.Unix(1_700_000_100, 0).UTC()
	server := newUDPMock(t, secret, func(request *Packet, raw []byte) ([]byte, error) {
		return signedResponse(request, secret, CodeCoAACK, Attributes{
			NewAttribute(AttrReplyMessage, []byte("modified")),
		})
	})
	client := newTestClient(t, ClientConfig{
		Address:       server.Addr(),
		Secret:        secret,
		NASIdentifier: "nas-1",
		NASIPAddress:  net.IPv4(192, 0, 2, 40),
	})

	response, err := client.SendCoA(context.Background(), &CoARequest{
		SessionID:      "session-1",
		UserName:       "alice",
		NASPort:        9,
		EventTimestamp: eventTime,
		Attributes: Attributes{
			NewAttribute(AttrFilterID, []byte("new-acl")),
			NewAttribute(AttrSessionTimeout, []byte{0, 0, 1, 44}),
			// Client-managed duplicates must be filtered, not sent twice. | 客户端管理的重复属性
			// 必须被过滤，不能发送两次。
			NewAttribute(AttrUserName, []byte("mallory")),
			NewAttribute(AttrAcctSessionID, []byte("rogue-session")),
			NewAttribute(AttrNASIPAddress, []byte{203, 0, 113, 1}),
			NewAttribute(AttrNASIdentifier, []byte("rogue-nas")),
			NewAttribute(AttrNASPort, []byte{0, 0, 0, 99}),
			NewAttribute(AttrEventTimestamp, []byte{0, 0, 0, 1}),
			NewAttribute(AttrMessageAuthenticator, make([]byte, 16)),
		},
	})
	if err != nil {
		t.Fatalf("SendCoA: %v", err)
	}
	if !response.Acknowledged() || response.Rejected() {
		t.Fatalf("unexpected response code %d", response.Code)
	}
	if response.Code != CodeCoAACK || response.ReplyMessage != "modified" {
		t.Fatalf("unexpected response: %+v", response)
	}
	if response.HasErrorCause {
		t.Fatalf("CoA-ACK unexpectedly carried Error-Cause %d", response.ErrorCause)
	}
}

func TestSendCoARequestAttributesAndAuthenticator(t *testing.T) {
	secret := []byte("testing-secret")
	eventTime := time.Unix(1_700_000_100, 0).UTC()
	server := newUDPMock(t, secret, func(request *Packet, raw []byte) ([]byte, error) {
		return signedResponse(request, secret, CodeCoAACK, nil)
	})
	client := newTestClient(t, ClientConfig{
		Address:       server.Addr(),
		Secret:        secret,
		NASIdentifier: "nas-1",
		NASIPAddress:  net.IPv4(192, 0, 2, 40),
	})
	if _, err := client.SendCoA(context.Background(), &CoARequest{
		SessionID:      "session-1",
		UserName:       "alice",
		NASPort:        9,
		EventTimestamp: eventTime,
		Attributes: Attributes{
			NewAttribute(AttrFilterID, []byte("new-acl")),
			NewAttribute(AttrSessionTimeout, []byte{0, 0, 1, 44}),
			NewAttribute(AttrUserName, []byte("mallory")),
			NewAttribute(AttrAcctSessionID, []byte("rogue-session")),
			NewAttribute(AttrNASIPAddress, []byte{203, 0, 113, 1}),
			NewAttribute(AttrNASIdentifier, []byte("rogue-nas")),
			NewAttribute(AttrNASPort, []byte{0, 0, 0, 99}),
			NewAttribute(AttrEventTimestamp, []byte{0, 0, 0, 1}),
			NewAttribute(AttrMessageAuthenticator, make([]byte, 16)),
		},
	}); err != nil {
		t.Fatalf("SendCoA: %v", err)
	}

	request := server.nextRequest(t)
	if request.packet.Code != CodeCoARequest {
		t.Fatalf("request code = %d, want %d", request.packet.Code, CodeCoARequest)
	}
	if err := verifyAccountingRequestAuthenticator(request.raw, secret); err != nil {
		t.Fatalf("RFC 5176 Request Authenticator: %v", err)
	}
	assertStringAttribute(t, request.packet.Attributes, AttrAcctSessionID, "session-1")
	assertStringAttribute(t, request.packet.Attributes, AttrUserName, "alice")
	assertStringAttribute(t, request.packet.Attributes, AttrNASIdentifier, "nas-1")
	assertStringAttribute(t, request.packet.Attributes, AttrFilterID, "new-acl")
	assertUint32Attribute(t, request.packet.Attributes, AttrNASPort, 9)
	assertUint32Attribute(t, request.packet.Attributes, AttrEventTimestamp, uint32(eventTime.Unix()))
	assertUint32Attribute(t, request.packet.Attributes, AttrSessionTimeout, 300)
	assertIPAttribute(t, request.packet.Attributes, AttrNASIPAddress, net.IPv4(192, 0, 2, 40))
	for _, attributeType := range []AttributeType{
		AttrUserName, AttrAcctSessionID, AttrNASIPAddress, AttrNASIdentifier, AttrNASPort,
		AttrEventTimestamp,
	} {
		if attributes := request.packet.Attributes.GetAll(attributeType); len(attributes) != 1 {
			t.Fatalf("attribute %d appears %d times, want 1", attributeType, len(attributes))
		}
	}
	if _, ok := request.packet.Attributes.Get(AttrMessageAuthenticator); ok {
		t.Fatal("request carried a Message-Authenticator without IncludeMessageAuthenticator")
	}
}

func TestSendCoANAKWithErrorCause(t *testing.T) {
	cases := []struct {
		name       string
		attributes Attributes
		wantCause  ErrorCause
		wantText   string
	}{
		{
			name:       "with error cause",
			attributes: Attributes{errorCauseAttribute(ErrorCauseResourcesUnavailable), NewAttribute(AttrReplyMessage, []byte("busy"))},
			wantCause:  ErrorCauseResourcesUnavailable,
			wantText:   "Resources Unavailable",
		},
		{
			name:       "without error cause",
			attributes: nil,
		},
	}
	for _, testCase := range cases {
		t.Run(testCase.name, func(t *testing.T) {
			secret := []byte("testing-secret")
			server := newUDPMock(t, secret, func(request *Packet, raw []byte) ([]byte, error) {
				return signedResponse(request, secret, CodeCoANAK, testCase.attributes)
			})
			client := newTestClient(t, ClientConfig{Address: server.Addr(), Secret: secret})
			response, err := client.SendCoA(context.Background(), &CoARequest{SessionID: "session-1"})
			if !errors.Is(err, ErrCoANAK) {
				t.Fatalf("error = %v, want ErrCoANAK", err)
			}
			if response == nil || !response.Rejected() || response.Acknowledged() || response.Code != CodeCoANAK {
				t.Fatalf("unexpected response: %+v", response)
			}
			if response.HasErrorCause != (testCase.wantCause != 0) {
				t.Fatalf("HasErrorCause = %v", response.HasErrorCause)
			}
			if response.ErrorCause != testCase.wantCause {
				t.Fatalf("ErrorCause = %d, want %d", response.ErrorCause, testCase.wantCause)
			}
			if testCase.wantCause != 0 {
				if response.ErrorCause.String() != testCase.wantText {
					t.Fatalf("ErrorCause.String() = %q, want %q", response.ErrorCause.String(), testCase.wantText)
				}
				if !strings.Contains(err.Error(), testCase.wantText) {
					t.Fatalf("error %q does not name the Error-Cause", err)
				}
				if response.ReplyMessage != "busy" {
					t.Fatalf("ReplyMessage = %q", response.ReplyMessage)
				}
			}
			if strings.Contains(err.Error(), string(secret)) {
				t.Fatalf("error leaks the shared secret: %v", err)
			}
		})
	}
}

func TestSendDisconnectACKAndNAK(t *testing.T) {
	cases := []struct {
		name         string
		responseCode Code
		attributes   Attributes
		wantCause    ErrorCause
		wantErr      error
	}{
		{
			name:         "ack residual context",
			responseCode: CodeDisconnectACK,
			attributes:   Attributes{errorCauseAttribute(ErrorCauseResidualSessionContextRemoved)},
			wantCause:    ErrorCauseResidualSessionContextRemoved,
		},
		{
			name:         "nak session context not found",
			responseCode: CodeDisconnectNAK,
			attributes:   Attributes{errorCauseAttribute(ErrorCauseSessionContextNotFound)},
			wantCause:    ErrorCauseSessionContextNotFound,
			wantErr:      ErrDisconnectNAK,
		},
	}
	for _, testCase := range cases {
		t.Run(testCase.name, func(t *testing.T) {
			secret := []byte("testing-secret")
			server := newUDPMock(t, secret, func(request *Packet, raw []byte) ([]byte, error) {
				return signedResponse(request, secret, testCase.responseCode, testCase.attributes)
			})
			client := newTestClient(t, ClientConfig{Address: server.Addr(), Secret: secret, NASIdentifier: "nas-1"})
			response, err := client.SendDisconnect(context.Background(), &DisconnectRequest{
				UserName: "alice",
				Attributes: Attributes{
					NewAttribute(AttrFramedIPAddress, []byte{198, 51, 100, 7}),
				},
			})
			if testCase.wantErr != nil {
				if !errors.Is(err, testCase.wantErr) {
					t.Fatalf("error = %v, want %v", err, testCase.wantErr)
				}
			} else if err != nil {
				t.Fatalf("SendDisconnect: %v", err)
			}
			if response == nil || response.Code != testCase.responseCode {
				t.Fatalf("unexpected response: %+v", response)
			}
			if response.Acknowledged() != (testCase.responseCode == CodeDisconnectACK) {
				t.Fatalf("Acknowledged = %v", response.Acknowledged())
			}
			if response.ErrorCause != testCase.wantCause || !response.HasErrorCause {
				t.Fatalf("ErrorCause = %d, %v", response.ErrorCause, response.HasErrorCause)
			}

			request := server.nextRequest(t)
			if request.packet.Code != CodeDisconnectRequest {
				t.Fatalf("request code = %d, want %d", request.packet.Code, CodeDisconnectRequest)
			}
			if err := verifyAccountingRequestAuthenticator(request.raw, secret); err != nil {
				t.Fatalf("Request Authenticator: %v", err)
			}
			assertStringAttribute(t, request.packet.Attributes, AttrUserName, "alice")
			assertStringAttribute(t, request.packet.Attributes, AttrNASIdentifier, "nas-1")
			assertIPAttribute(t, request.packet.Attributes, AttrFramedIPAddress, net.IPv4(198, 51, 100, 7))
			if _, ok := request.packet.Attributes.Uint32(AttrEventTimestamp); !ok {
				t.Fatal("request lacks Event-Timestamp")
			}
		})
	}
}

func TestDynamicMessageAuthenticator(t *testing.T) {
	secret := []byte("testing-secret")
	t.Run("request and response signed", func(t *testing.T) {
		server := newUDPMock(t, secret, func(request *Packet, raw []byte) ([]byte, error) {
			return signedMessageResponse(request, secret, CodeCoAACK, nil)
		})
		client := newTestClient(t, ClientConfig{Address: server.Addr(), Secret: secret})
		response, err := client.SendCoA(context.Background(), &CoARequest{
			SessionID:                   "session-1",
			IncludeMessageAuthenticator: true,
		})
		if err != nil {
			t.Fatalf("SendCoA: %v", err)
		}
		if !response.Acknowledged() {
			t.Fatalf("unexpected response: %+v", response)
		}
		request := server.nextRequest(t)
		if _, ok := request.packet.Attributes.Get(AttrMessageAuthenticator); !ok {
			t.Fatal("request lacks Message-Authenticator")
		}
		present, valid, err := verifyMessageAuthenticatorRaw(request.raw, secret, [16]byte{})
		if err != nil || !present || !valid {
			t.Fatalf("request Message-Authenticator = present %v valid %v err %v", present, valid, err)
		}
		if err := verifyAccountingRequestAuthenticator(request.raw, secret); err != nil {
			t.Fatalf("Request Authenticator: %v", err)
		}
	})
	t.Run("request authenticator covers signed message authenticator", func(t *testing.T) {
		// The RFC 5176 order is Message-Authenticator first, Request Authenticator second. A server
		// that recomputes the Request Authenticator over the signed attribute must agree. | RFC 5176
		// 的顺序是先 Message-Authenticator、后 Request Authenticator。服务器对已签名属性重算
		// Request Authenticator 时必须一致。
		server := newUDPMock(t, secret, func(request *Packet, raw []byte) ([]byte, error) {
			return signedMessageResponse(request, secret, CodeCoAACK, nil)
		})
		client := newTestClient(t, ClientConfig{Address: server.Addr(), Secret: secret})
		if _, err := client.SendCoA(context.Background(), &CoARequest{
			SessionID:                   "session-1",
			IncludeMessageAuthenticator: true,
		}); err != nil {
			t.Fatalf("SendCoA: %v", err)
		}
		request := server.nextRequest(t)
		attribute, ok := request.packet.Attributes.Get(AttrMessageAuthenticator)
		if !ok || bytes.Equal(attribute.Value, make([]byte, 16)) {
			t.Fatalf("Message-Authenticator was not signed: %x", attribute.Value)
		}
	})
	t.Run("missing required response message authenticator", func(t *testing.T) {
		server := newUDPMock(t, secret, func(request *Packet, raw []byte) ([]byte, error) {
			return signedResponse(request, secret, CodeCoAACK, nil)
		})
		client := newTestClient(t, ClientConfig{Address: server.Addr(), Secret: secret, Timeout: 80 * time.Millisecond})
		start := time.Now()
		_, err := client.SendCoA(context.Background(), &CoARequest{
			SessionID:                   "session-1",
			IncludeMessageAuthenticator: true,
		})
		if !errors.Is(err, ErrTimeout) {
			t.Fatalf("error = %v, want ErrTimeout", err)
		}
		if elapsed := time.Since(start); elapsed < 60*time.Millisecond {
			t.Fatalf("missing response Message-Authenticator failed the attempt after only %v", elapsed)
		}
	})
	t.Run("invalid then valid response message authenticator", func(t *testing.T) {
		cases := []struct {
			name         string
			responseCode Code
			send         sendDynamicFunc
		}{
			{
				name:         "coa",
				responseCode: CodeCoAACK,
				send: func(client *Client, ctx context.Context) error {
					_, err := client.SendCoA(ctx, &CoARequest{
						SessionID:                   "session-1",
						IncludeMessageAuthenticator: true,
					})
					return err
				},
			},
			{
				name:         "disconnect",
				responseCode: CodeDisconnectACK,
				send: func(client *Client, ctx context.Context) error {
					_, err := client.SendDisconnect(ctx, &DisconnectRequest{
						SessionID:                   "session-1",
						IncludeMessageAuthenticator: true,
					})
					return err
				},
			},
		}
		for _, testCase := range cases {
			t.Run(testCase.name+"/invalid then valid", func(t *testing.T) {
				server := newScriptedUDPServer(t, func(request *Packet) ([][]byte, error) {
					bad, err := signedResponse(request, secret, testCase.responseCode, Attributes{
						NewAttribute(AttrMessageAuthenticator, make([]byte, 16)),
					})
					if err != nil {
						return nil, err
					}
					good, err := signedMessageResponse(request, secret, testCase.responseCode, nil)
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
				if err := testCase.send(client, context.Background()); err != nil {
					t.Fatalf("send: %v", err)
				}
			})
			t.Run(testCase.name+"/invalid only times out", func(t *testing.T) {
				server := newUDPMock(t, secret, func(request *Packet, raw []byte) ([]byte, error) {
					return signedResponse(request, secret, testCase.responseCode, Attributes{
						NewAttribute(AttrMessageAuthenticator, make([]byte, 16)),
					})
				})
				client := newTestClient(t, ClientConfig{
					Address: server.Addr(),
					Secret:  secret,
					Timeout: 80 * time.Millisecond,
				})
				start := time.Now()
				err := testCase.send(client, context.Background())
				if !errors.Is(err, ErrTimeout) {
					t.Fatalf("error = %v, want ErrTimeout", err)
				}
				if elapsed := time.Since(start); elapsed < 60*time.Millisecond {
					t.Fatalf("invalid response Message-Authenticator failed the attempt after only %v", elapsed)
				}
			})
		}
	})
	t.Run("invalid response message authenticator", func(t *testing.T) {
		server := newUDPMock(t, secret, func(request *Packet, raw []byte) ([]byte, error) {
			return signedResponse(request, secret, CodeCoAACK, Attributes{
				NewAttribute(AttrMessageAuthenticator, make([]byte, 16)),
			})
		})
		client := newTestClient(t, ClientConfig{Address: server.Addr(), Secret: secret})
		_, err := client.SendCoA(context.Background(), &CoARequest{SessionID: "session-1"})
		if !errors.Is(err, ErrMessageAuthenticator) {
			t.Fatalf("error = %v, want ErrMessageAuthenticator", err)
		}
	})
	t.Run("optional response message authenticator", func(t *testing.T) {
		server := newUDPMock(t, secret, func(request *Packet, raw []byte) ([]byte, error) {
			return signedMessageResponse(request, secret, CodeDisconnectACK, nil)
		})
		client := newTestClient(t, ClientConfig{Address: server.Addr(), Secret: secret})
		response, err := client.SendDisconnect(context.Background(), &DisconnectRequest{SessionID: "session-1"})
		if err != nil || !response.Acknowledged() {
			t.Fatalf("SendDisconnect = %+v, %v", response, err)
		}
	})
}

func TestDynamicDiscardsBadResponseAuthenticator(t *testing.T) {
	secret := []byte("testing-secret")
	cases := []struct {
		name         string
		responseCode Code
		send         sendDynamicFunc
	}{
		{
			name:         "coa",
			responseCode: CodeCoAACK,
			send: func(client *Client, ctx context.Context) error {
				_, err := client.SendCoA(ctx, &CoARequest{SessionID: "session-1"})
				return err
			},
		},
		{
			name:         "disconnect",
			responseCode: CodeDisconnectACK,
			send: func(client *Client, ctx context.Context) error {
				_, err := client.SendDisconnect(ctx, &DisconnectRequest{SessionID: "session-1"})
				return err
			},
		},
	}
	for _, testCase := range cases {
		t.Run(testCase.name+"/bad then good", func(t *testing.T) {
			server := newScriptedUDPServer(t, func(request *Packet) ([][]byte, error) {
				bad, err := signedResponse(request, []byte("other-secret"), testCase.responseCode, nil)
				if err != nil {
					return nil, err
				}
				good, err := signedResponse(request, secret, testCase.responseCode, nil)
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
			if err := testCase.send(client, context.Background()); err != nil {
				t.Fatalf("send: %v", err)
			}
		})
		t.Run(testCase.name+"/bad only times out", func(t *testing.T) {
			server := newUDPMock(t, secret, func(request *Packet, raw []byte) ([]byte, error) {
				return signedResponse(request, []byte("other-secret"), testCase.responseCode, nil)
			})
			client := newTestClient(t, ClientConfig{
				Address: server.Addr(),
				Secret:  secret,
				Timeout: 80 * time.Millisecond,
			})
			start := time.Now()
			err := testCase.send(client, context.Background())
			if !errors.Is(err, ErrTimeout) {
				t.Fatalf("error = %v, want ErrTimeout", err)
			}
			if elapsed := time.Since(start); elapsed < 60*time.Millisecond {
				t.Fatalf("bad response failed the exchange after only %v", elapsed)
			}
			if strings.Contains(err.Error(), string(secret)) || strings.Contains(err.Error(), "other-secret") {
				t.Fatalf("error leaks a secret: %v", err)
			}
		})
	}
}

func TestDynamicRetransmissionKeepsPacket(t *testing.T) {
	secret := []byte("testing-secret")
	var attempts atomic.Int32
	server := newUDPMock(t, secret, func(request *Packet, raw []byte) ([]byte, error) {
		if attempts.Add(1) == 1 {
			return nil, nil
		}
		return signedResponse(request, secret, CodeCoAACK, nil)
	})
	client := newTestClient(t, ClientConfig{
		Address: server.Addr(),
		Secret:  secret,
		Timeout: 100 * time.Millisecond,
		Retries: 1,
	})
	start := time.Now()
	response, err := client.SendCoA(context.Background(), &CoARequest{SessionID: "session-1"})
	elapsed := time.Since(start)
	if err != nil || !response.Acknowledged() {
		t.Fatalf("SendCoA = %+v, %v", response, err)
	}
	if elapsed < 80*time.Millisecond {
		t.Fatalf("retransmission returned after only %v", elapsed)
	}
	first := server.nextRequest(t)
	second := server.nextRequest(t)
	if !bytes.Equal(first.raw, second.raw) {
		t.Fatal("retransmission changed the encoded packet; RFC 5176 duplicate detection requires identical bytes")
	}
	if first.packet.Identifier != second.packet.Identifier {
		t.Fatalf("identifier changed from %d to %d", first.packet.Identifier, second.packet.Identifier)
	}
	if first.packet.Authenticator != second.packet.Authenticator {
		t.Fatal("Request Authenticator changed across retransmissions")
	}
	firstTime, _ := first.packet.Attributes.Uint32(AttrEventTimestamp)
	secondTime, _ := second.packet.Attributes.Uint32(AttrEventTimestamp)
	if firstTime != secondTime {
		t.Fatalf("Event-Timestamp changed from %d to %d", firstTime, secondTime)
	}
}

func TestDynamicRejectsMalformedResponse(t *testing.T) {
	secret := []byte("testing-secret")
	malformedResponse := func(request *Packet, responseCode Code) [][]byte {
		short := make([]byte, 10)
		short[0] = byte(responseCode)
		short[1] = request.Identifier
		badLength := make([]byte, HeaderLength)
		badLength[0] = byte(responseCode)
		badLength[1] = request.Identifier
		binary.BigEndian.PutUint16(badLength[2:4], HeaderLength+32)
		return [][]byte{short, badLength}
	}
	cases := []struct {
		name         string
		responseCode Code
		send         sendDynamicFunc
	}{
		{
			name:         "coa",
			responseCode: CodeCoAACK,
			send: func(client *Client, ctx context.Context) error {
				_, err := client.SendCoA(ctx, &CoARequest{SessionID: "session-1"})
				return err
			},
		},
		{
			name:         "disconnect",
			responseCode: CodeDisconnectACK,
			send: func(client *Client, ctx context.Context) error {
				_, err := client.SendDisconnect(ctx, &DisconnectRequest{SessionID: "session-1"})
				return err
			},
		},
	}
	for _, testCase := range cases {
		t.Run(testCase.name+"/bad structure then good", func(t *testing.T) {
			server := newScriptedUDPServer(t, func(request *Packet) ([][]byte, error) {
				good, err := signedResponse(request, secret, testCase.responseCode, nil)
				if err != nil {
					return nil, err
				}
				return append(malformedResponse(request, testCase.responseCode), good), nil
			})
			client := newTestClient(t, ClientConfig{
				Address: server.LocalAddr().String(),
				Secret:  secret,
				Timeout: 500 * time.Millisecond,
			})
			if err := testCase.send(client, context.Background()); err != nil {
				t.Fatalf("send: %v", err)
			}
		})
		t.Run(testCase.name+"/bad structure only times out", func(t *testing.T) {
			server := newUDPMock(t, secret, func(request *Packet, raw []byte) ([]byte, error) {
				return malformedResponse(request, testCase.responseCode)[0], nil
			})
			client := newTestClient(t, ClientConfig{
				Address: server.Addr(),
				Secret:  secret,
				Timeout: 80 * time.Millisecond,
			})
			start := time.Now()
			err := testCase.send(client, context.Background())
			if !errors.Is(err, ErrTimeout) {
				t.Fatalf("error = %v, want ErrTimeout", err)
			}
			if elapsed := time.Since(start); elapsed < 60*time.Millisecond {
				t.Fatalf("malformed response failed the exchange after only %v", elapsed)
			}
		})
	}
}

func TestDynamicRejectsUnexpectedCode(t *testing.T) {
	secret := []byte("testing-secret")
	server := newUDPMock(t, secret, func(request *Packet, raw []byte) ([]byte, error) {
		return signedResponse(request, secret, CodeAccountingResponse, nil)
	})
	client := newTestClient(t, ClientConfig{Address: server.Addr(), Secret: secret})
	if _, err := client.SendCoA(context.Background(), &CoARequest{SessionID: "session-1"}); !errors.Is(err, ErrUnexpectedCode) {
		t.Fatalf("error = %v, want ErrUnexpectedCode", err)
	}
}

func TestDynamicIdentifierHandling(t *testing.T) {
	secret := []byte("testing-secret")
	t.Run("udp ignores another identifier and accepts the next datagram", func(t *testing.T) {
		conn, err := net.ListenPacket("udp4", "127.0.0.1:0")
		if err != nil {
			t.Fatalf("listen udp: %v", err)
		}
		t.Cleanup(func() {
			_ = conn.Close()
		})
		serveErr := make(chan error, 1)
		go func() {
			buf := make([]byte, MaxPacketLength)
			_ = conn.SetReadDeadline(time.Now().Add(5 * time.Second))
			n, addr, err := conn.ReadFrom(buf)
			if err != nil {
				serveErr <- err
				return
			}
			request, err := ParsePacket(buf[:n])
			if err != nil {
				serveErr <- err
				return
			}
			stale := &Packet{
				Code:          CodeCoAACK,
				Identifier:    request.Identifier + 1,
				Authenticator: request.Authenticator,
			}
			staleRaw, err := MarshalPacket(stale)
			if err != nil {
				serveErr <- err
				return
			}
			if err := applyResponseAuthenticator(staleRaw, secret); err != nil {
				serveErr <- err
				return
			}
			if _, err := conn.WriteTo(staleRaw, addr); err != nil {
				serveErr <- err
				return
			}
			correct, err := signedResponse(request, secret, CodeCoAACK, nil)
			if err != nil {
				serveErr <- err
				return
			}
			_, err = conn.WriteTo(correct, addr)
			serveErr <- err
		}()

		client := newTestClient(t, ClientConfig{Address: conn.LocalAddr().String(), Secret: secret})
		response, err := client.SendCoA(context.Background(), &CoARequest{SessionID: "session-1"})
		if err != nil || !response.Acknowledged() {
			t.Fatalf("SendCoA = %+v, %v", response, err)
		}
		select {
		case err := <-serveErr:
			if err != nil {
				t.Fatalf("udp server: %v", err)
			}
		case <-time.After(5 * time.Second):
			t.Fatal("udp server did not finish")
		}
	})
	t.Run("stream rejects another identifier", func(t *testing.T) {
		server := newTCPMock(t, secret, func(request *Packet, raw []byte) ([]byte, error) {
			wrong := &Packet{
				Code:          CodeCoAACK,
				Identifier:    request.Identifier + 1,
				Authenticator: request.Authenticator,
			}
			response, err := MarshalPacket(wrong)
			if err != nil {
				return nil, err
			}
			if err := applyResponseAuthenticator(response, secret); err != nil {
				return nil, err
			}
			return response, nil
		})
		client := newTestClient(t, ClientConfig{Network: NetworkTCP, Address: server.Addr(), Secret: secret})
		_, err := client.SendCoA(context.Background(), &CoARequest{SessionID: "session-1"})
		if !errors.Is(err, ErrUnexpectedIdentifier) {
			t.Fatalf("error = %v, want ErrUnexpectedIdentifier", err)
		}
	})
}

func TestDynamicContextCancellation(t *testing.T) {
	secret := []byte("testing-secret")
	t.Run("cancel", func(t *testing.T) {
		server := newUDPMock(t, secret, func(request *Packet, raw []byte) ([]byte, error) {
			return nil, nil
		})
		client := newTestClient(t, ClientConfig{Address: server.Addr(), Secret: secret, Timeout: 2 * time.Second})
		ctx, cancel := context.WithCancel(context.Background())
		timer := time.AfterFunc(50*time.Millisecond, cancel)
		defer timer.Stop()
		start := time.Now()
		_, err := client.SendDisconnect(ctx, &DisconnectRequest{SessionID: "session-1"})
		if !errors.Is(err, ErrCanceled) {
			t.Fatalf("error = %v, want ErrCanceled", err)
		}
		if elapsed := time.Since(start); elapsed > time.Second {
			t.Fatalf("cancellation took %v", elapsed)
		}
	})
	t.Run("deadline", func(t *testing.T) {
		server := newUDPMock(t, secret, func(request *Packet, raw []byte) ([]byte, error) {
			return nil, nil
		})
		client := newTestClient(t, ClientConfig{Address: server.Addr(), Secret: secret, Timeout: 2 * time.Second})
		ctx, cancel := context.WithTimeout(context.Background(), 50*time.Millisecond)
		defer cancel()
		_, err := client.SendCoA(ctx, &CoARequest{SessionID: "session-1"})
		if !errors.Is(err, ErrTimeout) {
			t.Fatalf("error = %v, want ErrTimeout", err)
		}
	})
	t.Run("already canceled", func(t *testing.T) {
		client := newTestClient(t, ClientConfig{Address: "127.0.0.1:1", Secret: secret})
		ctx, cancel := context.WithCancel(context.Background())
		cancel()
		if _, err := client.SendCoA(ctx, &CoARequest{SessionID: "session-1"}); !errors.Is(err, ErrCanceled) {
			t.Fatalf("error = %v, want ErrCanceled", err)
		}
	})
}

func TestDynamicInvalidRequests(t *testing.T) {
	client := newTestClient(t, ClientConfig{Address: "127.0.0.1:1", Secret: []byte("testing-secret")})
	cases := []struct {
		name    string
		request *DynamicAuthorizationRequest
	}{
		{name: "nil", request: nil},
		{name: "without session or user", request: &DynamicAuthorizationRequest{}},
		{name: "user without nas identity", request: &DynamicAuthorizationRequest{UserName: "alice"}},
		{name: "ipv6 nas", request: &DynamicAuthorizationRequest{SessionID: "s", NASIPAddress: net.ParseIP("2001:db8::1")}},
		{name: "event timestamp before epoch", request: &DynamicAuthorizationRequest{SessionID: "s", EventTimestamp: time.Unix(-1, 0)}},
		{name: "event timestamp after uint32", request: &DynamicAuthorizationRequest{SessionID: "s", EventTimestamp: time.Unix(1<<33, 0)}},
		{name: "error cause in request", request: &DynamicAuthorizationRequest{
			SessionID:  "s",
			Attributes: Attributes{errorCauseAttribute(ErrorCauseInvalidRequest)},
		}},
		{name: "invalid attribute value", request: &DynamicAuthorizationRequest{
			SessionID:  "s",
			Attributes: Attributes{NewAttribute(AttrSessionTimeout, []byte{0, 0, 1})},
		}},
		{name: "invalid error cause length", request: &DynamicAuthorizationRequest{
			SessionID:  "s",
			Attributes: Attributes{NewAttribute(AttrErrorCause, []byte{0, 0, 0})},
		}},
	}
	for _, testCase := range cases {
		t.Run(testCase.name, func(t *testing.T) {
			if _, err := client.SendCoA(context.Background(), testCase.request); !errors.Is(err, ErrInvalidRequest) {
				t.Fatalf("error = %v, want ErrInvalidRequest", err)
			}
		})
	}
}

func TestDynamicPacketRoundTrip(t *testing.T) {
	cases := []struct {
		name string
		code Code
	}{
		{name: "disconnect request", code: CodeDisconnectRequest},
		{name: "disconnect ack", code: CodeDisconnectACK},
		{name: "disconnect nak", code: CodeDisconnectNAK},
		{name: "coa request", code: CodeCoARequest},
		{name: "coa ack", code: CodeCoAACK},
		{name: "coa nak", code: CodeCoANAK},
	}
	for _, testCase := range cases {
		t.Run(testCase.name, func(t *testing.T) {
			attributes := Attributes{
				NewAttribute(AttrAcctSessionID, []byte("session-1")),
				NewAttribute(AttrUserName, []byte("alice")),
				NewAttribute(AttrNASIdentifier, []byte("nas-1")),
				NewAttribute(AttrEventTimestamp, []byte{0x65, 0x00, 0x00, 0x00}),
				errorCauseAttribute(ErrorCauseSessionContextNotFound),
			}
			packet := &Packet{Code: testCase.code, Identifier: 0x42, Attributes: attributes}
			raw, err := MarshalPacket(packet)
			if err != nil {
				t.Fatalf("MarshalPacket: %v", err)
			}
			parsed, err := ParsePacket(raw)
			if err != nil {
				t.Fatalf("ParsePacket: %v", err)
			}
			if parsed.Code != testCase.code || parsed.Identifier != 0x42 {
				t.Fatalf("unexpected header: %+v", parsed)
			}
			cause, ok := parsed.Attributes.Uint32(AttrErrorCause)
			if !ok || ErrorCause(cause) != ErrorCauseSessionContextNotFound {
				t.Fatalf("Error-Cause = %d, %v", cause, ok)
			}
			if err := verifyAccountingRequestAuthenticator(raw, []byte("testing-secret")); !errors.Is(err, ErrAuthenticator) {
				t.Fatalf("unauthenticated packet error = %v, want ErrAuthenticator", err)
			}
		})
	}
}

func TestErrorCauseValuesAndDictionary(t *testing.T) {
	cases := []struct {
		cause ErrorCause
		name  string
	}{
		{ErrorCauseResidualSessionContextRemoved, "Residual Session Context Removed"},
		{ErrorCauseInvalidEAPPacket, "Invalid EAP Packet (Ignored)"},
		{ErrorCauseUnsupportedAttribute, "Unsupported Attribute"},
		{ErrorCauseMissingAttribute, "Missing Attribute"},
		{ErrorCauseNASIdentificationMismatch, "NAS Identification Mismatch"},
		{ErrorCauseInvalidRequest, "Invalid Request"},
		{ErrorCauseUnsupportedService, "Unsupported Service"},
		{ErrorCauseUnsupportedExtension, "Unsupported Extension"},
		{ErrorCauseInvalidAttributeValue, "Invalid Attribute Value"},
		{ErrorCauseAdministrativelyProhibited, "Administratively Prohibited"},
		{ErrorCauseRequestNotRoutable, "Request Not Routable (Proxy)"},
		{ErrorCauseSessionContextNotFound, "Session Context Not Found"},
		{ErrorCauseSessionContextNotRemovable, "Session Context Not Removable"},
		{ErrorCauseOtherProxyProcessingError, "Other Proxy Processing Error"},
		{ErrorCauseResourcesUnavailable, "Resources Unavailable"},
		{ErrorCauseRequestInitiated, "Request Initiated"},
		{ErrorCauseMultipleSessionSelectionUnsupported, "Multiple Session Selection Unsupported"},
		{ErrorCause(999), "999"},
	}
	for _, testCase := range cases {
		if actual := testCase.cause.String(); actual != testCase.name {
			t.Fatalf("ErrorCause(%d).String() = %q, want %q", uint32(testCase.cause), actual, testCase.name)
		}
	}

	dictionary := NewBuiltinDictionary()
	if name, ok := dictionary.NameByType(AttrErrorCause); !ok || name != "Error-Cause" {
		t.Fatalf("NameByType(Error-Cause) = %q, %v", name, ok)
	}
	if value, ok := dictionary.ValueName(AttrErrorCause, uint32(ErrorCauseSessionContextNotFound)); !ok || value != "Session Context Not Found" {
		t.Fatalf("ValueName = %q, %v", value, ok)
	}
	if number, ok := dictionary.ValueNumber(AttrErrorCause, "resources unavailable"); !ok || ErrorCause(number) != ErrorCauseResourcesUnavailable {
		t.Fatalf("ValueNumber = %d, %v", number, ok)
	}

	badPacket := &Packet{
		Code:       CodeCoAACK,
		Attributes: Attributes{NewAttribute(AttrErrorCause, []byte{0, 0, 0})},
	}
	if _, err := MarshalPacket(badPacket); !errors.Is(err, ErrInvalidAttribute) {
		t.Fatalf("three-octet Error-Cause error = %v, want ErrInvalidAttribute", err)
	}
}

func TestSignDynamicRequestRequiresMessageAuthenticator(t *testing.T) {
	raw, err := MarshalPacket(&Packet{
		Code:       CodeCoARequest,
		Identifier: 1,
		Attributes: Attributes{NewAttribute(AttrUserName, []byte("alice"))},
	})
	if err != nil {
		t.Fatalf("MarshalPacket: %v", err)
	}
	if _, err := signDynamicRequest(raw, []byte("testing-secret"), true); !errors.Is(err, ErrMessageAuthenticator) {
		t.Fatalf("error = %v, want ErrMessageAuthenticator", err)
	}
}

func TestDynamicDefaultPort(t *testing.T) {
	cases := []struct {
		network string
		code    Code
		want    string
	}{
		{NetworkUDP, CodeAccessRequest, "1812"},
		{NetworkUDP, CodeAccountingRequest, "1813"},
		{NetworkUDP, CodeCoARequest, "3799"},
		{NetworkUDP, CodeCoAACK, "3799"},
		{NetworkUDP, CodeCoANAK, "3799"},
		{NetworkUDP, CodeDisconnectRequest, "3799"},
		{NetworkUDP, CodeDisconnectACK, "3799"},
		{NetworkUDP, CodeDisconnectNAK, "3799"},
		{NetworkTCP, CodeCoARequest, "2083"},
		{NetworkTLS, CodeDisconnectRequest, "2083"},
	}
	for _, testCase := range cases {
		if port := defaultPort(testCase.network, testCase.code); port != testCase.want {
			t.Fatalf("defaultPort(%q, %d) = %q, want %q", testCase.network, testCase.code, port, testCase.want)
		}
	}
	client := &Client{cfg: ClientConfig{Network: NetworkUDP, Address: "radius.example"}}
	if address := client.address(CodeCoARequest); address != "radius.example:3799" {
		t.Fatalf("address = %q, want radius.example:3799", address)
	}
}

func TestDynamicResponseHelpers(t *testing.T) {
	var nilResponse *DynamicAuthorizationResponse
	if nilResponse.Acknowledged() || nilResponse.Rejected() {
		t.Fatal("nil response reported a state")
	}
	codes := []struct {
		code         Code
		acknowledged bool
		rejected     bool
	}{
		{CodeCoAACK, true, false},
		{CodeCoANAK, false, true},
		{CodeDisconnectACK, true, false},
		{CodeDisconnectNAK, false, true},
		{CodeAccessAccept, false, false},
	}
	for _, testCase := range codes {
		response := &DynamicAuthorizationResponse{Code: testCase.code}
		if response.Acknowledged() != testCase.acknowledged || response.Rejected() != testCase.rejected {
			t.Fatalf("code %d = acknowledged %v rejected %v", testCase.code, response.Acknowledged(), response.Rejected())
		}
	}
}
