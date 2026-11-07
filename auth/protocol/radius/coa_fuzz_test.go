package radius

import "testing"

// FuzzDynamicAuthorizationResponse exercises the RFC 5176 ACK/NAK decode, verification and signing
// paths with arbitrary packets. | FuzzDynamicAuthorizationResponse 用任意报文覆盖 RFC 5176
// ACK/NAK 的解码、校验与签名路径。
func FuzzDynamicAuthorizationResponse(f *testing.F) {
	secret := []byte("fuzz-testing-secret")
	f.Add(rawPacket(CodeCoAACK, 1,
		tlv(AttrErrorCause, []byte{0, 0, 1, 246}),
		tlv(AttrReplyMessage, []byte("ok")),
		tlv(AttrMessageAuthenticator, make([]byte, 16)),
	))
	f.Add(rawPacket(CodeCoANAK, 2,
		tlv(AttrErrorCause, []byte{0, 0, 1, 250}),
	))
	f.Add(rawPacket(CodeDisconnectACK, 3))
	f.Add(rawPacket(CodeDisconnectNAK, 4,
		tlv(AttrErrorCause, []byte{0, 0, 1, 247}),
	))
	f.Add(rawPacket(CodeCoARequest, 5,
		tlv(AttrAcctSessionID, []byte("session-1")),
		tlv(AttrEventTimestamp, []byte{0x65, 0, 0, 0}),
	))
	f.Add([]byte{45, 1, 0, 20})
	f.Add([]byte{40, 255, 0, 20, 101, 6, 0, 0, 0, 0})

	f.Fuzz(func(t *testing.T, data []byte) {
		packet, err := ParsePacket(data)
		if err != nil {
			return
		}
		switch packet.Code {
		case CodeDisconnectRequest, CodeDisconnectACK, CodeDisconnectNAK,
			CodeCoARequest, CodeCoAACK, CodeCoANAK:
		default:
			return
		}
		response := decodeDynamicAuthorizationResponse(packet)
		if response.Code != packet.Code || response.Identifier != packet.Identifier {
			t.Fatalf("decoded response does not match packet: %+v", response)
		}
		_ = response.Acknowledged()
		_ = response.Rejected()
		_ = response.ErrorCause.String()

		var requestAuthenticator [16]byte
		copy(requestAuthenticator[:], data[4:HeaderLength])
		_, _, _ = verifyMessageAuthenticatorRaw(data, secret, requestAuthenticator)
		_ = verifyResponseAuthenticator(data, secret, requestAuthenticator)
		_ = verifyAccountingRequestAuthenticator(data, secret)

		signed := append([]byte(nil), data...)
		if _, err := signDynamicRequest(signed, secret, true); err == nil {
			// A successfully signed copy must still parse and keep its header. | 成功签名的副本
			// 必须仍可解析且保持头部不变。
			reparsed, err := ParsePacket(signed)
			if err != nil {
				t.Fatalf("signed packet no longer parses: %v", err)
			}
			if reparsed.Code != packet.Code || reparsed.Identifier != packet.Identifier {
				t.Fatalf("signed packet header changed: %+v", reparsed)
			}
		}
	})
}
