package kerberos

import (
	"bytes"
	"errors"
	"reflect"
	"testing"
	"time"
)

// sampleTime returns a fixed whole-second KerberosTime. | sampleTime 返回固定的整秒
// KerberosTime。
func sampleTime() KerberosTime {
	return NewKerberosTime(time.Date(2026, 11, 8, 12, 30, 45, 0, time.UTC))
}

// sampleKey returns a deterministic key of the requested enctype. | sampleKey 返回指定
// 加密类型的确定性密钥。
func sampleKey(t *testing.T, etype int32, fill byte) EncryptionKey {
	t.Helper()
	size, err := KeySize(etype)
	if err != nil {
		t.Fatalf("KeySize(%d): %v", etype, err)
	}
	return EncryptionKey{KeyType: etype, KeyValue: bytes.Repeat([]byte{fill}, size)}
}

// sampleTicket builds a complete ticket with an encrypted EncTicketPart. | sampleTicket
// 构建包含加密 EncTicketPart 的完整票据。
func sampleTicket(t *testing.T) Ticket {
	t.Helper()
	now := sampleTime()
	start := now
	renew := NewKerberosTime(now.Add(7 * 24 * time.Hour))
	part := EncTicketPart{
		Flags:     TicketFlagForwardable | TicketFlagPreAuthent | TicketFlagRenewable,
		Key:       sampleKey(t, ETypeAES256CTS, 0x11),
		CRealm:    "EXAMPLE.COM",
		CName:     NewPrincipalName(NameTypePrincipal, "alice"),
		Transited: TransitedEncoding{TrType: 1, Contents: []byte("EXAMPLE.COM")},
		AuthTime:  now,
		StartTime: &start,
		EndTime:   NewKerberosTime(now.Add(10 * time.Hour)),
		RenewTill: &renew,
		CAddr:     []HostAddress{{AddrType: 2, Address: []byte{192, 0, 2, 10}}},
		AuthorizationData: []TypedData{
			{DataType: 1, DataValue: []byte{0x01, 0x02}},
		},
	}
	return Ticket{
		TktVNO: PVNO,
		Realm:  "EXAMPLE.COM",
		SName:  NewPrincipalName(NameTypeSRVInst, "krbtgt", "EXAMPLE.COM"),
		EncPart: EncryptedData{
			EType:  ETypeAES256CTS,
			KVNO:   3,
			Cipher: appendEncTicketPart(part),
		},
	}
}

// TestAPReqRoundTrip verifies AP-REQ encoding and decoding. | TestAPReqRoundTrip 校验
// AP-REQ 编码与解码。
func TestAPReqRoundTrip(t *testing.T) {
	req := APReq{
		PVNO:      PVNO,
		MsgType:   MessageTypeAPReq,
		APOptions: APOptionMutualRequired,
		Ticket:    sampleTicket(t),
		Authenticator: EncryptedData{
			EType:  ETypeAES256CTS,
			KVNO:   4,
			Cipher: []byte{0xDE, 0xAD, 0xBE, 0xEF},
		},
	}
	encoded, err := req.Marshal()
	if err != nil {
		t.Fatalf("Marshal: %v", err)
	}
	if encoded[0] != 0x6E {
		t.Fatalf("application tag = 0x%02x, want 0x6E", encoded[0])
	}
	decoded, err := ParseAPReq(encoded)
	if err != nil {
		t.Fatalf("ParseAPReq: %v", err)
	}
	if !reflect.DeepEqual(decoded, req) {
		t.Fatalf("decoded = %#v, want %#v", decoded, req)
	}
	if _, err := ParseAPReq(append(encoded, 0)); err == nil {
		t.Fatal("ParseAPReq accepted trailing data")
	}
	if _, err := (APReq{Ticket: Ticket{}}).Marshal(); !errors.Is(err, ErrInvalidMessage) {
		t.Fatalf("Marshal without ticket error = %v, want ErrInvalidMessage", err)
	}
	if _, err := (APReq{Ticket: req.Ticket}).Marshal(); !errors.Is(err, ErrInvalidMessage) {
		t.Fatalf("Marshal without authenticator error = %v, want ErrInvalidMessage", err)
	}
}

// TestAPRepRoundTrip verifies AP-REP encoding and decoding. | TestAPRepRoundTrip 校验
// AP-REP 编码与解码。
func TestAPRepRoundTrip(t *testing.T) {
	rep := APRep{
		PVNO:    PVNO,
		MsgType: MessageTypeAPRep,
		EncPart: EncryptedData{EType: ETypeRC4HMAC, KVNO: 2, Cipher: []byte{1, 2, 3, 4}},
	}
	encoded, err := rep.Marshal()
	if err != nil {
		t.Fatalf("Marshal: %v", err)
	}
	if encoded[0] != 0x6F {
		t.Fatalf("application tag = 0x%02x, want 0x6F", encoded[0])
	}
	decoded, err := ParseAPRep(encoded)
	if err != nil {
		t.Fatalf("ParseAPRep: %v", err)
	}
	if !reflect.DeepEqual(decoded, rep) {
		t.Fatalf("decoded = %#v, want %#v", decoded, rep)
	}
	if _, err := (APRep{}).Marshal(); !errors.Is(err, ErrInvalidMessage) {
		t.Fatalf("empty Marshal error = %v, want ErrInvalidMessage", err)
	}
}

// TestKDCRequestRoundTrip verifies AS-REQ and TGS-REQ encoding and decoding. |
// TestKDCRequestRoundTrip 校验 AS-REQ 与 TGS-REQ 编码与解码。
func TestKDCRequestRoundTrip(t *testing.T) {
	now := sampleTime()
	from := now
	renew := NewKerberosTime(now.Add(time.Hour))
	body := KDCReqBody{
		KDCReqOptions: KDCOptionForwardable | KDCOptionRenewable,
		CName:         principalPointer(NewPrincipalName(NameTypePrincipal, "alice")),
		Realm:         "EXAMPLE.COM",
		SName:         principalPointer(NewPrincipalName(NameTypeSRVInst, "krbtgt", "EXAMPLE.COM")),
		From:          &from,
		Till:          NewKerberosTime(now.Add(10 * time.Hour)),
		RTime:         &renew,
		Nonce:         0xDEADBEEF,
		ETypes:        []int32{ETypeAES256CTS, ETypeAES128CTS, ETypeRC4HMAC},
		Addresses:     []HostAddress{{AddrType: 2, Address: []byte{10, 0, 0, 1}}},
		EncAuthorizationData: &EncryptedData{
			EType:  ETypeAES128CTS,
			Cipher: []byte{9, 8, 7},
		},
		AdditionalTickets: []Ticket{sampleTicket(t)},
	}
	pa := []PAData{{PADataType: PADataTypeEncTimestamp, PADataValue: []byte{0x30, 0x00}}}
	asReq := ASReq{PAData: pa, Body: body}
	encoded, err := asReq.Marshal()
	if err != nil {
		t.Fatalf("ASReq Marshal: %v", err)
	}
	if encoded[0] != 0x6A {
		t.Fatalf("AS-REQ application tag = 0x%02x, want 0x6A", encoded[0])
	}
	decodedAS, err := ParseASReq(encoded)
	if err != nil {
		t.Fatalf("ParseASReq: %v", err)
	}
	if !reflect.DeepEqual(decodedAS, asReq) {
		t.Fatalf("AS-REQ decoded = %#v, want %#v", decodedAS, asReq)
	}

	tgsReq := TGSReq{PAData: []PAData{{PADataType: PADataTypeTGSReq, PADataValue: []byte{0x6E, 0x00}}}, Body: body}
	encoded, err = tgsReq.Marshal()
	if err != nil {
		t.Fatalf("TGSReq Marshal: %v", err)
	}
	if encoded[0] != 0x6C {
		t.Fatalf("TGS-REQ application tag = 0x%02x, want 0x6C", encoded[0])
	}
	decodedTGS, err := ParseTGSReq(encoded)
	if err != nil {
		t.Fatalf("ParseTGSReq: %v", err)
	}
	if !reflect.DeepEqual(decodedTGS, tgsReq) {
		t.Fatalf("TGS-REQ decoded = %#v, want %#v", decodedTGS, tgsReq)
	}
	if _, err := ParseASReq(encoded); !messageError(err) {
		t.Fatalf("ParseASReq(TGS-REQ) error = %v, want ErrInvalidMessage or ErrASN1", err)
	}
}

// TestKDCReplyRoundTrip verifies AS-REP and TGS-REP encoding and decoding. |
// TestKDCReplyRoundTrip 校验 AS-REP 与 TGS-REP 编码与解码。
func TestKDCReplyRoundTrip(t *testing.T) {
	ticket := sampleTicket(t)
	asRep := ASRep{
		PAData:  []PAData{{PADataType: 19, PADataValue: []byte{1, 2}}},
		CRealm:  "EXAMPLE.COM",
		CName:   NewPrincipalName(NameTypePrincipal, "alice"),
		Ticket:  ticket,
		EncPart: EncryptedData{EType: ETypeAES256CTS, KVNO: 1, Cipher: []byte{4, 5, 6}},
	}
	encoded, err := asRep.Marshal()
	if err != nil {
		t.Fatalf("ASRep Marshal: %v", err)
	}
	if encoded[0] != 0x6B {
		t.Fatalf("AS-REP application tag = 0x%02x, want 0x6B", encoded[0])
	}
	decodedAS, err := ParseASRep(encoded)
	if err != nil {
		t.Fatalf("ParseASRep: %v", err)
	}
	if !reflect.DeepEqual(decodedAS, asRep) {
		t.Fatalf("AS-REP decoded = %#v, want %#v", decodedAS, asRep)
	}
	tgsRep := TGSRep{
		CRealm:  "EXAMPLE.COM",
		CName:   NewPrincipalName(NameTypePrincipal, "alice"),
		Ticket:  ticket,
		EncPart: EncryptedData{EType: ETypeRC4HMAC, KVNO: 5, Cipher: []byte{7, 8}},
	}
	encoded, err = tgsRep.Marshal()
	if err != nil {
		t.Fatalf("TGSRep Marshal: %v", err)
	}
	if encoded[0] != 0x6D {
		t.Fatalf("TGS-REP application tag = 0x%02x, want 0x6D", encoded[0])
	}
	decodedTGS, err := ParseTGSRep(encoded)
	if err != nil {
		t.Fatalf("ParseTGSRep: %v", err)
	}
	if !reflect.DeepEqual(decodedTGS, tgsRep) {
		t.Fatalf("TGS-REP decoded = %#v, want %#v", decodedTGS, tgsRep)
	}
}

// TestKRBErrorRoundTrip verifies KRB-ERROR encoding, decoding, and sentinel mapping. |
// TestKRBErrorRoundTrip 校验 KRB-ERROR 编码、解码与哨兵映射。
func TestKRBErrorRoundTrip(t *testing.T) {
	ctime := sampleTime()
	cusec := int32(123456)
	krbErr := KRBError{
		PVNO:      PVNO,
		MsgType:   MessageTypeKRBError,
		CTime:     &ctime,
		CUSec:     &cusec,
		STime:     sampleTime(),
		SUSec:     654321,
		ErrorCode: 25,
		CRealm:    "EXAMPLE.COM",
		CName:     principalPointer(NewPrincipalName(NameTypePrincipal, "alice")),
		Realm:     "EXAMPLE.COM",
		SName:     NewPrincipalName(NameTypeSRVInst, "krbtgt", "EXAMPLE.COM"),
		EText:     "need pre-authentication",
		EData:     []byte{0x30, 0x05, 0xA0, 0x03, 0x02, 0x01, 0x01},
	}
	encoded, err := krbErr.Marshal()
	if err != nil {
		t.Fatalf("Marshal: %v", err)
	}
	if encoded[0] != 0x7E {
		t.Fatalf("application tag = 0x%02x, want 0x7E", encoded[0])
	}
	decoded, err := ParseKRBError(encoded)
	if err != nil {
		t.Fatalf("ParseKRBError: %v", err)
	}
	if !reflect.DeepEqual(decoded, krbErr) {
		t.Fatalf("decoded = %#v, want %#v", decoded, krbErr)
	}
	if !errors.Is(decoded, ErrPreAuthRequired) {
		t.Fatal("KRB-ERROR is not classified as ErrPreAuthRequired")
	}
	if !errors.Is(decoded.Err(), ErrPreAuthRequired) {
		t.Fatal("KRB-ERROR.Err() is not classified as ErrPreAuthRequired")
	}
	if ErrorCodeName(decoded.ErrorCode) != "KDC_ERR_PREAUTH_REQUIRED" {
		t.Fatalf("ErrorCodeName = %q", ErrorCodeName(decoded.ErrorCode))
	}
	if ErrorCodeName(9999) != "" {
		t.Fatal("ErrorCodeName(9999) is not empty")
	}
}

// TestSentinelForCode verifies the RFC 4120 error code mapping. | TestSentinelForCode
// 校验 RFC 4120 错误码映射。
func TestSentinelForCode(t *testing.T) {
	tests := []struct {
		code int32
		want error
	}{
		{6, ErrClientNotFound},
		{7, ErrServerNotFound},
		{8, ErrPrincipalNotUnique},
		{14, ErrETypeNotSupported},
		{18, ErrClientRevoked},
		{23, ErrKeyExpired},
		{24, ErrPreAuthFailed},
		{25, ErrPreAuthRequired},
		{31, ErrBadIntegrity},
		{32, ErrTicketExpired},
		{33, ErrTicketNotYetValid},
		{34, ErrReplay},
		{35, ErrTicketNotForUs},
		{36, ErrTicketMismatch},
		{37, ErrClockSkew},
		{44, ErrBadKVNO},
		{45, ErrNoKey},
		{46, ErrMutualAuthFailed},
		{52, ErrResponseTooBig},
		{60, ErrKRBError},
		{9999, ErrKRBError},
	}
	for _, test := range tests {
		if got := sentinelForCode(test.code); !errors.Is(got, test.want) {
			t.Errorf("sentinelForCode(%d) = %v, want %v", test.code, got, test.want)
		}
	}
}

// TestEncTicketPartRoundTrip verifies the encrypted ticket body codec. |
// TestEncTicketPartRoundTrip 校验票据加密主体编解码。
func TestEncTicketPartRoundTrip(t *testing.T) {
	now := sampleTime()
	start := now
	renew := NewKerberosTime(now.Add(time.Hour))
	part := EncTicketPart{
		Flags:             TicketFlagForwardable | TicketFlagRenewable,
		Key:               sampleKey(t, ETypeRC4HMAC, 0x55),
		CRealm:            "EXAMPLE.COM",
		CName:             NewPrincipalName(NameTypePrincipal, "alice", "admin"),
		Transited:         TransitedEncoding{TrType: 1, Contents: []byte{0xAA, 0xBB}},
		AuthTime:          now,
		StartTime:         &start,
		EndTime:           NewKerberosTime(now.Add(2 * time.Hour)),
		RenewTill:         &renew,
		CAddr:             []HostAddress{{AddrType: 2, Address: []byte{127, 0, 0, 1}}, {AddrType: 20, Address: []byte{0, 1, 2, 3}}},
		AuthorizationData: []TypedData{{DataType: 2, DataValue: []byte{1}}, {DataType: 3, DataValue: nil}},
	}
	encoded := appendEncTicketPart(part)
	decoded, err := parseEncTicketPart(encoded)
	if err != nil {
		t.Fatalf("parseEncTicketPart: %v", err)
	}
	if !reflect.DeepEqual(decoded, part) {
		t.Fatalf("decoded = %#v, want %#v", decoded, part)
	}
	if _, err := parseEncTicketPart(encoded[:len(encoded)-1]); !negotiationError(err) {
		t.Fatalf("truncated parse error = %v, want ASN.1 failure", err)
	}
}

// TestAuthenticatorRoundTrip verifies the authenticator codec. |
// TestAuthenticatorRoundTrip 校验认证器编解码。
func TestAuthenticatorRoundTrip(t *testing.T) {
	now := sampleTime()
	subKey := sampleKey(t, ETypeAES128CTS, 0x66)
	sequence := uint32(0x01020304)
	usec := int32(424242)
	auth := Authenticator{
		AuthenticatorVNO: PVNO,
		CRealm:           "EXAMPLE.COM",
		CName:            NewPrincipalName(NameTypePrincipal, "alice"),
		Cksum:            &Checksum{CksumType: ChecksumTypeGSSAPI, Checksum: bytes.Repeat([]byte{0x77}, 24)},
		CUSec:            usec,
		CTime:            now,
		SubKey:           &subKey,
		SeqNumber:        &sequence,
		AuthorizationData: []TypedData{
			{DataType: 4, DataValue: []byte{9, 9}},
		},
	}
	encoded := appendAuthenticator(nil, auth)
	decoded, err := parseAuthenticator(encoded)
	if err != nil {
		t.Fatalf("parseAuthenticator: %v", err)
	}
	if !reflect.DeepEqual(decoded, auth) {
		t.Fatalf("decoded = %#v, want %#v", decoded, auth)
	}
	minimal := Authenticator{AuthenticatorVNO: PVNO, CRealm: "R", CName: NewPrincipalName(NameTypePrincipal, "bob"), CTime: now}
	decoded, err = parseAuthenticator(appendAuthenticator(nil, minimal))
	if err != nil {
		t.Fatalf("minimal parseAuthenticator: %v", err)
	}
	if decoded.Cksum != nil || decoded.SubKey != nil || decoded.SeqNumber != nil || len(decoded.AuthorizationData) != 0 {
		t.Fatalf("minimal decoded = %#v", decoded)
	}
}

// TestEncAPRepPartRoundTrip verifies the AP-REP encrypted body codec. |
// TestEncAPRepPartRoundTrip 校验 AP-REP 加密主体编解码。
func TestEncAPRepPartRoundTrip(t *testing.T) {
	subKey := sampleKey(t, ETypeAES256CTS, 0x88)
	sequence := uint32(77)
	part := EncAPRepPart{
		CTime:     sampleTime(),
		CUSec:     999,
		SubKey:    &subKey,
		SeqNumber: &sequence,
	}
	decoded, err := parseEncAPRepPart(appendEncAPRepPart(part))
	if err != nil {
		t.Fatalf("parseEncAPRepPart: %v", err)
	}
	if !reflect.DeepEqual(decoded, part) {
		t.Fatalf("decoded = %#v, want %#v", decoded, part)
	}
	minimal := EncAPRepPart{CTime: sampleTime(), CUSec: 1}
	decoded, err = parseEncAPRepPart(appendEncAPRepPart(minimal))
	if err != nil {
		t.Fatalf("minimal parseEncAPRepPart: %v", err)
	}
	if decoded.SubKey != nil || decoded.SeqNumber != nil {
		t.Fatalf("minimal decoded = %#v", decoded)
	}
}

// TestEncKDCRepPartRoundTrip verifies both AS-REP and TGS-REP encrypted bodies. |
// TestEncKDCRepPartRoundTrip 校验 AS-REP 与 TGS-REP 加密主体。
func TestEncKDCRepPartRoundTrip(t *testing.T) {
	now := sampleTime()
	start := now
	renew := NewKerberosTime(now.Add(time.Hour))
	expiry := NewKerberosTime(now.Add(30 * time.Minute))
	part := EncKDCRepPart{
		Key:           sampleKey(t, ETypeAES256CTS, 0x99),
		LastReq:       []LastReq{{LRType: 0, LRValue: now}, {LRType: 1, LRValue: now}},
		Nonce:         424242,
		KeyExpiration: &expiry,
		Flags:         TicketFlagInitial | TicketFlagPreAuthent,
		AuthTime:      now,
		StartTime:     &start,
		EndTime:       NewKerberosTime(now.Add(10 * time.Hour)),
		RenewTill:     &renew,
		SRealm:        "EXAMPLE.COM",
		SName:         NewPrincipalName(NameTypeSRVInst, "ldap", "dc1.example.com"),
		CAddr:         []HostAddress{{AddrType: 2, Address: []byte{192, 0, 2, 1}}},
	}
	for _, application := range []int{25, 26} {
		encoded := appendEncKDCRepPart(part, application)
		decoded, err := parseEncKDCRepPart(encoded, application)
		if err != nil {
			t.Fatalf("parseEncKDCRepPart(%d): %v", application, err)
		}
		if !reflect.DeepEqual(decoded, part) {
			t.Fatalf("application %d decoded = %#v, want %#v", application, decoded, part)
		}
		other := 25
		if application == 25 {
			other = 26
		}
		if _, err := parseEncKDCRepPart(encoded, other); err != nil {
			t.Fatalf("application %d did not accept the MIT-compatible tag %d: %v", application, other, err)
		}
		if _, err := parseEncKDCRepPart(encoded, 27); err == nil {
			t.Fatalf("application %d accepted the wrong application tag 27", application)
		}
	}
}

// TestParseAPReqErrors rejects structurally invalid AP-REQs. | TestParseAPReqErrors
// 拒绝结构非法的 AP-REQ。
func TestParseAPReqErrors(t *testing.T) {
	req := APReq{
		Ticket:        sampleTicket(t),
		Authenticator: EncryptedData{EType: ETypeAES256CTS, Cipher: []byte{1}},
	}
	encoded, err := req.Marshal()
	if err != nil {
		t.Fatalf("Marshal: %v", err)
	}
	if _, err := ParseAPReq(encoded[:len(encoded)-5]); err == nil {
		t.Fatal("ParseAPReq accepted a truncated message")
	}
	if _, err := ParseAPReq(append([]byte{0x00}, encoded[1:]...)); err == nil {
		t.Fatal("ParseAPReq accepted a wrong application tag")
	}
}

// principalPointer returns a pointer to a copy of principal. | principalPointer 返回
// principal 副本的指针。
func principalPointer(principal PrincipalName) *PrincipalName {
	return &principal
}

// messageError reports whether err is a malformed-message classification. |
// messageError 报告 err 是否属于畸形消息分类。
func messageError(err error) bool {
	return errors.Is(err, ErrInvalidMessage) || errors.Is(err, ErrASN1) || errors.Is(err, ErrTrailingData)
}

// TestKerberosFlagsWireOrder pins the RFC 4120 KerberosFlags bit order. The
// exported constants use RFC bit numbers, while BIT STRING encoding starts at
// the most significant bit. | TestKerberosFlagsWireOrder 固定 RFC 4120
// KerberosFlags 的位顺序。导出常量使用 RFC 位号，而 BIT STRING 编码从最高位开始。
func TestKerberosFlagsWireOrder(t *testing.T) {
	encoded := derAppendKerberosFlags(nil, uint32(KDCOptionForwardable|KDCOptionRenewable))
	if want := mustHex(t, "03050040800000"); !bytes.Equal(encoded, want) {
		t.Fatalf("KDC options = %x, want %x", encoded, want)
	}
	decoded, err := readKerberosFlags(encoded[2:])
	if err != nil {
		t.Fatalf("readKerberosFlags: %v", err)
	}
	options := KDCOptions(decoded)
	if !options.Has(KDCOptionForwardable) || !options.Has(KDCOptionRenewable) {
		t.Fatalf("decoded KDC options = 0x%08x", decoded)
	}
	if decoded != uint32(KDCOptionForwardable|KDCOptionRenewable) {
		t.Fatalf("decoded KDC options = 0x%08x, want 0x%08x", decoded, uint32(KDCOptionForwardable|KDCOptionRenewable))
	}
	ap := derAppendKerberosFlags(nil, uint32(APOptionMutualRequired))
	if want := mustHex(t, "03050020000000"); !bytes.Equal(ap, want) {
		t.Fatalf("AP options = %x, want %x", ap, want)
	}
	if !APOptions(APOptionMutualRequired).Has(APOptionMutualRequired) {
		t.Fatal("APOptionMutualRequired is not detected")
	}
}

// TestRandomNonceStaysInSignedRange keeps nonces interoperable with MIT krb5
// and Heimdal, which decode them as signed 32-bit integers. |
// TestRandomNonceStaysInSignedRange 让 nonce 与 MIT krb5 及 Heimdal 可互操作，
// 它们把 nonce 解码为有符号 32 位整数。
func TestRandomNonceStaysInSignedRange(t *testing.T) {
	for i := 0; i < 1000; i++ {
		nonce, err := randomUint32()
		if err != nil {
			t.Fatalf("randomUint32: %v", err)
		}
		if nonce == 0 || nonce > 0x7FFFFFFF {
			t.Fatalf("nonce %d is outside the interoperable signed range", nonce)
		}
	}
}
