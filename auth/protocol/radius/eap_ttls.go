package radius

import (
	"context"
	"encoding/binary"

	"github.com/shibingli/ydx/errs"
)

// TTLSAVP flag bits. | TTLSAVP 标志位。
const (
	// TTLSAVPFlagVendor marks an AVP that carries a Vendor-Id. | TTLSAVPFlagVendor 标记携带
	// Vendor-Id 的 AVP。
	TTLSAVPFlagVendor byte = 0x80
	// TTLSAVPFlagMandatory marks an AVP whose understanding is required. | TTLSAVPFlagMandatory 标记
	// 必须理解的 AVP。
	TTLSAVPFlagMandatory byte = 0x40
)

// EAP-TTLS AVP codes. Codes below 256 reuse RADIUS attribute numbers; Microsoft authentication
// attributes are vendor-specific AVPs with Vendor-Id 311. | EAP-TTLS AVP 编码。小于 256 的编码复用
// RADIUS 属性号；Microsoft 认证属性是 Vendor-Id 为 311 的厂商专用 AVP。
const (
	// TTLSAVPCodeUserName is the User-Name AVP code (RADIUS attribute 1). | TTLSAVPCodeUserName
	// 是 User-Name AVP 编码（RADIUS 属性 1）。
	TTLSAVPCodeUserName uint32 = 1
	// TTLSAVPCodeUserPassword is the User-Password AVP code (RADIUS attribute 2). | TTLSAVPCodeUserPassword
	// 是 User-Password AVP 编码（RADIUS 属性 2）。
	TTLSAVPCodeUserPassword uint32 = 2
	// TTLSAVPCodeState is the State AVP code (RADIUS attribute 24). | TTLSAVPCodeState 是 State AVP
	// 编码（RADIUS 属性 24）。
	TTLSAVPCodeState uint32 = 24
	// TTLSAVPCodeMSCHAPChallenge is the vendor-specific MS-CHAP-Challenge AVP code. |
	// TTLSAVPCodeMSCHAPChallenge 是厂商专用 MS-CHAP-Challenge AVP 编码。
	TTLSAVPCodeMSCHAPChallenge uint32 = 11
	// TTLSAVPCodeMSCHAP2Response is the vendor-specific MS-CHAP2-Response AVP code. |
	// TTLSAVPCodeMSCHAP2Response 是厂商专用 MS-CHAP2-Response AVP 编码。
	TTLSAVPCodeMSCHAP2Response uint32 = 25
	// TTLSAVPCodeMSCHAP2Success is the vendor-specific MS-CHAP2-Success AVP code. |
	// TTLSAVPCodeMSCHAP2Success 是厂商专用 MS-CHAP2-Success AVP 编码。
	TTLSAVPCodeMSCHAP2Success uint32 = 26
	// TTLSAVPCodeMSMPPESendKey is the vendor-specific MS-MPPE-Send-Key AVP code. |
	// TTLSAVPCodeMSMPPESendKey 是厂商专用 MS-MPPE-Send-Key AVP 编码。
	TTLSAVPCodeMSMPPESendKey uint32 = 16
	// TTLSAVPCodeMSMPPERecvKey is the vendor-specific MS-MPPE-Recv-Key AVP code. |
	// TTLSAVPCodeMSMPPERecvKey 是厂商专用 MS-MPPE-Recv-Key AVP 编码。
	TTLSAVPCodeMSMPPERecvKey uint32 = 17
)

// TTLSAVP is one Diameter-style attribute-value pair carried inside an EAP-TTLS tunnel. |
// TTLSAVP 是 EAP-TTLS 隧道内携带的一个 Diameter 风格属性值对。
//
// The wire layout is Code(4) || Flags(1) || Length(3) || Vendor-Id(4 when VendorSpecific) || Value
// || zero padding to a four-octet boundary. Length excludes padding and includes the header and
// Vendor-Id. | 线格式为 Code(4) || Flags(1) || Length(3) || Vendor-Id（VendorSpecific 时 4 字节）||
// Value || 补齐到四字节边界的零。Length 不含补齐，包含头部与 Vendor-Id。
type TTLSAVP struct {
	// Value is the AVP data. | Value 是 AVP 数据。
	Value []byte
	// Code is the 24-bit AVP code. | Code 是 24 位 AVP 编码。
	Code uint32
	// VendorID is the Vendor-Id when VendorSpecific is set. | VendorID 是 VendorSpecific 时的 Vendor-Id。
	VendorID uint32
	// Mandatory requests that the peer understand the AVP. | Mandatory 要求对端理解该 AVP。
	Mandatory bool
	// VendorSpecific marks a vendor-specific AVP. | VendorSpecific 标记厂商专用 AVP。
	VendorSpecific bool
}

// MarshalBinary encodes a as one padded AVP. | MarshalBinary 将 a 编码为补齐后的一个 AVP。
func (a TTLSAVP) MarshalBinary() ([]byte, error) {
	if a.Code > 0xFFFFFF {
		return nil, errs.Detail(ErrInvalidAttribute, "TTLS AVP code %d exceeds 24 bits", a.Code)
	}
	header := 8
	if a.VendorSpecific {
		header += 4
	}
	length := header + len(a.Value)
	if length > 0xFFFFFF {
		return nil, errs.Detail(ErrInvalidAttribute, "TTLS AVP length %d exceeds 24 bits", length)
	}
	padded := (length + 3) &^ 3
	out := make([]byte, padded)
	binary.BigEndian.PutUint32(out[0:4], a.Code)
	if a.VendorSpecific {
		out[4] |= TTLSAVPFlagVendor
	}
	if a.Mandatory {
		out[4] |= TTLSAVPFlagMandatory
	}
	out[5] = byte(length >> 16)
	out[6] = byte(length >> 8)
	out[7] = byte(length)
	offset := 8
	if a.VendorSpecific {
		binary.BigEndian.PutUint32(out[8:12], a.VendorID)
		offset = 12
	}
	copy(out[offset:], a.Value)
	return out, nil
}

// MarshalTTLSAVPs encodes a sequence of AVPs. | MarshalTTLSAVPs 编码一组 AVP。
func MarshalTTLSAVPs(avps []TTLSAVP) ([]byte, error) {
	total := 0
	encoded := make([][]byte, len(avps))
	for i, avp := range avps {
		raw, err := avp.MarshalBinary()
		if err != nil {
			return nil, err
		}
		if total+len(raw) > MaxEAPPacketLength {
			return nil, errs.Detail(ErrInvalidRequest, "TTLS AVP sequence exceeds the EAP packet limit")
		}
		encoded[i] = raw
		total += len(raw)
	}
	out := make([]byte, 0, total)
	for _, raw := range encoded {
		out = append(out, raw...)
	}
	return out, nil
}

// ParseTTLSAVPs decodes every AVP in data. Padding must be zero and every AVP must fit inside data.
// | ParseTTLSAVPs 解码 data 中的全部 AVP。补齐必须为零，每个 AVP 必须位于 data 内。
func ParseTTLSAVPs(data []byte) ([]TTLSAVP, error) {
	var avps []TTLSAVP
	for offset := 0; offset < len(data); {
		remaining := len(data) - offset
		if remaining < 8 {
			return nil, errs.Detail(ErrInvalidAttribute, "TTLS AVP header needs 8 octets, have %d", remaining)
		}
		code := binary.BigEndian.Uint32(data[offset : offset+4])
		if code > 0xFFFFFF {
			return nil, errs.Detail(ErrInvalidAttribute, "TTLS AVP code %d exceeds 24 bits", code)
		}
		flags := data[offset+4]
		length := int(data[offset+5])<<16 | int(data[offset+6])<<8 | int(data[offset+7])
		if length < 8 {
			return nil, errs.Detail(ErrInvalidAttribute, "TTLS AVP length %d is below 8", length)
		}
		if length > remaining {
			return nil, errs.Detail(ErrInvalidAttribute, "TTLS AVP length %d exceeds remaining %d", length, remaining)
		}
		header := 8
		vendorSpecific := flags&TTLSAVPFlagVendor != 0
		if vendorSpecific {
			if length < 12 {
				return nil, errs.Detail(ErrInvalidAttribute, "vendor-specific TTLS AVP length %d is below 12", length)
			}
			header = 12
		}
		avp := TTLSAVP{
			Code:           code,
			Mandatory:      flags&TTLSAVPFlagMandatory != 0,
			VendorSpecific: vendorSpecific,
		}
		if vendorSpecific {
			avp.VendorID = binary.BigEndian.Uint32(data[offset+8 : offset+12])
		}
		avp.Value = append([]byte(nil), data[offset+header:offset+length]...)
		padded := (length + 3) &^ 3
		if padded > remaining {
			padded = remaining
		}
		for i := offset + length; i < offset+padded; i++ {
			if data[i] != 0 {
				return nil, errs.Detail(ErrInvalidAttribute, "TTLS AVP padding is not zero")
			}
		}
		avps = append(avps, avp)
		offset += padded
	}
	return avps, nil
}

// eapTTLSState holds phase-2 state for one EAP-TTLS tunnel. | eapTTLSState 保存一条 EAP-TTLS 隧道的
// 第二阶段状态。
type eapTTLSState struct {
	keys      *MSCHAPv2ServerResult
	userName  string
	challenge []byte
	response  []byte
	method    EAPType
	ident     uint8
}

// processEAPTTLSLocked advances an EAP-TTLS conversation. The caller must hold session.mu. |
// processEAPTTLSLocked 推进 EAP-TTLS 交互。调用方必须持有 session.mu。
func (s *EAPServer) processEAPTTLSLocked(ctx context.Context, session *eapSession, packet *EAPPacket) (*AccessServerResult, error) {
	empty, message, incomplete, err := s.inboundTLSMessageLocked(session, packet)
	if err != nil {
		return s.failureLocked(session, packet.Identifier, 0)
	}
	if empty {
		if result, advanced, err := s.advanceTLSQueueLocked(session); advanced || err != nil {
			return result, err
		}
		switch session.phase {
		case EAPPhaseTLSHandshake:
			if session.tlsDone && !session.tlsPost {
				return s.beginTTLSPhase2Locked(ctx, session, packet.Identifier)
			}
		case EAPPhaseTTLSSuccess:
			return s.ttlsCompleteLocked(session, packet.Identifier)
		}
		return s.failureLocked(session, packet.Identifier, 0)
	}
	if incomplete {
		return s.tlsAcknowledgementLocked(session, EAPTypeTTLS, packet.Identifier)
	}
	switch session.phase {
	case EAPPhaseTLSHandshake:
		if session.tlsDone {
			return s.failureLocked(session, packet.Identifier, 0)
		}
		out, err := session.tls.processHandshake(ctx, message)
		if err != nil {
			return s.failureLocked(session, packet.Identifier, 0)
		}
		done, handshakeErr, established := session.tls.status()
		if !done {
			if len(out) == 0 {
				return s.tlsAcknowledgementLocked(session, EAPTypeTTLS, packet.Identifier)
			}
			return s.sendTLSFlightLocked(session, EAPTypeTTLS, out, EAPPhaseTLSHandshake)
		}
		if handshakeErr != nil || !established {
			return s.failureLocked(session, packet.Identifier, 0)
		}
		session.tlsDone = true
		if len(out) != 0 {
			return s.sendTLSFlightLocked(session, EAPTypeTTLS, out, EAPPhaseTLSHandshake)
		}
		return s.beginTTLSPhase2Locked(ctx, session, packet.Identifier)
	case EAPPhaseTTLSPhase2:
		return s.processTTLSInnerLocked(ctx, session, message, packet.Identifier)
	case EAPPhaseTTLSSuccess:
		return s.failureLocked(session, packet.Identifier, 0)
	default:
		return s.failureLocked(session, packet.Identifier, 0)
	}
}

// beginTTLSPhase2Locked creates the phase-2 challenge or credential request. The caller must hold
// session.mu. | beginTTLSPhase2Locked 创建第二阶段挑战或凭据请求。调用方必须持有 session.mu。
func (s *EAPServer) beginTTLSPhase2Locked(ctx context.Context, session *eapSession, identifier uint8) (*AccessServerResult, error) {
	state, ok := session.tls.connectionState()
	if !ok {
		return s.failureLocked(session, identifier, 0)
	}
	if s.requireClient && len(state.PeerCertificates) == 0 {
		return s.failureLocked(session, identifier, 0)
	}
	if len(s.ttlsMethods) == 0 {
		return s.failureLocked(session, identifier, 0)
	}
	session.tlsPost = true
	session.phase = EAPPhaseTTLSPhase2
	inner := &eapTTLSState{method: s.ttlsMethods[0], userName: session.username}
	session.inner = inner
	var avps []TTLSAVP
	switch inner.method {
	case EAPTypeIdentity:
		avps = []TTLSAVP{
			{Code: TTLSAVPCodeUserName, Mandatory: true},
			{Code: TTLSAVPCodeUserPassword, Mandatory: true},
		}
	case EAPTypeMSCHAPv2:
		challenge, err := GenerateMSCHAPv2Challenge()
		if err != nil {
			return nil, err
		}
		inner.challenge = append([]byte(nil), challenge[:]...)
		avps = []TTLSAVP{
			{Code: TTLSAVPCodeUserName, Mandatory: true},
			{
				Code:           TTLSAVPCodeMSCHAPChallenge,
				Mandatory:      true,
				VendorSpecific: true,
				VendorID:       VendorMicrosoft,
				Value:          append([]byte(nil), challenge[:]...),
			},
		}
	default:
		return s.failureLocked(session, identifier, 0)
	}
	raw, err := MarshalTTLSAVPs(avps)
	if err != nil {
		return nil, err
	}
	out, err := session.tls.writeApplication(ctx, raw)
	if err != nil {
		return s.failureLocked(session, identifier, 0)
	}
	if len(out) == 0 {
		return nil, errs.Detail(ErrInternal, "TTLS phase-2 request produced no TLS data")
	}
	return s.sendTLSFlightLocked(session, EAPTypeTTLS, out, EAPPhaseTTLSPhase2)
}

// processTTLSInnerLocked verifies the phase-2 credential response and sends the phase-2 result. The
// caller must hold session.mu. | processTTLSInnerLocked 校验第二阶段凭据响应并发送第二阶段结果。调用方
// 必须持有 session.mu。
func (s *EAPServer) processTTLSInnerLocked(ctx context.Context, session *eapSession, message []byte, identifier uint8) (*AccessServerResult, error) {
	defer zeroBytes(message)
	output, err := session.tls.feedApplication(ctx, message)
	if err != nil {
		return s.failureLocked(session, identifier, 0)
	}
	if len(output) != 0 {
		return s.sendTLSFlightLocked(session, EAPTypeTTLS, output, EAPPhaseTTLSPhase2)
	}
	plain, err := session.tls.readApplication(ctx)
	if err != nil {
		return s.failureLocked(session, identifier, 0)
	}
	avps, err := ParseTTLSAVPs(plain)
	zeroBytes(plain)
	if err != nil {
		return s.failureLocked(session, identifier, 0)
	}
	if err := validateTTLSAVPs(avps); err != nil {
		return s.failureLocked(session, identifier, 0)
	}
	inner := session.inner
	if inner == nil {
		return s.failureLocked(session, identifier, 0)
	}
	switch inner.method {
	case EAPTypeIdentity:
		if err := s.verifyTTLSPAPLocked(ctx, session, avps); err != nil {
			return s.failureLocked(session, identifier, 0)
		}
	case EAPTypeMSCHAPv2:
		if err := s.verifyTTLSMSCHAPv2Locked(ctx, session, avps); err != nil {
			return s.failureLocked(session, identifier, 0)
		}
	default:
		return s.failureLocked(session, identifier, 0)
	}
	result, err := s.ttlsPhase2SuccessLocked(ctx, session, identifier)
	if err != nil {
		return nil, err
	}
	return result, nil
}

// verifyTTLSPAPLocked verifies User-Name and User-Password AVPs. The caller must hold session.mu. |
// verifyTTLSPAPLocked 校验 User-Name 与 User-Password AVP。调用方必须持有 session.mu。
func (s *EAPServer) verifyTTLSPAPLocked(ctx context.Context, session *eapSession, avps []TTLSAVP) error {
	userName := session.username
	if value, ok := firstTTLSAVP(avps, TTLSAVPCodeUserName, 0); ok && len(value) != 0 {
		userName = string(value)
	}
	if userName == "" {
		return errs.Detail(ErrInvalidRequest, "TTLS PAP user name is empty")
	}
	passwordValue, ok := firstTTLSAVP(avps, TTLSAVPCodeUserPassword, 0)
	if !ok {
		return errs.Detail(ErrInvalidRequest, "TTLS PAP password AVP is missing")
	}
	defer zeroBytes(passwordValue)
	expected, err := lookupEAPPassword(ctx, s.password, userName)
	if err != nil {
		return err
	}
	defer zeroBytes(expected)
	if !constantTimeEqual(expected, passwordValue) {
		return errs.Detail(ErrInvalidRequest, "TTLS PAP password mismatch")
	}
	session.inner.userName = userName
	session.username = userName
	return nil
}

// verifyTTLSMSCHAPv2Locked verifies a vendor-specific MS-CHAP2-Response AVP. The caller must hold
// session.mu. | verifyTTLSMSCHAPv2Locked 校验厂商专用 MS-CHAP2-Response AVP。调用方必须持有
// session.mu。
func (s *EAPServer) verifyTTLSMSCHAPv2Locked(ctx context.Context, session *eapSession, avps []TTLSAVP) error {
	inner := session.inner
	response, ok := firstTTLSAVP(avps, TTLSAVPCodeMSCHAP2Response, VendorMicrosoft)
	if !ok || len(response) != msCHAPv2ResponseLength {
		return errs.Detail(ErrInvalidAttribute, "TTLS MS-CHAP2-Response is missing or malformed")
	}
	if response[0] == 0 {
		return errs.Detail(ErrInvalidAttribute, "TTLS MS-CHAP2-Response identifier is zero")
	}
	if challenge, ok := firstTTLSAVP(avps, TTLSAVPCodeMSCHAPChallenge, VendorMicrosoft); ok && !constantTimeEqual(challenge, inner.challenge) {
		return errs.Detail(ErrInvalidAttribute, "TTLS MS-CHAP-Challenge mismatch")
	}
	userName := inner.userName
	if value, ok := firstTTLSAVP(avps, TTLSAVPCodeUserName, 0); ok && len(value) != 0 {
		userName = string(value)
	}
	if userName == "" {
		return errs.Detail(ErrInvalidRequest, "TTLS MS-CHAPv2 user name is empty")
	}
	password, err := lookupEAPPassword(ctx, s.password, userName)
	if err != nil {
		return err
	}
	defer zeroBytes(password)
	result, err := VerifyMSCHAPv2Server(userName, string(password), inner.challenge, response)
	if err != nil {
		return err
	}
	if !result.Succeeded() {
		return errs.Detail(ErrInvalidRequest, "TTLS MS-CHAPv2 authentication failed")
	}
	inner.userName = userName
	inner.ident = response[0]
	inner.response = append([]byte(nil), response...)
	inner.keys = result
	session.username = userName
	return nil
}

// ttlsPhase2SuccessLocked sends the phase-2 success AVPs and prepares the final EAP-Success. The
// caller must hold session.mu. | ttlsPhase2SuccessLocked 发送第二阶段成功 AVP 并准备最终 EAP-Success。
// 调用方必须持有 session.mu。
func (s *EAPServer) ttlsPhase2SuccessLocked(ctx context.Context, session *eapSession, identifier uint8) (*AccessServerResult, error) {
	inner := session.inner
	var avps []TTLSAVP
	if inner.method == EAPTypeMSCHAPv2 {
		if inner.keys == nil || len(inner.keys.AuthenticatorResponse) != 42 {
			return nil, errs.Detail(ErrInternal, "TTLS MS-CHAPv2 success response is unavailable")
		}
		successValue := make([]byte, 1+len(inner.keys.AuthenticatorResponse))
		successValue[0] = inner.ident
		copy(successValue[1:], inner.keys.AuthenticatorResponse)
		avps = append(avps, TTLSAVP{
			Code:           TTLSAVPCodeMSCHAP2Success,
			Mandatory:      true,
			VendorSpecific: true,
			VendorID:       VendorMicrosoft,
			Value:          successValue,
		})
		if len(inner.keys.MPPESendKey) != 0 {
			avps = append(avps, TTLSAVP{
				Code:           TTLSAVPCodeMSMPPESendKey,
				Mandatory:      true,
				VendorSpecific: true,
				VendorID:       VendorMicrosoft,
				Value:          append([]byte(nil), inner.keys.MPPESendKey...),
			})
		}
		if len(inner.keys.MPPERecvKey) != 0 {
			avps = append(avps, TTLSAVP{
				Code:           TTLSAVPCodeMSMPPERecvKey,
				Mandatory:      true,
				VendorSpecific: true,
				VendorID:       VendorMicrosoft,
				Value:          append([]byte(nil), inner.keys.MPPERecvKey...),
			})
		}
	} else {
		// A zero-length AVP is the RFC 5281 phase-2 success indication for non-EAP methods. |
		// 零长度 AVP 是 RFC 5281 非 EAP 方法的第二阶段成功指示。
		avps = append(avps, TTLSAVP{Code: 0, Mandatory: true})
	}
	raw, err := MarshalTTLSAVPs(avps)
	if err != nil {
		return nil, err
	}
	out, err := session.tls.writeApplication(ctx, raw)
	if err != nil {
		return s.failureLocked(session, identifier, 0)
	}
	session.phase = EAPPhaseTTLSSuccess
	if len(out) == 0 {
		return s.ttlsCompleteLocked(session, identifier)
	}
	return s.sendTLSFlightLocked(session, EAPTypeTTLS, out, EAPPhaseTTLSSuccess)
}

// ttlsCompleteLocked returns the outer EAP-Success for an authenticated tunnel. The caller must hold
// session.mu. | ttlsCompleteLocked 为已认证隧道返回外层 EAP-Success。调用方必须持有 session.mu。
func (s *EAPServer) ttlsCompleteLocked(session *eapSession, identifier uint8) (*AccessServerResult, error) {
	inner := session.inner
	if inner == nil {
		return s.failureLocked(session, identifier, 0)
	}
	session.identity = inner.userName
	return s.successLocked(session, identifier, inner.keys, inner.userName)
}

// firstTTLSAVP returns the first AVP with code and vendor. | firstTTLSAVP 返回首个匹配 code 与 vendor
// 的 AVP。
func firstTTLSAVP(avps []TTLSAVP, code, vendor uint32) ([]byte, bool) {
	for _, avp := range avps {
		if avp.Code != code {
			continue
		}
		if vendor == 0 && avp.VendorSpecific {
			continue
		}
		if vendor != 0 && (!avp.VendorSpecific || avp.VendorID != vendor) {
			continue
		}
		return avp.Value, true
	}
	return nil, false
}

// validateTTLSAVPs rejects unknown mandatory AVPs. | validateTTLSAVPs 拒绝未知的强制 AVP。
func validateTTLSAVPs(avps []TTLSAVP) error {
	for _, avp := range avps {
		if !avp.Mandatory {
			continue
		}
		if avp.VendorSpecific {
			if avp.VendorID == VendorMicrosoft {
				switch avp.Code {
				case TTLSAVPCodeMSCHAPChallenge, TTLSAVPCodeMSCHAP2Response, TTLSAVPCodeMSMPPESendKey, TTLSAVPCodeMSMPPERecvKey:
					continue
				}
			}
			return errs.Detail(ErrInvalidAttribute, "unknown mandatory TTLS vendor AVP %d", avp.Code)
		}
		switch avp.Code {
		case 0, TTLSAVPCodeUserName, TTLSAVPCodeUserPassword, TTLSAVPCodeState:
			continue
		}
		return errs.Detail(ErrInvalidAttribute, "unknown mandatory TTLS AVP %d", avp.Code)
	}
	return nil
}
