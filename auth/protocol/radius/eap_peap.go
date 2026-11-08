package radius

import (
	"context"

	"github.com/shibingli/ydx/errs"
)

// eapPEAPState holds tunneled-authentication state for one PEAPv0 conversation. | eapPEAPState 保存
// 一次 PEAPv0 交互的隧道认证状态。
type eapPEAPState struct {
	keys      *MSCHAPv2ServerResult
	userName  string
	challenge []byte
	response  []byte
	ident     uint8
	stage     uint8
}

// PEAP inner EAP-MSCHAPv2 stages. | PEAP 内部 EAP-MSCHAPv2 阶段。
const (
	peapStageChallenge = iota
	peapStageSuccess
)

// processEAPPEAPLocked advances a PEAPv0 conversation. The caller must hold session.mu. |
// processEAPPEAPLocked 推进 PEAPv0 交互。调用方必须持有 session.mu。
func (s *EAPServer) processEAPPEAPLocked(ctx context.Context, session *eapSession, packet *EAPPacket) (*AccessServerResult, error) {
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
				return s.beginPEAPLocked(ctx, session, packet.Identifier)
			}
		case EAPPhasePEAPSuccess:
			return s.peapCompleteLocked(session, packet.Identifier)
		}
		return s.failureLocked(session, packet.Identifier, 0)
	}
	if incomplete {
		return s.tlsAcknowledgementLocked(session, EAPTypePEAP, packet.Identifier)
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
				return s.tlsAcknowledgementLocked(session, EAPTypePEAP, packet.Identifier)
			}
			return s.sendTLSFlightLocked(session, EAPTypePEAP, out, EAPPhaseTLSHandshake)
		}
		if handshakeErr != nil || !established {
			return s.failureLocked(session, packet.Identifier, 0)
		}
		session.tlsDone = true
		if len(out) != 0 {
			return s.sendTLSFlightLocked(session, EAPTypePEAP, out, EAPPhaseTLSHandshake)
		}
		return s.beginPEAPLocked(ctx, session, packet.Identifier)
	case EAPPhasePEAPIdentity, EAPPhasePEAPMSCHAPv2:
		return s.processPEAPInnerLocked(ctx, session, message, packet.Identifier)
	case EAPPhasePEAPSuccess:
		return s.failureLocked(session, packet.Identifier, 0)
	default:
		return s.failureLocked(session, packet.Identifier, 0)
	}
}

// beginPEAPLocked establishes the PEAP tunnel and requests the inner identity. The caller must hold
// session.mu. | beginPEAPLocked 建立 PEAP 隧道并请求内部身份。调用方必须持有 session.mu。
func (s *EAPServer) beginPEAPLocked(ctx context.Context, session *eapSession, identifier uint8) (*AccessServerResult, error) {
	state, ok := session.tls.connectionState()
	if !ok {
		return s.failureLocked(session, identifier, 0)
	}
	if s.requireClient && len(state.PeerCertificates) == 0 {
		return s.failureLocked(session, identifier, 0)
	}
	if s.password == nil {
		return s.failureLocked(session, identifier, 0)
	}
	session.tlsPost = true
	session.phase = EAPPhasePEAPIdentity
	session.peap = &eapPEAPState{userName: session.username}
	innerIdentifier := session.nextIdentifier()
	session.requestID = innerIdentifier
	request := newEAPRequest(innerIdentifier, EAPTypeIdentity, nil)
	return s.sendPEAPInnerLocked(ctx, session, request, EAPPhasePEAPIdentity)
}

// processPEAPInnerLocked handles one inner EAP packet. The caller must hold session.mu. |
// processPEAPInnerLocked 处理一个内部 EAP 报文。调用方必须持有 session.mu。
func (s *EAPServer) processPEAPInnerLocked(ctx context.Context, session *eapSession, message []byte, identifier uint8) (*AccessServerResult, error) {
	defer zeroBytes(message)
	output, err := session.tls.feedApplication(ctx, message)
	if err != nil {
		return s.failureLocked(session, identifier, 0)
	}
	if len(output) != 0 {
		return s.sendTLSFlightLocked(session, EAPTypePEAP, output, session.phase)
	}
	inner, err := readPEAPInnerPacket(ctx, session.tls)
	if err != nil {
		return s.failureLocked(session, identifier, 0)
	}
	peap := session.peap
	if peap == nil || inner.Code != EAPCodeResponse {
		return s.failureLocked(session, identifier, 0)
	}
	switch session.phase {
	case EAPPhasePEAPIdentity:
		if inner.Type != EAPTypeIdentity {
			return s.failureLocked(session, identifier, 0)
		}
		userName, err := EAPResponseIdentity(inner)
		if err != nil {
			return s.failureLocked(session, identifier, 0)
		}
		peap.userName = userName
		challenge, err := GenerateMSCHAPv2Challenge()
		if err != nil {
			return nil, err
		}
		peap.challenge = append([]byte(nil), challenge[:]...)
		challengeIdentifier := session.nextIdentifier()
		peap.ident = challengeIdentifier
		peap.stage = peapStageChallenge
		session.phase = EAPPhasePEAPMSCHAPv2
		data := make([]byte, 0, 18+len("radius"))
		data = append(data, 1, challengeIdentifier)
		data = append(data, challenge[:]...)
		data = append(data, "radius"...)
		request := newEAPRequest(challengeIdentifier, EAPTypeMSCHAPv2, data)
		return s.sendPEAPInnerLocked(ctx, session, request, EAPPhasePEAPMSCHAPv2)
	case EAPPhasePEAPMSCHAPv2:
		if inner.Type != EAPTypeMSCHAPv2 {
			return s.failureLocked(session, identifier, 0)
		}
		switch peap.stage {
		case peapStageChallenge:
			return s.processPEAPMSCHAPResponseLocked(ctx, session, inner, identifier)
		case peapStageSuccess:
			if len(inner.Data) != 0 {
				return s.failureLocked(session, identifier, 0)
			}
			success := newEAPSuccess(peap.ident)
			session.phase = EAPPhasePEAPSuccess
			return s.sendPEAPInnerLocked(ctx, session, success, EAPPhasePEAPSuccess)
		}
	}
	return s.failureLocked(session, identifier, 0)
}

// processPEAPMSCHAPResponseLocked verifies the inner EAP-MSCHAPv2 Response. The caller must hold
// session.mu. | processPEAPMSCHAPResponseLocked 校验内部 EAP-MSCHAPv2 Response。调用方必须持有
// session.mu。
func (s *EAPServer) processPEAPMSCHAPResponseLocked(ctx context.Context, session *eapSession, inner *EAPPacket, identifier uint8) (*AccessServerResult, error) {
	peap := session.peap
	if len(inner.Data) != 52 || inner.Data[0] != 2 || inner.Data[1] != peap.ident {
		return s.failureLocked(session, identifier, 0)
	}
	response := make([]byte, msCHAPv2ResponseLength)
	response[0] = inner.Data[1]
	response[1] = inner.Data[2]
	copy(response[2:18], inner.Data[3:19])
	copy(response[18:26], inner.Data[19:27])
	copy(response[26:50], inner.Data[27:51])
	defer zeroBytes(response)
	password, err := lookupEAPPassword(ctx, s.password, peap.userName)
	if err != nil {
		return s.failureLocked(session, identifier, 0)
	}
	defer zeroBytes(password)
	result, err := VerifyMSCHAPv2Server(peap.userName, string(password), peap.challenge, response)
	if err != nil || !result.Succeeded() {
		return s.failureLocked(session, identifier, 0)
	}
	peap.keys = result
	peap.response = append([]byte(nil), response...)
	peap.stage = peapStageSuccess
	successData := make([]byte, 0, 2+len(result.AuthenticatorResponse))
	successData = append(successData, 3, peap.ident)
	successData = append(successData, result.AuthenticatorResponse...)
	request := newEAPRequest(peap.ident, EAPTypeMSCHAPv2, successData)
	return s.sendPEAPInnerLocked(ctx, session, request, EAPPhasePEAPMSCHAPv2)
}

// sendPEAPInnerLocked encrypts one inner EAP packet and sends it as an outer TLS flight. The caller
// must hold session.mu. | sendPEAPInnerLocked 加密一个内部 EAP 报文并作为外层 TLS 飞行发送。调用方
// 必须持有 session.mu。
func (s *EAPServer) sendPEAPInnerLocked(ctx context.Context, session *eapSession, packet *EAPPacket, phase EAPPhase) (*AccessServerResult, error) {
	raw, err := packet.MarshalBinary()
	if err != nil {
		return nil, err
	}
	out, err := session.tls.writeApplication(ctx, raw)
	if err != nil {
		return s.failureLocked(session, packet.Identifier, 0)
	}
	if len(out) == 0 {
		return nil, errs.Detail(ErrInternal, "PEAP inner packet produced no TLS data")
	}
	return s.sendTLSFlightLocked(session, EAPTypePEAP, out, phase)
}

// readPEAPInnerPacket reads one complete tunneled EAP packet, joining TLS reads when necessary. |
// readPEAPInnerPacket 读取一个完整隧道 EAP 报文，必要时合并多次 TLS 读取。
func readPEAPInnerPacket(ctx context.Context, engine *eapTLSEngine) (*EAPPacket, error) {
	var buffer []byte
	for {
		chunk, err := engine.readApplication(ctx)
		if err != nil {
			return nil, err
		}
		if len(buffer)+len(chunk) > MaxEAPPacketLength {
			return nil, errs.Detail(ErrInvalidPacket, "PEAP inner EAP message exceeds %d octets", MaxEAPPacketLength)
		}
		buffer = append(buffer, chunk...)
		if len(buffer) < EAPHeaderLength {
			continue
		}
		declared := int(buffer[2])<<8 | int(buffer[3])
		if declared < EAPHeaderLength {
			return nil, errs.Detail(ErrInvalidPacket, "PEAP inner EAP length %d is below %d", declared, EAPHeaderLength)
		}
		if len(buffer) < declared {
			continue
		}
		if len(buffer) > declared {
			return nil, errs.Detail(ErrInvalidPacket, "PEAP inner EAP packet has %d trailing octets", len(buffer)-declared)
		}
		return ParseEAPPacket(buffer)
	}
}

// peapCompleteLocked returns the outer EAP-Success for an authenticated PEAP tunnel. The caller must
// hold session.mu. | peapCompleteLocked 为已认证 PEAP 隧道返回外层 EAP-Success。调用方必须持有
// session.mu。
func (s *EAPServer) peapCompleteLocked(session *eapSession, identifier uint8) (*AccessServerResult, error) {
	peap := session.peap
	if peap == nil || peap.userName == "" {
		return s.failureLocked(session, identifier, 0)
	}
	session.identity = peap.userName
	return s.successLocked(session, identifier, peap.keys, peap.userName)
}
