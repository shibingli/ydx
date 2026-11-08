package radius

import (
	"context"

	"github.com/shibingli/ydx/errs"
)

// processEAPTLSLocked advances an EAP-TLS conversation. The caller must hold session.mu. |
// processEAPTLSLocked 推进 EAP-TLS 交互。调用方必须持有 session.mu。
func (s *EAPServer) processEAPTLSLocked(ctx context.Context, session *eapSession, packet *EAPPacket) (*AccessServerResult, error) {
	empty, message, incomplete, err := s.inboundTLSMessageLocked(session, packet)
	if err != nil {
		return s.failureLocked(session, packet.Identifier, 0)
	}
	if empty {
		if result, advanced, err := s.advanceTLSQueueLocked(session); advanced || err != nil {
			return result, err
		}
		if session.tlsDone && session.phase == EAPPhaseTLSComplete {
			return s.tlsSuccessLocked(session, packet.Identifier)
		}
		return s.failureLocked(session, packet.Identifier, 0)
	}
	if incomplete {
		return s.tlsAcknowledgementLocked(session, EAPTypeTLS, packet.Identifier)
	}
	if session.tlsDone {
		// After the TLS handshake the only permitted peer message is the final empty acknowledgement
		// of the server's last flight. | TLS 握手完成后，对端唯一合法的消息是对服务器最后飞行的空确认。
		return s.failureLocked(session, packet.Identifier, 0)
	}
	out, err := session.tls.processHandshake(ctx, message)
	if err != nil {
		return s.failureLocked(session, packet.Identifier, 0)
	}
	done, handshakeErr, established := session.tls.status()
	if !done {
		if len(out) == 0 {
			return s.tlsAcknowledgementLocked(session, EAPTypeTLS, packet.Identifier)
		}
		return s.sendTLSFlightLocked(session, EAPTypeTLS, out, EAPPhaseTLSHandshake)
	}
	if handshakeErr != nil || !established {
		return s.failureLocked(session, packet.Identifier, 0)
	}
	session.tlsDone = true
	if len(out) != 0 {
		return s.sendTLSFlightLocked(session, EAPTypeTLS, out, EAPPhaseTLSComplete)
	}
	return s.tlsSuccessLocked(session, packet.Identifier)
}

// tlsSuccessLocked completes EAP-TLS and extracts the authenticated identity. The caller must hold
// session.mu. | tlsSuccessLocked 完成 EAP-TLS 并提取认证身份。调用方必须持有 session.mu。
func (s *EAPServer) tlsSuccessLocked(session *eapSession, identifier uint8) (*AccessServerResult, error) {
	state, ok := session.tls.connectionState()
	if !ok {
		return s.failureLocked(session, identifier, 0)
	}
	if s.requireClient && len(state.PeerCertificates) == 0 {
		return s.failureLocked(session, identifier, 0)
	}
	identity := session.username
	if len(state.PeerCertificates) > 0 {
		if extracted := s.certificateIdentity(state.PeerCertificates[0]); extracted != "" {
			identity = extracted
		}
	}
	if identity == "" {
		return s.failureLocked(session, identifier, 0)
	}
	session.identity = identity
	return s.successLocked(session, identifier, nil, identity)
}

// inboundTLSMessageLocked parses one peer TLS method value and reassembles fragmented peer messages.
// It reports an empty acknowledgement, a complete message, or an incomplete fragment that needs an
// acknowledgement. The caller must hold session.mu. | inboundTLSMessageLocked 解析一个对端 TLS 方法值并
// 重组分片消息。它报告空确认、完整消息或需要确认的未完成分片。调用方必须持有 session.mu。
func (s *EAPServer) inboundTLSMessageLocked(session *eapSession, packet *EAPPacket) (empty bool, message []byte, incomplete bool, err error) {
	flags, total, payload, err := parseTLSPayload(packet.Data, false)
	if err != nil {
		return false, nil, false, err
	}
	if flags&(EAPTLSFlagLength|EAPTLSFlagMore) != 0 && len(payload) == 0 {
		return false, nil, false, errs.Detail(ErrInvalidRequest, "EAP TLS fragment is empty")
	}
	if len(payload) == 0 {
		return true, nil, false, nil
	}
	if len(session.tlsQueue) != 0 {
		return false, nil, false, errs.Detail(ErrInvalidRequest, "peer sent TLS data before acknowledging the server flight")
	}
	complete, assembled, err := session.tlsAssembler.add(flags, total, payload)
	if err != nil {
		return false, nil, false, err
	}
	if !complete {
		return false, nil, true, nil
	}
	return false, assembled, false, nil
}

// advanceTLSQueueLocked sends the next queued server fragment, if any. The caller must hold
// session.mu. | advanceTLSQueueLocked 发送下一个排队服务器分片（如有）。调用方必须持有 session.mu。
func (s *EAPServer) advanceTLSQueueLocked(session *eapSession) (*AccessServerResult, bool, error) {
	if len(session.tlsQueue) == 0 {
		return nil, false, nil
	}
	fragment := session.tlsQueue[0]
	session.tlsQueue = session.tlsQueue[1:]
	identifier := session.nextIdentifier()
	session.requestID = identifier
	result, err := s.tlsRequestResultLocked(session, session.tlsMethod, fragment, identifier)
	return result, true, err
}

// sendTLSFlightLocked fragments and sends one outbound TLS flight. The caller must hold
// session.mu. | sendTLSFlightLocked 分片并发送一个出站 TLS 飞行。调用方必须持有 session.mu。
func (s *EAPServer) sendTLSFlightLocked(session *eapSession, method EAPType, data []byte, phase EAPPhase) (*AccessServerResult, error) {
	fragments, err := fragmentTLSData(data, s.fragmentSize, false)
	if err != nil {
		return nil, err
	}
	if len(fragments) == 0 {
		return nil, errs.Detail(ErrInternal, "EAP TLS flight is empty")
	}
	session.tlsMethod = method
	session.phase = phase
	session.tlsQueue = append(session.tlsQueue[:0], fragments[1:]...)
	identifier := session.nextIdentifier()
	session.requestID = identifier
	return s.tlsRequestResultLocked(session, method, fragments[0], identifier)
}

// tlsAcknowledgementLocked sends an empty TLS Request acknowledging a peer fragment. The caller must
// hold session.mu. | tlsAcknowledgementLocked 发送空 TLS Request 以确认对端分片。调用方必须持有
// session.mu。
func (s *EAPServer) tlsAcknowledgementLocked(session *eapSession, method EAPType, identifier uint8) (*AccessServerResult, error) {
	requestIdentifier := session.nextIdentifier()
	session.requestID = requestIdentifier
	return s.requestResultLocked(session, method, []byte{0}, requestIdentifier)
}
