package radius

import (
	"bytes"
	"crypto/tls"
	"errors"
	"sync"
	"testing"
)

// sendPEAPInner encrypts one inner EAP packet and sends it as an outer PEAP Response. |
// sendPEAPInner 加密一个内部 EAP 报文并作为外层 PEAP Response 发送。
func sendPEAPInner(t *testing.T, conversation *eapConversation, client *eapTestTLSClient, inner *EAPPacket) *AccessServerResult {
	t.Helper()
	raw, err := inner.MarshalBinary()
	if err != nil {
		t.Fatalf("marshal inner EAP packet: %v", err)
	}
	encrypted := client.writeApplication(t, raw)
	return conversation.send(eapResponse(conversation.request, EAPTypePEAP, append([]byte{0}, encrypted...)))
}

// receivePEAPInner acknowledges server fragments and returns the decrypted inner EAP packet and final
// outer Request identifier. | receivePEAPInner 确认服务器分片，返回已解密内部 EAP 报文与最终外层
// Request 标识符。
func receivePEAPInner(t *testing.T, conversation *eapConversation, client *eapTestTLSClient, result *AccessServerResult) (*EAPPacket, *EAPPacket) {
	t.Helper()
	data, finalRequest := receiveTunnelApplication(t, conversation, client, EAPTypePEAP, result)
	inner, err := ParseEAPPacket(data)
	if err != nil {
		t.Fatalf("parse PEAP inner EAP packet: %v", err)
	}
	return inner, finalRequest
}

// runPEAPAuthentication performs a complete PEAPv0 EAP-MSCHAPv2 exchange. It returns the final result
// and the inner MS-CHAPv2 challenge used. | runPEAPAuthentication 执行完整 PEAPv0 EAP-MSCHAPv2 交互，
// 返回最终结果与所用内部 MS-CHAPv2 挑战。
func runPEAPAuthentication(t *testing.T, server *EAPServer, client *eapTestTLSClient, outerIdentity, userName, password string) (*AccessServerResult, []byte) {
	t.Helper()
	conversation := newEAPConversation(t, server, outerIdentity)
	phase2 := runEAPTunnelHandshake(t, conversation, client, EAPTypePEAP, outerIdentity)
	identityRequest, err := ParseEAPPacket(phase2)
	if err != nil {
		t.Fatalf("parse inner identity request: %v", err)
	}
	if identityRequest.Code != EAPCodeRequest || identityRequest.Type != EAPTypeIdentity {
		t.Fatalf("inner identity request = %+v", identityRequest)
	}
	identityResponse := newEAPResponse(identityRequest.Identifier, EAPTypeIdentity, []byte(userName))
	result := sendPEAPInner(t, conversation, client, identityResponse)
	if !result.Challenge {
		return result, nil
	}
	challengeRequest, _ := receivePEAPInner(t, conversation, client, result)
	if challengeRequest.Code != EAPCodeRequest || challengeRequest.Type != EAPTypeMSCHAPv2 || len(challengeRequest.Data) < 18 {
		t.Fatalf("inner MS-CHAPv2 challenge = %+v", challengeRequest)
	}
	challenge := append([]byte(nil), challengeRequest.Data[2:18]...)
	innerResponse := newEAPResponse(challengeRequest.Identifier, EAPTypeMSCHAPv2, eapMSCHAPv2Response(t, userName, password, challengeRequest))
	result = sendPEAPInner(t, conversation, client, innerResponse)
	if !result.Challenge {
		return result, challenge
	}
	successRequest, _ := receivePEAPInner(t, conversation, client, result)
	if successRequest.Code != EAPCodeRequest || successRequest.Type != EAPTypeMSCHAPv2 ||
		len(successRequest.Data) != 44 || successRequest.Data[0] != 3 {
		t.Fatalf("inner MS-CHAPv2 success request = %+v", successRequest)
	}
	ack := newEAPResponse(successRequest.Identifier, EAPTypeMSCHAPv2, nil)
	result = sendPEAPInner(t, conversation, client, ack)
	if !result.Challenge {
		return result, challenge
	}
	innerSuccess, finalRequest := receivePEAPInner(t, conversation, client, result)
	if innerSuccess.Code != EAPCodeSuccess {
		t.Fatalf("inner EAP success = %+v", innerSuccess)
	}
	final := conversation.send(eapResponse(finalRequest, EAPTypePEAP, []byte{0}))
	return final, challenge
}

func TestEAPPEAPAuthentication(t *testing.T) {
	pki := newEAPTestPKI(t)
	server := eapTestServer(t, EAPServerConfig{
		TLSConfig: &tls.Config{Certificates: []tls.Certificate{pki.serverCert}, MinVersion: tls.VersionTLS12},
		Methods:   []EAPType{EAPTypePEAP},
	})
	client := newEAPTestTLSClient(eapTLSClientConfig(pki, false, tls.VersionTLS12))
	final, challenge := runPEAPAuthentication(t, server, client, "outer-user", "alice", "s3cret")
	if !final.Accept {
		t.Fatalf("PEAP result = %+v", final)
	}
	if final.Identity != "alice" {
		t.Fatalf("PEAP identity = %q, want alice", final.Identity)
	}
	if len(final.MPPESendKey) != 16 || len(final.MPPERecvKey) != 16 {
		t.Fatalf("PEAP MPPE keys = %x/%x", final.MPPESendKey, final.MPPERecvKey)
	}
	if bytes.Equal(final.MPPESendKey, final.MPPERecvKey) {
		t.Fatal("PEAP MPPE keys are identical")
	}
	if len(challenge) != 16 {
		t.Fatalf("PEAP inner challenge length = %d", len(challenge))
	}
	if packet := eapPacketFromResult(t, final); packet.Code != EAPCodeSuccess {
		t.Fatalf("final EAP code = %d", packet.Code)
	}
}

func TestEAPPEAPSmallFragments(t *testing.T) {
	pki := newEAPTestPKI(t)
	server := eapTestServer(t, EAPServerConfig{
		TLSConfig:    &tls.Config{Certificates: []tls.Certificate{pki.serverCert}, MinVersion: tls.VersionTLS12},
		Methods:      []EAPType{EAPTypePEAP},
		FragmentSize: 48,
	})
	client := newEAPTestTLSClient(eapTLSClientConfig(pki, false, tls.VersionTLS12))
	final, _ := runPEAPAuthentication(t, server, client, "outer-user", "alice", "s3cret")
	if !final.Accept {
		t.Fatalf("fragmented PEAP result = %+v", final)
	}
}

func TestEAPPEAPWrongPassword(t *testing.T) {
	pki := newEAPTestPKI(t)
	server := eapTestServer(t, EAPServerConfig{
		TLSConfig: &tls.Config{Certificates: []tls.Certificate{pki.serverCert}, MinVersion: tls.VersionTLS12},
		Methods:   []EAPType{EAPTypePEAP},
	})
	client := newEAPTestTLSClient(eapTLSClientConfig(pki, false, tls.VersionTLS12))
	final, _ := runPEAPAuthentication(t, server, client, "outer-user", "alice", "wrong")
	if final.Accept {
		t.Fatalf("wrong PEAP password accepted: %+v", final)
	}
	if packet := eapPacketFromResult(t, final); packet.Code != EAPCodeFailure {
		t.Fatalf("final EAP code = %d, want Failure", packet.Code)
	}
}

func TestEAPPEAPUnknownUser(t *testing.T) {
	pki := newEAPTestPKI(t)
	server := eapTestServer(t, EAPServerConfig{
		TLSConfig: &tls.Config{Certificates: []tls.Certificate{pki.serverCert}, MinVersion: tls.VersionTLS12},
		Methods:   []EAPType{EAPTypePEAP},
	})
	client := newEAPTestTLSClient(eapTLSClientConfig(pki, false, tls.VersionTLS12))
	final, _ := runPEAPAuthentication(t, server, client, "outer-user", "nobody", "s3cret")
	if final.Accept {
		t.Fatalf("unknown PEAP user accepted: %+v", final)
	}
}

func TestEAPPEAPRequiresClientCertificate(t *testing.T) {
	pki := newEAPTestPKI(t)
	server := eapTestServer(t, EAPServerConfig{
		TLSConfig: &tls.Config{
			Certificates: []tls.Certificate{pki.serverCert},
			ClientAuth:   tls.RequireAndVerifyClientCert,
			ClientCAs:    pki.roots,
			MinVersion:   tls.VersionTLS12,
		},
		Methods:                  []EAPType{EAPTypePEAP},
		RequireClientCertificate: true,
	})
	client := newEAPTestTLSClient(eapTLSClientConfig(pki, true, tls.VersionTLS12))
	final, _ := runPEAPAuthentication(t, server, client, "outer-user", "alice", "s3cret")
	if !final.Accept {
		t.Fatalf("PEAP with client certificate rejected: %+v", final)
	}
}

func TestEAPPEAPConcurrentTunnels(t *testing.T) {
	pki := newEAPTestPKI(t)
	server := eapTestServer(t, EAPServerConfig{
		TLSConfig:   &tls.Config{Certificates: []tls.Certificate{pki.serverCert}, MinVersion: tls.VersionTLS12},
		Methods:     []EAPType{EAPTypePEAP},
		MaxSessions: 32,
	})
	const tunnels = 4
	var wg sync.WaitGroup
	failures := make(chan error, tunnels)
	for i := 0; i < tunnels; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			client := newEAPTestTLSClient(eapTLSClientConfig(pki, false, tls.VersionTLS12))
			final, _ := runPEAPAuthentication(t, server, client, "outer-user", "alice", "s3cret")
			if !final.Accept {
				failures <- errors.New("concurrent PEAP tunnel rejected")
			}
		}()
	}
	wg.Wait()
	close(failures)
	for err := range failures {
		t.Error(err)
	}
}
