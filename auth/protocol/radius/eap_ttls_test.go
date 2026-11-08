package radius

import (
	"bytes"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"testing"
	"time"
)

// runEAPTunnelHandshake performs the outer TLS handshake for EAP-TTLS or PEAP and returns the first
// decrypted tunneled application message. | runEAPTunnelHandshake 为 EAP-TTLS 或 PEAP 执行外层 TLS
// 握手，并返回首条已解密隧道应用消息。
func runEAPTunnelHandshake(t *testing.T, conversation *eapConversation, client *eapTestTLSClient, method EAPType, outerIdentity string) []byte {
	t.Helper()
	result := conversation.identity(outerIdentity)
	if !result.Challenge {
		t.Fatalf("identity result = %+v, want tunnel Start", result)
	}
	if conversation.request.Type != method {
		t.Fatalf("outer method = %d, want %d", conversation.request.Type, method)
	}
	clientFlight := client.handshakeOutput(t)
	response := eapResponse(conversation.request, method, append([]byte{0}, clientFlight...))
	appStarted := false
	for attempt := 0; attempt < 64; attempt++ {
		result = conversation.send(response)
		if !result.Challenge {
			t.Fatalf("tunnel handshake ended early: %+v", result)
		}
		serverFlight, finalRequest := conversation.collectServerTLS(method)
		clientOut := client.process(t, serverFlight)
		if !appStarted && client.handshakeDone() {
			client.startApplicationReader()
			appStarted = true
		}
		if appStarted {
			data, ok, err := client.readApplicationAvailable(50 * time.Millisecond)
			if err != nil {
				t.Fatalf("tunnel application read: %v", err)
			}
			if ok {
				conversation.request = finalRequest
				return data
			}
		}
		if len(clientOut) != 0 {
			response = eapResponse(finalRequest, method, append([]byte{0}, clientOut...))
		} else {
			response = eapResponse(finalRequest, method, []byte{0})
		}
	}
	t.Fatal("EAP tunnel handshake did not reach phase 2")
	return nil
}

// sendTunnelApplication sends one encrypted application message as an outer EAP Response. |
// sendTunnelApplication 将一条加密应用消息作为外层 EAP Response 发送。
func sendTunnelApplication(t *testing.T, conversation *eapConversation, client *eapTestTLSClient, method EAPType, data []byte) *AccessServerResult {
	t.Helper()
	encrypted := client.writeApplication(t, data)
	return conversation.send(eapResponse(conversation.request, method, append([]byte{0}, encrypted...)))
}

// receiveTunnelApplication acknowledges server TLS fragments and returns one decrypted application
// message plus the final server Request identifier. | receiveTunnelApplication 确认服务器 TLS 分片，
// 返回一条已解密应用消息与最终服务器 Request 标识符。
func receiveTunnelApplication(t *testing.T, conversation *eapConversation, client *eapTestTLSClient, method EAPType, result *AccessServerResult) ([]byte, *EAPPacket) {
	t.Helper()
	if !result.Challenge {
		t.Fatalf("expected tunneled application challenge, got %+v", result)
	}
	serverFlight, finalRequest := conversation.collectServerTLS(method)
	conversation.request = finalRequest
	client.process(t, serverFlight)
	data, ok, err := client.readApplicationAvailable(500 * time.Millisecond)
	if err != nil {
		t.Fatalf("tunnel application read: %v", err)
	}
	if !ok {
		t.Fatal("no tunneled application message arrived")
	}
	return data, finalRequest
}

// finishTunnelAuthentication acknowledges the final tunneled server data and returns the outer
// EAP-Success result. | finishTunnelAuthentication 确认最终隧道服务器数据并返回外层 EAP-Success 结果。
func finishTunnelAuthentication(t *testing.T, conversation *eapConversation, method EAPType, finalRequest *EAPPacket) *AccessServerResult {
	t.Helper()
	result := conversation.send(eapResponse(finalRequest, method, []byte{0}))
	if !result.Accept {
		t.Fatalf("outer result = %+v, want Access-Accept", result)
	}
	return result
}

func TestTTLSAVPRoundTrip(t *testing.T) {
	avps := []TTLSAVP{
		{Code: TTLSAVPCodeUserName, Value: []byte("alice"), Mandatory: true},
		{Code: 200, Value: []byte("unknown-optional")},
		{
			Code:           TTLSAVPCodeMSCHAP2Success,
			Value:          bytes.Repeat([]byte{0xab}, 43),
			Mandatory:      true,
			VendorSpecific: true,
			VendorID:       VendorMicrosoft,
		},
	}
	encoded, err := MarshalTTLSAVPs(avps)
	if err != nil {
		t.Fatalf("MarshalTTLSAVPs: %v", err)
	}
	if len(encoded)%4 != 0 {
		t.Fatalf("encoded length %d is not four-octet aligned", len(encoded))
	}
	parsed, err := ParseTTLSAVPs(encoded)
	if err != nil {
		t.Fatalf("ParseTTLSAVPs: %v", err)
	}
	if len(parsed) != len(avps) {
		t.Fatalf("parsed %d AVPs, want %d", len(parsed), len(avps))
	}
	for i := range avps {
		if parsed[i].Code != avps[i].Code || parsed[i].Mandatory != avps[i].Mandatory ||
			parsed[i].VendorSpecific != avps[i].VendorSpecific || parsed[i].VendorID != avps[i].VendorID ||
			!bytes.Equal(parsed[i].Value, avps[i].Value) {
			t.Fatalf("AVP %d = %+v, want %+v", i, parsed[i], avps[i])
		}
	}
}

func TestTTLSAVPParseErrors(t *testing.T) {
	cases := [][]byte{
		{0, 0},
		{0, 0, 0, 1, 0, 0, 0, 7},
		{0, 0, 0, 1, 0, 0, 0, 12, 'x'},
		{0, 0, 0, 1, TTLSAVPFlagVendor, 0, 0, 8},
		{0, 0, 0, 1, 0, 0, 0, 8, 0, 0, 0, 1},
	}
	for i, data := range cases {
		if _, err := ParseTTLSAVPs(data); err == nil {
			t.Fatalf("case %d parsed malformed AVPs %x", i, data)
		}
	}
}

func TestEAPTTLSPAPAuthentication(t *testing.T) {
	pki := newEAPTestPKI(t)
	server := eapTestServer(t, EAPServerConfig{
		TLSConfig:        &tls.Config{Certificates: []tls.Certificate{pki.serverCert}, MinVersion: tls.VersionTLS12},
		Methods:          []EAPType{EAPTypeTTLS},
		TTLSInnerMethods: []EAPType{EAPTypeIdentity},
	})
	client := newEAPTestTLSClient(eapTLSClientConfig(pki, false, tls.VersionTLS12))
	conversation := newEAPConversation(t, server, "outer-user")
	phase2 := runEAPTunnelHandshake(t, conversation, client, EAPTypeTTLS, "outer-user")
	avps, err := ParseTTLSAVPs(phase2)
	if err != nil {
		t.Fatalf("parse phase-2 AVPs: %v", err)
	}
	if _, ok := firstTTLSAVP(avps, TTLSAVPCodeUserName, 0); !ok {
		t.Fatalf("phase-2 AVPs lack User-Name: %+v", avps)
	}
	if _, ok := firstTTLSAVP(avps, TTLSAVPCodeUserPassword, 0); !ok {
		t.Fatalf("phase-2 AVPs lack User-Password: %+v", avps)
	}
	response, err := MarshalTTLSAVPs([]TTLSAVP{
		{Code: TTLSAVPCodeUserName, Value: []byte("alice"), Mandatory: true},
		{Code: TTLSAVPCodeUserPassword, Value: []byte("s3cret"), Mandatory: true},
	})
	if err != nil {
		t.Fatalf("marshal PAP response: %v", err)
	}
	result := sendTunnelApplication(t, conversation, client, EAPTypeTTLS, response)
	successData, finalRequest := receiveTunnelApplication(t, conversation, client, EAPTypeTTLS, result)
	successAVPs, err := ParseTTLSAVPs(successData)
	if err != nil {
		t.Fatalf("parse phase-2 success: %v", err)
	}
	if len(successAVPs) != 1 || successAVPs[0].Code != 0 {
		t.Fatalf("phase-2 success AVPs = %+v", successAVPs)
	}
	final := finishTunnelAuthentication(t, conversation, EAPTypeTTLS, finalRequest)
	if final.Identity != "alice" {
		t.Fatalf("TTLS identity = %q, want alice", final.Identity)
	}
	if packet := eapPacketFromResult(t, final); packet.Code != EAPCodeSuccess {
		t.Fatalf("final EAP code = %d", packet.Code)
	}
}

func TestEAPTTLSMSCHAPv2Authentication(t *testing.T) {
	pki := newEAPTestPKI(t)
	server := eapTestServer(t, EAPServerConfig{
		TLSConfig:        &tls.Config{Certificates: []tls.Certificate{pki.serverCert}, MinVersion: tls.VersionTLS12},
		Methods:          []EAPType{EAPTypeTTLS},
		TTLSInnerMethods: []EAPType{EAPTypeMSCHAPv2},
	})
	client := newEAPTestTLSClient(eapTLSClientConfig(pki, false, tls.VersionTLS12))
	conversation := newEAPConversation(t, server, "outer-user")
	phase2 := runEAPTunnelHandshake(t, conversation, client, EAPTypeTTLS, "outer-user")
	avps, err := ParseTTLSAVPs(phase2)
	if err != nil {
		t.Fatalf("parse phase-2 AVPs: %v", err)
	}
	challenge, ok := firstTTLSAVP(avps, TTLSAVPCodeMSCHAPChallenge, VendorMicrosoft)
	if !ok || len(challenge) != 16 {
		t.Fatalf("MS-CHAP-Challenge AVP = %x, %v", challenge, ok)
	}
	const ident = 7
	peerChallenge := bytes.Repeat([]byte{0x5a}, 16)
	mschapResponse, err := MSCHAPv2Response("alice", "s3cret", challenge, peerChallenge, ident)
	if err != nil {
		t.Fatalf("MSCHAPv2Response: %v", err)
	}
	response, err := MarshalTTLSAVPs([]TTLSAVP{
		{Code: TTLSAVPCodeUserName, Value: []byte("alice"), Mandatory: true},
		{
			Code:           TTLSAVPCodeMSCHAP2Response,
			Value:          mschapResponse,
			Mandatory:      true,
			VendorSpecific: true,
			VendorID:       VendorMicrosoft,
		},
	})
	if err != nil {
		t.Fatalf("marshal MS-CHAPv2 response: %v", err)
	}
	result := sendTunnelApplication(t, conversation, client, EAPTypeTTLS, response)
	successData, finalRequest := receiveTunnelApplication(t, conversation, client, EAPTypeTTLS, result)
	successAVPs, err := ParseTTLSAVPs(successData)
	if err != nil {
		t.Fatalf("parse MS-CHAPv2 success: %v", err)
	}
	success, ok := firstTTLSAVP(successAVPs, TTLSAVPCodeMSCHAP2Success, VendorMicrosoft)
	if !ok || len(success) != 43 || success[0] != ident {
		t.Fatalf("MS-CHAP2-Success AVP = %x, %v", success, ok)
	}
	expected, err := MSCHAPv2AuthenticatorResponse("alice", "s3cret", challenge, mschapResponse)
	if err != nil {
		t.Fatalf("MSCHAPv2AuthenticatorResponse: %v", err)
	}
	if !bytes.Equal(success[1:], expected) {
		t.Fatalf("MS-CHAP2-Success = %x, want %x", success[1:], expected)
	}
	sendKey, ok := firstTTLSAVP(successAVPs, TTLSAVPCodeMSMPPESendKey, VendorMicrosoft)
	if !ok || len(sendKey) != 16 {
		t.Fatalf("MS-MPPE-Send-Key = %x, %v", sendKey, ok)
	}
	recvKey, ok := firstTTLSAVP(successAVPs, TTLSAVPCodeMSMPPERecvKey, VendorMicrosoft)
	if !ok || len(recvKey) != 16 {
		t.Fatalf("MS-MPPE-Recv-Key = %x, %v", recvKey, ok)
	}
	if bytes.Equal(sendKey, recvKey) {
		t.Fatal("TTLS MPPE keys are identical")
	}
	final := finishTunnelAuthentication(t, conversation, EAPTypeTTLS, finalRequest)
	if final.Identity != "alice" || len(final.MPPESendKey) != 16 || len(final.MPPERecvKey) != 16 {
		t.Fatalf("final = %+v", final)
	}
	if !bytes.Equal(final.MPPESendKey, sendKey) || !bytes.Equal(final.MPPERecvKey, recvKey) {
		t.Fatalf("outer MPPE keys differ from tunneled keys")
	}
}

func TestEAPTTLSWrongPassword(t *testing.T) {
	pki := newEAPTestPKI(t)
	server := eapTestServer(t, EAPServerConfig{
		TLSConfig:        &tls.Config{Certificates: []tls.Certificate{pki.serverCert}, MinVersion: tls.VersionTLS12},
		Methods:          []EAPType{EAPTypeTTLS},
		TTLSInnerMethods: []EAPType{EAPTypeIdentity},
	})
	client := newEAPTestTLSClient(eapTLSClientConfig(pki, false, tls.VersionTLS12))
	conversation := newEAPConversation(t, server, "outer-user")
	runEAPTunnelHandshake(t, conversation, client, EAPTypeTTLS, "outer-user")
	response, err := MarshalTTLSAVPs([]TTLSAVP{
		{Code: TTLSAVPCodeUserName, Value: []byte("alice"), Mandatory: true},
		{Code: TTLSAVPCodeUserPassword, Value: []byte("wrong"), Mandatory: true},
	})
	if err != nil {
		t.Fatalf("marshal PAP response: %v", err)
	}
	result := sendTunnelApplication(t, conversation, client, EAPTypeTTLS, response)
	if result.Accept {
		t.Fatalf("wrong TTLS password accepted: %+v", result)
	}
	if packet := eapPacketFromResult(t, result); packet.Code != EAPCodeFailure {
		t.Fatalf("final EAP code = %d, want Failure", packet.Code)
	}
}

func TestEAPTTLSUnknownMandatoryAVP(t *testing.T) {
	pki := newEAPTestPKI(t)
	server := eapTestServer(t, EAPServerConfig{
		TLSConfig:        &tls.Config{Certificates: []tls.Certificate{pki.serverCert}, MinVersion: tls.VersionTLS12},
		Methods:          []EAPType{EAPTypeTTLS},
		TTLSInnerMethods: []EAPType{EAPTypeIdentity},
	})
	client := newEAPTestTLSClient(eapTLSClientConfig(pki, false, tls.VersionTLS12))
	conversation := newEAPConversation(t, server, "outer-user")
	runEAPTunnelHandshake(t, conversation, client, EAPTypeTTLS, "outer-user")
	response, err := MarshalTTLSAVPs([]TTLSAVP{
		{Code: TTLSAVPCodeUserName, Value: []byte("alice"), Mandatory: true},
		{Code: TTLSAVPCodeUserPassword, Value: []byte("s3cret"), Mandatory: true},
		{Code: 250, Value: []byte("critical"), Mandatory: true},
	})
	if err != nil {
		t.Fatalf("marshal AVPs: %v", err)
	}
	result := sendTunnelApplication(t, conversation, client, EAPTypeTTLS, response)
	if result.Accept {
		t.Fatalf("unknown mandatory AVP accepted: %+v", result)
	}
}

func TestEAPTTLSRequiresClientCertificate(t *testing.T) {
	pki := newEAPTestPKI(t)
	server := eapTestServer(t, EAPServerConfig{
		TLSConfig: &tls.Config{
			Certificates: []tls.Certificate{pki.serverCert},
			ClientAuth:   tls.RequireAndVerifyClientCert,
			ClientCAs:    pki.roots,
			MinVersion:   tls.VersionTLS12,
		},
		Methods:                  []EAPType{EAPTypeTTLS},
		TTLSInnerMethods:         []EAPType{EAPTypeIdentity},
		RequireClientCertificate: true,
	})
	client := newEAPTestTLSClient(eapTLSClientConfig(pki, true, tls.VersionTLS12))
	conversation := newEAPConversation(t, server, "outer-user")
	phase2 := runEAPTunnelHandshake(t, conversation, client, EAPTypeTTLS, "outer-user")
	response, err := MarshalTTLSAVPs([]TTLSAVP{
		{Code: TTLSAVPCodeUserName, Value: []byte("alice"), Mandatory: true},
		{Code: TTLSAVPCodeUserPassword, Value: []byte("s3cret"), Mandatory: true},
	})
	if err != nil {
		t.Fatalf("marshal PAP response: %v", err)
	}
	_ = phase2
	result := sendTunnelApplication(t, conversation, client, EAPTypeTTLS, response)
	successData, finalRequest := receiveTunnelApplication(t, conversation, client, EAPTypeTTLS, result)
	if len(successData) == 0 {
		t.Fatal("empty TTLS success data")
	}
	final := finishTunnelAuthentication(t, conversation, EAPTypeTTLS, finalRequest)
	if !final.Accept {
		t.Fatalf("TTLS with client certificate rejected: %+v", final)
	}
}

func TestEAPTLSCertificateIdentityExtraction(t *testing.T) {
	pki := newEAPTestPKI(t)
	server := eapTestServer(t, EAPServerConfig{
		TLSConfig: &tls.Config{
			Certificates: []tls.Certificate{pki.serverCert},
			ClientAuth:   tls.VerifyClientCertIfGiven,
			ClientCAs:    pki.roots,
			MinVersion:   tls.VersionTLS12,
		},
		Methods: []EAPType{EAPTypeTLS},
		IdentityFromCertificate: func(certificate *x509.Certificate) string {
			return certificate.Subject.CommonName + "@test"
		},
	})
	client := newEAPTestTLSClient(eapTLSClientConfig(pki, true, tls.VersionTLS12))
	result := runEAPTLSAuthentication(t, server, client, "outer")
	if !result.Accept || result.Identity != "tls-client@test" {
		t.Fatalf("identity extraction result = %+v", result)
	}
}

func TestEAPTTLSServerConfigValidation(t *testing.T) {
	if _, err := NewEAPServer(EAPServerConfig{
		Methods:          []EAPType{EAPTypeTTLS},
		TTLSInnerMethods: []EAPType{EAPTypeIdentity},
	}); !errors.Is(err, ErrInvalidConfig) {
		t.Fatalf("TTLS without TLS config error = %v", err)
	}
	if _, err := NewEAPServer(EAPServerConfig{
		Methods:          []EAPType{EAPTypeTTLS},
		TLSConfig:        &tls.Config{},
		TTLSInnerMethods: []EAPType{EAPTypeIdentity},
	}); !errors.Is(err, ErrInvalidConfig) {
		t.Fatalf("TTLS inner methods without password error = %v", err)
	}
}

func TestEAPTTLSTunnelTimeout(t *testing.T) {
	pki := newEAPTestPKI(t)
	server := eapTestServer(t, EAPServerConfig{
		TLSConfig:        &tls.Config{Certificates: []tls.Certificate{pki.serverCert}, MinVersion: tls.VersionTLS12},
		Methods:          []EAPType{EAPTypeTTLS},
		TTLSInnerMethods: []EAPType{EAPTypeIdentity},
		Timeout:          300 * time.Millisecond,
	})
	client := newEAPTestTLSClient(eapTLSClientConfig(pki, false, tls.VersionTLS12))
	conversation := newEAPConversation(t, server, "outer-user")
	runEAPTunnelHandshake(t, conversation, client, EAPTypeTTLS, "outer-user")
	time.Sleep(350 * time.Millisecond)
	response, err := MarshalTTLSAVPs([]TTLSAVP{
		{Code: TTLSAVPCodeUserName, Value: []byte("alice"), Mandatory: true},
		{Code: TTLSAVPCodeUserPassword, Value: []byte("s3cret"), Mandatory: true},
	})
	if err != nil {
		t.Fatalf("marshal PAP response: %v", err)
	}
	result := sendTunnelApplication(t, conversation, client, EAPTypeTTLS, response)
	if result.Accept {
		t.Fatalf("expired TTLS session accepted: %+v", result)
	}
}
