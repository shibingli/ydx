package radius

import (
	"bytes"
	"context"
	"crypto/md5"
	"errors"
	"sync"
	"testing"
	"time"
)

// eapTestServer builds an EAP server with a fixed test user database. | eapTestServer 构建带固定测试用户
// 数据库的 EAP 服务器。
func eapTestServer(t *testing.T, config EAPServerConfig) *EAPServer {
	t.Helper()
	if config.Password == nil {
		config.Password = testEAPPasswordLookup(map[string]string{
			"alice": "s3cret",
			"bob":   "hunter2",
		})
	}
	server, err := NewEAPServer(config)
	if err != nil {
		t.Fatalf("NewEAPServer: %v", err)
	}
	t.Cleanup(func() {
		if err := server.Close(); err != nil {
			t.Errorf("EAPServer.Close: %v", err)
		}
	})
	return server
}

// testEAPPasswordLookup returns a lookup over a fixed password map. | testEAPPasswordLookup 返回固定口令
// 映射的查找函数。
func testEAPPasswordLookup(passwords map[string]string) EAPPasswordLookup {
	return func(ctx context.Context, userName string) ([]byte, error) {
		if err := ctx.Err(); err != nil {
			return nil, err
		}
		password, ok := passwords[userName]
		if !ok {
			return nil, errors.New("test lookup: user not found")
		}
		return []byte(password), nil
	}
}

// eapPacketFromResult extracts the only EAP packet carried by result. | eapPacketFromResult 提取 result
// 携带的唯一 EAP 报文。
func eapPacketFromResult(t *testing.T, result *AccessServerResult) *EAPPacket {
	t.Helper()
	if result == nil {
		t.Fatal("EAP result is nil")
	}
	raw, err := ReassembleEAPMessages(result.Attributes)
	if err != nil {
		t.Fatalf("ReassembleEAPMessages: %v", err)
	}
	packet, err := ParseEAPPacket(raw)
	if err != nil {
		t.Fatalf("ParseEAPPacket: %v", err)
	}
	return packet
}

// eapStart begins an EAP conversation and returns the first server Request and its State. |
// eapStart 开始 EAP 交互并返回首个服务器 Request 及其 State。
func eapStart(t *testing.T, server *EAPServer, userName string) (*EAPPacket, []byte) {
	t.Helper()
	result, err := server.AuthenticateAccess(context.Background(), &AccessServerRequest{
		UserName:   userName,
		Identifier: 1,
	})
	if err != nil {
		t.Fatalf("AuthenticateAccess start: %v", err)
	}
	return eapPacketFromResult(t, result), result.State
}

// eapContinue submits one EAP Response and returns the server result. | eapContinue 提交一个 EAP
// Response 并返回服务器结果。
func eapContinue(t *testing.T, server *EAPServer, state []byte, userName string, response *EAPPacket) *AccessServerResult {
	t.Helper()
	result, err := server.AuthenticateAccess(context.Background(), &AccessServerRequest{
		UserName:   userName,
		State:      state,
		EAPPacket:  response,
		Identifier: 9,
	})
	if err != nil {
		t.Fatalf("AuthenticateAccess continue: %v", err)
	}
	return result
}

// eapResponse builds a Response echoing the Request identifier. | eapResponse 构建回显 Request 标识符的
// Response。
func eapResponse(request *EAPPacket, method EAPType, data []byte) *EAPPacket {
	return newEAPResponse(request.Identifier, method, data)
}

// eapMD5Response computes an EAP-MD5 Response for a challenge. | eapMD5Response 为挑战计算 EAP-MD5
// Response。
func eapMD5Response(identifier uint8, password string, challenge []byte) []byte {
	digest := md5.New()
	digest.Write([]byte{identifier})
	digest.Write([]byte(password))
	digest.Write(challenge)
	value := make([]byte, 1+16)
	value[0] = 16
	copy(value[1:], digest.Sum(nil))
	return value
}

// eapMSCHAPv2Response derives the 52-octet EAP-MSCHAPv2 Response for a server challenge. |
// eapMSCHAPv2Response 为服务器挑战派生 52 字节 EAP-MSCHAPv2 Response。
func eapMSCHAPv2Response(t *testing.T, userName, password string, request *EAPPacket) []byte {
	t.Helper()
	if len(request.Data) < 18 || request.Data[0] != 1 {
		t.Fatalf("MS-CHAPv2 challenge data = %x", request.Data)
	}
	identifier := request.Data[1]
	challenge := request.Data[2:18]
	peerChallenge := bytes.Repeat([]byte{0x42}, 16)
	response, err := MSCHAPv2Response(userName, password, challenge, peerChallenge, identifier)
	if err != nil {
		t.Fatalf("MSCHAPv2Response: %v", err)
	}
	value := make([]byte, 52)
	value[0] = 2
	value[1] = response[0]
	value[2] = response[1]
	copy(value[3:19], response[2:18])
	copy(value[19:27], response[18:26])
	copy(value[27:51], response[26:50])
	return value
}

func TestEAPMD5Authentication(t *testing.T) {
	server := eapTestServer(t, EAPServerConfig{Methods: []EAPType{EAPTypeMD5}})
	request, state := eapStart(t, server, "alice")
	if request.Code != EAPCodeRequest || request.Type != EAPTypeIdentity {
		t.Fatalf("first request = %+v, want Request/Identity", request)
	}
	identity := eapResponse(request, EAPTypeIdentity, []byte("alice"))
	result := eapContinue(t, server, state, "alice", identity)
	challengeRequest := eapPacketFromResult(t, result)
	if challengeRequest.Code != EAPCodeRequest || challengeRequest.Type != EAPTypeMD5 {
		t.Fatalf("second request = %+v, want Request/MD5", challengeRequest)
	}
	if !result.Challenge || len(result.State) == 0 {
		t.Fatalf("challenge result = %+v", result)
	}
	if len(challengeRequest.Data) < 17 || challengeRequest.Data[0] != 16 {
		t.Fatalf("MD5 challenge data = %x", challengeRequest.Data)
	}
	response := eapResponse(challengeRequest, EAPTypeMD5, eapMD5Response(challengeRequest.Identifier, "s3cret", challengeRequest.Data[1:17]))
	final := eapContinue(t, server, result.State, "alice", response)
	if !final.Accept || final.Challenge {
		t.Fatalf("final result = %+v, want Access-Accept", final)
	}
	success := eapPacketFromResult(t, final)
	if success.Code != EAPCodeSuccess {
		t.Fatalf("final EAP code = %d, want Success", success.Code)
	}
	if final.Identity != "alice" {
		t.Fatalf("identity = %q", final.Identity)
	}
}

func TestEAPMD5WrongPassword(t *testing.T) {
	server := eapTestServer(t, EAPServerConfig{Methods: []EAPType{EAPTypeMD5}})
	request, state := eapStart(t, server, "alice")
	identity := eapResponse(request, EAPTypeIdentity, []byte("alice"))
	result := eapContinue(t, server, state, "alice", identity)
	challengeRequest := eapPacketFromResult(t, result)
	response := eapResponse(challengeRequest, EAPTypeMD5, eapMD5Response(challengeRequest.Identifier, "wrong", challengeRequest.Data[1:17]))
	final := eapContinue(t, server, result.State, "alice", response)
	if final.Accept {
		t.Fatalf("wrong password accepted: %+v", final)
	}
	if packet := eapPacketFromResult(t, final); packet.Code != EAPCodeFailure {
		t.Fatalf("final EAP code = %d, want Failure", packet.Code)
	}
}

func TestEAPMSCHAPv2AuthenticationAndKeys(t *testing.T) {
	server := eapTestServer(t, EAPServerConfig{Methods: []EAPType{EAPTypeMSCHAPv2}})
	request, state := eapStart(t, server, "alice")
	identity := eapResponse(request, EAPTypeIdentity, []byte("alice"))
	challengeResult := eapContinue(t, server, state, "alice", identity)
	challengeRequest := eapPacketFromResult(t, challengeResult)
	if challengeRequest.Type != EAPTypeMSCHAPv2 {
		t.Fatalf("challenge type = %d", challengeRequest.Type)
	}
	response := eapResponse(challengeRequest, EAPTypeMSCHAPv2, eapMSCHAPv2Response(t, "alice", "s3cret", challengeRequest))
	successRequestResult := eapContinue(t, server, challengeResult.State, "alice", response)
	successRequest := eapPacketFromResult(t, successRequestResult)
	if successRequest.Code != EAPCodeRequest || successRequest.Type != EAPTypeMSCHAPv2 {
		t.Fatalf("success request = %+v", successRequest)
	}
	if len(successRequest.Data) != 44 || successRequest.Data[0] != 3 {
		t.Fatalf("MS-CHAPv2 success data = %x", successRequest.Data)
	}
	ack := eapResponse(successRequest, EAPTypeMSCHAPv2, nil)
	final := eapContinue(t, server, successRequestResult.State, "alice", ack)
	if !final.Accept {
		t.Fatalf("final result = %+v", final)
	}
	if packet := eapPacketFromResult(t, final); packet.Code != EAPCodeSuccess {
		t.Fatalf("final EAP code = %d", packet.Code)
	}
	if len(final.MPPESendKey) != 16 || len(final.MPPERecvKey) != 16 {
		t.Fatalf("MPPE keys = %x/%x", final.MPPESendKey, final.MPPERecvKey)
	}
	if bytes.Equal(final.MPPESendKey, final.MPPERecvKey) {
		t.Fatal("server and peer MPPE keys are identical")
	}
}

func TestEAPMethodNakNegotiatesMD5(t *testing.T) {
	server := eapTestServer(t, EAPServerConfig{Methods: []EAPType{EAPTypeMSCHAPv2, EAPTypeMD5}})
	request, state := eapStart(t, server, "alice")
	identity := eapResponse(request, EAPTypeIdentity, []byte("alice"))
	result := eapContinue(t, server, state, "alice", identity)
	challenge := eapPacketFromResult(t, result)
	if challenge.Type != EAPTypeMSCHAPv2 {
		t.Fatalf("initial method = %d, want MSCHAPv2", challenge.Type)
	}
	nak := eapResponse(challenge, EAPTypeNak, []byte{byte(EAPTypeMD5)})
	md5Result := eapContinue(t, server, result.State, "alice", nak)
	md5Challenge := eapPacketFromResult(t, md5Result)
	if md5Challenge.Type != EAPTypeMD5 || md5Challenge.Code != EAPCodeRequest {
		t.Fatalf("Nak result = %+v, want MD5 Request", md5Challenge)
	}
	response := eapResponse(md5Challenge, EAPTypeMD5, eapMD5Response(md5Challenge.Identifier, "s3cret", md5Challenge.Data[1:17]))
	final := eapContinue(t, server, md5Result.State, "alice", response)
	if !final.Accept {
		t.Fatalf("final = %+v", final)
	}
}

func TestEAPUnknownStateAndExpiry(t *testing.T) {
	server := eapTestServer(t, EAPServerConfig{Methods: []EAPType{EAPTypeMD5}, Timeout: 20 * time.Millisecond})
	result, err := server.AuthenticateAccess(context.Background(), &AccessServerRequest{
		State:      []byte("unknown-state"),
		EAPPacket:  newEAPResponse(1, EAPTypeIdentity, []byte("alice")),
		Identifier: 3,
	})
	if err != nil {
		t.Fatalf("unknown state: %v", err)
	}
	if result.Accept {
		t.Fatal("unknown state accepted")
	}
	request, state := eapStart(t, server, "alice")
	identity := eapResponse(request, EAPTypeIdentity, []byte("alice"))
	challenge := eapContinue(t, server, state, "alice", identity)
	time.Sleep(60 * time.Millisecond)
	expired := eapContinue(t, server, challenge.State, "alice", eapResponse(eapPacketFromResult(t, challenge), EAPTypeMD5, bytes.Repeat([]byte{0}, 17)))
	if expired.Accept {
		t.Fatal("expired state accepted")
	}
}

func TestEAPRetransmissionCache(t *testing.T) {
	server := eapTestServer(t, EAPServerConfig{Methods: []EAPType{EAPTypeMD5}})
	request, state := eapStart(t, server, "alice")
	identity := eapResponse(request, EAPTypeIdentity, []byte("alice"))
	first := eapContinue(t, server, state, "alice", identity)
	second := eapContinue(t, server, first.State, "alice", identity)
	firstPacket := eapPacketFromResult(t, first)
	secondPacket := eapPacketFromResult(t, second)
	if firstPacket.Identifier != secondPacket.Identifier || !bytes.Equal(firstPacket.Data, secondPacket.Data) {
		t.Fatalf("retransmission reply differs: %+v vs %+v", firstPacket, secondPacket)
	}
}

func TestEAPConcurrentSessions(t *testing.T) {
	server := eapTestServer(t, EAPServerConfig{Methods: []EAPType{EAPTypeMD5}, MaxSessions: 64})
	const clients = 16
	var wg sync.WaitGroup
	errsCh := make(chan error, clients)
	for i := 0; i < clients; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			request, state := eapStart(t, server, "alice")
			identity := eapResponse(request, EAPTypeIdentity, []byte("alice"))
			challengeResult := eapContinue(t, server, state, "alice", identity)
			challenge := eapPacketFromResult(t, challengeResult)
			response := eapResponse(challenge, EAPTypeMD5, eapMD5Response(challenge.Identifier, "s3cret", challenge.Data[1:17]))
			final := eapContinue(t, server, challengeResult.State, "alice", response)
			if !final.Accept {
				errsCh <- errors.New("concurrent authentication rejected")
			}
		}()
	}
	wg.Wait()
	close(errsCh)
	for err := range errsCh {
		t.Error(err)
	}
}

func TestEAPServerConfigValidation(t *testing.T) {
	cases := []EAPServerConfig{
		{Methods: []EAPType{EAPTypeMD5}},
		{Methods: []EAPType{EAPTypeTLS}, Password: testEAPPasswordLookup(nil)},
		{Methods: []EAPType{EAPTypeIdentity}, Password: testEAPPasswordLookup(nil)},
		{Methods: []EAPType{EAPTypeMD5}, Password: testEAPPasswordLookup(nil), MaxSessions: -1},
		{Methods: []EAPType{EAPTypeMD5}, Password: testEAPPasswordLookup(nil), FragmentSize: -1},
		{Methods: []EAPType{EAPTypeMD5}, Password: testEAPPasswordLookup(nil), TTLSInnerMethods: []EAPType{EAPTypeTLS}},
	}
	for i, config := range cases {
		if _, err := NewEAPServer(config); !errors.Is(err, ErrInvalidConfig) {
			t.Fatalf("case %d error = %v, want ErrInvalidConfig", i, err)
		}
	}
}

func TestAccessServerEAPIntegration(t *testing.T) {
	secret := accountingServerSecret()
	eapServer := eapTestServer(t, EAPServerConfig{Methods: []EAPType{EAPTypeMD5}})
	mschap, err := NewMSCHAPv2Server(MSCHAPv2ServerConfig{
		Lookup:  testMSCHAPv2Lookup,
		Timeout: 2 * time.Second,
	})
	if err != nil {
		t.Fatalf("NewMSCHAPv2Server: %v", err)
	}
	t.Cleanup(func() {
		_ = mschap.Close()
	})
	server := startAccessServer(t, AccessServerConfig{
		Network:       "udp4",
		Address:       "127.0.0.1:0",
		Secret:        secret,
		MSCHAPv2:      mschap,
		Authenticator: eapServer,
		Logger:        testDynamicLogger(),
	})
	client := newTestClient(t, ClientConfig{
		Address:       server.Addr().String(),
		Secret:        secret,
		NASIdentifier: "nas-eap",
	})
	identity, err := newEAPResponse(1, EAPTypeIdentity, []byte("alice")).MarshalBinary()
	if err != nil {
		t.Fatalf("encode Identity: %v", err)
	}
	first, err := client.AccessRequest(context.Background(), &AccessRequest{
		UserName:    "alice",
		Method:      AuthEAP,
		EAPMessages: [][]byte{identity},
	})
	if err != nil {
		t.Fatalf("AccessRequest Identity: %v", err)
	}
	if !first.Challenged() || len(first.State) == 0 || len(first.EAPMessages) != 1 {
		t.Fatalf("first response = code %d, state %d bytes, EAP messages %d", first.Code, len(first.State), len(first.EAPMessages))
	}
	challenge, err := ParseEAPPacket(first.EAPMessages[0])
	if err != nil {
		t.Fatalf("parse challenge: %v", err)
	}
	if challenge.Code != EAPCodeRequest || challenge.Type != EAPTypeMD5 {
		t.Fatalf("challenge = %+v", challenge)
	}
	response, err := newEAPResponse(challenge.Identifier, EAPTypeMD5,
		eapMD5Response(challenge.Identifier, "s3cret", challenge.Data[1:17])).MarshalBinary()
	if err != nil {
		t.Fatalf("encode MD5 response: %v", err)
	}
	final, err := client.AccessRequest(context.Background(), &AccessRequest{
		UserName:    "alice",
		Method:      AuthEAP,
		State:       first.State,
		EAPMessages: [][]byte{response},
	})
	if err != nil {
		t.Fatalf("AccessRequest MD5 response: %v", err)
	}
	if !final.Accepted() || len(final.EAPMessages) != 1 {
		var detail *EAPPacket
		if len(final.EAPMessages) == 1 {
			detail, _ = ParseEAPPacket(final.EAPMessages[0])
		}
		t.Fatalf("final response = code %d, EAP messages %d, EAP packet %+v, reply %q", final.Code, len(final.EAPMessages), detail, final.ReplyMessage)
	}
	success, err := ParseEAPPacket(final.EAPMessages[0])
	if err != nil {
		t.Fatalf("parse success: %v", err)
	}
	if success.Code != EAPCodeSuccess {
		t.Fatalf("final EAP code = %d, want Success", success.Code)
	}
}

func TestEAPServerClose(t *testing.T) {
	server, err := NewEAPServer(EAPServerConfig{Methods: []EAPType{EAPTypeMD5}, Password: testEAPPasswordLookup(map[string]string{"alice": "s3cret"})})
	if err != nil {
		t.Fatalf("NewEAPServer: %v", err)
	}
	if err := server.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}
	if err := server.Close(); err != nil {
		t.Fatalf("second Close: %v", err)
	}
	if _, err := server.AuthenticateAccess(context.Background(), &AccessServerRequest{UserName: "alice"}); !errors.Is(err, ErrServerClosed) {
		t.Fatalf("AuthenticateAccess after Close = %v, want ErrServerClosed", err)
	}
}
