package ldap

import (
	"bytes"
	"crypto/hmac"
	"crypto/md5"
	"crypto/subtle"
	"crypto/tls"
	"encoding/binary"
	"errors"
	"strings"
	"sync"
	"testing"
	"time"
	"unicode/utf16"

	"github.com/shibingli/ydx/auth/directory/ntlm"
)

// ntlmTestPassword is an obvious fixed test password, never a real secret. |
// ntlmTestPassword 是明显的固定测试口令，绝非真实密钥。
const ntlmTestPassword = "Ntlm-Test-Password-123!"

// ntlmTestConfig drives the mock LDAP server through one NTLM SASL exchange. |
// ntlmTestConfig 驱动模拟 LDAP 服务端完成一次 NTLM SASL 交换。
type ntlmTestConfig struct {
	serverChallenge  [8]byte
	info             ntlm.TargetInfo
	mechanism        string
	raw              bool
	username         string
	domain           string
	password         string
	type1Domain      string
	workstation      string
	channelBinding   []byte
	wrapChallenge    func([]byte) ([]byte, error)
	firstResult      *ResultCode
	secondResult     *ResultCode
	finalCredentials []byte
}

// ntlmTestRecorder captures what the mock server observed. | ntlmTestRecorder
// 记录模拟服务端观测到的内容。
type ntlmTestRecorder struct {
	mu           sync.Mutex
	binds        int
	mechanisms   []string
	negotiate    *ntlm.NegotiateMessage
	authenticate *ntlm.AuthenticateMessage
	finalToken   *ntlm.SPNEGOToken
}

// snapshot returns a race-free view of the recorded exchange. | snapshot 返回已记录
// 交换的无竞态视图。
func (r *ntlmTestRecorder) snapshot() (int, []string, *ntlm.NegotiateMessage, *ntlm.AuthenticateMessage) {
	r.mu.Lock()
	defer r.mu.Unlock()
	return r.binds, append([]string(nil), r.mechanisms...), r.negotiate, r.authenticate
}

// finalSPNEGO returns the parsed final client SPNEGO token, if any. | finalSPNEGO
// 返回已解析的最终客户端 SPNEGO 令牌（如有）。
func (r *ntlmTestRecorder) finalSPNEGO() *ntlm.SPNEGOToken {
	r.mu.Lock()
	defer r.mu.Unlock()
	return r.finalToken
}

// ntlmTestHandler returns a mock handler that validates a complete NTLMv2
// exchange using the same public primitives a real Active Directory server
// would use. | ntlmTestHandler 返回模拟处理器，使用真实 Active Directory 服务端会用到的
// 同一组公开原语校验完整 NTLMv2 交换。
func ntlmTestHandler(t *testing.T, cfg ntlmTestConfig) (mockHandler, *ntlmTestRecorder) {
	t.Helper()
	recorder := &ntlmTestRecorder{}
	handler := func(session *mockSession, message *LDAPMessage) error {
		request, ok := message.Op.(*BindRequest)
		if !ok {
			return errors.New("NTLM mock: expected BindRequest")
		}
		authentication, ok := request.Authentication.(SASLAuthentication)
		if !ok {
			return errors.New("NTLM mock: expected SASL bind authentication")
		}
		if authentication.Mechanism != cfg.mechanism {
			return errors.New("NTLM mock: unexpected mechanism " + authentication.Mechanism)
		}
		recorder.mu.Lock()
		recorder.binds++
		position := recorder.binds % 2
		recorder.mechanisms = append(recorder.mechanisms, authentication.Mechanism)
		recorder.mu.Unlock()
		if position == 1 {
			return ntlmTestHandleInitial(session, message.MessageID, authentication, cfg, recorder)
		}
		return ntlmTestHandleFinal(session, message.MessageID, authentication, cfg, recorder)
	}
	return handler, recorder
}

// ntlmTestHandleInitial validates the Type 1 message and answers with a Type 2
// challenge. | ntlmTestHandleInitial 校验 Type 1 消息并返回 Type 2 挑战。
func ntlmTestHandleInitial(session *mockSession, messageID int, authentication SASLAuthentication, cfg ntlmTestConfig, recorder *ntlmTestRecorder) error {
	if cfg.firstResult != nil {
		return session.Write(&LDAPMessage{MessageID: messageID, Op: &BindResponse{Result: LDAPResult{Code: *cfg.firstResult}}})
	}
	token := authentication.Credentials
	if !cfg.raw {
		parsed, err := ntlm.ParseSPNEGOToken(token)
		if err != nil {
			return err
		}
		if !parsed.SupportsNTLM() {
			return errors.New("NTLM mock: client did not advertise NTLM")
		}
		token = parsed.Token()
	}
	negotiate, err := ntlm.DecodeNegotiate(token)
	if err != nil {
		return err
	}
	if !negotiate.Flags.Has(ntlm.FlagNTLM) || !negotiate.Flags.Has(ntlm.FlagUnicode) {
		return errors.New("NTLM mock: Type 1 lacks NTLM or Unicode")
	}
	if negotiate.Domain != cfg.type1Domain {
		return errors.New("NTLM mock: unexpected Type 1 domain " + negotiate.Domain)
	}
	if negotiate.Workstation != cfg.workstation {
		return errors.New("NTLM mock: unexpected Type 1 workstation " + negotiate.Workstation)
	}
	recorder.mu.Lock()
	recorder.negotiate = negotiate
	recorder.mu.Unlock()
	challenge, err := ntlmTestChallenge(cfg.serverChallenge, cfg.info)
	if err != nil {
		return err
	}
	var credentials []byte
	switch {
	case cfg.wrapChallenge != nil:
		credentials, err = cfg.wrapChallenge(challenge)
		if err != nil {
			return err
		}
	case cfg.raw:
		credentials = challenge
	default:
		credentials, err = ntlm.EncodeSPNEGOResponse(challenge)
		if err != nil {
			return err
		}
	}
	return session.Write(&LDAPMessage{
		MessageID: messageID,
		Op: &BindResponse{
			Result:                LDAPResult{Code: ResultSASLBindInProgress},
			ServerSASLCredentials: credentials,
		},
	})
}

// ntlmTestHandleFinal verifies the Type 3 proof and answers with the configured
// result. | ntlmTestHandleFinal 校验 Type 3 证明并按配置返回结果。
func ntlmTestHandleFinal(session *mockSession, messageID int, authentication SASLAuthentication, cfg ntlmTestConfig, recorder *ntlmTestRecorder) error {
	token := authentication.Credentials
	if !cfg.raw {
		parsed, err := ntlm.ParseSPNEGOToken(token)
		if err != nil {
			return err
		}
		recorder.mu.Lock()
		recorder.finalToken = parsed
		recorder.mu.Unlock()
		token = parsed.Token()
	}
	authenticate, err := ntlm.DecodeAuthenticate(token)
	if err != nil {
		return err
	}
	if err := ntlmTestVerifyAuthenticate(authenticate, cfg); err != nil {
		return err
	}
	recorder.mu.Lock()
	recorder.authenticate = authenticate
	recorder.mu.Unlock()
	if cfg.secondResult != nil {
		return session.Write(&LDAPMessage{MessageID: messageID, Op: &BindResponse{Result: LDAPResult{Code: *cfg.secondResult}}})
	}
	return session.Write(&LDAPMessage{
		MessageID: messageID,
		Op: &BindResponse{
			Result:                LDAPResult{Code: ResultSuccess},
			ServerSASLCredentials: cfg.finalCredentials,
		},
	})
}

// ntlmTestVerifyAuthenticate recomputes the NTLMv2 proof, LMv2 response and
// channel binding from the Type 3 message. | ntlmTestVerifyAuthenticate 从 Type 3
// 消息重新计算 NTLMv2 证明、LMv2 响应与通道绑定。
func ntlmTestVerifyAuthenticate(message *ntlm.AuthenticateMessage, cfg ntlmTestConfig) error {
	if message.Username != cfg.username {
		return errors.New("NTLM mock: unexpected user name " + message.Username)
	}
	if message.Domain != cfg.domain {
		return errors.New("NTLM mock: unexpected domain " + message.Domain)
	}
	if !message.Flags.Has(ntlm.FlagUnicode) {
		return errors.New("NTLM mock: Type 3 lacks Unicode")
	}
	if len(message.NTResponse) < 16+28+4+4 {
		return errors.New("NTLM mock: NT response is too short")
	}
	key := ntlm.NTLMv2Hash(cfg.password, cfg.username, cfg.domain)
	temp := message.NTResponse[16:]
	proof := ntlmTestHMACMD5(key, cfg.serverChallenge[:], temp)
	if subtle.ConstantTimeCompare(message.NTResponse[:16], proof) != 1 {
		return errors.New("NTLM mock: NT proof mismatch")
	}
	if len(message.LMResponse) != 24 {
		return errors.New("NTLM mock: LMv2 response length is not 24")
	}
	clientChallenge := message.LMResponse[16:]
	if !bytes.Equal(clientChallenge, temp[16:24]) {
		return errors.New("NTLM mock: LMv2 and NT responses use different client challenges")
	}
	lmProof := ntlmTestHMACMD5(key, cfg.serverChallenge[:], clientChallenge)
	if subtle.ConstantTimeCompare(message.LMResponse[:16], lmProof) != 1 {
		return errors.New("NTLM mock: LMv2 proof mismatch")
	}
	info, err := ntlm.ParseTargetInfo(temp[28 : len(temp)-4])
	if err != nil {
		return err
	}
	binding, present := info.Get(ntlm.AVChannelBindings)
	if cfg.channelBinding != nil {
		if !present {
			return errors.New("NTLM mock: Type 3 has no channel binding")
		}
		if subtle.ConstantTimeCompare(binding, cfg.channelBinding) != 1 {
			return errors.New("NTLM mock: Type 3 channel binding mismatch")
		}
	} else if present {
		return errors.New("NTLM mock: unexpected Type 3 channel binding")
	}
	return nil
}

// ntlmTestHMACMD5 returns HMAC-MD5 over the concatenated parts. | ntlmTestHMACMD5
// 返回拼接各部分后的 HMAC-MD5。
func ntlmTestHMACMD5(key []byte, parts ...[]byte) []byte {
	mac := hmac.New(md5.New, key)
	for _, part := range parts {
		_, _ = mac.Write(part)
	}
	return mac.Sum(nil)
}

// ntlmTestChallenge encodes a Type 2 challenge with the flags Active Directory
// normally returns. | ntlmTestChallenge 编码带 Active Directory 常见标志的 Type 2 挑战。
func ntlmTestChallenge(serverChallenge [8]byte, info ntlm.TargetInfo) ([]byte, error) {
	message := &ntlm.ChallengeMessage{
		Flags: ntlm.FlagUnicode | ntlm.FlagOEM | ntlm.FlagRequestTarget | ntlm.FlagNTLM |
			ntlm.FlagTargetInfo | ntlm.FlagVersion | ntlm.Flag128 | ntlm.Flag56 |
			ntlm.FlagExtendedSessionSecurity,
		ServerChallenge: serverChallenge,
		TargetName:      "EXAMPLE",
		TargetInfo:      info,
	}
	return message.Encode()
}

// ntlmTestTargetInfo returns a minimal Active Directory target-info sequence,
// optionally carrying a channel binding. | ntlmTestTargetInfo 返回最小 Active
// Directory 目标信息序列，可选携带通道绑定。
func ntlmTestTargetInfo(channelBinding []byte) ntlm.TargetInfo {
	info := ntlm.TargetInfo{
		{Type: ntlm.AVNbDomainName, Value: ntlmTestUTF16("EXAMPLE")},
		{Type: ntlm.AVNbComputerName, Value: ntlmTestUTF16("DC01")},
	}
	if len(channelBinding) > 0 {
		info = append(info, ntlm.AVPair{Type: ntlm.AVChannelBindings, Value: append([]byte(nil), channelBinding...)})
	}
	return info
}

// ntlmTestUTF16 encodes a string as UTF-16LE. | ntlmTestUTF16 把字符串编码为 UTF-16LE。
func ntlmTestUTF16(value string) []byte {
	units := utf16.Encode([]rune(value))
	out := make([]byte, len(units)*2)
	for index, unit := range units {
		binary.LittleEndian.PutUint16(out[index*2:], unit)
	}
	return out
}

// ntlmTestTLV encodes one DER tag-length-value. | ntlmTestTLV 编码一个 DER
// 标签-长度-值。
func ntlmTestTLV(tag byte, value []byte) []byte {
	out := make([]byte, 0, 1+len(value)+4)
	out = append(out, tag)
	out = append(out, ntlmTestLength(len(value))...)
	return append(out, value...)
}

// ntlmTestLength encodes a DER length in minimal form. | ntlmTestLength 以最小形式编码
// DER 长度。
func ntlmTestLength(length int) []byte {
	if length < 0x80 {
		return []byte{byte(length)}
	}
	var buffer [8]byte
	index := len(buffer)
	for value := length; value > 0; value >>= 8 {
		index--
		buffer[index] = byte(value)
	}
	out := []byte{0x80 | byte(len(buffer)-index)}
	return append(out, buffer[index:]...)
}

// ntlmTestSequence encodes a constructed DER value. | ntlmTestSequence 编码构造的 DER 值。
func ntlmTestSequence(tag byte, children ...[]byte) []byte {
	var content []byte
	for _, child := range children {
		content = append(content, child...)
	}
	return ntlmTestTLV(tag, content)
}

// ntlmTestNegTokenResp builds a server NegTokenResp with optional negState,
// supportedMech and responseToken fields. | ntlmTestNegTokenResp 构造带可选
// negState、supportedMech 与 responseToken 字段的服务端 NegTokenResp。
func ntlmTestNegTokenResp(state *ntlm.NegState, supportedMech, token []byte) []byte {
	fields := make([][]byte, 0, 3)
	if state != nil {
		fields = append(fields, ntlmTestTLV(0xA0, ntlmTestTLV(0x0A, []byte{byte(*state)})))
	}
	if len(supportedMech) > 0 {
		fields = append(fields, ntlmTestTLV(0xA1, ntlmTestTLV(0x06, supportedMech)))
	}
	if token != nil {
		fields = append(fields, ntlmTestTLV(0xA2, ntlmTestTLV(0x04, token)))
	}
	return ntlmTestTLV(0xA1, ntlmTestSequence(0x30, fields...))
}

// ntlmTestKerberosOID is the DER body of the Kerberos V5 object identifier. |
// ntlmTestKerberosOID 是 Kerberos V5 对象标识符的 DER 主体。
func ntlmTestKerberosOID() []byte {
	return []byte{0x2a, 0x86, 0x48, 0x86, 0xf7, 0x12, 0x01, 0x02, 0x02}
}

// ntlmTestDial opens a client to a mock server. | ntlmTestDial 打开到模拟服务端的客户端。
func ntlmTestDial(t *testing.T, server *mockServer, cfg ...Config) *Client {
	t.Helper()
	client, err := DialURL(mustTimeoutContext(t, 5*time.Second), server.URL(), cfg...)
	if err != nil {
		t.Fatalf("DialURL: %v", err)
	}
	t.Cleanup(func() { _ = client.Close() })
	return client
}

// TestBindNTLMGSSSPNEGO performs a successful GSS-SPNEGO NTLMv2 exchange. |
// TestBindNTLMGSSSPNEGO 执行成功的 GSS-SPNEGO NTLMv2 交换。
func TestBindNTLMGSSSPNEGO(t *testing.T) {
	serverChallenge := [8]byte{0x01, 0x23, 0x45, 0x67, 0x89, 0xab, 0xcd, 0xef}
	cfg := ntlmTestConfig{
		serverChallenge: serverChallenge,
		info:            ntlmTestTargetInfo(nil),
		mechanism:       SASLMechanismGSSSPNEGO,
		username:        "alice",
		domain:          "EXAMPLE",
		password:        ntlmTestPassword,
		type1Domain:     "EXAMPLE",
		workstation:     "WS",
	}
	handler, recorder := ntlmTestHandler(t, cfg)
	server := startMockServer(t, handler)
	client := ntlmTestDial(t, server)
	if err := client.BindNTLM(mustTimeoutContext(t, 5*time.Second), NTLMOptions{
		Username:    `EXAMPLE\alice`,
		Password:    ntlmTestPassword,
		Workstation: " WS ",
	}); err != nil {
		t.Fatalf("BindNTLM: %v", err)
	}
	binds, mechanisms, negotiate, authenticate := recorder.snapshot()
	if binds != 2 {
		t.Fatalf("binds = %d, want 2", binds)
	}
	if len(mechanisms) != 2 || mechanisms[0] != SASLMechanismGSSSPNEGO || mechanisms[1] != SASLMechanismGSSSPNEGO {
		t.Fatalf("mechanisms = %v, want GSS-SPNEGO twice", mechanisms)
	}
	if negotiate == nil || negotiate.Domain != "EXAMPLE" || negotiate.Workstation != "WS" {
		t.Fatalf("Type 1 = %+v, want domain EXAMPLE and workstation WS", negotiate)
	}
	if authenticate == nil || authenticate.Username != "alice" || authenticate.Domain != "EXAMPLE" {
		t.Fatalf("Type 3 = %+v, want EXAMPLE\\alice", authenticate)
	}
	if client.auth == nil || client.auth.kind != authNTLM {
		t.Fatalf("auth state = %+v, want authNTLM", client.auth)
	}
	if client.auth.ntlm.Mechanism != SASLMechanismGSSSPNEGO {
		t.Fatalf("retained mechanism = %q, want %q", client.auth.ntlm.Mechanism, SASLMechanismGSSSPNEGO)
	}
}

// TestBindSASLNTLMAlias verifies the compatibility alias performs the same
// exchange as BindNTLM. | TestBindSASLNTLMAlias 校验兼容别名执行与 BindNTLM 相同的交换。
func TestBindSASLNTLMAlias(t *testing.T) {
	mock := &ntlmAcceptorMock{
		newConfig: func() ntlm.AcceptorConfig { return ntlmAcceptorConfig(ntlmAcceptorOptions{}) },
	}
	server := startMockServer(t, mock.handle)
	client := ntlmTestDial(t, server)
	if err := client.BindSASLNTLM(mustTimeoutContext(t, 5*time.Second), NTLMOptions{
		Username: `EXAMPLE\alice`,
		Password: ntlmTestPassword,
	}); err != nil {
		t.Fatalf("BindSASLNTLM: %v", err)
	}
	connections, results, extraBinds, _ := mock.snapshot()
	if connections != 1 || results != 1 || extraBinds != 0 {
		t.Fatalf("connections = %d, results = %d, extra binds = %d, want 1, 1, 0", connections, results, extraBinds)
	}
	if client.auth == nil || client.auth.kind != authNTLM {
		t.Fatalf("auth state = %+v, want authNTLM", client.auth)
	}
}

// TestBindNTLMRawMechanism performs the exchange with raw NTLMSSP tokens. |
// TestBindNTLMRawMechanism 使用裸 NTLMSSP 令牌执行交换。
func TestBindNTLMRawMechanism(t *testing.T) {
	cfg := ntlmTestConfig{
		serverChallenge: [8]byte{0x10, 0x20, 0x30, 0x40, 0x50, 0x60, 0x70, 0x80},
		info:            ntlmTestTargetInfo(nil),
		mechanism:       SASLMechanismNTLM,
		raw:             true,
		username:        "alice",
		domain:          "EXAMPLE",
		password:        ntlmTestPassword,
		type1Domain:     "EXAMPLE",
	}
	handler, recorder := ntlmTestHandler(t, cfg)
	server := startMockServer(t, handler)
	client := ntlmTestDial(t, server)
	if err := client.BindNTLM(mustTimeoutContext(t, 5*time.Second), NTLMOptions{
		Username:  "alice",
		Password:  ntlmTestPassword,
		Domain:    "EXAMPLE",
		Mechanism: "ntlm",
	}); err != nil {
		t.Fatalf("BindNTLM: %v", err)
	}
	binds, mechanisms, negotiate, authenticate := recorder.snapshot()
	if binds != 2 {
		t.Fatalf("binds = %d, want 2", binds)
	}
	if len(mechanisms) != 2 || mechanisms[0] != SASLMechanismNTLM || mechanisms[1] != SASLMechanismNTLM {
		t.Fatalf("mechanisms = %v, want NTLM twice", mechanisms)
	}
	if negotiate == nil || authenticate == nil {
		t.Fatalf("missing messages: Type 1 = %v, Type 3 = %v", negotiate, authenticate)
	}
	if client.auth == nil || client.auth.kind != authNTLM || client.auth.ntlm.Mechanism != SASLMechanismNTLM {
		t.Fatalf("auth state = %+v, want retained raw NTLM", client.auth)
	}
}

// TestBindNTLMIdentityForms verifies DOMAIN\user, UPN and configured-domain
// normalization. | TestBindNTLMIdentityForms 校验 DOMAIN\user、UPN 与配置域规范化。
func TestBindNTLMIdentityForms(t *testing.T) {
	tests := []struct {
		name        string
		username    string
		domain      string
		wantUser    string
		wantDomain  string
		wantType1DN string
	}{
		{"backslash login", `EXAMPLE\alice`, "", "alice", "EXAMPLE", "EXAMPLE"},
		{"upn login", "alice@example.com", "EXAMPLE", "alice@example.com", "", ""},
		{"plain login with domain", "alice", "EXAMPLE", "alice", "EXAMPLE", "EXAMPLE"},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			cfg := ntlmTestConfig{
				serverChallenge: [8]byte{0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff, 0x11, 0x22},
				info:            ntlmTestTargetInfo(nil),
				mechanism:       SASLMechanismGSSSPNEGO,
				username:        test.wantUser,
				domain:          test.wantDomain,
				password:        ntlmTestPassword,
				type1Domain:     test.wantType1DN,
				workstation:     "WS",
			}
			handler, recorder := ntlmTestHandler(t, cfg)
			server := startMockServer(t, handler)
			client := ntlmTestDial(t, server)
			if err := client.BindNTLM(mustTimeoutContext(t, 5*time.Second), NTLMOptions{
				Username:    test.username,
				Password:    ntlmTestPassword,
				Domain:      test.domain,
				Workstation: "WS",
			}); err != nil {
				t.Fatalf("BindNTLM: %v", err)
			}
			_, _, negotiate, authenticate := recorder.snapshot()
			if negotiate == nil || authenticate == nil {
				t.Fatalf("missing messages: Type 1 = %v, Type 3 = %v", negotiate, authenticate)
			}
			if authenticate.Username != test.wantUser || authenticate.Domain != test.wantDomain {
				t.Fatalf("Type 3 identity = %s\\%s, want %s\\%s", authenticate.Domain, authenticate.Username, test.wantDomain, test.wantUser)
			}
		})
	}
}

// TestBindNTLMInvalidCredentials verifies a rejected final bind surfaces the LDAP
// sentinel without leaking the password. | TestBindNTLMInvalidCredentials 校验最终绑定
// 被拒时返回 LDAP 哨兵且不泄漏口令。
func TestBindNTLMInvalidCredentials(t *testing.T) {
	invalid := ResultInvalidCredentials
	cfg := ntlmTestConfig{
		serverChallenge: [8]byte{1, 2, 3, 4, 5, 6, 7, 8},
		info:            ntlmTestTargetInfo(nil),
		mechanism:       SASLMechanismGSSSPNEGO,
		username:        "alice",
		domain:          "EXAMPLE",
		password:        ntlmTestPassword,
		type1Domain:     "EXAMPLE",
		secondResult:    &invalid,
	}
	handler, recorder := ntlmTestHandler(t, cfg)
	server := startMockServer(t, handler)
	client := ntlmTestDial(t, server)
	err := client.BindNTLM(mustTimeoutContext(t, 5*time.Second), NTLMOptions{
		Username: `EXAMPLE\alice`,
		Password: ntlmTestPassword,
	})
	if err == nil {
		t.Fatal("BindNTLM succeeded, want invalid credentials")
	}
	if !errors.Is(err, ErrInvalidCredentials) {
		t.Fatalf("error = %v, want ErrInvalidCredentials", err)
	}
	if strings.Contains(err.Error(), ntlmTestPassword) {
		t.Fatalf("error leaks the password: %v", err)
	}
	binds, _, _, authenticate := recorder.snapshot()
	if binds != 2 {
		t.Fatalf("binds = %d, want 2", binds)
	}
	if authenticate == nil {
		t.Fatal("server did not receive a valid Type 3 message")
	}
	if client.auth != nil {
		t.Fatalf("auth state = %+v, want nil after failure", client.auth)
	}
}

// TestBindNTLMRejectsWrongChallenge verifies an all-zero server challenge is
// rejected before the client emits a Type 3 message. | TestBindNTLMRejectsWrongChallenge
// 校验客户端在发出 Type 3 消息之前拒绝全零服务端挑战。
func TestBindNTLMRejectsWrongChallenge(t *testing.T) {
	cfg := ntlmTestConfig{
		serverChallenge: [8]byte{},
		info:            ntlmTestTargetInfo(nil),
		mechanism:       SASLMechanismGSSSPNEGO,
		username:        "alice",
		domain:          "EXAMPLE",
		password:        ntlmTestPassword,
		type1Domain:     "EXAMPLE",
	}
	handler, recorder := ntlmTestHandler(t, cfg)
	server := startMockServer(t, handler)
	client := ntlmTestDial(t, server)
	err := client.BindNTLM(mustTimeoutContext(t, 5*time.Second), NTLMOptions{
		Username: `EXAMPLE\alice`,
		Password: ntlmTestPassword,
	})
	if err == nil {
		t.Fatal("BindNTLM accepted an all-zero challenge")
	}
	if !errors.Is(err, ntlm.ErrChallenge) || !errors.Is(err, ErrNTLM) {
		t.Fatalf("error = %v, want ErrChallenge and ErrNTLM", err)
	}
	if strings.Contains(err.Error(), ntlmTestPassword) {
		t.Fatalf("error leaks the password: %v", err)
	}
	binds, _, _, authenticate := recorder.snapshot()
	if binds != 1 {
		t.Fatalf("binds = %d, want 1 (no Type 3 after a rejected challenge)", binds)
	}
	if authenticate != nil {
		t.Fatal("client emitted a Type 3 message after a rejected challenge")
	}
}

// TestBindNTLMRejectsInvalidChallengeTokens covers malformed, empty and
// unacceptable SPNEGO challenge tokens. | TestBindNTLMRejectsInvalidChallengeTokens
// 覆盖畸形、空以及不可接受的 SPNEGO 挑战令牌。
func TestBindNTLMRejectsInvalidChallengeTokens(t *testing.T) {
	reject := ntlm.NegStateReject
	requestMIC := ntlm.NegStateRequestMIC
	acceptCompleted := ntlm.NegStateAcceptCompleted
	unknownState := ntlm.NegState(4)
	tests := []struct {
		name     string
		wrap     func([]byte) ([]byte, error)
		sentinel error
		accept   bool
	}{
		{
			name:     "malformed spnego",
			wrap:     func([]byte) ([]byte, error) { return []byte{0x05}, nil },
			sentinel: ntlm.ErrSPNEGO,
		},
		{
			name: "non ntlm mechanism",
			wrap: func(challenge []byte) ([]byte, error) {
				return ntlmTestNegTokenResp(nil, ntlmTestKerberosOID(), challenge), nil
			},
		},
		{
			name: "reject state",
			wrap: func(challenge []byte) ([]byte, error) {
				return ntlmTestNegTokenResp(&reject, nil, challenge), nil
			},
		},
		{
			name: "request mic state",
			wrap: func(challenge []byte) ([]byte, error) {
				return ntlmTestNegTokenResp(&requestMIC, nil, challenge), nil
			},
			accept: true,
		},
		{
			name: "accept completed state",
			wrap: func(challenge []byte) ([]byte, error) {
				return ntlmTestNegTokenResp(&acceptCompleted, nil, challenge), nil
			},
		},
		{
			name: "unknown state",
			wrap: func(challenge []byte) ([]byte, error) {
				return ntlmTestNegTokenResp(&unknownState, nil, challenge), nil
			},
			sentinel: ntlm.ErrSPNEGO,
		},
		{
			name: "empty challenge",
			wrap: func([]byte) ([]byte, error) { return nil, nil },
		},
		{
			name: "no mech token",
			wrap: func([]byte) ([]byte, error) {
				return ntlmTestNegTokenResp(nil, nil, nil), nil
			},
		},
		{
			name: "malformed type two",
			wrap: func([]byte) ([]byte, error) {
				return ntlm.EncodeSPNEGOResponse([]byte("not-an-ntlmssp-message"))
			},
			sentinel: ntlm.ErrMessage,
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			cfg := ntlmTestConfig{
				serverChallenge: [8]byte{9, 8, 7, 6, 5, 4, 3, 2},
				info:            ntlmTestTargetInfo(nil),
				mechanism:       SASLMechanismGSSSPNEGO,
				username:        "alice",
				domain:          "EXAMPLE",
				password:        ntlmTestPassword,
				type1Domain:     "EXAMPLE",
				wrapChallenge:   test.wrap,
			}
			handler, recorder := ntlmTestHandler(t, cfg)
			server := startMockServer(t, handler)
			client := ntlmTestDial(t, server)
			err := client.BindNTLM(mustTimeoutContext(t, 5*time.Second), NTLMOptions{
				Username: `EXAMPLE\alice`,
				Password: ntlmTestPassword,
			})
			if test.accept {
				// NegStateRequestMIC is a normal request for the client
				// mechListMIC, not an unsupported challenge. | NegStateRequestMIC
				// 是对客户端 mechListMIC 的正常请求，不是不支持的挑战。
				if err != nil {
					t.Fatalf("BindNTLM rejected a request-mic challenge: %v", err)
				}
				binds, _, _, authenticate := recorder.snapshot()
				if binds != 2 {
					t.Fatalf("binds = %d, want 2", binds)
				}
				if authenticate == nil {
					t.Fatal("client did not emit a Type 3 message")
				}
				final := recorder.finalSPNEGO()
				if final == nil || !final.HasMechListMIC {
					t.Fatalf("final SPNEGO token lacks a mechListMIC: %+v", final)
				}
				return
			}
			if err == nil {
				t.Fatal("BindNTLM accepted an invalid challenge token")
			}
			if !errors.Is(err, ErrNTLM) {
				t.Fatalf("error = %v, want ErrNTLM", err)
			}
			if test.sentinel != nil && !errors.Is(err, test.sentinel) {
				t.Fatalf("error = %v, want sentinel %v", err, test.sentinel)
			}
			binds, _, _, authenticate := recorder.snapshot()
			if binds != 1 {
				t.Fatalf("binds = %d, want 1", binds)
			}
			if authenticate != nil {
				t.Fatal("client emitted a Type 3 message after an invalid challenge")
			}
		})
	}
}

// TestBindNTLMFinalSPNEGOToken verifies the optional server token after the
// final bind. | TestBindNTLMFinalSPNEGOToken 校验最终绑定后可选的 SPNEGO 令牌。
func TestBindNTLMFinalSPNEGOToken(t *testing.T) {
	acceptCompleted := ntlm.NegStateAcceptCompleted
	acceptIncomplete := ntlm.NegStateAcceptIncomplete
	reject := ntlm.NegStateReject
	requestMIC := ntlm.NegStateRequestMIC
	unknownState := ntlm.NegState(4)
	tests := []struct {
		name        string
		credentials []byte
		wantErr     bool
		sentinel    error
	}{
		{
			name:        "accept completed",
			credentials: ntlmTestNegTokenResp(&acceptCompleted, nil, nil),
		},
		{
			name:        "accept incomplete",
			credentials: ntlmTestNegTokenResp(&acceptIncomplete, nil, nil),
			wantErr:     true,
			sentinel:    ntlm.ErrSPNEGOState,
		},
		{
			name:        "reject",
			credentials: ntlmTestNegTokenResp(&reject, nil, nil),
			wantErr:     true,
		},
		{
			name:        "request mic",
			credentials: ntlmTestNegTokenResp(&requestMIC, nil, nil),
			wantErr:     true,
		},
		{
			name:        "unknown state",
			credentials: ntlmTestNegTokenResp(&unknownState, nil, nil),
			wantErr:     true,
			sentinel:    ntlm.ErrSPNEGO,
		},
		{
			name:        "malformed token",
			credentials: []byte{0x05},
			wantErr:     true,
			sentinel:    ntlm.ErrSPNEGO,
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			cfg := ntlmTestConfig{
				serverChallenge:  [8]byte{3, 1, 4, 1, 5, 9, 2, 6},
				info:             ntlmTestTargetInfo(nil),
				mechanism:        SASLMechanismGSSSPNEGO,
				username:         "alice",
				domain:           "EXAMPLE",
				password:         ntlmTestPassword,
				type1Domain:      "EXAMPLE",
				finalCredentials: test.credentials,
			}
			handler, recorder := ntlmTestHandler(t, cfg)
			server := startMockServer(t, handler)
			client := ntlmTestDial(t, server)
			err := client.BindNTLM(mustTimeoutContext(t, 5*time.Second), NTLMOptions{
				Username: `EXAMPLE\alice`,
				Password: ntlmTestPassword,
			})
			if test.wantErr {
				if err == nil {
					t.Fatal("BindNTLM accepted an unacceptable final SPNEGO token")
				}
				if !errors.Is(err, ErrNTLM) {
					t.Fatalf("error = %v, want ErrNTLM", err)
				}
				if test.sentinel != nil && !errors.Is(err, test.sentinel) {
					t.Fatalf("error = %v, want sentinel %v", err, test.sentinel)
				}
				if client.auth != nil {
					t.Fatalf("auth state = %+v, want nil after failure", client.auth)
				}
				// The server reported success before the final token failed
				// verification, so the transport must be torn down. | 服务端在
				// 最终令牌校验失败前已报告成功，因此必须拆除传输。
				if client.conn != nil {
					t.Fatal("connection was not invalidated after a final SPNEGO failure")
				}
			} else if err != nil {
				t.Fatalf("BindNTLM: %v", err)
			}
			binds, _, _, authenticate := recorder.snapshot()
			if binds != 2 {
				t.Fatalf("binds = %d, want 2", binds)
			}
			if authenticate == nil {
				t.Fatal("server did not receive a valid Type 3 message")
			}
		})
	}
}

// TestBindNTLMChannelBindingTLS verifies tls-server-end-point channel binding
// over LDAPS. | TestBindNTLMChannelBindingTLS 校验 LDAPS 上的
// tls-server-end-point 通道绑定。
func TestBindNTLMChannelBindingTLS(t *testing.T) {
	certificate, pool := testCertificate(t)
	endpointHash, err := tlsServerEndPoint(certificate.Leaf)
	if err != nil {
		t.Fatalf("tlsServerEndPoint: %v", err)
	}
	binding, err := ntlm.ChannelBindingHash(endpointHash)
	if err != nil {
		t.Fatalf("ChannelBindingHash: %v", err)
	}
	cfg := ntlmTestConfig{
		serverChallenge: [8]byte{0xde, 0xad, 0xbe, 0xef, 0xca, 0xfe, 0xba, 0xbe},
		info:            ntlmTestTargetInfo(nil),
		mechanism:       SASLMechanismGSSSPNEGO,
		username:        "alice",
		domain:          "EXAMPLE",
		password:        ntlmTestPassword,
		type1Domain:     "EXAMPLE",
		channelBinding:  binding,
	}
	handler, recorder := ntlmTestHandler(t, cfg)
	serverTLS := &tls.Config{Certificates: []tls.Certificate{certificate}, MinVersion: tls.VersionTLS12}
	server := startMockServerTLS(t, serverTLS, handler)
	client := ntlmTestDial(t, server, Config{TLSConfig: testTLSConfig(pool)})
	if err := client.BindNTLM(mustTimeoutContext(t, 5*time.Second), NTLMOptions{
		Username:       `EXAMPLE\alice`,
		Password:       ntlmTestPassword,
		ChannelBinding: true,
	}); err != nil {
		t.Fatalf("BindNTLM: %v", err)
	}
	if _, secure := client.TLSConnectionState(); !secure {
		t.Fatal("connection is not TLS-protected")
	}
	binds, _, _, authenticate := recorder.snapshot()
	if binds != 2 {
		t.Fatalf("binds = %d, want 2", binds)
	}
	if authenticate == nil {
		t.Fatal("server did not receive a valid Type 3 message")
	}
}

// TestBindNTLMChannelBindingMismatch verifies a server binding without a client
// binding is rejected. | TestBindNTLMChannelBindingMismatch 校验服务端提供绑定而客户端
// 未配置时被拒绝。
func TestBindNTLMChannelBindingMismatch(t *testing.T) {
	wrong := bytes.Repeat([]byte{0xa5}, 16)
	cfg := ntlmTestConfig{
		serverChallenge: [8]byte{0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88},
		info:            ntlmTestTargetInfo(wrong),
		mechanism:       SASLMechanismGSSSPNEGO,
		username:        "alice",
		domain:          "EXAMPLE",
		password:        ntlmTestPassword,
		type1Domain:     "EXAMPLE",
	}
	handler, recorder := ntlmTestHandler(t, cfg)
	server := startMockServer(t, handler)
	client := ntlmTestDial(t, server)
	err := client.BindNTLM(mustTimeoutContext(t, 5*time.Second), NTLMOptions{
		Username: `EXAMPLE\alice`,
		Password: ntlmTestPassword,
	})
	if err == nil {
		t.Fatal("BindNTLM accepted an unexpected server channel binding")
	}
	if !errors.Is(err, ntlm.ErrChannelBindings) || !errors.Is(err, ErrNTLM) {
		t.Fatalf("error = %v, want ErrChannelBindings and ErrNTLM", err)
	}
	binds, _, _, authenticate := recorder.snapshot()
	if binds != 1 {
		t.Fatalf("binds = %d, want 1", binds)
	}
	if authenticate != nil {
		t.Fatal("client emitted a Type 3 message after a channel binding mismatch")
	}
}

// TestBindNTLMChannelBindingRequiresTLS verifies channel binding is refused on a
// plaintext connection. | TestBindNTLMChannelBindingRequiresTLS 校验明文连接上拒绝通道绑定。
func TestBindNTLMChannelBindingRequiresTLS(t *testing.T) {
	cfg := ntlmTestConfig{
		serverChallenge: [8]byte{1, 2, 3, 4, 5, 6, 7, 8},
		info:            ntlmTestTargetInfo(nil),
		mechanism:       SASLMechanismGSSSPNEGO,
		username:        "alice",
		domain:          "EXAMPLE",
		password:        ntlmTestPassword,
		type1Domain:     "EXAMPLE",
	}
	handler, recorder := ntlmTestHandler(t, cfg)
	server := startMockServer(t, handler)
	client := ntlmTestDial(t, server)
	err := client.BindNTLM(mustTimeoutContext(t, 5*time.Second), NTLMOptions{
		Username:       `EXAMPLE\alice`,
		Password:       ntlmTestPassword,
		ChannelBinding: true,
	})
	if err == nil {
		t.Fatal("BindNTLM accepted channel binding over plaintext")
	}
	if !errors.Is(err, ErrTLSRequired) {
		t.Fatalf("error = %v, want ErrTLSRequired", err)
	}
	binds, _, _, _ := recorder.snapshot()
	if binds != 0 {
		t.Fatalf("binds = %d, want 0", binds)
	}
	if client.auth != nil {
		t.Fatalf("auth state = %+v, want nil", client.auth)
	}
}

// TestBindNTLMServerResultErrors covers protocol-level result codes from the
// server. | TestBindNTLMServerResultErrors 覆盖服务端返回的协议级结果码。
func TestBindNTLMServerResultErrors(t *testing.T) {
	success := ResultSuccess
	invalid := ResultInvalidCredentials
	tests := []struct {
		name   string
		first  *ResultCode
		second *ResultCode
		want   error
	}{
		{
			name:  "completed without challenge",
			first: &success,
			want:  ErrNTLM,
		},
		{
			name:  "invalid credentials at first bind",
			first: &invalid,
			want:  ErrInvalidCredentials,
		},
		{
			name:   "invalid credentials at final bind",
			second: &invalid,
			want:   ErrInvalidCredentials,
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			cfg := ntlmTestConfig{
				serverChallenge: [8]byte{8, 7, 6, 5, 4, 3, 2, 1},
				info:            ntlmTestTargetInfo(nil),
				mechanism:       SASLMechanismGSSSPNEGO,
				username:        "alice",
				domain:          "EXAMPLE",
				password:        ntlmTestPassword,
				type1Domain:     "EXAMPLE",
				firstResult:     test.first,
				secondResult:    test.second,
			}
			handler, recorder := ntlmTestHandler(t, cfg)
			server := startMockServer(t, handler)
			client := ntlmTestDial(t, server)
			err := client.BindNTLM(mustTimeoutContext(t, 5*time.Second), NTLMOptions{
				Username: `EXAMPLE\alice`,
				Password: ntlmTestPassword,
			})
			if err == nil {
				t.Fatal("BindNTLM succeeded, want a server result error")
			}
			if !errors.Is(err, test.want) {
				t.Fatalf("error = %v, want %v", err, test.want)
			}
			if strings.Contains(err.Error(), ntlmTestPassword) {
				t.Fatalf("error leaks the password: %v", err)
			}
			if client.auth != nil {
				t.Fatalf("auth state = %+v, want nil", client.auth)
			}
			binds, _, _, _ := recorder.snapshot()
			wantBinds := 1
			if test.second != nil {
				wantBinds = 2
			}
			if binds != wantBinds {
				t.Fatalf("binds = %d, want %d", binds, wantBinds)
			}
		})
	}
}

// TestBindNTLMValidation rejects invalid options before any network I/O. |
// TestBindNTLMValidation 在任何网络 I/O 之前拒绝非法选项。
func TestBindNTLMValidation(t *testing.T) {
	tests := []struct {
		name    string
		options NTLMOptions
		want    error
		also    error
		secret  string
	}{
		{
			name:    "unsupported mechanism",
			options: NTLMOptions{Username: "alice", Password: ntlmTestPassword, Mechanism: "KERBEROS"},
			want:    ErrNTLM,
			secret:  ntlmTestPassword,
		},
		{
			name:    "empty username",
			options: NTLMOptions{Password: ntlmTestPassword},
			want:    ErrNTLM,
			secret:  ntlmTestPassword,
		},
		{
			name:    "empty password",
			options: NTLMOptions{Username: "alice"},
			want:    ErrEmptyPassword,
		},
		{
			name:    "nul in username",
			options: NTLMOptions{Username: "ali\x00ce", Password: ntlmTestPassword},
			want:    ErrNTLM,
			secret:  ntlmTestPassword,
		},
		{
			name:    "nul in password",
			options: NTLMOptions{Username: "alice", Password: "secret\x00value"},
			want:    ErrNTLM,
			secret:  "secret\x00value",
		},
		{
			name:    "malformed backslash login",
			options: NTLMOptions{Username: `EXAMPLE\`, Password: ntlmTestPassword},
			want:    ErrNTLM,
			secret:  ntlmTestPassword,
		},
		{
			name:    "conflicting domain",
			options: NTLMOptions{Username: `EXAMPLE\alice`, Password: ntlmTestPassword, Domain: "OTHER"},
			want:    ErrNTLM,
			secret:  ntlmTestPassword,
		},
		{
			name:    "ntlmv1 without legacy",
			options: NTLMOptions{Username: "alice", Password: ntlmTestPassword, ResponseMode: ntlm.ResponseNTLMv1},
			want:    ErrNTLM,
			also:    ntlm.ErrLegacyDisabled,
			secret:  ntlmTestPassword,
		},
		{
			name:    "ntlm2 session without legacy",
			options: NTLMOptions{Username: "alice", Password: ntlmTestPassword, ResponseMode: ntlm.ResponseNTLM2Session},
			want:    ErrNTLM,
			also:    ntlm.ErrLegacyDisabled,
			secret:  ntlmTestPassword,
		},
		{
			name: "channel binding with legacy mode",
			options: NTLMOptions{
				Username: "alice", Password: ntlmTestPassword,
				ResponseMode: ntlm.ResponseNTLMv1, AllowLegacy: true, ChannelBinding: true,
			},
			want:   ErrNTLM,
			secret: ntlmTestPassword,
		},
		{
			name: "force mic with legacy mode",
			options: NTLMOptions{
				Username: "alice", Password: ntlmTestPassword,
				ResponseMode: ntlm.ResponseNTLMv1, AllowLegacy: true, ForceMIC: true,
			},
			want:   ErrNTLM,
			also:   ntlm.ErrUnsupported,
			secret: ntlmTestPassword,
		},
		{
			name: "unknown response mode",
			options: NTLMOptions{
				Username: "alice", Password: ntlmTestPassword,
				ResponseMode: ntlm.ResponseMode(99), AllowLegacy: true,
			},
			want:   ErrNTLM,
			also:   ntlm.ErrUnsupported,
			secret: ntlmTestPassword,
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			client := &Client{}
			err := client.BindNTLM(mustTimeoutContext(t, time.Second), test.options)
			if err == nil {
				t.Fatal("BindNTLM accepted invalid options")
			}
			if !errors.Is(err, test.want) {
				t.Fatalf("error = %v, want %v", err, test.want)
			}
			if test.also != nil && !errors.Is(err, test.also) {
				t.Fatalf("error = %v, want also %v", err, test.also)
			}
			if test.secret != "" && strings.Contains(err.Error(), test.secret) {
				t.Fatalf("error leaks secret material: %v", err)
			}
		})
	}
}

// TestBindNTLMReconnectReplays verifies Reconnect repeats the NTLM exchange from
// retained credentials. | TestBindNTLMReconnectReplays 校验 Reconnect 使用保留凭据重放
// NTLM 交换。
func TestBindNTLMReconnectReplays(t *testing.T) {
	cfg := ntlmTestConfig{
		serverChallenge: [8]byte{0xc0, 0xff, 0xee, 0x11, 0x22, 0x33, 0x44, 0x55},
		info:            ntlmTestTargetInfo(nil),
		mechanism:       SASLMechanismGSSSPNEGO,
		username:        "alice",
		domain:          "EXAMPLE",
		password:        ntlmTestPassword,
		type1Domain:     "EXAMPLE",
	}
	handler, recorder := ntlmTestHandler(t, cfg)
	server := startMockServer(t, handler)
	client := ntlmTestDial(t, server)
	ctx := mustTimeoutContext(t, 5*time.Second)
	if err := client.BindNTLM(ctx, NTLMOptions{
		Username: `EXAMPLE\alice`,
		Password: ntlmTestPassword,
	}); err != nil {
		t.Fatalf("BindNTLM: %v", err)
	}
	if err := client.Reconnect(ctx); err != nil {
		t.Fatalf("Reconnect: %v", err)
	}
	binds, mechanisms, _, authenticate := recorder.snapshot()
	if binds != 4 {
		t.Fatalf("binds = %d, want 4 (two exchanges)", binds)
	}
	if len(mechanisms) != 4 {
		t.Fatalf("mechanisms = %v, want four SASL binds", mechanisms)
	}
	for _, mechanism := range mechanisms {
		if mechanism != SASLMechanismGSSSPNEGO {
			t.Fatalf("mechanism = %q, want %q", mechanism, SASLMechanismGSSSPNEGO)
		}
	}
	if authenticate == nil {
		t.Fatal("replayed exchange did not produce a valid Type 3 message")
	}
	if client.auth == nil || client.auth.kind != authNTLM {
		t.Fatalf("auth state = %+v, want authNTLM after replay", client.auth)
	}
}
