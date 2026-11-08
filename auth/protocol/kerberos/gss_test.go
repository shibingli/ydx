package kerberos

import (
	"bytes"
	"errors"
	"fmt"
	"testing"
	"time"
)

// newGSSClientForMock builds a GSS initiator backed by a mock-KDC client. |
// newGSSClientForMock 构建由模拟 KDC 客户端支持的 GSS 发起方。
func newGSSClientForMock(t *testing.T, m *mockKDC, etypes []int32, opts GSSClientOptions) *GSSClient {
	t.Helper()
	if len(etypes) == 0 {
		etypes = []int32{ETypeAES256CTS}
	}
	if opts.Client == nil {
		opts.Client = mustClient(t, m.clientConfig(etypes...))
	}
	if opts.Service == "" {
		opts.Service = m.opts.servicePrincipal
	}
	client, err := NewGSSClient(opts)
	if err != nil {
		t.Fatalf("NewGSSClient: %v", err)
	}
	return client
}

// newAcceptorForMock builds an acceptor using the mock-KDC service keytab. |
// newAcceptorForMock 使用模拟 KDC 的服务 keytab 构建接受方。
func newAcceptorForMock(t *testing.T, m *mockKDC, opts AcceptorOptions) *Acceptor {
	t.Helper()
	if opts.KeyTab == nil {
		opts.KeyTab = m.keytab()
	}
	if opts.Service == "" {
		opts.Service = m.opts.servicePrincipal
	}
	if opts.Realm == "" {
		opts.Realm = m.opts.realm
	}
	acceptor, err := NewAcceptor(opts)
	if err != nil {
		t.Fatalf("NewAcceptor: %v", err)
	}
	return acceptor
}

// gssInitial produces the first context token. | gssInitial 生成第一个上下文令牌。
func gssInitial(t *testing.T, g *GSSClient) []byte {
	t.Helper()
	token, err := g.InitialToken(testContext(t))
	if err != nil {
		t.Fatalf("InitialToken: %v", err)
	}
	return token
}

// establishGSSMutual performs a mutual raw or SPNEGO handshake. | establishGSSMutual
// 执行双向原始或 SPNEGO 握手。
func establishGSSMutual(t *testing.T, m *mockKDC, etypes []int32, opts GSSClientOptions) (*GSSClient, *GSSSession, *Acceptor) {
	t.Helper()
	opts.MutualAuth = true
	g := newGSSClientForMock(t, m, etypes, opts)
	a := newAcceptorForMock(t, m, AcceptorOptions{})
	initial := gssInitial(t, g)
	response, session, err := a.Accept(initial)
	if err != nil {
		t.Fatalf("Accept: %v", err)
	}
	if len(response) == 0 {
		t.Fatal("mutual authentication produced no acceptor token")
	}
	reply, done, err := g.Step(testContext(t), response)
	if err != nil {
		t.Fatalf("Step: %v", err)
	}
	if !done || len(reply) != 0 {
		t.Fatalf("Step done = %v, reply bytes = %d, want done with no reply", done, len(reply))
	}
	if !g.Complete() {
		t.Fatal("GSS client context is not complete")
	}
	if session == nil || !session.MutualAuth {
		t.Fatal("acceptor session is not mutually authenticated")
	}
	return g, session, a
}

// TestGSSPerMessageProtection covers handshake, wrapping, and MICs for every
// supported encryption type. | TestGSSPerMessageProtection 覆盖每种受支持加密类型的
// 握手、封装与 MIC。
func TestGSSPerMessageProtection(t *testing.T) {
	for _, etype := range []int32{ETypeAES256CTS, ETypeAES128CTS, ETypeRC4HMAC} {
		t.Run(fmt.Sprintf("etype %d", etype), func(t *testing.T) {
			m := startMockKDC(t, mockKDCOptions{password: "gss"})
			g, session, _ := establishGSSMutual(t, m, []int32{etype}, GSSClientOptions{})
			wantFlags := uint32(gssContextMutual | gssContextReplay | gssContextSequence | gssContextIntegrity)
			if session.ContextFlags&wantFlags != wantFlags {
				t.Fatalf("context flags = 0x%x, want 0x%x", session.ContextFlags, wantFlags)
			}
			if !session.ClientPrincipal.Equal(NewPrincipalName(NameTypePrincipal, m.opts.clientPrincipal)) || session.ClientRealm != m.opts.realm {
				t.Fatalf("session client = %s@%s", session.ClientPrincipal.String(), session.ClientRealm)
			}
			for round := 0; round < 3; round++ {
				clientData := []byte(fmt.Sprintf("client message %d", round))
				sealed := round%2 == 0
				token, err := g.Wrap(clientData, sealed)
				if err != nil {
					t.Fatalf("client Wrap: %v", err)
				}
				plain, confidential, err := session.Unwrap(token)
				if err != nil {
					t.Fatalf("session Unwrap: %v", err)
				}
				if !bytes.Equal(plain, clientData) || confidential != sealed {
					t.Fatalf("session Unwrap = %q/%v, want %q/%v", plain, confidential, clientData, sealed)
				}
				serverData := []byte(fmt.Sprintf("server message %d", round))
				reply, err := session.Wrap(serverData, !sealed)
				if err != nil {
					t.Fatalf("session Wrap: %v", err)
				}
				plain, confidential, err = g.Unwrap(reply)
				if err != nil {
					t.Fatalf("client Unwrap: %v", err)
				}
				if !bytes.Equal(plain, serverData) || confidential == sealed {
					t.Fatalf("client Unwrap = %q/%v, want %q/%v", plain, confidential, serverData, !sealed)
				}
			}
			clientMIC, err := g.MIC([]byte("client mic"))
			if err != nil {
				t.Fatalf("client MIC: %v", err)
			}
			if err := session.VerifyMIC([]byte("client mic"), clientMIC); err != nil {
				t.Fatalf("session VerifyMIC: %v", err)
			}
			serverMIC, err := session.MIC([]byte("server mic"))
			if err != nil {
				t.Fatalf("session MIC: %v", err)
			}
			if err := g.VerifyMIC([]byte("server mic"), serverMIC); err != nil {
				t.Fatalf("client VerifyMIC: %v", err)
			}
			m.check(t)
		})
	}
}

// TestGSSNonMutualRaw covers a raw handshake without AP-REP. | TestGSSNonMutualRaw
// 覆盖不带 AP-REP 的原始握手。
func TestGSSNonMutualRaw(t *testing.T) {
	m := startMockKDC(t, mockKDCOptions{password: "gss"})
	g := newGSSClientForMock(t, m, []int32{ETypeAES256CTS}, GSSClientOptions{MutualAuth: false})
	a := newAcceptorForMock(t, m, AcceptorOptions{})
	initial := gssInitial(t, g)
	if !g.Complete() {
		t.Fatal("non-mutual raw context should be established after InitialToken")
	}
	response, session, err := a.Accept(initial)
	if err != nil {
		t.Fatalf("Accept: %v", err)
	}
	if len(response) != 0 {
		t.Fatalf("non-mutual Accept returned %d bytes, want none", len(response))
	}
	if session.MutualAuth {
		t.Fatal("non-mutual session reports mutual authentication")
	}
	if _, _, err := g.Step(testContext(t), nil); !errors.Is(err, ErrGSSAPI) {
		t.Fatalf("Step after completion error = %v, want ErrGSSAPI", err)
	}
	token, err := g.Wrap([]byte("non-mutual"), true)
	if err != nil {
		t.Fatalf("Wrap: %v", err)
	}
	plain, _, err := session.Unwrap(token)
	if err != nil || string(plain) != "non-mutual" {
		t.Fatalf("Unwrap = %q, %v", plain, err)
	}
	m.check(t)
}

// TestGSSSPNEGOHandshake covers SPNEGO negotiation with and without mutual
// authentication. | TestGSSSPNEGOHandshake 覆盖带与不带双向认证的 SPNEGO 协商。
func TestGSSSPNEGOHandshake(t *testing.T) {
	for _, mutual := range []bool{true, false} {
		t.Run(fmt.Sprintf("mutual %v", mutual), func(t *testing.T) {
			m := startMockKDC(t, mockKDCOptions{password: "gss"})
			g := newGSSClientForMock(t, m, []int32{ETypeAES256CTS}, GSSClientOptions{SPNEGO: true, MutualAuth: mutual})
			a := newAcceptorForMock(t, m, AcceptorOptions{})
			initial := gssInitial(t, g)
			oid, rest, err := gssUnframe(initial)
			if err != nil || !equalOID(oid, gssOIDSPNEGO) {
				t.Fatalf("initial token OID = %v, %v", oid, err)
			}
			if !isSPNEGOToken(rest) {
				t.Fatal("initial SPNEGO token has no negotiation body")
			}
			response, session, err := a.Accept(initial)
			if err != nil {
				t.Fatalf("Accept: %v", err)
			}
			if len(response) == 0 || response[0] != 0xA1 {
				t.Fatalf("SPNEGO response prefix = 0x%02x", response[0])
			}
			reply, done, err := g.Step(testContext(t), response)
			if err != nil {
				t.Fatalf("Step: %v", err)
			}
			if !done || len(reply) != 0 {
				t.Fatalf("Step done = %v, reply = %d bytes", done, len(reply))
			}
			if session.MutualAuth != mutual {
				t.Fatalf("session mutual = %v, want %v", session.MutualAuth, mutual)
			}
			token, err := g.Wrap([]byte("spnego"), true)
			if err != nil {
				t.Fatalf("Wrap: %v", err)
			}
			plain, _, err := session.Unwrap(token)
			if err != nil || string(plain) != "spnego" {
				t.Fatalf("Unwrap = %q, %v", plain, err)
			}
			m.check(t)
		})
	}
}

// TestGSSSPNEGORequestMIC covers the acceptor request-mic transition. |
// TestGSSSPNEGORequestMIC 覆盖接受方 request-mic 状态转换。
func TestGSSSPNEGORequestMIC(t *testing.T) {
	m := startMockKDC(t, mockKDCOptions{password: "gss"})
	g := newGSSClientForMock(t, m, []int32{ETypeAES256CTS}, GSSClientOptions{SPNEGO: true, MutualAuth: true})
	a := newAcceptorForMock(t, m, AcceptorOptions{})
	initial := gssInitial(t, g)
	response, session, err := a.Accept(initial)
	if err != nil {
		t.Fatalf("Accept: %v", err)
	}
	parsed, err := parseNegTokenResp(response)
	if err != nil {
		t.Fatalf("parseNegTokenResp: %v", err)
	}
	requestMIC := negStateRequestMIC
	parsed.state = &requestMIC
	reply, done, err := g.Step(testContext(t), appendNegTokenResp(parsed))
	if err != nil {
		t.Fatalf("Step: %v", err)
	}
	if !done {
		t.Fatal("request-mic did not complete the context")
	}
	final, err := parseNegTokenResp(reply)
	if err != nil {
		t.Fatalf("parse reply: %v", err)
	}
	if final.state == nil || *final.state != negStateAcceptCompleted {
		t.Fatalf("final state = %v", final.state)
	}
	if len(final.mechListMIC) == 0 {
		t.Fatal("request-mic reply has no mechListMIC")
	}
	if err := session.VerifyMIC(g.mechListDER, final.mechListMIC); err != nil {
		t.Fatalf("acceptor VerifyMIC: %v", err)
	}
	m.check(t)
}

// TestGSSSPNEGOErrors covers malformed and rejected SPNEGO responses. |
// TestGSSSPNEGOErrors 覆盖畸形与被拒绝的 SPNEGO 响应。
func TestGSSSPNEGOErrors(t *testing.T) {
	m := startMockKDC(t, mockKDCOptions{password: "gss"})
	reject := negStateReject
	completed := negStateAcceptCompleted
	tests := []struct {
		name  string
		token []byte
		want  error
	}{
		{"reject", appendNegTokenResp(negTokenResp{state: &reject}), ErrSPNEGO},
		{"unsupported mechanism", appendNegTokenResp(negTokenResp{supportedMech: gssOIDSPNEGO}), ErrSPNEGO},
		{"mutual without AP-REP", appendNegTokenResp(negTokenResp{state: &completed}), ErrMutualAuthFailed},
		{"MIC before context", appendNegTokenResp(negTokenResp{state: &completed, mechListMIC: []byte{1, 2}}), ErrSPNEGO},
		{"garbage", []byte{0xFF}, ErrSPNEGO},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			g := newGSSClientForMock(t, m, []int32{ETypeAES256CTS}, GSSClientOptions{SPNEGO: true, MutualAuth: true})
			gssInitial(t, g)
			if _, _, err := g.Step(testContext(t), test.token); !errors.Is(err, test.want) {
				t.Fatalf("Step error = %v, want %v", err, test.want)
			}
		})
	}
}

// TestGSSAPRepValidation covers AP-REP time, enctype, and integrity failures. |
// TestGSSAPRepValidation 覆盖 AP-REP 时间、加密类型与完整性失败。
func TestGSSAPRepValidation(t *testing.T) {
	m := startMockKDC(t, mockKDCOptions{password: "gss"})
	g := newGSSClientForMock(t, m, []int32{ETypeAES256CTS}, GSSClientOptions{MutualAuth: true})
	a := newAcceptorForMock(t, m, AcceptorOptions{})
	initial := gssInitial(t, g)
	response, _, err := a.Accept(initial)
	if err != nil {
		t.Fatalf("Accept: %v", err)
	}
	t.Run("bad time", func(t *testing.T) {
		token := rewriteAPRep(t, g, response, func(part *EncAPRepPart) {
			part.CTime = NewKerberosTime(part.CTime.Time.Add(time.Second))
		})
		if _, _, err := g.Step(testContext(t), token); !errors.Is(err, ErrMutualAuthFailed) {
			t.Fatalf("Step error = %v, want ErrMutualAuthFailed", err)
		}
	})
	t.Run("wrong enctype", func(t *testing.T) {
		oid, rest, err := gssUnframe(response)
		if err != nil {
			t.Fatalf("gssUnframe: %v", err)
		}
		tokID, payload, err := parseKerberosMechToken(rest)
		if err != nil || tokID != gssTokenAPRep {
			t.Fatalf("mechanism token = 0x%04x, %v", tokID, err)
		}
		rep, err := ParseAPRep(payload)
		if err != nil {
			t.Fatalf("ParseAPRep: %v", err)
		}
		rep.EncPart.EType = ETypeAES128CTS
		data, err := rep.Marshal()
		if err != nil {
			t.Fatalf("AP-REP marshal: %v", err)
		}
		if _, _, err := g.Step(testContext(t), gssWrapKerberosToken(oid, gssTokenAPRep, data)); !errors.Is(err, ErrBadIntegrity) {
			t.Fatalf("Step error = %v, want ErrBadIntegrity", err)
		}
	})
	t.Run("tampered ciphertext", func(t *testing.T) {
		oid, rest, err := gssUnframe(response)
		if err != nil {
			t.Fatalf("gssUnframe: %v", err)
		}
		tokID, payload, err := parseKerberosMechToken(rest)
		if err != nil || tokID != gssTokenAPRep {
			t.Fatalf("mechanism token = 0x%04x, %v", tokID, err)
		}
		rep, err := ParseAPRep(payload)
		if err != nil {
			t.Fatalf("ParseAPRep: %v", err)
		}
		rep.EncPart.Cipher[len(rep.EncPart.Cipher)-1] ^= 0x01
		data, err := rep.Marshal()
		if err != nil {
			t.Fatalf("AP-REP marshal: %v", err)
		}
		if _, _, err := g.Step(testContext(t), gssWrapKerberosToken(oid, gssTokenAPRep, data)); !errors.Is(err, ErrMutualAuthFailed) {
			t.Fatalf("Step error = %v, want ErrMutualAuthFailed", err)
		}
	})
	t.Run("GSS error token", func(t *testing.T) {
		krbError, err := KRBError{
			STime:     NewKerberosTime(time.Now().UTC()),
			ErrorCode: 31,
			Realm:     m.opts.realm,
			SName:     m.servicePrincipal(),
		}.Marshal()
		if err != nil {
			t.Fatalf("KRB-ERROR marshal: %v", err)
		}
		token := gssWrapKerberosToken(gssOIDKerberosV5, gssTokenKRBError, krbError)
		if _, _, err := g.Step(testContext(t), token); !errors.Is(err, ErrBadIntegrity) {
			t.Fatalf("Step error = %v, want ErrBadIntegrity", err)
		}
	})
	t.Run("valid response still accepted", func(t *testing.T) {
		reply, done, err := g.Step(testContext(t), response)
		if err != nil {
			t.Fatalf("Step: %v", err)
		}
		if !done || len(reply) != 0 || !g.Complete() {
			t.Fatalf("Step done = %v, reply = %d bytes, complete = %v", done, len(reply), g.Complete())
		}
	})
	m.check(t)
}

// rewriteAPRep decrypts, mutates, and re-encrypts an acceptor AP-REP. |
// rewriteAPRep 解密、修改并重新加密接受方 AP-REP。
func rewriteAPRep(t *testing.T, g *GSSClient, response []byte, mutate func(*EncAPRepPart)) []byte {
	t.Helper()
	oid, rest, err := gssUnframe(response)
	if err != nil {
		t.Fatalf("gssUnframe: %v", err)
	}
	tokID, payload, err := parseKerberosMechToken(rest)
	if err != nil || tokID != gssTokenAPRep {
		t.Fatalf("mechanism token = 0x%04x, %v", tokID, err)
	}
	rep, err := ParseAPRep(payload)
	if err != nil {
		t.Fatalf("ParseAPRep: %v", err)
	}
	plain, err := DecryptMessage(g.ticket.SessionKey.KeyType, g.ticket.SessionKey.KeyValue, 12, rep.EncPart.Cipher)
	if err != nil {
		t.Fatalf("AP-REP decryption: %v", err)
	}
	part, err := parseEncAPRepPart(plain)
	if err != nil {
		t.Fatalf("parseEncAPRepPart: %v", err)
	}
	mutate(&part)
	ciphertext, err := EncryptMessage(g.ticket.SessionKey.KeyType, g.ticket.SessionKey.KeyValue, 12, appendEncAPRepPart(part))
	if err != nil {
		t.Fatalf("AP-REP encryption: %v", err)
	}
	rep.EncPart.Cipher = ciphertext
	data, err := rep.Marshal()
	if err != nil {
		t.Fatalf("AP-REP marshal: %v", err)
	}
	return gssWrapKerberosToken(oid, gssTokenAPRep, data)
}

// TestGSSChannelBindings covers channel-binding agreement and rejection. |
// TestGSSChannelBindings 覆盖通道绑定一致与拒绝。
func TestGSSChannelBindings(t *testing.T) {
	binding := bytes.Repeat([]byte{0x5A}, 16)
	other := bytes.Repeat([]byte{0xA5}, 16)
	t.Run("match", func(t *testing.T) {
		m := startMockKDC(t, mockKDCOptions{password: "gss"})
		g := newGSSClientForMock(t, m, []int32{ETypeAES256CTS}, GSSClientOptions{MutualAuth: true, ChannelBindings: binding})
		a := newAcceptorForMock(t, m, AcceptorOptions{RequireChannelBindings: true, ChannelBindings: binding})
		initial := gssInitial(t, g)
		response, _, err := a.Accept(initial)
		if err != nil {
			t.Fatalf("Accept: %v", err)
		}
		if _, done, err := g.Step(testContext(t), response); err != nil || !done {
			t.Fatalf("Step done = %v, err = %v", done, err)
		}
		m.check(t)
	})
	t.Run("mismatch", func(t *testing.T) {
		m := startMockKDC(t, mockKDCOptions{password: "gss"})
		g := newGSSClientForMock(t, m, []int32{ETypeAES256CTS}, GSSClientOptions{MutualAuth: true, ChannelBindings: binding})
		a := newAcceptorForMock(t, m, AcceptorOptions{RequireChannelBindings: true, ChannelBindings: other})
		if _, _, err := a.Accept(gssInitial(t, g)); !errors.Is(err, ErrChannelBinding) {
			t.Fatalf("Accept error = %v, want ErrChannelBinding", err)
		}
		m.check(t)
	})
	t.Run("missing", func(t *testing.T) {
		m := startMockKDC(t, mockKDCOptions{password: "gss"})
		g := newGSSClientForMock(t, m, []int32{ETypeAES256CTS}, GSSClientOptions{MutualAuth: true})
		a := newAcceptorForMock(t, m, AcceptorOptions{RequireChannelBindings: true, ChannelBindings: binding})
		if _, _, err := a.Accept(gssInitial(t, g)); !errors.Is(err, ErrChannelBinding) {
			t.Fatalf("Accept error = %v, want ErrChannelBinding", err)
		}
		m.check(t)
	})
	t.Run("constructor", func(t *testing.T) {
		m := startMockKDC(t, mockKDCOptions{password: "gss"})
		client := mustClient(t, m.clientConfig(ETypeAES256CTS))
		if _, err := NewGSSClient(GSSClientOptions{Client: client, Service: m.opts.servicePrincipal, ChannelBindings: make([]byte, 15)}); !errors.Is(err, ErrChannelBinding) {
			t.Fatalf("NewGSSClient error = %v, want ErrChannelBinding", err)
		}
		if _, err := NewAcceptor(AcceptorOptions{KeyTab: m.keytab(), ChannelBindings: make([]byte, 15)}); !errors.Is(err, ErrChannelBinding) {
			t.Fatalf("NewAcceptor error = %v, want ErrChannelBinding", err)
		}
		if _, err := NewAcceptor(AcceptorOptions{KeyTab: m.keytab(), RequireChannelBindings: true}); !errors.Is(err, ErrChannelBinding) {
			t.Fatalf("NewAcceptor missing binding error = %v, want ErrChannelBinding", err)
		}
	})
}

// TestGSSAcceptorFailures covers acceptor rejection of mismatched or invalid
// tickets. | TestGSSAcceptorFailures 覆盖接受方对不匹配或非法票据的拒绝。
func TestGSSAcceptorFailures(t *testing.T) {
	t.Run("bad kvno", func(t *testing.T) {
		m := startMockKDC(t, mockKDCOptions{password: "gss", serviceKVNO: 5, issueKVNO: 7})
		g := newGSSClientForMock(t, m, []int32{ETypeAES256CTS}, GSSClientOptions{MutualAuth: true})
		a := newAcceptorForMock(t, m, AcceptorOptions{})
		if _, _, err := a.Accept(gssInitial(t, g)); !errors.Is(err, ErrBadKVNO) {
			t.Fatalf("Accept error = %v, want ErrBadKVNO", err)
		}
		m.check(t)
	})
	t.Run("missing enctype", func(t *testing.T) {
		m := startMockKDC(t, mockKDCOptions{password: "gss"})
		key, err := randomKey(ETypeAES128CTS)
		if err != nil {
			t.Fatalf("randomKey: %v", err)
		}
		tab := NewKeyTab([]KeyTabEntry{{
			Principal: m.servicePrincipal(),
			Realm:     m.opts.realm,
			KVNO:      m.opts.serviceKVNO,
			Key:       key,
		}})
		g := newGSSClientForMock(t, m, []int32{ETypeAES256CTS}, GSSClientOptions{MutualAuth: true})
		a := newAcceptorForMock(t, m, AcceptorOptions{KeyTab: tab})
		if _, _, err := a.Accept(gssInitial(t, g)); !errors.Is(err, ErrNoKey) {
			t.Fatalf("Accept error = %v, want ErrNoKey", err)
		}
		m.check(t)
	})
	t.Run("service mismatch", func(t *testing.T) {
		m := startMockKDC(t, mockKDCOptions{password: "gss"})
		g := newGSSClientForMock(t, m, []int32{ETypeAES256CTS}, GSSClientOptions{MutualAuth: true})
		a := newAcceptorForMock(t, m, AcceptorOptions{Service: "http/other.example.com"})
		if _, _, err := a.Accept(gssInitial(t, g)); !errors.Is(err, ErrTicketNotForUs) {
			t.Fatalf("Accept error = %v, want ErrTicketNotForUs", err)
		}
		m.check(t)
	})
	t.Run("realm mismatch", func(t *testing.T) {
		m := startMockKDC(t, mockKDCOptions{password: "gss"})
		g := newGSSClientForMock(t, m, []int32{ETypeAES256CTS}, GSSClientOptions{MutualAuth: true})
		a := newAcceptorForMock(t, m, AcceptorOptions{Service: "ldap/dc1.example.com", Realm: "OTHER.COM"})
		if _, _, err := a.Accept(gssInitial(t, g)); !errors.Is(err, ErrTicketNotForUs) {
			t.Fatalf("Accept error = %v, want ErrTicketNotForUs", err)
		}
		m.check(t)
	})
	t.Run("invalid ticket flag", func(t *testing.T) {
		m := startMockKDC(t, mockKDCOptions{password: "gss", serviceFlags: TicketFlagInvalid})
		g := newGSSClientForMock(t, m, []int32{ETypeAES256CTS}, GSSClientOptions{MutualAuth: true})
		a := newAcceptorForMock(t, m, AcceptorOptions{})
		if _, _, err := a.Accept(gssInitial(t, g)); !errors.Is(err, ErrTicketNotForUs) {
			t.Fatalf("Accept error = %v, want ErrTicketNotForUs", err)
		}
		m.check(t)
	})
	t.Run("client name mismatch", func(t *testing.T) {
		m := startMockKDC(t, mockKDCOptions{password: "gss", clientNameMismatch: true})
		g := newGSSClientForMock(t, m, []int32{ETypeAES256CTS}, GSSClientOptions{MutualAuth: true})
		a := newAcceptorForMock(t, m, AcceptorOptions{})
		if _, _, err := a.Accept(gssInitial(t, g)); !errors.Is(err, ErrTicketMismatch) {
			t.Fatalf("Accept error = %v, want ErrTicketMismatch", err)
		}
		m.check(t)
	})
}

// TestGSSAcceptorTimeBoundaries covers ticket and authenticator time windows. |
// TestGSSAcceptorTimeBoundaries 覆盖票据与认证器时间窗口。
func TestGSSAcceptorTimeBoundaries(t *testing.T) {
	m := startMockKDC(t, mockKDCOptions{password: "gss"})
	g := newGSSClientForMock(t, m, []int32{ETypeAES256CTS}, GSSClientOptions{MutualAuth: true})
	initial := gssInitial(t, g)
	now := time.Now().UTC()
	tests := []struct {
		name   string
		offset time.Duration
		want   error
	}{
		{"authenticator skew", 6 * time.Minute, ErrClockSkew},
		{"ticket expired", 11 * time.Hour, ErrTicketExpired},
		{"ticket not yet valid", -10 * time.Minute, ErrTicketNotYetValid},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			a := newAcceptorForMock(t, m, AcceptorOptions{})
			offset := test.offset
			a.now = func() time.Time { return now.Add(offset) }
			_, _, err := a.Accept(initial)
			if !errors.Is(err, test.want) {
				t.Fatalf("Accept error = %v, want %v", err, test.want)
			}
		})
	}
}

// TestGSSAcceptorReplay rejects the same authenticator twice. | TestGSSAcceptorReplay
// 拒绝重复提交同一认证器。
func TestGSSAcceptorReplay(t *testing.T) {
	m := startMockKDC(t, mockKDCOptions{password: "gss"})
	g := newGSSClientForMock(t, m, []int32{ETypeAES256CTS}, GSSClientOptions{MutualAuth: true})
	a := newAcceptorForMock(t, m, AcceptorOptions{})
	initial := gssInitial(t, g)
	if _, _, err := a.Accept(initial); err != nil {
		t.Fatalf("first Accept: %v", err)
	}
	if _, _, err := a.Accept(initial); !errors.Is(err, ErrReplay) {
		t.Fatalf("second Accept error = %v, want ErrReplay", err)
	}
	m.check(t)
}

// TestGSSAcceptorTamperedTokens covers malformed AP-REQ fields and tampered
// ciphertexts. | TestGSSAcceptorTamperedTokens 覆盖畸形 AP-REQ 字段与被篡改的密文。
func TestGSSAcceptorTamperedTokens(t *testing.T) {
	tests := []struct {
		name   string
		mutate func(*APReq)
		want   error
	}{
		{"ticket version", func(req *APReq) { req.Ticket.TktVNO = 4 }, ErrInvalidMessage},
		{"ticket ciphertext", func(req *APReq) {
			req.Ticket.EncPart.Cipher[len(req.Ticket.EncPart.Cipher)-1] ^= 0x01
		}, ErrTicketNotForUs},
		{"authenticator ciphertext", func(req *APReq) {
			req.Authenticator.Cipher[len(req.Authenticator.Cipher)-1] ^= 0x01
		}, ErrBadIntegrity},
		{"authenticator enctype", func(req *APReq) { req.Authenticator.EType = ETypeAES128CTS }, ErrInvalidMessage},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			m := startMockKDC(t, mockKDCOptions{password: "gss"})
			g := newGSSClientForMock(t, m, []int32{ETypeAES256CTS}, GSSClientOptions{MutualAuth: true})
			a := newAcceptorForMock(t, m, AcceptorOptions{})
			initial := gssInitial(t, g)
			req, oid := parseInitialAPReq(t, initial)
			test.mutate(&req)
			if _, _, err := a.Accept(frameInitialAPReq(t, oid, req)); !errors.Is(err, test.want) {
				t.Fatalf("Accept error = %v, want %v", err, test.want)
			}
			m.check(t)
		})
	}
}

// TestGSSAcceptorAuthenticatorChecksum covers GSS checksum policy failures. |
// TestGSSAcceptorAuthenticatorChecksum 覆盖 GSS 校验和策略失败。
func TestGSSAcceptorAuthenticatorChecksum(t *testing.T) {
	tests := []struct {
		name   string
		mutate func(*Authenticator)
		want   error
	}{
		{"missing checksum", func(auth *Authenticator) { auth.Cksum = nil }, ErrGSSAPI},
		{"wrong checksum type", func(auth *Authenticator) { auth.Cksum.CksumType = 1 }, ErrGSSAPI},
		{"short checksum", func(auth *Authenticator) { auth.Cksum.Checksum = auth.Cksum.Checksum[:20] }, ErrGSSAPI},
		{"delegation", func(auth *Authenticator) { auth.Cksum.Checksum[20] |= 1 }, ErrGSSAPI},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			m := startMockKDC(t, mockKDCOptions{password: "gss"})
			g := newGSSClientForMock(t, m, []int32{ETypeAES256CTS}, GSSClientOptions{MutualAuth: true})
			a := newAcceptorForMock(t, m, AcceptorOptions{})
			initial := gssInitial(t, g)
			token := rewriteAuthenticator(t, g, initial, test.mutate)
			if _, _, err := a.Accept(token); !errors.Is(err, test.want) {
				t.Fatalf("Accept error = %v, want %v", err, test.want)
			}
			m.check(t)
		})
	}
}

// parseInitialAPReq parses a GSS-framed AP-REQ. | parseInitialAPReq 解析 GSS 封装的
// AP-REQ。
func parseInitialAPReq(t *testing.T, token []byte) (APReq, []uint32) {
	t.Helper()
	oid, rest, err := gssUnframe(token)
	if err != nil {
		t.Fatalf("gssUnframe: %v", err)
	}
	tokID, payload, err := parseKerberosMechToken(rest)
	if err != nil || tokID != gssTokenAPReq {
		t.Fatalf("mechanism token = 0x%04x, %v", tokID, err)
	}
	req, err := ParseAPReq(payload)
	if err != nil {
		t.Fatalf("ParseAPReq: %v", err)
	}
	return req, oid
}

// frameInitialAPReq frames an AP-REQ as a GSS initial context token. |
// frameInitialAPReq 把 AP-REQ 封装为 GSS 初始上下文令牌。
func frameInitialAPReq(t *testing.T, oid []uint32, req APReq) []byte {
	t.Helper()
	data, err := req.Marshal()
	if err != nil {
		t.Fatalf("AP-REQ marshal: %v", err)
	}
	return gssWrapKerberosToken(oid, gssTokenAPReq, data)
}

// rewriteAuthenticator decrypts, mutates, and re-encrypts the AP-REQ
// authenticator. | rewriteAuthenticator 解密、修改并重新加密 AP-REQ 认证器。
func rewriteAuthenticator(t *testing.T, g *GSSClient, initial []byte, mutate func(*Authenticator)) []byte {
	t.Helper()
	req, oid := parseInitialAPReq(t, initial)
	key := g.ticket.SessionKey
	plain, err := DecryptMessage(key.KeyType, key.KeyValue, 11, req.Authenticator.Cipher)
	if err != nil {
		t.Fatalf("authenticator decryption: %v", err)
	}
	auth, err := parseAuthenticator(plain)
	if err != nil {
		t.Fatalf("parseAuthenticator: %v", err)
	}
	mutate(&auth)
	ciphertext, err := EncryptMessage(key.KeyType, key.KeyValue, 11, appendAuthenticator(nil, auth))
	if err != nil {
		t.Fatalf("authenticator encryption: %v", err)
	}
	req.Authenticator = EncryptedData{EType: key.KeyType, Cipher: ciphertext}
	return frameInitialAPReq(t, oid, req)
}

// TestGSSPerMessageErrors covers direction, replay, integrity, and state
// failures. | TestGSSPerMessageErrors 覆盖方向、重放、完整性与状态失败。
func TestGSSPerMessageErrors(t *testing.T) {
	setup := func(t *testing.T) (*GSSClient, *GSSSession) {
		t.Helper()
		m := startMockKDC(t, mockKDCOptions{password: "gss"})
		g, session, _ := establishGSSMutual(t, m, []int32{ETypeAES256CTS}, GSSClientOptions{})
		return g, session
	}
	t.Run("context not established", func(t *testing.T) {
		m := startMockKDC(t, mockKDCOptions{password: "gss"})
		g := newGSSClientForMock(t, m, []int32{ETypeAES256CTS}, GSSClientOptions{})
		if _, err := g.Wrap([]byte("x"), false); !errors.Is(err, ErrGSSAPI) {
			t.Fatalf("Wrap error = %v, want ErrGSSAPI", err)
		}
		if _, _, err := g.Unwrap(nil); !errors.Is(err, ErrGSSAPI) {
			t.Fatalf("Unwrap error = %v, want ErrGSSAPI", err)
		}
		if _, err := g.MIC([]byte("x")); !errors.Is(err, ErrGSSAPI) {
			t.Fatalf("MIC error = %v, want ErrGSSAPI", err)
		}
		if err := g.VerifyMIC([]byte("x"), nil); !errors.Is(err, ErrGSSAPI) {
			t.Fatalf("VerifyMIC error = %v, want ErrGSSAPI", err)
		}
	})
	t.Run("wrong direction", func(t *testing.T) {
		_, session := setup(t)
		token, err := session.Wrap([]byte("own"), false)
		if err != nil {
			t.Fatalf("session Wrap: %v", err)
		}
		if _, _, err := session.Unwrap(token); !errors.Is(err, ErrGSSAPI) {
			t.Fatalf("session Unwrap error = %v, want ErrGSSAPI", err)
		}
	})
	t.Run("replayed wrap", func(t *testing.T) {
		g, session := setup(t)
		token, err := g.Wrap([]byte("once"), false)
		if err != nil {
			t.Fatalf("Wrap: %v", err)
		}
		if _, _, err := session.Unwrap(token); err != nil {
			t.Fatalf("first Unwrap: %v", err)
		}
		if _, _, err := session.Unwrap(token); !errors.Is(err, ErrSequence) {
			t.Fatalf("second Unwrap error = %v, want ErrSequence", err)
		}
	})
	t.Run("tampered integrity wrap", func(t *testing.T) {
		g, session := setup(t)
		token, err := g.Wrap([]byte("payload"), false)
		if err != nil {
			t.Fatalf("Wrap: %v", err)
		}
		token[16] ^= 0x01
		if _, _, err := session.Unwrap(token); !errors.Is(err, ErrBadIntegrity) {
			t.Fatalf("Unwrap error = %v, want ErrBadIntegrity", err)
		}
	})
	t.Run("tampered sealed wrap", func(t *testing.T) {
		g, session := setup(t)
		token, err := g.Wrap([]byte("payload"), true)
		if err != nil {
			t.Fatalf("Wrap: %v", err)
		}
		token[len(token)-1] ^= 0x01
		if _, _, err := session.Unwrap(token); err == nil {
			t.Fatal("tampered sealed token was accepted")
		}
	})
	t.Run("tampered MIC", func(t *testing.T) {
		g, session := setup(t)
		token, err := g.MIC([]byte("payload"))
		if err != nil {
			t.Fatalf("MIC: %v", err)
		}
		token[len(token)-1] ^= 0x01
		if err := session.VerifyMIC([]byte("payload"), token); !errors.Is(err, ErrBadIntegrity) {
			t.Fatalf("VerifyMIC error = %v, want ErrBadIntegrity", err)
		}
	})
	t.Run("wrong MIC data", func(t *testing.T) {
		g, session := setup(t)
		token, err := g.MIC([]byte("payload"))
		if err != nil {
			t.Fatalf("MIC: %v", err)
		}
		if err := session.VerifyMIC([]byte("other"), token); !errors.Is(err, ErrBadIntegrity) {
			t.Fatalf("VerifyMIC error = %v, want ErrBadIntegrity", err)
		}
	})
	t.Run("short tokens", func(t *testing.T) {
		_, session := setup(t)
		if _, _, err := session.Unwrap(make([]byte, 8)); !errors.Is(err, ErrGSSAPI) {
			t.Fatalf("Unwrap error = %v, want ErrGSSAPI", err)
		}
		if err := session.VerifyMIC(nil, make([]byte, 8)); !errors.Is(err, ErrGSSAPI) {
			t.Fatalf("VerifyMIC error = %v, want ErrGSSAPI", err)
		}
	})
	t.Run("wrong MIC direction", func(t *testing.T) {
		_, session := setup(t)
		token, err := session.MIC([]byte("own"))
		if err != nil {
			t.Fatalf("session MIC: %v", err)
		}
		if err := session.VerifyMIC([]byte("own"), token); !errors.Is(err, ErrGSSAPI) {
			t.Fatalf("session VerifyMIC error = %v, want ErrGSSAPI", err)
		}
	})
}

// TestGSSConfigurationErrors covers constructor and initial token failures. |
// TestGSSConfigurationErrors 覆盖构造器与初始令牌失败。
func TestGSSConfigurationErrors(t *testing.T) {
	m := startMockKDC(t, mockKDCOptions{password: "gss"})
	client := mustClient(t, m.clientConfig(ETypeAES256CTS))
	if _, err := NewGSSClient(GSSClientOptions{}); !errors.Is(err, ErrInvalidConfig) {
		t.Fatalf("nil client error = %v, want ErrInvalidConfig", err)
	}
	if _, err := NewGSSClient(GSSClientOptions{Client: client}); !errors.Is(err, ErrInvalidConfig) {
		t.Fatalf("empty service error = %v, want ErrInvalidConfig", err)
	}
	if _, err := NewAcceptor(AcceptorOptions{}); !errors.Is(err, ErrInvalidConfig) {
		t.Fatalf("nil keytab error = %v, want ErrInvalidConfig", err)
	}
	if _, err := NewAcceptor(AcceptorOptions{KeyTab: NewKeyTab(nil)}); !errors.Is(err, ErrInvalidConfig) {
		t.Fatalf("empty keytab error = %v, want ErrInvalidConfig", err)
	}
	acceptor := newAcceptorForMock(t, m, AcceptorOptions{})
	if _, _, err := acceptor.Accept(nil); !errors.Is(err, ErrGSSAPI) {
		t.Fatalf("empty token error = %v, want ErrGSSAPI", err)
	}
	unsupported := derAppendApplication(nil, 0, append(derAppendOID(nil, []uint32{1, 2, 3}), 0x01, 0x00))
	if _, _, err := acceptor.Accept(unsupported); !errors.Is(err, ErrGSSAPI) {
		t.Fatalf("unsupported mechanism error = %v, want ErrGSSAPI", err)
	}
	var nilAcceptor *Acceptor
	if _, _, err := nilAcceptor.Accept(nil); !errors.Is(err, ErrInvalidConfig) {
		t.Fatalf("nil acceptor error = %v, want ErrInvalidConfig", err)
	}
	if _, err := NewAcceptor(AcceptorOptions{KeyTab: m.keytab(), Service: "ldap//bad"}); err == nil {
		t.Fatal("NewAcceptor accepted a malformed service principal")
	}
}

// TestGSSMissingOptionalState covers nil receivers and incomplete sessions. |
// TestGSSMissingOptionalState 覆盖空接收者与不完整会话。
func TestGSSMissingOptionalState(t *testing.T) {
	var g *GSSClient
	if g.Complete() {
		t.Fatal("nil GSS client reports complete")
	}
	if _, realm := g.ClientPrincipal(); realm != "" {
		t.Fatalf("nil client realm = %q", realm)
	}
	if _, realm := g.TargetName(); realm != "" {
		t.Fatalf("nil target realm = %q", realm)
	}
	if _, err := g.Wrap(nil, false); !errors.Is(err, ErrGSSAPI) {
		t.Fatalf("nil Wrap error = %v", err)
	}
	if _, _, err := g.Unwrap(nil); !errors.Is(err, ErrGSSAPI) {
		t.Fatalf("nil Unwrap error = %v", err)
	}
	if _, err := g.MIC(nil); !errors.Is(err, ErrGSSAPI) {
		t.Fatalf("nil MIC error = %v", err)
	}
	if err := g.VerifyMIC(nil, nil); !errors.Is(err, ErrGSSAPI) {
		t.Fatalf("nil VerifyMIC error = %v", err)
	}
	var session *GSSSession
	if _, err := session.Wrap(nil, false); !errors.Is(err, ErrGSSAPI) {
		t.Fatalf("nil session Wrap error = %v", err)
	}
	if _, _, err := session.Unwrap(nil); !errors.Is(err, ErrGSSAPI) {
		t.Fatalf("nil session Unwrap error = %v", err)
	}
	if _, err := session.MIC(nil); !errors.Is(err, ErrGSSAPI) {
		t.Fatalf("nil session MIC error = %v", err)
	}
	if err := session.VerifyMIC(nil, nil); !errors.Is(err, ErrGSSAPI) {
		t.Fatalf("nil session VerifyMIC error = %v", err)
	}
}
