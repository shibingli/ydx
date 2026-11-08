package ldap

import (
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"net"
	"sync"
	"testing"
	"time"

	"github.com/shibingli/ydx/auth/directory/ntlm"
)

// ntlmAcceptorOptions configures the real ntlm.Acceptor instances used by the
// mock LDAP server. | ntlmAcceptorOptions 配置模拟 LDAP 服务端使用的真实
// ntlm.Acceptor 实例。
type ntlmAcceptorOptions struct {
	requireMechListMIC bool
	sendMechListMIC    bool
	requireMIC         bool
	allowRawNTLM       bool
}

// ntlmAcceptorState is the acceptor state bound to one LDAP transport. |
// ntlmAcceptorState 是绑定到单个 LDAP 传输的接受方状态。
type ntlmAcceptorState struct {
	acceptor   *ntlm.Acceptor
	binds      int
	mechanisms []string
}

// ntlmAcceptorMock runs a real ntlm.Acceptor per LDAP connection and records
// what the server observed. | ntlmAcceptorMock 为每个 LDAP 连接运行真实的
// ntlm.Acceptor，并记录服务端观测到的内容。
type ntlmAcceptorMock struct {
	newConfig   func() ntlm.AcceptorConfig
	tamperFinal func([]byte) []byte
	extraRound  bool

	mu          sync.Mutex
	states      map[net.Conn]*ntlmAcceptorState
	connections int
	results     []*ntlm.AcceptResult
	extraBinds  int
}

// handle processes one LDAP bind and drives the per-connection acceptor. |
// handle 处理一条 LDAP 绑定并驱动按连接划分的接受方。
func (m *ntlmAcceptorMock) handle(session *mockSession, message *LDAPMessage) error {
	request, ok := message.Op.(*BindRequest)
	if !ok {
		return errors.New("NTLM acceptor mock: expected BindRequest")
	}
	authentication, ok := request.Authentication.(SASLAuthentication)
	if !ok {
		return errors.New("NTLM acceptor mock: expected SASL bind authentication")
	}
	m.mu.Lock()
	if m.states == nil {
		m.states = make(map[net.Conn]*ntlmAcceptorState)
	}
	state := m.states[session.conn]
	if state == nil {
		state = &ntlmAcceptorState{}
		m.states[session.conn] = state
		m.connections++
	}
	state.binds++
	state.mechanisms = append(state.mechanisms, authentication.Mechanism)
	bind := state.binds
	if bind == 1 {
		acceptor, err := ntlm.NewAcceptor(m.newConfig())
		if err != nil {
			m.mu.Unlock()
			return err
		}
		state.acceptor = acceptor
	}
	acceptor := state.acceptor
	m.mu.Unlock()
	switch bind {
	case 1:
		challenge, err := acceptor.AcceptInitial(authentication.Credentials)
		if err != nil {
			return writeNTLMAcceptorResult(session, message.MessageID, ResultInvalidCredentials, nil)
		}
		return writeNTLMAcceptorResult(session, message.MessageID, ResultSASLBindInProgress, challenge)
	case 2:
		result, finalToken, err := acceptor.AcceptFinal(authentication.Credentials)
		if err != nil {
			return writeNTLMAcceptorResult(session, message.MessageID, ResultInvalidCredentials, nil)
		}
		m.mu.Lock()
		m.results = append(m.results, result)
		m.mu.Unlock()
		if m.extraRound {
			return writeNTLMAcceptorResult(session, message.MessageID, ResultSASLBindInProgress, nil)
		}
		if finalToken != nil && m.tamperFinal != nil {
			finalToken = m.tamperFinal(append([]byte(nil), finalToken...))
		}
		return writeNTLMAcceptorResult(session, message.MessageID, ResultSuccess, finalToken)
	default:
		// One transport must finish in exactly two binds; anything else is a
		// client that failed to tear down a failed exchange. |
		// 单个传输必须恰好用两次绑定完成；其它情况说明客户端未拆除失败的交换。
		m.mu.Lock()
		m.extraBinds++
		m.mu.Unlock()
		return writeNTLMAcceptorResult(session, message.MessageID, ResultInvalidCredentials, nil)
	}
}

// writeNTLMAcceptorResult writes one bind response. | writeNTLMAcceptorResult 写出
// 一条绑定响应。
func writeNTLMAcceptorResult(session *mockSession, messageID int, code ResultCode, credentials []byte) error {
	return session.Write(&LDAPMessage{
		MessageID: messageID,
		Op: &BindResponse{
			Result:                LDAPResult{Code: code},
			ServerSASLCredentials: credentials,
		},
	})
}

// snapshot returns connection, result and extra-bind counts. | snapshot 返回连接、
// 结果与额外绑定计数。
func (m *ntlmAcceptorMock) snapshot() (int, int, int, int) {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.connections, len(m.results), m.extraBinds, len(m.states)
}

// lastResult returns the most recent successful accept result. | lastResult 返回最近的
// 成功接受结果。
func (m *ntlmAcceptorMock) lastResult() *ntlm.AcceptResult {
	m.mu.Lock()
	defer m.mu.Unlock()
	if len(m.results) == 0 {
		return nil
	}
	return m.results[len(m.results)-1]
}

// mechanismLists returns the bind mechanisms observed on each connection. |
// mechanismLists 返回每条连接上观测到的绑定机制。
func (m *ntlmAcceptorMock) mechanismLists() [][]string {
	m.mu.Lock()
	defer m.mu.Unlock()
	lists := make([][]string, 0, len(m.states))
	for _, state := range m.states {
		lists = append(lists, append([]string(nil), state.mechanisms...))
	}
	return lists
}

// ntlmAcceptorConfig builds an acceptor that authenticates EXAMPLE\alice with
// the fixed test password. | ntlmAcceptorConfig 构建使用固定测试口令认证
// EXAMPLE\alice 的接受方。
func ntlmAcceptorConfig(options ntlmAcceptorOptions) ntlm.AcceptorConfig {
	return ntlm.AcceptorConfig{
		Domain:             "EXAMPLE",
		ServerName:         "DC01",
		ServerChallenge:    []byte{0x51, 0x52, 0x53, 0x54, 0x55, 0x56, 0x57, 0x58},
		RequireMechListMIC: options.requireMechListMIC,
		SendMechListMIC:    options.sendMechListMIC,
		RequireMIC:         options.requireMIC,
		AllowRawNTLM:       options.allowRawNTLM,
		Password: func(domain, username string) (string, bool) {
			if domain == "EXAMPLE" && username == "alice" {
				return ntlmTestPassword, true
			}
			return "", false
		},
	}
}

// ntlmTamperLastByte flips the final byte of a DER token, corrupting the
// trailing mechListMIC value. | ntlmTamperLastByte 翻转 DER 令牌的最后一个字节，破坏
// 末尾的 mechListMIC 值。
func ntlmTamperLastByte(token []byte) []byte {
	if len(token) > 0 {
		token[len(token)-1] ^= 0xff
	}
	return token
}

// TestBindNTLMWithAcceptor covers raw NTLM, SPNEGO, request-mic, Type 3 MIC and
// final server mechListMIC successes and failures against the real ntlm.Acceptor.
// Every failure must tear the transport down without a raw-NTLM fallback. |
// TestBindNTLMWithAcceptor 使用真实 ntlm.Acceptor 覆盖裸 NTLM、SPNEGO、
// request-mic、Type 3 MIC 以及最终服务端 mechListMIC 的成功与失败。每种失败都必须拆除
// 传输且不得回退到裸 NTLM。
func TestBindNTLMWithAcceptor(t *testing.T) {
	tests := []struct {
		name             string
		mechanism        string
		options          ntlmAcceptorOptions
		requireServerMIC bool
		tamperFinal      bool
		extraRound       bool
		wantErr          bool
		wantErrIs        error
		wantType3MIC     bool
		wantMechListMIC  bool
	}{
		{
			name:      "spnego",
			mechanism: SASLMechanismGSSSPNEGO,
		},
		{
			name:      "raw ntlm",
			mechanism: SASLMechanismNTLM,
			options:   ntlmAcceptorOptions{allowRawNTLM: true},
		},
		{
			name:      "request mic with server mic",
			mechanism: SASLMechanismGSSSPNEGO,
			options: ntlmAcceptorOptions{
				requireMechListMIC: true,
				sendMechListMIC:    true,
			},
			requireServerMIC: true,
			wantMechListMIC:  true,
		},
		{
			name:      "request mic without requiring server mic",
			mechanism: SASLMechanismGSSSPNEGO,
			options: ntlmAcceptorOptions{
				requireMechListMIC: true,
				sendMechListMIC:    true,
			},
			wantMechListMIC: true,
		},
		{
			name:         "type three mic required",
			mechanism:    SASLMechanismGSSSPNEGO,
			options:      ntlmAcceptorOptions{requireMIC: true},
			wantType3MIC: true,
		},
		{
			name:      "server mic missing",
			mechanism: SASLMechanismGSSSPNEGO,
			options: ntlmAcceptorOptions{
				requireMechListMIC: true,
				sendMechListMIC:    false,
			},
			requireServerMIC: true,
			wantErr:          true,
			wantErrIs:        ErrNTLM,
		},
		{
			name:      "server mic tampered",
			mechanism: SASLMechanismGSSSPNEGO,
			options: ntlmAcceptorOptions{
				requireMechListMIC: true,
				sendMechListMIC:    true,
			},
			requireServerMIC: true,
			tamperFinal:      true,
			wantErr:          true,
			wantErrIs:        ntlm.ErrMechListMIC,
		},
		{
			name:       "extra round after type three",
			mechanism:  SASLMechanismGSSSPNEGO,
			extraRound: true,
			wantErr:    true,
			wantErrIs:  ErrNTLM,
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			mock := &ntlmAcceptorMock{
				newConfig:   func() ntlm.AcceptorConfig { return ntlmAcceptorConfig(test.options) },
				tamperFinal: nil,
				extraRound:  test.extraRound,
			}
			if test.tamperFinal {
				mock.tamperFinal = ntlmTamperLastByte
			}
			server := startMockServer(t, mock.handle)
			client := ntlmTestDial(t, server)
			err := client.BindNTLM(mustTimeoutContext(t, 5*time.Second), NTLMOptions{
				Username:         `EXAMPLE\alice`,
				Password:         ntlmTestPassword,
				Mechanism:        test.mechanism,
				RequireServerMIC: test.requireServerMIC,
			})
			connections, results, extraBinds, states := mock.snapshot()
			if connections != 1 || states != 1 {
				t.Fatalf("connections = %d, states = %d, want 1", connections, states)
			}
			if extraBinds != 0 {
				t.Fatalf("extra binds = %d, want 0", extraBinds)
			}
			lists := mock.mechanismLists()
			if len(lists) != 1 || len(lists[0]) != 2 {
				t.Fatalf("mechanism lists = %v, want one connection with two binds", lists)
			}
			for _, mechanism := range lists[0] {
				if mechanism != test.mechanism {
					t.Fatalf("mechanism = %q, want %q (no fallback)", mechanism, test.mechanism)
				}
			}
			if test.wantErr {
				if err == nil {
					t.Fatal("BindNTLM succeeded, want a fail-closed error")
				}
				if !errors.Is(err, ErrNTLM) {
					t.Fatalf("error = %v, want ErrNTLM", err)
				}
				if test.wantErrIs != nil && !errors.Is(err, test.wantErrIs) {
					t.Fatalf("error = %v, want sentinel %v", err, test.wantErrIs)
				}
				if client.auth != nil {
					t.Fatalf("auth state = %+v, want nil", client.auth)
				}
				if client.conn != nil {
					t.Fatal("connection was not invalidated after a fail-closed error")
				}
				if results != 1 {
					t.Fatalf("accept results = %d, want 1", results)
				}
				return
			}
			if err != nil {
				t.Fatalf("BindNTLM: %v", err)
			}
			if results != 1 {
				t.Fatalf("accept results = %d, want 1", results)
			}
			result := mock.lastResult()
			if result == nil {
				t.Fatal("acceptor produced no result")
			}
			if result.Username != "alice" || result.Domain != "EXAMPLE" {
				t.Fatalf("accepted identity = %s\\%s, want EXAMPLE\\alice", result.Domain, result.Username)
			}
			if result.SPNEGO != (test.mechanism == SASLMechanismGSSSPNEGO) {
				t.Fatalf("SPNEGO = %v, want %v", result.SPNEGO, test.mechanism == SASLMechanismGSSSPNEGO)
			}
			if test.wantType3MIC && !result.MICVerified {
				t.Fatal("acceptor did not verify a Type 3 MIC")
			}
			if test.wantMechListMIC && !result.MechListMICVerified {
				t.Fatal("acceptor did not verify a client mechListMIC")
			}
			// LDAP SASL NTLM must never negotiate a PDU security layer. |
			// LDAP SASL NTLM 绝不能协商 PDU 安全层。
			if result.Flags.Has(ntlm.FlagSign) || result.Flags.Has(ntlm.FlagSeal) || result.Flags.Has(ntlm.FlagKeyExchange) {
				t.Fatalf("negotiated flags %#x request a PDU security layer", uint32(result.Flags))
			}
			if client.conn == nil || client.conn.sasl == nil {
				t.Fatal("successful bind did not attach a session to the transport")
			}
			if client.auth == nil || client.auth.kind != authNTLM {
				t.Fatalf("auth state = %+v, want authNTLM", client.auth)
			}
		})
	}
}

// TestBindNTLMReconnectRenegotiates verifies a reconnect builds a new acceptor
// exchange and never reuses the previous initial token. | TestBindNTLMReconnectRenegotiates
// 校验重连会构建新的接受方交换，且绝不复用之前的初始令牌。
func TestBindNTLMReconnectRenegotiates(t *testing.T) {
	mock := &ntlmAcceptorMock{
		newConfig: func() ntlm.AcceptorConfig {
			return ntlmAcceptorConfig(ntlmAcceptorOptions{
				requireMechListMIC: true,
				sendMechListMIC:    true,
			})
		},
	}
	server := startMockServer(t, mock.handle)
	client := ntlmTestDial(t, server)
	ctx := mustTimeoutContext(t, 5*time.Second)
	if err := client.BindNTLM(ctx, NTLMOptions{
		Username:         `EXAMPLE\alice`,
		Password:         ntlmTestPassword,
		RequireServerMIC: true,
	}); err != nil {
		t.Fatalf("BindNTLM: %v", err)
	}
	oldConn := client.conn
	if oldConn == nil || oldConn.sasl == nil {
		t.Fatal("first bind did not attach a session")
	}
	oldSession := oldConn.sasl
	if err := client.Reconnect(ctx); err != nil {
		t.Fatalf("Reconnect: %v", err)
	}
	if oldConn.sasl != nil {
		t.Fatal("reconnect left the old session attached")
	}
	if client.conn == nil || client.conn == oldConn {
		t.Fatal("reconnect did not establish a new transport")
	}
	if client.conn.sasl == nil || client.conn.sasl == oldSession {
		t.Fatal("reconnect did not create a new NTLM session")
	}
	connections, results, extraBinds, states := mock.snapshot()
	if connections != 2 || states != 2 {
		t.Fatalf("connections = %d, states = %d, want 2", connections, states)
	}
	if results != 2 {
		t.Fatalf("accept results = %d, want 2", results)
	}
	if extraBinds != 0 {
		t.Fatalf("extra binds = %d, want 0", extraBinds)
	}
	lists := mock.mechanismLists()
	if len(lists) != 2 {
		t.Fatalf("mechanism lists = %v, want two connections", lists)
	}
	for _, list := range lists {
		if len(list) != 2 {
			t.Fatalf("connection mechanisms = %v, want two binds", list)
		}
		for _, mechanism := range list {
			if mechanism != SASLMechanismGSSSPNEGO {
				t.Fatalf("mechanism = %q, want %q", mechanism, SASLMechanismGSSSPNEGO)
			}
		}
	}
	mock.mu.Lock()
	for _, result := range mock.results {
		if !result.MechListMICVerified || !result.SPNEGO {
			mock.mu.Unlock()
			t.Fatalf("replayed result did not verify the client mechListMIC: %+v", result)
		}
	}
	mock.mu.Unlock()
	if client.auth == nil || client.auth.kind != authNTLM {
		t.Fatalf("auth state = %+v, want authNTLM after replay", client.auth)
	}
}

// countingSASLSession counts Close calls without holding key material. |
// countingSASLSession 统计 Close 调用次数，不持有密钥材料。
type countingSASLSession struct {
	closes int
}

// Close increments the counter. | Close 增加计数。
func (s *countingSASLSession) Close() error {
	s.closes++
	return nil
}

// TestConnSASLSessionLifecycle verifies that replacing a session closes the old
// one, close wipes the bound session, and close is idempotent. |
// TestConnSASLSessionLifecycle 校验替换会话会关闭旧会话、close 清零绑定会话，且 close
// 可重复调用。
func TestConnSASLSessionLifecycle(t *testing.T) {
	clientSide, serverSide := net.Pipe()
	defer func() { _ = serverSide.Close() }()
	connection := newConn(clientSide, false, tls.ConnectionState{}, 0)
	first := &countingSASLSession{}
	second := &countingSASLSession{}
	connection.bindSASLSession(first)
	if first.closes != 0 {
		t.Fatalf("first session closed %d times before replacement", first.closes)
	}
	connection.bindSASLSession(second)
	if first.closes != 1 {
		t.Fatalf("first session closed %d times, want 1", first.closes)
	}
	if connection.sasl != second {
		t.Fatal("replacement session was not attached")
	}
	if err := connection.close(); err != nil {
		t.Fatalf("close: %v", err)
	}
	if second.closes != 1 {
		t.Fatalf("second session closed %d times, want 1", second.closes)
	}
	if connection.sasl != nil {
		t.Fatal("close left the session attached")
	}
	if err := connection.close(); err != nil {
		t.Fatalf("second close: %v", err)
	}
	if second.closes != 1 {
		t.Fatalf("second session closed %d times after idempotent close, want 1", second.closes)
	}
}

// TestUpgradeTLSTransfersSASLSession verifies a StartTLS upgrade keeps the
// session bound to the unchanged socket. | TestUpgradeTLSTransfersSASLSession 校验
// StartTLS 升级会在未变的套接字上保留绑定会话。
func TestUpgradeTLSTransfersSASLSession(t *testing.T) {
	certificate, pool := testCertificate(t)
	clientEnd, serverEnd := net.Pipe()
	connection := newConn(clientEnd, false, tls.ConnectionState{}, 0)
	session := &countingSASLSession{}
	connection.bindSASLSession(session)
	serverTLS := tls.Server(serverEnd, &tls.Config{
		Certificates: []tls.Certificate{certificate},
		MinVersion:   tls.VersionTLS12,
	})
	done := make(chan error, 1)
	go func() { done <- serverTLS.Handshake() }()
	upgraded, err := upgradeTLS(mustTimeoutContext(t, 5*time.Second), connection, normalizedConfig{
		tls:         testTLSConfig(pool),
		DialTimeout: 5 * time.Second,
	})
	if err != nil {
		t.Fatalf("upgradeTLS: %v", err)
	}
	if connection.sasl != nil {
		t.Fatal("upgrade left the session on the old transport")
	}
	if upgraded.sasl != session {
		t.Fatal("upgrade did not transfer the session")
	}
	// tls.Conn.Close would block writing close_notify into a synchronous pipe,
	// so exercise the session cleanup that close performs. | tls.Conn.Close
	// 会在同步管道上阻塞写出 close_notify，因此直接执行 close 所做的会话清理。
	upgraded.closeSASLSession()
	if session.closes != 1 {
		t.Fatalf("session closed %d times after upgrade cleanup, want 1", session.closes)
	}
	if upgraded.sasl != nil {
		t.Fatal("upgrade cleanup left the session attached")
	}
	_ = clientEnd.Close()
	_ = serverTLS.Close()
	if err := <-done; err != nil {
		t.Fatalf("server handshake: %v", err)
	}
}

// TestBindNTLMConcurrentClients verifies concurrent binds each negotiate their
// own session. | TestBindNTLMConcurrentClients 校验并发绑定各自协商独立会话。
func TestBindNTLMConcurrentClients(t *testing.T) {
	mock := &ntlmAcceptorMock{
		newConfig: func() ntlm.AcceptorConfig {
			return ntlmAcceptorConfig(ntlmAcceptorOptions{
				requireMechListMIC: true,
				sendMechListMIC:    true,
				requireMIC:         true,
			})
		},
	}
	server := startMockServer(t, mock.handle)
	const clients = 8
	var wg sync.WaitGroup
	errCh := make(chan error, clients)
	for index := 0; index < clients; index++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
			defer cancel()
			client, err := DialURL(ctx, server.URL())
			if err != nil {
				errCh <- fmt.Errorf("DialURL: %w", err)
				return
			}
			defer func() { _ = client.Close() }()
			if err := client.BindNTLM(ctx, NTLMOptions{
				Username:         `EXAMPLE\alice`,
				Password:         ntlmTestPassword,
				RequireServerMIC: true,
			}); err != nil {
				errCh <- fmt.Errorf("BindNTLM: %w", err)
				return
			}
			if client.conn == nil || client.conn.sasl == nil {
				errCh <- errors.New("successful bind did not attach a session")
			}
		}()
	}
	wg.Wait()
	close(errCh)
	for err := range errCh {
		t.Error(err)
	}
	connections, results, extraBinds, _ := mock.snapshot()
	if connections != clients {
		t.Fatalf("connections = %d, want %d", connections, clients)
	}
	if results != clients {
		t.Fatalf("accept results = %d, want %d", results, clients)
	}
	if extraBinds != 0 {
		t.Fatalf("extra binds = %d, want 0", extraBinds)
	}
}
