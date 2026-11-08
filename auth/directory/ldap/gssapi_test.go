package ldap

import (
	"bytes"
	"context"
	"crypto/tls"
	"errors"
	"net"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/shibingli/ydx/auth/directory/ntlm"
	"github.com/shibingli/ydx/auth/protocol/kerberos"
)

// fakeGSSContextToken is the acceptor context token understood by the fake
// initiator. | fakeGSSContextToken 是模拟发起方理解的接受方上下文令牌。
var fakeGSSContextToken = []byte("CTX-APREP")

// fakeGSSMechListMIC is the SPNEGO mechListMIC returned by the fake initiator. |
// fakeGSSMechListMIC 是模拟发起方返回的 SPNEGO mechListMIC。
var fakeGSSMechListMIC = []byte("CTX-MIC")

// fakeGSSWrap wraps plaintext with an observable, non-cryptographic header. |
// fakeGSSWrap 用可观测的非加密头部封装明文。
func fakeGSSWrap(confidential bool, payload []byte) []byte {
	token := make([]byte, 2+len(payload))
	token[0] = 0xFA
	if confidential {
		token[1] = 1
	}
	copy(token[2:], payload)
	return token
}

// fakeGSSUnwrap reverses fakeGSSWrap. | fakeGSSUnwrap 反向处理 fakeGSSWrap。
func fakeGSSUnwrap(token []byte) ([]byte, bool, error) {
	if len(token) < 2 || token[0] != 0xFA {
		return nil, false, errors.New("fake GSS: malformed token")
	}
	return append([]byte(nil), token[2:]...), token[1]&1 != 0, nil
}

// fakeGSSBehavior injects initiator failures. | fakeGSSBehavior 注入发起方故障。
type fakeGSSBehavior struct {
	sendMIC    bool
	initialErr error
	stepErr    error
	incomplete bool
	wrapErr    error
	unwrapErr  error
	factoryErr error
}

// fakeGSSRecorder records the options used for every exchange. | fakeGSSRecorder
// 记录每次交换使用的选项。
type fakeGSSRecorder struct {
	mu      sync.Mutex
	options []kerberos.GSSClientOptions
}

// record stores a defensive copy of options. | record 保存选项的防御性副本。
func (r *fakeGSSRecorder) record(options kerberos.GSSClientOptions) {
	options.ChannelBindings = append([]byte(nil), options.ChannelBindings...)
	r.mu.Lock()
	defer r.mu.Unlock()
	r.options = append(r.options, options)
}

// snapshot returns the recorded options. | snapshot 返回已记录的选项。
func (r *fakeGSSRecorder) snapshot() []kerberos.GSSClientOptions {
	r.mu.Lock()
	defer r.mu.Unlock()
	return append([]kerberos.GSSClientOptions(nil), r.options...)
}

// fakeGSSFactory returns an initiator factory bound to recorder and behavior. |
// fakeGSSFactory 返回绑定 recorder 与 behavior 的发起方工厂。
func fakeGSSFactory(recorder *fakeGSSRecorder, behavior fakeGSSBehavior) func(kerberos.GSSClientOptions) (gssInitiator, error) {
	return func(options kerberos.GSSClientOptions) (gssInitiator, error) {
		recorder.record(options)
		if behavior.factoryErr != nil {
			return nil, behavior.factoryErr
		}
		return &fakeGSSInitiator{behavior: behavior}, nil
	}
}

// fakeGSSInitiator is a deterministic GSSAPI context for SASL tests. | fakeGSSInitiator
// 是用于 SASL 测试的确定性 GSSAPI 上下文。
type fakeGSSInitiator struct {
	behavior fakeGSSBehavior
	complete bool
}

// InitialToken returns the fixed initial context token. | InitialToken 返回固定初始上下文令牌。
func (f *fakeGSSInitiator) InitialToken(context.Context) ([]byte, error) {
	if f.behavior.initialErr != nil {
		return nil, f.behavior.initialErr
	}
	return []byte("CTX-INITIAL"), nil
}

// Step consumes the fixed acceptor token. | Step 消费固定接受方令牌。
func (f *fakeGSSInitiator) Step(_ context.Context, token []byte) ([]byte, bool, error) {
	if f.behavior.stepErr != nil {
		return nil, false, f.behavior.stepErr
	}
	if f.behavior.incomplete {
		return nil, false, nil
	}
	if !bytes.Equal(token, fakeGSSContextToken) {
		return nil, false, errors.New("fake GSS: unexpected context token")
	}
	f.complete = true
	if f.behavior.sendMIC {
		return append([]byte(nil), fakeGSSMechListMIC...), true, nil
	}
	return nil, true, nil
}

// Complete reports whether the fake context is established. | Complete 报告模拟上下文是否已建立。
func (f *fakeGSSInitiator) Complete() bool { return f.complete }

// Wrap wraps one message. | Wrap 封装一条消息。
func (f *fakeGSSInitiator) Wrap(data []byte, confidential bool) ([]byte, error) {
	if f.behavior.wrapErr != nil {
		return nil, f.behavior.wrapErr
	}
	return fakeGSSWrap(confidential, data), nil
}

// Unwrap unwraps one message. | Unwrap 解封一条消息。
func (f *fakeGSSInitiator) Unwrap(token []byte) ([]byte, bool, error) {
	if f.behavior.unwrapErr != nil {
		return nil, false, f.behavior.unwrapErr
	}
	return fakeGSSUnwrap(token)
}

// gssServerConfig controls the mock LDAP GSSAPI server. | gssServerConfig 控制模拟
// LDAP GSSAPI 服务端。
type gssServerConfig struct {
	initialResult        *ResultCode
	initialSuccess       bool
	initialNoCredentials bool
	contextResult        *ResultCode
	contextNoCredentials bool
	serverLayers         byte
	serverMaxBuffer      int
	challengeLength      int
	confidential         bool
	finalResult          *ResultCode
	selectLayer          *byte
	selectMaxBuffer      int
	selectionFirst       bool
	successSelection     *byte
	finalEmptyChallenge  bool
}

// defaultGSSTestConfig returns a conforming no-security-layer server. |
// defaultGSSTestConfig 返回符合规范的无安全层服务端。
func defaultGSSTestConfig() gssServerConfig {
	return gssServerConfig{serverLayers: gssapiLayerNone}
}

// gssServerState tracks one LDAP connection through the SASL exchange. |
// gssServerState 跟踪一条 LDAP 连接上的 SASL 交换。
type gssServerState struct {
	phase   int
	mic     bool
	authzID []byte
	offer   []byte
}

// gssMockServer implements the server half of RFC 4752 for tests. | gssMockServer
// 在测试中实现 RFC 4752 的服务端部分。
type gssMockServer struct {
	cfg     gssServerConfig
	mu      sync.Mutex
	states  map[net.Conn]*gssServerState
	binds   int
	initial []byte
	mic     bool
	authzID []byte
	offer   []byte
}

// newGSSMockServer starts a mock LDAP server running the GSSAPI exchange. |
// newGSSMockServer 启动执行 GSSAPI 交换的模拟 LDAP 服务端。
func newGSSMockServer(t *testing.T, cfg gssServerConfig) (*mockServer, *gssMockServer) {
	t.Helper()
	state := &gssMockServer{cfg: cfg, states: make(map[net.Conn]*gssServerState)}
	server := startMockServer(t, state.handle)
	return server, state
}

// stateFor returns the connection state. | stateFor 返回连接状态。
func (s *gssMockServer) stateFor(conn net.Conn) *gssServerState {
	s.mu.Lock()
	defer s.mu.Unlock()
	state := s.states[conn]
	if state == nil {
		state = &gssServerState{}
		s.states[conn] = state
	}
	return state
}

// snapshot returns the recorded wire values. | snapshot 返回已记录的线上值。
func (s *gssMockServer) snapshot() (binds int, initial []byte, mic bool, authzID, offer []byte) {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.binds, append([]byte(nil), s.initial...), s.mic,
		append([]byte(nil), s.authzID...), append([]byte(nil), s.offer...)
}

// handle dispatches one LDAP request. | handle 分派一条 LDAP 请求。
func (s *gssMockServer) handle(session *mockSession, message *LDAPMessage) error {
	state := s.stateFor(session.conn)
	switch request := message.Op.(type) {
	case *BindRequest:
		authentication, ok := request.Authentication.(SASLAuthentication)
		if !ok {
			return errors.New("GSSAPI mock: expected SASL authentication")
		}
		return s.handleBind(session, message.MessageID, authentication, state)
	case *ExtendedRequest:
		if state.phase >= 5 && request.Name == OIDWhoAmI {
			return session.Write(&LDAPMessage{
				MessageID: message.MessageID,
				Op: &ExtendedResponse{
					Result: LDAPResult{Code: ResultSuccess},
					Value:  []byte("dn:uid=alice,dc=example,dc=com"),
				},
			})
		}
		return errors.New("GSSAPI mock: unexpected extended request")
	default:
		return errors.New("GSSAPI mock: unexpected operation")
	}
}

// handleBind advances the SASL state machine. | handleBind 推进 SASL 状态机。
func (s *gssMockServer) handleBind(session *mockSession, id int, authentication SASLAuthentication, state *gssServerState) error {
	if authentication.Mechanism != SASLMechanismGSSAPI {
		return errors.New("GSSAPI mock: unexpected mechanism " + authentication.Mechanism)
	}
	s.mu.Lock()
	s.binds++
	s.mu.Unlock()
	switch state.phase {
	case 0:
		s.mu.Lock()
		s.initial = append([]byte(nil), authentication.Credentials...)
		s.mu.Unlock()
		if s.cfg.initialResult != nil {
			state.phase = 5
			return session.writeSimpleResult(id, &BindResponse{Result: LDAPResult{Code: *s.cfg.initialResult}})
		}
		if s.cfg.initialSuccess {
			state.phase = 5
			return session.writeSimpleResult(id, &BindResponse{Result: LDAPResult{Code: ResultSuccess}})
		}
		state.phase = 1
		if s.cfg.initialNoCredentials {
			return session.writeSimpleResult(id, &BindResponse{Result: LDAPResult{Code: ResultSASLBindInProgress}})
		}
		return session.writeSimpleResult(id, &BindResponse{
			Result:                LDAPResult{Code: ResultSASLBindInProgress},
			ServerSASLCredentials: fakeGSSContextToken,
		})
	case 1:
		state.mic = bytes.Equal(authentication.Credentials, fakeGSSMechListMIC)
		s.mu.Lock()
		s.mic = state.mic
		s.mu.Unlock()
		if s.cfg.contextResult != nil {
			state.phase = 5
			return session.writeSimpleResult(id, &BindResponse{Result: LDAPResult{Code: *s.cfg.contextResult}})
		}
		if s.cfg.contextNoCredentials {
			state.phase = 2
			return session.writeSimpleResult(id, &BindResponse{Result: LDAPResult{Code: ResultSASLBindInProgress}})
		}
		state.phase = 2
		return session.writeSimpleResult(id, &BindResponse{
			Result:                LDAPResult{Code: ResultSASLBindInProgress},
			ServerSASLCredentials: s.layerChallenge(),
		})
	case 2:
		cleartext, confidential, err := fakeGSSUnwrap(authentication.Credentials)
		if err != nil {
			return err
		}
		if confidential || len(cleartext) < 4 {
			return errors.New("GSSAPI mock: malformed client layer offer")
		}
		state.offer = append([]byte(nil), cleartext...)
		state.authzID = append([]byte(nil), cleartext[4:]...)
		s.mu.Lock()
		s.offer = append([]byte(nil), cleartext...)
		s.authzID = append([]byte(nil), cleartext[4:]...)
		s.mu.Unlock()
		if s.cfg.selectionFirst {
			state.phase = 3
			return session.writeSimpleResult(id, &BindResponse{
				Result:                LDAPResult{Code: ResultSASLBindInProgress},
				ServerSASLCredentials: fakeGSSWrap(false, []byte{gssapiLayerNone, 0, 0, 0}),
			})
		}
		return s.finish(session, id, state)
	case 3:
		if len(authentication.Credentials) != 0 {
			return errors.New("GSSAPI mock: final response was not empty")
		}
		state.phase = 4
		return s.finish(session, id, state)
	default:
		return errors.New("GSSAPI mock: unexpected bind phase")
	}
}

// layerChallenge builds the wrapped server layer bitmask. | layerChallenge 构建封装的
// 服务端安全层位图。
func (s *gssMockServer) layerChallenge() []byte {
	length := s.cfg.challengeLength
	if length == 0 {
		length = 4
	}
	cleartext := make([]byte, length)
	if len(cleartext) > 0 {
		cleartext[0] = s.cfg.serverLayers
	}
	if len(cleartext) >= 4 {
		size := s.cfg.serverMaxBuffer
		cleartext[1] = byte(size >> 16)
		cleartext[2] = byte(size >> 8)
		cleartext[3] = byte(size)
	}
	return fakeGSSWrap(s.cfg.confidential, cleartext)
}

// finish sends the final bind response. | finish 发送最终绑定响应。
func (s *gssMockServer) finish(session *mockSession, id int, state *gssServerState) error {
	state.phase = 5
	if s.cfg.finalEmptyChallenge {
		state.phase = 4
		return session.writeSimpleResult(id, &BindResponse{Result: LDAPResult{Code: ResultSASLBindInProgress}})
	}
	if s.cfg.selectLayer != nil {
		selection := []byte{*s.cfg.selectLayer,
			byte(s.cfg.selectMaxBuffer >> 16), byte(s.cfg.selectMaxBuffer >> 8), byte(s.cfg.selectMaxBuffer)}
		return session.writeSimpleResult(id, &BindResponse{
			Result:                LDAPResult{Code: ResultSASLBindInProgress},
			ServerSASLCredentials: fakeGSSWrap(false, selection),
		})
	}
	if s.cfg.finalResult != nil {
		return session.writeSimpleResult(id, &BindResponse{Result: LDAPResult{Code: *s.cfg.finalResult}})
	}
	if s.cfg.successSelection != nil {
		selection := []byte{*s.cfg.successSelection, 0, 0, 0}
		return session.writeSimpleResult(id, &BindResponse{
			Result:                LDAPResult{Code: ResultSuccess},
			ServerSASLCredentials: fakeGSSWrap(false, selection),
		})
	}
	return session.writeSimpleResult(id, &BindResponse{Result: LDAPResult{Code: ResultSuccess}})
}

// newGSSTestKerberosClient returns a validation-only Kerberos client. | newGSSTestKerberosClient
// 返回仅用于校验的 Kerberos 客户端。
func newGSSTestKerberosClient(t *testing.T) *kerberos.Client {
	t.Helper()
	client, err := kerberos.NewClient(kerberos.Config{
		Realm:     "EXAMPLE.COM",
		Principal: "alice@EXAMPLE.COM",
		Password:  "kerberos-test-password",
		ETypes:    []int32{kerberos.ETypeAES256CTS},
	})
	if err != nil {
		t.Fatalf("kerberos.NewClient: %v", err)
	}
	return client
}

// gssTestOptions returns options wired to the fake initiator. | gssTestOptions
// 返回接入模拟发起方的选项。
func gssTestOptions(t *testing.T, recorder *fakeGSSRecorder, behavior fakeGSSBehavior) GSSAPIOptions {
	t.Helper()
	return GSSAPIOptions{
		Client:       newGSSTestKerberosClient(t),
		Service:      "ldap/dc1.example.com",
		ServiceRealm: "EXAMPLE.COM",
		newInitiator: fakeGSSFactory(recorder, behavior),
	}
}

// gssTestBindServer dials a mock server and performs one GSSAPI bind. |
// gssTestBindServer 拨号模拟服务端并执行一次 GSSAPI 绑定。
func gssTestBindServer(t *testing.T, server *mockServer, options GSSAPIOptions) (*Client, error) {
	t.Helper()
	client, err := DialURL(mustTimeoutContext(t, 5*time.Second), server.URL())
	if err != nil {
		t.Fatalf("DialURL: %v", err)
	}
	t.Cleanup(func() { _ = client.Close() })
	return client, client.BindSASLGSSAPI(mustTimeoutContext(t, 5*time.Second), options)
}

// TestBindSASLGSSAPI covers the raw, SPNEGO, MIC, and authzID exchanges. |
// TestBindSASLGSSAPI 覆盖原始、SPNEGO、MIC 与 authzID 交换。
func TestBindSASLGSSAPI(t *testing.T) {
	tests := []struct {
		name    string
		spnego  bool
		mic     bool
		authzID string
	}{
		{name: "raw kerberos"},
		{name: "spnego", spnego: true},
		{name: "spnego with mechListMIC", spnego: true, mic: true},
		{name: "authzid", authzID: "u:alice@example.com"},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			server, gssServer := newGSSMockServer(t, defaultGSSTestConfig())
			recorder := &fakeGSSRecorder{}
			options := gssTestOptions(t, recorder, fakeGSSBehavior{sendMIC: test.mic})
			options.SPNEGO = test.spnego
			options.AuthzID = test.authzID
			client, err := gssTestBindServer(t, server, options)
			if err != nil {
				t.Fatalf("BindSASLGSSAPI: %v", err)
			}
			if client.auth == nil || client.auth.kind != authGSSAPI {
				t.Fatalf("auth state = %+v", client.auth)
			}
			recorded := recorder.snapshot()
			if len(recorded) != 1 {
				t.Fatalf("initiator count = %d", len(recorded))
			}
			if !recorded[0].MutualAuth || recorded[0].SPNEGO != test.spnego ||
				recorded[0].Service != "ldap/dc1.example.com" || recorded[0].ServiceRealm != "EXAMPLE.COM" {
				t.Fatalf("initiator options = %+v", recorded[0])
			}
			binds, initial, mic, authzID, offer := gssServer.snapshot()
			if binds != 3 {
				t.Fatalf("binds = %d, want 3", binds)
			}
			if !bytes.Equal(initial, []byte("CTX-INITIAL")) {
				t.Fatalf("initial token = %q", initial)
			}
			if mic != test.mic {
				t.Fatalf("mechListMIC observed = %v, want %v", mic, test.mic)
			}
			if string(authzID) != test.authzID {
				t.Fatalf("authzID = %q, want %q", authzID, test.authzID)
			}
			if len(offer) != 4+len(test.authzID) || offer[0] != gssapiLayerNone || offer[1] != 0 || offer[2] != 0 || offer[3] != 0 {
				t.Fatalf("layer offer = %x", offer)
			}
		})
	}
}

// TestBindSASLGSSAPIChannelBinding covers tls-server-end-point derivation. |
// TestBindSASLGSSAPIChannelBinding 覆盖 tls-server-end-point 派生。
func TestBindSASLGSSAPIChannelBinding(t *testing.T) {
	certificate, pool := testCertificate(t)
	endpointHash, err := tlsServerEndPoint(certificate.Leaf)
	if err != nil {
		t.Fatalf("tlsServerEndPoint: %v", err)
	}
	binding, err := ntlm.ChannelBindingHash(endpointHash)
	if err != nil {
		t.Fatalf("ChannelBindingHash: %v", err)
	}
	gssServer := &gssMockServer{cfg: defaultGSSTestConfig(), states: make(map[net.Conn]*gssServerState)}
	server := startMockServerTLS(t, &tls.Config{Certificates: []tls.Certificate{certificate}, MinVersion: tls.VersionTLS12}, gssServer.handle)
	client, err := DialURL(mustTimeoutContext(t, 5*time.Second), server.URL(), Config{TLSConfig: testTLSConfig(pool)})
	if err != nil {
		t.Fatalf("DialURL: %v", err)
	}
	defer client.Close()
	recorder := &fakeGSSRecorder{}
	options := gssTestOptions(t, recorder, fakeGSSBehavior{})
	options.ChannelBinding = true
	if err := client.BindSASLGSSAPI(mustTimeoutContext(t, 5*time.Second), options); err != nil {
		t.Fatalf("BindSASLGSSAPI: %v", err)
	}
	if _, secure := client.TLSConnectionState(); !secure {
		t.Fatal("connection is not TLS-protected")
	}
	recorded := recorder.snapshot()
	if len(recorded) != 1 {
		t.Fatalf("initiator count = %d", len(recorded))
	}
	if !bytes.Equal(recorded[0].ChannelBindings, binding) {
		t.Fatalf("channel binding = %x, want %x", recorded[0].ChannelBindings, binding)
	}
	if binds, _, _, _, _ := gssServer.snapshot(); binds != 3 {
		t.Fatalf("binds = %d, want 3", binds)
	}
}

// TestBindSASLGSSAPIChannelBindingRequiresTLS verifies channel binding is
// refused on plaintext connections before any bind is sent. |
// TestBindSASLGSSAPIChannelBindingRequiresTLS 校验明文连接在发出任何绑定前拒绝通道绑定。
func TestBindSASLGSSAPIChannelBindingRequiresTLS(t *testing.T) {
	server, gssServer := newGSSMockServer(t, defaultGSSTestConfig())
	recorder := &fakeGSSRecorder{}
	options := gssTestOptions(t, recorder, fakeGSSBehavior{})
	options.ChannelBinding = true
	client, err := gssTestBindServer(t, server, options)
	if err == nil {
		t.Fatal("BindSASLGSSAPI accepted channel binding over plaintext")
	}
	if !errors.Is(err, ErrTLSRequired) {
		t.Fatalf("error = %v, want ErrTLSRequired", err)
	}
	if binds, _, _, _, _ := gssServer.snapshot(); binds != 0 {
		t.Fatalf("binds = %d, want 0", binds)
	}
	if len(recorder.snapshot()) != 0 {
		t.Fatal("initiator was built before channel binding validation")
	}
	if client.auth != nil {
		t.Fatalf("auth state = %+v, want nil", client.auth)
	}
}

// TestBindSASLGSSAPILayerVariants covers the tolerant and confirming layer
// exchanges. | TestBindSASLGSSAPILayerVariants 覆盖容错与确认型安全层交换。
func TestBindSASLGSSAPILayerVariants(t *testing.T) {
	none := gssapiLayerNone
	success := ResultSuccess
	tests := []struct {
		name  string
		cfg   gssServerConfig
		binds int
	}{
		{
			name:  "server completes after context without layer challenge",
			cfg:   gssServerConfig{contextResult: &success},
			binds: 2,
		},
		{
			name:  "server confirms selection with success",
			cfg:   gssServerConfig{serverLayers: gssapiLayerNone, successSelection: &none},
			binds: 3,
		},
		{
			name:  "server sends selection as an intermediate challenge",
			cfg:   gssServerConfig{serverLayers: gssapiLayerNone, selectionFirst: true},
			binds: 4,
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			server, gssServer := newGSSMockServer(t, test.cfg)
			client, err := gssTestBindServer(t, server, gssTestOptions(t, &fakeGSSRecorder{}, fakeGSSBehavior{}))
			if err != nil {
				t.Fatalf("BindSASLGSSAPI: %v", err)
			}
			if client.auth == nil || client.auth.kind != authGSSAPI {
				t.Fatalf("auth state = %+v", client.auth)
			}
			if binds, _, _, _, _ := gssServer.snapshot(); binds != test.binds {
				t.Fatalf("binds = %d, want %d", binds, test.binds)
			}
		})
	}
}

// TestBindSASLGSSAPIServerErrors covers malformed or rejecting server replies. |
// TestBindSASLGSSAPIServerErrors 覆盖畸形或拒绝的服务端响应。
func TestBindSASLGSSAPIServerErrors(t *testing.T) {
	invalid := ResultInvalidCredentials
	unsupported := ResultAuthMethodNotSupported
	integrity := byte(2)
	confidentiality := byte(4)
	none := gssapiLayerNone
	tests := []struct {
		name  string
		cfg   gssServerConfig
		want  error
		binds int
	}{
		{
			name:  "success before the context is established",
			cfg:   gssServerConfig{initialSuccess: true},
			want:  ErrSASL,
			binds: 1,
		},
		{
			name:  "empty context challenge",
			cfg:   gssServerConfig{initialNoCredentials: true},
			want:  ErrSASL,
			binds: 1,
		},
		{
			name:  "invalid credentials at the initial bind",
			cfg:   gssServerConfig{initialResult: &invalid},
			want:  ErrInvalidCredentials,
			binds: 1,
		},
		{
			name:  "unsupported mechanism at the initial bind",
			cfg:   gssServerConfig{initialResult: &unsupported},
			want:  ErrAuthMethodNotSupported,
			binds: 1,
		},
		{
			name:  "invalid credentials after the context token",
			cfg:   gssServerConfig{contextResult: &invalid},
			want:  ErrInvalidCredentials,
			binds: 2,
		},
		{
			name:  "missing layer challenge",
			cfg:   gssServerConfig{contextNoCredentials: true},
			want:  ErrSASL,
			binds: 2,
		},
		{
			name:  "no offered security layers",
			cfg:   gssServerConfig{serverLayers: 0},
			want:  ErrSASL,
			binds: 2,
		},
		{
			name:  "integrity only",
			cfg:   gssServerConfig{serverLayers: integrity},
			want:  ErrSASL,
			binds: 2,
		},
		{
			name:  "confidentiality only",
			cfg:   gssServerConfig{serverLayers: confidentiality},
			want:  ErrSASL,
			binds: 2,
		},
		{
			name:  "no layer with non-zero buffer",
			cfg:   gssServerConfig{serverLayers: gssapiLayerNone, serverMaxBuffer: 4096},
			want:  ErrSASL,
			binds: 2,
		},
		{
			name:  "confidential challenge",
			cfg:   gssServerConfig{serverLayers: gssapiLayerNone, confidential: true},
			want:  ErrSASL,
			binds: 2,
		},
		{
			name:  "short challenge",
			cfg:   gssServerConfig{serverLayers: gssapiLayerNone, challengeLength: 3},
			want:  ErrSASL,
			binds: 2,
		},
		{
			name:  "long challenge",
			cfg:   gssServerConfig{serverLayers: gssapiLayerNone, challengeLength: 5},
			want:  ErrSASL,
			binds: 2,
		},
		{
			name:  "selection without confirmation",
			cfg:   gssServerConfig{serverLayers: gssapiLayerNone, finalEmptyChallenge: true},
			want:  ErrSASL,
			binds: 3,
		},
		{
			name:  "unsupported selection layer",
			cfg:   gssServerConfig{serverLayers: gssapiLayerNone, selectLayer: &integrity},
			want:  ErrSASL,
			binds: 3,
		},
		{
			name:  "selection with non-zero buffer",
			cfg:   gssServerConfig{serverLayers: gssapiLayerNone, selectLayer: &none, selectMaxBuffer: 1024},
			want:  ErrSASL,
			binds: 3,
		},
		{
			name:  "success carrying an unsupported selection",
			cfg:   gssServerConfig{serverLayers: gssapiLayerNone, successSelection: &integrity},
			want:  ErrSASL,
			binds: 3,
		},
		{
			name:  "invalid credentials at the layer bind",
			cfg:   gssServerConfig{serverLayers: gssapiLayerNone, finalResult: &invalid},
			want:  ErrInvalidCredentials,
			binds: 3,
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			server, gssServer := newGSSMockServer(t, test.cfg)
			client, err := gssTestBindServer(t, server, gssTestOptions(t, &fakeGSSRecorder{}, fakeGSSBehavior{}))
			if err == nil {
				t.Fatal("BindSASLGSSAPI succeeded, want an error")
			}
			if !errors.Is(err, test.want) {
				t.Fatalf("error = %v, want %v", err, test.want)
			}
			if client.auth != nil {
				t.Fatalf("auth state = %+v, want nil", client.auth)
			}
			if binds, _, _, _, _ := gssServer.snapshot(); binds != test.binds {
				t.Fatalf("binds = %d, want %d", binds, test.binds)
			}
		})
	}
}

// TestBindSASLGSSAPIInitiatorErrors covers failures produced by the GSS context
// itself. | TestBindSASLGSSAPIInitiatorErrors 覆盖 GSS 上下文自身产生的故障。
func TestBindSASLGSSAPIInitiatorErrors(t *testing.T) {
	tests := []struct {
		name     string
		behavior fakeGSSBehavior
		want     error
		binds    int
	}{
		{
			name:     "factory failure",
			behavior: fakeGSSBehavior{factoryErr: kerberos.ErrInvalidConfig},
			want:     kerberos.ErrInvalidConfig,
			binds:    0,
		},
		{
			name:     "initial token failure",
			behavior: fakeGSSBehavior{initialErr: kerberos.ErrCredentials},
			want:     kerberos.ErrCredentials,
			binds:    0,
		},
		{
			name:     "step failure",
			behavior: fakeGSSBehavior{stepErr: kerberos.ErrBadIntegrity},
			want:     kerberos.ErrBadIntegrity,
			binds:    1,
		},
		{
			name:     "incomplete context without a token",
			behavior: fakeGSSBehavior{incomplete: true},
			want:     ErrSASL,
			binds:    1,
		},
		{
			name:     "wrap failure",
			behavior: fakeGSSBehavior{wrapErr: kerberos.ErrBadIntegrity},
			want:     kerberos.ErrBadIntegrity,
			binds:    2,
		},
		{
			name:     "unwrap failure",
			behavior: fakeGSSBehavior{unwrapErr: kerberos.ErrBadIntegrity},
			want:     kerberos.ErrBadIntegrity,
			binds:    2,
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			server, gssServer := newGSSMockServer(t, defaultGSSTestConfig())
			client, err := gssTestBindServer(t, server, gssTestOptions(t, &fakeGSSRecorder{}, test.behavior))
			if err == nil {
				t.Fatal("BindSASLGSSAPI succeeded, want an error")
			}
			if !errors.Is(err, test.want) {
				t.Fatalf("error = %v, want %v", err, test.want)
			}
			if !errors.Is(err, ErrSASL) {
				t.Fatalf("error = %v, want ErrSASL", err)
			}
			if binds, _, _, _, _ := gssServer.snapshot(); binds != test.binds {
				t.Fatalf("binds = %d, want %d", binds, test.binds)
			}
			if client.auth != nil {
				t.Fatalf("auth state = %+v, want nil", client.auth)
			}
		})
	}
}

// TestBindSASLGSSAPIValidation rejects invalid options before network I/O. |
// TestBindSASLGSSAPIValidation 在网络 I/O 之前拒绝非法选项。
func TestBindSASLGSSAPIValidation(t *testing.T) {
	validClient := newGSSTestKerberosClient(t)
	tests := []struct {
		name    string
		options GSSAPIOptions
		want    error
	}{
		{
			name:    "missing kerberos client",
			options: GSSAPIOptions{Service: "ldap/dc1.example.com"},
			want:    ErrInvalidConfig,
		},
		{
			name:    "empty service",
			options: GSSAPIOptions{Client: validClient, Service: "   "},
			want:    ErrInvalidConfig,
		},
		{
			name:    "authzid too long",
			options: GSSAPIOptions{Client: validClient, Service: "ldap/dc1.example.com", AuthzID: strings.Repeat("a", gssapiAuthzIDMaxLen+1)},
			want:    ErrSASL,
		},
		{
			name:    "authzid with invalid utf8",
			options: GSSAPIOptions{Client: validClient, Service: "ldap/dc1.example.com", AuthzID: "u:\xff"},
			want:    ErrSASL,
		},
		{
			name:    "authzid with nul",
			options: GSSAPIOptions{Client: validClient, Service: "ldap/dc1.example.com", AuthzID: "u:ali\x00ce"},
			want:    ErrSASL,
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			client := &Client{}
			err := client.BindSASLGSSAPI(mustTimeoutContext(t, time.Second), test.options)
			if err == nil {
				t.Fatal("BindSASLGSSAPI accepted invalid options")
			}
			if !errors.Is(err, test.want) {
				t.Fatalf("error = %v, want %v", err, test.want)
			}
			if client.auth != nil {
				t.Fatalf("auth state = %+v, want nil", client.auth)
			}
		})
	}
}

// TestConfigRejectsConflictingGSSAPI verifies Config validation before dialing. |
// TestConfigRejectsConflictingGSSAPI 校验拨号前的配置校验。
func TestConfigRejectsConflictingGSSAPI(t *testing.T) {
	validClient := newGSSTestKerberosClient(t)
	tests := []struct {
		name string
		cfg  Config
	}{
		{
			name: "simple bind and gssapi",
			cfg: Config{
				URL:          "ldap://127.0.0.1:1",
				BindDN:       "cn=admin,dc=example,dc=com",
				BindPassword: "password",
				GSSAPI:       &GSSAPIOptions{Client: validClient, Service: "ldap/dc1.example.com"},
			},
		},
		{
			name: "gssapi without client",
			cfg: Config{
				URL:    "ldap://127.0.0.1:1",
				GSSAPI: &GSSAPIOptions{Service: "ldap/dc1.example.com"},
			},
		},
		{
			name: "gssapi without service",
			cfg: Config{
				URL:    "ldap://127.0.0.1:1",
				GSSAPI: &GSSAPIOptions{Client: validClient},
			},
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			_, err := Dial(mustTimeoutContext(t, time.Second), test.cfg)
			if err == nil {
				t.Fatal("Dial accepted an invalid GSSAPI configuration")
			}
			if !errors.Is(err, ErrInvalidConfig) {
				t.Fatalf("error = %v, want ErrInvalidConfig", err)
			}
		})
	}
}

// TestDialWithGSSAPI verifies auto-bind, explicit reconnect and transparent
// replay after a transport failure. | TestDialWithGSSAPI 校验自动绑定、显式重连与
// 传输故障后的透明重放。
func TestDialWithGSSAPI(t *testing.T) {
	server, gssServer := newGSSMockServer(t, defaultGSSTestConfig())
	recorder := &fakeGSSRecorder{}
	options := gssTestOptions(t, recorder, fakeGSSBehavior{})
	options.SPNEGO = true
	options.AuthzID = "u:alice@example.com"
	client, err := DialURL(mustTimeoutContext(t, 5*time.Second), server.URL(), Config{GSSAPI: &options})
	if err != nil {
		t.Fatalf("DialURL: %v", err)
	}
	defer client.Close()
	if client.auth == nil || client.auth.kind != authGSSAPI || !client.auth.gssapi.SPNEGO {
		t.Fatalf("auth state = %+v", client.auth)
	}
	if binds, _, _, authzID, _ := gssServer.snapshot(); binds != 3 || string(authzID) != "u:alice@example.com" {
		t.Fatalf("binds = %d, authzID = %q, want 3 and the configured identity", binds, authzID)
	}
	if err := client.Reconnect(mustTimeoutContext(t, 5*time.Second)); err != nil {
		t.Fatalf("Reconnect: %v", err)
	}
	if binds, _, mic, authzID, _ := gssServer.snapshot(); binds != 6 || mic || string(authzID) != "u:alice@example.com" {
		t.Fatalf("after reconnect: binds = %d, mic = %v, authzID = %q", binds, mic, authzID)
	}
	if len(recorder.snapshot()) != 2 {
		t.Fatalf("initiator count = %d, want 2", len(recorder.snapshot()))
	}
	// Simulate a broken connection. The first operation reports the transport
	// failure; the next one reconnects and replays the retained options. | 模拟连接
	// 中断。第一次操作报告传输故障；下一次操作重连并重放保留的选项。
	server.closeAllConns(t)
	if _, err := client.WhoAmI(mustTimeoutContext(t, 5*time.Second)); err == nil {
		t.Fatal("WhoAmI succeeded on a closed connection")
	}
	identity, err := client.WhoAmI(mustTimeoutContext(t, 5*time.Second))
	if err != nil {
		t.Fatalf("WhoAmI after reconnect: %v", err)
	}
	if identity != "dn:uid=alice,dc=example,dc=com" {
		t.Fatalf("identity = %q", identity)
	}
	if binds, _, _, _, _ := gssServer.snapshot(); binds != 9 {
		t.Fatalf("binds = %d, want 9 (three exchanges)", binds)
	}
	if len(recorder.snapshot()) != 3 {
		t.Fatalf("initiator count = %d, want 3", len(recorder.snapshot()))
	}
	if client.auth == nil || client.auth.kind != authGSSAPI {
		t.Fatalf("auth state = %+v after replay", client.auth)
	}
}

// TestBindSASLGSSAPIReplacesPreviousAuth verifies a successful GSSAPI bind
// replaces an earlier simple bind and that a failed GSSAPI bind clears state. |
// TestBindSASLGSSAPIReplacesPreviousAuth 校验成功的 GSSAPI 绑定替换先前的简单绑定，
// 且失败的 GSSAPI 绑定清除状态。
func TestBindSASLGSSAPIReplacesPreviousAuth(t *testing.T) {
	server := startMockServer(t, func(session *mockSession, message *LDAPMessage) error {
		request, ok := message.Op.(*BindRequest)
		if !ok {
			return errors.New("unexpected operation")
		}
		if _, simple := request.Authentication.(SimpleAuthentication); simple {
			return session.writeSimpleResult(message.MessageID, &BindResponse{Result: LDAPResult{Code: ResultSuccess}})
		}
		return session.writeSimpleResult(message.MessageID, &BindResponse{Result: LDAPResult{Code: ResultInvalidCredentials}})
	})
	client, err := DialURL(mustTimeoutContext(t, 5*time.Second), server.URL())
	if err != nil {
		t.Fatalf("DialURL: %v", err)
	}
	defer client.Close()
	if err := client.Bind(mustTimeoutContext(t, 5*time.Second), "cn=admin,dc=example,dc=com", "password"); err != nil {
		t.Fatalf("Bind: %v", err)
	}
	if client.auth == nil || client.auth.kind != authSimple {
		t.Fatalf("auth state = %+v, want authSimple", client.auth)
	}
	err = client.BindSASLGSSAPI(mustTimeoutContext(t, 5*time.Second), gssTestOptions(t, &fakeGSSRecorder{}, fakeGSSBehavior{}))
	if err == nil {
		t.Fatal("BindSASLGSSAPI succeeded, want invalid credentials")
	}
	if !errors.Is(err, ErrInvalidCredentials) {
		t.Fatalf("error = %v, want ErrInvalidCredentials", err)
	}
	if client.auth != nil {
		t.Fatalf("auth state = %+v, want nil after a failed GSSAPI bind", client.auth)
	}
}
