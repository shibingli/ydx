package ldap

import (
	"bytes"
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"crypto/sha512"
	"crypto/subtle"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"hash"
	"strconv"
	"strings"
	"sync"
	"testing"

	ydbase64 "github.com/shibingli/ydx/base64"
)

// TestSASLPlain verifies the PLAIN credential wire format. | TestSASLPlain
// 校验 PLAIN 凭据的网络格式。
func TestSASLPlain(t *testing.T) {
	var (
		mu          sync.Mutex
		credentials [][]byte
	)
	server := startMockServer(t, func(session *mockSession, message *LDAPMessage) error {
		request, ok := message.Op.(*BindRequest)
		if !ok {
			return errors.New("expected bind")
		}
		if request.DN != "" {
			t.Errorf("SASL bind DN = %q", request.DN)
		}
		auth, ok := request.Authentication.(SASLAuthentication)
		if !ok || auth.Mechanism != SASLMechanismPlain {
			t.Fatalf("authentication = %#v", request.Authentication)
		}
		mu.Lock()
		credentials = append(credentials, append([]byte(nil), auth.Credentials...))
		mu.Unlock()
		return session.writeSimpleResult(message.MessageID, &BindResponse{Result: LDAPResult{Code: ResultSuccess}})
	})
	client, err := DialURL(context.Background(), server.URL())
	if err != nil {
		t.Fatalf("DialURL: %v", err)
	}
	defer client.Close()
	if err := client.BindSASLPlain(context.Background(), "alice", "secret"); err != nil {
		t.Fatalf("BindSASLPlain: %v", err)
	}
	if err := client.BindSASLPlainAuthzID(context.Background(), "dn:cn=admin", "alice", "secret"); err != nil {
		t.Fatalf("BindSASLPlainAuthzID: %v", err)
	}
	mu.Lock()
	defer mu.Unlock()
	want := [][]byte{
		[]byte("\x00alice\x00secret"),
		[]byte("dn:cn=admin\x00alice\x00secret"),
	}
	if len(credentials) != len(want) {
		t.Fatalf("credentials = %q", credentials)
	}
	for index := range want {
		if !bytes.Equal(credentials[index], want[index]) {
			t.Fatalf("credentials[%d] = %q, want %q", index, credentials[index], want[index])
		}
	}
}

// TestSASLPlainValidation verifies local PLAIN rejection. | TestSASLPlainValidation
// 校验 PLAIN 的本地拒绝。
func TestSASLPlainValidation(t *testing.T) {
	client := &Client{}
	if err := client.BindSASLPlain(context.Background(), "alice", ""); !errors.Is(err, ErrEmptyPassword) {
		t.Fatalf("empty password error = %v", err)
	}
	if err := client.BindSASLPlain(context.Background(), "", "secret"); !errors.Is(err, ErrSASL) {
		t.Fatalf("empty username error = %v", err)
	}
	if err := client.BindSASLPlain(context.Background(), "alice", "se\x00cret"); !errors.Is(err, ErrSASL) {
		t.Fatalf("NUL password error = %v", err)
	}
}

// TestSASLPlainEmptyPasswordDoesNotDial verifies no connection is made for an
// invalid PLAIN bind. | TestSASLPlainEmptyPasswordDoesNotDial 校验非法 PLAIN 绑定
// 不会建立连接。
func TestSASLPlainEmptyPasswordDoesNotDial(t *testing.T) {
	server := startMockServer(t, func(session *mockSession, message *LDAPMessage) error {
		t.Error("server received a bind for an empty password")
		return nil
	})
	client, err := DialURL(context.Background(), server.URL())
	if err != nil {
		t.Fatalf("DialURL: %v", err)
	}
	defer client.Close()
	if err := client.BindSASLPlain(context.Background(), "alice", ""); !errors.Is(err, ErrEmptyPassword) {
		t.Fatalf("error = %v", err)
	}
}

// TestSASLPlainRequiresTLS verifies Config.RequireSASLPlainTLS rejects a
// cleartext bind without sending credentials and accepts a TLS-protected bind. |
// TestSASLPlainRequiresTLS 校验 Config.RequireSASLPlainTLS 拒绝明文绑定且不发送凭据，
// 并接受 TLS 保护下的绑定。
func TestSASLPlainRequiresTLS(t *testing.T) {
	t.Run("rejects cleartext", func(t *testing.T) {
		server := startMockServer(t, func(session *mockSession, message *LDAPMessage) error {
			if _, ok := message.Op.(*BindRequest); ok {
				t.Error("cleartext PLAIN bind reached the server")
				return session.writeSimpleResult(message.MessageID, &BindResponse{Result: LDAPResult{Code: ResultSuccess}})
			}
			return errors.New("unexpected operation")
		})
		client, err := DialURL(context.Background(), server.URL(), Config{RequireSASLPlainTLS: true})
		if err != nil {
			t.Fatalf("DialURL: %v", err)
		}
		defer client.Close()
		if err := client.BindSASLPlain(context.Background(), "alice", "secret"); !errors.Is(err, ErrTLSRequired) {
			t.Fatalf("BindSASLPlain error = %v", err)
		}
		if err := client.BindSASLPlainAuthzID(context.Background(), "dn:cn=admin", "alice", "secret"); !errors.Is(err, ErrTLSRequired) {
			t.Fatalf("BindSASLPlainAuthzID error = %v", err)
		}
		if client.auth != nil {
			t.Fatalf("rejected bind stored authentication: %+v", client.auth)
		}
	})
	t.Run("accepts TLS", func(t *testing.T) {
		certificate, pool := testCertificate(t)
		var (
			mu          sync.Mutex
			credentials [][]byte
		)
		server := startMockServerTLS(t, &tls.Config{Certificates: []tls.Certificate{certificate}, MinVersion: tls.VersionTLS12},
			func(session *mockSession, message *LDAPMessage) error {
				request, ok := message.Op.(*BindRequest)
				if !ok {
					return errors.New("expected bind")
				}
				auth, ok := request.Authentication.(SASLAuthentication)
				if !ok || auth.Mechanism != SASLMechanismPlain {
					return errors.New("expected PLAIN")
				}
				mu.Lock()
				credentials = append(credentials, append([]byte(nil), auth.Credentials...))
				mu.Unlock()
				return session.writeSimpleResult(message.MessageID, &BindResponse{Result: LDAPResult{Code: ResultSuccess}})
			})
		client, err := DialURL(context.Background(), server.URL(), Config{
			TLSConfig:           testTLSConfig(pool),
			RequireSASLPlainTLS: true,
		})
		if err != nil {
			t.Fatalf("DialURL: %v", err)
		}
		defer client.Close()
		if err := client.BindSASLPlain(context.Background(), "alice", "secret"); err != nil {
			t.Fatalf("BindSASLPlain: %v", err)
		}
		mu.Lock()
		defer mu.Unlock()
		if len(credentials) != 1 || !bytes.Equal(credentials[0], []byte("\x00alice\x00secret")) {
			t.Fatalf("credentials = %q", credentials)
		}
	})
}

// TestSASLExternal verifies EXTERNAL requires TLS and handles one challenge. |
// TestSASLExternal 校验 EXTERNAL 需要 TLS 并处理一次挑战。
func TestSASLExternal(t *testing.T) {
	t.Run("requires TLS", func(t *testing.T) {
		server := startMockServer(t, func(session *mockSession, message *LDAPMessage) error {
			return nil
		})
		client, err := DialURL(context.Background(), server.URL())
		if err != nil {
			t.Fatalf("DialURL: %v", err)
		}
		defer client.Close()
		if err := client.BindSASLExternal(context.Background()); !errors.Is(err, ErrTLSRequired) {
			t.Fatalf("error = %v", err)
		}
	})
	t.Run("challenge", func(t *testing.T) {
		certificate, pool := testCertificate(t)
		var (
			mu         sync.Mutex
			identities []string
		)
		server := startMockServerTLS(t, &tls.Config{Certificates: []tls.Certificate{certificate}, MinVersion: tls.VersionTLS12},
			func(session *mockSession, message *LDAPMessage) error {
				request, ok := message.Op.(*BindRequest)
				if !ok {
					return errors.New("expected bind")
				}
				auth, ok := request.Authentication.(SASLAuthentication)
				if !ok || auth.Mechanism != SASLMechanismExternal {
					return errors.New("expected EXTERNAL")
				}
				mu.Lock()
				identities = append(identities, string(auth.Credentials))
				attempt := len(identities)
				mu.Unlock()
				if attempt == 1 {
					return session.writeSimpleResult(message.MessageID, &BindResponse{
						Result:                LDAPResult{Code: ResultSASLBindInProgress},
						ServerSASLCredentials: []byte("continue"),
					})
				}
				return session.writeSimpleResult(message.MessageID, &BindResponse{Result: LDAPResult{Code: ResultSuccess}})
			})
		client, err := DialURL(context.Background(), server.URL(), Config{TLSConfig: testTLSConfig(pool)})
		if err != nil {
			t.Fatalf("DialURL: %v", err)
		}
		defer client.Close()
		if err := client.BindSASLExternal(context.Background(), "dn:cn=admin"); err != nil {
			t.Fatalf("BindSASLExternal: %v", err)
		}
		mu.Lock()
		defer mu.Unlock()
		if len(identities) != 2 || identities[0] != "dn:cn=admin" || identities[1] != "dn:cn=admin" {
			t.Fatalf("identities = %q", identities)
		}
	})
	if err := (&Client{}).BindSASLExternal(context.Background(), "a", "b"); !errors.Is(err, ErrInvalidConfig) {
		t.Fatalf("multiple authzID error = %v", err)
	}
}

// scramMockServer implements the server half of SCRAM-SHA-256/512. | scramMockServer
// 实现 SCRAM-SHA-256/512 的服务端半部。
type scramMockServer struct {
	t             *testing.T
	mechanism     string
	password      string
	newHash       func() hash.Hash
	serverFirst   string
	clientFirst   string
	phase         int
	badSignature  bool
	proofRejected bool
}

// handle processes one SCRAM bind message. | handle 处理一条 SCRAM 绑定消息。
func (s *scramMockServer) handle(session *mockSession, message *LDAPMessage) error {
	request, ok := message.Op.(*BindRequest)
	if !ok {
		return errors.New("expected bind")
	}
	auth, ok := request.Authentication.(SASLAuthentication)
	if !ok || auth.Mechanism != s.mechanism {
		return errors.New("unexpected SCRAM mechanism")
	}
	if s.phase == 0 {
		s.phase = 1
		clientFirst := string(auth.Credentials)
		if !strings.HasPrefix(clientFirst, "n,,") {
			return errors.New("unexpected GS2 header")
		}
		s.clientFirst = strings.TrimPrefix(clientFirst, "n,,")
		nonce := scramAttribute(s.clientFirst, "r")
		if nonce == "" || scramAttribute(s.clientFirst, "n") != "alice" {
			return errors.New("unexpected client-first message")
		}
		s.serverFirst = "r=" + nonce + "SERVER,s=" + ydbase64.StdEncoding.EncodeToString([]byte("test-salt")) + ",i=4096"
		return session.writeSimpleResult(message.MessageID, &BindResponse{
			Result:                LDAPResult{Code: ResultSASLBindInProgress},
			ServerSASLCredentials: []byte(s.serverFirst),
		})
	}
	final := string(auth.Credentials)
	proofIndex := strings.LastIndex(final, ",p=")
	if proofIndex < 0 {
		return errors.New("client-final lacks proof")
	}
	withoutProof := final[:proofIndex]
	proof, err := ydbase64.StdEncoding.DecodeString(final[proofIndex+3:])
	if err != nil {
		return err
	}
	if scramAttribute(withoutProof, "c") != "biws" {
		return errors.New("unexpected channel binding value")
	}
	serverNonce := scramAttribute(s.serverFirst, "r")
	if scramAttribute(withoutProof, "r") != serverNonce {
		return errors.New("client nonce mismatch")
	}
	password := s.password
	if s.proofRejected {
		password = "different-password"
	}
	salted, err := pbkdf2Key(s.newHash, password, []byte("test-salt"), 4096, s.newHash().Size())
	if err != nil {
		return err
	}
	clientKey := hmacBytes(s.newHash, salted, []byte("Client Key"))
	storedKey := hashBytes(s.newHash, clientKey)
	authMessage := s.clientFirst + "," + s.serverFirst + "," + withoutProof
	clientSignature := hmacBytes(s.newHash, storedKey, []byte(authMessage))
	expectedProof := make([]byte, len(clientKey))
	for index := range clientKey {
		expectedProof[index] = clientKey[index] ^ clientSignature[index]
	}
	if subtle.ConstantTimeCompare(proof, expectedProof) != 1 {
		return session.writeSimpleResult(message.MessageID, &BindResponse{Result: LDAPResult{
			Code:              ResultInvalidCredentials,
			DiagnosticMessage: "invalid SCRAM proof",
		}})
	}
	serverKey := hmacBytes(s.newHash, salted, []byte("Server Key"))
	signature := hmacBytes(s.newHash, serverKey, []byte(authMessage))
	if s.badSignature {
		signature = bytes.Repeat([]byte{0x00}, len(signature))
	}
	return session.writeSimpleResult(message.MessageID, &BindResponse{
		Result:                LDAPResult{Code: ResultSuccess},
		ServerSASLCredentials: []byte("v=" + ydbase64.StdEncoding.EncodeToString(signature)),
	})
}

// scramAttribute extracts a SCRAM attribute. | scramAttribute 提取 SCRAM 属性。
func scramAttribute(message, attribute string) string {
	for _, field := range strings.Split(message, ",") {
		if len(field) >= 2 && field[0] == attribute[0] && field[1] == '=' {
			return field[2:]
		}
	}
	return ""
}

// newSCRAMMock starts a SCRAM mock server for the selected mechanism. | newSCRAMMock
// 为选定机制启动 SCRAM 模拟服务端。
func newSCRAMMock(t *testing.T, mechanism string, newHash func() hash.Hash) (*scramMockServer, *mockServer) {
	t.Helper()
	mock := &scramMockServer{
		t:         t,
		mechanism: mechanism,
		password:  "secret",
		newHash:   newHash,
	}
	server := startMockServer(t, mock.handle)
	return mock, server
}

// TestSCRAMBind verifies complete SCRAM authentication and signature checking. |
// TestSCRAMBind 校验完整 SCRAM 认证与签名检查。
func TestSCRAMBind(t *testing.T) {
	tests := []struct {
		name      string
		mechanism string
		newHash   func() hash.Hash
		bind      func(context.Context, *Client) error
	}{
		{
			name:      "sha256",
			mechanism: SASLMechanismSCRAMSHA256,
			newHash:   sha256.New,
			bind: func(ctx context.Context, client *Client) error {
				return client.BindSCRAM256(ctx, "alice", "secret")
			},
		},
		{
			name:      "sha512",
			mechanism: SASLMechanismSCRAMSHA512,
			newHash:   sha512.New,
			bind: func(ctx context.Context, client *Client) error {
				return client.BindSCRAM512(ctx, "alice", "secret")
			},
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			_, server := newSCRAMMock(t, test.mechanism, test.newHash)
			client, err := DialURL(context.Background(), server.URL())
			if err != nil {
				t.Fatalf("DialURL: %v", err)
			}
			defer client.Close()
			if err := test.bind(context.Background(), client); err != nil {
				t.Fatalf("bind: %v", err)
			}
		})
	}
}

// TestSCRAMRejectsDuplicateServerFirstAttributes verifies the server-first
// message stays within the RFC 5802 ABNF, where nonce, salt and iteration
// count appear at most once. | TestSCRAMRejectsDuplicateServerFirstAttributes
// 验证服务端首条消息符合 RFC 5802 ABNF：随机数、盐与迭代次数最多出现一次。
func TestSCRAMRejectsDuplicateServerFirstAttributes(t *testing.T) {
	const clientNonce = "client-nonce"
	tests := []string{
		"r=" + clientNonce + "-server,s=c2FsdA==,i=4096,r=" + clientNonce + "-again",
		"r=" + clientNonce + "-server,s=c2FsdA==,i=4096,i=8192",
		"r=" + clientNonce + "-server,s=c2FsdA==,s=c2FsdA==,i=4096",
	}
	for _, message := range tests {
		if _, _, _, err := parseSCRAMServerFirst(message, clientNonce); !errors.Is(err, ErrSCRAM) {
			t.Fatalf("parseSCRAMServerFirst(%q) error = %v, want ErrSCRAM", message, err)
		}
	}
}

// TestSCRAMFailures verifies proof and server signature failures. | TestSCRAMFailures
// 校验证明与服务端签名失败。
func TestSCRAMFailures(t *testing.T) {
	t.Run("bad proof", func(t *testing.T) {
		mock, server := newSCRAMMock(t, SASLMechanismSCRAMSHA256, sha256.New)
		mock.proofRejected = true
		client, err := DialURL(context.Background(), server.URL())
		if err != nil {
			t.Fatalf("DialURL: %v", err)
		}
		defer client.Close()
		if err := client.BindSCRAM256(context.Background(), "alice", "secret"); !errors.Is(err, ErrInvalidCredentials) {
			t.Fatalf("error = %v", err)
		}
	})
	t.Run("bad server signature", func(t *testing.T) {
		mock, server := newSCRAMMock(t, SASLMechanismSCRAMSHA256, sha256.New)
		mock.badSignature = true
		client, err := DialURL(context.Background(), server.URL())
		if err != nil {
			t.Fatalf("DialURL: %v", err)
		}
		defer client.Close()
		if err := client.BindSCRAM256(context.Background(), "alice", "secret"); !errors.Is(err, ErrSCRAM) {
			t.Fatalf("error = %v", err)
		}
	})
}

// TestSCRAMValidation verifies local SCRAM option validation. | TestSCRAMValidation
// 校验 SCRAM 选项的本地验证。
func TestSCRAMValidation(t *testing.T) {
	client := &Client{}
	cases := []struct {
		options SCRAMOptions
		match   error
	}{
		{options: SCRAMOptions{Password: "secret"}, match: ErrSCRAM},
		{options: SCRAMOptions{Username: "alice"}, match: ErrEmptyPassword},
		{options: SCRAMOptions{Username: "alice", Password: "secret", Mechanism: "SCRAM-MD5"}, match: ErrSCRAM},
		{options: SCRAMOptions{Username: "alice", Password: "secret", Mechanism: "SCRAM-SHA-256-PLUS"}, match: ErrSCRAM},
		{options: SCRAMOptions{Username: "a\x00b", Password: "secret"}, match: ErrSCRAM},
	}
	for _, test := range cases {
		if err := client.BindSCRAM(context.Background(), test.options); !errors.Is(err, test.match) {
			t.Fatalf("BindSCRAM(%+v) error = %v", test.options, err)
		}
	}
}

// TestSCRAMChannelBindingRequiresTLS verifies channel binding is rejected on
// plaintext connections. | TestSCRAMChannelBindingRequiresTLS 校验明文连接拒绝通道绑定。
func TestSCRAMChannelBindingRequiresTLS(t *testing.T) {
	server := startMockServer(t, func(session *mockSession, message *LDAPMessage) error {
		return nil
	})
	client, err := DialURL(context.Background(), server.URL())
	if err != nil {
		t.Fatalf("DialURL: %v", err)
	}
	defer client.Close()
	err = client.BindSCRAM(context.Background(), SCRAMOptions{
		Username:       "alice",
		Password:       "secret",
		ChannelBinding: true,
	})
	if !errors.Is(err, ErrTLSRequired) {
		t.Fatalf("error = %v", err)
	}
}

// TestSCRAMParameters verifies mechanism selection. | TestSCRAMParameters 校验机制选择。
func TestSCRAMParameters(t *testing.T) {
	tests := []struct {
		options   SCRAMOptions
		mechanism string
	}{
		{options: SCRAMOptions{}, mechanism: SASLMechanismSCRAMSHA256},
		{options: SCRAMOptions{Mechanism: "scram-sha-512"}, mechanism: SASLMechanismSCRAMSHA512},
		{options: SCRAMOptions{ChannelBinding: true}, mechanism: "SCRAM-SHA-256-PLUS"},
		{options: SCRAMOptions{Mechanism: "SCRAM-SHA-512-PLUS", ChannelBinding: true}, mechanism: "SCRAM-SHA-512-PLUS"},
	}
	for _, test := range tests {
		mechanism, newHash, size, err := scramParameters(test.options)
		if err != nil {
			t.Fatalf("scramParameters(%+v): %v", test.options, err)
		}
		if mechanism != test.mechanism || newHash == nil || size <= 0 {
			t.Fatalf("result = %q %T %d", mechanism, newHash, size)
		}
	}
	if _, _, _, err := scramParameters(SCRAMOptions{Mechanism: "SCRAM-SHA-1"}); !errors.Is(err, ErrSCRAM) {
		t.Fatalf("unsupported mechanism error = %v", err)
	}
}

// TestParseSCRAMServerFirst verifies server-first parsing. | TestParseSCRAMServerFirst
// 校验 server-first 解析。
func TestParseSCRAMServerFirst(t *testing.T) {
	valid := "r=clientSERVER,s=" + ydbase64.StdEncoding.EncodeToString([]byte("salt")) + ",i=4096"
	nonce, salt, iterations, err := parseSCRAMServerFirst(valid, "client")
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	if nonce != "clientSERVER" || string(salt) != "salt" || iterations != 4096 {
		t.Fatalf("parsed = %q %q %d", nonce, salt, iterations)
	}
	invalid := []struct {
		message string
		nonce   string
	}{
		{message: "r=clientSERVER,s=c2FsdA==,i=4096,m=ext", nonce: "client"},
		{message: "r=other,s=c2FsdA==,i=4096", nonce: "client"},
		{message: "r=client,s=c2FsdA==,i=4096", nonce: "client"},
		{message: "r=clientSERVER,s=,i=4096", nonce: "client"},
		{message: "r=clientSERVER,s=***,i=4096", nonce: "client"},
		{message: "r=clientSERVER,s=c2FsdA==,i=0", nonce: "client"},
		{message: "r=clientSERVER,s=c2FsdA==,i=abc", nonce: "client"},
		{message: "r=clientSERVER,s=c2FsdA==,i=10000001", nonce: "client"},
		{message: "malformed", nonce: "client"},
	}
	for _, test := range invalid {
		if _, _, _, err := parseSCRAMServerFirst(test.message, test.nonce); !errors.Is(err, ErrSCRAM) {
			t.Fatalf("parseSCRAMServerFirst(%q) error = %v", test.message, err)
		}
	}
}

// TestParseSCRAMServerFinal verifies server-final parsing. | TestParseSCRAMServerFinal
// 校验 server-final 解析。
func TestParseSCRAMServerFinal(t *testing.T) {
	signature, err := parseSCRAMServerFinal("v=" + ydbase64.StdEncoding.EncodeToString([]byte("sig")) + ",ignored=1")
	if err != nil || string(signature) != "sig" {
		t.Fatalf("parse = %q, %v", signature, err)
	}
	invalid := []string{
		"",
		"e=invalid-proof",
		"v=***",
		"x=abc",
	}
	for _, message := range invalid {
		if _, err := parseSCRAMServerFinal(message); err == nil {
			t.Fatalf("parseSCRAMServerFinal(%q) succeeded", message)
		}
	}
}

// TestTLSServerEndPoint verifies RFC 5929 certificate hashing. | TestTLSServerEndPoint
// 校验 RFC 5929 证书哈希。
func TestTLSServerEndPoint(t *testing.T) {
	certificate, _ := testCertificate(t)
	endpoint, err := tlsServerEndPoint(certificate.Leaf)
	if err != nil {
		t.Fatalf("tlsServerEndPoint: %v", err)
	}
	want := sha256.Sum256(certificate.Leaf.Raw)
	if !bytes.Equal(endpoint, want[:]) {
		t.Fatal("ECDSA SHA-256 endpoint mismatch")
	}
	cases := []struct {
		algorithm x509.SignatureAlgorithm
		want      func([]byte) []byte
	}{
		{algorithm: x509.SHA384WithRSA, want: func(data []byte) []byte { sum := sha512.Sum384(data); return sum[:] }},
		{algorithm: x509.SHA512WithRSA, want: func(data []byte) []byte { sum := sha512.Sum512(data); return sum[:] }},
		{algorithm: x509.MD5WithRSA, want: func(data []byte) []byte { sum := sha256.Sum256(data); return sum[:] }},
	}
	for _, test := range cases {
		certificate := &x509.Certificate{Raw: []byte("certificate"), SignatureAlgorithm: test.algorithm}
		got, err := tlsServerEndPoint(certificate)
		if err != nil {
			t.Fatalf("algorithm %v: %v", test.algorithm, err)
		}
		if !bytes.Equal(got, test.want(certificate.Raw)) {
			t.Fatalf("algorithm %v mismatch", test.algorithm)
		}
	}
	if _, err := tlsServerEndPoint(nil); !errors.Is(err, ErrSASL) {
		t.Fatalf("nil certificate error = %v", err)
	}
	if _, err := tlsServerEndPoint(&x509.Certificate{}); !errors.Is(err, ErrSASL) {
		t.Fatalf("empty certificate error = %v", err)
	}
}

// TestEscapeSCRAMName verifies SCRAM name escaping. | TestEscapeSCRAMName 校验 SCRAM 名称转义。
func TestEscapeSCRAMName(t *testing.T) {
	tests := []struct {
		input string
		want  string
	}{
		{input: "alice", want: "alice"},
		{input: "a=b", want: "a=3Db"},
		{input: "a,b", want: "a=2Cb"},
		{input: "a=,b", want: "a=3D=2Cb"},
	}
	for _, test := range tests {
		if got := escapeSCRAMName(test.input); got != test.want {
			t.Fatalf("escapeSCRAMName(%q) = %q", test.input, got)
		}
	}
}

// TestPBKDF2Key verifies password key derivation. | TestPBKDF2Key 校验口令密钥派生。
func TestPBKDF2Key(t *testing.T) {
	key, err := pbkdf2Key(sha256.New, "password", []byte("salt"), 2, sha256.Size)
	if err != nil {
		t.Fatalf("pbkdf2Key: %v", err)
	}
	if len(key) != sha256.Size {
		t.Fatalf("key length = %d", len(key))
	}
	second, err := pbkdf2Key(sha256.New, "password", []byte("salt"), 2, sha256.Size)
	if err != nil || !hmac.Equal(key, second) {
		t.Fatalf("derivation is not deterministic: %v", err)
	}
}

// TestSCRAMServerFirstNonceReuse ensures the server nonce must extend the client
// nonce. | TestSCRAMServerFirstNonceReuse 确保服务端随机数必须扩展客户端随机数。
func TestSCRAMServerFirstNonceReuse(t *testing.T) {
	if _, _, _, err := parseSCRAMServerFirst("r=abc,s=c2FsdA==,i=1", "abc"); !errors.Is(err, ErrSCRAM) {
		t.Fatalf("error = %v", err)
	}
	if _, _, _, err := parseSCRAMServerFirst("r=abcd,s=c2FsdA==,i=1", "abc"); err != nil {
		t.Fatalf("valid prefix error = %v", err)
	}
}

// TestSCRAMIterationCeiling verifies the iteration upper bound. | TestSCRAMIterationCeiling
// 校验迭代次数上限。
func TestSCRAMIterationCeiling(t *testing.T) {
	message := "r=clientSERVER,s=c2FsdA==,i=" + strconv.Itoa(10_000_000)
	if _, _, _, err := parseSCRAMServerFirst(message, "client"); err != nil {
		t.Fatalf("limit rejected: %v", err)
	}
	message = "r=clientSERVER,s=c2FsdA==,i=" + strconv.Itoa(10_000_001)
	if _, _, _, err := parseSCRAMServerFirst(message, "client"); !errors.Is(err, ErrSCRAM) {
		t.Fatalf("above limit error = %v", err)
	}
}
