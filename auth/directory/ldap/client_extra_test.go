package ldap

import (
	"bytes"
	"context"
	"crypto/tls"
	"errors"
	"net"
	"sync"
	"testing"
	"time"
)

// TestClientURLAccessor verifies the endpoint accessor including nil receivers. |
// TestClientURLAccessor 校验端点访问器，包括空接收者。
func TestClientURLAccessor(t *testing.T) {
	var nilClient *Client
	if got := nilClient.URL(); got != "" {
		t.Fatalf("nil URL = %q", got)
	}
	server := startMockServer(t, func(session *mockSession, message *LDAPMessage) error {
		return session.writeSimpleResult(message.MessageID, &SearchResultDone{Result: LDAPResult{Code: ResultSuccess}})
	})
	client, err := DialURL(context.Background(), server.URL())
	if err != nil {
		t.Fatalf("DialURL: %v", err)
	}
	defer client.Close()
	if got := client.URL(); got != server.URL() {
		t.Fatalf("URL = %q, want %q", got, server.URL())
	}
}

// TestClientBindAnonymous verifies anonymous binds send an empty simple bind. |
// TestClientBindAnonymous 校验匿名绑定发送空的简单绑定。
func TestClientBindAnonymous(t *testing.T) {
	var (
		mu    sync.Mutex
		binds int
	)
	server := startMockServer(t, func(session *mockSession, message *LDAPMessage) error {
		request, ok := message.Op.(*BindRequest)
		if !ok {
			return errors.New("expected bind")
		}
		auth, ok := request.Authentication.(SimpleAuthentication)
		if request.Version != 3 || request.DN != "" || !ok || auth.Password != "" {
			return errors.New("anonymous bind carried credentials")
		}
		mu.Lock()
		binds++
		mu.Unlock()
		return session.writeSimpleResult(message.MessageID, &BindResponse{Result: LDAPResult{Code: ResultSuccess}})
	})
	client, err := DialURL(context.Background(), server.URL())
	if err != nil {
		t.Fatalf("DialURL: %v", err)
	}
	defer client.Close()
	if err := client.BindAnonymous(context.Background()); err != nil {
		t.Fatalf("BindAnonymous: %v", err)
	}
	if err := client.BindAnonymous(nil); err != nil {
		t.Fatalf("BindAnonymous nil context: %v", err)
	}
	if client.auth != nil {
		t.Fatalf("anonymous bind retained auth state: %+v", client.auth)
	}
	mu.Lock()
	defer mu.Unlock()
	if binds != 2 {
		t.Fatalf("binds = %d", binds)
	}
}

// TestClientAddAndSearchEntries verifies the Add helper and entry-only search. |
// TestClientAddAndSearchEntries 校验 Add 辅助方法与仅返回条目的搜索。
func TestClientAddAndSearchEntries(t *testing.T) {
	server := startMockServer(t, func(session *mockSession, message *LDAPMessage) error {
		switch request := message.Op.(type) {
		case *AddRequest:
			if request.DN == "cn=dup,dc=example,dc=com" {
				return session.writeSimpleResult(message.MessageID, &AddResponse{
					Result: LDAPResult{Code: ResultEntryAlreadyExists},
				})
			}
			if request.DN != "cn=new,dc=example,dc=com" || len(request.Attributes) != 1 ||
				request.Attributes[0].Type != "cn" {
				return errors.New("unexpected add request")
			}
			return session.writeSimpleResult(message.MessageID, &AddResponse{Result: LDAPResult{Code: ResultSuccess}})
		case *SearchRequest:
			if err := session.writeEntry(message.MessageID, "cn=new,dc=example,dc=com",
				Attribute{Type: "cn", Values: []string{"new"}}); err != nil {
				return err
			}
			return session.writeSearchDone(message.MessageID, LDAPResult{Code: ResultSuccess})
		default:
			return errors.New("unexpected operation")
		}
	})
	client, err := DialURL(context.Background(), server.URL())
	if err != nil {
		t.Fatalf("DialURL: %v", err)
	}
	defer client.Close()
	attributes := []Attribute{{Type: "cn", Values: []string{"new"}}}
	if err := client.Add(context.Background(), "cn=new,dc=example,dc=com", attributes); err != nil {
		t.Fatalf("Add: %v", err)
	}
	if err := client.Add(context.Background(), "cn=dup,dc=example,dc=com", attributes); !errors.Is(err, ErrEntryAlreadyExists) {
		t.Fatalf("duplicate Add error = %v", err)
	}
	entries, err := client.SearchEntries(context.Background(), SearchOptions{Filter: Present("objectClass")})
	if err != nil || len(entries) != 1 || entries[0].DN != "cn=new,dc=example,dc=com" {
		t.Fatalf("SearchEntries = %+v, %v", entries, err)
	}
	entries, err = client.SearchEntries(context.Background(), SearchOptions{Scope: Scope(9), Filter: Present("objectClass")})
	if entries != nil || !errors.Is(err, ErrInvalidMessage) {
		t.Fatalf("invalid scope SearchEntries = %v, %v", entries, err)
	}
}

// TestConnHelpers verifies deadline clearing and nil-safe transport helpers. |
// TestConnHelpers 校验期限清除与空安全的传输辅助方法。
func TestConnHelpers(t *testing.T) {
	left, right := net.Pipe()
	defer func() { _ = left.Close() }()
	defer func() { _ = right.Close() }()
	connection := newConn(left, false, tls.ConnectionState{}, 0)
	if connection.maxSize != DefaultMaxMessageSize {
		t.Fatalf("maxSize = %d", connection.maxSize)
	}
	if err := connection.setDeadline(context.Background(), time.Second); err != nil {
		t.Fatalf("setDeadline: %v", err)
	}
	if err := connection.clearDeadline(); err != nil {
		t.Fatalf("clearDeadline: %v", err)
	}
	if err := connection.close(); err != nil {
		t.Fatalf("close: %v", err)
	}
	var nilConn *conn
	if err := nilConn.close(); err != nil {
		t.Fatalf("nil close: %v", err)
	}
	if err := (&conn{}).close(); err != nil {
		t.Fatalf("empty close: %v", err)
	}
}

// TestStartTLSFromConfig verifies Config.StartTLS upgrades the initial connection. |
// TestStartTLSFromConfig 校验 Config.StartTLS 在首次连接时执行升级。
func TestStartTLSFromConfig(t *testing.T) {
	t.Run("success", func(t *testing.T) {
		certificate, pool := testCertificate(t)
		server := startMockServer(t, func(session *mockSession, message *LDAPMessage) error {
			switch request := message.Op.(type) {
			case *ExtendedRequest:
				if request.Name != OIDStartTLS {
					return errors.New("unexpected extended request")
				}
				if err := session.writeSimpleResult(message.MessageID,
					&ExtendedResponse{Result: LDAPResult{Code: ResultSuccess}}); err != nil {
					return err
				}
				session.Upgrade(&tls.Config{Certificates: []tls.Certificate{certificate}, MinVersion: tls.VersionTLS12})
				return nil
			case *BindRequest:
				return session.writeSimpleResult(message.MessageID, &BindResponse{Result: LDAPResult{Code: ResultSuccess}})
			default:
				return errors.New("unexpected operation")
			}
		})
		client, err := DialURL(context.Background(), server.URL(),
			Config{StartTLS: true, TLSConfig: testTLSConfig(pool)})
		if err != nil {
			t.Fatalf("DialURL: %v", err)
		}
		defer client.Close()
		if state, secure := client.TLSConnectionState(); !secure || len(state.PeerCertificates) == 0 {
			t.Fatalf("TLS state = %+v, secure = %t", state, secure)
		}
		if err := client.Bind(context.Background(), "cn=user", "password"); err != nil {
			t.Fatalf("Bind after config StartTLS: %v", err)
		}
	})
	t.Run("extended result failure", func(t *testing.T) {
		server := startMockServer(t, func(session *mockSession, message *LDAPMessage) error {
			return session.writeSimpleResult(message.MessageID,
				&ExtendedResponse{Result: LDAPResult{Code: ResultUnavailable, DiagnosticMessage: "maintenance"}})
		})
		_, err := DialURL(context.Background(), server.URL(), Config{StartTLS: true, TLSConfig: &tls.Config{MinVersion: tls.VersionTLS12}})
		if !errors.Is(err, ErrUnavailable) {
			t.Fatalf("StartTLS failure = %v", err)
		}
	})
	t.Run("wrong response type", func(t *testing.T) {
		server := startMockServer(t, func(session *mockSession, message *LDAPMessage) error {
			return session.writeSimpleResult(message.MessageID, &BindResponse{Result: LDAPResult{Code: ResultSuccess}})
		})
		_, err := DialURL(context.Background(), server.URL(), Config{StartTLS: true, TLSConfig: &tls.Config{MinVersion: tls.VersionTLS12}})
		if !errors.Is(err, ErrUnexpectedResponse) {
			t.Fatalf("wrong StartTLS response = %v", err)
		}
	})
	t.Run("buffered plaintext injection", func(t *testing.T) {
		server := startMockServer(t, func(session *mockSession, message *LDAPMessage) error {
			data, err := encodeLDAPMessage(&LDAPMessage{MessageID: message.MessageID,
				Op: &ExtendedResponse{Result: LDAPResult{Code: ResultSuccess}}})
			if err != nil {
				return err
			}
			_, err = session.conn.Write(append(data, []byte("GET / HTTP/1.1\r\n\r\n")...))
			return err
		})
		_, err := DialURL(context.Background(), server.URL(), Config{StartTLS: true, TLSConfig: &tls.Config{MinVersion: tls.VersionTLS12}})
		if !errors.Is(err, ErrProtocolError) || !errors.Is(err, ErrNetwork) {
			t.Fatalf("buffered plaintext StartTLS = %v", err)
		}
	})
	t.Run("nil transport", func(t *testing.T) {
		empty := &Client{}
		if err := empty.startTLSLockedWith(context.Background(), empty.cfg); !errors.Is(err, ErrClosed) {
			t.Fatalf("nil transport StartTLS = %v", err)
		}
	})
}

// TestClientReconnectReplaysSASLPlain verifies PLAIN credentials are replayed on
// reconnect. | TestClientReconnectReplaysSASLPlain 校验重连时重放 PLAIN 凭据。
func TestClientReconnectReplaysSASLPlain(t *testing.T) {
	var (
		mu         sync.Mutex
		binds      int
		searches   int
		expected   = []byte("\x00alice\x00secret")
		sawWrongCB bool
	)
	server := startMockServer(t, func(session *mockSession, message *LDAPMessage) error {
		switch request := message.Op.(type) {
		case *BindRequest:
			auth, ok := request.Authentication.(SASLAuthentication)
			if !ok || auth.Mechanism != SASLMechanismPlain {
				return errors.New("expected PLAIN bind")
			}
			if !bytes.Equal(auth.Credentials, expected) {
				mu.Lock()
				sawWrongCB = true
				mu.Unlock()
			}
			mu.Lock()
			binds++
			mu.Unlock()
			return session.writeSimpleResult(message.MessageID, &BindResponse{Result: LDAPResult{Code: ResultSuccess}})
		case *SearchRequest:
			mu.Lock()
			searches++
			count := searches
			mu.Unlock()
			if count == 1 {
				return errCloseMockConn
			}
			if err := session.writeEntry(message.MessageID, "cn=recovered", Attribute{Type: "cn", Values: []string{"recovered"}}); err != nil {
				return err
			}
			return session.writeSearchDone(message.MessageID, LDAPResult{Code: ResultSuccess})
		default:
			return errors.New("unexpected operation")
		}
	})
	client, err := DialURL(context.Background(), server.URL())
	if err != nil {
		t.Fatalf("DialURL: %v", err)
	}
	defer client.Close()
	if err := client.BindSASLPlain(context.Background(), "alice", "secret"); err != nil {
		t.Fatalf("BindSASLPlain: %v", err)
	}
	if _, err := client.Search(context.Background(), SearchOptions{Filter: Present("objectClass")}); err == nil {
		t.Fatal("first search unexpectedly succeeded")
	}
	result, err := client.Search(context.Background(), SearchOptions{Filter: Present("objectClass")})
	if err != nil || len(result.Entries) != 1 || result.Entries[0].DN != "cn=recovered" {
		t.Fatalf("second search = %+v, %v", result, err)
	}
	mu.Lock()
	defer mu.Unlock()
	if binds != 2 || searches != 2 || sawWrongCB {
		t.Fatalf("binds = %d searches = %d wrong credentials = %t", binds, searches, sawWrongCB)
	}
}

// TestClientReconnectReplaysSASLExternal verifies EXTERNAL is replayed over TLS. |
// TestClientReconnectReplaysSASLExternal 校验 TLS 上重放 EXTERNAL。
func TestClientReconnectReplaysSASLExternal(t *testing.T) {
	certificate, pool := testCertificate(t)
	var (
		mu       sync.Mutex
		binds    int
		searches int
	)
	server := startMockServerTLS(t, &tls.Config{Certificates: []tls.Certificate{certificate}, MinVersion: tls.VersionTLS12},
		func(session *mockSession, message *LDAPMessage) error {
			switch request := message.Op.(type) {
			case *BindRequest:
				auth, ok := request.Authentication.(SASLAuthentication)
				if !ok || auth.Mechanism != SASLMechanismExternal || string(auth.Credentials) != "dn:cn=admin" {
					return errors.New("unexpected EXTERNAL bind")
				}
				mu.Lock()
				binds++
				mu.Unlock()
				return session.writeSimpleResult(message.MessageID, &BindResponse{Result: LDAPResult{Code: ResultSuccess}})
			case *SearchRequest:
				mu.Lock()
				searches++
				count := searches
				mu.Unlock()
				if count == 1 {
					return errCloseMockConn
				}
				if err := session.writeEntry(message.MessageID, "cn=recovered"); err != nil {
					return err
				}
				return session.writeSearchDone(message.MessageID, LDAPResult{Code: ResultSuccess})
			default:
				return errors.New("unexpected operation")
			}
		})
	client, err := DialURL(context.Background(), server.URL(), Config{TLSConfig: testTLSConfig(pool)})
	if err != nil {
		t.Fatalf("DialURL: %v", err)
	}
	defer client.Close()
	if err := client.BindSASLExternal(context.Background(), "dn:cn=admin"); err != nil {
		t.Fatalf("BindSASLExternal: %v", err)
	}
	if _, err := client.Search(context.Background(), SearchOptions{Filter: Present("objectClass")}); err == nil {
		t.Fatal("first search unexpectedly succeeded")
	}
	result, err := client.Search(context.Background(), SearchOptions{Filter: Present("objectClass")})
	if err != nil || len(result.Entries) != 1 || result.Entries[0].DN != "cn=recovered" {
		t.Fatalf("second search = %+v, %v", result, err)
	}
	mu.Lock()
	defer mu.Unlock()
	if binds != 2 || searches != 2 {
		t.Fatalf("binds = %d searches = %d", binds, searches)
	}
}

// TestClientReplayUnknownAuthKind verifies corrupted replay state fails closed. |
// TestClientReplayUnknownAuthKind 校验损坏的重放状态安全失败。
func TestClientReplayUnknownAuthKind(t *testing.T) {
	server := startMockServer(t, func(session *mockSession, message *LDAPMessage) error {
		if _, ok := message.Op.(*SearchRequest); !ok {
			return errors.New("unexpected operation during replay")
		}
		return session.writeSearchDone(message.MessageID, LDAPResult{Code: ResultSuccess})
	})
	client, err := DialURL(context.Background(), server.URL())
	if err != nil {
		t.Fatalf("DialURL: %v", err)
	}
	defer client.Close()
	client.mu.Lock()
	client.auth = &authState{kind: authKind(200)}
	client.invalidateConnLocked()
	client.mu.Unlock()
	if _, err := client.Search(context.Background(), SearchOptions{Filter: Present("objectClass")}); !errors.Is(err, ErrInvalidConfig) {
		t.Fatalf("unknown replay kind = %v", err)
	}
	if !client.IsClosed() && client.conn != nil {
		t.Fatal("failed replay left a live connection")
	}
}
