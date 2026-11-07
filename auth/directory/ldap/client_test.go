package ldap

import (
	"context"
	"crypto/tls"
	"errors"
	"net"
	"reflect"
	"strings"
	"sync"
	"testing"
	"time"
)

// TestDialConfiguration verifies URL and config validation before I/O. |
// TestDialConfiguration 校验 I/O 前的地址与配置校验。
func TestDialConfiguration(t *testing.T) {
	invalidURLs := []string{
		"",
		"http://example.com",
		"ldap://",
		"ldap://user:pass@example.com",
		"ldap://example.com/dc=example",
		"ldap://example.com?x",
		"ldap://example.com#fragment",
		"ldap://example.com:0",
		"ldap://example.com:70000",
	}
	for _, raw := range invalidURLs {
		if _, err := Dial(context.Background(), Config{URL: raw}); !errors.Is(err, ErrInvalidURL) {
			t.Fatalf("Dial(%q) error = %v", raw, err)
		}
	}
	invalidConfigs := []Config{
		{URL: "ldaps://example.com", StartTLS: true},
		{URL: "ldap://example.com", BindDN: "cn=admin"},
		{URL: "ldap://example.com", BindPassword: "secret"},
		{URL: "ldap://example.com", Timeout: -1},
		{URL: "ldap://example.com", DialTimeout: -1},
		{URL: "ldap://example.com", PoolSize: -1},
		{URL: "ldap://example.com", MaxIdle: -1},
		{URL: "ldap://example.com", MaxIdleTime: -1},
		{URL: "ldap://example.com", MaxMessageSize: -1},
		{URL: "ldap://example.com", MaxMessageSize: 1<<30 + 1},
	}
	for _, cfg := range invalidConfigs {
		if _, err := Dial(context.Background(), cfg); !errors.Is(err, ErrInvalidConfig) {
			t.Fatalf("Dial(%+v) error = %v", cfg, err)
		}
	}
	if _, err := DialURL(context.Background(), "ldap://example.com", Config{}, Config{}); !errors.Is(err, ErrInvalidConfig) {
		t.Fatalf("DialURL multiple configs error = %v", err)
	}
	goodEndpoints := []struct {
		raw    string
		addr   string
		secure bool
	}{
		{raw: "ldap://example.com", addr: "example.com:389"},
		{raw: "ldaps://example.com", addr: "example.com:636", secure: true},
		{raw: "ldap://example.com:1389", addr: "example.com:1389"},
		{raw: "ldap://[::1]:389", addr: "[::1]:389"},
	}
	for _, test := range goodEndpoints {
		endpoint, err := parseEndpoint(test.raw)
		if err != nil {
			t.Fatalf("parseEndpoint(%q): %v", test.raw, err)
		}
		if endpoint.address != test.addr || endpoint.secure != test.secure {
			t.Fatalf("endpoint %q = %+v", test.raw, endpoint)
		}
	}
	if _, err := DialURL(context.Background(), "ldap://127.0.0.1:1", Config{Timeout: time.Millisecond, DialTimeout: time.Millisecond}); err == nil {
		t.Fatal("expected connection failure")
	}
}

// TestClientBindAndSearch verifies bind and search exchange including references,
// intermediates and controls. | TestClientBindAndSearch 校验绑定与搜索交换，包括转介、
// 中间响应与控件。
func TestClientBindAndSearch(t *testing.T) {
	server := startMockServer(t, func(session *mockSession, message *LDAPMessage) error {
		switch request := message.Op.(type) {
		case *BindRequest:
			auth, ok := request.Authentication.(SimpleAuthentication)
			if !ok {
				return errors.New("expected simple authentication")
			}
			code := ResultSuccess
			if request.DN != "cn=admin,dc=example,dc=com" || auth.Password != "secret" {
				code = ResultInvalidCredentials
			}
			return session.writeSimpleResult(message.MessageID, &BindResponse{Result: LDAPResult{Code: code}})
		case *SearchRequest:
			if request.BaseDN != "dc=example,dc=com" || request.Scope != ScopeWholeSubtree {
				t.Errorf("search base/scope = %q/%d", request.BaseDN, request.Scope)
			}
			if !reflect.DeepEqual(request.Attributes, []string{"dn", "cn", "mail"}) {
				t.Errorf("search attributes = %v", request.Attributes)
			}
			wantFilter := "(&(objectClass=person)(uid=alice))"
			if request.Filter.String() != wantFilter {
				t.Errorf("search filter = %s, want %s", request.Filter, wantFilter)
			}
			if err := session.writeEntry(message.MessageID, "uid=alice,dc=example,dc=com",
				Attribute{Type: "uid", Values: []string{"alice"}},
				Attribute{Type: "mail", Values: []string{"alice@example.com"}},
			); err != nil {
				return err
			}
			if err := session.Write(&LDAPMessage{MessageID: message.MessageID, Op: &IntermediateResponse{Name: "1.2.3", Value: []byte("working")}}); err != nil {
				return err
			}
			if err := session.writeSearchReference(message.MessageID, "ldap://ref.example.com/dc=example"); err != nil {
				return err
			}
			if err := session.writeEntry(message.MessageID, "uid=bob,dc=example,dc=com", Attribute{Type: "uid", Values: []string{"bob"}}); err != nil {
				return err
			}
			return session.writeSearchDone(message.MessageID,
				LDAPResult{Code: ResultSuccess, Referrals: []string{"ldap://result.example.com/dc=example"}},
				Control{Type: OIDManageDsaIT, Criticality: true},
			)
		default:
			return errors.New("unexpected operation")
		}
	})
	client, err := DialURL(context.Background(), server.URL())
	if err != nil {
		t.Fatalf("DialURL: %v", err)
	}
	defer client.Close()
	if err := client.Bind(context.Background(), "cn=admin,dc=example,dc=com", "secret"); err != nil {
		t.Fatalf("Bind: %v", err)
	}
	var referrals []string
	result, err := client.Search(context.Background(), SearchOptions{
		BaseDN:     "dc=example,dc=com",
		Scope:      ScopeWholeSubtree,
		Filter:     And(Equal("objectClass", "person"), Equal("uid", "alice")),
		Attributes: []string{"dn", "cn", "mail"},
		OnReferral: func(ctx context.Context, urls []string) error {
			referrals = append(referrals, urls...)
			return nil
		},
	})
	if err != nil {
		t.Fatalf("Search: %v", err)
	}
	if len(result.Entries) != 2 {
		t.Fatalf("entries = %d", len(result.Entries))
	}
	if result.Entries[0].First("uid") != "alice" || result.Entries[1].First("uid") != "bob" {
		t.Fatalf("entries = %+v", result.Entries)
	}
	if len(result.Intermediates) != 1 || result.Intermediates[0].Name != "1.2.3" {
		t.Fatalf("intermediates = %+v", result.Intermediates)
	}
	if !reflect.DeepEqual(result.Referrals, []string{"ldap://ref.example.com/dc=example", "ldap://result.example.com/dc=example"}) {
		t.Fatalf("referrals = %v", result.Referrals)
	}
	if !reflect.DeepEqual(referrals, result.Referrals) {
		t.Fatalf("handler referrals = %v", referrals)
	}
	if len(result.Controls) != 1 || result.Controls[0].Type != OIDManageDsaIT {
		t.Fatalf("controls = %+v", result.Controls)
	}
	if result.Result.Code != ResultSuccess {
		t.Fatalf("result = %+v", result.Result)
	}
}

// TestClientAutoBind verifies config-driven bind and failure handling. | TestClientAutoBind
// 校验配置驱动绑定与失败处理。
func TestClientAutoBind(t *testing.T) {
	var (
		mu    sync.Mutex
		binds int
	)
	server := startMockServer(t, func(session *mockSession, message *LDAPMessage) error {
		request, ok := message.Op.(*BindRequest)
		if !ok {
			return errors.New("expected bind")
		}
		mu.Lock()
		binds++
		mu.Unlock()
		auth := request.Authentication.(SimpleAuthentication)
		code := ResultSuccess
		if request.DN != "cn=service" || auth.Password != "good" {
			code = ResultInvalidCredentials
		}
		return session.writeSimpleResult(message.MessageID, &BindResponse{Result: LDAPResult{Code: code}})
	})
	client, err := Dial(context.Background(), Config{
		URL:          server.URL(),
		BindDN:       "cn=service",
		BindPassword: "good",
	})
	if err != nil {
		t.Fatalf("Dial: %v", err)
	}
	_ = client.Close()
	mu.Lock()
	count := binds
	mu.Unlock()
	if count != 1 {
		t.Fatalf("binds = %d", count)
	}
	if _, err := Dial(context.Background(), Config{
		URL:          server.URL(),
		BindDN:       "cn=service",
		BindPassword: "bad",
	}); !errors.Is(err, ErrInvalidCredentials) {
		t.Fatalf("wrong password error = %v", err)
	}
}

// TestClientLocalPasswordChecks verifies empty passwords never reach the wire. |
// TestClientLocalPasswordChecks 校验空口令绝不会进入网络。
func TestClientLocalPasswordChecks(t *testing.T) {
	client := &Client{}
	if err := client.Bind(context.Background(), "cn=user", ""); !errors.Is(err, ErrEmptyPassword) {
		t.Fatalf("Bind error = %v", err)
	}
	if err := client.BindSASLPlain(context.Background(), "user", ""); !errors.Is(err, ErrEmptyPassword) {
		t.Fatalf("BindSASLPlain error = %v", err)
	}
	if err := client.BindSCRAM(context.Background(), SCRAMOptions{Username: "user"}); !errors.Is(err, ErrEmptyPassword) {
		t.Fatalf("BindSCRAM error = %v", err)
	}
	if err := client.BindSASLPlain(context.Background(), "", "password"); !errors.Is(err, ErrSASL) {
		t.Fatalf("plain empty username error = %v", err)
	}
}

// TestClientSearchPaging verifies automatic RFC 2696 paging and sorting. |
// TestClientSearchPaging 校验自动 RFC 2696 分页与排序。
func TestClientSearchPaging(t *testing.T) {
	t.Run("success", func(t *testing.T) {
		var (
			mu      sync.Mutex
			cookies [][]byte
			sizes   []int
			sorts   int
		)
		server := startMockServer(t, func(session *mockSession, message *LDAPMessage) error {
			request, ok := message.Op.(*SearchRequest)
			if !ok {
				return errors.New("expected search")
			}
			_ = request
			control, ok := findControl(message.Controls, OIDPagedResults)
			if !ok {
				return errors.New("missing paged control")
			}
			size, cookie, err := ParsePagedResultsControl(control)
			if err != nil {
				return err
			}
			mu.Lock()
			cookies = append(cookies, append([]byte(nil), cookie...))
			sizes = append(sizes, size)
			if _, ok := findControl(message.Controls, OIDSortRequest); ok {
				sorts++
			}
			page := len(cookies)
			mu.Unlock()
			switch page {
			case 1:
				if err := session.writeEntry(message.MessageID, "cn=page1", Attribute{Type: "cn", Values: []string{"page1"}}); err != nil {
					return err
				}
				return session.writeSearchDone(message.MessageID, LDAPResult{Code: ResultSuccess}, PagedResultsControl(2, []byte("page2")))
			case 2:
				if err := session.writeEntry(message.MessageID, "cn=page2", Attribute{Type: "cn", Values: []string{"page2"}}); err != nil {
					return err
				}
				return session.writeSearchDone(message.MessageID, LDAPResult{Code: ResultSuccess}, PagedResultsControl(2, nil))
			default:
				return errors.New("too many pages")
			}
		})
		client, err := DialURL(context.Background(), server.URL())
		if err != nil {
			t.Fatalf("DialURL: %v", err)
		}
		defer client.Close()
		result, err := client.Search(context.Background(), SearchOptions{
			BaseDN:   "dc=example,dc=com",
			Scope:    ScopeWholeSubtree,
			Filter:   Present("objectClass"),
			PageSize: 2,
			SortKeys: []SortKey{{Attribute: "cn"}},
		})
		if err != nil {
			t.Fatalf("Search: %v", err)
		}
		if len(result.Entries) != 2 || result.Entries[0].DN != "cn=page1" || result.Entries[1].DN != "cn=page2" {
			t.Fatalf("entries = %+v", result.Entries)
		}
		mu.Lock()
		defer mu.Unlock()
		if len(cookies) != 2 || len(cookies[0]) != 0 || string(cookies[1]) != "page2" {
			t.Fatalf("cookies = %q", cookies)
		}
		if !reflect.DeepEqual(sizes, []int{2, 2}) || sorts != 2 {
			t.Fatalf("sizes = %v sorts = %d", sizes, sorts)
		}
	})
	t.Run("unsupported", func(t *testing.T) {
		server := startMockServer(t, func(session *mockSession, message *LDAPMessage) error {
			if err := session.writeEntry(message.MessageID, "cn=x", Attribute{Type: "cn", Values: []string{"x"}}); err != nil {
				return err
			}
			return session.writeSearchDone(message.MessageID, LDAPResult{Code: ResultSuccess})
		})
		client, err := DialURL(context.Background(), server.URL())
		if err != nil {
			t.Fatalf("DialURL: %v", err)
		}
		defer client.Close()
		result, err := client.Search(context.Background(), SearchOptions{
			Filter: Present("objectClass"), PageSize: 1,
		})
		if !errors.Is(err, ErrPagingUnsupported) {
			t.Fatalf("error = %v", err)
		}
		if result == nil || len(result.Entries) != 1 {
			t.Fatalf("result = %+v", result)
		}
	})
	t.Run("loop", func(t *testing.T) {
		var requests int
		server := startMockServer(t, func(session *mockSession, message *LDAPMessage) error {
			requests++
			return session.writeSearchDone(message.MessageID, LDAPResult{Code: ResultSuccess}, PagedResultsControl(1, []byte("same")))
		})
		client, err := DialURL(context.Background(), server.URL())
		if err != nil {
			t.Fatalf("DialURL: %v", err)
		}
		defer client.Close()
		if _, err := client.Search(context.Background(), SearchOptions{Filter: Present("objectClass"), PageSize: 1}); !errors.Is(err, ErrPagingLoop) {
			t.Fatalf("error = %v", err)
		}
		if requests != 2 {
			t.Fatalf("requests = %d", requests)
		}
	})
	t.Run("cookie cycle", func(t *testing.T) {
		var requests int
		server := startMockServer(t, func(session *mockSession, message *LDAPMessage) error {
			requests++
			// A -> B -> A must be detected even when consecutive cookies differ.
			// | 即使相邻 Cookie 不同，也必须检测到 A -> B -> A 的循环。
			cookies := [][]byte{[]byte("a"), []byte("b"), []byte("a")}
			index := requests - 1
			if index >= len(cookies) {
				index = len(cookies) - 1
			}
			return session.writeSearchDone(message.MessageID, LDAPResult{Code: ResultSuccess}, PagedResultsControl(1, cookies[index]))
		})
		client, err := DialURL(context.Background(), server.URL())
		if err != nil {
			t.Fatalf("DialURL: %v", err)
		}
		defer client.Close()
		if _, err := client.Search(context.Background(), SearchOptions{Filter: Present("objectClass"), PageSize: 1}); !errors.Is(err, ErrPagingLoop) {
			t.Fatalf("error = %v", err)
		}
		if requests != 3 {
			t.Fatalf("requests = %d, want 3", requests)
		}
	})
	t.Run("page limit", func(t *testing.T) {
		var requests int
		server := startMockServer(t, func(session *mockSession, message *LDAPMessage) error {
			requests++
			return session.writeSearchDone(message.MessageID, LDAPResult{Code: ResultSuccess}, PagedResultsControl(1, []byte{byte(requests)}))
		})
		client, err := DialURL(context.Background(), server.URL())
		if err != nil {
			t.Fatalf("DialURL: %v", err)
		}
		defer client.Close()
		_, err = client.Search(context.Background(), SearchOptions{Filter: Present("objectClass"), PageSize: 1, MaxPages: 2})
		if !errors.Is(err, ErrPagingLimit) {
			t.Fatalf("error = %v", err)
		}
		if requests != 2 {
			t.Fatalf("requests = %d, want 2", requests)
		}
	})
	t.Run("negative page limit", func(t *testing.T) {
		server := startMockServer(t, func(session *mockSession, message *LDAPMessage) error {
			return errors.New("no request expected")
		})
		client, err := DialURL(context.Background(), server.URL())
		if err != nil {
			t.Fatalf("DialURL: %v", err)
		}
		defer client.Close()
		if _, err := client.Search(context.Background(), SearchOptions{Filter: Present("objectClass"), PageSize: 1, MaxPages: -1}); !errors.Is(err, ErrInvalidMessage) {
			t.Fatalf("error = %v", err)
		}
	})
}

// TestClientCRUD verifies every write and extended operation. | TestClientCRUD
// 校验全部写操作与扩展操作。
func TestClientCRUD(t *testing.T) {
	server := startMockServer(t, func(session *mockSession, message *LDAPMessage) error {
		switch request := message.Op.(type) {
		case *AddRequest:
			if request.DN != "cn=new,dc=example,dc=com" || len(request.Attributes) != 2 {
				return errors.New("unexpected add request")
			}
			return session.Write(&LDAPMessage{MessageID: message.MessageID,
				Op:       &AddResponse{Result: LDAPResult{Code: ResultSuccess}},
				Controls: []Control{{Type: "1.2.3", Value: []byte("post-read")}},
			})
		case *ModifyRequest:
			if request.DN != "cn=new,dc=example,dc=com" || len(request.Changes) != 2 || request.Changes[1].Operation != ModifyIncrement {
				return errors.New("unexpected modify request")
			}
			return session.writeSimpleResult(message.MessageID, &ModifyResponse{Result: LDAPResult{Code: ResultSuccess}})
		case *DeleteRequest:
			if request.DN != "cn=new,dc=example,dc=com" {
				return errors.New("unexpected delete request")
			}
			return session.writeSimpleResult(message.MessageID, &DeleteResponse{Result: LDAPResult{Code: ResultSuccess}})
		case *ModifyDNRequest:
			if request.NewRDN != "cn=renamed" || !request.DeleteOldRDN || request.NewSuperior != "ou=people" {
				return errors.New("unexpected modify DN request")
			}
			return session.writeSimpleResult(message.MessageID, &ModifyDNResponse{Result: LDAPResult{Code: ResultSuccess}})
		case *CompareRequest:
			code := ResultCompareTrue
			switch request.Value {
			case "no":
				code = ResultCompareFalse
			case "error":
				code = ResultNoSuchObject
			}
			return session.writeSimpleResult(message.MessageID, &CompareResponse{Result: LDAPResult{Code: code}})
		case *ExtendedRequest:
			switch request.Name {
			case OIDWhoAmI:
				return session.writeSimpleResult(message.MessageID, &ExtendedResponse{
					Result: LDAPResult{Code: ResultSuccess},
					Value:  []byte("dn:cn=admin"),
				})
			case OIDPasswordModify:
				if !strings.Contains(string(request.Value), "old-secret") || !strings.Contains(string(request.Value), "new-secret") {
					return errors.New("password modify request lacks credentials")
				}
				encoder := newBEREncoder(64)
				encoder.open(berClassUniversal, berTagSequence)
				encoder.primitive(berClassContext, 0, []byte("generated-secret"))
				encoder.close()
				return session.writeSimpleResult(message.MessageID, &ExtendedResponse{
					Result: LDAPResult{Code: ResultSuccess},
					Value:  encoder.bytes(),
				})
			case "1.2.3.fail":
				return session.writeSimpleResult(message.MessageID, &ExtendedResponse{Result: LDAPResult{Code: ResultUnwillingToPerform}})
			default:
				return session.writeSimpleResult(message.MessageID, &ExtendedResponse{Result: LDAPResult{Code: ResultProtocolError}})
			}
		default:
			return errors.New("unexpected operation")
		}
	})
	client, err := DialURL(context.Background(), server.URL())
	if err != nil {
		t.Fatalf("DialURL: %v", err)
	}
	defer client.Close()
	ctx := context.Background()
	attributes := []Attribute{
		{Type: "objectClass", Values: []string{"top", "person"}},
		{Type: "cn", Values: []string{"new"}},
	}
	added, err := client.AddWithResult(ctx, "cn=new,dc=example,dc=com", attributes)
	if err != nil {
		t.Fatalf("AddWithResult: %v", err)
	}
	if len(added.Controls) != 1 || added.Controls[0].Type != "1.2.3" {
		t.Fatalf("add controls = %+v", added.Controls)
	}
	if err := client.Modify(ctx, "cn=new,dc=example,dc=com", []ModifyChange{
		{Operation: ModifyReplace, Attribute: Attribute{Type: "cn", Values: []string{"new"}}},
		{Operation: ModifyIncrement, Attribute: Attribute{Type: "loginCount", Values: []string{"1"}}},
	}); err != nil {
		t.Fatalf("Modify: %v", err)
	}
	if err := client.Delete(ctx, "cn=new,dc=example,dc=com"); err != nil {
		t.Fatalf("Delete: %v", err)
	}
	if err := client.ModifyDN(ctx, "cn=new,dc=example,dc=com", "cn=renamed", true, "ou=people"); err != nil {
		t.Fatalf("ModifyDN: %v", err)
	}
	if value, err := client.Compare(ctx, "cn=x", "cn", "yes"); err != nil || !value {
		t.Fatalf("Compare true = %t, %v", value, err)
	}
	if value, err := client.Compare(ctx, "cn=x", "cn", "no"); err != nil || value {
		t.Fatalf("Compare false = %t, %v", value, err)
	}
	if _, err := client.Compare(ctx, "cn=x", "cn", "error"); !errors.Is(err, ErrNoSuchObject) {
		t.Fatalf("Compare error = %v", err)
	}
	identity, err := client.WhoAmI(ctx)
	if err != nil || identity != "dn:cn=admin" {
		t.Fatalf("WhoAmI = %q, %v", identity, err)
	}
	generated, err := client.PasswordModify(ctx, "cn=user", "old-secret", "new-secret")
	if err != nil || generated != "generated-secret" {
		t.Fatalf("PasswordModify = %q, %v", generated, err)
	}
	response, err := client.Extended(ctx, "1.2.3.fail", nil)
	if !errors.Is(err, ErrUnwillingToPerform) || response == nil {
		t.Fatalf("Extended = %+v, %v", response, err)
	}
}

// TestClientStartTLS verifies StartTLS upgrade and TLS connection state. |
// TestClientStartTLS 校验 StartTLS 升级与 TLS 连接状态。
func TestClientStartTLS(t *testing.T) {
	certificate, pool := testCertificate(t)
	server := startMockServer(t, func(session *mockSession, message *LDAPMessage) error {
		switch request := message.Op.(type) {
		case *ExtendedRequest:
			if request.Name != OIDStartTLS {
				return errors.New("unexpected extended request")
			}
			if err := session.writeSimpleResult(message.MessageID, &ExtendedResponse{Result: LDAPResult{Code: ResultSuccess}}); err != nil {
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
	client, err := DialURL(context.Background(), server.URL())
	if err != nil {
		t.Fatalf("DialURL: %v", err)
	}
	defer client.Close()
	clientTLS := testTLSConfig(pool)
	if err := client.StartTLS(context.Background(), clientTLS); err != nil {
		t.Fatalf("StartTLS: %v", err)
	}
	state, secure := client.TLSConnectionState()
	if !secure || len(state.PeerCertificates) == 0 {
		t.Fatalf("TLS state = %+v, secure = %t", state, secure)
	}
	if err := client.StartTLS(context.Background(), clientTLS); err != nil {
		t.Fatalf("second StartTLS: %v", err)
	}
	if err := client.Bind(context.Background(), "cn=user", "password"); err != nil {
		t.Fatalf("bind over TLS: %v", err)
	}
}

// TestClientStartTLSRequiresNoBind verifies StartTLS cannot follow a bind. |
// TestClientStartTLSRequiresNoBind 校验 StartTLS 不能在绑定后执行。
func TestClientStartTLSRequiresNoBind(t *testing.T) {
	server := startMockServer(t, func(session *mockSession, message *LDAPMessage) error {
		switch message.Op.(type) {
		case *BindRequest:
			return session.writeSimpleResult(message.MessageID, &BindResponse{Result: LDAPResult{Code: ResultSuccess}})
		default:
			return errors.New("unexpected operation")
		}
	})
	client, err := DialURL(context.Background(), server.URL())
	if err != nil {
		t.Fatalf("DialURL: %v", err)
	}
	defer client.Close()
	if err := client.Bind(context.Background(), "cn=user", "password"); err != nil {
		t.Fatalf("Bind: %v", err)
	}
	if err := client.StartTLS(context.Background(), &tls.Config{}); !errors.Is(err, ErrInvalidConfig) {
		t.Fatalf("StartTLS after bind error = %v", err)
	}
}

// TestClientLDAPS verifies an immediate TLS connection with certificate
// verification. | TestClientLDAPS 校验带证书校验的即时 TLS 连接。
func TestClientLDAPS(t *testing.T) {
	certificate, pool := testCertificate(t)
	server := startMockServerTLS(t, &tls.Config{Certificates: []tls.Certificate{certificate}, MinVersion: tls.VersionTLS12},
		func(session *mockSession, message *LDAPMessage) error {
			if _, ok := message.Op.(*SearchRequest); !ok {
				return errors.New("expected search")
			}
			if err := session.writeEntry(message.MessageID, "", Attribute{Type: "defaultNamingContext", Values: []string{"DC=example,DC=com"}}); err != nil {
				return err
			}
			return session.writeSearchDone(message.MessageID, LDAPResult{Code: ResultSuccess})
		})
	client, err := DialURL(context.Background(), server.URL(), Config{TLSConfig: testTLSConfig(pool)})
	if err != nil {
		t.Fatalf("DialURL: %v", err)
	}
	defer client.Close()
	_, secure := client.TLSConnectionState()
	if !secure {
		t.Fatal("LDAPS client is not secure")
	}
	root, err := client.RootDSE(context.Background())
	if err != nil {
		t.Fatalf("RootDSE: %v", err)
	}
	if root.First("defaultNamingContext") != "DC=example,DC=com" {
		t.Fatalf("root = %+v", root)
	}
}

// TestClientReconnectReplaysAuthentication verifies transparent reconnection. |
// TestClientReconnectReplaysAuthentication 校验透明重连。
func TestClientReconnectReplaysAuthentication(t *testing.T) {
	var (
		mu          sync.Mutex
		bindCount   int
		searchCount int
	)
	server := startMockServer(t, func(session *mockSession, message *LDAPMessage) error {
		switch request := message.Op.(type) {
		case *BindRequest:
			auth := request.Authentication.(SimpleAuthentication)
			if request.DN != "cn=user" || auth.Password != "password" {
				return errors.New("unexpected bind")
			}
			mu.Lock()
			bindCount++
			mu.Unlock()
			return session.writeSimpleResult(message.MessageID, &BindResponse{Result: LDAPResult{Code: ResultSuccess}})
		case *SearchRequest:
			mu.Lock()
			searchCount++
			count := searchCount
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
	if err := client.Bind(context.Background(), "cn=user", "password"); err != nil {
		t.Fatalf("Bind: %v", err)
	}
	if _, err := client.Search(context.Background(), SearchOptions{Filter: Present("objectClass")}); err == nil {
		t.Fatal("first search unexpectedly succeeded")
	}
	result, err := client.Search(context.Background(), SearchOptions{Filter: Present("objectClass")})
	if err != nil {
		t.Fatalf("second search: %v", err)
	}
	if len(result.Entries) != 1 || result.Entries[0].DN != "cn=recovered" {
		t.Fatalf("entries = %+v", result.Entries)
	}
	mu.Lock()
	defer mu.Unlock()
	if bindCount != 2 || searchCount != 2 {
		t.Fatalf("binds = %d searches = %d", bindCount, searchCount)
	}
}

// TestClientCancellationAndTimeout verifies context cancellation and read
// deadlines. | TestClientCancellationAndTimeout 校验上下文取消与读取期限。
func TestClientCancellationAndTimeout(t *testing.T) {
	t.Run("context", func(t *testing.T) {
		var (
			mu          sync.Mutex
			searchCount int
		)
		server := startMockServer(t, func(session *mockSession, message *LDAPMessage) error {
			mu.Lock()
			searchCount++
			count := searchCount
			mu.Unlock()
			if count == 1 {
				return nil
			}
			if err := session.writeEntry(message.MessageID, "cn=after", Attribute{Type: "cn", Values: []string{"after"}}); err != nil {
				return err
			}
			return session.writeSearchDone(message.MessageID, LDAPResult{Code: ResultSuccess})
		})
		client, err := DialURL(context.Background(), server.URL(), Config{Timeout: 5 * time.Second})
		if err != nil {
			t.Fatalf("DialURL: %v", err)
		}
		defer client.Close()
		ctx := mustTimeoutContext(t, 500*time.Millisecond)
		if _, err := client.Search(ctx, SearchOptions{Filter: Present("objectClass")}); !errors.Is(err, context.DeadlineExceeded) {
			t.Fatalf("canceled search error = %v", err)
		}
		result, err := client.Search(context.Background(), SearchOptions{Filter: Present("objectClass")})
		if err != nil {
			t.Fatalf("search after cancellation: %v", err)
		}
		if len(result.Entries) != 1 {
			t.Fatalf("entries = %+v", result.Entries)
		}
	})
	t.Run("read deadline", func(t *testing.T) {
		server := startMockServer(t, func(session *mockSession, message *LDAPMessage) error {
			return nil
		})
		client, err := DialURL(context.Background(), server.URL(), Config{Timeout: 250 * time.Millisecond})
		if err != nil {
			t.Fatalf("DialURL: %v", err)
		}
		defer client.Close()
		if _, err := client.Search(context.Background(), SearchOptions{Filter: Present("objectClass")}); !errors.Is(err, ErrTimeout) {
			t.Fatalf("timeout error = %v", err)
		}
	})
}

// TestClientSearchStreamAndReferralErrors verifies streaming and referral hook
// failures. | TestClientSearchStreamAndReferralErrors 校验流式处理与转介钩子失败。
func TestClientSearchStreamAndReferralErrors(t *testing.T) {
	var (
		mu       sync.Mutex
		requests int
	)
	server := startMockServer(t, func(session *mockSession, message *LDAPMessage) error {
		mu.Lock()
		requests++
		index := requests
		mu.Unlock()
		if index == 1 {
			if err := session.writeEntry(message.MessageID, "cn=a", Attribute{Type: "cn", Values: []string{"a"}}); err != nil {
				return err
			}
			if err := session.writeEntry(message.MessageID, "cn=b", Attribute{Type: "cn", Values: []string{"b"}}); err != nil {
				return err
			}
			return session.writeSearchDone(message.MessageID, LDAPResult{Code: ResultSuccess})
		}
		return session.writeSearchReference(message.MessageID, "ldap://ref.example.com/dc=example")
	})
	client, err := DialURL(context.Background(), server.URL())
	if err != nil {
		t.Fatalf("DialURL: %v", err)
	}
	defer client.Close()
	var seen []string
	stream, err := client.SearchStream(context.Background(), SearchOptions{Filter: Present("objectClass")}, func(entry *Entry) error {
		seen = append(seen, entry.DN)
		return nil
	})
	if err != nil {
		t.Fatalf("SearchStream: %v", err)
	}
	if !reflect.DeepEqual(seen, []string{"cn=a", "cn=b"}) {
		t.Fatalf("seen = %v", seen)
	}
	if len(stream.Entries) != 0 {
		t.Fatalf("stream collected entries: %+v", stream.Entries)
	}
	referralError := errors.New("referral rejected")
	_, err = client.Search(context.Background(), SearchOptions{
		Filter: Present("objectClass"),
		OnReferral: func(ctx context.Context, urls []string) error {
			return referralError
		},
	})
	if !errors.Is(err, referralError) {
		t.Fatalf("referral error = %v", err)
	}
}

// TestClientUnexpectedResponses verifies desynchronizing response handling. |
// TestClientUnexpectedResponses 校验失步响应的处理。
func TestClientUnexpectedResponses(t *testing.T) {
	t.Run("message ID", func(t *testing.T) {
		var requests int
		server := startMockServer(t, func(session *mockSession, message *LDAPMessage) error {
			requests++
			if requests == 1 {
				return session.writeSearchDone(message.MessageID+1, LDAPResult{Code: ResultSuccess})
			}
			return session.writeSearchDone(message.MessageID, LDAPResult{Code: ResultSuccess})
		})
		client, err := DialURL(context.Background(), server.URL())
		if err != nil {
			t.Fatalf("DialURL: %v", err)
		}
		defer client.Close()
		if _, err := client.Search(context.Background(), SearchOptions{Filter: Present("objectClass")}); !errors.Is(err, ErrUnexpectedResponse) {
			t.Fatalf("message ID error = %v", err)
		}
		if _, err := client.Search(context.Background(), SearchOptions{Filter: Present("objectClass")}); err != nil {
			t.Fatalf("search after resync: %v", err)
		}
	})
	t.Run("wrong operation", func(t *testing.T) {
		server := startMockServer(t, func(session *mockSession, message *LDAPMessage) error {
			return session.writeSimpleResult(message.MessageID, &AddResponse{Result: LDAPResult{Code: ResultSuccess}})
		})
		client, err := DialURL(context.Background(), server.URL())
		if err != nil {
			t.Fatalf("DialURL: %v", err)
		}
		defer client.Close()
		if _, err := client.Search(context.Background(), SearchOptions{Filter: Present("objectClass")}); !errors.Is(err, ErrUnexpectedResponse) {
			t.Fatalf("wrong operation error = %v", err)
		}
	})
	t.Run("unsolicited notice", func(t *testing.T) {
		server := startMockServer(t, func(session *mockSession, message *LDAPMessage) error {
			return session.Write(&LDAPMessage{MessageID: 0, Op: &ExtendedResponse{
				Result: LDAPResult{Code: ResultUnavailable, DiagnosticMessage: "going down"},
				Name:   OIDNoticeOfDisconnection,
			}})
		})
		client, err := DialURL(context.Background(), server.URL())
		if err != nil {
			t.Fatalf("DialURL: %v", err)
		}
		defer client.Close()
		if _, err := client.Search(context.Background(), SearchOptions{Filter: Present("objectClass")}); !errors.Is(err, ErrUnavailable) {
			t.Fatalf("notice error = %v", err)
		}
	})
}

// TestClientRootDSEAndSchema verifies root DSE, schema and health helpers. |
// TestClientRootDSEAndSchema 校验根 DSE、模式与健康检查辅助方法。
func TestClientRootDSEAndSchema(t *testing.T) {
	server := startMockServer(t, func(session *mockSession, message *LDAPMessage) error {
		request, ok := message.Op.(*SearchRequest)
		if !ok {
			return errors.New("expected search")
		}
		switch request.BaseDN {
		case "":
			if request.Scope != ScopeBaseObject {
				return errors.New("root DSE is not base scoped")
			}
			if err := session.writeEntry(message.MessageID, "", Attribute{Type: "subschemaSubentry", Values: []string{"cn=Subschema"}}); err != nil {
				return err
			}
			return session.writeSearchDone(message.MessageID, LDAPResult{Code: ResultSuccess})
		case "cn=Subschema":
			if err := session.writeEntry(message.MessageID, "cn=Subschema", Attribute{Type: "objectClass", Values: []string{"subschema"}}); err != nil {
				return err
			}
			return session.writeSearchDone(message.MessageID, LDAPResult{Code: ResultSuccess})
		default:
			return errors.New("unexpected search base")
		}
	})
	client, err := DialURL(context.Background(), server.URL())
	if err != nil {
		t.Fatalf("DialURL: %v", err)
	}
	defer client.Close()
	root, err := client.RootDSE(context.Background())
	if err != nil {
		t.Fatalf("RootDSE: %v", err)
	}
	if root.First("subschemaSubentry") != "cn=Subschema" {
		t.Fatalf("root = %+v", root)
	}
	schema, err := client.Schema(context.Background())
	if err != nil {
		t.Fatalf("Schema: %v", err)
	}
	if schema.DN != "cn=Subschema" {
		t.Fatalf("schema = %+v", schema)
	}
	if err := client.Health(context.Background()); err != nil {
		t.Fatalf("Health: %v", err)
	}
}

// TestClientRootDSEErrors verifies root DSE and schema failure paths. |
// TestClientRootDSEErrors 校验根 DSE 与模式的失败路径。
func TestClientRootDSEErrors(t *testing.T) {
	t.Run("no root entry", func(t *testing.T) {
		server := startMockServer(t, func(session *mockSession, message *LDAPMessage) error {
			return session.writeSearchDone(message.MessageID, LDAPResult{Code: ResultSuccess})
		})
		client, err := DialURL(context.Background(), server.URL())
		if err != nil {
			t.Fatalf("DialURL: %v", err)
		}
		defer client.Close()
		if _, err := client.RootDSE(context.Background()); !errors.Is(err, ErrNoSuchObject) {
			t.Fatalf("RootDSE error = %v", err)
		}
	})
	t.Run("no subschema attribute", func(t *testing.T) {
		server := startMockServer(t, func(session *mockSession, message *LDAPMessage) error {
			if err := session.writeEntry(message.MessageID, "", Attribute{Type: "namingContexts", Values: []string{"dc=example"}}); err != nil {
				return err
			}
			return session.writeSearchDone(message.MessageID, LDAPResult{Code: ResultSuccess})
		})
		client, err := DialURL(context.Background(), server.URL())
		if err != nil {
			t.Fatalf("DialURL: %v", err)
		}
		defer client.Close()
		if _, err := client.Schema(context.Background()); !errors.Is(err, ErrNoSuchAttribute) {
			t.Fatalf("Schema error = %v", err)
		}
	})
}

// TestClientObviousValidation verifies local search validation. | TestClientObviousValidation
// 校验本地搜索参数验证。
func TestClientObviousValidation(t *testing.T) {
	client := &Client{}
	cases := []struct {
		options SearchOptions
		match   error
	}{
		{options: SearchOptions{Scope: Scope(9), Filter: Present("cn")}, match: ErrInvalidMessage},
		{options: SearchOptions{Scope: ScopeBaseObject, PageSize: -1, Filter: Present("cn")}, match: ErrInvalidMessage},
		{options: SearchOptions{Scope: ScopeBaseObject, SizeLimit: -1, Filter: Present("cn")}, match: ErrInvalidMessage},
		{options: SearchOptions{Scope: ScopeBaseObject, Filter: nil}, match: ErrInvalidFilter},
	}
	for _, test := range cases {
		if _, err := client.Search(context.Background(), test.options); !errors.Is(err, test.match) {
			t.Fatalf("Search(%+v) error = %v", test.options, err)
		}
	}
	if _, err := client.SearchStream(context.Background(), SearchOptions{Filter: Present("cn")}, nil); !errors.Is(err, ErrInvalidMessage) {
		t.Fatalf("nil handler error = %v", err)
	}
}

// TestClientCloseAndUnbind verifies lifecycle transitions. | TestClientCloseAndUnbind
// 校验生命周期状态转换。
func TestClientCloseAndUnbind(t *testing.T) {
	t.Run("close", func(t *testing.T) {
		server := startMockServer(t, func(session *mockSession, message *LDAPMessage) error {
			return errors.New("unexpected operation")
		})
		client, err := DialURL(context.Background(), server.URL())
		if err != nil {
			t.Fatalf("DialURL: %v", err)
		}
		if err := client.Close(); err != nil {
			t.Fatalf("Close: %v", err)
		}
		if !client.IsClosed() {
			t.Fatal("client is not closed")
		}
		if err := client.Close(); err != nil {
			t.Fatalf("second Close: %v", err)
		}
		if _, err := client.Search(context.Background(), SearchOptions{Filter: Present("objectClass")}); !errors.Is(err, ErrClosed) {
			t.Fatalf("Search after Close error = %v", err)
		}
		if err := client.Unbind(context.Background()); !errors.Is(err, ErrClosed) {
			t.Fatalf("Unbind after Close error = %v", err)
		}
	})
	t.Run("unbind", func(t *testing.T) {
		unbound := make(chan struct{})
		server := startMockServer(t, func(session *mockSession, message *LDAPMessage) error {
			if _, ok := message.Op.(*UnbindRequest); !ok {
				return errors.New("expected unbind")
			}
			close(unbound)
			return nil
		})
		client, err := DialURL(context.Background(), server.URL())
		if err != nil {
			t.Fatalf("DialURL: %v", err)
		}
		if err := client.Unbind(context.Background()); err != nil {
			t.Fatalf("Unbind: %v", err)
		}
		select {
		case <-unbound:
		case <-time.After(time.Second):
			t.Fatal("server did not receive unbind")
		}
		if !client.IsClosed() {
			t.Fatal("client is not closed after unbind")
		}
	})
}

// TestClientMessageSizeLimits verifies both read and write size limits. |
// TestClientMessageSizeLimits 校验读取与写出大小限制。
func TestClientMessageSizeLimits(t *testing.T) {
	t.Run("read", func(t *testing.T) {
		server := startMockServer(t, func(session *mockSession, message *LDAPMessage) error {
			return session.writeSimpleResult(message.MessageID, &BindResponse{Result: LDAPResult{
				Code:              ResultInvalidCredentials,
				DiagnosticMessage: strings.Repeat("x", 200),
			}})
		})
		client, err := DialURL(context.Background(), server.URL(), Config{MaxMessageSize: 64})
		if err != nil {
			t.Fatalf("DialURL: %v", err)
		}
		defer client.Close()
		if err := client.Bind(context.Background(), "cn=user", "password"); !errors.Is(err, ErrInvalidMessageTooLarge) {
			t.Fatalf("read limit error = %v", err)
		}
	})
	t.Run("write", func(t *testing.T) {
		server := startMockServer(t, func(session *mockSession, message *LDAPMessage) error {
			return errors.New("unexpected operation")
		})
		client, err := DialURL(context.Background(), server.URL(), Config{MaxMessageSize: 32})
		if err != nil {
			t.Fatalf("DialURL: %v", err)
		}
		defer client.Close()
		if err := client.Bind(context.Background(), "cn=user", strings.Repeat("p", 128)); !errors.Is(err, ErrInvalidMessageTooLarge) {
			t.Fatalf("write limit error = %v", err)
		}
	})
}

// TestClientReconnectMethod verifies explicit Reconnect. | TestClientReconnectMethod
// 校验显式 Reconnect。
func TestClientReconnectMethod(t *testing.T) {
	var (
		mu    sync.Mutex
		binds int
	)
	server := startMockServer(t, func(session *mockSession, message *LDAPMessage) error {
		switch request := message.Op.(type) {
		case *BindRequest:
			mu.Lock()
			binds++
			mu.Unlock()
			return session.writeSimpleResult(message.MessageID, &BindResponse{Result: LDAPResult{Code: ResultSuccess}})
		case *SearchRequest:
			_ = request
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
	if err := client.Bind(context.Background(), "cn=user", "password"); err != nil {
		t.Fatalf("Bind: %v", err)
	}
	if err := client.Reconnect(context.Background()); err != nil {
		t.Fatalf("Reconnect: %v", err)
	}
	mu.Lock()
	count := binds
	mu.Unlock()
	if count != 2 {
		t.Fatalf("binds = %d", count)
	}
	if _, err := client.Search(context.Background(), SearchOptions{Filter: Present("objectClass")}); err != nil {
		t.Fatalf("Search after Reconnect: %v", err)
	}
}

// TestClientDisconnectedDial verifies connection errors are classified. |
// TestClientDisconnectedDial 校验连接错误分类。
func TestClientDisconnectedDial(t *testing.T) {
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	address := listener.Addr().String()
	_ = listener.Close()
	if _, err := Dial(context.Background(), Config{URL: "ldap://" + address, DialTimeout: time.Second}); !errors.Is(err, ErrNetwork) {
		t.Fatalf("dial error = %v", err)
	}
}
