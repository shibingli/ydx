package kerberos

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"net"
	"testing"
	"time"
)

// mustClient builds a client or fails the test. | mustClient 构建客户端，失败时让测试失败。
func mustClient(t *testing.T, cfg Config) *Client {
	t.Helper()
	client, err := NewClient(cfg)
	if err != nil {
		t.Fatalf("NewClient: %v", err)
	}
	return client
}

// decryptTicketPart decrypts an issued ticket with key. | decryptTicketPart 用 key 解密
// 已签发的票据。
func decryptTicketPart(t *testing.T, ticket Ticket, key EncryptionKey) EncTicketPart {
	t.Helper()
	plain, err := DecryptMessage(key.KeyType, key.KeyValue, 2, ticket.EncPart.Cipher)
	if err != nil {
		t.Fatalf("ticket decryption: %v", err)
	}
	part, err := parseEncTicketPart(plain)
	if err != nil {
		t.Fatalf("ticket parsing: %v", err)
	}
	return part
}

// equalKey reports whether two keys have the same type and value. | equalKey 报告两个密钥
// 的类型与值是否相同。
func equalKey(a, b EncryptionKey) bool {
	return a.KeyType == b.KeyType && bytes.Equal(a.KeyValue, b.KeyValue)
}

// TestClientPasswordLoginWithPreAuth covers the pre-authentication challenge and
// retry with explicit salt and iteration hints. | TestClientPasswordLoginWithPreAuth
// 覆盖带显式盐与迭代提示的预认证挑战与重试。
func TestClientPasswordLoginWithPreAuth(t *testing.T) {
	const password = "correct horse battery staple"
	m := startMockKDC(t, mockKDCOptions{
		password:       password,
		requirePreAuth: true,
		sendHints:      true,
		hintSalt:       "EXAMPLE.COMcustomsalt",
		hintIterations: 1000,
	})
	client := mustClient(t, m.clientConfig(ETypeAES256CTS))
	session, err := client.Login(testContext(t))
	if err != nil {
		t.Fatalf("Login: %v", err)
	}
	if session.ClientRealm != m.opts.realm {
		t.Fatalf("client realm = %q, want %q", session.ClientRealm, m.opts.realm)
	}
	wantClient := NewPrincipalName(NameTypePrincipal, m.opts.clientPrincipal)
	if !session.ClientPrincipal.Equal(wantClient) {
		t.Fatalf("client principal = %s, want %s", session.ClientPrincipal.String(), wantClient.String())
	}
	if session.SessionKey.KeyType != ETypeAES256CTS {
		t.Fatalf("session key type = %d, want %d", session.SessionKey.KeyType, ETypeAES256CTS)
	}
	part := decryptTicketPart(t, session.TGT, m.opts.krbtgtKey)
	if !equalKey(part.Key, session.SessionKey) {
		t.Fatal("TGT session key differs from the AS-REP key")
	}
	if !part.CName.Equal(wantClient) || part.CRealm != m.opts.realm {
		t.Fatalf("TGT client = %s@%s", part.CName.String(), part.CRealm)
	}
	if !part.Flags.Has(TicketFlagPreAuthent) || !part.Flags.Has(TicketFlagForwardable) {
		t.Fatalf("TGT flags = 0x%x", uint32(part.Flags))
	}
	if !part.AuthTime.Time.Equal(session.AuthTime.Time) || !part.EndTime.Time.Equal(session.EndTime.Time) {
		t.Fatal("session times differ from the ticket times")
	}
	as, tgs := m.counts()
	if as != 2 || tgs != 0 {
		t.Fatalf("request counts = AS %d TGS %d, want AS 2 TGS 0", as, tgs)
	}
	m.check(t)
}

// TestClientPasswordLoginDefaultHints covers a challenge without salt hints. |
// TestClientPasswordLoginDefaultHints 覆盖不带盐提示的挑战。
func TestClientPasswordLoginDefaultHints(t *testing.T) {
	m := startMockKDC(t, mockKDCOptions{
		password:       "hunter2",
		requirePreAuth: true,
	})
	client := mustClient(t, m.clientConfig(ETypeAES128CTS))
	if _, err := client.Login(testContext(t)); err != nil {
		t.Fatalf("Login: %v", err)
	}
	as, _ := m.counts()
	if as != 2 {
		t.Fatalf("AS requests = %d, want 2", as)
	}
	m.check(t)
}

// TestClientKeyTabLoginSelectsAvailableKey verifies keytab credentials skip an
// unavailable encryption type. | TestClientKeyTabLoginSelectsAvailableKey 校验 keytab
// 凭据会跳过不可用的加密类型。
func TestClientKeyTabLoginSelectsAvailableKey(t *testing.T) {
	clientKey, err := randomKey(ETypeAES128CTS)
	if err != nil {
		t.Fatalf("randomKey: %v", err)
	}
	m := startMockKDC(t, mockKDCOptions{
		clientKey:      &clientKey,
		clientKVNO:     4,
		requirePreAuth: true,
		sendHints:      true,
	})
	tab, err := m.clientKeytab(ETypeAES128CTS)
	if err != nil {
		t.Fatalf("clientKeytab: %v", err)
	}
	cfg := m.clientConfig(ETypeAES256CTS, ETypeAES128CTS)
	cfg.KeyTab = tab
	client := mustClient(t, cfg)
	session, err := client.Login(testContext(t))
	if err != nil {
		t.Fatalf("Login: %v", err)
	}
	// The KDC picks the session key from the request list; reaching this point
	// already proves the pre-authentication key came from the AES128 keytab
	// entry, because the mock rejects an AES256 long-term key. | KDC 从请求列表选择
	// 会话密钥；能走到这里已证明预认证密钥来自 AES128 keytab 条目，因为模拟 KDC 会拒绝
	// AES256 长期密钥。
	if _, err := KeySize(session.SessionKey.KeyType); err != nil {
		t.Fatalf("session key: %v", err)
	}
	m.check(t)
}

// TestClientServiceTicket verifies TGS acquisition and ticket contents. |
// TestClientServiceTicket 校验 TGS 获取与服务票据内容。
func TestClientServiceTicket(t *testing.T) {
	m := startMockKDC(t, mockKDCOptions{password: "service", serviceKVNO: 3, issueKVNO: 7})
	client := mustClient(t, m.clientConfig(ETypeAES256CTS))
	ctx := testContext(t)
	if _, err := client.Login(ctx); err != nil {
		t.Fatalf("Login: %v", err)
	}
	service := m.opts.servicePrincipal + "@" + m.opts.realm
	ticket, err := client.GetServiceTicket(ctx, service)
	if err != nil {
		t.Fatalf("GetServiceTicket: %v", err)
	}
	wantService := m.servicePrincipal()
	if !ticket.ServicePrincipal.Equal(wantService) || ticket.ServiceRealm != m.opts.realm {
		t.Fatalf("service = %s@%s, want %s@%s", ticket.ServicePrincipal.String(), ticket.ServiceRealm,
			wantService.String(), m.opts.realm)
	}
	if ticket.Ticket.EncPart.EType != m.opts.serviceKey.KeyType {
		t.Fatalf("ticket enctype = %d, want %d", ticket.Ticket.EncPart.EType, m.opts.serviceKey.KeyType)
	}
	if ticket.Ticket.EncPart.KVNO != 7 {
		t.Fatalf("ticket kvno = %d, want 7", ticket.Ticket.EncPart.KVNO)
	}
	part := decryptTicketPart(t, ticket.Ticket, m.opts.serviceKey)
	if !equalKey(part.Key, ticket.SessionKey) {
		t.Fatal("ticket session key differs from the TGS-REP key")
	}
	if !part.CName.Equal(ticket.ClientPrincipal) || part.CRealm != ticket.ClientRealm {
		t.Fatalf("ticket client = %s@%s, TGS-REP client = %s@%s", part.CName.String(), part.CRealm,
			ticket.ClientPrincipal.String(), ticket.ClientRealm)
	}
	if !ticket.Ticket.SName.Equal(wantService) {
		t.Fatalf("ticket server = %s, want %s", ticket.Ticket.SName.String(), wantService.String())
	}
	if !ticket.Flags.Has(TicketFlagForwardable) {
		t.Fatalf("service ticket flags = 0x%x", uint32(ticket.Flags))
	}
	as, tgs := m.counts()
	if as != 1 || tgs != 1 {
		t.Fatalf("request counts = AS %d TGS %d, want AS 1 TGS 1", as, tgs)
	}
	m.check(t)
}

// TestClientTransportSelection covers UDP-to-TCP fallback and TCP preference. |
// TestClientTransportSelection 覆盖 UDP 到 TCP 的回退与 TCP 偏好。
func TestClientTransportSelection(t *testing.T) {
	t.Run("udp fallback", func(t *testing.T) {
		m := startMockKDC(t, mockKDCOptions{
			password:       "fallback",
			requirePreAuth: true,
			forceUDPTooBig: true,
		})
		client := mustClient(t, m.clientConfig(ETypeAES256CTS))
		if _, err := client.Login(testContext(t)); err != nil {
			t.Fatalf("Login: %v", err)
		}
		udp, tcp := m.transportCounts()
		if udp == 0 || tcp == 0 {
			t.Fatalf("transport counts = UDP %d TCP %d, want both non-zero", udp, tcp)
		}
		as, _ := m.counts()
		if as != 2 {
			t.Fatalf("AS requests = %d, want 2", as)
		}
		m.check(t)
	})
	t.Run("prefer tcp", func(t *testing.T) {
		m := startMockKDC(t, mockKDCOptions{
			password:       "prefertcp",
			requirePreAuth: true,
		})
		cfg := m.clientConfig(ETypeAES256CTS)
		cfg.PreferTCP = true
		client := mustClient(t, cfg)
		if _, err := client.Login(testContext(t)); err != nil {
			t.Fatalf("Login: %v", err)
		}
		udp, tcp := m.transportCounts()
		if udp != 0 || tcp == 0 {
			t.Fatalf("transport counts = UDP %d TCP %d, want UDP 0 and TCP non-zero", udp, tcp)
		}
		m.check(t)
	})
}

// TestClientKRBErrorMapping maps AS exchange error codes to sentinels. |
// TestClientKRBErrorMapping 把 AS 交换错误码映射到哨兵错误。
func TestClientKRBErrorMapping(t *testing.T) {
	tests := []struct {
		code int32
		want error
	}{
		{6, ErrClientNotFound},
		{7, ErrServerNotFound},
		{8, ErrPrincipalNotUnique},
		{12, ErrKRBError},
		{14, ErrETypeNotSupported},
		{18, ErrClientRevoked},
		{23, ErrKeyExpired},
		{24, ErrPreAuthFailed},
		{25, ErrPreAuthRequired},
		{31, ErrBadIntegrity},
		{32, ErrTicketExpired},
		{33, ErrTicketNotYetValid},
		{34, ErrReplay},
		{35, ErrTicketNotForUs},
		{36, ErrTicketMismatch},
		{37, ErrClockSkew},
		{44, ErrBadKVNO},
		{45, ErrNoKey},
		{46, ErrMutualAuthFailed},
		{52, ErrResponseTooBig},
		{60, ErrKRBError},
	}
	for _, test := range tests {
		name := ErrorCodeName(test.code)
		if name == "" {
			name = fmt.Sprintf("code %d", test.code)
		}
		t.Run(name, func(t *testing.T) {
			m := startMockKDC(t, mockKDCOptions{
				password:   "mapping",
				forceError: test.code,
			})
			client := mustClient(t, m.clientConfig(ETypeAES256CTS))
			_, err := client.Login(testContext(t))
			if !errors.Is(err, test.want) {
				t.Fatalf("Login error = %v, want %v", err, test.want)
			}
			m.check(t)
		})
	}
}

// TestClientWrongPassword covers pre-authentication rejection. |
// TestClientWrongPassword 覆盖预认证拒绝。
func TestClientWrongPassword(t *testing.T) {
	m := startMockKDC(t, mockKDCOptions{
		password:       "the-right-password",
		requirePreAuth: true,
		sendHints:      true,
	})
	cfg := m.clientConfig(ETypeAES256CTS)
	cfg.Password = "the-wrong-password"
	client := mustClient(t, cfg)
	_, err := client.Login(testContext(t))
	if !errors.Is(err, ErrPreAuthFailed) {
		t.Fatalf("Login error = %v, want ErrPreAuthFailed", err)
	}
	as, _ := m.counts()
	if as != 2 {
		t.Fatalf("AS requests = %d, want 2", as)
	}
	m.check(t)
}

// TestClientTGSErrorMapping maps TGS exchange error codes to sentinels. |
// TestClientTGSErrorMapping 把 TGS 交换错误码映射到哨兵错误。
func TestClientTGSErrorMapping(t *testing.T) {
	tests := []struct {
		code int32
		want error
	}{
		{7, ErrServerNotFound},
		{14, ErrETypeNotSupported},
		{36, ErrTicketMismatch},
		{60, ErrKRBError},
	}
	for _, test := range tests {
		t.Run(ErrorCodeName(test.code), func(t *testing.T) {
			m := startMockKDC(t, mockKDCOptions{password: "tgserror", forceTGSError: test.code})
			client := mustClient(t, m.clientConfig(ETypeAES256CTS))
			ctx := testContext(t)
			if _, err := client.Login(ctx); err != nil {
				t.Fatalf("Login: %v", err)
			}
			_, err := client.GetServiceTicket(ctx, m.opts.servicePrincipal)
			if !errors.Is(err, test.want) {
				t.Fatalf("GetServiceTicket error = %v, want %v", err, test.want)
			}
			m.check(t)
		})
	}
}

// TestClientKDCUnavailable covers connection and cancellation failures. |
// TestClientKDCUnavailable 覆盖连接与取消失败。
func TestClientKDCUnavailable(t *testing.T) {
	t.Run("refused", func(t *testing.T) {
		client := mustClient(t, Config{
			KDC:       []string{"127.0.0.1:1"},
			Realm:     "EXAMPLE.COM",
			Principal: "alice",
			Password:  "refused",
			ETypes:    []int32{ETypeAES256CTS},
			Timeout:   500 * time.Millisecond,
			PreferTCP: true,
		})
		_, err := client.Login(testContext(t))
		if !errors.Is(err, ErrKDCUnavailable) {
			t.Fatalf("Login error = %v, want ErrKDCUnavailable", err)
		}
	})
	t.Run("cancelled", func(t *testing.T) {
		m := startMockKDC(t, mockKDCOptions{password: "cancelled"})
		client := mustClient(t, m.clientConfig(ETypeAES256CTS))
		ctx, cancel := context.WithCancel(testContext(t))
		cancel()
		_, err := client.Login(ctx)
		if !errors.Is(err, context.Canceled) {
			t.Fatalf("Login error = %v, want context.Canceled", err)
		}
	})
}

// fakeDNS implements the discovery resolver with fixed records. | fakeDNS 用固定记录
// 实现发现解析器。
type fakeDNS struct {
	srv       map[string][]*net.SRV
	srvErr    map[string]error
	txt       map[string][]string
	txtErr    error
	srvCalls  []string
	txtCalls  []string
	srvLookup func(service, proto, name string) (string, []*net.SRV, error)
}

// LookupSRV returns the configured SRV records. | LookupSRV 返回配置的 SRV 记录。
func (f *fakeDNS) LookupSRV(ctx context.Context, service, proto, name string) (string, []*net.SRV, error) {
	f.srvCalls = append(f.srvCalls, proto+" "+name)
	if f.srvLookup != nil {
		return f.srvLookup(service, proto, name)
	}
	if err := f.srvErr[proto]; err != nil {
		return "", nil, err
	}
	return "", f.srv[proto], nil
}

// LookupTXT returns the configured TXT records. | LookupTXT 返回配置的 TXT 记录。
func (f *fakeDNS) LookupTXT(ctx context.Context, name string) ([]string, error) {
	f.txtCalls = append(f.txtCalls, name)
	if f.txtErr != nil {
		return nil, f.txtErr
	}
	return f.txt[name], nil
}

// TestDiscoverKDCs covers protocol preference and missing records. | TestDiscoverKDCs
// 覆盖协议偏好与缺失记录。
func TestDiscoverKDCs(t *testing.T) {
	t.Run("udp first", func(t *testing.T) {
		resolver := &fakeDNS{srv: map[string][]*net.SRV{
			"udp": {{Target: "kdc1.example.com.", Port: 88}},
			"tcp": {{Target: "kdc2.example.com.", Port: 750}},
		}}
		servers, err := discoverKDCs(testContext(t), "EXAMPLE.COM", resolver, false)
		if err != nil {
			t.Fatalf("discoverKDCs: %v", err)
		}
		want := []string{"kdc1.example.com:88"}
		if len(servers) != 1 || servers[0] != want[0] {
			t.Fatalf("servers = %v, want %v", servers, want)
		}
		if len(resolver.srvCalls) != 1 || resolver.srvCalls[0] != "udp EXAMPLE.COM" {
			t.Fatalf("SRV calls = %v", resolver.srvCalls)
		}
	})
	t.Run("tcp fallback", func(t *testing.T) {
		resolver := &fakeDNS{srv: map[string][]*net.SRV{
			"tcp": {{Target: "kdc2.example.com.", Port: 750}},
		}}
		servers, err := discoverKDCs(testContext(t), "EXAMPLE.COM", resolver, false)
		if err != nil {
			t.Fatalf("discoverKDCs: %v", err)
		}
		want := []string{"kdc2.example.com:750"}
		if len(servers) != 1 || servers[0] != want[0] {
			t.Fatalf("servers = %v, want %v", servers, want)
		}
		if len(resolver.srvCalls) != 2 || resolver.srvCalls[0] != "udp EXAMPLE.COM" || resolver.srvCalls[1] != "tcp EXAMPLE.COM" {
			t.Fatalf("SRV calls = %v", resolver.srvCalls)
		}
	})
	t.Run("prefer tcp", func(t *testing.T) {
		resolver := &fakeDNS{srv: map[string][]*net.SRV{
			"tcp": {{Target: "kdc2.example.com.", Port: 0}},
		}}
		servers, err := discoverKDCs(testContext(t), "EXAMPLE.COM", resolver, true)
		if err != nil {
			t.Fatalf("discoverKDCs: %v", err)
		}
		if len(servers) != 1 || servers[0] != "kdc2.example.com:88" {
			t.Fatalf("servers = %v", servers)
		}
	})
	t.Run("not found", func(t *testing.T) {
		resolver := &fakeDNS{srvErr: map[string]error{
			"udp": errors.New("no such host"),
			"tcp": errors.New("no such host"),
		}}
		if _, err := discoverKDCs(testContext(t), "EXAMPLE.COM", resolver, false); !errors.Is(err, ErrKDCNotFound) {
			t.Fatalf("discoverKDCs error = %v, want ErrKDCNotFound", err)
		}
	})
}

// TestDiscoverRealm covers TXT realm discovery. | TestDiscoverRealm 覆盖 TXT realm 发现。
func TestDiscoverRealm(t *testing.T) {
	resolver := &fakeDNS{txt: map[string][]string{
		"_kerberos.host.example.com": {` "example.com" `},
	}}
	realm, err := discoverRealm(testContext(t), "host.example.com.", resolver)
	if err != nil {
		t.Fatalf("discoverRealm: %v", err)
	}
	if realm != "EXAMPLE.COM" {
		t.Fatalf("realm = %q, want EXAMPLE.COM", realm)
	}
	if len(resolver.txtCalls) != 1 || resolver.txtCalls[0] != "_kerberos.host.example.com" {
		t.Fatalf("TXT calls = %v", resolver.txtCalls)
	}
	if _, err := discoverRealm(testContext(t), "", resolver); !errors.Is(err, ErrRealmNotFound) {
		t.Fatalf("empty host error = %v, want ErrRealmNotFound", err)
	}
	broken := &fakeDNS{txtErr: errors.New("lookup failed")}
	if _, err := discoverRealm(testContext(t), "host.example.com", broken); !errors.Is(err, ErrRealmNotFound) {
		t.Fatalf("lookup error = %v, want ErrRealmNotFound", err)
	}
	missing := &fakeDNS{txt: map[string][]string{"_kerberos.host.example.com": {"  "}}}
	if _, err := discoverRealm(testContext(t), "host.example.com", missing); !errors.Is(err, ErrRealmNotFound) {
		t.Fatalf("empty TXT error = %v, want ErrRealmNotFound", err)
	}
}
