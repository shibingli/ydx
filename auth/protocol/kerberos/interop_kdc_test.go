//go:build interopkdc

package kerberos

import (
	"bytes"
	"context"
	"os"
	"testing"
	"time"
)

const (
	// interopRealm is the realm of the MIT KDC test database. | interopRealm 是 MIT KDC
	// 测试数据库的 realm。
	interopRealm = "EXAMPLE.COM"
	// interopClient is the client principal created in the test database. | interopClient
	// 是测试数据库中创建的客户端主体。
	interopClient = "alice@EXAMPLE.COM"
	// interopPassword is an obvious fixed test password, never a real secret. |
	// interopPassword 是明显的固定测试口令，绝非真实密钥。
	interopPassword = "Alice-Test-Password-1"
	// interopService is the service principal created in the test database. | interopService
	// 是测试数据库中创建的服务主体。
	interopService = "ldap/dc1.example.com"
)

// interopEndpoint reads the opt-in KDC and keytab settings. | interopEndpoint 读取
// 可选启用的 KDC 与 keytab 设置。
func interopEndpoint(t *testing.T) (string, string) {
	t.Helper()
	kdc := os.Getenv("YDX_KERBEROS_INTEROP_KDC")
	keytab := os.Getenv("YDX_KERBEROS_INTEROP_KEYTAB")
	if kdc == "" || keytab == "" {
		t.Fatal("set YDX_KERBEROS_INTEROP_KDC and YDX_KERBEROS_INTEROP_KEYTAB to run the MIT KDC interop test")
	}
	return kdc, keytab
}

// interopContext bounds one interop exchange. | interopContext 限制一次互操作交换。
func interopContext(t *testing.T) context.Context {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	t.Cleanup(cancel)
	return ctx
}

// TestInteropMITKDC exchanges real Kerberos messages with a MIT KDC: AS-REQ
// pre-authentication with string2key, TGS-REQ, AP-REQ/AP-REP with mutual
// authentication and channel bindings, SPNEGO, and per-message protection. |
// TestInteropMITKDC 与 MIT KDC 交换真实 Kerberos 消息：使用 string2key 的 AS-REQ
// 预认证、TGS-REQ、带双向认证与通道绑定的 AP-REQ/AP-REP、SPNEGO 以及每消息保护。
func TestInteropMITKDC(t *testing.T) {
	kdc, keytabPath := interopEndpoint(t)
	data, err := os.ReadFile(keytabPath)
	if err != nil {
		t.Fatalf("read keytab: %v", err)
	}
	table, err := ParseKeyTab(data)
	if err != nil {
		t.Fatalf("ParseKeyTab: %v", err)
	}
	entries := table.Entries()
	if len(entries) == 0 {
		t.Fatal("keytab has no entries")
	}
	wantService := NewPrincipalName(NameTypePrincipal, "ldap", "dc1.example.com")
	for _, entry := range entries {
		if entry.Realm != interopRealm || !entry.Principal.Equal(wantService) {
			t.Fatalf("keytab entry principal = %s@%s, want %s@%s", entry.Principal.String(), entry.Realm, wantService.String(), interopRealm)
		}
		if entry.KVNO != 2 {
			t.Fatalf("keytab entry kvno = %d, want 2", entry.KVNO)
		}
		if entry.Key.KeyType != ETypeAES256CTS && entry.Key.KeyType != ETypeAES128CTS {
			t.Fatalf("keytab entry enctype = %d, want AES256 or AES128", entry.Key.KeyType)
		}
	}
	client, err := NewClient(Config{
		KDC:        []string{kdc},
		Realm:      interopRealm,
		Principal:  interopClient,
		Password:   interopPassword,
		ETypes:     []int32{ETypeAES256CTS, ETypeAES128CTS},
		PreferTCP:  true,
		DisableDNS: true,
	})
	if err != nil {
		t.Fatalf("NewClient: %v", err)
	}
	session, err := client.Login(interopContext(t))
	if err != nil {
		t.Fatalf("Login: %v", err)
	}
	if session.ClientRealm != interopRealm || session.ClientPrincipal.String() != "alice" {
		t.Fatalf("session client = %s@%s, want alice@%s", session.ClientPrincipal.String(), session.ClientRealm, interopRealm)
	}
	if session.SessionKey.KeyType != ETypeAES256CTS && session.SessionKey.KeyType != ETypeAES128CTS {
		t.Fatalf("TGT session key enctype = %d", session.SessionKey.KeyType)
	}
	if len(session.TGT.EncPart.Cipher) == 0 {
		t.Fatal("TGT is empty")
	}
	binding := []byte("0123456789abcdef")
	acceptor, err := NewAcceptor(AcceptorOptions{
		KeyTab:                 table,
		Service:                interopService,
		Realm:                  interopRealm,
		RequireChannelBindings: true,
		ChannelBindings:        binding,
	})
	if err != nil {
		t.Fatalf("NewAcceptor: %v", err)
	}
	runInteropGSS(t, client, acceptor, binding, false)
	runInteropGSS(t, client, acceptor, binding, true)
	ticket, err := client.GetServiceTicket(interopContext(t), interopService+"@"+interopRealm)
	if err != nil {
		t.Fatalf("GetServiceTicket: %v", err)
	}
	if ticket.ServiceRealm != interopRealm || !equalPrincipalComponents(ticket.ServicePrincipal, wantService) {
		t.Fatalf("service ticket = %s@%s", ticket.ServicePrincipal.String(), ticket.ServiceRealm)
	}
	if len(ticket.Ticket.EncPart.Cipher) == 0 {
		t.Fatal("service ticket is empty")
	}
}

// runInteropGSS performs one mutual GSS exchange and checks both directions of
// wrap and MIC protection. | runInteropGSS 执行一次双向 GSS 交换，并校验两个方向的
// 封装与 MIC 保护。
func runInteropGSS(t *testing.T, client *Client, acceptor *Acceptor, binding []byte, spnego bool) {
	t.Helper()
	initiator, err := NewGSSClient(GSSClientOptions{
		Client:          client,
		Service:         interopService,
		ServiceRealm:    interopRealm,
		MutualAuth:      true,
		SPNEGO:          spnego,
		ChannelBindings: binding,
	})
	if err != nil {
		t.Fatalf("NewGSSClient: %v", err)
	}
	initial, err := initiator.InitialToken(interopContext(t))
	if err != nil {
		t.Fatalf("InitialToken: %v", err)
	}
	response, accepted, err := acceptor.Accept(initial)
	if err != nil {
		t.Fatalf("Accept: %v", err)
	}
	if len(response) == 0 {
		t.Fatal("acceptor returned no AP-REP token")
	}
	if accepted == nil || !accepted.MutualAuth {
		t.Fatal("acceptor session is not mutually authenticated")
	}
	if accepted.ClientRealm != interopRealm || accepted.ClientPrincipal.String() != "alice" {
		t.Fatalf("accepted client = %s@%s", accepted.ClientPrincipal.String(), accepted.ClientRealm)
	}
	reply, done, err := initiator.Step(interopContext(t), response)
	if err != nil {
		t.Fatalf("Step: %v", err)
	}
	if !done || len(reply) != 0 || !initiator.Complete() {
		t.Fatalf("context completion: done = %v, reply = %d bytes, complete = %v", done, len(reply), initiator.Complete())
	}
	clientData := []byte("interop client payload")
	token, err := initiator.Wrap(clientData, true)
	if err != nil {
		t.Fatalf("initiator Wrap: %v", err)
	}
	plain, confidential, err := accepted.Unwrap(token)
	if err != nil {
		t.Fatalf("acceptor Unwrap: %v", err)
	}
	if !confidential || !bytes.Equal(plain, clientData) {
		t.Fatalf("acceptor Unwrap = %q/%v", plain, confidential)
	}
	serverData := []byte("interop server payload")
	token, err = accepted.Wrap(serverData, false)
	if err != nil {
		t.Fatalf("acceptor Wrap: %v", err)
	}
	plain, confidential, err = initiator.Unwrap(token)
	if err != nil {
		t.Fatalf("initiator Unwrap: %v", err)
	}
	if confidential || !bytes.Equal(plain, serverData) {
		t.Fatalf("initiator Unwrap = %q/%v", plain, confidential)
	}
	clientMIC, err := initiator.MIC(clientData)
	if err != nil {
		t.Fatalf("initiator MIC: %v", err)
	}
	if err := accepted.VerifyMIC(clientData, clientMIC); err != nil {
		t.Fatalf("acceptor VerifyMIC: %v", err)
	}
	serverMIC, err := accepted.MIC(serverData)
	if err != nil {
		t.Fatalf("acceptor MIC: %v", err)
	}
	if err := initiator.VerifyMIC(serverData, serverMIC); err != nil {
		t.Fatalf("initiator VerifyMIC: %v", err)
	}
}
