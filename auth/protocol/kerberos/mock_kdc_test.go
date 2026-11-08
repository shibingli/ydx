package kerberos

import (
	"context"
	"crypto/subtle"
	"encoding/binary"
	"fmt"
	"io"
	"net"
	"sync"
	"testing"
	"time"

	"github.com/shibingli/ydx/errs"
)

// mockKDCOptions configures the in-memory KDC used by client and GSS tests. |
// mockKDCOptions 配置客户端与 GSS 测试使用的内存 KDC。
type mockKDCOptions struct {
	realm              string
	clientPrincipal    string
	servicePrincipal   string
	password           string
	clientKey          *EncryptionKey
	clientKVNO         int32
	krbtgtKey          EncryptionKey
	serviceKey         EncryptionKey
	serviceKVNO        int32
	requirePreAuth     bool
	sendHints          bool
	hintSalt           string
	hintIterations     int
	forceError         int32
	forceTGSError      int32
	forceUDPTooBig     bool
	issueKVNO          int32
	ticketLifetime     time.Duration
	clientNameMismatch bool
	serviceFlags       TicketFlags
}

// mockKDC is a UDP and TCP KDC implementing the AS and TGS exchanges needed by
// the package tests. | mockKDC 是实现包测试所需 AS 与 TGS 交换的 UDP/TCP KDC。
type mockKDC struct {
	opts mockKDCOptions

	tcp            net.Listener
	udp            net.PacketConn
	addr           string
	wg             sync.WaitGroup
	closeOnce      sync.Once
	mu             sync.Mutex
	failures       []string
	asRequests     int
	tgsRequests    int
	udpRequests    int
	tcpConnections int
}

// startMockKDC starts a mock KDC on one loopback port for UDP and TCP. |
// startMockKDC 在一个回环端口上启动同时服务 UDP 与 TCP 的模拟 KDC。
func startMockKDC(t *testing.T, opts mockKDCOptions) *mockKDC {
	t.Helper()
	if opts.realm == "" {
		opts.realm = "EXAMPLE.COM"
	}
	if opts.clientPrincipal == "" {
		opts.clientPrincipal = "alice"
	}
	if opts.clientKVNO == 0 {
		opts.clientKVNO = 1
	}
	if opts.serviceKVNO == 0 {
		opts.serviceKVNO = 1
	}
	if opts.servicePrincipal == "" {
		opts.servicePrincipal = "ldap/dc1.example.com"
	}
	if opts.hintIterations == 0 {
		opts.hintIterations = DefaultStringToKeyIterations
	}
	if opts.krbtgtKey.KeyType == 0 {
		key, err := randomKey(ETypeAES256CTS)
		if err != nil {
			t.Fatalf("mock KDC krbtgt key: %v", err)
		}
		opts.krbtgtKey = key
	}
	if opts.serviceKey.KeyType == 0 {
		key, err := randomKey(ETypeAES256CTS)
		if err != nil {
			t.Fatalf("mock KDC service key: %v", err)
		}
		opts.serviceKey = key
	}
	if opts.issueKVNO == 0 {
		opts.issueKVNO = opts.serviceKVNO
	}
	if opts.ticketLifetime == 0 {
		opts.ticketLifetime = 10 * time.Hour
	}
	var (
		listener net.Listener
		packet   net.PacketConn
	)
	// Windows reserves broad UDP port ranges (Hyper-V, NAT), and an ephemeral TCP port inside one
	// cannot be paired with UDP. Retrying enough candidates crosses those ranges deterministically. |
	// Windows 会保留大段 UDP 端口（Hyper-V/NAT），落在其中的临时 TCP 端口无法配对 UDP。通过足够多的
	// 候选端口重试可确定性地跨过这些区间。
	for attempt := 0; attempt < 1024; attempt++ {
		tcp, err := net.Listen("tcp", "127.0.0.1:0")
		if err != nil {
			continue
		}
		udp, err := net.ListenPacket("udp", tcp.Addr().String())
		if err != nil {
			_ = tcp.Close()
			continue
		}
		listener, packet = tcp, udp
		break
	}
	if listener == nil || packet == nil {
		t.Fatal("mock KDC could not bind a shared TCP/UDP loopback port | mock KDC 无法绑定共享的 TCP/UDP 回环端口")
	}
	server := &mockKDC{opts: opts, tcp: listener, udp: packet, addr: listener.Addr().String()}
	server.wg.Add(2)
	go server.serveUDP()
	go server.serveTCP()
	t.Cleanup(server.Close)
	return server
}

// Addr returns the KDC host:port. | Addr 返回 KDC 的 host:port。
func (m *mockKDC) Addr() string { return m.addr }

// Close stops both listeners and waits for their goroutines. | Close 停止两个监听器并等待
// 其协程退出。
func (m *mockKDC) Close() {
	if m == nil {
		return
	}
	m.closeOnce.Do(func() {
		_ = m.tcp.Close()
		_ = m.udp.Close()
		m.wg.Wait()
	})
}

// serveUDP answers datagrams until the socket closes. | serveUDP 在套接字关闭前应答数据报。
func (m *mockKDC) serveUDP() {
	defer m.wg.Done()
	buffer := make([]byte, 64<<10)
	for {
		n, remote, err := m.udp.ReadFrom(buffer)
		if err != nil {
			return
		}
		request := append([]byte(nil), buffer[:n]...)
		m.mu.Lock()
		m.udpRequests++
		m.mu.Unlock()
		if m.opts.forceUDPTooBig {
			if reply := m.errorReply(52, nil); len(reply) > 0 {
				_, _ = m.udp.WriteTo(reply, remote)
			}
			continue
		}
		reply := m.handle(request)
		if len(reply) > 0 {
			_, _ = m.udp.WriteTo(reply, remote)
		}
	}
}

// serveTCP accepts length-framed requests until the listener closes. | serveTCP 在监听器
// 关闭前接受带长度帧的请求。
func (m *mockKDC) serveTCP() {
	defer m.wg.Done()
	for {
		conn, err := m.tcp.Accept()
		if err != nil {
			return
		}
		m.mu.Lock()
		m.tcpConnections++
		m.mu.Unlock()
		m.wg.Add(1)
		go func(conn net.Conn) {
			defer m.wg.Done()
			defer conn.Close()
			_ = conn.SetDeadline(time.Now().Add(10 * time.Second))
			for {
				var header [4]byte
				if _, err := io.ReadFull(conn, header[:]); err != nil {
					return
				}
				size := binary.BigEndian.Uint32(header[:])
				if size == 0 || size > 1<<20 {
					m.fail("TCP request size %d", size)
					return
				}
				request := make([]byte, int(size))
				if _, err := io.ReadFull(conn, request); err != nil {
					m.fail("TCP request read: %v", err)
					return
				}
				reply := m.handle(request)
				if len(reply) == 0 {
					return
				}
				frame := make([]byte, 4+len(reply))
				binary.BigEndian.PutUint32(frame, uint32(len(reply)))
				copy(frame[4:], reply)
				if _, err := conn.Write(frame); err != nil {
					return
				}
			}
		}(conn)
	}
}

// fail records a server-side protocol failure. | fail 记录服务端协议故障。
func (m *mockKDC) fail(format string, args ...any) {
	m.mu.Lock()
	m.failures = append(m.failures, fmt.Sprintf(format, args...))
	m.mu.Unlock()
}

// check fails the test when the mock KDC recorded a protocol error. | check 在模拟 KDC
// 记录了协议错误时让测试失败。
func (m *mockKDC) check(t *testing.T) {
	t.Helper()
	m.mu.Lock()
	defer m.mu.Unlock()
	if len(m.failures) > 0 {
		t.Fatalf("mock KDC failures: %v", m.failures)
	}
}

// counts returns the observed AS and TGS request counts. | counts 返回观察到的 AS 与 TGS
// 请求数。
func (m *mockKDC) counts() (int, int) {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.asRequests, m.tgsRequests
}

// transportCounts returns observed UDP requests and TCP connections. |
// transportCounts 返回观察到的 UDP 请求与 TCP 连接数。
func (m *mockKDC) transportCounts() (int, int) {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.udpRequests, m.tcpConnections
}

// handle dispatches one KDC request. | handle 分派一条 KDC 请求。
func (m *mockKDC) handle(request []byte) []byte {
	if len(request) == 0 {
		m.fail("empty KDC request")
		return nil
	}
	switch request[0] {
	case 0x6A:
		m.mu.Lock()
		m.asRequests++
		m.mu.Unlock()
		return m.handleAS(request)
	case 0x6C:
		m.mu.Lock()
		m.tgsRequests++
		m.mu.Unlock()
		return m.handleTGS(request)
	default:
		m.fail("unexpected KDC request tag 0x%02x", request[0])
		return m.errorReply(60, nil)
	}
}

// errorReply builds a KRB-ERROR for the mock realm. | errorReply 为模拟 realm 构建 KRB-ERROR。
func (m *mockKDC) errorReply(code int32, edata []byte) []byte {
	now := time.Now().UTC()
	reply := KRBError{
		STime:     NewKerberosTime(now),
		SUSec:     kerberosUSec(now),
		ErrorCode: code,
		Realm:     m.opts.realm,
		SName:     NewPrincipalName(NameTypeSRVInst, "krbtgt", m.opts.realm),
		EData:     edata,
	}
	data, err := reply.Marshal()
	if err != nil {
		m.fail("KRB-ERROR marshal: %v", err)
		return nil
	}
	return data
}

// effectiveSalt returns the salt the mock uses for password-derived keys. | effectiveSalt
// 返回模拟 KDC 为口令派生密钥使用的盐。
func (m *mockKDC) effectiveSalt() string {
	if m.opts.hintSalt != "" {
		return m.opts.hintSalt
	}
	return defaultSaltFor(m.opts.realm, NewPrincipalName(NameTypePrincipal, m.opts.clientPrincipal))
}

// clientLongTermKey returns the client key for etype. | clientLongTermKey 返回客户端在
// etype 下的长期密钥。
func (m *mockKDC) clientLongTermKey(etype int32) (EncryptionKey, error) {
	if m.opts.clientKey != nil {
		if m.opts.clientKey.KeyType != etype {
			return EncryptionKey{}, errsDetail("client key etype %d, want %d", m.opts.clientKey.KeyType, etype)
		}
		return *m.opts.clientKey, nil
	}
	value, err := StringToKey(m.opts.password, m.effectiveSalt(), m.opts.hintIterations, etype)
	if err != nil {
		return EncryptionKey{}, err
	}
	return EncryptionKey{KeyType: etype, KeyValue: value}, nil
}

// preAuthHints builds METHOD-DATA carrying PA-ETYPE-INFO2. | preAuthHints 构建携带
// PA-ETYPE-INFO2 的 METHOD-DATA。
func (m *mockKDC) preAuthHints(etypes []int32) []byte {
	entries := make([][]byte, 0, len(etypes))
	for _, etype := range etypes {
		parts := [][]byte{appendIntContext(nil, 0, etype)}
		if m.opts.sendHints {
			parts = append(parts, appendStringContext(nil, 1, m.effectiveSalt()))
			params := make([]byte, 4)
			binary.BigEndian.PutUint32(params, uint32(m.opts.hintIterations))
			parts = append(parts, appendOctetsContext(nil, 2, params))
		}
		entries = append(entries, derAppendSequence(nil, parts...))
	}
	return encodePADataSequence([]PAData{{
		PADataType:  PADataTypeETypeInfo2,
		PADataValue: derAppendSequence(nil, entries...),
	}})
}

// supportedFromRequest selects the first supported encryption type offered by a
// request. | supportedFromRequest 选择请求提供的第一种受支持加密类型。
func supportedFromRequest(etypes []int32) (int32, bool) {
	for _, etype := range etypes {
		switch etype {
		case ETypeAES128CTS, ETypeAES256CTS, ETypeRC4HMAC:
			return etype, true
		}
	}
	return 0, false
}

// handleAS implements the AS exchange with an optional pre-authentication
// challenge. | handleAS 实现带可选预认证挑战的 AS 交换。
func (m *mockKDC) handleAS(request []byte) []byte {
	if m.opts.forceError != 0 {
		return m.errorReply(m.opts.forceError, nil)
	}
	req, err := ParseASReq(request)
	if err != nil {
		m.fail("AS-REQ parse: %v", err)
		return m.errorReply(60, nil)
	}
	wantClient := NewPrincipalName(NameTypePrincipal, m.opts.clientPrincipal)
	wantServer := NewPrincipalName(NameTypeSRVInst, "krbtgt", m.opts.realm)
	if req.Body.Realm != m.opts.realm ||
		(req.Body.CName != nil && !equalPrincipalComponents(*req.Body.CName, wantClient)) ||
		req.Body.SName == nil || !equalPrincipalComponents(*req.Body.SName, wantServer) {
		return m.errorReply(6, nil)
	}
	etype, ok := supportedFromRequest(req.Body.ETypes)
	if !ok {
		return m.errorReply(14, nil)
	}
	paType := etype
	var clientKey EncryptionKey
	seenPreAuth := false
	for _, pa := range req.PAData {
		if pa.PADataType != PADataTypeEncTimestamp {
			continue
		}
		encrypted, err := parseEncryptedData(pa.PADataValue)
		if err != nil {
			m.fail("PA-ENC-TIMESTAMP parse: %v", err)
			return m.errorReply(60, nil)
		}
		clientKey, err = m.clientLongTermKey(encrypted.EType)
		if err != nil {
			return m.errorReply(24, nil)
		}
		plain, err := DecryptMessage(encrypted.EType, clientKey.KeyValue, 1, encrypted.Cipher)
		if err != nil {
			return m.errorReply(24, nil)
		}
		timestamp, err := parsePAEncTSEnc(plain)
		if err != nil {
			return m.errorReply(24, nil)
		}
		if delta := time.Since(timestamp.PATimestamp.Time); delta < -5*time.Minute || delta > 5*time.Minute {
			return m.errorReply(37, nil)
		}
		paType = encrypted.EType
		seenPreAuth = true
		break
	}
	if m.opts.requirePreAuth && !seenPreAuth {
		return m.errorReply(25, m.preAuthHints(req.Body.ETypes))
	}
	if !seenPreAuth {
		clientKey, err = m.clientLongTermKey(paType)
		if err != nil {
			return m.errorReply(24, nil)
		}
	}
	now := time.Now().UTC()
	authTime := NewKerberosTime(now)
	start := NewKerberosTime(now.Add(-time.Minute))
	end := NewKerberosTime(now.Add(m.opts.ticketLifetime))
	renew := NewKerberosTime(now.Add(24 * time.Hour))
	sessionKey, err := randomKey(etype)
	if err != nil {
		m.fail("session key: %v", err)
		return m.errorReply(60, nil)
	}
	flags := TicketFlagForwardable | TicketFlagRenewable | TicketFlagPreAuthent
	krbtgt := NewPrincipalName(NameTypeSRVInst, "krbtgt", m.opts.realm)
	tgt, err := m.issueTicket(krbtgt, sessionKey, wantClient, flags, authTime, start, end, renew, m.opts.krbtgtKey, 0)
	if err != nil {
		m.fail("TGT issue: %v", err)
		return m.errorReply(60, nil)
	}
	repPart := EncKDCRepPart{
		Key:       sessionKey,
		LastReq:   []LastReq{{LRType: 0, LRValue: authTime}},
		Nonce:     req.Body.Nonce,
		Flags:     flags,
		AuthTime:  authTime,
		StartTime: &start,
		EndTime:   end,
		RenewTill: &renew,
		SRealm:    m.opts.realm,
		SName:     krbtgt,
	}
	plain := appendEncKDCRepPart(repPart, 25)
	cipher, err := EncryptMessage(clientKey.KeyType, clientKey.KeyValue, 3, plain)
	if err != nil {
		m.fail("AS-REP encryption: %v", err)
		return m.errorReply(60, nil)
	}
	reply, err := marshalKDCRep(MessageTypeASRep, nil, m.opts.realm, wantClient, tgt,
		EncryptedData{EType: clientKey.KeyType, KVNO: m.opts.clientKVNO, Cipher: cipher})
	if err != nil {
		m.fail("AS-REP marshal: %v", err)
		return m.errorReply(60, nil)
	}
	return reply
}

// issueTicket builds an encrypted ticket. | issueTicket 构建加密票据。
func (m *mockKDC) issueTicket(server PrincipalName, sessionKey EncryptionKey, client PrincipalName,
	flags TicketFlags, authTime, start, end, renew KerberosTime, key EncryptionKey, kvno int32) (Ticket, error) {
	part := EncTicketPart{
		Flags:     flags,
		Key:       sessionKey,
		CRealm:    m.opts.realm,
		CName:     client,
		Transited: TransitedEncoding{TrType: 0},
		AuthTime:  authTime,
		StartTime: &start,
		EndTime:   end,
		RenewTill: &renew,
	}
	cipher, err := EncryptMessage(key.KeyType, key.KeyValue, 2, appendEncTicketPart(part))
	if err != nil {
		return Ticket{}, err
	}
	return Ticket{
		TktVNO:  PVNO,
		Realm:   m.opts.realm,
		SName:   server,
		EncPart: EncryptedData{EType: key.KeyType, KVNO: kvno, Cipher: cipher},
	}, nil
}

// handleTGS validates PA-TGS-REQ and issues a service ticket. | handleTGS 校验
// PA-TGS-REQ 并签发服务票据。
func (m *mockKDC) handleTGS(request []byte) []byte {
	if m.opts.forceTGSError != 0 {
		return m.errorReply(m.opts.forceTGSError, nil)
	}
	if m.opts.forceError != 0 {
		return m.errorReply(m.opts.forceError, nil)
	}
	req, err := ParseTGSReq(request)
	if err != nil {
		m.fail("TGS-REQ parse: %v", err)
		return m.errorReply(60, nil)
	}
	var apReqData []byte
	for _, pa := range req.PAData {
		if pa.PADataType == PADataTypeTGSReq {
			apReqData = pa.PADataValue
			break
		}
	}
	if len(apReqData) == 0 {
		return m.errorReply(60, nil)
	}
	apReq, err := ParseAPReq(apReqData)
	if err != nil {
		m.fail("PA-TGS-REQ AP-REQ parse: %v", err)
		return m.errorReply(60, nil)
	}
	krbtgt := NewPrincipalName(NameTypeSRVInst, "krbtgt", m.opts.realm)
	if apReq.Ticket.Realm != m.opts.realm || !equalPrincipalComponents(apReq.Ticket.SName, krbtgt) {
		return m.errorReply(35, nil)
	}
	if apReq.Ticket.EncPart.EType != m.opts.krbtgtKey.KeyType {
		return m.errorReply(35, nil)
	}
	ticketPlain, err := DecryptMessage(m.opts.krbtgtKey.KeyType, m.opts.krbtgtKey.KeyValue, 2, apReq.Ticket.EncPart.Cipher)
	if err != nil {
		return m.errorReply(35, nil)
	}
	tgtPart, err := parseEncTicketPart(ticketPlain)
	if err != nil {
		m.fail("TGT decrypt: %v", err)
		return m.errorReply(60, nil)
	}
	authPlain, err := DecryptMessage(tgtPart.Key.KeyType, tgtPart.Key.KeyValue, 7, apReq.Authenticator.Cipher)
	if err != nil {
		return m.errorReply(31, nil)
	}
	authenticator, err := parseAuthenticator(authPlain)
	if err != nil {
		m.fail("TGS authenticator: %v", err)
		return m.errorReply(60, nil)
	}
	if !equalPrincipalComponents(authenticator.CName, tgtPart.CName) || authenticator.CRealm != tgtPart.CRealm {
		return m.errorReply(36, nil)
	}
	if delta := time.Since(authenticator.CTime.Time); delta < -5*time.Minute || delta > 5*time.Minute {
		return m.errorReply(37, nil)
	}
	if authenticator.Cksum == nil {
		return m.errorReply(31, nil)
	}
	wantChecksumType, err := ChecksumTypeForKey(tgtPart.Key.KeyType)
	if err != nil || authenticator.Cksum.CksumType != wantChecksumType {
		return m.errorReply(31, nil)
	}
	bodyDER := appendKDCReqBody(req.Body)
	wantChecksum, err := ChecksumMessage(tgtPart.Key.KeyType, tgtPart.Key.KeyValue, 6, bodyDER)
	if err != nil || subtle.ConstantTimeCompare(wantChecksum, authenticator.Cksum.Checksum) != 1 {
		return m.errorReply(31, nil)
	}
	if req.Body.SName == nil || !equalPrincipalComponents(*req.Body.SName, m.servicePrincipal()) {
		return m.errorReply(7, nil)
	}
	etype, ok := supportedFromRequest(req.Body.ETypes)
	if !ok {
		return m.errorReply(14, nil)
	}
	now := time.Now().UTC()
	authTime := NewKerberosTime(now)
	start := NewKerberosTime(now.Add(-time.Minute))
	end := NewKerberosTime(now.Add(m.opts.ticketLifetime))
	renew := NewKerberosTime(now.Add(24 * time.Hour))
	sessionKey, err := randomKey(etype)
	if err != nil {
		m.fail("service session key: %v", err)
		return m.errorReply(60, nil)
	}
	service := m.servicePrincipal()
	flags := TicketFlagForwardable | TicketFlagRenewable
	if m.opts.serviceFlags != 0 {
		flags = m.opts.serviceFlags
	}
	ticketClient := tgtPart.CName
	if m.opts.clientNameMismatch {
		ticketClient = NewPrincipalName(NameTypePrincipal, "mallory")
	}
	ticket, err := m.issueTicket(service, sessionKey, ticketClient, flags, authTime, start, end, renew,
		m.opts.serviceKey, m.opts.issueKVNO)
	if err != nil {
		m.fail("service ticket issue: %v", err)
		return m.errorReply(60, nil)
	}
	replyClient := tgtPart.CName
	repPart := EncKDCRepPart{
		Key:       sessionKey,
		LastReq:   []LastReq{{LRType: 0, LRValue: authTime}},
		Nonce:     req.Body.Nonce,
		Flags:     flags,
		AuthTime:  authTime,
		StartTime: &start,
		EndTime:   end,
		RenewTill: &renew,
		SRealm:    m.opts.realm,
		SName:     service,
	}
	plain := appendEncKDCRepPart(repPart, 26)
	cipher, err := EncryptMessage(tgtPart.Key.KeyType, tgtPart.Key.KeyValue, 8, plain)
	if err != nil {
		m.fail("TGS-REP encryption: %v", err)
		return m.errorReply(60, nil)
	}
	reply, err := marshalKDCRep(MessageTypeTGSRep, nil, m.opts.realm, replyClient, ticket,
		EncryptedData{EType: tgtPart.Key.KeyType, Cipher: cipher})
	if err != nil {
		m.fail("TGS-REP marshal: %v", err)
		return m.errorReply(60, nil)
	}
	return reply
}

// servicePrincipal returns the configured service principal. | servicePrincipal 返回
// 配置的服务主体。
func (m *mockKDC) servicePrincipal() PrincipalName {
	principal, _, err := ParseServicePrincipal(m.opts.servicePrincipal, m.opts.realm)
	if err != nil {
		return NewPrincipalName(NameTypeSRVInst, "ldap", "dc1.example.com")
	}
	return principal
}

// keytab returns an acceptor keytab carrying the service key. | keytab 返回携带服务密钥的
// 接受方 keytab。
func (m *mockKDC) keytab() *KeyTab {
	return NewKeyTab([]KeyTabEntry{{
		Principal: m.servicePrincipal(),
		Realm:     m.opts.realm,
		KVNO:      m.opts.serviceKVNO,
		Key:       m.opts.serviceKey,
	}})
}

// clientKeytab returns a client keytab carrying the client long-term key. |
// clientKeytab 返回携带客户端长期密钥的客户端 keytab。
func (m *mockKDC) clientKeytab(etype int32) (*KeyTab, error) {
	key, err := m.clientLongTermKey(etype)
	if err != nil {
		return nil, err
	}
	return NewKeyTab([]KeyTabEntry{{
		Principal: NewPrincipalName(NameTypePrincipal, m.opts.clientPrincipal),
		Realm:     m.opts.realm,
		KVNO:      m.opts.clientKVNO,
		Key:       key,
	}}), nil
}

// clientConfig returns a password client configuration targeting the mock KDC. |
// clientConfig 返回指向模拟 KDC 的口令客户端配置。
func (m *mockKDC) clientConfig(etypes ...int32) Config {
	return Config{
		KDC:       []string{m.addr},
		Realm:     m.opts.realm,
		Principal: m.opts.clientPrincipal,
		Password:  m.opts.password,
		ETypes:    etypes,
		Timeout:   5 * time.Second,
	}
}

// testContext returns a bounded context for KDC tests. | testContext 返回 KDC 测试用的
// 有界上下文。
func testContext(t *testing.T) context.Context {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	t.Cleanup(cancel)
	return ctx
}

// errsDetail builds a plain classified error for mock helpers. | errsDetail 为模拟辅助
// 函数构建分类错误。
func errsDetail(format string, args ...any) error {
	return errs.Detail(ErrInvalidConfig, format, args...)
}
