package kerberos

import (
	"context"
	"crypto/rand"
	"encoding/binary"
	"net"
	"os"
	"sync"
	"time"

	"github.com/shibingli/ydx/errs"
)

// Config configures a Kerberos client. | Config 配置 Kerberos 客户端。
type Config struct {
	// KDC lists explicit KDC endpoints as host or host:port. An empty list enables
	// DNS SRV discovery. | KDC 列出显式 KDC 端点，形式为主机或 host:port。空列表启用
	// DNS SRV 发现。
	KDC []string
	// Realm is the client realm. An empty value falls back to the principal realm,
	// then to DNS TXT discovery. | Realm 是客户端 realm。空值回退到主体 realm，再回退
	// 到 DNS TXT 发现。
	Realm string
	// Principal is the client principal, optionally carrying @realm. | Principal 是
	// 客户端主体，可带 @realm。
	Principal string
	// Password is the client password. | Password 是客户端口令。
	Password string
	// KeyTab is an in-memory keytab. | KeyTab 是内存中的 keytab。
	KeyTab *KeyTab
	// KeyTabPath is a keytab file to load when KeyTab is nil. | KeyTabPath 是在 KeyTab
	// 为空时加载的 keytab 文件。
	KeyTabPath string
	// ETypes lists acceptable encryption types, most preferred first. The default is
	// aes256-cts, aes128-cts, and rc4-hmac. | ETypes 列出可接受的加密类型，优先者在前。
	// 默认是 aes256-cts、aes128-cts 与 rc4-hmac。
	ETypes []int32
	// Timeout bounds each KDC exchange. Zero selects ten seconds. | Timeout 限制每次
	// KDC 交换。零值选择十秒。
	Timeout time.Duration
	// Retries is the number of extra attempts after the first. | Retries 是首次尝试之后
	// 的额外尝试次数。
	Retries int
	// PreferTCP starts with TCP instead of UDP. | PreferTCP 以 TCP 而不是 UDP 开始。
	PreferTCP bool
	// DNSResolver overrides the resolver used for discovery. | DNSResolver 覆盖发现所用
	// 的解析器。
	DNSResolver *net.Resolver
	// DisableDNS prevents TXT realm discovery when no realm is configured. | DisableDNS
	// 阻止在未配置 realm 时进行 TXT realm 发现。
	DisableDNS bool
	// ClockSkew is the accepted clock difference for ticket and authenticator checks.
	// Zero selects five minutes. | ClockSkew 是票据与认证器检查允许的时钟差。零值选择
	// 五分钟。
	ClockSkew time.Duration
	// TicketLifetime is the requested initial ticket lifetime. Zero selects ten hours. | TicketLifetime
	// 是请求的初始票据寿命。零值选择十小时。
	TicketLifetime time.Duration
	// RenewLifetime is the requested renewable lifetime. Zero selects seven days. | RenewLifetime
	// 是请求的可续期寿命。零值选择七天。
	RenewLifetime time.Duration
}

// Session is an authenticated Kerberos client session carrying a TGT. | Session 是携带
// TGT 的已认证 Kerberos 客户端会话。
type Session struct {
	// ClientPrincipal is the authenticated client principal. | ClientPrincipal 是已认证
	// 客户端主体。
	ClientPrincipal PrincipalName
	// ClientRealm is the authenticated client realm. | ClientRealm 是已认证客户端 realm。
	ClientRealm string
	// TGT is the ticket-granting ticket. | TGT 是票据授予票据。
	TGT Ticket
	// SessionKey is the TGT session key. | SessionKey 是 TGT 会话密钥。
	SessionKey EncryptionKey
	// Flags are the TGT ticket flags. | Flags 是 TGT 票据标志。
	Flags TicketFlags
	// AuthTime is the initial authentication time. | AuthTime 是初始认证时间。
	AuthTime KerberosTime
	// StartTime is the ticket start time. | StartTime 是票据生效时间。
	StartTime KerberosTime
	// EndTime is the ticket expiry time. | EndTime 是票据过期时间。
	EndTime KerberosTime
	// RenewTill is the renewal deadline when renewable. | RenewTill 是可续期时的续期期限。
	RenewTill KerberosTime
}

// ServiceTicket is a service ticket obtained from the TGS. | ServiceTicket 是从 TGS
// 获得的服务票据。
type ServiceTicket struct {
	// ServicePrincipal is the requested service principal. | ServicePrincipal 是请求的
	// 服务主体。
	ServicePrincipal PrincipalName
	// ServiceRealm is the service realm. | ServiceRealm 是服务 realm。
	ServiceRealm string
	// Ticket is the service ticket. | Ticket 是服务票据。
	Ticket Ticket
	// SessionKey is the service session key. | SessionKey 是服务会话密钥。
	SessionKey EncryptionKey
	// ClientPrincipal is the client principal from the TGS reply. | ClientPrincipal 是
	// TGS 回复中的客户端主体。
	ClientPrincipal PrincipalName
	// ClientRealm is the client realm from the TGS reply. | ClientRealm 是 TGS 回复中的
	// 客户端 realm。
	ClientRealm string
	// Flags are the service ticket flags. | Flags 是服务票据标志。
	Flags TicketFlags
	// AuthTime is the authentication time. | AuthTime 是认证时间。
	AuthTime KerberosTime
	// StartTime is the ticket start time. | StartTime 是票据生效时间。
	StartTime KerberosTime
	// EndTime is the ticket expiry time. | EndTime 是票据过期时间。
	EndTime KerberosTime
	// RenewTill is the renewal deadline when renewable. | RenewTill 是可续期时的续期期限。
	RenewTill KerberosTime
}

// Client is a Kerberos V5 client. It is safe for concurrent use. | Client 是 Kerberos V5
// 客户端。它可以安全并发使用。
type Client struct {
	cfg         Config
	credentials *Credentials
	eTypes      []int32
	clockSkew   time.Duration
	lifetime    time.Duration
	renew       time.Duration
	now         func() time.Time

	mu        sync.Mutex
	realm     string
	transport *kdcTransport
	session   *Session
	loginMu   sync.Mutex
}

// NewClient validates cfg and builds a client. | NewClient 校验 cfg 并构建客户端。
func NewClient(cfg Config) (*Client, error) {
	if cfg.KeyTab != nil && cfg.KeyTabPath != "" {
		return nil, errs.Detail(ErrInvalidConfig, "KeyTab and KeyTabPath are mutually exclusive | KeyTab 与 KeyTabPath 互斥")
	}
	if cfg.Password != "" && (cfg.KeyTab != nil || cfg.KeyTabPath != "") {
		return nil, errs.Detail(ErrInvalidConfig, "password and keytab credentials are mutually exclusive | 口令与 keytab 凭据互斥")
	}
	if cfg.Password == "" && cfg.KeyTab == nil && cfg.KeyTabPath == "" {
		return nil, errs.Detail(ErrInvalidConfig, "no password or keytab credentials | 没有口令或 keytab 凭据")
	}
	keyTab := cfg.KeyTab
	if cfg.KeyTabPath != "" {
		loaded, err := ReadKeyTabFile(cfg.KeyTabPath)
		if err != nil {
			return nil, err
		}
		keyTab = loaded
	}
	var credentials *Credentials
	var err error
	if cfg.Password != "" {
		credentials, err = NewPasswordCredentials(cfg.Principal, cfg.Realm, cfg.Password)
	} else {
		credentials, err = NewKeyTabCredentials(cfg.Principal, cfg.Realm, keyTab)
	}
	if err != nil {
		return nil, err
	}
	if credentials.Realm != "" && cfg.Realm != "" && credentials.Realm != cfg.Realm {
		return nil, errs.Detail(ErrInvalidConfig, "principal realm %s differs from configured realm %s | 主体 realm %s 与配置 realm %s 不同",
			credentials.Realm, cfg.Realm, credentials.Realm, cfg.Realm)
	}
	eTypes, err := normalizeETypes(cfg.ETypes)
	if err != nil {
		return nil, err
	}
	clockSkew := cfg.ClockSkew
	if clockSkew == 0 {
		clockSkew = 5 * time.Minute
	}
	if clockSkew < 0 {
		return nil, errs.Detail(ErrInvalidConfig, "negative clock skew | 时钟偏移为负")
	}
	lifetime := cfg.TicketLifetime
	if lifetime == 0 {
		lifetime = 10 * time.Hour
	}
	if lifetime <= 0 {
		return nil, errs.Detail(ErrInvalidConfig, "ticket lifetime must be positive | 票据寿命必须为正")
	}
	renew := cfg.RenewLifetime
	if renew == 0 {
		renew = 7 * 24 * time.Hour
	}
	if renew < lifetime {
		renew = lifetime
	}
	resolver := cfg.DNSResolver
	transport := (*kdcTransport)(nil)
	realm := cfg.Realm
	if realm == "" {
		realm = credentials.Realm
	}
	if realm != "" {
		transport = newKDCTransport(cfg.KDC, realm, cfg.Timeout, cfg.Retries, cfg.PreferTCP, resolver)
	}
	return &Client{
		cfg:         cfg,
		credentials: credentials,
		eTypes:      eTypes,
		clockSkew:   clockSkew,
		lifetime:    lifetime,
		renew:       renew,
		now:         func() time.Time { return time.Now().UTC() },
		realm:       realm,
		transport:   transport,
	}, nil
}

// normalizeETypes validates and deduplicates encryption types. | normalizeETypes 校验并
// 去重加密类型。
func normalizeETypes(values []int32) ([]int32, error) {
	if len(values) == 0 {
		return SupportedETypes(), nil
	}
	seen := make(map[int32]bool, len(values))
	out := make([]int32, 0, len(values))
	for _, value := range values {
		if _, err := KeySize(value); err != nil {
			return nil, err
		}
		if seen[value] {
			continue
		}
		seen[value] = true
		out = append(out, value)
	}
	if len(out) == 0 {
		return nil, errs.Detail(ErrInvalidConfig, "empty encryption type list | 加密类型列表为空")
	}
	return out, nil
}

// resolveRealm determines the client realm from configuration, the principal, or
// DNS TXT discovery. | resolveRealm 从配置、主体或 DNS TXT 发现确定客户端 realm。
func (c *Client) resolveRealm(ctx context.Context) (string, error) {
	c.mu.Lock()
	realm := c.realm
	c.mu.Unlock()
	if realm != "" {
		return realm, nil
	}
	if c.cfg.DisableDNS {
		return "", errs.Detail(ErrRealmNotFound, "no realm configured and DNS discovery is disabled | 未配置 realm 且 DNS 发现已禁用")
	}
	host, err := os.Hostname()
	if err != nil {
		return "", errs.WrapDetail(err, ErrRealmNotFound, "cannot determine local host for realm discovery | 无法确定本地主机以进行 realm 发现")
	}
	resolver := c.cfg.DNSResolver
	if resolver == nil {
		resolver = net.DefaultResolver
	}
	discovered, err := discoverRealm(ctx, host, resolver)
	if err != nil {
		return "", err
	}
	c.mu.Lock()
	if c.realm == "" {
		c.realm = discovered
	}
	realm = c.realm
	c.mu.Unlock()
	return realm, nil
}

// kdcTransportFor returns the transport, creating it once the realm is known. | kdcTransportFor
// 返回传输，并在已知 realm 后创建它。
func (c *Client) kdcTransportFor(ctx context.Context) (*kdcTransport, error) {
	realm, err := c.resolveRealm(ctx)
	if err != nil {
		return nil, err
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.transport == nil {
		c.transport = newKDCTransport(c.cfg.KDC, realm, c.cfg.Timeout, c.cfg.Retries, c.cfg.PreferTCP, c.cfg.DNSResolver)
	}
	return c.transport, nil
}

// Login performs an AS exchange and stores the resulting session. | Login 执行 AS 交换
// 并保存结果会话。
func (c *Client) Login(ctx context.Context) (*Session, error) {
	c.loginMu.Lock()
	defer c.loginMu.Unlock()
	return c.login(ctx)
}

// EnsureSession returns a valid session, authenticating when necessary. | EnsureSession
// 返回有效会话，必要时进行认证。
func (c *Client) EnsureSession(ctx context.Context) (*Session, error) {
	if session := c.currentSession(); session != nil && session.valid(c.now(), 30*time.Second) {
		return session, nil
	}
	c.loginMu.Lock()
	defer c.loginMu.Unlock()
	if session := c.currentSession(); session != nil && session.valid(c.now(), 30*time.Second) {
		return session, nil
	}
	return c.login(ctx)
}

// currentSession returns the stored session snapshot. | currentSession 返回已保存会话的快照。
func (c *Client) currentSession() *Session {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.session == nil {
		return nil
	}
	snapshot := *c.session
	return &snapshot
}

// valid reports whether the session can still issue service tickets. | valid 报告会话是否
// 仍可签发服务票据。
func (s *Session) valid(now time.Time, margin time.Duration) bool {
	if s == nil || len(s.SessionKey.KeyValue) == 0 {
		return false
	}
	if _, err := KeySize(s.SessionKey.KeyType); err != nil {
		return false
	}
	return s.EndTime.Time.After(now.Add(margin)) && s.TGT.TktVNO == PVNO
}

// login performs one AS exchange. | login 执行一次 AS 交换。
func (c *Client) login(ctx context.Context) (*Session, error) {
	realm, err := c.resolveRealm(ctx)
	if err != nil {
		return nil, err
	}
	nonce, err := randomUint32()
	if err != nil {
		return nil, err
	}
	now := c.now()
	till := NewKerberosTime(now.Add(c.lifetime))
	renew := NewKerberosTime(now.Add(c.renew))
	clientPrincipal := c.credentials.Principal
	tgtPrincipal := NewPrincipalName(NameTypePrincipal, "krbtgt", realm)
	body := KDCReqBody{
		KDCReqOptions: KDCOptionForwardable | KDCOptionRenewable,
		CName:         &clientPrincipal,
		Realm:         realm,
		SName:         &tgtPrincipal,
		Till:          till,
		RTime:         &renew,
		Nonce:         nonce,
		ETypes:        append([]int32(nil), c.eTypes...),
	}
	request := ASReq{Body: body}
	reply, err := c.roundTripKDC(ctx, request.Marshal)
	if err != nil {
		return nil, err
	}
	krbErr, err := kdcErrorFromReply(reply)
	if err != nil {
		return nil, err
	}
	var hints etypeHints
	if krbErr != nil {
		if krbErr.ErrorCode != 25 {
			return nil, krbErr.Err()
		}
		hints = parsePreAuthHints(krbErr.EData)
		selection, err := c.selectPreAuth(realm, hints)
		if err != nil {
			return nil, errs.WrapDetail(err, ErrPreAuthRequired, "cannot answer KDC pre-authentication challenge | 无法应答 KDC 预认证挑战")
		}
		usec := kerberosUSec(c.now())
		timestamp := PAEncTSEnc{PATimestamp: NewKerberosTime(c.now()), PAUSec: &usec}
		ciphertext, err := EncryptMessage(selection.EType, selection.Key.KeyValue, 1, marshalPAEncTSEnc(timestamp))
		if err != nil {
			return nil, err
		}
		encrypted := EncryptedData{EType: selection.EType, KVNO: selection.KVNO, Cipher: ciphertext}
		request.PAData = []PAData{{
			PADataType:  PADataTypeEncTimestamp,
			PADataValue: appendEncryptedData(nil, encrypted),
		}}
		reply, err = c.roundTripKDC(ctx, request.Marshal)
		if err != nil {
			return nil, err
		}
		krbErr, err = kdcErrorFromReply(reply)
		if err != nil {
			return nil, err
		}
		if krbErr != nil {
			return nil, krbErr.Err()
		}
	}
	rep, err := ParseASRep(reply)
	if err != nil {
		return nil, err
	}
	key, err := c.responseKey(rep.EncPart.EType, rep.EncPart.KVNO, realm, hints)
	if err != nil {
		return nil, err
	}
	plain, err := DecryptMessage(rep.EncPart.EType, key.KeyValue, 3, rep.EncPart.Cipher)
	if err != nil {
		return nil, err
	}
	part, err := parseEncKDCRepPart(plain, 25)
	if err != nil {
		return nil, err
	}
	if part.Nonce != nonce {
		return nil, errs.Detail(ErrInvalidMessage, "AS-REP nonce %d does not match %d | AS-REP nonce %d 与 %d 不匹配",
			part.Nonce, nonce, part.Nonce, nonce)
	}
	if part.SRealm != realm {
		return nil, errs.Detail(ErrInvalidMessage, "AS-REP realm %s does not match %s | AS-REP realm %s 与 %s 不匹配",
			part.SRealm, realm, part.SRealm, realm)
	}
	if len(part.SName.NameString) != 2 || part.SName.NameString[0] != "krbtgt" || part.SName.NameString[1] != realm {
		return nil, errs.Detail(ErrInvalidMessage, "AS-REP server is not krbtgt/%s | AS-REP 服务端不是 krbtgt/%s", realm, realm)
	}
	if rep.CRealm != realm || !equalPrincipalComponents(rep.CName, clientPrincipal) {
		return nil, errs.Detail(ErrInvalidMessage, "AS-REP client %s@%s does not match %s@%s | AS-REP 客户端 %s@%s 与 %s@%s 不匹配",
			rep.CName.String(), rep.CRealm, clientPrincipal.String(), realm,
			rep.CName.String(), rep.CRealm, clientPrincipal.String(), realm)
	}
	if _, err := KeySize(part.Key.KeyType); err != nil {
		return nil, err
	}
	if err := validateTimes(part.AuthTime, part.StartTime, part.EndTime, c.now(), c.clockSkew); err != nil {
		return nil, err
	}
	session := &Session{
		ClientPrincipal: clientPrincipal,
		ClientRealm:     realm,
		TGT:             rep.Ticket,
		SessionKey:      part.Key,
		Flags:           part.Flags,
		AuthTime:        part.AuthTime,
		StartTime:       timeOr(part.StartTime, part.AuthTime),
		EndTime:         part.EndTime,
		RenewTill:       timeValue(part.RenewTill),
	}
	c.mu.Lock()
	c.session = session
	c.mu.Unlock()
	snapshot := *session
	return &snapshot, nil
}

// GetServiceTicket requests a service ticket for service. The service name may
// carry an explicit realm. | GetServiceTicket 为 service 请求服务票据。服务名可携带
// 显式 realm。
func (c *Client) GetServiceTicket(ctx context.Context, service string) (*ServiceTicket, error) {
	session, err := c.EnsureSession(ctx)
	if err != nil {
		return nil, err
	}
	spn, spnRealm, err := ParseServicePrincipal(service, session.ClientRealm)
	if err != nil {
		return nil, err
	}
	if spnRealm == "" {
		return nil, errs.Detail(ErrInvalidConfig, "service principal %q has no realm | 服务主体 %q 没有 realm", service, service)
	}
	if _, err := KeySize(session.SessionKey.KeyType); err != nil {
		return nil, err
	}
	nonce, err := randomUint32()
	if err != nil {
		return nil, err
	}
	options := KDCOptions(0)
	if session.Flags.Has(TicketFlagForwardable) {
		options.Set(KDCOptionForwardable)
	}
	now := c.now()
	body := KDCReqBody{
		KDCReqOptions: options,
		Realm:         spnRealm,
		SName:         &spn,
		Till:          NewKerberosTime(now.Add(c.lifetime)),
		Nonce:         nonce,
		ETypes:        append([]int32(nil), c.eTypes...),
	}
	bodyDER := appendKDCReqBody(body)
	checksumType, err := ChecksumTypeForKey(session.SessionKey.KeyType)
	if err != nil {
		return nil, err
	}
	checksum, err := ChecksumMessage(session.SessionKey.KeyType, session.SessionKey.KeyValue, 6, bodyDER)
	if err != nil {
		return nil, err
	}
	usec := kerberosUSec(now)
	authenticator := Authenticator{
		AuthenticatorVNO: PVNO,
		CRealm:           session.ClientRealm,
		CName:            session.ClientPrincipal,
		Cksum:            &Checksum{CksumType: checksumType, Checksum: checksum},
		CUSec:            usec,
		CTime:            NewKerberosTime(now),
	}
	encryptedAuthenticator, err := encryptAuthenticator(authenticator, session.SessionKey, 7)
	if err != nil {
		return nil, err
	}
	apReq := APReq{
		PVNO:          PVNO,
		MsgType:       MessageTypeAPReq,
		APOptions:     0,
		Ticket:        session.TGT,
		Authenticator: encryptedAuthenticator,
	}
	apReqData, err := apReq.Marshal()
	if err != nil {
		return nil, err
	}
	request := TGSReq{
		PAData: []PAData{{PADataType: PADataTypeTGSReq, PADataValue: apReqData}},
		Body:   body,
	}
	reply, err := c.roundTripKDC(ctx, request.Marshal)
	if err != nil {
		return nil, err
	}
	krbErr, err := kdcErrorFromReply(reply)
	if err != nil {
		return nil, err
	}
	if krbErr != nil {
		return nil, krbErr.Err()
	}
	rep, err := ParseTGSRep(reply)
	if err != nil {
		return nil, err
	}
	plain, err := DecryptMessage(session.SessionKey.KeyType, session.SessionKey.KeyValue, 8, rep.EncPart.Cipher)
	if err != nil {
		return nil, err
	}
	part, err := parseEncKDCRepPart(plain, 26)
	if err != nil {
		return nil, err
	}
	if part.Nonce != nonce {
		return nil, errs.Detail(ErrInvalidMessage, "TGS-REP nonce %d does not match %d | TGS-REP nonce %d 与 %d 不匹配",
			part.Nonce, nonce, part.Nonce, nonce)
	}
	if part.SRealm != spnRealm || !equalPrincipalComponents(part.SName, spn) {
		return nil, errs.Detail(ErrInvalidMessage, "TGS-REP server %s@%s does not match %s@%s | TGS-REP 服务端 %s@%s 与 %s@%s 不匹配",
			part.SName.String(), part.SRealm, spn.String(), spnRealm, part.SName.String(), part.SRealm, spn.String(), spnRealm)
	}
	if _, err := KeySize(part.Key.KeyType); err != nil {
		return nil, err
	}
	if err := validateTimes(part.AuthTime, part.StartTime, part.EndTime, c.now(), c.clockSkew); err != nil {
		return nil, err
	}
	ticket := &ServiceTicket{
		ServicePrincipal: spn,
		ServiceRealm:     spnRealm,
		Ticket:           rep.Ticket,
		SessionKey:       part.Key,
		ClientPrincipal:  session.ClientPrincipal,
		ClientRealm:      session.ClientRealm,
		Flags:            part.Flags,
		AuthTime:         part.AuthTime,
		StartTime:        timeOr(part.StartTime, part.AuthTime),
		EndTime:          part.EndTime,
		RenewTill:        timeValue(part.RenewTill),
	}
	return ticket, nil
}

// roundTripKDC marshals a request and exchanges it with the KDC. | roundTripKDC 编组请求
// 并与 KDC 交换。
func (c *Client) roundTripKDC(ctx context.Context, marshal func() ([]byte, error)) ([]byte, error) {
	request, err := marshal()
	if err != nil {
		return nil, err
	}
	transport, err := c.kdcTransportFor(ctx)
	if err != nil {
		return nil, err
	}
	return transport.exchange(ctx, request)
}

// kdcErrorFromReply decodes a KRB-ERROR response when present. | kdcErrorFromReply 在
// 存在时解码 KRB-ERROR 响应。
func kdcErrorFromReply(reply []byte) (*KRBError, error) {
	if len(reply) == 0 || reply[0] != 0x7E {
		return nil, nil
	}
	parsed, err := ParseKRBError(reply)
	if err != nil {
		return nil, err
	}
	return &parsed, nil
}

// selectPreAuth chooses an encryption type and key for PA-ENC-TIMESTAMP. | selectPreAuth
// 为 PA-ENC-TIMESTAMP 选择加密类型与密钥。
func (c *Client) selectPreAuth(realm string, hints etypeHints) (preAuthSelection, error) {
	for _, etype := range c.eTypes {
		if len(hints.info2) > 0 {
			if _, ok := hints.info2[etype]; !ok {
				continue
			}
		}
		salt, iterations, err := hints.saltAndIterations(etype, realm, c.credentials.Principal)
		if err != nil {
			return preAuthSelection{}, err
		}
		if c.credentials.KeyTab != nil {
			entry, err := c.credentials.KeyTab.Lookup(c.credentials.Principal, realm, etype, 0)
			if err != nil {
				continue
			}
			return preAuthSelection{EType: etype, Key: entry.Key, KVNO: entry.KVNO, Salt: salt, Iterations: iterations}, nil
		}
		key, err := c.credentials.passwordKey(etype, salt, iterations)
		if err != nil {
			return preAuthSelection{}, err
		}
		return preAuthSelection{EType: etype, Key: key, Salt: salt, Iterations: iterations}, nil
	}
	return preAuthSelection{}, errs.Detail(ErrETypeNotSupported, "no mutually supported encryption type for pre-authentication | 预认证没有相互支持的加密类型")
}

// responseKey finds the key that decrypts the KDC reply encrypted part. | responseKey
// 查找解密 KDC 回复加密部分的密钥。
func (c *Client) responseKey(etype, kvno int32, realm string, hints etypeHints) (EncryptionKey, error) {
	if c.credentials.KeyTab != nil {
		entry, err := c.credentials.KeyTab.Lookup(c.credentials.Principal, realm, etype, kvno)
		if err != nil {
			return EncryptionKey{}, err
		}
		return entry.Key, nil
	}
	salt, iterations, err := hints.saltAndIterations(etype, realm, c.credentials.Principal)
	if err != nil {
		return EncryptionKey{}, err
	}
	return c.credentials.passwordKey(etype, salt, iterations)
}

// preAuthSelection records the chosen pre-authentication key. | preAuthSelection 记录
// 选定的预认证密钥。
type preAuthSelection struct {
	// EType is the selected long-term key encryption type. | EType 是选定的长期密钥加密类型。
	EType int32
	// Key is the selected long-term key. | Key 是选定的长期密钥。
	Key EncryptionKey
	// KVNO is the selected key version number, or zero when unknown. | KVNO 是选定的密钥版本号，
	// 未知时为零。
	KVNO int32
	// Salt is the string2key salt supplied by the KDC. | Salt 是 KDC 提供的 string2key 盐。
	Salt string
	// Iterations is the string2key iteration count, or zero for the default. | Iterations 是
	// string2key 迭代次数，零值表示默认。
	Iterations int
}

// etypeHints collects KDC pre-authentication salt information. | etypeHints 收集 KDC
// 预认证盐信息。
type etypeHints struct {
	info2  map[int32]ETypeInfo2Entry
	info1  map[int32]string
	pwSalt *string
}

// parsePreAuthHints extracts ETYPE-INFO2, ETYPE-INFO, and PW-SALT hints from
// METHOD-DATA. Malformed optional hints are ignored so a KDC that sends unknown
// pre-authentication data can still be tried. | parsePreAuthHints 从 METHOD-DATA 提取
// ETYPE-INFO2、ETYPE-INFO 与 PW-SALT 提示。畸形的可选提示会被忽略，以便仍能尝试发送
// 未知预认证数据的 KDC。
func parsePreAuthHints(data []byte) etypeHints {
	hints := etypeHints{info2: map[int32]ETypeInfo2Entry{}, info1: map[int32]string{}}
	if len(data) == 0 {
		return hints
	}
	padata, err := parsePADataSequence(data)
	if err != nil {
		return hints
	}
	for _, item := range padata {
		switch item.PADataType {
		case PADataTypeETypeInfo2:
			entries, err := parseETypeInfo2(item.PADataValue)
			if err != nil {
				continue
			}
			for _, entry := range entries {
				hints.info2[entry.EType] = entry
			}
		case PADataTypeETypeInfo:
			entries, err := parseETypeInfo(item.PADataValue)
			if err != nil {
				continue
			}
			for etype, salt := range entries {
				hints.info1[etype] = salt
			}
		case PADataTypePWSSalt:
			salt, err := parseKerberosString(item.PADataValue)
			if err != nil {
				continue
			}
			hints.pwSalt = &salt
		}
	}
	return hints
}

// saltAndIterations returns the salt and PBKDF2 iteration count for etype. | saltAndIterations
// 返回 etype 的盐与 PBKDF2 迭代次数。
func (h etypeHints) saltAndIterations(etype int32, realm string, principal PrincipalName) (string, int, error) {
	salt := defaultSaltFor(realm, principal)
	iterations := 0
	if entry, ok := h.info2[etype]; ok {
		if entry.Salt != nil {
			salt = *entry.Salt
		}
		parsed, err := parseS2KParams(entry.S2KParams)
		if err != nil {
			return "", 0, err
		}
		iterations = parsed
		return salt, iterations, nil
	}
	if value, ok := h.info1[etype]; ok {
		return value, 0, nil
	}
	if h.pwSalt != nil {
		return *h.pwSalt, 0, nil
	}
	return salt, iterations, nil
}

// parseS2KParams decodes the RFC 3962 four-byte iteration parameter. | parseS2KParams
// 解码 RFC 3962 四字节迭代参数。
func parseS2KParams(params []byte) (int, error) {
	if len(params) == 0 {
		return 0, nil
	}
	if len(params) != 4 {
		return 0, errs.Detail(ErrInvalidConfig, "s2kparams length %d, want 4 | s2kparams 长度 %d，期望 4", len(params), len(params))
	}
	value := binary.BigEndian.Uint32(params)
	if value == 0 {
		return 0, errs.Detail(ErrInvalidConfig, "s2kparams requests 2^32 iterations, which is not supported | s2kparams 请求 2^32 次迭代，不受支持")
	}
	const maxIterations = 1 << 24
	if value > maxIterations {
		return 0, errs.Detail(ErrInvalidConfig, "s2kparams iteration count %d exceeds %d | s2kparams 迭代次数 %d 超过 %d",
			value, maxIterations, value, maxIterations)
	}
	return int(value), nil
}

// parseETypeInfo decodes the legacy PA-ETYPE-INFO salt list. | parseETypeInfo 解码旧式
// PA-ETYPE-INFO 盐列表。
func parseETypeInfo(data []byte) (map[int32]string, error) {
	content, err := sequenceContent(data)
	if err != nil {
		return nil, err
	}
	result := map[int32]string{}
	r := newDERReader(content)
	for r.remaining() > 0 {
		entry, err := r.expect(derTagSequence)
		if err != nil {
			return nil, err
		}
		var etype int32
		var salt string
		seen := false
		er := newDERReader(entry)
		for er.remaining() > 0 {
			tag, value, err := er.next()
			if err != nil {
				return nil, err
			}
			switch tag {
			case 0xA0:
				number, err := readContextInt32(value)
				if err != nil {
					return nil, err
				}
				etype = number
				seen = true
			case 0xA1:
				salt, err = readContextString(value)
				if err != nil {
					return nil, err
				}
			default:
				return nil, errASN1("unexpected ETYPE-INFO field 0x%02x | 意外的 ETYPE-INFO 字段 0x%02x", tag, tag)
			}
		}
		if !seen {
			return nil, errASN1("ETYPE-INFO entry is missing its enctype | ETYPE-INFO 条目缺少加密类型")
		}
		result[etype] = salt
	}
	return result, nil
}

// parseKerberosString decodes a single tagged KerberosString value. | parseKerberosString
// 解码单个带标签的 KerberosString 值。
func parseKerberosString(data []byte) (string, error) {
	r := newDERReader(data)
	value, err := readString(r)
	if err != nil {
		return "", err
	}
	return value, r.end()
}

// encryptAuthenticator encodes and encrypts an Authenticator. | encryptAuthenticator
// 编码并加密 Authenticator。
func encryptAuthenticator(authenticator Authenticator, key EncryptionKey, usage uint32) (EncryptedData, error) {
	plain := appendAuthenticator(nil, authenticator)
	ciphertext, err := EncryptMessage(key.KeyType, key.KeyValue, usage, plain)
	if err != nil {
		return EncryptedData{}, err
	}
	return EncryptedData{EType: key.KeyType, KVNO: 0, Cipher: ciphertext}, nil
}

// validateTimes checks authentication and ticket validity against the clock skew. | validateTimes
// 按允许时钟偏移检查认证时间与票据有效期。
func validateTimes(authTime KerberosTime, startTime *KerberosTime, endTime KerberosTime, now time.Time, skew time.Duration) error {
	start := authTime
	if startTime != nil {
		start = *startTime
	}
	if start.IsZero() || endTime.IsZero() {
		return errs.Detail(ErrInvalidMessage, "ticket has no start or end time | 票据没有生效或过期时间")
	}
	if start.Time.After(now.Add(skew)) {
		return errs.Detail(ErrTicketNotYetValid, "ticket starts at %s, now %s | 票据于 %s 生效，当前 %s",
			start.UTC().Format(time.RFC3339), now.Format(time.RFC3339), start.UTC().Format(time.RFC3339), now.Format(time.RFC3339))
	}
	if endTime.Time.Before(now.Add(-skew)) {
		return errs.Detail(ErrTicketExpired, "ticket expired at %s, now %s | 票据于 %s 过期，当前 %s",
			endTime.UTC().Format(time.RFC3339), now.Format(time.RFC3339), endTime.UTC().Format(time.RFC3339), now.Format(time.RFC3339))
	}
	return nil
}

// equalPrincipalComponents compares principal components without name types. | equalPrincipalComponents
// 比较主体组成部分，忽略名称类型。
func equalPrincipalComponents(a, b PrincipalName) bool {
	if len(a.NameString) != len(b.NameString) {
		return false
	}
	for i := range a.NameString {
		if a.NameString[i] != b.NameString[i] {
			return false
		}
	}
	return true
}

// defaultSaltFor returns the default RFC 4120 salt. | defaultSaltFor 返回默认 RFC 4120 盐。
func defaultSaltFor(realm string, principal PrincipalName) string {
	result := realm
	for _, component := range principal.NameString {
		result += component
	}
	return result
}

// timeOr returns the pointer value when present, else fallback. | timeOr 在指针存在时返回
// 其值，否则返回后备值。
func timeOr(value *KerberosTime, fallback KerberosTime) KerberosTime {
	if value != nil {
		return *value
	}
	return fallback
}

// timeValue dereferences an optional KerberosTime. | timeValue 解引用可选 KerberosTime。
func timeValue(value *KerberosTime) KerberosTime {
	if value == nil {
		return KerberosTime{}
	}
	return *value
}

// randomUint32 returns a non-zero random nonce limited to 31 bits. MIT krb5 and
// Heimdal encode nonces as signed 32-bit integers and reject values with the
// high bit set, so interoperable clients must keep the top bit clear (the same
// behavior as MIT k5_generate_nonce). | randomUint32 返回非零且限制为 31 位的随机
// nonce。MIT krb5 与 Heimdal 把 nonce 编码为有符号 32 位整数并拒绝最高位为 1 的值，
// 因此可互操作的客户端必须清除最高位（与 MIT k5_generate_nonce 行为一致）。
func randomUint32() (uint32, error) {
	var raw [4]byte
	if _, err := rand.Read(raw[:]); err != nil {
		return 0, errs.WrapDetail(err, ErrRandom, "nonce generation failed | nonce 生成失败")
	}
	value := binary.BigEndian.Uint32(raw[:]) & 0x7FFFFFFF
	if value == 0 {
		value = 1
	}
	return value, nil
}

// kerberosUSec returns the microsecond field for a time. | kerberosUSec 返回时间的微秒字段。
func kerberosUSec(value time.Time) int32 {
	return int32(value.Nanosecond() / 1000)
}
