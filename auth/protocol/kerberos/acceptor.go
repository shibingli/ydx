package kerberos

import (
	"crypto/sha256"
	"encoding/binary"
	"errors"
	"sync"
	"time"

	"github.com/shibingli/ydx/errs"
)

// AcceptorOptions configures a Kerberos GSS-API acceptor. | AcceptorOptions 配置
// Kerberos GSS-API 接受方。
type AcceptorOptions struct {
	// KeyTab supplies the long-term service keys used to decrypt tickets. It is
	// required. | KeyTab 提供用于解密票据的服务长期密钥。该项必需。
	KeyTab *KeyTab
	// Service is the expected service principal, for example "ldap/dc1.example.com".
	// An empty value accepts any service principal present in the keytab. | Service
	// 是期望的服务主体，例如 "ldap/dc1.example.com"。空值接受 keytab 中的任意服务主体。
	Service string
	// Realm restricts accepted tickets to one realm. An empty value accepts the
	// ticket realm supplied by the client. | Realm 把接受的票据限制在一个 realm。空值
	// 接受客户端提供的票据 realm。
	Realm string
	// ClockSkew is the accepted difference between the client authenticator time
	// and the acceptor clock. Zero selects DefaultClockSkew. | ClockSkew 是接受的客户端
	// 认证器时间与接受方时钟之差。零值选择 DefaultClockSkew。
	ClockSkew time.Duration
	// ReplayCache rejects a repeated authenticator. A nil value creates a cache
	// with DefaultReplayCacheTTL. | ReplayCache 拒绝重复的认证器。空值创建使用
	// DefaultReplayCacheTTL 的缓存。
	ReplayCache *ReplayCache
	// RequireChannelBindings rejects authenticators whose RFC 4121 channel-binding
	// hash differs from ChannelBindings. | RequireChannelBindings 拒绝 RFC 4121 通道
	// 绑定哈希与 ChannelBindings 不同的认证器。
	RequireChannelBindings bool
	// ChannelBindings is the expected 16-octet RFC 4121 channel-binding hash. For
	// SASL tls-server-end-point it is the hash of the server certificate. | ChannelBindings
	// 是期望的 16 字节 RFC 4121 通道绑定哈希。对于 SASL tls-server-end-point，它是服务端
	// 证书的哈希。
	ChannelBindings []byte
}

// Acceptor validates Kerberos AP-REQs and establishes GSS-API acceptor sessions.
// It is safe for concurrent use. | Acceptor 校验 Kerberos AP-REQ 并建立 GSS-API 接受方
// 会话。它可以安全并发使用。
type Acceptor struct {
	keyTab      *KeyTab
	service     PrincipalName
	haveService bool
	realm       string
	clockSkew   time.Duration
	replay      *ReplayCache
	requireBind bool
	channelBind []byte
	now         func() time.Time
}

// NewAcceptor validates opts and returns an acceptor. | NewAcceptor 校验 opts 并返回
// 接受方。
func NewAcceptor(opts AcceptorOptions) (*Acceptor, error) {
	if opts.KeyTab == nil {
		return nil, errs.Detail(ErrInvalidConfig, "acceptor requires a keytab | 接受方需要 keytab")
	}
	if len(opts.KeyTab.Entries()) == 0 {
		return nil, errs.Detail(ErrInvalidConfig, "acceptor keytab has no entries | 接受方 keytab 没有条目")
	}
	if len(opts.ChannelBindings) != 0 && len(opts.ChannelBindings) != 16 {
		return nil, errs.Detail(ErrChannelBinding, "channel bindings are %d octets, want 16 | 通道绑定为 %d 字节，期望 16",
			len(opts.ChannelBindings), len(opts.ChannelBindings))
	}
	if opts.RequireChannelBindings && len(opts.ChannelBindings) != 16 {
		return nil, errs.Detail(ErrChannelBinding, "channel binding is required but not configured | 要求通道绑定但未配置")
	}
	skew := opts.ClockSkew
	if skew <= 0 {
		skew = DefaultClockSkew
	}
	replay := opts.ReplayCache
	if replay == nil {
		replay = NewReplayCache(DefaultReplayCacheTTL)
	}
	acceptor := &Acceptor{
		keyTab:      opts.KeyTab,
		realm:       opts.Realm,
		clockSkew:   skew,
		replay:      replay,
		requireBind: opts.RequireChannelBindings,
		channelBind: append([]byte(nil), opts.ChannelBindings...),
		now:         func() time.Time { return time.Now().UTC() },
	}
	if opts.Service != "" {
		principal, realm, err := ParseServicePrincipal(opts.Service, opts.Realm)
		if err != nil {
			return nil, err
		}
		acceptor.service = principal
		acceptor.haveService = true
		if acceptor.realm == "" {
			acceptor.realm = realm
		}
	}
	return acceptor, nil
}

// GSSSession is an established GSS-API acceptor context. Its per-message methods
// are serialized. | GSSSession 是已建立的 GSS-API 接受方上下文。其每消息方法串行执行。
type GSSSession struct {
	// ClientPrincipal is the authenticated client principal. | ClientPrincipal 是已认证的
	// 客户端主体。
	ClientPrincipal PrincipalName
	// ClientRealm is the authenticated client realm. | ClientRealm 是已认证的客户端 realm。
	ClientRealm string
	// AuthTime is the ticket authentication time. | AuthTime 是票据认证时间。
	AuthTime KerberosTime
	// StartTime is the effective ticket start time. | StartTime 是票据生效时间。
	StartTime KerberosTime
	// EndTime is the ticket expiry time. | EndTime 是票据过期时间。
	EndTime KerberosTime
	// RenewTill is the optional ticket renewal deadline. | RenewTill 是可选票据续期期限。
	RenewTill *KerberosTime
	// TicketFlags are the ticket flags from the service ticket. | TicketFlags 是服务票据中的
	// 票据标志。
	TicketFlags TicketFlags
	// ContextFlags are the RFC 4121 context flags asserted by the initiator. | ContextFlags
	// 是发起方声明的 RFC 4121 上下文标志。
	ContextFlags uint32
	// MutualAuth reports whether an AP-REP was returned. | MutualAuth 报告是否返回了 AP-REP。
	MutualAuth bool

	mu  sync.Mutex
	ctx *gssMessageContext
}

// Wrap protects data in a GSS WRAP token. confidential selects sealing. | Wrap 使用
// GSS WRAP 令牌保护 data。confidential 选择是否加密。
func (s *GSSSession) Wrap(data []byte, confidential bool) ([]byte, error) {
	if s == nil {
		return nil, errs.Detail(ErrGSSAPI, "nil GSS session | GSS 会话为空")
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.ctx == nil {
		return nil, errs.Detail(ErrGSSAPI, "GSS session is not established | GSS 会话尚未建立")
	}
	return s.ctx.wrap(data, confidential)
}

// Unwrap verifies and opens a GSS WRAP token sent by the initiator. It reports
// whether the payload was confidential. | Unwrap 校验并解包发起方发送的 GSS WRAP 令牌，
// 并报告载荷是否受机密性保护。
func (s *GSSSession) Unwrap(token []byte) ([]byte, bool, error) {
	if s == nil {
		return nil, false, errs.Detail(ErrGSSAPI, "nil GSS session | GSS 会话为空")
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.ctx == nil {
		return nil, false, errs.Detail(ErrGSSAPI, "GSS session is not established | GSS 会话尚未建立")
	}
	return s.ctx.unwrap(token)
}

// MIC produces a GSS MIC token over data. | MIC 对 data 生成 GSS MIC 令牌。
func (s *GSSSession) MIC(data []byte) ([]byte, error) {
	if s == nil {
		return nil, errs.Detail(ErrGSSAPI, "nil GSS session | GSS 会话为空")
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.ctx == nil {
		return nil, errs.Detail(ErrGSSAPI, "GSS session is not established | GSS 会话尚未建立")
	}
	return s.ctx.mic(data)
}

// VerifyMIC verifies an initiator MIC token over data. | VerifyMIC 校验发起方对 data 生成
// 的 MIC 令牌。
func (s *GSSSession) VerifyMIC(data, token []byte) error {
	if s == nil {
		return errs.Detail(ErrGSSAPI, "nil GSS session | GSS 会话为空")
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.ctx == nil {
		return errs.Detail(ErrGSSAPI, "GSS session is not established | GSS 会话尚未建立")
	}
	return s.ctx.verifyMIC(data, token)
}

// acceptToken is one decoded initial GSS token. | acceptToken 是一个解码后的初始 GSS 令牌。
type acceptToken struct {
	apReq       []byte
	spnego      bool
	mechOID     []uint32
	mechListDER []byte
	mechListMIC []byte
}

// acceptResult is the validated AP-REQ state needed to finish the exchange. |
// acceptResult 是完成交换所需的有效 AP-REQ 状态。
type acceptResult struct {
	session      *GSSSession
	apRep        []byte
	initiatorKey EncryptionKey
	authSeq      uint32
}

// Accept validates one initial context token, which may be a raw Kerberos GSS
// token, a SPNEGO NegTokenInit, or a bare AP-REQ. It returns the response token
// (nil when no AP-REP is required) and the established session. | Accept 校验一个初始
// 上下文令牌，它可以是原始 Kerberos GSS 令牌、SPNEGO NegTokenInit 或裸 AP-REQ。它返回响应
// 令牌（无需 AP-REP 时为空）与已建立的会话。
func (a *Acceptor) Accept(token []byte) ([]byte, *GSSSession, error) {
	if a == nil {
		return nil, nil, errs.Detail(ErrInvalidConfig, "nil acceptor | 接受方为空")
	}
	parsed, err := parseAcceptToken(token)
	if err != nil {
		return nil, nil, err
	}
	request, err := ParseAPReq(parsed.apReq)
	if err != nil {
		return nil, nil, err
	}
	result, err := a.acceptAPReq(request)
	if err != nil {
		return nil, nil, err
	}
	session := result.session
	if len(parsed.mechListMIC) > 0 {
		microContext := &gssMessageContext{
			key:            result.initiatorKey,
			sendAcceptor:   true,
			acceptorSubkey: false,
			recvSeq:        uint64(result.authSeq),
		}
		if err := microContext.verifyMIC(parsed.mechListDER, parsed.mechListMIC); err != nil {
			return nil, nil, errs.WrapDetail(err, ErrSPNEGO, "SPNEGO mechListMIC verification failed | SPNEGO mechListMIC 校验失败")
		}
		session.mu.Lock()
		session.ctx.recvSeq = microContext.recvSeq
		mic, err := session.ctx.mic(parsed.mechListDER)
		session.mu.Unlock()
		if err != nil {
			return nil, nil, err
		}
		return a.spnegoResponse(parsed, result.apRep, mic), session, nil
	}
	if !parsed.spnego {
		return frameAcceptResponse(parsed.mechOID, result.apRep), session, nil
	}
	return a.spnegoResponse(parsed, result.apRep, nil), session, nil
}

// spnegoResponse builds a NegTokenResp carrying an optional AP-REP and
// mechListMIC. | spnegoResponse 构建携带可选 AP-REP 与 mechListMIC 的 NegTokenResp。
func (a *Acceptor) spnegoResponse(parsed *acceptToken, apRep, mechListMIC []byte) []byte {
	state := negStateAcceptCompleted
	response := negTokenResp{
		state:         &state,
		supportedMech: parsed.mechOID,
		mechListMIC:   mechListMIC,
	}
	if len(apRep) > 0 {
		response.responseToken = gssWrapKerberosToken(parsed.mechOID, gssTokenAPRep, apRep)
	}
	return appendNegTokenResp(response)
}

// acceptAPReq validates a parsed AP-REQ against the keytab and returns the
// resulting session plus the optional AP-REP body. | acceptAPReq 按 keytab 校验解析后的
// AP-REQ，并返回结果会话与可选 AP-REP 主体。
func (a *Acceptor) acceptAPReq(request APReq) (*acceptResult, error) {
	ticket := request.Ticket
	if ticket.TktVNO != PVNO {
		return nil, errs.Detail(ErrInvalidMessage, "ticket version %d | 票据版本 %d", ticket.TktVNO, ticket.TktVNO)
	}
	if len(ticket.EncPart.Cipher) == 0 || ticket.EncPart.EType == 0 {
		return nil, errs.Detail(ErrInvalidMessage, "ticket has no encrypted part | 票据没有加密部分")
	}
	if ticket.Realm == "" || len(ticket.SName.NameString) == 0 {
		return nil, errs.Detail(ErrInvalidMessage, "ticket has no server principal | 票据没有服务端主体")
	}
	if a.haveService {
		if !equalPrincipalComponents(ticket.SName, a.service) {
			return nil, errs.Detail(ErrTicketNotForUs, "ticket is for %s, acceptor is %s | 票据属于 %s，接受方为 %s",
				ticket.SName.String(), a.service.String(), ticket.SName.String(), a.service.String())
		}
	}
	if a.realm != "" && ticket.Realm != a.realm {
		return nil, errs.Detail(ErrTicketNotForUs, "ticket realm %s, acceptor realm %s | 票据 realm %s，接受方 realm %s",
			ticket.Realm, a.realm, ticket.Realm, a.realm)
	}
	entry, err := lookupAcceptorKey(a.keyTab, ticket)
	if err != nil {
		return nil, err
	}
	ticketPlain, err := DecryptMessage(entry.Key.KeyType, entry.Key.KeyValue, 2, ticket.EncPart.Cipher)
	if err != nil {
		return nil, errs.WrapDetail(err, ErrTicketNotForUs, "service ticket decryption failed | 服务票据解密失败")
	}
	part, err := parseEncTicketPart(ticketPlain)
	if err != nil {
		return nil, err
	}
	if part.Flags.Has(TicketFlagInvalid) {
		return nil, errs.Detail(ErrTicketNotForUs, "service ticket is marked invalid | 服务票据被标记为无效")
	}
	if part.CRealm == "" || len(part.CName.NameString) == 0 {
		return nil, errs.Detail(ErrInvalidMessage, "ticket has no client principal | 票据没有客户端主体")
	}
	if _, err := KeySize(part.Key.KeyType); err != nil {
		return nil, err
	}
	now := a.now()
	if err := validateTimes(part.AuthTime, part.StartTime, part.EndTime, now, a.clockSkew); err != nil {
		return nil, err
	}
	authenticatorPlain, err := DecryptMessage(part.Key.KeyType, part.Key.KeyValue, 11, request.Authenticator.Cipher)
	if err != nil {
		return nil, errs.WrapDetail(err, ErrBadIntegrity, "authenticator decryption failed | 认证器解密失败")
	}
	authenticator, err := parseAuthenticator(authenticatorPlain)
	if err != nil {
		return nil, err
	}
	if authenticator.AuthenticatorVNO != PVNO {
		return nil, errs.Detail(ErrInvalidMessage, "authenticator version %d | 认证器版本 %d",
			authenticator.AuthenticatorVNO, authenticator.AuthenticatorVNO)
	}
	if !equalPrincipalComponents(authenticator.CName, part.CName) || authenticator.CRealm != part.CRealm {
		return nil, errs.Detail(ErrTicketMismatch, "authenticator identity differs from the ticket identity | 认证器身份与票据身份不同")
	}
	if authenticator.CTime.IsZero() {
		return nil, errs.Detail(ErrTime, "authenticator has no client time | 认证器没有客户端时间")
	}
	if authenticator.CUSec < 0 || authenticator.CUSec >= 1_000_000 {
		return nil, errs.Detail(ErrTime, "authenticator microsecond field %d is out of range | 认证器微秒字段 %d 超出范围",
			authenticator.CUSec, authenticator.CUSec)
	}
	if authenticator.CTime.Time.Before(now.Add(-a.clockSkew)) || authenticator.CTime.Time.After(now.Add(a.clockSkew)) {
		return nil, errs.Detail(ErrClockSkew, "authenticator time %s is outside the accepted window around %s | 认证器时间 %s 超出 %s 附近的可接受窗口",
			authenticator.CTime.UTC().Format(time.RFC3339), now.Format(time.RFC3339),
			authenticator.CTime.UTC().Format(time.RFC3339), now.Format(time.RFC3339))
	}
	contextFlags, err := a.validateAuthenticatorChecksum(authenticator, request, part)
	if err != nil {
		return nil, err
	}
	if !a.replay.Add(authenticatorReplayKey(part.CRealm, part.CName, authenticator), now, now.Add(a.clockSkew)) {
		return nil, errs.Detail(ErrReplay, "authenticator was already presented | 认证器已被提交过")
	}
	initiatorKey := part.Key
	if authenticator.SubKey != nil {
		if _, err := KeySize(authenticator.SubKey.KeyType); err != nil {
			return nil, err
		}
		initiatorKey = *authenticator.SubKey
	}
	var authSequence uint32
	if authenticator.SeqNumber != nil {
		authSequence = *authenticator.SeqNumber
	}
	mutual := request.APOptions.Has(APOptionMutualRequired) || contextFlags&gssContextMutual != 0
	sessionKey := initiatorKey
	acceptorSubkey := false
	var sendSequence uint64
	var apRep []byte
	if mutual {
		subKey, err := randomKey(part.Key.KeyType)
		if err != nil {
			return nil, err
		}
		sequence, err := randomUint32()
		if err != nil {
			return nil, err
		}
		repPart := EncAPRepPart{
			CTime:     authenticator.CTime,
			CUSec:     authenticator.CUSec,
			SubKey:    &subKey,
			SeqNumber: &sequence,
		}
		repPlain := appendEncAPRepPart(repPart)
		ciphertext, err := EncryptMessage(part.Key.KeyType, part.Key.KeyValue, 12, repPlain)
		if err != nil {
			return nil, err
		}
		rep := APRep{
			PVNO:    PVNO,
			MsgType: MessageTypeAPRep,
			EncPart: EncryptedData{
				EType:  part.Key.KeyType,
				Cipher: ciphertext,
			},
		}
		apRep, err = rep.Marshal()
		if err != nil {
			return nil, err
		}
		sessionKey = subKey
		acceptorSubkey = true
		sendSequence = uint64(sequence)
	}
	session := &GSSSession{
		ClientPrincipal: part.CName,
		ClientRealm:     part.CRealm,
		AuthTime:        part.AuthTime,
		StartTime:       timeOr(part.StartTime, part.AuthTime),
		EndTime:         part.EndTime,
		RenewTill:       part.RenewTill,
		TicketFlags:     part.Flags,
		ContextFlags:    contextFlags,
		MutualAuth:      mutual,
		ctx: &gssMessageContext{
			key:            sessionKey,
			sendAcceptor:   true,
			acceptorSubkey: acceptorSubkey,
			sendSeq:        sendSequence,
			recvSeq:        uint64(authSequence),
		},
	}
	return &acceptResult{
		session:      session,
		apRep:        apRep,
		initiatorKey: initiatorKey,
		authSeq:      authSequence,
	}, nil
}

// gssChecksumBindingLength is the RFC 4121 Lgth value naming the 16-octet
// channel-binding hash carried by a GSS authenticator checksum. |
// gssChecksumBindingLength 是 RFC 4121 中命名 GSS 认证器校验和所携带 16 字节通道绑定哈希的
// Lgth 值。
const gssChecksumBindingLength = 16

// validateAuthenticatorChecksum validates the RFC 4121 GSS checksum, channel
// binding, and context flags of an authenticator. | validateAuthenticatorChecksum
// 校验认证器的 RFC 4121 GSS 校验和、通道绑定与上下文标志。
func (a *Acceptor) validateAuthenticatorChecksum(authenticator Authenticator, request APReq, part EncTicketPart) (uint32, error) {
	checksum := authenticator.Cksum
	if checksum == nil {
		return 0, errs.Detail(ErrGSSAPI, "authenticator has no GSS checksum | 认证器没有 GSS 校验和")
	}
	if checksum.CksumType != ChecksumTypeGSSAPI {
		return 0, errs.Detail(ErrGSSAPI, "authenticator checksum type %d, want 0x%04x | 认证器校验和类型 %d，期望 0x%04x",
			checksum.CksumType, ChecksumTypeGSSAPI, checksum.CksumType, ChecksumTypeGSSAPI)
	}
	if len(checksum.Checksum) != 24 {
		return 0, errs.Detail(ErrGSSAPI, "GSS checksum is %d octets, want 24 | GSS 校验和为 %d 字节，期望 24",
			len(checksum.Checksum), len(checksum.Checksum))
	}
	bindingLength := binary.LittleEndian.Uint32(checksum.Checksum[0:4])
	if bindingLength != gssChecksumBindingLength {
		return 0, errs.Detail(ErrGSSAPI, "GSS checksum binding length is %d, want %d | GSS 校验和绑定长度为 %d，期望 %d",
			bindingLength, gssChecksumBindingLength, bindingLength, gssChecksumBindingLength)
	}
	contextFlags := binary.LittleEndian.Uint32(checksum.Checksum[20:24])
	if contextFlags&gssContextDeleg != 0 {
		return 0, errs.Detail(ErrGSSAPI, "delegated credentials are not supported | 不支持凭据委派")
	}
	if a.requireBind {
		if !gssChannelBindingMatches(checksum.Checksum[4:20], a.channelBind) {
			return 0, errs.Detail(ErrChannelBinding, "GSS channel binding does not match the acceptor binding | GSS 通道绑定与接受方绑定不匹配")
		}
	}
	if request.Authenticator.EType != 0 && request.Authenticator.EType != part.Key.KeyType {
		return 0, errs.Detail(ErrInvalidMessage, "authenticator enctype %d differs from the ticket key %d | 认证器加密类型 %d 与票据密钥 %d 不同",
			request.Authenticator.EType, part.Key.KeyType, request.Authenticator.EType, part.Key.KeyType)
	}
	return contextFlags, nil
}

// parseAcceptToken decodes a raw Kerberos initial token, a SPNEGO negotiation
// token, or a bare AP-REQ. | parseAcceptToken 解码原始 Kerberos 初始令牌、SPNEGO 协商
// 令牌或裸 AP-REQ。
func parseAcceptToken(token []byte) (*acceptToken, error) {
	if len(token) == 0 {
		return nil, errs.Detail(ErrGSSAPI, "empty acceptor token | 空的接受方令牌")
	}
	if token[0] == byte(derTagApplicationBase|14) {
		return &acceptToken{apReq: append([]byte(nil), token...), mechOID: gssOIDKerberosV5}, nil
	}
	if token[0] == 0xA0 {
		init, err := parseNegTokenInit(token)
		if err != nil {
			return nil, err
		}
		return selectSPNEGOMechanism(init)
	}
	if token[0] != byte(derTagApplicationBase) {
		return nil, errs.Detail(ErrGSSAPI, "unrecognized initial token prefix 0x%02x | 无法识别的初始令牌前缀 0x%02x",
			token[0], token[0])
	}
	oid, rest, err := gssUnframe(token)
	if err != nil {
		return nil, err
	}
	if equalOID(oid, gssOIDSPNEGO) {
		if len(rest) == 0 || !isSPNEGOToken(rest) {
			return nil, errs.Detail(ErrSPNEGO, "SPNEGO token has no negotiation body | SPNEGO 令牌没有协商主体")
		}
		init, err := parseNegTokenInit(rest)
		if err != nil {
			return nil, err
		}
		return selectSPNEGOMechanism(init)
	}
	if !equalOID(oid, gssOIDKerberosV5) && !equalOID(oid, gssOIDMSLegacyKerberos) {
		return nil, errs.Detail(ErrGSSAPI, "unsupported GSS mechanism %s | 不支持的 GSS 机制 %s", formatOID(oid), formatOID(oid))
	}
	frameOID, apReq, err := parseKerberosAPReqToken(token)
	if err != nil {
		return nil, err
	}
	return &acceptToken{apReq: apReq, mechOID: frameOID}, nil
}

// selectSPNEGOMechanism chooses the first Kerberos mechanism offered by a
// NegTokenInit and extracts its AP-REQ. | selectSPNEGOMechanism 选择 NegTokenInit 提供的
// 第一个 Kerberos 机制并提取其 AP-REQ。
func selectSPNEGOMechanism(init negTokenInit) (*acceptToken, error) {
	var selected []uint32
	for _, mechanism := range init.mechTypes {
		if equalOID(mechanism, gssOIDKerberosV5) || equalOID(mechanism, gssOIDMSLegacyKerberos) {
			selected = mechanism
			break
		}
	}
	if selected == nil {
		return nil, errs.Detail(ErrSPNEGO, "client offered no supported Kerberos mechanism | 客户端未提供受支持的 Kerberos 机制")
	}
	if len(init.mechToken) == 0 {
		return nil, errs.Detail(ErrSPNEGO, "SPNEGO NegTokenInit has no mechanism token | SPNEGO NegTokenInit 没有机制令牌")
	}
	innerOID, apReq, err := parseKerberosAPReqToken(init.mechToken)
	if err != nil {
		return nil, err
	}
	if !equalOID(innerOID, gssOIDKerberosV5) && !equalOID(innerOID, gssOIDMSLegacyKerberos) {
		return nil, errs.Detail(ErrSPNEGO, "SPNEGO mechanism token uses %s | SPNEGO 机制令牌使用 %s",
			formatOID(innerOID), formatOID(innerOID))
	}
	return &acceptToken{
		apReq:       apReq,
		spnego:      true,
		mechOID:     selected,
		mechListDER: init.mechListDER,
		mechListMIC: init.mechListMIC,
	}, nil
}

// parseKerberosAPReqToken accepts a GSS-framed AP-REQ or a bare AP-REQ. |
// parseKerberosAPReqToken 接受 GSS 封装的 AP-REQ 或裸 AP-REQ。
func parseKerberosAPReqToken(data []byte) ([]uint32, []byte, error) {
	if len(data) == 0 {
		return nil, nil, errs.Detail(ErrGSSAPI, "empty Kerberos mechanism token | 空的 Kerberos 机制令牌")
	}
	if data[0] == byte(derTagApplicationBase|14) {
		return gssOIDKerberosV5, append([]byte(nil), data...), nil
	}
	if data[0] != byte(derTagApplicationBase) {
		return nil, nil, errs.Detail(ErrGSSAPI, "Kerberos mechanism token has prefix 0x%02x, want an AP-REQ | Kerberos 机制令牌前缀为 0x%02x，期望 AP-REQ",
			data[0], data[0])
	}
	oid, rest, err := gssUnframe(data)
	if err != nil {
		return nil, nil, err
	}
	tokID, payload, err := parseKerberosMechToken(rest)
	if err != nil {
		return nil, nil, err
	}
	if tokID != gssTokenAPReq {
		return nil, nil, errs.Detail(ErrGSSAPI, "GSS TOK_ID 0x%04x is not an AP-REQ | GSS TOK_ID 0x%04x 不是 AP-REQ",
			tokID, tokID)
	}
	if len(payload) == 0 || payload[0] != byte(derTagApplicationBase|14) {
		return nil, nil, errs.Detail(ErrGSSAPI, "GSS AP-REQ payload is malformed | GSS AP-REQ 载荷畸形")
	}
	return oid, payload, nil
}

// frameAcceptResponse frames a raw AP-REP with oid, or returns nil when no
// AP-REP is required. | frameAcceptResponse 用 oid 封装裸 AP-REP；无需 AP-REP 时返回空。
func frameAcceptResponse(oid []uint32, apRep []byte) []byte {
	if len(apRep) == 0 {
		return nil
	}
	return gssWrapKerberosToken(oid, gssTokenAPRep, apRep)
}

// lookupAcceptorKey selects the keytab key for a ticket. A ticket naming a kvno
// that the keytab lacks is reported as ErrBadKVNO. | lookupAcceptorKey 为票据选择
// keytab 密钥。票据指定了 keytab 缺失的 kvno 时报告 ErrBadKVNO。
func lookupAcceptorKey(keyTab *KeyTab, ticket Ticket) (KeyTabEntry, error) {
	entry, err := keyTab.Lookup(ticket.SName, ticket.Realm, ticket.EncPart.EType, ticket.EncPart.KVNO)
	if err == nil {
		return entry, nil
	}
	if ticket.EncPart.KVNO != 0 && errors.Is(err, ErrNoKey) {
		if _, fallback := keyTab.Lookup(ticket.SName, ticket.Realm, ticket.EncPart.EType, 0); fallback == nil {
			return KeyTabEntry{}, errs.Detail(ErrBadKVNO, "keytab has no kvno %d for %s | keytab 没有 %s 的 kvno %d",
				ticket.EncPart.KVNO, ticket.SName.String(), ticket.SName.String(), ticket.EncPart.KVNO)
		}
	}
	return KeyTabEntry{}, err
}

// authenticatorReplayKey derives the replay-cache key of an authenticator. |
// authenticatorReplayKey 派生认证器的重放缓存键。
func authenticatorReplayKey(realm string, principal PrincipalName, authenticator Authenticator) string {
	hash := sha256.New()
	_, _ = hash.Write([]byte(realm))
	for _, component := range principal.NameString {
		_, _ = hash.Write([]byte{0})
		_, _ = hash.Write([]byte(component))
	}
	if !authenticator.CTime.IsZero() {
		_, _ = hash.Write([]byte(authenticator.CTime.UTC().Format("20060102150405Z")))
	}
	var usec [4]byte
	binary.BigEndian.PutUint32(usec[:], uint32(authenticator.CUSec))
	_, _ = hash.Write([]byte{0})
	_, _ = hash.Write(usec[:])
	return string(hash.Sum(nil))
}
