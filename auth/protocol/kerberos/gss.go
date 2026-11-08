package kerberos

import (
	"context"
	"crypto/rand"
	"crypto/subtle"
	"encoding/binary"
	"sync"

	"github.com/shibingli/ydx/errs"
)

// GSSClientOptions configures a Kerberos GSS-API initiator context. | GSSClientOptions
// 配置 Kerberos GSS-API 发起方上下文。
type GSSClientOptions struct {
	// Client is the authenticated Kerberos client that supplies service tickets. | Client
	// 是提供服务票据的已认证 Kerberos 客户端。
	Client *Client
	// Service is the target service principal, for example "ldap/dc1.example.com".
	// It may carry an explicit realm. | Service 是目标服务主体，例如
	// "ldap/dc1.example.com"。它可以携带显式 realm。
	Service string
	// ServiceRealm overrides the realm used for a service name without one. | ServiceRealm
	// 覆盖未携带 realm 的服务名所用 realm。
	ServiceRealm string
	// MutualAuth requests mutual authentication (AP-REP). SASL GSSAPI requires it. |
	// MutualAuth 请求双向认证（AP-REP）。SASL GSSAPI 需要它。
	MutualAuth bool
	// SPNEGO wraps the Kerberos mechanism in SPNEGO negotiation tokens. | SPNEGO 把
	// Kerberos 机制包装在 SPNEGO 协商令牌中。
	SPNEGO bool
	// ChannelBindings is the 16-octet RFC 4121 channel-binding hash supplied to the
	// acceptor. An empty value means no channel binding. SASL tls-server-end-point
	// passes the hash of the peer certificate here. | ChannelBindings 是提供给接受方的
	// 16 字节 RFC 4121 通道绑定哈希。空值表示无通道绑定。SASL tls-server-end-point 在此
	// 传入对端证书哈希。
	ChannelBindings []byte
}

// GSSClient is a Kerberos GSS-API initiator context. It performs the AP exchange
// itself and then protects per-message tokens with RFC 4121 or, for rc4-hmac,
// RFC 4757 tokens. Token operations are serialized; the context must not be
// shared between authentication exchanges. | GSSClient 是 Kerberos GSS-API 发起方
// 上下文。它自行执行 AP 交换，然后使用 RFC 4121 或 rc4-hmac 的 RFC 4757 令牌保护每条消息。
// 令牌操作串行化；上下文不得在多个认证交换之间共享。
type GSSClient struct {
	opts GSSClientOptions

	mu          sync.Mutex
	ticket      *ServiceTicket
	subKey      EncryptionKey
	authTime    KerberosTime
	authUSec    int32
	authSeq     uint32
	mechListDER []byte
	ctx         *gssMessageContext
	started     bool
	done        bool
	spnegoMech  []uint32
}

// NewGSSClient validates opts and returns an initiator context. | NewGSSClient 校验 opts
// 并返回发起方上下文。
func NewGSSClient(opts GSSClientOptions) (*GSSClient, error) {
	if opts.Client == nil {
		return nil, errs.Detail(ErrInvalidConfig, "GSS client requires a Kerberos client | GSS 客户端需要 Kerberos 客户端")
	}
	if opts.Service == "" {
		return nil, errs.Detail(ErrInvalidConfig, "GSS client requires a service principal | GSS 客户端需要服务主体")
	}
	if len(opts.ChannelBindings) != 0 && len(opts.ChannelBindings) != 16 {
		return nil, errs.Detail(ErrChannelBinding, "channel bindings are %d octets, want 16 | 通道绑定为 %d 字节，期望 16",
			len(opts.ChannelBindings), len(opts.ChannelBindings))
	}
	return &GSSClient{opts: opts}, nil
}

// InitialToken obtains a service ticket, builds the AP-REQ, and returns the GSS
// initial context token. In SPNEGO mode the AP-REQ is carried in a
// NegTokenInit. | InitialToken 获取服务票据、构建 AP-REQ 并返回 GSS 初始上下文令牌。
// SPNEGO 模式下 AP-REQ 由 NegTokenInit 携带。
func (g *GSSClient) InitialToken(ctx context.Context) ([]byte, error) {
	g.mu.Lock()
	defer g.mu.Unlock()
	if g.started {
		return nil, errs.Detail(ErrGSSAPI, "GSS initial token was already produced | 已生成过 GSS 初始令牌")
	}
	service, err := g.resolvedService()
	if err != nil {
		return nil, err
	}
	ticket, err := g.opts.Client.GetServiceTicket(ctx, service)
	if err != nil {
		return nil, err
	}
	subKey, err := randomKey(ticket.SessionKey.KeyType)
	if err != nil {
		return nil, err
	}
	sequence, err := randomUint32()
	if err != nil {
		return nil, err
	}
	now := g.opts.Client.now()
	usec := kerberosUSec(now)
	flags := gssContextReplay | gssContextSequence | gssContextIntegrity
	if g.opts.MutualAuth {
		flags |= gssContextMutual
	}
	checksum := make([]byte, 24)
	binary.LittleEndian.PutUint32(checksum[:4], gssChecksumBindingLength)
	copy(checksum[4:20], g.channelBindings())
	binary.LittleEndian.PutUint32(checksum[20:24], flags)
	authenticator := Authenticator{
		AuthenticatorVNO: PVNO,
		CRealm:           ticket.ClientRealm,
		CName:            ticket.ClientPrincipal,
		Cksum:            &Checksum{CksumType: ChecksumTypeGSSAPI, Checksum: checksum},
		CUSec:            usec,
		CTime:            NewKerberosTime(now),
		SubKey:           &subKey,
		SeqNumber:        &sequence,
	}
	encryptedAuthenticator, err := encryptAuthenticator(authenticator, ticket.SessionKey, 11)
	if err != nil {
		return nil, err
	}
	options := APOptions(0)
	if g.opts.MutualAuth {
		options.Set(APOptionMutualRequired)
	}
	request := APReq{
		PVNO:          PVNO,
		MsgType:       MessageTypeAPReq,
		APOptions:     options,
		Ticket:        ticket.Ticket,
		Authenticator: encryptedAuthenticator,
	}
	requestData, err := request.Marshal()
	if err != nil {
		return nil, err
	}
	apReqToken := gssWrapKerberosToken(gssOIDKerberosV5, gssTokenAPReq, requestData)
	g.ticket = ticket
	g.subKey = subKey
	g.authTime = authenticator.CTime
	g.authUSec = usec
	g.authSeq = sequence
	g.started = true
	if !g.opts.MutualAuth {
		g.establish(subKey, false, sequence, 0)
		if !g.opts.SPNEGO {
			g.done = true
		}
	}
	if !g.opts.SPNEGO {
		return apReqToken, nil
	}
	mechList := appendMechTypeList(nil, [][]uint32{gssOIDKerberosV5})
	g.mechListDER = mechList
	g.spnegoMech = gssOIDKerberosV5
	init := negTokenInit{
		mechTypes:   [][]uint32{gssOIDKerberosV5},
		mechListDER: mechList,
		mechToken:   apReqToken,
	}
	content := derAppendOID(nil, gssOIDSPNEGO)
	content = append(content, appendNegTokenInit(init)...)
	return derAppendApplication(nil, 0, content), nil
}

// Step consumes one acceptor token and returns a reply when the mechanism needs
// one. done reports that the context is established and no further GSS token is
// expected. | Step 消费一个接受方令牌，并在机制需要时返回回复。done 报告上下文已建立且
// 不再期待后续 GSS 令牌。
func (g *GSSClient) Step(ctx context.Context, token []byte) ([]byte, bool, error) {
	g.mu.Lock()
	defer g.mu.Unlock()
	if !g.started {
		return nil, false, errs.Detail(ErrGSSAPI, "GSS context is not started | GSS 上下文尚未启动")
	}
	if g.done {
		return nil, false, errs.Detail(ErrGSSAPI, "GSS context is already established | GSS 上下文已建立")
	}
	if err := ctx.Err(); err != nil {
		return nil, false, errs.WrapDetail(err, ErrGSSAPI, "GSS step canceled | GSS 步骤被取消")
	}
	if g.opts.SPNEGO {
		return g.stepSPNEGO(token)
	}
	return g.stepKerberos(token)
}

// stepKerberos handles a raw Kerberos mechanism token. | stepKerberos 处理原始 Kerberos
// 机制令牌。
func (g *GSSClient) stepKerberos(token []byte) ([]byte, bool, error) {
	oid, tokID, payload, err := parseKerberosGSSInput(token)
	if err != nil {
		return nil, false, err
	}
	if !equalOID(oid, gssOIDKerberosV5) && !equalOID(oid, gssOIDMSLegacyKerberos) {
		return nil, false, errs.Detail(ErrGSSAPI, "unexpected GSS mechanism %s | 意外的 GSS 机制 %s",
			formatOID(oid), formatOID(oid))
	}
	switch tokID {
	case gssTokenAPRep:
		rep, err := ParseAPRep(payload)
		if err != nil {
			return nil, false, err
		}
		if err := g.verifyAPRep(rep); err != nil {
			return nil, false, err
		}
		g.done = true
		return nil, true, nil
	case gssTokenKRBError:
		return nil, false, gssTokenError(payload)
	default:
		return nil, false, errs.Detail(ErrGSSAPI, "unexpected Kerberos GSS TOK_ID 0x%04x | 意外的 Kerberos GSS TOK_ID 0x%04x",
			tokID, tokID)
	}
}

// stepSPNEGO handles a SPNEGO negotiation response. | stepSPNEGO 处理 SPNEGO 协商响应。
func (g *GSSClient) stepSPNEGO(token []byte) ([]byte, bool, error) {
	response, err := parseSPNEGOResponse(token)
	if err != nil {
		return nil, false, err
	}
	if response.supportedMech != nil &&
		!equalOID(response.supportedMech, gssOIDKerberosV5) &&
		!equalOID(response.supportedMech, gssOIDMSLegacyKerberos) {
		return nil, false, errs.Detail(ErrSPNEGO, "acceptor selected unsupported mechanism %s | 接受方选择了不支持的机制 %s",
			formatOID(response.supportedMech), formatOID(response.supportedMech))
	}
	if response.state != nil && *response.state == negStateReject {
		if len(response.responseToken) > 0 {
			if err := g.consumeSPNEGOMechToken(response.responseToken); err != nil {
				return nil, false, err
			}
		}
		return nil, false, errs.Detail(ErrSPNEGO, "acceptor rejected the SPNEGO negotiation | 接受方拒绝了 SPNEGO 协商")
	}
	if len(response.responseToken) > 0 {
		if err := g.consumeSPNEGOMechToken(response.responseToken); err != nil {
			return nil, false, err
		}
	}
	if len(response.mechListMIC) > 0 {
		if !g.Complete() {
			return nil, false, errs.Detail(ErrSPNEGO, "SPNEGO mechListMIC arrived before the context was established | 上下文建立前收到 SPNEGO mechListMIC")
		}
		if err := g.ctx.verifyMIC(g.mechListDER, response.mechListMIC); err != nil {
			return nil, false, errs.WrapDetail(err, ErrSPNEGO, "SPNEGO mechListMIC verification failed | SPNEGO mechListMIC 校验失败")
		}
	}
	state := negStateAcceptCompleted
	if response.state != nil {
		state = *response.state
	}
	switch state {
	case negStateRequestMIC:
		if !g.Complete() {
			return nil, false, errs.Detail(ErrSPNEGO, "acceptor requested a mechListMIC before authentication completed | 接受方在认证完成前请求 mechListMIC")
		}
		mic, err := g.ctx.mic(g.mechListDER)
		if err != nil {
			return nil, false, err
		}
		completed := negStateAcceptCompleted
		reply := appendNegTokenResp(negTokenResp{
			state:       &completed,
			mechListMIC: mic,
		})
		g.done = true
		return reply, true, nil
	case negStateAcceptIncomplete:
		if !g.Complete() {
			return nil, false, errs.Detail(ErrSPNEGO, "acceptor requested more tokens but supplied no usable AP-REP | 接受方请求更多令牌但未提供可用 AP-REP")
		}
		var mechMIC []byte
		if len(response.mechListMIC) > 0 {
			mechMIC, err = g.ctx.mic(g.mechListDER)
			if err != nil {
				return nil, false, err
			}
		}
		completed := negStateAcceptCompleted
		reply := appendNegTokenResp(negTokenResp{
			state:       &completed,
			mechListMIC: mechMIC,
		})
		g.done = true
		return reply, true, nil
	default:
		if !g.Complete() {
			if g.opts.MutualAuth {
				return nil, false, errs.Detail(ErrMutualAuthFailed, "SPNEGO negotiation completed without an AP-REP | SPNEGO 协商在缺少 AP-REP 的情况下完成")
			}
			g.establish(g.subKey, false, g.authSeq, 0)
		}
		g.done = true
		return nil, true, nil
	}
}

// consumeSPNEGOMechToken verifies a mechanism token carried in a SPNEGO
// response. Only a Kerberos AP-REP or KRB-ERROR is accepted. | consumeSPNEGOMechToken
// 校验 SPNEGO 响应携带的机制令牌。仅接受 Kerberos AP-REP 或 KRB-ERROR。
func (g *GSSClient) consumeSPNEGOMechToken(token []byte) error {
	oid, tokID, payload, err := parseKerberosGSSInput(token)
	if err != nil {
		return err
	}
	if !equalOID(oid, gssOIDKerberosV5) && !equalOID(oid, gssOIDMSLegacyKerberos) {
		return errs.Detail(ErrSPNEGO, "SPNEGO mechanism token uses %s | SPNEGO 机制令牌使用 %s", formatOID(oid), formatOID(oid))
	}
	switch tokID {
	case gssTokenAPRep:
		rep, err := ParseAPRep(payload)
		if err != nil {
			return err
		}
		return g.verifyAPRep(rep)
	case gssTokenKRBError:
		return gssTokenError(payload)
	default:
		return errs.Detail(ErrSPNEGO, "unexpected SPNEGO mechanism TOK_ID 0x%04x | 意外的 SPNEGO 机制 TOK_ID 0x%04x", tokID, tokID)
	}
}

// verifyAPRep decrypts and validates an AP-REP and establishes the context. | verifyAPRep
// 解密并校验 AP-REP，随后建立上下文。
func (g *GSSClient) verifyAPRep(rep APRep) error {
	ticket := g.ticket
	if ticket == nil {
		return errs.Detail(ErrGSSAPI, "AP-REP arrived without a service ticket | AP-REP 到达时没有服务票据")
	}
	if rep.EncPart.EType != ticket.SessionKey.KeyType {
		return errs.Detail(ErrBadIntegrity, "AP-REP enctype %d does not match the session key %d | AP-REP 加密类型 %d 与会话密钥 %d 不匹配",
			rep.EncPart.EType, ticket.SessionKey.KeyType, rep.EncPart.EType, ticket.SessionKey.KeyType)
	}
	plain, err := DecryptMessage(ticket.SessionKey.KeyType, ticket.SessionKey.KeyValue, 12, rep.EncPart.Cipher)
	if err != nil {
		return errs.WrapDetail(err, ErrMutualAuthFailed, "AP-REP decryption failed | AP-REP 解密失败")
	}
	part, err := parseEncAPRepPart(plain)
	if err != nil {
		return err
	}
	if !part.CTime.Equal(g.authTime.Time) || part.CUSec != g.authUSec {
		return errs.Detail(ErrMutualAuthFailed, "AP-REP does not echo the authenticator time | AP-REP 未回显认证器时间")
	}
	key := g.subKey
	acceptorSubkey := false
	if part.SubKey != nil {
		if _, err := KeySize(part.SubKey.KeyType); err != nil {
			return err
		}
		key = *part.SubKey
		acceptorSubkey = true
	}
	recvSequence := uint64(0)
	if part.SeqNumber != nil {
		recvSequence = uint64(*part.SeqNumber)
	}
	g.establish(key, acceptorSubkey, g.authSeq, recvSequence)
	return nil
}

// establish installs the per-message context. | establish 安装每消息上下文。
func (g *GSSClient) establish(key EncryptionKey, acceptorSubkey bool, sendSequence uint32, recvSequence uint64) {
	g.ctx = &gssMessageContext{
		key:            key,
		sendAcceptor:   false,
		acceptorSubkey: acceptorSubkey,
		sendSeq:        uint64(sendSequence),
		recvSeq:        recvSequence,
	}
}

// Complete reports whether the GSS context is established. | Complete 报告 GSS 上下文是否
// 已建立。
func (g *GSSClient) Complete() bool { return g != nil && g.ctx != nil }

// ClientPrincipal returns the authenticated client principal and realm. | ClientPrincipal
// 返回已认证的客户端主体与 realm。
func (g *GSSClient) ClientPrincipal() (PrincipalName, string) {
	if g == nil || g.ticket == nil {
		return PrincipalName{}, ""
	}
	return g.ticket.ClientPrincipal, g.ticket.ClientRealm
}

// TargetName returns the service principal and realm of the target. | TargetName 返回目标
// 服务主体与 realm。
func (g *GSSClient) TargetName() (PrincipalName, string) {
	if g == nil || g.ticket == nil {
		return PrincipalName{}, ""
	}
	return g.ticket.ServicePrincipal, g.ticket.ServiceRealm
}

// Flags returns the RFC 4121 context flags asserted in the authenticator. | Flags
// 返回认证器中声明的 RFC 4121 上下文标志。
func (g *GSSClient) Flags() uint32 {
	flags := gssContextReplay | gssContextSequence | gssContextIntegrity
	if g != nil && g.opts.MutualAuth {
		flags |= gssContextMutual
	}
	return flags
}

// Wrap protects data in a GSS WRAP token. confidential selects sealing. | Wrap 使用
// GSS WRAP 令牌保护 data。confidential 选择是否加密。
func (g *GSSClient) Wrap(data []byte, confidential bool) ([]byte, error) {
	if g == nil {
		return nil, errs.Detail(ErrGSSAPI, "nil GSS client | GSS 客户端为空")
	}
	g.mu.Lock()
	defer g.mu.Unlock()
	if g.ctx == nil {
		return nil, errs.Detail(ErrGSSAPI, "GSS context is not established | GSS 上下文尚未建立")
	}
	return g.ctx.wrap(data, confidential)
}

// Unwrap verifies and opens a GSS WRAP token. It reports whether the payload was
// confidential. | Unwrap 校验并解包 GSS WRAP 令牌，并报告载荷是否受机密性保护。
func (g *GSSClient) Unwrap(token []byte) ([]byte, bool, error) {
	if g == nil {
		return nil, false, errs.Detail(ErrGSSAPI, "nil GSS client | GSS 客户端为空")
	}
	g.mu.Lock()
	defer g.mu.Unlock()
	if g.ctx == nil {
		return nil, false, errs.Detail(ErrGSSAPI, "GSS context is not established | GSS 上下文尚未建立")
	}
	return g.ctx.unwrap(token)
}

// MIC produces a GSS MIC token over data. | MIC 对 data 生成 GSS MIC 令牌。
func (g *GSSClient) MIC(data []byte) ([]byte, error) {
	if g == nil {
		return nil, errs.Detail(ErrGSSAPI, "nil GSS client | GSS 客户端为空")
	}
	g.mu.Lock()
	defer g.mu.Unlock()
	if g.ctx == nil {
		return nil, errs.Detail(ErrGSSAPI, "GSS context is not established | GSS 上下文尚未建立")
	}
	return g.ctx.mic(data)
}

// VerifyMIC verifies an acceptor MIC token over data. | VerifyMIC 校验接受方对 data 生成的
// MIC 令牌。
func (g *GSSClient) VerifyMIC(data, token []byte) error {
	if g == nil {
		return errs.Detail(ErrGSSAPI, "nil GSS client | GSS 客户端为空")
	}
	g.mu.Lock()
	defer g.mu.Unlock()
	if g.ctx == nil {
		return errs.Detail(ErrGSSAPI, "GSS context is not established | GSS 上下文尚未建立")
	}
	return g.ctx.verifyMIC(data, token)
}

// resolvedService returns the configured service name with an explicit realm when
// ServiceRealm is configured. | resolvedService 在配置 ServiceRealm 时返回带显式 realm
// 的服务名。
func (g *GSSClient) resolvedService() (string, error) {
	service := g.opts.Service
	if g.opts.ServiceRealm == "" {
		return service, nil
	}
	_, realm, err := ParseServicePrincipal(service, "")
	if err != nil {
		return "", err
	}
	if realm == "" {
		return service + "@" + g.opts.ServiceRealm, nil
	}
	if realm != g.opts.ServiceRealm {
		return "", errs.Detail(ErrInvalidConfig, "service realm %s differs from configured realm %s | 服务 realm %s 与配置 realm %s 不同",
			realm, g.opts.ServiceRealm, realm, g.opts.ServiceRealm)
	}
	return service, nil
}

// channelBindings returns the 16-octet binding value asserted in the authenticator. |
// channelBindings 返回认证器中声明的 16 字节绑定值。
func (g *GSSClient) channelBindings() []byte {
	out := make([]byte, 16)
	if len(g.opts.ChannelBindings) == 16 {
		copy(out, g.opts.ChannelBindings)
	}
	return out
}

// randomKey generates a random protocol key of etype. | randomKey 生成 etype 的随机协议密钥。
func randomKey(etype int32) (EncryptionKey, error) {
	size, err := KeySize(etype)
	if err != nil {
		return EncryptionKey{}, err
	}
	value := make([]byte, size)
	if _, err := rand.Read(value); err != nil {
		return EncryptionKey{}, errs.WrapDetail(err, ErrRandom, "subkey generation failed | 子密钥生成失败")
	}
	return EncryptionKey{KeyType: etype, KeyValue: value}, nil
}

// gssWrapKerberosToken frames an OID and Kerberos TOK_ID as a GSS initial context
// token. | gssWrapKerberosToken 把 OID 与 Kerberos TOK_ID 封装为 GSS 初始上下文令牌。
func gssWrapKerberosToken(oid []uint32, tokID uint16, payload []byte) []byte {
	content := derAppendOID(nil, oid)
	content = append(content, byte(tokID>>8), byte(tokID))
	content = append(content, payload...)
	return derAppendApplication(nil, 0, content)
}

// gssUnframe extracts the OID and remaining bytes of a GSS initial context token. |
// gssUnframe 提取 GSS 初始上下文令牌的 OID 与剩余字节。
func gssUnframe(data []byte) ([]uint32, []byte, error) {
	if len(data) == 0 || data[0] != byte(derTagApplicationBase) {
		return nil, nil, errs.Detail(ErrGSSAPI, "token is not a GSS initial context token | 令牌不是 GSS 初始上下文令牌")
	}
	r := newDERReader(data)
	content, err := r.expect(byte(derTagApplicationBase))
	if err != nil {
		return nil, nil, err
	}
	if err := r.end(); err != nil {
		return nil, nil, err
	}
	cr := newDERReader(content)
	oidContent, err := cr.expect(derTagOID)
	if err != nil {
		return nil, nil, err
	}
	oid, err := parseOIDContent(oidContent)
	if err != nil {
		return nil, nil, err
	}
	return oid, append([]byte(nil), content[cr.off:]...), nil
}

// parseKerberosMechToken splits a two-octet TOK_ID from a Kerberos mechanism
// token. | parseKerberosMechToken 从 Kerberos 机制令牌中切分两字节 TOK_ID。
func parseKerberosMechToken(data []byte) (uint16, []byte, error) {
	if len(data) < 2 {
		return 0, nil, errs.Detail(ErrGSSAPI, "Kerberos mechanism token is shorter than its TOK_ID | Kerberos 机制令牌短于其 TOK_ID")
	}
	return binary.BigEndian.Uint16(data[:2]), data[2:], nil
}

// parseKerberosGSSInput accepts a GSS-framed Kerberos token or a bare AP-REP /
// KRB-ERROR for interoperability. | parseKerberosGSSInput 接受 GSS 封装的 Kerberos
// 令牌，或为互操作接受裸 AP-REP / KRB-ERROR。
func parseKerberosGSSInput(data []byte) ([]uint32, uint16, []byte, error) {
	if len(data) > 0 && data[0] == byte(derTagApplicationBase) {
		oid, rest, err := gssUnframe(data)
		if err != nil {
			return nil, 0, nil, err
		}
		tokID, payload, err := parseKerberosMechToken(rest)
		if err != nil {
			return nil, 0, nil, err
		}
		return oid, tokID, payload, nil
	}
	if len(data) > 0 && data[0] == byte(derTagApplicationBase|15) {
		return gssOIDKerberosV5, gssTokenAPRep, data, nil
	}
	if len(data) > 0 && data[0] == byte(derTagApplicationBase|30) {
		return gssOIDKerberosV5, gssTokenKRBError, data, nil
	}
	return nil, 0, nil, errs.Detail(ErrGSSAPI, "unrecognized Kerberos GSS token | 无法识别的 Kerberos GSS 令牌")
}

// parseSPNEGOResponse decodes the acceptor half of a SPNEGO negotiation. It
// accepts a bare NegTokenResp, a GSS-framed negotiation token, or a bare Kerberos
// AP-REP. | parseSPNEGOResponse 解码 SPNEGO 协商的接受方部分。它接受裸 NegTokenResp、
// GSS 封装的协商令牌或裸 Kerberos AP-REP。
func parseSPNEGOResponse(data []byte) (negTokenResp, error) {
	var response negTokenResp
	if len(data) == 0 {
		return response, errs.Detail(ErrSPNEGO, "empty SPNEGO token | 空 SPNEGO 令牌")
	}
	if isSPNEGOToken(data) {
		return parseNegTokenResp(data)
	}
	if data[0] == byte(derTagApplicationBase|15) {
		token := gssWrapKerberosToken(gssOIDKerberosV5, gssTokenAPRep, data)
		return negTokenResp{responseToken: token}, nil
	}
	if data[0] != byte(derTagApplicationBase) {
		return response, errs.Detail(ErrSPNEGO, "unrecognized SPNEGO token prefix 0x%02x | 无法识别的 SPNEGO 令牌前缀 0x%02x",
			data[0], data[0])
	}
	oid, rest, err := gssUnframe(data)
	if err != nil {
		return response, err
	}
	if equalOID(oid, gssOIDSPNEGO) {
		if len(rest) == 0 {
			return response, errs.Detail(ErrSPNEGO, "SPNEGO token has no negotiation body | SPNEGO 令牌没有协商主体")
		}
		if isSPNEGOToken(rest) {
			return parseNegTokenResp(rest)
		}
		return response, errs.Detail(ErrSPNEGO, "SPNEGO negotiation body has prefix 0x%02x | SPNEGO 协商主体前缀为 0x%02x",
			rest[0], rest[0])
	}
	if equalOID(oid, gssOIDKerberosV5) || equalOID(oid, gssOIDMSLegacyKerberos) {
		return negTokenResp{responseToken: data}, nil
	}
	return response, errs.Detail(ErrSPNEGO, "unexpected GSS mechanism %s in SPNEGO exchange | SPNEGO 交换中出现意外的 GSS 机制 %s",
		formatOID(oid), formatOID(oid))
}

// gssTokenError decodes a Kerberos error token and returns its classified error. |
// gssTokenError 解码 Kerberos 错误令牌并返回其分类错误。
func gssTokenError(payload []byte) error {
	parsed, err := ParseKRBError(payload)
	if err != nil {
		return errs.WrapDetail(err, ErrGSSAPI, "malformed Kerberos error token | 畸形的 Kerberos 错误令牌")
	}
	return parsed.Err()
}

// gssChannelBindingMatches compares an authenticator channel-binding hash with
// the expected value. | gssChannelBindingMatches 比较认证器通道绑定哈希与期望值。
func gssChannelBindingMatches(actual, expected []byte) bool {
	return len(actual) == 16 && len(expected) == 16 && subtle.ConstantTimeCompare(actual, expected) == 1
}
