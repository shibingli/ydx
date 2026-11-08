package ldap

import (
	"context"
	"strings"
	"unicode/utf8"

	"github.com/shibingli/ydx/auth/directory/ntlm"
	"github.com/shibingli/ydx/auth/protocol/kerberos"
	"github.com/shibingli/ydx/errs"
)

const (
	// SASLMechanismGSSAPI is the RFC 4752 GSSAPI SASL mechanism. | SASLMechanismGSSAPI
	// 是 RFC 4752 GSSAPI SASL 机制。
	SASLMechanismGSSAPI = "GSSAPI"

	// gssapiLayerNone is the RFC 4752 no-security-layer bit. | gssapiLayerNone 是
	// RFC 4752 无安全层位。
	gssapiLayerNone byte = 1
	// gssapiAuthzIDMaxLen is the RFC 4752 authorization identity limit. | gssapiAuthzIDMaxLen
	// 是 RFC 4752 授权身份长度上限。
	gssapiAuthzIDMaxLen = 1024
)

// GSSAPIOptions configures a Kerberos GSSAPI SASL bind. | GSSAPIOptions 配置
// Kerberos GSSAPI SASL 绑定。
type GSSAPIOptions struct {
	// Client is the authenticated Kerberos client that obtains service tickets. It
	// is required and remains owned by the caller. | Client 是获取服务票据的已认证
	// Kerberos 客户端。该项必需，且仍归调用方所有。
	Client *kerberos.Client
	// Service is the LDAP service principal, for example "ldap/dc1.example.com". It
	// may carry an explicit realm. | Service 是 LDAP 服务主体，例如
	// "ldap/dc1.example.com"。它可以携带显式 realm。
	Service string
	// ServiceRealm overrides the realm used for a service name without one. | ServiceRealm
	// 覆盖未携带 realm 的服务名所用 realm。
	ServiceRealm string
	// AuthzID optionally requests an authorization identity. It must be valid UTF-8
	// without NUL bytes and at most 1024 octets (RFC 4752). | AuthzID 可选地请求
	// 授权身份。它必须是合法 UTF-8、不含 NUL 字节且不超过 1024 字节（RFC 4752）。
	AuthzID string
	// SPNEGO wraps the Kerberos context in SPNEGO negotiation tokens (GSS-SPNEGO
	// style). The SASL mechanism name remains GSSAPI. | SPNEGO 把 Kerberos 上下文包装
	// 在 SPNEGO 协商令牌中（GSS-SPNEGO 风格）。SASL 机制名仍为 GSSAPI。
	SPNEGO bool
	// ChannelBinding derives the tls-server-end-point channel binding from the TLS
	// peer certificate and authenticates it in the AP-REQ. It requires a
	// TLS-protected connection. | ChannelBinding 从 TLS 对端证书派生
	// tls-server-end-point 通道绑定并在 AP-REQ 中认证。它要求 TLS 保护的连接。
	ChannelBinding bool
	// newInitiator overrides the GSS initiator constructor in tests. | newInitiator
	// 在测试中覆盖 GSS 发起方构造器。
	newInitiator func(kerberos.GSSClientOptions) (gssInitiator, error)
}

// gssInitiator is the GSSAPI context subset used by the SASL bind. It is
// implemented by kerberos.GSSClient and replaced only in tests. | gssInitiator 是
// SASL 绑定使用的 GSSAPI 上下文子集。它由 kerberos.GSSClient 实现，仅在测试中替换。
type gssInitiator interface {
	// InitialToken produces the first context token. | InitialToken 生成第一个上下文令牌。
	InitialToken(ctx context.Context) ([]byte, error)
	// Step consumes one acceptor token. | Step 消费一个接受方令牌。
	Step(ctx context.Context, token []byte) ([]byte, bool, error)
	// Complete reports whether the context is established. | Complete 报告上下文是否已建立。
	Complete() bool
	// Wrap protects one message. | Wrap 保护一条消息。
	Wrap(data []byte, confidential bool) ([]byte, error)
	// Unwrap verifies and decrypts one message. | Unwrap 校验并解密一条消息。
	Unwrap(token []byte) ([]byte, bool, error)
}

// BindSASLGSSAPI authenticates with the RFC 4752 GSSAPI mechanism over the
// existing connection. The Kerberos context always requires mutual
// authentication, and the no-security-layer option is negotiated and verified;
// a server that selects integrity or confidentiality is rejected because this
// client does not wrap subsequent LDAP messages. The last successful options
// are retained for transparent replay after a reconnect. | BindSASLGSSAPI 在现有
// 连接上使用 RFC 4752 GSSAPI 机制认证。Kerberos 上下文始终要求双向认证，并协商与校验
// 无安全层选项；选择完整性或机密性层的服务端会被拒绝，因为本客户端不封装后续 LDAP 消息。
// 最后一次成功的选项会保留，用于重连后的透明重放。
func (c *Client) BindSASLGSSAPI(ctx context.Context, options GSSAPIOptions) error {
	normalized, err := normalizeGSSAPIOptions(options)
	if err != nil {
		return err
	}
	release, err := c.acquire(ctx, false)
	if err != nil {
		return err
	}
	defer release()
	if err := c.performSASLGSSAPILocked(ctx, normalized); err != nil {
		c.auth = nil
		return err
	}
	c.auth = &authState{kind: authGSSAPI, gssapi: normalized}
	return nil
}

// normalizeGSSAPIOptions validates the options shared by the initial bind and
// connection replay. | normalizeGSSAPIOptions 校验初始绑定与连接重放共用的选项。
func normalizeGSSAPIOptions(options GSSAPIOptions) (GSSAPIOptions, error) {
	if options.Client == nil {
		return GSSAPIOptions{}, errs.Detail(ErrInvalidConfig, "GSSAPI requires a Kerberos client | GSSAPI 需要 Kerberos 客户端")
	}
	options.Service = strings.TrimSpace(options.Service)
	if options.Service == "" {
		return GSSAPIOptions{}, errs.Detail(ErrInvalidConfig, "GSSAPI service principal is empty | GSSAPI 服务主体为空")
	}
	options.ServiceRealm = strings.TrimSpace(options.ServiceRealm)
	if len(options.AuthzID) > gssapiAuthzIDMaxLen {
		return GSSAPIOptions{}, errs.Detail(ErrSASL, "GSSAPI authzID exceeds %d octets | GSSAPI authzID 超过 %d 字节",
			gssapiAuthzIDMaxLen, gssapiAuthzIDMaxLen)
	}
	if !utf8.ValidString(options.AuthzID) {
		return GSSAPIOptions{}, errs.Detail(ErrSASL, "GSSAPI authzID is not valid UTF-8 | GSSAPI authzID 不是合法 UTF-8")
	}
	if strings.IndexByte(options.AuthzID, 0) >= 0 {
		return GSSAPIOptions{}, errs.Detail(ErrSASL, "GSSAPI authzID contains NUL | GSSAPI authzID 包含 NUL")
	}
	return options, nil
}

// buildGSSInitiator constructs the Kerberos GSS initiator for one SASL exchange. |
// buildGSSInitiator 为一次 SASL 交换构建 Kerberos GSS 发起方。
func (options GSSAPIOptions) buildGSSInitiator(channelBindings []byte) (gssInitiator, error) {
	clientOptions := kerberos.GSSClientOptions{
		Client:          options.Client,
		Service:         options.Service,
		ServiceRealm:    options.ServiceRealm,
		MutualAuth:      true,
		SPNEGO:          options.SPNEGO,
		ChannelBindings: append([]byte(nil), channelBindings...),
	}
	if options.newInitiator != nil {
		initiator, err := options.newInitiator(clientOptions)
		if err != nil {
			return nil, wrapGSSAPIError(err)
		}
		return initiator, nil
	}
	initiator, err := kerberos.NewGSSClient(clientOptions)
	if err != nil {
		return nil, wrapGSSAPIError(err)
	}
	return initiator, nil
}

// performSASLGSSAPILocked performs one complete GSSAPI SASL exchange without
// changing replay state. | performSASLGSSAPILocked 执行一次完整 GSSAPI SASL 交换，
// 且不改变重放状态。
func (c *Client) performSASLGSSAPILocked(ctx context.Context, options GSSAPIOptions) error {
	normalized, err := normalizeGSSAPIOptions(options)
	if err != nil {
		return err
	}
	var channelBindings []byte
	if normalized.ChannelBinding {
		channelBindings, err = c.gssapiChannelBindingLocked()
		if err != nil {
			return err
		}
	}
	initiator, err := normalized.buildGSSInitiator(channelBindings)
	if err != nil {
		return err
	}
	initial, err := initiator.InitialToken(ctx)
	if err != nil {
		return wrapGSSAPIError(err)
	}
	response, err := c.saslBindLocked(ctx, SASLMechanismGSSAPI, initial)
	if err != nil {
		return err
	}
	for !initiator.Complete() {
		if response.Result.Code == ResultSuccess {
			return errs.Detail(ErrSASL, "server completed the GSSAPI bind before the context was established | 服务端在 GSSAPI 上下文建立前完成绑定")
		}
		if response.Result.Code != ResultSASLBindInProgress {
			return newResultError("SASL GSSAPI bind", response.Result)
		}
		if len(response.ServerSASLCredentials) == 0 {
			return errs.Detail(ErrSASL, "server GSSAPI context challenge is empty | 服务端 GSSAPI 上下文挑战为空")
		}
		reply, done, err := initiator.Step(ctx, response.ServerSASLCredentials)
		if err != nil {
			return wrapGSSAPIError(err)
		}
		if !done && len(reply) == 0 {
			return errs.Detail(ErrSASL, "GSSAPI context is incomplete but the client produced no token | GSSAPI 上下文未完成但客户端未产生令牌")
		}
		response, err = c.saslBindLocked(ctx, SASLMechanismGSSAPI, reply)
		if err != nil {
			return err
		}
	}
	if response.Result.Code == ResultSuccess {
		// Some servers complete an unlayered bind without the RFC 4752 layer
		// challenge. Accept that only now that the context is authenticated. | 部分
		// 服务端在无安全层绑定时不发送 RFC 4752 安全层挑战。只有在上下文已认证后才接受。
		if len(response.ServerSASLCredentials) == 0 {
			return nil
		}
		if err := c.verifyGSSAPILayerSelection(initiator, response.ServerSASLCredentials); err != nil {
			return err
		}
		return nil
	}
	if response.Result.Code != ResultSASLBindInProgress {
		return newResultError("SASL GSSAPI bind", response.Result)
	}
	if len(response.ServerSASLCredentials) == 0 {
		return errs.Detail(ErrSASL, "server did not send a GSSAPI security layer challenge | 服务端未发送 GSSAPI 安全层挑战")
	}
	layers, maxBuffer, err := unwrapGSSAPILayerToken(initiator, response.ServerSASLCredentials, true)
	if err != nil {
		return err
	}
	if layers&gssapiLayerNone == 0 {
		return errs.Detail(ErrSASL, "server does not offer the no-security-layer option | 服务端未提供无安全层选项")
	}
	if layers == gssapiLayerNone && maxBuffer != 0 {
		return errs.Detail(ErrSASL, "server without a security layer advertised a non-zero buffer | 无安全层的服务端通告了非零缓冲区")
	}
	offer := make([]byte, 4, 4+len(normalized.AuthzID))
	offer[0] = gssapiLayerNone
	// The client does not implement a security layer, so its maximum receive
	// buffer is zero (RFC 4752). | 客户端未实现安全层，因此其最大接收缓冲区为零（RFC 4752）。
	offer = append(offer, normalized.AuthzID...)
	wrappedOffer, err := initiator.Wrap(offer, false)
	if err != nil {
		return wrapGSSAPIError(err)
	}
	response, err = c.saslBindLocked(ctx, SASLMechanismGSSAPI, wrappedOffer)
	if err != nil {
		return err
	}
	if response.Result.Code == ResultSuccess {
		if len(response.ServerSASLCredentials) > 0 {
			if err := c.verifyGSSAPILayerSelection(initiator, response.ServerSASLCredentials); err != nil {
				return err
			}
		}
		return nil
	}
	if response.Result.Code != ResultSASLBindInProgress {
		return newResultError("SASL GSSAPI bind", response.Result)
	}
	if len(response.ServerSASLCredentials) == 0 {
		return errs.Detail(ErrSASL, "server did not confirm the GSSAPI security layer | 服务端未确认 GSSAPI 安全层")
	}
	if err := c.verifyGSSAPILayerSelection(initiator, response.ServerSASLCredentials); err != nil {
		return err
	}
	response, err = c.saslBindLocked(ctx, SASLMechanismGSSAPI, nil)
	if err != nil {
		return err
	}
	if response.Result.Code != ResultSuccess {
		return newResultError("SASL GSSAPI bind", response.Result)
	}
	if len(response.ServerSASLCredentials) > 0 {
		return errs.Detail(ErrSASL, "server returned data with the final GSSAPI bind result | 服务端在最终 GSSAPI 绑定结果中返回了数据")
	}
	return nil
}

// unwrapGSSAPILayerToken unwraps an RFC 4752 four-octet layer token. When
// challenge is true the first octet is the server's supported-layer bitmask;
// otherwise it is the selected layer. | unwrapGSSAPILayerToken 解封 RFC 4752 四字节
// 安全层令牌。challenge 为 true 时首字节是服务端支持层位图，否则是选定层。
func unwrapGSSAPILayerToken(initiator gssInitiator, token []byte, challenge bool) (byte, int, error) {
	cleartext, confidential, err := initiator.Unwrap(token)
	if err != nil {
		return 0, 0, wrapGSSAPIError(err)
	}
	if confidential {
		return 0, 0, errs.Detail(ErrSASL, "GSSAPI security layer token is confidential | GSSAPI 安全层令牌使用了机密性保护")
	}
	if len(cleartext) != 4 {
		return 0, 0, errs.Detail(ErrSASL, "GSSAPI security layer token is %d octets, want 4 | GSSAPI 安全层令牌为 %d 字节，期望 4",
			len(cleartext), len(cleartext))
	}
	if challenge && cleartext[0] == 0 {
		return 0, 0, errs.Detail(ErrSASL, "server advertised no security layers | 服务端未通告任何安全层")
	}
	maxBuffer := int(cleartext[1])<<16 | int(cleartext[2])<<8 | int(cleartext[3])
	return cleartext[0], maxBuffer, nil
}

// verifyGSSAPILayerSelection verifies that the server selected the
// no-security-layer option this client offered. | verifyGSSAPILayerSelection 校验
// 服务端选择了本客户端提供的无安全层选项。
func (c *Client) verifyGSSAPILayerSelection(initiator gssInitiator, token []byte) error {
	selection, maxBuffer, err := unwrapGSSAPILayerToken(initiator, token, false)
	if err != nil {
		return err
	}
	if selection != gssapiLayerNone {
		return errs.Detail(ErrSASL, "server selected unsupported GSSAPI security layer %d | 服务端选择了不支持的 GSSAPI 安全层 %d",
			selection, selection)
	}
	// No security layer means the buffer limit is not applicable; RFC 4752
	// requires zero because the client advertised zero. | 无安全层时缓冲区上限不适用；
	// 由于客户端通告为零，RFC 4752 要求返回零。
	if maxBuffer != 0 {
		return errs.Detail(ErrSASL, "server selected no security layer but advertised buffer %d | 服务端选择无安全层却通告缓冲区 %d",
			maxBuffer, maxBuffer)
	}
	return nil
}

// gssapiChannelBindingLocked derives the tls-server-end-point GSS channel
// binding from the current TLS peer certificate. The result is the 16-octet
// value authenticated in the AP-REQ checksum and matches the NTLM channel
// binding construction used by this package. | gssapiChannelBindingLocked 从当前
// TLS 对端证书派生 tls-server-end-point GSS 通道绑定。结果是 AP-REQ 校验和中认证的
// 16 字节值，与本包 NTLM 通道绑定构造一致。
func (c *Client) gssapiChannelBindingLocked() ([]byte, error) {
	if c.conn == nil || !c.conn.secure {
		return nil, ErrTLSRequired
	}
	certificates := c.conn.tlsState.PeerCertificates
	if len(certificates) == 0 {
		return nil, errs.Detail(ErrSASL, "TLS connection has no peer certificate | TLS 连接没有对端证书")
	}
	endpointHash, err := tlsServerEndPoint(certificates[0])
	if err != nil {
		return nil, err
	}
	binding, err := ntlm.ChannelBindingHash(endpointHash)
	if err != nil {
		return nil, errs.WrapDetail(err, ErrSASL, "cannot derive the GSSAPI channel binding | 无法派生 GSSAPI 通道绑定")
	}
	return binding, nil
}

// wrapGSSAPIError keeps errors.Is working for both ErrSASL and the underlying
// Kerberos sentinel. | wrapGSSAPIError 使 errors.Is 同时匹配 ErrSASL 与底层
// Kerberos 哨兵。
func wrapGSSAPIError(err error) error {
	if err == nil {
		return nil
	}
	return errs.WrapDetail(err, ErrSASL, "SASL GSSAPI authentication failed | SASL GSSAPI 认证失败")
}
