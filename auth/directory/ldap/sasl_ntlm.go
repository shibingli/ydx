package ldap

import (
	"context"
	"strings"

	"github.com/shibingli/ydx/auth/directory/ntlm"
	"github.com/shibingli/ydx/errs"
)

// SASL mechanisms used for NTLM authentication. | 用于 NTLM 认证的 SASL 机制。
const (
	// SASLMechanismGSSSPNEGO is the RFC 4178 GSS-SPNEGO mechanism carrying
	// NTLMSSP tokens. | SASLMechanismGSSSPNEGO 是承载 NTLMSSP 令牌的 RFC 4178
	// GSS-SPNEGO 机制。
	SASLMechanismGSSSPNEGO = "GSS-SPNEGO"
	// SASLMechanismNTLM is the raw NTLMSSP SASL mechanism understood by some
	// servers. | SASLMechanismNTLM 是部分服务端支持的裸 NTLMSSP SASL 机制。
	SASLMechanismNTLM = "NTLM"
)

// connSASLSession is a key-bearing authentication session whose keying material
// must not outlive the transport that authenticated it. Both ntlm.Client and
// ntlm.SPNEGOClient implement it. | connSASLSession 是携带密钥材料的认证会话，其密钥
// 材料不得比完成认证的传输存活更久。ntlm.Client 与 ntlm.SPNEGOClient 都实现该接口。
type connSASLSession interface {
	// Close wipes the session keys. | Close 清零会话密钥。
	Close() error
}

// NTLMOptions configures an NTLMv2 SASL bind. NTLMv1 and the NTLM2 session
// response stay disabled unless AllowLegacy is true. | NTLMOptions 配置 NTLMv2
// SASL 绑定。除非 AllowLegacy 为 true，否则 NTLMv1 与 NTLM2 会话响应保持禁用。
//
// LDAP SASL NTLM defines no PDU security layer: the negotiated session key is
// retained only to verify the SPNEGO mechListMIC during the bind and is wiped
// when the connection closes or is replaced. This client never signs, seals,
// encrypts or decrypts LDAP PDUs with NTLM. | LDAP SASL NTLM 不定义 PDU 安全层：
// 协商出的会话密钥仅用于绑定期间校验 SPNEGO mechListMIC，并在连接关闭或被替换时清零。本客户端
// 绝不用 NTLM 对 LDAP PDU 进行签名、密封、加密或解密。
type NTLMOptions struct {
	// Username is the account name. DOMAIN\user and user@realm forms are
	// accepted. | Username 是账户名。接受 DOMAIN\user 与 user@realm 形式。
	Username string
	// Password is the account password. It is never logged. | Password 是账户口令。
	// 绝不记录日志。
	Password string
	// Domain is the Active Directory domain when Username is not a UPN or a
	// DOMAIN\user login. | 当 Username 不是 UPN 或 DOMAIN\user 登录时，Domain 是
	// Active Directory 域。
	Domain string
	// Workstation is the optional client workstation name. | Workstation 是可选客户端
	// 工作站名称。
	Workstation string
	// Mechanism is GSS-SPNEGO (default) or NTLM. | Mechanism 是 GSS-SPNEGO（默认）或
	// NTLM。
	Mechanism string
	// ResponseMode selects NTLMv2 (default), NTLMv1, or the NTLM2 session
	// response. Non-default modes require AllowLegacy. | ResponseMode 选择 NTLMv2
	// （默认）、NTLMv1 或 NTLM2 会话响应。非默认模式需要 AllowLegacy。
	ResponseMode ntlm.ResponseMode
	// AllowLegacy explicitly enables the legacy NTLMv1 and NTLM2 session
	// responses. | AllowLegacy 显式启用旧式 NTLMv1 与 NTLM2 会话响应。
	AllowLegacy bool
	// AllowMissingTargetInfo permits an NTLMv2 challenge without AV pairs.
	// Active Directory always supplies them. | AllowMissingTargetInfo 允许没有 AV 对的
	// NTLMv2 挑战。Active Directory 总会提供 AV 对。
	AllowMissingTargetInfo bool
	// ForceMIC requests a Type 3 MIC even when the server does not set
	// MsvAvMICPresent. MICs are implemented only for NTLMv2. | ForceMIC 即使在服务端未
	// 设置 MsvAvMICPresent 时也请求 Type 3 MIC。MIC 仅为 NTLMv2 实现。
	ForceMIC bool
	// RequireServerMIC requires the acceptor's final SPNEGO NegTokenResp to carry
	// a valid mechListMIC. It applies only to GSS-SPNEGO and fails closed when the
	// server sends no final token or omits the MIC. | RequireServerMIC 要求接受方的最终
	// SPNEGO NegTokenResp 携带有效的 mechListMIC。它仅适用于 GSS-SPNEGO，并在服务端未发送
	// 最终令牌或省略 MIC 时失败关闭。
	RequireServerMIC bool
	// ChannelBinding derives a tls-server-end-point channel binding from the TLS
	// peer certificate and authenticates its hash in MsvAvChannelBindings. It
	// requires a TLS-protected connection and NTLMv2. | ChannelBinding 从 TLS 对端证书
	// 派生 tls-server-end-point 通道绑定，并在 MsvAvChannelBindings 中认证其哈希。它要求
	// TLS 保护的连接与 NTLMv2。
	ChannelBinding bool
}

// normalizeNTLMOptions validates mechanism selection and credentials shared by
// the initial bind and connection replay. | normalizeNTLMOptions 校验初始绑定与连接
// 重放共用的机制选择与凭据。
func normalizeNTLMOptions(options NTLMOptions) (NTLMOptions, error) {
	mechanism := strings.ToUpper(strings.TrimSpace(options.Mechanism))
	if mechanism == "" {
		mechanism = SASLMechanismGSSSPNEGO
	}
	switch mechanism {
	case SASLMechanismGSSSPNEGO, SASLMechanismNTLM:
	default:
		return NTLMOptions{}, errs.Detail(ErrNTLM, "unsupported SASL mechanism %q | 不支持的 SASL 机制 %q", options.Mechanism, options.Mechanism)
	}
	options.Mechanism = mechanism
	if strings.TrimSpace(options.Username) == "" {
		return NTLMOptions{}, errs.Detail(ErrNTLM, "NTLM username is empty | NTLM 用户名为空")
	}
	if options.Password == "" {
		return NTLMOptions{}, ErrEmptyPassword
	}
	if strings.IndexByte(options.Username, 0) >= 0 || strings.IndexByte(options.Password, 0) >= 0 ||
		strings.IndexByte(options.Domain, 0) >= 0 || strings.IndexByte(options.Workstation, 0) >= 0 {
		return NTLMOptions{}, errs.Detail(ErrNTLM, "NTLM credentials contain NUL | NTLM 凭据包含 NUL")
	}
	if _, _, err := ntlm.SplitUsername(options.Username, options.Domain); err != nil {
		return NTLMOptions{}, errs.WrapDetail(err, ErrNTLM, "NTLM login is invalid | NTLM 登录名非法")
	}
	if options.ChannelBinding && options.ResponseMode != ntlm.ResponseNTLMv2 {
		return NTLMOptions{}, errs.Detail(ErrNTLM, "channel binding requires NTLMv2 | 通道绑定需要 NTLMv2")
	}
	if options.RequireServerMIC && mechanism != SASLMechanismGSSSPNEGO {
		return NTLMOptions{}, errs.Detail(ErrNTLM, "RequireServerMIC requires GSS-SPNEGO | RequireServerMIC 需要 GSS-SPNEGO")
	}
	return options, nil
}

// ntlmConfig converts the options into an NTLM client configuration. NTLM
// message signing, sealing and session-key exchange are deliberately left
// disabled: LDAP SASL NTLM has no PDU security layer. | ntlmConfig 把选项转换为
// NTLM 客户端配置。NTLM 消息签名、密封与会话密钥交换被有意保持禁用：LDAP SASL NTLM 没有
// PDU 安全层。
func (o NTLMOptions) ntlmConfig(channelBindings []byte) ntlm.Config {
	return ntlm.Config{
		Domain:                 o.Domain,
		Username:               o.Username,
		Password:               o.Password,
		Workstation:            o.Workstation,
		ResponseMode:           o.ResponseMode,
		AllowLegacy:            o.AllowLegacy,
		AllowMissingTargetInfo: o.AllowMissingTargetInfo,
		ForceMIC:               o.ForceMIC,
		ChannelBindings:        channelBindings,
	}
}

// BindNTLM authenticates with SASL GSS-SPNEGO (default) or raw NTLM carrying an
// NTLMv2 challenge-response exchange over the existing LDAP client. GSS-SPNEGO
// uses ntlm.SPNEGOClient, which handles NegState (including request-mic and
// accept-incomplete), generates the client mechListMIC and verifies the server
// mechListMIC fail closed. Raw NTLM uses ntlm.Client directly. The Type 1, Type
// 2 and Type 3 messages are validated by ydx/auth/directory/ntlm; only NTLMv2 is
// enabled unless AllowLegacy is set. Every bind starts a new exchange that
// renegotiates from a fresh Type 1 message, and the negotiated session key is
// bound to the connection and wiped on close or reconnect. | BindNTLM 使用 SASL
// GSS-SPNEGO（默认）或裸 NTLM 在现有 LDAP 客户端上执行 NTLMv2 挑战响应认证。GSS-SPNEGO
// 使用 ntlm.SPNEGOClient 处理 NegState（包括 request-mic 与 accept-incomplete）、生成客户端
// mechListMIC 并失败关闭地校验服务端 mechListMIC。裸 NTLM 直接使用 ntlm.Client。Type 1、
// Type 2 与 Type 3 消息由 ydx/auth/directory/ntlm 校验；除非设置 AllowLegacy，否则仅启用
// NTLMv2。每次绑定都从全新的 Type 1 消息开始重新协商，协商出的会话密钥绑定到连接，并在连接
// 关闭或重连时清零。
func (c *Client) BindNTLM(ctx context.Context, options NTLMOptions) error {
	normalized, err := normalizeNTLMOptions(options)
	if err != nil {
		return err
	}
	// Validate response-mode gating before any network I/O. The probe client
	// derives key material, so wipe it immediately. | 在任何网络 I/O 之前校验响应模式
	// 门禁。探测客户端会派生密钥材料，因此立即清零。
	probe, err := ntlm.NewClient(normalized.ntlmConfig(nil))
	if err != nil {
		return wrapNTLMError(err)
	}
	_ = probe.Close()
	release, err := c.acquire(ctx, false)
	if err != nil {
		return err
	}
	defer release()
	if err := c.performNTLMLocked(ctx, normalized); err != nil {
		c.auth = nil
		return err
	}
	c.auth = &authState{kind: authNTLM, ntlm: normalized}
	return nil
}

// BindSASLNTLM is an alias for BindNTLM retained for callers that used the
// earlier method name. | BindSASLNTLM 是 BindNTLM 的别名，供使用旧方法名的调用方使用。
func (c *Client) BindSASLNTLM(ctx context.Context, options NTLMOptions) error {
	return c.BindNTLM(ctx, options)
}

// ntlmExchange is one NTLM SASL authentication exchange. One instance performs
// exactly one exchange and must be discarded afterwards; a reconnect builds a
// new instance and renegotiates from a new Type 1 message. | ntlmExchange 是一次
// NTLM SASL 认证交换。一个实例只执行一次交换，之后必须丢弃；重连会构建新实例并从新的
// Type 1 消息重新协商。
type ntlmExchange interface {
	connSASLSession
	// Initial returns the first client token. | Initial 返回第一个客户端令牌。
	Initial() ([]byte, error)
	// Respond consumes the server challenge and returns the final client
	// token. | Respond 消费服务端挑战并返回最终客户端令牌。
	Respond(challenge []byte) ([]byte, error)
	// Final consumes an optional final server token fail closed. | Final 失败关闭地
	// 消费可选的服务端最终令牌。
	Final(token []byte) error
	// Complete finishes an exchange whose server sent no final token. |
	// Complete 结束服务端未发送最终令牌的交换。
	Complete() error
}

// newNTLMExchange builds the exchange driver for the selected SASL mechanism. |
// newNTLMExchange 为所选 SASL 机制构建交换驱动器。
func newNTLMExchange(options NTLMOptions, channelBindings []byte) (ntlmExchange, error) {
	if options.Mechanism == SASLMechanismGSSSPNEGO {
		client, err := ntlm.NewSPNEGOClient(options.ntlmConfig(channelBindings))
		if err != nil {
			return nil, wrapNTLMError(err)
		}
		return &ntlmSPNEGOExchange{client: client}, nil
	}
	client, err := ntlm.NewClient(options.ntlmConfig(channelBindings))
	if err != nil {
		return nil, wrapNTLMError(err)
	}
	return &ntlmRawExchange{client: client}, nil
}

// ntlmSPNEGOExchange drives a GSS-SPNEGO exchange with ntlm.SPNEGOClient. |
// ntlmSPNEGOExchange 使用 ntlm.SPNEGOClient 驱动 GSS-SPNEGO 交换。
type ntlmSPNEGOExchange struct {
	client *ntlm.SPNEGOClient
}

// Initial returns the GSS-API InitialContextToken with the Type 1 message. |
// Initial 返回携带 Type 1 消息的 GSS-API InitialContextToken。
func (e *ntlmSPNEGOExchange) Initial() ([]byte, error) {
	return e.client.InitialToken()
}

// Respond consumes the wrapped Type 2 challenge and returns the final
// NegTokenResp carrying the Type 3 message and mechListMIC. | Respond 消费包装的
// Type 2 挑战并返回携带 Type 3 消息与 mechListMIC 的最终 NegTokenResp。
func (e *ntlmSPNEGOExchange) Respond(challenge []byte) ([]byte, error) {
	return e.client.AcceptToken(challenge)
}

// Final verifies the optional final server NegTokenResp, including its
// mechListMIC when present. | Final 校验可选的服务端最终 NegTokenResp，包括存在时的
// mechListMIC。
func (e *ntlmSPNEGOExchange) Final(token []byte) error {
	_, err := e.client.AcceptToken(token)
	return err
}

// Complete marks the exchange completed when the server sent no final token. |
// Complete 在服务端未发送最终令牌时把交换标记为完成。
func (e *ntlmSPNEGOExchange) Complete() error {
	return e.client.Complete()
}

// Close wipes the SPNEGO client's session keys. | Close 清零 SPNEGO 客户端的会话密钥。
func (e *ntlmSPNEGOExchange) Close() error {
	return e.client.Close()
}

// ntlmRawExchange drives a raw NTLMSSP exchange with ntlm.Client. |
// ntlmRawExchange 使用 ntlm.Client 驱动裸 NTLMSSP 交换。
type ntlmRawExchange struct {
	client *ntlm.Client
}

// Initial returns the Type 1 NEGOTIATE_MESSAGE. | Initial 返回 Type 1
// NEGOTIATE_MESSAGE。
func (e *ntlmRawExchange) Initial() ([]byte, error) {
	return e.client.Negotiate()
}

// Respond consumes the Type 2 challenge and returns the Type 3 message. |
// Respond 消费 Type 2 挑战并返回 Type 3 消息。
func (e *ntlmRawExchange) Respond(challenge []byte) ([]byte, error) {
	return e.client.Authenticate(challenge)
}

// Final rejects a final success payload because raw NTLM defines no server
// token after the Type 3 message. | Final 拒绝最终成功载荷，因为裸 NTLM 在 Type 3
// 消息之后不定义服务端令牌。
func (e *ntlmRawExchange) Final(token []byte) error {
	if len(token) > 0 {
		return errs.Detail(ErrNTLM, "raw NTLM success carries unexpected SASL data | 裸 NTLM 成功响应携带意外的 SASL 数据")
	}
	return nil
}

// Complete accepts the absence of a final server token. | Complete 接受服务端没有最终
// 令牌的情况。
func (e *ntlmRawExchange) Complete() error {
	return nil
}

// Close wipes the raw NTLM client's session keys. | Close 清零裸 NTLM 客户端的会话密钥。
func (e *ntlmRawExchange) Close() error {
	return e.client.Close()
}

// performNTLMLocked performs one complete NTLM exchange without changing replay
// state. Channel bindings, if requested, are derived from the current TLS
// connection. On success the session key is bound to the transport so that
// closing or replacing the connection wipes it. | performNTLMLocked 执行一次完整
// NTLM 交换且不改变重放状态。如请求通道绑定，则从当前 TLS 连接派生。成功后会话密钥绑定到
// 传输，因此关闭或替换连接会将其清零。
func (c *Client) performNTLMLocked(ctx context.Context, options NTLMOptions) error {
	normalized, err := normalizeNTLMOptions(options)
	if err != nil {
		return err
	}
	if c.conn == nil {
		return ErrClosed
	}
	var channelBindings []byte
	if normalized.ChannelBinding {
		channelBindings, err = c.ntlmChannelBindingLocked()
		if err != nil {
			return err
		}
	}
	// A new Bind resets the server-side authorization state, so the previous
	// session is no longer usable. | 新的绑定会重置服务端授权状态，因此旧会话不再可用。
	c.conn.closeSASLSession()
	exchange, err := newNTLMExchange(normalized, channelBindings)
	if err != nil {
		return err
	}
	attached := false
	defer func() {
		if !attached {
			_ = exchange.Close()
		}
	}()
	initial, err := exchange.Initial()
	if err != nil {
		return wrapNTLMError(err)
	}
	response, err := c.saslBindLocked(ctx, normalized.Mechanism, initial)
	if err != nil {
		return err
	}
	if response.Result.Code == ResultSuccess {
		return errs.Detail(ErrNTLM, "server completed NTLM without a challenge | 服务端未挑战即完成 NTLM")
	}
	if response.Result.Code != ResultSASLBindInProgress {
		return newResultError("SASL NTLM bind", response.Result)
	}
	if len(response.ServerSASLCredentials) == 0 {
		return errs.Detail(ErrNTLM, "server NTLM challenge is empty | 服务端 NTLM 挑战为空")
	}
	final, err := exchange.Respond(response.ServerSASLCredentials)
	if err != nil {
		return wrapNTLMError(err)
	}
	response, err = c.saslBindLocked(ctx, normalized.Mechanism, final)
	if err != nil {
		return err
	}
	if response.Result.Code != ResultSuccess {
		if response.Result.Code == ResultSASLBindInProgress {
			// The ntlm package completes NTLM SPNEGO in at most two round
			// trips; an extra round cannot be answered without inventing a
			// token, and continuing would leave the SASL exchange half open.
			// | ntlm 包最多用两个往返完成 NTLM SPNEGO；额外轮次无法在不编造令牌的
			// 情况下应答，继续下去会让 SASL 交换处于半开状态。
			c.invalidateConnLocked()
			return errs.Detail(ErrNTLM, "server requested another SPNEGO round after the Type 3 message | 服务端在 Type 3 消息之后请求额外 SPNEGO 轮次")
		}
		return newResultError("SASL NTLM bind", response.Result)
	}
	if len(response.ServerSASLCredentials) > 0 {
		if normalized.RequireServerMIC {
			if err := checkNTLMServerMechListMIC(response.ServerSASLCredentials); err != nil {
				c.invalidateConnLocked()
				return err
			}
		}
		if err := exchange.Final(response.ServerSASLCredentials); err != nil {
			// The server reported success but the final SPNEGO token or its
			// mechListMIC failed. Never fall back to unauthenticated framing:
			// tear the connection down instead. | 服务端报告成功，但最终 SPNEGO
			// 令牌或其 mechListMIC 校验失败。绝不回退到无认证的分帧：直接拆掉连接。
			c.invalidateConnLocked()
			return wrapNTLMError(err)
		}
	} else {
		if normalized.RequireServerMIC {
			c.invalidateConnLocked()
			return errs.Detail(ErrNTLM, "server did not return a final SPNEGO token with a mechListMIC | 服务端未返回携带 mechListMIC 的最终 SPNEGO 令牌")
		}
		if err := exchange.Complete(); err != nil {
			c.invalidateConnLocked()
			return wrapNTLMError(err)
		}
	}
	c.conn.bindSASLSession(exchange)
	attached = true
	return nil
}

// checkNTLMServerMechListMIC verifies that a final SPNEGO token carries a
// mechListMIC before ntlm.SPNEGOClient verifies its value. | checkNTLMServerMechListMIC
// 在 ntlm.SPNEGOClient 校验其值之前确认最终 SPNEGO 令牌携带 mechListMIC。
func checkNTLMServerMechListMIC(data []byte) error {
	token, err := ntlm.ParseSPNEGOToken(data)
	if err != nil {
		return wrapNTLMError(err)
	}
	if !token.HasMechListMIC {
		return errs.Detail(ErrNTLM, "server final SPNEGO token has no mechListMIC | 服务端最终 SPNEGO 令牌没有 mechListMIC")
	}
	return nil
}

// ntlmChannelBindingLocked derives the 16-byte GSS channel binding from the
// current TLS peer certificate. | ntlmChannelBindingLocked 从当前 TLS 对端证书派生
// 16 字节 GSS 通道绑定。
func (c *Client) ntlmChannelBindingLocked() ([]byte, error) {
	if c.conn == nil || !c.conn.secure {
		return nil, ErrTLSRequired
	}
	certificates := c.conn.tlsState.PeerCertificates
	if len(certificates) == 0 {
		return nil, errs.Detail(ErrNTLM, "TLS connection has no peer certificate | TLS 连接没有对端证书")
	}
	endpointHash, err := tlsServerEndPoint(certificates[0])
	if err != nil {
		return nil, errs.WrapDetail(err, ErrNTLM, "cannot hash the peer certificate | 无法计算对端证书哈希")
	}
	binding, err := ntlm.ChannelBindingHash(endpointHash)
	if err != nil {
		return nil, errs.WrapDetail(err, ErrNTLM, "cannot derive the channel binding | 无法派生通道绑定")
	}
	return binding, nil
}

// wrapNTLMError keeps errors.Is working for both ErrNTLM and the underlying
// NTLM sentinel. | wrapNTLMError 使 errors.Is 同时匹配 ErrNTLM 与底层 NTLM 哨兵。
func wrapNTLMError(err error) error {
	if err == nil {
		return nil
	}
	return errs.WrapDetail(err, ErrNTLM, "NTLM authentication failed | NTLM 认证失败")
}
