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

// NTLMOptions configures an NTLMv2 SASL bind. NTLMv1 and the NTLM2 session
// response stay disabled unless AllowLegacy is true. | NTLMOptions 配置 NTLMv2
// SASL 绑定。除非 AllowLegacy 为 true，否则 NTLMv1 与 NTLM2 会话响应保持禁用。
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
	return options, nil
}

// ntlmConfig converts the options into an NTLM client configuration. |
// ntlmConfig 把选项转换为 NTLM 客户端配置。
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
// NTLMv2 challenge-response exchange over the existing LDAP client. The Type 1,
// Type 2 and Type 3 messages are validated by ydx/auth/directory/ntlm; only
// NTLMv2 is enabled unless AllowLegacy is set. | BindNTLM 使用 SASL GSS-SPNEGO
// （默认）或裸 NTLM 在现有 LDAP 客户端上执行 NTLMv2 挑战响应认证。Type 1、Type 2 与
// Type 3 消息由 ydx/auth/directory/ntlm 校验；除非设置 AllowLegacy，否则仅启用 NTLMv2。
func (c *Client) BindNTLM(ctx context.Context, options NTLMOptions) error {
	normalized, err := normalizeNTLMOptions(options)
	if err != nil {
		return err
	}
	// Validate response-mode gating before any network I/O. | 在任何网络 I/O 之前
	// 校验响应模式门禁。
	if _, err := ntlm.NewClient(normalized.ntlmConfig(nil)); err != nil {
		return wrapNTLMError(err)
	}
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

// performNTLMLocked performs one complete NTLM exchange without changing replay
// state. Channel bindings, if requested, are derived from the current TLS
// connection. | performNTLMLocked 执行一次完整 NTLM 交换且不改变重放状态。如请求通道
// 绑定，则从当前 TLS 连接派生。
func (c *Client) performNTLMLocked(ctx context.Context, options NTLMOptions) error {
	normalized, err := normalizeNTLMOptions(options)
	if err != nil {
		return err
	}
	var channelBindings []byte
	if normalized.ChannelBinding {
		channelBindings, err = c.ntlmChannelBindingLocked()
		if err != nil {
			return err
		}
	}
	client, err := ntlm.NewClient(normalized.ntlmConfig(channelBindings))
	if err != nil {
		return wrapNTLMError(err)
	}
	negotiate, err := client.Negotiate()
	if err != nil {
		return wrapNTLMError(err)
	}
	initial := negotiate
	if normalized.Mechanism == SASLMechanismGSSSPNEGO {
		initial, err = ntlm.EncodeSPNEGONegotiateInit(negotiate)
		if err != nil {
			return wrapNTLMError(err)
		}
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
	challenge := response.ServerSASLCredentials
	if len(challenge) == 0 {
		return errs.Detail(ErrNTLM, "server NTLM challenge is empty | 服务端 NTLM 挑战为空")
	}
	if normalized.Mechanism == SASLMechanismGSSSPNEGO {
		token, err := ntlm.ParseSPNEGOToken(challenge)
		if err != nil {
			return wrapNTLMError(err)
		}
		if err := checkNTLMChallengeToken(token); err != nil {
			return err
		}
		challenge = token.Token()
		if len(challenge) == 0 {
			return errs.Detail(ErrNTLM, "SPNEGO challenge carries no NTLM token | SPNEGO 挑战未携带 NTLM 令牌")
		}
	}
	authenticate, err := client.Authenticate(challenge)
	if err != nil {
		return wrapNTLMError(err)
	}
	final := authenticate
	if normalized.Mechanism == SASLMechanismGSSSPNEGO {
		final, err = ntlm.EncodeSPNEGOResponse(authenticate)
		if err != nil {
			return wrapNTLMError(err)
		}
	}
	response, err = c.saslBindLocked(ctx, normalized.Mechanism, final)
	if err != nil {
		return err
	}
	if response.Result.Code != ResultSuccess {
		return newResultError("SASL NTLM bind", response.Result)
	}
	if normalized.Mechanism == SASLMechanismGSSSPNEGO && len(response.ServerSASLCredentials) > 0 {
		if err := checkNTLMFinalToken(response.ServerSASLCredentials); err != nil {
			return err
		}
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

// checkNTLMChallengeToken validates the SPNEGO token that carries the Type 2
// challenge. | checkNTLMChallengeToken 校验携带 Type 2 挑战的 SPNEGO 令牌。
func checkNTLMChallengeToken(token *ntlm.SPNEGOToken) error {
	if !token.SupportsNTLM() {
		return errs.Detail(ErrNTLM, "SPNEGO server does not select NTLM | SPNEGO 服务端未选择 NTLM")
	}
	if !token.HasNegState {
		return nil
	}
	switch token.NegState {
	case ntlm.NegStateAcceptIncomplete:
		return nil
	case ntlm.NegStateReject:
		return errs.Detail(ErrNTLM, "server rejected SPNEGO negotiation | 服务端拒绝 SPNEGO 协商")
	case ntlm.NegStateRequestMIC:
		return errs.Detail(ErrNTLM, "server requires a SPNEGO mechListMIC, which is unsupported | 服务端要求 SPNEGO mechListMIC，不受支持")
	case ntlm.NegStateAcceptCompleted:
		return errs.Detail(ErrNTLM, "server completed SPNEGO before NTLM authentication | 服务端在 NTLM 认证前完成 SPNEGO")
	default:
		return errs.Detail(ErrNTLM, "unknown SPNEGO negotiation state | 未知 SPNEGO 协商状态")
	}
}

// checkNTLMFinalToken validates the optional SPNEGO token in the final bind
// response. | checkNTLMFinalToken 校验最终绑定响应中的可选 SPNEGO 令牌。
func checkNTLMFinalToken(data []byte) error {
	token, err := ntlm.ParseSPNEGOToken(data)
	if err != nil {
		return wrapNTLMError(err)
	}
	if !token.HasNegState {
		return nil
	}
	switch token.NegState {
	case ntlm.NegStateAcceptCompleted, ntlm.NegStateAcceptIncomplete:
		return nil
	case ntlm.NegStateReject:
		return errs.Detail(ErrNTLM, "server rejected SPNEGO negotiation | 服务端拒绝 SPNEGO 协商")
	case ntlm.NegStateRequestMIC:
		return errs.Detail(ErrNTLM, "server requires a SPNEGO mechListMIC, which is unsupported | 服务端要求 SPNEGO mechListMIC，不受支持")
	default:
		return errs.Detail(ErrNTLM, "unknown SPNEGO negotiation state | 未知 SPNEGO 协商状态")
	}
}

// wrapNTLMError keeps errors.Is working for both ErrNTLM and the underlying
// NTLM sentinel. | wrapNTLMError 使 errors.Is 同时匹配 ErrNTLM 与底层 NTLM 哨兵。
func wrapNTLMError(err error) error {
	if err == nil {
		return nil
	}
	return errs.WrapDetail(err, ErrNTLM, "NTLM authentication failed | NTLM 认证失败")
}
