package ntlm

import (
	"github.com/shibingli/ydx/errs"
)

// NegotiatedFlags returns the flag set carried by the Type 3 message. The
// result is available only after a successful Authenticate call. | NegotiatedFlags
// 返回 Type 3 消息携带的标志集。仅在 Authenticate 成功后可用。
func (c *Client) NegotiatedFlags() (NegotiateFlags, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.closed {
		return 0, errs.Detail(ErrClientState, "client is closed | 客户端已关闭")
	}
	if c.state != clientStateAuthenticated {
		return 0, errs.Detail(ErrClientState, "negotiated flags require a completed Authenticate | 协商标志需要已完成的 Authenticate")
	}
	return c.negotiatedFlags, nil
}

// UsedMIC reports whether the Type 3 message produced by Authenticate contains
// an NTLM MIC. | UsedMIC 报告 Authenticate 生成的 Type 3 消息是否包含 NTLM MIC。
func (c *Client) UsedMIC() bool {
	c.mu.Lock()
	defer c.mu.Unlock()
	return !c.closed && c.usedMIC
}

// MechListMIC computes the SPNEGO mechListMIC for the retained NTLMv2 session
// base key over a DER-encoded SEQUENCE OF OID mechanism list. It must be called
// after Authenticate. Legacy response modes do not derive a session base key
// and therefore return ErrMechListMIC. | MechListMIC 使用保留的 NTLMv2 会话基础密钥，
// 对 DER 编码的 SEQUENCE OF OID 机制列表计算 SPNEGO mechListMIC。必须在 Authenticate
// 之后调用。旧式响应模式不派生会话基础密钥，因此返回 ErrMechListMIC。
func (c *Client) MechListMIC(mechTypesDER []byte) ([]byte, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.closed {
		return nil, errs.Detail(ErrClientState, "client is closed | 客户端已关闭")
	}
	if c.state != clientStateAuthenticated {
		return nil, errs.Detail(ErrClientState, "mechListMIC requires a completed Authenticate | mechListMIC 需要已完成的 Authenticate")
	}
	if len(c.sessionBaseKey) == 0 {
		return nil, errs.Detail(ErrMechListMIC, "session base key is unavailable for the selected response mode | 所选响应模式没有会话基础密钥")
	}
	return ComputeMechListMIC(c.sessionBaseKey, mechTypesDER, c.negotiatedFlags)
}

// VerifyMechListMIC verifies a server-provided mechListMIC in constant time
// using the retained NTLMv2 session base key and negotiated flags. It must be
// called after Authenticate. | VerifyMechListMIC 使用保留的 NTLMv2 会话基础密钥与
// 协商标志，以常量时间校验服务端提供的 mechListMIC。必须在 Authenticate 之后调用。
func (c *Client) VerifyMechListMIC(mechTypesDER, mic []byte) error {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.closed {
		return errs.Detail(ErrClientState, "client is closed | 客户端已关闭")
	}
	if c.state != clientStateAuthenticated {
		return errs.Detail(ErrClientState, "mechListMIC verification requires a completed Authenticate | mechListMIC 校验需要已完成的 Authenticate")
	}
	if len(c.sessionBaseKey) == 0 {
		return errs.Detail(ErrMechListMIC, "session base key is unavailable for the selected response mode | 所选响应模式没有会话基础密钥")
	}
	return VerifyMechListMIC(c.sessionBaseKey, mechTypesDER, mic, c.negotiatedFlags)
}

// SecuritySession returns the connection-oriented NTLMSSP signing and sealing
// state created by a successful Authenticate. The returned session is safe for
// concurrent use and shares its lifetime with the client: closing the client
// closes the session. It returns ErrSessionSecurity when neither message signing
// nor message sealing was negotiated, and ErrClientState before Authenticate or
// after Close. | SecuritySession 返回成功的 Authenticate 创建的面向连接的 NTLMSSP
// 签名与密封状态。返回的会话可安全并发使用，并与客户端共享生命周期：关闭客户端会关闭会话。
// 未协商消息签名与消息密封时返回 ErrSessionSecurity，Authenticate 之前或 Close 之后返回
// ErrClientState。
func (c *Client) SecuritySession() (*SecuritySession, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.closed {
		return nil, errs.Detail(ErrClientState, "client is closed | 客户端已关闭")
	}
	if c.state != clientStateAuthenticated {
		return nil, errs.Detail(ErrClientState, "security session requires a completed Authenticate | 安全会话需要已完成的 Authenticate")
	}
	if c.security == nil {
		return nil, errs.Detail(ErrSessionSecurity, "message signing and sealing were not negotiated | 未协商消息签名或密封")
	}
	return c.security, nil
}

// ExportedSessionKey returns a copy of the 16-byte session key exported by the
// exchange. With FlagKeyExchange it is the random key carried encrypted in the
// Type 3 SessionKey field; otherwise it equals the NTLMv2 SessionBaseKey. The
// copy is keying material and the caller should wipe it when no longer needed.
// Legacy response modes have no exported session key. | ExportedSessionKey 返回交换
// 导出的 16 字节会话密钥副本。协商 FlagKeyExchange 时它是 Type 3 SessionKey 字段中加密携带的
// 随机密钥；否则等于 NTLMv2 SessionBaseKey。副本是密钥材料，调用方应在不再需要时清零。旧式
// 响应模式没有导出会话密钥。
func (c *Client) ExportedSessionKey() ([]byte, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.closed {
		return nil, errs.Detail(ErrClientState, "client is closed | 客户端已关闭")
	}
	if c.state != clientStateAuthenticated {
		return nil, errs.Detail(ErrClientState, "exported session key requires a completed Authenticate | 导出会话密钥需要已完成的 Authenticate")
	}
	if len(c.exportedSessionKey) == 0 {
		return nil, errs.Detail(ErrSessionSecurity, "exported session key is unavailable for the selected response mode | 所选响应模式没有导出会话密钥")
	}
	return append([]byte(nil), c.exportedSessionKey...), nil
}

// Sign returns the 16-byte client-to-server NTLMSSP message signature for
// message. It requires negotiated FlagSign and advances the client-to-server
// sequence number. | Sign 返回 message 的 16 字节客户端到服务端 NTLMSSP 消息签名。它
// 要求已协商 FlagSign，并推进客户端到服务端的序列号。
func (c *Client) Sign(message []byte) ([]byte, error) {
	security, err := c.securityFor(FlagSign, ErrSigningNotNegotiated)
	if err != nil {
		return nil, err
	}
	return security.Sign(message)
}

// Verify checks a server-to-client NTLMSSP message signature in constant time
// and advances the server-to-client sequence number. It requires negotiated
// FlagSign. A mismatch fails the security session closed. | Verify 以常量时间校验
// 服务端到客户端的 NTLMSSP 消息签名，并推进服务端到客户端的序列号。它要求已协商 FlagSign。
// 不匹配会失败关闭安全会话。
func (c *Client) Verify(message, signature []byte) error {
	security, err := c.securityFor(FlagSign, ErrSigningNotNegotiated)
	if err != nil {
		return err
	}
	return security.Verify(message, signature)
}

// Seal encrypts a client-to-server message with RC4 and appends its NTLMSSP
// signature. It requires negotiated FlagSeal and FlagSign and advances the
// client-to-server sequence number. | Seal 使用 RC4 加密客户端到服务端消息并附加其
// NTLMSSP 签名。它要求已协商 FlagSeal 与 FlagSign，并推进客户端到服务端的序列号。
func (c *Client) Seal(message []byte) ([]byte, error) {
	security, err := c.securityFor(FlagSeal, ErrSealingNotNegotiated)
	if err != nil {
		return nil, err
	}
	return security.Seal(message)
}

// Unseal decrypts a server-to-client sealed message and verifies its trailing
// signature in constant time. It requires negotiated FlagSeal and FlagSign and
// advances the server-to-client sequence number. A mismatch fails the security
// session closed. | Unseal 解密服务端到客户端的密封消息，并以常量时间校验其尾部签名。它
// 要求已协商 FlagSeal 与 FlagSign，并推进服务端到客户端的序列号。不匹配会失败关闭安全
// 会话。
func (c *Client) Unseal(sealed []byte) ([]byte, error) {
	security, err := c.securityFor(FlagSeal, ErrSealingNotNegotiated)
	if err != nil {
		return nil, err
	}
	return security.Unseal(sealed)
}

// securityFor returns the security session when the required capability was
// negotiated. | securityFor 在所需能力已协商时返回安全会话。
func (c *Client) securityFor(required NegotiateFlags, missing error) (*SecuritySession, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.closed {
		return nil, errs.Detail(ErrClientState, "client is closed | 客户端已关闭")
	}
	if c.state != clientStateAuthenticated {
		return nil, errs.Detail(ErrClientState, "message security requires a completed Authenticate | 消息安全需要已完成的 Authenticate")
	}
	if c.security == nil || !c.negotiatedFlags.Has(required) {
		return nil, errs.Detail(missing, "negotiated flags do not include the required capability | 协商标志缺少所需能力")
	}
	return c.security, nil
}

// Close wipes the retained session keys, derived security state and message
// buffers. Close is idempotent. | Close 清零保留的会话密钥、派生安全状态与消息缓冲区。
// Close 可重复调用。
func (c *Client) Close() error {
	c.mu.Lock()
	if c.closed {
		c.mu.Unlock()
		return nil
	}
	c.closed = true
	security := c.security
	c.security = nil
	wipe(c.responseKey)
	wipe(c.lmResponseKey)
	wipe(c.sessionBaseKey)
	wipe(c.exportedSessionKey)
	wipe(c.randomSessionKey)
	wipe(c.negotiate)
	c.responseKey = nil
	c.lmResponseKey = nil
	c.sessionBaseKey = nil
	c.exportedSessionKey = nil
	c.randomSessionKey = nil
	c.negotiate = nil
	c.negotiatedFlags = 0
	c.usedMIC = false
	c.mu.Unlock()
	if security != nil {
		return security.Close()
	}
	return nil
}
