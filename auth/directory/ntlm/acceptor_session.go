package ntlm

import (
	"github.com/shibingli/ydx/errs"
)

// SecuritySession returns the connection-oriented NTLMSSP signing and sealing
// state created by a successful AcceptFinal. The returned session is safe for
// concurrent use and shares its lifetime with the acceptor: closing the acceptor
// closes the session. It returns ErrSessionSecurity when neither message signing
// nor message sealing was negotiated, and ErrAcceptorState before AcceptFinal or
// after Close. | SecuritySession 返回成功的 AcceptFinal 创建的面向连接的 NTLMSSP
// 签名与密封状态。返回的会话可安全并发使用，并与接受方共享生命周期：关闭接受方会关闭会话。
// 未协商消息签名与消息密封时返回 ErrSessionSecurity，AcceptFinal 之前或 Close 之后返回
// ErrAcceptorState。
func (a *Acceptor) SecuritySession() (*SecuritySession, error) {
	a.mu.Lock()
	defer a.mu.Unlock()
	if a.closed {
		return nil, errs.Detail(ErrAcceptorState, "acceptor is closed | 接受方已关闭")
	}
	if a.state != SPNEGOStateCompleted {
		return nil, errs.Detail(ErrAcceptorState, "security session requires a completed AcceptFinal | 安全会话需要已完成的 AcceptFinal")
	}
	if a.security == nil {
		return nil, errs.Detail(ErrSessionSecurity, "message signing and sealing were not negotiated | 未协商消息签名或密封")
	}
	return a.security, nil
}

// ExportedSessionKey returns a copy of the 16-byte session key exported by the
// exchange. With FlagKeyExchange it is the decrypted Type 3 SessionKey;
// otherwise it equals the NTLMv2 SessionBaseKey. The copy is keying material and
// the caller should wipe it when no longer needed. | ExportedSessionKey 返回交换
// 导出的 16 字节会话密钥副本。协商 FlagKeyExchange 时它是解密后的 Type 3 SessionKey；
// 否则等于 NTLMv2 SessionBaseKey。副本是密钥材料，调用方应在不再需要时清零。
func (a *Acceptor) ExportedSessionKey() ([]byte, error) {
	a.mu.Lock()
	defer a.mu.Unlock()
	if a.closed {
		return nil, errs.Detail(ErrAcceptorState, "acceptor is closed | 接受方已关闭")
	}
	if a.state != SPNEGOStateCompleted {
		return nil, errs.Detail(ErrAcceptorState, "exported session key requires a completed AcceptFinal | 导出会话密钥需要已完成的 AcceptFinal")
	}
	if len(a.exportedSessionKey) == 0 {
		return nil, errs.Detail(ErrSessionSecurity, "exported session key is unavailable | 导出会话密钥不可用")
	}
	return append([]byte(nil), a.exportedSessionKey...), nil
}

// Sign returns the 16-byte server-to-client NTLMSSP message signature for
// message. It requires negotiated FlagSign and advances the server-to-client
// sequence number. | Sign 返回 message 的 16 字节服务端到客户端 NTLMSSP 消息签名。它
// 要求已协商 FlagSign，并推进服务端到客户端的序列号。
func (a *Acceptor) Sign(message []byte) ([]byte, error) {
	security, err := a.securityFor(FlagSign, ErrSigningNotNegotiated)
	if err != nil {
		return nil, err
	}
	return security.Sign(message)
}

// Verify checks a client-to-server NTLMSSP message signature in constant time
// and advances the client-to-server sequence number. It requires negotiated
// FlagSign. A mismatch fails the security session closed. | Verify 以常量时间校验
// 客户端到服务端的 NTLMSSP 消息签名，并推进客户端到服务端的序列号。它要求已协商 FlagSign。
// 不匹配会失败关闭安全会话。
func (a *Acceptor) Verify(message, signature []byte) error {
	security, err := a.securityFor(FlagSign, ErrSigningNotNegotiated)
	if err != nil {
		return err
	}
	return security.Verify(message, signature)
}

// Seal encrypts a server-to-client message with RC4 and appends its NTLMSSP
// signature. It requires negotiated FlagSeal and FlagSign and advances the
// server-to-client sequence number. | Seal 使用 RC4 加密服务端到客户端消息并附加其
// NTLMSSP 签名。它要求已协商 FlagSeal 与 FlagSign，并推进服务端到客户端的序列号。
func (a *Acceptor) Seal(message []byte) ([]byte, error) {
	security, err := a.securityFor(FlagSeal, ErrSealingNotNegotiated)
	if err != nil {
		return nil, err
	}
	return security.Seal(message)
}

// Unseal decrypts a client-to-server sealed message and verifies its trailing
// signature in constant time. It requires negotiated FlagSeal and FlagSign and
// advances the client-to-server sequence number. A mismatch fails the security
// session closed. | Unseal 解密客户端到服务端的密封消息，并以常量时间校验其尾部签名。它
// 要求已协商 FlagSeal 与 FlagSign，并推进客户端到服务端的序列号。不匹配会失败关闭安全
// 会话。
func (a *Acceptor) Unseal(sealed []byte) ([]byte, error) {
	security, err := a.securityFor(FlagSeal, ErrSealingNotNegotiated)
	if err != nil {
		return nil, err
	}
	return security.Unseal(sealed)
}

// securityFor returns the security session when the required capability was
// negotiated. | securityFor 在所需能力已协商时返回安全会话。
func (a *Acceptor) securityFor(required NegotiateFlags, missing error) (*SecuritySession, error) {
	a.mu.Lock()
	defer a.mu.Unlock()
	if a.closed {
		return nil, errs.Detail(ErrAcceptorState, "acceptor is closed | 接受方已关闭")
	}
	if a.state != SPNEGOStateCompleted {
		return nil, errs.Detail(ErrAcceptorState, "message security requires a completed AcceptFinal | 消息安全需要已完成的 AcceptFinal")
	}
	if a.security == nil || !a.security.Flags().Has(required) {
		return nil, errs.Detail(missing, "negotiated flags do not include the required capability | 协商标志缺少所需能力")
	}
	return a.security, nil
}

// Close wipes the retained exported session key and closes the security session.
// Close is idempotent. | Close 清零保留的导出会话密钥并关闭安全会话。Close 可重复调用。
func (a *Acceptor) Close() error {
	a.mu.Lock()
	if a.closed {
		a.mu.Unlock()
		return nil
	}
	a.closed = true
	security := a.security
	a.security = nil
	wipe(a.exportedSessionKey)
	a.exportedSessionKey = nil
	a.mu.Unlock()
	if security != nil {
		return security.Close()
	}
	return nil
}
