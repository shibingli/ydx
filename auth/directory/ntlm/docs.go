// Package ntlm implements NTLMv2 client authentication as used by Active
// Directory. | ntlm 包实现 Active Directory 使用的 NTLMv2 客户端认证。
//
// # Protocol coverage | 协议覆盖
//
// The package encodes and decodes NTLMSSP Type 1 NEGOTIATE_MESSAGE, Type 2
// CHALLENGE_MESSAGE and Type 3 AUTHENTICATE_MESSAGE structures with full bounds
// checking, negotiates the MS-NLMP flag set, parses target-info AV pairs, and
// derives the NTLMv2 hash, NT proof string, NTLMv2 response, LMv2 response and
// session base key. It can add an MsvAvChannelBindings AV pair for RFC 5929
// tls-server-end-point channel binding and an NTLM MIC over the Type 1/2/3
// messages, including the zeroed-MIC encoding required by MS-NLMP 3.1.5.1.2. |
// 本包编码与解码 NTLMSSP Type 1 NEGOTIATE_MESSAGE、Type 2 CHALLENGE_MESSAGE 与 Type 3
// AUTHENTICATE_MESSAGE 结构，进行完整边界检查，协商 MS-NLMP 标志集，解析 target-info
// AV 对，并派生 NTLMv2 哈希、NT proof 字符串、NTLMv2 响应、LMv2 响应与会话基础密钥。
// 它可添加 MsvAvChannelBindings AV 对以支持 RFC 5929 tls-server-end-point 通道绑定，
// 并可在 Type 1/2/3 消息上附加 NTLM MIC，包括 MS-NLMP 3.1.5.1.2 要求的 MIC 置零编码。
//
// NTLMv1 and the NTLM2 session response exist only for compatibility with
// legacy servers. They are rejected unless Config.AllowLegacy is true; the
// default response mode is NTLMv2. Message signing and sealing are not
// implemented. | NTLMv1 与 NTLM2 会话响应仅用于兼容旧式服务端。除非
// Config.AllowLegacy 为 true，否则它们会被拒绝；默认响应模式是 NTLMv2。未实现消息签名与
// 密封。
//
// # SPNEGO | SPNEGO
//
// EncodeSPNEGONegotiateInit and ParseSPNEGOToken implement the minimal SPNEGO
// (RFC 4178) framing that Active Directory requires for SASL GSS-SPNEGO: a
// NegTokenInit advertising the NTLMSSP OID in the initial context token and a
// NegTokenResp carrying the Type 2 and Type 3 messages. They are helpers for
// the LDAP integration, not a general GSSAPI implementation. | EncodeSPNEGONegotiateInit
// 与 ParseSPNEGOToken 实现 Active Directory 的 SASL GSS-SPNEGO 所需的最小 SPNEGO
// （RFC 4178）分帧：初始上下文令牌中通过 NegTokenInit 声明 NTLMSSP OID，并用
// NegTokenResp 携带 Type 2 与 Type 3 消息。它们是 LDAP 集成的辅助函数，不是通用 GSSAPI
// 实现。
//
// # Boundary | 边界
//
// This package is a client only: it never validates a Type 3 message and has no
// server session-key derivation for signing or sealing. Kerberos, GSSAPI
// initial-context negotiation, credential delegation, and SASL security layers
// are separate protocols and remain unimplemented. | 本包仅实现客户端：它不校验 Type 3
// 消息，也没有用于签名或密封的服务端会话密钥派生。Kerberos、GSSAPI 初始上下文协商、
// 凭据委派与 SASL 安全层属于其它协议，仍未实现。
//
// # Example | 示例
//
//	client, err := ntlm.NewClient(ntlm.Config{
//		Domain:   "EXAMPLE",
//		Username: "alice",
//		Password: password,
//	})
//	if err != nil {
//		return err
//	}
//	negotiate, err := client.Negotiate()
//	if err != nil {
//		return err
//	}
//	authenticate, err := client.Authenticate(challenge)
//	if err != nil {
//		return err
//	}
//	_, _ = negotiate, authenticate
package ntlm
