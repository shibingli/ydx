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
// default response mode is NTLMv2. | NTLMv1 与 NTLM2 会话响应仅用于兼容旧式服务端。除非
// Config.AllowLegacy 为 true，否则它们会被拒绝；默认响应模式是 NTLMv2。
//
// # Session security | 会话安全
//
// MS-NLMP 3.4.2 through 3.4.4 message signing and sealing are implemented for
// both peers. Setting Config.Sign, Config.Seal and Config.KeyExchange on a
// Client, or the matching AcceptorConfig fields, negotiates FlagSign, FlagSeal
// and FlagKeyExchange. Signing and sealing require extended session security,
// and sealing also requires signing. After the exchange,
// Client.SecuritySession and Acceptor.SecuritySession expose Sign, Verify, Seal
// and Unseal. The client signs and seals client-to-server traffic with
// ClientSigningKey and ClientSealingKey and verifies server-to-client traffic
// with the server keys; the acceptor uses the opposite directions. A signature
// is 16 bytes: version 1, the first eight bytes of HMAC-MD5 over the
// little-endian sequence number and plaintext, and the sequence number. One RC4
// cipher state persists per direction, sequence numbers start at zero, and the
// receiver requires strict in-order delivery. A checksum or sequence failure
// wipes the session and closes it. With FlagKeyExchange the client encrypts a
// random exported session key into the Type 3 SessionKey field with the
// SessionBaseKey, and the acceptor decrypts it; without it the exported key is
// the SessionBaseKey. ExportedSessionKey returns a copy and Close wipes all
// retained key material. | 两个对端均实现 MS-NLMP 3.4.2 至 3.4.4 的消息签名与密封。在
// Client 上设置 Config.Sign、Config.Seal 与 Config.KeyExchange，或在 AcceptorConfig
// 中设置对应字段，可协商 FlagSign、FlagSeal 与 FlagKeyExchange。签名与密封需要扩展会话
// 安全，密封还需要签名。交换完成后，Client.SecuritySession 与
// Acceptor.SecuritySession 提供 Sign、Verify、Seal 与 Unseal。客户端使用
// ClientSigningKey 与 ClientSealingKey 对客户端到服务端流量签名并密封，使用服务端密钥校验
// 服务端到客户端流量；接受方方向相反。签名为 16 字节：版本 1、对小端序列号与明文计算的
// HMAC-MD5 前八字节以及序列号。每个方向保持一个 RC4 密码状态，序列号从零开始，接收方要求
// 严格按序交付。校验和或序列号失败会清零并关闭会话。协商 FlagKeyExchange 时，客户端使用
// SessionBaseKey 把随机导出会话密钥加密到 Type 3 的 SessionKey 字段，接受方解密；未协商时
// 导出密钥就是 SessionBaseKey。ExportedSessionKey 返回副本，Close 清零所有保留的密钥材料。
//
// # SPNEGO | SPNEGO
//
// SPNEGO (RFC 4178, MS-SPNG) framing is implemented for both peers. SPNEGOClient
// drives a NegTokenInit advertising the NTLMSSP OID, consumes a NegTokenResp or
// NegTokenInit challenge, verifies an optional server mechListMIC, and returns a
// final NegTokenResp carrying the Type 3 message and a mechListMIC. The acceptor
// accepts the same exchange, handles NegState accept-incomplete, request-mic,
// reject and accept-completed, and enforces a client mechListMIC when required
// or when a Type 3 MIC is present. All DER lengths and structures are parsed
// strictly and checked for bounds. | 两个对端均实现 SPNEGO（RFC 4178、MS-SPNG）分帧。
// SPNEGOClient 驱动声明 NTLMSSP OID 的 NegTokenInit，消费 NegTokenResp 或
// NegTokenInit 挑战，校验可选的服务端 mechListMIC，并返回携带 Type 3 消息与
// mechListMIC 的最终 NegTokenResp。接受方接受同一交换，处理 NegState
// accept-incomplete、request-mic、reject 与 accept-completed，并在要求时或存在 Type 3
// MIC 时强制校验客户端 mechListMIC。所有 DER 长度与结构均严格解析并进行边界检查。
//
// A mechListMIC is HMAC-MD5 over "NTLMSSP\0" followed by the canonical DER
// mechanisms list, keyed with the NTLMv2 SessionBaseKey. When the negotiated
// flags contain FlagKeyExchange the HMAC is additionally RC4-encapsulated with
// the same key. The client retains the SessionBaseKey after Authenticate so it
// can generate and verify mechListMIC values; legacy responses do not derive
// that key and therefore cannot produce a mechListMIC. | mechListMIC 是以 NTLMv2
// SessionBaseKey 为密钥，对 "NTLMSSP\0" 后接规范 DER 机制列表计算的 HMAC-MD5。当协商标志
// 包含 FlagKeyExchange 时，HMAC 还使用同一密钥进行 RC4 封装。客户端在 Authenticate 后保留
// SessionBaseKey，以便生成与校验 mechListMIC；旧式响应不派生该密钥，因此无法产生
// mechListMIC。
//
// # Acceptor | 接受方
//
// NewAcceptor builds a single-use server that validates NTLMv2 NT proof strings,
// optional LMv2 responses, the echoed temporary structure, the Type 3 MIC and a
// client mechListMIC. It supports SPNEGO framing and, when AllowRawNTLM is set,
// bare NTLMSSP tokens. Passwords are obtained only through the configured
// callback and are never retained or logged; ResponseKey callbacks may supply a
// precomputed NTLMv2Hash instead. Only the NTLMv2 response format is accepted;
// legacy NTLMv1 and NTLM2 session responses are rejected. | NewAcceptor 构建单次使用
// 的服务端，校验 NTLMv2 NT proof 字符串、可选 LMv2 响应、回显的临时结构、Type 3 MIC 与
// 客户端 mechListMIC。它支持 SPNEGO 分帧，并在设置 AllowRawNTLM 时支持裸 NTLMSSP 令牌。
// 口令仅通过配置的回调获取，绝不保留或记录日志；ResponseKey 回调可改为提供预计算的
// NTLMv2Hash。仅接受 NTLMv2 响应格式；旧式 NTLMv1 与 NTLM2 会话响应会被拒绝。
//
// # Boundary | 边界
//
// Kerberos, GSSAPI initial-context negotiation, credential delegation, and SASL
// security layers are separate protocols and remain unimplemented. The package
// does not implement the legacy non-extended-session-security signing path,
// datagram signing, or session-key exchange forms other than the NTLMv2 RC4
// encapsulation of an exported session key. | Kerberos、GSSAPI 初始上下文协商、
// 凭据委派与 SASL 安全层属于其它协议，仍未实现。本包未实现旧式非扩展会话安全签名路径、
// 数据报签名以及 NTLMv2 RC4 导出会话密钥封装之外的会话密钥交换形式。
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
//
//	serverClient, err := ntlm.NewClient(ntlm.Config{
//		Domain:   "EXAMPLE",
//		Username: "alice",
//		Password: password,
//	})
//	if err != nil {
//		return err
//	}
//	serverNegotiate, err := serverClient.Negotiate()
//	if err != nil {
//		return err
//	}
//	acceptor, err := ntlm.NewAcceptor(ntlm.AcceptorConfig{
//		Domain:       "EXAMPLE",
//		AllowRawNTLM: true,
//		Password: func(domain, username string) (string, bool) {
//			return lookupPassword(domain, username)
//		},
//	})
//	if err != nil {
//		return err
//	}
//	serverChallenge, err := acceptor.AcceptInitial(serverNegotiate)
//	if err != nil {
//		return err
//	}
//	serverAuthenticate, err := serverClient.Authenticate(serverChallenge)
//	if err != nil {
//		return err
//	}
//	result, finalToken, err := acceptor.AcceptFinal(serverAuthenticate)
//	_, _, _ = result, finalToken, err
package ntlm
