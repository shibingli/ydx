package ntlm

import (
	"strings"

	"github.com/shibingli/ydx/errs"
)

// Signature is the eight-byte NTLMSSP message signature. | Signature 是八字节的
// NTLMSSP 消息签名。
const Signature = "NTLMSSP\x00"

// MessageType is the NTLMSSP message type field. | MessageType 是 NTLMSSP 消息
// 类型字段。
type MessageType uint32

const (
	// MessageTypeNegotiate is the Type 1 NEGOTIATE_MESSAGE. | MessageTypeNegotiate
	// 是 Type 1 NEGOTIATE_MESSAGE。
	MessageTypeNegotiate MessageType = 1
	// MessageTypeChallenge is the Type 2 CHALLENGE_MESSAGE. | MessageTypeChallenge
	// 是 Type 2 CHALLENGE_MESSAGE。
	MessageTypeChallenge MessageType = 2
	// MessageTypeAuthenticate is the Type 3 AUTHENTICATE_MESSAGE. | MessageTypeAuthenticate
	// 是 Type 3 AUTHENTICATE_MESSAGE。
	MessageTypeAuthenticate MessageType = 3
)

// NegotiateFlags is the NTLMSSP negotiate-flags bit set. | NegotiateFlags 是
// NTLMSSP 协商标志位集合。
type NegotiateFlags uint32

// NTLMSSP negotiate flags defined by MS-NLMP 2.2.2.5. | MS-NLMP 2.2.2.5 定义的
// NTLMSSP 协商标志。
const (
	// FlagUnicode requests Unicode (UTF-16LE) strings. | FlagUnicode 请求 Unicode（UTF-16LE）字符串。
	FlagUnicode NegotiateFlags = 0x00000001
	// FlagOEM requests OEM strings. | FlagOEM 请求 OEM 字符串。
	FlagOEM NegotiateFlags = 0x00000002
	// FlagRequestTarget requests a target name in the challenge. | FlagRequestTarget 请求在挑战中返回目标名称。
	FlagRequestTarget NegotiateFlags = 0x00000004
	// FlagSign requests message signing. | FlagSign 请求消息签名。
	FlagSign NegotiateFlags = 0x00000010
	// FlagSeal requests message sealing. | FlagSeal 请求消息密封。
	FlagSeal NegotiateFlags = 0x00000020
	// FlagDatagram requests datagram authentication. | FlagDatagram 请求数据报认证。
	FlagDatagram NegotiateFlags = 0x00000040
	// FlagLMKey requests LM session-key derivation. | FlagLMKey 请求 LM 会话密钥派生。
	FlagLMKey NegotiateFlags = 0x00000080
	// FlagNTLM requests NTLM authentication. | FlagNTLM 请求 NTLM 认证。
	FlagNTLM NegotiateFlags = 0x00000200
	// FlagNTLMOnly requests NTLM-only authentication. | FlagNTLMOnly 请求仅 NTLM 认证。
	FlagNTLMOnly NegotiateFlags = 0x00000400
	// FlagAnonymous requests anonymous authentication. | FlagAnonymous 请求匿名认证。
	FlagAnonymous NegotiateFlags = 0x00000800
	// FlagOEMDomainSupplied marks an OEM-encoded domain field. | FlagOEMDomainSupplied 标记 OEM 编码的域字段。
	FlagOEMDomainSupplied NegotiateFlags = 0x00001000
	// FlagOEMWorkstationSupplied marks an OEM-encoded workstation field. |
	// FlagOEMWorkstationSupplied 标记 OEM 编码的工作站字段。
	FlagOEMWorkstationSupplied NegotiateFlags = 0x00002000
	// FlagAlwaysSign requests signing on every message. | FlagAlwaysSign 请求对每条消息签名。
	FlagAlwaysSign NegotiateFlags = 0x00008000
	// FlagTargetTypeDomain marks the target as a domain. | FlagTargetTypeDomain 标记目标为域。
	FlagTargetTypeDomain NegotiateFlags = 0x00010000
	// FlagTargetTypeServer marks the target as a server. | FlagTargetTypeServer 标记目标为服务器。
	FlagTargetTypeServer NegotiateFlags = 0x00020000
	// FlagExtendedSessionSecurity requests NTLM extended session security. |
	// FlagExtendedSessionSecurity 请求 NTLM 扩展会话安全。
	FlagExtendedSessionSecurity NegotiateFlags = 0x00080000
	// FlagIdentify requests identify-level impersonation. | FlagIdentify 请求 identify 级模拟。
	FlagIdentify NegotiateFlags = 0x00100000
	// FlagRequestNonNTSessionKey requests a non-NT session key. | FlagRequestNonNTSessionKey 请求非 NT 会话密钥。
	FlagRequestNonNTSessionKey NegotiateFlags = 0x00400000
	// FlagTargetInfo requests target info in the challenge. | FlagTargetInfo 请求在挑战中返回目标信息。
	FlagTargetInfo NegotiateFlags = 0x00800000
	// FlagVersion requests a version field. | FlagVersion 请求版本字段。
	FlagVersion NegotiateFlags = 0x02000000
	// Flag128 requests 128-bit session keys. | Flag128 请求 128 位会话密钥。
	Flag128 NegotiateFlags = 0x20000000
	// FlagKeyExchange requests session-key exchange. | FlagKeyExchange 请求会话密钥交换。
	FlagKeyExchange NegotiateFlags = 0x40000000
	// Flag56 requests 56-bit session keys. | Flag56 请求 56 位会话密钥。
	Flag56 NegotiateFlags = 0x80000000
)

// Has reports whether every bit of flag is set in f. | Has 报告 f 中是否设置了 flag
// 的每一位。
func (f NegotiateFlags) Has(flag NegotiateFlags) bool {
	return f&flag == flag
}

// Version is the eight-byte NTLMSSP version structure. | Version 是八字节的
// NTLMSSP 版本结构。
type Version struct {
	// Major is the major version number. | Major 是主版本号。
	Major uint8
	// Minor is the minor version number. | Minor 是次版本号。
	Minor uint8
	// Build is the build number. | Build 是构建号。
	Build uint16
	// Revision is the NTLMSSP revision, normally 0x0f. | Revision 是 NTLMSSP 修订号，
	// 通常为 0x0f。
	Revision uint8
}

// DefaultVersion returns the version field this client sends. | DefaultVersion 返回
// 本客户端发送的版本字段。
func DefaultVersion() Version {
	return Version{Major: 10, Minor: 0, Build: 19041, Revision: 0x0f}
}

// ResponseMode selects the challenge-response algorithm. | ResponseMode 选择挑战响应
// 算法。
type ResponseMode uint8

const (
	// ResponseNTLMv2 selects NTLMv2, the default and only mode enabled without
	// AllowLegacy. | ResponseNTLMv2 选择 NTLMv2，这是未启用 AllowLegacy 时唯一可用的
	// 默认模式。
	ResponseNTLMv2 ResponseMode = iota
	// ResponseNTLMv1 selects the legacy NTLMv1 response and requires
	// Config.AllowLegacy. | ResponseNTLMv1 选择旧式 NTLMv1 响应，需要
	// Config.AllowLegacy。
	ResponseNTLMv1
	// ResponseNTLM2Session selects the legacy NTLM2 session response and requires
	// Config.AllowLegacy. | ResponseNTLM2Session 选择旧式 NTLM2 会话响应，需要
	// Config.AllowLegacy。
	ResponseNTLM2Session
)

// String returns a stable name for the response mode. | String 返回响应模式的稳定名称。
func (m ResponseMode) String() string {
	switch m {
	case ResponseNTLMv2:
		return "NTLMv2"
	case ResponseNTLMv1:
		return "NTLMv1"
	case ResponseNTLM2Session:
		return "NTLM2-session"
	default:
		return "unknown"
	}
}

// The declared sentinels of the package. | 本包声明的哨兵错误。
var (
	// ErrMessage reports a malformed NTLMSSP message. | ErrMessage 表示 NTLMSSP 消息畸形。
	ErrMessage = errs.New("ntlm: invalid message | ntlm：消息非法")
	// ErrCredentials reports unusable credential input. | ErrCredentials 表示凭据输入不可用。
	ErrCredentials = errs.New("ntlm: invalid credentials | ntlm：凭据非法")
	// ErrChallenge reports a challenge that violates this client's policy. |
	// ErrChallenge 表示挑战违反本客户端策略。
	ErrChallenge = errs.New("ntlm: invalid challenge | ntlm：挑战非法")
	// ErrTargetInfo reports malformed or missing target information. | ErrTargetInfo
	// 表示目标信息畸形或缺失。
	ErrTargetInfo = errs.New("ntlm: invalid target info | ntlm：目标信息非法")
	// ErrLegacyDisabled reports a legacy algorithm selected without AllowLegacy. |
	// ErrLegacyDisabled 表示未启用 AllowLegacy 却选择了旧式算法。
	ErrLegacyDisabled = errs.New("ntlm: legacy NTLMv1/NTLM2 is disabled | ntlm：已禁用旧式 NTLMv1/NTLM2")
	// ErrUnsupported reports a feature this client does not implement. | ErrUnsupported
	// 表示本客户端未实现该功能。
	ErrUnsupported = errs.New("ntlm: unsupported feature | ntlm：不支持的功能")
	// ErrChannelBindings reports unusable or mismatched channel bindings. |
	// ErrChannelBindings 表示通道绑定不可用或不匹配。
	ErrChannelBindings = errs.New("ntlm: invalid channel bindings | ntlm：通道绑定非法")
	// ErrClientState reports message methods used out of order or twice. |
	// ErrClientState 表示消息方法顺序错误或重复调用。
	ErrClientState = errs.New("ntlm: invalid client state | ntlm：客户端状态非法")
	// ErrSPNEGO reports a malformed or unacceptable SPNEGO token. | ErrSPNEGO 表示
	// SPNEGO 令牌畸形或不可接受。
	ErrSPNEGO = errs.New("ntlm: invalid SPNEGO token | ntlm：SPNEGO 令牌非法")
	// ErrRandom reports a failure of the cryptographic random source. | ErrRandom 表示
	// 加密随机源失败。
	ErrRandom = errs.New("ntlm: random source failed | ntlm：随机源失败")
)

// SplitUsername resolves Active Directory login forms into the NTLM domain and
// user name. DOMAIN\user splits at the backslash, an explicit domain that
// conflicts with the login is rejected, user@domain is treated as a UPN with an
// empty NTLM domain, and a plain name uses domain verbatim. | SplitUsername 把
// Active Directory 登录形式解析为 NTLM 域与用户名。DOMAIN\user 按反斜杠拆分，显式域与
// 登录冲突时被拒绝，user@domain 视为 UPN 且 NTLM 域为空，裸名称原样使用 domain。
func SplitUsername(login, domain string) (userDomain, userName string, err error) {
	login = strings.TrimSpace(login)
	domain = strings.TrimSpace(domain)
	if login == "" {
		return "", "", errs.Detail(ErrCredentials, "username is empty | 用户名为空")
	}
	if strings.IndexByte(login, 0) >= 0 || strings.IndexByte(domain, 0) >= 0 {
		return "", "", errs.Detail(ErrCredentials, "username or domain contains NUL | 用户名或域包含 NUL")
	}
	if index := strings.IndexByte(login, '\\'); index >= 0 {
		userDomain = login[:index]
		userName = login[index+1:]
		if userDomain == "" || userName == "" {
			return "", "", errs.Detail(ErrCredentials, "malformed DOMAIN\\user login | DOMAIN\\user 登录格式错误")
		}
		if domain != "" && !strings.EqualFold(domain, userDomain) {
			return "", "", errs.Detail(ErrCredentials, "login domain conflicts with configured domain | 登录域与配置域冲突")
		}
		return userDomain, userName, nil
	}
	if strings.IndexByte(login, '@') >= 0 {
		// A UPN already carries its realm; MS-NLMP hashes it with an empty
		// DomainName. | UPN 自带领域；MS-NLMP 使用空 DomainName 计算哈希。
		return "", login, nil
	}
	return domain, login, nil
}
