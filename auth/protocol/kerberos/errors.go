package kerberos

import (
	"github.com/shibingli/ydx/errs"
)

// The declared sentinels of the package. | 本包声明的哨兵错误。
//
// Every failure path returns one of these values directly or wraps it with
// errs.Detail / errs.Wrap, so callers classify failures with errors.Is instead
// of matching text. | 所有失败路径都直接返回其中之一，或通过 errs.Detail /
// errs.Wrap 包装，因此调用方用 errors.Is 分类错误而不是匹配文案。
var (
	// ErrInvalidConfig reports an unusable client, acceptor, or discovery setting. | ErrInvalidConfig 表示客户端、校验端或发现配置不可用。
	ErrInvalidConfig = errs.New("kerberos: invalid configuration | kerberos：配置非法")
	// ErrInvalidMessage reports a malformed ASN.1 or Kerberos message. | ErrInvalidMessage 表示 ASN.1 或 Kerberos 消息畸形。
	ErrInvalidMessage = errs.New("kerberos: invalid message | kerberos：消息非法")
	// ErrASN1 reports a DER encoding or decoding failure. | ErrASN1 表示 DER 编解码失败。
	ErrASN1 = errs.New("kerberos: ASN.1 error | kerberos：ASN.1 错误")
	// ErrTrailingData reports extra bytes after a complete DER value. | ErrTrailingData 表示完整 DER 值之后还有多余字节。
	ErrTrailingData = errs.New("kerberos: trailing data | kerberos：存在尾随数据")
	// ErrCredentials reports an unusable or missing credential. | ErrCredentials 表示凭据不可用或缺失。
	ErrCredentials = errs.New("kerberos: credentials unavailable | kerberos：凭据不可用")
	// ErrKeytab reports a malformed or unsupported keytab. | ErrKeytab 表示 keytab 畸形或不受支持。
	ErrKeytab = errs.New("kerberos: invalid keytab | kerberos：keytab 非法")
	// ErrNoKey reports that no key matches the principal, enctype, and kvno. | ErrNoKey 表示没有匹配主体、加密类型与 kvno 的密钥。
	ErrNoKey = errs.New("kerberos: no matching key | kerberos：没有匹配的密钥")
	// ErrUnsupportedEType reports an encryption type this package does not implement. | ErrUnsupportedEType 表示本包未实现该加密类型。
	ErrUnsupportedEType = errs.New("kerberos: unsupported encryption type | kerberos：不支持的加密类型")
	// ErrUnsupportedChecksum reports a checksum type this package does not implement. | ErrUnsupportedChecksum 表示本包未实现该校验和类型。
	ErrUnsupportedChecksum = errs.New("kerberos: unsupported checksum type | kerberos：不支持的校验和类型")
	// ErrDecrypt reports a failure to decrypt an encrypted part. | ErrDecrypt 表示无法解密加密部分。
	ErrDecrypt = errs.New("kerberos: decryption failed | kerberos：解密失败")
	// ErrChecksumMismatch reports a failed integrity check. | ErrChecksumMismatch 表示完整性校验失败。
	ErrChecksumMismatch = errs.New("kerberos: checksum mismatch | kerberos：校验和不匹配")
	// ErrKDCUnavailable reports that no KDC could be reached. | ErrKDCUnavailable 表示无法连接任何 KDC。
	ErrKDCUnavailable = errs.New("kerberos: KDC unavailable | kerberos：KDC 不可用")
	// ErrKDCTimeout reports that every KDC attempt exceeded its deadline. | ErrKDCTimeout 表示所有 KDC 尝试均超时。
	ErrKDCTimeout = errs.New("kerberos: KDC timeout | kerberos：KDC 超时")
	// ErrKDCNotFound reports that discovery found no KDC for a realm. | ErrKDCNotFound 表示没有为 realm 发现任何 KDC。
	ErrKDCNotFound = errs.New("kerberos: KDC not found | kerberos：未找到 KDC")
	// ErrRealmNotFound reports that no realm could be discovered. | ErrRealmNotFound 表示无法发现 realm。
	ErrRealmNotFound = errs.New("kerberos: realm not found | kerberos：未找到 realm")
	// ErrKRBError is the generic sentinel for a KRB-ERROR without a more specific mapping. | ErrKRBError 是没有更具体映射的 KRB-ERROR 的通用哨兵。
	ErrKRBError = errs.New("kerberos: KDC error | kerberos：KDC 错误")
	// ErrClientNotFound reports KDC_ERR_C_PRINCIPAL_UNKNOWN (6). | ErrClientNotFound 表示 KDC_ERR_C_PRINCIPAL_UNKNOWN（6）。
	ErrClientNotFound = errs.New("kerberos: client principal unknown | kerberos：客户端主体未知")
	// ErrServerNotFound reports KDC_ERR_S_PRINCIPAL_UNKNOWN (7). | ErrServerNotFound 表示 KDC_ERR_S_PRINCIPAL_UNKNOWN（7）。
	ErrServerNotFound = errs.New("kerberos: server principal unknown | kerberos：服务端主体未知")
	// ErrPrincipalNotUnique reports KDC_ERR_PRINCIPAL_NOT_UNIQUE (8). | ErrPrincipalNotUnique 表示 KDC_ERR_PRINCIPAL_NOT_UNIQUE（8）。
	ErrPrincipalNotUnique = errs.New("kerberos: principal not unique | kerberos：主体不唯一")
	// ErrETypeNotSupported reports KDC_ERR_ETYPE_NOSUPP (14). | ErrETypeNotSupported 表示 KDC_ERR_ETYPE_NOSUPP（14）。
	ErrETypeNotSupported = errs.New("kerberos: encryption type not supported by KDC | kerberos：KDC 不支持该加密类型")
	// ErrClientRevoked reports KDC_ERR_CLIENT_REVOKED (18). | ErrClientRevoked 表示 KDC_ERR_CLIENT_REVOKED（18）。
	ErrClientRevoked = errs.New("kerberos: client credentials revoked | kerberos：客户端凭据已吊销")
	// ErrKeyExpired reports KDC_ERR_KEY_EXPIRED (23). | ErrKeyExpired 表示 KDC_ERR_KEY_EXPIRED（23）。
	ErrKeyExpired = errs.New("kerberos: password expired | kerberos：口令已过期")
	// ErrPreAuthFailed reports KDC_ERR_PREAUTH_FAILED (24). | ErrPreAuthFailed 表示 KDC_ERR_PREAUTH_FAILED（24）。
	ErrPreAuthFailed = errs.New("kerberos: pre-authentication failed | kerberos：预认证失败")
	// ErrPreAuthRequired reports KDC_ERR_PREAUTH_REQUIRED (25). | ErrPreAuthRequired 表示 KDC_ERR_PREAUTH_REQUIRED（25）。
	ErrPreAuthRequired = errs.New("kerberos: pre-authentication required | kerberos：需要预认证")
	// ErrBadIntegrity reports KRB_AP_ERR_BAD_INTEGRITY (31). | ErrBadIntegrity 表示 KRB_AP_ERR_BAD_INTEGRITY（31）。
	ErrBadIntegrity = errs.New("kerberos: integrity check failed | kerberos：完整性校验失败")
	// ErrTicketExpired reports KRB_AP_ERR_TKT_EXPIRED (32). | ErrTicketExpired 表示 KRB_AP_ERR_TKT_EXPIRED（32）。
	ErrTicketExpired = errs.New("kerberos: ticket expired | kerberos：票据已过期")
	// ErrTicketNotYetValid reports KRB_AP_ERR_TKT_NYV (33). | ErrTicketNotYetValid 表示 KRB_AP_ERR_TKT_NYV（33）。
	ErrTicketNotYetValid = errs.New("kerberos: ticket not yet valid | kerberos：票据尚未生效")
	// ErrReplay reports KRB_AP_ERR_REPEAT (34). | ErrReplay 表示 KRB_AP_ERR_REPEAT（34）。
	ErrReplay = errs.New("kerberos: replay detected | kerberos：检测到重放")
	// ErrTicketNotForUs reports KRB_AP_ERR_NOT_US (35). | ErrTicketNotForUs 表示 KRB_AP_ERR_NOT_US（35）。
	ErrTicketNotForUs = errs.New("kerberos: ticket is not for this service | kerberos：票据不属于本服务")
	// ErrTicketMismatch reports KRB_AP_ERR_BADMATCH (36). | ErrTicketMismatch 表示 KRB_AP_ERR_BADMATCH（36）。
	ErrTicketMismatch = errs.New("kerberos: ticket and authenticator do not match | kerberos：票据与认证器不匹配")
	// ErrClockSkew reports KRB_AP_ERR_SKEW (37). | ErrClockSkew 表示 KRB_AP_ERR_SKEW（37）。
	ErrClockSkew = errs.New("kerberos: clock skew too great | kerberos：时钟偏移过大")
	// ErrBadKVNO reports KRB_AP_ERR_BADKEYVER (44). | ErrBadKVNO 表示 KRB_AP_ERR_BADKEYVER（44）。
	ErrBadKVNO = errs.New("kerberos: key version unavailable | kerberos：密钥版本不可用")
	// ErrMutualAuthFailed reports KRB_AP_ERR_MUT_FAIL (46). | ErrMutualAuthFailed 表示 KRB_AP_ERR_MUT_FAIL（46）。
	ErrMutualAuthFailed = errs.New("kerberos: mutual authentication failed | kerberos：双向认证失败")
	// ErrResponseTooBig reports KRB_ERR_RESPONSE_TOO_BIG (52). | ErrResponseTooBig 表示 KRB_ERR_RESPONSE_TOO_BIG（52）。
	ErrResponseTooBig = errs.New("kerberos: response too big | kerberos：响应过大")
	// ErrGSSAPI reports a GSS-API token or context failure. | ErrGSSAPI 表示 GSS-API 令牌或上下文失败。
	ErrGSSAPI = errs.New("kerberos: GSS-API failure | kerberos：GSS-API 失败")
	// ErrSPNEGO reports an SPNEGO negotiation failure. | ErrSPNEGO 表示 SPNEGO 协商失败。
	ErrSPNEGO = errs.New("kerberos: SPNEGO failure | kerberos：SPNEGO 失败")
	// ErrChannelBinding reports a channel binding mismatch or unusable binding. | ErrChannelBinding 表示通道绑定不匹配或不可用。
	ErrChannelBinding = errs.New("kerberos: channel binding failure | kerberos：通道绑定失败")
	// ErrTime reports an invalid KerberosTime value. | ErrTime 表示 KerberosTime 值非法。
	ErrTime = errs.New("kerberos: invalid time | kerberos：时间非法")
	// ErrSequence reports an out-of-order or duplicate GSS sequence number. | ErrSequence 表示 GSS 序列号乱序或重复。
	ErrSequence = errs.New("kerberos: sequence number error | kerberos：序列号错误")
	// ErrRandom reports a failure of the cryptographic random source. | ErrRandom 表示密码学随机源失败。
	ErrRandom = errs.New("kerberos: random source failed | kerberos：随机源失败")
)

// krbErrorNames maps RFC 4120 error codes to their symbolic names. | krbErrorNames
// 把 RFC 4120 错误码映射到符号名。
var krbErrorNames = map[int32]string{
	0:  "KDC_ERR_NONE",
	1:  "KDC_ERR_NAME_EXP",
	2:  "KDC_ERR_SERVICE_EXP",
	3:  "KDC_ERR_BAD_PVNO",
	4:  "KDC_ERR_C_OLD_MAST_KVNO",
	5:  "KDC_ERR_S_OLD_MAST_KVNO",
	6:  "KDC_ERR_C_PRINCIPAL_UNKNOWN",
	7:  "KDC_ERR_S_PRINCIPAL_UNKNOWN",
	8:  "KDC_ERR_PRINCIPAL_NOT_UNIQUE",
	9:  "KDC_ERR_NULL_KEY",
	10: "KDC_ERR_CANNOT_POSTDATE",
	11: "KDC_ERR_NEVER_VALID",
	12: "KDC_ERR_POLICY",
	13: "KDC_ERR_BADOPTION",
	14: "KDC_ERR_ETYPE_NOSUPP",
	15: "KDC_ERR_SUMTYPE_NOSUPP",
	16: "KDC_ERR_PADATA_TYPE_NOSUPP",
	17: "KDC_ERR_TRTYPE_NOSUPP",
	18: "KDC_ERR_CLIENT_REVOKED",
	19: "KDC_ERR_SERVICE_REVOKED",
	20: "KDC_ERR_TGT_REVOKED",
	21: "KDC_ERR_CLIENT_NOTYET",
	22: "KDC_ERR_SERVICE_NOTYET",
	23: "KDC_ERR_KEY_EXPIRED",
	24: "KDC_ERR_PREAUTH_FAILED",
	25: "KDC_ERR_PREAUTH_REQUIRED",
	26: "KDC_ERR_SERVER_NOMATCH",
	27: "KDC_ERR_MUST_USE_USER2USER",
	28: "KDC_ERR_PATH_NOT_ACCEPTED",
	29: "KDC_ERR_SVC_UNAVAILABLE",
	31: "KRB_AP_ERR_BAD_INTEGRITY",
	32: "KRB_AP_ERR_TKT_EXPIRED",
	33: "KRB_AP_ERR_TKT_NYV",
	34: "KRB_AP_ERR_REPEAT",
	35: "KRB_AP_ERR_NOT_US",
	36: "KRB_AP_ERR_BADMATCH",
	37: "KRB_AP_ERR_SKEW",
	38: "KRB_AP_ERR_BADADDR",
	39: "KRB_AP_ERR_BADVERSION",
	40: "KRB_AP_ERR_MSG_TYPE",
	41: "KRB_AP_ERR_MODIFIED",
	42: "KRB_AP_ERR_BADORDER",
	44: "KRB_AP_ERR_BADKEYVER",
	45: "KRB_AP_ERR_NOKEY",
	46: "KRB_AP_ERR_MUT_FAIL",
	47: "KRB_AP_ERR_BADDIRECTION",
	48: "KRB_AP_ERR_METHOD",
	49: "KRB_AP_ERR_BADSEQ",
	50: "KRB_AP_ERR_INAPP_CKSUM",
	51: "KRB_AP_PATH_NOT_ACCEPTED",
	52: "KRB_ERR_RESPONSE_TOO_BIG",
	60: "KRB_ERR_GENERIC",
	61: "KRB_ERR_FIELD_TOOLONG",
	67: "KRB_AP_ERR_NO_TGT",
	69: "KRB_AP_ERR_USER_TO_USER_REQUIRED",
}

// ErrorCodeName returns the RFC 4120 symbolic name for code, or an empty string
// when the code is unknown. | ErrorCodeName 返回 RFC 4120 符号名；未知错误码返回空字符串。
func ErrorCodeName(code int32) string { return krbErrorNames[code] }

// sentinelForCode maps a Kerberos error code to a declared sentinel. | sentinelForCode
// 把 Kerberos 错误码映射到已声明的哨兵错误。
func sentinelForCode(code int32) error {
	switch code {
	case 6:
		return ErrClientNotFound
	case 7:
		return ErrServerNotFound
	case 8:
		return ErrPrincipalNotUnique
	case 14:
		return ErrETypeNotSupported
	case 18:
		return ErrClientRevoked
	case 23:
		return ErrKeyExpired
	case 24:
		return ErrPreAuthFailed
	case 25:
		return ErrPreAuthRequired
	case 31:
		return ErrBadIntegrity
	case 32:
		return ErrTicketExpired
	case 33:
		return ErrTicketNotYetValid
	case 34:
		return ErrReplay
	case 35:
		return ErrTicketNotForUs
	case 36:
		return ErrTicketMismatch
	case 37:
		return ErrClockSkew
	case 44:
		return ErrBadKVNO
	case 45:
		return ErrNoKey
	case 46:
		return ErrMutualAuthFailed
	case 52:
		return ErrResponseTooBig
	default:
		return ErrKRBError
	}
}
