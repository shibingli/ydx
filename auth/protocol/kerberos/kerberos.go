package kerberos

import (
	"time"

	"github.com/shibingli/ydx/errs"
)

// DefaultClockSkew is the accepted clock difference when validating Kerberos
// times. RFC 4120 deployments commonly allow five minutes. | DefaultClockSkew 是
// 校验 Kerberos 时间时接受的最大时钟偏差。RFC 4120 部署通常允许五分钟。
const DefaultClockSkew = 5 * time.Minute

// DefaultReplayCacheTTL is the retention time of one accepted authenticator. | DefaultReplayCacheTTL
// 是一条已接受认证器的最短保留时间。
const DefaultReplayCacheTTL = DefaultClockSkew

// GSSAPI mechanism identifiers used by this package. | 本包使用的 GSSAPI 机制标识。
const (
	// GSSMechanismKerberos is the Kerberos V5 GSSAPI mechanism OID. | GSSMechanismKerberos 是
	// Kerberos V5 GSSAPI 机制 OID。
	GSSMechanismKerberos = "1.2.840.113554.1.2.2"
	// GSSMechanismSPNEGO is the SPNEGO mechanism OID (RFC 4178). | GSSMechanismSPNEGO 是
	// SPNEGO 机制 OID（RFC 4178）。
	GSSMechanismSPNEGO = "1.3.6.1.5.5.2"
	// GSSMechanismMSLegacyKerberos is the historical Microsoft Kerberos OID accepted
	// for interoperability. | GSSMechanismMSLegacyKerberos 是为互操作而接受的历史
	// Microsoft Kerberos OID。
	GSSMechanismMSLegacyKerberos = "1.2.840.48018.1.2.2"
)

// gssOIDKerberosV5 is the DER form of the Kerberos V5 mechanism OID. | gssOIDKerberosV5
// 是 Kerberos V5 机制 OID 的 DER 形式。
var gssOIDKerberosV5 = []uint32{1, 2, 840, 113554, 1, 2, 2}

// gssOIDMSLegacyKerberos is the DER form of the historical Microsoft Kerberos
// mechanism OID. | gssOIDMSLegacyKerberos 是历史 Microsoft Kerberos 机制 OID 的
// DER 形式。
var gssOIDMSLegacyKerberos = []uint32{1, 2, 840, 48018, 1, 2, 2}

// gssOIDSPNEGO is the DER form of the SPNEGO mechanism OID. | gssOIDSPNEGO 是 SPNEGO
// 机制 OID 的 DER 形式。
var gssOIDSPNEGO = []uint32{1, 3, 6, 1, 5, 5, 2}

// gssTokenAPReq, gssTokenAPRep and gssTokenKRBError are the RFC 4121 TOK_ID
// values carried inside the GSS initial context token. | gssTokenAPReq、
// gssTokenAPRep 与 gssTokenKRBError 是 GSS 初始上下文令牌内部携带的 RFC 4121 TOK_ID。
const (
	gssTokenAPReq    = 0x0100
	gssTokenAPRep    = 0x0200
	gssTokenKRBError = 0x0300
	gssTokenMIC      = 0x0404
	gssTokenWrap     = 0x0504
)

// gssContextFlags are the RFC 4121 authenticator checksum flags. | gssContextFlags 是
// RFC 4121 认证器校验和标志。
const (
	gssContextDeleg        uint32 = 1 << 0
	gssContextMutual       uint32 = 1 << 1
	gssContextReplay       uint32 = 1 << 2
	gssContextSequence     uint32 = 1 << 3
	gssContextConfidential uint32 = 1 << 4
	gssContextIntegrity    uint32 = 1 << 5
)

// gssTokenFlagSentByAcceptor, gssTokenFlagSealed and gssTokenFlagAcceptorSubkey
// are the RFC 4121 per-message token flags. | gssTokenFlagSentByAcceptor、
// gssTokenFlagSealed 与 gssTokenFlagAcceptorSubkey 是 RFC 4121 每条消息令牌标志。
const (
	gssTokenFlagSentByAcceptor byte = 1 << 0
	gssTokenFlagSealed         byte = 1 << 1
	gssTokenFlagAcceptorSubkey byte = 1 << 2
)

// gssSealingUsage returns the RFC 4121 key usage for a WRAP token sent by the
// initiator or acceptor. | gssSealingUsage 返回发起方或接受方发送 WRAP 令牌时使用的
// RFC 4121 密钥用途。
func gssSealingUsage(sentByAcceptor bool) uint32 {
	if sentByAcceptor {
		return 22
	}
	return 24
}

// gssMICUsage returns the RFC 4121 key usage for a MIC token sent by the
// initiator or acceptor. | gssMICUsage 返回发起方或接受方发送 MIC 令牌时使用的 RFC 4121
// 密钥用途。
func gssMICUsage(sentByAcceptor bool) uint32 {
	if sentByAcceptor {
		return 23
	}
	return 25
}

// gssDirectionBytes returns the RFC 1964 legacy sequence-number direction
// suffix. | gssDirectionBytes 返回 RFC 1964 传统序列号方向后缀。
func gssDirectionBytes(sentByAcceptor bool) []byte {
	if sentByAcceptor {
		return []byte{0, 0, 0, 0}
	}
	return []byte{0xFF, 0xFF, 0xFF, 0xFF}
}

// errGSSToken builds a GSSAPI token framing error. | errGSSToken 构建 GSSAPI 令牌
// 分帧错误。
func errGSSToken(format string, args ...any) error {
	return errs.Detail(ErrGSSAPI, format, args...)
}
