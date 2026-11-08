package webauthn

import (
	"context"
	"fmt"

	"github.com/shibingli/ydx/errs"
)

// TPM 2.0 response codes used for failure classification. | 用于失败分类的 TPM 2.0 响应码。
const (
	// TPMRCSuccess is TPM_RC_SUCCESS. | TPMRCSuccess 是 TPM_RC_SUCCESS。
	TPMRCSuccess uint32 = 0x000
	// TPMRCInitialize is TPM_RC_INITIALIZE. | TPMRCInitialize 是 TPM_RC_INITIALIZE。
	TPMRCInitialize uint32 = 0x100
	// TPMRCFailure is TPM_RC_FAILURE. | TPMRCFailure 是 TPM_RC_FAILURE。
	TPMRCFailure uint32 = 0x101
	// TPMRCSequence is TPM_RC_SEQUENCE. | TPMRCSequence 是 TPM_RC_SEQUENCE。
	TPMRCSequence uint32 = 0x103
	// TPMRCPrivate is TPM_RC_PRIVATE. | TPMRCPrivate 是 TPM_RC_PRIVATE。
	TPMRCPrivate uint32 = 0x10B
	// TPMRCHmac is TPM_RC_HMAC. | TPMRCHmac 是 TPM_RC_HMAC。
	TPMRCHmac uint32 = 0x119
	// TPMRCDisabled is TPM_RC_DISABLED. | TPMRCDisabled 是 TPM_RC_DISABLED。
	TPMRCDisabled uint32 = 0x120
	// TPMRCExclusive is TPM_RC_EXCLUSIVE. | TPMRCExclusive 是 TPM_RC_EXCLUSIVE。
	TPMRCExclusive uint32 = 0x121
	// TPMRCAuthType is TPM_RC_AUTH_TYPE. | TPMRCAuthType 是 TPM_RC_AUTH_TYPE。
	TPMRCAuthType uint32 = 0x124
	// TPMRCAuthMissing is TPM_RC_AUTH_MISSING. | TPMRCAuthMissing 是 TPM_RC_AUTH_MISSING。
	TPMRCAuthMissing uint32 = 0x125
	// TPMRCPolicy is TPM_RC_POLICY. | TPMRCPolicy 是 TPM_RC_POLICY。
	TPMRCPolicy uint32 = 0x126
	// TPMRCPCR is TPM_RC_PCR. | TPMRCPCR 是 TPM_RC_PCR。
	TPMRCPCR uint32 = 0x127
	// TPMRCPCRChanged is TPM_RC_PCR_CHANGED. | TPMRCPCRChanged 是 TPM_RC_PCR_CHANGED。
	TPMRCPCRChanged uint32 = 0x128
	// TPMRCUpgrade is TPM_RC_UPGRADE. | TPMRCUpgrade 是 TPM_RC_UPGRADE。
	TPMRCUpgrade uint32 = 0x12D
	// TPMRCTooManyContexts is TPM_RC_TOO_MANY_CONTEXTS. | TPMRCTooManyContexts 是 TPM_RC_TOO_MANY_CONTEXTS。
	TPMRCTooManyContexts uint32 = 0x12E
	// TPMRCAuthUnavailable is TPM_RC_AUTH_UNAVAILABLE. | TPMRCAuthUnavailable 是 TPM_RC_AUTH_UNAVAILABLE。
	TPMRCAuthUnavailable uint32 = 0x12F
	// TPMRCReboot is TPM_RC_REBOOT. | TPMRCReboot 是 TPM_RC_REBOOT。
	TPMRCReboot uint32 = 0x130
	// TPMRCUnbalanced is TPM_RC_UNBALANCED. | TPMRCUnbalanced 是 TPM_RC_UNBALANCED。
	TPMRCUnbalanced uint32 = 0x131
	// TPMRCCommandSize is TPM_RC_COMMAND_SIZE. | TPMRCCommandSize 是 TPM_RC_COMMAND_SIZE。
	TPMRCCommandSize uint32 = 0x142
	// TPMRCCommandCode is TPM_RC_COMMAND_CODE. | TPMRCCommandCode 是 TPM_RC_COMMAND_CODE。
	TPMRCCommandCode uint32 = 0x143
	// TPMRCAuthSize is TPM_RC_AUTHSIZE. | TPMRCAuthSize 是 TPM_RC_AUTHSIZE。
	TPMRCAuthSize uint32 = 0x144
	// TPMRCAuthContext is TPM_RC_AUTH_CONTEXT. | TPMRCAuthContext 是 TPM_RC_AUTH_CONTEXT。
	TPMRCAuthContext uint32 = 0x145
	// TPMRCNVRange is TPM_RC_NV_RANGE. | TPMRCNVRange 是 TPM_RC_NV_RANGE。
	TPMRCNVRange uint32 = 0x146
	// TPMRCNVSize is TPM_RC_NV_SIZE. | TPMRCNVSize 是 TPM_RC_NV_SIZE。
	TPMRCNVSize uint32 = 0x147
	// TPMRCNVLocked is TPM_RC_NV_LOCKED. | TPMRCNVLocked 是 TPM_RC_NV_LOCKED。
	TPMRCNVLocked uint32 = 0x148
	// TPMRCNVAuthorization is TPM_RC_NV_AUTHORIZATION. | TPMRCNVAuthorization 是 TPM_RC_NV_AUTHORIZATION。
	TPMRCNVAuthorization uint32 = 0x149
	// TPMRCNVUninitialized is TPM_RC_NV_UNINITIALIZED. | TPMRCNVUninitialized 是 TPM_RC_NV_UNINITIALIZED。
	TPMRCNVUninitialized uint32 = 0x14A
	// TPMRCNVSpace is TPM_RC_NV_SPACE. | TPMRCNVSpace 是 TPM_RC_NV_SPACE。
	TPMRCNVSpace uint32 = 0x14B
	// TPMRCNVDefined is TPM_RC_NV_DEFINED. | TPMRCNVDefined 是 TPM_RC_NV_DEFINED。
	TPMRCNVDefined uint32 = 0x14C
	// TPMRCBadContext is TPM_RC_BAD_CONTEXT. | TPMRCBadContext 是 TPM_RC_BAD_CONTEXT。
	TPMRCBadContext uint32 = 0x150
	// TPMRCCPHash is TPM_RC_CPHASH. | TPMRCCPHash 是 TPM_RC_CPHASH。
	TPMRCCPHash uint32 = 0x151
	// TPMRCParent is TPM_RC_PARENT. | TPMRCParent 是 TPM_RC_PARENT。
	TPMRCParent uint32 = 0x152
	// TPMRCNeedsTest is TPM_RC_NEEDS_TEST. | TPMRCNeedsTest 是 TPM_RC_NEEDS_TEST。
	TPMRCNeedsTest uint32 = 0x153
	// TPMRCNoResult is TPM_RC_NO_RESULT. | TPMRCNoResult 是 TPM_RC_NO_RESULT。
	TPMRCNoResult uint32 = 0x154
	// TPMRCSensitive is TPM_RC_SENSITIVE. | TPMRCSensitive 是 TPM_RC_SENSITIVE。
	TPMRCSensitive uint32 = 0x155
)

// TPM 2.0 format-one response codes. | TPM 2.0 格式一响应码。
const (
	// TPMRCAsymmetric is TPM_RC_ASYMMETRIC. | TPMRCAsymmetric 是 TPM_RC_ASYMMETRIC。
	TPMRCAsymmetric uint32 = 0x081
	// TPMAttributes is TPM_RC_ATTRIBUTES. | TPMAttributes 是 TPM_RC_ATTRIBUTES。
	TPMAttributes uint32 = 0x082
	// TPMRCHash is TPM_RC_HASH. | TPMRCHash 是 TPM_RC_HASH。
	TPMRCHash uint32 = 0x083
	// TPMRCValue is TPM_RC_VALUE. | TPMRCValue 是 TPM_RC_VALUE。
	TPMRCValue uint32 = 0x084
	// TPMRCHierarchy is TPM_RC_HIERARCHY. | TPMRCHierarchy 是 TPM_RC_HIERARCHY。
	TPMRCHierarchy uint32 = 0x085
	// TPMRCKeySize is TPM_RC_KEY_SIZE. | TPMRCKeySize 是 TPM_RC_KEY_SIZE。
	TPMRCKeySize uint32 = 0x087
	// TPMRCMGF is TPM_RC_MGF. | TPMRCMGF 是 TPM_RC_MGF。
	TPMRCMGF uint32 = 0x088
	// TPMRCMode is TPM_RC_MODE. | TPMRCMode 是 TPM_RC_MODE。
	TPMRCMode uint32 = 0x089
	// TPMRCType is TPM_RC_TYPE. | TPMRCType 是 TPM_RC_TYPE。
	TPMRCType uint32 = 0x08A
	// TPMRCHandle is TPM_RC_HANDLE. | TPMRCHandle 是 TPM_RC_HANDLE。
	TPMRCHandle uint32 = 0x08B
	// TPMRCKDF is TPM_RC_KDF. | TPMRCKDF 是 TPM_RC_KDF。
	TPMRCKDF uint32 = 0x08C
	// TPMRCRange is TPM_RC_RANGE. | TPMRCRange 是 TPM_RC_RANGE。
	TPMRCRange uint32 = 0x08D
	// TPMRCAuthFail is TPM_RC_AUTH_FAIL. | TPMRCAuthFail 是 TPM_RC_AUTH_FAIL。
	TPMRCAuthFail uint32 = 0x08E
	// TPMRCNonce is TPM_RC_NONCE. | TPMRCNonce 是 TPM_RC_NONCE。
	TPMRCNonce uint32 = 0x08F
	// TPMRCPP is TPM_RC_PP. | TPMRCPP 是 TPM_RC_PP。
	TPMRCPP uint32 = 0x090
	// TPMRCScheme is TPM_RC_SCHEME. | TPMRCScheme 是 TPM_RC_SCHEME。
	TPMRCScheme uint32 = 0x092
	// TPMRCSize is TPM_RC_SIZE. | TPMRCSize 是 TPM_RC_SIZE。
	TPMRCSize uint32 = 0x095
	// TPMRCSymmetric is TPM_RC_SYMMETRIC. | TPMRCSymmetric 是 TPM_RC_SYMMETRIC。
	TPMRCSymmetric uint32 = 0x096
	// TPMRCTag is TPM_RC_TAG. | TPMRCTag 是 TPM_RC_TAG。
	TPMRCTag uint32 = 0x097
	// TPMRCSelector is TPM_RC_SELECTOR. | TPMRCSelector 是 TPM_RC_SELECTOR。
	TPMRCSelector uint32 = 0x098
	// TPMRCInsufficient is TPM_RC_INSUFFICIENT. | TPMRCInsufficient 是 TPM_RC_INSUFFICIENT。
	TPMRCInsufficient uint32 = 0x09A
	// TPMRCSignature is TPM_RC_SIGNATURE. | TPMRCSignature 是 TPM_RC_SIGNATURE。
	TPMRCSignature uint32 = 0x09B
	// TPMRCKey is TPM_RC_KEY. | TPMRCKey 是 TPM_RC_KEY。
	TPMRCKey uint32 = 0x09C
	// TPMRCPolicyFailed is TPM_RC_POLICY. | TPMRCPolicyFailed 是 TPM_RC_POLICY。
	TPMRCPolicyFailed uint32 = 0x09D
	// TPMRCIntegrity is TPM_RC_INTEGRITY. | TPMRCIntegrity 是 TPM_RC_INTEGRITY。
	TPMRCIntegrity uint32 = 0x09F
	// TPMRCTicket is TPM_RC_TICKET. | TPMRCTicket 是 TPM_RC_TICKET。
	TPMRCTicket uint32 = 0x0A0
	// TPMRCReservedBits is TPM_RC_RESERVED_BITS. | TPMRCReservedBits 是 TPM_RC_RESERVED_BITS。
	TPMRCReservedBits uint32 = 0x0A1
	// TPMRCBadAuth is TPM_RC_BAD_AUTH. | TPMRCBadAuth 是 TPM_RC_BAD_AUTH。
	TPMRCBadAuth uint32 = 0x0A2
	// TPMRCExpired is TPM_RC_EXPIRED. | TPMRCExpired 是 TPM_RC_EXPIRED。
	TPMRCExpired uint32 = 0x0A3
	// TPMRCPolicyCC is TPM_RC_POLICY_CC. | TPMRCPolicyCC 是 TPM_RC_POLICY_CC。
	TPMRCPolicyCC uint32 = 0x0A4
	// TPMRCBinding is TPM_RC_BINDING. | TPMRCBinding 是 TPM_RC_BINDING。
	TPMRCBinding uint32 = 0x0A5
	// TPMRCCurve is TPM_RC_CURVE. | TPMRCCurve 是 TPM_RC_CURVE。
	TPMRCCurve uint32 = 0x0A6
	// TPMRCECCPoint is TPM_RC_ECC_POINT. | TPMRCECCPoint 是 TPM_RC_ECC_POINT。
	TPMRCECCPoint uint32 = 0x0A7
)

// tpmErrorBase returns the response code with optional parameter, session and NV index bits removed. |
// tpmErrorBase 返回去掉可选参数、会话与 NV 索引位后的响应码。
//
// Format-one errors are identified by bit 7 of the low byte. The P bit (0x40) and the N field
// (0xF00) are cleared before the name lookup; the low six bits carry the error number itself. Warning
// codes in the 0x900..0x97F range have bit 7 clear and are returned unchanged, so they never alias
// format-zero errors. | 格式一错误由低字节第 7 位识别。查名前清除 P 位（0x40）与 N 字段（0xF00）；
// 低六位本身是错误号。0x900..0x97F 范围的警告码第 7 位为 0，原样返回，因此绝不会与格式零错误混淆。
func tpmErrorBase(code uint32) uint32 {
	if code&0x080 != 0 {
		return code &^ 0xF40
	}
	return code
}

// TPMResponseCodeName returns the TPM 2.0 constant name for a response code. | TPMResponseCodeName
// 返回响应码对应的 TPM 2.0 常量名。
//
// Format-one codes carry an optional parameter, session or handle index; the index is removed before
// looking up the name. Unknown codes are rendered as TPM_RC_UNKNOWN_0x........ | 格式一响应码可能带有
// 参数、会话或句柄索引；查名前会去掉索引。未知码渲染为 TPM_RC_UNKNOWN_0x........。
func TPMResponseCodeName(code uint32) string {
	base := tpmErrorBase(code)
	if name, ok := tpmResponseCodeNames[base]; ok {
		return name
	}
	return fmt.Sprintf("TPM_RC_UNKNOWN_0x%08X", code)
}

// tpmResponseCodeNames maps base response codes to their specification names. | tpmResponseCodeNames
// 把基础响应码映射为规范名称。
var tpmResponseCodeNames = map[uint32]string{
	TPMRCSuccess:         "TPM_RC_SUCCESS",
	TPMRCInitialize:      "TPM_RC_INITIALIZE",
	TPMRCFailure:         "TPM_RC_FAILURE",
	TPMRCSequence:        "TPM_RC_SEQUENCE",
	TPMRCPrivate:         "TPM_RC_PRIVATE",
	TPMRCHmac:            "TPM_RC_HMAC",
	TPMRCDisabled:        "TPM_RC_DISABLED",
	TPMRCExclusive:       "TPM_RC_EXCLUSIVE",
	TPMRCAuthType:        "TPM_RC_AUTH_TYPE",
	TPMRCAuthMissing:     "TPM_RC_AUTH_MISSING",
	TPMRCPolicy:          "TPM_RC_POLICY",
	TPMRCPCR:             "TPM_RC_PCR",
	TPMRCPCRChanged:      "TPM_RC_PCR_CHANGED",
	TPMRCUpgrade:         "TPM_RC_UPGRADE",
	TPMRCTooManyContexts: "TPM_RC_TOO_MANY_CONTEXTS",
	TPMRCAuthUnavailable: "TPM_RC_AUTH_UNAVAILABLE",
	TPMRCReboot:          "TPM_RC_REBOOT",
	TPMRCUnbalanced:      "TPM_RC_UNBALANCED",
	TPMRCCommandSize:     "TPM_RC_COMMAND_SIZE",
	TPMRCCommandCode:     "TPM_RC_COMMAND_CODE",
	TPMRCAuthSize:        "TPM_RC_AUTHSIZE",
	TPMRCAuthContext:     "TPM_RC_AUTH_CONTEXT",
	TPMRCNVRange:         "TPM_RC_NV_RANGE",
	TPMRCNVSize:          "TPM_RC_NV_SIZE",
	TPMRCNVLocked:        "TPM_RC_NV_LOCKED",
	TPMRCNVAuthorization: "TPM_RC_NV_AUTHORIZATION",
	TPMRCNVUninitialized: "TPM_RC_NV_UNINITIALIZED",
	TPMRCNVSpace:         "TPM_RC_NV_SPACE",
	TPMRCNVDefined:       "TPM_RC_NV_DEFINED",
	TPMRCBadContext:      "TPM_RC_BAD_CONTEXT",
	TPMRCCPHash:          "TPM_RC_CPHASH",
	TPMRCParent:          "TPM_RC_PARENT",
	TPMRCNeedsTest:       "TPM_RC_NEEDS_TEST",
	TPMRCNoResult:        "TPM_RC_NO_RESULT",
	TPMRCSensitive:       "TPM_RC_SENSITIVE",
	TPMRCAsymmetric:      "TPM_RC_ASYMMETRIC",
	TPMAttributes:        "TPM_RC_ATTRIBUTES",
	TPMRCHash:            "TPM_RC_HASH",
	TPMRCValue:           "TPM_RC_VALUE",
	TPMRCHierarchy:       "TPM_RC_HIERARCHY",
	TPMRCKeySize:         "TPM_RC_KEY_SIZE",
	TPMRCMGF:             "TPM_RC_MGF",
	TPMRCMode:            "TPM_RC_MODE",
	TPMRCType:            "TPM_RC_TYPE",
	TPMRCHandle:          "TPM_RC_HANDLE",
	TPMRCKDF:             "TPM_RC_KDF",
	TPMRCRange:           "TPM_RC_RANGE",
	TPMRCAuthFail:        "TPM_RC_AUTH_FAIL",
	TPMRCNonce:           "TPM_RC_NONCE",
	TPMRCPP:              "TPM_RC_PP",
	TPMRCScheme:          "TPM_RC_SCHEME",
	TPMRCSize:            "TPM_RC_SIZE",
	TPMRCSymmetric:       "TPM_RC_SYMMETRIC",
	TPMRCTag:             "TPM_RC_TAG",
	TPMRCSelector:        "TPM_RC_SELECTOR",
	TPMRCInsufficient:    "TPM_RC_INSUFFICIENT",
	TPMRCSignature:       "TPM_RC_SIGNATURE",
	TPMRCKey:             "TPM_RC_KEY",
	TPMRCPolicyFailed:    "TPM_RC_POLICY",
	TPMRCIntegrity:       "TPM_RC_INTEGRITY",
	TPMRCTicket:          "TPM_RC_TICKET",
	TPMRCReservedBits:    "TPM_RC_RESERVED_BITS",
	TPMRCBadAuth:         "TPM_RC_BAD_AUTH",
	TPMRCExpired:         "TPM_RC_EXPIRED",
	TPMRCPolicyCC:        "TPM_RC_POLICY_CC",
	TPMRCBinding:         "TPM_RC_BINDING",
	TPMRCCurve:           "TPM_RC_CURVE",
	TPMRCECCPoint:        "TPM_RC_ECC_POINT",
	0x901:                "TPM_RC_CONTEXT_GAP",
	0x902:                "TPM_RC_OBJECT_MEMORY",
	0x903:                "TPM_RC_SESSION_MEMORY",
	0x904:                "TPM_RC_MEMORY",
	0x905:                "TPM_RC_SESSION_HANDLES",
	0x906:                "TPM_RC_OBJECT_HANDLES",
	0x907:                "TPM_RC_LOCALITY",
	0x908:                "TPM_RC_YIELDED",
	0x909:                "TPM_RC_CANCELED",
	0x90A:                "TPM_RC_TESTING",
	0x930:                "TPM_RC_NV_RATE",
	0x931:                "TPM_RC_LOCKOUT",
	0x932:                "TPM_RC_RETRY",
	0x933:                "TPM_RC_NV_UNAVAILABLE",
	0x97F:                "TPM_RC_NOT_USED",
}

// TPMError reports a non-zero TPM response code. | TPMError 报告非零 TPM 响应码。
//
// Errors.Is with ErrTPMCommand matches every TPMError; use errors.As to inspect Code. | 使用
// errors.Is 与 ErrTPMCommand 可匹配任何 TPMError；使用 errors.As 检查 Code。
type TPMError struct {
	// Code is the raw response code including parameter and session index bits. | Code 是包含参数与
	// 会话索引位的原始响应码。
	Code uint32
}

// Error implements error. | Error 实现 error。
func (e *TPMError) Error() string {
	name := TPMResponseCodeName(e.Code)
	return fmt.Sprintf("webauthn: TPM command failed: %s (%#08x) | webauthn：TPM 命令失败：%s（%#08x）",
		name, e.Code, name, e.Code)
}

// Unwrap returns ErrTPMCommand. | Unwrap 返回 ErrTPMCommand。
func (e *TPMError) Unwrap() error { return ErrTPMCommand }

// tpmCommandHandleCount returns the number of command handles for a supported command code. |
// tpmCommandHandleCount 返回支持的命令码的命令句柄数。
func tpmCommandHandleCount(code uint32) (int, bool) {
	switch code {
	case TPMCCActivateCredential:
		return 2, true
	case TPMCCMakeCredential, TPMCCFlushContext, TPMCCReadPublic:
		return 1, true
	case TPMCCGetCapability:
		return 0, true
	default:
		return 0, false
	}
}

// TPM2Command is a marshaled TPM 2.0 command. | TPM2Command 是已编码的 TPM 2.0 命令。
type TPM2Command struct {
	// Tag is TPM_ST_NO_SESSIONS or TPM_ST_SESSIONS. | Tag 为 TPM_ST_NO_SESSIONS 或 TPM_ST_SESSIONS。
	Tag uint16
	// CommandCode is the TPM_CC command code. | CommandCode 是 TPM_CC 命令码。
	CommandCode uint32
	// Handles are the command handles in wire order. | Handles 是按线上顺序排列的命令句柄。
	Handles []uint32
	// Auth is the authorization area for a TPM_ST_SESSIONS command. | Auth 是 TPM_ST_SESSIONS
	// 命令的授权区。
	Auth []TPMSAuthCommand
	// Parameters is the concatenated command parameter area. | Parameters 是串联的命令参数区。
	Parameters []byte
}

// Marshal returns the complete TPM 2.0 command wire image. | Marshal 返回完整 TPM 2.0 命令线上镜像。
func (c *TPM2Command) Marshal() ([]byte, error) {
	if c == nil {
		return nil, errs.Detail(ErrTPMStructure, "nil TPM command | TPM 命令为空")
	}
	if c.Tag != TPMSTNoSessions && c.Tag != TPMSTSessions {
		return nil, errs.Detail(ErrTPMStructure, "TPM command tag %#04x is not a supported tag | TPM 命令标签 %#04x 不是支持的标签",
			c.Tag, c.Tag)
	}
	expectedHandles, ok := tpmCommandHandleCount(c.CommandCode)
	if !ok {
		return nil, errs.Detail(ErrNotSupported, "unsupported TPM command code %#08x | 不支持的 TPM 命令码 %#08x",
			c.CommandCode, c.CommandCode)
	}
	if len(c.Handles) != expectedHandles {
		return nil, errs.Detail(ErrTPMStructure, "TPM command %#08x needs %d handles, got %d | TPM 命令 %#08x 需要 %d 个句柄，得到 %d",
			c.CommandCode, expectedHandles, len(c.Handles), c.CommandCode, expectedHandles, len(c.Handles))
	}
	if c.Tag == TPMSTNoSessions && len(c.Auth) > 0 {
		return nil, errs.Detail(ErrTPMStructure, "TPM_ST_NO_SESSIONS command carries authorization entries | TPM_ST_NO_SESSIONS 命令携带授权条目")
	}
	if c.Tag == TPMSTSessions && len(c.Auth) == 0 {
		return nil, errs.Detail(ErrTPMStructure, "TPM_ST_SESSIONS command lacks an authorization entry | TPM_ST_SESSIONS 命令缺少授权条目")
	}
	if len(c.Auth) > 8 {
		return nil, errs.Detail(ErrTPMStructure, "TPM command has %d authorization entries, limit 8 | TPM 命令有 %d 个授权条目，上限 8",
			len(c.Auth), len(c.Auth))
	}
	authSize := 0
	for index := range c.Auth {
		encoded, err := c.Auth[index].Marshal()
		if err != nil {
			return nil, err
		}
		authSize += len(encoded)
	}
	bodySize := 4*len(c.Handles) + len(c.Parameters)
	if c.Tag == TPMSTSessions {
		bodySize += 4 + authSize
	}
	size := 10 + bodySize
	if size > MaxTPM2CommandSize {
		return nil, errs.Detail(ErrTPMStructure, "TPM command is %d bytes, limit %d | TPM 命令为 %d 字节，上限 %d",
			size, MaxTPM2CommandSize, size, MaxTPM2CommandSize)
	}
	out := make([]byte, 0, size)
	out = tpm2AppendU16(out, c.Tag)
	out = tpm2AppendU32(out, uint32(size))
	out = tpm2AppendU32(out, c.CommandCode)
	for _, handle := range c.Handles {
		out = tpm2AppendU32(out, handle)
	}
	if c.Tag == TPMSTSessions {
		out = tpm2AppendU32(out, uint32(authSize))
		for index := range c.Auth {
			encoded, err := c.Auth[index].Marshal()
			if err != nil {
				return nil, err
			}
			out = append(out, encoded...)
		}
	}
	out = append(out, c.Parameters...)
	return out, nil
}

// ParseTPM2Command decodes exactly one TPM 2.0 command. | ParseTPM2Command 解码恰好一个 TPM 2.0 命令。
func ParseTPM2Command(data []byte) (*TPM2Command, error) {
	if len(data) < 10 {
		return nil, errs.Detail(ErrTPMStructure, "TPM command is %d bytes, header needs 10 | TPM 命令为 %d 字节，头部需要 10",
			len(data), len(data))
	}
	r := &tpm2Reader{data: data}
	tag, err := r.u16()
	if err != nil {
		return nil, err
	}
	if tag != TPMSTNoSessions && tag != TPMSTSessions {
		return nil, errs.Detail(ErrTPMStructure, "TPM command tag %#04x is not a supported tag | TPM 命令标签 %#04x 不是支持的标签",
			tag, tag)
	}
	size, err := r.u32()
	if err != nil {
		return nil, err
	}
	if size != uint32(len(data)) {
		return nil, errs.Detail(ErrTPMStructure, "TPM command header size %d differs from %d bytes | TPM 命令头大小 %d 与 %d 字节不一致",
			size, len(data), size, len(data))
	}
	if size > MaxTPM2CommandSize {
		return nil, errs.Detail(ErrTPMStructure, "TPM command is %d bytes, limit %d | TPM 命令为 %d 字节，上限 %d",
			size, MaxTPM2CommandSize, size, MaxTPM2CommandSize)
	}
	code, err := r.u32()
	if err != nil {
		return nil, err
	}
	handleCount, ok := tpmCommandHandleCount(code)
	if !ok {
		return nil, errs.Detail(ErrNotSupported, "unsupported TPM command code %#08x | 不支持的 TPM 命令码 %#08x", code, code)
	}
	command := &TPM2Command{Tag: tag, CommandCode: code}
	for index := 0; index < handleCount; index++ {
		handle, err := r.u32()
		if err != nil {
			return nil, err
		}
		command.Handles = append(command.Handles, handle)
	}
	if tag == TPMSTSessions {
		authSize, err := r.u32()
		if err != nil {
			return nil, err
		}
		if uint64(authSize) > uint64(r.remaining()) {
			return nil, errs.Detail(ErrTPMStructure, "TPM authorization area is %d bytes, %d remain | TPM 授权区为 %d 字节，剩余 %d",
				authSize, r.remaining(), authSize, r.remaining())
		}
		authEnd := r.off + int(authSize)
		for r.off < authEnd {
			entry, consumed, err := ParseTPMSAuthCommand(r.data[r.off:authEnd])
			if err != nil {
				return nil, err
			}
			if consumed == 0 || r.off+consumed > authEnd {
				return nil, errs.Detail(ErrTPMStructure, "TPM authorization entry overruns the %d byte area | TPM 授权条目越过 %d 字节区域",
					authSize, authSize)
			}
			command.Auth = append(command.Auth, entry)
			r.off += consumed
		}
		if len(command.Auth) == 0 {
			return nil, errs.Detail(ErrTPMStructure, "TPM authorization area is empty | TPM 授权区为空")
		}
		if len(command.Auth) > 8 {
			return nil, errs.Detail(ErrTPMStructure, "TPM command has %d authorization entries, limit 8 | TPM 命令有 %d 个授权条目，上限 8",
				len(command.Auth), len(command.Auth))
		}
	}
	command.Parameters = append([]byte(nil), data[r.off:]...)
	return command, nil
}

// TPM2Response is a parsed TPM 2.0 response. | TPM2Response 是已解析的 TPM 2.0 响应。
//
// None of the commands in this subsystem returns handles, so Parameters begins immediately after the
// response header (NO_SESSIONS) or after the parameterSize field (SESSIONS). | 本子系统中的所有命令都
// 不返回句柄，因此 Parameters 紧接响应头（NO_SESSIONS）或 parameterSize 字段（SESSIONS）之后。
type TPM2Response struct {
	// Tag is TPM_ST_NO_SESSIONS or TPM_ST_SESSIONS. | Tag 为 TPM_ST_NO_SESSIONS 或 TPM_ST_SESSIONS。
	Tag uint16
	// ResponseCode is the TPM response code. | ResponseCode 是 TPM 响应码。
	ResponseCode uint32
	// Parameters is the response parameter area. | Parameters 是响应参数区。
	Parameters []byte
	// Auth is the response authorization area for a TPM_ST_SESSIONS response. | Auth 是
	// TPM_ST_SESSIONS 响应的响应授权区。
	Auth []TPMSAuthResponse
}

// ParseTPM2Response decodes exactly one TPM 2.0 response. | ParseTPM2Response 解码恰好一个 TPM 2.0 响应。
func ParseTPM2Response(data []byte) (*TPM2Response, error) {
	if len(data) < 10 {
		return nil, errs.Detail(ErrTPMStructure, "TPM response is %d bytes, header needs 10 | TPM 响应为 %d 字节，头部需要 10",
			len(data), len(data))
	}
	r := &tpm2Reader{data: data}
	tag, err := r.u16()
	if err != nil {
		return nil, err
	}
	if tag != TPMSTNoSessions && tag != TPMSTSessions {
		return nil, errs.Detail(ErrTPMStructure, "TPM response tag %#04x is not a supported tag | TPM 响应标签 %#04x 不是支持的标签",
			tag, tag)
	}
	size, err := r.u32()
	if err != nil {
		return nil, err
	}
	if size != uint32(len(data)) {
		return nil, errs.Detail(ErrTPMStructure, "TPM response header size %d differs from %d bytes | TPM 响应头大小 %d 与 %d 字节不一致",
			size, len(data), size, len(data))
	}
	if size > MaxTPM2CommandSize {
		return nil, errs.Detail(ErrTPMStructure, "TPM response is %d bytes, limit %d | TPM 响应为 %d 字节，上限 %d",
			size, MaxTPM2CommandSize, size, MaxTPM2CommandSize)
	}
	code, err := r.u32()
	if err != nil {
		return nil, err
	}
	response := &TPM2Response{Tag: tag, ResponseCode: code}
	if code != TPMRCSuccess {
		if !r.done() {
			return nil, errs.Detail(ErrTPMStructure, "TPM error response has %d trailing bytes | TPM 错误响应有 %d 个多余字节",
				r.remaining(), r.remaining())
		}
		return response, nil
	}
	if tag == TPMSTNoSessions {
		response.Parameters = append([]byte(nil), data[r.off:]...)
		return response, nil
	}
	parameterSize, err := r.u32()
	if err != nil {
		return nil, err
	}
	parameters, err := r.bytes(int(parameterSize))
	if err != nil {
		return nil, err
	}
	response.Parameters = append([]byte(nil), parameters...)
	for !r.done() {
		entry, consumed, err := ParseTPMSAuthResponse(data[r.off:])
		if err != nil {
			return nil, err
		}
		if consumed == 0 {
			return nil, errs.Detail(ErrTPMStructure, "TPM response authorization entry is empty | TPM 响应授权条目为空")
		}
		response.Auth = append(response.Auth, entry)
		r.off += consumed
	}
	if len(response.Auth) > 8 {
		return nil, errs.Detail(ErrTPMStructure, "TPM response has %d authorization entries, limit 8 | TPM 响应有 %d 个授权条目，上限 8",
			len(response.Auth), len(response.Auth))
	}
	return response, nil
}

// TPM2Call sends a command to device and parses the response. | TPM2Call 向 device 发送命令并解析响应。
//
// A non-zero TPM response code is returned as *TPMError wrapping ErrTPMCommand together with the
// parsed response, so callers can inspect both. | 非零 TPM 响应码会以包装 ErrTPMCommand 的 *TPMError
// 连同已解析响应返回，调用方可以同时检查二者。
func TPM2Call(ctx context.Context, device TPM, command *TPM2Command) (*TPM2Response, error) {
	if device == nil {
		return nil, errs.Detail(ErrTPMUnavailable, "nil TPM device | TPM 设备为空")
	}
	raw, err := command.Marshal()
	if err != nil {
		return nil, err
	}
	reply, err := device.Execute(ctx, raw)
	if err != nil {
		return nil, err
	}
	response, err := ParseTPM2Response(reply)
	if err != nil {
		return nil, err
	}
	if response.ResponseCode != TPMRCSuccess {
		return response, &TPMError{Code: response.ResponseCode}
	}
	return response, nil
}

// tpm2PasswordAuth returns a TPM_RS_PW authorization entry with an empty password. | tpm2PasswordAuth
// 返回带空密码的 TPM_RS_PW 授权条目。
//
// The caller must still authenticate the authorization value through the authorization HMAC or a
// password; an empty password is valid only for objects whose authValue is empty. | 调用方仍须通过授权
// HMAC 或密码认证授权值；空密码仅对 authValue 为空的对象有效。
func tpm2PasswordAuth() TPMSAuthCommand {
	return TPMSAuthCommand{SessionHandle: TPMRSPassword}
}
