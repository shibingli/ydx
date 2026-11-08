package ntlm

import (
	"crypto/rc4"

	"github.com/shibingli/ydx/errs"
)

// MechListMICSize is the size in bytes of an NTLM SPNEGO mechListMIC. |
// MechListMICSize 是 NTLM SPNEGO mechListMIC 的字节大小。
const MechListMICSize = micSize

// mechListMICPrefix is the NTLMSSP signature prefixed to the DER mechanism
// list before hashing. | mechListMICPrefix 是哈希前追加到 DER 机制列表的 NTLMSSP
// 签名。
var mechListMICPrefix = []byte(Signature)

// EncodeMechTypeList encodes mechanisms as the DER SEQUENCE OF OID used by the
// SPNEGO mechTypes field and by the mechListMIC input. Every mechanism must be a
// non-empty DER OID value without its tag or length. | EncodeMechTypeList 把
// mechanisms 编码为 SPNEGO mechTypes 字段与 mechListMIC 输入使用的 DER
// SEQUENCE OF OID。每个机制必须是非空 DER OID 值，不含标签与长度。
func EncodeMechTypeList(mechanisms [][]byte) ([]byte, error) {
	if len(mechanisms) == 0 {
		return nil, errs.Detail(ErrSPNEGO, "mechanism list is empty | 机制列表为空")
	}
	builder := &derBuilder{}
	encoded := make([][]byte, 0, len(mechanisms))
	for _, mechanism := range mechanisms {
		if len(mechanism) == 0 {
			return nil, errs.Detail(ErrSPNEGO, "mechanism OID is empty | 机制 OID 为空")
		}
		encoded = append(encoded, builder.tlv(0x06, mechanism))
	}
	list := builder.seq(0x30, encoded...)
	if builder.err != nil {
		return nil, builder.err
	}
	return list, nil
}

// validateMechTypeList checks that data is one canonical DER SEQUENCE OF OID
// with no trailing bytes. | validateMechTypeList 校验 data 是一个规范 DER
// SEQUENCE OF OID 且没有尾随字节。
func validateMechTypeList(data []byte) error {
	tag, value, rest, err := readDER(data)
	if err != nil {
		return err
	}
	if tag != 0x30 {
		return errs.Detail(ErrSPNEGO, "mech type list is not a SEQUENCE | 机制类型列表不是 SEQUENCE")
	}
	if len(rest) != 0 {
		return errs.Detail(ErrSPNEGO, "bytes follow the mech type list | 机制类型列表之后仍有字节")
	}
	if _, err := parseMechTypes(value); err != nil {
		return err
	}
	return nil
}

// ComputeMechListMIC computes the SPNEGO mechListMIC defined by MS-SPNG 3.1.5.1:
// HMAC-MD5(sessionBaseKey, "NTLMSSP\0" || mechTypesDER). When the negotiated
// flags contain FlagKeyExchange, the 16-byte HMAC result is additionally
// RC4-encapsulated with the session base key, matching the NTLM signing key
// exchange path. sessionBaseKey is the 16-byte NTLMv2 SessionBaseKey and
// mechTypesDER is the canonical DER SEQUENCE OF OID over which the MIC is
// computed. | ComputeMechListMIC 计算 MS-SPNG 3.1.5.1 定义的 SPNEGO mechListMIC：
// HMAC-MD5(sessionBaseKey, "NTLMSSP\0" || mechTypesDER)。当协商标志包含
// FlagKeyExchange 时，16 字节 HMAC 结果额外使用会话基础密钥进行 RC4 封装，对应 NTLM
// 签名密钥交换路径。sessionBaseKey 是 16 字节 NTLMv2 SessionBaseKey，mechTypesDER
// 是计算 MIC 所用的规范 DER SEQUENCE OF OID。
func ComputeMechListMIC(sessionBaseKey, mechTypesDER []byte, flags NegotiateFlags) ([]byte, error) {
	if len(sessionBaseKey) != md4Size {
		return nil, errs.Detail(ErrMechListMIC, "session base key is %d bytes, want %d | 会话基础密钥为 %d 字节，期望 %d", len(sessionBaseKey), md4Size, len(sessionBaseKey), md4Size)
	}
	if err := validateMechTypeList(mechTypesDER); err != nil {
		return nil, errs.WrapDetail(err, ErrMechListMIC, "mech type list is invalid | 机制类型列表非法")
	}
	input := make([]byte, 0, len(mechListMICPrefix)+len(mechTypesDER))
	input = append(input, mechListMICPrefix...)
	input = append(input, mechTypesDER...)
	mic := hmacMD5(sessionBaseKey, input)
	if !flags.Has(FlagKeyExchange) {
		return mic, nil
	}
	cipher, err := rc4.NewCipher(sessionBaseKey)
	if err != nil {
		return nil, errs.WrapDetail(err, ErrMechListMIC, "RC4 encapsulation setup failed | RC4 封装初始化失败")
	}
	encapsulated := make([]byte, len(mic))
	cipher.XORKeyStream(encapsulated, mic)
	return encapsulated, nil
}

// VerifyMechListMIC recomputes and compares a mechListMIC in constant time.
// A nil or differently sized MIC is rejected with ErrMechListMIC. |
// VerifyMechListMIC 以常量时间重新计算并比较 mechListMIC。nil 或长度不同的 MIC 会以
// ErrMechListMIC 拒绝。
func VerifyMechListMIC(sessionBaseKey, mechTypesDER, mic []byte, flags NegotiateFlags) error {
	if len(mic) != MechListMICSize {
		return errs.Detail(ErrMechListMIC, "mechListMIC is %d bytes, want %d | mechListMIC 为 %d 字节，期望 %d", len(mic), MechListMICSize, len(mic), MechListMICSize)
	}
	expected, err := ComputeMechListMIC(sessionBaseKey, mechTypesDER, flags)
	if err != nil {
		return err
	}
	if !constantTimeEqual(expected, mic) {
		return errs.Detail(ErrMechListMIC, "mechListMIC does not match | mechListMIC 不匹配")
	}
	return nil
}
