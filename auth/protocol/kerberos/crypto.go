package kerberos

import (
	"crypto/pbkdf2"
	"crypto/sha1"
	"crypto/subtle"

	"github.com/shibingli/ydx/errs"
)

// DefaultStringToKeyIterations is the RFC 3962 PBKDF2 iteration count used when
// the KDC supplies no s2kparams. | DefaultStringToKeyIterations 是 KDC 未提供
// s2kparams 时使用的 RFC 3962 PBKDF2 迭代次数。
const DefaultStringToKeyIterations = 4096

// SupportedETypes returns the encryption types implemented by this package, most
// preferred first. | SupportedETypes 返回本包实现的加密类型，优先者在前。
func SupportedETypes() []int32 {
	return []int32{ETypeAES256CTS, ETypeAES128CTS, ETypeRC4HMAC}
}

// KeySize returns the protocol key size in bytes for etype. | KeySize 返回 etype 的协议
// 密钥字节数。
func KeySize(etype int32) (int, error) {
	switch etype {
	case ETypeAES128CTS:
		return 16, nil
	case ETypeAES256CTS:
		return 32, nil
	case ETypeRC4HMAC:
		return 16, nil
	default:
		return 0, errs.Detail(ErrUnsupportedEType, "encryption type %d | 加密类型 %d", etype, etype)
	}
}

// ChecksumTypeForKey returns the keyed checksum type used with etype. | ChecksumTypeForKey
// 返回与 etype 配套的带密钥校验和类型。
func ChecksumTypeForKey(etype int32) (int32, error) {
	switch etype {
	case ETypeAES128CTS:
		return ChecksumTypeHMACSHA1AES128, nil
	case ETypeAES256CTS:
		return ChecksumTypeHMACSHA1AES256, nil
	case ETypeRC4HMAC:
		return ChecksumTypeHMACMD5, nil
	default:
		return 0, errs.Detail(ErrUnsupportedEType, "encryption type %d | 加密类型 %d", etype, etype)
	}
}

// StringToKey derives a protocol key from a password and salt. For AES types the
// RFC 3962 PBKDF2-HMAC-SHA1 derivation is used; for rc4-hmac the RFC 4757 MD4
// derivation is used and salt and iterations are ignored. Iterations less than
// one select DefaultStringToKeyIterations. | StringToKey 从口令与盐派生协议密钥。AES
// 类型使用 RFC 3962 PBKDF2-HMAC-SHA1；rc4-hmac 使用 RFC 4757 MD4，忽略盐与迭代次数。
// 迭代次数小于一时选择 DefaultStringToKeyIterations。
func StringToKey(password, salt string, iterations int, etype int32) ([]byte, error) {
	switch etype {
	case ETypeAES128CTS, ETypeAES256CTS:
		size, err := KeySize(etype)
		if err != nil {
			return nil, err
		}
		if iterations < 1 {
			iterations = DefaultStringToKeyIterations
		}
		seed, err := pbkdf2.Key(sha1.New, password, []byte(salt), iterations, size)
		if err != nil {
			return nil, errs.WrapDetail(err, ErrCredentials, "PBKDF2 key derivation failed | PBKDF2 密钥派生失败")
		}
		return deriveRandom(seed, []byte("kerberos")), nil
	case ETypeRC4HMAC:
		return rc4StringToKey(password)
	default:
		return nil, errs.Detail(ErrUnsupportedEType, "encryption type %d | 加密类型 %d", etype, etype)
	}
}

// deriveRandom implements the RFC 3961 DR function for AES keys. | deriveRandom 为 AES
// 密钥实现 RFC 3961 DR 函数。
func deriveRandom(protocolKey, constant []byte) []byte {
	if len(protocolKey) != 16 && len(protocolKey) != 32 {
		return nil
	}
	block := nfold(constant, 16)
	if len(block) != 16 {
		return nil
	}
	out := make([]byte, 0, len(protocolKey)+16)
	for len(out) < len(protocolKey) {
		block = aesEncryptBlock(protocolKey, block)
		out = append(out, block...)
	}
	return out[:len(protocolKey)]
}

// deriveKeyUsage derives an AES usage key with the RFC 3961 DK function. The
// octet is 0xAA for encryption, 0x55 for integrity, and 0x99 for checksums. | deriveKeyUsage
// 用 RFC 3961 DK 函数派生 AES 用途密钥。octet 为 0xAA 表示加密、0x55 表示完整性、
// 0x99 表示校验和。
func deriveKeyUsage(protocolKey []byte, usage uint32, octet byte) []byte {
	constant := make([]byte, 5)
	constant[0] = byte(usage >> 24)
	constant[1] = byte(usage >> 16)
	constant[2] = byte(usage >> 8)
	constant[3] = byte(usage)
	constant[4] = octet
	return deriveRandom(protocolKey, constant)
}

// checkKeyType validates the key length for etype. | checkKeyType 校验 etype 的密钥长度。
func checkKeyType(etype int32, key []byte) error {
	size, err := KeySize(etype)
	if err != nil {
		return err
	}
	if len(key) != size {
		return errs.Detail(ErrInvalidConfig, "key for encryption type %d is %d bytes, want %d | 加密类型 %d 的密钥为 %d 字节，期望 %d",
			etype, len(key), size, etype, len(key), size)
	}
	return nil
}

// EncryptMessage encrypts plaintext with a Kerberos protocol key and usage,
// returning the RFC 3962 or RFC 4757 wire form including its integrity tag. | EncryptMessage
// 用 Kerberos 协议密钥与用途加密 plaintext，返回包含完整性标签的 RFC 3962 或 RFC 4757
// 线格式。
func EncryptMessage(etype int32, key []byte, usage uint32, plaintext []byte) ([]byte, error) {
	if err := checkKeyType(etype, key); err != nil {
		return nil, err
	}
	switch etype {
	case ETypeAES128CTS, ETypeAES256CTS:
		return aesEncryptMessage(key, usage, plaintext)
	case ETypeRC4HMAC:
		return rc4EncryptMessage(key, usage, plaintext, nil)
	default:
		return nil, errs.Detail(ErrUnsupportedEType, "encryption type %d | 加密类型 %d", etype, etype)
	}
}

// DecryptMessage decrypts a Kerberos encrypted message and verifies its integrity
// tag. | DecryptMessage 解密 Kerberos 加密消息并校验完整性标签。
func DecryptMessage(etype int32, key []byte, usage uint32, ciphertext []byte) ([]byte, error) {
	if err := checkKeyType(etype, key); err != nil {
		return nil, err
	}
	switch etype {
	case ETypeAES128CTS, ETypeAES256CTS:
		return aesDecryptMessage(key, usage, ciphertext)
	case ETypeRC4HMAC:
		return rc4DecryptMessage(key, usage, ciphertext)
	default:
		return nil, errs.Detail(ErrUnsupportedEType, "encryption type %d | 加密类型 %d", etype, etype)
	}
}

// ChecksumMessage computes a keyed checksum over data with a Kerberos usage. | ChecksumMessage
// 用 Kerberos 用途对 data 计算带密钥校验和。
func ChecksumMessage(etype int32, key []byte, usage uint32, data []byte) ([]byte, error) {
	if err := checkKeyType(etype, key); err != nil {
		return nil, err
	}
	switch etype {
	case ETypeAES128CTS, ETypeAES256CTS:
		derived := deriveKeyUsage(key, usage, 0x99)
		if derived == nil {
			return nil, errs.Detail(ErrChecksumMismatch, "checksum key derivation failed | 校验和密钥派生失败")
		}
		return hmacSHA1Truncated(derived, data), nil
	case ETypeRC4HMAC:
		return rc4Checksum(key, usage, data), nil
	default:
		return nil, errs.Detail(ErrUnsupportedEType, "encryption type %d | 加密类型 %d", etype, etype)
	}
}

// VerifyChecksum verifies a keyed checksum over data. | VerifyChecksum 校验 data 上的
// 带密钥校验和。
func VerifyChecksum(etype int32, key []byte, usage uint32, data, checksum []byte) error {
	expected, err := ChecksumMessage(etype, key, usage, data)
	if err != nil {
		return err
	}
	if subtle.ConstantTimeCompare(expected, checksum) != 1 {
		return errs.Detail(ErrChecksumMismatch, "checksum type %d | 校验和类型 %d", etype, etype)
	}
	return nil
}
