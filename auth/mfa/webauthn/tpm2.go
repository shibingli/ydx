package webauthn

import (
	"crypto"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"crypto/sha512"
	"encoding/binary"

	"github.com/shibingli/ydx/errs"
)

// TPM 2.0 structure tags used on the command and response wire. | TPM 2.0 命令与响应线上使用的结构标签。
const (
	// TPMSTNoSessions marks a command or response without an authorization area. | TPMSTNoSessions 标记不带授权区的命令或响应。
	TPMSTNoSessions uint16 = 0x8001
	// TPMSTSessions marks a command or response with an authorization area. | TPMSTSessions 标记带授权区的命令或响应。
	TPMSTSessions uint16 = 0x8002
	// TPMSTCreation is the ticket tag of a creation ticket. | TPMSTCreation 是创建票据的标签。
	TPMSTCreation uint16 = 0x8021
	// TPMSTVerified is the ticket tag of a verified ticket. | TPMSTVerified 是已验证票据的标签。
	TPMSTVerified uint16 = 0x8022
	// TPMSTAuthSecret is the ticket tag of an authorization-secret ticket. | TPMSTAuthSecret 是授权秘密票据的标签。
	TPMSTAuthSecret uint16 = 0x8023
	// TPMSTHashcheck is the ticket tag of a hash-check ticket. | TPMSTHashcheck 是哈希校验票据的标签。
	TPMSTHashcheck uint16 = 0x8024
)

// TPM 2.0 generated-value magic and attestation types. | TPM 2.0 生成值魔术数与认证类型。
const (
	// TPMGeneratedValue is the magic value in every TPMS_ATTEST structure. | TPMGeneratedValue 是每个 TPMS_ATTEST 结构中的魔术数。
	TPMGeneratedValue uint32 = 0xff544347
	// TPMStAttestCertify is the TPMS_ATTEST type produced by TPM2_Certify and TPM2_ActivateCredential. |
	// TPMStAttestCertify 是 TPM2_Certify 与 TPM2_ActivateCredential 产生的 TPMS_ATTEST 类型。
	TPMStAttestCertify uint16 = 0x8017
)

// TPM 2.0 algorithm identifiers. | TPM 2.0 算法标识。
const (
	// TPMAlgRSA is TPM_ALG_RSA. | TPMAlgRSA 是 TPM_ALG_RSA。
	TPMAlgRSA uint16 = 0x0001
	// TPMAlgSHA1 is TPM_ALG_SHA1. | TPMAlgSHA1 是 TPM_ALG_SHA1。
	TPMAlgSHA1 uint16 = 0x0004
	// TPMAlgAES is TPM_ALG_AES. | TPMAlgAES 是 TPM_ALG_AES。
	TPMAlgAES uint16 = 0x0006
	// TPMAlgKeyedHash is TPM_ALG_KEYEDHASH. | TPMAlgKeyedHash 是 TPM_ALG_KEYEDHASH。
	TPMAlgKeyedHash uint16 = 0x0008
	// TPMAlgXOR is TPM_ALG_XOR. | TPMAlgXOR 是 TPM_ALG_XOR。
	TPMAlgXOR uint16 = 0x000A
	// TPMAlgSHA256 is TPM_ALG_SHA256. | TPMAlgSHA256 是 TPM_ALG_SHA256。
	TPMAlgSHA256 uint16 = 0x000B
	// TPMAlgSHA384 is TPM_ALG_SHA384. | TPMAlgSHA384 是 TPM_ALG_SHA384。
	TPMAlgSHA384 uint16 = 0x000C
	// TPMAlgSHA512 is TPM_ALG_SHA512. | TPMAlgSHA512 是 TPM_ALG_SHA512。
	TPMAlgSHA512 uint16 = 0x000D
	// TPMAlgNULL is TPM_ALG_NULL. | TPMAlgNULL 是 TPM_ALG_NULL。
	TPMAlgNULL uint16 = 0x0010
	// TPMAlgRSASSA is TPM_ALG_RSASSA. | TPMAlgRSASSA 是 TPM_ALG_RSASSA。
	TPMAlgRSASSA uint16 = 0x0014
	// TPMAlgRSAES is TPM_ALG_RSAES. | TPMAlgRSAES 是 TPM_ALG_RSAES。
	TPMAlgRSAES uint16 = 0x0015
	// TPMAlgRSAPSS is TPM_ALG_RSAPSS. | TPMAlgRSAPSS 是 TPM_ALG_RSAPSS。
	TPMAlgRSAPSS uint16 = 0x0016
	// TPMAlgOAEP is TPM_ALG_OAEP. | TPMAlgOAEP 是 TPM_ALG_OAEP。
	TPMAlgOAEP uint16 = 0x0017
	// TPMAlgECDSA is TPM_ALG_ECDSA. | TPMAlgECDSA 是 TPM_ALG_ECDSA。
	TPMAlgECDSA uint16 = 0x0018
	// TPMAlgECDH is TPM_ALG_ECDH. | TPMAlgECDH 是 TPM_ALG_ECDH。
	TPMAlgECDH uint16 = 0x0019
	// TPMAlgECDAA is TPM_ALG_ECDAA. | TPMAlgECDAA 是 TPM_ALG_ECDAA。
	TPMAlgECDAA uint16 = 0x001A
	// TPMAlgECSCHNORR is TPM_ALG_ECSCHNORR. | TPMAlgECSCHNORR 是 TPM_ALG_ECSCHNORR。
	TPMAlgECSCHNORR uint16 = 0x001C
	// TPMAlgKDF1SP80056A is TPM_ALG_KDF1_SP800_56A. | TPMAlgKDF1SP80056A 是 TPM_ALG_KDF1_SP800_56A。
	TPMAlgKDF1SP80056A uint16 = 0x0020
	// TPMAlgKDF2 is TPM_ALG_KDF2. | TPMAlgKDF2 是 TPM_ALG_KDF2。
	TPMAlgKDF2 uint16 = 0x0021
	// TPMAlgKDF1SP800108 is TPM_ALG_KDF1_SP800_108. | TPMAlgKDF1SP800108 是 TPM_ALG_KDF1_SP800_108。
	TPMAlgKDF1SP800108 uint16 = 0x0022
	// TPMAlgECC is TPM_ALG_ECC. | TPMAlgECC 是 TPM_ALG_ECC。
	TPMAlgECC uint16 = 0x0023
	// TPMAlgSymCipher is TPM_ALG_SYMCIPHER. | TPMAlgSymCipher 是 TPM_ALG_SYMCIPHER。
	TPMAlgSymCipher uint16 = 0x0025
	// TPMAlgCTR is TPM_ALG_CTR. | TPMAlgCTR 是 TPM_ALG_CTR。
	TPMAlgCTR uint16 = 0x0040
	// TPMAlgOFB is TPM_ALG_OFB. | TPMAlgOFB 是 TPM_ALG_OFB。
	TPMAlgOFB uint16 = 0x0041
	// TPMAlgCBC is TPM_ALG_CBC. | TPMAlgCBC 是 TPM_ALG_CBC。
	TPMAlgCBC uint16 = 0x0042
	// TPMAlgCFB is TPM_ALG_CFB. | TPMAlgCFB 是 TPM_ALG_CFB。
	TPMAlgCFB uint16 = 0x0043
	// TPMAlgECB is TPM_ALG_ECB. | TPMAlgECB 是 TPM_ALG_ECB。
	TPMAlgECB uint16 = 0x0044
)

// TPM 2.0 elliptic-curve identifiers. | TPM 2.0 椭圆曲线标识。
const (
	// TPMEccNISTP192 is TPM_ECC_NIST_P192. | TPMEccNISTP192 是 TPM_ECC_NIST_P192。
	TPMEccNISTP192 uint16 = 0x0001
	// TPMEccNISTP224 is TPM_ECC_NIST_P224. | TPMEccNISTP224 是 TPM_ECC_NIST_P224。
	TPMEccNISTP224 uint16 = 0x0002
	// TPMEccNISTP256 is TPM_ECC_NIST_P256. | TPMEccNISTP256 是 TPM_ECC_NIST_P256。
	TPMEccNISTP256 uint16 = 0x0003
	// TPMEccNISTP384 is TPM_ECC_NIST_P384. | TPMEccNISTP384 是 TPM_ECC_NIST_P384。
	TPMEccNISTP384 uint16 = 0x0004
	// TPMEccNISTP521 is TPM_ECC_NIST_P521. | TPMEccNISTP521 是 TPM_ECC_NIST_P521。
	TPMEccNISTP521 uint16 = 0x0005
)

// TPM 2.0 object attributes used by endorsement and attestation keys. | 背书密钥与认证密钥使用的 TPM 2.0 对象属性。
const (
	// TPMAFixedTPM is TPMA_OBJECT_fixedTPM. | TPMAFixedTPM 是 TPMA_OBJECT_fixedTPM。
	TPMAFixedTPM uint32 = 0x00000002
	// TPMAFixedParent is TPMA_OBJECT_fixedParent. | TPMAFixedParent 是 TPMA_OBJECT_fixedParent。
	TPMAFixedParent uint32 = 0x00000010
	// TPMASensitiveDataOrigin is TPMA_OBJECT_sensitiveDataOrigin. | TPMASensitiveDataOrigin 是 TPMA_OBJECT_sensitiveDataOrigin。
	TPMASensitiveDataOrigin uint32 = 0x00000020
	// TPMAUserWithAuth is TPMA_OBJECT_userWithAuth. | TPMAUserWithAuth 是 TPMA_OBJECT_userWithAuth。
	TPMAUserWithAuth uint32 = 0x00000040
	// TPMAAdminWithPolicy is TPMA_OBJECT_adminWithPolicy. | TPMAAdminWithPolicy 是 TPMA_OBJECT_adminWithPolicy。
	TPMAAdminWithPolicy uint32 = 0x00000080
	// TPMANoDA is TPMA_OBJECT_noDA. | TPMANoDA 是 TPMA_OBJECT_noDA。
	TPMANoDA uint32 = 0x00000400
	// TPMARestricted is TPMA_OBJECT_restricted. | TPMARestricted 是 TPMA_OBJECT_restricted。
	TPMARestricted uint32 = 0x00010000
	// TPMADecrypt is TPMA_OBJECT_decrypt. | TPMADecrypt 是 TPMA_OBJECT_decrypt。
	TPMADecrypt uint32 = 0x00020000
	// TPMASign is TPMA_OBJECT_sign. | TPMASign 是 TPMA_OBJECT_sign。
	TPMASign uint32 = 0x00040000
)

// TPM 2.0 command codes implemented by this package. | 本包实现的 TPM 2.0 命令码。
const (
	// TPMCCActivateCredential is TPM_CC_ActivateCredential. | TPMCCActivateCredential 是 TPM_CC_ActivateCredential。
	TPMCCActivateCredential uint32 = 0x00000147
	// TPMCCMakeCredential is TPM_CC_MakeCredential. | TPMCCMakeCredential 是 TPM_CC_MakeCredential。
	TPMCCMakeCredential uint32 = 0x00000163
	// TPMCCFlushContext is TPM_CC_FlushContext. | TPMCCFlushContext 是 TPM_CC_FlushContext。
	TPMCCFlushContext uint32 = 0x00000165
	// TPMCCReadPublic is TPM_CC_ReadPublic. | TPMCCReadPublic 是 TPM_CC_ReadPublic。
	TPMCCReadPublic uint32 = 0x00000173
	// TPMCCGetCapability is TPM_CC_GetCapability. | TPMCCGetCapability 是 TPM_CC_GetCapability。
	TPMCCGetCapability uint32 = 0x0000017A
)

// TPM 2.0 permanent handles and capability selectors. | TPM 2.0 永久句柄与能力选择符。
const (
	// TPMRHOwner is TPM_RH_OWNER. | TPMRHOwner 是 TPM_RH_OWNER。
	TPMRHOwner uint32 = 0x40000001
	// TPMRHNull is TPM_RH_NULL. | TPMRHNull 是 TPM_RH_NULL。
	TPMRHNull uint32 = 0x40000007
	// TPMRSPassword is TPM_RS_PW, the password authorization session. | TPMRSPassword 是 TPM_RS_PW，密码授权会话。
	TPMRSPassword uint32 = 0x40000009
	// TPMCapHandles is TPM_CAP_HANDLES. | TPMCapHandles 是 TPM_CAP_HANDLES。
	TPMCapHandles uint32 = 0x00000001
	// TPMCapTPMProperties is TPM_CAP_TPM_PROPERTIES. | TPMCapTPMProperties 是 TPM_CAP_TPM_PROPERTIES。
	TPMCapTPMProperties uint32 = 0x00000006
	// TPMPropertyManufacturer is TPM_PT_MANUFACTURER. | TPMPropertyManufacturer 是 TPM_PT_MANUFACTURER。
	TPMPropertyManufacturer uint32 = 0x00000105
	// TPMPropertyFirmwareVersion1 is TPM_PT_FIRMWARE_VERSION_1. | TPMPropertyFirmwareVersion1 是 TPM_PT_FIRMWARE_VERSION_1。
	TPMPropertyFirmwareVersion1 uint32 = 0x0000010B
)

// TPM 2.0 wire limits that bound untrusted input. | 限制不可信输入的 TPM 2.0 线上长度上限。
const (
	// MaxTPM2CommandSize is the largest accepted command or response size in bytes. | MaxTPM2CommandSize 是接受的最大命令或响应字节数。
	MaxTPM2CommandSize = 65536
	// MaxTPM2BUFFERSize is the largest TPM2B buffer accepted by the codec. | MaxTPM2BUFFERSize 是编解码器接受的最大 TPM2B 缓冲区。
	MaxTPM2BUFFERSize = 65535
	// maxTPMRSAKeyBytes is the largest accepted RSA modulus size in bytes. | maxTPMRSAKeyBytes 是接受的最大 RSA 模数字节数。
	maxTPMRSAKeyBytes = 1024
	// maxTPMNameSize is the largest TPM Name size: algorithm identifier plus a SHA-512 digest. |
	// maxTPMNameSize 是最大 TPM Name 字节数：算法标识加上 SHA-512 摘要。
	maxTPMNameSize = 2 + sha512.Size
	// maxTPMSchemeCount is the largest accepted TPML_PCR_SELECTION count. | maxTPMSchemeCount 是接受的最大 TPML_PCR_SELECTION 条目数。
	maxTPMSchemeCount = 16
)

// tpm2Reader decodes big-endian TPM structures with explicit length checks. | tpm2Reader 解码大端 TPM 结构并显式检查长度。
type tpm2Reader struct {
	data []byte
	off  int
}

// remaining returns the number of unread bytes. | remaining 返回未读字节数。
func (r *tpm2Reader) remaining() int { return len(r.data) - r.off }

// bytes returns the next n bytes without copying. | bytes 返回接下来 n 字节且不复制。
func (r *tpm2Reader) bytes(n int) ([]byte, error) {
	if n < 0 || n > r.remaining() {
		return nil, errs.Detail(ErrTPMStructure, "TPM structure is truncated: need %d bytes, have %d | TPM 结构被截断：需要 %d 字节，剩余 %d",
			n, r.remaining(), n, r.remaining())
	}
	out := r.data[r.off : r.off+n]
	r.off += n
	return out, nil
}

// u8 reads one byte. | u8 读取一个字节。
func (r *tpm2Reader) u8() (uint8, error) {
	b, err := r.bytes(1)
	if err != nil {
		return 0, err
	}
	return b[0], nil
}

// u16 reads a big-endian uint16. | u16 读取大端 uint16。
func (r *tpm2Reader) u16() (uint16, error) {
	b, err := r.bytes(2)
	if err != nil {
		return 0, err
	}
	return binary.BigEndian.Uint16(b), nil
}

// u32 reads a big-endian uint32. | u32 读取大端 uint32。
func (r *tpm2Reader) u32() (uint32, error) {
	b, err := r.bytes(4)
	if err != nil {
		return 0, err
	}
	return binary.BigEndian.Uint32(b), nil
}

// u64 reads a big-endian uint64. | u64 读取大端 uint64。
func (r *tpm2Reader) u64() (uint64, error) {
	b, err := r.bytes(8)
	if err != nil {
		return 0, err
	}
	return binary.BigEndian.Uint64(b), nil
}

// sized reads a TPM2B value and returns its contents. | sized 读取 TPM2B 值并返回其内容。
func (r *tpm2Reader) sized(max int) ([]byte, error) {
	size, err := r.u16()
	if err != nil {
		return nil, err
	}
	if int(size) > max {
		return nil, errs.Detail(ErrTPMStructure, "TPM2B size %d exceeds the %d byte limit | TPM2B 大小 %d 超过 %d 字节上限",
			size, max, size, max)
	}
	return r.bytes(int(size))
}

// done reports whether every byte has been consumed. | done 报告是否已消费全部字节。
func (r *tpm2Reader) done() bool { return r.off == len(r.data) }

// tpm2AppendU16 appends a big-endian uint16. | tpm2AppendU16 追加大端 uint16。
func tpm2AppendU16(dst []byte, value uint16) []byte {
	return append(dst, byte(value>>8), byte(value))
}

// tpm2AppendU32 appends a big-endian uint32. | tpm2AppendU32 追加大端 uint32。
func tpm2AppendU32(dst []byte, value uint32) []byte {
	return append(dst, byte(value>>24), byte(value>>16), byte(value>>8), byte(value))
}

// tpm2AppendU64 appends a big-endian uint64. | tpm2AppendU64 追加大端 uint64。
func tpm2AppendU64(dst []byte, value uint64) []byte {
	return append(dst, byte(value>>56), byte(value>>48), byte(value>>40), byte(value>>32),
		byte(value>>24), byte(value>>16), byte(value>>8), byte(value))
}

// tpm2AppendSized appends a TPM2B-encoded byte slice. | tpm2AppendSized 追加 TPM2B 编码的字节切片。
func tpm2AppendSized(dst, value []byte) ([]byte, error) {
	if len(value) > MaxTPM2BUFFERSize {
		return nil, errs.Detail(ErrTPMStructure, "TPM2B value is %d bytes, limit %d | TPM2B 值为 %d 字节，上限 %d",
			len(value), MaxTPM2BUFFERSize, len(value), MaxTPM2BUFFERSize)
	}
	dst = tpm2AppendU16(dst, uint16(len(value)))
	return append(dst, value...), nil
}

// TPM2B is a size-prefixed TPM byte buffer. | TPM2B 是带长度前缀的 TPM 字节缓冲区。
type TPM2B struct {
	// Buffer is the TPM2B contents without the two-byte size prefix. | Buffer 是不含两字节长度前缀的 TPM2B 内容。
	Buffer []byte
}

// NewTPM2B returns a TPM2B holding a copy of buffer. | NewTPM2B 返回保存 buffer 副本的 TPM2B。
func NewTPM2B(buffer []byte) TPM2B {
	return TPM2B{Buffer: append([]byte(nil), buffer...)}
}

// Marshal returns the TPM2B wire encoding. | Marshal 返回 TPM2B 线上编码。
func (b TPM2B) Marshal() ([]byte, error) {
	return tpm2AppendSized(nil, b.Buffer)
}

// AppendTo appends the TPM2B wire encoding to dst. | AppendTo 把 TPM2B 线上编码追加到 dst。
func (b TPM2B) AppendTo(dst []byte) ([]byte, error) {
	return tpm2AppendSized(dst, b.Buffer)
}

// Clone returns a deep copy of the buffer. | Clone 返回缓冲区深拷贝。
func (b TPM2B) Clone() TPM2B {
	return TPM2B{Buffer: append([]byte(nil), b.Buffer...)}
}

// ParseTPM2B decodes a TPM2B value and returns it with the number of bytes consumed. |
// ParseTPM2B 解码 TPM2B 值，并返回它及消费的字节数。
func ParseTPM2B(data []byte) (TPM2B, int, error) {
	r := &tpm2Reader{data: data}
	buffer, err := r.sized(MaxTPM2BUFFERSize)
	if err != nil {
		return TPM2B{}, 0, err
	}
	return TPM2B{Buffer: append([]byte(nil), buffer...)}, r.off, nil
}

// TPM2BAuth is a TPM2B_AUTH. | TPM2BAuth 是 TPM2B_AUTH。
type TPM2BAuth = TPM2B

// TPM2BDigest is a TPM2B_DIGEST. | TPM2BDigest 是 TPM2B_DIGEST。
type TPM2BDigest = TPM2B

// TPM2BNonce is a TPM2B_NONCE. | TPM2BNonce 是 TPM2B_NONCE。
type TPM2BNonce = TPM2B

// TPM2BIDObject is a TPM2B_ID_OBJECT carrying a protected credential. | TPM2BIDObject 是携带受保护凭据的 TPM2B_ID_OBJECT。
type TPM2BIDObject = TPM2B

// TPM2BEncryptedSecret is a TPM2B_ENCRYPTED_SECRET. | TPM2BEncryptedSecret 是 TPM2B_ENCRYPTED_SECRET。
type TPM2BEncryptedSecret = TPM2B

// TPM2BAttest is a TPM2B_ATTEST. | TPM2BAttest 是 TPM2B_ATTEST。
type TPM2BAttest = TPM2B

// TPM2BData is a TPM2B_DATA. | TPM2BData 是 TPM2B_DATA。
type TPM2BData = TPM2B

// TPM2BName is a TPM2B_NAME holding a TPM Name. | TPM2BName 是保存 TPM Name 的 TPM2B_NAME。
type TPM2BName struct {
	// Name is the raw Name: the name algorithm followed by its digest. | Name 是原始 Name：名称算法后跟其摘要。
	Name []byte
}

// Marshal returns the TPM2B_NAME wire encoding. | Marshal 返回 TPM2B_NAME 线上编码。
func (n TPM2BName) Marshal() ([]byte, error) {
	if err := n.Validate(); err != nil {
		return nil, err
	}
	return tpm2AppendSized(nil, n.Name)
}

// Validate checks that the Name has a supported algorithm and matching digest size. |
// Validate 检查 Name 是否具有支持的算法与匹配的摘要长度。
func (n TPM2BName) Validate() error {
	if len(n.Name) < 2 || len(n.Name) > maxTPMNameSize {
		return errs.Detail(ErrTPMStructure, "TPM Name length %d is outside 2..%d | TPM Name 长度 %d 超出 2..%d",
			len(n.Name), maxTPMNameSize, len(n.Name), maxTPMNameSize)
	}
	algorithm := binary.BigEndian.Uint16(n.Name[:2])
	hash, ok := TPMHash(algorithm)
	if !ok {
		return errs.Detail(ErrUnsupportedAlgorithm, "TPM Name algorithm %#04x | TPM Name 算法 %#04x", algorithm, algorithm)
	}
	if len(n.Name) != 2+hash.Size() {
		return errs.Detail(ErrTPMStructure, "TPM Name digest is %d bytes, algorithm %#04x needs %d | TPM Name 摘要为 %d 字节，算法 %#04x 需要 %d",
			len(n.Name)-2, algorithm, hash.Size(), len(n.Name)-2, algorithm, hash.Size())
	}
	return nil
}

// ParseTPM2BName decodes a TPM2B_NAME and returns it with the number of bytes consumed. |
// ParseTPM2BName 解码 TPM2B_NAME，并返回它及消费的字节数。
func ParseTPM2BName(data []byte) (TPM2BName, int, error) {
	r := &tpm2Reader{data: data}
	raw, err := r.sized(maxTPMNameSize)
	if err != nil {
		return TPM2BName{}, 0, err
	}
	name := TPM2BName{Name: append([]byte(nil), raw...)}
	if err := name.Validate(); err != nil {
		return TPM2BName{}, 0, err
	}
	return name, r.off, nil
}

// TPMHash maps a TPM 2.0 hash algorithm identifier to crypto.Hash. | TPMHash 把 TPM 2.0 哈希算法标识映射为 crypto.Hash。
func TPMHash(algorithm uint16) (crypto.Hash, bool) {
	switch algorithm {
	case TPMAlgSHA256:
		return crypto.SHA256, true
	case TPMAlgSHA384:
		return crypto.SHA384, true
	case TPMAlgSHA512:
		return crypto.SHA512, true
	default:
		return 0, false
	}
}

// TPMHashAlgorithm maps crypto.Hash to a TPM 2.0 hash algorithm identifier. | TPMHashAlgorithm 把 crypto.Hash 映射为 TPM 2.0 哈希算法标识。
func TPMHashAlgorithm(hash crypto.Hash) (uint16, bool) {
	switch hash {
	case crypto.SHA256:
		return TPMAlgSHA256, true
	case crypto.SHA384:
		return TPMAlgSHA384, true
	case crypto.SHA512:
		return TPMAlgSHA512, true
	default:
		return 0, false
	}
}

// tpm2HashConstructor returns the hash constructor for a supported TPM hash algorithm. |
// tpm2HashConstructor 返回支持的 TPM 哈希算法的构造函数。
func tpm2HashConstructor(algorithm uint16) (func() hashWriter, int, error) {
	// The explicit imports make every supported hash available without linking the
	// crypto package's optional implementations.
	switch algorithm {
	case TPMAlgSHA256:
		return func() hashWriter { return sha256.New() }, sha256.Size, nil
	case TPMAlgSHA384:
		return func() hashWriter { return sha512.New384() }, sha512.Size384, nil
	case TPMAlgSHA512:
		return func() hashWriter { return sha512.New() }, sha512.Size, nil
	default:
		return nil, 0, errs.Detail(ErrUnsupportedAlgorithm, "TPM hash algorithm %#04x is not supported | 不支持 TPM 哈希算法 %#04x",
			algorithm, algorithm)
	}
}

// hashWriter is the subset of hash.Hash used by the TPM codec. | hashWriter 是 TPM 编解码器使用的 hash.Hash 子集。
type hashWriter interface {
	// Write appends data and returns the number of bytes written. | Write 追加数据并返回写入字节数。
	Write([]byte) (int, error)
	// Sum appends the current digest without changing the hash state. | Sum 在不改变哈希状态的情况下
	// 追加当前摘要。
	Sum([]byte) []byte
}

// KDFa implements the TPM 2.0 counter-mode HMAC key derivation function. | KDFa 实现 TPM 2.0 计数器模式
// HMAC 密钥派生函数。
//
// key is the HMAC key, label the ASCII label without its terminating NUL (one is appended), contextU
// and contextV are optional context values, and bits is the requested output length. The function
// rejects unsupported hashes and output lengths outside 8..32768 bits. | key 是 HMAC 密钥，label 是
// 不含结尾 NUL 的 ASCII 标签（函数会追加一个），contextU 与 contextV 是可选上下文值，bits 是请求的
// 输出位数。函数拒绝不支持的哈希以及 8..32768 位之外的输出长度。
func KDFa(hash crypto.Hash, key, label, contextU, contextV []byte, bits int) ([]byte, error) {
	return tpm2KDF(hash, key, label, contextU, contextV, bits, true)
}

// KDFe implements the TPM 2.0 ECDH key derivation function. | KDFe 实现 TPM 2.0 ECDH 密钥派生函数。
//
// The output is HMAC(counter || Z || label || NUL || partyUInfo || partyVInfo || bits), truncated to
// bits. The label must not include its terminating NUL. | 输出为
// HMAC(counter || Z || label || NUL || partyUInfo || partyVInfo || bits) 截断到 bits。label 不得包含
// 结尾 NUL。
func KDFe(hash crypto.Hash, z, label, partyUInfo, partyVInfo []byte, bits int) ([]byte, error) {
	return tpm2KDF(hash, z, label, partyUInfo, partyVInfo, bits, false)
}

// tpm2KDF implements KDFa and KDFe; useA selects the KDFa layout. | tpm2KDF 实现 KDFa 与 KDFe；
// useA 选择 KDFa 布局。
//
// KDFa hashes HMAC(key, counter || label || NUL || contextU || contextV || bits). KDFe hashes
// HASH(counter || Z || label || NUL || partyUInfo || partyVInfo || bits), where Z arrives in key;
// it is a plain hash, not an HMAC. | KDFa 计算
// HMAC(key, counter || label || NUL || contextU || contextV || bits)。KDFe 计算
// HASH(counter || Z || label || NUL || partyUInfo || partyVInfo || bits)，其中 Z 通过 key 传入；
// 它是普通哈希而非 HMAC。
func tpm2KDF(hash crypto.Hash, key, label, contextU, contextV []byte, bits int, useA bool) ([]byte, error) {
	if bits < 8 || bits > 32768 {
		return nil, errs.Detail(ErrInvalidConfig, "TPM KDF output %d bits is outside 8..32768 | TPM KDF 输出 %d 位超出 8..32768",
			bits, bits)
	}
	algorithm, ok := TPMHashAlgorithm(hash)
	if !ok {
		return nil, errs.Detail(ErrUnsupportedAlgorithm, "TPM KDF hash %v is not supported | 不支持 TPM KDF 哈希 %v", hash, hash)
	}
	newHash, size, err := tpm2HashConstructor(algorithm)
	if err != nil {
		return nil, err
	}
	if len(label) > 64 {
		return nil, errs.Detail(ErrInvalidConfig, "TPM KDF label is %d bytes, limit 64 | TPM KDF 标签为 %d 字节，上限 64", len(label), len(label))
	}
	needed := (bits + 7) / 8
	blocks := (needed + size - 1) / size
	if blocks > 32768 {
		return nil, errs.Detail(ErrInvalidConfig, "TPM KDF needs %d blocks | TPM KDF 需要 %d 个块", blocks, blocks)
	}
	out := make([]byte, 0, blocks*size)
	labelBuffer := make([]byte, 0, len(label)+1)
	labelBuffer = append(labelBuffer, label...)
	labelBuffer = append(labelBuffer, 0)
	var length [4]byte
	binary.BigEndian.PutUint32(length[:], uint32(bits))
	for counter := 1; counter <= blocks; counter++ {
		var count [4]byte
		binary.BigEndian.PutUint32(count[:], uint32(counter))
		if useA {
			mac := hmac.New(hash.New, key)
			_, _ = mac.Write(count[:])
			_, _ = mac.Write(labelBuffer)
			_, _ = mac.Write(contextU)
			_, _ = mac.Write(contextV)
			_, _ = mac.Write(length[:])
			out = mac.Sum(out)
			continue
		}
		hasher := newHash()
		_, _ = hasher.Write(count[:])
		_, _ = hasher.Write(key)
		_, _ = hasher.Write(labelBuffer)
		_, _ = hasher.Write(contextU)
		_, _ = hasher.Write(contextV)
		_, _ = hasher.Write(length[:])
		out = hasher.Sum(out)
	}
	return out[:needed], nil
}

// TPMName computes the TPM Name of a marshaled TPMT_PUBLIC area. | TPMName 计算已编码 TPMT_PUBLIC 区域的 TPM Name。
func TPMName(publicArea []byte) ([]byte, error) {
	parsed, err := ParseTPMTPublic(publicArea)
	if err != nil {
		return nil, err
	}
	return parsed.Name(publicArea)
}

// TPMNameFromPublic computes the TPM Name of a parsed public area. | TPMNameFromPublic 计算已解析公钥区域的 TPM Name。
func TPMNameFromPublic(publicArea *TPMTPublic) ([]byte, error) {
	if publicArea == nil {
		return nil, errs.Detail(ErrTPMStructure, "nil TPM public area | TPM 公钥区域为空")
	}
	encoded, err := publicArea.Marshal()
	if err != nil {
		return nil, err
	}
	return publicArea.Name(encoded)
}

// Name computes the TPM Name of the given marshaled public area. | Name 计算给定已编码公钥区域的 TPM Name。
func (p *TPMTPublic) Name(publicArea []byte) ([]byte, error) {
	if p == nil {
		return nil, errs.Detail(ErrTPMStructure, "nil TPM public area | TPM 公钥区域为空")
	}
	hash, ok := TPMHash(p.NameAlg)
	if !ok {
		return nil, errs.Detail(ErrUnsupportedAlgorithm, "TPM name algorithm %#04x | TPM name 算法 %#04x", p.NameAlg, p.NameAlg)
	}
	hasher := hash.New()
	_, _ = hasher.Write(publicArea)
	out := make([]byte, 2, 2+hash.Size())
	out[0] = byte(p.NameAlg >> 8)
	out[1] = byte(p.NameAlg)
	return append(out, hasher.Sum(nil)...), nil
}

// TPMRandom fills buffer from the cryptographic random source. | TPMRandom 从密码学随机源填充 buffer。
func tpmRandom(buffer []byte) error {
	if _, err := rand.Read(buffer); err != nil {
		return errs.WrapDetail(err, ErrChallengeGeneration, "TPM random generation failed | TPM 随机数生成失败")
	}
	return nil
}
