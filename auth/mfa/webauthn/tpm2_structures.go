package webauthn

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rsa"
	"math/big"

	"github.com/shibingli/ydx/errs"
)

// Bounds applied while decoding TPM 2.0 public and sensitive areas. | 解码 TPM 2.0 公钥与敏感区域时使用的界限。
const (
	// maxTPMECCParameterSize is the largest accepted ECC coordinate size in bytes (P-521). |
	// maxTPMECCParameterSize 是接受的最大 ECC 坐标字节数（P-521）。
	maxTPMECCParameterSize = 66
	// maxTPMAuthPolicySize is the largest accepted TPMT_PUBLIC authPolicy. | maxTPMAuthPolicySize 是
	// 接受的最大 TPMT_PUBLIC authPolicy 字节数。
	maxTPMAuthPolicySize = 64
	// maxTPMPCRSelectSize is the largest accepted TPMS_PCR_SELECTION sizeofSelect value. |
	// maxTPMPCRSelectSize 是接受的最大 TPMS_PCR_SELECTION sizeofSelect 值。
	maxTPMPCRSelectSize = 4
	// maxTPMSensitiveSize is the largest accepted sensitive composite value in bytes. |
	// maxTPMSensitiveSize 是接受的最大敏感复合值字节数。
	maxTPMSensitiveSize = maxTPMRSAKeyBytes
	// maxTPMTicketDigestSize is the largest accepted ticket digest. | maxTPMTicketDigestSize 是接受的
	// 最大票据摘要字节数。
	maxTPMTicketDigestSize = 64
)

// TPMSymDefObject is a TPMT_SYM_DEF_OBJECT describing a symmetric algorithm. | TPMSymDefObject 是
// 描述对称算法的 TPMT_SYM_DEF_OBJECT。
//
// Algorithm is TPM_ALG_NULL or a symmetric algorithm such as TPM_ALG_AES. KeyBits and Mode are present
// only when Algorithm is not TPM_ALG_NULL; the NULL descriptor is encoded as the two algorithm bytes
// alone, matching the conditional marshaling rules of TPM 2.0 Part 2. | Algorithm 为 TPM_ALG_NULL 或
// TPM_ALG_AES 等对称算法。仅当 Algorithm 不是 TPM_ALG_NULL 时 KeyBits 与 Mode 才存在；NULL 描述符仅
// 编码两个算法字节，符合 TPM 2.0 第二部分的条件编码规则。
type TPMSymDefObject struct {
	// Algorithm is the symmetric algorithm identifier. | Algorithm 是对称算法标识。
	Algorithm uint16
	// KeyBits is the key size in bits for AES, SM4, Camellia or XOR. | KeyBits 是 AES、SM4、
	// Camellia 或 XOR 的密钥位数。
	KeyBits uint16
	// Mode is the symmetric mode identifier. | Mode 是对称模式标识。
	Mode uint16
}

// isNull reports whether the descriptor is TPM_ALG_NULL. | isNull 报告描述符是否为 TPM_ALG_NULL。
func (s TPMSymDefObject) isNull() bool { return s.Algorithm == TPMAlgNULL }

// Marshal returns the TPMT_SYM_DEF_OBJECT encoding. | Marshal 返回 TPMT_SYM_DEF_OBJECT 编码。
func (s TPMSymDefObject) Marshal() ([]byte, error) {
	if s.Algorithm == TPMAlgNULL {
		// TPMU_SYM_KEY_BITS and TPMU_SYM_MODE are empty for TPM_ALG_NULL.
		if s.KeyBits != 0 || s.Mode != 0 {
			return nil, errs.Detail(ErrTPMStructure, "TPM_ALG_NULL symmetric descriptor carries key bits %d and mode %#04x | TPM_ALG_NULL 对称描述符携带密钥位数 %d 与模式 %#04x",
				s.KeyBits, s.Mode, s.KeyBits, s.Mode)
		}
		return tpm2AppendU16(nil, TPMAlgNULL), nil
	}
	if s.Algorithm != TPMAlgAES && s.Algorithm != TPMAlgXOR {
		return nil, errs.Detail(ErrTPMStructure, "unsupported symmetric algorithm %#04x in TPM public area | TPM 公钥区域中不支持的对称算法 %#04x",
			s.Algorithm, s.Algorithm)
	}
	switch s.Algorithm {
	case TPMAlgAES:
		if s.KeyBits != 128 && s.KeyBits != 192 && s.KeyBits != 256 {
			return nil, errs.Detail(ErrTPMStructure, "AES key size %d is not 128, 192 or 256 | AES 密钥位数 %d 不是 128、192 或 256",
				s.KeyBits, s.KeyBits)
		}
	case TPMAlgXOR:
		if _, ok := TPMHash(s.KeyBits); !ok {
			return nil, errs.Detail(ErrTPMStructure, "XOR KDF hash %#04x is not supported | 不支持 XOR KDF 哈希 %#04x", s.KeyBits, s.KeyBits)
		}
	}
	if s.Mode != TPMAlgNULL && s.Mode != TPMAlgCTR && s.Mode != TPMAlgOFB && s.Mode != TPMAlgCBC &&
		s.Mode != TPMAlgCFB && s.Mode != TPMAlgECB {
		return nil, errs.Detail(ErrTPMStructure, "unsupported symmetric mode %#04x in TPM public area | TPM 公钥区域中不支持的对称模式 %#04x",
			s.Mode, s.Mode)
	}
	out := tpm2AppendU16(nil, s.Algorithm)
	out = tpm2AppendU16(out, s.KeyBits)
	return tpm2AppendU16(out, s.Mode), nil
}

// parseTPMSymDefObject decodes a TPMT_SYM_DEF_OBJECT. | parseTPMSymDefObject 解码 TPMT_SYM_DEF_OBJECT。
func parseTPMSymDefObject(r *tpm2Reader) (TPMSymDefObject, error) {
	algorithm, err := r.u16()
	if err != nil {
		return TPMSymDefObject{}, err
	}
	descriptor := TPMSymDefObject{Algorithm: algorithm}
	if algorithm == TPMAlgNULL {
		return descriptor, nil
	}
	if algorithm != TPMAlgAES && algorithm != TPMAlgXOR {
		return TPMSymDefObject{}, errs.Detail(ErrTPMStructure, "unsupported symmetric algorithm %#04x in TPM public area | TPM 公钥区域中不支持的对称算法 %#04x",
			algorithm, algorithm)
	}
	keyBits, err := r.u16()
	if err != nil {
		return TPMSymDefObject{}, err
	}
	mode, err := r.u16()
	if err != nil {
		return TPMSymDefObject{}, err
	}
	descriptor.KeyBits = keyBits
	descriptor.Mode = mode
	return descriptor, descriptor.validate()
}

// validate checks a symmetric descriptor. | validate 校验对称描述符。
func (s TPMSymDefObject) validate() error {
	_, err := s.Marshal()
	return err
}

// TPMTKDFScheme is a TPMT_KDF_SCHEME. | TPMTKDFScheme 是 TPMT_KDF_SCHEME。
type TPMTKDFScheme struct {
	// Scheme is the key derivation function identifier. | Scheme 是密钥派生函数标识。
	Scheme uint16
	// HashAlg is the hash used by the KDF, present only for a non-NULL scheme. | HashAlg 是 KDF 使用的
	// 哈希，仅在非 NULL 方案时存在。
	HashAlg uint16
}

// Marshal returns the TPMT_KDF_SCHEME encoding. | Marshal 返回 TPMT_KDF_SCHEME 编码。
func (s TPMTKDFScheme) Marshal() ([]byte, error) {
	out := tpm2AppendU16(nil, s.Scheme)
	if s.Scheme == TPMAlgNULL {
		return out, nil
	}
	if s.Scheme != TPMAlgKDF1SP80056A && s.Scheme != TPMAlgKDF2 && s.Scheme != TPMAlgKDF1SP800108 {
		return nil, errs.Detail(ErrTPMStructure, "unsupported KDF scheme %#04x | 不支持的 KDF 方案 %#04x", s.Scheme, s.Scheme)
	}
	if _, ok := TPMHash(s.HashAlg); !ok {
		return nil, errs.Detail(ErrTPMStructure, "unsupported KDF hash %#04x | 不支持的 KDF 哈希 %#04x", s.HashAlg, s.HashAlg)
	}
	return tpm2AppendU16(out, s.HashAlg), nil
}

// parseTPMTKDFScheme decodes a TPMT_KDF_SCHEME. | parseTPMTKDFScheme 解码 TPMT_KDF_SCHEME。
func parseTPMTKDFScheme(r *tpm2Reader) (TPMTKDFScheme, error) {
	scheme, err := r.u16()
	if err != nil {
		return TPMTKDFScheme{}, err
	}
	descriptor := TPMTKDFScheme{Scheme: scheme}
	if scheme == TPMAlgNULL {
		return descriptor, nil
	}
	if scheme != TPMAlgKDF1SP80056A && scheme != TPMAlgKDF2 && scheme != TPMAlgKDF1SP800108 {
		return TPMTKDFScheme{}, errs.Detail(ErrTPMStructure, "unsupported KDF scheme %#04x | 不支持的 KDF 方案 %#04x", scheme, scheme)
	}
	hash, err := r.u16()
	if err != nil {
		return TPMTKDFScheme{}, err
	}
	if _, ok := TPMHash(hash); !ok {
		return TPMTKDFScheme{}, errs.Detail(ErrTPMStructure, "unsupported KDF hash %#04x | 不支持的 KDF 哈希 %#04x", hash, hash)
	}
	descriptor.HashAlg = hash
	return descriptor, nil
}

// TPMTRSAScheme is a TPMT_RSA_SCHEME. | TPMTRSAScheme 是 TPMT_RSA_SCHEME。
type TPMTRSAScheme struct {
	// Scheme is TPM_ALG_NULL, TPM_ALG_RSAES, TPM_ALG_RSASSA, TPM_ALG_RSAPSS or TPM_ALG_OAEP. |
	// Scheme 为 TPM_ALG_NULL、TPM_ALG_RSAES、TPM_ALG_RSASSA、TPM_ALG_RSAPSS 或 TPM_ALG_OAEP。
	Scheme uint16
	// HashAlg is the scheme hash, present for RSASSA, RSAPSS and OAEP. | HashAlg 是方案哈希，在
	// RSASSA、RSAPSS 与 OAEP 时存在。
	HashAlg uint16
}

// Marshal returns the TPMT_RSA_SCHEME encoding. | Marshal 返回 TPMT_RSA_SCHEME 编码。
func (s TPMTRSAScheme) Marshal() ([]byte, error) {
	out := tpm2AppendU16(nil, s.Scheme)
	switch s.Scheme {
	case TPMAlgNULL, TPMAlgRSAES:
		return out, nil
	case TPMAlgRSASSA, TPMAlgRSAPSS, TPMAlgOAEP:
		if _, ok := TPMHash(s.HashAlg); !ok {
			return nil, errs.Detail(ErrTPMStructure, "unsupported RSA scheme hash %#04x | 不支持的 RSA 方案哈希 %#04x", s.HashAlg, s.HashAlg)
		}
		return tpm2AppendU16(out, s.HashAlg), nil
	default:
		return nil, errs.Detail(ErrTPMStructure, "unsupported RSA scheme %#04x | 不支持的 RSA 方案 %#04x", s.Scheme, s.Scheme)
	}
}

// parseTPMTRSAScheme decodes a TPMT_RSA_SCHEME. | parseTPMTRSAScheme 解码 TPMT_RSA_SCHEME。
func parseTPMTRSAScheme(r *tpm2Reader) (TPMTRSAScheme, error) {
	scheme, err := r.u16()
	if err != nil {
		return TPMTRSAScheme{}, err
	}
	descriptor := TPMTRSAScheme{Scheme: scheme}
	switch scheme {
	case TPMAlgNULL, TPMAlgRSAES:
		return descriptor, nil
	case TPMAlgRSASSA, TPMAlgRSAPSS, TPMAlgOAEP:
		hash, err := r.u16()
		if err != nil {
			return TPMTRSAScheme{}, err
		}
		if _, ok := TPMHash(hash); !ok {
			return TPMTRSAScheme{}, errs.Detail(ErrTPMStructure, "unsupported RSA scheme hash %#04x | 不支持的 RSA 方案哈希 %#04x", hash, hash)
		}
		descriptor.HashAlg = hash
		return descriptor, nil
	default:
		return TPMTRSAScheme{}, errs.Detail(ErrTPMStructure, "unsupported RSA scheme %#04x | 不支持的 RSA 方案 %#04x", scheme, scheme)
	}
}

// TPMTECCScheme is a TPMT_ECC_SCHEME. | TPMTECCScheme 是 TPMT_ECC_SCHEME。
//
// Every non-NULL ECC scheme carries one hash algorithm in its details union, including ECDH whose
// TPMU_ASYM_SCHEME member is TPMS_SCHEME_ECDH (hashAlg). The ECDH key derivation scheme proper lives
// in TPMS_ECC_PARMS.kdf and is exposed as TPMTPublic.KDF. | 每个非 NULL ECC 方案的 details 联合都携带
// 一个哈希算法，包括 ECDH，其 TPMU_ASYM_SCHEME 成员为 TPMS_SCHEME_ECDH（hashAlg）。真正的 ECDH
// 密钥派生方案位于 TPMS_ECC_PARMS.kdf，由 TPMTPublic.KDF 暴露。
type TPMTECCScheme struct {
	// Scheme is TPM_ALG_NULL, TPM_ALG_ECDSA, TPM_ALG_ECDAA, TPM_ALG_ECSCHNORR or TPM_ALG_ECDH. |
	// Scheme 为 TPM_ALG_NULL、TPM_ALG_ECDSA、TPM_ALG_ECDAA、TPM_ALG_ECSCHNORR 或 TPM_ALG_ECDH。
	Scheme uint16
	// HashAlg is the scheme hash, present whenever Scheme is not TPM_ALG_NULL. | HashAlg 是方案哈希，
	// 当 Scheme 不是 TPM_ALG_NULL 时存在。
	HashAlg uint16
}

// Marshal returns the TPMT_ECC_SCHEME encoding. | Marshal 返回 TPMT_ECC_SCHEME 编码。
func (s TPMTECCScheme) Marshal() ([]byte, error) {
	out := tpm2AppendU16(nil, s.Scheme)
	switch s.Scheme {
	case TPMAlgNULL:
		return out, nil
	case TPMAlgECDSA, TPMAlgECDAA, TPMAlgECSCHNORR, TPMAlgECDH:
		if _, ok := TPMHash(s.HashAlg); !ok {
			return nil, errs.Detail(ErrTPMStructure, "unsupported ECC scheme hash %#04x | 不支持的 ECC 方案哈希 %#04x", s.HashAlg, s.HashAlg)
		}
		return tpm2AppendU16(out, s.HashAlg), nil
	default:
		return nil, errs.Detail(ErrTPMStructure, "unsupported ECC scheme %#04x | 不支持的 ECC 方案 %#04x", s.Scheme, s.Scheme)
	}
}

// parseTPMTECCScheme decodes a TPMT_ECC_SCHEME. | parseTPMTECCScheme 解码 TPMT_ECC_SCHEME。
func parseTPMTECCScheme(r *tpm2Reader) (TPMTECCScheme, error) {
	scheme, err := r.u16()
	if err != nil {
		return TPMTECCScheme{}, err
	}
	descriptor := TPMTECCScheme{Scheme: scheme}
	switch scheme {
	case TPMAlgNULL:
		return descriptor, nil
	case TPMAlgECDSA, TPMAlgECDAA, TPMAlgECSCHNORR, TPMAlgECDH:
		hash, err := r.u16()
		if err != nil {
			return TPMTECCScheme{}, err
		}
		if _, ok := TPMHash(hash); !ok {
			return TPMTECCScheme{}, errs.Detail(ErrTPMStructure, "unsupported ECC scheme hash %#04x | 不支持的 ECC 方案哈希 %#04x", hash, hash)
		}
		descriptor.HashAlg = hash
		return descriptor, nil
	default:
		return TPMTECCScheme{}, errs.Detail(ErrTPMStructure, "unsupported ECC scheme %#04x | 不支持的 ECC 方案 %#04x", scheme, scheme)
	}
}

// TPMSEccPoint is a TPMS_ECC_POINT. | TPMSEccPoint 是 TPMS_ECC_POINT。
type TPMSEccPoint struct {
	// X is the affine X coordinate without leading zero bytes. | X 是不带前导零字节的仿射 X 坐标。
	X []byte
	// Y is the affine Y coordinate without leading zero bytes. | Y 是不带前导零字节的仿射 Y 坐标。
	Y []byte
}

// Marshal returns the TPMS_ECC_POINT encoding. | Marshal 返回 TPMS_ECC_POINT 编码。
func (p TPMSEccPoint) Marshal() ([]byte, error) {
	if len(p.X) == 0 || len(p.X) > maxTPMECCParameterSize || len(p.Y) == 0 || len(p.Y) > maxTPMECCParameterSize {
		return nil, errs.Detail(ErrTPMStructure, "ECC coordinate sizes %d/%d are outside 1..%d | ECC 坐标长度 %d/%d 超出 1..%d",
			len(p.X), len(p.Y), maxTPMECCParameterSize, len(p.X), len(p.Y), maxTPMECCParameterSize)
	}
	out, err := tpm2AppendSized(nil, p.X)
	if err != nil {
		return nil, err
	}
	return tpm2AppendSized(out, p.Y)
}

// parseTPMSEccPoint decodes a TPMS_ECC_POINT. | parseTPMSEccPoint 解码 TPMS_ECC_POINT。
func parseTPMSEccPoint(r *tpm2Reader) (TPMSEccPoint, error) {
	x, err := r.sized(maxTPMECCParameterSize)
	if err != nil {
		return TPMSEccPoint{}, err
	}
	y, err := r.sized(maxTPMECCParameterSize)
	if err != nil {
		return TPMSEccPoint{}, err
	}
	if len(x) == 0 || len(y) == 0 {
		return TPMSEccPoint{}, errs.Detail(ErrTPMStructure, "ECC coordinate is empty | ECC 坐标为空")
	}
	return TPMSEccPoint{X: append([]byte(nil), x...), Y: append([]byte(nil), y...)}, nil
}

// TPMSClockInfo is a TPMS_CLOCK_INFO. | TPMSClockInfo 是 TPMS_CLOCK_INFO。
type TPMSClockInfo struct {
	// Clock is the TPM clock in milliseconds. | Clock 是 TPM 毫秒时钟。
	Clock uint64
	// ResetCount is the number of TPM resets. | ResetCount 是 TPM 重置次数。
	ResetCount uint32
	// RestartCount is the number of TPM restarts. | RestartCount 是 TPM 重启次数。
	RestartCount uint32
	// Safe reports whether the clock is safe. | Safe 报告时钟是否安全。
	Safe uint8
}

// TPMTPublic is a TPMT_PUBLIC public area. | TPMTPublic 是 TPMT_PUBLIC 公钥区域。
//
// The zero value with Type and NameAlg set can be marshaled; ParseTPMTPublic validates every nested
// length, algorithm, curve and key component before returning a value, so callers may treat a parsed
// public area as structurally sound. | 设置了 Type 与 NameAlg 的零值可以被编码；ParseTPMTPublic 在
// 返回前校验每个嵌套长度、算法、曲线与密钥分量，因此调用方可把已解析公钥区域视为结构合法。
type TPMTPublic struct {
	// Type is the public key type: TPM_ALG_RSA, TPM_ALG_ECC, TPM_ALG_KEYEDHASH or TPM_ALG_SYMCIPHER. |
	// Type 是公钥类型：TPM_ALG_RSA、TPM_ALG_ECC、TPM_ALG_KEYEDHASH 或 TPM_ALG_SYMCIPHER。
	Type uint16
	// NameAlg is the Name algorithm. | NameAlg 是 Name 算法。
	NameAlg uint16
	// ObjectAttributes is the TPMA_OBJECT bit field. | ObjectAttributes 是 TPMA_OBJECT 位字段。
	ObjectAttributes uint32
	// AuthPolicy is the TPM2B_DIGEST authorization policy. | AuthPolicy 是 TPM2B_DIGEST 授权策略。
	AuthPolicy []byte
	// Symmetric is the symmetric definition used by restricted keys. | Symmetric 是受限密钥使用的对称定义。
	Symmetric TPMSymDefObject
	// RSAScheme is the RSA scheme for TPM_ALG_RSA keys. | RSAScheme 是 TPM_ALG_RSA 密钥的 RSA 方案。
	RSAScheme TPMTRSAScheme
	// KeyBits is the RSA modulus size in bits. | KeyBits 是 RSA 模数位数。
	KeyBits uint16
	// Exponent is the RSA public exponent; zero means the TPM default 65537. | Exponent 是 RSA 公钥
	// 指数；零表示 TPM 默认值 65537。
	Exponent uint32
	// ECCScheme is the ECC scheme for TPM_ALG_ECC keys. | ECCScheme 是 TPM_ALG_ECC 密钥的 ECC 方案。
	ECCScheme TPMTECCScheme
	// CurveID is the TPM ECC curve identifier. | CurveID 是 TPM ECC 曲线标识。
	CurveID uint16
	// KDF is the TPMS_ECC_PARMS key derivation scheme; it is meaningful for ECDH. | KDF 是
	// TPMS_ECC_PARMS 密钥派生方案；对 ECDH 有意义。
	KDF TPMTKDFScheme
	// RSAModulus is the RSA unique field. | RSAModulus 是 RSA unique 字段。
	RSAModulus []byte
	// ECCPoint is the ECC unique field. | ECCPoint 是 ECC unique 字段。
	ECCPoint TPMSEccPoint
}

// ParseTPMTPublic decodes exactly one raw TPMT_PUBLIC area. | ParseTPMTPublic 解码恰好一个原始
// TPMT_PUBLIC 区域。
func ParseTPMTPublic(data []byte) (*TPMTPublic, error) {
	if len(data) == 0 {
		return nil, errs.Detail(ErrTPMStructure, "empty TPM public area | TPM 公钥区域为空")
	}
	r := &tpm2Reader{data: data}
	public, err := parseTPMTPublic(r)
	if err != nil {
		return nil, err
	}
	if !r.done() {
		return nil, errs.Detail(ErrTPMStructure, "TPM public area has %d trailing bytes | TPM 公钥区域有 %d 个多余字节",
			r.remaining(), r.remaining())
	}
	return public, nil
}

// parseTPMTPublic decodes a TPMT_PUBLIC from the reader. | parseTPMTPublic 从读取器解码 TPMT_PUBLIC。
func parseTPMTPublic(r *tpm2Reader) (*TPMTPublic, error) {
	publicType, err := r.u16()
	if err != nil {
		return nil, err
	}
	nameAlg, err := r.u16()
	if err != nil {
		return nil, err
	}
	if _, ok := TPMHash(nameAlg); !ok {
		return nil, errs.Detail(ErrUnsupportedAlgorithm, "unsupported TPM Name algorithm %#04x | 不支持的 TPM Name 算法 %#04x",
			nameAlg, nameAlg)
	}
	attributes, err := r.u32()
	if err != nil {
		return nil, err
	}
	authPolicy, err := r.sized(maxTPMAuthPolicySize)
	if err != nil {
		return nil, err
	}
	public := &TPMTPublic{
		Type:             publicType,
		NameAlg:          nameAlg,
		ObjectAttributes: attributes,
		AuthPolicy:       append([]byte(nil), authPolicy...),
	}
	switch publicType {
	case TPMAlgRSA:
		if err := parseTPMRSAPublic(r, public); err != nil {
			return nil, err
		}
	case TPMAlgECC:
		if err := parseTPMECCPublic(r, public); err != nil {
			return nil, err
		}
	default:
		return nil, errs.Detail(ErrUnsupportedKey, "unsupported TPM public key type %#04x | 不支持的 TPM 公钥类型 %#04x",
			publicType, publicType)
	}
	if err := public.Validate(); err != nil {
		return nil, err
	}
	return public, nil
}

// parseTPMRSAPublic decodes the parameters and unique fields of an RSA public area. |
// parseTPMRSAPublic 解码 RSA 公钥区域的参数与 unique 字段。
func parseTPMRSAPublic(r *tpm2Reader, public *TPMTPublic) error {
	symmetric, err := parseTPMSymDefObject(r)
	if err != nil {
		return err
	}
	scheme, err := parseTPMTRSAScheme(r)
	if err != nil {
		return err
	}
	keyBits, err := r.u16()
	if err != nil {
		return err
	}
	exponent, err := r.u32()
	if err != nil {
		return err
	}
	modulus, err := r.sized(maxTPMRSAKeyBytes)
	if err != nil {
		return err
	}
	public.Symmetric = symmetric
	public.RSAScheme = scheme
	public.KeyBits = keyBits
	public.Exponent = exponent
	public.RSAModulus = append([]byte(nil), modulus...)
	return nil
}

// parseTPMECCPublic decodes the parameters and unique fields of an ECC public area. |
// parseTPMECCPublic 解码 ECC 公钥区域的参数与 unique 字段。
func parseTPMECCPublic(r *tpm2Reader, public *TPMTPublic) error {
	symmetric, err := parseTPMSymDefObject(r)
	if err != nil {
		return err
	}
	scheme, err := parseTPMTECCScheme(r)
	if err != nil {
		return err
	}
	curve, err := r.u16()
	if err != nil {
		return err
	}
	kdf, err := parseTPMTKDFScheme(r)
	if err != nil {
		return err
	}
	point, err := parseTPMSEccPoint(r)
	if err != nil {
		return err
	}
	public.Symmetric = symmetric
	public.ECCScheme = scheme
	public.CurveID = curve
	public.KDF = kdf
	public.ECCPoint = point
	return nil
}

// Marshal returns the raw TPMT_PUBLIC encoding. | Marshal 返回原始 TPMT_PUBLIC 编码。
func (p *TPMTPublic) Marshal() ([]byte, error) {
	if p == nil {
		return nil, errs.Detail(ErrTPMStructure, "nil TPM public area | TPM 公钥区域为空")
	}
	if err := p.Validate(); err != nil {
		return nil, err
	}
	out := tpm2AppendU16(nil, p.Type)
	out = tpm2AppendU16(out, p.NameAlg)
	out = tpm2AppendU32(out, p.ObjectAttributes)
	var err error
	out, err = tpm2AppendSized(out, p.AuthPolicy)
	if err != nil {
		return nil, err
	}
	switch p.Type {
	case TPMAlgRSA:
		symmetric, err := p.Symmetric.Marshal()
		if err != nil {
			return nil, err
		}
		scheme, err := p.RSAScheme.Marshal()
		if err != nil {
			return nil, err
		}
		out = append(out, symmetric...)
		out = append(out, scheme...)
		out = tpm2AppendU16(out, p.KeyBits)
		out = tpm2AppendU32(out, p.Exponent)
		out, err = tpm2AppendSized(out, p.RSAModulus)
		if err != nil {
			return nil, err
		}
	case TPMAlgECC:
		symmetric, err := p.Symmetric.Marshal()
		if err != nil {
			return nil, err
		}
		scheme, err := p.ECCScheme.Marshal()
		if err != nil {
			return nil, err
		}
		kdf, err := p.KDF.Marshal()
		if err != nil {
			return nil, err
		}
		out = append(out, symmetric...)
		out = append(out, scheme...)
		out = tpm2AppendU16(out, p.CurveID)
		out = append(out, kdf...)
		point, err := p.ECCPoint.Marshal()
		if err != nil {
			return nil, err
		}
		out = append(out, point...)
	}
	return out, nil
}

// Validate checks the public area fields and key material. | Validate 校验公钥区域字段与密钥材料。
func (p *TPMTPublic) Validate() error {
	if p == nil {
		return errs.Detail(ErrTPMStructure, "nil TPM public area | TPM 公钥区域为空")
	}
	if _, ok := TPMHash(p.NameAlg); !ok {
		return errs.Detail(ErrUnsupportedAlgorithm, "unsupported TPM Name algorithm %#04x | 不支持的 TPM Name 算法 %#04x",
			p.NameAlg, p.NameAlg)
	}
	if len(p.AuthPolicy) > maxTPMAuthPolicySize {
		return errs.Detail(ErrTPMStructure, "TPM authPolicy is %d bytes, limit %d | TPM authPolicy 为 %d 字节，上限 %d",
			len(p.AuthPolicy), maxTPMAuthPolicySize, len(p.AuthPolicy), maxTPMAuthPolicySize)
	}
	switch p.Type {
	case TPMAlgRSA:
		return p.validateRSA()
	case TPMAlgECC:
		return p.validateECC()
	default:
		return errs.Detail(ErrUnsupportedKey, "unsupported TPM public key type %#04x | 不支持的 TPM 公钥类型 %#04x", p.Type, p.Type)
	}
}

// validateRSA checks an RSA public area. | validateRSA 校验 RSA 公钥区域。
func (p *TPMTPublic) validateRSA() error {
	if p.KeyBits < 1024 || p.KeyBits > maxTPMRSAKeyBytes*8 || p.KeyBits%8 != 0 {
		return errs.Detail(ErrTPMStructure, "RSA key size %d is outside 1024..%d bits | RSA 密钥位数 %d 超出 1024..%d 位",
			p.KeyBits, maxTPMRSAKeyBytes*8, p.KeyBits, maxTPMRSAKeyBytes*8)
	}
	modulusBytes := int(p.KeyBits / 8)
	if len(p.RSAModulus) != modulusBytes {
		return errs.Detail(ErrTPMStructure, "RSA modulus is %d bytes, key size %d needs %d | RSA 模数为 %d 字节，密钥位数 %d 需要 %d",
			len(p.RSAModulus), p.KeyBits, modulusBytes, len(p.RSAModulus), p.KeyBits, modulusBytes)
	}
	modulus := new(big.Int).SetBytes(p.RSAModulus)
	if modulus.Sign() == 0 || modulus.Bit(0) == 0 || modulus.BitLen() != int(p.KeyBits) {
		return errs.Detail(ErrTPMStructure, "RSA modulus is not a valid %d-bit odd integer | RSA 模数不是合法的 %d 位奇数",
			p.KeyBits, p.KeyBits)
	}
	if p.Exponent != 0 && p.Exponent != tpmDefaultExponent {
		return errs.Detail(ErrTPMStructure, "RSA exponent %d is not supported | 不支持 RSA 指数 %d", p.Exponent, p.Exponent)
	}
	if err := p.Symmetric.validate(); err != nil {
		return err
	}
	_, err := p.RSAScheme.Marshal()
	return err
}

// validateECC checks an ECC public area. | validateECC 校验 ECC 公钥区域。
func (p *TPMTPublic) validateECC() error {
	curve, err := tpmECCCurve(p.CurveID)
	if err != nil {
		return err
	}
	if err := p.ECCPoint.validate(curve); err != nil {
		return err
	}
	if err := p.Symmetric.validate(); err != nil {
		return err
	}
	if _, err := p.ECCScheme.Marshal(); err != nil {
		return err
	}
	_, err = p.KDF.Marshal()
	return err
}

// validate checks that the point is on the named curve. | validate 校验点位于指定曲线上。
func (p TPMSEccPoint) validate(curve elliptic.Curve) error {
	if len(p.X) > maxTPMECCParameterSize || len(p.Y) > maxTPMECCParameterSize {
		return errs.Detail(ErrTPMStructure, "ECC coordinate is too large | ECC 坐标过大")
	}
	x := new(big.Int).SetBytes(p.X)
	y := new(big.Int).SetBytes(p.Y)
	if !curve.IsOnCurve(x, y) {
		return errs.Detail(ErrTPMStructure, "ECC point is not on the TPM curve | ECC 点不在 TPM 曲线上")
	}
	return nil
}

// tpmECCCurve maps a TPM curve identifier to elliptic.Curve. | tpmECCCurve 把 TPM 曲线标识映射为 elliptic.Curve。
func tpmECCCurve(id uint16) (elliptic.Curve, error) {
	switch id {
	case TPMEccNISTP256:
		return elliptic.P256(), nil
	case TPMEccNISTP384:
		return elliptic.P384(), nil
	case TPMEccNISTP521:
		return elliptic.P521(), nil
	default:
		return nil, errs.Detail(ErrUnsupportedKey, "unsupported TPM ECC curve %#04x | 不支持的 TPM ECC 曲线 %#04x", id, id)
	}
}

// tpmECCFieldSize returns the coordinate size of a TPM curve in bytes. | tpmECCFieldSize 返回 TPM 曲线的
// 坐标字节数。
func tpmECCFieldSize(id uint16) (int, error) {
	switch id {
	case TPMEccNISTP256:
		return 32, nil
	case TPMEccNISTP384:
		return 48, nil
	case TPMEccNISTP521:
		return 66, nil
	default:
		return 0, errs.Detail(ErrUnsupportedKey, "unsupported TPM ECC curve %#04x | 不支持的 TPM ECC 曲线 %#04x", id, id)
	}
}

// PublicKey returns the public key described by the area. | PublicKey 返回公钥区域描述的公钥。
func (p *TPMTPublic) PublicKey() (crypto.PublicKey, error) {
	if p == nil {
		return nil, errs.Detail(ErrTPMStructure, "nil TPM public area | TPM 公钥区域为空")
	}
	if err := p.Validate(); err != nil {
		return nil, err
	}
	switch p.Type {
	case TPMAlgRSA:
		exponent := int(p.Exponent)
		if exponent == 0 {
			exponent = tpmDefaultExponent
		}
		modulus := new(big.Int).SetBytes(p.RSAModulus)
		return &rsa.PublicKey{N: modulus, E: exponent}, nil
	case TPMAlgECC:
		curve, err := tpmECCCurve(p.CurveID)
		if err != nil {
			return nil, err
		}
		x := new(big.Int).SetBytes(p.ECCPoint.X)
		y := new(big.Int).SetBytes(p.ECCPoint.Y)
		return &ecdsa.PublicKey{Curve: curve, X: x, Y: y}, nil
	default:
		return nil, errs.Detail(ErrUnsupportedKey, "unsupported TPM public key type %#04x | 不支持的 TPM 公钥类型 %#04x", p.Type, p.Type)
	}
}

// IsRestrictedDecrypt reports whether the object has both the restricted and decrypt attributes. |
// IsRestrictedDecrypt 报告对象是否同时具有 restricted 与 decrypt 属性。
func (p *TPMTPublic) IsRestrictedDecrypt() bool {
	if p == nil {
		return false
	}
	const required = TPMARestricted | TPMADecrypt
	return p.ObjectAttributes&required == required
}

// StorageSymmetric returns the effective AES key bits and mode used for credential protection. |
// StorageSymmetric 返回凭据保护实际使用的 AES 密钥位数与模式。
//
// A TPM_ALG_NULL symmetric definition is treated as AES-128-CFB, as required by TPM 2.0 Part 3 for
// TPM2_MakeCredential. Only AES with CFB mode is accepted because that is the only mode the
// credential-activation protocol defines. | TPM_ALG_NULL 对称定义按 TPM 2.0 第三部分对
// TPM2_MakeCredential 的要求视为 AES-128-CFB。只接受 CFB 模式的 AES，因为凭据激活协议仅定义该模式。
func (p *TPMTPublic) StorageSymmetric() (int, error) {
	if p == nil {
		return 0, errs.Detail(ErrTPMStructure, "nil TPM public area | TPM 公钥区域为空")
	}
	symmetric := p.Symmetric
	if symmetric.isNull() {
		return 128, nil
	}
	if symmetric.Algorithm != TPMAlgAES {
		return 0, errs.Detail(ErrTPMStructure, "endorsement key storage algorithm %#04x is not AES | 背书密钥存储算法 %#04x 不是 AES",
			symmetric.Algorithm, symmetric.Algorithm)
	}
	if symmetric.KeyBits != 128 && symmetric.KeyBits != 192 && symmetric.KeyBits != 256 {
		return 0, errs.Detail(ErrTPMStructure, "endorsement key AES size %d is not 128, 192 or 256 | 背书密钥 AES 位数 %d 不是 128、192 或 256",
			symmetric.KeyBits, symmetric.KeyBits)
	}
	if symmetric.Mode != TPMAlgCFB {
		return 0, errs.Detail(ErrTPMStructure, "endorsement key storage mode %#04x is not CFB | 背书密钥存储模式 %#04x 不是 CFB",
			symmetric.Mode, symmetric.Mode)
	}
	return int(symmetric.KeyBits), nil
}

// TPM2BPublic is a TPM2B_PUBLIC. | TPM2BPublic 是 TPM2B_PUBLIC。
type TPM2BPublic struct {
	// Public is the parsed public area. | Public 是已解析公钥区域。
	Public TPMTPublic
	// Raw is the exact TPMT_PUBLIC bytes as received; nil means Marshal computes them. | Raw 是收到的
	// 精确 TPMT_PUBLIC 字节；nil 表示由 Marshal 计算。
	Raw []byte
}

// PublicArea returns the exact TPMT_PUBLIC bytes, preferring the original input. | PublicArea 返回
// 精确的 TPMT_PUBLIC 字节，优先使用原始输入。
func (b TPM2BPublic) PublicArea() ([]byte, error) {
	if len(b.Raw) > 0 {
		return append([]byte(nil), b.Raw...), nil
	}
	return b.Public.Marshal()
}

// Marshal returns the TPM2B_PUBLIC encoding. | Marshal 返回 TPM2B_PUBLIC 编码。
func (b TPM2BPublic) Marshal() ([]byte, error) {
	area, err := b.PublicArea()
	if err != nil {
		return nil, err
	}
	return tpm2AppendSized(nil, area)
}

// Name computes the Name of the exact public area bytes. | Name 计算精确公钥区域字节的 Name。
func (b TPM2BPublic) Name() ([]byte, error) {
	area, err := b.PublicArea()
	if err != nil {
		return nil, err
	}
	return b.Public.Name(area)
}

// ParseTPM2BPublic decodes a TPM2B_PUBLIC and returns it with the number of bytes consumed. |
// ParseTPM2BPublic 解码 TPM2B_PUBLIC，并返回它及消费的字节数。
func ParseTPM2BPublic(data []byte) (TPM2BPublic, int, error) {
	r := &tpm2Reader{data: data}
	area, err := r.sized(MaxTPM2BUFFERSize)
	if err != nil {
		return TPM2BPublic{}, 0, err
	}
	public, err := ParseTPMTPublic(area)
	if err != nil {
		return TPM2BPublic{}, 0, err
	}
	return TPM2BPublic{Public: *public, Raw: append([]byte(nil), area...)}, r.off, nil
}

// TPMTSensitive is a TPMT_SENSITIVE. | TPMTSensitive 是 TPMT_SENSITIVE。
type TPMTSensitive struct {
	// Type is the TPM_ALG_KEYEDHASH, TPM_ALG_RSA, TPM_ALG_ECC or TPM_ALG_SYMCIPHER type. | Type 是
	// TPM_ALG_KEYEDHASH、TPM_ALG_RSA、TPM_ALG_ECC 或 TPM_ALG_SYMCIPHER 类型。
	Type uint16
	// AuthValue is the TPM2B_AUTH value. | AuthValue 是 TPM2B_AUTH 值。
	AuthValue []byte
	// SeedValue is the TPM2B_DIGEST seed value. | SeedValue 是 TPM2B_DIGEST 种子值。
	SeedValue []byte
	// Sensitive is the type-specific sensitive composite. | Sensitive 是类型相关的敏感复合值。
	Sensitive []byte
}

// ParseTPMTSensitive decodes exactly one raw TPMT_SENSITIVE area. | ParseTPMTSensitive 解码恰好一个
// 原始 TPMT_SENSITIVE 区域。
func ParseTPMTSensitive(data []byte) (*TPMTSensitive, error) {
	if len(data) == 0 {
		return nil, errs.Detail(ErrTPMStructure, "empty TPM sensitive area | TPM 敏感区域为空")
	}
	r := &tpm2Reader{data: data}
	sensitiveType, err := r.u16()
	if err != nil {
		return nil, err
	}
	authValue, err := r.sized(MaxTPM2BUFFERSize)
	if err != nil {
		return nil, err
	}
	seedValue, err := r.sized(maxTPMAuthPolicySize)
	if err != nil {
		return nil, err
	}
	composite, err := r.sized(maxTPMSensitiveSize)
	if err != nil {
		return nil, err
	}
	if (sensitiveType == TPMAlgRSA || sensitiveType == TPMAlgECC || sensitiveType == TPMAlgSymCipher ||
		sensitiveType == TPMAlgKeyedHash) && len(composite) == 0 {
		return nil, errs.Detail(ErrTPMStructure, "TPM sensitive composite is empty | TPM 敏感复合值为空")
	}
	sensitive := &TPMTSensitive{
		Type:      sensitiveType,
		AuthValue: append([]byte(nil), authValue...),
		SeedValue: append([]byte(nil), seedValue...),
		Sensitive: append([]byte(nil), composite...),
	}
	if !r.done() {
		return nil, errs.Detail(ErrTPMStructure, "TPM sensitive area has %d trailing bytes | TPM 敏感区域有 %d 个多余字节",
			r.remaining(), r.remaining())
	}
	return sensitive, nil
}

// Marshal returns the raw TPMT_SENSITIVE encoding. | Marshal 返回原始 TPMT_SENSITIVE 编码。
func (s *TPMTSensitive) Marshal() ([]byte, error) {
	if s == nil {
		return nil, errs.Detail(ErrTPMStructure, "nil TPM sensitive area | TPM 敏感区域为空")
	}
	switch s.Type {
	case TPMAlgRSA, TPMAlgECC, TPMAlgSymCipher, TPMAlgKeyedHash:
	default:
		return nil, errs.Detail(ErrUnsupportedKey, "unsupported TPM sensitive type %#04x | 不支持的 TPM 敏感类型 %#04x", s.Type, s.Type)
	}
	if len(s.Sensitive) == 0 {
		return nil, errs.Detail(ErrTPMStructure, "TPM sensitive composite is empty | TPM 敏感复合值为空")
	}
	out := tpm2AppendU16(nil, s.Type)
	var err error
	out, err = tpm2AppendSized(out, s.AuthValue)
	if err != nil {
		return nil, err
	}
	out, err = tpm2AppendSized(out, s.SeedValue)
	if err != nil {
		return nil, err
	}
	return tpm2AppendSized(out, s.Sensitive)
}

// TPM2BSensitive is a TPM2B_SENSITIVE. | TPM2BSensitive 是 TPM2B_SENSITIVE。
type TPM2BSensitive struct {
	// Sensitive is the parsed sensitive area. | Sensitive 是已解析敏感区域。
	Sensitive TPMTSensitive
}

// Marshal returns the TPM2B_SENSITIVE encoding. | Marshal 返回 TPM2B_SENSITIVE 编码。
func (b TPM2BSensitive) Marshal() ([]byte, error) {
	area, err := b.Sensitive.Marshal()
	if err != nil {
		return nil, err
	}
	return tpm2AppendSized(nil, area)
}

// ParseTPM2BSensitive decodes a TPM2B_SENSITIVE and returns it with the number of bytes consumed. |
// ParseTPM2BSensitive 解码 TPM2B_SENSITIVE，并返回它及消费的字节数。
func ParseTPM2BSensitive(data []byte) (TPM2BSensitive, int, error) {
	r := &tpm2Reader{data: data}
	area, err := r.sized(MaxTPM2BUFFERSize)
	if err != nil {
		return TPM2BSensitive{}, 0, err
	}
	sensitive, err := ParseTPMTSensitive(area)
	if err != nil {
		return TPM2BSensitive{}, 0, err
	}
	return TPM2BSensitive{Sensitive: *sensitive}, r.off, nil
}

// TPMSPCRSelection is a TPMS_PCR_SELECTION. | TPMSPCRSelection 是 TPMS_PCR_SELECTION。
type TPMSPCRSelection struct {
	// Hash is the PCR bank hash algorithm. | Hash 是 PCR bank 哈希算法。
	Hash uint16
	// Select is the PCR bitmap; its length is sizeofSelect. | Select 是 PCR 位图；其长度即 sizeofSelect。
	Select []byte
}

// TPMLPCRSelection is a TPML_PCR_SELECTION. | TPMLPCRSelection 是 TPML_PCR_SELECTION。
type TPMLPCRSelection struct {
	// Selections are the per-bank PCR selections. | Selections 是各 bank 的 PCR 选择。
	Selections []TPMSPCRSelection
}

// Marshal returns the TPML_PCR_SELECTION encoding. | Marshal 返回 TPML_PCR_SELECTION 编码。
func (l TPMLPCRSelection) Marshal() ([]byte, error) {
	if len(l.Selections) > maxTPMSchemeCount {
		return nil, errs.Detail(ErrTPMStructure, "PCR selection count %d exceeds %d | PCR 选择数 %d 超过 %d",
			len(l.Selections), maxTPMSchemeCount, len(l.Selections), maxTPMSchemeCount)
	}
	out := tpm2AppendU32(nil, uint32(len(l.Selections)))
	for index, selection := range l.Selections {
		if _, ok := TPMHash(selection.Hash); !ok {
			return nil, errs.Detail(ErrUnsupportedAlgorithm, "PCR selection %d hash %#04x is unsupported | PCR 选择 %d 哈希 %#04x 不受支持",
				index, selection.Hash, index, selection.Hash)
		}
		if len(selection.Select) > maxTPMPCRSelectSize {
			return nil, errs.Detail(ErrTPMStructure, "PCR selection %d bitmap is %d bytes, limit %d | PCR 选择 %d 位图为 %d 字节，上限 %d",
				index, len(selection.Select), maxTPMPCRSelectSize, index, len(selection.Select), maxTPMPCRSelectSize)
		}
		out = tpm2AppendU16(out, selection.Hash)
		out = append(out, byte(len(selection.Select)))
		out = append(out, selection.Select...)
	}
	return out, nil
}

// ParseTPMLPCRSelection decodes a TPML_PCR_SELECTION and returns it with the number of bytes consumed. |
// ParseTPMLPCRSelection 解码 TPML_PCR_SELECTION，并返回它及消费的字节数。
func ParseTPMLPCRSelection(data []byte) (TPMLPCRSelection, int, error) {
	r := &tpm2Reader{data: data}
	count, err := r.u32()
	if err != nil {
		return TPMLPCRSelection{}, 0, err
	}
	if count > maxTPMSchemeCount {
		return TPMLPCRSelection{}, 0, errs.Detail(ErrTPMStructure, "PCR selection count %d exceeds %d | PCR 选择数 %d 超过 %d",
			count, maxTPMSchemeCount, count, maxTPMSchemeCount)
	}
	list := TPMLPCRSelection{Selections: make([]TPMSPCRSelection, 0, count)}
	for index := uint32(0); index < count; index++ {
		hash, err := r.u16()
		if err != nil {
			return TPMLPCRSelection{}, 0, err
		}
		if _, ok := TPMHash(hash); !ok {
			return TPMLPCRSelection{}, 0, errs.Detail(ErrUnsupportedAlgorithm, "PCR selection %d hash %#04x is unsupported | PCR 选择 %d 哈希 %#04x 不受支持",
				index, hash, index, hash)
		}
		size, err := r.u8()
		if err != nil {
			return TPMLPCRSelection{}, 0, err
		}
		if int(size) > maxTPMPCRSelectSize {
			return TPMLPCRSelection{}, 0, errs.Detail(ErrTPMStructure, "PCR selection %d bitmap is %d bytes, limit %d | PCR 选择 %d 位图为 %d 字节，上限 %d",
				index, size, maxTPMPCRSelectSize, index, size, maxTPMPCRSelectSize)
		}
		bitmap, err := r.bytes(int(size))
		if err != nil {
			return TPMLPCRSelection{}, 0, err
		}
		list.Selections = append(list.Selections, TPMSPCRSelection{
			Hash:   hash,
			Select: append([]byte(nil), bitmap...),
		})
	}
	return list, r.off, nil
}

// TPMTTicket is one of the TPMT_TK_CREATION, TPMT_TK_VERIFIED, TPMT_TK_AUTH or TPMT_TK_HASHCHECK
// structures. | TPMTTicket 是 TPMT_TK_CREATION、TPMT_TK_VERIFIED、TPMT_TK_AUTH 或 TPMT_TK_HASHCHECK
// 之一。
type TPMTTicket struct {
	// Tag is the ticket tag. | Tag 是票据标签。
	Tag uint16
	// Hierarchy is the hierarchy that produced the ticket. | Hierarchy 是产生票据的层级。
	Hierarchy uint32
	// Digest is the ticket digest. | Digest 是票据摘要。
	Digest []byte
}

// ParseTPMTTicket decodes a TPMT_TK_* structure and returns it with the number of bytes consumed. |
// ParseTPMTTicket 解码 TPMT_TK_* 结构，并返回它及消费的字节数。
func ParseTPMTTicket(data []byte) (TPMTTicket, int, error) {
	r := &tpm2Reader{data: data}
	tag, err := r.u16()
	if err != nil {
		return TPMTTicket{}, 0, err
	}
	switch tag {
	case TPMSTCreation, TPMSTVerified, TPMSTAuthSecret, TPMSTHashcheck:
	default:
		return TPMTTicket{}, 0, errs.Detail(ErrTPMStructure, "unknown ticket tag %#04x | 未知票据标签 %#04x", tag, tag)
	}
	hierarchy, err := r.u32()
	if err != nil {
		return TPMTTicket{}, 0, err
	}
	digest, err := r.sized(maxTPMTicketDigestSize)
	if err != nil {
		return TPMTTicket{}, 0, err
	}
	return TPMTTicket{
		Tag:       tag,
		Hierarchy: hierarchy,
		Digest:    append([]byte(nil), digest...),
	}, r.off, nil
}

// Marshal returns the TPMT_TK_* encoding. | Marshal 返回 TPMT_TK_* 编码。
func (t TPMTTicket) Marshal() ([]byte, error) {
	switch t.Tag {
	case TPMSTCreation, TPMSTVerified, TPMSTAuthSecret, TPMSTHashcheck:
	default:
		return nil, errs.Detail(ErrTPMStructure, "unknown ticket tag %#04x | 未知票据标签 %#04x", t.Tag, t.Tag)
	}
	if len(t.Digest) > maxTPMTicketDigestSize {
		return nil, errs.Detail(ErrTPMStructure, "ticket digest is %d bytes, limit %d | 票据摘要为 %d 字节，上限 %d",
			len(t.Digest), maxTPMTicketDigestSize, len(t.Digest), maxTPMTicketDigestSize)
	}
	out := tpm2AppendU16(nil, t.Tag)
	out = tpm2AppendU32(out, t.Hierarchy)
	return tpm2AppendSized(out, t.Digest)
}

// TPMSAuthCommand is a TPMS_AUTH_COMMAND authorization area entry. | TPMSAuthCommand 是
// TPMS_AUTH_COMMAND 授权区条目。
type TPMSAuthCommand struct {
	// SessionHandle is the authorized session or TPM_RS_PW. | SessionHandle 是授权会话或 TPM_RS_PW。
	SessionHandle uint32
	// Nonce is the session nonce. | Nonce 是会话随机数。
	Nonce []byte
	// SessionAttributes is the session attribute byte. | SessionAttributes 是会话属性字节。
	SessionAttributes uint8
	// HMAC is the password authorization or session HMAC. | HMAC 是密码授权或会话 HMAC。
	HMAC []byte
}

// Marshal returns the TPMS_AUTH_COMMAND encoding. | Marshal 返回 TPMS_AUTH_COMMAND 编码。
func (a TPMSAuthCommand) Marshal() ([]byte, error) {
	out := tpm2AppendU32(nil, a.SessionHandle)
	var err error
	out, err = tpm2AppendSized(out, a.Nonce)
	if err != nil {
		return nil, err
	}
	out = append(out, a.SessionAttributes)
	return tpm2AppendSized(out, a.HMAC)
}

// ParseTPMSAuthCommand decodes a TPMS_AUTH_COMMAND and returns it with the number of bytes consumed. |
// ParseTPMSAuthCommand 解码 TPMS_AUTH_COMMAND，并返回它及消费的字节数。
func ParseTPMSAuthCommand(data []byte) (TPMSAuthCommand, int, error) {
	r := &tpm2Reader{data: data}
	handle, err := r.u32()
	if err != nil {
		return TPMSAuthCommand{}, 0, err
	}
	nonce, err := r.sized(64)
	if err != nil {
		return TPMSAuthCommand{}, 0, err
	}
	attributes, err := r.u8()
	if err != nil {
		return TPMSAuthCommand{}, 0, err
	}
	hmacValue, err := r.sized(64)
	if err != nil {
		return TPMSAuthCommand{}, 0, err
	}
	return TPMSAuthCommand{
		SessionHandle:     handle,
		Nonce:             append([]byte(nil), nonce...),
		SessionAttributes: attributes,
		HMAC:              append([]byte(nil), hmacValue...),
	}, r.off, nil
}

// TPMSAuthResponse is a TPMS_AUTH_RESPONSE authorization area entry. | TPMSAuthResponse 是
// TPMS_AUTH_RESPONSE 授权区条目。
type TPMSAuthResponse struct {
	// Nonce is the session nonce. | Nonce 是会话随机数。
	Nonce []byte
	// SessionAttributes is the session attribute byte. | SessionAttributes 是会话属性字节。
	SessionAttributes uint8
	// HMAC is the response HMAC. | HMAC 是响应 HMAC。
	HMAC []byte
}

// ParseTPMSAuthResponse decodes a TPMS_AUTH_RESPONSE and returns it with the number of bytes consumed. |
// ParseTPMSAuthResponse 解码 TPMS_AUTH_RESPONSE，并返回它及消费的字节数。
func ParseTPMSAuthResponse(data []byte) (TPMSAuthResponse, int, error) {
	r := &tpm2Reader{data: data}
	nonce, err := r.sized(64)
	if err != nil {
		return TPMSAuthResponse{}, 0, err
	}
	attributes, err := r.u8()
	if err != nil {
		return TPMSAuthResponse{}, 0, err
	}
	hmacValue, err := r.sized(64)
	if err != nil {
		return TPMSAuthResponse{}, 0, err
	}
	return TPMSAuthResponse{
		Nonce:             append([]byte(nil), nonce...),
		SessionAttributes: attributes,
		HMAC:              append([]byte(nil), hmacValue...),
	}, r.off, nil
}

// Marshal returns the TPMS_AUTH_RESPONSE encoding. | Marshal 返回 TPMS_AUTH_RESPONSE 编码。
func (a TPMSAuthResponse) Marshal() ([]byte, error) {
	var err error
	out, err := tpm2AppendSized(nil, a.Nonce)
	if err != nil {
		return nil, err
	}
	out = append(out, a.SessionAttributes)
	return tpm2AppendSized(out, a.HMAC)
}

// TPMSAttest is a TPMS_ATTEST structure with a TPMS_CERTIFY_INFO attested union. | TPMSAttest 是带
// TPMS_CERTIFY_INFO 认证联合的 TPMS_ATTEST 结构。
type TPMSAttest struct {
	// Magic is TPM_GENERATED_VALUE. | Magic 是 TPM_GENERATED_VALUE。
	Magic uint32
	// Type is the attestation type. | Type 是认证类型。
	Type uint16
	// QualifiedSigner is the qualified name of the signing key. | QualifiedSigner 是签名密钥的限定名。
	QualifiedSigner []byte
	// ExtraData is the caller-provided extra data. | ExtraData 是调用方提供的附加数据。
	ExtraData []byte
	// ClockInfo is the TPM clock information. | ClockInfo 是 TPM 时钟信息。
	ClockInfo TPMSClockInfo
	// FirmwareVersion is the TPM firmware version. | FirmwareVersion 是 TPM 固件版本。
	FirmwareVersion uint64
	// Name is the certified object Name from TPMS_CERTIFY_INFO. | Name 是 TPMS_CERTIFY_INFO 中受认证
	// 对象的 Name。
	Name []byte
	// QualifiedName is the qualified Name from TPMS_CERTIFY_INFO. | QualifiedName 是
	// TPMS_CERTIFY_INFO 中的限定 Name。
	QualifiedName []byte
}

// Marshal returns the TPMS_ATTEST encoding for a TPM_ST_ATTEST_CERTIFY value. | Marshal 返回
// TPM_ST_ATTEST_CERTIFY 值的 TPMS_ATTEST 编码。
func (a TPMSAttest) Marshal() ([]byte, error) {
	if a.Magic != TPMGeneratedValue {
		return nil, errs.Detail(ErrTPMStructure, "attestation magic %#08x is not TPM_GENERATED_VALUE | 认证魔术数 %#08x 不是 TPM_GENERATED_VALUE",
			a.Magic, a.Magic)
	}
	if a.Type != TPMStAttestCertify {
		return nil, errs.Detail(ErrTPMStructure, "attestation type %#04x is not TPM_ST_ATTEST_CERTIFY | 认证类型 %#04x 不是 TPM_ST_ATTEST_CERTIFY",
			a.Type, a.Type)
	}
	out := make([]byte, 0, 128)
	out = tpm2AppendU32(out, a.Magic)
	out = tpm2AppendU16(out, a.Type)
	var err error
	out, err = tpm2AppendSized(out, a.QualifiedSigner)
	if err != nil {
		return nil, err
	}
	out, err = tpm2AppendSized(out, a.ExtraData)
	if err != nil {
		return nil, err
	}
	out = tpm2AppendU64(out, a.ClockInfo.Clock)
	out = tpm2AppendU32(out, a.ClockInfo.ResetCount)
	out = tpm2AppendU32(out, a.ClockInfo.RestartCount)
	out = append(out, a.ClockInfo.Safe)
	out = tpm2AppendU64(out, a.FirmwareVersion)
	out, err = tpm2AppendSized(out, a.Name)
	if err != nil {
		return nil, err
	}
	return tpm2AppendSized(out, a.QualifiedName)
}

// ParseTPMSAttest decodes exactly one TPMS_ATTEST with a TPMS_CERTIFY_INFO union. |
// ParseTPMSAttest 解码恰好一个带 TPMS_CERTIFY_INFO 联合的 TPMS_ATTEST。
//
// The subsystem only produces and consumes certify attestations, so other union variants are
// reported as unsupported instead of being guessed. | 本子系统只生成与消费 certify 认证，因此其他联合
// 变体会被报告为不支持，而不会被猜测解析。
func ParseTPMSAttest(data []byte) (*TPMSAttest, error) {
	if len(data) == 0 {
		return nil, errs.Detail(ErrTPMStructure, "empty TPMS_ATTEST | TPMS_ATTEST 为空")
	}
	r := &tpm2Reader{data: data}
	magic, err := r.u32()
	if err != nil {
		return nil, err
	}
	if magic != TPMGeneratedValue {
		return nil, errs.Detail(ErrTPMStructure, "attestation magic %#08x is not TPM_GENERATED_VALUE | 认证魔术数 %#08x 不是 TPM_GENERATED_VALUE",
			magic, magic)
	}
	attestType, err := r.u16()
	if err != nil {
		return nil, err
	}
	if attestType != TPMStAttestCertify {
		return nil, errs.Detail(ErrUnsupportedAttestation, "attestation type %#04x has no certify union | 认证类型 %#04x 不含 certify 联合",
			attestType, attestType)
	}
	signer, err := r.sized(maxTPMNameSize)
	if err != nil {
		return nil, err
	}
	extraData, err := r.sized(64)
	if err != nil {
		return nil, err
	}
	clock, err := r.u64()
	if err != nil {
		return nil, err
	}
	resetCount, err := r.u32()
	if err != nil {
		return nil, err
	}
	restartCount, err := r.u32()
	if err != nil {
		return nil, err
	}
	safe, err := r.u8()
	if err != nil {
		return nil, err
	}
	if safe > 1 {
		return nil, errs.Detail(ErrTPMStructure, "attestation clock safe byte is %d | 认证时钟 safe 字节为 %d", safe, safe)
	}
	firmware, err := r.u64()
	if err != nil {
		return nil, err
	}
	name, err := r.sized(maxTPMNameSize)
	if err != nil {
		return nil, err
	}
	qualifiedName, err := r.sized(maxTPMNameSize)
	if err != nil {
		return nil, err
	}
	if !r.done() {
		return nil, errs.Detail(ErrTPMStructure, "TPMS_ATTEST has %d trailing bytes | TPMS_ATTEST 有 %d 个多余字节",
			r.remaining(), r.remaining())
	}
	attest := &TPMSAttest{
		Magic:           magic,
		Type:            attestType,
		QualifiedSigner: append([]byte(nil), signer...),
		ExtraData:       append([]byte(nil), extraData...),
		ClockInfo: TPMSClockInfo{
			Clock:        clock,
			ResetCount:   resetCount,
			RestartCount: restartCount,
			Safe:         safe,
		},
		FirmwareVersion: firmware,
		Name:            append([]byte(nil), name...),
		QualifiedName:   append([]byte(nil), qualifiedName...),
	}
	if len(attest.Name) > 0 {
		if err := (TPM2BName{Name: attest.Name}).Validate(); err != nil {
			return nil, err
		}
	}
	return attest, nil
}
