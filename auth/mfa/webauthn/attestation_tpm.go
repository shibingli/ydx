package webauthn

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"math/big"

	"github.com/shibingli/ydx/errs"
)

// TPM constants used by the tpm attestation format. | tpm 认证声明格式使用的 TPM 常量。
const (
	tpmGeneratedMagic  = 0xff544347
	tpmStAttestCertify = 0x8017

	tpmAlgRSA    = 0x0001
	tpmAlgSHA256 = 0x000B
	tpmAlgSHA384 = 0x000C
	tpmAlgSHA512 = 0x000D
	tpmAlgNULL   = 0x0010
	tpmAlgRSASSA = 0x0014
	tpmAlgRSAPSS = 0x0016
	tpmAlgECDSA  = 0x0018
	tpmAlgECC    = 0x0023

	tpmEccNISTP256 = 0x0003
	tpmEccNISTP384 = 0x0004
	tpmEccNISTP521 = 0x0005

	tpmDefaultExponent = 65537
)

// TPM attestation certificate profile OIDs. | TPM 认证证书配置 OID。
var (
	tpmManufacturerOID = asn1.ObjectIdentifier{2, 23, 133, 2, 1}
	tpmModelOID        = asn1.ObjectIdentifier{2, 23, 133, 2, 2}
	tpmVersionOID      = asn1.ObjectIdentifier{2, 23, 133, 2, 3}
	tcgKpAIKCertOID    = asn1.ObjectIdentifier{2, 23, 133, 8, 3}
	subjectAltNameOID  = asn1.ObjectIdentifier{2, 5, 29, 17}
)

// tpmPublicArea is the parsed subset of a TPMT_PUBLIC structure. | tpmPublicArea 是 TPMT_PUBLIC 结构解析后的子集。
type tpmPublicArea struct {
	keyType   uint16
	nameAlg   uint16
	publicKey crypto.PublicKey
}

// tpmAttest is the parsed subset of a TPMS_ATTEST structure. | tpmAttest 是 TPMS_ATTEST 结构解析后的子集。
type tpmAttest struct {
	extraData []byte
	name      []byte
}

// tpmReader reads big-endian TPM structures without panicking on malformed input. | tpmReader 读取大端 TPM 结构，且不会因非法输入而 panic。
type tpmReader struct {
	data []byte
	off  int
}

func (r *tpmReader) remaining() int { return len(r.data) - r.off }

func (r *tpmReader) readN(n int) ([]byte, error) {
	if n < 0 || n > r.remaining() {
		return nil, errs.Detail(ErrInvalidAttestation, "TPM structure is truncated | TPM 结构被截断")
	}
	out := r.data[r.off : r.off+n]
	r.off += n
	return out, nil
}

func (r *tpmReader) u8() (uint8, error) {
	b, err := r.readN(1)
	if err != nil {
		return 0, err
	}
	return b[0], nil
}

func (r *tpmReader) u16() (uint16, error) {
	b, err := r.readN(2)
	if err != nil {
		return 0, err
	}
	return uint16(b[0])<<8 | uint16(b[1]), nil
}

func (r *tpmReader) u32() (uint32, error) {
	b, err := r.readN(4)
	if err != nil {
		return 0, err
	}
	return uint32(b[0])<<24 | uint32(b[1])<<16 | uint32(b[2])<<8 | uint32(b[3]), nil
}

func (r *tpmReader) u64() (uint64, error) {
	b, err := r.readN(8)
	if err != nil {
		return 0, err
	}
	var v uint64
	for _, x := range b {
		v = v<<8 | uint64(x)
	}
	return v, nil
}

func (r *tpmReader) sized() ([]byte, error) {
	n, err := r.u16()
	if err != nil {
		return nil, err
	}
	return r.readN(int(n))
}

func (r *tpmReader) skip(n int) error {
	_, err := r.readN(n)
	return err
}

func (r *tpmReader) done() bool { return r.off == len(r.data) }

// verifyTPM implements the tpm attestation format. | verifyTPM 实现 tpm 认证声明格式。
func (o *AttestationObject) verifyTPM(result *AttestationResult, clientDataHash []byte, opts AttestationOptions) error {
	version, err := attestationStatementText(o.AttStmt, "ver")
	if err != nil {
		return err
	}
	if version != "2.0" {
		return errs.Detail(ErrUnsupportedAttestation, "tpm attestation version %q | tpm 认证声明版本 %q", version, version)
	}
	alg, err := attestationStatementInt(o.AttStmt, "alg")
	if err != nil {
		return err
	}
	hash, ok := HashForAlgorithm(alg)
	if !ok || hash == 0 {
		return errs.Detail(ErrUnsupportedAlgorithm, "tpm attestation algorithm %d | tpm 认证声明算法 %d", alg, alg)
	}
	signature, err := attestationStatementBytes(o.AttStmt, "sig")
	if err != nil {
		return err
	}
	certInfoRaw, err := attestationStatementBytes(o.AttStmt, "certInfo")
	if err != nil {
		return err
	}
	pubAreaRaw, err := attestationStatementBytes(o.AttStmt, "pubArea")
	if err != nil {
		return err
	}
	x5c, present, err := attestationStatementX5C(o.AttStmt)
	if err != nil {
		return err
	}
	if !present {
		return errs.Detail(ErrInvalidAttestation, "tpm attestation lacks x5c | tpm 认证声明缺少 x5c")
	}
	certs, err := parseX5C(x5c)
	if err != nil {
		return err
	}
	leaf := certs[0]
	if err := verifyTPMCertificate(leaf); err != nil {
		return err
	}
	pubArea, err := parseTPMPublicArea(pubAreaRaw)
	if err != nil {
		return err
	}
	credentialKey, err := attestationCredentialPublicKey(o.AuthData)
	if err != nil {
		return err
	}
	credentialPublicKey, err := credentialKey.PublicKey()
	if err != nil {
		return err
	}
	if !samePublicKey(pubArea.publicKey, credentialPublicKey) {
		return errs.Detail(ErrInvalidAttestation, "tpm pubArea key differs from the credential key | tpm pubArea 密钥与凭据密钥不一致")
	}
	attest, err := parseTPMSAttest(certInfoRaw)
	if err != nil {
		return err
	}
	hasher := hash.New()
	_, _ = hasher.Write(o.AuthDataRaw)
	_, _ = hasher.Write(clientDataHash)
	expectedExtraData := hasher.Sum(nil)
	if !constantTimeEqual(attest.extraData, expectedExtraData) {
		return errs.Detail(ErrInvalidAttestation, "tpm certInfo extraData does not cover authData || clientDataHash | tpm certInfo extraData 未覆盖 authData || clientDataHash")
	}
	if err := verifyTPMPubAreaName(pubArea, pubAreaRaw, attest.name); err != nil {
		return err
	}
	tpmSignature, err := parseTPMSignature(signature)
	if err != nil {
		return err
	}
	if !tpmSignatureMatchesAlgorithm(tpmSignature, alg) {
		return errs.Detail(ErrAlgorithmMismatch, "tpm signature algorithm does not match %s | tpm 签名算法与 %s 不匹配", AlgorithmName(alg), AlgorithmName(alg))
	}
	if err := VerifySignature(alg, leaf.PublicKey, certInfoRaw, tpmSignature.signature); err != nil {
		return errs.WrapDetail(err, ErrSignatureInvalid, "tpm attestation signature is invalid | tpm 认证声明签名无效")
	}
	verified, err := verifyCertificateChain(certs, opts)
	if err != nil {
		return err
	}
	result.Type = AttestationTypeAttCA
	result.TrustPath = certs
	result.TrustVerified = verified
	return nil
}

// parseTPMPublicArea parses a TPMT_PUBLIC structure. | parseTPMPublicArea 解析 TPMT_PUBLIC 结构。
func parseTPMPublicArea(raw []byte) (*tpmPublicArea, error) {
	r := &tpmReader{data: raw}
	keyType, err := r.u16()
	if err != nil {
		return nil, err
	}
	nameAlg, err := r.u16()
	if err != nil {
		return nil, err
	}
	if _, err := r.u32(); err != nil { // objectAttributes
		return nil, err
	}
	if _, err := r.sized(); err != nil { // authPolicy
		return nil, err
	}
	if _, ok := tpmHash(nameAlg); !ok {
		return nil, errs.Detail(ErrUnsupportedAlgorithm, "tpm name algorithm %#04x | tpm name 算法 %#04x", nameAlg, nameAlg)
	}
	area := &tpmPublicArea{keyType: keyType, nameAlg: nameAlg}
	switch keyType {
	case tpmAlgRSA:
		if err := skipTPMSymmetric(r); err != nil {
			return nil, err
		}
		if err := skipTPMScheme(r, tpmAlgRSASSA, tpmAlgRSAPSS); err != nil {
			return nil, err
		}
		if _, err := r.u16(); err != nil { // keyBits
			return nil, err
		}
		exponent, err := r.u32()
		if err != nil {
			return nil, err
		}
		modulus, err := r.sized()
		if err != nil {
			return nil, err
		}
		if len(modulus) == 0 {
			return nil, errs.Detail(ErrInvalidAttestation, "tpm RSA modulus is empty | tpm RSA 模数为空")
		}
		e := int(exponent)
		if e == 0 {
			e = tpmDefaultExponent
		}
		if e < 3 || e%2 == 0 {
			return nil, errs.Detail(ErrInvalidAttestation, "tpm RSA exponent %d is invalid | tpm RSA 指数 %d 非法", e, e)
		}
		area.publicKey = &rsa.PublicKey{N: new(big.Int).SetBytes(modulus), E: e}
	case tpmAlgECC:
		if err := skipTPMSymmetric(r); err != nil {
			return nil, err
		}
		if err := skipTPMScheme(r, tpmAlgECDSA); err != nil {
			return nil, err
		}
		curveID, err := r.u16()
		if err != nil {
			return nil, err
		}
		var curve elliptic.Curve
		switch curveID {
		case tpmEccNISTP256:
			curve = elliptic.P256()
		case tpmEccNISTP384:
			curve = elliptic.P384()
		case tpmEccNISTP521:
			curve = elliptic.P521()
		default:
			return nil, errs.Detail(ErrUnsupportedKey, "tpm ECC curve %#04x | tpm ECC 曲线 %#04x", curveID, curveID)
		}
		if err := skipTPMKDF(r); err != nil {
			return nil, err
		}
		x, err := r.sized()
		if err != nil {
			return nil, err
		}
		y, err := r.sized()
		if err != nil {
			return nil, err
		}
		if len(x) == 0 || len(y) == 0 {
			return nil, errs.Detail(ErrInvalidAttestation, "tpm ECC point is empty | tpm ECC 点为空")
		}
		publicKey, err := ecdsa.ParseUncompressedPublicKey(curve, uncompressedPoint(x, y))
		if err != nil {
			return nil, errs.WrapDetail(err, ErrInvalidAttestation, "tpm ECC point is invalid | tpm ECC 点非法")
		}
		area.publicKey = publicKey
	default:
		return nil, errs.Detail(ErrUnsupportedKey, "tpm key type %#04x | tpm 密钥类型 %#04x", keyType, keyType)
	}
	if !r.done() {
		return nil, errs.Detail(ErrInvalidAttestation, "tpm pubArea has trailing bytes | tpm pubArea 存在尾随字节")
	}
	return area, nil
}

// skipTPMSymmetric skips a TPMT_SYM_DEF_OBJECT structure. | skipTPMSymmetric 跳过 TPMT_SYM_DEF_OBJECT 结构。
func skipTPMSymmetric(r *tpmReader) error {
	algorithm, err := r.u16()
	if err != nil {
		return err
	}
	if algorithm == tpmAlgNULL {
		return nil
	}
	if _, err := r.u16(); err != nil { // keyBits
		return err
	}
	_, err = r.u16() // mode
	return err
}

// skipTPMScheme skips a TPMT_RSA_SCHEME or TPMT_ECC_SCHEME structure. | skipTPMScheme 跳过 TPMT_RSA_SCHEME 或 TPMT_ECC_SCHEME 结构。
func skipTPMScheme(r *tpmReader, allowed ...uint16) error {
	algorithm, err := r.u16()
	if err != nil {
		return err
	}
	if algorithm == tpmAlgNULL {
		return nil
	}
	known := false
	for _, candidate := range allowed {
		if algorithm == candidate {
			known = true
			break
		}
	}
	if !known {
		return errs.Detail(ErrUnsupportedAlgorithm, "tpm scheme %#04x | tpm 方案 %#04x", algorithm, algorithm)
	}
	_, err = r.u16() // hashAlg
	return err
}

// skipTPMKDF skips a TPMT_KDF_SCHEME structure. | skipTPMKDF 跳过 TPMT_KDF_SCHEME 结构。
func skipTPMKDF(r *tpmReader) error {
	algorithm, err := r.u16()
	if err != nil {
		return err
	}
	switch algorithm {
	case tpmAlgNULL:
		return nil
	case 0x0020, 0x0021, 0x0022: // KDF1_SP800_56A, KDF2, KDF1_SP800_108
		_, err = r.u16()
		return err
	default:
		return errs.Detail(ErrUnsupportedAlgorithm, "tpm KDF scheme %#04x | tpm KDF 方案 %#04x", algorithm, algorithm)
	}
}

// parseTPMSAttest parses the subset of TPMS_ATTEST needed for verification. | parseTPMSAttest 解析校验所需的 TPMS_ATTEST 子集。
func parseTPMSAttest(raw []byte) (*tpmAttest, error) {
	r := &tpmReader{data: raw}
	magic, err := r.u32()
	if err != nil {
		return nil, err
	}
	if magic != tpmGeneratedMagic {
		return nil, errs.Detail(ErrInvalidAttestation, "tpm certInfo magic is %#08x | tpm certInfo magic 为 %#08x", magic, magic)
	}
	attestType, err := r.u16()
	if err != nil {
		return nil, err
	}
	if attestType != tpmStAttestCertify {
		return nil, errs.Detail(ErrInvalidAttestation, "tpm certInfo type is %#04x | tpm certInfo 类型为 %#04x", attestType, attestType)
	}
	if _, err := r.sized(); err != nil { // qualifiedSigner
		return nil, err
	}
	extraData, err := r.sized()
	if err != nil {
		return nil, err
	}
	if err := r.skip(8 + 4 + 4 + 1 + 8); err != nil { // clockInfo and firmwareVersion
		return nil, err
	}
	name, err := r.sized()
	if err != nil {
		return nil, err
	}
	if _, err := r.sized(); err != nil { // qualifiedName
		return nil, err
	}
	if !r.done() {
		return nil, errs.Detail(ErrInvalidAttestation, "tpm certInfo has trailing bytes | tpm certInfo 存在尾随字节")
	}
	return &tpmAttest{extraData: append([]byte(nil), extraData...), name: append([]byte(nil), name...)}, nil
}

// verifyTPMPubAreaName checks that the attested name hashes the supplied pubArea. | verifyTPMPubAreaName 校验被认证的 name 对给定 pubArea 的哈希。
func verifyTPMPubAreaName(area *tpmPublicArea, raw, attestedName []byte) error {
	hash, ok := tpmHash(area.nameAlg)
	if !ok {
		return errs.Detail(ErrUnsupportedAlgorithm, "tpm name algorithm %#04x | tpm name 算法 %#04x", area.nameAlg, area.nameAlg)
	}
	hasher := hash.New()
	_, _ = hasher.Write(raw)
	expected := make([]byte, 2, 2+hash.Size())
	expected[0] = byte(area.nameAlg >> 8)
	expected[1] = byte(area.nameAlg)
	expected = append(expected, hasher.Sum(nil)...)
	if !constantTimeEqual(attestedName, expected) {
		return errs.Detail(ErrInvalidAttestation, "tpm pubArea name does not match the attested name | tpm pubArea name 与被认证的 name 不匹配")
	}
	return nil
}

// tpmSignature is a parsed TPMT_SIGNATURE. | tpmSignature 是解析后的 TPMT_SIGNATURE。
type tpmSignature struct {
	sigAlg    uint16
	hashAlg   uint16
	signature []byte
}

// parseTPMSignature parses a TPMT_SIGNATURE structure into a signature accepted by VerifySignature. | parseTPMSignature 把 TPMT_SIGNATURE 解析为 VerifySignature 可接受的签名。
func parseTPMSignature(raw []byte) (*tpmSignature, error) {
	r := &tpmReader{data: raw}
	sigAlg, err := r.u16()
	if err != nil {
		return nil, err
	}
	switch sigAlg {
	case tpmAlgRSASSA, tpmAlgRSAPSS:
		hashAlg, err := r.u16()
		if err != nil {
			return nil, err
		}
		signature, err := r.sized()
		if err != nil {
			return nil, err
		}
		if !r.done() {
			return nil, errs.Detail(ErrInvalidAttestation, "tpm signature has trailing bytes | tpm 签名存在尾随字节")
		}
		return &tpmSignature{sigAlg: sigAlg, hashAlg: hashAlg, signature: signature}, nil
	case tpmAlgECDSA:
		hashAlg, err := r.u16()
		if err != nil {
			return nil, err
		}
		rValue, err := r.sized()
		if err != nil {
			return nil, err
		}
		sValue, err := r.sized()
		if err != nil {
			return nil, err
		}
		if !r.done() {
			return nil, errs.Detail(ErrInvalidAttestation, "tpm signature has trailing bytes | tpm 签名存在尾随字节")
		}
		der, err := asn1.Marshal(struct {
			R *big.Int
			S *big.Int
		}{R: new(big.Int).SetBytes(rValue), S: new(big.Int).SetBytes(sValue)})
		if err != nil {
			return nil, errs.Wrap(err, ErrInvalidAttestation)
		}
		return &tpmSignature{sigAlg: sigAlg, hashAlg: hashAlg, signature: der}, nil
	default:
		return nil, errs.Detail(ErrUnsupportedAlgorithm, "tpm signature algorithm %#04x | tpm 签名算法 %#04x", sigAlg, sigAlg)
	}
}

// tpmSignatureMatchesAlgorithm checks that the TPM signature scheme and hash match a COSE algorithm. | tpmSignatureMatchesAlgorithm 检查 TPM 签名方案与哈希是否匹配 COSE 算法。
func tpmSignatureMatchesAlgorithm(signature *tpmSignature, alg int) bool {
	if signature == nil {
		return false
	}
	hash, ok := HashForAlgorithm(alg)
	if !ok || hash == 0 {
		return false
	}
	hashAlg, ok := tpmHashAlgorithm(hash)
	if !ok || signature.hashAlg != hashAlg {
		return false
	}
	switch alg {
	case AlgES256, AlgES384, AlgES512:
		return signature.sigAlg == tpmAlgECDSA
	case AlgRS256, AlgRS384, AlgRS512:
		return signature.sigAlg == tpmAlgRSASSA
	case AlgPS256, AlgPS384, AlgPS512:
		return signature.sigAlg == tpmAlgRSAPSS
	default:
		return false
	}
}

// tpmHash maps a TPM hash algorithm identifier to crypto.Hash. | tpmHash 把 TPM 哈希算法标识映射为 crypto.Hash。
func tpmHash(algorithm uint16) (crypto.Hash, bool) {
	switch algorithm {
	case tpmAlgSHA256:
		return crypto.SHA256, true
	case tpmAlgSHA384:
		return crypto.SHA384, true
	case tpmAlgSHA512:
		return crypto.SHA512, true
	default:
		return 0, false
	}
}

// tpmHashAlgorithm maps crypto.Hash to a TPM hash algorithm identifier. | tpmHashAlgorithm 把 crypto.Hash 映射为 TPM 哈希算法标识。
func tpmHashAlgorithm(hash crypto.Hash) (uint16, bool) {
	switch hash {
	case crypto.SHA256:
		return tpmAlgSHA256, true
	case crypto.SHA384:
		return tpmAlgSHA384, true
	case crypto.SHA512:
		return tpmAlgSHA512, true
	default:
		return 0, false
	}
}

// verifyTPMCertificate checks the TPM attestation certificate profile. | verifyTPMCertificate 检查 TPM 认证证书配置。
func verifyTPMCertificate(cert *x509.Certificate) error {
	if cert.Version != 3 {
		return errs.Detail(ErrInvalidAttestation, "tpm attestation certificate is not X.509 v3 | tpm 认证证书不是 X.509 v3")
	}
	if cert.Subject.String() != "" {
		return errs.Detail(ErrInvalidAttestation, "tpm attestation certificate subject is not empty | tpm 认证证书主题非空")
	}
	if cert.BasicConstraintsValid && cert.IsCA {
		return errs.Detail(ErrInvalidAttestation, "tpm attestation certificate is a CA | tpm 认证证书是 CA")
	}
	if !containsOID(cert.UnknownExtKeyUsage, tcgKpAIKCertOID) {
		return errs.Detail(ErrInvalidAttestation, "tpm attestation certificate lacks the AIK EKU | tpm 认证证书缺少 AIK EKU")
	}
	value, ok := certificateExtension(cert, subjectAltNameOID)
	if !ok {
		return errs.Detail(ErrInvalidAttestation, "tpm attestation certificate lacks a subjectAltName | tpm 认证证书缺少 subjectAltName")
	}
	attributes, err := parseDirectoryNameAttributes(value)
	if err != nil {
		return err
	}
	for _, oid := range []asn1.ObjectIdentifier{tpmManufacturerOID, tpmModelOID, tpmVersionOID} {
		if _, ok := attributes[oid.String()]; !ok {
			return errs.Detail(ErrInvalidAttestation, "tpm attestation certificate SAN lacks %s | tpm 认证证书 SAN 缺少 %s", oid.String(), oid.String())
		}
	}
	if attributes[tpmVersionOID.String()] != "id:FFFFF1D0" {
		return errs.Detail(ErrInvalidAttestation, "tpm version attribute is %q, want id:FFFFF1D0 | tpm 版本属性为 %q，期望 id:FFFFF1D0",
			attributes[tpmVersionOID.String()], attributes[tpmVersionOID.String()])
	}
	return nil
}

// parseDirectoryNameAttributes extracts the attribute values of DirectoryName SANs. | parseDirectoryNameAttributes 提取 DirectoryName SAN 的属性值。
func parseDirectoryNameAttributes(sanValue []byte) (map[string]string, error) {
	var sequence asn1.RawValue
	rest, err := asn1.Unmarshal(sanValue, &sequence)
	if err != nil || len(rest) != 0 || sequence.Tag != asn1.TagSequence {
		return nil, errs.Detail(ErrInvalidAttestation, "subjectAltName is malformed | subjectAltName 格式非法")
	}
	elements, err := derElements(sequence.Bytes)
	if err != nil {
		return nil, errs.WrapDetail(err, ErrInvalidAttestation, "subjectAltName is malformed | subjectAltName 格式非法")
	}
	attributes := make(map[string]string)
	for _, element := range elements {
		if element.class != derClassContext || element.tag != 4 {
			continue
		}
		var rdns pkix.RDNSequence
		rest, err := asn1.Unmarshal(element.content, &rdns)
		if err != nil || len(rest) != 0 {
			return nil, errs.Detail(ErrInvalidAttestation, "directoryName SAN is malformed | directoryName SAN 格式非法")
		}
		for _, set := range rdns {
			for _, attribute := range set {
				if value, ok := asn1String(attribute.Value); ok {
					attributes[attribute.Type.String()] = value
				}
			}
		}
	}
	return attributes, nil
}

// asn1String converts a decoded ASN.1 string value to a Go string. | asn1String 把解码后的 ASN.1 字符串值转换为 Go 字符串。
func asn1String(value any) (string, bool) {
	switch v := value.(type) {
	case string:
		return v, true
	case []byte:
		return string(v), true
	default:
		return "", false
	}
}

// containsOID reports whether oids contains want. | containsOID 报告 oids 是否包含 want。
func containsOID(oids []asn1.ObjectIdentifier, want asn1.ObjectIdentifier) bool {
	for _, oid := range oids {
		if oid.Equal(want) {
			return true
		}
	}
	return false
}
