package webauthn

import (
	"crypto/ecdsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/asn1"
	"math/big"

	"github.com/shibingli/ydx/errs"
)

// verifyPacked implements the packed attestation format. | verifyPacked 实现 packed 认证声明格式。
func (o *AttestationObject) verifyPacked(result *AttestationResult, clientDataHash []byte, opts AttestationOptions) error {
	alg, err := attestationStatementInt(o.AttStmt, "alg")
	if err != nil {
		return err
	}
	if _, ok := HashForAlgorithm(alg); !ok {
		return errs.Detail(ErrUnsupportedAlgorithm, "packed attestation algorithm %d | packed 认证声明算法 %d", alg, alg)
	}
	signature, err := attestationStatementBytes(o.AttStmt, "sig")
	if err != nil {
		return err
	}
	signed := signedAttestationData(o.AuthDataRaw, clientDataHash)
	x5c, present, err := attestationStatementX5C(o.AttStmt)
	if err != nil {
		return err
	}
	if present {
		certs, err := parseX5C(x5c)
		if err != nil {
			return err
		}
		leaf := certs[0]
		if leaf.Version != 3 {
			return errs.Detail(ErrInvalidAttestation, "packed attestation certificate is not X.509 v3 | packed 认证证书不是 X.509 v3")
		}
		if err := VerifySignature(alg, leaf.PublicKey, signed, signature); err != nil {
			return errs.WrapDetail(err, ErrSignatureInvalid, "packed attestation signature is invalid | packed 认证声明签名无效")
		}
		if err := verifyAAGUIDExtension(leaf, result.AAGUID); err != nil {
			return err
		}
		verified, err := verifyCertificateChain(certs, opts)
		if err != nil {
			return err
		}
		result.TrustPath = certs
		result.TrustVerified = verified
		if leaf.IsCA {
			result.Type = AttestationTypeAttCA
		} else {
			result.Type = AttestationTypeBasic
		}
		return nil
	}
	key, err := attestationCredentialPublicKey(o.AuthData)
	if err != nil {
		return err
	}
	if key.Algorithm() != alg {
		return errs.Detail(ErrAlgorithmMismatch, "packed self attestation algorithm %d does not match credential key %d | packed 自认证算法 %d 与凭据密钥 %d 不一致",
			alg, key.Algorithm(), alg, key.Algorithm())
	}
	if err := key.Verify(alg, signed, signature); err != nil {
		return errs.WrapDetail(err, ErrSignatureInvalid, "packed self attestation signature is invalid | packed 自认证签名无效")
	}
	result.Type = AttestationTypeSelf
	return nil
}

// verifyFIDOU2F implements the fido-u2f attestation format. | verifyFIDOU2F 实现 fido-u2f 认证声明格式。
func (o *AttestationObject) verifyFIDOU2F(result *AttestationResult, clientDataHash []byte, opts AttestationOptions) error {
	signature, err := attestationStatementBytes(o.AttStmt, "sig")
	if err != nil {
		return err
	}
	x5c, present, err := attestationStatementX5C(o.AttStmt)
	if err != nil {
		return err
	}
	if !present {
		return errs.Detail(ErrInvalidAttestation, "fido-u2f attestation lacks x5c | fido-u2f 认证声明缺少 x5c")
	}
	certs, err := parseX5C(x5c)
	if err != nil {
		return err
	}
	leaf := certs[0]
	if _, ok := leaf.PublicKey.(*ecdsa.PublicKey); !ok {
		return errs.Detail(ErrInvalidAttestation, "fido-u2f attestation certificate is not an EC key | fido-u2f 认证证书不是 EC 密钥")
	}
	key, err := attestationCredentialPublicKey(o.AuthData)
	if err != nil {
		return err
	}
	if key.Kty != KeyTypeEC2 || key.Crv != CurveP256 || len(key.X) != 32 || len(key.Y) != 32 {
		return errs.Detail(ErrUnsupportedKey, "fido-u2f requires a P-256 credential key | fido-u2f 要求 P-256 凭据密钥")
	}
	signed := make([]byte, 0, 1+32+32+len(o.AuthData.CredentialID)+65)
	signed = append(signed, 0x00)
	signed = append(signed, o.AuthData.RPIDHash[:]...)
	signed = append(signed, clientDataHash...)
	signed = append(signed, o.AuthData.CredentialID...)
	signed = append(signed, 0x04)
	signed = append(signed, key.X...)
	signed = append(signed, key.Y...)
	if err := VerifySignature(AlgES256, leaf.PublicKey, signed, signature); err != nil {
		return errs.WrapDetail(err, ErrSignatureInvalid, "fido-u2f attestation signature is invalid | fido-u2f 认证声明签名无效")
	}
	verified, err := verifyCertificateChain(certs, opts)
	if err != nil {
		return err
	}
	result.Type = AttestationTypeBasic
	result.TrustPath = certs
	result.TrustVerified = verified
	return nil
}

// appleNonceOID is the Apple anonymous attestation nonce extension. | appleNonceOID 是 Apple 匿名认证 nonce 扩展。
var appleNonceOID = asn1.ObjectIdentifier{1, 2, 840, 113635, 100, 8, 2}

// verifyApple implements the apple anonymous attestation format. | verifyApple 实现 apple 匿名认证声明格式。
func (o *AttestationObject) verifyApple(result *AttestationResult, clientDataHash []byte, opts AttestationOptions) error {
	x5c, present, err := attestationStatementX5C(o.AttStmt)
	if err != nil {
		return err
	}
	if !present {
		return errs.Detail(ErrInvalidAttestation, "apple attestation lacks x5c | apple 认证声明缺少 x5c")
	}
	certs, err := parseX5C(x5c)
	if err != nil {
		return err
	}
	leaf := certs[0]
	key, err := attestationCredentialPublicKey(o.AuthData)
	if err != nil {
		return err
	}
	credentialPublicKey, err := key.PublicKey()
	if err != nil {
		return err
	}
	if !samePublicKey(leaf.PublicKey, credentialPublicKey) {
		return errs.Detail(ErrInvalidAttestation, "apple attestation certificate key differs from the credential key | apple 认证证书密钥与凭据密钥不一致")
	}
	value, ok := certificateExtension(leaf, appleNonceOID)
	if !ok {
		return errs.Detail(ErrInvalidAttestation, "apple attestation certificate lacks the nonce extension | apple 认证证书缺少 nonce 扩展")
	}
	var nonceExtension struct {
		Nonce []byte `asn1:"tag:1,explicit"`
	}
	rest, err := asn1.Unmarshal(value, &nonceExtension)
	if err != nil || len(rest) != 0 {
		return errs.Detail(ErrInvalidAttestation, "apple nonce extension is malformed | apple nonce 扩展格式非法")
	}
	expected := sha256.Sum256(signedAttestationData(o.AuthDataRaw, clientDataHash))
	if !constantTimeEqual(nonceExtension.Nonce, expected[:]) {
		return errs.Detail(ErrInvalidAttestation, "apple nonce does not match authData || clientDataHash | apple nonce 与 authData || clientDataHash 不匹配")
	}
	verified, err := verifyCertificateChain(certs, opts)
	if err != nil {
		return err
	}
	result.Type = AttestationTypeBasic
	result.TrustPath = certs
	result.TrustVerified = verified
	return nil
}

// certificateExtension returns the raw extension value for oid. | certificateExtension 返回 oid 对应的原始扩展值。
func certificateExtension(cert *x509.Certificate, oid asn1.ObjectIdentifier) ([]byte, bool) {
	if cert == nil {
		return nil, false
	}
	for i := range cert.Extensions {
		if cert.Extensions[i].Id.Equal(oid) {
			return cert.Extensions[i].Value, true
		}
	}
	return nil, false
}

// DER element classes and tags used by the attestation parsers. | 认证声明解析器使用的 DER 类别与标签。
const (
	derClassUniversal = 0
	derClassContext   = 2
	derTagInteger     = 2
	derTagOctetString = 4
	derTagSequence    = 16
	derTagSet         = 17
)

// derElement is a single DER TLV. | derElement 是单个 DER TLV。
type derElement struct {
	class       int
	tag         int
	constructed bool
	content     []byte
	full        []byte
}

// parseDERElement reads one DER element. | parseDERElement 读取一个 DER 元素。
func parseDERElement(data []byte) (derElement, []byte, error) {
	return parseDERElementDepth(data, 0)
}

// parseDERElementDepth reads one DER element with a nesting bound. | parseDERElementDepth 在嵌套上限内读取一个 DER 元素。
func parseDERElementDepth(data []byte, depth int) (derElement, []byte, error) {
	var element derElement
	if depth > 16 {
		return element, nil, errs.Detail(ErrInvalidAttestation, "DER nesting is too deep | DER 嵌套过深")
	}
	if len(data) < 2 {
		return element, nil, errs.Detail(ErrInvalidAttestation, "truncated DER element | DER 元素被截断")
	}
	first := data[0]
	element.class = int(first >> 6)
	element.constructed = first&0x20 != 0
	element.tag = int(first & 0x1f)
	offset := 1
	if element.tag == 0x1f {
		element.tag = 0
		for {
			if offset >= len(data) {
				return element, nil, errs.Detail(ErrInvalidAttestation, "truncated DER tag | DER 标签被截断")
			}
			b := data[offset]
			offset++
			if element.tag > (1<<24)-1 {
				return element, nil, errs.Detail(ErrInvalidAttestation, "DER tag is too large | DER 标签过大")
			}
			element.tag = element.tag<<7 | int(b&0x7f)
			if b&0x80 == 0 {
				break
			}
		}
	}
	if offset >= len(data) {
		return element, nil, errs.Detail(ErrInvalidAttestation, "truncated DER length | DER 长度被截断")
	}
	lengthByte := data[offset]
	offset++
	var length int
	if lengthByte&0x80 == 0 {
		length = int(lengthByte)
	} else {
		count := int(lengthByte & 0x7f)
		if count == 0 {
			return element, nil, errs.Detail(ErrInvalidAttestation, "indefinite DER length | DER 长度为不定长")
		}
		if count > 4 || offset+count > len(data) {
			return element, nil, errs.Detail(ErrInvalidAttestation, "invalid DER length | DER 长度非法")
		}
		for i := 0; i < count; i++ {
			length = length<<8 | int(data[offset+i])
		}
		offset += count
	}
	if length < 0 || offset+length > len(data) {
		return element, nil, errs.Detail(ErrInvalidAttestation, "DER content is truncated | DER 内容被截断")
	}
	element.content = data[offset : offset+length]
	element.full = data[:offset+length]
	return element, data[offset+length:], nil
}

// derElements parses all DER elements in content. | derElements 解析 content 中的全部 DER 元素。
func derElements(content []byte) ([]derElement, error) {
	var out []derElement
	rest := content
	for len(rest) > 0 {
		element, remainder, err := parseDERElement(rest)
		if err != nil {
			return nil, err
		}
		out = append(out, element)
		rest = remainder
	}
	return out, nil
}

// parseDERPositiveInt parses a non-negative DER INTEGER content. | parseDERPositiveInt 解析非负 DER INTEGER 内容。
func parseDERPositiveInt(content []byte) (int, error) {
	if len(content) == 0 {
		return 0, errs.Detail(ErrInvalidAttestation, "empty DER integer | 空 DER 整数")
	}
	if content[0]&0x80 != 0 {
		return 0, errs.Detail(ErrInvalidAttestation, "negative DER integer | 负 DER 整数")
	}
	value := new(big.Int).SetBytes(content)
	if !value.IsInt64() || value.Int64() > int64(^uint(0)>>1) {
		return 0, errs.Detail(ErrInvalidAttestation, "DER integer is too large | DER 整数过大")
	}
	return int(value.Int64()), nil
}

// containsInt reports whether values contains want. | containsInt 报告 values 是否包含 want。
func containsInt(values []int, want int) bool {
	for _, value := range values {
		if value == want {
			return true
		}
	}
	return false
}
