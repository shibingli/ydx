package saml

import (
	"context"
	"crypto/x509"
	"time"

	"github.com/shibingli/ydx/auth/crypto/xmlsig"
	"github.com/shibingli/ydx/guomi"
)

// XMLDSigSigner adapts xmlsig.Sign to the SAML XMLSigner interface. | XMLDSigSigner 把 xmlsig.Sign
// 适配为 SAML XMLSigner 接口。
type XMLDSigSigner struct {
	// PrivateKey is an RSA, ECDSA or Ed25519 private key. | PrivateKey 是 RSA、ECDSA 或 Ed25519 私钥。
	PrivateKey any
	// SM2Key enables SM2-with-SM3 signing. | SM2Key 启用 SM2-with-SM3 签名。
	SM2Key *guomi.PrivateKey
	// Certificate is written into KeyInfo and checked against the key. | Certificate 写入 KeyInfo 并与密钥比对。
	Certificate *x509.Certificate
	// Certificates adds further certificates to X509Data. | Certificates 向 X509Data 追加证书。
	Certificates []*x509.Certificate
	// SignatureMethod overrides the XMLDSig signature algorithm URI. | SignatureMethod 覆盖 XMLDSig
	// 签名算法 URI。
	SignatureMethod string
	// DigestMethod overrides the XMLDSig digest algorithm URI. | DigestMethod 覆盖 XMLDSig 摘要算法 URI。
	DigestMethod string
	// InclusiveNamespaces is the exclusive C14N PrefixList. | InclusiveNamespaces 是排他 C14N 的 PrefixList。
	InclusiveNamespaces []string
	// Exclusive selects exclusive C14N; SAML deployments normally set it. | Exclusive 选择排他 C14N；SAML 部署通常开启。
	Exclusive bool
	// Prefix is the Signature namespace prefix; "ds" is the SAML convention. | Prefix 是 Signature 命名空间前缀；SAML 约定为 "ds"。
	Prefix string
	// SignaturePosition overrides where the enveloped Signature is inserted. Empty keeps the SAML
	// schema order by inserting it directly after the Issuer element, falling back to the last
	// child when no Issuer is present. | SignaturePosition 覆盖封套签名的插入位置。为空时按 SAML
	// schema 顺序插入到 Issuer 之后；没有 Issuer 时追加为最后一个子节点。
	SignaturePosition string
}

// SignElement signs the element with elementID. | SignElement 为 elementID 元素签名。
func (s *XMLDSigSigner) SignElement(document []byte, elementID string) ([]byte, error) {
	prefix := s.Prefix
	if prefix == "" {
		prefix = "ds"
	}
	position := s.SignaturePosition
	if position == "" {
		position = "Issuer"
	}
	return xmlsig.Sign(document, xmlsig.SignOptions{
		PrivateKey:          s.PrivateKey,
		SM2Key:              s.SM2Key,
		Certificate:         s.Certificate,
		Certificates:        s.Certificates,
		ID:                  elementID,
		SignatureMethod:     s.SignatureMethod,
		DigestMethod:        s.DigestMethod,
		InclusiveNamespaces: s.InclusiveNamespaces,
		Exclusive:           s.Exclusive,
		IncludeKeyInfo:      s.Certificate != nil || len(s.Certificates) > 0,
		Prefix:              prefix,
		SignaturePosition:   position,
	})
}

// XMLDSigVerifier adapts xmlsig.VerifyElement to the SAML SignatureVerifier interface. | XMLDSigVerifier
// 把 xmlsig.VerifyElement 适配为 SAML SignatureVerifier 接口。
type XMLDSigVerifier struct {
	// Certificates are caller-trusted signer certificates. | Certificates 是调用方信任的签名证书。
	Certificates []*x509.Certificate
	// Roots enables X.509 chain validation for embedded certificates. | Roots 对内嵌证书启用 X.509 链校验。
	Roots *x509.CertPool
	// HMACKey enables HMAC signature methods. | HMACKey 启用 HMAC 签名方法。
	HMACKey []byte
	// SM2PublicKey enables SM2-with-SM3 verification. | SM2PublicKey 启用 SM2-with-SM3 校验。
	SM2PublicKey *guomi.PublicKey
	// AllowedSignatureMethods overrides the default signature allowlist. | AllowedSignatureMethods 覆盖默认签名允许列表。
	AllowedSignatureMethods []string
	// AllowedDigestMethods overrides the default digest allowlist. | AllowedDigestMethods 覆盖默认摘要允许列表。
	AllowedDigestMethods []string
	// ClockSkew tolerates certificate time drift; zero means two minutes. | ClockSkew 容忍证书时间偏差；零值表示 2 分钟。
	ClockSkew time.Duration
	// Now overrides the clock. | Now 替换时钟。
	Now func() time.Time
	// TrustKeyInfo accepts an embedded KeyValue without a certificate; unsafe for untrusted input. | TrustKeyInfo
	// 在没有证书时接受内嵌 KeyValue；对不可信输入不安全。
	TrustKeyInfo bool
}

// VerifySignature verifies the signature bound to elementID. | VerifySignature 校验绑定到 elementID 的签名。
func (v *XMLDSigVerifier) VerifySignature(_ context.Context, document []byte, elementID string) error {
	_, err := xmlsig.VerifyElement(document, elementID, xmlsig.VerifyOptions{
		Certificates:            v.Certificates,
		Roots:                   v.Roots,
		HMACKey:                 v.HMACKey,
		SM2PublicKey:            v.SM2PublicKey,
		ID:                      elementID,
		AllowedSignatureMethods: v.AllowedSignatureMethods,
		AllowedDigestMethods:    v.AllowedDigestMethods,
		ClockSkew:               v.ClockSkew,
		Now:                     v.Now,
		RequireReference:        true,
		TrustKeyInfo:            v.TrustKeyInfo,
	})
	return err
}
