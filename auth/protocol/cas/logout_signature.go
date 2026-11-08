package cas

import (
	"context"
	"crypto/x509"
	"errors"
	"time"

	"github.com/shibingli/ydx/auth/crypto/xmlsig"
	"github.com/shibingli/ydx/errs"
	"github.com/shibingli/ydx/guomi"
	"github.com/shibingli/ydx/xml"
)

// LogoutRequestSignatureVerifier verifies the XML signature of an inbound LogoutRequest. |
// LogoutRequestSignatureVerifier 校验入站 LogoutRequest 的 XML 签名。
//
// The implementation must verify that some signature reference resolves to the exact LogoutRequest
// element identified by requestID and that every reference stays inside that element. That
// requirement defeats signature wrapping, where an attacker keeps a valid signature over an innocent
// element and changes the element the server actually reads. Reject duplicate IDs and any reference
// outside the target. | 实现必须校验某个签名引用解析到 requestID 命名的确切 LogoutRequest 元素，且
// 每个引用都停留在该元素内部。该要求抵御签名包裹攻击：攻击者保留覆盖无害元素的有效签名，却修改服务端
// 实际读取的元素。实现必须拒绝重复 ID 与任何超出目标的引用。
type LogoutRequestSignatureVerifier interface {
	// VerifyLogoutRequest returns nil only when document carries a valid signature covering the
	// LogoutRequest element with the given ID. | VerifyLogoutRequest 仅在 document 携带覆盖给定 ID
	// LogoutRequest 元素的有效签名时返回 nil。
	VerifyLogoutRequest(ctx context.Context, document []byte, requestID string) error
}

// LogoutRequestSignatureVerifierFunc adapts a function to LogoutRequestSignatureVerifier. |
// LogoutRequestSignatureVerifierFunc 把函数适配为 LogoutRequestSignatureVerifier。
type LogoutRequestSignatureVerifierFunc func(ctx context.Context, document []byte, requestID string) error

// VerifyLogoutRequest calls f. | VerifyLogoutRequest 调用 f。
func (f LogoutRequestSignatureVerifierFunc) VerifyLogoutRequest(ctx context.Context, document []byte, requestID string) error {
	if f == nil {
		return errs.Detail(ErrInvalidLogoutSignature, "no signature verifier configured | 未配置签名校验器")
	}
	return f(ctx, document, requestID)
}

// LogoutRequestXMLDSigVerifier verifies LogoutRequest signatures with auth/crypto/xmlsig. It accepts
// exactly one signature bound to the LogoutRequest ID and requires a non-empty reference URI, so a
// detached or wrapped signature cannot be replayed against a different request element. |
// LogoutRequestXMLDSigVerifier 使用 auth/crypto/xmlsig 校验 LogoutRequest 签名。它只接受绑定到
// LogoutRequest ID 的单个签名，并要求非空引用 URI，因此分离或包裹的签名无法被重放到不同的请求元素上。
type LogoutRequestXMLDSigVerifier struct {
	// Certificates are caller-trusted signer certificates. | Certificates 是调用方信任的签名证书。
	Certificates []*x509.Certificate
	// Roots enables X.509 chain validation for certificates embedded in KeyInfo. | Roots 对 KeyInfo
	// 内嵌证书启用 X.509 链校验。
	Roots *x509.CertPool
	// HMACKey enables HMAC signature methods. | HMACKey 启用 HMAC 签名方法。
	HMACKey []byte
	// SM2PublicKey enables SM2-with-SM3 verification. | SM2PublicKey 启用 SM2-with-SM3 校验。
	SM2PublicKey *guomi.PublicKey
	// AllowedSignatureMethods overrides the default signature allowlist. | AllowedSignatureMethods
	// 覆盖默认签名允许列表。
	AllowedSignatureMethods []string
	// AllowedDigestMethods overrides the default digest allowlist. | AllowedDigestMethods 覆盖默认
	// 摘要允许列表。
	AllowedDigestMethods []string
	// ClockSkew tolerates certificate NotBefore/NotAfter drift. | ClockSkew 容忍证书有效期偏差。
	ClockSkew time.Duration
	// Now overrides the verification clock; nil means time.Now. | Now 替换校验时钟；空值表示
	// time.Now。
	Now func() time.Time
	// TrustKeyInfo accepts an embedded KeyValue without a trusted certificate or root. It is unsafe
	// for documents from untrusted senders. | TrustKeyInfo 在没有受信证书或根时接受内嵌 KeyValue。
	// 对不可信发送方的文档启用它并不安全。
	TrustKeyInfo bool
}

// VerifyLogoutRequest verifies the XML signature bound to requestID. | VerifyLogoutRequest 校验绑定到
// requestID 的 XML 签名。
func (v *LogoutRequestXMLDSigVerifier) VerifyLogoutRequest(_ context.Context, document []byte, requestID string) error {
	if v == nil {
		return errs.Detail(ErrInvalidLogoutSignature, "no signature verifier configured | 未配置签名校验器")
	}
	if requestID == "" {
		return errs.Detail(ErrInvalidLogoutSignature, "signed logout request has no ID | 已签名登出请求缺少 ID")
	}
	_, err := xmlsig.VerifyElement(document, requestID, xmlsig.VerifyOptions{
		Certificates:            v.Certificates,
		Roots:                   v.Roots,
		HMACKey:                 v.HMACKey,
		SM2PublicKey:            v.SM2PublicKey,
		ID:                      requestID,
		AllowedSignatureMethods: v.AllowedSignatureMethods,
		AllowedDigestMethods:    v.AllowedDigestMethods,
		ClockSkew:               v.ClockSkew,
		Now:                     v.Now,
		RequireReference:        true,
		TrustKeyInfo:            v.TrustKeyInfo,
	})
	if err != nil {
		return errs.WrapDetail(err, ErrInvalidLogoutSignature, "logout request signature verification failed | 登出请求签名校验失败")
	}
	return nil
}

// verifyLogoutRequestSignature applies the server signature policy to an inbound LogoutRequest. A
// request without a Signature is accepted unless RequireSignedLogoutRequest is set. A request with a
// Signature must pass the configured verifier; when no verifier is configured it is rejected, so a
// misspelled or missing verifier cannot silently turn signature checking off. | verifyLogoutRequestSignature
// 对入站 LogoutRequest 应用服务端签名策略。不带 Signature 的请求除非设置 RequireSignedLogoutRequest，
// 否则被接受。带 Signature 的请求必须通过配置的校验器；未配置校验器时会被拒绝，避免拼写错误或遗漏配置
// 悄然关闭签名校验。
func (s *Server) verifyLogoutRequestSignature(ctx context.Context, document []byte, request *LogoutRequest) error {
	if !logoutRequestHasSignature(document) {
		if s.config.RequireSignedLogoutRequest {
			return errs.Detail(ErrInvalidLogoutSignature, "logout request is not signed | 登出请求未签名")
		}
		return nil
	}
	verifier := s.config.LogoutRequestSignatureVerifier
	if verifier == nil {
		return errs.Detail(ErrInvalidLogoutSignature, "logout request is signed but no verifier is configured | 登出请求已签名但未配置校验器")
	}
	if request == nil || request.ID == "" {
		return errs.Detail(ErrInvalidLogoutSignature, "signed logout request has no ID | 已签名登出请求缺少 ID")
	}
	if err := verifier.VerifyLogoutRequest(ctx, document, request.ID); err != nil {
		if errors.Is(err, ErrInvalidLogoutSignature) {
			return err
		}
		return errs.WrapDetail(err, ErrInvalidLogoutSignature, "logout request signature is invalid | 登出请求签名无效")
	}
	return nil
}

// logoutRequestHasSignature reports whether document contains an XML Signature element. A signature
// in any namespace counts, because an unexpected signature must never be silently ignored. |
// logoutRequestHasSignature 报告 document 是否包含 XML Signature 元素。任何命名空间下的签名都计入，
// 因为意外的签名绝不能被静默忽略。
func logoutRequestHasSignature(document []byte) bool {
	decoder := xml.NewDecoderBytes(document)
	for {
		token, err := decoder.Token()
		if err != nil {
			return false
		}
		start, ok := token.(xml.StartElement)
		if !ok || start.Name.Local != "Signature" {
			continue
		}
		if start.Name.Space == "" || start.Name.Space == xmlsig.NamespaceXMLDSig {
			return true
		}
	}
}
