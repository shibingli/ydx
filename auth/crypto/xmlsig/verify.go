package xmlsig

import (
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/rsa"
	"crypto/subtle"
	"crypto/x509"
	"math/big"
	"time"

	"github.com/shibingli/ydx/errs"
	"github.com/shibingli/ydx/guomi"
)

// VerifyOptions controls XML Signature verification. | VerifyOptions 控制 XML 签名校验。
type VerifyOptions struct {
	// Certificates are caller-trusted signer certificates. Embedded KeyInfo certificates are
	// never trusted by themselves. | Certificates 是调用方信任的签名证书。内嵌于 KeyInfo 的证书
	// 本身从不被信任。
	Certificates []*x509.Certificate
	// Roots enables X.509 chain validation. KeyInfo certificates may then be used when they
	// chain to a configured root. | Roots 启用 X.509 证书链校验。此时内嵌于 KeyInfo 的证书只要
	// 能链到受信根即可使用。
	Roots *x509.CertPool
	// HMACKey is the secret for HMAC SignatureMethods. | HMACKey 是 HMAC SignatureMethod 的密钥。
	HMACKey []byte
	// SM2PublicKey is the public key for SM2-with-SM3 signatures. | SM2PublicKey 是
	// SM2-with-SM3 签名的公钥。
	SM2PublicKey *guomi.PublicKey
	// ID selects the exact element that must be covered by the signature. | ID 选择必须被签名
	// 覆盖的确切元素。
	ID string
	// AllowedSignatureMethods overrides the default SignatureMethod allowlist. SHA-1 and HMAC
	// methods must be listed explicitly. | AllowedSignatureMethods 覆盖默认 SignatureMethod
	// 允许列表。SHA-1 与 HMAC 方法必须显式列出。
	AllowedSignatureMethods []string
	// AllowedDigestMethods overrides the default DigestMethod allowlist. SHA-1 must be listed
	// explicitly. | AllowedDigestMethods 覆盖默认 DigestMethod 允许列表。SHA-1 必须显式列出。
	AllowedDigestMethods []string
	// ClockSkew tolerates certificate NotBefore/NotAfter drift. | ClockSkew 容忍证书
	// NotBefore/NotAfter 的时间偏差。
	ClockSkew time.Duration
	// Now supplies the verification clock; nil means time.Now. | Now 提供校验时钟；nil 表示
	// time.Now。
	Now func() time.Time
	// RequireReference requires at least one non-empty reference URI targeting the verified
	// element. | RequireReference 要求至少一个非空引用 URI 指向被校验元素。
	RequireReference bool
	// TrustKeyInfo accepts an embedded KeyValue when no certificate or root is supplied. It is
	// insecure for untrusted documents. | TrustKeyInfo 在没有证书或根时接受内嵌 KeyValue。对不可信
	// 文档启用它并不安全。
	TrustKeyInfo bool
}

// VerifyResult reports the verified signature metadata. | VerifyResult 报告已验证签名的元数据。
type VerifyResult struct {
	// SignedElementID is the ID carried by the selected reference, if any. | SignedElementID 是
	// 被选中引用携带的 ID（如有）。
	SignedElementID string
	// ReferenceURI is the selected reference URI. | ReferenceURI 是被选中的引用 URI。
	ReferenceURI string
	// SignatureMethod is the verified SignatureMethod URI. | SignatureMethod 是已验证的
	// SignatureMethod URI。
	SignatureMethod string
	// DigestMethod is the DigestMethod URI of the selected reference. | DigestMethod 是被选中
	// Reference 的 DigestMethod URI。
	DigestMethod string
	// Certificate is the signer certificate when certificate verification was used. |
	// Certificate 是使用证书校验时的签名者证书。
	Certificate *x509.Certificate
	// Signer is the public key or secret-derived verifier that validated the signature. | Signer
	// 是验证签名的公钥或由密钥派生的校验者。
	Signer any
}

// Verify checks a single XML Signature in data. When opts.ID is set it behaves like VerifyElement.
// Otherwise exactly one Signature element may exist, and at least one reference must cover the
// document root. | Verify 校验 data 中的单个 XML 签名。opts.ID 非空时行为与 VerifyElement 相同。
// 否则文档中必须恰好存在一个 Signature 元素，且至少一个引用必须覆盖根元素。
func Verify(data []byte, opts VerifyOptions) (*VerifyResult, error) {
	if opts.ID != "" {
		return VerifyElement(data, opts.ID, opts)
	}
	doc, err := parseXML(data)
	if err != nil {
		return nil, err
	}
	signatures := collectSignatures(doc.root)
	switch len(signatures) {
	case 0:
		return nil, errs.Detail(ErrNoSignature, "no Signature element found | 未找到 Signature 元素")
	case 1:
	default:
		return nil, errs.Detail(ErrMultipleSignatures, "document contains %d Signature elements | 文档包含 %d 个 Signature 元素", len(signatures), len(signatures))
	}
	return verifySignature(doc, signatures[0], &verifyBinding{root: doc.root, requireReference: opts.RequireReference}, opts)
}

// VerifyElement checks the signature bound to the element carrying id. The signature must either
// live inside that element or reference it from elsewhere, and every reference must resolve to the
// element or one of its descendants. At least one reference must resolve to the element itself. |
// VerifyElement 校验绑定到 id 元素的签名。签名必须位于该元素内部，或从别处引用该元素；每个引用
// 都必须解析到该元素或其子代，且至少一个引用解析到该元素本身。
func VerifyElement(data []byte, id string, opts VerifyOptions) (*VerifyResult, error) {
	if id == "" {
		return nil, errs.Detail(ErrInvalidOption, "empty element ID | 元素 ID 为空")
	}
	doc, err := parseXML(data)
	if err != nil {
		return nil, err
	}
	target, err := findElementByID(doc.root, id)
	if err != nil {
		return nil, err
	}
	type candidate struct {
		node   *xmlNode
		parsed *parsedSignature
	}
	var candidates []candidate
	for _, sig := range collectSignatures(doc.root) {
		ps, err := parseSignature(sig)
		if err != nil {
			continue
		}
		for _, ref := range ps.refList {
			res, err := resolveReferenceURI(doc.root, ref.uri)
			if err == nil && res.node == target {
				candidates = append(candidates, candidate{node: sig, parsed: ps})
				break
			}
		}
	}
	switch len(candidates) {
	case 0:
		return nil, errs.Detail(ErrNoSignature, "no signature bound to element %q | 没有绑定到元素 %q 的签名", id, id)
	case 1:
	default:
		return nil, errs.Detail(ErrMultipleSignatures, "%d signatures are bound to element %q | 元素 %q 绑定了 %d 个签名", len(candidates), id, id, len(candidates))
	}
	return verifyParsedSignature(doc, candidates[0].node, candidates[0].parsed, &verifyBinding{root: doc.root, target: target, requireReference: opts.RequireReference}, opts)
}

// verifyBinding records the element-level expectations of one verification. | verifyBinding 记录
// 一次校验的元素级预期。
type verifyBinding struct {
	root             *xmlNode
	target           *xmlNode
	requireReference bool
}

// verifySignature verifies one parsed signature against the binding. | verifySignature 按绑定校验
// 一个解析后的签名。
func verifySignature(doc *xmlDocument, sig *xmlNode, binding *verifyBinding, opts VerifyOptions) (*VerifyResult, error) {
	ps, err := parseSignature(sig)
	if err != nil {
		return nil, err
	}
	return verifyParsedSignature(doc, sig, ps, binding, opts)
}

// verifyParsedSignature verifies a signature whose structure is already parsed. | verifyParsedSignature
// 校验一个结构已解析的签名。
func verifyParsedSignature(doc *xmlDocument, sig *xmlNode, ps *parsedSignature, binding *verifyBinding, opts VerifyOptions) (*VerifyResult, error) {
	spec, err := signatureSpecForURI(ps.signatureMethod, opts.AllowedSignatureMethods)
	if err != nil {
		return nil, err
	}
	// RSAPSSParams can select a digest independently of the SignatureMethod URI; apply the same
	// digest allowlist so parameters cannot silently re-enable SHA-1. | RSAPSSParams 可以独立于
	// SignatureMethod URI 选择摘要算法；这里应用同一摘要白名单，避免参数悄悄重新启用 SHA-1。
	if spec.kind == sigKindRSAPSS && !algorithmAllowed(spec.digest.uri, opts.AllowedDigestMethods, defaultDigestURIs) {
		return nil, errs.Detail(ErrAlgorithmNotAllowed, "RSA-PSS digest algorithm %q is not allowed | 不允许 RSA-PSS 摘要算法 %q", spec.digest.uri, spec.digest.uri)
	}

	result := &VerifyResult{
		SignatureMethod: ps.signatureMethod,
	}
	var (
		anyExact     bool
		anyNonEmpty  bool
		selectedRef  *parsedReference
		selectedNode *xmlNode
		exactRef     *parsedReference
		exactNode    *xmlNode
	)
	for _, ref := range ps.refList {
		res, err := resolveReferenceURI(binding.root, ref.uri)
		if err != nil {
			return nil, err
		}
		exact := false
		if binding.target != nil {
			if !isDescendantOrSelf(res.node, binding.target) {
				return nil, errs.Detail(ErrReferenceMismatch, "reference %q escapes the verified element | 引用 %q 超出了被校验元素", ref.uri, ref.uri)
			}
			exact = res.node == binding.target
		} else {
			exact = res.node == binding.root
		}
		digestSpec, err := digestSpecForURI(ref.digestMethod, opts.AllowedDigestMethods)
		if err != nil {
			return nil, err
		}
		input, err := canonicalizeReferenceInput(doc, ref, res, sig)
		if err != nil {
			return nil, err
		}
		sum := computeDigest(digestSpec, input)
		if len(sum) != len(ref.digestValue) || subtle.ConstantTimeCompare(sum, ref.digestValue) != 1 {
			return nil, errs.Detail(ErrDigestMismatch, "reference %q digest does not match | 引用 %q 的摘要不匹配", ref.uri, ref.uri)
		}
		if exact {
			anyExact = true
			if exactRef == nil {
				exactRef = ref
				exactNode = res.node
			}
		}
		if ref.uri != "" {
			anyNonEmpty = true
		}
		if selectedRef == nil {
			selectedRef = ref
			selectedNode = res.node
		}
	}
	if !anyExact {
		if binding.target != nil {
			return nil, errs.Detail(ErrReferenceMismatch, "no reference resolves to the verified element | 没有引用解析到被校验元素")
		}
		return nil, errs.Detail(ErrUnsigned, "no reference resolves to the document element | 没有引用解析到文档元素")
	}
	if exactRef != nil {
		selectedRef = exactRef
		selectedNode = exactNode
	}
	if binding.requireReference && !anyNonEmpty {
		return nil, errs.Detail(ErrUnsigned, "a non-empty reference URI is required | 需要非空引用 URI")
	}

	signedInfo := canonicalizeSubtree(ps.signedInfo, ps.c14nOpts)
	usedCert, signer, err := verifySignatureValue(ps, signedInfo, opts)
	if err != nil {
		return nil, err
	}
	result.SignatureMethod = ps.signatureMethod
	result.ReferenceURI = selectedRef.uri
	result.DigestMethod = selectedRef.digestMethod
	result.SignedElementID = referenceID(selectedNode, selectedRef)
	result.Certificate = usedCert
	result.Signer = signer
	return result, nil
}

// referenceID returns the ID of a resolved reference node. | referenceID 返回已解析引用节点的 ID。
func referenceID(n *xmlNode, ref *parsedReference) string {
	if n == nil || ref == nil {
		return ""
	}
	if len(ref.uri) > 1 && ref.uri[0] == '#' && ref.uri != "#xpointer(/)" {
		return n.attrID()
	}
	return ""
}

// attrID returns the first identifier attribute value on n. | attrID 返回 n 上首个标识属性值。
func (n *xmlNode) attrID() string {
	for _, a := range n.attrs {
		if isIDAttribute(a) {
			return a.value
		}
	}
	return ""
}

// collectSignatures returns XMLDSig Signature elements in document order. | collectSignatures 按
// 文档顺序返回 XMLDSig Signature 元素。
func collectSignatures(root *xmlNode) []*xmlNode {
	var out []*xmlNode
	walkElements(root, func(n *xmlNode) {
		if n.local != "Signature" {
			return
		}
		if ns := elementNamespace(n); ns == "" || ns == NamespaceXMLDSig {
			out = append(out, n)
		}
	})
	return out
}

// isDescendantOrSelf reports whether n is ancestor or lies below it. | isDescendantOrSelf 判断 n
// 是否为 ancestor 或位于其下。
func isDescendantOrSelf(n, ancestor *xmlNode) bool {
	for cur := n; cur != nil; cur = cur.parent {
		if cur == ancestor {
			return true
		}
	}
	return false
}

// verifySignatureValue selects key material and verifies SignatureValue. | verifySignatureValue
// 选择密钥材料并校验 SignatureValue。
func verifySignatureValue(ps *parsedSignature, signedInfo []byte, opts VerifyOptions) (*x509.Certificate, any, error) {
	spec := ps.spec
	switch spec.kind {
	case sigKindHMAC:
		if len(opts.HMACKey) == 0 {
			return nil, nil, errs.Detail(ErrKeyRequired, "HMAC key required | 需要 HMAC 密钥")
		}
		expected := computeHMAC(spec.digest, opts.HMACKey, signedInfo)
		if len(expected) != len(ps.signatureValue) || subtle.ConstantTimeCompare(expected, ps.signatureValue) != 1 {
			return nil, nil, errs.Detail(ErrSignatureInvalid, "HMAC signature does not match | HMAC 签名不匹配")
		}
		return nil, nil, nil
	case sigKindSM2:
		if opts.SM2PublicKey == nil {
			return nil, nil, errs.Detail(ErrKeyRequired, "SM2 public key required | 需要 SM2 公钥")
		}
		ok, err := guomi.Verify(opts.SM2PublicKey, signedInfo, ps.signatureValue)
		if err != nil {
			return nil, nil, errs.Wrap(err, ErrSignatureInvalid)
		}
		if !ok {
			return nil, nil, errs.Detail(ErrSignatureInvalid, "SM2 signature does not match | SM2 签名不匹配")
		}
		return nil, opts.SM2PublicKey, nil
	}

	candidates, intermediates := certificateCandidates(ps, opts)
	if len(candidates) == 0 {
		if opts.TrustKeyInfo {
			if signer, ok := embeddedKey(ps.keyInfo, spec.kind); ok {
				if err := verifyBytes(spec, signer, signedInfo, ps.signatureValue, ps.saltLength); err != nil {
					return nil, nil, err
				}
				return nil, signer, nil
			}
		}
		if ps.keyInfo != nil && (len(ps.keyInfo.certificates) > 0 || len(ps.keyInfo.keyNames) > 0 || ps.keyInfo.rsaKey != nil || ps.keyInfo.ecKey != nil) {
			return nil, nil, errs.Detail(ErrUntrustedKey, "KeyInfo contains key material but no caller trust anchor was supplied | KeyInfo 含密钥材料，但调用方未提供信任锚")
		}
		return nil, nil, errs.Detail(ErrKeyRequired, "no verification key available | 没有可用的校验密钥")
	}

	now := time.Now()
	if opts.Now != nil {
		now = opts.Now()
	}
	var lastCertErr error
	for _, cert := range candidates {
		// Selectors narrow an explicit certificate set only when KeyInfo carries no certificate
		// of its own; an embedded X509Certificate is already a direct reference. | 仅当 KeyInfo 未
		// 自带证书时，选择器才用于缩小显式证书集合；内嵌 X509Certificate 本身就是直接引用。
		if ps.keyInfo != nil && len(ps.keyInfo.certificates) == 0 && ps.keyInfo.hasSelectors() {
			matches, err := ps.keyInfo.matchesCertificate(cert)
			if err != nil {
				return nil, nil, err
			}
			if !matches {
				continue
			}
		}
		if err := validateCertificate(cert, opts.Roots, intermediates, now, opts.ClockSkew); err != nil {
			lastCertErr = err
			continue
		}
		if err := verifyBytes(spec, cert.PublicKey, signedInfo, ps.signatureValue, ps.saltLength); err != nil {
			continue
		}
		return cert, cert.PublicKey, nil
	}
	if lastCertErr != nil {
		return nil, nil, lastCertErr
	}
	return nil, nil, errs.Detail(ErrSignatureInvalid, "no candidate certificate validated the signature | 没有候选证书能验证该签名")
}

// certificateCandidates returns the certificates to try and the intermediate pool. | certificateCandidates
// 返回待尝试的证书与中间证书池。
func certificateCandidates(ps *parsedSignature, opts VerifyOptions) ([]*x509.Certificate, []*x509.Certificate) {
	var keyInfoCerts []*x509.Certificate
	if ps.keyInfo != nil {
		keyInfoCerts = ps.keyInfo.certificates
	}
	intermediates := append(append([]*x509.Certificate(nil), opts.Certificates...), keyInfoCerts...)

	switch {
	case len(opts.Certificates) > 0:
		return opts.Certificates, intermediates
	case opts.Roots != nil:
		return keyInfoCerts, intermediates
	case opts.TrustKeyInfo:
		return keyInfoCerts, intermediates
	default:
		return nil, intermediates
	}
}

// embeddedKey returns a KeyValue public key when it matches the signature kind. | embeddedKey 在
// KeyValue 公钥与签名类别匹配时返回该公钥。
func embeddedKey(ki *parsedKeyInfo, kind signatureKind) (any, bool) {
	if ki == nil {
		return nil, false
	}
	switch kind {
	case sigKindRSA, sigKindRSAPSS:
		return ki.rsaKey, ki.rsaKey != nil
	case sigKindECDSA:
		return ki.ecKey, ki.ecKey != nil
	default:
		return nil, false
	}
}

// verifyBytes verifies a signature over data with pub. | verifyBytes 使用 pub 校验 data 上的签名。
func verifyBytes(spec signatureSpec, pub any, data, signature []byte, saltLength int) error {
	switch spec.kind {
	case sigKindRSA:
		key, ok := pub.(*rsa.PublicKey)
		if !ok {
			return errs.Detail(ErrKeyMismatch, "RSA public key required | 需要 RSA 公钥")
		}
		digest := computeDigest(spec.digest, data)
		if err := rsa.VerifyPKCS1v15(key, spec.hash, digest, signature); err != nil {
			return errs.WrapDetail(err, ErrSignatureInvalid, "RSA signature verification failed | RSA 签名校验失败")
		}
		return nil
	case sigKindRSAPSS:
		key, ok := pub.(*rsa.PublicKey)
		if !ok {
			return errs.Detail(ErrKeyMismatch, "RSA public key required | 需要 RSA 公钥")
		}
		digest := computeDigest(spec.digest, data)
		opts := &rsa.PSSOptions{SaltLength: saltLength, Hash: spec.hash}
		if err := rsa.VerifyPSS(key, spec.hash, digest, signature, opts); err != nil {
			return errs.WrapDetail(err, ErrSignatureInvalid, "RSA-PSS signature verification failed | RSA-PSS 签名校验失败")
		}
		return nil
	case sigKindECDSA:
		key, ok := pub.(*ecdsa.PublicKey)
		if !ok {
			return errs.Detail(ErrKeyMismatch, "ECDSA public key required | 需要 ECDSA 公钥")
		}
		size := (key.Curve.Params().BitSize + 7) / 8
		if len(signature) != 2*size {
			return errs.Detail(ErrSignatureInvalid, "ECDSA signature has wrong length | ECDSA 签名长度错误")
		}
		digest := computeDigest(spec.digest, data)
		r := new(big.Int).SetBytes(signature[:size])
		s := new(big.Int).SetBytes(signature[size:])
		if !ecdsa.Verify(key, digest, r, s) {
			return errs.Detail(ErrSignatureInvalid, "ECDSA signature verification failed | ECDSA 签名校验失败")
		}
		return nil
	case sigKindEd25519:
		key, ok := pub.(ed25519.PublicKey)
		if !ok {
			return errs.Detail(ErrKeyMismatch, "Ed25519 public key required | 需要 Ed25519 公钥")
		}
		if len(key) != ed25519.PublicKeySize || !ed25519.Verify(key, data, signature) {
			return errs.Detail(ErrSignatureInvalid, "Ed25519 signature verification failed | Ed25519 签名校验失败")
		}
		return nil
	case sigKindSM2:
		key, ok := pub.(*guomi.PublicKey)
		if !ok {
			return errs.Detail(ErrKeyMismatch, "SM2 public key required | 需要 SM2 公钥")
		}
		ok, err := guomi.Verify(key, data, signature)
		if err != nil {
			return errs.Wrap(err, ErrSignatureInvalid)
		}
		if !ok {
			return errs.Detail(ErrSignatureInvalid, "SM2 signature verification failed | SM2 签名校验失败")
		}
		return nil
	default:
		return errs.Detail(ErrUnsupported, "unsupported signature kind | 不支持的签名类型")
	}
}
