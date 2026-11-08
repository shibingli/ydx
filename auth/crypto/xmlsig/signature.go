package xmlsig

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"math/big"
	"time"

	"github.com/shibingli/ydx/base64"
	"github.com/shibingli/ydx/errs"
	"github.com/shibingli/ydx/guomi"
)

// SignOptions controls XML Signature creation. | SignOptions 控制 XML 签名创建。
type SignOptions struct {
	// PrivateKey is an RSA, ECDSA or Ed25519 private key. | PrivateKey 是 RSA、ECDSA 或 Ed25519
	// 私钥。
	PrivateKey any
	// HMACKey enables HMAC signing when set. | HMACKey 设置后启用 HMAC 签名。
	HMACKey []byte
	// SM2Key enables SM2-with-SM3 signing when set. | SM2Key 设置后启用 SM2-with-SM3 签名。
	SM2Key *guomi.PrivateKey
	// Certificate is included in KeyInfo and checked against the signing key. | Certificate 会写入
	// KeyInfo，并与签名密钥比对。
	Certificate *x509.Certificate
	// Certificates adds further certificates to X509Data. | Certificates 向 X509Data 追加证书。
	Certificates []*x509.Certificate
	// ID selects the element carrying this identifier as the signed target. Empty selects the
	// document root. | ID 选择带有该标识的元素作为签名目标；为空时选择根元素。
	ID string
	// SignatureMethod overrides the SignatureMethod URI. | SignatureMethod 覆盖 SignatureMethod URI。
	SignatureMethod string
	// DigestMethod overrides the Reference DigestMethod URI. | DigestMethod 覆盖 Reference 的
	// DigestMethod URI。
	DigestMethod string
	// InclusiveNamespaces is the exclusive canonicalization PrefixList. | InclusiveNamespaces 是
	// 排他规范化的 PrefixList。
	InclusiveNamespaces []string
	// Exclusive selects exclusive canonicalization. | Exclusive 选择排他规范化。
	Exclusive bool
	// WithComments keeps comments in canonicalized content. | WithComments 在规范化内容中保留注释。
	WithComments bool
	// IncludeKeyInfo writes a KeyInfo element. | IncludeKeyInfo 写入 KeyInfo 元素。
	IncludeKeyInfo bool
	// Prefix is the namespace prefix for generated Signature elements. Empty uses the default
	// namespace. | Prefix 是生成的 Signature 元素的命名空间前缀；为空时使用默认命名空间。
	Prefix string
	// SignaturePosition controls where an enveloped Signature is inserted. "last" (or empty)
	// appends it after all existing children, "first" inserts it before the first child, and any
	// other value is treated as the local name of the preceding sibling (for example "Issuer"),
	// so schema-ordered documents can keep Signature directly after their issuer element. When the
	// named sibling is absent the signature is appended. | SignaturePosition 控制封套签名的插入
	// 位置。"last"（或空值）追加为最后一个子节点，"first" 插入为首个子节点，其它取值视为前一个兄弟
	// 元素的本地名（例如 "Issuer"），从而让遵循 schema 顺序的文档把 Signature 紧跟在签发方之后。
	// 指定兄弟元素不存在时追加到末尾。
	SignaturePosition string
	// Now supplies the signing clock. It is reserved for future timestamp support and may be nil.
	// | Now 提供签名时钟。该字段为未来的时间戳支持预留，可为 nil。
	Now func() time.Time
	// Detached returns only the Signature element instead of inserting it into the document. |
	// Detached 仅返回 Signature 元素，不把它插入文档。
	Detached bool
	// KeyName writes a KeyName element into KeyInfo. | KeyName 向 KeyInfo 写入 KeyName 元素。
	KeyName string
	// CanonicalizationMethod overrides the canonicalization algorithm URI. | CanonicalizationMethod
	// 覆盖规范化算法 URI。
	CanonicalizationMethod string
}

// Sign creates an enveloped or detached XML Signature over data. For an enveloped signature the
// generated Signature is placed according to SignOptions.SignaturePosition, by default as the last
// child of the target element. For a detached signature the returned bytes contain only the
// Signature element. | Sign 对 data 创建封套或分离 XML 签名。封套签名按
// SignOptions.SignaturePosition 放置，默认追加为目标元素的最后一个子节点；分离签名仅返回
// Signature 元素字节。
func Sign(data []byte, opts SignOptions) ([]byte, error) {
	doc, err := parseXML(data)
	if err != nil {
		return nil, err
	}
	if opts.Prefix == "xml" || opts.Prefix == "xmlns" {
		return nil, errs.Detail(ErrInvalidOption, "reserved namespace prefix %q | 保留命名空间前缀 %q", opts.Prefix, opts.Prefix)
	}
	target := doc.root
	if opts.ID != "" {
		target, err = findElementByID(doc.root, opts.ID)
		if err != nil {
			return nil, err
		}
	}
	spec, digestSpec, key, err := signingAlgorithms(opts)
	if err != nil {
		return nil, err
	}
	c14nOpts, c14nURI, err := signingCanonicalization(opts)
	if err != nil {
		return nil, err
	}

	referenceURI := ""
	if opts.ID != "" {
		referenceURI = "#" + opts.ID
	}
	var toDigest []byte
	if referenceURI == "" {
		toDigest = canonicalizeDocument(doc, c14nOpts)
	} else {
		toDigest = canonicalizeSubtree(target, c14nOpts)
	}
	digestValue := computeDigest(digestSpec, toDigest)

	sig := newElement(opts.Prefix, "Signature")
	if opts.Prefix == "" {
		sig.addNamespaceDecl("", NamespaceXMLDSig)
	} else {
		sig.addNamespaceDecl(opts.Prefix, NamespaceXMLDSig)
	}
	signedInfo := newElement(opts.Prefix, "SignedInfo")
	sig.appendChild(signedInfo)

	c14nMethod := newElement(opts.Prefix, "CanonicalizationMethod")
	c14nMethod.setAttr("", "Algorithm", c14nURI)
	// The PrefixList applies whenever the effective canonicalization is exclusive, including when
	// the caller selected it solely through CanonicalizationMethod. | 只要实际规范化算法为排他
	// 规范化就写入 PrefixList，包括调用方仅通过 CanonicalizationMethod 选择排他算法的情况。
	if c14nOpts.Exclusive && len(opts.InclusiveNamespaces) > 0 {
		c14nMethod.appendChild(buildInclusiveNamespaces(opts.Prefix, opts.InclusiveNamespaces))
	}
	signedInfo.appendChild(c14nMethod)

	sigMethod := newElement(opts.Prefix, "SignatureMethod")
	sigMethod.setAttr("", "Algorithm", spec.uri)
	signedInfo.appendChild(sigMethod)

	reference := newElement(opts.Prefix, "Reference")
	reference.setAttr("", "URI", referenceURI)
	transforms := newElement(opts.Prefix, "Transforms")
	if !opts.Detached {
		tr := newElement(opts.Prefix, "Transform")
		tr.setAttr("", "Algorithm", transformEnvelopedURI)
		transforms.appendChild(tr)
	}
	tr := newElement(opts.Prefix, "Transform")
	tr.setAttr("", "Algorithm", c14nURI)
	if c14nOpts.Exclusive && len(opts.InclusiveNamespaces) > 0 {
		tr.appendChild(buildInclusiveNamespaces(opts.Prefix, opts.InclusiveNamespaces))
	}
	transforms.appendChild(tr)
	reference.appendChild(transforms)

	digestMethod := newElement(opts.Prefix, "DigestMethod")
	digestMethod.setAttr("", "Algorithm", digestSpec.uri)
	reference.appendChild(digestMethod)
	digestValueNode := newElement(opts.Prefix, "DigestValue")
	digestValueNode.appendText(base64.StdEncoding.EncodeToString(digestValue))
	reference.appendChild(digestValueNode)
	signedInfo.appendChild(reference)

	signatureValue := newElement(opts.Prefix, "SignatureValue")
	sig.appendChild(signatureValue)

	if !opts.Detached {
		insertSignature(target, sig, opts.SignaturePosition)
	}

	signedBytes := canonicalizeSubtree(signedInfo, c14nOpts)
	value, err := signBytes(spec, key, signedBytes)
	if err != nil {
		return nil, err
	}
	signatureValue.appendText(base64.StdEncoding.EncodeToString(value))

	if opts.IncludeKeyInfo {
		keyInfo, err := buildKeyInfo(opts.Prefix, opts, key)
		if err != nil {
			return nil, err
		}
		sig.appendChild(keyInfo)
	}
	if opts.Detached {
		return serializeNodeBytes(sig), nil
	}
	return serializeDocument(doc), nil
}

// signingAlgorithms resolves the signature method, digest method and signing key. | signingAlgorithms
// 解析签名方法、摘要方法与签名密钥。
func signingAlgorithms(opts SignOptions) (signatureSpec, digestSpec, any, error) {
	keys := 0
	if opts.PrivateKey != nil {
		keys++
	}
	if len(opts.HMACKey) > 0 {
		keys++
	}
	if opts.SM2Key != nil {
		keys++
	}
	if keys != 1 {
		return signatureSpec{}, digestSpec{}, nil, errs.Detail(ErrKeyRequired, "exactly one signing key is required | 必须且只能提供一个签名密钥")
	}

	var (
		method string
		key    any
	)
	switch {
	case opts.SM2Key != nil:
		method = sigSM2SM3URI
		key = opts.SM2Key
	case len(opts.HMACKey) > 0:
		method = sigHMACSHA256URI
		key = opts.HMACKey
	default:
		key = opts.PrivateKey
		switch k := key.(type) {
		case *rsa.PrivateKey:
			method = sigRSASHA256URI
		case *ecdsa.PrivateKey:
			method = defaultECDSAURIForCurve(k.Curve.Params().BitSize)
		case ed25519.PrivateKey:
			method = sigEd25519URI
		default:
			return signatureSpec{}, digestSpec{}, nil, errs.Detail(ErrKeyMismatch, "unsupported private key type %T | 不支持的私钥类型 %T", key, key)
		}
	}
	if opts.SignatureMethod != "" {
		method = opts.SignatureMethod
	}
	spec, ok := signatureSpecs[method]
	if !ok {
		return signatureSpec{}, digestSpec{}, nil, errs.Detail(ErrUnsupported, "signature algorithm %q is not supported | 不支持签名算法 %q", method, method)
	}
	if err := checkSigningKeyType(spec, key); err != nil {
		return signatureSpec{}, digestSpec{}, nil, err
	}

	digestURI := opts.DigestMethod
	if digestURI == "" {
		digestURI = defaultDigestURIFor(spec)
	}
	dspec, ok := digestSpecs[digestURI]
	if !ok {
		return signatureSpec{}, digestSpec{}, nil, errs.Detail(ErrUnsupported, "digest algorithm %q is not supported | 不支持摘要算法 %q", digestURI, digestURI)
	}
	return spec, dspec, key, nil
}

// checkSigningKeyType verifies that key matches the method family. | checkSigningKeyType 验证密钥
// 与方法族匹配。
func checkSigningKeyType(spec signatureSpec, key any) error {
	switch spec.kind {
	case sigKindRSA, sigKindRSAPSS:
		if _, ok := key.(*rsa.PrivateKey); !ok {
			return errs.Detail(ErrKeyMismatch, "RSA signature requires an RSA private key | RSA 签名需要 RSA 私钥")
		}
	case sigKindECDSA:
		if _, ok := key.(*ecdsa.PrivateKey); !ok {
			return errs.Detail(ErrKeyMismatch, "ECDSA signature requires an ECDSA private key | ECDSA 签名需要 ECDSA 私钥")
		}
	case sigKindEd25519:
		if _, ok := key.(ed25519.PrivateKey); !ok {
			return errs.Detail(ErrKeyMismatch, "Ed25519 signature requires an Ed25519 private key | Ed25519 签名需要 Ed25519 私钥")
		}
	case sigKindHMAC:
		if _, ok := key.([]byte); !ok {
			return errs.Detail(ErrKeyMismatch, "HMAC signature requires a byte key | HMAC 签名需要字节密钥")
		}
	case sigKindSM2:
		if _, ok := key.(*guomi.PrivateKey); !ok {
			return errs.Detail(ErrKeyMismatch, "SM2 signature requires a guomi private key | SM2 签名需要 guomi 私钥")
		}
	}
	return nil
}

// defaultECDSAURIForCurve picks an ECDSA method from the curve size. | defaultECDSAURIForCurve 按
// 曲线位数选择 ECDSA 方法。
func defaultECDSAURIForCurve(bits int) string {
	switch {
	case bits > 384:
		return sigECDSASHA512URI
	case bits > 256:
		return sigECDSASHA384URI
	default:
		return sigECDSASHA256URI
	}
}

// defaultDigestURIFor picks the reference digest matching a signature method. | defaultDigestURIFor
// 选择与签名方法匹配的引用摘要。
func defaultDigestURIFor(spec signatureSpec) string {
	switch spec.kind {
	case sigKindSM2:
		return digestSM3URI
	case sigKindEd25519:
		return digestSHA256URI
	default:
		if spec.digest.uri != "" {
			return spec.digest.uri
		}
		return digestSHA256URI
	}
}

// signingCanonicalization resolves the canonicalization method for signing. | signingCanonicalization
// 解析签名使用的规范化方法。
func signingCanonicalization(opts SignOptions) (CanonicalizeOptions, string, error) {
	if opts.CanonicalizationMethod != "" {
		c14nOpts, err := c14nSpecForURI(opts.CanonicalizationMethod)
		if err != nil {
			return CanonicalizeOptions{}, "", err
		}
		c14nOpts.InclusiveNamespaces = opts.InclusiveNamespaces
		return c14nOpts, opts.CanonicalizationMethod, nil
	}
	c14nOpts := CanonicalizeOptions{
		Version:             "1.0",
		Exclusive:           opts.Exclusive,
		WithComments:        opts.WithComments,
		InclusiveNamespaces: opts.InclusiveNamespaces,
	}
	return c14nOpts, c14nOptionsURI(c14nOpts), nil
}

// c14nOptionsURI maps canonicalization options to the standard algorithm URI. | c14nOptionsURI 把
// 规范化选项映射为标准算法 URI。
func c14nOptionsURI(opts CanonicalizeOptions) string {
	switch {
	case opts.Exclusive && opts.WithComments:
		return excC14NWithCommentsURI
	case opts.Exclusive:
		return excC14NURI
	case opts.Version == "1.1" && opts.WithComments:
		return c14n11WithCommentsURI
	case opts.Version == "1.1":
		return c14n11URI
	case opts.WithComments:
		return c14n10WithCommentsURI
	default:
		return c14n10URI
	}
}

// buildInclusiveNamespaces constructs an ec:InclusiveNamespaces child in the exclusive C14N
// namespace. | buildInclusiveNamespaces 在排他规范化命名空间中构造 ec:InclusiveNamespaces 子元素。
func buildInclusiveNamespaces(_ string, list []string) *xmlNode {
	n := newElement("ec", "InclusiveNamespaces")
	n.addNamespaceDecl("ec", NamespaceExcC14N)
	n.setAttr("", "PrefixList", joinPrefixList(list))
	return n
}

// insertSignature places sig relative to target according to position. The default appends the
// signature; "first" prepends it; any other non-empty value names the preceding sibling element
// and falls back to appending when that sibling is absent. | insertSignature 按 position 把 sig 插入
// target。默认追加签名；"first" 前置；其它非空取值视为前一个兄弟元素的本地名，兄弟不存在时追加。
func insertSignature(target, sig *xmlNode, position string) {
	if position == "" || position == "last" {
		target.appendChild(sig)
		return
	}
	if position == "first" {
		sig.parent = target
		target.children = append([]*xmlNode{sig}, target.children...)
		return
	}
	index := -1
	for i, child := range target.children {
		if child.kind == elementNode && child.local == position {
			index = i
		}
	}
	if index < 0 {
		target.appendChild(sig)
		return
	}
	sig.parent = target
	target.children = append(target.children, nil)
	copy(target.children[index+2:], target.children[index+1:])
	target.children[index+1] = sig
}

// joinPrefixList joins prefixes with a single space, mapping the empty prefix to #default. |
// joinPrefixList 用单个空格连接前缀，并把空前缀映射为 #default。
func joinPrefixList(list []string) string {
	var b bytes.Buffer
	for i, p := range list {
		if i != 0 {
			b.WriteByte(' ')
		}
		if p == "" {
			b.WriteString("#default")
		} else {
			b.WriteString(p)
		}
	}
	return b.String()
}

// newElement creates an internal element node. | newElement 创建内部元素节点。
func newElement(prefix, local string) *xmlNode {
	return &xmlNode{kind: elementNode, prefix: prefix, local: local}
}

// signBytes signs data with the supplied key. | signBytes 使用给定密钥对 data 签名。
func signBytes(spec signatureSpec, key any, data []byte) ([]byte, error) {
	switch spec.kind {
	case sigKindRSA:
		priv, ok := key.(*rsa.PrivateKey)
		if !ok {
			return nil, errs.Detail(ErrKeyMismatch, "RSA key required | 需要 RSA 密钥")
		}
		digest := computeDigest(spec.digest, data)
		return rsa.SignPKCS1v15(rand.Reader, priv, spec.hash, digest)
	case sigKindRSAPSS:
		priv, ok := key.(*rsa.PrivateKey)
		if !ok {
			return nil, errs.Detail(ErrKeyMismatch, "RSA key required | 需要 RSA 密钥")
		}
		digest := computeDigest(spec.digest, data)
		return rsa.SignPSS(rand.Reader, priv, spec.hash, digest, &rsa.PSSOptions{SaltLength: rsa.PSSSaltLengthEqualsHash, Hash: spec.hash})
	case sigKindECDSA:
		priv, ok := key.(*ecdsa.PrivateKey)
		if !ok {
			return nil, errs.Detail(ErrKeyMismatch, "ECDSA key required | 需要 ECDSA 密钥")
		}
		digest := computeDigest(spec.digest, data)
		r, s, err := ecdsa.Sign(rand.Reader, priv, digest)
		if err != nil {
			return nil, errs.Wrap(err, ErrSignatureInvalid)
		}
		return marshalECDSASignature(priv.Curve.Params().BitSize, r, s), nil
	case sigKindEd25519:
		priv, ok := key.(ed25519.PrivateKey)
		if !ok {
			return nil, errs.Detail(ErrKeyMismatch, "Ed25519 key required | 需要 Ed25519 密钥")
		}
		return ed25519.Sign(priv, data), nil
	case sigKindHMAC:
		secret, ok := key.([]byte)
		if !ok {
			return nil, errs.Detail(ErrKeyMismatch, "HMAC key required | 需要 HMAC 密钥")
		}
		return computeHMAC(spec.digest, secret, data), nil
	case sigKindSM2:
		priv, ok := key.(*guomi.PrivateKey)
		if !ok {
			return nil, errs.Detail(ErrKeyMismatch, "SM2 key required | 需要 SM2 密钥")
		}
		return guomi.Sign(priv, data)
	default:
		return nil, errs.Detail(ErrUnsupported, "unsupported signature kind | 不支持的签名类型")
	}
}

// marshalECDSASignature encodes r and s as fixed-width big-endian integers. | marshalECDSASignature
// 把 r 与 s 编码为定长大端整数。
func marshalECDSASignature(bits int, r, s *big.Int) []byte {
	size := (bits + 7) / 8
	out := make([]byte, 2*size)
	r.FillBytes(out[:size])
	s.FillBytes(out[size:])
	return out
}

// publicKeysEqual compares two public keys. | publicKeysEqual 比较两个公钥。
func publicKeysEqual(a, b any) bool {
	switch ak := a.(type) {
	case *rsa.PublicKey:
		bk, ok := b.(*rsa.PublicKey)
		return ok && ak.N.Cmp(bk.N) == 0 && ak.E == bk.E
	case *ecdsa.PublicKey:
		bk, ok := b.(*ecdsa.PublicKey)
		return ok && ak.Equal(bk)
	case ed25519.PublicKey:
		bk, ok := b.(ed25519.PublicKey)
		return ok && bytes.Equal(ak, bk)
	case *guomi.PublicKey:
		bk, ok := b.(*guomi.PublicKey)
		if !ok {
			return false
		}
		ar, br := ak.Raw(), bk.Raw()
		if ar == nil || br == nil {
			return ar == nil && br == nil
		}
		return ar.Equal(br)
	default:
		return false
	}
}

// signingCertificates returns the certificates to embed, de-duplicated. | signingCertificates 返回
// 待嵌入的证书，已去重。
func signingCertificates(opts SignOptions) []*x509.Certificate {
	var out []*x509.Certificate
	add := func(c *x509.Certificate) {
		if c == nil {
			return
		}
		for _, existing := range out {
			if bytes.Equal(existing.Raw, c.Raw) {
				return
			}
		}
		out = append(out, c)
	}
	add(opts.Certificate)
	for _, c := range opts.Certificates {
		add(c)
	}
	return out
}
