package xmlsig

import (
	"crypto"
	"crypto/rsa"
	"strconv"
	"strings"

	"github.com/shibingli/ydx/base64"
	"github.com/shibingli/ydx/errs"
)

// parsedSignature is the decoded structure of a Signature element. | parsedSignature 是 Signature
// 元素的解码结构。
type parsedSignature struct {
	node            *xmlNode
	signedInfo      *xmlNode
	signatureValue  []byte
	c14nOpts        CanonicalizeOptions
	c14nURI         string
	signatureMethod string
	saltLength      int
	spec            signatureSpec
	refList         []*parsedReference
	keyInfo         *parsedKeyInfo
}

// parsedReference is one decoded Reference element. | parsedReference 是一个解码后的 Reference
// 元素。
type parsedReference struct {
	node         *xmlNode
	uri          string
	transforms   []parsedTransform
	digestMethod string
	digestValue  []byte
}

// parsedTransform is one decoded Transform element. | parsedTransform 是一个解码后的 Transform
// 元素。
type parsedTransform struct {
	algorithm string
	c14nOpts  *CanonicalizeOptions
}

// parseSignature decodes and validates the structure of sig. | parseSignature 解码并校验 sig 的
// 结构。
func parseSignature(sig *xmlNode) (*parsedSignature, error) {
	if sig == nil || sig.kind != elementNode || sig.local != "Signature" {
		return nil, errs.Detail(ErrMalformed, "not a Signature element | 不是 Signature 元素")
	}
	if ns := elementNamespace(sig); ns != "" && ns != NamespaceXMLDSig {
		return nil, errs.Detail(ErrMalformed, "Signature element uses namespace %q | Signature 元素使用了命名空间 %q", ns, ns)
	}
	signedInfo, err := exactlyOneChild(sig, "SignedInfo")
	if err != nil {
		return nil, err
	}
	signatureValueNode, err := exactlyOneChild(sig, "SignatureValue")
	if err != nil {
		return nil, err
	}
	signatureValue, err := decodeBase64Element(signatureValueNode)
	if err != nil {
		return nil, err
	}

	c14nMethod, err := exactlyOneChild(signedInfo, "CanonicalizationMethod")
	if err != nil {
		return nil, err
	}
	c14nURI, err := requiredAttribute(c14nMethod, "Algorithm")
	if err != nil {
		return nil, err
	}
	c14nOpts, err := c14nSpecForURI(c14nURI)
	if err != nil {
		return nil, err
	}
	c14nOpts.InclusiveNamespaces = parseInclusiveNamespaces(c14nMethod)

	sigMethodNode, err := exactlyOneChild(signedInfo, "SignatureMethod")
	if err != nil {
		return nil, err
	}
	signatureMethod, err := requiredAttribute(sigMethodNode, "Algorithm")
	if err != nil {
		return nil, err
	}
	spec, ok := signatureSpecs[signatureMethod]
	if !ok {
		return nil, errs.Detail(ErrUnsupported, "signature algorithm %q is not supported | 不支持签名算法 %q", signatureMethod, signatureMethod)
	}
	saltLength := rsa.PSSSaltLengthAuto
	if spec.kind == sigKindRSAPSS {
		spec, saltLength, err = parsePSSParams(sigMethodNode, spec)
		if err != nil {
			return nil, err
		}
	}

	refNodes := signedInfo.childrenByLocal("Reference")
	if len(refNodes) == 0 {
		return nil, errs.Detail(ErrUnsigned, "SignedInfo has no Reference | SignedInfo 不含 Reference")
	}
	refs := make([]*parsedReference, 0, len(refNodes))
	for _, refNode := range refNodes {
		ref, err := parseReference(refNode)
		if err != nil {
			return nil, err
		}
		refs = append(refs, ref)
	}

	var keyInfo *parsedKeyInfo
	if ki := sig.childByLocal("KeyInfo"); ki != nil {
		keyInfo, err = parseKeyInfo(ki)
		if err != nil {
			return nil, err
		}
	}

	return &parsedSignature{
		node:            sig,
		signedInfo:      signedInfo,
		signatureValue:  signatureValue,
		c14nOpts:        c14nOpts,
		c14nURI:         c14nURI,
		signatureMethod: signatureMethod,
		saltLength:      saltLength,
		spec:            spec,
		refList:         refs,
		keyInfo:         keyInfo,
	}, nil
}

// parseReference decodes one Reference element. | parseReference 解码一个 Reference 元素。
func parseReference(ref *xmlNode) (*parsedReference, error) {
	uri := ""
	if v, ok := ref.attrValue("", "URI"); ok {
		uri = v
	}
	var transforms []parsedTransform
	if tn := ref.childByLocal("Transforms"); tn != nil {
		for _, tr := range tn.childrenByLocal("Transform") {
			alg, err := requiredAttribute(tr, "Algorithm")
			if err != nil {
				return nil, err
			}
			pt := parsedTransform{algorithm: alg}
			switch {
			case isCanonicalizationURI(alg):
				opts, err := c14nSpecForURI(alg)
				if err != nil {
					return nil, err
				}
				opts.InclusiveNamespaces = parseInclusiveNamespaces(tr)
				pt.c14nOpts = &opts
			case alg == transformEnvelopedURI, alg == transformBase64URI:
			case strings.Contains(strings.ToLower(alg), "xpath"):
				return nil, errs.Detail(ErrUnsupported, "XPath transforms are not supported | 不支持 XPath 变换")
			default:
				return nil, errs.Detail(ErrUnsupported, "transform %q is not supported | 不支持变换 %q", alg, alg)
			}
			transforms = append(transforms, pt)
		}
	}
	enveloped := 0
	base64Count := 0
	for i, tr := range transforms {
		switch tr.algorithm {
		case transformEnvelopedURI:
			enveloped++
			if i != 0 {
				return nil, errs.Detail(ErrMalformed, "the enveloped-signature transform must be first | enveloped-signature 变换必须位于首位")
			}
		case transformBase64URI:
			base64Count++
			if i != len(transforms)-1 {
				return nil, errs.Detail(ErrMalformed, "the base64 transform must be last | base64 变换必须位于末位")
			}
		}
	}
	if enveloped > 1 || base64Count > 1 {
		return nil, errs.Detail(ErrMalformed, "duplicate transform | 变换重复")
	}

	digestMethodNode, err := exactlyOneChild(ref, "DigestMethod")
	if err != nil {
		return nil, err
	}
	digestMethod, err := requiredAttribute(digestMethodNode, "Algorithm")
	if err != nil {
		return nil, err
	}
	digestValueNode, err := exactlyOneChild(ref, "DigestValue")
	if err != nil {
		return nil, err
	}
	digestValue, err := decodeBase64Element(digestValueNode)
	if err != nil {
		return nil, err
	}
	return &parsedReference{
		node:         ref,
		uri:          uri,
		transforms:   transforms,
		digestMethod: digestMethod,
		digestValue:  digestValue,
	}, nil
}

// parsePSSParams applies optional RSAPSSParams to spec and returns the salt length. | parsePSSParams
// 把可选的 RSAPSSParams 应用到 spec，并返回盐长度。
func parsePSSParams(sigMethod *xmlNode, spec signatureSpec) (signatureSpec, int, error) {
	saltLength := rsa.PSSSaltLengthAuto
	params := sigMethod.childByLocal("RSAPSSParams")
	if params == nil {
		return spec, saltLength, nil
	}
	if dm := params.childByLocal("DigestMethod"); dm != nil {
		alg, err := requiredAttribute(dm, "Algorithm")
		if err != nil {
			return spec, 0, err
		}
		dspec, ok := digestSpecs[alg]
		if !ok || dspec.hash == 0 {
			return spec, 0, errs.Detail(ErrUnsupported, "RSA-PSS digest %q is not supported | 不支持 RSA-PSS 摘要 %q", alg, alg)
		}
		spec.digest = dspec
		spec.hash = dspec.hash
	}
	if mgf := params.childByLocal("MGF"); mgf != nil {
		alg, err := requiredAttribute(mgf, "Algorithm")
		if err != nil {
			return spec, 0, err
		}
		mgfHash, ok := mgfHashFromURI(alg)
		if !ok {
			return spec, 0, errs.Detail(ErrUnsupported, "RSA-PSS MGF %q is not supported | 不支持 RSA-PSS MGF %q", alg, alg)
		}
		if mgfHash != 0 && mgfHash != spec.hash {
			return spec, 0, errs.Detail(ErrUnsupported, "RSA-PSS MGF hash must equal the digest hash | RSA-PSS MGF 摘要必须与主摘要一致")
		}
	}
	if sl := params.childByLocal("SaltLength"); sl != nil {
		n, err := strconv.Atoi(strings.TrimSpace(elementText(sl)))
		if err != nil || n < 0 {
			return spec, 0, errs.Detail(ErrMalformed, "invalid RSA-PSS SaltLength | RSA-PSS SaltLength 非法")
		}
		saltLength = n
	}
	return spec, saltLength, nil
}

// mgfHashFromURI maps an MGF1 URI to its digest. A zero hash means the URI does not name one and
// the digest hash is assumed. | mgfHashFromURI 把 MGF1 URI 映射为摘要。零值表示 URI 未指明摘要，
// 此时假定使用主摘要。
func mgfHashFromURI(uri string) (crypto.Hash, bool) {
	switch uri {
	case "http://www.w3.org/2007/05/xmldsig-more#MGF1":
		return 0, true
	case "http://www.w3.org/2007/05/xmldsig-more#mgf1sha1":
		return crypto.SHA1, true
	case "http://www.w3.org/2007/05/xmldsig-more#mgf1sha256":
		return crypto.SHA256, true
	case "http://www.w3.org/2007/05/xmldsig-more#mgf1sha384":
		return crypto.SHA384, true
	case "http://www.w3.org/2007/05/xmldsig-more#mgf1sha512":
		return crypto.SHA512, true
	default:
		return 0, false
	}
}

// exactlyOneChild returns the single direct child element with the given local name. | exactlyOneChild
// 返回具有给定本地名的唯一直接子元素。
func exactlyOneChild(n *xmlNode, local string) (*xmlNode, error) {
	children := n.childrenByLocal(local)
	if len(children) != 1 {
		return nil, errs.Detail(ErrMalformed, "element <%s> requires exactly one <%s> child, found %d | 元素 <%s> 需要且仅需要一个 <%s> 子元素，实际 %d 个", n.local, local, len(children), n.local, local, len(children))
	}
	return children[0], nil
}

// requiredAttribute returns a non-empty attribute value. | requiredAttribute 返回非空属性值。
func requiredAttribute(n *xmlNode, local string) (string, error) {
	v, ok := n.attrValue("", local)
	if !ok || v == "" {
		return "", errs.Detail(ErrMalformed, "element <%s> requires attribute %s | 元素 <%s> 缺少属性 %s", n.local, local, n.local, local)
	}
	return v, nil
}

// decodeBase64Element decodes the whitespace-separated base64 text of n. | decodeBase64Element 解码
// n 中可含空白的 base64 文本。
func decodeBase64Element(n *xmlNode) ([]byte, error) {
	text := stripXMLWhitespace(elementText(n))
	if text == "" {
		return nil, errs.Detail(ErrMalformed, "empty base64 value in <%s> | <%s> 中的 base64 值为空", n.local, n.local)
	}
	data, err := base64.StdEncoding.DecodeString(text)
	if err != nil {
		return nil, errs.WrapDetail(err, ErrMalformed, "invalid base64 in <%s> | <%s> 中的 base64 非法", n.local, n.local)
	}
	return data, nil
}

// stripXMLWhitespace removes XML whitespace from s. | stripXMLWhitespace 从 s 中删除 XML 空白。
func stripXMLWhitespace(s string) string {
	return strings.Map(func(r rune) rune {
		switch r {
		case ' ', '\t', '\r', '\n':
			return -1
		}
		return r
	}, s)
}

// parseInclusiveNamespaces returns the PrefixList of an InclusiveNamespaces child. | parseInclusiveNamespaces
// 返回 InclusiveNamespaces 子元素的 PrefixList。
func parseInclusiveNamespaces(n *xmlNode) []string {
	for _, c := range n.children {
		if c.kind != elementNode || c.local != "InclusiveNamespaces" {
			continue
		}
		v, _ := c.attrValue("", "PrefixList")
		return strings.Fields(v)
	}
	return nil
}

// elementNamespace resolves the namespace URI of an element name. | elementNamespace 解析元素名的
// 命名空间 URI。
func elementNamespace(n *xmlNode) string {
	uri, _ := resolvePrefix(n, n.prefix)
	return uri
}
