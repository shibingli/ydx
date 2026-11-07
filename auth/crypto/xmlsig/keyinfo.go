package xmlsig

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rsa"
	"crypto/subtle"
	"crypto/x509"
	"math/big"
	"time"

	"github.com/shibingli/ydx/base64"
	"github.com/shibingli/ydx/errs"
)

// issuerSerial is a parsed X509IssuerSerial selector. | issuerSerial 是解析后的 X509IssuerSerial
// 选择器。
type issuerSerial struct {
	issuer string
	serial string
}

// x509Digest is a parsed X509Digest selector. | x509Digest 是解析后的 X509Digest 选择器。
type x509Digest struct {
	algorithm string
	value     []byte
}

// parsedKeyInfo is the decoded content of a KeyInfo element. | parsedKeyInfo 是 KeyInfo 元素的
// 解码内容。
type parsedKeyInfo struct {
	certificates  []*x509.Certificate
	subjectNames  []string
	issuerSerials []issuerSerial
	keyIDs        [][]byte
	digests       []x509Digest
	rsaKey        *rsa.PublicKey
	ecKey         *ecdsa.PublicKey
	keyNames      []string
}

// buildKeyInfo constructs the KeyInfo element written by Sign. | buildKeyInfo 构造 Sign 写入的
// KeyInfo 元素。
func buildKeyInfo(prefix string, opts SignOptions, key any) (*xmlNode, error) {
	ki := newElement(prefix, "KeyInfo")
	certs := signingCertificates(opts)
	if len(certs) > 0 {
		if err := signingCertificateMatches(certs[0], key); err != nil {
			return nil, err
		}
		x509Data := newElement(prefix, "X509Data")
		for _, cert := range certs {
			n := newElement(prefix, "X509Certificate")
			n.appendText(base64.StdEncoding.EncodeToString(cert.Raw))
			x509Data.appendChild(n)
		}
		ki.appendChild(x509Data)
	} else {
		switch pub := key.(type) {
		case *rsa.PrivateKey:
			ki.appendChild(buildRSAKeyValue(prefix, pub.PublicKey))
		case *ecdsa.PrivateKey:
			ecValue, err := buildECKeyValue(prefix, pub.PublicKey)
			if err != nil {
				return nil, err
			}
			ki.appendChild(ecValue)
		}
	}
	if opts.KeyName != "" {
		kn := newElement(prefix, "KeyName")
		kn.appendText(opts.KeyName)
		ki.appendChild(kn)
	}
	return ki, nil
}

// signingCertificateMatches reports a certificate/private-key mismatch. | signingCertificateMatches
// 报告证书与私钥不匹配。
func signingCertificateMatches(cert *x509.Certificate, key any) error {
	var pub any
	switch k := key.(type) {
	case *rsa.PrivateKey:
		pub = &k.PublicKey
	case *ecdsa.PrivateKey:
		pub = &k.PublicKey
	case interface{ Public() any }:
		pub = k.Public()
	default:
		return nil
	}
	if !publicKeysEqual(cert.PublicKey, pub) {
		return errs.Detail(ErrKeyMismatch, "certificate public key does not match the signing key | 证书公钥与签名密钥不匹配")
	}
	return nil
}

// buildRSAKeyValue constructs an RSAKeyValue element. | buildRSAKeyValue 构造 RSAKeyValue 元素。
func buildRSAKeyValue(prefix string, pub rsa.PublicKey) *xmlNode {
	kv := newElement(prefix, "KeyValue")
	rv := newElement(prefix, "RSAKeyValue")
	modulus := newElement(prefix, "Modulus")
	modulus.appendText(base64.StdEncoding.EncodeToString(pub.N.Bytes()))
	exponent := newElement(prefix, "Exponent")
	exponent.appendText(base64.StdEncoding.EncodeToString(big.NewInt(int64(pub.E)).Bytes()))
	rv.appendChild(modulus)
	rv.appendChild(exponent)
	kv.appendChild(rv)
	return kv
}

// buildECKeyValue constructs an ECKeyValue element using the XML Signature 1.1 namespace. |
// buildECKeyValue 使用 XML 签名 1.1 命名空间构造 ECKeyValue 元素。
func buildECKeyValue(prefix string, pub ecdsa.PublicKey) (*xmlNode, error) {
	uri := curveURI(pub.Curve)
	if uri == "" {
		return nil, errs.Detail(ErrUnsupported, "elliptic curve is not supported | 不支持该椭圆曲线")
	}
	pointBytes, err := pub.Bytes()
	if err != nil {
		return nil, errs.WrapDetail(err, ErrKeyMismatch, "EC public key is invalid | EC 公钥非法")
	}
	kv := newElement(prefix, "KeyValue")
	ec := newElement("dsig11", "ECKeyValue")
	ec.addNamespaceDecl("dsig11", NamespaceXMLDSig11)
	curve := newElement("dsig11", "NamedCurve")
	curve.setAttr("", "URI", uri)
	point := newElement("dsig11", "PublicKey")
	point.appendText(base64.StdEncoding.EncodeToString(pointBytes))
	ec.appendChild(curve)
	ec.appendChild(point)
	kv.appendChild(ec)
	return kv, nil
}

// curveURI returns the XML Signature 1.1 URI for a NIST curve. | curveURI 返回 NIST 曲线的
// XML 签名 1.1 URI。
func curveURI(curve elliptic.Curve) string {
	switch curve {
	case elliptic.P256():
		return "http://www.w3.org/2001/04/xmldsig-more#secp256r1"
	case elliptic.P384():
		return "http://www.w3.org/2001/04/xmldsig-more#secp384r1"
	case elliptic.P521():
		return "http://www.w3.org/2001/04/xmldsig-more#secp521r1"
	default:
		return ""
	}
}

// curveFromURI maps an XML Signature curve URI or OID to a curve. | curveFromURI 把 XML 签名曲线
// URI 或 OID 映射为曲线。
func curveFromURI(uri string) (elliptic.Curve, bool) {
	switch uri {
	case "http://www.w3.org/2001/04/xmldsig-more#secp256r1", "urn:oid:1.2.840.10045.3.1.7":
		return elliptic.P256(), true
	case "http://www.w3.org/2001/04/xmldsig-more#secp384r1", "urn:oid:1.3.132.0.34":
		return elliptic.P384(), true
	case "http://www.w3.org/2001/04/xmldsig-more#secp521r1", "urn:oid:1.3.132.0.35":
		return elliptic.P521(), true
	default:
		return nil, false
	}
}

// parseKeyInfo decodes a KeyInfo element. | parseKeyInfo 解码 KeyInfo 元素。
func parseKeyInfo(ki *xmlNode) (*parsedKeyInfo, error) {
	out := &parsedKeyInfo{}
	for _, child := range ki.children {
		if child.kind != elementNode {
			continue
		}
		switch child.local {
		case "KeyName":
			out.keyNames = append(out.keyNames, trimSpaceText(elementText(child)))
		case "KeyValue":
			if err := parseKeyValue(child, out); err != nil {
				return nil, err
			}
		case "X509Data":
			if err := parseX509Data(child, out); err != nil {
				return nil, err
			}
		case "RetrievalMethod":
			return nil, errs.Detail(ErrUnsupported, "KeyInfo RetrievalMethod is not supported | 不支持 KeyInfo RetrievalMethod")
		}
	}
	return out, nil
}

// parseKeyValue decodes RSAKeyValue and ECKeyValue. | parseKeyValue 解码 RSAKeyValue 与
// ECKeyValue。
func parseKeyValue(kv *xmlNode, out *parsedKeyInfo) error {
	if rv := kv.childByLocal("RSAKeyValue"); rv != nil {
		if out.rsaKey != nil {
			return errs.Detail(ErrMalformed, "duplicate RSAKeyValue | RSAKeyValue 重复")
		}
		pub, err := parseRSAKeyValue(rv)
		if err != nil {
			return err
		}
		out.rsaKey = pub
	}
	if ec := kv.childByLocal("ECKeyValue"); ec != nil {
		if out.ecKey != nil {
			return errs.Detail(ErrMalformed, "duplicate ECKeyValue | ECKeyValue 重复")
		}
		pub, err := parseECKeyValue(ec)
		if err != nil {
			return err
		}
		out.ecKey = pub
	}
	return nil
}

// parseRSAKeyValue decodes an RSA public key. | parseRSAKeyValue 解码 RSA 公钥。
func parseRSAKeyValue(rv *xmlNode) (*rsa.PublicKey, error) {
	modulusNode, err := exactlyOneChild(rv, "Modulus")
	if err != nil {
		return nil, err
	}
	exponentNode, err := exactlyOneChild(rv, "Exponent")
	if err != nil {
		return nil, err
	}
	modulusBytes, err := decodeBase64Element(modulusNode)
	if err != nil {
		return nil, err
	}
	exponentBytes, err := decodeBase64Element(exponentNode)
	if err != nil {
		return nil, err
	}
	n := new(big.Int).SetBytes(modulusBytes)
	e := new(big.Int).SetBytes(exponentBytes)
	if n.Sign() <= 0 || n.BitLen() < 1024 {
		return nil, errs.Detail(ErrKeyMismatch, "RSA modulus is too small | RSA 模数过小")
	}
	if !e.IsInt64() || e.Int64() < 3 || e.Int64() > 1<<31-1 {
		return nil, errs.Detail(ErrKeyMismatch, "invalid RSA public exponent | RSA 公钥指数非法")
	}
	return &rsa.PublicKey{N: n, E: int(e.Int64())}, nil
}

// parseECKeyValue decodes an EC public key. | parseECKeyValue 解码 EC 公钥。
func parseECKeyValue(ec *xmlNode) (*ecdsa.PublicKey, error) {
	curveNode, err := exactlyOneChild(ec, "NamedCurve")
	if err != nil {
		return nil, err
	}
	uri, err := requiredAttribute(curveNode, "URI")
	if err != nil {
		return nil, err
	}
	curve, ok := curveFromURI(uri)
	if !ok {
		return nil, errs.Detail(ErrUnsupported, "elliptic curve %q is not supported | 不支持椭圆曲线 %q", uri, uri)
	}
	pointNode, err := exactlyOneChild(ec, "PublicKey")
	if err != nil {
		return nil, err
	}
	point, err := decodeBase64Element(pointNode)
	if err != nil {
		return nil, err
	}
	pub, err := ecdsa.ParseUncompressedPublicKey(curve, point)
	if err != nil {
		return nil, errs.WrapDetail(err, ErrKeyMismatch, "invalid EC public point | EC 公钥点非法")
	}
	return pub, nil
}

// parseX509Data decodes the identifiers inside X509Data. | parseX509Data 解码 X509Data 内的标识。
func parseX509Data(data *xmlNode, out *parsedKeyInfo) error {
	for _, child := range data.children {
		if child.kind != elementNode {
			continue
		}
		switch child.local {
		case "X509Certificate":
			raw, err := decodeBase64Element(child)
			if err != nil {
				return err
			}
			cert, err := x509.ParseCertificate(raw)
			if err != nil {
				return errs.WrapDetail(err, ErrCertificateInvalid, "cannot parse X509Certificate | 无法解析 X509Certificate")
			}
			out.certificates = append(out.certificates, cert)
		case "X509SubjectName":
			out.subjectNames = append(out.subjectNames, trimSpaceText(elementText(child)))
		case "X509IssuerSerial":
			issuerNode := child.childByLocal("X509IssuerName")
			serialNode := child.childByLocal("X509SerialNumber")
			if issuerNode == nil || serialNode == nil {
				return errs.Detail(ErrMalformed, "incomplete X509IssuerSerial | X509IssuerSerial 不完整")
			}
			out.issuerSerials = append(out.issuerSerials, issuerSerial{
				issuer: trimSpaceText(elementText(issuerNode)),
				serial: trimSpaceText(elementText(serialNode)),
			})
		case "X509SKI":
			ski, err := decodeBase64Element(child)
			if err != nil {
				return err
			}
			out.keyIDs = append(out.keyIDs, ski)
		case "X509Digest":
			alg, err := requiredAttribute(child, "Algorithm")
			if err != nil {
				return err
			}
			value, err := decodeBase64Element(child)
			if err != nil {
				return err
			}
			out.digests = append(out.digests, x509Digest{algorithm: alg, value: value})
		}
	}
	return nil
}

// hasSelectors reports whether KeyInfo carries X509Data selector identifiers. | hasSelectors 判断
// KeyInfo 是否携带 X509Data 选择器标识。
func (ki *parsedKeyInfo) hasSelectors() bool {
	if ki == nil {
		return false
	}
	return len(ki.subjectNames) > 0 || len(ki.issuerSerials) > 0 || len(ki.keyIDs) > 0 || len(ki.digests) > 0
}

// matchesCertificate applies X509Data selector identifiers to a certificate. | matchesCertificate
// 把 X509Data 选择器标识应用到证书。
func (ki *parsedKeyInfo) matchesCertificate(cert *x509.Certificate) (bool, error) {
	if ki == nil {
		return true, nil
	}
	hasSelector := len(ki.subjectNames) > 0 || len(ki.issuerSerials) > 0 || len(ki.keyIDs) > 0 || len(ki.digests) > 0
	if !hasSelector {
		return true, nil
	}
	for _, name := range ki.subjectNames {
		if cert.Subject.String() == name {
			return true, nil
		}
	}
	for _, is := range ki.issuerSerials {
		if cert.Issuer.String() == is.issuer && cert.SerialNumber.String() == is.serial {
			return true, nil
		}
	}
	for _, ski := range ki.keyIDs {
		if len(ski) > 0 && subtle.ConstantTimeCompare(cert.SubjectKeyId, ski) == 1 {
			return true, nil
		}
	}
	for _, d := range ki.digests {
		spec, ok := digestSpecs[d.algorithm]
		if !ok {
			return false, errs.Detail(ErrUnsupported, "X509Digest algorithm %q is not supported | 不支持 X509Digest 算法 %q", d.algorithm, d.algorithm)
		}
		if len(d.value) == spec.size && subtle.ConstantTimeCompare(computeDigest(spec, cert.Raw), d.value) == 1 {
			return true, nil
		}
	}
	return false, nil
}

// validateCertificate checks validity, key usage and, when roots is set, the chain. |
// validateCertificate 检查有效期、密钥用途；roots 非空时还检查证书链。
func validateCertificate(cert *x509.Certificate, roots *x509.CertPool, intermediates []*x509.Certificate, now time.Time, skew time.Duration) error {
	if cert == nil {
		return errs.Detail(ErrCertificateInvalid, "nil certificate | 证书为 nil")
	}
	if now.Add(skew).Before(cert.NotBefore) {
		return errs.Detail(ErrCertificateInvalid, "certificate is not yet valid | 证书尚未生效")
	}
	if now.Add(-skew).After(cert.NotAfter) {
		return errs.Detail(ErrCertificateInvalid, "certificate has expired | 证书已过期")
	}
	if cert.KeyUsage != 0 && cert.KeyUsage&x509.KeyUsageDigitalSignature == 0 {
		return errs.Detail(ErrCertificateInvalid, "certificate key usage does not allow digital signatures | 证书密钥用途不允许数字签名")
	}
	if roots != nil {
		pool := x509.NewCertPool()
		for _, candidate := range intermediates {
			if candidate != nil && candidate != cert {
				pool.AddCert(candidate)
			}
		}
		_, err := cert.Verify(x509.VerifyOptions{
			Roots:         roots,
			Intermediates: pool,
			CurrentTime:   now,
			KeyUsages:     []x509.ExtKeyUsage{x509.ExtKeyUsageAny},
		})
		if err != nil {
			return errs.WrapDetail(err, ErrCertificateInvalid, "certificate chain validation failed | 证书链校验失败")
		}
	}
	return nil
}
