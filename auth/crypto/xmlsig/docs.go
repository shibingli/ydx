// Package xmlsig implements XML Canonicalization, XML Signature and XML Encryption for the
// ydx auth module. | xmlsig 包为 ydx auth 模块实现 XML 规范化、XML 签名与 XML 加密。
//
// The package preserves namespace prefixes while parsing, so canonical forms match the W3C
// Canonical XML 1.0/1.1 and Exclusive XML Canonicalization specifications. Signatures support
// the enveloped and detached modes, same-document references of the form "", "#id",
// "#xpointer(/)" and "#xpointer(id('ID'))", and the enveloped-signature, canonicalization and
// base64 transforms. Encryption supports AES-CBC, AES-GCM, SM4-CBC, SM4-GCM, RSA key transport,
// AES key wrap and SM2 key transport.
//
// 本包在解析时保留命名空间前缀，因此规范形式符合 W3C Canonical XML 1.0/1.1 与 Exclusive XML
// Canonicalization 规范。签名支持封套与分离模式、""、"#id"、"#xpointer(/)" 与
// "#xpointer(id('ID'))" 形式的本文档引用，以及 enveloped-signature、规范化与 base64 变换。加密
// 支持 AES-CBC、AES-GCM、SM4-CBC、SM4-GCM、RSA 密钥传输、AES 密钥包装与 SM2 密钥传输。
//
// # Security model
//
// Verification never trusts keys embedded in a document unless the caller supplies trusted
// certificates, a root pool, or explicitly enables TrustKeyInfo. SHA-1 digests, SHA-1 signature
// methods, HMAC signature methods and RSA PKCS#1 v1.5 key transport are disabled by default and
// must be enabled explicitly. Duplicate identifiers, multiple signatures bound to one element,
// external references, XPath transforms and CipherReference elements are rejected.
//
// # 安全模型
//
// 除非调用方提供受信证书、根证书池或显式启用 TrustKeyInfo，校验从不信任文档内嵌的密钥。SHA-1
// 摘要、SHA-1 签名方法、HMAC 签名方法与 RSA PKCS#1 v1.5 密钥传输默认禁用，必须显式启用。重复
// 标识、绑定到同一元素的多个签名、外部引用、XPath 变换与 CipherReference 元素都会被拒绝。
//
// # Native Go usage
//
//	key, _ := rsa.GenerateKey(rand.Reader, 2048)
//	signed, err := xmlsig.Sign(document, xmlsig.SignOptions{PrivateKey: key, ID: "order-1"})
//	if err != nil {
//		return err
//	}
//	result, err := xmlsig.VerifyElement(signed, "order-1", xmlsig.VerifyOptions{
//		Certificates: []*x509.Certificate{cert},
//	})
//
// # YD router usage
//
//	router.HandleRaw(http.MethodPost, "/signed", func(w http.ResponseWriter, r *http.Request) {
//		body, _ := io.ReadAll(r.Body)
//		if _, err := xmlsig.VerifyElement(body, "order-1", xmlsig.VerifyOptions{
//			Certificates: []*x509.Certificate{cert},
//		}); err != nil {
//			http.Error(w, "invalid signature", http.StatusBadRequest)
//			return
//		}
//		w.WriteHeader(http.StatusNoContent)
//	})
package xmlsig
