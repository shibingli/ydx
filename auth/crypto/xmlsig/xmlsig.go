package xmlsig

// Reserved XML namespaces. | 保留的 XML 命名空间。
const (
	// xmlNamespaceURI is the namespace implicitly bound to the xml prefix. | xmlNamespaceURI 是
	// xml 前缀隐式绑定的命名空间。
	xmlNamespaceURI = "http://www.w3.org/XML/1998/namespace"
	// xmlnsNamespaceURI is the reserved namespace of namespace declarations. | xmlnsNamespaceURI
	// 是命名空间声明的保留命名空间。
	xmlnsNamespaceURI = "http://www.w3.org/2000/xmlns/"
)

// XML namespaces used by XML Signature and XML Encryption. | XML 签名与 XML 加密使用的命名空间。
const (
	// NamespaceXMLDSig is the XML Signature 1.0/1.1 namespace. | NamespaceXMLDSig 是 XML 签名
	// 1.0/1.1 命名空间。
	NamespaceXMLDSig = "http://www.w3.org/2000/09/xmldsig#"
	// NamespaceXMLDSig11 is the XML Signature 1.1 namespace (ECKeyValue and friends). |
	// NamespaceXMLDSig11 是 XML 签名 1.1 命名空间（ECKeyValue 等）。
	NamespaceXMLDSig11 = "http://www.w3.org/2009/xmldsig11#"
	// NamespaceXMLEnc is the XML Encryption 1.0 namespace. | NamespaceXMLEnc 是 XML 加密 1.0
	// 命名空间。
	NamespaceXMLEnc = "http://www.w3.org/2001/04/xmlenc#"
	// NamespaceXMLEnc11 is the XML Encryption 1.1 namespace. | NamespaceXMLEnc11 是 XML 加密
	// 1.1 命名空间。
	NamespaceXMLEnc11 = "http://www.w3.org/2009/xmlenc11#"
	// NamespaceExcC14N is the Exclusive XML Canonicalization namespace. | NamespaceExcC14N 是
	// 排他 XML 规范化命名空间。
	NamespaceExcC14N = "http://www.w3.org/2001/10/xml-exc-c14n#"
)

// Canonicalization algorithm URIs accepted by this package. | 本包接受的规范化算法 URI。
const (
	c14n10URI              = "http://www.w3.org/TR/2001/REC-xml-c14n-20010315"
	c14n10WithCommentsURI  = "http://www.w3.org/TR/2001/REC-xml-c14n-20010315#WithComments"
	c14n11URI              = "http://www.w3.org/2006/12/xml-c14n11"
	c14n11WithCommentsURI  = "http://www.w3.org/2006/12/xml-c14n11#WithComments"
	excC14NURI             = NamespaceExcC14N
	excC14NWithCommentsURI = NamespaceExcC14N + "WithComments"
)

// Digest algorithm URIs accepted by this package. | 本包接受的摘要算法 URI。
const (
	digestSHA1URI   = "http://www.w3.org/2000/09/xmldsig#sha1"
	digestSHA256URI = "http://www.w3.org/2001/04/xmlenc#sha256"
	digestSHA384URI = "http://www.w3.org/2001/04/xmldsig-more#sha384"
	digestSHA512URI = "http://www.w3.org/2001/04/xmlenc#sha512"
	digestSM3URI    = "http://www.w3.org/2001/04/xmldsig-more#sm3"

	// Alternate SHA-256/512 URIs used by some implementations. | 部分实现使用的 SHA-256/512 备用 URI。
	digestSHA256AltURI = "http://www.w3.org/2001/04/xmldsig-more#sha256"
	digestSHA512AltURI = "http://www.w3.org/2001/04/xmldsig-more#sha512"
)

// Signature algorithm URIs accepted by this package. | 本包接受的签名算法 URI。
const (
	sigRSASHA1URI   = "http://www.w3.org/2000/09/xmldsig#rsa-sha1"
	sigRSASHA256URI = "http://www.w3.org/2001/04/xmldsig-more#rsa-sha256"
	sigRSASHA384URI = "http://www.w3.org/2001/04/xmldsig-more#rsa-sha384"
	sigRSASHA512URI = "http://www.w3.org/2001/04/xmldsig-more#rsa-sha512"

	sigRSAPSSURI       = "http://www.w3.org/2007/05/xmldsig-more#rsa-pss"
	sigRSAPSSSHA256URI = "http://www.w3.org/2007/05/xmldsig-more#sha256-rsa-MGF1"
	sigRSAPSSSHA384URI = "http://www.w3.org/2007/05/xmldsig-more#sha384-rsa-MGF1"
	sigRSAPSSSHA512URI = "http://www.w3.org/2007/05/xmldsig-more#sha512-rsa-MGF1"

	sigECDSASHA1URI   = "http://www.w3.org/2001/04/xmldsig-more#ecdsa-sha1"
	sigECDSASHA256URI = "http://www.w3.org/2001/04/xmldsig-more#ecdsa-sha256"
	sigECDSASHA384URI = "http://www.w3.org/2001/04/xmldsig-more#ecdsa-sha384"
	sigECDSASHA512URI = "http://www.w3.org/2001/04/xmldsig-more#ecdsa-sha512"

	sigEd25519URI      = "http://www.w3.org/2021/04/xmldsig-more#eddsa-ed25519"
	sigEd25519ShortURI = "http://www.w3.org/2021/04/xmldsig-more#ed25519"

	sigHMACSHA1URI   = "http://www.w3.org/2000/09/xmldsig#hmac-sha1"
	sigHMACSHA256URI = "http://www.w3.org/2001/04/xmldsig-more#hmac-sha256"
	sigHMACSHA384URI = "http://www.w3.org/2001/04/xmldsig-more#hmac-sha384"
	sigHMACSHA512URI = "http://www.w3.org/2001/04/xmldsig-more#hmac-sha512"
	sigHMACSM3URI    = "http://www.w3.org/2001/04/xmldsig-more#hmac-sm3"

	sigSM2SM3URI      = "http://www.w3.org/2001/04/xmldsig-more#sm2-sm3"
	sigSM2SM3ShortURI = "sm2-sm3"
)

// Transform algorithm URIs accepted by this package. | 本包接受的变换算法 URI。
const (
	transformEnvelopedURI = "http://www.w3.org/2000/09/xmldsig#enveloped-signature"
	transformBase64URI    = "http://www.w3.org/2000/09/xmldsig#base64"
)

// XML Encryption algorithm URIs accepted by this package. | 本包接受的 XML 加密算法 URI。
const (
	encAES128CBCURI = "http://www.w3.org/2001/04/xmlenc#aes128-cbc"
	encAES192CBCURI = "http://www.w3.org/2001/04/xmlenc#aes192-cbc"
	encAES256CBCURI = "http://www.w3.org/2001/04/xmlenc#aes256-cbc"
	encAES128GCMURI = "http://www.w3.org/2009/xmlenc11#aes128-gcm"
	encAES192GCMURI = "http://www.w3.org/2009/xmlenc11#aes192-gcm"
	encAES256GCMURI = "http://www.w3.org/2009/xmlenc11#aes256-gcm"

	// The SM4 URIs below follow the widely deployed xmldsig-more naming. | 以下 SM4 URI 沿用广泛
	// 部署的 xmldsig-more 命名。
	encSM4CBCURI = "http://www.w3.org/2001/04/xmldsig-more#sm4-cbc"
	encSM4GCMURI = "http://www.w3.org/2001/04/xmldsig-more#sm4-gcm"

	encRSA15URI      = "http://www.w3.org/2001/04/xmlenc#rsa-1_5"
	encRSAOAEPURI    = "http://www.w3.org/2001/04/xmlenc#rsa-oaep-mgf1p"
	encRSAOAEP11URI  = "http://www.w3.org/2009/xmlenc11#rsa-oaep"
	encSM2URI        = "http://www.w3.org/2001/04/xmldsig-more#sm2"
	encSM2EncryptURI = "http://www.w3.org/2001/04/xmldsig-more#sm2-encrypt"

	encAES128KWURI = "http://www.w3.org/2001/04/xmlenc#kw-aes128"
	encAES192KWURI = "http://www.w3.org/2001/04/xmlenc#kw-aes192"
	encAES256KWURI = "http://www.w3.org/2001/04/xmlenc#kw-aes256"
)

// CanonicalizeOptions controls XML canonicalization. | CanonicalizeOptions 控制 XML 规范化。
type CanonicalizeOptions struct {
	// Exclusive selects Exclusive XML Canonicalization instead of inclusive C14N. | Exclusive
	// 选择排他 XML 规范化而非包容规范化。
	Exclusive bool
	// WithComments keeps comment nodes in the canonical form. | WithComments 在规范形式中保留
	// 注释节点。
	WithComments bool
	// InclusiveNamespaces lists prefixes treated inclusively by exclusive canonicalization.
	// The token "#default" selects the default namespace. | InclusiveNamespaces 列出排他规范化
	// 中按包容规则处理的前缀；"#default" 表示默认命名空间。
	InclusiveNamespaces []string
	// Version is "1.0" or "1.1"; empty selects 1.0. Both versions share the same namespace and
	// attribute rules here; "1.1" only labels the xml:base fixup as 1.1 semantics. | Version 为
	// "1.0" 或 "1.1"，空值表示 1.0。两者在本实现中共用命名空间与属性规则，"1.1" 仅把 xml:base
	// 修正标记为 1.1 语义。
	Version string
}
