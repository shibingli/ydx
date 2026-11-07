package xmlsig

import (
	"crypto/rsa"
	"crypto/x509"

	"github.com/shibingli/ydx/base64"
	"github.com/shibingli/ydx/errs"
	"github.com/shibingli/ydx/guomi"
)

// defaultMaxPayload bounds plaintext and ciphertext sizes when no limit is configured. | defaultMaxPayload
// 在未配置限制时约束明文与密文大小。
const defaultMaxPayload = 64 << 20

// EncryptOptions controls XML Encryption. | EncryptOptions 控制 XML 加密。
type EncryptOptions struct {
	// Algorithm is the data-encryption URI. Empty selects AES-256-GCM. | Algorithm 是数据加密
	// URI；为空时选择 AES-256-GCM。
	Algorithm string
	// KeyTransport is the RSA or SM2 key-transport URI. Empty selects RSA-OAEP-256 for RSA keys
	// and SM2 for SM2 keys. | KeyTransport 是 RSA 或 SM2 密钥传输 URI。为空时 RSA 密钥选择
	// RSA-OAEP-256，SM2 密钥选择 SM2。
	KeyTransport string
	// KeyWrap is the AES key-wrap URI used when key is a []byte KEK. Empty selects the wrap
	// matching the KEK length. | KeyWrap 是 key 为 []byte KEK 时使用的 AES 密钥包装 URI；为空时
	// 按 KEK 长度选择。
	KeyWrap string
	// CarriedKeyName records a key name on EncryptedData and EncryptedKey. | CarriedKeyName 在
	// EncryptedData 与 EncryptedKey 上记录密钥名。
	CarriedKeyName string
	// MIMEType is copied to the EncryptedData MIMEType attribute. | MIMEType 写入 EncryptedData
	// 的 MIMEType 属性。
	MIMEType string
	// Type is copied to the EncryptedData Type attribute. | Type 写入 EncryptedData 的 Type 属性。
	Type string
	// ID assigns the EncryptedData Id attribute. EncryptElement defaults it to the target's ID. |
	// ID 设置 EncryptedData 的 Id 属性。EncryptElement 默认沿用目标元素的 ID。
	ID string
	// Prefix is the XML Encryption namespace prefix. Empty selects "xenc". | Prefix 是 XML 加密
	// 命名空间前缀；为空时选择 "xenc"。
	Prefix string
	// IncludeKeyInfo is reserved for symmetry; key transport always writes a ds:KeyInfo. |
	// IncludeKeyInfo 为对称性保留；密钥传输始终写入 ds:KeyInfo。
	IncludeKeyInfo bool
	// AllowRSA1_5 enables the insecure RSA PKCS#1 v1.5 key transport. | AllowRSA1_5 启用不安全的
	// RSA PKCS#1 v1.5 密钥传输。
	AllowRSA1_5 bool
	// MaxBytes bounds the plaintext size. Zero selects 64 MiB. | MaxBytes 约束明文大小；零值表示
	// 64 MiB。
	MaxBytes int64
	// KeyName is written to EncryptedKey/KeyInfo as a ds:KeyName. | KeyName 写入
	// EncryptedKey/KeyInfo 的 ds:KeyName。
	KeyName string
}

// Encrypt encrypts plaintext and returns a standalone EncryptedData element. key may be a raw
// content-encryption key ([]byte), an AES key-encryption key ([]byte with KeyWrap), an RSA public
// key or certificate, or an SM2 public key. | Encrypt 加密 plaintext 并返回独立的 EncryptedData
// 元素。key 可以是内容加密密钥（[]byte）、AES 密钥包装密钥（[]byte 且设置 KeyWrap）、RSA 公钥或
// 证书，或 SM2 公钥。
func Encrypt(plaintext []byte, key any, opts EncryptOptions) ([]byte, error) {
	if opts.MaxBytes <= 0 {
		opts.MaxBytes = defaultMaxPayload
	}
	if int64(len(plaintext)) > opts.MaxBytes {
		return nil, errs.Detail(ErrLimit, "plaintext exceeds %d bytes | 明文超过 %d 字节", opts.MaxBytes, opts.MaxBytes)
	}
	element, err := encryptData(plaintext, key, opts, opts.ID)
	if err != nil {
		return nil, err
	}
	return serializeNodeBytes(element), nil
}

// EncryptElement encrypts the element carrying id and replaces it with EncryptedData. When id is
// empty the document root is encrypted. | EncryptElement 加密带有 id 的元素并替换为 EncryptedData。
// id 为空时加密根元素。
func EncryptElement(data []byte, id string, key any, opts EncryptOptions) ([]byte, error) {
	if opts.MaxBytes <= 0 {
		opts.MaxBytes = defaultMaxPayload
	}
	doc, err := parseXML(data)
	if err != nil {
		return nil, err
	}
	target := doc.root
	if id != "" {
		target, err = findElementByID(doc.root, id)
		if err != nil {
			return nil, err
		}
	}
	plaintext := serializeElementStandalone(target)
	if int64(len(plaintext)) > opts.MaxBytes {
		return nil, errs.Detail(ErrLimit, "plaintext exceeds %d bytes | 明文超过 %d 字节", opts.MaxBytes, opts.MaxBytes)
	}
	referenceID := opts.ID
	if referenceID == "" {
		referenceID = target.attrID()
	}
	replacement, err := encryptData(plaintext, key, opts, referenceID)
	if err != nil {
		return nil, err
	}
	replaceDocumentNode(doc, target, replacement)
	return serializeDocument(doc), nil
}

// encryptData builds an EncryptedData element. referenceID populates the EncryptedKey ReferenceList. |
// encryptData 构造 EncryptedData 元素。referenceID 用于填充 EncryptedKey 的 ReferenceList。
func encryptData(plaintext []byte, key any, opts EncryptOptions, referenceID string) (*xmlNode, error) {
	algorithmURI := opts.Algorithm
	if algorithmURI == "" {
		algorithmURI = defaultBlockCipherURI
	}
	spec, err := blockCipherSpecForURI(algorithmURI, nil)
	if err != nil {
		return nil, err
	}
	prefix := opts.Prefix
	if prefix == "" {
		prefix = "xenc"
	}
	if prefix == "xml" || prefix == "xmlns" {
		return nil, errs.Detail(ErrInvalidOption, "reserved namespace prefix %q | 保留命名空间前缀 %q", prefix, prefix)
	}
	dsPrefix := "ds"
	if prefix == "ds" {
		dsPrefix = "dsig"
	}

	var (
		cek    []byte
		encKey *xmlNode
	)
	switch k := key.(type) {
	case []byte:
		if opts.KeyWrap != "" || len(k) != spec.keyLen {
			if _, err := keyWrapSizeFor(opts.KeyWrap, len(k)); err != nil {
				return nil, err
			}
			cek, err = randomBytes(spec.keyLen)
			if err != nil {
				return nil, err
			}
			wrapped, err := aesKeyWrap(k, cek)
			if err != nil {
				return nil, err
			}
			wrapURI := opts.KeyWrap
			if wrapURI == "" {
				wrapURI = keyWrapDefaultURI(len(k))
			}
			encKey = buildEncryptedKey(prefix, dsPrefix, wrapURI, wrapped, referenceID, opts)
		} else {
			cek = append([]byte(nil), k...)
		}
	case *rsa.PublicKey:
		cek, err = randomBytes(spec.keyLen)
		if err != nil {
			return nil, err
		}
		wrapped, transportURI, err := encryptRSAKey(k, cek, opts.AllowRSA1_5, opts.KeyTransport)
		if err != nil {
			return nil, err
		}
		encKey = buildEncryptedKey(prefix, dsPrefix, transportURI, wrapped, referenceID, opts)
	case *x509.Certificate:
		pub, ok := k.PublicKey.(*rsa.PublicKey)
		if !ok {
			return nil, errs.Detail(ErrUnsupported, "only RSA certificates can transport keys | 只有 RSA 证书可以传输密钥")
		}
		cek, err = randomBytes(spec.keyLen)
		if err != nil {
			return nil, err
		}
		wrapped, transportURI, err := encryptRSAKey(pub, cek, opts.AllowRSA1_5, opts.KeyTransport)
		if err != nil {
			return nil, err
		}
		encKey = buildEncryptedKey(prefix, dsPrefix, transportURI, wrapped, referenceID, opts)
	case *guomi.PublicKey:
		if opts.KeyTransport != "" && opts.KeyTransport != encSM2URI && opts.KeyTransport != encSM2EncryptURI {
			return nil, errs.Detail(ErrUnsupported, "SM2 keys require SM2 key transport | SM2 密钥需要使用 SM2 密钥传输")
		}
		cek, err = randomBytes(spec.keyLen)
		if err != nil {
			return nil, err
		}
		wrapped, err := guomi.Encrypt(k, cek)
		if err != nil {
			return nil, errs.Wrap(err, ErrEncrypt)
		}
		encKey = buildEncryptedKey(prefix, dsPrefix, defaultSM2KeyTransportURI, wrapped, referenceID, opts)
	default:
		return nil, errs.Detail(ErrKeyMismatch, "unsupported encryption key type %T | 不支持的加密密钥类型 %T", key, key)
	}

	ciphertext, err := encryptBlock(spec, cek, plaintext)
	if err != nil {
		return nil, err
	}

	ed := newElement(prefix, "EncryptedData")
	ed.addNamespaceDecl(prefix, NamespaceXMLEnc)
	if encKey != nil {
		ed.addNamespaceDecl(dsPrefix, NamespaceXMLDSig)
	}
	if opts.Type != "" {
		ed.setAttr("", "Type", opts.Type)
	}
	if opts.MIMEType != "" {
		ed.setAttr("", "MIMEType", opts.MIMEType)
	}
	if referenceID != "" {
		ed.setAttr("", "Id", referenceID)
	}
	em := newElement(prefix, "EncryptionMethod")
	em.setAttr("", "Algorithm", spec.uri)
	ed.appendChild(em)
	if encKey != nil {
		keyInfo := newElement(dsPrefix, "KeyInfo")
		keyInfo.appendChild(encKey)
		ed.appendChild(keyInfo)
	}
	cipherData := newElement(prefix, "CipherData")
	cipherValue := newElement(prefix, "CipherValue")
	cipherValue.appendText(base64.StdEncoding.EncodeToString(ciphertext))
	cipherData.appendChild(cipherValue)
	ed.appendChild(cipherData)
	if opts.CarriedKeyName != "" {
		carried := newElement(prefix, "CarriedKeyName")
		carried.appendText(opts.CarriedKeyName)
		ed.appendChild(carried)
	}
	return ed, nil
}

// buildEncryptedKey constructs an EncryptedKey element. | buildEncryptedKey 构造 EncryptedKey
// 元素。
func buildEncryptedKey(prefix, dsPrefix, transportURI string, wrapped []byte, referenceID string, opts EncryptOptions) *xmlNode {
	ek := newElement(prefix, "EncryptedKey")
	em := newElement(prefix, "EncryptionMethod")
	em.setAttr("", "Algorithm", transportURI)
	if transportURI == encRSAOAEP11URI {
		dm := newElement(dsPrefix, "DigestMethod")
		dm.setAttr("", "Algorithm", digestSHA256URI)
		em.appendChild(dm)
		mgf := newElement("xenc11", "MGF")
		mgf.addNamespaceDecl("xenc11", NamespaceXMLEnc11)
		mgf.setAttr("", "Algorithm", "http://www.w3.org/2009/xmlenc11#mgf1sha256")
		em.appendChild(mgf)
	}
	ek.appendChild(em)
	cipherData := newElement(prefix, "CipherData")
	cipherValue := newElement(prefix, "CipherValue")
	cipherValue.appendText(base64.StdEncoding.EncodeToString(wrapped))
	cipherData.appendChild(cipherValue)
	ek.appendChild(cipherData)
	if referenceID != "" {
		list := newElement(prefix, "ReferenceList")
		ref := newElement(prefix, "DataReference")
		ref.setAttr("", "URI", "#"+referenceID)
		list.appendChild(ref)
		ek.appendChild(list)
	}
	if opts.KeyName != "" {
		keyInfo := newElement(dsPrefix, "KeyInfo")
		keyName := newElement(dsPrefix, "KeyName")
		keyName.appendText(opts.KeyName)
		keyInfo.appendChild(keyName)
		ek.appendChild(keyInfo)
	}
	if opts.CarriedKeyName != "" {
		carried := newElement(prefix, "CarriedKeyName")
		carried.appendText(opts.CarriedKeyName)
		ek.appendChild(carried)
	}
	return ek
}

// replaceDocumentNode substitutes replacement for target in its parent or at the document root. |
// replaceDocumentNode 在父节点或文档根处用 replacement 替换 target。
func replaceDocumentNode(doc *xmlDocument, target, replacement *xmlNode) {
	if target.parent == nil {
		for i, n := range doc.children {
			if n == target {
				doc.children[i] = replacement
				replacement.parent = nil
				doc.root = replacement
				return
			}
		}
		doc.root = replacement
		doc.children = append(doc.children, replacement)
		return
	}
	parent := target.parent
	for i, n := range parent.children {
		if n == target {
			parent.children[i] = replacement
			replacement.parent = parent
			return
		}
	}
}
