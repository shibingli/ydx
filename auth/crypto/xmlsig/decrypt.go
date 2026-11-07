package xmlsig

import (
	"crypto/rand"
	"crypto/rsa"

	"github.com/shibingli/ydx/errs"
	"github.com/shibingli/ydx/guomi"
)

// mgf1SHA256URI is the MGF1 with SHA-256 algorithm URI. | mgf1SHA256URI 是使用 SHA-256 的 MGF1
// 算法 URI。
const mgf1SHA256URI = "http://www.w3.org/2009/xmlenc11#mgf1sha256"

// defaultKeyTransportURIs is the key-transport allowlist used when the caller supplies none.
// RSA PKCS#1 v1.5 is deliberately absent and must be enabled explicitly. | defaultKeyTransportURIs
// 是调用方未提供时使用的密钥传输允许列表。RSA PKCS#1 v1.5 被刻意排除，必须显式启用。
var defaultKeyTransportURIs = []string{
	encRSAOAEPURI, encRSAOAEP11URI, encSM2URI, encSM2EncryptURI,
	encAES128KWURI, encAES192KWURI, encAES256KWURI,
}

// DecryptOptions controls XML decryption. | DecryptOptions 控制 XML 解密。
type DecryptOptions struct {
	// AllowedAlgorithms restricts data-encryption URIs. Empty selects the package defaults. |
	// AllowedAlgorithms 限制数据加密 URI；为空时使用包默认值。
	AllowedAlgorithms []string
	// AllowedKeyTransports restricts key-transport and key-wrap URIs. Empty selects the package
	// defaults, which exclude RSA PKCS#1 v1.5. Prefer RSA-OAEP or RSA-OAEP-256; PKCS#1 v1.5 is
	// vulnerable to Bleichenbacher-style padding oracles and only for legacy interoperability. |
	// AllowedKeyTransports 限制密钥传输与密钥包装 URI；为空时使用包默认值，其中不含 RSA PKCS#1 v1.5。
	// 优先使用 RSA-OAEP 或 RSA-OAEP-256；PKCS#1 v1.5 存在 Bleichenbacher 式填充预言风险，仅用于
	// 遗留互操作。
	AllowedKeyTransports []string
	// AllowRSA1_5 enables decryption of RSA PKCS#1 v1.5 key transport. Only enable it for legacy
	// senders; all padding failures are reported as ErrDecrypt. | AllowRSA1_5 启用 RSA PKCS#1 v1.5
	// 密钥传输解密。仅对遗留发送方启用；所有填充失败统一报告 ErrDecrypt。
	AllowRSA1_5 bool
	// MaxBytes bounds ciphertext and plaintext sizes. Zero selects 64 MiB. | MaxBytes 约束密文与
	// 明文大小；零值表示 64 MiB。
	MaxBytes int64
	// KeyName selects among multiple EncryptedKey candidates by ds:KeyName. Empty disables the
	// filter. | KeyName 依据 ds:KeyName 在多个 EncryptedKey 候选间选择；为空时不筛选。
	KeyName string
}

// Decrypt decrypts an EncryptedData element, either standalone or the single top-level
// EncryptedData in a document, and returns the plaintext bytes. | Decrypt 解密独立的 EncryptedData
// 元素或文档中唯一的顶层 EncryptedData，并返回明文字节。
func Decrypt(data []byte, key any, opts DecryptOptions) ([]byte, error) {
	if opts.MaxBytes <= 0 {
		opts.MaxBytes = defaultMaxPayload
	}
	doc, err := parseXML(data)
	if err != nil {
		return nil, err
	}
	candidates := topLevelEncryptedData(doc.root)
	if len(candidates) != 1 {
		return nil, errs.Detail(ErrMalformed, "expected exactly one EncryptedData, found %d | 期望且仅期望一个 EncryptedData，实际 %d 个", len(candidates), len(candidates))
	}
	ed, err := parseEncryptedData(candidates[0], opts.MaxBytes)
	if err != nil {
		return nil, err
	}
	return decryptData(doc, ed, key, opts)
}

// DecryptElement decrypts the single top-level EncryptedData in data and replaces it with the
// decrypted XML element. The decrypted payload must be one well-formed element. | DecryptElement
// 解密 data 中唯一的顶层 EncryptedData，并用解出的 XML 元素替换它。解出的载荷必须是一个良构元素。
func DecryptElement(data []byte, key any, opts DecryptOptions) ([]byte, error) {
	if opts.MaxBytes <= 0 {
		opts.MaxBytes = defaultMaxPayload
	}
	doc, err := parseXML(data)
	if err != nil {
		return nil, err
	}
	candidates := topLevelEncryptedData(doc.root)
	if len(candidates) != 1 {
		return nil, errs.Detail(ErrMalformed, "expected exactly one EncryptedData, found %d | 期望且仅期望一个 EncryptedData，实际 %d 个", len(candidates), len(candidates))
	}
	target := candidates[0]
	ed, err := parseEncryptedData(target, opts.MaxBytes)
	if err != nil {
		return nil, err
	}
	plaintext, err := decryptData(doc, ed, key, opts)
	if err != nil {
		return nil, err
	}
	payload, err := parseXML(plaintext)
	if err != nil {
		return nil, errs.WrapDetail(err, ErrMalformed, "decrypted payload is not a well-formed element | 解密载荷不是良构元素")
	}
	replacement := payload.root
	replaceDocumentNode(doc, target, replacement)
	return serializeDocument(doc), nil
}

// topLevelEncryptedData returns EncryptedData elements not nested inside another EncryptedData. |
// topLevelEncryptedData 返回未嵌套在其它 EncryptedData 内的 EncryptedData 元素。
func topLevelEncryptedData(root *xmlNode) []*xmlNode {
	var out []*xmlNode
	var walk func(*xmlNode)
	walk = func(n *xmlNode) {
		if n.kind != elementNode {
			return
		}
		if n.local == "EncryptedData" && elementNamespace(n) == NamespaceXMLEnc {
			out = append(out, n)
			return
		}
		for _, child := range n.children {
			walk(child)
		}
	}
	walk(root)
	return out
}

// decryptData resolves the content-encryption key and decrypts one EncryptedData element. |
// decryptData 解析内容加密密钥并解密一个 EncryptedData 元素。
func decryptData(doc *xmlDocument, ed *parsedEncryptedData, key any, opts DecryptOptions) ([]byte, error) {
	spec, err := blockCipherSpecForURI(ed.algorithm, opts.AllowedAlgorithms)
	if err != nil {
		return nil, err
	}
	if int64(len(ed.cipherValue)) > opts.MaxBytes {
		return nil, errs.Detail(ErrLimit, "ciphertext exceeds %d bytes | 密文超过 %d 字节", opts.MaxBytes, opts.MaxBytes)
	}
	encryptedKey, err := selectEncryptedKey(doc, ed, opts)
	if err != nil {
		return nil, err
	}
	var cek []byte
	if encryptedKey != nil {
		cek, err = resolveEncryptedKey(encryptedKey, key, opts, 0)
		if err != nil {
			return nil, err
		}
	} else {
		direct, ok := key.([]byte)
		if !ok {
			return nil, errs.Detail(ErrKeyRequired, "EncryptedData has no EncryptedKey and the key is not a content key | EncryptedData 不含 EncryptedKey，且密钥不是内容密钥")
		}
		cek = append([]byte(nil), direct...)
	}
	if len(cek) != spec.keyLen {
		return nil, errs.Detail(ErrKeyMismatch, "content key length %d does not match %s | 内容密钥长度 %d 与 %s 不匹配", len(cek), ed.algorithm, len(cek), ed.algorithm)
	}
	plaintext, err := decryptBlock(spec, cek, ed.cipherValue)
	if err != nil {
		return nil, err
	}
	if int64(len(plaintext)) > opts.MaxBytes {
		return nil, errs.Detail(ErrLimit, "plaintext exceeds %d bytes | 明文超过 %d 字节", opts.MaxBytes, opts.MaxBytes)
	}
	return plaintext, nil
}

// selectEncryptedKey chooses the unique EncryptedKey bound to ed, either inline in its KeyInfo or
// elsewhere in the document through ReferenceList or CarriedKeyName. | selectEncryptedKey 选择与 ed
// 绑定的唯一 EncryptedKey，它可位于 KeyInfo 内，也可通过 ReferenceList 或 CarriedKeyName 关联到
// 文档其它位置。
func selectEncryptedKey(doc *xmlDocument, ed *parsedEncryptedData, opts DecryptOptions) (*parsedEncryptedKey, error) {
	inline := filterEncryptedKeys(ed.encryptedKeys, opts.KeyName)
	var external []*parsedEncryptedKey
	for _, candidate := range collectExternalEncryptedKeys(doc.root, opts.MaxBytes) {
		if encryptedKeyMatches(candidate, ed, opts.KeyName) {
			external = append(external, candidate)
		}
	}
	total := len(inline) + len(external)
	if total == 0 {
		if opts.KeyName != "" && len(ed.encryptedKeys) > 0 {
			return nil, errs.Detail(ErrKeyMismatch, "no EncryptedKey matches KeyName %q | 没有 EncryptedKey 匹配 KeyName %q", opts.KeyName, opts.KeyName)
		}
		return nil, nil
	}
	if total > 1 {
		return nil, errs.Detail(ErrMalformed, "EncryptedData has %d matching EncryptedKey elements | EncryptedData 匹配到 %d 个 EncryptedKey", total, total)
	}
	if len(inline) == 1 {
		return inline[0], nil
	}
	return external[0], nil
}

// filterEncryptedKeys applies the optional ds:KeyName filter. | filterEncryptedKeys 应用可选的
// ds:KeyName 筛选。
func filterEncryptedKeys(keys []*parsedEncryptedKey, name string) []*parsedEncryptedKey {
	if name == "" {
		return keys
	}
	var out []*parsedEncryptedKey
	for _, key := range keys {
		for _, candidate := range key.keyNames {
			if candidate == name {
				out = append(out, key)
				break
			}
		}
	}
	return out
}

// encryptedKeyMatches reports whether an external EncryptedKey refers to ed. | encryptedKeyMatches
// 判断外部 EncryptedKey 是否指向 ed。
func encryptedKeyMatches(ek *parsedEncryptedKey, ed *parsedEncryptedData, keyName string) bool {
	if ed.id != "" && len(ek.dataRefs) > 0 {
		for _, ref := range ek.dataRefs {
			if ref == "#"+ed.id || ref == "#xpointer(id('"+ed.id+"'))" || ref == "#xpointer(id(\""+ed.id+"\"))" {
				return true
			}
		}
		return false
	}
	if ed.carriedKeyName != "" && ek.carriedKeyName == ed.carriedKeyName {
		return true
	}
	if keyName != "" {
		for _, candidate := range ek.keyNames {
			if candidate == keyName {
				return true
			}
		}
	}
	return false
}

// resolveEncryptedKey unwraps or decrypts one EncryptedKey and returns the transported key bytes.
// Nested EncryptedKey elements supply a key-encryption key to an outer AES key wrap. |
// resolveEncryptedKey 解包或解密一个 EncryptedKey 并返回传输的密钥字节。嵌套 EncryptedKey 为外层
// AES 密钥包装提供密钥加密密钥。
func resolveEncryptedKey(ek *parsedEncryptedKey, key any, opts DecryptOptions, depth int) ([]byte, error) {
	if depth > maxEncryptedKeyNesting {
		return nil, errs.Detail(ErrLimit, "EncryptedKey nesting exceeds %d | EncryptedKey 嵌套超过 %d 层", maxEncryptedKeyNesting, maxEncryptedKeyNesting)
	}
	if len(ek.nestedKeys) > 1 {
		return nil, errs.Detail(ErrMalformed, "EncryptedKey has %d nested EncryptedKey elements | EncryptedKey 含 %d 个嵌套 EncryptedKey", len(ek.nestedKeys), len(ek.nestedKeys))
	}
	if !allowedKeyTransport(ek.algorithm, opts) {
		return nil, errs.Detail(ErrAlgorithmNotAllowed, "key transport %q is not allowed | 密钥传输 %q 不被允许", ek.algorithm, ek.algorithm)
	}
	if _, wrapped := keyWrapKeySizes[ek.algorithm]; wrapped {
		var kek []byte
		if len(ek.nestedKeys) == 1 {
			nested, err := resolveEncryptedKey(ek.nestedKeys[0], key, opts, depth+1)
			if err != nil {
				return nil, err
			}
			kek = nested
		} else {
			direct, ok := key.([]byte)
			if !ok {
				return nil, errs.Detail(ErrKeyRequired, "AES key wrap requires a []byte KEK | AES 密钥包装需要 []byte KEK")
			}
			kek = direct
		}
		if _, err := keyWrapSizeFor(ek.algorithm, len(kek)); err != nil {
			return nil, err
		}
		return aesKeyUnwrap(kek, ek.cipherValue)
	}
	if len(ek.nestedKeys) != 0 {
		return nil, errs.Detail(ErrMalformed, "nested EncryptedKey requires an AES key-wrap outer method | 嵌套 EncryptedKey 要求外层使用 AES 密钥包装")
	}
	switch ek.algorithm {
	case encSM2URI, encSM2EncryptURI:
		priv, ok := key.(*guomi.PrivateKey)
		if !ok {
			return nil, errs.Detail(ErrKeyMismatch, "SM2 private key required | 需要 SM2 私钥")
		}
		plaintext, err := guomi.Decrypt(priv, ek.cipherValue)
		if err != nil {
			return nil, errs.Detail(ErrDecrypt, "SM2 key transport failed | SM2 密钥传输失败")
		}
		return plaintext, nil
	case encRSA15URI, encRSAOAEPURI, encRSAOAEP11URI:
		priv, ok := key.(*rsa.PrivateKey)
		if !ok {
			return nil, errs.Detail(ErrKeyMismatch, "RSA private key required | 需要 RSA 私钥")
		}
		return decryptRSAKey(priv, ek)
	default:
		return nil, errs.Detail(ErrUnsupported, "key transport %q is not supported | 不支持密钥传输 %q", ek.algorithm, ek.algorithm)
	}
}

// allowedKeyTransport applies the key-transport allowlist and the RSA1_5 opt-in. |
// allowedKeyTransport 应用密钥传输允许列表与 RSA1_5 显式启用规则。
func allowedKeyTransport(uri string, opts DecryptOptions) bool {
	if uri == encRSA15URI {
		if !opts.AllowRSA1_5 {
			return false
		}
		if len(opts.AllowedKeyTransports) == 0 {
			return true
		}
	}
	return algorithmAllowed(uri, opts.AllowedKeyTransports, defaultKeyTransportURIs)
}

// decryptRSAKey decrypts an RSA-transported key. All padding failures collapse to ErrDecrypt. |
// decryptRSAKey 解密 RSA 传输的密钥。所有填充失败统一返回 ErrDecrypt。
func decryptRSAKey(priv *rsa.PrivateKey, ek *parsedEncryptedKey) ([]byte, error) {
	switch ek.algorithm {
	case encRSA15URI:
		plaintext, err := rsa.DecryptPKCS1v15(rand.Reader, priv, ek.cipherValue)
		if err != nil {
			return nil, errs.Detail(ErrDecrypt, "RSA PKCS#1 v1.5 key transport failed | RSA PKCS#1 v1.5 密钥传输失败")
		}
		return plaintext, nil
	case encRSAOAEPURI:
		if ek.digestURI != "" && ek.digestURI != digestSHA1URI {
			return nil, errs.Detail(ErrUnsupported, "RSA-OAEP requires SHA-1 DigestMethod | RSA-OAEP 要求 SHA-1 DigestMethod")
		}
		if ek.mgfURI != "" && ek.mgfURI != "http://www.w3.org/2007/05/xmldsig-more#mgf1sha1" {
			return nil, errs.Detail(ErrUnsupported, "RSA-OAEP requires MGF1 with SHA-1 | RSA-OAEP 要求 SHA-1 的 MGF1")
		}
		plaintext, err := rsa.DecryptOAEP(newSHA1Hash(), rand.Reader, priv, ek.cipherValue, nil)
		if err != nil {
			return nil, errs.Detail(ErrDecrypt, "RSA-OAEP key transport failed | RSA-OAEP 密钥传输失败")
		}
		return plaintext, nil
	case encRSAOAEP11URI:
		if ek.digestURI != "" && ek.digestURI != digestSHA256URI && ek.digestURI != digestSHA256AltURI {
			return nil, errs.Detail(ErrUnsupported, "RSA-OAEP-256 requires SHA-256 DigestMethod | RSA-OAEP-256 要求 SHA-256 DigestMethod")
		}
		if ek.mgfURI != "" && ek.mgfURI != mgf1SHA256URI {
			return nil, errs.Detail(ErrUnsupported, "RSA-OAEP-256 requires MGF1 with SHA-256 | RSA-OAEP-256 要求 SHA-256 的 MGF1")
		}
		plaintext, err := rsa.DecryptOAEP(newSHA256Hash(), rand.Reader, priv, ek.cipherValue, nil)
		if err != nil {
			return nil, errs.Detail(ErrDecrypt, "RSA-OAEP-256 key transport failed | RSA-OAEP-256 密钥传输失败")
		}
		return plaintext, nil
	default:
		return nil, errs.Detail(ErrUnsupported, "key transport %q is not supported | 不支持密钥传输 %q", ek.algorithm, ek.algorithm)
	}
}
