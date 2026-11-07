package xmlsig

import (
	"github.com/shibingli/ydx/base64"
	"github.com/shibingli/ydx/errs"
)

// maxEncryptedKeyNesting bounds recursive EncryptedKey resolution. | maxEncryptedKeyNesting 限制
// EncryptedKey 递归解析深度。
const maxEncryptedKeyNesting = 4

// parsedEncryptedData is the decoded form of an EncryptedData element. | parsedEncryptedData 是
// EncryptedData 元素的解码形式。
type parsedEncryptedData struct {
	node           *xmlNode
	id             string
	algorithm      string
	cipherValue    []byte
	keyNames       []string
	encryptedKeys  []*parsedEncryptedKey
	carriedKeyName string
}

// parsedEncryptedKey is the decoded form of an EncryptedKey element. | parsedEncryptedKey 是
// EncryptedKey 元素的解码形式。
type parsedEncryptedKey struct {
	node           *xmlNode
	id             string
	recipient      string
	algorithm      string
	digestURI      string
	mgfURI         string
	cipherValue    []byte
	keyNames       []string
	nestedKeys     []*parsedEncryptedKey
	dataRefs       []string
	carriedKeyName string
}

// parseEncryptedData decodes a standalone EncryptedData element. | parseEncryptedData 解码独立的
// EncryptedData 元素。
func parseEncryptedData(n *xmlNode, maxBytes int64) (*parsedEncryptedData, error) {
	if n == nil || n.kind != elementNode || n.local != "EncryptedData" {
		return nil, errs.Detail(ErrMalformed, "not an EncryptedData element | 不是 EncryptedData 元素")
	}
	if ns := elementNamespace(n); ns != NamespaceXMLEnc {
		return nil, errs.Detail(ErrMalformed, "EncryptedData uses namespace %q | EncryptedData 使用了命名空间 %q", ns, ns)
	}
	out := &parsedEncryptedData{node: n}
	out.id, _ = n.attrValue("", "Id")
	for _, child := range n.children {
		if child.kind != elementNode {
			continue
		}
		switch {
		case child.local == "EncryptionMethod" && elementNamespace(child) == NamespaceXMLEnc:
			if out.algorithm != "" {
				return nil, errs.Detail(ErrMalformed, "duplicate EncryptionMethod | EncryptionMethod 重复")
			}
			algorithm, err := requiredAttribute(child, "Algorithm")
			if err != nil {
				return nil, err
			}
			out.algorithm = algorithm
		case child.local == "CipherData" && elementNamespace(child) == NamespaceXMLEnc:
			if out.cipherValue != nil {
				return nil, errs.Detail(ErrMalformed, "duplicate CipherData | CipherData 重复")
			}
			value, err := parseCipherData(child, maxBytes)
			if err != nil {
				return nil, err
			}
			out.cipherValue = value
		case child.local == "KeyInfo" && elementNamespace(child) == NamespaceXMLDSig:
			keys, names, err := parseEncryptionKeyInfo(child, 1, maxBytes)
			if err != nil {
				return nil, err
			}
			out.encryptedKeys = append(out.encryptedKeys, keys...)
			out.keyNames = append(out.keyNames, names...)
		case child.local == "CarriedKeyName" && elementNamespace(child) == NamespaceXMLEnc:
			out.carriedKeyName = trimSpaceText(elementText(child))
		}
	}
	if out.algorithm == "" {
		return nil, errs.Detail(ErrMalformed, "EncryptedData has no EncryptionMethod | EncryptedData 缺少 EncryptionMethod")
	}
	if out.cipherValue == nil {
		return nil, errs.Detail(ErrMalformed, "EncryptedData has no CipherValue | EncryptedData 缺少 CipherValue")
	}
	return out, nil
}

// parseEncryptedKey decodes an EncryptedKey element. | parseEncryptedKey 解码 EncryptedKey 元素。
func parseEncryptedKey(n *xmlNode, depth int, maxBytes int64) (*parsedEncryptedKey, error) {
	if depth > maxEncryptedKeyNesting {
		return nil, errs.Detail(ErrLimit, "EncryptedKey nesting exceeds %d | EncryptedKey 嵌套超过 %d 层", maxEncryptedKeyNesting, maxEncryptedKeyNesting)
	}
	if n == nil || n.kind != elementNode || n.local != "EncryptedKey" {
		return nil, errs.Detail(ErrMalformed, "not an EncryptedKey element | 不是 EncryptedKey 元素")
	}
	if ns := elementNamespace(n); ns != NamespaceXMLEnc {
		return nil, errs.Detail(ErrMalformed, "EncryptedKey uses namespace %q | EncryptedKey 使用了命名空间 %q", ns, ns)
	}
	out := &parsedEncryptedKey{node: n}
	out.id, _ = n.attrValue("", "Id")
	out.recipient, _ = n.attrValue("", "Recipient")
	for _, child := range n.children {
		if child.kind != elementNode {
			continue
		}
		switch {
		case child.local == "EncryptionMethod" && elementNamespace(child) == NamespaceXMLEnc:
			if out.algorithm != "" {
				return nil, errs.Detail(ErrMalformed, "duplicate EncryptionMethod | EncryptionMethod 重复")
			}
			algorithm, err := requiredAttribute(child, "Algorithm")
			if err != nil {
				return nil, err
			}
			out.algorithm = algorithm
			digestURI, mgfURI, err := parseOAEPParams(child)
			if err != nil {
				return nil, err
			}
			out.digestURI, out.mgfURI = digestURI, mgfURI
		case child.local == "CipherData" && elementNamespace(child) == NamespaceXMLEnc:
			if out.cipherValue != nil {
				return nil, errs.Detail(ErrMalformed, "duplicate CipherData | CipherData 重复")
			}
			value, err := parseCipherData(child, maxBytes)
			if err != nil {
				return nil, err
			}
			out.cipherValue = value
		case child.local == "KeyInfo" && elementNamespace(child) == NamespaceXMLDSig:
			keys, names, err := parseEncryptionKeyInfo(child, depth+1, maxBytes)
			if err != nil {
				return nil, err
			}
			out.nestedKeys = append(out.nestedKeys, keys...)
			out.keyNames = append(out.keyNames, names...)
		case child.local == "ReferenceList" && elementNamespace(child) == NamespaceXMLEnc:
			refs, err := parseReferenceList(child)
			if err != nil {
				return nil, err
			}
			out.dataRefs = append(out.dataRefs, refs...)
		case child.local == "CarriedKeyName" && elementNamespace(child) == NamespaceXMLEnc:
			out.carriedKeyName = trimSpaceText(elementText(child))
		}
	}
	if out.algorithm == "" {
		return nil, errs.Detail(ErrMalformed, "EncryptedKey has no EncryptionMethod | EncryptedKey 缺少 EncryptionMethod")
	}
	if out.cipherValue == nil {
		return nil, errs.Detail(ErrMalformed, "EncryptedKey has no CipherValue | EncryptedKey 缺少 CipherValue")
	}
	return out, nil
}

// parseEncryptionKeyInfo decodes EncryptedKey and KeyName children of a KeyInfo element. |
// parseEncryptionKeyInfo 解码 KeyInfo 中的 EncryptedKey 与 KeyName 子元素。
func parseEncryptionKeyInfo(ki *xmlNode, depth int, maxBytes int64) ([]*parsedEncryptedKey, []string, error) {
	var (
		keys  []*parsedEncryptedKey
		names []string
	)
	for _, child := range ki.children {
		if child.kind != elementNode {
			continue
		}
		switch {
		case child.local == "EncryptedKey" && elementNamespace(child) == NamespaceXMLEnc:
			key, err := parseEncryptedKey(child, depth, maxBytes)
			if err != nil {
				return nil, nil, err
			}
			keys = append(keys, key)
		case child.local == "KeyName" && elementNamespace(child) == NamespaceXMLDSig:
			names = append(names, trimSpaceText(elementText(child)))
		case child.local == "RetrievalMethod":
			return nil, nil, errs.Detail(ErrUnsupported, "KeyInfo RetrievalMethod is not supported | 不支持 KeyInfo RetrievalMethod")
		}
	}
	return keys, names, nil
}

// parseCipherData returns the CipherValue of a CipherData element. CipherReference is rejected
// because external cipher references are never fetched. | parseCipherData 返回 CipherData 的
// CipherValue。外部 CipherReference 一律拒绝。
func parseCipherData(n *xmlNode, maxBytes int64) ([]byte, error) {
	var value *xmlNode
	for _, child := range n.children {
		if child.kind != elementNode {
			continue
		}
		switch {
		case child.local == "CipherValue" && elementNamespace(child) == NamespaceXMLEnc:
			if value != nil {
				return nil, errs.Detail(ErrMalformed, "duplicate CipherValue | CipherValue 重复")
			}
			value = child
		case child.local == "CipherReference":
			return nil, errs.Detail(ErrUnsupported, "CipherReference is not supported | 不支持 CipherReference")
		}
	}
	if value == nil {
		return nil, errs.Detail(ErrMalformed, "CipherData has no CipherValue | CipherData 缺少 CipherValue")
	}
	return decodeCipherValue(value, maxBytes)
}

// decodeCipherValue decodes base64 ciphertext and enforces maxBytes. | decodeCipherValue 解码 base64
// 密文并执行 maxBytes 限制。
func decodeCipherValue(n *xmlNode, maxBytes int64) ([]byte, error) {
	text := stripXMLWhitespace(elementText(n))
	if maxBytes > 0 && int64(len(text)) > maxBytes*4/3+8 {
		return nil, errs.Detail(ErrLimit, "ciphertext exceeds %d bytes | 密文超过 %d 字节", maxBytes, maxBytes)
	}
	data, err := base64.StdEncoding.DecodeString(text)
	if err != nil {
		return nil, errs.WrapDetail(err, ErrMalformed, "invalid CipherValue base64 | CipherValue 的 base64 非法")
	}
	if maxBytes > 0 && int64(len(data)) > maxBytes {
		return nil, errs.Detail(ErrLimit, "ciphertext exceeds %d bytes | 密文超过 %d 字节", maxBytes, maxBytes)
	}
	if len(data) == 0 {
		return nil, errs.Detail(ErrMalformed, "empty CipherValue | CipherValue 为空")
	}
	return data, nil
}

// parseReferenceList collects DataReference URIs. | parseReferenceList 收集 DataReference URI。
func parseReferenceList(n *xmlNode) ([]string, error) {
	var out []string
	for _, child := range n.children {
		if child.kind != elementNode {
			continue
		}
		if child.local != "DataReference" || elementNamespace(child) != NamespaceXMLEnc {
			continue
		}
		uri, ok := child.attrValue("", "URI")
		if !ok || uri == "" {
			return nil, errs.Detail(ErrMalformed, "DataReference has no URI | DataReference 缺少 URI")
		}
		out = append(out, uri)
	}
	return out, nil
}

// parseOAEPParams reads the optional DigestMethod and MGF parameters of an RSA-OAEP
// EncryptionMethod. | parseOAEPParams 读取 RSA-OAEP EncryptionMethod 中可选的 DigestMethod 与 MGF
// 参数。
func parseOAEPParams(method *xmlNode) (string, string, error) {
	var digestURI, mgfURI string
	for _, child := range method.children {
		if child.kind != elementNode {
			continue
		}
		switch {
		case child.local == "DigestMethod" && elementNamespace(child) == NamespaceXMLDSig:
			uri, err := requiredAttribute(child, "Algorithm")
			if err != nil {
				return "", "", err
			}
			digestURI = uri
		case child.local == "MGF" && elementNamespace(child) == NamespaceXMLEnc11:
			uri, err := requiredAttribute(child, "Algorithm")
			if err != nil {
				return "", "", err
			}
			mgfURI = uri
		}
	}
	return digestURI, mgfURI, nil
}

// collectExternalEncryptedKeys returns EncryptedKey elements that are not nested inside an
// EncryptedData element. | collectExternalEncryptedKeys 返回未嵌套在 EncryptedData 内的 EncryptedKey
// 元素。
func collectExternalEncryptedKeys(root *xmlNode, maxBytes int64) []*parsedEncryptedKey {
	var keys []*parsedEncryptedKey
	var walk func(*xmlNode)
	walk = func(n *xmlNode) {
		if n.kind != elementNode {
			return
		}
		ns := elementNamespace(n)
		if n.local == "EncryptedData" && ns == NamespaceXMLEnc {
			return
		}
		if n.local == "EncryptedKey" && ns == NamespaceXMLEnc {
			key, err := parseEncryptedKey(n, 1, maxBytes)
			if err == nil {
				keys = append(keys, key)
			}
			return
		}
		for _, child := range n.children {
			walk(child)
		}
	}
	walk(root)
	return keys
}
