package xmlsig

import (
	"strings"

	"github.com/shibingli/ydx/base64"
	"github.com/shibingli/ydx/errs"
)

// resolvedReference is the element selected by a Reference URI. | resolvedReference 是 Reference
// URI 选中的元素。
type resolvedReference struct {
	node         *xmlNode
	documentMode bool
	id           string
}

// resolveReferenceURI resolves the supported same-document reference forms. | resolveReferenceURI
// 解析支持的本文档引用形式。
func resolveReferenceURI(root *xmlNode, uri string) (*resolvedReference, error) {
	switch {
	case uri == "":
		return &resolvedReference{node: root, documentMode: true}, nil
	case uri == "#xpointer(/)":
		return &resolvedReference{node: root, documentMode: true}, nil
	case strings.HasPrefix(uri, "#xpointer(id(") && strings.HasSuffix(uri, "))"):
		inner := strings.TrimSuffix(strings.TrimPrefix(uri, "#xpointer(id("), "))")
		id := unquoteXPointerID(inner)
		if id == "" {
			return nil, errs.Detail(ErrReference, "empty xpointer ID | xpointer ID 为空")
		}
		n, err := findElementByID(root, id)
		if err != nil {
			return nil, err
		}
		return &resolvedReference{node: n, id: id}, nil
	case strings.HasPrefix(uri, "#xpointer("):
		return nil, errs.Detail(ErrUnsupported, "xpointer expression %q is not supported | 不支持 xpointer 表达式 %q", uri, uri)
	case strings.HasPrefix(uri, "#"):
		id := uri[1:]
		if id == "" {
			return nil, errs.Detail(ErrReference, "empty reference fragment | 引用片段为空")
		}
		n, err := findElementByID(root, id)
		if err != nil {
			return nil, err
		}
		return &resolvedReference{node: n, id: id}, nil
	default:
		return nil, errs.Detail(ErrReference, "external reference %q is not supported | 不支持外部引用 %q", uri, uri)
	}
}

// unquoteXPointerID strips optional single or double quotes. | unquoteXPointerID 去除可选的单引号
// 或双引号。
func unquoteXPointerID(s string) string {
	if len(s) >= 2 {
		if (s[0] == '\'' && s[len(s)-1] == '\'') || (s[0] == '"' && s[len(s)-1] == '"') {
			return s[1 : len(s)-1]
		}
	}
	return s
}

// canonicalizeReferenceInput applies the Reference transforms in order and returns the octets to
// digest. The signature element is removed wherever the enveloped-signature transform appears. |
// canonicalizeReferenceInput 按顺序应用 Reference 变换并返回待摘要的八位组。出现
// enveloped-signature 变换时会移除签名元素。
func canonicalizeReferenceInput(doc *xmlDocument, ref *parsedReference, res *resolvedReference, signature *xmlNode) ([]byte, error) {
	var (
		data     []byte
		haveData bool
		exclude  *xmlNode
		c14nDone bool
	)
	for _, tr := range ref.transforms {
		switch tr.algorithm {
		case transformEnvelopedURI:
			if c14nDone {
				return nil, errs.Detail(ErrMalformed, "the enveloped-signature transform must precede canonicalization | enveloped-signature 变换必须位于规范化之前")
			}
			exclude = signature
		case transformBase64URI:
			var input []byte
			if haveData {
				input = data
			} else {
				input = []byte(elementTextExcluding(res.node, exclude))
			}
			decoded, err := base64.StdEncoding.DecodeString(stripXMLWhitespace(string(input)))
			if err != nil {
				return nil, errs.WrapDetail(err, ErrReference, "invalid base64 transform input | base64 变换输入非法")
			}
			data = decoded
			haveData = true
		default:
			if c14nDone {
				return nil, errs.Detail(ErrMalformed, "only the base64 transform may follow canonicalization | 规范化之后只允许 base64 变换")
			}
			opts := CanonicalizeOptions{}
			if tr.c14nOpts != nil {
				opts = *tr.c14nOpts
			}
			c := newCanonicalizer(opts)
			c.exclude = exclude
			if res.documentMode {
				data = c.canonicalizeDocument(doc)
			} else {
				data = c.canonicalizeSubtree(res.node)
			}
			haveData = true
			c14nDone = true
		}
	}
	if !haveData {
		c := newCanonicalizer(CanonicalizeOptions{})
		c.exclude = exclude
		if res.documentMode {
			data = c.canonicalizeDocument(doc)
		} else {
			data = c.canonicalizeSubtree(res.node)
		}
	}
	return data, nil
}

// elementTextExcluding returns descendant text with an excluded element subtree removed. |
// elementTextExcluding 返回后代文本，并排除指定元素子树。
func elementTextExcluding(n *xmlNode, exclude *xmlNode) string {
	var b strings.Builder
	var walk func(*xmlNode)
	walk = func(cur *xmlNode) {
		if cur == exclude {
			return
		}
		switch cur.kind {
		case textNode:
			b.Write(cur.data)
		case elementNode:
			for _, c := range cur.children {
				walk(c)
			}
		}
	}
	walk(n)
	return b.String()
}
