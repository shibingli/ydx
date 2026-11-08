package xml

import "io"

// Valid reports whether data is a well-formed XML document. It is stricter than Token-based
// parsing in two ways required by the XML specification: it rejects duplicate attributes (by
// expanded name) and non-whitespace character data outside the single root element. | Valid 判断
// data 是否为良构 XML 文档。它比基于 Token 的解析更严格地执行 XML 规范的两点要求：拒绝重复属性
// （按展开后的名称）与单一根元素之外的非空白字符数据。
func Valid(data []byte) bool {
	d := NewDecoderBytes(data)
	depth := 0
	rootSeen := false
	rootClosed := false
	bomAllowed := true
	var ev event
	for {
		err := d.nextEvent(&ev)
		if err == io.EOF {
			break
		}
		if err != nil {
			return false
		}
		switch ev.kind {
		case evStart:
			if rootClosed {
				return false
			}
			if depth == 0 {
				if rootSeen {
					return false
				}
				rootSeen = true
				bomAllowed = false
			}
			for i := range ev.attrs {
				for j := i + 1; j < len(ev.attrs); j++ {
					if ev.attrs[i].Name == ev.attrs[j].Name {
						return false
					}
				}
			}
			depth++
		case evEnd:
			depth--
			if depth == 0 {
				rootClosed = true
			}
		case evText:
			if depth == 0 {
				data := ev.data
				if isAllXMLSpace(data) {
					continue
				}
				// A UTF-8 BOM may precede the prolog, including whitespace that follows it in
				// the same character-data token. | UTF-8 BOM 可以位于序言之前，其后同一字符数据
				// token 中的空白同样合法。
				if bomAllowed && d.tokenStartOffset() == 0 {
					if rest, ok := trimUTF8BOM(data); ok && isAllXMLSpace(rest) {
						bomAllowed = false
						continue
					}
				}
				return false
			}
		}
	}
	return rootSeen && rootClosed && depth == 0
}

func isAllXMLSpace(b []byte) bool {
	for _, c := range b {
		if c != ' ' && c != '\t' && c != '\r' && c != '\n' {
			return false
		}
	}
	return true
}

// trimUTF8BOM reports whether b starts with a UTF-8 byte order mark and returns the remainder. |
// trimUTF8BOM 判断 b 是否以 UTF-8 字节顺序标记开头，并返回剩余字节。
func trimUTF8BOM(b []byte) ([]byte, bool) {
	if len(b) >= 3 && b[0] == 0xEF && b[1] == 0xBB && b[2] == 0xBF {
		return b[3:], true
	}
	return b, false
}
