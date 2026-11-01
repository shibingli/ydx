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
				if isAllXMLSpace(ev.data) {
					continue
				}
				if bomAllowed && isUTF8BOM(ev.data) {
					bomAllowed = false
					continue
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

func isUTF8BOM(b []byte) bool {
	return len(b) == 3 && b[0] == 0xEF && b[1] == 0xBB && b[2] == 0xBF
}
