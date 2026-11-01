//go:build !xml_std

package xml

import "github.com/shibingli/ydx/errs"

func (l *lexer) bang(ev *event) error {
	b, err := l.mustPeek()
	if err != nil {
		return err
	}
	switch b {
	case '-':
		if err := l.s.advance(1); err != nil {
			return err
		}
		b, err = l.mustPeek()
		if err != nil {
			return err
		}
		if b != '-' {
			return l.syntax("invalid sequence <!- not part of <!--")
		}
		if err := l.s.advance(1); err != nil {
			return err
		}
		return l.comment(ev)
	case '[':
		if err := l.s.advance(1); err != nil {
			return err
		}
		for _, want := range []byte("CDATA[") {
			b, err = l.mustPeek()
			if err != nil {
				return err
			}
			if b != want {
				return l.syntax("invalid <![ sequence")
			}
			if err := l.s.advance(1); err != nil {
				return err
			}
		}
		return l.cdata(ev)
	default:
		return l.directive(ev)
	}
}

func (l *lexer) comment(ev *event) error {
	s := l.s
	buf := l.textBuf[:0]
	from := 0
	for {
		idx, err := s.findByteAt(from, '-')
		if err != nil {
			return err
		}
		if idx < 0 {
			return l.syntax("unexpected EOF in comment")
		}
		avail := s.available()
		buf = append(buf, avail[from:idx]...)
		if err := l.checkSize(len(buf)); err != nil {
			return err
		}
		if err := s.advance(idx - from); err != nil {
			return err
		}
		if err := s.ensure(3); err != nil {
			return err
		}
		a := s.available()
		if len(a) >= 3 && a[0] == '-' && a[1] == '-' && a[2] == '>' {
			if err := s.advance(3); err != nil {
				return err
			}
			l.textBuf = buf
			ev.kind = evComment
			ev.data = buf
			return nil
		}
		if len(a) >= 2 && a[0] == '-' && a[1] == '-' {
			return l.syntax(`invalid sequence "--" not allowed in comments`)
		}
		buf = append(buf, '-')
		if err := s.advance(1); err != nil {
			return err
		}
		from = 0
	}
}

func (l *lexer) cdata(ev *event) error {
	s := l.s
	buf := l.textBuf[:0]
	from := 0
	for {
		idx, err := s.findAny2At(from, ']', '\r')
		if err != nil {
			return err
		}
		if idx < 0 {
			avail := s.available()
			buf = append(buf, avail[from:]...)
			if err := l.checkSize(len(buf)); err != nil {
				return err
			}
			if err := s.advance(len(avail) - from); err != nil {
				return err
			}
			if s.r == nil || s.eof {
				return l.syntax("unexpected EOF in CDATA section")
			}
			from = 0
			continue
		}
		avail := s.available()
		buf = append(buf, avail[from:idx]...)
		if err := l.checkSize(len(buf)); err != nil {
			return err
		}
		if err := s.advance(idx - from); err != nil {
			return err
		}
		avail = s.available()
		if avail[0] == ']' {
			if err := s.ensure(3); err != nil {
				return err
			}
			a := s.available()
			if len(a) >= 3 && a[0] == ']' && a[1] == ']' && a[2] == '>' {
				if err := s.advance(3); err != nil {
					return err
				}
				l.textBuf = buf
				if msg := validateXMLText(buf); msg != "" {
					return l.syntax(msg)
				}
				ev.kind = evText
				ev.data = buf
				return nil
			}
			buf = append(buf, ']')
			if err := s.advance(1); err != nil {
				return err
			}
		} else {
			buf = append(buf, '\n')
			if err := s.advance(1); err != nil {
				return err
			}
			if err := s.ensure(1); err != nil {
				return err
			}
			if s.end > s.pos && s.data[s.pos] == '\n' {
				if err := s.advance(1); err != nil {
					return err
				}
			}
		}
		from = 0
	}
}

func (l *lexer) procInst(ev *event) error {
	s := l.s
	target, ok, err := l.readNameString()
	if err != nil {
		return err
	}
	if !ok {
		return l.syntax("expected target name after <?")
	}
	if err := l.skipSpace(); err != nil {
		return err
	}
	buf := l.textBuf[:0]
	from := 0
	for {
		idx, err := s.findByteAt(from, '?')
		if err != nil {
			return err
		}
		if idx < 0 {
			return l.syntax("unexpected EOF in processing instruction")
		}
		avail := s.available()
		buf = append(buf, avail[from:idx]...)
		if err := l.checkSize(len(buf)); err != nil {
			return err
		}
		if err := s.advance(idx - from); err != nil {
			return err
		}
		if err := s.ensure(2); err != nil {
			return err
		}
		a := s.available()
		if len(a) >= 2 && a[0] == '?' && a[1] == '>' {
			if err := s.advance(2); err != nil {
				return err
			}
			l.textBuf = buf
			ev.kind = evProcInst
			ev.target = target
			ev.data = buf
			return nil
		}
		buf = append(buf, '?')
		if err := s.advance(1); err != nil {
			return err
		}
		from = 0
	}
}

func (l *lexer) directive(ev *event) error {
	buf := l.textBuf[:0]
	var quote byte
	depth := 0
	for {
		b, err := l.mustReadByte()
		if err != nil {
			return err
		}
		if quote == 0 && b == '>' && depth == 0 {
			break
		}
		switch {
		case b == quote:
			quote = 0
		case quote != 0:
		case b == '\'' || b == '"':
			quote = b
		case b == '>':
			depth--
		case b == '<':
			matched, err := l.consumeSeq("!--")
			if err != nil {
				return err
			}
			if matched {
				if err := l.skipUntil("-->"); err != nil {
					return err
				}
				buf = append(buf, ' ')
				continue
			}
			depth++
		}
		buf = append(buf, b)
		if err := l.checkSize(len(buf)); err != nil {
			return err
		}
	}
	l.textBuf = buf
	l.parseDTD(buf)
	ev.kind = evDirective
	ev.data = buf
	return nil
}

func (l *lexer) readNameString() (string, bool, error) {
	b, ok, err := l.readNameBytes()
	if err != nil || !ok {
		return "", ok, err
	}
	return l.intern(b), true, nil
}

// readName reads one qualified name and splits it into prefix and local parts. | readName 读取一个
// 限定名并切分为前缀与本地名。
func (l *lexer) readName() (Name, bool, error) {
	b, ok, err := l.readNameBytes()
	if err != nil || !ok {
		return Name{}, ok, err
	}
	rn, ok := splitRawName(b)
	if !ok {
		return Name{}, false, l.syntax("invalid XML name: " + string(b))
	}
	if len(rn.space) == 0 {
		return Name{Local: l.intern(rn.local)}, true, nil
	}
	return Name{Space: l.intern(rn.space), Local: l.intern(rn.local)}, true, nil
}

// readNameBytes reads the raw bytes of one XML name without consuming the delimiter. | readNameBytes
// 读取一个 XML 名称的原始字节，不消费其后的分隔符。
func (l *lexer) readNameBytes() ([]byte, bool, error) {
	s := l.s
	if err := s.ensure(1); err != nil {
		return nil, false, err
	}
	if s.end == s.pos {
		return nil, false, nil
	}
	avail := s.available()
	i := 0
	for i < len(avail) && isNameScanByte(avail[i]) {
		i++
	}
	if i < len(avail) || s.eof || s.r == nil {
		if i == 0 {
			return nil, false, nil
		}
		name := avail[:i]
		if err := s.advance(i); err != nil {
			return nil, false, err
		}
		if !isNameBytes(name) {
			return nil, false, l.syntax("invalid XML name: " + string(name))
		}
		return name, true, nil
	}
	buf := append([]byte(nil), avail[:i]...)
	if err := s.advance(i); err != nil {
		return nil, false, err
	}
	for {
		if err := s.ensure(64); err != nil {
			return nil, false, err
		}
		avail = s.available()
		j := 0
		for j < len(avail) && isNameScanByte(avail[j]) {
			j++
		}
		buf = append(buf, avail[:j]...)
		if len(buf) > l.tokenLimit() {
			return nil, false, errs.Detail(ErrLimit, "name exceeds MaxTokenSize | 名称超过 MaxTokenSize")
		}
		if err := s.advance(j); err != nil {
			return nil, false, err
		}
		if j < len(avail) || s.eof || s.r == nil {
			break
		}
	}
	if !isNameBytes(buf) {
		return nil, false, l.syntax("invalid XML name: " + string(buf))
	}
	return buf, true, nil
}

func (l *lexer) attrValue() ([]byte, error) {
	s := l.s
	if err := s.ensure(1); err != nil {
		return nil, err
	}
	if s.end == s.pos {
		return nil, l.syntax("unexpected EOF in attribute")
	}
	q := s.data[s.pos]
	if q != '"' && q != '\'' {
		if l.d.Strict {
			return nil, l.syntax("unquoted or missing attribute value in element")
		}
		buf := l.valBuf[:0]
		for {
			if err := s.ensure(1); err != nil {
				return nil, err
			}
			if s.end == s.pos {
				break
			}
			c := s.data[s.pos]
			if !isUnquotedAttrByte(c) {
				break
			}
			buf = append(buf, c)
			if err := s.advance(1); err != nil {
				return nil, err
			}
		}
		l.valBuf = buf
		return buf, nil
	}
	if err := s.advance(1); err != nil {
		return nil, err
	}
	idx, err := s.findAny4At(0, q, '&', '\r', '<')
	if err != nil {
		return nil, err
	}
	if idx < 0 {
		return nil, l.syntax("unexpected EOF in attribute")
	}
	avail := s.available()
	if !s.owned && avail[idx] == q {
		val := avail[:idx]
		if err := s.advance(idx + 1); err != nil {
			return nil, err
		}
		if msg := validateXMLText(val); msg != "" {
			return nil, l.syntax(msg)
		}
		return val, nil
	}
	buf := l.valBuf[:0]
	from := 0
	for {
		avail = s.available()
		buf = append(buf, avail[from:idx]...)
		if err := l.checkSize(len(buf)); err != nil {
			return nil, err
		}
		if err := s.advance(idx - from); err != nil {
			return nil, err
		}
		avail = s.available()
		switch avail[0] {
		case q:
			if err := s.advance(1); err != nil {
				return nil, err
			}
			l.valBuf = buf
			if msg := validateXMLText(buf); msg != "" {
				return nil, l.syntax(msg)
			}
			return buf, nil
		case '&':
			buf, err = l.decodeEntity(buf)
			if err != nil {
				return nil, err
			}
			if err := l.checkSize(len(buf)); err != nil {
				return nil, err
			}
		case '\r':
			buf = append(buf, '\n')
			if err := s.advance(1); err != nil {
				return nil, err
			}
			if err := s.ensure(1); err != nil {
				return nil, err
			}
			if s.end > s.pos && s.data[s.pos] == '\n' {
				if err := s.advance(1); err != nil {
					return nil, err
				}
			}
		case '<':
			return nil, l.syntax("unescaped < inside quoted string")
		}
		from = 0
		idx, err = s.findAny4At(0, q, '&', '\r', '<')
		if err != nil {
			return nil, err
		}
		if idx < 0 {
			return nil, l.syntax("unexpected EOF in attribute")
		}
	}
}

func isUnquotedAttrByte(c byte) bool {
	return 'a' <= c && c <= 'z' || 'A' <= c && c <= 'Z' ||
		'0' <= c && c <= '9' || c == '_' || c == ':' || c == '-'
}
