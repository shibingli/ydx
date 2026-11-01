//go:build !xml_std

package xml

import (
	"bytes"
	"io"
	"unsafe"

	"github.com/shibingli/ydx/errs"
)

// rawName is a qualified name split into its optional prefix and local part. | rawName 是切分为
// 可选前缀与本地名的限定名。
type rawName struct {
	space []byte
	local []byte
}

// lexer tokenizes XML input from a source. | lexer 从 source 对 XML 输入进行词法分析。
type lexer struct {
	s *source
	d *Decoder

	names    map[string]string
	entities map[string]string

	pendingEnd Name

	textBuf []byte
	valBuf  []byte
	attrBuf []Attr

	entityBudget int64
	pendingEndOK bool

	budgetInit bool
}

func (l *lexer) syntax(msg string) error {
	line, _ := l.s.posLine()
	return &SyntaxError{Msg: msg, Line: line}
}

func (l *lexer) tokenLimit() int { return l.d.limits().MaxTokenSize }

func (l *lexer) checkSize(n int) error {
	if n > l.tokenLimit() {
		return errs.Detail(ErrLimit, "token exceeds MaxTokenSize | token 超过 MaxTokenSize")
	}
	return nil
}

// intern returns a shared string for b. The transient lookup string aliases b, but inserted map
// keys always own their bytes. | intern 返回 b 的共享字符串；用于查找的临时字符串引用 b，但插入
// 映射的键始终拥有独立字节。
func (l *lexer) intern(b []byte) string {
	if len(b) == 0 {
		return ""
	}
	if l.names == nil {
		l.names = make(map[string]string)
	}
	key := unsafe.String(unsafe.SliceData(b), len(b))
	if v, ok := l.names[key]; ok {
		return v
	}
	v := string(b)
	l.names[v] = v
	return v
}

// str returns a stable string for b. In byte-slice mode, values that point into the immutable
// input are aliased without copying; decoded scratch values are copied. | str 返回 b 的稳定字符串。
// 字节切片模式下，指向不可变输入的字节会被无拷贝地别名引用；解码产生的临时值会被复制。
func (l *lexer) str(b []byte) string {
	if len(b) == 0 {
		return ""
	}
	if !l.s.owned && sliceWithin(b, l.s.data) {
		return unsafe.String(unsafe.SliceData(b), len(b))
	}
	return string(b)
}

// nextRaw returns the next raw token. | nextRaw 返回下一个原始 token。
func (l *lexer) nextRaw() (Token, error) {
	var ev event
	if err := l.nextRawEvent(&ev); err != nil {
		return nil, err
	}
	return ev.token(), nil
}

// nextRawEvent fills ev with the next raw event. Self-closing elements expand into evStart
// followed by evEnd. | nextRawEvent 用下一个原始事件填充 ev；自闭合元素展开为 evStart 后跟 evEnd。
func (l *lexer) nextRawEvent(ev *event) error {
	if l.pendingEndOK {
		l.pendingEndOK = false
		ev.kind = evEnd
		ev.name = l.pendingEnd
		return nil
	}
	if err := l.s.ensure(1); err != nil {
		return err
	}
	if l.s.end == l.s.pos {
		if l.s.err != nil {
			return l.s.err
		}
		return io.EOF
	}
	if l.s.data[l.s.pos] != '<' {
		return l.text(ev)
	}
	if err := l.s.advance(1); err != nil {
		return err
	}
	if err := l.s.ensure(1); err != nil {
		return err
	}
	if l.s.end == l.s.pos {
		return l.syntax("unexpected EOF")
	}
	switch l.s.data[l.s.pos] {
	case '/':
		if err := l.s.advance(1); err != nil {
			return err
		}
		return l.endTag(ev)
	case '?':
		if err := l.s.advance(1); err != nil {
			return err
		}
		return l.procInst(ev)
	case '!':
		if err := l.s.advance(1); err != nil {
			return err
		}
		return l.bang(ev)
	default:
		return l.startTag(ev)
	}
}

func (l *lexer) text(ev *event) error {
	s := l.s
	idx, err := s.findAny4At(0, '<', '&', '\r', ']')
	if err != nil {
		return err
	}
	if idx < 0 && !s.owned {
		data := s.data[s.pos:s.end]
		if err := s.advance(len(data)); err != nil {
			return err
		}
		if msg := validateXMLText(data); msg != "" {
			return l.syntax(msg)
		}
		ev.kind = evText
		ev.data = data
		return nil
	}
	buf := l.textBuf[:0]
	from := 0
	for {
		avail := s.available()
		if idx < 0 {
			buf = append(buf, avail[from:]...)
			if err := l.checkSize(len(buf)); err != nil {
				return err
			}
			if err := s.advance(len(avail) - from); err != nil {
				return err
			}
			if s.r == nil || s.eof {
				break
			}
			from = 0
			idx, err = s.findAny4At(0, '<', '&', '\r', ']')
			if err != nil {
				return err
			}
			continue
		}
		buf = append(buf, avail[from:idx]...)
		if err := l.checkSize(len(buf)); err != nil {
			return err
		}
		if err := s.advance(idx - from); err != nil {
			return err
		}
		avail = s.available()
		switch avail[0] {
		case '<':
			l.textBuf = buf
			if msg := validateXMLText(buf); msg != "" {
				return l.syntax(msg)
			}
			ev.kind = evText
			ev.data = buf
			return nil
		case '&':
			buf, err = l.decodeEntity(buf)
			if err != nil {
				return err
			}
			if err := l.checkSize(len(buf)); err != nil {
				return err
			}
		case '\r':
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
		case ']':
			if err := s.ensure(3); err != nil {
				return err
			}
			a := s.available()
			if len(a) >= 3 && a[0] == ']' && a[1] == ']' && a[2] == '>' {
				return l.syntax("unescaped ]]> not in CDATA section")
			}
			buf = append(buf, ']')
			if err := s.advance(1); err != nil {
				return err
			}
		}
		from = 0
		idx, err = s.findAny4At(0, '<', '&', '\r', ']')
		if err != nil {
			return err
		}
	}
	l.textBuf = buf
	if msg := validateXMLText(buf); msg != "" {
		return l.syntax(msg)
	}
	ev.kind = evText
	ev.data = buf
	return nil
}

func (l *lexer) startTag(ev *event) error {
	name, ok, err := l.readName()
	if err != nil {
		return err
	}
	if !ok {
		return l.syntax("expected element name after <")
	}
	l.attrBuf = l.attrBuf[:0]
	empty := false
	for {
		if err := l.skipSpace(); err != nil {
			return err
		}
		b, err := l.mustPeek()
		if err != nil {
			return err
		}
		if b == '>' {
			if err := l.s.advance(1); err != nil {
				return err
			}
			break
		}
		if b == '/' {
			if err := l.s.advance(1); err != nil {
				return err
			}
			b, err = l.mustPeek()
			if err != nil {
				return err
			}
			if b != '>' {
				return l.syntax("expected /> in element")
			}
			if err := l.s.advance(1); err != nil {
				return err
			}
			empty = true
			break
		}
		an, ok, err := l.readName()
		if err != nil {
			return err
		}
		if !ok {
			return l.syntax("expected attribute name in element")
		}
		if err := l.skipSpace(); err != nil {
			return err
		}
		b, err = l.mustPeek()
		if err != nil {
			return err
		}
		var value []byte
		if b != '=' {
			if l.d.Strict {
				return l.syntax("attribute name without = in element")
			}
			value = []byte(an.Local)
		} else {
			if err := l.s.advance(1); err != nil {
				return err
			}
			if err := l.skipSpace(); err != nil {
				return err
			}
			value, err = l.attrValue()
			if err != nil {
				return err
			}
		}
		l.attrBuf = append(l.attrBuf, Attr{Name: an, Value: l.str(value)})
	}
	if empty {
		l.pendingEnd = name
		l.pendingEndOK = true
	}
	attrs := make([]Attr, len(l.attrBuf))
	copy(attrs, l.attrBuf)
	ev.kind = evStart
	ev.name = name
	ev.attrs = attrs
	return nil
}

func (l *lexer) endTag(ev *event) error {
	name, ok, err := l.readName()
	if err != nil {
		return err
	}
	if !ok {
		return l.syntax("expected element name after </")
	}
	if err := l.skipSpace(); err != nil {
		return err
	}
	b, err := l.mustPeek()
	if err != nil {
		return err
	}
	if b != '>' {
		return l.syntax("invalid characters between </" + name.Local + " and >")
	}
	if err := l.s.advance(1); err != nil {
		return err
	}
	ev.kind = evEnd
	ev.name = name
	return nil
}

func (l *lexer) mustPeek() (byte, error) {
	if err := l.s.ensure(1); err != nil {
		return 0, err
	}
	if l.s.end == l.s.pos {
		return 0, l.syntax("unexpected EOF")
	}
	return l.s.data[l.s.pos], nil
}

func (l *lexer) mustReadByte() (byte, error) {
	b, err := l.mustPeek()
	if err != nil {
		return 0, err
	}
	if err := l.s.advance(1); err != nil {
		return 0, err
	}
	return b, nil
}

func (l *lexer) skipSpace() error {
	for {
		if err := l.s.ensure(1); err != nil {
			return err
		}
		if l.s.end == l.s.pos {
			return nil
		}
		switch l.s.data[l.s.pos] {
		case ' ', '\t', '\r', '\n':
			if err := l.s.advance(1); err != nil {
				return err
			}
		default:
			return nil
		}
	}
}

func (l *lexer) consumeSeq(seq string) (bool, error) {
	if err := l.s.ensure(len(seq)); err != nil {
		return false, err
	}
	a := l.s.available()
	if len(a) < len(seq) || !bytes.Equal(a[:len(seq)], []byte(seq)) {
		return false, nil
	}
	if err := l.s.advance(len(seq)); err != nil {
		return false, err
	}
	return true, nil
}

func (l *lexer) skipUntil(seq string) error {
	idx, err := l.s.findSequence(0, []byte(seq))
	if err != nil {
		return err
	}
	if idx < 0 {
		return l.syntax("unexpected EOF in comment")
	}
	return l.s.advance(idx + len(seq))
}

// readName reads and validates one XML name, returning its qualified string. | readName 读取并
// 校验一个 XML 名称，返回其限定字符串。
