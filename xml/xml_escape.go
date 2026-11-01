package xml

import (
	"bytes"
	"io"
	"unicode/utf8"
)

// Header is a generic XML header suitable for use with Marshal. | Header 是适合与 Marshal 搭配使用的
// 通用 XML 头。
const Header = `<?xml version="1.0" encoding="UTF-8"?>` + "\n"

var (
	escQuot = []byte("&#34;")
	escApos = []byte("&#39;")
	escAmp  = []byte("&amp;")
	escLT   = []byte("&lt;")
	escGT   = []byte("&gt;")
	escTab  = []byte("&#x9;")
	escNL   = []byte("&#xA;")
	escCR   = []byte("&#xD;")
	escFFFD = []byte("�")
)

// EscapeText writes to w the properly escaped XML equivalent of the plain text data s. | EscapeText
// 把纯文本 s 对应的合法转义 XML 写入 w。
func EscapeText(w io.Writer, s []byte) error {
	return escapeText(w, s, true)
}

func escapeText(w io.Writer, s []byte, escapeNewline bool) error {
	var esc []byte
	last := 0
	for i := 0; i < len(s); {
		r, width := utf8.DecodeRune(s[i:])
		i += width
		switch r {
		case '"':
			esc = escQuot
		case '\'':
			esc = escApos
		case '&':
			esc = escAmp
		case '<':
			esc = escLT
		case '>':
			esc = escGT
		case '\t':
			esc = escTab
		case '\n':
			if !escapeNewline {
				continue
			}
			esc = escNL
		case '\r':
			esc = escCR
		default:
			if !isInCharacterRange(r) || (r == 0xFFFD && width == 1) {
				esc = escFFFD
				break
			}
			continue
		}
		if _, err := w.Write(s[last : i-width]); err != nil {
			return err
		}
		if _, err := w.Write(esc); err != nil {
			return err
		}
		last = i
	}
	_, err := w.Write(s[last:])
	return err
}

// EscapeString writes the properly escaped XML equivalent of s to the printer. | EscapeString 把 s
// 对应的合法转义 XML 写入 printer。
func (p *printer) EscapeString(s string) {
	var esc []byte
	last := 0
	for i := 0; i < len(s); {
		r, width := utf8.DecodeRuneInString(s[i:])
		i += width
		switch r {
		case '"':
			esc = escQuot
		case '\'':
			esc = escApos
		case '&':
			esc = escAmp
		case '<':
			esc = escLT
		case '>':
			esc = escGT
		case '\t':
			esc = escTab
		case '\n':
			esc = escNL
		case '\r':
			esc = escCR
		default:
			if !isInCharacterRange(r) || (r == 0xFFFD && width == 1) {
				esc = escFFFD
				break
			}
			continue
		}
		p.WriteString(s[last : i-width])
		p.Write(esc)
		last = i
	}
	p.WriteString(s[last:])
}

// Escape is like EscapeText but omits the error return value. Deprecated: use EscapeText. | Escape
// 类似 EscapeText 但省略错误返回值。已弃用：请使用 EscapeText。
func Escape(w io.Writer, s []byte) {
	EscapeText(w, s)
}

var (
	cdataStart  = []byte("<![CDATA[")
	cdataEnd    = []byte("]]>")
	cdataEscape = []byte("]]]]><![CDATA[>")
)

// emitCDATA writes to w the CDATA-wrapped plain text data s, splitting nested ]]> markers. |
// emitCDATA 把 CDATA 包裹的纯文本 s 写入 w，并拆分内嵌的 ]]> 标记。
func emitCDATA(w io.Writer, s []byte) error {
	if len(s) == 0 {
		return nil
	}
	if _, err := w.Write(cdataStart); err != nil {
		return err
	}
	for {
		before, after, ok := bytes.Cut(s, cdataEnd)
		if !ok {
			break
		}
		if _, err := w.Write(before); err != nil {
			return err
		}
		if _, err := w.Write(cdataEscape); err != nil {
			return err
		}
		s = after
	}
	if _, err := w.Write(s); err != nil {
		return err
	}
	_, err := w.Write(cdataEnd)
	return err
}
