package xml

import (
	"bytes"
	"encoding/binary"
	"io"
	"math/bits"
	"unicode/utf8"
	"unsafe"
)

// The SWAR helpers below find the first byte that the escape loop must inspect: any byte
// outside printable ASCII, any control byte, and the XML/attribute metacharacters " ' & < >.
// Clean ASCII text, which dominates element text and attribute values, is then copied with one
// write instead of one rune decode per byte. | 以下 SWAR 辅助函数定位转义循环必须检查的首个
// 字节：可打印 ASCII 之外的字节、控制字节，以及 XML/属性元字符 " ' & < >。占绝大多数的纯 ASCII
// 元素文本与属性值因此只需一次写入，而不是逐字节解码。
const (
	escapeHighBits = 0x8080808080808080
	escapeLowBits  = 0x0101010101010101
)

func escapeSpread(c byte) uint64 { return uint64(c) * escapeLowBits }

func escapeZeroMask(x uint64) uint64 { return (x - escapeLowBits) & ^x & escapeHighBits }

func escapeLess20Mask(x uint64) uint64 {
	return (x - escapeSpread(0x20)) & ^x & escapeHighBits
}

// escapeMask marks every byte that needs the slow path. | escapeMask 标记需要慢路径的每个字节。
func escapeMask(w uint64) uint64 {
	m := w & escapeHighBits
	m |= escapeLess20Mask(w)
	m |= escapeZeroMask(w ^ escapeSpread('"'))
	m |= escapeZeroMask(w ^ escapeSpread('\''))
	m |= escapeZeroMask(w ^ escapeSpread('&'))
	m |= escapeZeroMask(w ^ escapeSpread('<'))
	m |= escapeZeroMask(w ^ escapeSpread('>'))
	return m
}

// needsEscapeByte reports whether c must be handled by the rune-level escape loop. |
// needsEscapeByte 判断 c 是否必须交由图元级转义循环处理。
func needsEscapeByte(c byte) bool {
	return c < 0x20 || c >= 0x80 || c == '"' || c == '\'' || c == '&' || c == '<' || c == '>'
}

// firstEscapeByteString returns the index of the first byte needing escaping, or -1. |
// firstEscapeByteString 返回首个需要转义的字节下标，未找到返回 -1。
func firstEscapeByteString(s string) int {
	i := 0
	for ; i+8 <= len(s); i += 8 {
		w := binary.LittleEndian.Uint64(unsafe.Slice(unsafe.StringData(s[i:]), 8))
		if m := escapeMask(w); m != 0 {
			return i + bits.TrailingZeros64(m)/8
		}
	}
	for ; i < len(s); i++ {
		if needsEscapeByte(s[i]) {
			return i
		}
	}
	return -1
}

// firstEscapeByteSlice returns the index of the first byte needing escaping, or -1. |
// firstEscapeByteSlice 返回首个需要转义的字节下标，未找到返回 -1。
func firstEscapeByteSlice(s []byte) int {
	i := 0
	for ; i+8 <= len(s); i += 8 {
		w := binary.LittleEndian.Uint64(s[i:])
		if m := escapeMask(w); m != 0 {
			return i + bits.TrailingZeros64(m)/8
		}
	}
	for ; i < len(s); i++ {
		if needsEscapeByte(s[i]) {
			return i
		}
	}
	return -1
}

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
	if i := firstEscapeByteSlice(s); i < 0 {
		_, err := w.Write(s)
		return err
	} else if i > 0 {
		if _, err := w.Write(s[:i]); err != nil {
			return err
		}
		s = s[i:]
	}
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
	if i := firstEscapeByteString(s); i < 0 {
		p.WriteString(s)
		return
	} else if i > 0 {
		p.WriteString(s[:i])
		s = s[i:]
	}
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
