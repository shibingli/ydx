//go:build !xml_std

package xml

import (
	"bytes"
	"strconv"
	"strings"
	"unicode"
	"unicode/utf8"

	"github.com/shibingli/ydx/errs"
)

var entityValues = map[string]string{
	"lt":   "<",
	"gt":   ">",
	"amp":  "&",
	"apos": "'",
	"quot": `"`,
}

// validateXMLText reports the first illegal XML character or invalid UTF-8 sequence. It returns
// an empty string when the text is valid. | validateXMLText 报告首个非法 XML 字符或非法 UTF-8 序列；
// 文本合法时返回空字符串。
func validateXMLText(b []byte) string {
	for i := 0; i < len(b); {
		c := b[i]
		if c < utf8.RuneSelf {
			if c != 0x09 && c != 0x0A && c != 0x0D && c < 0x20 {
				return "illegal character code " + strconv.QuoteRune(rune(c))
			}
			i++
			continue
		}
		r, size := utf8.DecodeRune(b[i:])
		if r == utf8.RuneError && size == 1 {
			return "invalid UTF-8"
		}
		if !isInCharacterRange(r) {
			return "illegal character code " + strconv.QuoteRune(r)
		}
		i += size
	}
	return ""
}

func isNameByte(c byte) bool {
	return 'A' <= c && c <= 'Z' ||
		'a' <= c && c <= 'z' ||
		'0' <= c && c <= '9' ||
		c == '_' || c == ':' || c == '.' || c == '-'
}

func isNameScanByte(c byte) bool { return c >= utf8.RuneSelf || isNameByte(c) }

// splitRawName splits a raw qualified name at its single colon. Names with zero or one colon
// where a side is empty are treated as local names, matching encoding/xml. | splitRawName 在唯一的
// 冒号处切分原始限定名；无冒号或冒号一侧为空时按本地名处理，与 encoding/xml 一致。
func splitRawName(s []byte) (rawName, bool) {
	n := 0
	colon := -1
	for i, c := range s {
		if c == ':' {
			n++
			colon = i
		}
	}
	if n > 1 {
		return rawName{}, false
	}
	if n == 1 && colon > 0 && colon+1 < len(s) {
		return rawName{space: s[:colon], local: s[colon+1:]}, true
	}
	return rawName{local: s}, true
}

// decodeEntity parses one entity reference starting at '&' and appends its replacement to dst. |
// decodeEntity 解析从 '&' 开始的一个实体引用，并把替换文本追加到 dst。
func (l *lexer) decodeEntity(dst []byte) ([]byte, error) {
	s := l.s
	raw := make([]byte, 0, 16)
	consume := func(n int) error {
		raw = append(raw, s.available()[:n]...)
		return s.advance(n)
	}
	if err := consume(1); err != nil { // &
		return dst, err
	}
	if err := s.ensure(1); err != nil {
		return dst, err
	}
	buf := s.available()
	if len(buf) == 0 {
		return l.entityFallback(dst, raw)
	}
	if buf[0] == '#' {
		base := 10
		if err := consume(1); err != nil {
			return dst, err
		}
		if err := s.ensure(1); err != nil {
			return dst, err
		}
		buf = s.available()
		if len(buf) > 0 && buf[0] == 'x' {
			base = 16
			if err := consume(1); err != nil {
				return dst, err
			}
		}
		digits := len(raw)
		for {
			if err := s.ensure(1); err != nil {
				return dst, err
			}
			buf = s.available()
			if len(buf) == 0 || !isBaseDigit(buf[0], base) {
				break
			}
			if err := consume(1); err != nil {
				return dst, err
			}
		}
		if err := s.ensure(1); err != nil {
			return dst, err
		}
		buf = s.available()
		if len(buf) == 0 || buf[0] != ';' {
			return l.entityFallback(dst, raw)
		}
		if err := consume(1); err != nil {
			return dst, err
		}
		if len(raw) <= digits+1 {
			return l.entityFallback(dst, raw)
		}
		digitsRaw := raw[digits : len(raw)-1]
		n, err := strconv.ParseUint(string(digitsRaw), base, 64)
		if err != nil || n > unicode.MaxRune {
			return l.entityFallback(dst, raw)
		}
		return append(dst, string(rune(n))...), nil
	}

	// Named entity.
	nameStart := len(raw)
	for {
		if err := s.ensure(1); err != nil {
			return dst, err
		}
		buf = s.available()
		if len(buf) == 0 || !isNameScanByte(buf[0]) {
			break
		}
		if err := consume(1); err != nil {
			return dst, err
		}
	}
	if err := s.ensure(1); err != nil {
		return dst, err
	}
	buf = s.available()
	if len(buf) == 0 || buf[0] != ';' {
		return l.entityFallback(dst, raw)
	}
	if err := consume(1); err != nil {
		return dst, err
	}
	nameRaw := raw[nameStart : len(raw)-1]
	if !isNameBytes(nameRaw) {
		return l.entityFallback(dst, raw)
	}
	name := string(nameRaw)
	if v, ok := entityValues[name]; ok {
		return append(dst, v...), nil
	}
	if l.d.Entity != nil {
		if v, ok := l.d.Entity[name]; ok {
			return append(dst, v...), nil
		}
	}
	if v, ok := l.entities[name]; ok {
		return l.appendDTDEntity(dst, v, 1)
	}
	return l.entityFallback(dst, raw)
}

func isBaseDigit(c byte, base int) bool {
	if '0' <= c && c <= '9' {
		return true
	}
	return base == 16 && ('a' <= c && c <= 'f' || 'A' <= c && c <= 'F')
}

// entityFallback returns the raw entity text in non-strict mode and a syntax error in strict
// mode. | entityFallback 在非严格模式下返回原始实体文本，在严格模式下返回语法错误。
func (l *lexer) entityFallback(dst, raw []byte) ([]byte, error) {
	if !l.d.Strict {
		return append(dst, raw...), nil
	}
	return dst, l.syntax("invalid character entity " + string(raw))
}

// appendDTDEntity expands a DTD entity value recursively with depth and size budgets. | appendDTDEntity
// 在深度与大小预算下递归展开 DTD 实体值。
func (l *lexer) appendDTDEntity(dst []byte, value string, depth int) ([]byte, error) {
	if !l.budgetInit {
		l.entityBudget = l.d.limits().MaxEntityExpansion
		l.budgetInit = true
	}
	if depth > l.d.limits().MaxEntityDepth {
		return dst, errs.Detail(ErrLimit, "entity expansion depth exceeded | 实体展开深度超限")
	}
	start := len(dst)
	for i := 0; i < len(value); {
		if value[i] != '&' {
			dst = append(dst, value[i])
			i++
			continue
		}
		j := strings.IndexByte(value[i:], ';')
		if j < 0 {
			dst = append(dst, value[i:]...)
			break
		}
		ref := value[i+1 : i+j]
		if len(ref) > 0 && ref[0] == '#' {
			base := 10
			digits := ref[1:]
			if len(digits) > 0 && digits[0] == 'x' {
				base = 16
				digits = digits[1:]
			}
			n, err := strconv.ParseUint(digits, base, 64)
			if err == nil && n <= unicode.MaxRune {
				dst = append(dst, string(rune(n))...)
			} else {
				dst = append(dst, value[i:i+j+1]...)
			}
		} else if v, ok := entityValues[ref]; ok {
			dst = append(dst, v...)
		} else if v, ok := l.entities[ref]; ok {
			var err error
			dst, err = l.appendDTDEntity(dst, v, depth+1)
			if err != nil {
				return dst, err
			}
		} else if l.d.Entity != nil {
			if v, ok := l.d.Entity[ref]; ok {
				dst = append(dst, v...)
			} else {
				dst = append(dst, value[i:i+j+1]...)
			}
		} else {
			dst = append(dst, value[i:i+j+1]...)
		}
		i += j + 1
	}
	if int64(len(dst)-start) > l.entityBudget {
		return dst, errs.Detail(ErrLimit, "entity expansion exceeds MaxEntityExpansion | 实体展开超过 MaxEntityExpansion")
	}
	l.entityBudget -= int64(len(dst) - start)
	return dst, nil
}

// parseDTD records internal-subset general entity declarations from a DOCTYPE directive. External
// entities are never loaded. | parseDTD 从 DOCTYPE 指令记录内部子集通用实体声明；绝不加载外部实体。
func (l *lexer) parseDTD(data []byte) {
	if !bytes.HasPrefix(data, []byte("DOCTYPE")) {
		return
	}
	open := bytes.IndexByte(data, '[')
	if open < 0 {
		return
	}
	var quote byte
	closeIdx := -1
	for i := open + 1; i < len(data); i++ {
		c := data[i]
		if quote != 0 {
			if c == quote {
				quote = 0
			}
			continue
		}
		switch c {
		case '\'', '"':
			quote = c
		case ']':
			closeIdx = i
			i = len(data)
		}
	}
	if closeIdx < 0 {
		return
	}
	subset := data[open+1 : closeIdx]
	for i := 0; i < len(subset); {
		if subset[i] != '<' {
			i++
			continue
		}
		rest := subset[i:]
		switch {
		case bytes.HasPrefix(rest, []byte("<!--")):
			if j := bytes.Index(rest[4:], []byte("-->")); j >= 0 {
				i += 4 + j + 3
			} else {
				return
			}
		case bytes.HasPrefix(rest, []byte("<?")):
			if j := bytes.Index(rest[2:], []byte("?>")); j >= 0 {
				i += 2 + j + 2
			} else {
				return
			}
		case bytes.HasPrefix(rest, []byte("<!ENTITY")):
			next, ok := l.parseEntityDecl(rest[len("<!ENTITY"):])
			if !ok {
				return
			}
			i += len("<!ENTITY") + next
		default:
			end := directiveEnd(rest[2:])
			if end < 0 {
				return
			}
			i += 2 + end + 1
		}
	}
}

// parseEntityDecl parses one entity declaration body after "<!ENTITY". | parseEntityDecl 解析
// "<!ENTITY" 之后的一个实体声明主体。
func (l *lexer) parseEntityDecl(b []byte) (int, bool) {
	i := 0
	for i < len(b) && isSpaceByte(b[i]) {
		i++
	}
	if i < len(b) && b[i] == '%' {
		return skipDecl(b, i), true
	}
	nameStart := i
	for i < len(b) && isNameScanByte(b[i]) {
		i++
	}
	if nameStart == i || !isNameBytes(b[nameStart:i]) {
		return skipDecl(b, i), true
	}
	name := string(b[nameStart:i])
	for i < len(b) && isSpaceByte(b[i]) {
		i++
	}
	if i >= len(b) {
		return 0, false
	}
	if b[i] == '\'' || b[i] == '"' {
		q := b[i]
		i++
		valStart := i
		for i < len(b) && b[i] != q {
			i++
		}
		if i >= len(b) {
			return 0, false
		}
		value := string(b[valStart:i])
		i++
		if l.entities == nil {
			l.entities = make(map[string]string)
		}
		if _, exists := l.entities[name]; !exists {
			l.entities[name] = value
		}
		return skipDecl(b, i), true
	}
	// External entity: do not load it.
	return skipDecl(b, i), true
}

func skipDecl(b []byte, i int) int {
	var quote byte
	for ; i < len(b); i++ {
		c := b[i]
		if quote != 0 {
			if c == quote {
				quote = 0
			}
			continue
		}
		switch c {
		case '\'', '"':
			quote = c
		case '>':
			return i + 1
		}
	}
	return len(b)
}

func directiveEnd(b []byte) int {
	var quote byte
	for i := 0; i < len(b); i++ {
		c := b[i]
		if quote != 0 {
			if c == quote {
				quote = 0
			}
			continue
		}
		switch c {
		case '\'', '"':
			quote = c
		case '>':
			return i
		}
	}
	return -1
}

func isSpaceByte(c byte) bool {
	return c == ' ' || c == '\t' || c == '\r' || c == '\n'
}
