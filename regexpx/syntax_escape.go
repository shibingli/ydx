package regexpx

import (
	"unicode"
	"unicode/utf8"
)

// parseEscape parses a backslash escape outside a character class. | parseEscape 解析字符类之外的
// 反斜杠转义。
func (p *parser) parseEscape(flags flagSet) node {
	p.pos++ // consume '\\'
	if p.pos >= len(p.runes) {
		p.fail("trailing backslash | 结尾反斜杠")
		return nil
	}
	r := p.next()
	switch r {
	case 'a':
		return p.literal('\a', flags)
	case 'f':
		return p.literal('\f', flags)
	case 't':
		return p.literal('\t', flags)
	case 'n':
		return p.literal('\n', flags)
	case 'r':
		return p.literal('\r', flags)
	case 'v':
		return p.literal('\v', flags)
	case 'e':
		return p.literal(0x1B, flags)
	case 'c':
		return p.parseControl(flags)
	case 'd':
		return classNode(asciiDigit, false, flags)
	case 'D':
		return classNode(asciiDigit, true, flags)
	case 's':
		return classNode(asciiSpace, false, flags)
	case 'S':
		return classNode(asciiSpace, true, flags)
	case 'w':
		return classNode(asciiWord, false, flags)
	case 'W':
		return classNode(asciiWord, true, flags)
	case 'b':
		return &nAssert{kind: assertWordBoundary}
	case 'B':
		return &nAssert{kind: assertNotWordBoundary}
	case 'A':
		return &nAssert{kind: assertBeginText}
	case 'z':
		return &nAssert{kind: assertEndText}
	case 'Z':
		return &nAssert{kind: assertEndTextFinalNewline}
	case 'p', 'P':
		b := &classBuilder{}
		if !p.parseUnicodeClass(b, r == 'P') {
			return nil
		}
		return &nClass{c: b.build(false, false)}
	case 'x':
		value, ok := p.parseHex()
		if !ok {
			return nil
		}
		return p.literal(value, flags)
	case '0':
		value, ok := p.parseOctal(r)
		if !ok {
			return nil
		}
		return p.literal(value, flags)
	case 'k':
		return p.parseNamedBackref(flags)
	case 'Q':
		return p.parseQuoted(flags)
	case '8', '9':
		return p.parseNumericBackref(r, flags)
	}
	if r >= '1' && r <= '7' {
		return p.parseAmbiguousEscape(r, flags)
	}
	if r == 'E' {
		p.fail(`unexpected \E | 意外的 \E`)
		return nil
	}
	if isASCIIPunct(r) {
		return p.literal(r, flags)
	}
	p.failf("invalid escape sequence \\%c | 非法的转义序列 \\%c", r, r)
	return nil
}

// parseControl parses \cX into a control character. | parseControl 把 \cX 解析为控制字符。
func (p *parser) parseControl(flags flagSet) node {
	r := p.peek()
	if r == -1 {
		p.fail(`trailing \c | 结尾的 \c`)
		return nil
	}
	p.pos++
	if r >= 'a' && r <= 'z' {
		r -= 'a' - 'A'
	}
	if r < '@' || r > '_' {
		p.fail(`invalid \c escape | 非法的 \c 转义`)
		return nil
	}
	return p.literal(r&0x1F, flags)
}

// parseHex parses \xHH or \x{H...}. | parseHex 解析 \xHH 或 \x{H...}。
func (p *parser) parseHex() (rune, bool) {
	if p.peek() == '{' {
		p.pos++
		start := p.pos
		for p.pos < len(p.runes) && p.runes[p.pos] != '}' {
			p.pos++
		}
		if p.pos >= len(p.runes) {
			p.fail(`missing } in \x{...} | \x{...} 缺少 }`)
			return 0, false
		}
		digits := p.runes[start:p.pos]
		p.pos++
		value, ok := parseHexDigits(digits)
		if !ok || value > unicode.MaxRune {
			p.fail(`invalid \x{...} escape | 非法的 \x{...} 转义`)
			return 0, false
		}
		return value, true
	}
	if p.pos+2 > len(p.runes) {
		p.fail(`invalid \x escape | 非法的 \x 转义`)
		return 0, false
	}
	value, ok := parseHexDigits(p.runes[p.pos : p.pos+2])
	if !ok {
		p.fail(`invalid \x escape | 非法的 \x 转义`)
		return 0, false
	}
	p.pos += 2
	return value, true
}

// parseOctal parses up to two further octal digits after the leading digit. | parseOctal 解析前导数字之后
// 最多两位八进制数字。
func (p *parser) parseOctal(lead rune) (rune, bool) {
	value := int(lead - '0')
	for i := 0; i < 2; i++ {
		r := p.peek()
		if r < '0' || r > '7' {
			break
		}
		value = value<<3 | int(r-'0')
		p.pos++
	}
	if value > unicode.MaxRune {
		p.fail(`octal escape out of range | 八进制转义超出范围`)
		return 0, false
	}
	return rune(value), true
}

// parseAmbiguousEscape parses \1..\7, which is a backreference when the pattern has that many groups
// and an octal escape otherwise. | parseAmbiguousEscape 解析 \1..\7：模式中的分组足够多时按反向引用处理，
// 否则按八进制转义处理。
func (p *parser) parseAmbiguousEscape(lead rune, flags flagSet) node {
	value := int(lead - '0')
	if p.peek() >= '0' && p.peek() <= '7' {
		value = value*8 + int(p.next()-'0')
		if p.peek() >= '0' && p.peek() <= '7' {
			value = value*8 + int(p.next()-'0')
		}
	}
	if value == 0 || value > unicode.MaxRune {
		p.fail(`octal escape out of range | 八进制转义超出范围`)
		return nil
	}
	return &nAmbig{value: rune(value), fold: flags&flagFold != 0}
}

// parseNumericBackref parses \8 and \9 plus further decimal digits. | parseNumericBackref 解析 \8、\9 及
// 后续十进制数字。
func (p *parser) parseNumericBackref(lead rune, flags flagSet) node {
	value := int(lead - '0')
	for p.peek() >= '0' && p.peek() <= '9' {
		value = value*10 + int(p.next()-'0')
		if value > 1<<20 {
			p.fail("backreference number too large | 反向引用编号过大")
			return nil
		}
	}
	return &nAmbig{value: rune(value), fold: flags&flagFold != 0}
}

// parseNamedBackref parses \k<name> or \k'name'. | parseNamedBackref 解析 \k<name> 或 \k'name'。
func (p *parser) parseNamedBackref(flags flagSet) node {
	open := p.peek()
	var close rune
	switch open {
	case '<':
		close = '>'
	case '\'':
		close = '\''
	default:
		p.fail(`invalid \k backreference | 非法的 \k 反向引用`)
		return nil
	}
	p.pos++
	name := p.parseName(close)
	return &nBackref{index: -1, name: name, fold: flags&flagFold != 0}
}

// parseQuoted parses \Q...\E into literal nodes. | parseQuoted 把 \Q...\E 解析为字面量节点。
func (p *parser) parseQuoted(flags flagSet) node {
	var subs []node
	for p.pos < len(p.runes) {
		if p.runes[p.pos] == '\\' && p.peekAt(1) == 'E' {
			p.pos += 2
			break
		}
		subs = append(subs, p.literal(p.next(), flags))
	}
	if len(subs) == 0 {
		return &nEmpty{}
	}
	if len(subs) == 1 {
		return subs[0]
	}
	return &nConcat{sub: subs}
}

// parseUnicodeClass parses the body of \p or \P into b. | parseUnicodeClass 把 \p 或 \P 的主体解析到 b。
func (p *parser) parseUnicodeClass(b *classBuilder, neg bool) bool {
	var name string
	if p.peek() == '{' {
		p.pos++
		start := p.pos
		for p.pos < len(p.runes) && p.runes[p.pos] != '}' {
			p.pos++
		}
		if p.pos >= len(p.runes) {
			p.fail(`missing } in \p{...} | \p{...} 缺少 }`)
			return false
		}
		name = string(p.runes[start:p.pos])
		p.pos++
	} else {
		r := p.peek()
		if r == -1 {
			p.fail(`missing name after \p | \p 后缺少名称`)
			return false
		}
		name = string(p.next())
	}
	table, ok := lookupUnicodeTable(name)
	if !ok {
		p.failf("invalid Unicode class %q | 非法的 Unicode 类 %q", name, name)
		return false
	}
	if neg {
		b.addTableComplement(table)
	} else if table == nil {
		b.addRanges([]runeRange{{0, unicode.MaxRune}})
	} else {
		b.addTable(table)
	}
	return true
}

// lookupUnicodeTable resolves a Unicode class name. A nil table with ok=true means "any rune". |
// lookupUnicodeTable 解析 Unicode 类名；ok 为 true 且 table 为 nil 表示「任意符文」。
func lookupUnicodeTable(name string) (*unicode.RangeTable, bool) {
	if name == "Any" {
		return nil, true
	}
	if t, ok := unicode.Categories[name]; ok {
		return t, true
	}
	if t, ok := unicode.Scripts[name]; ok {
		return t, true
	}
	if t, ok := unicode.Properties[name]; ok {
		return t, true
	}
	return nil, false
}

// parseHexDigits converts hexadecimal runes. | parseHexDigits 转换十六进制符文。
func parseHexDigits(digits []rune) (rune, bool) {
	if len(digits) == 0 {
		return 0, false
	}
	var value rune
	for _, r := range digits {
		var d rune
		switch {
		case r >= '0' && r <= '9':
			d = r - '0'
		case r >= 'a' && r <= 'f':
			d = r - 'a' + 10
		case r >= 'A' && r <= 'F':
			d = r - 'A' + 10
		default:
			return 0, false
		}
		if value > (unicode.MaxRune-d)/16 {
			return 0, false
		}
		value = value*16 + d
	}
	return value, true
}

// isASCIIPunct reports whether r is ASCII punctuation that may be backslash-escaped. | isASCIIPunct
// 报告 r 是否为可被反斜杠转义的 ASCII 标点。
func isASCIIPunct(r rune) bool {
	return r < utf8.RuneSelf && r > 0x20 && r < 0x7F &&
		!(r >= '0' && r <= '9') && !(r >= 'A' && r <= 'Z') && !(r >= 'a' && r <= 'z')
}
