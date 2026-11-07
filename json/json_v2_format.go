package json

// formatV2 rewrites compact JSON with the whitespace layout requested by jsontext formatting
// options, matching encoding/json/v2: multiline output nests one indent per level, and the
// spacing options add one space after ':' or ',' without changing string contents. The input is
// already validated by the encoder, so this pass is purely syntactic. |
// formatV2 按 jsontext 格式化选项重写紧凑 JSON，与 encoding/json/v2 一致：多行输出每层缩进一次，
// 间距选项在 ':' 或 ',' 后加一个空格，不改变字符串内容。输入已通过编码器校验，因此本过程只做
// 语法层面的重写。
func formatV2(src []byte, cfg *v2Config) []byte {
	indent := cfg.indent
	if cfg.multiline && !cfg.indentSet {
		indent = "\t"
	}
	prefix := cfg.indentPrefix
	dst := make([]byte, 0, len(src)+len(src)/4+16)
	depth := 0
	inString := false
	escaped := false
	newline := func() {
		dst = append(dst, '\n')
		dst = append(dst, prefix...)
		for i := 0; i < depth; i++ {
			dst = append(dst, indent...)
		}
	}
	for i := 0; i < len(src); i++ {
		c := src[i]
		if inString {
			dst = append(dst, c)
			if escaped {
				escaped = false
			} else if c == '\\' {
				escaped = true
			} else if c == '"' {
				inString = false
			}
			continue
		}
		switch c {
		case '"':
			inString = true
			dst = append(dst, c)
		case '{', '[':
			dst = append(dst, c)
			if cfg.multiline && i+1 < len(src) && src[i+1] != '}' && src[i+1] != ']' {
				depth++
				newline()
				continue
			}
			depth++
		case '}', ']':
			depth--
			if cfg.multiline && i > 0 && src[i-1] != '{' && src[i-1] != '[' {
				newline()
			}
			dst = append(dst, c)
		case ',':
			dst = append(dst, c)
			if cfg.multiline {
				newline()
			} else if cfg.spaceAfterComma {
				dst = append(dst, ' ')
			}
		case ':':
			dst = append(dst, c)
			if cfg.spaceAfterColon || cfg.multiline {
				dst = append(dst, ' ')
			}
		case ' ', '\t', '\n', '\r':
			// The encoder emits no insignificant whitespace; drop any that appears. | 编码器不产生
			// 无意义空白；若出现则丢弃。
		default:
			dst = append(dst, c)
		}
	}
	return dst
}
