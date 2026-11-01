package xml

import "strings"

// procInstValue extracts a quoted parameter from an XML declaration body. | procInstValue 从
// XML 声明体中提取带引号的参数值。
func procInstValue(param, s string) string {
	param += "="
	for i := 0; i+len(param) < len(s); {
		k := strings.Index(s[i:], param)
		if k < 0 {
			return ""
		}
		i += k + len(param)
		if i >= len(s) {
			return ""
		}
		if c := s[i]; c == '\'' || c == '"' {
			i++
			j := strings.IndexByte(s[i:], c)
			if j < 0 {
				return ""
			}
			return s[i : i+j]
		}
	}
	return ""
}
