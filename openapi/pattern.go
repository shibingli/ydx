package openapi

import "strings"

// ScanPathTemplate converts a simple ":param" / "*param" pattern into an OpenAPI path
// template and returns its path parameters. | ScanPathTemplate 把简单的 ":param" / "*param"
// 模式转换为 OpenAPI 路径模板，并返回其路径参数。
//
// It is the textual converter used by Builder.AddRoute and by router adapters when their own
// pattern parser rejects a pattern. It understands only the two capture markers, not the full
// syntax of any particular router. | 它是 Builder.AddRoute 与路由适配器在自身模式解析失败时使用的
// 文本转换器，只理解两种捕获标记，不理解任何特定路由器的完整语法。
func ScanPathTemplate(pattern string) (string, []Parameter) {
	var (
		b      strings.Builder
		params []Parameter
		seen   = map[string]bool{}
	)
	if !strings.HasPrefix(pattern, "/") {
		b.WriteByte('/')
	}
	for i := 0; i < len(pattern); i++ {
		c := pattern[i]
		if c != ':' && c != '*' {
			b.WriteByte(c)
			continue
		}
		j := i + 1
		for j < len(pattern) && isPathNameChar(pattern[j]) {
			j++
		}
		if j == i+1 {
			b.WriteByte(c)
			continue
		}
		name := pattern[i+1 : j]
		b.WriteString("{" + name + "}")
		if !seen[name] {
			seen[name] = true
			params = append(params, pathParameter(name))
		}
		i = j - 1
	}
	out := b.String()
	if out == "" {
		out = "/"
	}
	return out, params
}
