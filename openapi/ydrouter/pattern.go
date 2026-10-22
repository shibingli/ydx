package ydrouter

import (
	"strings"

	"github.com/shibingli/ydx/openapi"
	"github.com/shibingli/ydx/router"
)

// pathTemplate converts a router pattern into an OpenAPI path template and returns the path
// parameters it declares. | pathTemplate 把路由模式转换为 OpenAPI 路径模板，并返回其声明的路径参数。
//
// "/report/:id-xx.png" becomes "/report/{id}-xx.png"; "/static/*filepath" becomes
// "/static/{filepath}"; a trailing slash segment is preserved without producing an empty
// parameter name. A pattern the router itself rejects falls back to the textual converter in
// the openapi package. | "/report/:id-xx.png" 变为 "/report/{id}-xx.png"；"/static/*filepath"
// 变为 "/static/{filepath}"；尾斜杠段被保留且不产生空参数名。路由器自身拒绝的模式回退到
// openapi 包中的文本转换器。
func pathTemplate(pattern string) (string, []openapi.Parameter) {
	segments, err := router.ParsePattern(pattern)
	if err != nil {
		return openapi.ScanPathTemplate(pattern)
	}
	var (
		b        strings.Builder
		params   []openapi.Parameter
		trailing bool
	)
	for _, segment := range segments {
		if segment.TrailingSlash {
			trailing = true
			continue
		}
		b.WriteByte('/')
		switch segment.Kind {
		case router.SegStatic:
			b.WriteString(segment.Literal)
		case router.SegParam, router.SegWildcard:
			b.WriteString("{" + segment.Name + "}")
			params = append(params, pathParameter(segment.Name))
		case router.SegMixed:
			for _, token := range segment.Tokens {
				if token.Kind == router.TokenLiteral {
					b.WriteString(token.Text)
					continue
				}
				b.WriteString("{" + token.Text + "}")
				params = append(params, pathParameter(token.Text))
			}
		default:
			b.WriteString(segment.Raw)
		}
	}
	if trailing {
		b.WriteByte('/')
	}
	out := b.String()
	if out == "" {
		out = "/"
	}
	return out, params
}

// pathParameter builds the required string path parameter a template declares. | pathParameter
// 构造模板声明的必填字符串路径参数。
func pathParameter(name string) openapi.Parameter {
	return openapi.Parameter{
		Name:     name,
		In:       "path",
		Required: true,
		Schema:   &openapi.Schema{Type: "string"},
	}
}
