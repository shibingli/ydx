package render

import (
	"bytes"
	htmltmpl "html/template"
	"io"
	"testing"
	texttmpl "text/template"

	ydxrender "github.com/shibingli/ydx/render"
)

// benchCompareTemplate is the page body exercised by every engine. It uses the same tr/can
// bindings and four range items as the ydx benchmark. | benchCompareTemplate 是每个引擎执行的页面
// 正文，使用与 ydx 基准相同的 tr/can 绑定与四个 range 元素。
const benchCompareTemplate = `<h1>{{tr "home.title"}}</h1>{{if can "user:create"}}<b>yes</b>{{else}}<i>no</i>{{end}}{{range .Items}}<li>{{tr "item.name" .}}</li>{{end}}`

// benchCompareItems is the range payload shared by every engine. | benchCompareItems 是每个引擎共享的 range 载荷。
var benchCompareItems = []string{"a", "b", "c", "d"}

// newHTMLTemplate parses the comparison template with html/template and a FuncMap that mirrors
// the ydx bindings. | newHTMLTemplate 用 html/template 与镜像 ydx 绑定的 FuncMap 解析对比模板。
func newHTMLTemplate(tb testing.TB, translate bool, allow bool) *htmltmpl.Template {
	tb.Helper()
	funcs := htmltmpl.FuncMap{
		"tr": func(string, ...any) string {
			if translate {
				return "message"
			}
			return "home.title"
		},
		"can": func(string) bool { return allow },
	}
	tmpl, err := htmltmpl.New("page").Funcs(funcs).Parse(benchCompareTemplate)
	if err != nil {
		tb.Fatalf("html/template Parse failed | html/template 解析失败: %v", err)
	}
	return tmpl
}

// newTextTemplate parses the same template with text/template as the no-escaping lower bound. |
// newTextTemplate 用 text/template 解析同一模板，作为不做上下文转义的性能下界。
func newTextTemplate(tb testing.TB, translate bool, allow bool) *texttmpl.Template {
	tb.Helper()
	funcs := texttmpl.FuncMap{
		"tr": func(string, ...any) string {
			if translate {
				return "message"
			}
			return "home.title"
		},
		"can": func(string) bool { return allow },
	}
	tmpl, err := texttmpl.New("page").Funcs(funcs).Parse(benchCompareTemplate)
	if err != nil {
		tb.Fatalf("text/template Parse failed | text/template 解析失败: %v", err)
	}
	return tmpl
}

// BenchmarkRenderCompare compares the compiled ydx engine with html/template and text/template
// executing the same page. The bindings case supplies a translator and an allowing authority;
// the fallback case leaves both absent. html/template is the closest semantic peer; text/template
// is a lower bound that skips contextual escaping. |
// BenchmarkRenderCompare 对比编译式 ydx 引擎与执行同一页面的 html/template、text/template。
// bindings 用例提供译者与放行权限主体；fallback 用例两者都缺席。html/template 是语义最接近的
// 对照；text/template 是跳过上下文转义的性能下界。
func BenchmarkRenderCompare(b *testing.B) {
	data := map[string]any{"Items": benchCompareItems}
	ydxWithBindings := map[string]any{
		ydxrender.TranslatorKey: zeroTranslator{},
		ydxrender.AuthzKey:      benchAuthz{key: "admin", allow: true},
		"Items":                 benchCompareItems,
	}
	ydxFallback := map[string]any{
		"Items": benchCompareItems,
	}

	b.Run("bindings/ydx", func(b *testing.B) {
		e := newBenchEngine(b)
		if err := e.Render(io.Discard, "pages/home.html", ydxWithBindings); err != nil {
			b.Fatalf("warm-up Render failed | 预热 Render 失败: %v", err)
		}
		b.ReportAllocs()
		b.ResetTimer()
		for i := 0; i < b.N; i++ {
			if err := e.Render(io.Discard, "pages/home.html", ydxWithBindings); err != nil {
				b.Fatalf("Render failed | Render 失败: %v", err)
			}
		}
	})
	b.Run("bindings/html", func(b *testing.B) {
		tmpl := newHTMLTemplate(b, true, true)
		if err := tmpl.Execute(io.Discard, data); err != nil {
			b.Fatalf("warm-up Execute failed | 预热 Execute 失败: %v", err)
		}
		b.ReportAllocs()
		b.ResetTimer()
		for i := 0; i < b.N; i++ {
			if err := tmpl.Execute(io.Discard, data); err != nil {
				b.Fatalf("Execute failed | Execute 失败: %v", err)
			}
		}
	})
	b.Run("bindings/text", func(b *testing.B) {
		tmpl := newTextTemplate(b, true, true)
		if err := tmpl.Execute(io.Discard, data); err != nil {
			b.Fatalf("warm-up Execute failed | 预热 Execute 失败: %v", err)
		}
		b.ReportAllocs()
		b.ResetTimer()
		for i := 0; i < b.N; i++ {
			if err := tmpl.Execute(io.Discard, data); err != nil {
				b.Fatalf("Execute failed | Execute 失败: %v", err)
			}
		}
	})

	b.Run("fallback/ydx", func(b *testing.B) {
		e := newBenchEngine(b)
		if err := e.Render(io.Discard, "pages/home.html", ydxFallback); err != nil {
			b.Fatalf("warm-up Render failed | 预热 Render 失败: %v", err)
		}
		b.ReportAllocs()
		b.ResetTimer()
		for i := 0; i < b.N; i++ {
			if err := e.Render(io.Discard, "pages/home.html", ydxFallback); err != nil {
				b.Fatalf("Render failed | Render 失败: %v", err)
			}
		}
	})
	b.Run("fallback/html", func(b *testing.B) {
		tmpl := newHTMLTemplate(b, false, false)
		if err := tmpl.Execute(io.Discard, data); err != nil {
			b.Fatalf("warm-up Execute failed | 预热 Execute 失败: %v", err)
		}
		b.ReportAllocs()
		b.ResetTimer()
		for i := 0; i < b.N; i++ {
			if err := tmpl.Execute(io.Discard, data); err != nil {
				b.Fatalf("Execute failed | Execute 失败: %v", err)
			}
		}
	})
	b.Run("fallback/text", func(b *testing.B) {
		tmpl := newTextTemplate(b, false, false)
		if err := tmpl.Execute(io.Discard, data); err != nil {
			b.Fatalf("warm-up Execute failed | 预热 Execute 失败: %v", err)
		}
		b.ReportAllocs()
		b.ResetTimer()
		for i := 0; i < b.N; i++ {
			if err := tmpl.Execute(io.Discard, data); err != nil {
				b.Fatalf("Execute failed | Execute 失败: %v", err)
			}
		}
	})
}

// TestRenderCompareParity proves that the compiled executor, html/template and text/template
// produce the same page for the benchmark data, so the comparison measures execution rather
// than differing output. | TestRenderCompareParity 证明编译执行器、html/template 与
// text/template 对基准数据产生相同页面，使对比测量的是执行而非不同输出。
func TestRenderCompareParity(t *testing.T) {
	e := newBenchEngine(t)
	data := map[string]any{"Items": benchCompareItems}
	ydxData := map[string]any{
		ydxrender.TranslatorKey: zeroTranslator{},
		ydxrender.AuthzKey:      benchAuthz{key: "admin", allow: true},
		"Items":                 benchCompareItems,
	}
	var ydxOut bytes.Buffer
	if err := e.Render(&ydxOut, "pages/home.html", ydxData); err != nil {
		t.Fatalf("ydx Render failed | ydx Render 失败: %v", err)
	}
	var htmlOut bytes.Buffer
	if err := newHTMLTemplate(t, true, true).Execute(&htmlOut, data); err != nil {
		t.Fatalf("html/template Execute failed | html/template Execute 失败: %v", err)
	}
	if ydxOut.String() != htmlOut.String() {
		t.Fatalf("ydx and html/template output differ | ydx 与 html/template 输出不一致:\nydx=%q\nhtml=%q", ydxOut.String(), htmlOut.String())
	}
	var textOut bytes.Buffer
	if err := newTextTemplate(t, true, true).Execute(&textOut, data); err != nil {
		t.Fatalf("text/template Execute failed | text/template Execute 失败: %v", err)
	}
	if ydxOut.String() != textOut.String() {
		t.Fatalf("ydx and text/template output differ | ydx 与 text/template 输出不一致:\nydx=%q\ntext=%q", ydxOut.String(), textOut.String())
	}
}
