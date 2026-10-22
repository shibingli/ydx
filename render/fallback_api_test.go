package render_test

import (
	"testing"

	"github.com/shibingli/ydx/render"
)

// TestUsesFallbackReportsFastAndFallbackTemplates proves the diagnostic
// distinguishes the compiled executor from the standard-library fallback. |
// TestUsesFallbackReportsFastAndFallbackTemplates 证明诊断方法能区分编译执行器与
// 标准库回退执行器。
func TestUsesFallbackReportsFastAndFallbackTemplates(t *testing.T) {
	mem := writeTemplates(t, map[string]string{
		"templates/pages/fast.html": `<h1>{{.Title}}</h1>`,
		// A template invoked in a JavaScript context makes html/template derive a
		// context clone that the compiled executor cannot address. | 在 JavaScript
		// 上下文中调用模板会让 html/template 派生上下文克隆，编译执行器无法寻址。
		"templates/pages/script.html": `<script>var x = {{template "frag" .}};</script>{{define "frag"}}hi{{end}}`,
	})
	e, err := render.New(mem, render.Options{Root: "templates"})
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	if e.UsesFallback("pages/fast.html") {
		t.Error("pages/fast.html unexpectedly uses the fallback")
	}
	if !e.UsesFallback("pages/script.html") {
		t.Error("pages/script.html should use the fallback for a derived JavaScript context")
	}
}

// TestUsesFallbackUnknownNameFailsClosed proves a misspelled name cannot pass a
// fast-path guard silently. | TestUsesFallbackUnknownNameFailsClosed 证明拼写错误的名称
// 不会让快速路径守卫静默通过。
func TestUsesFallbackUnknownNameFailsClosed(t *testing.T) {
	mem := writeTemplates(t, map[string]string{
		"templates/pages/fast.html": `<h1>{{.Title}}</h1>`,
	})
	e, err := render.New(mem, render.Options{Root: "templates"})
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	if !e.UsesFallback("pages/does-not-exist.html") {
		t.Fatal("unknown template names must report fallback (fail closed)")
	}
}
