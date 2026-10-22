// Package render compiles html/template sets into an immutable, high-throughput
// execution program. | Package render 把 html/template 模板集编译为不可变的高吞吐执行程序。
//
// html/template stays the parser and the contextual escaper: it understands the full
// text/template syntax and rewrites every dynamic action with the escapers its
// HTML/JS/CSS/URL state machine demands. The compiled executor then walks that
// already-safe tree without text/template's per-render reflection setup, so syntax
// and security semantics are exactly the standard library's while the hot path is
// considerably faster. | html/template 仍是解析器与上下文转义器：它理解完整的
// text/template 语法，并按 HTML/JS/CSS/URL 状态机为每个动态动作重写转义器。编译执行器随后
// 遍历这棵已安全的树，不再承担 text/template 每次渲染的反射装配开销，因此语法与安全语义与
// 标准库完全一致，而热路径显著更快。
//
// Templates are addressed by their slash-separated path relative to the scan root, for
// example "layouts/base.html" or "pages/users.html". Every file under the root is parsed
// into one template set, so partials can be invoked by name from any page. Dev mode
// recompiles on every render so template edits take effect without a restart, which is
// what `yd dev` relies on. | 模板以相对扫描根的斜杠路径寻址，例如 "layouts/base.html" 或
// "pages/users.html"。根目录下的每个文件都会被解析进同一个模板集，因此任意页面都可按名称调用
// 局部模板。Dev 模式在每次渲染时重新编译，模板改动无需重启即可生效，`yd dev` 依赖该行为。
//
// User-facing text is written as `{{ tr "some.key" }}`. The engine ships no catalog of
// its own: a translator is injected through the render data under TranslatorKey, and tr
// returns the key when none is injected. Permissions work the same way through AuthzKey.
// | 面向用户的文案写作 `{{ tr "some.key" }}`。引擎本身不附带任何语言目录：译者通过渲染数据中的
// TranslatorKey 键注入，未注入时 tr 返回键本身。权限同理，通过 AuthzKey 注入。
//
// UsesFallback reports whether a template entry is executed by the standard-library
// fallback; it exists so framework template sets can assert they stay on the fast
// executor across package boundaries. | UsesFallback 报告某个模板入口是否由标准库回退执行器
// 执行；它用于让框架模板集在跨包场景下断言仍处于快速执行器路径。
//
// Typical usage | 典型用法：
//
//	engine, err := render.New(afs.NewEmbed(embedded), render.Options{})
//	if err != nil {
//		return err
//	}
//	if err := engine.Render(w, "pages/users.html", data); err != nil {
//		return err
//	}
package render
