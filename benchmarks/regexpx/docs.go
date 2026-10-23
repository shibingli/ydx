// Package regexpx contains the regular-expression benchmarks that live outside the component module,
// so github.com/shibingli/ydx/regexpx never depends on benchmark-only code or comparison libraries. |
// Package regexpx 保存位于组件模块之外的正则基准，使 github.com/shibingli/ydx/regexpx 不依赖基准专用
// 代码或对比库。
//
// Compared with the standard library regexp, github.com/dlclark/regexp2, github.com/grafana/regexp
// and github.com/wasilibs/go-re2. | 对比标准库 regexp、github.com/dlclark/regexp2、
// github.com/grafana/regexp 与 github.com/wasilibs/go-re2。
//
// Run with | 运行方式：
//
//	cd benchmarks/regexpx
//	GOWORK=off go test -run '^$' -bench . -benchmem
package regexpx
