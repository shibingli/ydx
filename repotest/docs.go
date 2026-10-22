// Package repotest contains repository-level guards for the ydx multi-module workspace. |
// Package repotest 包含 ydx 多模块工作区的仓库级守卫。
//
// The guards verify that every module ships docs.go, go.mod and go.sum, that extracted packages
// keep the framework's architectural rules (no yd imports, no direct stdlib codecs or regexp, no
// direct panics, no fmt.Errorf outside errs, no foreign keys and no cgo SQLite driver), and that
// every benchmark lives in its own benchmarks module. | 守卫验证每个模块都带有 docs.go、go.mod 与
// go.sum，拆分后的包继续遵守框架架构规则（不 import yd、不直接使用标准库编解码或 regexp、
// 不直接 panic、errs 之外不用 fmt.Errorf、不使用外键与 cgo SQLite 驱动），并确保所有基准都位于
// 独立的 benchmarks 模块中。
//
// Run from the repository root or this directory. | 从仓库根目录或本目录运行：
//
//	go test ./repotest
package repotest
