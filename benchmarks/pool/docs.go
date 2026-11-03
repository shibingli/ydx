// Package pool contains the goroutine-pool benchmarks that live outside the component
// module, so github.com/shibingli/ydx/pool never depends on benchmark-only code. |
// Package pool 保存位于组件模块之外的协程池基准，使 github.com/shibingli/ydx/pool 不依赖
// 基准专用代码。
//
// Compared with github.com/panjf2000/ants/v2, github.com/alitto/pond/v2,
// github.com/gammazero/workerpool, github.com/sourcegraph/conc/pool and a bounded
// raw-goroutine baseline; see README.md for the measured tables. | 对比
// github.com/panjf2000/ants/v2、github.com/alitto/pond/v2、github.com/gammazero/workerpool、
// github.com/sourcegraph/conc/pool 与有界裸 goroutine 基线；实测表见 README.md。
//
// Run with | 运行方式：
//
//	cd benchmarks/pool
//	GOWORK=off go test -run '^$' -bench . -benchmem -count 5 -benchtime 1s
//
// The pool/v0.1.0 sub-directory tag must exist for GOWORK=off runs; before it is
// published, use a temporary go.work outside the repository. | GOWORK=off 运行要求
// pool/v0.1.0 子目录标签已存在；发布前请在仓库外使用临时 go.work。
package pool
