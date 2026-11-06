// Package wal benchmarks the ydx WAL against tidwall/wal and rosedblabs/wal.
// | Package wal 将 ydx WAL 与 tidwall/wal、rosedblabs/wal 进行基准对比。
//
// The module is a runtime gate: it depends on the published
// github.com/shibingli/ydx/wal module instead of a local path. During
// development, run it through a go.work file created outside both repositories;
// no replace directive may be committed. | 该模块是运行门禁：依赖已发布的
// github.com/shibingli/ydx/wal 模块而非本地路径。开发期通过两个仓库之外的 go.work
// 运行，不得提交 replace 指令。
//
// Run every comparison with:
// | 运行全部对比：
//
//	GOWORK=off go test -run '^$' -bench . -benchtime 2s -count 5
package wal
