// Package cron contains the benchmarks for github.com/shibingli/ydx/cron. |
// Package cron 保存 github.com/shibingli/ydx/cron 的基准。
//
// Parsing and Next are compared with github.com/robfig/cron/v3; the scheduler
// create/list/get/remove paths are compared with robfig/cron/v3 and
// github.com/go-co-op/gocron/v2; github.com/adhocore/gronx supplies a
// parse-and-next reference. The module also contains a correctness gate that
// compares 200 consecutive activations with robfig for every shared syntax
// form. | 解析与 Next 对比 github.com/robfig/cron/v3；调度器创建、列举、读取与删除路径
// 对比 robfig/cron/v3 与 github.com/go-co-op/gocron/v2；github.com/adhocore/gronx
// 提供“解析 + 下次触发”参考。模块还包含正确性门禁：对所有共享语法形式与 robfig 比较
// 连续 200 次触发。
//
// Run with | 运行方式：
//
//	cd benchmarks/cron
//	GOWORK=off go test -run '^$' -bench . -benchmem -count=5 -benchtime=500ms
//
// The module requires the published cron/v0.1.1 tag; until that tag is pushed,
// use a temporary go.work outside the repository. | 模块需要已发布的 cron/v0.1.1
// 标签；标签推送前请在仓库外使用临时 go.work。
package cron
