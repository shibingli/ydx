# workflow 基准 — 调度器扫描与实例发起

本模块测量 `github.com/shibingli/ydx/workflow` 的调度器生命周期、空扫描与最小实例发起。
工作流引擎没有可直接对比的主流 Go 实现（BPMN 引擎的状态模型、审批语义与存储接口差异过大），
因此这里只给出 ydx 的绝对值，作为回归基线而不是跨库排名。

## 环境与口径

- 主机：Windows 11，Intel Core i9-10980HK（8 核 16 线程），Go 1.27.3，`GOMAXPROCS=16`。
- 存储：`glebarez/sqlite` 临时文件数据库（纯 Go，无 CGO），每个基准独立建库并迁移。
- 采样：`-count=5 -benchtime=500ms -benchmem`，取中位数；SQLite 的 fsync 与后台负载会
  让绝对值波动，表内数字只用于同一环境的回归比较。
- 正确性：`go test ./... -race` 覆盖调度器、共享实例、定时事件与多副本领取；基准不替代
  正确性测试。

## 结果

| 场景 | ns/op | B/op | allocs/op |
|---|---:|---:|---:|
| 调度器启动 + 停止（私有 cron，1h 间隔） | 65.6 µs | 4.0 KiB | 48 |
| 空扫描一次（`RunOnce`，无到期工作） | 516 µs | 64.2 KiB | 316 |
| 发起最小实例（开始 → 结束，SQLite） | 6.66 ms | 150 KiB | 1470 |

## 口径说明

1. **启动 + 停止**包含 `ydx/cron` 的实例创建、任务注册、事件循环与工作协程的启动和关闭；
   共享调度器模式不创建私有 cron 实例，生命周期由应用负责。
2. **空扫描**调用 `Service.RunDue`，依次查询到期催办、待投递通知与到期定时令牌；空库也
   要支付三次 SQLite 查询与事务开销，因此 64 KiB/316 allocs 主要来自 GORM 与 SQLite，
   不是调度器本身。真实部署应按到期记录数量评估扫描成本。
3. **发起实例**包含定义版本读取、实例/令牌/事件写入与自动完成；SQLite 事务提交占主导。
   它用于观察引擎写路径的回归，不应与内存型状态机直接比较。
4. 所有基准的数据库与迁移都在计时区之外；`StartInstance` 的数据库会随 `b.N` 增长，
   后段迭代承担更大的表，绝对值偏保守。

## 复现

```bash
cd benchmarks/workflow
GOWORK=off go test -run '^$' -bench . -benchmem -count=5 -benchtime=500ms
```

本模块依赖已发布的 `workflow/v0.1.3` 子目录标签。标签推送前可在仓库外创建临时 `go.work`
或使用本地 `replace` 联调；`go.work` 与 `replace` 都不得提交。
