# gc — 空闲期垃圾回收调度

`github.com/shibingli/ydx/gc` 把额外的 `runtime.GC` / `debug.FreeOSMemory` 调用安排在
进程空闲窗口，而不是固定墙钟时刻。它等待可配置的安静期、跳过繁忙时段，并在接近内存
上限时强制执行回收。

| 项 | 值 |
|---|---|
| 模块路径 | `github.com/shibingli/ydx/gc` |
| 包名 | `gc` |
| Go 版本 | 1.27.3 |
| 许可证 | Apache-2.0 |

## 功能

- `ModeSoft`：执行 `runtime.GC`，只触发一轮 Go 垃圾回收。
- `ModeRelease`：执行 `debug.FreeOSMemory`，并把空闲页归还操作系统。
- 负载门：默认读取进程自身 CPU 利用率（`runtime/metrics`，相对 `GOMAXPROCS`）；
  `Options.Load` 可替换为业务指标，`Options.Busy` 可追加在途请求数等硬门。
- 安静窗口：负载连续低于 `Options.LoadThreshold` 达到 `Options.QuietWindow` 才回收。
- 堆下限：`Options.MinHeap` 避免在小堆上空转。
- 内存压力：映射堆达到生效内存上限的 `Options.PressureRatio` 时，无论负载如何都回收。
- 自适应退避：回收量过小时把下次间隔翻倍，直至 `Options.MaxInterval`。
- 预设：`gentle`、`balanced`、`aggressive`、`off`。
- 配置驱动：`OptionsFromConfig` 读取 `gc.*` 配置段。

## 特性

- **单协程生命周期**：`Start` 幂等，`Stop` 等待正在执行的回收；协程不会在 `Stop` 成功后
  继续存活。
- **失败关闭**：`Load` / `Busy` 回调发生 panic 或不再上报读数时，按“繁忙”处理，未知
  状态绝不会在高峰触发回收。
- **压力优先**：内存压力压过繁忙门，避免无人值守进程无限增长；压力强制回收后的复查
  间隔不超过一分钟。
- **抖动**：`Options.Jitter` 打散多实例的回收时刻，避免同时停顿。
- **panic 限流**：坏回调每分钟最多上报一次 Error，不会刷爆日志。
- **统计可观测**：`Stats` 返回一致副本，不阻塞在回收上。

## 快速开始

```go
package main

import (
	"context"
	"time"

	"github.com/shibingli/ydx/gc"
)

func main() {
	s, err := gc.New(gc.Options{
		Enabled:       true,
		Interval:      10 * time.Minute,
		Mode:          gc.ModeRelease,
		QuietWindow:   30 * time.Second,
		LoadThreshold: 20, // 进程 CPU 利用率低于 20% 视为空闲
	})
	if err != nil {
		return
	}
	s.Start()
	defer func() {
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		_ = s.Stop(ctx)
	}()

	select {}
}
```

配置驱动：

```go
opts, err := gc.OptionsFromConfig(cfg) // 读取 gc.* 配置段与 strategy 预设
if err != nil {
	return err
}
s, err := gc.New(opts)
```

## 应用场景

- **长驻服务**：在夜间或低峰期把空闲内存归还操作系统，降低 RSS 与容器 OOM 风险。
- **批处理/离线任务**：任务间隙执行软回收，避免固定定时器在业务高峰触发停顿。
- **内存受限容器**：以 cgroup 限额为上限，压力接近阈值时强制执行 `FreeOSMemory`。
- **多实例部署**：通过 jitter 打散回收时刻，避免所有副本同时停顿。
- **手动运维**：`off` 预设关闭后台调度，保留 `Run` 等手动入口供管理接口触发。

## 性能指标

本模块没有独立基准；它不进入请求路径，成本只发生在回收周期：

- 调度器只拥有一个后台协程；稳态下每次唤醒只读一次 CPU 指标与堆指标。
- `ModeSoft` 的成本等于一次 `runtime.GC`；`ModeRelease` 额外调用
  `debug.FreeOSMemory`，会把空闲页归还操作系统，成本更高但降低 RSS。
- 负载门、安静窗口与堆下限共同避免“为了回收而回收”；自适应退避避免对全存活堆反复回收。
- `Stop` 由调用方 context 限定等待，不会无限阻塞；正在执行的回收不可取消。
- 内存压力路径优先于负载门，保证无人值守进程在达到上限前一定回收。

> 具体停顿时间取决于堆大小、对象存活率与 GOGC，无法给出跨程序固定数字。建议在目标
> 服务上用 `GODEBUG=gctrace=1` 或 `runtime/metrics` 观察回收前后的停顿与 RSS。

## 第三方依赖与鸣谢

本模块没有第三方运行时依赖。仓库内依赖：

- [`config`](../config/README.md)：`OptionsFromConfig` 读取 `gc.*` 配置。
- [`log`](../log/README.md)：生命周期与回收记录。
- [`sysinfo`](../sysinfo/README.md)：内存上限与可用内存。
- [`errs`](../errs/README.md)：哨兵错误。

测试使用 `github.com/spf13/afero`（Apache-2.0）构造内存配置。

## 相关模块

- [`sysinfo`](../sysinfo/README.md)：CPU 与内存探测。
- [`config`](../config/README.md)：配置分层与热重载。
- [`log`](../log/README.md)：结构化日志。

## 许可证

Apache-2.0，见仓库根目录 [`LICENSE`](../LICENSE)。
