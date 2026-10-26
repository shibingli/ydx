# sysinfo — 运行时容量与内存探测

`github.com/shibingli/ydx/sysinfo` 提供算法确定并行度、缓冲大小与内存预算所需的运行时
容量：逻辑 CPU、`GOMAXPROCS`、主机内存、cgroup 限额与当前可用内存。所有取值都来自进程
运行环境，不写死硬件假设。

| 项 | 值 |
|---|---|
| 模块路径 | `github.com/shibingli/ydx/sysinfo` |
| 包名 | `sysinfo` |
| Go 版本 | 1.27.3 |
| 许可证 | Apache-2.0 |

## 功能

- `NumCPU` / `GOMAXPROCS` / `Parallelism`：返回逻辑 CPU、调度器并行度与至少为 1 的
  CPU 密集工作协程数。
- `IsMultiCore`：判断当前环境是否有多于一个调度槽，供算法选择并行或串行路径。
- `MemoryTotal`：返回进程可见的总内存字节数。
- `MemoryLimit`：返回生效内存上限，即主机总量与 cgroup 限额中的较小者。
- `MemoryAvailable`：返回当前可用内存字节数。
- `CPUSnapshot` / `CPUSample`：读取进程 CPU 利用率快照，供 GC 调度等后台策略使用。

## 特性

- **容器感知**：Linux 上读取 cgroup v1/v2 限额，并与 `/proc/meminfo` 的主机总量取较小值；
  cgroup 的 `max` 与接近 2^63 的“无限”哨兵值会归一化为 0。
- **平台可缺失**：平台无法提供某项数值时返回 0，调用方据此回退到保守默认值，而不是
  把未知当成无限资源。
- **启动期缓存**：`MemoryTotal` / `MemoryLimit` 通过 `sync.Once` 只读取一次；
  `MemoryAvailable` 随运行变化，因此不缓存。
- **无第三方依赖**：只使用 Go 标准库与平台系统调用/伪文件。
- **双重语义**：`NumCPU` 是硬件视角，`GOMAXPROCS` / `Parallelism` 是调度器视角；容器
  CPU 配额在后者的语义下更准确。

## 快速开始

```go
package main

import (
	"fmt"

	"github.com/shibingli/ydx/sysinfo"
)

func main() {
	workers := sysinfo.Parallelism()
	fmt.Printf("cpus=%d gomaxprocs=%d workers=%d\n",
		sysinfo.NumCPU(), sysinfo.GOMAXPROCS(), workers)

	if limit := sysinfo.MemoryLimit(); limit > 0 {
		fmt.Printf("memory limit: %d MiB\n", limit>>20)
	}
	if avail := sysinfo.MemoryAvailable(); avail > 0 {
		fmt.Printf("memory available: %d MiB\n", avail>>20)
	}

	if sysinfo.IsMultiCore() {
		// 启用并行扫描/并行压缩等路径。
	}
}
```

## 应用场景

- **工作池 sizing**：把 `Parallelism()` 作为 CPU 密集型 worker 数的默认值。
- **缓冲与批大小**：按 `MemoryLimit()` 的比例决定缓存预算、批处理字节数或压缩窗口。
- **内存压力策略**：结合 `MemoryAvailable()` 与 GC 调度器决定是否提前回收。
- **自适应算法**：base64/json/regexpx 等模块按核心数与指令集选择并行路径。
- **容器部署**：避免读 `runtime.NumCPU()` 得到宿主机核数却忽略 cgroup 配额。

## 性能指标

本模块没有独立基准；查询成本按设计分为三档：

| 查询 | 成本 | 说明 |
|---|---|---|
| `NumCPU` / `GOMAXPROCS` / `Parallelism` | 极低 | 直接调用 `runtime`，无堆分配 |
| `MemoryTotal` / `MemoryLimit` | 首次读取后近似免费 | `sync.Once` 缓存；首次读取 `/proc/meminfo` 或 cgroup 文件 |
| `MemoryAvailable` | 每次读取 | 需要读取 `/proc/meminfo` 或平台接口，适合低频采样而非逐请求调用 |
| `CPUSnapshot` | 每次采样 | 读取 `runtime/metrics`，供后台策略使用 |

> 不要在每个请求中调用 `MemoryAvailable`；把结果缓存在调度器或健康检查周期中。

## 第三方依赖与鸣谢

本模块只依赖 Go 标准库，没有第三方运行时依赖。

## 相关模块

- [`gc`](../gc/README.md)：使用内存上限与可用内存做压力判定。
- [`base64`](../base64/README.md)、[`json`](../json/README.md)、[`regexpx`](../regexpx/README.md)：
  按 `Parallelism()` 选择并行内核。
- [`log`](../log/README.md)：构造期读取主机名等环境信息。

## 许可证

Apache-2.0，见仓库根目录 [`LICENSE`](../LICENSE)。
