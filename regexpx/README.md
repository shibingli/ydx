# regexpx — 自研正则引擎

`github.com/shibingli/ydx/regexpx` 是仓库唯一的正则表达式入口。它由自研解析器与执行
引擎实现，而不是包装第三方库：兼容 RE2 语法，并支持现有代码依赖的 .NET 构造（环视、
反向引用、命名分组、原子组与占有量词）。

| 项 | 值 |
|---|---|
| 模块路径 | `github.com/shibingli/ydx/regexpx` |
| 包名 | `regexpx` |
| Go 版本 | 1.27.3 |
| 许可证 | Apache-2.0 |
| 默认超时 | 100 ms（`MatchTimeout`） |

## 功能

- `Compile` / `MustCompile`：编译模式。
- `CompilePOSIX` / `MustCompilePOSIX`：POSIX 模式，选择最左最长匹配，并拒绝标准库在
  POSIX 模式下排除的 Perl/.NET 转义与分组。
- 常用方法与标准库镜像：`MatchString`、`FindString`、`FindStringIndex`、`FindAllString`、
  `FindAllStringIndex`、`ReplaceAllString` 等。
- 完整补齐标准库 API：`Longest`、`LiteralPrefix`、`Expand` / `ExpandString`、
  `ReplaceAllLiteral` / `ReplaceAllLiteralString`、`MatchReader`、`FindReaderIndex`、
  `FindReaderSubmatchIndex`、`MarshalText` / `UnmarshalText`、`AppendText`、`Copy`，
  以及包级 `Match` / `MatchString` / `MatchReader`。
- E 变体暴露 `ErrMatchTimeout`，适合校验类调用。
- `FindAllStringParallel` / `FindAllStringIndexParallel`：在大输入且存在可靠起点过滤器时
  并行扫描。
- `QuoteMeta`：转义字面量。

## 特性

- **双引擎**：
  - 不含环视与反向引用的模式运行在线性时间 Pike VM 上，不回溯，代价与输入长度线性相关，
    无需超时。
  - 需要环视/反向引用的模式运行在回溯 VM 上，受强制 `MatchTimeout` 与硬步数预算约束；
    超过任一限制按未匹配处理，校验类调用失败关闭。
- **快速路径**：整模式字面量 SIMD 扫描、单符文重复线性扫描、`(?s).*literal.*` 单次
  字面量搜索、定长序列确定循环、URL 形态确定性遍历、邮箱 `@` 反向扫描、锚定 `^body$`
  的惰性 ASCII DFA。
- **SIMD 预过滤**：amd64 SSE4.1 / SSE4.2 / AVX2 / AVX-512BW 与 arm64 NEON 内核在
  `init` 时选择；AVX-512 只要求 F + BW 与 OS opmask/ZMM 支持，不要求 VBMI。
- **并行扫描**：存在可靠且具选择性的起点过滤器时按块并行；可匹配空串、锚定与回溯模式
  自动回退顺序执行，结果与顺序 API 一致。
- **字节偏移**：所有索引一律是字节偏移，与执行引擎无关。
- **最左最长**：`Longest` 切换为最左最长；线性引擎直接跟踪最长结束位置，含环视/反向引用
  的模式在回溯引擎上从最长候选结束位置向下测试。`Longest` 是配置方法，不得与匹配并发
  执行。
- **兼容 oracle**：`LiteralPrefix` 与 `Longest` 的子匹配/替换路径对 `regexp` 可接受的模式
  惰性使用标准库视图，保证 POSIX 子表达式语义一致；分组 0 的 `MatchString`/`FindString`
  仍走原生引擎，regexpx 独有的 .NET 构造不受影响。
- **Reader 优化**：`MatchReader` 指数分块提前返回；定长且无边界断言的 `FindReaderIndex`/
  `FindReaderSubmatchIndex` 使用滚动窗口，避免读完整个流。

## 快速开始

```go
package main

import (
	"fmt"

	"github.com/shibingli/ydx/regexpx"
)

var (
	tenantRe = regexpx.MustCompile(`^[a-z][a-z0-9_-]*$`)
	dateRe   = regexpx.MustCompile(`\d{4}-\d{2}-\d{2}`)
)

func main() {
	fmt.Println(tenantRe.MatchString("acme_01"))

	loc := dateRe.FindStringIndex("released 2026-10-24")
	if loc != nil {
		fmt.Println("date:", "released 2026-10-24"[loc[0]:loc[1]])
	}

	// 大文本并行查找（结果与顺序 API 一致）。
	text := "... large corpus ..."
	_ = dateRe.FindAllStringIndexParallel(text, -1)
}
```

需要区分“未匹配”和“超时”时，使用 E 变体：

```go
re := regexpx.MustCompile(`^(a+)+$`)
matches, err := re.FindAllStringE("aaaaaaaaaaaaaaaaaaaaaaaa!", -1)
if errors.Is(err, regexpx.ErrMatchTimeout) {
	// 按未匹配处理，失败关闭；matches 是超时前已收集的部分结果。
}
```

> `MatchString` 不返回错误：超过时间或步数预算的回溯匹配直接按未匹配处理。



## 应用场景

- **输入校验**：租户名、ID、日期、邮箱、URL、路径参数。
- **日志/文本解析**：从大文本中批量提取日期、邮箱、URL。
- **WAF/内容过滤**：带超时与步数预算的回溯模式，避免灾难性回溯。
- **路由与请求头**：`middleware/requestid` 等模块做轻量格式校验。
- **大语料扫描**：利用 SIMD 预过滤与并行 API 提高吞吐。

## 性能指标

基准模块：[`benchmarks/regexpx`](../benchmarks/regexpx/README.md)。参考环境为 AMD Ryzen
AI MAX+ 395（Zen 5，AVX-512）、Go 1.27.3、Linux，`GOMAXPROCS=32`，模式在计时外编译，
取中位数。

| 场景 | ydx/regexpx | 标准库 `regexp` | `regexp2` | `go-re2` |
|---|---:|---:|---:|---:|
| `MatchString/literal` | **10.70 ns** | 226.9 ns | 176.4 µs | 2.216 µs |
| `MatchString/email` | **36.73 ns** | 527.1 ns | 170.1 µs | 2.001 µs |
| `MatchString/date` | **38.53 ns** | 492.7 ns | 170.6 µs | 2.032 µs |
| `MatchString/anchored_id` | **11.30 ns** | 120.3 ns | 113.4 ns | 89.67 ns |
| `FindAll/email`（256 KiB） | **94.98 µs** | 5.679 ms | 21.1 ms | 732.3 µs |
| `FindAll/date`（256 KiB） | **110.8 µs** | 3.872 ms | 3.54 ms | 705.5 µs |

- 主表所有匹配/查找/批量扫描场景领先；`FindAll/email` 约为标准库的 1/60、go-re2 的 1/7.7。
- 简单模式编译（`BenchmarkCompile`）仍慢于标准库（约 780 vs 253 ns），属于启动期一次性
  成本，不影响请求热路径。
- 并行 API 在 4 MiB 文本上对日期/邮箱有收益（4.11 ms → 2.94 ms；3.47 ms → 2.65 ms）；
  小语料与密集通用 NFA 扫描建议使用顺序 API。
- 各 SIMD 回退路径结果一致；没有 AVX2 时按 SSE4.2 → SSE4.1 → 标量回退。

> 绝对值受 CPU 与负载影响；跨实现比较请优先看同一行相对值。完整 32 场景、arm64 与
> AVX-512 数据见基准 README。

## 第三方依赖与鸣谢

本模块没有第三方运行时依赖，只依赖 Go 标准库与 `ydx/errs`。

基准对比对象：标准库 `regexp`、[`grafana/regexp`](https://github.com/grafana/regexp)、
[`dlclark/regexp2`](https://github.com/dlclark/regexp2) 与
[`wasilibs/go-re2`](https://github.com/wasilibs/go-re2)。它们只出现在
`benchmarks/regexpx`，不进入产品模块依赖。

## 相关模块

- [`router`](../router/README.md)：路由模式解析与参数校验。
- [`middleware/requestid`](../middleware/requestid/README.md)：请求 ID 格式校验。
- [`openapi`](../openapi/README.md)：注解解析中的模式处理。

## 许可证

Apache-2.0，见仓库根目录 [`LICENSE`](../LICENSE)。
