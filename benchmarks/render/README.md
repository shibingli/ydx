# benchmarks/render — 编译式模板执行对比

> 环境、指标口径与公平性约定见 [../README.md](../README.md)。

`ydx/render` 把 `html/template` 模板集编译成不可变执行程序：解析与上下文转义仍由
`html/template` 完成，热路径遍历已编译的节点，不再承担 `text/template` 每次渲染的
反射装配。本基准比较它与 `html/template`、`text/template` 的稳态执行成本。

## 对比对象

| 实现 | 版本 | 说明 |
|---|---|---|
| ydx/render | v0.1.0 | 编译式执行器，`tr`/`can` 通过数据键注入 |
| `html/template` | Go 1.27.2 | 语义最接近的对照，保留上下文转义 |
| `text/template` | Go 1.27.2 | 不做 HTML 上下文转义的性能下界 |

## 场景

同一个页面模板：

```html
<h1>{{tr "home.title"}}</h1>
{{if can "user:create"}}<b>yes</b>{{else}}<i>no</i>{{end}}
{{range .Items}}<li>{{tr "item.name" .}}</li>{{end}}
```

- `bindings`：`tr` 返回 `"message"`，`can` 返回 `true`；ydx 通过
  `TranslatorKey`/`AuthzKey` 注入，标准库通过 `FuncMap` 注入。
- `fallback`：不注入译者与权限主体；ydx 的 `tr` 返回键、`can` 返回 `false`，
  标准库的 `FuncMap` 返回同样结果。
- 模板在计时前解析/编译一次；计时只包含执行与写入 `io.Discard`。
- `TestRenderCompareParity` 在测试阶段校验三个引擎对同一数据产出完全相同的页面，
  避免把“输出不同”误当成执行成本差异。

## 关键结果

| 场景 | ydx | html/template | text/template |
|---|---:|---:|---:|
| 带绑定 | 635.3 ns | 6.985 µs | 4.437 µs |
| 无绑定（回退） | 628.0 ns | 7.068 µs | 4.442 µs |

- ydx 比 `html/template` 快约 11 倍，比 `text/template` 快约 7 倍；绑定是否存在对
  ydx 影响很小（635.3 ns vs 628.0 ns）。
- 分配：ydx 为 4 allocs/op、64 B/op；`html/template` 为 70 allocs/op、1.713 KiB/op；
  `text/template` 为 45 allocs/op、1.165 KiB/op。差异主要来自反射调用与每次渲染的
  状态构造。
- 既有 ydx 基准：带译者 665.0 ns，无绑定 631.7 ns，带译者+权限 645.4 ns，与对比表
  同一量级。

## 完整数据

<details>
<summary>5 轮均值</summary>

**github.com/shibingli/ydx/benchmarks/render**

| Benchmark | ns/op | B/op | allocs/op | MB/s |
|---|---:|---:|---:|---:|
| `Render/with_translator` | 665.0 ns | 64 | 4 |  |
| `Render/without_bindings` | 631.7 ns | 64 | 4 |  |
| `Render/with_translator_and_authz` | 645.4 ns | 64 | 4 |  |
| `RenderCompare/bindings/ydx` | 635.3 ns | 64 | 4 |  |
| `RenderCompare/bindings/html` | 6.985 µs | 1.713 KiB | 70 |  |
| `RenderCompare/bindings/text` | 4.437 µs | 1.165 KiB | 45 |  |
| `RenderCompare/fallback/ydx` | 628.0 ns | 64 | 4 |  |
| `RenderCompare/fallback/html` | 7.068 µs | 1.713 KiB | 70 |  |
| `RenderCompare/fallback/text` | 4.442 µs | 1.165 KiB | 45 |  |
</details>

## 复现

```bash
cd benchmarks/render
GOWORK=off go test -run '^$' -bench . -benchmem -count=5 -benchtime=500ms
```

## 口径与限制

- 计时只包含**稳态执行**，不包含模板解析/编译；ydx 的编译成本发生在 `render.New`
  或 dev 模式重编译时。
- `text/template` 是性能下界，不做 HTML 上下文转义；它不保证与 `html/template` 相同
  的安全语义，不能作为生产等价实现。
- 绑定注入方式不同：ydx 使用渲染数据中的 `TranslatorKey`/`AuthzKey`，标准库使用
  `FuncMap` 闭包；两者的函数调用成本接近，但并非逐指令相同。
- 页面只有 4 个 range 元素和两个绑定；更大模板会放大编译执行器的相对优势，也会
  放大输出写入成本。
- 同一轮内 5 个样本不足以给出 95% 置信区间；同一轮内小于约 5% 的差异视为噪声；
  跨轮次绝对数值可能因 CPU 频率/温度漂移。
