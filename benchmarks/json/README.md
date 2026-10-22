# benchmarks/json — 自适应 JSON 对比

> 环境、指标口径与公平性约定见 [../README.md](../README.md)。

`ydx/json` 在 amd64 上使用自研原生编解码器，非 amd64 使用 `goccy/go-json`，
`jsonx_std` 构建标签回退到 `encoding/json`。本基准在 amd64 上比较原生后端与四个
主流 JSON 实现，所有实现解析同一份固定结构体载荷。

## 对比对象

| 实现 | 版本 | 配置 |
|---|---|---|
| ydx/json | v0.1.0（amd64 原生后端） | 默认构建 |
| `encoding/json` | Go 1.27.2 | 标准库 |
| `github.com/goccy/go-json` | v0.11.2 | 默认配置 |
| `github.com/json-iterator/go` | v1.1.12 | `ConfigCompatibleWithStandardLibrary` |
| `github.com/bytedance/sonic` | v1.15.4 | 默认配置，运行时 JIT |
| `github.com/segmentio/encoding/json` | v0.5.4 | 默认配置 |

## 场景

- `Marshal/one`：单个 5 字段用户对象。
- `Marshal/many`：64 个相同用户对象组成的切片。
- `Unmarshal/one`、`Unmarshal/many`：解码到每次新建的目标值。
- 每个子基准在计时前执行一次预热，避免首次缓存与 sonic 的运行时编译污染稳态。

## 关键结果

| 场景 | ydx | stdlib | goccy | jsoniter | sonic | segmentio |
|---|---:|---:|---:|---:|---:|---:|
| `Marshal/one` | 328.7 ns | 682.3 ns | 220.4 ns | 332.1 ns | 224.1 ns | 264.8 ns |
| `Marshal/many` | 10.84 µs | 31.15 µs | 9.973 µs | 17.76 µs | 8.262 µs | 13.35 µs |
| `Unmarshal/one` | 491.6 ns | 1.318 µs | 427.3 ns | 626.7 ns | 794.4 ns | 740.6 ns |
| `Unmarshal/many` | 36.13 µs | 75.17 µs | 25.99 µs | 43.31 µs | 43.24 µs | 48.30 µs |

- 相对标准库：`Marshal/many` 快约 2.9 倍，`Unmarshal/many` 快约 2.1 倍，单对象路径
  也快约 2 倍；这是自适应层的核心收益。
- 相对专用高性能库：goccy 与 sonic 在多数场景仍领先 8%–30%；ydx 在 `Marshal/one`
  上接近 jsoniter，落后 goccy/sonic；`Unmarshal/one` 介于 goccy 与 jsoniter 之间。
  在 64 对象解码上，ydx 明显快于 jsoniter、sonic 与 segmentio。
- 分配：`Marshal/many` 为 2 allocs/op、8.688 KiB/op（输出缓冲按增长策略扩容）；
  goccy 为 1 alloc/op、6.005 KiB/op。`Unmarshal/many` 为 69 allocs/op，标准库为
  200 allocs/op。

## 完整数据

<details>
<summary>5 轮均值</summary>

**github.com/shibingli/ydx/benchmarks/json**

| Benchmark | ns/op | B/op | allocs/op | MB/s |
|---|---:|---:|---:|---:|
| `Marshal/one/jsonx` | 328.7 ns | 96 | 1 |  |
| `Marshal/one/stdlib` | 682.3 ns | 160 | 2 |  |
| `Marshal/one/goccy` | 220.4 ns | 96 | 1 |  |
| `Marshal/one/jsoniter` | 332.1 ns | 96 | 1 |  |
| `Marshal/one/sonic` | 224.1 ns | 116 | 2 |  |
| `Marshal/one/segmentio` | 264.8 ns | 96 | 1 |  |
| `Marshal/many/jsonx` | 10.84 µs | 8.688 KiB | 2 |  |
| `Marshal/many/stdlib` | 31.15 µs | 6.027 KiB | 2 |  |
| `Marshal/many/goccy` | 9.973 µs | 6.005 KiB | 1 |  |
| `Marshal/many/jsoniter` | 17.76 µs | 6.005 KiB | 1 |  |
| `Marshal/many/sonic` | 8.262 µs | 6.118 KiB | 2 |  |
| `Marshal/many/segmentio` | 13.35 µs | 6.005 KiB | 1 |  |
| `Unmarshal/one/jsonx` | 491.6 ns | 176 | 3 |  |
| `Unmarshal/one/stdlib` | 1.318 µs | 176 | 4 |  |
| `Unmarshal/one/goccy` | 427.3 ns | 152 | 2 |  |
| `Unmarshal/one/jsoniter` | 626.7 ns | 208 | 8 |  |
| `Unmarshal/one/sonic` | 794.4 ns | 299 | 5 |  |
| `Unmarshal/one/segmentio` | 740.6 ns | 256 | 6 |  |
| `Unmarshal/many/jsonx` | 36.13 µs | 14.06 KiB | 69 |  |
| `Unmarshal/many/stdlib` | 75.17 µs | 16.10 KiB | 200 |  |
| `Unmarshal/many/goccy` | 25.99 µs | 10.29 KiB | 66 |  |
| `Unmarshal/many/jsoniter` | 43.31 µs | 18.10 KiB | 456 |  |
| `Unmarshal/many/sonic` | 43.24 µs | 21.28 KiB | 137 |  |
| `Unmarshal/many/segmentio` | 48.30 µs | 21.96 KiB | 325 |  |
</details>

## 复现

```bash
cd benchmarks/json
GOWORK=off go test -run '^$' -bench . -benchmem -count=5 -benchtime=500ms
```

## 口径与限制

- 本机是 amd64，ydx 走自研原生后端；非 amd64 会走 goccy，结果不同。
- jsoniter 使用与标准库兼容配置，而不是 `ConfigFastest`；后者会放宽部分语义，无法与
  其它实现直接对比。
- sonic 首次调用包含运行时编译；基准在计时区外预热，但 JIT 结果会受 CPU 特性影响。
- `Unmarshal` 每次迭代创建新目标值，分配数包含目标分配；这使所有解码器承担相同的
  目标构造成本。
- 同一轮内 5 个样本不足以给出 95% 置信区间；同一轮内小于约 5% 的差异视为噪声；
  跨轮次绝对数值可能因 CPU 频率/温度漂移。
