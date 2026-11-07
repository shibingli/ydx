# json — 硬件自适应 JSON 编解码（v1 + v2）

`github.com/shibingli/ydx/json` 是 ydx 的 JSON 统一入口。默认构建使用自研原生编解码器：
amd64 使用手写 SSE2/AVX2/AVX-512BW 字符串扫描内核，arm64 使用手写 NEON，其它架构使用
可移植 SWAR/标量路径；显式 `jsonx_std` 标签可回退到标准库。

同一套原生编解码内核同时提供 `encoding/json` v1 与 `encoding/json/v2` 两套 API：不传选项时
保持 v1 行为不变；传入 v2 选项时从 `DefaultOptionsV2` 开始按 v2 语义执行。v2 语义、选项判定、
Marshaler 分派、原始值规范化与错误构造均由本包原生实现，不转调 `encoding/json/v2` 的语义引擎。

| 项 | 值 |
|---|---|
| 模块路径 | `github.com/shibingli/ydx/json` |
| 包名 | `json` |
| Go 版本 | 1.27.3 |
| 许可证 | Apache-2.0 |

## 功能

- 导出与 `encoding/json` 完全对齐的符号集：
  - 函数：`Marshal`、`Unmarshal`、`MarshalIndent`、`Valid`、`Compact`、`Indent`、
    `HTMLEscape`、`NewEncoder`、`NewDecoder`。
  - `Encoder`：`Encode`、`SetEscapeHTML`、`SetIndent`。
  - `Decoder`：`Decode`、`UseNumber`、`DisallowUnknownFields`、`Token`、`More`、
    `Buffered`、`InputOffset`。
  - 类型别名：`Number`、`RawMessage`、`Delim`、`Token`、`Marshaler`、`Unmarshaler`，以及
    全部标准错误类型（`SyntaxError`、`UnmarshalTypeError`、`InvalidUnmarshalError`、
    `UnsupportedTypeError`、`UnsupportedValueError`、`MarshalerError` 与两个已弃用类型）
    和 v1/v2 `Options` 辅助函数。
- 导出与 `encoding/json/v2` 完全对齐的符号集：
  - 函数：`Marshal`、`Unmarshal`（均为 `opts ...Options` 变参）、`MarshalWrite`、
    `UnmarshalRead`、`MarshalEncode`、`UnmarshalDecode`。
  - 选项：`DefaultOptionsV2`、`Deterministic`、`FormatNilMapAsNull`、`FormatNilSliceAsNull`、
    `JoinOptions`、`MatchCaseInsensitiveNames`、`OmitZeroStructFields`、
    `RejectUnknownMembers`、`StringifyNumbers`、`WithMarshalers`、`WithUnmarshalers`、
    `GetOption`，以及全部 v1 兼容选项构造器。
  - 自定义编解码：`MarshalerTo`、`UnmarshalerFrom`、`Marshalers`、`Unmarshalers`、
    `MarshalFunc`、`MarshalToFunc`、`UnmarshalFunc`、`UnmarshalFromFunc`、
    `JoinMarshalers`、`JoinUnmarshalers`。
  - 错误：`SemanticError`、`ErrUnknownName`，与标准库同类型；`errors.As` / `errors.Is`
    可直接使用。
- `Prewarm(samples ...any)`：启动期预编译编码/解码计划。
- `Backend()`：返回 `"yd-native"` 或 `"encoding/json"`。
- 跨后端稳定错误：`ErrSyntax`、`ErrTypeMismatch`，可用 `errors.Is` 判定；同时可用
  `errors.As` 取出与标准库同类型、同文案、同字节偏移的 `*json.SyntaxError`、
  `*json.UnmarshalTypeError` 等错误。

## 兼容 API

与 `encoding/json` v1 逐项对齐的完整接口：

| 类别 | 符号 |
|---|---|
| 函数 | `Marshal`、`Unmarshal`、`MarshalIndent`、`Valid`、`Compact`、`Indent`、`HTMLEscape`、`NewEncoder`、`NewDecoder` |
| `Encoder` | `Encode`、`SetEscapeHTML`、`SetIndent` |
| `Decoder` | `Decode`、`UseNumber`、`DisallowUnknownFields`、`Token`、`More`、`Buffered`、`InputOffset` |
| 类型 | `Number`、`RawMessage`、`Delim`、`Token`、`Marshaler`、`Unmarshaler`（均为 `encoding/json` 类型别名，方法与语义完全继承） |
| 错误类型 | `SyntaxError`、`UnmarshalTypeError`、`InvalidUnmarshalError`、`UnsupportedTypeError`、`UnsupportedValueError`、`MarshalerError`、`InvalidUTF8Error`、`UnmarshalFieldError` |
| v1/v2 选项 | `Options` 与全部 `DefaultOptionsV1` / `CallMethodsWithLegacySemantics` 等辅助函数 |

错误类型、错误文案与字节偏移在两个后端下都与标准库一致，`errors.As` 可直接使用；
`Token` 序列、`More`/`Buffered`/`InputOffset`、`SetIndent`、`DisallowUnknownFields`
的行为均有逐项对拍测试覆盖。

Unicode 与标签别名同样逐项对拍 `encoding/json`：CJK、表情符号（含 ZWJ 组合）、组合
附加符、RTL 文本、控制字符、U+2028/U+2029 与非法 UTF-8 在字符串、对象键与字段名中的
编码/解码；`json:"别名"`、`json:"🚀"`、含空格或标点的标签名、保留字符截断规则、
`omitempty`/`omitzero`/`string`/`-` 选项以及 `SetEscapeHTML` 对字段名的转义。

## v2 API 与语义

`Marshal` / `Unmarshal` 是变参函数，按是否传入选项选择语义：

```go
// v1 行为完全不变。
b, _ := json.Marshal(v)

// v2 语义：从 DefaultOptionsV2 开始应用选项。
b, _ = json.Marshal(v, json.DefaultOptionsV2(), json.Deterministic(true))

// 显式 v1 语义 + 覆盖项。
opts := json.JoinOptions(json.DefaultOptionsV1(), json.FormatDurationAsNano(true))
b, _ = json.Marshal(v, opts)
```

v2 原生覆盖：

- 默认值差异：不转义 HTML / U+2028 / U+2029、nil slice → `[]`、nil map → `{}`、
  大小写敏感字段匹配、拒绝重复键与非法 UTF-8、精确数组长度、`omitempty` 按 JSON 形态判空。
- 选项：`Deterministic`、`FormatNilMapAsNull`、`FormatNilSliceAsNull`、
  `MatchCaseInsensitiveNames`、`OmitZeroStructFields`、`RejectUnknownMembers`、
  `StringifyNumbers`、`FormatByteArrayAsArray`、`FormatDurationAsNano`、
  `AllowDuplicateNames`、`AllowInvalidUTF8`、`EscapeForHTML`、`EscapeForJS`、
  `PreserveRawStrings`、`CanonicalizeRawInts`、`CanonicalizeRawFloats`、`ReorderRawObjects`、
  `Multiline`、`WithIndent`、`WithIndentPrefix`、`SpaceAfterColon`、`SpaceAfterComma`。
- v2 结构体标签：`case:ignore` / `case:strict`、`embed`，以及 `json:",embed"` 的
  `map[string]T` / `jsontext.Value` 嵌入回退。
- 自定义编解码：`MarshalJSONTo` / `UnmarshalJSONFrom`、`MarshalFunc`、`MarshalToFunc`、
  `UnmarshalFunc`、`UnmarshalFromFunc`、`JoinMarshalers` / `JoinUnmarshalers` 均为原生执行。
- 原始值：`jsontext.Value` / `json.RawMessage` 按 v2 规则重写字符串、规范化数字、重排成员，
  Marshaler 输出同样经语义校验与重写。
- 错误：原生构造标准库同类型的 `*jsontext.SyntacticError` 与 `*json.SemanticError`，
  包括重复键、非法 UTF-8、数组长度、未知成员与 `time.Duration` 无默认表示等。

> `encoding/json/v2` 与 `jsontext` 在当前 Go 1.27 工具链中默认启用。若消费方使用
> `GOEXPERIMENT=none` 或更早的工具链，v2 符号不可用；v1 路径不受影响。

## 特性

- **语义基线是标准库**：字符串 HTML 转义、map key 排序、`[]byte` 走 StdEncoding Base64、
  `time.Time` 走 RFC3339Nano，并兼容 `json.Marshaler`、`json.TextMarshaler`、
  `json.RawMessage`、`omitempty`。`Compact` / `Indent` / `HTMLEscape` 的输出、
  `Decoder.Token` / `More` / `Buffered` / `InputOffset` 的行为、`SetIndent` /
  `DisallowUnknownFields` 的语义均与 `encoding/json` 对拍一致。
- **错误类型兼容**：错误路径上用标准库复解析失败输入，取得与 `encoding/json` 完全相同的
  错误类型、文案与偏移；成功路径不受影响。
- **无反射热路径**：按类型缓存编码/解码计划；字段可直接按内存读取的结构体走无反射快速
  编码器；字符串扫描由 SIMD 内核完成。
- **池化缓冲**：中/大载荷先写池化缓冲，再复制为精确大小结果；结构体切片使用按类型池化
  缓冲与一次精确最终分配；字符串使用只追加 arena。
- **启动期预热**：固定载荷类型的服务可在启动期调用 `Prewarm`，把计划构建成本移出首个
  请求；嵌套结构体、切片、数组与 map 递归预热。
- **并发扩展**：解码使用每 P 的解码器池，16→32 P 仍继续提升。
- **无 `GOEXPERIMENT=simd`**：SIMD 内核不需要实验特性；v2 兼容层使用当前工具链默认启用的
  `encoding/json/v2` 类型与选项载体。不依赖 cgo。
- **v1 / v2 同一内核**：v2 选项在原生计划上直接生效，默认 v2 路径与 v1 保持相同的分配特征
  （单对象 Marshal 96 B/1 alloc、Unmarshal 目标外 0 额外分配）。

## 快速开始

```go
package main

import (
	"fmt"

	"github.com/shibingli/ydx/json"
)

type User struct {
	ID    int64  `json:"id"`
	Name  string `json:"name"`
	Email string `json:"email,omitempty"`
}

func main() {
	// 启动期预热固定载荷类型。
	json.Prewarm(User{}, (*User)(nil), (*[]User)(nil))

	b, err := json.Marshal(User{ID: 1, Name: "Ada"})
	if err != nil {
		return
	}

	var out User
	if err := json.Unmarshal(b, &out); err != nil {
		return
	}
	fmt.Println(string(b), out.Name)
}
```

回退到标准库排障：

```bash
go build -tags jsonx_std ./...
```

## 应用场景

- **高 QPS API**：请求/响应体编解码，减少 CPU 与分配。
- **固定载荷服务**：启动期 `Prewarm`，避免首个请求承担计划构建延迟。
- **网关/BFF**：大数组与嵌套对象的序列化。
- **日志与审计**：结构化记录中的嵌套字段编码。
- **跨架构部署**：amd64、arm64 与其它架构共用一套 API。

## 性能指标

基准模块：[`benchmarks/json`](../benchmarks/json/README.md)。参考环境为 AMD Ryzen
AI MAX+ 395（Zen 5，AVX-512）、Go 1.27.3、Linux，`-count=5`、`-benchtime=500ms`
中位数；2026-11-07 在远程 Zen5、Neoverse-N2（arm64）与 Xeon（amd64）三台主机上完成
v2 入口的兼容性与性能复测。

| 场景 | ydx/json | `encoding/json` | goccy | sonic |
|---|---:|---:|---:|---:|
| `Marshal/one` | **73.8 ns** | 312.9 ns | 88.0 ns | 88.5 ns |
| `Marshal/many`（64 对象） | **3.010 µs** | 12.61 µs | 4.173 µs | 3.011 µs |
| `Marshal/large`（1024 对象） | 47.91 µs | 200.5 µs | 66.02 µs | **46.98 µs** |
| `Unmarshal/one` | 126.3 ns | 539.5 ns | **121.1 ns** | 190.3 ns |
| `Unmarshal/many` | **6.718 µs** | 28.71 µs | 6.767 µs | 10.59 µs |
| `Unmarshal/large` | **103.3 µs** | 445.4 µs | 109.0 µs | 162.0 µs |

7 字段 `record` 载荷（含 `time.Time` 与长小数）：

| 场景 | ydx/json v1 | ydx/json v2 | go-json | sonic-std | `encoding/json` |
|---|---:|---:|---:|---:|---:|
| `Marshal/n=1` | 111.0 ns | **109.2 ns** | 124.7 ns | 278.1 ns | 433.9 ns |
| `Marshal/n=100` | 9.60 µs | **9.29 µs** | 11.37 µs | 16.96 µs | 31.85 µs |
| `Marshal/n=1000` | 92.20 µs | **89.60 µs** | 112.6 µs | 175.2 µs | 310.2 µs |
| `Unmarshal/n=1` | **223.8 ns** | 224.5 ns | 246.6 ns | 413.3 ns | 889.7 ns |
| `Unmarshal/n=100` | **16.61 µs** | 16.95 µs | 18.70 µs | 31.11 µs | 78.46 µs |
| `Unmarshal/n=1000` | **163.1 µs** | 168.8 µs | 180.9 µs | 308.3 µs | 765.8 µs |

- 相对标准库：编码快约 4.2–4.3 倍，解码快约 4.3 倍；v2 相对 `stdlib-v2` 见下节。
- v1 在 4/6 主场景最优；`Marshal/large` 与 sonic 相差约 2%，`Unmarshal/one` 与 goccy
  相差约 4%（分配更少：136 B 对 152 B）。v2 在三个编码场景全场最优，解码场景比 v1 慢
  0–3.5%。
- 分配特征与代码生成型实现持平：`Marshal/one` 96 B / 1 alloc，`Marshal/many` 约
  6.16 KiB / 1 alloc；`Unmarshal` 的分配包含目标值本身。
- `Prewarm` 对复杂类型可把首次 `Marshal` 从 42.1 µs 降到 6.43 µs（约 6.6×），
  首次 `Unmarshal` 从 20.8 µs 降到 8.35 µs（约 2.5×）。

> 完整表格、arm64 与并行数据见基准 README；同一轮内小于约 5% 的差异视为噪声。

### v2 API 性能

`benchmarks/json` 现在同时对比 v2 入口：`jsonx-v2`（本包，`DefaultOptionsV2()`）与
`stdlib-v2`（`encoding/json/v2`），并与 `go-json-v2`、goccy、sonic 等同表运行。开发机
（i9-10980HK，Windows，Go 1.27.3）初步中位数：

| 场景 | jsonx-v2 | stdlib-v2 | 相对 |
|---|---:|---:|---:|
| `Marshal/one` | 71.1 ns | 314.3 ns | 4.4× |
| `Marshal/many`（64 对象） | 2.796 µs | 12.84 µs | 4.6× |
| `Marshal/large`（1024 对象） | 43.81 µs | 203.4 µs | 4.6× |
| `Unmarshal/one` | 128.9 ns | 436.5 ns | 3.4× |
| `Unmarshal/many` | 6.830 µs | 24.58 µs | 3.6× |
| `Unmarshal/large` | 105.9 µs | 393.7 µs | 3.7× |

v2 与 v1 使用同一份原生计划与缓冲策略，默认 v2 路径的分配次数与 v1 相同（单对象
Marshal 96 B/1 alloc、Unmarshal 136 B/2 alloc）。重复键与 UTF-8 校验使
`Unmarshal/one`、`Unmarshal/many` 比 v1 慢约 5% 和 2%，其余四个场景与 v1 持平或更快。

## 第三方依赖与鸣谢

本模块没有第三方运行时依赖，只依赖 Go 标准库与 ydx 内部模块（`base64`、`errs`、`sysinfo`）。

基准对比对象：`encoding/json`、[`goccy/go-json`](https://github.com/goccy/go-json)、
[`json-iterator/go`](https://github.com/json-iterator/go)、
[`bytedance/sonic`](https://github.com/bytedance/sonic)、
[`segmentio/encoding`](https://github.com/segmentio/encoding) 与
[`go-json-experiment/json`](https://github.com/go-json-experiment/json)。这些库只出现在
`benchmarks/json`，不进入产品模块依赖。

## 相关模块

- [`base64`](../base64/README.md)：`[]byte` 字段的 Base64 编码。
- [`redis`](../redis/README.md)、[`cache`](../cache/README.md)：缓存载荷序列化。
- [`asynq`](../asynq/README.md)：任务 Payload 编解码。
- [`openapi`](../openapi/README.md)：文档模型只经本模块序列化。

## 许可证

Apache-2.0，见仓库根目录 [`LICENSE`](../LICENSE)。
