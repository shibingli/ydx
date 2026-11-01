# benchmarks/xml — ydx/xml 与主流 XML 库对比

本模块将 `github.com/shibingli/ydx/xml` 与标准库 `encoding/xml` 以及三个主流第三方
XML 库做兼容性与性能对比：

| 库 | 定位 |
|---|---|
| `encoding/xml` | 标准库 Token / Unmarshal / Marshal 基线 |
| `github.com/beevik/etree` | 轻量 DOM + 路径查询 |
| `github.com/antchfx/xmlquery` | DOM + 完整 XPath 1.0 |
| `github.com/clbanning/mxj/v2` | XML ↔ `map[string]interface{}` 转换与路径取值 |

## 发布门禁与运行方式

本模块依赖 `github.com/shibingli/ydx/xml v0.1.1`。在该子目录标签发布之前，`go.mod`
中的版本无法从代理解析；请在**仓库之外**创建临时 `go.work`，同时纳入 `xml` 与
`benchmarks/xml` 后运行（不得提交 `replace` 或 `go.work`）：

```bash
mkdir -p /tmp/xmlws && cd /tmp/xmlws
go work init /path/to/ydx/xml /path/to/ydx/benchmarks/xml
cd /path/to/ydx/benchmarks/xml
GOWORK=/tmp/xmlws/go.work go test -run 'Test.*Compatibility' -v
GOWORK=/tmp/xmlws/go.work go test -run '^$' -bench . -benchmem -benchtime=1s -count=5
```

`xml/v0.1.1` 发布后删除临时 workspace，执行 `go mod tidy` 生成最终 `go.sum` 即可按普通
基准模块运行。

## 兼容性结果

共享语料覆盖：属性、谓词、命名空间、CDATA、字符实体、注释、嵌套路径、8000 条记录的大
文档、以及 50 个随机生成的合法文档。所有测试通过（`go test -run Test.*Compatibility`）。

| 能力 | ydx/xml | etree | xmlquery | mxj |
|---|:---:|:---:|:---:|:---:|
| 元素文本 / 属性 / 谓词 | ✅ | ✅ | ✅ | ✅ |
| 命名空间限定查询 | ✅ Clark `{uri}local` | ✅ 前缀 | ✅ `local-name()` | ✅ 丢弃前缀 |
| CDATA / 实体解码 | ✅ | ✅ | ✅ | ✅ |
| 注释 | ✅ DOM 节点 | ✅ 树节点 | ✅ `comment()` | ❌ 丢弃 |
| 完整 XPath 1.0 | 子集（路径/谓词/后代轴） | 子集 | ✅ | 路径语法不同 |
| 流式解析（O(深度) 内存） | ✅ Decoder / Selector / EachFile | ❌ 需整树 | ❌ 需整树 | ❌ 需整 map |
| UTF-16 BOM 自动转码 | ✅ 原生后端 | ❌ | ❌ | ❌ |
| 内部 DTD 实体（带预算） | ✅ 原生后端 | ❌ | ❌ | ❌ |
| 结构体反序列化 / 序列化 | ✅ 完整 `encoding/xml` 语义 | 手写映射 | 手写映射 | 手写映射 |

语义说明：

- ydx 路径以元素终结时，`Value`/`Values` 返回该元素的**直接文本**（与 `text()` 一致）；
  `xmlquery.InnerText()` 返回全部后代文本。对比测试统一使用叶子元素，避免口径差异。
- etree 的 `Space` 保留前缀，ydx 与 xmlquery 解析为命名空间 URL；对比时按各自约定断言。
- mxj 是 map 化表示，不保留注释、前缀与顺序；其 `ValuesForPath` 查询非常快，但 parse
  成本与内存最高。

## API 兼容性测试

`api_compat_test.go` 用共享语料与 `encoding/xml` 逐项对拍：

- `TestStdlibTokenCompatibility`：`Token` 与 `RawToken` 流（起始/结束元素、属性、
  字符数据、注释、CDATA、处理指令、指令、命名空间）；
- `TestStdlibUnmarshalCompatibility`：结构体反序列化（属性、嵌套元素、数值）；
- `TestStdlibMarshalCompatibility`：`Marshal`、`MarshalIndent`、`Encoder.Encode` 与
  缩进输出；
- `TestStdlibEscapeCompatibility`：`EscapeText` 与 `Header`；
- `TestDOMAgainstStdlibTokens`：DOM 路径查询结果与标准库 Token 流解码结果一致；
- `TestUnicodeTokenCompatibility`、`TestUnicodeMarshalCompatibility`、
  `TestUnicodeEscapeCompatibility`：CJK 元素/属性名与文本、表情符号、数字字符引用、
  注释/CDATA/PI、CJK 标签别名（`xml:"别名"`、`xml:"类型,attr"`、`xml:",chardata"`）
  以及非法 UTF-8 输入与 `encoding/xml` 一致。

## 性能结果（1.7 MB catalog，8000 条记录）

方法：`-benchmem -benchtime=1s`，每台机器 `-count=3` 或 `-count=5` 取中位数；同一轮内
比较，不跨机器混比。吞吐 = 载荷大小 / ns·op。

### AMD Ryzen AI MAX+ 395（Zen 5，AVX-512，32 vCPU）

| 基准 | ydx/xml | encoding/xml | etree | xmlquery | mxj |
|---|---:|---:|---:|---:|---:|
| Parse（DOM/map） | **22.55 ms** / 71.3 MB/s | — | 28.09 ms | 29.15 ms | 34.60 ms |
| Query（DOM 预解析） | **0.865 ms** / 1.82 GB/s | — | 1.814 ms | 1.489 ms | 0.157 ms¹ |
| Query（流式 Selector） | 11.20 ms / 143.6 MB/s | — | — | — | — |
| Token 流 | **13.46 ms** / 119.5 MB/s | 18.67 ms / 86.1 MB/s | — | — | — |
| Unmarshal | **22.79 ms** / 70.5 MB/s | 27.07 ms / 59.4 MB/s | — | — | — |
| Marshal | **3.758 ms** | 6.358 ms | 2.935 ms² | — | 5.692 ms² |
| Valid | 10.30 ms / 156.1 MB/s | — | — | — | — |

### AMD64 AVX-512（Intel Xeon Platinum，4 vCPU）

| 基准 | ydx/xml | encoding/xml | etree | xmlquery | mxj |
|---|---:|---:|---:|---:|---:|
| Parse | **56.92 ms** / 28.25 MB/s | — | 67.21 ms | 81.09 ms | 82.11 ms |
| Query（DOM） | **3.266 ms** / 492 MB/s | — | 8.684 ms | 5.179 ms | 0.650 ms¹ |
| Query（流式 Selector） | 36.67 ms / 43.84 MB/s | — | — | — | — |
| Token 流 | **41.85 ms** / 38.41 MB/s | 51.41 ms / 31.27 MB/s | — | — | — |
| Unmarshal | **68.93 ms** / 23.33 MB/s | 76.51 ms / 21.01 MB/s | — | — | — |
| Marshal | **12.94 ms** | 21.85 ms | 9.406 ms² | — | 18.83 ms² |
| Valid | 34.83 ms / 46.16 MB/s | — | — | — | — |

### ARM64（aarch64，4 vCPU，NEON）

| 基准 | ydx/xml | encoding/xml | etree | xmlquery | mxj |
|---|---:|---:|---:|---:|---:|
| Parse | **42.17 ms** / 38.13 MB/s | — | 49.93 ms | 61.17 ms | 70.04 ms |
| Query（DOM） | **1.932 ms** / 832 MB/s | — | 6.266 ms | 4.267 ms | 0.857 ms¹ |
| Query（流式 Selector） | 29.22 ms / 55.03 MB/s | — | — | — | — |
| Token 流 | **33.86 ms** / 47.47 MB/s | 42.17 ms / 38.13 MB/s | — | — | — |
| Unmarshal | **53.45 ms** / 30.08 MB/s | 61.14 ms / 26.29 MB/s | — | — | — |
| Marshal | **10.40 ms** | 16.69 ms | 7.539 ms² | — | 15.72 ms² |
| Valid | 27.96 ms / 57.50 MB/s | — | — | — | — |

### 本机 Windows（Intel i9-10980HK，AVX2，16 线程）

| 基准 | ydx/xml | encoding/xml | etree | xmlquery | mxj |
|---|---:|---:|---:|---:|---:|
| Parse | **37.0 ms** / 46 MB/s | — | 48.1 ms | 56.8 ms | 61.2 ms |
| Query（DOM） | **2.76 ms** / 611 MB/s | — | 5.00 ms | 4.23 ms | 0.37 ms¹ |
| Query（流式 Selector） | 26.2 ms / 64 MB/s | — | — | — | — |
| Token 流 | **27.8 ms** / 61 MB/s | 38.3 ms / 44 MB/s | — | — | — |
| Unmarshal | **44.6 ms** / 38 MB/s | 52.2 ms / 32 MB/s | — | — | — |
| Marshal | **13.6 ms** | 15.5 ms | 6.35 ms² | — | 13.4 ms² |
| Valid | 27.1 ms / 62 MB/s | — | — | — | — |

脚注：

1. mxj 的查询是已构建 map 的键查找，不遍历 XML 树；其 Parse 成本与内存最高，需按
   “parse + query”总成本比较。
2. etree 与 mxj 的序列化对象是已解析的树/map，而 ydx 与 encoding/xml 的 `Marshal`
   对 Go 结构体做反射编组；两者不是同一操作的严格对照，仅供参考。

## 观察与已执行的优化

- **Token 流**：事件化内部路径去掉 Token 接口装箱后，分配从 240k/10.5 MB 降到
  144k/5.95 MB，吞吐较标准库高 21%–38%。
- **DOM Parse**：同样的无装箱事件路径把分配从 448k/29 MB 降到 208k/18.4 MB，速度超过
  etree（本机 +30%，Zen 5 +23%，ARM64 +15%），内存与 etree 基本持平。
- **Selector / Valid**：分配从 240k/10.5 MB 降到 8k/387 KB，吞吐提升约 50%–130%；
  内存只与深度和在途匹配文本相关。
- **Unmarshal**：保留与 `encoding/xml` 完全一致的反射计划语义；Token 层提速带动
  Unmarshal 比标准库快约 16%（22.79 ms vs 27.07 ms）。
- **Marshal**：2026-11-01 完成三项优化——纯 ASCII 文本走 SWAR 转义扫描快速路径、
  `Marshal`/`MarshalIndent` 直接写入单个字节切片（去掉 `bytes.Buffer` + `bufio.Writer`
  中转）、非结构体类型跳过 `sync.Map` 类型信息查找并为预声明类型跳过四次接口探测。
  Zen 5 上从 6.35 ms 降到 3.76 ms（1.69×），快于标准库（6.36 ms）与 mxj（5.69 ms），
  分配从 11.6k 次降到 9.9k 次；与 etree 的 2.94 ms 仍有约 1.28× 差距，但 etree 序列化的是
  已解析树，而 ydx 与标准库一样是对 Go 结构体做反射编组（见脚注 2）。
- **DOM 查询**：编译式路径在预解析 DOM 上快于 etree 与 xmlquery；mxj 的 map 查询更快，
  但需计入其最高的 parse 成本。
