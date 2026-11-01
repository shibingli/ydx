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

本模块依赖 `github.com/shibingli/ydx/xml v0.1.0`。在该子目录标签发布之前，`go.mod`
中的版本无法从代理解析；请在**仓库之外**创建临时 `go.work`，同时纳入 `xml` 与
`benchmarks/xml` 后运行（不得提交 `replace` 或 `go.work`）：

```bash
mkdir -p /tmp/xmlws && cd /tmp/xmlws
go work init /path/to/ydx/xml /path/to/ydx/benchmarks/xml
cd /path/to/ydx/benchmarks/xml
GOWORK=/tmp/xmlws/go.work go test -run 'Test.*Compatibility' -v
GOWORK=/tmp/xmlws/go.work go test -run '^$' -bench . -benchmem -benchtime=1s -count=5
```

`xml/v0.1.0` 发布后删除临时 workspace，执行 `go mod tidy` 生成最终 `go.sum` 即可按普通
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

## 性能结果（1.7 MB catalog，8000 条记录）

方法：`-benchmem -benchtime=1s`，每台机器 `-count=3` 或 `-count=5` 取中位数；同一轮内
比较，不跨机器混比。吞吐 = 载荷大小 / ns·op。

### AMD Ryzen AI MAX+ 395（Zen 5，AVX-512，32 vCPU）

| 基准 | ydx/xml | encoding/xml | etree | xmlquery | mxj |
|---|---:|---:|---:|---:|---:|
| Parse（DOM/map） | **21.8 ms** / 77 MB/s | — | 28.3 ms | 27.5 ms | 29.8 ms |
| Query（DOM 预解析） | **0.82 ms** / 2.0 GB/s | — | 1.88 ms | 1.53 ms | 0.15 ms¹ |
| Query（流式 Selector） | 11.0 ms / 153 MB/s | — | — | — | — |
| Token 流 | **13.4 ms** / 125 MB/s | 18.7 ms / 91 MB/s | — | — | — |
| Unmarshal | **24.5 ms** / 69 MB/s | 27.1 ms / 61 MB/s | — | — | — |
| Marshal | **6.19 ms** | 6.33 ms | 2.69 ms² | — | 5.25 ms² |
| Valid | 10.3 ms / 164 MB/s | — | — | — | — |

### AMD64 AVX-512（Intel Xeon Platinum，4 vCPU）

| 基准 | ydx/xml | encoding/xml | etree | xmlquery | mxj |
|---|---:|---:|---:|---:|---:|
| Parse | **56.9 ms** / 29.6 MB/s | — | 66.5 ms | 81.3 ms | 82.5 ms |
| Query（DOM） | **3.02 ms** / 558 MB/s | — | 8.01 ms | 4.62 ms | 0.61 ms¹ |
| Query（流式 Selector） | 37.0 ms / 45.5 MB/s | — | — | — | — |
| Token 流 | **44.0 ms** / 38.3 MB/s | 54.0 ms / 31.2 MB/s | — | — | — |
| Unmarshal | **70.2 ms** / 24.0 MB/s | 78.4 ms / 21.5 MB/s | — | — | — |
| Marshal | 20.4 ms | **20.2 ms** | 8.39 ms² | — | 17.2 ms² |
| Valid | 35.1 ms / 48.0 MB/s | — | — | — | — |

### ARM64（aarch64，4 vCPU，NEON）

| 基准 | ydx/xml | encoding/xml | etree | xmlquery | mxj |
|---|---:|---:|---:|---:|---:|
| Parse | **42.1 ms** / 40 MB/s | — | 49.6 ms | 60.9 ms | 69.5 ms |
| Query（DOM） | **1.76 ms** / 956 MB/s | — | 5.36 ms | 3.48 ms | 0.70 ms¹ |
| Query（流式 Selector） | 29.7 ms / 57 MB/s | — | — | — | — |
| Token 流 | **34.9 ms** / 48 MB/s | 42.3 ms / 40 MB/s | — | — | — |
| Unmarshal | **53.2 ms** / 32 MB/s | 59.8 ms / 28 MB/s | — | — | — |
| Marshal | 14.5 ms | **14.2 ms** | 6.33 ms² | — | 13.0 ms² |
| Valid | 28.1 ms / 60 MB/s | — | — | — | — |

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
- **Unmarshal/Marshal**：保留与 `encoding/xml` 完全一致的反射计划语义；Token 层提速
  带动 Unmarshal 比标准库快 11%–17%，Marshal 在 AMD64 上略快、ARM64 上约 2% 慢。
- **DOM 查询**：编译式路径在预解析 DOM 上快于 etree 与 xmlquery；mxj 的 map 查询更快，
  但需计入其最高的 parse 成本。
