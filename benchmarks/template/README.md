# Go 模板引擎兼容性与性能基准

独立 Go 模块，对比 `ydx/render` 编译式 HTML 引擎（yd 框架使用同一引擎）与主流 Go 模板引擎。所有实现共享**同一份数据、
同一份页面语义**，并分别用各引擎的惯用语法表达；转义、布局、包含与自定义函数能力由
`BenchmarkEngines` / `TestEscapingMatrix` 实际执行验证，而不是按文档推断。

## 工作负载

一个 100 行的列表页（`page100`）和一个 5 行的短页（`small5`），两者使用同一模板：

- HTML 文本、带引号属性、URL 查询串三类上下文；
- `if/else`、`range`、嵌套字段访问；
- 每行 7 个字段（ID、Name、Email、URL、Class、Note、Active）；
- 数据中带有 `<script>`、`"`、`&`、`<` 等必须被转义的字符。

输出约 25 KB（100 行），因此基准同时衡量循环开销、上下文转义与输出缓冲管理。

各引擎模板位于 `templates/`；quicktemplate 与 templ 的生成代码（`page_qtpl.go`、
`page_templ.go`）随模块提交，生成命令见文末。

## 运行

```bash
cd benchmarks/template

# 正确性 + 转义矩阵
go test ./...

# 多核
go test -run '^$' -bench BenchmarkEngines -benchmem -benchtime=1s -count=5

# 单核
GOMAXPROCS=1 go test -run '^$' -bench BenchmarkEngines -benchmem -benchtime=1s -count=5

# 输出物化（所有引擎写入可复用的 bytes.Buffer）
go test -run '^$' -bench BenchmarkEnginesMaterialized -benchmem -benchtime=2s -count=5

# 每实现独立进程，消除同进程顺序与 GC 偏差
for e in yd-render html/template text/template jet pongo2 liquid raymond mustache quicktemplate templ; do
  YD_BENCH_ONLY=$e go test -run '^$' -bench BenchmarkEngines -benchmem -benchtime=1s -count=5
done
```

`YD_BENCH_ONLY` 接受逗号分隔的引擎名。

## 渲染微基准（并入自原 benchmarks/render）

原 `benchmarks/render` 与 `benchmarks/template` 都在对比 `ydx/render` 与 `html/template`、
`text/template`，属于同一引擎的重复对比，已合并到本模块：

- `BenchmarkRender`：`tr` / `can` 绑定、权限主体与无绑定回退的稳态执行成本；
- `BenchmarkRenderCompare`：同一页面在 ydx、`html/template`、`text/template` 上的
  `bindings` / `fallback` 两组对比，并有 `TestRenderCompareParity` 校验三者输出逐字节一致。

```bash
go test -run '^$' -bench '^BenchmarkRender$' -benchmem -count=5 -benchtime=500ms
go test -run '^$' -bench '^BenchmarkRenderCompare$' -benchmem -count=5 -benchtime=500ms
```

Zen 5 参考主机结果：`bindings/ydx` **253.7 ns**（html/template 3.43 µs、text/template
2.12 µs），`fallback/ydx` **253.5 ns**（html/template 3.41 µs、text/template 2.13 µs）；
ydx 为 4 allocs/op、64 B/op，另两者为 70/45 allocs、1.7/1.2 KiB/op。

## 兼容性矩阵

✅ 原生支持；⚠️ 需要显式配置或仅部分支持；❌ 不支持。

| 能力 | **yd-render** | html/template | text/template | Jet | Pongo2 | Liquid | Raymond | Mustache | quicktemplate | templ |
|---|---|---|---|---|---|---|---|---|---|---|
| 兼容 html/template 语法 | ✅ | ✅ | ✅ | ❌ | ❌ | ❌ | ❌ | ❌ | ❌（Go 代码生成） | ❌（Go 代码生成） |
| 默认 HTML 自动转义 | ✅ | ✅ | ❌ | ✅ | ✅ | ⚠️ 需 `SetAutoEscapeReplacer` | ✅ | ✅ | ⚠️ 需 `{%s %}` | ✅ |
| 上下文感知转义（属性/URL/JS/CSS） | ✅ | ✅ | ❌ | ❌（仅 HTML） | ❌（仅 HTML） | ❌（仅 HTML） | ❌（仅 HTML） | ❌（仅 HTML） | ❌（手动选择 `{%q %}`/`{%u %}`） | ✅ |
| 危险 URL 协议拦截 | ✅ | ✅ | ❌ | ❌ | ❌ | ❌ | ❌ | ❌ | ❌ | ✅ |
| 布局/模板继承 | ✅ `define`/`template`/`block` | ✅ | ✅ | ✅ `extends`/`block` | ✅ `extends`/`block` | ✅ `layout` | ❌（用 partial 组合） | ❌（用 partial 组合） | ✅ Go 组合/嵌入 | ✅ 组件组合 |
| 包含/局部模板 | ✅ | ✅ | ✅ | ✅ `include` | ✅ `include` | ✅ `include` | ✅ partial | ✅ partial | ✅ Go 函数调用 | ✅ 组件调用 |
| 自定义函数 | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ 过滤器 | ✅ helper | ❌（logic-less） | ✅ Go 函数 | ✅ Go 函数 |
| 安全类型绕过转义 | ✅ `template.HTML` 等 | ✅ | ❌（无转义） | ✅ `safeHtml` | ✅ `safe` 过滤器 | ⚠️ `raw` 过滤器 | ✅ `SafeString` | ✅ 三花括号 | ✅ `{%s= %}` | ✅ `templ.SafeHTML` |
| 模板预编译/缓存 | ✅ 加载期编译为不可变程序 | ✅ 首次执行时转义并缓存 | ✅ 解析树缓存 | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ 编译期生成 Go | ✅ 编译期生成 Go |
| 并发安全渲染 | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ |
| 运行时第三方依赖 | 0（标准库 + 本仓） | 0 | 0 | 1 | 2 | 3 | 2 | 1 | 1 | 1 |

### 转义矩阵（`go test -run TestEscapingMatrix -v` 实测）

敌意输入：文本 `<script>alert(...)</script>`、属性 `" onmouseover="alert(...)`、
URL `javascript:alert(...)`。

| 引擎 | 文本转义 | 属性转义 | URL 协议拦截 |
|---|---:|---:|---:|
| **yd-render** | ✅ | ✅ | ✅ |
| html/template | ✅ | ✅ | ✅ |
| text/template | ❌ | ❌ | ❌ |
| Jet | ✅ | ✅ | ❌ |
| Pongo2 | ✅ | ✅ | ❌ |
| Liquid（开启自动转义） | ✅ | ✅ | ❌ |
| Raymond | ✅ | ✅ | ❌ |
| Mustache | ✅ | ✅ | ❌ |
| quicktemplate（`{%s %}`） | ✅ | ✅ | ❌ |
| templ | ✅ | ✅ | ✅ |

结论：只有 `html/template`、`yd-render` 与 `templ` 同时具备**上下文感知转义与危险协议拦截**。
其它引擎的 HTML 转义能挡住文本与属性注入，但 `javascript:` URL 会原样进入 `href`。

## 性能（Linux 参考主机最终结果，2026-10-24）

测试平台：AMD Ryzen AI MAX+ 395（16 核 32 线程），Ubuntu 26.04.1，Go 1.27.3
linux/amd64，CPU governor `performance`；`GOMAXPROCS=32`、`-count=5`、`-benchtime=500ms`，
取中位数。所有实现同进程、同一数据、同一页面语义。

### 流式（`io.Discard`，ns/op）

| 引擎 | page100 | small5 | parallel | page100 allocs/op |
|---|---:|---:|---:|---:|
| quicktemplate | **15,147** | **905.5** | **1,024** | **0** |
| **yd-render** | 18,326 | 1,165 | 1,797 | 0 |
| templ | 58,521 | 4,202 | 20,052 | 1,823 |
| Jet | 67,480 | 4,548 | 20,616 | 6 |
| text/template | 103,015 | 6,449 | 13,069 | 811 |
| Pongo2 | 141,310 | 10,159 | 43,879 | 3,759 |
| Mustache | 159,716 | 8,981 | 43,960 | 5,633 |
| Liquid | 189,450 | 11,828 | 48,085 | 6,753 |
| html/template | 472,690 | 27,201 | 91,102 | 7,142 |
| Raymond | 909,216 | 31,957 | 459,878 | 10,561 |

### 输出物化（写入可复用 `bytes.Buffer`，ns/op）

| 引擎 | page100 | small5 | 相对 yd-render（page100） |
|---|---:|---:|---:|
| **yd-render** | **18,777** | **1,165** | **1.00×** |
| quicktemplate | 21,458 | 1,275 | 1.14× |
| templ | 57,568 | 3,734 | 3.07× |
| Jet | 71,476 | 4,869 | 3.81× |
| text/template | 107,100 | 6,750 | 5.70× |
| Pongo2 | 154,843 | 10,511 | 8.25× |
| Mustache | 154,412 | 8,535 | 8.22× |
| Liquid | 189,377 | 11,542 | 10.09× |
| html/template | 473,245 | 27,138 | 25.20× |
| Raymond | 810,739 | 32,131 | 43.18× |

- 流式口径下 quicktemplate 仍快约 21%（page100）/ 29%（small5）：它是编译期生成的
  Go 代码，把每段文本直接写进 `io.Discard`，既不物化输出也不做运行时取数。
- 物化口径下 **yd-render 反超 quicktemplate 约 13%（page100）/ 9%（small5）**：
  yd 只做一次 `Write`，quicktemplate 的逐段写在本口径下累计为更多调用。
- 对标准库与其它运行时引擎，两个口径的结论一致：yd-render 比 html/template 快
  25.8×（page100）/ 23.4×（small5），比 text/template 快 5.6×，比 Jet 快 3.7×，
  比 templ 快 3.2×，且 `page100` 为 0 allocs/op。

## 性能（Windows 本机，2026-10-19）

测试平台：Intel Core i9-10980HK，16 个逻辑 CPU，Windows 11 Pro for Workstations，
Go 1.27.3 windows/amd64，`-benchtime=2s`、每个实现 3–5 遍，取中位数。

> 这是开发机口径。仓库主表使用 Linux x86_64 基准平台；跨机比较请以相对关系为准，
> 绝对数值会受电源策略、温度与后台负载影响（通常 ±15%）。

### 单核（`GOMAXPROCS=1`，ns/op）

| 引擎 | page100 | small5 | page100 B/op | page100 allocs/op |
|---|---:|---:|---:|---:|
| quicktemplate | **27,036** | **1,615** | **0** | **0** |
| **yd-render** | **41,748** | **2,583** | **0** | **0** |
| templ | 140,378 | 8,546 | 68,735 | 1,823 |
| Jet | 165,985 | 11,002 | 496 | 6 |
| text/template | 247,408 | 15,198 | 11,544 | 811 |
| Mustache | 375,931 | 20,755 | 113,246 | 5,633 |
| Pongo2 | 377,589 | 25,947 | 158,824 | 3,759 |
| Liquid | 453,718 | 26,902 | 114,952 | 6,753 |
| html/template | 1,055,921 | 61,091 | 155,664 | 7,142 |
| Raymond | 1,548,407 | 70,209 | 1,793,001 | 10,551 |

### 输出物化对比（`io.Discard` vs 真实缓冲）

上面的基准把输出写到 `io.Discard`，它隔离 CPU 但不衡量产出字节的成本。代码生成式
引擎可以直接把每个片段流进 `io.Discard`，而 yd-render 为保证「要么整页、要么无输出」
先把页面物化到池化缓冲。下表把同一页面渲染进可复用的 `bytes.Buffer`，让所有引擎都为
输出字节付费：

| 引擎 | 物化 page100（ns/op） | 相对 yd-render |
|---|---:|---:|
| quicktemplate | 38,961 | 0.96× |
| **yd-render** | **40,729** | **1.00×** |
| templ | 141,924 | 3.49× |
| Jet | 174,533 | 4.29× |
| text/template | 244,277 | 6.00× |
| Pongo2 | 379,825 | 9.33× |
| Mustache | 386,264 | 9.48× |
| Liquid | 468,324 | 11.50× |
| html/template | 1,089,349 | 26.75× |
| Raymond | 1,590,651 | 39.06× |

物化输出后，yd-render 与 quicktemplate 的差距从 **1.54×** 缩小到 **1.04×**：
quicktemplate 在 `io.Discard` 下的优势主要来自「不物化输出」，而不是解释执行本身；
剩余的约 4% 是完整上下文转义、URL 协议过滤与规范化带来的必要成本。

### 多核顺序（16 逻辑 CPU，ns/op）

| 引擎 | page100 | small5 | page100 B/op | page100 allocs/op |
|---|---:|---:|---:|---:|
| quicktemplate | **24,585** | **1,472** | **0** | **0** |
| **yd-render** | **42,316** | **2,697** | **0** | **0** |
| templ | 116,737 | 7,259 | 68,735 | 1,823 |
| Jet | 177,106 | 11,410 | 496 | 6 |
| text/template | 233,454 | 14,245 | 11,544 | 811 |
| Mustache | 337,050 | 16,810 | 113,246 | 5,633 |
| Pongo2 | 390,528 | 26,192 | 158,824 | 3,759 |
| Liquid | 401,528 | 25,092 | 114,952 | 6,753 |
| html/template | 928,885 | 53,810 | 155,664 | 7,142 |
| Raymond | 2,512,155 | 68,011 | 1,793,001 | 10,551 |

### 并行（`b.RunParallel`，page100，ns/op）

| 引擎 | ns/op | 相对顺序执行加速 | 等效页面吞吐 |
|---|---:|---:|---:|
| quicktemplate | **4,612** | 5.3× | ~216,800 页/s |
| **yd-render** | **8,794** | 4.8× | **~113,700 页/s** |
| Jet | 43,902 | 4.0× | ~22,780 页/s |
| text/template | 57,911 | 4.0× | ~17,270 页/s |
| templ | 56,338 | 2.1× | ~17,750 页/s |
| Mustache | 137,501 | 2.5× | ~7,270 页/s |
| Pongo2 | 148,743 | 2.6× | ~6,720 页/s |
| Liquid | 168,353 | 2.4× | ~5,940 页/s |
| html/template | 324,839 | 2.9× | ~3,080 页/s |
| Raymond | 1,529,209 | 1.6× | ~650 页/s |

### 结论

- **对标标准库**：`yd-render` 在 100 行页面上比 `html/template` 快 **25.3×**
  （41.7 µs vs 1,055.9 µs），分配从 **7,142 次降到 0 次**；比同样不做上下文转义的
  `text/template` 仍快 **5.9×**；小页面快 **23.7×**。
- **对标主流运行时引擎**：单核比 Jet 快 **4.0×**、比 Pongo2 快 **9.0×**、
  比 Mustache 快 **9.0×**、比 Liquid 快 **10.9×**、比 Raymond 快 **37.1×**；
  比代码生成式的 templ 快 **3.4×**，且保留完整的 html/template 语法兼容。
- **与代码生成引擎的差距**：在 `io.Discard` 口径下 quicktemplate 仍快 **1.54×**；
  但把输出物化到真实缓冲后，两者为 **40.7 µs vs 39.0 µs（1.04×）**，基本持平。
  quicktemplate 的优势主要来自流式写出与只转义 5 个 HTML 字符；yd-render 则执行
  完整上下文转义与 URL 协议过滤/规范化。
- **并行扩展**：`yd-render` 的并行吞吐约为 html/template 的 **36.9×**，顺序执行到并行
  加速 **4.8×**；Raymond、Mustache、Liquid 的并行伸缩较差（输出字符串分配与全局锁竞争）。
- **分配**：`yd-render` 在 100 行页面与 5 行页面上均为 **0 allocs/op**：映射数据直接按键
  读取、结构体行以 `reflect.Value` 直通、字符串变量保持引用、输出缓冲以句柄池化。
  Jet 的 6 次分配来自其内部对象池；html/template 为 7,142 次。

## yd 引擎为什么快

1. **复用标准库前端**：解析与上下文转义仍由 `html/template` 完成，因此语法与安全语义
   与标准库逐字节一致；执行阶段换成自研节点图，不再走 `text/template` 的逐次反射调用。
2. **加载期编译**：模板在 `New` 时被编译为不可变程序；渲染只做指针遍历，没有解析、
   没有 clone、没有逐请求的函数表重建。
3. **按次执行绑定**：译者与权限主体存放在每次渲染的状态中，`tr`/`can` 直接读取，
   不再为每个语言/角色组合克隆整棵模板树。
4. **零装箱热路径**：单字段动作走 `reflect.Value` 路径，字符串/整数/布尔不装箱；
   单绑定动作（`tr`、`perm`、`can`）有专门的无接口输出路径。
5. **单遍链式转义**：URL 过滤、规范化、百分号编码与属性转义在同一遍扫描中完成，
   不产生中间字符串；HTML 转义按模式使用 256 项替换码表。
6. **扁平列表步骤**：静态文本直接存在列表项中，省去每段文本的一次接口分派与节点分配。
7. **缓冲复用**：引擎按页面实际增长后的容量保留输出缓冲；标准库和门面共享同一缓冲池。
8. **确定性缓存**：编译程序不可变、并发只读；不存在的按请求缓存失效问题。

## 生成代码

```bash
# quicktemplate
go run github.com/valyala/quicktemplate/qtc -file=templates/page.qtpl
mv templates/page.qtpl.go page_qtpl.go

# templ
go run github.com/a-h/templ/cmd/templ@v0.3.1070 generate ./templates/page.templ
mv templates/page_templ.go page_templ.go
```

生成文件已提交，日常运行不需要重新生成。

## 复现注意事项

- 每个实现都在同一进程内解析一次、复用已编译模板；基准循环只测渲染。
- Liquid 启用了 `render.HtmlEscaper` 自动转义，否则其默认输出不转义，对比会失真。
- Pongo2 的 Context 每轮重新构造，属于其正常调用成本；yd/html/Jet 直接接收结构体指针。
- quicktemplate 使用 `{%s %}`（HTML 转义）而非 `{%s= %}`（原样输出），否则对比不公平。
- 所有引擎的模板都用各自惯用语法表达同一页面语义，输出不要求逐字节相同（转义细节不同），
  但 `TestEnginesProduceOutput` 会校验行数与关键标记。
