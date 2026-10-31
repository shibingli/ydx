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
| 性能数据 | [`PERFORMANCE.md`](PERFORMANCE.md) |
| 基准源码 | [`benchmarks/regexpx`](../benchmarks/regexpx/README.md) |

## 目录

1. [安装与导入](#1-安装与导入)
2. [编译与模式](#2-编译与模式)
3. [匹配与查找](#3-匹配与查找)
4. [捕获与命名分组](#4-捕获与命名分组)
5. [替换与模板](#5-替换与模板)
6. [Reader API](#6-reader-api)
7. [文本序列化与 Copy](#7-文本序列化与-copy)
8. [并行 API](#8-并行-api)
9. [并发与生命周期](#9-并发与生命周期)
10. [超时、安全与错误](#10-超时安全与错误)
11. [从标准库迁移](#11-从标准库迁移)
12. [常见问题](#12-常见问题)
13. [性能](#13-性能)
14. [依赖、相关模块与许可证](#14-依赖相关模块与许可证)

## 1. 安装与导入

```bash
go get github.com/shibingli/ydx/regexpx@v0.1.11
```

```go
import "github.com/shibingli/ydx/regexpx"
```

> `v0.1.11` 起提供本文档中的 `*Into` 调用方缓冲区 API 与惰性 ASCII 搜索 DFA。

包标识符为 `regexpx`，与目录名一致。产品模块只依赖 Go 标准库与 `ydx/errs`；本包不依赖
第三方正则库。

## 2. 编译与模式

### 2.1 Compile / MustCompile

```go
re, err := regexpx.Compile(`^[a-z][a-z0-9_-]*$`)
if err != nil {
    // 使用 errors.Is(err, regexpx.ErrCompile) 判定语法错误
}
if re.MatchString("acme_01") {
    // ...
}
```

`MustCompile` 用于包级初始化；非法模式会 panic：

```go
var tenantRe = regexpx.MustCompile(`^[a-z][a-z0-9_-]*$`)
```

`Compile` 接受 RE2 语法，并额外支持：

- 环视：`(?=...)`、`(?!...)`、`(?<=...)`、`(?<!...)`；
- 反向引用：`\1`、`\k<name>`；
- 命名分组：`(?P<name>...)`、`(?<name>...)`；
- 原子组：`(?>...)`；
- 占有量词：`*+`、`++`、`?+`、`{m,n}+`。

命名分组名遵循标准库规则：`[A-Za-z0-9_]+`，允许数字开头，不允许非 ASCII 字符。

### 2.2 CompilePOSIX / MustCompilePOSIX

```go
re := regexpx.MustCompilePOSIX(`a|aa`)
re.FindString("aa") // "aa"，最左最长
```

- 使用标准库 POSIX parser 作为语法 oracle：`\d`、`\w`、`\s`、`\A`、`\b`、`\1`、
  `(?...)` 等非 POSIX 语法会被拒绝。
- POSIX 模式下 `^`/`$` 是行锚点；否定字符类不匹配换行；连续量词按 POSIX 嵌套重复解释。
- 默认启用最左最长匹配。

### 2.3 编译错误

```go
if _, err := regexpx.Compile(`(`); errors.Is(err, regexpx.ErrCompile) {
    // 语法错误
}
```

`CompilePOSIX` 的语法错误同样包装 `ErrCompile`。错误文本包含模式与位置，但不会包含运行期
输入内容。

## 3. 匹配与查找

### 3.1 常用 API

| 方法 | 返回 |
|---|---|
| `MatchString(s string) bool` | 是否包含匹配 |
| `Match(b []byte) bool` | 同上，字节输入 |
| `FindString(s string) string` | 首个匹配文本；无匹配为 `""` |
| `FindStringIndex(s string) []int` | 首个匹配的字节偏移对；无匹配为 `nil` |
| `FindStringSubmatch(s string) []string` | 首个匹配及各分组文本 |
| `FindStringSubmatchIndex(s string) []int` | 首个匹配及各分组字节偏移 |
| `FindStringSubmatchInto(dst []string, s string) []string` | 同上，复用调用方字符串缓冲区 |
| `FindStringSubmatchIndexInto(dst []int, s string) []int` | 同上，复用调用方索引缓冲区 |
| `FindAllString(s string, n int) []string` | 所有非重叠匹配；`n < 0` 表示全部 |
| `FindAllStringIndex(s string, n int) [][]int` | 所有匹配的字节偏移 |
| `FindAllStringSubmatch(s string, n int) [][]string` | 所有匹配及分组文本 |
| `FindAllStringSubmatchIndex(s string, n int) [][]int` | 所有匹配及分组偏移 |

字节输入对应 `Find`、`FindIndex`、`FindSubmatch`、`FindSubmatchIndex`、`FindAll`、
`FindAllIndex`、`FindAllSubmatch`、`FindAllSubmatchIndex`；缓冲区版本为
`FindSubmatchInto` 与 `FindSubmatchIndexInto`。

```go
re := regexpx.MustCompile(`(\d{4})-(\d{2})-(\d{2})`)
loc := re.FindStringSubmatchIndex("released 2026-10-31")
if loc != nil {
    whole := "released 2026-10-31"[loc[0]:loc[1]]
    year := "released 2026-10-31"[loc[2]:loc[3]]
    _, _ = whole, year
}
```

所有索引都是**字节偏移**，不是 rune 下标。未参与匹配的分组在 `SubmatchIndex` 中为
`-1, -1`；未匹配的 `Submatch` 元素为空字符串。

### 3.1.1 调用方缓冲区（零分配）

高频捕获场景可以用 `*Into` 方法复用调用方切片，避免每次调用分配索引与字符串切片：

```go
func parseLine(re *regexpx.Regexp, line string) (string, string) {
    var indexStorage [32]int
    var groupStorage [16]string
    loc := re.FindStringSubmatchIndexInto(indexStorage[:0], line)
    if loc == nil || loc[2] < 0 {
        return "", ""
    }
    groups := re.FindStringSubmatchInto(groupStorage[:0], line)
    return groups[1], groups[2]
}
```

调用方也可以把这两个数组放在请求上下文或对象池中，在每个 goroutine 内复用；不要把同一组
缓冲区交给并发调用。

规则如下：

- 只看 `dst` 的**容量**，不看长度；通常传 `dst[:0]`。容量足够时返回切片复用 `dst`，
  否则分配新切片。
- 索引结果长度为 `2 * (NumSubexp()+1)`，字符串结果长度为 `NumSubexp()+1`；无匹配返回
  `nil`。未匹配分组在索引中为 `-1, -1`，在字符串中为空串。
- 返回的字符串是输入的子串，不复制内容；输入必须在使用期间保持有效。
- 线性引擎（不含环视/反向引用）预热后为零分配；回溯模式仍可能分配引擎内部捕获状态。
- 缓冲区属于单次调用；不要把同一个 `dst` 交给并发调用，也不要让调用方缓冲区与输入
  生命周期混淆。每个 goroutine 使用自己的缓冲区即可。
- `Longest`、`CompilePOSIX`、命名分组与未匹配分组语义与对应的分配版本完全一致。
- 字节输入使用 `FindSubmatchIndexInto(dst []int, b []byte)` 与
  `FindSubmatchInto(dst [][]byte, b []byte)`。

```go
var byteGroups [8][]byte
groups := re.FindSubmatchInto(byteGroups[:0], []byte("user=alice"))
if groups != nil {
    // groups[1] 是 b 的子切片，不复制内容
}
```

基准测试 `TestFindStringSubmatchIntoAllocations` 验证预热后字符串/索引缓冲区 API 为
`0 allocs/op`。

### 3.2 空匹配规则

`FindAll*` 与标准库一致：紧邻上一个匹配的空匹配会被跳过。例如 `a*` 在 `"baa"` 上不会在
同一个位置重复返回空匹配。替换、`Split` 与 Reader 查找复用同一规则。

### 3.3 E 变体与超时

E 变体把引擎错误显式返回：

```go
re := regexpx.MustCompile(`^(a+)+$`)
matches, err := re.FindAllStringE("aaaaaaaaaaaaaaaaaaaaaaaa!", -1)
if errors.Is(err, regexpx.ErrMatchTimeout) {
    // 失败关闭：按未匹配处理；matches 是超时前已收集的部分结果。
}
```

可用的 E 变体包括 `FindAllStringE`、`FindAllStringIndexE`、`FindAllStringSubmatchE`、
`FindAllStringSubmatchIndexE`、`ReplaceAllStringE`。普通方法不返回错误：回溯超时按未匹配
处理，替换类方法在超时时返回原输入。

### 3.4 Longest

```go
re := regexpx.MustCompile(`a|aa`)
re.FindString("aa") // "a"
re.Longest()
re.FindString("aa") // "aa"
```

- `Longest` 是配置方法，**不得与匹配并发执行**；对副本调用不影响原对象。
- 线性引擎直接跟踪最左最长匹配。
- 对需要环视/反向引用的模式，回溯引擎按候选结束位置从长到短查找；这类模式本身应避免放在
  高频路径。
- 子匹配与替换路径对 `regexp` 可接受的模式使用惰性标准库视图，保证 POSIX 子表达式语义；
  regexpx 独有的 .NET 构造仍走原生引擎。

### 3.5 LiteralPrefix

```go
re := regexpx.MustCompile(`^api/v\d+/`)
prefix, complete := re.LiteralPrefix()
// prefix == "api/v"，complete == false
```

- `prefix` 是每个匹配都必须以其开头的字面量；`complete` 表示整个模式是否恰好等于该字面量。
- 结果按标准库语义计算，可用于预过滤或路由分派。
- 计算是惰性的；首次调用后走原子快路径，后续约 2 ns。

### 3.6 包级便捷函数

```go
ok, err := regexpx.MatchString(`^v\d+$`, "v2")
ok, err = regexpx.Match(`^v\d+$`, []byte("v2"))
ok, err = regexpx.MatchReader(`^v\d+$`, strings.NewReader("v2"))
```

包级函数每次调用都会编译模式，适合一次性脚本，不适合请求热路径。

## 4. 捕获与命名分组

```go
re := regexpx.MustCompile(`(?P<year>\d{4})-(?P<month>\d{2})`)
names := re.SubexpNames()       // ["", "year", "month"]
idx := re.SubexpIndex("month")  // 2
sub := re.FindStringSubmatch("2026-10")
// sub[0] == "2026-10", sub[1] == "2026", sub[2] == "10"
```

- `NumSubexp` 返回分组数量（不含整个匹配）。
- `SubexpIndex` 对不存在的名称返回 `-1`。
- 组名只允许 `[A-Za-z0-9_]+`；重复名称在编译期报错。
- 标准库 `Expand` 模板中的变量名允许 Unicode 字母/数字；但只有与上述 ASCII 组名匹配时才会
  产生内容。

## 5. 替换与模板

### 5.1 ReplaceAll 系列

| 方法 | 说明 |
|---|---|
| `ReplaceAllString(src, repl string) string` | `$name`/`${name}` 模板替换 |
| `ReplaceAllStringE(src, repl string)` | 同上，返回引擎错误 |
| `ReplaceAllStringFunc(src string, f func(string) string)` | 每次匹配调用函数 |
| `ReplaceAll(src, repl []byte) []byte` | 字节版本模板替换 |
| `ReplaceAllFunc(src []byte, f func([]byte) []byte) []byte` | 字节版本函数替换 |
| `ReplaceAllLiteralString(src, repl string) string` | 不展开 `$`，按字面量替换 |
| `ReplaceAllLiteral(src, repl []byte) []byte` | 字节版本字面量替换 |

```go
re := regexpx.MustCompile(`(\w+)@(\w+)\.com`)
out := re.ReplaceAllString("alice@example.com bob@example.com", "$2:$1")
// "example:alice example:bob"

out = re.ReplaceAllLiteralString("alice@example.com", "$2:$1")
// "$2:$1"
```

### 5.2 Expand / ExpandString

`Expand` 使用调用方提供的 `match` 索引，不重新匹配：

```go
re := regexpx.MustCompile(`(?P<first>\w+) (?P<last>\w+)`)
src := "Eric Shi"
match := re.FindStringSubmatchIndex(src)
out := re.ExpandString(nil, "$last, $first", src, match)
// "Shi, Eric"
```

`Expand` / `ExpandString` 的模板规则：

- `$name` 与 `${name}` 引用命名分组；
- `$1`、`${1}` 引用数字分组；
- `$$` 输出字面量 `$`；
- `$1x` 被解释为名称 `1x`，不是“分组 1 + x”；需要分组 1 后接 x 时写 `${1}x`；
- 数字名称有前导零时按名称查找（例如 `$01` 查找名为 `01` 的分组）；
- 数字索引超过 1e8 或匹配数组过短时输出空串，不会 panic；
- 模板中的 Unicode 名称会被解析，但只有能匹配实际组名时才有输出。

### 5.3 超时与部分结果

`ReplaceAllStringE` 在回溯引擎超时时返回已生成的部分结果与 `ErrMatchTimeout`；
`ReplaceAllString` 看到错误后返回原输入，避免把半成品写回业务数据。线性引擎不超时。

## 6. Reader API

### 6.1 MatchReader

```go
re := regexpx.MustCompile(`token=\w+`)
ok := re.MatchReader(strings.NewReader("x token=abc y"))
```

- 任何 `ReadRune` 错误都按输入结束处理，错误发生前已成立的匹配仍然有效。
- 对没有结尾/行/词边界断言且无回溯构造的模式，按指数分块提前返回；早期匹配不需要读完
  整个流。
- 其他模式会读完 reader 后再匹配。

### 6.2 FindReaderIndex / FindReaderSubmatchIndex

```go
re := regexpx.MustCompile(`a(b+)`)
idx := re.FindReaderIndex(strings.NewReader("xxabbbz"))
// [2, 6]
sub := re.FindReaderSubmatchIndex(strings.NewReader("xxabbbz"))
// [2, 6, 3, 6]
```

- 返回的偏移使用 `ReadRune` 上报的 `size` 累加，而不是把符文重新编码为 UTF-8 后的字节数。
  自定义 RuneReader 返回非标准 size 时，偏移与标准库一致。
- 读取错误按 EOF 处理。
- 定长、无开头/结尾/词/行断言、无回溯的模式使用滚动窗口提前返回；其他模式读完整个流。

### 6.3 Reader 使用建议

- 大文件/网络流优先使用定长模式或可提前判定的模式。
- 需要完整上下文或结尾断言的模式会缓冲全部输入；超大流请先做长度上限或分块预处理。
- 自定义 RuneReader 应保证 `ReadRune` 返回的 size 与实际消费的字节数一致。

## 7. 文本序列化与 Copy

### 7.1 AppendText / MarshalText / UnmarshalText

```go
re := regexpx.MustCompile(`a+`)

text, _ := re.MarshalText()       // []byte("a+")
buf, _ := re.AppendText([]byte("prefix:"))
// "prefix:a+"

var decoded regexpx.Regexp
if err := decoded.UnmarshalText([]byte(`b+`)); err != nil {
    // 编译失败；原对象保持不变
}
```

- `MarshalText` 返回模式原文。
- `UnmarshalText` 使用普通 `Compile` 重新编译并替换接收者；失败时接收者不变。
- `UnmarshalText` 会重置 `Longest` 状态，与标准库行为一致。

### 7.2 Copy

```go
original := regexpx.MustCompile(`a|aa`)
copy := original.Copy()
copy.Longest()

original.FindString("aa") // "a"
copy.FindString("aa")     // "aa"
```

`Copy` 是 O(1) 结构复制，共享编译程序、命名表和惰性缓存，但 `Longest` 标志按值复制，
因此配置互不影响。不要与匹配并发调用 `Longest`。

## 8. 并行 API

```go
re := regexpx.MustCompile(`\d{4}-\d{2}-\d{2}`)
results := re.FindAllStringIndexParallel(largeText, -1)
```

- `FindAllStringParallel` / `FindAllStringIndexParallel` 在输入较大且存在可靠、选择性的
  起点过滤器时分块并行。
- 可空模式、锚定模式、回溯模式与不适合过滤的模式自动回退顺序执行。
- 结果与顺序 API 完全一致；不要用 `runtime.GOMAXPROCS` 之外的假设推断并行收益。

## 9. 并发与生命周期

- `Regexp` 编译完成后可被多个 goroutine 并发用于匹配、查找、替换与 Reader API。
- `Longest` 是配置方法，不能与匹配并发执行；需要在副本上配置时使用 `Copy`。
- `UnmarshalText` 会替换接收者，不能与其他使用该接收者的操作并发。
- 编译后的 `Regexp` 持有共享的不可变 program；GC 在最后一个引用消失后回收。

## 10. 超时、安全与错误

- 不含环视/反向引用的模式运行在线性时间 Pike VM 上，不回溯，无需超时。
- 含环视/反向引用的模式运行在回溯 VM 上，受 `MatchTimeout`（默认 100 ms）与硬步数预算
  约束；超过任一限制按未匹配处理，校验类调用失败关闭。
- 这类模式不应直接处理不可信大输入；优先改写为线性模式，或在调用前限制输入长度。
- `ErrCompile` 表示语法/编译错误；`ErrMatchTimeout` 表示回溯超时。
- 普通匹配方法不返回错误；需要区分超时与未匹配时使用 E 变体。
- 错误文本不包含运行期输入内容；替换/模板不会把未验证的规则细节回显给最终用户。

## 11. 从标准库迁移

大多数调用可以直接把 `regexp` 替换为 `regexpx`：

```go
- re, err := regexp.Compile(pattern)
+ re, err := regexpx.Compile(pattern)
```

| 标准库 | regexpx | 说明 |
|---|---|---|
| `Compile` / `MustCompile` | 同名 | 额外支持 .NET 构造 |
| `CompilePOSIX` / `MustCompilePOSIX` | 同名 | 使用标准库 POSIX 语法 oracle |
| `Match` / `MatchString` / `MatchReader` | 同名 | 包级函数 |
| `Find*` / `FindAll*` | 同名 | 字节偏移语义一致 |
| `Longest` | 同名 | 子匹配/替换对 RE2 模式使用惰性标准库 oracle |
| `LiteralPrefix` | 同名 | 标准库兼容 |
| `Expand` / `ExpandString` | 同名 | 模板规则对齐 |
| `ReplaceAllLiteral*` | 同名 | 新增补齐 |
| `MatchReader` / `FindReader*` | 同名 | 错误按 EOF，偏移按上报 size |
| `MarshalText` / `UnmarshalText` / `AppendText` / `Copy` | 同名 | 新增补齐 |
| `NumSubexp` / `SubexpNames` / `SubexpIndex` | 同名 | 组名规则与标准库一致 |

需要注意的差异：

1. `Compile` 接受标准库拒绝的 .NET 构造；这类模式无法用标准库作为 oracle。
2. `CompilePOSIX` 的语法拒绝集合以标准库 POSIX parser 为准；语义上补齐了 POSIX 行锚点、
   否定字符类与嵌套量词。
3. `Longest` 的子匹配/替换在 RE2 模式上委托惰性标准库视图；`.NET` 构造保留原生语义。
4. Reader 的字节偏移按 `ReadRune` 上报的 size 计算，而不是重新编码后的 UTF-8 长度。
5. 回溯模式有 `MatchTimeout` 与步数预算；标准库的 RE2 引擎没有这类超时。

## 12. 常见问题

### 12.1 `FindString` 返回空串，是没匹配还是空匹配？

`FindString` 无法区分两者；需要区分时使用 `FindStringIndex` / `FindStringSubmatchIndex`：
`nil` 表示无匹配，`[i, i]` 表示空匹配。

### 12.2 为什么 `$1x` 没有输出分组 1 加 x？

模板名称按最长连续字母/数字/下划线解析，`$1x` 是名称 `1x`。写成 `${1}x`。

### 12.3 为什么 `$01` 和 `$1` 不同？

数字名称有前导零时按名称查找，`$01` 查找名为 `01` 的分组；`$1` 才是数字分组 1。

### 12.4 `Expand` 会 panic 吗？

正常匹配不会；匹配数组过短或索引越界时对应引用输出空串。只有调用方传入非法参数才会触发
常规 panic。

### 12.5 `MatchReader` 会读完整个 reader 吗？

不一定。没有结尾/行/词边界断言且无回溯构造时，它按指数分块提前返回；其他模式会读完。
需要严格控制内存时，优先使用定长模式或先限制流长度。

### 12.6 为什么 `FindReaderIndex` 的偏移和字符串下标不同？

它使用 `ReadRune` 上报的 `size` 累加；自定义 reader 若上报的不是 UTF-8 字节长度，偏移会
与重新编码后的字符串不同，但与标准库一致。

### 12.7 `Longest` 能并发调用吗？

不能。它修改匹配配置，必须在匹配开始前调用；需要独立配置时使用 `Copy`。

### 12.8 `CompilePOSIX` 为什么拒绝我的 Perl 模式？

POSIX 模式只接受标准库 POSIX parser 接受的语法；`\d`、`\w`、`(?i)`、`\A`、`\b`、反向
引用等应改用普通 `Compile`，或改写为 POSIX 字符类。

### 12.9 回溯模式超时后为什么返回“未匹配”？

这是失败关闭策略：宁可不匹配，也不让灾难性回溯拖垮服务。对校验类调用，超时按不匹配处理；
需要显式错误时使用 E 变体。

### 12.10 包级 `MatchString` 适合热路径吗？

不适合。它每次调用都会编译模式；请求热路径应复用 `Compile`/`MustCompile` 的结果。

### 12.11 为什么大型模式第一次 `MatchString` 比较慢？

满足条件的大型宽首字节模式会在首次匹配时构建惰性 ASCII 搜索 DFA，之后长期加速。构建由
`sync.Once` 保护，多个并发首次调用只会构建一次。对延迟敏感的启动路径，可以在服务接收流量
前用一个良性输入预热：

```go
// 932236 形态下，该输入通过预过滤并触发 DFA 构建。
re.MatchString("value-0-hello-world")
```

预热输入必须能通过最小长度/必需字节/必需字面量等前置过滤；否则会在到达 DFA 前返回，
不会构建。具体输入应按规则集选择。

DFA 只影响性能；回退路径保证结果一致。

## 13. 性能

新增兼容 API 与 `Longest` 快路径的完整对比数据见 [`PERFORMANCE.md`](PERFORMANCE.md)：

- `Copy` 已与标准库同为 160 B、1 alloc，耗时在同一量级；
- `ReplaceAllString` 约为标准库的 1/2.8，`ReplaceAllLiteralString` 约 1/3–1/6（受标准库样本波动影响）；
- `Longest` 通配/线性快路径比标准库快 2–3 个数量级，单运行快约 5–6x；
- `MatchReader`/`FindReaderIndex` 早期匹配比标准库快约 1.5–1.7x；
- v0.1.11 增加最小匹配长度短路、无捕获 Pike VM 快路径与 AST 必需字节/字面量预过滤；短输入可提前返回，标点密集或宽首字节模式可快数十到数百倍；
- 大型宽首字节通用模式在首次匹配时构建惰性 ASCII 搜索 DFA；CRS 932236/932260 形态的善意值可快约 40–70x，非 ASCII 输入、不支持断言或状态上限溢出时自动回退 Pike VM；
- 新增调用方缓冲区 API，预热后的子匹配索引/字符串结果可 0 allocs/op；
- `LiteralPrefix` 约 2.2 ns，唯一仍有相对差距的项目，但不在热路径。

通用匹配/查找场景的 Zen 5、AVX2、AVX-512、arm64 与并行数据见
[`benchmarks/regexpx/README.md`](../benchmarks/regexpx/README.md)。

### 13.1 惰性 ASCII 搜索 DFA

对满足以下条件的模式，`regexpx` 会在**首次匹配时**自动构建惰性 ASCII 搜索 DFA，无需任何
配置或新 API：

- 不含环视、反向引用或原子组等回溯构造；
- 没有字面量前缀，且首字节集足够宽（避免抢占已有的前缀/首字节快路径）；
- 指令数不少于 128 且不超过 8192；
- 只包含起始/结束/单词边界断言（行锚点 `(?m)`、`\Z` 等会回退）。

行为与保证：

```go
// commandNames 是足够大的命令名集合（类似 OWASP CRS 932236 的形态）。
pattern := `(?i)(?:^(?:json\.|\x5c)?|` + strings.Join(commandNames, "|") + `\b)[a-z0-9_]+`
re := regexpx.MustCompile(pattern)
// 首次调用构建 DFA；后续调用直接扫描。
matched := re.MatchString("json.cmd42x")
```

- `MatchString` / 字节 `Match` 在 ASCII 输入上直接采用 DFA 结果；带捕获的
  `Find*Submatch*` 只把 DFA 当作存在性预过滤，命中后仍由 Pike VM 生成捕获。
- 输入出现非 ASCII 字节、构建时发现不支持构造或状态数超过 1024 时，自动回退到 Pike VM，
  结果与不回退时完全一致。
- DFA 状态按需增长，已完成的转移以原子方式读取；多个 goroutine 可并发使用同一个
  `Regexp`。首次构建是串行的一次性成本；此后稳态搜索无锁，首次遇到新的字母表转移时仍会短暂
  加锁计算。
- 构建在 `sync.Once` 内完成；首次调用会承担字母表与起始状态的构建成本。当前 CRS
  932236/932260 形态约 0.5 ms/模式，稳态搜索约 0.10–0.27 µs。
- 该路径只影响性能，不改变 `Longest`、POSIX、捕获、未匹配分组或超时语义。

若希望精确观测是否构建成功，可在包内测试中使用 `searchDFA()`；公开 API 不暴露 DFA 对象，
避免调用方依赖内部状态。

## 14. 依赖、相关模块与许可证

- 运行时依赖：Go 标准库、`github.com/shibingli/ydx/errs`。
- 基准对比库只出现在 `benchmarks/regexpx`，不进入产品模块。
- 相关模块：[`router`](../router/README.md)、[`middleware/requestid`](../middleware/requestid/README.md)、
  [`openapi`](../openapi/README.md)。
- 许可证：Apache-2.0，见仓库根目录 [`LICENSE`](../LICENSE)。
