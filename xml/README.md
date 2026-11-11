# xml — 硬件自适应 XML 编解码与路径查询

`github.com/shibingli/ydx/xml` 是 ydx 的 XML 统一入口。默认构建使用自研原生后端：
amd64 手写 SSE2 / AVX2 / AVX-512BW 扫描内核，arm64 手写 NEON，其它架构使用可移植的
8 字节 SWAR/标量实现；显式 `xml_std` 标签可回退到标准库 `encoding/xml` 的原始词法分析，
上层 API 保持不变。

| 项 | 值 |
|---|---|
| 模块路径 | `github.com/shibingli/ydx/xml` |
| 包名 | `xml` |
| Go 版本 | 1.27.4 |
| 许可证 | Apache-2.0 |
| 后端 | `yd-native`（默认）/ `encoding/xml`（`xml_std` 标签） |

## 定位

- **完整对齐 `encoding/xml`**：解析、反序列化、序列化与全部公开类型/错误。
- **多种路径解析方案**：Token 事件流、逐记录 `Decode`、零拷贝 DOM + 编译式路径、
  流式 `Selector`（不建 DOM，内存 O(深度)）、`Node` 手工导航。
- **超大文档**：`Decoder` / `Selector` / `EachFile` 使用有界缓冲；DOM 为内存模式。
- **硬件自适应**：无需 `GOEXPERIMENT`，无 cgo；同一份代码在 AMD64、ARM64 与其它架构构建。

## 完整兼容清单

以下符号与 `encoding/xml` 语义对齐：

- 函数：`Marshal`、`MarshalIndent`、`Unmarshal`、`NewDecoder`、`NewEncoder`、
  `NewTokenDecoder`、`CopyToken`、`EscapeText`、`Escape`（兼容别名）、`Header`。
- 类型：`Name`、`Attr`、`CharData`、`Comment`、`Directive`、`ProcInst`、
  `StartElement`、`EndElement`、`Token`、`TokenReader`、`Decoder`、`Encoder`、
  `Marshaler`、`MarshalerAttr`、`Unmarshaler`、`UnmarshalerAttr`、`SyntaxError`、
  `TagPathError`、`UnsupportedTypeError`、`UnmarshalError`。
- `Decoder`：`Strict`、`AutoClose`、`Entity`、`CharsetReader`、`DefaultSpace`，
  以及 `Token`、`RawToken`、`Skip`、`Decode`、`DecodeElement`、`InputOffset`、
  `InputPos`。
- `Encoder`：`Encode`、`EncodeElement`、`EncodeToken`、`Flush`、`Indent`、`Close`。
- 标签语义：`name`、`ns name`、`,attr`、`,chardata`、`,cdata`、`,innerxml`、
  `,comment`、`,any`、`,any,attr`、`,omitempty`、`a>b>c`、`-`、`XMLName`、
  匿名嵌入字段、`Name`/`Attr` 字段、指针/切片/`[]byte`、`encoding.TextMarshaler`/
  `TextUnmarshaler`。
- 命名空间：默认命名空间、前缀解析、未定义前缀、`xml` 预定义命名空间、`xmlns`/`xmlns:p`
  声明、`DefaultSpace`，以及序列化时自动生成前缀。

`Token` 返回的字节切片遵循标准库语义：在下一次 `Token`/`RawToken` 调用前有效；但
`StartElement.Attr` 切片与名称/属性值字符串是独立的稳定值，可在后续调用后继续持有。

Unicode 兼容同样逐项对拍 `encoding/xml`：CJK 元素/属性名与文本、表情符号、数字字符
引用（含代理对码点）、注释、CDATA、处理指令，以及 `xml:"别名"`、`xml:"类型,attr"`、
`xml:",chardata"`、`xml:",innerxml"`、`xml:"外层>内层"` 等标签别名；非法 UTF-8 在
`EscapeText` 中与标准库一样输出 U+FFFD。

## 原生扩展

以下能力是标准库没有或更严格的行为，默认开启且不破坏合法文档的兼容性：

- **UTF-16**：自动识别 LE/BE BOM 并转码为 UTF-8；UTF-8 BOM 与标准库一致，作为字符数据
  返回。声明的其它编码仍通过 `CharsetReader` 处理。
- **内部 DTD 实体**：支持 `<!DOCTYPE ... [<!ENTITY name "value">]>` 的文本实体展开，
  带总字节预算与递归深度预算（默认 8 MiB / 16 层），防止 billion laughs；**绝不加载外部实体**。
- **资源上限 `Limits`**：`MaxDepth`、`MaxTokenSize`、`MaxNodes`、`MaxEntityExpansion`、
  `MaxEntityDepth`、`MaxTextSize`、`MaxMatches`，零值使用安全默认值。
- **`Valid`**：严格良构检查，除标签配对、实体、字符集外，还拒绝重复属性（按展开名）与
  根元素之外的非空白文本。
- **`Parse` / `Document` / `Node`**：零拷贝 DOM；`InnerXML` / `OuterXML` 直接返回源字节
  视图，`Text` / `AppendText` / `Attr` / `FirstChild` / `NextSibling` 提供导航。
- **`Compile` 路径查询**：点号式（0 基）与 XPath 风格（1 基），支持 `*`、`{uri}local`、
  `[n]`、`[*]`、`[@a]`、`[@a='v']`、`//` 后代轴、`@attr` 与 `text()`/`#text` 终结符。
- **`Selector` 流式查询**：在 Token 流上执行同一套路径状态机，适用超大文档；`Match.Text`
  为已解码终结值，`CaptureRaw` 在字节源上返回外层 XML 原始视图。`EachFile` 提供文件级入口。

## 快速开始

### 反序列化与序列化

```go
package main

import (
	"fmt"

	"github.com/shibingli/ydx/xml"
)

type Book struct {
	ID    int    `xml:"id,attr"`
	Title string `xml:"title"`
	Price string `xml:"price"`
}

type Catalog struct {
	Books []Book `xml:"book"`
}

func main() {
	data := []byte(`<catalog><book id="1"><title>Go</title><price>9.9</price></book></catalog>`)

	var c Catalog
	if err := xml.Unmarshal(data, &c); err != nil {
		panic(err)
	}
	out, err := xml.Marshal(c)
	if err != nil {
		panic(err)
	}
	fmt.Println(string(out))
}
```

### Token 流（最低内存）

```go
dec := xml.NewDecoder(r)
dec.Strict = true
for {
	tok, err := dec.Token()
	if err == io.EOF {
		break
	}
	if err != nil {
		return err
	}
	switch t := tok.(type) {
	case xml.StartElement:
		// t.Name / t.Attr
	case xml.CharData:
		// t
	case xml.EndElement:
		// t.Name
	}
}
```

### 逐记录解码超大文档

```go
dec := xml.NewDecoder(file)
// 先消费到容器起始元素
if tok, err := dec.Token(); err != nil {
	return err
} else {
	_ = tok
}
for {
	var rec Record
	if err := dec.Decode(&rec); err == io.EOF {
		break
	} else if err != nil {
		return err
	}
	handle(rec)
}
```

### DOM + 编译式路径

```go
doc, err := xml.Parse(data)
if err != nil {
	return err
}

p, err := xml.Compile("/bookstore/book[@id=\"b2\"]/price")
if err != nil {
	return err
}

price, ok := doc.Value(p) // 首个终结值
titles, _ := xml.Compile("//title")
all := doc.Values(titles) // 所有标题
books, _ := xml.Compile("//book")
node := doc.SelectOne(books)
raw := node.InnerXML() // 零拷贝原始视图
```

### 流式 Selector（超大文档）

```go
p, err := xml.Compile("/catalog/book/title")
if err != nil {
	return err
}

err = xml.EachFile("catalog.xml", p, func(m *xml.Match) error {
	// m.Text 在下一次 Next 前有效；需要保留时请复制
	use(string(m.Text))
	return nil
})
```

`Selector` 直接使用 `[]byte` 时支持 `CaptureRaw`：

```go
s := xml.NewSelectorBytesWithOptions(data, p, xml.SelectorOptions{CaptureRaw: true})
for s.Next() {
	outer := s.Match().Raw // 指向输入源的原始外层 XML
	_ = outer
}
if err := s.Err(); err != nil {
	return err
}
```

### YD 路由

```go
r := router.New()
r.POST("/orders", func(c *router.Ctx) {
	var order Order
	if err := xml.NewDecoder(c.Body()).Decode(&order); err != nil {
		_ = c.String(http.StatusBadRequest, err.Error())
		return
	}
	_ = c.JSON(http.StatusOK, order)
})
```

### 原生 `net/http`

```go
http.HandleFunc("/orders", func(w http.ResponseWriter, r *http.Request) {
	var order Order
	if err := xml.NewDecoder(r.Body).Decode(&order); err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	w.Header().Set("Content-Type", "application/xml")
	_ = xml.NewEncoder(w).Encode(order)
})
```

## 路径语法

| 写法 | 说明 |
|---|---|
| `bookstore.book[0].title` | 点号式：0 基下标，`.` 为子元素轴 |
| `bookstore.book[*].title` | `[*]` 匹配全部 |
| `bookstore.book[@id='b2'].price` | 属性谓词 |
| `bookstore.book[0].@id` | 属性终结符 |
| `bookstore.book[0].#text` | 直接文本终结符 |
| `/bookstore/book[1]/title` | XPath 风格：1 基下标，`/` 为子元素轴 |
| `//title` | 后代轴，匹配任意深度 |
| `/bookstore//price` | 子元素后再后代轴 |
| `/bookstore/book[@id="b2"]/price` | 双引号属性谓词 |
| `/bookstore/book[1]/text()` | `text()` 终结符 |
| `//{urn:x}name` | Clark 记法按命名空间匹配 |

说明：

- 含 `/` 的表达式按 XPath 风格解析（下标 1 基）；不含 `/` 的表达式按点号风格解析（下标 0 基）。
  两种风格不要混用。
- 无命名空间的步骤名只比较本地名（任意命名空间）；需要限定命名空间时使用 `{uri}local`。
- 属性谓词先于下标求值；后代轴下标按文档顺序全局计数，子轴下标按父元素分组计数。
- 路径步骤上限 64；编译结果 `*Path` 不可变、可并发共享。

## 资源与安全

- `Limits` 零值默认：深度 10000、单 token 64 MiB、实体展开 8 MiB / 16 层、
  Selector 单次匹配文本 8 MiB；`MaxNodes`、`MaxMatches` 默认不限制。
- 外部 DTD/外部实体永不加载；内部实体展开受预算限制。
- `NewDecoderBytes` 的数据在解析器及其 token 使用期间不得修改（零拷贝视图）。
- 错误分类：`errors.Is(err, ErrSyntax / ErrTypeMismatch / ErrLimit / ErrUnsupported /
  ErrPathSyntax)`；`errors.As` 可取 `*SyntaxError`、`*TagPathError`、
  `*UnsupportedTypeError`。

## 性能

测试载荷：约 1.7 MB 的 catalog 文档（8000 条记录，含属性、嵌套元素、实体文本）；
`-benchmem`，每台机器 `-count=3`/`-count=5` 取中位数，同一轮内比较。Zen 5、Xeon 与 ARM64
数据于 2026-11-01 在 v0.1.1 上以 `-benchtime=500ms` 复采；Windows 表为 2026-10-24 的
`-benchtime=1s` 快照，两台主机的绝对值不可跨机比较。完整的第三方对比、兼容性矩阵与方法见
[`benchmarks/xml/README.md`](../benchmarks/xml/README.md)。

### AMD Ryzen AI MAX+ 395（Zen 5，AVX-512，32 vCPU）

| 基准 | ydx/xml | encoding/xml | etree | xmlquery | mxj |
|---|---:|---:|---:|---:|---:|
| DOM Parse | **22.55 ms** / 71.3 MB/s | — | 28.09 ms | 29.15 ms | 34.60 ms |
| DOM 路径查询 | **0.865 ms** / 1.82 GB/s | — | 1.814 ms | 1.489 ms | 0.157 ms¹ |
| 流式 Selector | 11.20 ms / 143.6 MB/s | — | — | — | — |
| Token 流 | **13.46 ms** / 119.5 MB/s | 18.67 ms / 86.1 MB/s | — | — | — |
| Unmarshal | **22.79 ms** / 70.5 MB/s | 27.07 ms / 59.4 MB/s | — | — | — |
| Marshal | **3.758 ms** | 6.358 ms | 2.935 ms² | — | 5.692 ms² |
| Valid | 10.30 ms / 156.1 MB/s | — | — | — | — |

### AMD64 AVX-512（Intel Xeon Platinum，4 vCPU）

| 基准 | ydx/xml | encoding/xml | etree | xmlquery | mxj |
|---|---:|---:|---:|---:|---:|
| DOM Parse | **56.92 ms** / 28.25 MB/s | — | 67.21 ms | 81.09 ms | 82.11 ms |
| DOM 路径查询 | **3.266 ms** / 492 MB/s | — | 8.684 ms | 5.179 ms | 0.650 ms¹ |
| 流式 Selector | 36.67 ms / 43.84 MB/s | — | — | — | — |
| Token 流 | **41.85 ms** / 38.41 MB/s | 51.41 ms / 31.27 MB/s | — | — | — |
| Unmarshal | **68.93 ms** / 23.33 MB/s | 76.51 ms / 21.01 MB/s | — | — | — |
| Marshal | **12.94 ms** | 21.85 ms | 9.406 ms² | — | 18.83 ms² |
| Valid | 34.83 ms / 46.16 MB/s | — | — | — | — |

### ARM64（aarch64，4 vCPU，NEON）

| 基准 | ydx/xml | encoding/xml | etree | xmlquery | mxj |
|---|---:|---:|---:|---:|---:|
| DOM Parse | **42.17 ms** / 38.13 MB/s | — | 49.93 ms | 61.17 ms | 70.04 ms |
| DOM 路径查询 | **1.932 ms** / 832 MB/s | — | 6.266 ms | 4.267 ms | 0.857 ms¹ |
| 流式 Selector | 29.22 ms / 55.03 MB/s | — | — | — | — |
| Token 流 | **33.86 ms** / 47.47 MB/s | 42.17 ms / 38.13 MB/s | — | — | — |
| Unmarshal | **53.45 ms** / 30.08 MB/s | 61.14 ms / 26.29 MB/s | — | — | — |
| Marshal | **10.40 ms** | 16.69 ms | 7.539 ms² | — | 15.72 ms² |
| Valid | 27.96 ms / 57.50 MB/s | — | — | — | — |

### 本机 Windows（Intel i9-10980HK，AVX2，16 线程）

| 基准 | ydx/xml | encoding/xml | etree | xmlquery | mxj |
|---|---:|---:|---:|---:|---:|
| DOM Parse | **37.0 ms** / 46 MB/s | — | 48.1 ms | 56.8 ms | 61.2 ms |
| DOM 路径查询 | **2.76 ms** / 611 MB/s | — | 5.00 ms | 4.23 ms | 0.37 ms¹ |
| 流式 Selector | 26.2 ms / 64 MB/s | — | — | — | — |
| Token 流 | **27.8 ms** / 61 MB/s | 38.3 ms / 44 MB/s | — | — | — |
| Unmarshal | **44.6 ms** / 38 MB/s | 52.2 ms / 32 MB/s | — | — | — |
| Marshal | **13.6 ms** | 15.5 ms | 6.35 ms² | — | 13.4 ms² |
| Valid | 27.1 ms / 62 MB/s | — | — | — | — |

脚注：

1. mxj 查询是已构建 map 的键查找，不遍历 XML 树；其 Parse 成本与内存最高，应按
   “parse + query”总成本比较。
2. etree 与 mxj 的序列化对象是已解析的树/map；ydx 与 encoding/xml 的 `Marshal` 对
   Go 结构体做反射编组，不是同一操作的严格对照。

### 内存与分配

- DOM Parse：208k allocs / 18.4 MB（etree 464k / 17.6 MB）。无装箱事件路径去掉了
  Token 接口分配，DOM 内存与 etree 基本持平。
- Token 流：144k allocs / 5.95 MB（encoding/xml 352k / 11.1 MB）。
- Selector / Valid：8k allocs / 387 KB，内存只与嵌套深度和在途匹配文本相关。

## 测试与验证

- 标准库逐 token 差分：Token / RawToken / 命名空间 / 宽松模式 / CharsetReader /
  InputOffset / InputPos / NewTokenDecoder；1–16 字节分块读取；随机生成文档。
- Unmarshal 全标签矩阵差分、Marshal 字节级差分、随机值往返、billion laughs 预算、
  UTF-16、DTD 实体（原生后端）。
- `-race`：本机 amd64 与远程 arm64 原生运行均通过。
- 远程验证：amd64 AVX-512（两台主机，含 Zen 5 与 Xeon）与 aarch64 NEON。
- 跨架构构建：386、arm、loong64、riscv64、ppc64/ppc64le、s390x、mips64/mips64le。
- `xml_force_scalar` 差分构建；`repotest` 仓库守卫。

## 与标准库的明确差异

- 原生后端额外支持 UTF-16 BOM 自动转码、内部 DTD 实体（受预算限制）、`Valid` 的重复
  属性检查、DOM/路径/Selector、`Limits` 与 `Prewarm`。
- `xml_std` 后端不支持 DTD 实体与 UTF-16 自动检测（由标准库行为决定），其余 API 与
  原生后端一致。
- 宽松模式下，若一个不匹配的结束标签关闭了声明命名空间的元素，原生后端会回退该命名空间
  绑定并接受文档；`encoding/xml` 会保留绑定并报 `unexpected end element`。这是有意的良性
  差异，宽松解析以能继续读取为准。
- 实体替换文本按字符数据处理，不重新解析其中的标记（不执行实体中的元素/属性）。
