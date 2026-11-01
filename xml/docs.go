// Package xml provides a self-developed, hardware-adaptive XML codec that mirrors the complete
// encoding/xml API while adding streaming path queries and a zero-copy DOM. | Package xml 提供
// 自研、硬件自适应的 XML 编解码器，完整对齐 encoding/xml API，并增加流式路径查询与零拷贝 DOM。
//
// Backend routing is transparent to callers: | 后端分流对调用方完全透明：
//
//   - without the xml_std tag, every architecture uses the native backend. amd64 uses
//     hand-written SSE2, AVX2 and AVX-512BW scan kernels selected at runtime by instruction-set
//     level; arm64 uses hand-written NEON; other architectures use portable 8-byte SWAR/scalar
//     scanning. No cgo and no GOEXPERIMENT are required. Backend() returns "yd-native"; |
//     未设置 xml_std 标签时，所有架构使用原生后端。amd64 使用手写 SSE2、AVX2、AVX-512BW 扫描
//     内核并按指令集级别在运行时择优；arm64 使用手写 NEON；其它架构使用可移植的 8 字节
//     SWAR/标量扫描。无 cgo、不需要 GOEXPERIMENT。Backend() 返回 "yd-native"；
//   - with the xml_std tag, raw tokenization delegates to encoding/xml while all higher-level
//     behavior stays shared. Backend() returns "encoding/xml". | 设置 xml_std 标签时，原始词法
//     分析委托给 encoding/xml，所有上层行为仍共享同一实现。Backend() 返回 "encoding/xml"。
//
// Full compatibility | 完整兼容：
//
//   - Token, Decoder (Strict, AutoClose, Entity, CharsetReader, DefaultSpace, Token, RawToken,
//     Skip, Decode, DecodeElement, InputOffset, InputPos), NewTokenDecoder, CopyToken;
//   - Unmarshal with every encoding/xml tag mode (name, namespace, attr, chardata, cdata,
//     innerxml, comment, any, any+attr, omitempty, a>b>c nesting, XMLName, embedded fields,
//     Name/Attr, pointers, slices, TextUnmarshaler, Unmarshaler, UnmarshalerAttr);
//   - Marshal/MarshalIndent/NewEncoder with Encode, EncodeElement, EncodeToken, Flush, Indent,
//     Close; Marshaler, MarshalerAttr, TextMarshaler, namespace prefix generation;
//   - EscapeText, Header, HTMLAutoClose, HTMLEntity, SyntaxError, TagPathError,
//     UnsupportedTypeError and UnmarshalError. | Token、Decoder 全字段与方法、
//     NewTokenDecoder、CopyToken；Unmarshal 全部标签模式；Marshal/Encoder 全 API；
//     EscapeText、Header、HTMLAutoClose、HTMLEntity 与全部错误类型。
//
// Native extensions | 原生扩展：
//
//   - UTF-16 LE/BE BOM auto-detection and transcoding; UTF-8 BOM follows encoding/xml and is
//     returned as character data by Token. | UTF-16 LE/BE BOM 自动检测与转码；UTF-8 BOM 遵循
//     encoding/xml，Token 会把它作为字符数据返回；
//   - internal-subset DTD general entities with expansion depth and byte budgets (no external
//     entity loading); | 内部子集 DTD 通用实体，带展开深度与字节预算（不加载外部实体）；
//   - Limits bounding depth, token size, DOM nodes, entity expansion, selector text and match
//     count; | Limits 限制深度、token 大小、DOM 节点、实体展开、Selector 文本与匹配数；
//   - Valid, a stricter well-formedness check that also rejects duplicate attributes and text
//     outside the root; | Valid 是更严格的良构检查，还会拒绝重复属性与根元素之外的文本；
//   - Document/Node DOM with raw InnerXML/OuterXML views and navigation helpers; | Document/Node
//     DOM，提供原始 InnerXML/OuterXML 视图与导航辅助方法；
//   - compiled Path queries in dot style (zero-based) or XPath style (one-based), executed over
//     a DOM or streamed by Selector with O(depth) memory. | 编译式 Path 查询，支持点号风格
//     （0 基）与 XPath 风格（1 基），可在 DOM 上执行，也可由 Selector 以 O(深度) 内存流式执行。
//
// Typical native Go usage | 典型原生 Go 用法：
//
//	type Book struct {
//		ID    int    `xml:"id,attr"`
//		Title string `xml:"title"`
//	}
//
//	var books struct {
//		Items []Book `xml:"book"`
//	}
//	if err := xml.Unmarshal(data, &books); err != nil {
//		return err
//	}
//
//	out, err := xml.Marshal(books)
//
// DOM and path queries | DOM 与路径查询：
//
//	doc, err := xml.Parse(data)
//	if err != nil {
//		return err
//	}
//	title, err := xml.Compile("bookstore.book[0].title")
//	if err != nil {
//		return err
//	}
//	name, ok := doc.Value(title)
//
// Streaming queries for very large documents | 超大文档的流式查询：
//
//	p, _ := xml.Compile("/bookstore/book/title")
//	err := xml.EachFile("catalog.xml", p, func(m *xml.Match) error {
//		process(m.Text)
//		return nil
//	})
//
// Token stream | Token 流：
//
//	dec := xml.NewDecoder(r)
//	for {
//		tok, err := dec.Token()
//		if err == io.EOF {
//			break
//		}
//		if err != nil {
//			return err
//		}
//		_ = tok
//	}
//
// YD router usage | YD 路由用法：
//
//	r := router.New()
//	r.POST("/orders", func(c *router.Ctx) {
//		var order Order
//		if err := xml.NewDecoder(c.Body()).Decode(&order); err != nil {
//			_ = c.String(http.StatusBadRequest, err.Error())
//			return
//		}
//		_ = c.JSON(http.StatusOK, order)
//	})
//
// Native net/http usage | 原生 net/http 用法：
//
//	http.HandleFunc("/orders", func(w http.ResponseWriter, r *http.Request) {
//		var order Order
//		if err := xml.NewDecoder(r.Body).Decode(&order); err != nil {
//			http.Error(w, err.Error(), http.StatusBadRequest)
//			return
//		}
//		w.Header().Set("Content-Type", "application/xml")
//		_ = xml.NewEncoder(w).Encode(order)
//	})
//
// Errors can be classified with errors.Is against ErrSyntax, ErrTypeMismatch, ErrLimit,
// ErrUnsupported and ErrPathSyntax, while SyntaxError, TagPathError and UnsupportedTypeError
// remain available through errors.As. | 错误可用 errors.Is 按 ErrSyntax、ErrTypeMismatch、
// ErrLimit、ErrUnsupported、ErrPathSyntax 分类，同时可通过 errors.As 获取 SyntaxError、
// TagPathError 与 UnsupportedTypeError。
//
// The import path is github.com/shibingli/ydx/xml and the package identifier is xml, matching the
// directory name. | 导入路径是 github.com/shibingli/ydx/xml，包标识符为 xml，与目录名一致。
package xml
