package xml

import (
	"io"

	"github.com/shibingli/ydx/errs"
)

var (
	// ErrSyntax indicates the input is not well-formed XML. | ErrSyntax 表示输入不是合法的 XML。
	//
	// The native backend classifies every lexical or structural error as ErrSyntax, and the
	// original contextual error is kept in the chain so errors.Is/As can inspect it. | 原生后端
	// 把所有词法或结构错误归类为 ErrSyntax，并通过错误链保留带上下文的原始错误，可用
	// errors.Is/As 进一步判定。
	ErrSyntax = errs.New("xml: invalid XML syntax | xml：非法的 XML 语法")

	// ErrTypeMismatch indicates the XML is well-formed but cannot be mapped to the target Go
	// value. | ErrTypeMismatch 表示 XML 本身合法，但无法映射到目标 Go 值。
	ErrTypeMismatch = errs.New("xml: XML value does not match target Go type | xml：XML 值与目标 Go 类型不匹配")

	// ErrLimit indicates a configured limit was exceeded, such as maximum depth, token size,
	// node count or entity expansion. | ErrLimit 表示超出配置上限，例如最大深度、token 大小、
	// 节点数或实体展开量。
	ErrLimit = errs.New("xml: configured limit exceeded | xml：超出配置上限")

	// ErrUnsupported indicates a feature is not supported by the active backend, such as
	// external entities or XML 1.1. | ErrUnsupported 表示当前后端不支持该特性，例如外部实体或
	// XML 1.1。
	ErrUnsupported = errs.New("xml: unsupported XML feature | xml：不支持的 XML 特性")

	// ErrPathSyntax indicates a malformed path expression. | ErrPathSyntax 表示路径表达式格式错误。
	ErrPathSyntax = errs.New("xml: invalid path expression | xml：非法的路径表达式")
)

// Name is an XML name with an optional namespace. | Name 是带可选命名空间的 XML 名称。
//
// Space holds the namespace URL after namespace translation by Token, or the literal prefix
// returned by RawToken. Local holds the local name. | Space 在 Token 解析后是命名空间 URL，
// 在 RawToken 中可能是原始前缀；Local 是本地名。
type Name struct {
	Space, Local string
}

// String renders the name in Clark notation when a namespace is present. | 存在命名空间时按
// Clark 记法渲染名称。
func (n Name) String() string {
	if n.Space == "" {
		return n.Local
	}
	return "{" + n.Space + "}" + n.Local
}

// Attr is an XML attribute. | Attr 表示一个 XML 属性。
type Attr struct {
	Name  Name
	Value string
}

// StartElement is an XML start element token. | StartElement 是 XML 起始元素 token。
type StartElement struct {
	Name Name
	Attr []Attr
}

// Copy returns a deep copy of the token. | Copy 返回 token 的深拷贝。
func (e StartElement) Copy() Token {
	attrs := make([]Attr, len(e.Attr))
	copy(attrs, e.Attr)
	e.Attr = attrs
	return e
}

// End returns the matching end element token. | End 返回匹配的结束元素 token。
func (e StartElement) End() EndElement {
	return EndElement{Name: e.Name}
}

// EndElement is an XML end element token. | EndElement 是 XML 结束元素 token。
type EndElement struct {
	Name Name
}

// Copy returns a deep copy of the token. | Copy 返回 token 的深拷贝。
func (e EndElement) Copy() Token {
	return e
}

// CharData is character data, with character and entity references already resolved. | CharData
// 是字符数据，字符引用与实体引用已完成解码。
type CharData []byte

// Copy returns a deep copy of the token. | Copy 返回 token 的深拷贝。
func (c CharData) Copy() Token {
	data := make([]byte, len(c))
	copy(data, c)
	return CharData(data)
}

// String returns the character data as a string. | String 以字符串形式返回字符数据。
func (c CharData) String() string { return string(c) }

// Comment is an XML comment, without the enclosing <!-- and -->. | Comment 是 XML 注释，
// 不包含外层的 <!-- 与 -->。
type Comment []byte

// Copy returns a deep copy of the token. | Copy 返回 token 的深拷贝。
func (c Comment) Copy() Token {
	data := make([]byte, len(c))
	copy(data, c)
	return Comment(data)
}

// String returns the comment as a string. | String 以字符串形式返回注释内容。
func (c Comment) String() string { return string(c) }

// ProcInst is an XML processing instruction. | ProcInst 是 XML 处理指令。
type ProcInst struct {
	Target string
	Inst   []byte
}

// Copy returns a deep copy of the token. | Copy 返回 token 的深拷贝。
func (p ProcInst) Copy() Token {
	inst := make([]byte, len(p.Inst))
	copy(inst, p.Inst)
	p.Inst = inst
	return p
}

// Directive is an XML directive such as <!DOCTYPE ...>. | Directive 是 XML 指令，例如
// <!DOCTYPE ...>。
type Directive []byte

// Copy returns a deep copy of the token. | Copy 返回 token 的深拷贝。
func (d Directive) Copy() Token {
	data := make([]byte, len(d))
	copy(data, d)
	return Directive(data)
}

// Token is one of StartElement, EndElement, CharData, Comment, ProcInst or Directive. |
// Token 是 StartElement、EndElement、CharData、Comment、ProcInst 或 Directive 之一。
type Token interface{}

// TokenReader is implemented by token streams. | TokenReader 由 token 流实现。
type TokenReader interface {
	Token() (Token, error)
}

// CopyToken returns a deep copy of t. | CopyToken 返回 t 的深拷贝。
//
// Character data, comments, directives and processing instruction payloads are copied, and the
// attribute slice of a start element is copied. | 字符数据、注释、指令与处理指令载荷都会被复制，
// 起始元素的属性切片也会被复制。
func CopyToken(t Token) Token {
	switch t := t.(type) {
	case StartElement:
		return t.Copy()
	case EndElement:
		return t.Copy()
	case CharData:
		return t.Copy()
	case Comment:
		return t.Copy()
	case ProcInst:
		return t.Copy()
	case Directive:
		return t.Copy()
	}
	return t
}

// Limits bounds parser resource usage. The zero value selects the documented defaults. |
// Limits 限制解析器资源占用，零值表示使用文档化默认值。
type Limits struct {
	// MaxDepth is the maximum element nesting depth; 0 means 10000. | MaxDepth 是最大元素
	// 嵌套深度，0 表示 10000。
	MaxDepth int

	// MaxTokenSize is the maximum size of one token (text, attribute value, comment, PI or
	// directive) in bytes; 0 means 64 MiB. It also bounds ,innerxml capture. | MaxTokenSize
	// 是单个 token（文本、属性值、注释、PI 或指令）的最大字节数，0 表示 64 MiB；同时限制
	// ,innerxml 的捕获量。
	MaxTokenSize int

	// MaxNodes is the maximum number of DOM nodes; 0 means unlimited. | MaxNodes 是 DOM 节点
	// 上限，0 表示不限制。
	MaxNodes int

	// MaxEntityExpansion is the maximum number of bytes produced by custom or DTD entity
	// expansion per parse; 0 means 8 MiB. | MaxEntityExpansion 是单次解析中自定义或 DTD 实体
	// 展开产生的最大字节数，0 表示 8 MiB。
	MaxEntityExpansion int64

	// MaxEntityDepth is the maximum recursive entity expansion depth; 0 means 16. |
	// MaxEntityDepth 是实体递归展开的最大深度，0 表示 16。
	MaxEntityDepth int

	// MaxTextSize is the maximum text captured for one Selector match; 0 means 8 MiB. |
	// MaxTextSize 是单个 Selector 匹配捕获的最大文本量，0 表示 8 MiB。
	MaxTextSize int

	// MaxMatches is the maximum number of Selector matches; 0 means unlimited. | MaxMatches
	// 是 Selector 匹配数量上限，0 表示不限制。
	MaxMatches int
}

const (
	defaultMaxDepth           = 10000
	defaultMaxTokenSize       = 64 << 20
	defaultMaxEntityExpansion = 8 << 20
	defaultMaxEntityDepth     = 16
	defaultMaxTextSize        = 8 << 20
)

func (l Limits) normalized() Limits {
	if l.MaxDepth <= 0 {
		l.MaxDepth = defaultMaxDepth
	}
	if l.MaxTokenSize <= 0 {
		l.MaxTokenSize = defaultMaxTokenSize
	}
	if l.MaxEntityExpansion <= 0 {
		l.MaxEntityExpansion = defaultMaxEntityExpansion
	}
	if l.MaxEntityDepth <= 0 {
		l.MaxEntityDepth = defaultMaxEntityDepth
	}
	if l.MaxTextSize <= 0 {
		l.MaxTextSize = defaultMaxTextSize
	}
	return l
}

// ParseOptions configures Parse and ParseReader. | ParseOptions 配置 Parse 与 ParseReader。
type ParseOptions struct {

	// Entity adds non-standard entity mappings. | Entity 增加非标准实体映射。
	Entity map[string]string

	// CharsetReader converts a declared non-UTF-8 encoding to UTF-8. | CharsetReader 把声明的
	// 非 UTF-8 编码转换为 UTF-8。
	CharsetReader func(charset string, input io.Reader) (io.Reader, error)

	// DefaultSpace is the default namespace for unadorned element names. | DefaultSpace 是
	// 无前缀元素名的默认命名空间。
	DefaultSpace string

	// AutoClose lists element names that are closed implicitly in lenient mode. | AutoClose
	// 列出宽松模式下隐式关闭的元素名。
	AutoClose []string

	// Limits bounds resource usage. | Limits 限制资源占用。
	Limits Limits

	// Lenient disables strict well-formedness checks; the default zero value is strict. |
	// Lenient 关闭严格良构检查，默认零值是严格模式。
	Lenient bool

	// DiscardComments drops comment nodes from the DOM. | DiscardComments 丢弃 DOM 中的注释节点。
	DiscardComments bool

	// DiscardProcInst drops processing instruction nodes from the DOM. | DiscardProcInst 丢弃
	// DOM 中的处理指令节点。
	DiscardProcInst bool

	// DiscardDirectives drops directive nodes from the DOM. | DiscardDirectives 丢弃 DOM 中的
	// 指令节点。
	DiscardDirectives bool
}
