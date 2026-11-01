package xml

import (
	"errors"
	"io"
	"reflect"

	"github.com/shibingli/ydx/errs"
)

// captureMark records the state of a source capture region. | captureMark 记录 source 捕获区的状态。
type captureMark struct {
	index  int
	offset int64
	active int
}

// rawSource supplies raw XML tokens: names are not namespace-translated and start/end elements
// are not matched. Self-closing elements are expanded into StartElement followed by EndElement.
// | rawSource 提供原始 XML token：名称未做命名空间翻译，起始/结束元素未配对；自闭合元素会展开为
// StartElement 后跟 EndElement。
type rawSource interface {
	nextRaw() (Token, error)
	nextRawEvent() (event, error)
	offset() int64
	pos() (line, column int)
	beginCapture() captureMark
	endCapture(m captureMark, endOffset int64) []byte
	bytes() ([]byte, bool)
}

// Decoder represents an XML parser reading a particular input stream. It mirrors
// encoding/xml.Decoder. | Decoder 表示读取特定输入流的 XML 解析器，与 encoding/xml.Decoder 对齐。
type Decoder struct {
	src rawSource

	// Entity maps non-standard entity names to replacements. The five predefined entities are
	// always present. | Entity 把非标准实体名映射为替换文本；五个预定义实体始终存在。
	Entity map[string]string

	// CharsetReader converts a declared non-UTF-8 charset to UTF-8. | CharsetReader 把声明的
	// 非 UTF-8 字符集转换为 UTF-8。
	CharsetReader func(charset string, input io.Reader) (io.Reader, error)

	// DefaultSpace is the default namespace for unadorned element names. | DefaultSpace 是
	// 无前缀元素名的默认命名空间。
	DefaultSpace string

	// AutoClose lists element names treated as closed immediately after they are opened when
	// Strict is false. | Strict 为 false 时，AutoClose 列出打开后立即视为关闭的元素名。
	AutoClose []string

	filter tokenFilter

	// Limits bounds resource usage; the zero value selects safe defaults. | Limits 限制资源
	// 占用，零值使用安全默认值。
	Limits Limits

	depth int

	// Strict defaults to true, enforcing the requirements of the XML specification. | Strict 默认
	// 为 true，强制执行 XML 规范的良构要求。
	Strict bool

	inUnmarshalXML bool
}

var errRawToken = errs.New("xml: cannot use RawToken from UnmarshalXML method | xml：不能在 UnmarshalXML 方法中使用 RawToken")

// NewDecoder creates a new XML parser reading from r. | NewDecoder 创建从 r 读取的 XML 解析器。
func NewDecoder(r io.Reader) *Decoder {
	d := &Decoder{Strict: true}
	d.src = newRawSourceFromReader(d, r)
	d.filter.init(d, d.src)
	return d
}

// NewDecoderBytes creates a new XML parser reading directly from data without copying. The data
// must not be modified while the decoder or any token derived from it is in use. | NewDecoderBytes
// 创建直接从 data 读取且不复制数据的解析器；解码器或其派生的 token 使用期间不得修改 data。
func NewDecoderBytes(data []byte) *Decoder {
	d := &Decoder{Strict: true}
	d.src = newRawSourceFromBytes(d, data)
	d.filter.init(d, d.src)
	return d
}

// NewTokenDecoder creates a decoder that reads raw tokens from t. If t is already a *Decoder,
// it is returned unchanged. | NewTokenDecoder 创建从 t 读取原始 token 的解码器；若 t 已是
// *Decoder 则原样返回。
func NewTokenDecoder(t TokenReader) *Decoder {
	if d, ok := t.(*Decoder); ok {
		return d
	}
	d := &Decoder{Strict: true}
	d.src = &tokenReaderSource{tokens: t}
	d.filter.init(d, d.src)
	return d
}

// limits returns the effective resource limits. | limits 返回生效的资源上限。
func (d *Decoder) limits() Limits { return d.Limits.normalized() }

// Token returns the next XML token in the input stream, with namespace prefixes translated and
// start/end elements verified. | Token 返回输入流中的下一个 XML token，完成命名空间前缀翻译并校验
// 起始/结束元素配对。
func (d *Decoder) Token() (Token, error) {
	t, err := d.filter.next()
	if err != nil {
		return nil, d.classify(err)
	}
	return t, nil
}

// nextEvent fills ev with the next filtered event without boxing it in the Token interface. |
// nextEvent 用下一个过滤后的事件填充 ev，不装箱到 Token 接口。
func (d *Decoder) nextEvent(ev *event) error {
	if err := d.filter.nextEvent(ev); err != nil {
		return d.classify(err)
	}
	return nil
}

// tokenToEvent converts a public Token into an internal event. | tokenToEvent 把公开 Token 转换为
// 内部事件。
func tokenToEvent(t Token, ev *event) bool {
	switch t := t.(type) {
	case StartElement:
		ev.kind = evStart
		ev.name = t.Name
		ev.attrs = t.Attr
		return true
	case EndElement:
		ev.kind = evEnd
		ev.name = t.Name
		return true
	case CharData:
		ev.kind = evText
		ev.data = t
		return true
	case Comment:
		ev.kind = evComment
		ev.data = t
		return true
	case ProcInst:
		ev.kind = evProcInst
		ev.target = t.Target
		ev.data = t.Inst
		return true
	case Directive:
		ev.kind = evDirective
		ev.data = t
		return true
	}
	return false
}

// RawToken is like Token but does not translate namespaces or verify matching start and end
// elements. | RawToken 类似 Token，但不翻译命名空间，也不校验起始/结束元素配对。
func (d *Decoder) RawToken() (Token, error) {
	if d.inUnmarshalXML {
		return nil, errRawToken
	}
	t, err := d.src.nextRaw()
	if err != nil {
		return nil, d.classify(err)
	}
	return t, nil
}

// classify annotates lexical errors with ErrSyntax while preserving the concrete error for
// errors.As. | classify 为词法错误附加 ErrSyntax，同时保留具体错误供 errors.As 使用。
func (d *Decoder) classify(err error) error {
	if err == nil || err == io.EOF {
		return err
	}
	if errors.Is(err, ErrSyntax) || errors.Is(err, ErrLimit) || errors.Is(err, ErrUnsupported) {
		return err
	}
	var se *SyntaxError
	if errors.As(err, &se) {
		return errs.Wrap(err, ErrSyntax)
	}
	return err
}

// Skip reads tokens until it has consumed the end element matching the most recent start element
// already consumed, skipping nested structures. | Skip 读取 token 直到消费与最近已消费起始元素匹配的
// 结束元素，跳过嵌套结构。
func (d *Decoder) Skip() error {
	var depth int
	for {
		t, err := d.Token()
		if err != nil {
			return err
		}
		switch t.(type) {
		case StartElement:
			depth++
		case EndElement:
			if depth == 0 {
				return nil
			}
			depth--
		}
	}
}

// InputOffset returns the input stream byte offset of the current decoder position. | InputOffset
// 返回解码器当前位置的输入流字节偏移。
func (d *Decoder) InputOffset() int64 { return d.src.offset() }

// InputPos returns the line and one-based column of the current decoder position. | InputPos 返回
// 当前位置的行号与从一开始的列号。
func (d *Decoder) InputPos() (line, column int) { return d.src.pos() }

// beginInnerCapture starts a capture of raw bytes for ,innerxml. | beginInnerCapture 开始为
// ,innerxml 捕获原始字节。
func (d *Decoder) beginInnerCapture() captureMark { return d.src.beginCapture() }

// endInnerCapture finishes a capture at endOffset. | endInnerCapture 在 endOffset 处结束捕获。
func (d *Decoder) endInnerCapture(m captureMark, endOffset int64) []byte {
	return d.src.endCapture(m, endOffset)
}

// tokenStartOffset returns the byte offset at which the most recently consumed raw token began.
// | tokenStartOffset 返回最近消费的原始 token 的起始字节偏移。
func (d *Decoder) tokenStartOffset() int64 { return d.filter.lastStart }

// Decode works like Unmarshal, except it reads the decoder stream to find the start element. |
// Decode 类似 Unmarshal，但从解码器流中查找起始元素。
func (d *Decoder) Decode(v any) error { return d.DecodeElement(v, nil) }

// DecodeElement works like Unmarshal except that it takes a pointer to the start XML element to
// decode into v. | DecodeElement 类似 Unmarshal，但接收指向起始 XML 元素的指针用于解码。
func (d *Decoder) DecodeElement(v any, start *StartElement) error {
	val := reflect.ValueOf(v)
	if val.Kind() != reflect.Pointer {
		return errs.Detail(ErrTypeMismatch, "non-pointer passed to Unmarshal | 传给 Unmarshal 的不是指针")
	}
	if val.IsNil() {
		return errs.Detail(ErrTypeMismatch, "nil pointer passed to Unmarshal | 传给 Unmarshal 的是 nil 指针")
	}
	return d.unmarshal(val.Elem(), start)
}

// Unmarshaler is the interface implemented by objects that can unmarshal an XML element
// description of themselves. | Unmarshaler 由能够自行反序列化 XML 元素描述的对象实现。
type Unmarshaler interface {
	UnmarshalXML(d *Decoder, start StartElement) error
}

// UnmarshalerAttr is the interface implemented by objects that can unmarshal an XML attribute
// description of themselves. | UnmarshalerAttr 由能够自行反序列化 XML 属性描述的对象实现。
type UnmarshalerAttr interface {
	UnmarshalXMLAttr(attr Attr) error
}

// tokenReaderSource adapts an arbitrary TokenReader to rawSource. | tokenReaderSource 把任意
// TokenReader 适配为 rawSource。
type tokenReaderSource struct {
	tokens TokenReader
}

func (s *tokenReaderSource) nextRaw() (Token, error) { return s.tokens.Token() }
func (s *tokenReaderSource) nextRawEvent() (event, error) {
	for {
		t, err := s.tokens.Token()
		if err != nil {
			return event{}, err
		}
		if t == nil {
			continue
		}
		var ev event
		if tokenToEvent(t, &ev) {
			return ev, nil
		}
	}
}
func (s *tokenReaderSource) offset() int64   { return 0 }
func (s *tokenReaderSource) pos() (int, int) { return 1, 1 }
func (s *tokenReaderSource) beginCapture() captureMark {
	return captureMark{}
}
func (s *tokenReaderSource) endCapture(captureMark, int64) []byte { return nil }
func (s *tokenReaderSource) bytes() ([]byte, bool)                { return nil, false }
