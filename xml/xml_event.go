package xml

// eventKind identifies an internal, allocation-free parser event. | eventKind 标识内部无分配的
// 解析事件。
type eventKind uint8

const (
	evNone eventKind = iota
	evStart
	evEnd
	evText
	evComment
	evProcInst
	evDirective
)

// event is the internal event form shared by DOM, Selector, Valid and the public Token wrapper.
// | event 是由 DOM、Selector、Valid 与公开 Token 包装共享的内部事件形式。
type event struct {
	name   Name
	target string
	attrs  []Attr
	data   []byte
	kind   eventKind
}

// token converts an event to the public Token interface. | token 把事件转换为公开 Token 接口。
func (e *event) token() Token {
	switch e.kind {
	case evStart:
		return StartElement{Name: e.name, Attr: e.attrs}
	case evEnd:
		return EndElement{Name: e.name}
	case evText:
		return CharData(e.data)
	case evComment:
		return Comment(e.data)
	case evProcInst:
		return ProcInst{Target: e.target, Inst: e.data}
	case evDirective:
		return Directive(e.data)
	}
	return nil
}
