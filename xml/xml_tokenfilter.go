package xml

import (
	"io"
	"strings"
)

const (
	xmlURL      = "http://www.w3.org/XML/1998/namespace"
	xmlnsPrefix = "xmlns"
	xmlPrefix   = "xml"
)

// nsBinding records a namespace binding that must be undone when its element ends. | nsBinding
// 记录元素结束时需要撤销的命名空间绑定。
type nsBinding struct {
	prefix string
	old    string
	had    bool
}

// elemFrame is one open element and the namespace bindings it introduced. | elemFrame 表示一个
// 打开的元素及其引入的命名空间绑定。
type elemFrame struct {
	name     Name
	bindings []nsBinding
}

// tokenFilter turns raw tokens into encoding/xml-compatible tokens: it translates namespace
// prefixes, verifies start/end matching and applies AutoClose in lenient mode. | tokenFilter 把
// 原始 token 转换为与 encoding/xml 兼容的 token：翻译命名空间前缀、校验起止配对，并在宽松模式下
// 应用 AutoClose。
type tokenFilter struct {
	d   *Decoder
	src rawSource

	ns      map[string]string
	stack   []elemFrame
	pending []event

	depth     int
	lastStart int64
	lastEnd   int64
}

func (f *tokenFilter) init(d *Decoder, src rawSource) {
	f.d = d
	f.src = src
	f.ns = make(map[string]string)
}

func (f *tokenFilter) syntax(msg string) error {
	line, _ := f.src.pos()
	return &SyntaxError{Msg: msg, Line: line}
}

// next returns the next filtered token. | next 返回下一个过滤后的 token。
func (f *tokenFilter) next() (Token, error) {
	var ev event
	if err := f.nextEvent(&ev); err != nil {
		return nil, err
	}
	return ev.token(), nil
}

// nextEvent fills ev with the next filtered event. | nextEvent 用下一个过滤后的事件填充 ev。
func (f *tokenFilter) nextEvent(ev *event) error {
	for {
		var raw event
		if len(f.pending) > 0 {
			raw = f.pending[0]
			f.pending = f.pending[1:]
		} else {
			f.lastStart = f.src.offset()
			var err error
			raw, err = f.src.nextRawEvent()
			f.lastEnd = f.src.offset()
			if err == io.EOF && len(f.stack) > 0 {
				return f.syntax("unexpected EOF")
			}
			if err != nil {
				return err
			}
			if raw.kind == evNone {
				continue
			}
			if !f.d.Strict {
				if closing, ok := f.autoClose(&raw); ok {
					f.pending = append(f.pending, raw)
					raw = closing
				}
			}
		}
		switch raw.kind {
		case evStart:
			return f.handleStart(&raw, ev)
		case evEnd:
			return f.handleEnd(&raw, ev)
		default:
			*ev = raw
			return nil
		}
	}
}

// autoClose returns a synthetic end event when the top open element is in AutoClose and raw does
// not close it. | 当栈顶元素位于 AutoClose 且 raw 未关闭它时，autoClose 返回合成的结束事件。
func (f *tokenFilter) autoClose(raw *event) (event, bool) {
	if len(f.stack) == 0 {
		return event{}, false
	}
	top := f.stack[len(f.stack)-1].name
	for _, s := range f.d.AutoClose {
		if strings.EqualFold(s, top.Local) {
			if raw.kind == evEnd && strings.EqualFold(raw.name.Local, top.Local) {
				return event{}, false
			}
			return event{kind: evEnd, name: top}, true
		}
	}
	return event{}, false
}

func (f *tokenFilter) handleStart(raw *event, ev *event) error {
	if f.depth+1 > f.d.limits().MaxDepth {
		return ErrLimit
	}
	frame := elemFrame{name: raw.name}
	for _, a := range raw.attrs {
		if a.Name.Space == xmlnsPrefix {
			frame.bindings = append(frame.bindings, f.bind(a.Name.Local, a.Value))
			continue
		}
		if a.Name.Space == "" && a.Name.Local == xmlnsPrefix {
			frame.bindings = append(frame.bindings, f.bind("", a.Value))
		}
	}
	f.stack = append(f.stack, frame)
	f.depth++
	f.translate(&raw.name, true)
	for i := range raw.attrs {
		f.translate(&raw.attrs[i].Name, false)
	}
	*ev = *raw
	return nil
}

func (f *tokenFilter) bind(prefix, url string) nsBinding {
	old, had := f.ns[prefix]
	f.ns[prefix] = url
	return nsBinding{prefix: prefix, old: old, had: had}
}

func (f *tokenFilter) handleEnd(raw *event, ev *event) error {
	if len(f.stack) == 0 {
		return f.syntax("unexpected end element </" + raw.name.Local + ">")
	}
	top := f.stack[len(f.stack)-1]
	if top.name.Local != raw.name.Local {
		if f.d.Strict {
			return f.syntax("element <" + top.name.Local + "> closed by </" + raw.name.Local + ">")
		}
		// Match encoding/xml: emit the raw name recorded on the stack for the element being
		// popped (no namespace translation), then replay the mismatched end tag against the
		// enclosing element on the next call. | 与 encoding/xml 一致：先为被弹出的元素发出栈上
		// 记录的原始名称（不做命名空间翻译），再在下次调用时用错配的结束标签匹配外层元素。
		f.popFrame()
		f.pending = append(f.pending, event{})
		copy(f.pending[1:], f.pending)
		f.pending[0] = *raw
		*ev = event{kind: evEnd, name: top.name}
		return nil
	}
	if top.name.Space != raw.name.Space {
		ns := raw.name.Space
		if ns == "" {
			ns = `""`
		}
		return f.syntax("element <" + top.name.Local + "> in space " + top.name.Space +
			" closed by </" + raw.name.Local + "> in space " + ns)
	}
	name := raw.name
	f.translate(&name, true)
	f.popFrame()
	*ev = event{kind: evEnd, name: name}
	return nil
}

func (f *tokenFilter) popFrame() {
	top := f.stack[len(f.stack)-1]
	for i := len(top.bindings) - 1; i >= 0; i-- {
		b := top.bindings[i]
		if b.had {
			f.ns[b.prefix] = b.old
		} else {
			delete(f.ns, b.prefix)
		}
	}
	f.stack = f.stack[:len(f.stack)-1]
	f.depth--
}

// translate applies namespace translation to n, mirroring encoding/xml. | translate 对 n 应用
// 命名空间翻译，行为与 encoding/xml 一致。
func (f *tokenFilter) translate(n *Name, isElementName bool) {
	switch {
	case n.Space == xmlnsPrefix:
		return
	case n.Space == "" && !isElementName:
		return
	case n.Space == xmlPrefix:
		n.Space = xmlURL
	case n.Space == "" && n.Local == xmlnsPrefix:
		return
	}
	if v, ok := f.ns[n.Space]; ok {
		n.Space = v
	} else if n.Space == "" {
		n.Space = f.d.DefaultSpace
	}
}
