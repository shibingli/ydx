package xml

import (
	"bytes"
	"encoding"
	"reflect"
	"strconv"
	"strings"

	"github.com/shibingli/ydx/errs"
)

// Marshal returns the XML encoding of v. It mirrors encoding/xml.Marshal. | Marshal 返回 v 的 XML
// 编码，行为与 encoding/xml.Marshal 一致。
func Marshal(v any) ([]byte, error) {
	var b bytes.Buffer
	enc := NewEncoder(&b)
	if err := enc.Encode(v); err != nil {
		return nil, err
	}
	if err := enc.Close(); err != nil {
		return nil, err
	}
	return b.Bytes(), nil
}

// MarshalIndent works like Marshal, but each element begins on a new indented line. | MarshalIndent
// 类似 Marshal，但每个元素从新行开始并缩进。
func MarshalIndent(v any, prefix, indent string) ([]byte, error) {
	var b bytes.Buffer
	enc := NewEncoder(&b)
	enc.Indent(prefix, indent)
	if err := enc.Encode(v); err != nil {
		return nil, err
	}
	if err := enc.Close(); err != nil {
		return nil, err
	}
	return b.Bytes(), nil
}

// Marshaler is the interface implemented by objects that can marshal themselves into valid XML
// elements. | Marshaler 由能够自行编组为合法 XML 元素的对象实现。
type Marshaler interface {
	MarshalXML(e *Encoder, start StartElement) error
}

// MarshalerAttr is the interface implemented by objects that can marshal themselves into valid
// XML attributes. | MarshalerAttr 由能够自行编组为合法 XML 属性的对象实现。
type MarshalerAttr interface {
	MarshalXMLAttr(name Name) (Attr, error)
}

func (p *printer) marshalValue(val reflect.Value, finfo *fieldInfo, startTemplate *StartElement) error {
	if startTemplate != nil && startTemplate.Name.Local == "" {
		return errs.Detail(ErrTypeMismatch, "xml: EncodeElement of StartElement with missing name")
	}
	if !val.IsValid() {
		return nil
	}
	if finfo != nil && finfo.flags&fOmitEmpty != 0 && isEmptyValue(val) {
		return nil
	}

	for val.Kind() == reflect.Interface || val.Kind() == reflect.Pointer {
		if val.IsNil() {
			return nil
		}
		val = val.Elem()
	}

	kind := val.Kind()
	typ := val.Type()

	if val.CanInterface() {
		if marshaler, ok := reflect.TypeAssert[Marshaler](val); ok {
			return p.marshalInterface(marshaler, defaultStart(typ, finfo, startTemplate))
		}
	}
	if val.CanAddr() {
		pv := val.Addr()
		if pv.CanInterface() {
			if marshaler, ok := reflect.TypeAssert[Marshaler](pv); ok {
				return p.marshalInterface(marshaler, defaultStart(pv.Type(), finfo, startTemplate))
			}
		}
	}
	if val.CanInterface() {
		if tm, ok := reflect.TypeAssert[encoding.TextMarshaler](val); ok {
			return p.marshalTextInterface(tm, defaultStart(typ, finfo, startTemplate))
		}
	}
	if val.CanAddr() {
		pv := val.Addr()
		if pv.CanInterface() {
			if tm, ok := reflect.TypeAssert[encoding.TextMarshaler](pv); ok {
				return p.marshalTextInterface(tm, defaultStart(pv.Type(), finfo, startTemplate))
			}
		}
	}

	if (kind == reflect.Slice || kind == reflect.Array) && typ.Elem().Kind() != reflect.Uint8 {
		for i, n := 0, val.Len(); i < n; i++ {
			if err := p.marshalValue(val.Index(i), finfo, startTemplate); err != nil {
				return err
			}
		}
		return nil
	}

	tinfo, err := getTypeInfo(typ)
	if err != nil {
		return err
	}

	var start StartElement
	if startTemplate != nil {
		start.Name = startTemplate.Name
		start.Attr = append(start.Attr, startTemplate.Attr...)
	} else if tinfo.xmlname != nil {
		xmlname := tinfo.xmlname
		if xmlname.name != "" {
			start.Name.Space, start.Name.Local = xmlname.xmlns, xmlname.name
		} else {
			fv := xmlname.value(val, dontInitNilPointers)
			if v, ok := reflect.TypeAssert[Name](fv); ok && v.Local != "" {
				start.Name = v
			}
		}
	}
	if start.Name.Local == "" && finfo != nil {
		start.Name.Space, start.Name.Local = finfo.xmlns, finfo.name
	}
	if start.Name.Local == "" {
		name := typ.Name()
		if i := strings.IndexByte(name, '['); i >= 0 {
			name = name[:i]
		}
		if name == "" {
			return &UnsupportedTypeError{typ}
		}
		start.Name.Local = name
	}

	for i := range tinfo.fields {
		finfo := &tinfo.fields[i]
		if finfo.flags&fAttr == 0 {
			continue
		}
		fv := finfo.value(val, dontInitNilPointers)
		if finfo.flags&fOmitEmpty != 0 && (!fv.IsValid() || isEmptyValue(fv)) {
			continue
		}
		if fv.Kind() == reflect.Interface && fv.IsNil() {
			continue
		}
		name := Name{Space: finfo.xmlns, Local: finfo.name}
		if err := p.marshalAttr(&start, name, fv); err != nil {
			return err
		}
	}

	if tinfo.xmlname != nil && start.Name.Space == "" &&
		tinfo.xmlname.xmlns == "" && tinfo.xmlname.name == "" &&
		len(p.tags) != 0 && p.tags[len(p.tags)-1].Space != "" {
		start.Attr = append(start.Attr, Attr{Name{"", xmlnsPrefix}, ""})
	}
	if err := p.writeStart(&start); err != nil {
		return err
	}

	if val.Kind() == reflect.Struct {
		err = p.marshalStruct(tinfo, val)
	} else {
		s, b, err1 := p.marshalSimple(typ, val)
		if err1 != nil {
			err = err1
		} else if b != nil {
			EscapeText(p, b)
		} else {
			p.EscapeString(s)
		}
	}
	if err != nil {
		return err
	}
	if err := p.writeEnd(start.Name); err != nil {
		return err
	}
	return p.cachedWriteError()
}

func (p *printer) marshalAttr(start *StartElement, name Name, val reflect.Value) error {
	if val.CanInterface() {
		if marshaler, ok := reflect.TypeAssert[MarshalerAttr](val); ok {
			attr, err := marshaler.MarshalXMLAttr(name)
			if err != nil {
				return err
			}
			if attr.Name.Local != "" {
				start.Attr = append(start.Attr, attr)
			}
			return nil
		}
	}
	if val.CanAddr() {
		pv := val.Addr()
		if pv.CanInterface() {
			if marshaler, ok := reflect.TypeAssert[MarshalerAttr](pv); ok {
				attr, err := marshaler.MarshalXMLAttr(name)
				if err != nil {
					return err
				}
				if attr.Name.Local != "" {
					start.Attr = append(start.Attr, attr)
				}
				return nil
			}
		}
	}
	if val.CanInterface() {
		if tm, ok := reflect.TypeAssert[encoding.TextMarshaler](val); ok {
			text, err := tm.MarshalText()
			if err != nil {
				return err
			}
			start.Attr = append(start.Attr, Attr{name, string(text)})
			return nil
		}
	}
	if val.CanAddr() {
		pv := val.Addr()
		if pv.CanInterface() {
			if tm, ok := reflect.TypeAssert[encoding.TextMarshaler](pv); ok {
				text, err := tm.MarshalText()
				if err != nil {
					return err
				}
				start.Attr = append(start.Attr, Attr{name, string(text)})
				return nil
			}
		}
	}

	switch val.Kind() {
	case reflect.Pointer, reflect.Interface:
		if val.IsNil() {
			return nil
		}
		val = val.Elem()
	}
	if val.Kind() == reflect.Slice && val.Type().Elem().Kind() != reflect.Uint8 {
		n := val.Len()
		for i := 0; i < n; i++ {
			if err := p.marshalAttr(start, name, val.Index(i)); err != nil {
				return err
			}
		}
		return nil
	}
	if val.Type() == attrType {
		attr, _ := reflect.TypeAssert[Attr](val)
		start.Attr = append(start.Attr, attr)
		return nil
	}
	s, b, err := p.marshalSimple(val.Type(), val)
	if err != nil {
		return err
	}
	if b != nil {
		s = string(b)
	}
	start.Attr = append(start.Attr, Attr{name, s})
	return nil
}

func defaultStart(typ reflect.Type, finfo *fieldInfo, startTemplate *StartElement) StartElement {
	var start StartElement
	if startTemplate != nil {
		start.Name = startTemplate.Name
		start.Attr = append(start.Attr, startTemplate.Attr...)
	} else if finfo != nil && finfo.name != "" {
		start.Name.Local = finfo.name
		start.Name.Space = finfo.xmlns
	} else if typ.Name() != "" {
		start.Name.Local = typ.Name()
	} else {
		start.Name.Local = typ.Elem().Name()
	}
	return start
}

func (p *printer) marshalInterface(val Marshaler, start StartElement) error {
	p.tags = append(p.tags, Name{})
	n := len(p.tags)
	if err := val.MarshalXML(p.encoder, start); err != nil {
		return err
	}
	if len(p.tags) > n {
		return errs.Detail(ErrTypeMismatch, "xml: %s.MarshalXML wrote invalid XML: <%s> not closed",
			receiverType(val), p.tags[len(p.tags)-1].Local)
	}
	p.tags = p.tags[:n-1]
	return nil
}

func (p *printer) marshalTextInterface(val encoding.TextMarshaler, start StartElement) error {
	if err := p.writeStart(&start); err != nil {
		return err
	}
	text, err := val.MarshalText()
	if err != nil {
		return err
	}
	EscapeText(p, text)
	return p.writeEnd(start.Name)
}

func (p *printer) marshalSimple(typ reflect.Type, val reflect.Value) (string, []byte, error) {
	switch val.Kind() {
	case reflect.Int, reflect.Int8, reflect.Int16, reflect.Int32, reflect.Int64:
		return strconv.FormatInt(val.Int(), 10), nil, nil
	case reflect.Uint, reflect.Uint8, reflect.Uint16, reflect.Uint32, reflect.Uint64, reflect.Uintptr:
		return strconv.FormatUint(val.Uint(), 10), nil, nil
	case reflect.Float32, reflect.Float64:
		return strconv.FormatFloat(val.Float(), 'g', -1, val.Type().Bits()), nil, nil
	case reflect.String:
		return val.String(), nil, nil
	case reflect.Bool:
		return strconv.FormatBool(val.Bool()), nil, nil
	case reflect.Array:
		if typ.Elem().Kind() != reflect.Uint8 {
			break
		}
		var bytes []byte
		if val.CanAddr() {
			bytes = val.Bytes()
		} else {
			bytes = make([]byte, val.Len())
			reflect.Copy(reflect.ValueOf(bytes), val)
		}
		return "", bytes, nil
	case reflect.Slice:
		if typ.Elem().Kind() != reflect.Uint8 {
			break
		}
		return "", val.Bytes(), nil
	}
	return "", nil, &UnsupportedTypeError{typ}
}

func indirect(vf reflect.Value) reflect.Value {
	for vf.Kind() == reflect.Interface || vf.Kind() == reflect.Pointer {
		if vf.IsNil() {
			return vf
		}
		vf = vf.Elem()
	}
	return vf
}

func (p *printer) marshalStruct(tinfo *typeInfo, val reflect.Value) error {
	s := parentStack{p: p}
	for i := range tinfo.fields {
		finfo := &tinfo.fields[i]
		if finfo.flags&fAttr != 0 {
			continue
		}
		vf := finfo.value(val, dontInitNilPointers)
		if !vf.IsValid() {
			continue
		}

		switch finfo.flags & fMode {
		case fCDATA, fCharData:
			emit := EscapeText
			if finfo.flags&fMode == fCDATA {
				emit = emitCDATA
			}
			if err := s.trim(finfo.parents); err != nil {
				return err
			}
			if vf.CanInterface() {
				if tm, ok := reflect.TypeAssert[encoding.TextMarshaler](vf); ok {
					data, err := tm.MarshalText()
					if err != nil {
						return err
					}
					if err := emit(p, data); err != nil {
						return err
					}
					continue
				}
			}
			if vf.CanAddr() {
				pv := vf.Addr()
				if pv.CanInterface() {
					if tm, ok := reflect.TypeAssert[encoding.TextMarshaler](pv); ok {
						data, err := tm.MarshalText()
						if err != nil {
							return err
						}
						if err := emit(p, data); err != nil {
							return err
						}
						continue
					}
				}
			}

			var scratch [64]byte
			vf = indirect(vf)
			switch vf.Kind() {
			case reflect.Int, reflect.Int8, reflect.Int16, reflect.Int32, reflect.Int64:
				if err := emit(p, strconv.AppendInt(scratch[:0], vf.Int(), 10)); err != nil {
					return err
				}
			case reflect.Uint, reflect.Uint8, reflect.Uint16, reflect.Uint32, reflect.Uint64, reflect.Uintptr:
				if err := emit(p, strconv.AppendUint(scratch[:0], vf.Uint(), 10)); err != nil {
					return err
				}
			case reflect.Float32, reflect.Float64:
				if err := emit(p, strconv.AppendFloat(scratch[:0], vf.Float(), 'g', -1, vf.Type().Bits())); err != nil {
					return err
				}
			case reflect.Bool:
				if err := emit(p, strconv.AppendBool(scratch[:0], vf.Bool())); err != nil {
					return err
				}
			case reflect.String:
				if err := emit(p, []byte(vf.String())); err != nil {
					return err
				}
			case reflect.Slice:
				if elem, ok := reflect.TypeAssert[[]byte](vf); ok {
					if err := emit(p, elem); err != nil {
						return err
					}
				}
			}
			continue

		case fComment:
			if err := s.trim(finfo.parents); err != nil {
				return err
			}
			vf = indirect(vf)
			k := vf.Kind()
			if !(k == reflect.String || k == reflect.Slice && vf.Type().Elem().Kind() == reflect.Uint8) {
				return errs.Detail(ErrTypeMismatch, "xml: bad type for comment field of %s", val.Type())
			}
			if vf.Len() == 0 {
				continue
			}
			p.writeIndent(0)
			p.WriteString("<!--")
			dashDash := false
			dashLast := false
			switch k {
			case reflect.String:
				s := vf.String()
				dashDash = strings.Contains(s, "--")
				dashLast = s[len(s)-1] == '-'
				if !dashDash {
					p.WriteString(s)
				}
			case reflect.Slice:
				b := vf.Bytes()
				dashDash = bytes.Contains(b, ddBytes)
				dashLast = b[len(b)-1] == '-'
				if !dashDash {
					p.Write(b)
				}
			}
			if dashDash {
				return errs.Detail(ErrTypeMismatch, `xml: comments must not contain "--"`)
			}
			if dashLast {
				p.WriteByte(' ')
			}
			p.WriteString("-->")
			continue

		case fInnerXML:
			vf = indirect(vf)
			iface := vf.Interface()
			switch raw := iface.(type) {
			case []byte:
				p.Write(raw)
				continue
			case string:
				p.WriteString(raw)
				continue
			}

		case fElement, fElement | fAny:
			if err := s.trim(finfo.parents); err != nil {
				return err
			}
			if len(finfo.parents) > len(s.stack) {
				if vf.Kind() != reflect.Pointer && vf.Kind() != reflect.Interface || !vf.IsNil() {
					if err := s.push(finfo.parents[len(s.stack):]); err != nil {
						return err
					}
				}
			}
		}
		if err := p.marshalValue(vf, finfo, nil); err != nil {
			return err
		}
	}
	_ = s.trim(nil)
	return p.cachedWriteError()
}

type parentStack struct {
	p     *printer
	stack []string
}

func (s *parentStack) trim(parents []string) error {
	split := 0
	for ; split < len(parents) && split < len(s.stack); split++ {
		if parents[split] != s.stack[split] {
			break
		}
	}
	for i := len(s.stack) - 1; i >= split; i-- {
		if err := s.p.writeEnd(Name{Local: s.stack[i]}); err != nil {
			return err
		}
	}
	s.stack = s.stack[:split]
	return nil
}

func (s *parentStack) push(parents []string) error {
	for i := 0; i < len(parents); i++ {
		if err := s.p.writeStart(&StartElement{Name: Name{Local: parents[i]}}); err != nil {
			return err
		}
	}
	s.stack = append(s.stack, parents...)
	return nil
}

func isEmptyValue(v reflect.Value) bool {
	switch v.Kind() {
	case reflect.Array, reflect.Map, reflect.Slice, reflect.String:
		return v.Len() == 0
	case reflect.Bool,
		reflect.Int, reflect.Int8, reflect.Int16, reflect.Int32, reflect.Int64,
		reflect.Uint, reflect.Uint8, reflect.Uint16, reflect.Uint32, reflect.Uint64, reflect.Uintptr,
		reflect.Float32, reflect.Float64,
		reflect.Interface, reflect.Pointer:
		return v.IsZero()
	}
	return false
}
