package xml

import (
	"encoding"
	"reflect"
	"strconv"
	"strings"

	"github.com/shibingli/ydx/errs"
)

// Unmarshal parses the XML-encoded data and stores the result in the value pointed to by v, which
// must be an arbitrary struct, slice or string. It mirrors encoding/xml.Unmarshal. | Unmarshal 解析
// XML 数据并把结果存入 v 指向的值；v 必须是任意结构体、切片或字符串，行为与
// encoding/xml.Unmarshal 一致。
func Unmarshal(data []byte, v any) error {
	return NewDecoderBytes(data).Decode(v)
}

const maxUnmarshalDepth = 10000

// receiverType returns the receiver type to use in an expression like "%s.MethodName". |
// receiverType 返回类似 "%s.MethodName" 表达式中使用的接收者类型。
func receiverType(val any) string {
	t := reflect.TypeOf(val)
	if t.Name() != "" {
		return t.String()
	}
	return "(" + t.String() + ")"
}

func (d *Decoder) unmarshalInterface(val Unmarshaler, start *StartElement) error {
	want := d.filter.depth - 1
	saved := d.inUnmarshalXML
	d.inUnmarshalXML = true
	err := val.UnmarshalXML(d, *start)
	d.inUnmarshalXML = saved
	if err != nil {
		return err
	}
	if d.filter.depth != want {
		return errs.Detail(ErrTypeMismatch, "%s.UnmarshalXML did not consume entire <%s> element",
			receiverType(val), start.Name.Local)
	}
	return nil
}

func (d *Decoder) unmarshalTextInterface(val encoding.TextUnmarshaler) error {
	var buf []byte
	depth := 1
	for depth > 0 {
		t, err := d.Token()
		if err != nil {
			return err
		}
		switch t := t.(type) {
		case CharData:
			if depth == 1 {
				buf = append(buf, t...)
			}
		case StartElement:
			depth++
		case EndElement:
			depth--
		}
	}
	return val.UnmarshalText(buf)
}

func (d *Decoder) unmarshalAttr(val reflect.Value, attr Attr) error {
	if val.Kind() == reflect.Pointer {
		if val.IsNil() {
			val.Set(reflect.New(val.Type().Elem()))
		}
		val = val.Elem()
	}
	if val.CanInterface() {
		if unmarshaler, ok := reflect.TypeAssert[UnmarshalerAttr](val); ok {
			return unmarshaler.UnmarshalXMLAttr(attr)
		}
	}
	if val.CanAddr() {
		pv := val.Addr()
		if pv.CanInterface() {
			if unmarshaler, ok := reflect.TypeAssert[UnmarshalerAttr](pv); ok {
				return unmarshaler.UnmarshalXMLAttr(attr)
			}
		}
	}
	if val.CanInterface() {
		if tu, ok := reflect.TypeAssert[encoding.TextUnmarshaler](val); ok {
			return tu.UnmarshalText([]byte(attr.Value))
		}
	}
	if val.CanAddr() {
		pv := val.Addr()
		if pv.CanInterface() {
			if tu, ok := reflect.TypeAssert[encoding.TextUnmarshaler](pv); ok {
				return tu.UnmarshalText([]byte(attr.Value))
			}
		}
	}

	if val.Kind() == reflect.Slice && val.Type().Elem().Kind() != reflect.Uint8 {
		n := val.Len()
		val.Grow(1)
		val.SetLen(n + 1)
		if err := d.unmarshalAttr(val.Index(n), attr); err != nil {
			val.SetLen(n)
			return err
		}
		return nil
	}

	if val.Type() == attrType {
		val.Set(reflect.ValueOf(attr))
		return nil
	}
	return copyValue(val, []byte(attr.Value))
}

// unmarshal a single XML element into val. | unmarshal 把单个 XML 元素解码到 val。
func (d *Decoder) unmarshal(val reflect.Value, start *StartElement) error {
	if d.filter.depth > maxUnmarshalDepth {
		return errs.Detail(ErrLimit, "exceeded max depth | 超过最大深度")
	}
	if start == nil {
		for {
			tok, err := d.Token()
			if err != nil {
				return err
			}
			if t, ok := tok.(StartElement); ok {
				start = &t
				break
			}
		}
	}

	if val.Kind() == reflect.Interface && !val.IsNil() {
		e := val.Elem()
		if e.Kind() == reflect.Pointer && !e.IsNil() {
			val = e
		}
	}

	if val.Kind() == reflect.Pointer {
		if val.IsNil() {
			val.Set(reflect.New(val.Type().Elem()))
		}
		val = val.Elem()
	}

	if val.CanInterface() {
		if unmarshaler, ok := reflect.TypeAssert[Unmarshaler](val); ok {
			return d.unmarshalInterface(unmarshaler, start)
		}
	}
	if val.CanAddr() {
		pv := val.Addr()
		if pv.CanInterface() {
			if unmarshaler, ok := reflect.TypeAssert[Unmarshaler](pv); ok {
				return d.unmarshalInterface(unmarshaler, start)
			}
		}
	}
	if val.CanInterface() {
		if tu, ok := reflect.TypeAssert[encoding.TextUnmarshaler](val); ok {
			return d.unmarshalTextInterface(tu)
		}
	}
	if val.CanAddr() {
		pv := val.Addr()
		if pv.CanInterface() {
			if tu, ok := reflect.TypeAssert[encoding.TextUnmarshaler](pv); ok {
				return d.unmarshalTextInterface(tu)
			}
		}
	}

	var (
		data        []byte
		saveData    reflect.Value
		comment     []byte
		saveComment reflect.Value
		saveXML     reflect.Value
		saveXMLMark captureMark
		saveXMLData []byte
		saveAny     reflect.Value
		sv          reflect.Value
		tinfo       *typeInfo
		err         error
	)

	switch v := val; v.Kind() {
	default:
		return errs.Detail(ErrTypeMismatch, "unknown type %s", v.Type())

	case reflect.Interface:
		return d.Skip()

	case reflect.Slice:
		typ := v.Type()
		if typ.Elem().Kind() == reflect.Uint8 {
			saveData = v
			break
		}
		n := v.Len()
		v.Grow(1)
		v.SetLen(n + 1)
		if err := d.unmarshal(v.Index(n), start); err != nil {
			v.SetLen(n)
			return err
		}
		return nil

	case reflect.Bool, reflect.Float32, reflect.Float64, reflect.Int, reflect.Int8, reflect.Int16,
		reflect.Int32, reflect.Int64, reflect.Uint, reflect.Uint8, reflect.Uint16, reflect.Uint32,
		reflect.Uint64, reflect.Uintptr, reflect.String:
		saveData = v

	case reflect.Struct:
		typ := v.Type()
		if typ == nameType {
			v.Set(reflect.ValueOf(start.Name))
			break
		}
		sv = v
		tinfo, err = getTypeInfo(typ)
		if err != nil {
			return err
		}

		if tinfo.xmlname != nil {
			finfo := tinfo.xmlname
			if finfo.name != "" && finfo.name != start.Name.Local {
				return UnmarshalError("expected element type <" + finfo.name + "> but have <" + start.Name.Local + ">")
			}
			if finfo.xmlns != "" && finfo.xmlns != start.Name.Space {
				e := "expected element <" + finfo.name + "> in name space " + finfo.xmlns + " but have "
				if start.Name.Space == "" {
					e += "no name space"
				} else {
					e += start.Name.Space
				}
				return UnmarshalError(e)
			}
			fv := finfo.value(sv, initNilPointers)
			if _, ok := reflect.TypeAssert[Name](fv); ok {
				fv.Set(reflect.ValueOf(start.Name))
			}
		}

		for _, a := range start.Attr {
			handled := false
			any := -1
			for i := range tinfo.fields {
				finfo := &tinfo.fields[i]
				switch finfo.flags & fMode {
				case fAttr:
					strv := finfo.value(sv, initNilPointers)
					if a.Name.Local == finfo.name && (finfo.xmlns == "" || finfo.xmlns == a.Name.Space) {
						if err := d.unmarshalAttr(strv, a); err != nil {
							return err
						}
						handled = true
					}
				case fAny | fAttr:
					if any == -1 {
						any = i
					}
				}
			}
			if !handled && any >= 0 {
				finfo := &tinfo.fields[any]
				strv := finfo.value(sv, initNilPointers)
				if err := d.unmarshalAttr(strv, a); err != nil {
					return err
				}
			}
		}

		for i := range tinfo.fields {
			finfo := &tinfo.fields[i]
			switch finfo.flags & fMode {
			case fCDATA, fCharData:
				if !saveData.IsValid() {
					saveData = finfo.value(sv, initNilPointers)
				}
			case fComment:
				if !saveComment.IsValid() {
					saveComment = finfo.value(sv, initNilPointers)
				}
			case fAny, fAny | fElement:
				if !saveAny.IsValid() {
					saveAny = finfo.value(sv, initNilPointers)
				}
			case fInnerXML:
				if !saveXML.IsValid() {
					saveXML = finfo.value(sv, initNilPointers)
					saveXMLMark = d.beginInnerCapture()
				}
			}
		}
	}

Loop:
	for {
		tok, err := d.Token()
		if err != nil {
			return err
		}
		switch t := tok.(type) {
		case StartElement:
			consumed := false
			if sv.IsValid() {
				consumed, err = d.unmarshalPath(tinfo, sv, nil, &t)
				if err != nil {
					return err
				}
				if !consumed && saveAny.IsValid() {
					consumed = true
					if err := d.unmarshal(saveAny, &t); err != nil {
						return err
					}
				}
			}
			if !consumed {
				if err := d.Skip(); err != nil {
					return err
				}
			}

		case EndElement:
			if saveXML.IsValid() {
				saveXMLData = d.endInnerCapture(saveXMLMark, d.tokenStartOffset())
			}
			break Loop

		case CharData:
			if saveData.IsValid() {
				data = append(data, t...)
			}

		case Comment:
			if saveComment.IsValid() {
				comment = append(comment, t...)
			}
		}
	}

	if saveData.IsValid() && saveData.CanInterface() {
		if tu, ok := reflect.TypeAssert[encoding.TextUnmarshaler](saveData); ok {
			if err := tu.UnmarshalText(data); err != nil {
				return err
			}
			saveData = reflect.Value{}
		}
	}
	if saveData.IsValid() && saveData.CanAddr() {
		pv := saveData.Addr()
		if pv.CanInterface() {
			if tu, ok := reflect.TypeAssert[encoding.TextUnmarshaler](pv); ok {
				if err := tu.UnmarshalText(data); err != nil {
					return err
				}
				saveData = reflect.Value{}
			}
		}
	}
	if err := copyValue(saveData, data); err != nil {
		return err
	}

	switch t := saveComment; t.Kind() {
	case reflect.String:
		t.SetString(string(comment))
	case reflect.Slice:
		t.Set(reflect.ValueOf(comment))
	}

	switch t := saveXML; t.Kind() {
	case reflect.String:
		t.SetString(string(saveXMLData))
	case reflect.Slice:
		if t.Type().Elem().Kind() == reflect.Uint8 {
			t.Set(reflect.ValueOf(saveXMLData))
		}
	}
	return nil
}

func copyValue(dst reflect.Value, src []byte) (err error) {
	dst0 := dst
	if dst.Kind() == reflect.Pointer {
		if dst.IsNil() {
			dst.Set(reflect.New(dst.Type().Elem()))
		}
		dst = dst.Elem()
	}

	switch dst.Kind() {
	case reflect.Invalid:
	case reflect.Int, reflect.Int8, reflect.Int16, reflect.Int32, reflect.Int64:
		if len(src) == 0 {
			dst.SetInt(0)
			return nil
		}
		itmp, err := strconv.ParseInt(strings.TrimSpace(string(src)), 10, dst.Type().Bits())
		if err != nil {
			return errs.Wrap(err, ErrTypeMismatch)
		}
		dst.SetInt(itmp)
	case reflect.Uint, reflect.Uint8, reflect.Uint16, reflect.Uint32, reflect.Uint64, reflect.Uintptr:
		if len(src) == 0 {
			dst.SetUint(0)
			return nil
		}
		utmp, err := strconv.ParseUint(strings.TrimSpace(string(src)), 10, dst.Type().Bits())
		if err != nil {
			return errs.Wrap(err, ErrTypeMismatch)
		}
		dst.SetUint(utmp)
	case reflect.Float32, reflect.Float64:
		if len(src) == 0 {
			dst.SetFloat(0)
			return nil
		}
		ftmp, err := strconv.ParseFloat(strings.TrimSpace(string(src)), dst.Type().Bits())
		if err != nil {
			return errs.Wrap(err, ErrTypeMismatch)
		}
		dst.SetFloat(ftmp)
	case reflect.Bool:
		if len(src) == 0 {
			dst.SetBool(false)
			return nil
		}
		value, err := strconv.ParseBool(strings.TrimSpace(string(src)))
		if err != nil {
			return errs.Wrap(err, ErrTypeMismatch)
		}
		dst.SetBool(value)
	case reflect.String:
		dst.SetString(string(src))
	case reflect.Slice:
		if len(src) == 0 {
			src = []byte{}
		}
		dst.SetBytes(src)
	default:
		return errs.Detail(ErrTypeMismatch, "cannot unmarshal into %s", dst0.Type())
	}
	return nil
}

// unmarshalPath walks down an XML structure looking for wanted paths. | unmarshalPath 沿 XML 结构
// 向下查找目标路径。
func (d *Decoder) unmarshalPath(tinfo *typeInfo, sv reflect.Value, parents []string, start *StartElement) (consumed bool, err error) {
	recurse := false
Loop:
	for i := range tinfo.fields {
		finfo := &tinfo.fields[i]
		if finfo.flags&fElement == 0 || len(finfo.parents) < len(parents) || finfo.xmlns != "" && finfo.xmlns != start.Name.Space {
			continue
		}
		for j := range parents {
			if parents[j] != finfo.parents[j] {
				continue Loop
			}
		}
		if len(finfo.parents) == len(parents) && finfo.name == start.Name.Local {
			return true, d.unmarshal(finfo.value(sv, initNilPointers), start)
		}
		if len(finfo.parents) > len(parents) && finfo.parents[len(parents)] == start.Name.Local {
			recurse = true
			parents = finfo.parents[:len(parents)+1]
			break
		}
	}
	if !recurse {
		return false, nil
	}
	for {
		var tok Token
		tok, err = d.Token()
		if err != nil {
			return true, err
		}
		switch t := tok.(type) {
		case StartElement:
			consumed2, err := d.unmarshalPath(tinfo, sv, parents, &t)
			if err != nil {
				return true, err
			}
			if !consumed2 {
				if err := d.Skip(); err != nil {
					return true, err
				}
			}
		case EndElement:
			return true, nil
		}
	}
}

// Prewarm compiles and installs decoding plans for the given samples, moving plan construction out
// of the first request. Pass a value or pointer to warm its type; typed nil pointers are accepted.
// Prewarm is idempotent and safe to call concurrently. | Prewarm 为给定样本编译并安装解码计划，把
// 计划构建成本移出首个请求；可传值或指针，类型化 nil 指针亦可。Prewarm 幂等且可并发调用。
func Prewarm(samples ...any) {
	seen := make(map[reflect.Type]bool)
	for _, s := range samples {
		warmType(reflect.TypeOf(s), seen)
	}
}

func warmType(t reflect.Type, seen map[reflect.Type]bool) {
	if t == nil {
		return
	}
	for t.Kind() == reflect.Pointer {
		t = t.Elem()
	}
	if seen[t] {
		return
	}
	seen[t] = true
	switch t.Kind() {
	case reflect.Struct:
		if t == nameType {
			return
		}
		ti, err := getTypeInfo(t)
		if err != nil {
			return
		}
		for _, f := range ti.fields {
			warmType(t.FieldByIndex(f.idx).Type, seen)
		}
	case reflect.Slice, reflect.Array:
		warmType(t.Elem(), seen)
	case reflect.Map:
		warmType(t.Key(), seen)
		warmType(t.Elem(), seen)
	}
}
