package xml

import (
	"reflect"
	"strings"
	"sync"

	"github.com/shibingli/ydx/errs"
)

// typeInfo holds details for the XML representation of a type. | typeInfo 保存类型的 XML 表示细节。
type typeInfo struct {
	xmlname *fieldInfo
	fields  []fieldInfo
}

// fieldInfo holds details for the XML representation of a single field. | fieldInfo 保存单个字段的
// XML 表示细节。
type fieldInfo struct {
	name    string
	xmlns   string
	idx     []int
	parents []string
	flags   fieldFlags
}

type fieldFlags int

const (
	fElement fieldFlags = 1 << iota
	fAttr
	fCDATA
	fCharData
	fInnerXML
	fComment
	fAny

	fOmitEmpty

	fMode = fElement | fAttr | fCDATA | fCharData | fInnerXML | fComment | fAny

	xmlName = "XMLName"
)

var tinfoMap sync.Map // map[reflect.Type]*typeInfo

var nameType = reflect.TypeFor[Name]()
var attrType = reflect.TypeFor[Attr]()

// getTypeInfo returns the typeInfo structure with details necessary for marshaling and
// unmarshaling typ. | getTypeInfo 返回编组与解组 typ 所需的类型信息。
func getTypeInfo(typ reflect.Type) (*typeInfo, error) {
	if ti, ok := tinfoMap.Load(typ); ok {
		return ti.(*typeInfo), nil
	}

	tinfo := &typeInfo{}
	if typ.Kind() == reflect.Struct && typ != nameType {
		n := typ.NumField()
		for i := 0; i < n; i++ {
			f := typ.Field(i)
			if (!f.IsExported() && !f.Anonymous) || f.Tag.Get("xml") == "-" {
				continue
			}
			if f.Anonymous {
				t := f.Type
				if t.Kind() == reflect.Pointer {
					t = t.Elem()
				}
				if t.Kind() == reflect.Struct {
					inner, err := getTypeInfo(t)
					if err != nil {
						return nil, err
					}
					if tinfo.xmlname == nil {
						tinfo.xmlname = inner.xmlname
					}
					for _, finfo := range inner.fields {
						finfo.idx = append([]int{i}, finfo.idx...)
						if err := addFieldInfo(typ, tinfo, &finfo); err != nil {
							return nil, err
						}
					}
					continue
				}
			}

			finfo, err := structFieldInfo(typ, &f)
			if err != nil {
				return nil, err
			}
			if f.Name == xmlName {
				tinfo.xmlname = finfo
				continue
			}
			if err := addFieldInfo(typ, tinfo, finfo); err != nil {
				return nil, err
			}
		}
	}

	ti, _ := tinfoMap.LoadOrStore(typ, tinfo)
	return ti.(*typeInfo), nil
}

// structFieldInfo builds and returns a fieldInfo for f. | structFieldInfo 构建并返回 f 的 fieldInfo。
func structFieldInfo(typ reflect.Type, f *reflect.StructField) (*fieldInfo, error) {
	finfo := &fieldInfo{idx: f.Index}

	tag := f.Tag.Get("xml")
	if ns, t, ok := strings.Cut(tag, " "); ok {
		finfo.xmlns, tag = ns, t
	}

	tokens := strings.Split(tag, ",")
	if len(tokens) == 1 {
		finfo.flags = fElement
	} else {
		tag = tokens[0]
		for _, flag := range tokens[1:] {
			switch flag {
			case "attr":
				finfo.flags |= fAttr
			case "cdata":
				finfo.flags |= fCDATA
			case "chardata":
				finfo.flags |= fCharData
			case "innerxml":
				finfo.flags |= fInnerXML
			case "comment":
				finfo.flags |= fComment
			case "any":
				finfo.flags |= fAny
			case "omitempty":
				finfo.flags |= fOmitEmpty
			}
		}

		valid := true
		switch mode := finfo.flags & fMode; mode {
		case 0:
			finfo.flags |= fElement
		case fAttr, fCDATA, fCharData, fInnerXML, fComment, fAny, fAny | fAttr:
			if f.Name == xmlName || tag != "" && mode != fAttr {
				valid = false
			}
		default:
			valid = false
		}
		if finfo.flags&fMode == fAny {
			finfo.flags |= fElement
		}
		if finfo.flags&fOmitEmpty != 0 && finfo.flags&(fElement|fAttr) == 0 {
			valid = false
		}
		if !valid {
			return nil, errs.Detail(ErrTypeMismatch, "invalid tag in field %s of type %s: %q", f.Name, typ, f.Tag.Get("xml"))
		}
	}

	if finfo.xmlns != "" && tag == "" {
		return nil, errs.Detail(ErrTypeMismatch, "namespace without name in field %s of type %s: %q", f.Name, typ, f.Tag.Get("xml"))
	}

	if f.Name == xmlName {
		finfo.name = tag
		return finfo, nil
	}

	if tag == "" {
		if xmlname := lookupXMLName(f.Type); xmlname != nil {
			finfo.xmlns, finfo.name = xmlname.xmlns, xmlname.name
		} else {
			finfo.name = f.Name
		}
		return finfo, nil
	}

	parents := strings.Split(tag, ">")
	if parents[0] == "" {
		parents[0] = f.Name
	}
	if parents[len(parents)-1] == "" {
		return nil, errs.Detail(ErrTypeMismatch, "trailing '>' in field %s of type %s", f.Name, typ)
	}
	finfo.name = parents[len(parents)-1]
	if len(parents) > 1 {
		if finfo.flags&fElement == 0 {
			return nil, errs.Detail(ErrTypeMismatch, "%s chain not valid with %s flag", tag, strings.Join(tokens[1:], ","))
		}
		finfo.parents = parents[:len(parents)-1]
	}

	if finfo.flags&fElement != 0 {
		ftyp := f.Type
		xmlname := lookupXMLName(ftyp)
		if xmlname != nil && xmlname.name != finfo.name {
			return nil, errs.Detail(ErrTypeMismatch, "name %q in tag of %s.%s conflicts with name %q in %s.XMLName",
				finfo.name, typ, f.Name, xmlname.name, ftyp)
		}
	}
	return finfo, nil
}

// lookupXMLName returns the fieldInfo for typ's XMLName field in case it exists and has a valid
// xml field tag, otherwise it returns nil. | lookupXMLName 返回 typ 的 XMLName 字段信息（若存在且
// 标签有效），否则返回 nil。
func lookupXMLName(typ reflect.Type) (xmlname *fieldInfo) {
	for typ.Kind() == reflect.Pointer {
		typ = typ.Elem()
	}
	if typ.Kind() != reflect.Struct {
		return nil
	}
	for i, n := 0, typ.NumField(); i < n; i++ {
		f := typ.Field(i)
		if f.Name != xmlName {
			continue
		}
		finfo, err := structFieldInfo(typ, &f)
		if err == nil && finfo.name != "" {
			return finfo
		}
		break
	}
	return nil
}

// addFieldInfo adds finfo to tinfo.fields if there are no conflicts, or if conflicts arise from
// previous fields obtained from deeper embedded structures. | addFieldInfo 在无冲突或冲突来自更深的
// 嵌入字段时把 finfo 加入 tinfo.fields。
func addFieldInfo(typ reflect.Type, tinfo *typeInfo, newf *fieldInfo) error {
	var conflicts []int
Loop:
	for i := range tinfo.fields {
		oldf := &tinfo.fields[i]
		if oldf.flags&fMode != newf.flags&fMode {
			continue
		}
		if oldf.xmlns != "" && newf.xmlns != "" && oldf.xmlns != newf.xmlns {
			continue
		}
		minl := len(newf.parents)
		if len(oldf.parents) < minl {
			minl = len(oldf.parents)
		}
		for p := 0; p < minl; p++ {
			if oldf.parents[p] != newf.parents[p] {
				continue Loop
			}
		}
		if len(oldf.parents) > len(newf.parents) {
			if oldf.parents[len(newf.parents)] == newf.name {
				conflicts = append(conflicts, i)
			}
		} else if len(oldf.parents) < len(newf.parents) {
			if newf.parents[len(oldf.parents)] == oldf.name {
				conflicts = append(conflicts, i)
			}
		} else if newf.name == oldf.name && newf.xmlns == oldf.xmlns {
			conflicts = append(conflicts, i)
		}
	}
	if conflicts == nil {
		tinfo.fields = append(tinfo.fields, *newf)
		return nil
	}
	for _, i := range conflicts {
		if len(tinfo.fields[i].idx) < len(newf.idx) {
			return nil
		}
	}
	for _, i := range conflicts {
		oldf := &tinfo.fields[i]
		if len(oldf.idx) == len(newf.idx) {
			f1 := typ.FieldByIndex(oldf.idx)
			f2 := typ.FieldByIndex(newf.idx)
			return &TagPathError{typ, f1.Name, f1.Tag.Get("xml"), f2.Name, f2.Tag.Get("xml")}
		}
	}
	for c := len(conflicts) - 1; c >= 0; c-- {
		i := conflicts[c]
		copy(tinfo.fields[i:], tinfo.fields[i+1:])
		tinfo.fields = tinfo.fields[:len(tinfo.fields)-1]
	}
	tinfo.fields = append(tinfo.fields, *newf)
	return nil
}

const (
	initNilPointers     = true
	dontInitNilPointers = false
)

// value returns v's field value corresponding to finfo. | value 返回 v 中对应 finfo 的字段值。
func (finfo *fieldInfo) value(v reflect.Value, shouldInitNilPointers bool) reflect.Value {
	for i, x := range finfo.idx {
		if i > 0 {
			t := v.Type()
			if t.Kind() == reflect.Pointer && t.Elem().Kind() == reflect.Struct {
				if v.IsNil() {
					if !shouldInitNilPointers {
						return reflect.Value{}
					}
					v.Set(reflect.New(v.Type().Elem()))
				}
				v = v.Elem()
			}
		}
		v = v.Field(x)
	}
	return v
}
