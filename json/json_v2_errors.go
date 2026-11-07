//go:build !jsonx_std

package json

import (
	stdjsonv2 "encoding/json/v2"
	"errors"
	"reflect"
	"unsafe"

	"encoding/json/jsontext"
)

// semanticErrorMirror mirrors the leading fields of json.SemanticError so the unexported action
// field, which selects the error wording, can be set. The exported fields are copied through the
// real type; only the action string needs this view. | semanticErrorMirror 镜像
// json.SemanticError 的前导字段，用于设置决定文案的未导出 action。导出字段仍通过真实类型写入，
// 只有 action 需要这个视图。
type semanticErrorMirror struct {
	GoType      reflect.Type
	Err         error
	action      string
	JSONPointer jsontext.Pointer
	JSONValue   jsontext.Value
	ByteOffset  int64
	JSONKind    jsontext.Kind
}

// setSemanticAction sets the unexported action field of a SemanticError. |
// setSemanticAction 设置 SemanticError 的未导出 action 字段。
func setSemanticAction(se *stdjsonv2.SemanticError, action string) {
	(*semanticErrorMirror)(unsafe.Pointer(se)).action = action
}

// newMarshalSemanticError builds a v2 marshal error of the standard library's type. |
// newMarshalSemanticError 构造标准库类型的 v2 编码错误。
func newMarshalSemanticError(t reflect.Type, msg string) error {
	se := &stdjsonv2.SemanticError{GoType: t}
	if msg != "" {
		se.Err = errors.New(msg)
	}
	setSemanticAction(se, "marshal")
	return se
}

// newUnmarshalSemanticError builds a v2 unmarshal error of the standard library's type. |
// newUnmarshalSemanticError 构造标准库类型的 v2 解码错误。
func newUnmarshalSemanticError(t reflect.Type, kind jsontext.Kind, value jsontext.Value, msg string) error {
	se := &stdjsonv2.SemanticError{GoType: t, JSONKind: kind, JSONValue: value}
	if msg != "" {
		se.Err = errors.New(msg)
	}
	setSemanticAction(se, "unmarshal")
	return se
}

// newMarshalInvalidUTF8Error builds the standard v2 error for invalid UTF-8 during encoding. |
// newMarshalInvalidUTF8Error 构造编码期间非法 UTF-8 的标准 v2 错误。
func newMarshalInvalidUTF8Error() error {
	return &jsontext.SyntacticError{Err: errors.New("invalid UTF-8")}
}

// newDuplicateNameError builds the standard library's duplicate member error. |
// newDuplicateNameError 构造标准库的重复成员错误。
func newDuplicateNameError(offset int64, pointer jsontext.Pointer) error {
	return &jsontext.SyntacticError{ByteOffset: offset, JSONPointer: pointer, Err: jsontext.ErrDuplicateName}
}
