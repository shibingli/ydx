package xml

import (
	"fmt"
	"reflect"
)

// A SyntaxError represents a syntax error in the XML input stream. | SyntaxError 表示 XML 输入
// 流中的语法错误。
type SyntaxError struct {
	Msg  string
	Line int
}

// Error returns the error message with its line number, matching encoding/xml. | Error 返回带行号
// 的错误消息，与 encoding/xml 一致。
func (e *SyntaxError) Error() string {
	return fmt.Sprintf("XML syntax error on line %d: %s", e.Line, e.Msg)
}

// A TagPathError represents an error in the unmarshaling process caused by the use of field
// tags with conflicting paths. | TagPathError 表示反序列化过程中字段标签路径冲突导致的错误。
type TagPathError struct {
	Struct       reflect.Type
	Field1, Tag1 string
	Field2, Tag2 string
}

// Error returns the conflicting field description, matching encoding/xml. | Error 返回冲突字段
// 描述，与 encoding/xml 一致。
func (e *TagPathError) Error() string {
	return fmt.Sprintf("%s field %q with tag %q conflicts with field %q with tag %q",
		e.Struct, e.Field1, e.Tag1, e.Field2, e.Tag2)
}

// An UnsupportedTypeError is returned by Marshal when attempting to encode an unsupported value
// type. | UnsupportedTypeError 在 Marshal 尝试编码不支持的值类型时返回。
type UnsupportedTypeError struct {
	Type reflect.Type
}

// Error returns the unsupported type description, matching encoding/xml. | Error 返回不支持类型
// 的描述，与 encoding/xml 一致。
func (e *UnsupportedTypeError) Error() string {
	return "xml: unsupported type: " + e.Type.String()
}

// An UnmarshalError represents an error in the unmarshaling process. | UnmarshalError 表示反序列化
// 过程中的错误。
type UnmarshalError string

// Error returns the error text. | Error 返回错误文本。
func (e UnmarshalError) Error() string { return string(e) }
