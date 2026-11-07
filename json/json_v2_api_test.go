package json_test

import (
	"encoding/json/jsontext"
	stdjsonv2 "encoding/json/v2"
	"io"
	"testing"

	jsonx "github.com/shibingli/ydx/json"
)

// The compile-time assignments below pin the exported v2 API surface to the exact signatures of
// encoding/json/v2. A signature drift fails the build instead of surfacing at a call site. |
// 以下编译期赋值把导出的 v2 API 面钉死为 encoding/json/v2 的确切签名；签名漂移会在编译期失败，
// 而不是在调用点才暴露。
var (
	_ func(in any, opts ...jsonx.Options) ([]byte, error)   = jsonx.Marshal
	_ func(in []byte, out any, opts ...jsonx.Options) error = jsonx.Unmarshal

	_ func(out io.Writer, in any, opts ...jsonx.Options) error         = jsonx.MarshalWrite
	_ func(in io.Reader, out any, opts ...jsonx.Options) error         = jsonx.UnmarshalRead
	_ func(out *jsontext.Encoder, in any, opts ...jsonx.Options) error = jsonx.MarshalEncode
	_ func(in *jsontext.Decoder, out any, opts ...jsonx.Options) error = jsonx.UnmarshalDecode

	_ func() jsonx.Options                    = jsonx.DefaultOptionsV2
	_ func(bool) jsonx.Options                = jsonx.Deterministic
	_ func(bool) jsonx.Options                = jsonx.FormatNilMapAsNull
	_ func(bool) jsonx.Options                = jsonx.FormatNilSliceAsNull
	_ func(...jsonx.Options) jsonx.Options    = jsonx.JoinOptions
	_ func(bool) jsonx.Options                = jsonx.MatchCaseInsensitiveNames
	_ func(bool) jsonx.Options                = jsonx.OmitZeroStructFields
	_ func(bool) jsonx.Options                = jsonx.RejectUnknownMembers
	_ func(bool) jsonx.Options                = jsonx.StringifyNumbers
	_ func(*jsonx.Marshalers) jsonx.Options   = jsonx.WithMarshalers
	_ func(*jsonx.Unmarshalers) jsonx.Options = jsonx.WithUnmarshalers

	_ func(jsonx.Options, func(bool) jsonx.Options) (bool, bool) = jsonx.GetOption[bool]

	_ func(...*jsonx.Marshalers) *jsonx.Marshalers                 = jsonx.JoinMarshalers
	_ func(...*jsonx.Unmarshalers) *jsonx.Unmarshalers             = jsonx.JoinUnmarshalers
	_ func(func(int) ([]byte, error)) *jsonx.Marshalers            = jsonx.MarshalFunc[int]
	_ func(func(*jsontext.Encoder, int) error) *jsonx.Marshalers   = jsonx.MarshalToFunc[int]
	_ func(func([]byte, int) error) *jsonx.Unmarshalers            = jsonx.UnmarshalFunc[int]
	_ func(func(*jsontext.Decoder, int) error) *jsonx.Unmarshalers = jsonx.UnmarshalFromFunc[int]

	_ error = jsonx.ErrUnknownName
)

// TestV2ErrorValuesAreShared verifies the exported v2 error and type aliases are the standard
// library's, so errors.As / errors.Is interoperate with encoding/json/v2. |
// TestV2ErrorValuesAreShared 验证导出的 v2 错误与类型别名就是标准库的类型，使 errors.As /
// errors.Is 能与 encoding/json/v2 互操作。
func TestV2ErrorValuesAreShared(t *testing.T) {
	if jsonx.ErrUnknownName != stdjsonv2.ErrUnknownName {
		t.Fatalf("ErrUnknownName is not the standard library value | ErrUnknownName 不是标准库的值")
	}
	var serr *stdjsonv2.SemanticError
	if _, ok := any(serr).(*jsonx.SemanticError); !ok {
		t.Fatalf("SemanticError alias does not match encoding/json/v2 | SemanticError 别名与 encoding/json/v2 不一致")
	}
}
