package json_test

import (
	"bytes"
	"encoding/json/jsontext"
	stdjsonv2 "encoding/json/v2"
	"errors"
	"io"
	"reflect"
	"sort"
	"testing"

	jsonx "github.com/shibingli/ydx/json"
)

// v2CaseIgnoreField uses the v2 case:ignore tag option. | v2CaseIgnoreField 使用 v2 的
// case:ignore 标签选项。
type v2CaseIgnoreField struct {
	Value int `json:"my-value,case:ignore"`
}

// v2CaseStrictField uses the v2 case:strict tag option. | v2CaseStrictField 使用 v2 的
// case:strict 标签选项。
type v2CaseStrictField struct {
	Value int `json:"my-value,case:strict"`
}

// TestV2CaseTag compares the per-field case matching options against encoding/json/v2. |
// TestV2CaseTag 与 encoding/json/v2 对比逐字段大小写匹配选项。
func TestV2CaseTag(t *testing.T) {
	inputs := []string{
		`{"my-value":1}`, `{"MY-VALUE":2}`, `{"my_value":3}`, `{"myvalue":4}`, `{"MyValue":5}`,
	}
	for _, target := range []any{new(v2CaseIgnoreField), new(v2CaseStrictField)} {
		for _, in := range inputs {
			got := reflect.New(reflect.TypeOf(target).Elem()).Interface()
			want := reflect.New(reflect.TypeOf(target).Elem()).Interface()
			gotErr := jsonx.Unmarshal([]byte(in), got, v2Defaults()...)
			wantErr := stdjsonv2.Unmarshal([]byte(in), want, v2Defaults()...)
			if (gotErr == nil) != (wantErr == nil) || !reflect.DeepEqual(got, want) {
				t.Errorf("%s into %T = (%v, %v) want (%v, %v) | 解码不一致", in, target, got, gotErr, want, wantErr)
			}
			gotOut, gotErr := jsonx.Marshal(got, v2Defaults()...)
			wantOut, wantErr := stdjsonv2.Marshal(want, v2Defaults()...)
			if (gotErr == nil) != (wantErr == nil) || !bytes.Equal(gotOut, wantOut) {
				t.Errorf("%T Marshal = (%s, %v) want (%s, %v) | 编码不一致", target, gotOut, gotErr, wantOut, wantErr)
			}
		}
	}
}

// v2EmbedInner is promoted through an explicit embed tag. | v2EmbedInner 通过显式 embed 标签提升。
type v2EmbedInner struct {
	X int    `json:"x"`
	Y string `json:"y,omitempty"`
}

// v2EmbedOuter embeds a named field explicitly. | v2EmbedOuter 显式嵌入一个命名字段。
type v2EmbedOuter struct {
	Inner v2EmbedInner `json:"embed"`
	Z     int          `json:"z"`
}

// v2EmbedMap captures unknown members in a map fallback. | v2EmbedMap 用 map 回退捕获未知成员。
type v2EmbedMap struct {
	A     int            `json:"a"`
	Extra map[string]int `json:",embed"`
}

// v2EmbedValue captures unknown members in a raw value fallback. | v2EmbedValue 用原始值回退捕获
// 未知成员。
type v2EmbedValue struct {
	A     int            `json:"a"`
	Extra jsontext.Value `json:",embed"`
}

// TestV2EmbedFallback compares embedded map and raw-value fallbacks. |
// TestV2EmbedFallback 对比嵌入 map 与原始值回退。
func TestV2EmbedFallback(t *testing.T) {
	m := v2EmbedMap{A: 1, Extra: map[string]int{"x": 2, "y": 3}}
	// The jsonx_std backend delegates v2 marshaling to the standard library, whose default map
	// order is unspecified; Deterministic makes the byte comparison meaningful. | jsonx_std
	// 后端把 v2 编码交给标准库，其默认 map 顺序未指定；Deterministic 使字节比较有意义。
	det := []jsonx.Options{jsonx.DefaultOptionsV2(), jsonx.Deterministic(true)}
	got, gotErr := jsonx.Marshal(m, det...)
	want, wantErr := stdjsonv2.Marshal(m, det...)
	if (gotErr == nil) != (wantErr == nil) || !bytes.Equal(got, want) {
		t.Fatalf("map Marshal = (%s, %v) want (%s, %v) | 编码不一致", got, gotErr, want, wantErr)
	}
	var gotM, wantM v2EmbedMap
	gotErr = jsonx.Unmarshal([]byte(`{"a":1,"x":2,"y":3}`), &gotM, v2Defaults()...)
	wantErr = stdjsonv2.Unmarshal([]byte(`{"a":1,"x":2,"y":3}`), &wantM, v2Defaults()...)
	if (gotErr == nil) != (wantErr == nil) || !reflect.DeepEqual(gotM, wantM) {
		t.Fatalf("map Unmarshal = (%+v, %v) want (%+v, %v) | 解码不一致", gotM, gotErr, wantM, wantErr)
	}

	v := v2EmbedValue{A: 1, Extra: jsontext.Value(`{ "x" : 2, "y" : 3 }`)}
	got, gotErr = jsonx.Marshal(v, v2Defaults()...)
	want, wantErr = stdjsonv2.Marshal(v, v2Defaults()...)
	if (gotErr == nil) != (wantErr == nil) || !bytes.Equal(got, want) {
		t.Fatalf("value Marshal = (%s, %v) want (%s, %v) | 编码不一致", got, gotErr, want, wantErr)
	}
	var gotV, wantV v2EmbedValue
	gotErr = jsonx.Unmarshal([]byte(`{"a":1,"x":2,"y":3}`), &gotV, v2Defaults()...)
	wantErr = stdjsonv2.Unmarshal([]byte(`{"a":1,"x":2,"y":3}`), &wantV, v2Defaults()...)
	if (gotErr == nil) != (wantErr == nil) || !reflect.DeepEqual(gotV, wantV) {
		t.Fatalf("value Unmarshal = (%+v, %v) want (%+v, %v) | 解码不一致", gotV, gotErr, wantV, wantErr)
	}
	// Duplicate names between a regular field and the fallback are rejected. |
	// 常规字段与回退之间的重复名会被拒绝。
	if _, err := jsonx.Marshal(v2EmbedMap{A: 1, Extra: map[string]int{"a": 4}}, v2Defaults()...); err == nil {
		t.Fatalf("duplicate fallback name was accepted | 重复的回退名被接受")
	}
	if _, err := stdjsonv2.Marshal(v2EmbedMap{A: 1, Extra: map[string]int{"a": 4}}, v2Defaults()...); err == nil {
		t.Fatalf("stdlib duplicate fallback name was accepted | 标准库接受了重复的回退名")
	}
}

// TestV2EmbedTag compares explicit embed promotion. | TestV2EmbedTag 对比显式 embed 提升。
func TestV2EmbedTag(t *testing.T) {
	v := v2EmbedOuter{Inner: v2EmbedInner{X: 1, Y: "y"}, Z: 2}
	got, gotErr := jsonx.Marshal(v, v2Defaults()...)
	want, wantErr := stdjsonv2.Marshal(v, v2Defaults()...)
	if (gotErr == nil) != (wantErr == nil) || !bytes.Equal(got, want) {
		t.Fatalf("Marshal = (%s, %v) want (%s, %v) | 编码不一致", got, gotErr, want, wantErr)
	}
	var gotBack, wantBack v2EmbedOuter
	gotErr = jsonx.Unmarshal([]byte(`{"x":3,"y":"q","z":4}`), &gotBack, v2Defaults()...)
	wantErr = stdjsonv2.Unmarshal([]byte(`{"x":3,"y":"q","z":4}`), &wantBack, v2Defaults()...)
	if (gotErr == nil) != (wantErr == nil) || !reflect.DeepEqual(gotBack, wantBack) {
		t.Fatalf("Unmarshal = (%+v, %v) want (%+v, %v) | 解码不一致", gotBack, gotErr, wantBack, wantErr)
	}
}

// TestV2CustomMarshalers compares user-provided type-specific marshal and unmarshal funcs. |
// TestV2CustomMarshalers 对比用户提供的类型专用编解码函数。
func TestV2CustomMarshalers(t *testing.T) {
	m := jsonx.JoinMarshalers(
		jsonx.MarshalFunc(func(v int) ([]byte, error) { return []byte(`"int:` + itoa(v) + `"`), nil }),
		jsonx.MarshalToFunc(func(enc *jsontext.Encoder, v string) error {
			return enc.WriteToken(jsontext.String("str:" + v))
		}),
	)
	u := jsonx.JoinUnmarshalers(
		jsonx.UnmarshalFunc(func(data []byte, v *int) error {
			var s string
			if err := stdjsonv2.Unmarshal(data, &s); err != nil {
				return err
			}
			*v = len(s)
			return nil
		}),
		jsonx.UnmarshalFromFunc(func(dec *jsontext.Decoder, v *string) error {
			tok, err := dec.ReadToken()
			if err != nil {
				return err
			}
			*v = tok.String()
			return nil
		}),
	)
	type payload struct {
		N int    `json:"n"`
		S string `json:"s"`
	}
	v := payload{N: 7, S: "x"}
	opts := []jsonx.Options{jsonx.DefaultOptionsV2(), jsonx.WithMarshalers(m)}
	got, gotErr := jsonx.Marshal(v, opts...)
	want, wantErr := stdjsonv2.Marshal(v, opts...)
	if (gotErr == nil) != (wantErr == nil) || !bytes.Equal(got, want) {
		t.Fatalf("Marshal = (%s, %v) want (%s, %v) | 编码不一致", got, gotErr, want, wantErr)
	}
	var gotBack, wantBack payload
	uopts := []jsonx.Options{jsonx.DefaultOptionsV2(), jsonx.WithUnmarshalers(u)}
	gotErr = jsonx.Unmarshal(got, &gotBack, uopts...)
	wantErr = stdjsonv2.Unmarshal(got, &wantBack, uopts...)
	if (gotErr == nil) != (wantErr == nil) || !reflect.DeepEqual(gotBack, wantBack) {
		t.Fatalf("Unmarshal = (%+v, %v) want (%+v, %v) | 解码不一致", gotBack, gotErr, wantBack, wantErr)
	}
}

// itoa is a tiny test-local integer formatter. | itoa 是测试内的小型整数格式化函数。
func itoa(v int) string {
	if v == 0 {
		return "0"
	}
	var b [20]byte
	i := len(b)
	for v > 0 {
		i--
		b[i] = byte('0' + v%10)
		v /= 10
	}
	return string(b[i:])
}

// TestV2Streams compares the stream-oriented v2 entry points. | TestV2Streams 对比面向流的 v2 入口。
func TestV2Streams(t *testing.T) {
	type payload struct {
		A int      `json:"a"`
		B []string `json:"b"`
	}
	v := payload{A: 3, B: []string{"x", "y"}}
	var gotBuf, wantBuf bytes.Buffer
	if err := jsonx.MarshalWrite(&gotBuf, v, v2Defaults()...); err != nil {
		t.Fatalf("MarshalWrite: %v", err)
	}
	if err := stdjsonv2.MarshalWrite(&wantBuf, v, v2Defaults()...); err != nil {
		t.Fatalf("stdlib MarshalWrite: %v", err)
	}
	if gotBuf.String() != wantBuf.String() {
		t.Fatalf("MarshalWrite = %q want %q | 输出不一致", gotBuf.String(), wantBuf.String())
	}
	var gotV, wantV payload
	if err := jsonx.UnmarshalRead(bytes.NewReader(gotBuf.Bytes()), &gotV, v2Defaults()...); err != nil {
		t.Fatalf("UnmarshalRead: %v", err)
	}
	if err := stdjsonv2.UnmarshalRead(bytes.NewReader(gotBuf.Bytes()), &wantV, v2Defaults()...); err != nil {
		t.Fatalf("stdlib UnmarshalRead: %v", err)
	}
	if !reflect.DeepEqual(gotV, wantV) {
		t.Fatalf("UnmarshalRead = %+v want %+v | 解码不一致", gotV, wantV)
	}

	var gotEncBuf, wantEncBuf bytes.Buffer
	gotEnc := jsontext.NewEncoder(&gotEncBuf)
	wantEnc := jsontext.NewEncoder(&wantEncBuf)
	if err := jsonx.MarshalEncode(gotEnc, v, v2Defaults()...); err != nil {
		t.Fatalf("MarshalEncode: %v", err)
	}
	if err := stdjsonv2.MarshalEncode(wantEnc, v, v2Defaults()...); err != nil {
		t.Fatalf("stdlib MarshalEncode: %v", err)
	}
	if gotEncBuf.String() != wantEncBuf.String() {
		t.Fatalf("MarshalEncode = %q want %q | 输出不一致", gotEncBuf.String(), wantEncBuf.String())
	}
	var gotD, wantD payload
	gotDec := jsontext.NewDecoder(bytes.NewReader(gotBuf.Bytes()))
	wantDec := jsontext.NewDecoder(bytes.NewReader(gotBuf.Bytes()))
	if err := jsonx.UnmarshalDecode(gotDec, &gotD, v2Defaults()...); err != nil {
		t.Fatalf("UnmarshalDecode: %v", err)
	}
	if err := stdjsonv2.UnmarshalDecode(wantDec, &wantD, v2Defaults()...); err != nil {
		t.Fatalf("stdlib UnmarshalDecode: %v", err)
	}
	if !reflect.DeepEqual(gotD, wantD) {
		t.Fatalf("UnmarshalDecode = %+v want %+v | 解码不一致", gotD, wantD)
	}
	_ = io.Discard
}

// TestV2GetOptionAndJoin verifies option introspection. | TestV2GetOptionAndJoin 验证选项内省。
func TestV2GetOptionAndJoin(t *testing.T) {
	opts := jsonx.JoinOptions(jsonx.DefaultOptionsV2(), jsonx.Deterministic(true), jsonx.FormatNilSliceAsNull(true))
	if v, ok := jsonx.GetOption(opts, jsonx.Deterministic); !ok || !v {
		t.Fatalf("Deterministic = (%v, %v) want (true, true)", v, ok)
	}
	if v, ok := jsonx.GetOption(opts, jsonx.FormatNilSliceAsNull); !ok || !v {
		t.Fatalf("FormatNilSliceAsNull = (%v, %v) want (true, true)", v, ok)
	}
	// OmitZeroStructFields is not part of DefaultOptionsV2's presence mask, so it is absent. |
	// OmitZeroStructFields 不在 DefaultOptionsV2 的存在位掩码中，因此不存在。
	if v, ok := jsonx.GetOption(opts, jsonx.OmitZeroStructFields); ok || v {
		t.Fatalf("OmitZeroStructFields = (%v, %v) want (false, false)", v, ok)
	}
}

// v2Node is a recursive type for round-trip testing. | v2Node 是用于往返测试的递归类型。
type v2Node struct {
	Value int      `json:"v"`
	Next  *v2Node  `json:"next,omitempty"`
	List  []v2Node `json:"list,omitempty"`
}

// TestV2RecursiveRoundTrip compares a recursive type against the standard library. |
// TestV2RecursiveRoundTrip 与标准库对比递归类型。
func TestV2RecursiveRoundTrip(t *testing.T) {
	v := v2Node{Value: 1, Next: &v2Node{Value: 2, List: []v2Node{{Value: 3}}}}
	got, gotErr := jsonx.Marshal(v, v2Defaults()...)
	want, wantErr := stdjsonv2.Marshal(v, v2Defaults()...)
	if (gotErr == nil) != (wantErr == nil) || !bytes.Equal(got, want) {
		t.Fatalf("Marshal = (%s, %v) want (%s, %v) | 编码不一致", got, gotErr, want, wantErr)
	}
	var gotBack, wantBack v2Node
	if err := jsonx.Unmarshal(got, &gotBack, v2Defaults()...); err != nil {
		t.Fatalf("Unmarshal: %v", err)
	}
	if err := stdjsonv2.Unmarshal(got, &wantBack, v2Defaults()...); err != nil {
		t.Fatalf("stdlib Unmarshal: %v", err)
	}
	if !reflect.DeepEqual(gotBack, wantBack) {
		t.Fatalf("Unmarshal = %+v want %+v | 解码不一致", gotBack, wantBack)
	}
}

// TestV2DeterministicMap compares deterministic map output exactly. |
// TestV2DeterministicMap 精确对比确定性 map 输出。
func TestV2DeterministicMap(t *testing.T) {
	m := map[string]int{"b": 2, "a": 1, "c": 3}
	opts := []jsonx.Options{jsonx.DefaultOptionsV2(), jsonx.Deterministic(true)}
	got, gotErr := jsonx.Marshal(m, opts...)
	want, wantErr := stdjsonv2.Marshal(m, opts...)
	if (gotErr == nil) != (wantErr == nil) || !bytes.Equal(got, want) {
		t.Fatalf("Marshal = (%s, %v) want (%s, %v) | 编码不一致", got, gotErr, want, wantErr)
	}
	// The default v2 mode is not required to preserve order, but the output must be valid and
	// decode to the same value. | 默认 v2 模式不要求保持顺序，但输出必须合法并解码为相同值。
	raw, err := jsonx.Marshal(m, v2Defaults()...)
	if err != nil {
		t.Fatalf("Marshal default: %v", err)
	}
	var gotMap, wantMap map[string]int
	if err := jsonx.Unmarshal(raw, &gotMap, v2Defaults()...); err != nil {
		t.Fatalf("Unmarshal: %v", err)
	}
	if err := stdjsonv2.Unmarshal(raw, &wantMap, v2Defaults()...); err != nil {
		t.Fatalf("stdlib Unmarshal: %v", err)
	}
	if !reflect.DeepEqual(gotMap, wantMap) {
		t.Fatalf("map round trip = %v want %v", gotMap, wantMap)
	}
	keys := make([]string, 0, len(gotMap))
	for k := range gotMap {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	if len(keys) != 3 {
		t.Fatalf("decoded keys = %v", keys)
	}
}

// TestV2InvalidUTF8Marshal compares encoding of invalid UTF-8. |
// TestV2InvalidUTF8Marshal 对比非法 UTF-8 的编码行为。
func TestV2InvalidUTF8Marshal(t *testing.T) {
	in := string([]byte{'a', 0xff, 'b'})
	_, gotErr := jsonx.Marshal(in, v2Defaults()...)
	_, wantErr := stdjsonv2.Marshal(in, v2Defaults()...)
	if (gotErr == nil) != (wantErr == nil) {
		t.Fatalf("error = %v want %v | 错误不一致", gotErr, wantErr)
	}
	var gotSyn, wantSyn *jsontext.SyntacticError
	_ = errors.As(gotErr, &gotSyn)
	_ = errors.As(wantErr, &wantSyn)
	if (gotSyn != nil) != (wantSyn != nil) {
		t.Fatalf("syntactic type = %v want %v | 错误类型不一致", gotErr, wantErr)
	}
}
