package json_test

import (
	"encoding/json/jsontext"
	stdjsonv2 "encoding/json/v2"
	"errors"
	"reflect"
	"testing"
	"time"

	jsonx "github.com/shibingli/ydx/json"
)

// v2UnmarshalPair decodes the same input with this package and the standard library using the
// same options and returns the two errors. | v2UnmarshalPair 用相同选项分别经本包与标准库解码同一
// 输入，返回两个错误。
func v2UnmarshalPair(t *testing.T, in string, newTarget func() any, opts ...jsonx.Options) (any, any, error, error) {
	t.Helper()
	gotTarget, wantTarget := newTarget(), newTarget()
	gotErr := jsonx.Unmarshal([]byte(in), gotTarget, opts...)
	wantErr := stdjsonv2.Unmarshal([]byte(in), wantTarget, opts...)
	return gotTarget, wantTarget, gotErr, wantErr
}

// TestV2UnmarshalScalarsAndContainers compares v2 decoding of scalars and nil-able containers. |
// TestV2UnmarshalScalarsAndContainers 对比标量与可空容器的 v2 解码。
func TestV2UnmarshalScalarsAndContainers(t *testing.T) {
	cases := []struct {
		in  string
		new func() any
	}{
		{"null", func() any { return new(any) }},
		{"true", func() any { return new(bool) }},
		{"-42", func() any { return new(int64) }},
		{"1.5", func() any { return new(float64) }},
		{`"x<&>"`, func() any { return new(string) }},
		{`[]`, func() any { return new([]int) }},
		{"null", func() any { return new([]int) }},
		{`[]`, func() any { return new(map[string]int) }},
		{"null", func() any { return new(map[string]int) }},
		{`"AQID"`, func() any { return new([3]byte) }},
		{`[1,2,3]`, func() any { return new([3]byte) }},
		{`"AQID"`, func() any { return new([]byte) }},
	}
	for _, c := range cases {
		got, want, gotErr, wantErr := v2UnmarshalPair(t, c.in, c.new, v2Defaults()...)
		if (gotErr == nil) != (wantErr == nil) {
			t.Errorf("Unmarshal(%s) error = %v want %v | 错误不一致", c.in, gotErr, wantErr)
			continue
		}
		if gotErr == nil && !reflect.DeepEqual(got, want) {
			t.Errorf("Unmarshal(%s) = %#v want %#v | 解码不一致", c.in, got, want)
		}
	}
}

// v2CaseTarget is used for field-name matching tests. | v2CaseTarget 用于字段名匹配测试。
type v2CaseTarget struct {
	ID   int    `json:"id"`
	Name string `json:"name"`
}

// TestV2UnmarshalCaseSensitivity compares strict and insensitive name matching. |
// TestV2UnmarshalCaseSensitivity 对比严格与大小写不敏感的名称匹配。
func TestV2UnmarshalCaseSensitivity(t *testing.T) {
	inputs := []string{`{"ID":1,"NAME":"x"}`, `{"id":1,"name":"x"}`}
	for _, in := range inputs {
		got, want, gotErr, wantErr := v2UnmarshalPair(t, in, func() any { return new(v2CaseTarget) }, v2Defaults()...)
		if (gotErr == nil) != (wantErr == nil) || !reflect.DeepEqual(got, want) {
			t.Errorf("Unmarshal(%s) = (%#v, %v) want (%#v, %v) | 解码不一致", in, got, gotErr, want, wantErr)
		}
		got, want, gotErr, wantErr = v2UnmarshalPair(t, in, func() any { return new(v2CaseTarget) },
			jsonx.JoinOptions(jsonx.DefaultOptionsV2(), jsonx.MatchCaseInsensitiveNames(true)))
		if (gotErr == nil) != (wantErr == nil) || !reflect.DeepEqual(got, want) {
			t.Errorf("Unmarshal(%s, insensitive) = (%#v, %v) want (%#v, %v) | 解码不一致", in, got, gotErr, want, wantErr)
		}
	}
}

// TestV2UnmarshalStrictInput compares duplicate-name and invalid-UTF-8 rejection. |
// TestV2UnmarshalStrictInput 对比重复键与非法 UTF-8 的拒绝。
func TestV2UnmarshalStrictInput(t *testing.T) {
	cases := []struct {
		name   string
		in     string
		opts   []jsonx.Options
		target func() any
	}{
		{"duplicate", `{"a":1,"a":2}`, v2Defaults(), func() any { return new(map[string]int) }},
		{"duplicate-allowed", `{"a":1,"a":2}`, []jsonx.Options{stdjsonv2.JoinOptions(jsonx.DefaultOptionsV2(), jsontext.AllowDuplicateNames(true))}, func() any { return new(map[string]int) }},
		{"invalid-utf8", "\"a\xffb\"", v2Defaults(), func() any { return new(string) }},
		{"invalid-utf8-allowed", "\"a\xffb\"", []jsonx.Options{stdjsonv2.JoinOptions(jsonx.DefaultOptionsV2(), jsontext.AllowInvalidUTF8(true))}, func() any { return new(string) }},
		{"array-too-few", `[1]`, v2Defaults(), func() any { return new([2]int) }},
		{"array-too-many", `[1,2,3]`, v2Defaults(), func() any { return new([2]int) }},
		{"array-any-length", `[1,2,3]`, []jsonx.Options{stdjsonv2.JoinOptions(jsonx.DefaultOptionsV2(), jsonx.UnmarshalArrayFromAnyLength(true))}, func() any { return new([2]int) }},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			got, want, gotErr, wantErr := v2UnmarshalPair(t, c.in, c.target, c.opts...)
			if (gotErr == nil) != (wantErr == nil) {
				t.Fatalf("error = %v want %v | 错误不一致", gotErr, wantErr)
			}
			if gotErr == nil && !reflect.DeepEqual(got, want) {
				t.Errorf("value = %#v want %#v | 值不一致", got, want)
			}
		})
	}
}

// TestV2UnmarshalOptions compares the remaining option-driven behaviors. |
// TestV2UnmarshalOptions 对比其余选项驱动的行为。
func TestV2UnmarshalOptions(t *testing.T) {
	type dur struct {
		D time.Duration `json:"d"`
	}
	cases := []struct {
		name   string
		in     string
		opts   []jsonx.Options
		target func() any
	}{
		{"stringify", `{"N":"42"}`, []jsonx.Options{jsonx.StringifyNumbers(true)}, func() any { return new(struct{ N int }) }},
		{"reject-unknown", `{"id":1,"x":2}`, []jsonx.Options{jsonx.JoinOptions(jsonx.DefaultOptionsV2(), jsonx.RejectUnknownMembers(true))}, func() any { return new(v2CaseTarget) }},
		{"duration-nano", `{"d":1500000000}`, []jsonx.Options{jsonx.JoinOptions(jsonx.DefaultOptionsV2(), jsonx.FormatDurationAsNano(true))}, func() any { return new(dur) }},
		{"duration-default", `{"d":1500000000}`, v2Defaults(), func() any { return new(dur) }},
		{"byte-array-array", `{"A":[1,2,3]}`, []jsonx.Options{jsonx.JoinOptions(jsonx.DefaultOptionsV2(), jsonx.FormatByteArrayAsArray(true))}, func() any { return new(struct{ A [3]byte }) }},
		{"byte-array-base64", `{"A":"AQID"}`, v2Defaults(), func() any { return new(struct{ A [3]byte }) }},
		{"raw-duplicate", `{"a":1,"a":2}`, v2Defaults(), func() any { return new(jsontext.Value) }},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			got, want, gotErr, wantErr := v2UnmarshalPair(t, c.in, c.target, c.opts...)
			if (gotErr == nil) != (wantErr == nil) {
				t.Fatalf("error = %v want %v | 错误不一致", gotErr, wantErr)
			}
			if gotErr == nil && !reflect.DeepEqual(got, want) {
				t.Errorf("value = %#v want %#v | 值不一致", got, want)
			}
		})
	}
}

// v2UnmarshalerFrom implements UnmarshalJSONFrom. | v2UnmarshalerFrom 实现 UnmarshalJSONFrom。
type v2UnmarshalerFrom struct {
	V string
}

// UnmarshalJSONFrom reads one JSON string token. | UnmarshalJSONFrom 读取一个 JSON 字符串记号。
func (u *v2UnmarshalerFrom) UnmarshalJSONFrom(dec *jsontext.Decoder) error {
	tok, err := dec.ReadToken()
	if err != nil {
		return err
	}
	u.V = tok.String()
	return nil
}

// TestV2UnmarshalMethods compares custom unmarshal method dispatch. | TestV2UnmarshalMethods 对比
// 自定义解码方法的分派。
func TestV2UnmarshalMethods(t *testing.T) {
	var got, want v2UnmarshalerFrom
	gotErr := jsonx.Unmarshal([]byte(`"x<&>"`), &got, v2Defaults()...)
	wantErr := stdjsonv2.Unmarshal([]byte(`"x<&>"`), &want, v2Defaults()...)
	if (gotErr == nil) != (wantErr == nil) || got.V != want.V {
		t.Fatalf("UnmarshalerFrom = (%q, %v) want (%q, %v) | 解码不一致", got.V, gotErr, want.V, wantErr)
	}
}

// TestV2UnmarshalErrors compares error types for failing inputs. |
// TestV2UnmarshalErrors 对比失败输入的错误类型。
func TestV2UnmarshalErrors(t *testing.T) {
	type target struct {
		ID int `json:"id"`
	}
	cases := []struct {
		in string
		v  any
	}{
		{`{"id":"x"}`, new(target)},
		{`{"id":}`, new(target)},
		{`null`, nil},
		{`1`, (*int)(nil)},
	}
	for _, c := range cases {
		gotErr := jsonx.Unmarshal([]byte(c.in), c.v, v2Defaults()...)
		wantErr := stdjsonv2.Unmarshal([]byte(c.in), c.v, v2Defaults()...)
		if (gotErr == nil) != (wantErr == nil) {
			t.Errorf("Unmarshal(%q) error = %v want %v | 错误不一致", c.in, gotErr, wantErr)
			continue
		}
		if wantErr == nil {
			continue
		}
		var gotSyn, wantSyn *jsontext.SyntacticError
		if errors.As(gotErr, &gotSyn) != errors.As(wantErr, &wantSyn) {
			t.Errorf("Unmarshal(%q) syntactic type = %v want %v | 语法错误类型不一致", c.in, gotErr, wantErr)
		}
		var gotSem, wantSem *stdjsonv2.SemanticError
		if errors.As(gotErr, &gotSem) != errors.As(wantErr, &wantSem) {
			t.Errorf("Unmarshal(%q) semantic type = %v want %v | 语义错误类型不一致", c.in, gotErr, wantErr)
		}
	}
}
