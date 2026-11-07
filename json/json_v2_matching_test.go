package json_test

import (
	stdjsonv2 "encoding/json/v2"
	"reflect"
	"testing"

	jsonx "github.com/shibingli/ydx/json"
)

// v2LooseName uses a field name containing a dash. | v2LooseName 使用含连字符的字段名。
type v2LooseName struct {
	Value int `json:"my-value"`
}

// TestV2LooseNameMatching compares global case-insensitive matching, which v2 also applies
// across dashes and underscores. | TestV2LooseNameMatching 对比全局大小写不敏感匹配；v2 同时
// 忽略连字符与下划线。
func TestV2LooseNameMatching(t *testing.T) {
	inputs := []string{`{"my-value":1}`, `{"MY-VALUE":2}`, `{"my_value":3}`, `{"myvalue":4}`, `{"MyValue":5}`}
	opts := []jsonx.Options{stdjsonv2.JoinOptions(jsonx.DefaultOptionsV2(), jsonx.MatchCaseInsensitiveNames(true))}
	for _, in := range inputs {
		got, want := new(v2LooseName), new(v2LooseName)
		gotErr := jsonx.Unmarshal([]byte(in), got, opts...)
		wantErr := stdjsonv2.Unmarshal([]byte(in), want, opts...)
		if (gotErr == nil) != (wantErr == nil) || !reflect.DeepEqual(got, want) {
			t.Errorf("Unmarshal(%s) = (%+v, %v) want (%+v, %v) | 解码不一致", in, got, gotErr, want, wantErr)
		}
	}
}

// TestV2DuplicateWithLooseNames compares duplicate handling when two distinct names match one
// field. | TestV2DuplicateWithLooseNames 对比两个不同名称匹配同一字段时的重复处理。
func TestV2DuplicateWithLooseNames(t *testing.T) {
	in := `{"id":1,"ID":2}`
	opts := []jsonx.Options{stdjsonv2.JoinOptions(jsonx.DefaultOptionsV2(), jsonx.MatchCaseInsensitiveNames(true))}
	type target struct {
		ID int `json:"id"`
	}
	got, want := new(target), new(target)
	gotErr := jsonx.Unmarshal([]byte(in), got, opts...)
	wantErr := stdjsonv2.Unmarshal([]byte(in), want, opts...)
	if (gotErr == nil) != (wantErr == nil) || !reflect.DeepEqual(got, want) {
		t.Errorf("Unmarshal(%s) = (%+v, %v) want (%+v, %v) | 解码不一致", in, got, gotErr, want, wantErr)
	}
}

// TestV2StringifyNumbersAny compares recursive StringifyNumbers decoding into any. |
// TestV2StringifyNumbersAny 对比递归 StringifyNumbers 解码进 any。
func TestV2StringifyNumbersAny(t *testing.T) {
	for _, in := range []string{`"42"`, `{"a":"1","b":2}`, `["3","4"]`} {
		opts := []jsonx.Options{jsonx.StringifyNumbers(true)}
		var got, want any
		gotErr := jsonx.Unmarshal([]byte(in), &got, opts...)
		wantErr := stdjsonv2.Unmarshal([]byte(in), &want, opts...)
		if (gotErr == nil) != (wantErr == nil) || !reflect.DeepEqual(got, want) {
			t.Errorf("Unmarshal(%s) = (%#v, %v) want (%#v, %v) | 解码不一致", in, got, gotErr, want, wantErr)
		}
	}
}
