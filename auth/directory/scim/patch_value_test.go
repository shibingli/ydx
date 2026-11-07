package scim

import (
	"errors"
	"testing"
)

// TestAsObjectAndDecodeInto verifies JSON object coercion. | TestAsObjectAndDecodeInto 校验 JSON
// 对象转换。
func TestAsObjectAndDecodeInto(t *testing.T) {
	object := map[string]any{"a": "b"}
	got, err := asObject(object)
	if err != nil || got["a"] != "b" {
		t.Fatalf("asObject map = %#v, %v", got, err)
	}
	if _, err := asObject(nil); err == nil || !errors.Is(err, ErrInvalidValue) {
		t.Fatalf("asObject nil error = %v", err)
	}
	if _, err := asObject("text"); err == nil || !errors.Is(err, ErrInvalidValue) {
		t.Fatalf("asObject string error = %v", err)
	}
	if _, err := asObject(42); err == nil || !errors.Is(err, ErrInvalidValue) {
		t.Fatalf("asObject number error = %v", err)
	}
	var target map[string]any
	if err := decodeInto(map[string]any{"x": "y"}, &target); err != nil || target["x"] != "y" {
		t.Fatalf("decodeInto = %#v, %v", target, err)
	}
	if err := decodeInto(func() {}, &target); err == nil || !errors.Is(err, ErrInvalidValue) {
		t.Fatalf("decodeInto marshal error = %v", err)
	}
	if err := decodeInto("text", &target); err == nil || !errors.Is(err, ErrInvalidValue) {
		t.Fatalf("decodeInto unmarshal error = %v", err)
	}
}

// TestAsStringAndBool verifies scalar coercion helpers. | TestAsStringAndBool 校验标量转换辅助函数。
func TestAsStringAndBool(t *testing.T) {
	strings := []struct {
		input any
		want  string
		ok    bool
	}{
		{"x", "x", true},
		{1.5, "1.5", true},
		{float32(1.5), "1.5", true},
		{2, "2", true},
		{int64(3), "3", true},
		{int32(4), "4", true},
		{true, "", false},
	}
	for _, testCase := range strings {
		got, ok := asString(testCase.input)
		if got != testCase.want || ok != testCase.ok {
			t.Fatalf("asString(%#v) = %q, %v; want %q, %v", testCase.input, got, ok, testCase.want, testCase.ok)
		}
	}
	bools := []struct {
		input any
		want  bool
		ok    bool
	}{
		{true, true, true},
		{false, false, true},
		{"TRUE", true, true},
		{"false", false, true},
		{"yes", false, false},
		{1, false, false},
	}
	for _, testCase := range bools {
		got, ok := asBool(testCase.input)
		if got != testCase.want || ok != testCase.ok {
			t.Fatalf("asBool(%#v) = %v, %v; want %v, %v", testCase.input, got, ok, testCase.want, testCase.ok)
		}
	}
}

// TestObjectStringAndBool verifies sub-attribute readers. | TestObjectStringAndBool 校验子属性读取。
func TestObjectStringAndBool(t *testing.T) {
	object := map[string]any{
		"name":    "Alice",
		"number":  float64(2),
		"enabled": true,
		"flag":    "TRUE",
		"nil":     nil,
		"bad":     []string{"x"},
	}
	if got, err := objectString(object, "NAME"); err != nil || got != "Alice" {
		t.Fatalf("objectString name = %q, %v", got, err)
	}
	if got, err := objectString(object, "number"); err != nil || got != "2" {
		t.Fatalf("objectString number = %q, %v", got, err)
	}
	if got, err := objectString(object, "nil"); err != nil || got != "" {
		t.Fatalf("objectString nil = %q, %v", got, err)
	}
	if got, err := objectString(object, "missing"); err != nil || got != "" {
		t.Fatalf("objectString missing = %q, %v", got, err)
	}
	if _, err := objectString(object, "bad"); err == nil || !errors.Is(err, ErrInvalidValue) {
		t.Fatalf("objectString bad error = %v", err)
	}
	if got, err := objectBool(object, "enabled"); err != nil || !got {
		t.Fatalf("objectBool enabled = %v, %v", got, err)
	}
	if got, err := objectBool(object, "flag"); err != nil || !got {
		t.Fatalf("objectBool flag = %v, %v", got, err)
	}
	if got, err := objectBool(object, "nil"); err != nil || got {
		t.Fatalf("objectBool nil = %v, %v", got, err)
	}
	if got, err := objectBool(object, "missing"); err != nil || got {
		t.Fatalf("objectBool missing = %v, %v", got, err)
	}
	if _, err := objectBool(object, "bad"); err == nil || !errors.Is(err, ErrInvalidValue) {
		t.Fatalf("objectBool bad error = %v", err)
	}
}

// TestMergeNameAndManagerFields verifies complex sub-attribute merging. |
// TestMergeNameAndManagerFields 校验复杂子属性合并。
func TestMergeNameAndManagerFields(t *testing.T) {
	name := &Name{}
	err := mergeNameFields(name, map[string]any{
		"formatted":       "F",
		"familyName":      "Fa",
		"givenname":       "G",
		"middleName":      "M",
		"honorificPrefix": "P",
		"honorificSuffix": "S",
	})
	if err != nil {
		t.Fatalf("mergeNameFields: %v", err)
	}
	want := Name{Formatted: "F", FamilyName: "Fa", GivenName: "G", MiddleName: "M",
		HonorificPrefix: "P", HonorificSuffix: "S"}
	if *name != want {
		t.Fatalf("name = %+v", name)
	}
	if err := mergeNameFields(name, map[string]any{"unknown": "x"}); err == nil || !errors.Is(err, ErrInvalidPath) {
		t.Fatalf("unknown name field error = %v", err)
	}
	if err := mergeNameFields(name, map[string]any{"givenName": []string{"x"}}); err == nil || !errors.Is(err, ErrInvalidValue) {
		t.Fatalf("invalid name field error = %v", err)
	}
	manager := &Manager{}
	err = mergeManagerFields(manager, map[string]any{"value": "v", "displayName": "D", "$ref": "r"})
	if err != nil {
		t.Fatalf("mergeManagerFields: %v", err)
	}
	if manager.Value != "v" || manager.DisplayName != "D" || manager.Ref != "r" {
		t.Fatalf("manager = %+v", manager)
	}
	if err := mergeManagerFields(manager, map[string]any{"ref": "r2"}); err != nil || manager.Ref != "r2" {
		t.Fatalf("ref alias = %+v, %v", manager, err)
	}
	if err := mergeManagerFields(manager, map[string]any{"unknown": "x"}); err == nil || !errors.Is(err, ErrInvalidPath) {
		t.Fatalf("unknown manager field error = %v", err)
	}
	if err := mergeManagerFields(manager, map[string]any{"value": 1.5}); err != nil {
		t.Fatalf("numeric manager value error = %v", err)
	}
	if manager.Value != "1.5" {
		t.Fatalf("numeric manager value = %q", manager.Value)
	}
	if err := mergeManagerFields(manager, map[string]any{"value": []string{"x"}}); err == nil || !errors.Is(err, ErrInvalidValue) {
		t.Fatalf("invalid manager field error = %v", err)
	}
}

// TestDecodeMultiValues verifies scalar, array and object multi-value decoding. |
// TestDecodeMultiValues 校验标量、数组与对象多值解码。
func TestDecodeMultiValues(t *testing.T) {
	direct := []MultiValue{{Value: "a"}, {Value: "b"}}
	if got, err := decodeMultiValues(direct); err != nil || len(got) != 2 || got[0].Value != "a" {
		t.Fatalf("direct = %#v, %v", got, err)
	}
	if got, err := decodeMultiValues([]string{"a", "b"}); err != nil || len(got) != 2 {
		t.Fatalf("strings = %#v, %v", got, err)
	}
	if _, err := decodeMultiValues([]string{""}); err == nil || !errors.Is(err, ErrInvalidValue) {
		t.Fatalf("empty string error = %v", err)
	}
	if got, err := decodeMultiValues([]any{"a", map[string]any{"value": "b"}, []any{"c"}}); err != nil || len(got) != 3 {
		t.Fatalf("any list = %#v, %v", got, err)
	}
	if got, err := decodeMultiValues("a"); err != nil || len(got) != 1 || got[0].Value != "a" {
		t.Fatalf("scalar = %#v, %v", got, err)
	}
	if _, err := decodeMultiValues(""); err == nil || !errors.Is(err, ErrInvalidValue) {
		t.Fatalf("empty scalar error = %v", err)
	}
	if _, err := decodeMultiValues(nil); err == nil || !errors.Is(err, ErrInvalidValue) {
		t.Fatalf("nil error = %v", err)
	}
	if got, err := decodeMultiValues(map[string]any{"value": "a", "type": "work"}); err != nil || got[0].Type != "work" {
		t.Fatalf("object = %#v, %v", got, err)
	}
	if _, err := decodeMultiValues(map[string]any{"type": "work"}); err == nil || !errors.Is(err, ErrInvalidValue) {
		t.Fatalf("object without value error = %v", err)
	}
	if _, err := decodeMultiValues(42); err == nil || !errors.Is(err, ErrInvalidValue) {
		t.Fatalf("number error = %v", err)
	}
}

// TestPatchMultiValuesBranches verifies every multi-value PATCH branch. |
// TestPatchMultiValuesBranches 校验每个多值 PATCH 分支。
func TestPatchMultiValuesBranches(t *testing.T) {
	base := func() []MultiValue {
		return []MultiValue{{Value: "a", Type: "work", Primary: true}, {Value: "b", Type: "home"}}
	}
	if err := patchMultiValues(ptrList(nil), &AttributePath{Attribute: "emails"}, patchRemove, nil); err == nil || !errors.Is(err, ErrNoTarget) {
		t.Fatalf("remove empty error = %v", err)
	}
	list := base()
	if err := patchMultiValues(&list, &AttributePath{Attribute: "emails"}, patchRemove, nil); err != nil || list != nil {
		t.Fatalf("remove all = %#v, %v", list, err)
	}
	list = base()
	if err := patchMultiValues(&list, &AttributePath{Attribute: "emails"}, patchReplace, []any{"x"}); err != nil || len(list) != 1 || list[0].Value != "x" {
		t.Fatalf("replace = %#v, %v", list, err)
	}
	list = base()
	if err := patchMultiValues(&list, &AttributePath{Attribute: "emails"}, patchAdd, []any{"a", "c"}); err != nil || len(list) != 3 {
		t.Fatalf("add unique = %#v, %v", list, err)
	}
	list = base()
	if err := patchMultiValues(&list, &AttributePath{Attribute: "emails", SubAttribute: "value"}, patchReplace, "x"); err == nil || !errors.Is(err, ErrInvalidPath) {
		t.Fatalf("sub-attribute without filter error = %v", err)
	}
	list = base()
	path := &AttributePath{Attribute: "emails", ValueFilter: mustFilter(t, `type eq "missing"`)}
	if err := patchMultiValues(&list, path, patchAdd, "c"); err != nil || len(list) != 3 {
		t.Fatalf("filtered add no match = %#v, %v", list, err)
	}
	if err := patchMultiValues(&list, path, patchReplace, "c"); err == nil || !errors.Is(err, ErrNoTarget) {
		t.Fatalf("filtered no match error = %v", err)
	}
	list = base()
	work := &AttributePath{Attribute: "emails", ValueFilter: mustFilter(t, `type eq "work"`)}
	if err := patchMultiValues(&list, work, patchRemove, nil); err != nil || len(list) != 1 || list[0].Value != "b" {
		t.Fatalf("filtered remove = %#v, %v", list, err)
	}
	list = base()
	workValue := &AttributePath{Attribute: "emails", SubAttribute: "value", ValueFilter: mustFilter(t, `type eq "work"`)}
	if err := patchMultiValues(&list, workValue, patchRemove, nil); err != nil || list[0].Value != "" {
		t.Fatalf("filtered sub remove = %#v, %v", list, err)
	}
	for _, sub := range []string{"display", "type", "value", "$ref", "ref"} {
		list = base()
		subPath := &AttributePath{Attribute: "emails", SubAttribute: sub, ValueFilter: mustFilter(t, `type eq "work"`)}
		if err := patchMultiValues(&list, subPath, patchReplace, "x"); err != nil {
			t.Fatalf("sub %q: %v", sub, err)
		}
		if list[0].Display != "x" && sub == "display" {
			t.Fatalf("display not set: %+v", list[0])
		}
	}
	list = base()
	primaryPath := &AttributePath{Attribute: "emails", SubAttribute: "primary", ValueFilter: mustFilter(t, `type eq "home"`)}
	if err := patchMultiValues(&list, primaryPath, patchReplace, true); err != nil || !list[1].Primary {
		t.Fatalf("primary set = %#v, %v", list, err)
	}
	if err := patchMultiValues(&list, primaryPath, patchReplace, "maybe"); err == nil || !errors.Is(err, ErrInvalidValue) {
		t.Fatalf("primary invalid error = %v", err)
	}
	unknownPath := &AttributePath{Attribute: "emails", SubAttribute: "unknown", ValueFilter: mustFilter(t, `type eq "work"`)}
	if err := patchMultiValues(&list, unknownPath, patchReplace, "x"); err == nil || !errors.Is(err, ErrInvalidPath) {
		t.Fatalf("unknown sub error = %v", err)
	}
	list = base()
	objectPath := &AttributePath{Attribute: "emails", ValueFilter: mustFilter(t, `type eq "work"`)}
	if err := patchMultiValues(&list, objectPath, patchReplace, map[string]any{"display": "Work", "primary": false, "$ref": "r"}); err != nil {
		t.Fatalf("object merge: %v", err)
	}
	if list[0].Display != "Work" || list[0].Primary || list[0].Ref != "r" {
		t.Fatalf("object merge = %+v", list[0])
	}
	if err := patchMultiValues(&list, objectPath, patchReplace, func() {}); err == nil {
		t.Fatalf("non-object merge succeeded")
	}
	if err := patchMultiValues(&list, objectPath, patchReplace, map[string]any{"unknown": "x"}); err == nil || !errors.Is(err, ErrInvalidPath) {
		t.Fatalf("unknown merge field error = %v", err)
	}
	list = base()
	if err := patchMultiValues(&list, objectPath, patchAdd, map[string]any{"display": "Z"}); err != nil || list[0].Display != "Z" {
		t.Fatalf("filtered add matching = %#v, %v", list, err)
	}
}

// ptrList returns a pointer to an empty multi-value list. | ptrList 返回空多值列表的指针。
func ptrList(_ []MultiValue) *[]MultiValue {
	list := []MultiValue{}
	return &list
}

// TestDecodeAddresses verifies address decoding. | TestDecodeAddresses 校验地址解码。
func TestDecodeAddresses(t *testing.T) {
	if got, err := decodeAddresses([]Address{{Locality: "L"}}); err != nil || got[0].Locality != "L" {
		t.Fatalf("direct = %#v, %v", got, err)
	}
	if got, err := decodeAddresses([]any{map[string]any{"locality": "L"}, Address{Locality: "M"}}); err != nil || len(got) != 2 {
		t.Fatalf("any list = %#v, %v", got, err)
	}
	if _, err := decodeAddresses([]any{42}); err == nil || !errors.Is(err, ErrInvalidValue) {
		t.Fatalf("bad list error = %v", err)
	}
	if got, err := decodeAddresses(map[string]any{"locality": "L"}); err != nil || got[0].Locality != "L" {
		t.Fatalf("object = %#v, %v", got, err)
	}
	if _, err := decodeAddresses(nil); err == nil || !errors.Is(err, ErrInvalidValue) {
		t.Fatalf("nil error = %v", err)
	}
	if _, err := decodeAddresses(42); err == nil || !errors.Is(err, ErrInvalidValue) {
		t.Fatalf("number error = %v", err)
	}
	address := Address{Formatted: "F", StreetAddress: "S", Locality: "L", Region: "R", PostalCode: "P", Country: "C", Type: "T"}
	if !containsAddress([]Address{address}, address) {
		t.Fatalf("containsAddress did not match")
	}
	if containsAddress([]Address{address}, Address{Locality: "X"}) {
		t.Fatalf("containsAddress false positive")
	}
}

// TestPatchAddressesBranches verifies every address PATCH branch. |
// TestPatchAddressesBranches 校验每个地址 PATCH 分支。
func TestPatchAddressesBranches(t *testing.T) {
	base := func() []Address {
		return []Address{{Formatted: "F", Locality: "L", Type: "work", Primary: true}, {Formatted: "G", Locality: "M", Type: "home"}}
	}
	if err := patchAddresses(&[]Address{}, &AttributePath{Attribute: "addresses"}, patchRemove, nil); err == nil || !errors.Is(err, ErrNoTarget) {
		t.Fatalf("remove empty error = %v", err)
	}
	list := base()
	if err := patchAddresses(&list, &AttributePath{Attribute: "addresses"}, patchRemove, nil); err != nil || list != nil {
		t.Fatalf("remove all = %#v, %v", list, err)
	}
	list = base()
	if err := patchAddresses(&list, &AttributePath{Attribute: "addresses"}, patchReplace, []any{map[string]any{"locality": "Z"}}); err != nil || len(list) != 1 || list[0].Locality != "Z" {
		t.Fatalf("replace = %#v, %v", list, err)
	}
	list = base()
	if err := patchAddresses(&list, &AttributePath{Attribute: "addresses"}, patchAdd, base()[0]); err != nil || len(list) != 2 {
		t.Fatalf("add duplicate = %#v, %v", list, err)
	}
	list = base()
	if err := patchAddresses(&list, &AttributePath{Attribute: "addresses"}, patchAdd, Address{Locality: "N"}); err != nil || len(list) != 3 {
		t.Fatalf("add unique = %#v, %v", list, err)
	}
	list = base()
	if err := patchAddresses(&list, &AttributePath{Attribute: "addresses", SubAttribute: "locality"}, patchReplace, "x"); err == nil || !errors.Is(err, ErrInvalidPath) {
		t.Fatalf("sub without filter error = %v", err)
	}
	missing := &AttributePath{Attribute: "addresses", ValueFilter: mustFilter(t, `type eq "other"`)}
	if err := patchAddresses(&list, missing, patchAdd, Address{Locality: "N"}); err != nil || len(list) != 3 {
		t.Fatalf("filtered add no match = %#v, %v", list, err)
	}
	absent := &AttributePath{Attribute: "addresses", ValueFilter: mustFilter(t, `type eq "absent"`)}
	if err := patchAddresses(&list, absent, patchReplace, Address{Locality: "N"}); err == nil || !errors.Is(err, ErrNoTarget) {
		t.Fatalf("filtered no match error = %v", err)
	}
	list = base()
	work := &AttributePath{Attribute: "addresses", ValueFilter: mustFilter(t, `type eq "work"`)}
	if err := patchAddresses(&list, work, patchRemove, nil); err != nil || len(list) != 1 || list[0].Type != "home" {
		t.Fatalf("filtered remove = %#v, %v", list, err)
	}
	for _, sub := range []string{"formatted", "streetaddress", "locality", "region", "postalcode", "country", "type"} {
		list = base()
		subPath := &AttributePath{Attribute: "addresses", SubAttribute: sub, ValueFilter: mustFilter(t, `type eq "work"`)}
		if err := patchAddresses(&list, subPath, patchReplace, "x"); err != nil {
			t.Fatalf("sub %q: %v", sub, err)
		}
		list = base()
		if err := patchAddresses(&list, subPath, patchRemove, nil); err != nil {
			t.Fatalf("sub remove %q: %v", sub, err)
		}
	}
	list = base()
	primaryPath := &AttributePath{Attribute: "addresses", SubAttribute: "primary", ValueFilter: mustFilter(t, `type eq "home"`)}
	if err := patchAddresses(&list, primaryPath, patchReplace, "TRUE"); err != nil || !list[1].Primary {
		t.Fatalf("primary set = %#v, %v", list, err)
	}
	if err := patchAddresses(&list, primaryPath, patchReplace, 2); err == nil || !errors.Is(err, ErrInvalidValue) {
		t.Fatalf("primary invalid error = %v", err)
	}
	unknown := &AttributePath{Attribute: "addresses", SubAttribute: "unknown", ValueFilter: mustFilter(t, `type eq "work"`)}
	if err := patchAddresses(&list, unknown, patchReplace, "x"); err == nil || !errors.Is(err, ErrInvalidPath) {
		t.Fatalf("unknown sub error = %v", err)
	}
	list = base()
	if err := patchAddresses(&list, work, patchReplace, map[string]any{"locality": "X", "primary": false}); err != nil || list[0].Locality != "X" || list[0].Primary {
		t.Fatalf("object merge = %#v, %v", list, err)
	}
	if err := patchAddresses(&list, work, patchReplace, "not-an-object"); err == nil || !errors.Is(err, ErrInvalidValue) {
		t.Fatalf("non-object merge error = %v", err)
	}
	if err := patchAddresses(&list, work, patchReplace, map[string]any{"unknown": "x"}); err == nil || !errors.Is(err, ErrInvalidPath) {
		t.Fatalf("unknown merge field error = %v", err)
	}
}

// TestDecodeGroupMembers verifies group member decoding. | TestDecodeGroupMembers 校验组成员解码。
func TestDecodeGroupMembers(t *testing.T) {
	if got, err := decodeGroupMembers([]GroupMember{{Value: "u1"}}); err != nil || got[0].Value != "u1" {
		t.Fatalf("direct = %#v, %v", got, err)
	}
	if got, err := decodeGroupMembers([]string{"u1", "u2"}); err != nil || len(got) != 2 {
		t.Fatalf("strings = %#v, %v", got, err)
	}
	if _, err := decodeGroupMembers([]string{""}); err == nil || !errors.Is(err, ErrInvalidValue) {
		t.Fatalf("empty string error = %v", err)
	}
	if got, err := decodeGroupMembers([]any{"u1", []any{"u2"}, map[string]any{"value": "u3"}}); err != nil || len(got) != 3 {
		t.Fatalf("any list = %#v, %v", got, err)
	}
	if got, err := decodeGroupMembers("u1"); err != nil || got[0].Value != "u1" {
		t.Fatalf("scalar = %#v, %v", got, err)
	}
	if _, err := decodeGroupMembers(""); err == nil || !errors.Is(err, ErrInvalidValue) {
		t.Fatalf("empty scalar error = %v", err)
	}
	if _, err := decodeGroupMembers(nil); err == nil || !errors.Is(err, ErrInvalidValue) {
		t.Fatalf("nil error = %v", err)
	}
	if got, err := decodeGroupMembers(map[string]any{"value": "u1", "display": "Alice"}); err != nil || got[0].Display != "Alice" {
		t.Fatalf("object = %#v, %v", got, err)
	}
	if _, err := decodeGroupMembers(map[string]any{"display": "Alice"}); err == nil || !errors.Is(err, ErrInvalidValue) {
		t.Fatalf("object without value error = %v", err)
	}
	if _, err := decodeGroupMembers(42); err == nil || !errors.Is(err, ErrInvalidValue) {
		t.Fatalf("number error = %v", err)
	}
	if !containsGroupMember([]GroupMember{{Value: "u1"}}, GroupMember{Value: "u1"}) {
		t.Fatalf("containsGroupMember did not match")
	}
	if containsGroupMember([]GroupMember{{Value: "u1"}}, GroupMember{Value: "u2"}) {
		t.Fatalf("containsGroupMember false positive")
	}
}

// TestPatchGroupMembersBranches verifies every group member PATCH branch. |
// TestPatchGroupMembersBranches 校验每个组成员 PATCH 分支。
func TestPatchGroupMembersBranches(t *testing.T) {
	base := func() []GroupMember {
		return []GroupMember{{Value: "u1", Display: "Alice", Type: "User", Ref: "r1"}, {Value: "u2", Display: "Bob"}}
	}
	if err := patchGroupMembers(&[]GroupMember{}, &AttributePath{Attribute: "members"}, patchRemove, nil); err == nil || !errors.Is(err, ErrNoTarget) {
		t.Fatalf("remove empty error = %v", err)
	}
	list := base()
	if err := patchGroupMembers(&list, &AttributePath{Attribute: "members"}, patchRemove, nil); err != nil || list != nil {
		t.Fatalf("remove all = %#v, %v", list, err)
	}
	list = base()
	if err := patchGroupMembers(&list, &AttributePath{Attribute: "members"}, patchReplace, []string{"u3"}); err != nil || len(list) != 1 || list[0].Value != "u3" {
		t.Fatalf("replace = %#v, %v", list, err)
	}
	list = base()
	if err := patchGroupMembers(&list, &AttributePath{Attribute: "members"}, patchAdd, GroupMember{Value: "u1"}); err != nil || len(list) != 2 {
		t.Fatalf("add duplicate = %#v, %v", list, err)
	}
	if err := patchGroupMembers(&list, &AttributePath{Attribute: "members"}, patchAdd, map[string]any{"value": "u3"}); err != nil || len(list) != 3 {
		t.Fatalf("add unique = %#v, %v", list, err)
	}
	if err := patchGroupMembers(&list, &AttributePath{Attribute: "members", SubAttribute: "display"}, patchReplace, "x"); err == nil || !errors.Is(err, ErrInvalidPath) {
		t.Fatalf("sub without filter error = %v", err)
	}
	missing := &AttributePath{Attribute: "members", ValueFilter: mustFilter(t, `value eq "u99"`)}
	if err := patchGroupMembers(&list, missing, patchAdd, "u99"); err != nil || len(list) != 4 {
		t.Fatalf("filtered add no match = %#v, %v", list, err)
	}
	absent := &AttributePath{Attribute: "members", ValueFilter: mustFilter(t, `value eq "absent"`)}
	if err := patchGroupMembers(&list, absent, patchRemove, nil); err == nil || !errors.Is(err, ErrNoTarget) {
		t.Fatalf("filtered no match error = %v", err)
	}
	list = base()
	first := &AttributePath{Attribute: "members", ValueFilter: mustFilter(t, `value eq "u1"`)}
	if err := patchGroupMembers(&list, first, patchRemove, nil); err != nil || len(list) != 1 || list[0].Value != "u2" {
		t.Fatalf("filtered remove = %#v, %v", list, err)
	}
	for _, sub := range []string{"value", "display", "type", "$ref", "ref"} {
		list = base()
		subPath := &AttributePath{Attribute: "members", SubAttribute: sub, ValueFilter: mustFilter(t, `value eq "u1"`)}
		if err := patchGroupMembers(&list, subPath, patchReplace, "x"); err != nil {
			t.Fatalf("sub %q: %v", sub, err)
		}
		list = base()
		if err := patchGroupMembers(&list, subPath, patchRemove, nil); err != nil {
			t.Fatalf("sub remove %q: %v", sub, err)
		}
	}
	list = base()
	unknown := &AttributePath{Attribute: "members", SubAttribute: "unknown", ValueFilter: mustFilter(t, `value eq "u1"`)}
	if err := patchGroupMembers(&list, unknown, patchReplace, "x"); err == nil || !errors.Is(err, ErrInvalidPath) {
		t.Fatalf("unknown sub error = %v", err)
	}
	if err := patchGroupMembers(&list, unknown, patchRemove, nil); err == nil || !errors.Is(err, ErrInvalidPath) {
		t.Fatalf("unknown remove sub error = %v", err)
	}
	badValue := &AttributePath{Attribute: "members", SubAttribute: "display", ValueFilter: mustFilter(t, `value eq "u1"`)}
	if err := patchGroupMembers(&list, badValue, patchReplace, true); err == nil || !errors.Is(err, ErrInvalidValue) {
		t.Fatalf("non-string member sub error = %v", err)
	}
	first = &AttributePath{Attribute: "members", ValueFilter: mustFilter(t, `value eq "u1"`)}
	if err := patchGroupMembers(&list, first, patchReplace, map[string]any{"display": "Alicia", "type": "Group", "$ref": "r2"}); err != nil {
		t.Fatalf("object merge: %v", err)
	}
	if list[0].Display != "Alicia" || list[0].Type != "Group" || list[0].Ref != "r2" {
		t.Fatalf("object merge = %+v", list[0])
	}
	if err := patchGroupMembers(&list, first, patchReplace, map[string]any{"unknown": "x"}); err == nil || !errors.Is(err, ErrInvalidPath) {
		t.Fatalf("unknown merge field error = %v", err)
	}
	if err := patchGroupMembers(&list, first, patchReplace, 42); err == nil || !errors.Is(err, ErrInvalidValue) {
		t.Fatalf("non-object merge error = %v", err)
	}
	if indexes := matchedMemberIndexes(list, nil); indexes != nil {
		t.Fatalf("nil member filter indexes = %v", indexes)
	}
	if indexes := matchedAddressIndexes(nil, nil); indexes != nil {
		t.Fatalf("nil address filter indexes = %v", indexes)
	}
	if indexes := matchedMultiIndexes(nil, nil); indexes != nil {
		t.Fatalf("nil multi filter indexes = %v", indexes)
	}
}
