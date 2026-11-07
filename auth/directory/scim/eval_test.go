package scim

import (
	"reflect"
	"strings"
	"testing"
	"time"
)

// TestScalarValueKinds verifies every scalar projection branch, including time values used by
// dateTime attributes. | TestScalarValueKinds 校验每个标量投影分支，包括 dateTime 属性使用的
// 时间值。
func TestScalarValueKinds(t *testing.T) {
	instant := time.Date(2024, 5, 6, 7, 8, 9, 0, time.UTC)
	instantPtr := &instant
	var nilTime *time.Time
	multi := MultiValue{Value: "multi"}
	multiPtr := &multi
	address := Address{Formatted: "1 Main"}
	addressPtr := &address
	group := GroupValue{Value: "group"}
	groupPtr := &group
	member := GroupMember{Value: "member"}
	memberPtr := &member
	manager := Manager{Value: "manager"}
	managerPtr := &manager
	name := Name{Formatted: "Name"}
	namePtr := &name
	tests := []struct {
		name  string
		input any
		want  any
		ok    bool
	}{
		{name: "nil", input: nil, want: nil, ok: true},
		{name: "string", input: "x", want: "x", ok: true},
		{name: "bool", input: true, want: true, ok: true},
		{name: "float64", input: 1.5, want: 1.5, ok: true},
		{name: "float32", input: float32(1.5), want: 1.5, ok: true},
		{name: "int", input: 2, want: 2.0, ok: true},
		{name: "int8", input: int8(2), want: 2.0, ok: true},
		{name: "int16", input: int16(2), want: 2.0, ok: true},
		{name: "int32", input: int32(2), want: 2.0, ok: true},
		{name: "int64", input: int64(2), want: 2.0, ok: true},
		{name: "uint", input: uint(2), want: 2.0, ok: true},
		{name: "uint8", input: uint8(2), want: 2.0, ok: true},
		{name: "uint16", input: uint16(2), want: 2.0, ok: true},
		{name: "uint32", input: uint32(2), want: 2.0, ok: true},
		{name: "uint64", input: uint64(2), want: 2.0, ok: true},
		{name: "time", input: instant, want: instant, ok: true},
		{name: "time pointer", input: instantPtr, want: instant, ok: true},
		{name: "nil time pointer", input: nilTime, want: nil, ok: true},
		{name: "multi", input: multi, want: "multi", ok: true},
		{name: "multi pointer", input: multiPtr, want: "multi", ok: true},
		{name: "nil multi pointer", input: (*MultiValue)(nil), want: nil, ok: true},
		{name: "address", input: address, want: "1 Main", ok: true},
		{name: "address pointer", input: addressPtr, want: "1 Main", ok: true},
		{name: "nil address pointer", input: (*Address)(nil), want: nil, ok: true},
		{name: "group value", input: group, want: "group", ok: true},
		{name: "group value pointer", input: groupPtr, want: "group", ok: true},
		{name: "nil group value pointer", input: (*GroupValue)(nil), want: nil, ok: true},
		{name: "group member", input: member, want: "member", ok: true},
		{name: "group member pointer", input: memberPtr, want: "member", ok: true},
		{name: "nil group member pointer", input: (*GroupMember)(nil), want: nil, ok: true},
		{name: "manager", input: manager, want: "manager", ok: true},
		{name: "manager pointer", input: managerPtr, want: "manager", ok: true},
		{name: "nil manager pointer", input: (*Manager)(nil), want: nil, ok: true},
		{name: "name", input: name, want: "Name", ok: true},
		{name: "name pointer", input: namePtr, want: "Name", ok: true},
		{name: "nil name pointer", input: (*Name)(nil), want: nil, ok: true},
		{name: "map value", input: map[string]any{"value": "v"}, want: "v", ok: true},
		{name: "map formatted", input: map[string]any{"Formatted": "f"}, want: "f", ok: true},
		{name: "map display", input: map[string]any{"display": "d"}, want: "d", ok: true},
		{name: "map empty", input: map[string]any{"other": "x"}, want: nil, ok: false},
		{name: "unsupported", input: struct{}{}, want: nil, ok: false},
	}
	for _, testCase := range tests {
		t.Run(testCase.name, func(t *testing.T) {
			got, ok := scalarValue(testCase.input)
			if ok != testCase.ok || !reflect.DeepEqual(got, testCase.want) {
				t.Fatalf("scalarValue = (%#v, %v), want (%#v, %v)", got, ok, testCase.want, testCase.ok)
			}
		})
	}
}

// TestScalarStringHelpers verifies string, numeric and presence helpers. |
// TestScalarStringHelpers 校验字符串、数值与存在性辅助函数。
func TestScalarStringHelpers(t *testing.T) {
	instant := time.Date(2024, 1, 2, 3, 4, 5, 0, time.UTC)
	if text, ok := scalarString("x"); !ok || text != "x" {
		t.Fatalf("scalarString string = %q, %v", text, ok)
	}
	if text, ok := scalarString(true); !ok || text != "true" {
		t.Fatalf("scalarString true = %q, %v", text, ok)
	}
	if text, ok := scalarString(false); !ok || text != "false" {
		t.Fatalf("scalarString false = %q, %v", text, ok)
	}
	if text, ok := scalarString(2.5); !ok || text != "2.5" {
		t.Fatalf("scalarString number = %q, %v", text, ok)
	}
	if text, ok := scalarString(instant); !ok || text != formatTime(instant) {
		t.Fatalf("scalarString time = %q, %v", text, ok)
	}
	if _, ok := scalarString(2); ok {
		t.Fatalf("scalarString int accepted")
	}
	if !isStringScalar("x") || isStringScalar(1) {
		t.Fatalf("isStringScalar mismatch")
	}
	if got := scalarStringOf("x"); got != "x" {
		t.Fatalf("scalarStringOf = %q", got)
	}
	if got := scalarStringOf(1); got != "" {
		t.Fatalf("scalarStringOf non-string = %q", got)
	}
	numeric := []struct {
		input any
		want  float64
		ok    bool
	}{
		{float64(1), 1, true},
		{float32(2), 2, true},
		{int(3), 3, true},
		{int64(4), 4, true},
		{int32(5), 5, true},
		{"6.5", 6.5, true},
		{"bad", 0, false},
		{true, 0, false},
	}
	for _, testCase := range numeric {
		got, ok := numericScalar(testCase.input)
		if got != testCase.want || ok != testCase.ok {
			t.Fatalf("numericScalar(%#v) = %v, %v; want %v, %v", testCase.input, got, ok, testCase.want, testCase.ok)
		}
	}
	if nonEmptyScalar(nil) || nonEmptyScalar("") {
		t.Fatalf("empty scalars reported non-empty")
	}
	if !nonEmptyScalar("x") || !nonEmptyScalar(false) || !nonEmptyScalar(0) {
		t.Fatalf("non-empty scalars reported empty")
	}
	if !nonEmptyScalar(struct{}{}) {
		t.Fatalf("opaque non-nil value reported empty")
	}
}

// TestCompareOneLiteralKinds verifies null, boolean, numeric and string comparisons. |
// TestCompareOneLiteralKinds 校验 null、布尔、数值与字符串比较。
func TestCompareOneLiteralKinds(t *testing.T) {
	tests := []struct {
		name   string
		actual any
		op     compareOp
		want   literal
		expect bool
	}{
		{name: "null equal empty", actual: "", op: opEQ, want: literal{kind: litNull}, expect: true},
		{name: "null not equal value", actual: "x", op: opNE, want: literal{kind: litNull}, expect: true},
		{name: "null not equal nil", actual: nil, op: opNE, want: literal{kind: litNull}, expect: false},
		{name: "null unsupported op", actual: "x", op: opCO, want: literal{kind: litNull}, expect: false},
		{name: "bool equal", actual: true, op: opEQ, want: literal{kind: litBool, boolean: true}, expect: true},
		{name: "bool not equal", actual: true, op: opNE, want: literal{kind: litBool, boolean: false}, expect: true},
		{name: "bool other op", actual: true, op: opGT, want: literal{kind: litBool, boolean: true}, expect: false},
		{name: "bool type mismatch ne", actual: "true", op: opNE, want: literal{kind: litBool, boolean: true}, expect: true},
		{name: "bool type mismatch eq", actual: "true", op: opEQ, want: literal{kind: litBool, boolean: true}, expect: false},
		{name: "number equal", actual: 2.0, op: opEQ, want: literal{kind: litNumber, text: "2", number: 2}, expect: true},
		{name: "number greater", actual: "3", op: opGT, want: literal{kind: litNumber, text: "2", number: 2}, expect: true},
		{name: "number less", actual: 1.0, op: opLT, want: literal{kind: litNumber, text: "2", number: 2}, expect: true},
		{name: "number non-numeric ne", actual: "x", op: opNE, want: literal{kind: litNumber, text: "2", number: 2}, expect: true},
		{name: "number non-numeric eq", actual: "x", op: opEQ, want: literal{kind: litNumber, text: "2", number: 2}, expect: false},
		{name: "string equal fold", actual: "Alice", op: opEQ, want: literal{kind: litString, text: "alice"}, expect: true},
		{name: "string not equal", actual: "Alice", op: opNE, want: literal{kind: litString, text: "bob"}, expect: true},
		{name: "string contains", actual: "Alice Smith", op: opCO, want: literal{kind: litString, text: "SMITH"}, expect: true},
		{name: "string starts", actual: "Alice", op: opSW, want: literal{kind: litString, text: "AL"}, expect: true},
		{name: "string ends", actual: "Alice", op: opEW, want: literal{kind: litString, text: "CE"}, expect: true},
		{name: "string greater", actual: "b", op: opGT, want: literal{kind: litString, text: "a"}, expect: true},
		{name: "string greater equal", actual: "a", op: opGE, want: literal{kind: litString, text: "a"}, expect: true},
		{name: "string less", actual: "a", op: opLT, want: literal{kind: litString, text: "b"}, expect: true},
		{name: "string less equal", actual: "b", op: opLE, want: literal{kind: litString, text: "b"}, expect: true},
		{name: "unsupported value ne", actual: nil, op: opNE, want: literal{kind: litString, text: "x"}, expect: true},
		{name: "unsupported value eq", actual: nil, op: opEQ, want: literal{kind: litString, text: "x"}, expect: false},
	}
	for _, testCase := range tests {
		t.Run(testCase.name, func(t *testing.T) {
			if got := compareOne(testCase.actual, testCase.op, testCase.want); got != testCase.expect {
				t.Fatalf("compareOne = %v, want %v", got, testCase.expect)
			}
		})
	}
}

// TestCompareOrderedAndFloat verifies ordered date, numeric and textual comparison. |
// TestCompareOrderedAndFloat 校验有序日期、数值与文本比较。
func TestCompareOrderedAndFloat(t *testing.T) {
	if !compareOrdered("2024-01-02T00:00:00Z", "2024-01-01T00:00:00Z", opGT) {
		t.Fatalf("date comparison failed")
	}
	if !compareOrdered("10", "2", opGT) {
		t.Fatalf("numeric comparison failed")
	}
	if !compareOrdered("b", "A", opGT) {
		t.Fatalf("text comparison failed")
	}
	if !compareOrdered("a", "a", opGE) || !compareOrdered("a", "a", opLE) {
		t.Fatalf("text equality comparisons failed")
	}
	if compareOrdered("a", "b", opGT) || compareOrdered("b", "a", opLT) {
		t.Fatalf("text ordering inverted")
	}
	if compareOrdered("a", "b", opEQ) {
		t.Fatalf("unsupported operator matched")
	}
	if !compareFloat(1, 2, opLT) || !compareFloat(2, 2, opLE) || !compareFloat(2, 1, opGT) ||
		!compareFloat(2, 2, opGE) || !compareFloat(2, 2, opEQ) || !compareFloat(2, 1, opNE) {
		t.Fatalf("compareFloat mismatch")
	}
	if compareFloat(1, 2, opCO) {
		t.Fatalf("compareFloat unsupported op matched")
	}
}

// TestFlattenValueVariants verifies JSON-like value flattening. | TestFlattenValueVariants 校验类
// JSON 值展开。
func TestFlattenValueVariants(t *testing.T) {
	if got := flattenValue(nil); !reflect.DeepEqual(got, []any{nil}) {
		t.Fatalf("nil = %#v", got)
	}
	list := []any{"a", "b"}
	if got := flattenValue(list); !reflect.DeepEqual(got, list) {
		t.Fatalf("[]any = %#v", got)
	}
	if got := flattenValue([]string{"a"}); !reflect.DeepEqual(got, []any{"a"}) {
		t.Fatalf("[]string = %#v", got)
	}
	multi := []MultiValue{{Value: "m"}}
	if got := flattenValue(multi); len(got) != 1 || got[0].(*MultiValue).Value != "m" {
		t.Fatalf("[]MultiValue = %#v", got)
	}
	addresses := []Address{{Locality: "L"}}
	if got := flattenValue(addresses); len(got) != 1 || got[0].(*Address).Locality != "L" {
		t.Fatalf("[]Address = %#v", got)
	}
	members := []GroupMember{{Value: "u"}}
	if got := flattenValue(members); len(got) != 1 || got[0].(*GroupMember).Value != "u" {
		t.Fatalf("[]GroupMember = %#v", got)
	}
	groups := []GroupValue{{Value: "g"}}
	if got := flattenValue(groups); len(got) != 1 || got[0].(*GroupValue).Value != "g" {
		t.Fatalf("[]GroupValue = %#v", got)
	}
	if got := flattenValue("scalar"); !reflect.DeepEqual(got, []any{"scalar"}) {
		t.Fatalf("scalar = %#v", got)
	}
	if got := multiValues(multi); len(got) != 1 || got[0].(*MultiValue) != &multi[0] {
		t.Fatalf("multiValues = %#v", got)
	}
	if got := addressValues(addresses); len(got) != 1 || got[0].(*Address) != &addresses[0] {
		t.Fatalf("addressValues = %#v", got)
	}
	if got := groupValues(groups); len(got) != 1 || got[0].(*GroupValue) != &groups[0] {
		t.Fatalf("groupValues = %#v", got)
	}
	if got := groupMemberValues(members); len(got) != 1 || got[0].(*GroupMember) != &members[0] {
		t.Fatalf("groupMemberValues = %#v", got)
	}
	if got := stringValues([]string{"a"}); !reflect.DeepEqual(got, []any{"a"}) {
		t.Fatalf("stringValues = %#v", got)
	}
}

// TestAttributeValuesByTargetType verifies attribute lookup for every supported value and pointer
// type. | TestAttributeValuesByTargetType 校验每种受支持值与指针类型的属性查找。
func TestAttributeValuesByTargetType(t *testing.T) {
	user := testUser()
	group := &Group{ID: "g1", DisplayName: "Admins", Schemas: []string{GroupSchema},
		Members: []GroupMember{{Value: "u1"}}, Meta: &Meta{Version: "1"}}
	enterprise := user.EnterpriseUser
	multi := MultiValue{Value: "m", Display: "M", Type: "work", Primary: true, Ref: "ref"}
	address := Address{Formatted: "F", StreetAddress: "S", Locality: "L", Region: "R",
		PostalCode: "P", Country: "C", Type: "work", Primary: true}
	groupValue := GroupValue{Value: "g", Display: "G", Type: "Group", Ref: "ref"}
	member := GroupMember{Value: "m", Display: "M", Type: "User", Ref: "ref"}
	manager := Manager{Value: "v", DisplayName: "D", Ref: "ref"}
	name := Name{Formatted: "F", FamilyName: "Fa", GivenName: "G", MiddleName: "M",
		HonorificPrefix: "P", HonorificSuffix: "S"}
	tests := []struct {
		name   string
		target any
		attr   string
		want   []any
		ok     bool
	}{
		{name: "nil target", target: nil, attr: "id", ok: false},
		{name: "nil user pointer", target: (*User)(nil), attr: "id", ok: false},
		{name: "user value", target: *user, attr: "userName", want: []any{"Alice"}, ok: true},
		{name: "nil group pointer", target: (*Group)(nil), attr: "id", ok: false},
		{name: "group value", target: *group, attr: "displayName", want: []any{"Admins"}, ok: true},
		{name: "nil enterprise pointer", target: (*EnterpriseUser)(nil), attr: "department", ok: false},
		{name: "enterprise value", target: *enterprise, attr: "department", want: []any{"Engineering"}, ok: true},
		{name: "nil name pointer", target: (*Name)(nil), attr: "formatted", ok: false},
		{name: "name value", target: name, attr: "givenName", want: []any{"G"}, ok: true},
		{name: "nil manager pointer", target: (*Manager)(nil), attr: "value", ok: false},
		{name: "manager value", target: manager, attr: "displayName", want: []any{"D"}, ok: true},
		{name: "nil multi pointer", target: (*MultiValue)(nil), attr: "value", ok: false},
		{name: "multi value", target: multi, attr: "type", want: []any{"work"}, ok: true},
		{name: "nil address pointer", target: (*Address)(nil), attr: "locality", ok: false},
		{name: "address value", target: address, attr: "country", want: []any{"C"}, ok: true},
		{name: "nil group value pointer", target: (*GroupValue)(nil), attr: "value", ok: false},
		{name: "group value attr", target: groupValue, attr: "display", want: []any{"G"}, ok: true},
		{name: "nil member pointer", target: (*GroupMember)(nil), attr: "value", ok: false},
		{name: "member value", target: member, attr: "type", want: []any{"User"}, ok: true},
		{name: "map exact", target: map[string]any{"userName": "Alice"}, attr: "userName", want: []any{"Alice"}, ok: true},
		{name: "map case insensitive", target: map[string]any{"UserName": "Alice"}, attr: "username", want: []any{"Alice"}, ok: true},
		{name: "map missing", target: map[string]any{"other": "x"}, attr: "userName", ok: false},
		{name: "string map", target: map[string]string{"UserName": "Alice"}, attr: "username", want: []any{"Alice"}, ok: true},
		{name: "string map missing", target: map[string]string{"other": "x"}, attr: "userName", ok: false},
		{name: "unsupported target", target: 42, attr: "id", ok: false},
	}
	for _, testCase := range tests {
		t.Run(testCase.name, func(t *testing.T) {
			got, ok := attributeValues(testCase.target, testCase.attr)
			if ok != testCase.ok || !reflect.DeepEqual(got, testCase.want) {
				t.Fatalf("attributeValues = (%#v, %v), want (%#v, %v)", got, ok, testCase.want, testCase.ok)
			}
		})
	}
}

// TestSchemaTargetSelection verifies schema-qualified path resolution. |
// TestSchemaTargetSelection 校验带 Schema 限定的路径解析。
func TestSchemaTargetSelection(t *testing.T) {
	user := testUser()
	enterprise := user.EnterpriseUser
	coreMap := map[string]any{"userName": "Alice"}
	enterpriseMap := map[string]any{EnterpriseUserSchema: map[string]any{"department": "Engineering"}}
	enterpriseCaseMap := map[string]any{"URN:IETF:PARAMS:SCIM:SCHEMAS:EXTENSION:ENTERPRISE:2.0:USER": map[string]any{"division": "R&D"}}
	tests := []struct {
		name     string
		resource any
		schema   string
		want     any
		ok       bool
	}{
		{name: "no schema", resource: user, schema: "", want: user, ok: true},
		{name: "enterprise user", resource: user, schema: EnterpriseUserSchema, want: enterprise, ok: true},
		{name: "enterprise missing", resource: &User{}, schema: EnterpriseUserSchema, ok: false},
		{name: "enterprise user value", resource: *user, schema: EnterpriseUserSchema, want: enterprise, ok: true},
		{name: "enterprise direct", resource: enterprise, schema: EnterpriseUserSchema, want: enterprise, ok: true},
		{name: "enterprise direct nil", resource: (*EnterpriseUser)(nil), schema: EnterpriseUserSchema, ok: false},
		{name: "enterprise map", resource: enterpriseMap, schema: EnterpriseUserSchema, want: map[string]any{"department": "Engineering"}, ok: true},
		{name: "enterprise map case", resource: enterpriseCaseMap, schema: EnterpriseUserSchema, want: map[string]any{"division": "R&D"}, ok: true},
		{name: "enterprise map missing", resource: coreMap, schema: EnterpriseUserSchema, ok: false},
		{name: "enterprise unsupported", resource: 42, schema: EnterpriseUserSchema, ok: false},
		{name: "core user pointer", resource: user, schema: UserSchema, want: user, ok: true},
		{name: "core user value", resource: *user, schema: UserSchema, want: *user, ok: true},
		{name: "core user map", resource: coreMap, schema: UserSchema, want: coreMap, ok: true},
		{name: "core user unsupported", resource: enterprise, schema: UserSchema, want: enterprise, ok: true},
		{name: "core group pointer", resource: &Group{ID: "g"}, schema: GroupSchema, want: &Group{ID: "g"}, ok: true},
		{name: "core group value", resource: Group{ID: "g"}, schema: GroupSchema, want: Group{ID: "g"}, ok: true},
		{name: "core group map", resource: coreMap, schema: GroupSchema, want: coreMap, ok: true},
		{name: "core group unsupported", resource: 42, schema: GroupSchema, ok: false},
		{name: "unknown schema map", resource: enterpriseMap, schema: "urn:example:2.0:Thing", ok: false},
		{name: "unknown schema non-map", resource: 42, schema: "urn:example:2.0:Thing", ok: false},
	}
	for _, testCase := range tests {
		t.Run(testCase.name, func(t *testing.T) {
			got, ok := schemaTarget(testCase.resource, testCase.schema)
			if ok != testCase.ok {
				t.Fatalf("schemaTarget ok = %v, want %v", ok, testCase.ok)
			}
			if testCase.ok && !reflect.DeepEqual(got, testCase.want) {
				t.Fatalf("schemaTarget = %#v, want %#v", got, testCase.want)
			}
		})
	}
}

// TestAttributePathValuesAndFirstValue verifies value-filter projection, sub-attribute projection
// and first-value extraction. | TestAttributePathValuesAndFirstValue 校验值过滤器投影、子属性投影与
// 首值提取。
func TestAttributePathValuesAndFirstValue(t *testing.T) {
	user := testUser()
	path, err := ParseAttributePath(`emails[type eq "work"].value`)
	if err != nil {
		t.Fatalf("ParseAttributePath: %v", err)
	}
	values, ok := path.values(user)
	if !ok || !reflect.DeepEqual(values, []any{"alice@example.com"}) {
		t.Fatalf("values = %#v, %v", values, ok)
	}
	first, ok := path.FirstValue(user)
	if !ok || first != "alice@example.com" {
		t.Fatalf("FirstValue = %#v, %v", first, ok)
	}
	if _, ok := path.FirstValue(&User{}); ok {
		t.Fatalf("FirstValue matched missing attribute")
	}
	bare := &AttributePath{}
	if values, ok := bare.values(user); !ok || len(values) != 1 || values[0] != user {
		t.Fatalf("bare path = %#v, %v", values, ok)
	}
	opaque := struct{}{}
	if values, ok := bare.values(opaque); !ok || len(values) != 1 || values[0] != opaque {
		t.Fatalf("bare path opaque = %#v, %v", values, ok)
	}
	unknown := &AttributePath{Attribute: "missing"}
	if _, ok := unknown.values(user); ok {
		t.Fatalf("unknown attribute matched")
	}
	filtered := &AttributePath{Attribute: "emails", ValueFilter: mustFilter(t, `type eq "other"`)}
	if _, ok := filtered.values(user); ok {
		t.Fatalf("non-matching value filter resolved")
	}
	projected := &AttributePath{Attribute: "emails", SubAttribute: "missing"}
	if _, ok := projected.values(user); ok {
		t.Fatalf("missing sub-attribute resolved")
	}
	unknownSchema := &AttributePath{Schema: "urn:example:2.0:User", Attribute: "userName"}
	if _, ok := unknownSchema.values(user); ok {
		t.Fatalf("unknown schema resolved")
	}
}

// mustFilter parses a filter or fails the test. | mustFilter 解析过滤器，失败时终止测试。
func mustFilter(t *testing.T, text string) Filter {
	t.Helper()
	filter, err := ParseFilter(text)
	if err != nil {
		t.Fatalf("ParseFilter(%q): %v", text, err)
	}
	return filter
}

// TestUserAttributeValuesExhaustive verifies every User attribute name. |
// TestUserAttributeValuesExhaustive 校验每个 User 属性名。
func TestUserAttributeValuesExhaustive(t *testing.T) {
	user := testUser()
	user.ExternalID = "ext"
	user.ProfileURL = "https://example.com/alice"
	user.UserType = "Employee"
	user.PreferredLanguage = "en"
	user.Locale = "en-US"
	user.Timezone = "UTC"
	user.IMs = []MultiValue{{Value: "alice-im"}}
	user.Photos = []MultiValue{{Value: "https://example.com/a.png"}}
	user.Entitlements = []MultiValue{{Value: "ent"}}
	user.Roles = []MultiValue{{Value: "admin"}}
	user.X509Certificates = []MultiValue{{Value: "cert"}}
	user.Groups = []GroupValue{{Value: "g1", Display: "Admins"}}
	user.Meta = &Meta{Version: `W/"1"`}
	tests := []struct {
		attr string
		want []any
		ok   bool
	}{
		{"id", []any{"u1"}, true},
		{"externalId", []any{"ext"}, true},
		{"userName", []any{"Alice"}, true},
		{"displayName", []any{"Alice Smith"}, true},
		{"nickName", []any{"Ali"}, true},
		{"profileUrl", []any{"https://example.com/alice"}, true},
		{"title", []any{"Engineer"}, true},
		{"userType", []any{"Employee"}, true},
		{"preferredLanguage", []any{"en"}, true},
		{"locale", []any{"en-US"}, true},
		{"timezone", []any{"UTC"}, true},
		{"active", []any{true}, true},
		{"emails", []any{&user.Emails[0], &user.Emails[1]}, true},
		{"phoneNumbers", []any{&user.PhoneNumbers[0]}, true},
		{"ims", []any{&user.IMs[0]}, true},
		{"photos", []any{&user.Photos[0]}, true},
		{"entitlements", []any{&user.Entitlements[0]}, true},
		{"roles", []any{&user.Roles[0]}, true},
		{"x509Certificates", []any{&user.X509Certificates[0]}, true},
		{"groups", []any{&user.Groups[0]}, true},
		{"meta", []any{user.Meta}, true},
		{"schemas", []any{UserSchema}, true},
		{"password", nil, false},
		{"unknown", nil, false},
	}
	for _, testCase := range tests {
		values, ok := userAttributeValues(user, lowerName(testCase.attr))
		if ok != testCase.ok || !valueSliceEqual(values, testCase.want) {
			t.Fatalf("userAttributeValues(%q) = (%#v, %v), want (%#v, %v)", testCase.attr, values, ok, testCase.want, testCase.ok)
		}
	}
	user.Meta = nil
	if _, ok := userAttributeValues(user, "meta"); ok {
		t.Fatalf("nil meta resolved")
	}
	empty := &User{}
	if values, ok := userAttributeValues(empty, "name"); ok {
		t.Fatalf("nil name resolved: %#v", values)
	}
	if values, ok := userAttributeValues(empty, lowerName(EnterpriseUserSchema)); ok {
		t.Fatalf("nil enterprise resolved: %#v", values)
	}
	if values, ok := userAttributeValues(user, lowerName(EnterpriseUserSchema)); !ok || len(values) != 1 {
		t.Fatalf("enterprise schema = %#v, %v", values, ok)
	}
}

// lowerName lowercases an attribute name for direct helper calls. | lowerName 为直接辅助函数调用
// 把属性名转为小写。
func lowerName(name string) string {
	return strings.ToLower(name)
}

// valueSliceEqual compares attribute value slices by deep equality. | valueSliceEqual 以深比较比较
// 属性值切片。
func valueSliceEqual(got, want []any) bool {
	return reflect.DeepEqual(got, want)
}

// TestGroupAndComplexAttributeValues verifies Group, enterprise and complex attribute names. |
// TestGroupAndComplexAttributeValues 校验 Group、企业扩展与复杂属性名。
func TestGroupAndComplexAttributeValues(t *testing.T) {
	group := &Group{ID: "g1", ExternalID: "ext", DisplayName: "Admins",
		Members: []GroupMember{{Value: "u1"}}, Meta: &Meta{Version: `W/"1"`}, Schemas: []string{GroupSchema}}
	name := &Name{Formatted: "F", FamilyName: "Fa", GivenName: "G", MiddleName: "M",
		HonorificPrefix: "P", HonorificSuffix: "S"}
	manager := &Manager{Value: "v", DisplayName: "D", Ref: "r"}
	multi := &MultiValue{Value: "v", Display: "D", Type: "T", Primary: true, Ref: "r"}
	address := &Address{Formatted: "F", StreetAddress: "S", Locality: "L", Region: "R",
		PostalCode: "P", Country: "C", Type: "T", Primary: true}
	groupValue := &GroupValue{Value: "v", Display: "D", Type: "T", Ref: "r"}
	member := &GroupMember{Value: "v", Display: "D", Type: "T", Ref: "r"}
	enterprise := &EnterpriseUser{EmployeeNumber: "E", CostCenter: "C", Organization: "O",
		Division: "D", Department: "Dep", Manager: manager}
	type lookup struct {
		attr string
		want []any
		ok   bool
	}
	groupTests := []lookup{
		{"id", []any{"g1"}, true},
		{"externalId", []any{"ext"}, true},
		{"displayName", []any{"Admins"}, true},
		{"members", []any{&group.Members[0]}, true},
		{"meta", []any{group.Meta}, true},
		{"schemas", []any{GroupSchema}, true},
		{"unknown", nil, false},
	}
	for _, testCase := range groupTests {
		values, ok := groupAttributeValues(group, lowerName(testCase.attr))
		if ok != testCase.ok || !reflect.DeepEqual(values, testCase.want) {
			t.Fatalf("groupAttributeValues(%q) = (%#v, %v)", testCase.attr, values, ok)
		}
	}
	group.Meta = nil
	if _, ok := groupAttributeValues(group, "meta"); ok {
		t.Fatalf("nil group meta resolved")
	}
	enterpriseTests := []lookup{
		{"employeeNumber", []any{"E"}, true},
		{"costCenter", []any{"C"}, true},
		{"organization", []any{"O"}, true},
		{"division", []any{"D"}, true},
		{"department", []any{"Dep"}, true},
		{"manager", []any{manager}, true},
		{"unknown", nil, false},
	}
	for _, testCase := range enterpriseTests {
		values, ok := enterpriseAttributeValues(enterprise, lowerName(testCase.attr))
		if ok != testCase.ok || !reflect.DeepEqual(values, testCase.want) {
			t.Fatalf("enterpriseAttributeValues(%q) = (%#v, %v)", testCase.attr, values, ok)
		}
	}
	enterprise.Manager = nil
	if _, ok := enterpriseAttributeValues(enterprise, "manager"); ok {
		t.Fatalf("nil manager resolved")
	}
	nameTests := []lookup{
		{"formatted", []any{"F"}, true},
		{"familyName", []any{"Fa"}, true},
		{"givenName", []any{"G"}, true},
		{"middleName", []any{"M"}, true},
		{"honorificPrefix", []any{"P"}, true},
		{"honorificSuffix", []any{"S"}, true},
		{"unknown", nil, false},
	}
	for _, testCase := range nameTests {
		values, ok := nameAttributeValues(name, lowerName(testCase.attr))
		if ok != testCase.ok || !reflect.DeepEqual(values, testCase.want) {
			t.Fatalf("nameAttributeValues(%q) = (%#v, %v)", testCase.attr, values, ok)
		}
	}
	managerTests := []lookup{
		{"value", []any{"v"}, true},
		{"displayName", []any{"D"}, true},
		{"$ref", []any{"r"}, true},
		{"ref", []any{"r"}, true},
		{"unknown", nil, false},
	}
	for _, testCase := range managerTests {
		values, ok := managerAttributeValues(manager, lowerName(testCase.attr))
		if ok != testCase.ok || !reflect.DeepEqual(values, testCase.want) {
			t.Fatalf("managerAttributeValues(%q) = (%#v, %v)", testCase.attr, values, ok)
		}
	}
	multiTests := []lookup{
		{"value", []any{"v"}, true},
		{"display", []any{"D"}, true},
		{"type", []any{"T"}, true},
		{"primary", []any{true}, true},
		{"$ref", []any{"r"}, true},
		{"ref", []any{"r"}, true},
		{"unknown", nil, false},
	}
	for _, testCase := range multiTests {
		values, ok := multiAttributeValues(multi, lowerName(testCase.attr))
		if ok != testCase.ok || !reflect.DeepEqual(values, testCase.want) {
			t.Fatalf("multiAttributeValues(%q) = (%#v, %v)", testCase.attr, values, ok)
		}
	}
	addressTests := []lookup{
		{"formatted", []any{"F"}, true},
		{"streetAddress", []any{"S"}, true},
		{"locality", []any{"L"}, true},
		{"region", []any{"R"}, true},
		{"postalCode", []any{"P"}, true},
		{"country", []any{"C"}, true},
		{"type", []any{"T"}, true},
		{"primary", []any{true}, true},
		{"unknown", nil, false},
	}
	for _, testCase := range addressTests {
		values, ok := addressAttributeValues(address, lowerName(testCase.attr))
		if ok != testCase.ok || !reflect.DeepEqual(values, testCase.want) {
			t.Fatalf("addressAttributeValues(%q) = (%#v, %v)", testCase.attr, values, ok)
		}
	}
	valueTests := []lookup{
		{"value", []any{"v"}, true},
		{"display", []any{"D"}, true},
		{"type", []any{"T"}, true},
		{"$ref", []any{"r"}, true},
		{"ref", []any{"r"}, true},
		{"unknown", nil, false},
	}
	for _, testCase := range valueTests {
		values, ok := groupValueAttributeValues(groupValue, lowerName(testCase.attr))
		if ok != testCase.ok || !reflect.DeepEqual(values, testCase.want) {
			t.Fatalf("groupValueAttributeValues(%q) = (%#v, %v)", testCase.attr, values, ok)
		}
		values, ok = groupMemberAttributeValues(member, lowerName(testCase.attr))
		if ok != testCase.ok || !reflect.DeepEqual(values, testCase.want) {
			t.Fatalf("groupMemberAttributeValues(%q) = (%#v, %v)", testCase.attr, values, ok)
		}
	}
	if sub, ok := subValue(multi, "type"); !ok || sub != "T" {
		t.Fatalf("subValue = %#v, %v", sub, ok)
	}
	if _, ok := subValue(multi, "missing"); ok {
		t.Fatalf("subValue matched missing sub-attribute")
	}
	if raw, ok := ciMapValue(map[string]any{"Key": "v"}, "key"); !ok || raw != "v" {
		t.Fatalf("ciMapValue = %#v, %v", raw, ok)
	}
	if _, ok := ciMapValue(map[string]any{"other": "v"}, "key"); ok {
		t.Fatalf("ciMapValue matched missing key")
	}
}

// TestSortTextAndSortPath verifies sorting through complex paths and fallbacks. |
// TestSortTextAndSortPath 校验通过复杂路径与回退的排序。
func TestSortTextAndSortPath(t *testing.T) {
	users := []*User{
		{UserName: "b", Emails: []MultiValue{{Value: "b@example.com"}}},
		{UserName: "a", Emails: []MultiValue{{Value: "a@example.com"}}},
		{UserName: "c"},
	}
	SortUsers(users, "emails.value", SortAscending)
	if users[0].UserName != "c" || users[1].UserName != "a" || users[2].UserName != "b" {
		t.Fatalf("email sort = %q, %q, %q", users[0].UserName, users[1].UserName, users[2].UserName)
	}
	SortUsers(users, "emails.value", SortDescending)
	if users[0].UserName != "b" || users[2].UserName != "c" {
		t.Fatalf("email descending sort = %q, %q, %q", users[0].UserName, users[1].UserName, users[2].UserName)
	}
	groups := []*Group{
		{DisplayName: "b", Members: []GroupMember{{Value: "2"}}},
		{DisplayName: "a", Members: []GroupMember{{Value: "1"}}},
	}
	SortGroups(groups, "members.value", SortAscending)
	if groups[0].DisplayName != "a" {
		t.Fatalf("member sort = %q", groups[0].DisplayName)
	}
	if path := sortPath("invalid path!", "userName"); path == nil || path.Attribute != "userName" {
		t.Fatalf("sortPath fallback = %#v", path)
	}
	if text := sortText(&User{}, mustPath(t, "userName")); text != "" {
		t.Fatalf("sortText missing = %q", text)
	}
	if text := sortText(struct{}{}, mustPath(t, "userName")); text != "" {
		t.Fatalf("sortText unsupported = %q", text)
	}
	instant := time.Date(2024, 2, 3, 4, 5, 6, 0, time.UTC)
	if text := sortText(map[string]any{"when": instant}, mustPath(t, "when")); text != formatTime(instant) {
		t.Fatalf("sortText time = %q", text)
	}
}

// mustPath parses an attribute path or fails the test. | mustPath 解析属性路径，失败时终止测试。
func mustPath(t *testing.T, text string) *AttributePath {
	t.Helper()
	path, err := ParseAttributePath(text)
	if err != nil {
		t.Fatalf("ParseAttributePath(%q): %v", text, err)
	}
	return path
}

// TestFilterMatchTimeValues verifies dateTime comparison for map resources carrying time.Time. |
// TestFilterMatchTimeValues 校验携带 time.Time 的映射资源按 dateTime 比较。
func TestFilterMatchTimeValues(t *testing.T) {
	instant := time.Date(2024, 6, 7, 8, 9, 10, 0, time.UTC)
	resource := map[string]any{
		"created":  instant,
		"updated":  &instant,
		"optional": (*time.Time)(nil),
	}
	cases := []struct {
		filter string
		want   bool
	}{
		{`created gt "2024-06-01T00:00:00Z"`, true},
		{`updated lt "2025-01-01T00:00:00Z"`, true},
		{`created eq "2024-06-07T08:09:10Z"`, true},
		{`optional pr`, false},
		{`optional eq null`, true},
	}
	for _, testCase := range cases {
		filter := mustFilter(t, testCase.filter)
		if got := filter.Match(resource); got != testCase.want {
			t.Fatalf("Match(%q) = %v, want %v", testCase.filter, got, testCase.want)
		}
	}
}
