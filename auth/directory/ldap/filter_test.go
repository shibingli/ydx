package ldap

import (
	"errors"
	"reflect"
	"strings"
	"testing"
)

// TestParseFilterVectors verifies RFC 4515 parsing and canonical rendering. |
// TestParseFilterVectors 校验 RFC 4515 解析与规范渲染。
func TestParseFilterVectors(t *testing.T) {
	tests := []struct {
		input string
		want  string
		kind  any
	}{
		{input: "(cn=Babs Jensen)", want: "(cn=Babs Jensen)", kind: &EqualityFilter{}},
		{input: "(!(cn=Tim Howes))", want: "(!(cn=Tim Howes))", kind: &NotFilter{}},
		{input: "(&(objectClass=Person)(|(sn=Jensen)(cn=Babs J*)))", want: "(&(objectClass=Person)(|(sn=Jensen)(cn=Babs J*)))", kind: &AndFilter{}},
		{input: "(o=univ*of*mich*)", want: "(o=univ*of*mich*)", kind: &SubstringFilter{}},
		{input: "(seeAlso=)", want: "(seeAlso=)", kind: &EqualityFilter{}},
		{input: "(cn:caseExactMatch:=Fred Flintstone)", want: "(cn:caseExactMatch:=Fred Flintstone)", kind: &ExtensibleMatchFilter{}},
		{input: "(cn:=Betty Rubble)", want: "(cn:=Betty Rubble)", kind: &ExtensibleMatchFilter{}},
		{input: "(sn:dn:2.4.6.8.10:=Barney Rubble)", want: "(sn:dn:2.4.6.8.10:=Barney Rubble)", kind: &ExtensibleMatchFilter{}},
		{input: `(o=Parens R Us \28for all your parenthetical needs\29)`, want: "(o=Parens R Us \\28for all your parenthetical needs\\29)", kind: &EqualityFilter{}},
		{input: `(cn=*\2A*)`, want: `(cn=*\2A*)`, kind: &SubstringFilter{}},
		{input: `(filename=C:\5cMyFile)`, want: `(filename=C:\5CMyFile)`, kind: &EqualityFilter{}},
		{input: `(bin=\00\00\00\04)`, want: `(bin=\00\00\00\04)`, kind: &EqualityFilter{}},
		{input: `(sn=Lu\c4\8di\c4\87)`, want: `(sn=Lu\C4\8Di\C4\87)`, kind: &EqualityFilter{}},
		{input: `(1.3.6.1.4.1.1466.0=\04\02\48\69)`, want: `(1.3.6.1.4.1.1466.0=\04\02Hi)`, kind: &EqualityFilter{}},
		{input: "(age>=21)", want: "(age>=21)", kind: &GreaterOrEqualFilter{}},
		{input: "(age<=65)", want: "(age<=65)", kind: &LessOrEqualFilter{}},
		{input: "(cn~=Babs)", want: "(cn~=Babs)", kind: &ApproxFilter{}},
		{input: "(mail=*)", want: "(mail=*)", kind: &PresentFilter{}},
		{input: "(cn=John*Doe)", want: "(cn=John*Doe)", kind: &SubstringFilter{}},
		{input: "  (&(a=1)(b=2))  ", want: "(&(a=1)(b=2))", kind: &AndFilter{}},
	}
	for _, test := range tests {
		t.Run(test.input, func(t *testing.T) {
			filter, err := ParseFilter(test.input)
			if err != nil {
				t.Fatalf("ParseFilter: %v", err)
			}
			if got := reflect.TypeOf(filter); got != reflect.TypeOf(test.kind) {
				t.Fatalf("type %v, want %v", got, reflect.TypeOf(test.kind))
			}
			if got := filter.String(); got != test.want {
				t.Fatalf("String = %q, want %q", got, test.want)
			}
			if err := ValidateFilter(filter); err != nil {
				t.Fatalf("ValidateFilter: %v", err)
			}
		})
	}
}

// TestParseFilterInvalid verifies malformed filters are rejected. | TestParseFilterInvalid
// 校验畸形过滤器被拒绝。
func TestParseFilterInvalid(t *testing.T) {
	inputs := []string{
		"",
		"cn=test",
		"()",
		"(&)",
		"(|)",
		"(cn=foo",
		"(cn=foo))",
		`(cn=\zz)`,
		`(cn=\2)`,
		"(:=x)",
		"(&(cn=a)(cn=b)",
		"(cn:dn:dn:=x)",
		"(cn:rule:rule2:=x)",
		"(=x)",
		"(cn>=*)",
	}
	for _, input := range inputs {
		t.Run(input, func(t *testing.T) {
			if _, err := ParseFilter(input); err == nil {
				t.Fatalf("ParseFilter(%q) succeeded", input)
			} else if !errors.Is(err, ErrInvalidFilter) {
				t.Fatalf("error %v is not ErrInvalidFilter", err)
			}
		})
	}
}

// TestFilterBERRoundTrip verifies every filter type survives BER encoding. |
// TestFilterBERRoundTrip 校验每种过滤器类型都能通过 BER 编码往返。
func TestFilterBERRoundTrip(t *testing.T) {
	filters := []Filter{
		And(Equal("objectClass", "person"), Present("mail")),
		Or(Equal("uid", "alice"), Equal("uid", "bob")),
		Not(Equal("disabled", "true")),
		Equal("cn", "Babs Jensen"),
		Substrings("cn", "Bar", []string{"ney", "Rub"}, "ble"),
		Present("description"),
		GreaterOrEqual("age", "21"),
		LessOrEqual("age", "65"),
		Approximate("cn", "Babs"),
		ExtensibleMatch("1.2.840.113556.1.4.1941", "member", "cn=x", true),
		ExtensibleMatch("", "cn", "value", false),
	}
	for _, filter := range filters {
		encoder := newBEREncoder(128)
		encodeFilter(encoder, filter)
		reader := newBERReader(encoder.bytes())
		decoded, err := decodeFilter(reader)
		if err != nil {
			t.Fatalf("%s decode: %v", filter, err)
		}
		if err := reader.expectEnd(); err != nil {
			t.Fatalf("%s trailing: %v", filter, err)
		}
		if got, want := decoded.String(), filter.String(); got != want {
			t.Fatalf("round trip %q, want %q", got, want)
		}
	}
}

// TestFilterValidate verifies constructor constraints. | TestFilterValidate
// 校验构造器约束。
func TestFilterValidate(t *testing.T) {
	valid := []Filter{
		And(Equal("cn", "x")),
		Or(Present("cn")),
		Not(Equal("cn", "x")),
		Substrings("cn", "a", nil, "b"),
		Substrings("cn", "", []string{"a"}, ""),
		ExtensibleMatch("1.2.3", "", "x", false),
	}
	for _, filter := range valid {
		if err := ValidateFilter(filter); err != nil {
			t.Fatalf("%s: %v", filter, err)
		}
	}
	invalid := []Filter{
		nil,
		And(),
		Or(),
		Not(nil),
		Equal("", "x"),
		Present(""),
		Equal("bad attribute", "x"),
		Substrings("cn", "", nil, ""),
		&SubstringFilter{Attribute: "cn", Any: []string{""}},
		&ExtensibleMatchFilter{Value: "x"},
		&ExtensibleMatchFilter{MatchingRule: " ", Attribute: "cn", Value: "x"},
	}
	for _, filter := range invalid {
		if err := ValidateFilter(filter); !errors.Is(err, ErrInvalidFilter) {
			t.Fatalf("%#v: error %v", filter, err)
		}
	}
}

// TestEscapeFilterValue verifies RFC 4515 escaping. | TestEscapeFilterValue 校验 RFC 4515 转义。
func TestEscapeFilterValue(t *testing.T) {
	tests := []struct {
		input string
		want  string
	}{
		{input: "plain", want: "plain"},
		{input: "a*b", want: `a\2Ab`},
		{input: "a(b)", want: `a\28b\29`},
		{input: `a\b`, want: `a\5Cb`},
		{input: "a\x00b", want: `a\00b`},
		{input: "a\tb", want: `a\09b`},
		{input: "héllo", want: `h\C3\A9llo`},
	}
	for _, test := range tests {
		if got := EscapeFilterValue(test.input); got != test.want {
			t.Fatalf("EscapeFilterValue(%q) = %q, want %q", test.input, got, test.want)
		}
	}
}

// TestFilterConstructors verifies convenience constructors preserve values. |
// TestFilterConstructors 校验便捷构造器保留参数。
func TestFilterConstructors(t *testing.T) {
	sub := Substrings("cn", "a", []string{"", "b", ""}, "c")
	filter, ok := sub.(*SubstringFilter)
	if !ok {
		t.Fatalf("type %T", sub)
	}
	if !reflect.DeepEqual(filter.Any, []string{"b"}) {
		t.Fatalf("Any = %v", filter.Any)
	}
	ext, ok := ExtensibleMatch("rule", "attr", "value", true).(*ExtensibleMatchFilter)
	if !ok {
		t.Fatalf("extensible type")
	}
	if ext.MatchingRule != "rule" || ext.Attribute != "attr" || ext.Value != "value" || !ext.DNAttributes {
		t.Fatalf("extensible fields = %+v", ext)
	}
}

// TestParseFilterDepthLimit verifies that hostile deeply nested filters are rejected instead of
// exhausting the stack. | TestParseFilterDepthLimit 校验恶意深度嵌套过滤器被拒绝，避免耗尽栈。
func TestParseFilterDepthLimit(t *testing.T) {
	nested := func(depth int) string {
		return strings.Repeat("(!", depth) + "(cn=x)" + strings.Repeat(")", depth)
	}
	// The parser counts every filter node, so maxFilterDepth-1 nested NOT nodes plus the leaf
	// equality reach exactly maxFilterDepth. | 解析器统计每个过滤器节点，因此 maxFilterDepth-1 层
	// NOT 加叶子等值过滤器正好达到 maxFilterDepth。
	if _, err := ParseFilter(nested(maxFilterDepth - 1)); err != nil {
		t.Fatalf("filter at depth limit: %v", err)
	}
	if _, err := ParseFilter(nested(maxFilterDepth)); !errors.Is(err, ErrInvalidFilter) {
		t.Fatalf("filter above depth limit: %v", err)
	}
	deepAnd := strings.Repeat("(&", maxFilterDepth) + "(cn=x)" + strings.Repeat(")", maxFilterDepth)
	if _, err := ParseFilter(deepAnd); !errors.Is(err, ErrInvalidFilter) {
		t.Fatalf("AND above depth limit: %v", err)
	}
}

// TestFilterStringNilAndEdges verifies nil receivers and empty components render valid RFC 4515. |
// TestFilterStringNilAndEdges 校验空接收者与空组成部分渲染为合法 RFC 4515。
func TestFilterStringNilAndEdges(t *testing.T) {
	cases := []struct {
		filter Filter
		want   string
	}{
		{(*AndFilter)(nil), "(&)"},
		{&AndFilter{Filters: []Filter{nil, Equal("cn", "x")}}, "(&(cn=x))"},
		{(*OrFilter)(nil), "(|)"},
		{&OrFilter{Filters: []Filter{nil, Present("mail")}}, "(|(mail=*))"},
		{(*NotFilter)(nil), "(!)"},
		{&NotFilter{}, "(!)"},
		{(*EqualityFilter)(nil), "(=)"},
		{&EqualityFilter{Attribute: "cn", Value: "a*b"}, `(cn=a\2Ab)`},
		{(*SubstringFilter)(nil), "(=)"},
		{&SubstringFilter{Attribute: "cn", Initial: "a", Any: []string{"b", ""}, Final: "c"}, "(cn=a*b**c)"},
		{&SubstringFilter{Attribute: "cn", Initial: "a"}, "(cn=a*)"},
		{&SubstringFilter{Attribute: "cn", Final: "c"}, "(cn=*c)"},
		{(*PresentFilter)(nil), "(=*)"},
		{(*GreaterOrEqualFilter)(nil), "(>=)"},
		{&GreaterOrEqualFilter{Attribute: "age", Value: "21"}, "(age>=21)"},
		{(*LessOrEqualFilter)(nil), "(<=)"},
		{&LessOrEqualFilter{Attribute: "age", Value: "65"}, "(age<=65)"},
		{(*ApproxFilter)(nil), "(~=)"},
		{&ApproxFilter{Attribute: "cn", Value: "Babs"}, "(cn~=Babs)"},
		{(*ExtensibleMatchFilter)(nil), "(:=)"},
		{&ExtensibleMatchFilter{MatchingRule: "1.2.3", Value: "x"}, "(:1.2.3:=x)"},
		{&ExtensibleMatchFilter{Attribute: "cn", Value: "x"}, "(cn:=x)"},
		{&ExtensibleMatchFilter{MatchingRule: "1.2.3", Attribute: "cn", Value: "x", DNAttributes: true}, "(cn:dn:1.2.3:=x)"},
	}
	for _, testCase := range cases {
		if got := testCase.filter.String(); got != testCase.want {
			t.Fatalf("%#v String = %q, want %q", testCase.filter, got, testCase.want)
		}
	}
}

// TestFilterEncodeEdges verifies nil and empty filters encode without panicking. |
// TestFilterEncodeEdges 校验空过滤器编码不会 panic。
func TestFilterEncodeEdges(t *testing.T) {
	filters := []Filter{
		nil,
		(*AndFilter)(nil),
		&AndFilter{Filters: []Filter{nil}},
		(*OrFilter)(nil),
		(*NotFilter)(nil),
		(*EqualityFilter)(nil),
		(*SubstringFilter)(nil),
		(*PresentFilter)(nil),
		(*GreaterOrEqualFilter)(nil),
		(*LessOrEqualFilter)(nil),
		(*ApproxFilter)(nil),
		(*ExtensibleMatchFilter)(nil),
	}
	for _, filter := range filters {
		encoder := newBEREncoder(64)
		encodeFilter(encoder, filter)
		if len(encoder.bytes()) == 0 {
			t.Fatalf("%#v encoded no bytes", filter)
		}
	}
}

// TestParseAssertionValueEscapes verifies every RFC 4515 escape branch. |
// TestParseAssertionValueEscapes 校验每个 RFC 4515 转义分支。
func TestParseAssertionValueEscapes(t *testing.T) {
	valid := map[string]string{
		`(cn=\41)`:       "A",
		`(cn=\61)`:       "a",
		`(cn=\00)`:       "\x00",
		`(cn=\C3\A9)`:    "é",
		`(cn=a\2Ab)`:     "a*b",
		`(cn=a\28b\29c)`: "a(b)c",
		`(cn=a\5Cb)`:     `a\b`,
	}
	for input, want := range valid {
		filter, err := ParseFilter(input)
		if err != nil {
			t.Fatalf("ParseFilter(%q): %v", input, err)
		}
		equality, ok := filter.(*EqualityFilter)
		if !ok || equality.Value != want {
			t.Fatalf("ParseFilter(%q) = %#v, want value %q", input, filter, want)
		}
	}
	invalid := []string{`(cn=\)`, `(cn=\0)`, `(cn=\0g)`, `(cn=\g0)`}
	for _, input := range invalid {
		if _, err := ParseFilter(input); !errors.Is(err, ErrInvalidFilter) {
			t.Fatalf("ParseFilter(%q) error = %v", input, err)
		}
	}
}
