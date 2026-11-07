package scim

import (
	"errors"
	"strings"
	"testing"
)

// testUser returns a User fixture for filter evaluation. | testUser 返回用于过滤器求值的 User 测试
// 数据。
func testUser() *User {
	return &User{
		Schemas:     []string{UserSchema},
		ID:          "u1",
		UserName:    "Alice",
		DisplayName: "Alice Smith",
		NickName:    "Ali",
		Title:       "Engineer",
		Active:      boolPtr(true),
		Name: &Name{
			Formatted:  "Alice Smith",
			FamilyName: "Smith",
			GivenName:  "Alice",
		},
		Emails: []MultiValue{
			{Value: "alice@example.com", Type: "work", Primary: true},
			{Value: "alice@home.example", Type: "home"},
		},
		PhoneNumbers: []MultiValue{{Value: "+1-555-0100", Type: "work"}},
		Addresses: []Address{
			{Formatted: "1 Main St, Springfield", Locality: "Springfield", Country: "US", Type: "work", Primary: true},
			{Formatted: "2 Side St, Paris", Locality: "Paris", Country: "FR", Type: "home"},
		},
		EnterpriseUser: &EnterpriseUser{
			EmployeeNumber: "E-42",
			Department:     "Engineering",
			Organization:   "Acme",
			Manager:        &Manager{Value: "m1", DisplayName: "Bob Manager"},
		},
	}
}

func TestParseFilterComparisonOperators(t *testing.T) {
	user := testUser()
	cases := []struct {
		name   string
		filter string
		want   bool
	}{
		{"eq case insensitive value", `userName eq "alice"`, true},
		{"eq attribute case insensitive", `USERNAME EQ "Alice"`, true},
		{"ne", `userName ne "bob"`, true},
		{"ne false", `userName ne "alice"`, false},
		{"co", `displayName co "smith"`, true},
		{"co none", `displayName co "jones"`, false},
		{"sw", `displayName sw "alice"`, true},
		{"ew", `displayName ew "smith"`, true},
		{"boolean eq", `active eq true`, true},
		{"boolean ne", `active ne false`, true},
		{"id", `id eq "u1"`, true},
	}
	for _, testCase := range cases {
		t.Run(testCase.name, func(t *testing.T) {
			filter, err := ParseFilter(testCase.filter)
			if err != nil {
				t.Fatalf("ParseFilter(%q) error = %v", testCase.filter, err)
			}
			if got := filter.Match(user); got != testCase.want {
				t.Fatalf("Match(%q) = %v, want %v", testCase.filter, got, testCase.want)
			}
		})
	}
}

func TestParseFilterNumericAndDateOperators(t *testing.T) {
	resource := map[string]any{
		"age":     float64(30),
		"created": "2024-01-02T03:04:05Z",
		"mixed":   float64(2.5),
	}
	cases := []struct {
		filter string
		want   bool
	}{
		{"age gt 20", true},
		{"age ge 30", true},
		{"age lt 31", true},
		{"age le 30", true},
		{"age gt 30", false},
		{"age eq 30", true},
		{"mixed eq 2.5", true},
		{"created gt \"2024-01-01T00:00:00Z\"", true},
		{"created lt \"2024-01-01T00:00:00Z\"", false},
	}
	for _, testCase := range cases {
		filter, err := ParseFilter(testCase.filter)
		if err != nil {
			t.Fatalf("ParseFilter(%q) error = %v", testCase.filter, err)
		}
		if got := filter.Match(resource); got != testCase.want {
			t.Fatalf("Match(%q) = %v, want %v", testCase.filter, got, testCase.want)
		}
	}
}

func TestParseFilterValueFilterAndSubAttribute(t *testing.T) {
	user := testUser()
	cases := []struct {
		filter string
		want   bool
	}{
		{`emails[type eq "work"].value eq "alice@example.com"`, true},
		{`emails[type eq "work"].value ew "@example.com"`, true},
		{`emails[type eq "home"].value co "home"`, true},
		{`emails[type eq "other"].value eq "x"`, false},
		{`addresses[type eq "home"].locality eq "paris"`, true},
		{`phoneNumbers[type eq "work"].value sw "+1"`, true},
		{`name.givenName eq "alice"`, true},
		{`name.familyName sw "smi"`, true},
	}
	for _, testCase := range cases {
		filter, err := ParseFilter(testCase.filter)
		if err != nil {
			t.Fatalf("ParseFilter(%q) error = %v", testCase.filter, err)
		}
		if got := filter.Match(user); got != testCase.want {
			t.Fatalf("Match(%q) = %v, want %v", testCase.filter, got, testCase.want)
		}
	}
}

func TestParseFilterEnterpriseSchemaPaths(t *testing.T) {
	user := testUser()
	cases := []struct {
		filter string
		want   bool
	}{
		{`urn:ietf:params:scim:schemas:extension:enterprise:2.0:User:department eq "Engineering"`, true},
		{`urn:ietf:params:scim:schemas:extension:enterprise:2.0:User:organization sw "Ac"`, true},
		{`urn:ietf:params:scim:schemas:extension:enterprise:2.0:User:manager.value eq "m1"`, true},
		{`urn:ietf:params:scim:schemas:extension:enterprise:2.0:User:manager.displayName co "manager"`, true},
		{`urn:ietf:params:scim:schemas:extension:enterprise:2.0:User:employeeNumber eq "E-42"`, true},
		{`urn:ietf:params:scim:schemas:extension:enterprise:2.0:User:department eq "Sales"`, false},
	}
	for _, testCase := range cases {
		filter, err := ParseFilter(testCase.filter)
		if err != nil {
			t.Fatalf("ParseFilter(%q) error = %v", testCase.filter, err)
		}
		if got := filter.Match(user); got != testCase.want {
			t.Fatalf("Match(%q) = %v, want %v", testCase.filter, got, testCase.want)
		}
	}
}

func TestParseFilterLogicalOperatorsAndPresence(t *testing.T) {
	user := testUser()
	cases := []struct {
		filter string
		want   bool
	}{
		{`userName sw "a" and active eq true`, true},
		{`userName eq "bob" or title eq "Engineer"`, true},
		{`(userName eq "alice" or userName eq "bob") and displayName co "smith"`, true},
		{`not (userName eq "bob")`, true},
		{`not (userName eq "alice")`, false},
		{`emails pr`, true},
		{`nickName pr`, true},
		{`title pr`, true},
		{`ims pr`, false},
		{`manager pr`, false},
	}
	for _, testCase := range cases {
		filter, err := ParseFilter(testCase.filter)
		if err != nil {
			t.Fatalf("ParseFilter(%q) error = %v", testCase.filter, err)
		}
		if got := filter.Match(user); got != testCase.want {
			t.Fatalf("Match(%q) = %v, want %v", testCase.filter, got, testCase.want)
		}
	}
}

func TestParseFilterInvalidExpressions(t *testing.T) {
	inputs := []string{
		"",
		"   ",
		"userName",
		"userName eq",
		`userName xx "alice"`,
		`emails[type eq "work"`,
		`userName eq "alice" trailing`,
		`userName eq "unterminated`,
		`not userName eq "alice"`,
		`userName eq "alice" and`,
		`()`,
	}
	for _, input := range inputs {
		_, err := ParseFilter(input)
		if err == nil {
			t.Fatalf("ParseFilter(%q) succeeded, want error", input)
		}
		if !errors.Is(err, ErrInvalidFilter) {
			t.Fatalf("ParseFilter(%q) error = %v, want ErrInvalidFilter", input, err)
		}
	}
}

func TestParseAttributePath(t *testing.T) {
	path, err := ParseAttributePath(`emails[type eq "work"].value`)
	if err != nil {
		t.Fatalf("ParseAttributePath error = %v", err)
	}
	if path.Attribute != "emails" || path.SubAttribute != "value" || path.ValueFilter == nil {
		t.Fatalf("path = %+v", path)
	}
	if got := path.String(); got != `emails[type eq "work"].value` {
		t.Fatalf("String() = %q", got)
	}
	urnPath, err := ParseAttributePath(`urn:ietf:params:scim:schemas:extension:enterprise:2.0:User:manager.value`)
	if err != nil {
		t.Fatalf("ParseAttributePath URN error = %v", err)
	}
	if urnPath.Schema != EnterpriseUserSchema || urnPath.Attribute != "manager" || urnPath.SubAttribute != "value" {
		t.Fatalf("URN path = %+v", urnPath)
	}
	invalid := []string{"", "emails[", "emails[type eq]", `emails[type eq "work"]extra`}
	for _, input := range invalid {
		if _, err := ParseAttributePath(input); err == nil || !errors.Is(err, ErrInvalidPath) {
			t.Fatalf("ParseAttributePath(%q) error = %v, want ErrInvalidPath", input, err)
		}
	}
}

func TestFilterStringCanonicalForm(t *testing.T) {
	filter, err := ParseFilter(`USERNAME EQ "Alice" AND active EQ TRUE`)
	if err != nil {
		t.Fatalf("ParseFilter error = %v", err)
	}
	if got := filter.String(); got != `USERNAME eq "Alice" and active eq true` {
		t.Fatalf("String() = %q", got)
	}
}

func TestFilterMatchOtherResourceTypes(t *testing.T) {
	group := &Group{DisplayName: "Admins", Members: []GroupMember{{Value: "u1", Display: "Alice"}}}
	filter, err := ParseFilter(`displayName eq "admins" and members[value eq "u1"].display eq "Alice"`)
	if err != nil {
		t.Fatalf("ParseFilter error = %v", err)
	}
	if !filter.Match(group) {
		t.Fatalf("group filter did not match")
	}
	enterprise := testUser().EnterpriseUser
	filter, err = ParseFilter(`department eq "Engineering"`)
	if err != nil {
		t.Fatalf("ParseFilter error = %v", err)
	}
	if !filter.Match(enterprise) {
		t.Fatalf("enterprise filter did not match")
	}
	value := MultiValue{Value: "a@example.com", Type: "work"}
	filter, err = ParseFilter(`type eq "work"`)
	if err != nil {
		t.Fatalf("ParseFilter error = %v", err)
	}
	if !filter.Match(value) {
		t.Fatalf("multi-value filter did not match")
	}
}

func TestSortUsersAndGroups(t *testing.T) {
	users := []*User{
		{UserName: "carol"},
		{UserName: "alice"},
		{UserName: "bob"},
	}
	SortUsers(users, "", SortAscending)
	if users[0].UserName != "alice" || users[2].UserName != "carol" {
		t.Fatalf("ascending sort = %q, %q, %q", users[0].UserName, users[1].UserName, users[2].UserName)
	}
	SortUsers(users, "userName", SortDescending)
	if users[0].UserName != "carol" || users[2].UserName != "alice" {
		t.Fatalf("descending sort = %q, %q, %q", users[0].UserName, users[1].UserName, users[2].UserName)
	}
	groups := []*Group{{DisplayName: "z"}, {DisplayName: "a"}}
	SortGroups(groups, "", SortAscending)
	if groups[0].DisplayName != "a" {
		t.Fatalf("group sort = %q", groups[0].DisplayName)
	}
	if _, err := ParseSortOrder("sideways"); err == nil {
		t.Fatalf("ParseSortOrder accepted invalid direction")
	}
	if order, err := ParseSortOrder("DESCENDING"); err != nil || order != SortDescending {
		t.Fatalf("ParseSortOrder descending = %v, %v", order, err)
	}
}

// TestParseFilterDepthLimit verifies that hostile deeply nested filters are rejected instead of
// exhausting the stack. | TestParseFilterDepthLimit 校验恶意深度嵌套过滤器被拒绝，避免耗尽栈。
func TestParseFilterDepthLimit(t *testing.T) {
	paren := func(depth int) string {
		return strings.Repeat("(", depth) + `userName eq "x"` + strings.Repeat(")", depth)
	}
	if _, err := ParseFilter(paren(maxFilterDepth - 1)); err != nil {
		t.Fatalf("parentheses at depth limit: %v", err)
	}
	if _, err := ParseFilter(paren(maxFilterDepth)); !errors.Is(err, ErrInvalidFilter) {
		t.Fatalf("parentheses above depth limit: %v", err)
	}
	nots := func(depth int) string {
		return strings.Repeat("not (", depth) + `userName eq "x"` + strings.Repeat(")", depth)
	}
	if _, err := ParseFilter(nots(maxFilterDepth - 1)); err != nil {
		t.Fatalf("not chain at depth limit: %v", err)
	}
	if _, err := ParseFilter(nots(maxFilterDepth)); !errors.Is(err, ErrInvalidFilter) {
		t.Fatalf("not chain above depth limit: %v", err)
	}
}

// TestAttributePathStringSchemaOnly verifies a schema-only path renders without a trailing colon.
// | TestAttributePathStringSchemaOnly 校验仅含 Schema 的路径渲染时没有尾随冒号。
func TestAttributePathStringSchemaOnly(t *testing.T) {
	path := &AttributePath{Schema: UserSchema}
	if got := path.String(); got != UserSchema {
		t.Fatalf("String() = %q, want %q", got, UserSchema)
	}
	full := &AttributePath{Schema: EnterpriseUserSchema, Attribute: "manager", SubAttribute: "value"}
	want := EnterpriseUserSchema + ":manager.value"
	if got := full.String(); got != want {
		t.Fatalf("String() = %q, want %q", got, want)
	}
	var nilPath *AttributePath
	if got := nilPath.String(); got != "" {
		t.Fatalf("nil String() = %q", got)
	}
}

// TestLogicalFilterStringPrecedence verifies mixed and / or filters keep their grouping when
// rendered. | TestLogicalFilterStringPrecedence 校验混合 and / or 过滤器渲染时保留分组。
func TestLogicalFilterStringPrecedence(t *testing.T) {
	filter, err := ParseFilter(`(a eq "1" or b eq "2") and c eq "3"`)
	if err != nil {
		t.Fatalf("ParseFilter: %v", err)
	}
	want := `(a eq "1" or b eq "2") and c eq "3"`
	if got := filter.String(); got != want {
		t.Fatalf("String() = %q, want %q", got, want)
	}
	reparsed, err := ParseFilter(filter.String())
	if err != nil {
		t.Fatalf("reparse: %v", err)
	}
	resource := map[string]any{"a": "1", "c": "3"}
	if !filter.Match(resource) || !reparsed.Match(resource) {
		t.Fatalf("mixed filter lost precedence after rendering")
	}
	same, err := ParseFilter(`a eq "1" and b eq "2" and c eq "3"`)
	if err != nil {
		t.Fatalf("ParseFilter same: %v", err)
	}
	if got := same.String(); got != `a eq "1" and b eq "2" and c eq "3"` {
		t.Fatalf("same-operator String() = %q", got)
	}
}

// TestParseFilterEscapes verifies JSON-style string escapes and canonical re-quoting. |
// TestParseFilterEscapes 校验 JSON 风格字符串转义与规范化重新引用。
func TestParseFilterEscapes(t *testing.T) {
	cases := []struct {
		filter string
		value  string
	}{
		{`userName eq "a\"b"`, `a"b`},
		{`userName eq "a\\b"`, `a\b`},
		{`userName eq "a\/b"`, "a/b"},
		{`userName eq "a\bb"`, "a\bb"},
		{`userName eq "a\fb"`, "a\fb"},
		{`userName eq "a\nb"`, "a\nb"},
		{`userName eq "a\rb"`, "a\rb"},
		{`userName eq "a\tb"`, "a\tb"},
		{`userName eq "Alice"`, "Alice"},
		{`userName eq "😀"`, "\U0001F600"},
	}
	for _, testCase := range cases {
		filter, err := ParseFilter(testCase.filter)
		if err != nil {
			t.Fatalf("ParseFilter(%q): %v", testCase.filter, err)
		}
		resource := map[string]any{"userName": testCase.value}
		if !filter.Match(resource) {
			t.Fatalf("Match(%q) did not match %q", testCase.filter, testCase.value)
		}
		reparsed, err := ParseFilter(filter.String())
		if err != nil {
			t.Fatalf("reparse %q: %v", filter.String(), err)
		}
		if !reparsed.Match(resource) {
			t.Fatalf("reparsed %q did not match %q", filter.String(), testCase.value)
		}
	}
	invalid := []string{
		`userName eq "a\qb"`,
		`userName eq "a\u12"`,
		`userName eq "a\uZZZZ"`,
	}
	for _, input := range invalid {
		if _, err := ParseFilter(input); !errors.Is(err, ErrInvalidFilter) {
			t.Fatalf("ParseFilter(%q) error = %v, want ErrInvalidFilter", input, err)
		}
	}
}

// TestFilterComparisonOperatorsCanonical verifies every comparison operator survives Parse /
// String. | TestFilterComparisonOperatorsCanonical 校验每个比较运算符经过 Parse / String。
func TestFilterComparisonOperatorsCanonical(t *testing.T) {
	operators := []string{"eq", "ne", "co", "sw", "ew", "gt", "ge", "lt", "le"}
	for _, operator := range operators {
		input := `userName ` + strings.ToUpper(operator) + ` "a"`
		filter, err := ParseFilter(input)
		if err != nil {
			t.Fatalf("ParseFilter(%q): %v", input, err)
		}
		want := `userName ` + operator + ` "a"`
		if got := filter.String(); got != want {
			t.Fatalf("String() = %q, want %q", got, want)
		}
	}
	nullFilter, err := ParseFilter(`nickName eq null`)
	if err != nil {
		t.Fatalf("ParseFilter null: %v", err)
	}
	if got := nullFilter.String(); got != "nickName eq null" {
		t.Fatalf("null String() = %q", got)
	}
	boolFilter, err := ParseFilter(`active eq TRUE`)
	if err != nil {
		t.Fatalf("ParseFilter bool: %v", err)
	}
	if got := boolFilter.String(); got != "active eq true" {
		t.Fatalf("bool String() = %q", got)
	}
	numberFilter, err := ParseFilter(`age eq 42.5`)
	if err != nil {
		t.Fatalf("ParseFilter number: %v", err)
	}
	if got := numberFilter.String(); got != "age eq 42.5" {
		t.Fatalf("number String() = %q", got)
	}
}
