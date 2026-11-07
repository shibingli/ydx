package scim

import (
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/shibingli/ydx/errs"
)

// SortOrder names a SCIM sort direction. | SortOrder 命名 SCIM 排序方向。
type SortOrder string

const (
	// SortAscending sorts from the lowest value to the highest. | SortAscending 从最小值到最大值排序。
	SortAscending SortOrder = "ascending"
	// SortDescending sorts from the highest value to the lowest. | SortDescending 从最大值到最小值排序。
	SortDescending SortOrder = "descending"
)

// ParseSortOrder parses an RFC 7644 sortOrder value case-insensitively; an empty value yields
// ascending. | ParseSortOrder 以大小写不敏感方式解析 RFC 7644 sortOrder 取值；空值返回升序。
func ParseSortOrder(value string) (SortOrder, error) {
	switch strings.ToLower(strings.TrimSpace(value)) {
	case "", string(SortAscending):
		return SortAscending, nil
	case string(SortDescending):
		return SortDescending, nil
	}
	return "", errs.Detail(ErrInvalidValue, "invalid sortOrder %q | 非法 sortOrder %q", value, value)
}

// Match reports whether resource satisfies the attribute expression. | Match 报告 resource 是否
// 满足属性表达式。
func (f *attributeFilter) Match(resource any) bool {
	values, ok := f.path.values(resource)
	if !ok || len(values) == 0 {
		return false
	}
	if f.op == opNE {
		for _, value := range values {
			if compareOne(value, opEQ, f.value) {
				return false
			}
		}
		return true
	}
	for _, value := range values {
		if compareOne(value, f.op, f.value) {
			return true
		}
	}
	return false
}

// Match reports whether the attribute is present and non-empty. | Match 报告属性是否存在且非空。
func (f *presenceFilter) Match(resource any) bool {
	values, ok := f.path.values(resource)
	if !ok {
		return false
	}
	for _, value := range values {
		if nonEmptyScalar(value) {
			return true
		}
	}
	return false
}

// Match short-circuits the conjunction or disjunction. | Match 对合取或析取短路求值。
func (f *logicalFilter) Match(resource any) bool {
	if f.op == "or" {
		return f.left.Match(resource) || f.right.Match(resource)
	}
	return f.left.Match(resource) && f.right.Match(resource)
}

// Match negates the inner filter. | Match 对内部过滤器取反。
func (f *notFilter) Match(resource any) bool { return !f.inner.Match(resource) }

// values resolves an attribute path against a resource. | values 把属性路径解析到资源上。
func (p *AttributePath) values(resource any) ([]any, bool) {
	target, ok := schemaTarget(resource, p.Schema)
	if !ok || target == nil {
		return nil, false
	}
	if p.Attribute == "" {
		return []any{target}, true
	}
	values, ok := attributeValues(target, p.Attribute)
	if !ok {
		return nil, false
	}
	if p.ValueFilter != nil {
		matched := make([]any, 0, len(values))
		for _, value := range values {
			if p.ValueFilter.Match(value) {
				matched = append(matched, value)
			}
		}
		if len(matched) == 0 {
			return nil, false
		}
		values = matched
	}
	if p.SubAttribute != "" {
		projected := make([]any, 0, len(values))
		for _, value := range values {
			if sub, ok := subValue(value, p.SubAttribute); ok {
				projected = append(projected, sub)
			}
		}
		if len(projected) == 0 {
			return nil, false
		}
		values = projected
	}
	return values, true
}

// FirstValue returns the first scalar value resolved by the path, and whether one exists. | FirstValue
// 返回路径解析出的首个标量值，以及该值是否存在。
func (p *AttributePath) FirstValue(resource any) (any, bool) {
	values, ok := p.values(resource)
	if !ok || len(values) == 0 {
		return nil, false
	}
	return values[0], true
}

// schemaTarget selects the object a schema-qualified path applies to. | schemaTarget 选择带 Schema
// 限定的路径所作用的对象。
func schemaTarget(resource any, schema string) (any, bool) {
	if schema == "" {
		return resource, true
	}
	if isEnterpriseSchema(schema) {
		switch value := resource.(type) {
		case *User:
			if value == nil || value.EnterpriseUser == nil {
				return nil, false
			}
			return value.EnterpriseUser, true
		case User:
			if value.EnterpriseUser == nil {
				return nil, false
			}
			return value.EnterpriseUser, true
		case *EnterpriseUser:
			if value == nil {
				return nil, false
			}
			return value, true
		case EnterpriseUser:
			return value, true
		case map[string]any:
			return ciMapValue(value, schema)
		}
		return nil, false
	}
	if isCoreUserSchema(schema) {
		switch value := resource.(type) {
		case *User, User, *EnterpriseUser, EnterpriseUser:
			return resource, true
		case map[string]any:
			return value, true
		}
		return nil, false
	}
	if isCoreGroupSchema(schema) {
		switch value := resource.(type) {
		case *Group, Group:
			return resource, true
		case map[string]any:
			return value, true
		}
		return nil, false
	}
	if value, ok := resource.(map[string]any); ok {
		return ciMapValue(value, schema)
	}
	return nil, false
}

// attributeValues returns the values of name on target. | attributeValues 返回 target 上 name 的
// 取值。
func attributeValues(target any, name string) ([]any, bool) {
	if target == nil {
		return nil, false
	}
	lower := strings.ToLower(name)
	switch value := target.(type) {
	case *User:
		if value == nil {
			return nil, false
		}
		return userAttributeValues(value, lower)
	case User:
		return userAttributeValues(&value, lower)
	case *Group:
		if value == nil {
			return nil, false
		}
		return groupAttributeValues(value, lower)
	case Group:
		return groupAttributeValues(&value, lower)
	case *EnterpriseUser:
		if value == nil {
			return nil, false
		}
		return enterpriseAttributeValues(value, lower)
	case EnterpriseUser:
		return enterpriseAttributeValues(&value, lower)
	case *Name:
		if value == nil {
			return nil, false
		}
		return nameAttributeValues(value, lower)
	case Name:
		return nameAttributeValues(&value, lower)
	case *Manager:
		if value == nil {
			return nil, false
		}
		return managerAttributeValues(value, lower)
	case Manager:
		return managerAttributeValues(&value, lower)
	case *MultiValue:
		if value == nil {
			return nil, false
		}
		return multiAttributeValues(value, lower)
	case MultiValue:
		return multiAttributeValues(&value, lower)
	case *Address:
		if value == nil {
			return nil, false
		}
		return addressAttributeValues(value, lower)
	case Address:
		return addressAttributeValues(&value, lower)
	case *GroupValue:
		if value == nil {
			return nil, false
		}
		return groupValueAttributeValues(value, lower)
	case GroupValue:
		return groupValueAttributeValues(&value, lower)
	case *GroupMember:
		if value == nil {
			return nil, false
		}
		return groupMemberAttributeValues(value, lower)
	case GroupMember:
		return groupMemberAttributeValues(&value, lower)
	case map[string]any:
		if raw, ok := ciMapValue(value, name); ok {
			return flattenValue(raw), true
		}
		return nil, false
	case map[string]string:
		for key, raw := range value {
			if strings.EqualFold(key, name) {
				return []any{raw}, true
			}
		}
	}
	return nil, false
}

// userAttributeValues returns a User attribute by lowercase name. | userAttributeValues 按小写
// 名称返回 User 属性。
func userAttributeValues(u *User, lower string) ([]any, bool) {
	switch lower {
	case "id":
		return []any{u.ID}, true
	case "externalid":
		return []any{u.ExternalID}, true
	case "username":
		return []any{u.UserName}, true
	case "name":
		if u.Name == nil {
			return nil, false
		}
		return []any{u.Name}, true
	case "displayname":
		return []any{u.DisplayName}, true
	case "nickname":
		return []any{u.NickName}, true
	case "profileurl":
		return []any{u.ProfileURL}, true
	case "title":
		return []any{u.Title}, true
	case "usertype":
		return []any{u.UserType}, true
	case "preferredlanguage":
		return []any{u.PreferredLanguage}, true
	case "locale":
		return []any{u.Locale}, true
	case "timezone":
		return []any{u.Timezone}, true
	case "active":
		return []any{u.ActiveValue()}, true
	case "password":
		return nil, false
	case "emails":
		return multiValues(u.Emails), true
	case "phonenumbers":
		return multiValues(u.PhoneNumbers), true
	case "ims":
		return multiValues(u.IMs), true
	case "photos":
		return multiValues(u.Photos), true
	case "entitlements":
		return multiValues(u.Entitlements), true
	case "roles":
		return multiValues(u.Roles), true
	case "x509certificates":
		return multiValues(u.X509Certificates), true
	case "addresses":
		return addressValues(u.Addresses), true
	case "groups":
		return groupValues(u.Groups), true
	case "meta":
		if u.Meta == nil {
			return nil, false
		}
		return []any{u.Meta}, true
	case "schemas":
		return stringValues(u.Schemas), true
	}
	if strings.EqualFold(lower, EnterpriseUserSchema) {
		if u.EnterpriseUser == nil {
			return nil, false
		}
		return []any{u.EnterpriseUser}, true
	}
	return nil, false
}

// groupAttributeValues returns a Group attribute by lowercase name. | groupAttributeValues 按小写
// 名称返回 Group 属性。
func groupAttributeValues(g *Group, lower string) ([]any, bool) {
	switch lower {
	case "id":
		return []any{g.ID}, true
	case "externalid":
		return []any{g.ExternalID}, true
	case "displayname":
		return []any{g.DisplayName}, true
	case "members":
		return groupMemberValues(g.Members), true
	case "meta":
		if g.Meta == nil {
			return nil, false
		}
		return []any{g.Meta}, true
	case "schemas":
		return stringValues(g.Schemas), true
	}
	return nil, false
}

// enterpriseAttributeValues returns an EnterpriseUser attribute by lowercase name. |
// enterpriseAttributeValues 按小写名称返回 EnterpriseUser 属性。
func enterpriseAttributeValues(e *EnterpriseUser, lower string) ([]any, bool) {
	switch lower {
	case "employeenumber":
		return []any{e.EmployeeNumber}, true
	case "costcenter":
		return []any{e.CostCenter}, true
	case "organization":
		return []any{e.Organization}, true
	case "division":
		return []any{e.Division}, true
	case "department":
		return []any{e.Department}, true
	case "manager":
		if e.Manager == nil {
			return nil, false
		}
		return []any{e.Manager}, true
	}
	return nil, false
}

// nameAttributeValues returns a Name attribute by lowercase name. | nameAttributeValues 按小写
// 名称返回 Name 属性。
func nameAttributeValues(n *Name, lower string) ([]any, bool) {
	switch lower {
	case "formatted":
		return []any{n.Formatted}, true
	case "familyname":
		return []any{n.FamilyName}, true
	case "givenname":
		return []any{n.GivenName}, true
	case "middlename":
		return []any{n.MiddleName}, true
	case "honorificprefix":
		return []any{n.HonorificPrefix}, true
	case "honorificsuffix":
		return []any{n.HonorificSuffix}, true
	}
	return nil, false
}

// managerAttributeValues returns a Manager attribute by lowercase name. | managerAttributeValues
// 按小写名称返回 Manager 属性。
func managerAttributeValues(m *Manager, lower string) ([]any, bool) {
	switch lower {
	case "value":
		return []any{m.Value}, true
	case "displayname":
		return []any{m.DisplayName}, true
	case "$ref", "ref":
		return []any{m.Ref}, true
	}
	return nil, false
}

// multiAttributeValues returns a MultiValue attribute by lowercase name. | multiAttributeValues
// 按小写名称返回 MultiValue 属性。
func multiAttributeValues(m *MultiValue, lower string) ([]any, bool) {
	switch lower {
	case "value":
		return []any{m.Value}, true
	case "display":
		return []any{m.Display}, true
	case "type":
		return []any{m.Type}, true
	case "primary":
		return []any{m.Primary}, true
	case "$ref", "ref":
		return []any{m.Ref}, true
	}
	return nil, false
}

// addressAttributeValues returns an Address attribute by lowercase name. | addressAttributeValues
// 按小写名称返回 Address 属性。
func addressAttributeValues(a *Address, lower string) ([]any, bool) {
	switch lower {
	case "formatted":
		return []any{a.Formatted}, true
	case "streetaddress":
		return []any{a.StreetAddress}, true
	case "locality":
		return []any{a.Locality}, true
	case "region":
		return []any{a.Region}, true
	case "postalcode":
		return []any{a.PostalCode}, true
	case "country":
		return []any{a.Country}, true
	case "type":
		return []any{a.Type}, true
	case "primary":
		return []any{a.Primary}, true
	}
	return nil, false
}

// groupValueAttributeValues returns a GroupValue attribute by lowercase name. |
// groupValueAttributeValues 按小写名称返回 GroupValue 属性。
func groupValueAttributeValues(g *GroupValue, lower string) ([]any, bool) {
	switch lower {
	case "value":
		return []any{g.Value}, true
	case "display":
		return []any{g.Display}, true
	case "type":
		return []any{g.Type}, true
	case "$ref", "ref":
		return []any{g.Ref}, true
	}
	return nil, false
}

// groupMemberAttributeValues returns a GroupMember attribute by lowercase name. |
// groupMemberAttributeValues 按小写名称返回 GroupMember 属性。
func groupMemberAttributeValues(m *GroupMember, lower string) ([]any, bool) {
	switch lower {
	case "value":
		return []any{m.Value}, true
	case "display":
		return []any{m.Display}, true
	case "type":
		return []any{m.Type}, true
	case "$ref", "ref":
		return []any{m.Ref}, true
	}
	return nil, false
}

// subValue projects a sub-attribute from one complex value. | subValue 从单个复杂值投影子属性。
func subValue(entry any, sub string) (any, bool) {
	values, ok := attributeValues(entry, sub)
	if !ok || len(values) == 0 {
		return nil, false
	}
	return values[0], true
}

// ciMapValue returns a map member under case-insensitive key matching. | ciMapValue 以大小写不敏感
// 的键匹配返回映射成员。
func ciMapValue(m map[string]any, key string) (any, bool) {
	if value, ok := m[key]; ok {
		return value, true
	}
	for candidate, value := range m {
		if strings.EqualFold(candidate, key) {
			return value, true
		}
	}
	return nil, false
}

// flattenValue expands a JSON-like value into a list of attribute values. | flattenValue 把类 JSON
// 值展开为属性值列表。
func flattenValue(value any) []any {
	switch list := value.(type) {
	case nil:
		return []any{nil}
	case []any:
		return list
	case []string:
		out := make([]any, len(list))
		for i := range list {
			out[i] = list[i]
		}
		return out
	case []MultiValue:
		return multiValues(list)
	case []Address:
		return addressValues(list)
	case []GroupMember:
		return groupMemberValues(list)
	case []GroupValue:
		return groupValues(list)
	default:
		return []any{value}
	}
}

// multiValues converts a MultiValue slice into a value list. | multiValues 把 MultiValue 切片转换
// 为值列表。
func multiValues(list []MultiValue) []any {
	out := make([]any, len(list))
	for i := range list {
		out[i] = &list[i]
	}
	return out
}

// addressValues converts an Address slice into a value list. | addressValues 把 Address 切片转换
// 为值列表。
func addressValues(list []Address) []any {
	out := make([]any, len(list))
	for i := range list {
		out[i] = &list[i]
	}
	return out
}

// groupValues converts a GroupValue slice into a value list. | groupValues 把 GroupValue 切片转换
// 为值列表。
func groupValues(list []GroupValue) []any {
	out := make([]any, len(list))
	for i := range list {
		out[i] = &list[i]
	}
	return out
}

// groupMemberValues converts a GroupMember slice into a value list. | groupMemberValues 把
// GroupMember 切片转换为值列表。
func groupMemberValues(list []GroupMember) []any {
	out := make([]any, len(list))
	for i := range list {
		out[i] = &list[i]
	}
	return out
}

// stringValues converts a string slice into a value list. | stringValues 把字符串切片转换为值列表。
func stringValues(list []string) []any {
	out := make([]any, len(list))
	for i := range list {
		out[i] = list[i]
	}
	return out
}

// scalarValue projects a complex value onto its scalar comparison value. | scalarValue 把复杂值
// 投影为标量比较值。
func scalarValue(value any) (any, bool) {
	switch item := value.(type) {
	case nil:
		return nil, true
	case string:
		return item, true
	case bool:
		return item, true
	case float64:
		return item, true
	case float32:
		return float64(item), true
	case int:
		return float64(item), true
	case int8:
		return float64(item), true
	case int16:
		return float64(item), true
	case int32:
		return float64(item), true
	case int64:
		return float64(item), true
	case uint:
		return float64(item), true
	case uint8:
		return float64(item), true
	case uint16:
		return float64(item), true
	case uint32:
		return float64(item), true
	case uint64:
		return float64(item), true
	case time.Time:
		return item, true
	case *time.Time:
		if item == nil {
			return nil, true
		}
		return *item, true
	case *MultiValue:
		if item == nil {
			return nil, true
		}
		return item.Value, true
	case MultiValue:
		return item.Value, true
	case *Address:
		if item == nil {
			return nil, true
		}
		return item.Formatted, true
	case Address:
		return item.Formatted, true
	case *GroupValue:
		if item == nil {
			return nil, true
		}
		return item.Value, true
	case GroupValue:
		return item.Value, true
	case *GroupMember:
		if item == nil {
			return nil, true
		}
		return item.Value, true
	case GroupMember:
		return item.Value, true
	case *Manager:
		if item == nil {
			return nil, true
		}
		return item.Value, true
	case Manager:
		return item.Value, true
	case *Name:
		if item == nil {
			return nil, true
		}
		return item.Formatted, true
	case Name:
		return item.Formatted, true
	case map[string]any:
		for _, key := range []string{"value", "formatted", "display"} {
			if raw, ok := ciMapValue(item, key); ok {
				if scalar, ok := scalarValue(raw); ok {
					return scalar, true
				}
			}
		}
	}
	return nil, false
}

// scalarString renders a scalar as a comparison string. | scalarString 把标量渲染为比较字符串。
func scalarString(value any) (string, bool) {
	switch item := value.(type) {
	case string:
		return item, true
	case bool:
		if item {
			return "true", true
		}
		return "false", true
	case float64:
		return strconv.FormatFloat(item, 'f', -1, 64), true
	case time.Time:
		return formatTime(item), true
	}
	return "", false
}

// nonEmptyScalar reports whether a value is present and non-empty. | nonEmptyScalar 报告值是否存在
// 且非空。
func nonEmptyScalar(value any) bool {
	scalar, ok := scalarValue(value)
	if !ok {
		return value != nil
	}
	if scalar == nil {
		return false
	}
	if text, ok := scalar.(string); ok {
		return text != ""
	}
	return true
}

// compareOne applies op to one actual value and the expected literal. | compareOne 对一个实际值
// 与期望字面量应用 op。
func compareOne(actual any, op compareOp, want literal) bool {
	scalar, present := scalarValue(actual)
	if !present {
		return false
	}
	if want.kind == litNull {
		empty := scalar == nil || (isStringScalar(scalar) && scalarStringOf(scalar) == "")
		switch op {
		case opEQ:
			return empty
		case opNE:
			return !empty
		}
		return false
	}
	if want.kind == litBool {
		boolean, ok := scalar.(bool)
		if !ok {
			return op == opNE
		}
		switch op {
		case opEQ:
			return boolean == want.boolean
		case opNE:
			return boolean != want.boolean
		}
		return false
	}
	if want.kind == litNumber {
		if number, ok := numericScalar(scalar); ok {
			return compareFloat(number, want.number, op)
		}
	}
	text, ok := scalarString(scalar)
	if !ok {
		return op == opNE
	}
	switch op {
	case opEQ:
		return strings.EqualFold(text, want.text)
	case opNE:
		return !strings.EqualFold(text, want.text)
	case opCO:
		return strings.Contains(strings.ToLower(text), strings.ToLower(want.text))
	case opSW:
		return strings.HasPrefix(strings.ToLower(text), strings.ToLower(want.text))
	case opEW:
		return strings.HasSuffix(strings.ToLower(text), strings.ToLower(want.text))
	case opGT, opGE, opLT, opLE:
		return compareOrdered(text, want.text, op)
	}
	return false
}

// isStringScalar reports whether value is a string. | isStringScalar 报告 value 是否为字符串。
func isStringScalar(value any) bool {
	_, ok := value.(string)
	return ok
}

// scalarStringOf renders a string scalar. | scalarStringOf 渲染字符串标量。
func scalarStringOf(value any) string {
	text, _ := value.(string)
	return text
}

// numericScalar converts a scalar to a float64 when possible. | numericScalar 在可能时把标量转换
// 为 float64。
func numericScalar(value any) (float64, bool) {
	switch item := value.(type) {
	case float64:
		return item, true
	case float32:
		return float64(item), true
	case int:
		return float64(item), true
	case int64:
		return float64(item), true
	case int32:
		return float64(item), true
	case string:
		number, err := strconv.ParseFloat(item, 64)
		return number, err == nil
	}
	return 0, false
}

// compareFloat applies a comparison operator to two numbers. | compareFloat 对两个数值应用比较
// 运算符。
func compareFloat(left, right float64, op compareOp) bool {
	switch op {
	case opEQ:
		return left == right
	case opNE:
		return left != right
	case opGT:
		return left > right
	case opGE:
		return left >= right
	case opLT:
		return left < right
	case opLE:
		return left <= right
	}
	return false
}

// compareOrdered compares two strings as dates, then numbers, then case-insensitive text. |
// compareOrdered 依次按日期、数值与大小写不敏感文本比较两个字符串。
func compareOrdered(left, right string, op compareOp) bool {
	if leftTime, leftErr := time.Parse(time.RFC3339, left); leftErr == nil {
		if rightTime, rightErr := time.Parse(time.RFC3339, right); rightErr == nil {
			return compareFloat(float64(leftTime.UnixNano()), float64(rightTime.UnixNano()), op)
		}
	}
	if leftNumber, leftErr := strconv.ParseFloat(left, 64); leftErr == nil {
		if rightNumber, rightErr := strconv.ParseFloat(right, 64); rightErr == nil {
			return compareFloat(leftNumber, rightNumber, op)
		}
	}
	lowerLeft := strings.ToLower(left)
	lowerRight := strings.ToLower(right)
	switch op {
	case opGT:
		return lowerLeft > lowerRight
	case opGE:
		return lowerLeft >= lowerRight
	case opLT:
		return lowerLeft < lowerRight
	case opLE:
		return lowerLeft <= lowerRight
	}
	return false
}

// SortUsers sorts users in place by the RFC 7644 sortBy path. An empty sortBy sorts by userName.
// | SortUsers 按 RFC 7644 sortBy 路径就地排序 users。sortBy 为空时按 userName 排序。
func SortUsers(users []*User, sortBy string, order SortOrder) {
	path := sortPath(sortBy, "userName")
	sort.SliceStable(users, func(i, j int) bool {
		return sortLess(users[i], users[j], path, order)
	})
}

// SortGroups sorts groups in place by the RFC 7644 sortBy path. An empty sortBy sorts by
// displayName. | SortGroups 按 RFC 7644 sortBy 路径就地排序 groups。sortBy 为空时按 displayName
// 排序。
func SortGroups(groups []*Group, sortBy string, order SortOrder) {
	path := sortPath(sortBy, "displayName")
	sort.SliceStable(groups, func(i, j int) bool {
		return sortLess(groups[i], groups[j], path, order)
	})
}

// sortPath parses sortBy into a path, falling back to the resource default attribute. | sortPath
// 把 sortBy 解析为路径，失败时回退到资源默认属性。
func sortPath(sortBy, fallback string) *AttributePath {
	text := strings.TrimSpace(sortBy)
	if text == "" {
		text = fallback
	}
	path, err := ParseAttributePath(text)
	if err != nil {
		path, _ = ParseAttributePath(fallback)
	}
	return path
}

// sortLess reports whether a sorts before b. | sortLess 报告 a 是否排在 b 之前。
func sortLess(a, b any, path *AttributePath, order SortOrder) bool {
	left := strings.ToLower(sortText(a, path))
	right := strings.ToLower(sortText(b, path))
	if order == SortDescending {
		return right < left
	}
	return left < right
}

// sortText returns the leading scalar of a resource under path. | sortText 返回资源在路径下的首个
// 标量文本。
func sortText(resource any, path *AttributePath) string {
	value, ok := path.FirstValue(resource)
	if !ok {
		return ""
	}
	scalar, ok := scalarValue(value)
	if !ok {
		return ""
	}
	text, _ := scalarString(scalar)
	return text
}
