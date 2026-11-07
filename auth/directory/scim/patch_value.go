package scim

import (
	"strconv"
	"strings"

	"github.com/shibingli/ydx/errs"
	ydxjson "github.com/shibingli/ydx/json"
)

// asObject decodes value into a JSON object. | asObject 把 value 解码为 JSON 对象。
func asObject(value any) (map[string]any, error) {
	if object, ok := value.(map[string]any); ok {
		return object, nil
	}
	var object map[string]any
	if err := decodeInto(value, &object); err != nil {
		return nil, err
	}
	if object == nil {
		return nil, errs.Detail(ErrInvalidValue, "expected a JSON object | 期望 JSON 对象")
	}
	return object, nil
}

// decodeInto marshals value and unmarshals it into target through ydx/json. | decodeInto 经
// ydx/json 把 value 序列化后反序列化到 target。
func decodeInto(value any, target any) error {
	data, err := ydxjson.Marshal(value)
	if err != nil {
		return errs.Detail(ErrInvalidValue, "cannot encode value | 无法编码值")
	}
	if err := ydxjson.Unmarshal(data, target); err != nil {
		return errs.Detail(ErrInvalidValue, "cannot decode value | 无法解码值")
	}
	return nil
}

// asString accepts a string or a JSON number rendered as text. | asString 接受字符串或渲染为文本
// 的 JSON 数值。
func asString(value any) (string, bool) {
	switch item := value.(type) {
	case string:
		return item, true
	case float64:
		return strconv.FormatFloat(item, 'f', -1, 64), true
	case float32:
		return strconv.FormatFloat(float64(item), 'f', -1, 32), true
	case int:
		return strconv.Itoa(item), true
	case int64:
		return strconv.FormatInt(item, 10), true
	case int32:
		return strconv.FormatInt(int64(item), 10), true
	}
	return "", false
}

// asBool accepts a boolean or its textual form. | asBool 接受布尔值或其文本形式。
func asBool(value any) (bool, bool) {
	switch item := value.(type) {
	case bool:
		return item, true
	case string:
		switch strings.ToLower(item) {
		case "true":
			return true, true
		case "false":
			return false, true
		}
	}
	return false, false
}

// objectString reads a string sub-attribute from a decoded object. | objectString 从已解码对象读取
// 字符串子属性。
func objectString(object map[string]any, key string) (string, error) {
	raw, ok := ciMapValue(object, key)
	if !ok || raw == nil {
		return "", nil
	}
	text, ok := asString(raw)
	if !ok {
		return "", errs.Detail(ErrInvalidValue, "sub-attribute %q must be a string | 子属性 %q 必须是字符串", key, key)
	}
	return text, nil
}

// objectBool reads a boolean sub-attribute from a decoded object. | objectBool 从已解码对象读取
// 布尔子属性。
func objectBool(object map[string]any, key string) (bool, error) {
	raw, ok := ciMapValue(object, key)
	if !ok || raw == nil {
		return false, nil
	}
	value, ok := asBool(raw)
	if !ok {
		return false, errs.Detail(ErrInvalidValue, "sub-attribute %q must be a boolean | 子属性 %q 必须是布尔值", key, key)
	}
	return value, nil
}

// mergeNameFields merges the sub-attributes present in object into n. | mergeNameFields 把 object
// 中存在的子属性合并到 n。
func mergeNameFields(n *Name, object map[string]any) error {
	for key := range object {
		switch strings.ToLower(key) {
		case "formatted":
			text, err := objectString(object, key)
			if err != nil {
				return err
			}
			n.Formatted = text
		case "familyname":
			text, err := objectString(object, key)
			if err != nil {
				return err
			}
			n.FamilyName = text
		case "givenname":
			text, err := objectString(object, key)
			if err != nil {
				return err
			}
			n.GivenName = text
		case "middlename":
			text, err := objectString(object, key)
			if err != nil {
				return err
			}
			n.MiddleName = text
		case "honorificprefix":
			text, err := objectString(object, key)
			if err != nil {
				return err
			}
			n.HonorificPrefix = text
		case "honorificsuffix":
			text, err := objectString(object, key)
			if err != nil {
				return err
			}
			n.HonorificSuffix = text
		default:
			return errs.Detail(ErrInvalidPath, "unknown name sub-attribute %q | 未知的 name 子属性 %q", key, key)
		}
	}
	return nil
}

// mergeManagerFields merges the sub-attributes present in object into m. | mergeManagerFields 把
// object 中存在的子属性合并到 m。
func mergeManagerFields(m *Manager, object map[string]any) error {
	for key := range object {
		text, err := objectString(object, key)
		if err != nil {
			return err
		}
		switch strings.ToLower(key) {
		case "value":
			m.Value = text
		case "displayname":
			m.DisplayName = text
		case "$ref", "ref":
			m.Ref = text
		default:
			return errs.Detail(ErrInvalidPath, "unknown manager sub-attribute %q | 未知的 manager 子属性 %q", key, key)
		}
	}
	return nil
}

// decodeMultiValues decodes a scalar, object or array into multi-valued members. | decodeMultiValues
// 把标量、对象或数组解码为多值成员。
func decodeMultiValues(value any) ([]MultiValue, error) {
	switch items := value.(type) {
	case []MultiValue:
		out := make([]MultiValue, len(items))
		copy(out, items)
		return out, nil
	case []string:
		out := make([]MultiValue, 0, len(items))
		for _, item := range items {
			if item == "" {
				return nil, errs.Detail(ErrInvalidValue, "multi-valued value must not be empty | 多值属性的值不能为空")
			}
			out = append(out, MultiValue{Value: item})
		}
		return out, nil
	case []any:
		out := make([]MultiValue, 0, len(items))
		for _, item := range items {
			entries, err := decodeMultiValues(item)
			if err != nil {
				return nil, err
			}
			out = append(out, entries...)
		}
		return out, nil
	case string:
		if items == "" {
			return nil, errs.Detail(ErrInvalidValue, "multi-valued value must not be empty | 多值属性的值不能为空")
		}
		return []MultiValue{{Value: items}}, nil
	case nil:
		return nil, errs.Detail(ErrInvalidValue, "missing multi-valued value | 缺少多值属性值")
	}
	var single MultiValue
	if err := decodeInto(value, &single); err != nil {
		return nil, err
	}
	if single.Value == "" {
		return nil, errs.Detail(ErrInvalidValue, "multi-valued value requires value | 多值属性需要 value")
	}
	return []MultiValue{single}, nil
}

// containsMultiValue reports whether list already holds an entry with the same value. |
// containsMultiValue 报告 list 是否已包含相同 value 的条目。
func containsMultiValue(list []MultiValue, want MultiValue) bool {
	for i := range list {
		if strings.EqualFold(list[i].Value, want.Value) {
			return true
		}
	}
	return false
}

// matchedMultiIndexes returns the indexes of entries selected by filter. | matchedMultiIndexes
// 返回被 filter 选中的条目索引。
func matchedMultiIndexes(list []MultiValue, filter Filter) []int {
	if filter == nil {
		return nil
	}
	indexes := make([]int, 0, len(list))
	for i := range list {
		if filter.Match(&list[i]) {
			indexes = append(indexes, i)
		}
	}
	return indexes
}

// removeMultiIndexes removes the selected indexes from list. | removeMultiIndexes 从 list 移除选中
// 的索引。
func removeMultiIndexes(list *[]MultiValue, indexes []int) {
	if len(indexes) == 0 {
		return
	}
	drop := make(map[int]bool, len(indexes))
	for _, index := range indexes {
		drop[index] = true
	}
	out := (*list)[:0]
	for i := range *list {
		if !drop[i] {
			out = append(out, (*list)[i])
		}
	}
	*list = out
}

// patchMultiValues applies one operation to a []MultiValue attribute. | patchMultiValues 对一个
// []MultiValue 属性应用一个操作。
func patchMultiValues(list *[]MultiValue, path *AttributePath, kind patchOpKind, value any) error {
	if path.ValueFilter == nil {
		if path.SubAttribute != "" {
			return errs.Detail(ErrInvalidPath, "a value filter is required for sub-attribute %q | 子属性 %q 需要值过滤器",
				path.SubAttribute, path.SubAttribute)
		}
		switch kind {
		case patchRemove:
			if len(*list) == 0 {
				return errs.Detail(ErrNoTarget, "attribute %q is absent | 属性 %q 不存在", path.Attribute, path.Attribute)
			}
			*list = nil
			return nil
		case patchReplace:
			entries, err := decodeMultiValues(value)
			if err != nil {
				return err
			}
			*list = entries
			return nil
		case patchAdd:
			entries, err := decodeMultiValues(value)
			if err != nil {
				return err
			}
			for _, entry := range entries {
				if !containsMultiValue(*list, entry) {
					*list = append(*list, entry)
				}
			}
			return nil
		}
	}
	indexes := matchedMultiIndexes(*list, path.ValueFilter)
	if len(indexes) == 0 {
		if kind == patchAdd {
			entries, err := decodeMultiValues(value)
			if err != nil {
				return err
			}
			*list = append(*list, entries...)
			return nil
		}
		return errs.Detail(ErrNoTarget, "no %q entry matches the value filter | 没有 %q 条目匹配值过滤器",
			path.Attribute, path.Attribute)
	}
	if kind == patchRemove {
		if path.SubAttribute != "" {
			for _, index := range indexes {
				if err := setMultiSubField(&(*list)[index], path.SubAttribute, patchRemove, nil); err != nil {
					return err
				}
			}
			return nil
		}
		removeMultiIndexes(list, indexes)
		return nil
	}
	if path.SubAttribute != "" {
		for _, index := range indexes {
			if err := setMultiSubField(&(*list)[index], path.SubAttribute, kind, value); err != nil {
				return err
			}
		}
		return nil
	}
	object, err := asObject(value)
	if err != nil {
		return err
	}
	for _, index := range indexes {
		if err := mergeMultiValueFields(&(*list)[index], object); err != nil {
			return err
		}
	}
	return nil
}

// setMultiSubField sets or clears one sub-attribute of m. | setMultiSubField 设置或清除 m 的一个
// 子属性。
func setMultiSubField(m *MultiValue, sub string, kind patchOpKind, value any) error {
	clearing := kind == patchRemove || value == nil
	text := func() (string, error) {
		if clearing {
			return "", nil
		}
		converted, ok := asString(value)
		if !ok {
			return "", errs.Detail(ErrInvalidValue, "sub-attribute %q must be a string | 子属性 %q 必须是字符串", sub, sub)
		}
		return converted, nil
	}
	switch strings.ToLower(sub) {
	case "value":
		converted, err := text()
		if err != nil {
			return err
		}
		m.Value = converted
	case "display":
		converted, err := text()
		if err != nil {
			return err
		}
		m.Display = converted
	case "type":
		converted, err := text()
		if err != nil {
			return err
		}
		m.Type = converted
	case "primary":
		if clearing {
			m.Primary = false
			return nil
		}
		converted, ok := asBool(value)
		if !ok {
			return errs.Detail(ErrInvalidValue, "sub-attribute primary must be a boolean | 子属性 primary 必须是布尔值")
		}
		m.Primary = converted
	case "$ref", "ref":
		converted, err := text()
		if err != nil {
			return err
		}
		m.Ref = converted
	default:
		return errs.Detail(ErrInvalidPath, "unknown sub-attribute %q | 未知的子属性 %q", sub, sub)
	}
	return nil
}

// mergeMultiValueFields merges object into m. | mergeMultiValueFields 把 object 合并到 m。
func mergeMultiValueFields(m *MultiValue, object map[string]any) error {
	for key := range object {
		if err := setMultiSubField(m, key, patchReplace, object[key]); err != nil {
			return err
		}
	}
	return nil
}

// decodeAddresses decodes an object or array into addresses. | decodeAddresses 把对象或数组解码为
// 地址。
func decodeAddresses(value any) ([]Address, error) {
	switch items := value.(type) {
	case []Address:
		out := make([]Address, len(items))
		copy(out, items)
		return out, nil
	case []any:
		out := make([]Address, 0, len(items))
		for _, item := range items {
			var address Address
			if err := decodeInto(item, &address); err != nil {
				return nil, err
			}
			out = append(out, address)
		}
		return out, nil
	case nil:
		return nil, errs.Detail(ErrInvalidValue, "missing addresses value | 缺少 addresses 值")
	}
	var single Address
	if err := decodeInto(value, &single); err != nil {
		return nil, err
	}
	return []Address{single}, nil
}

// containsAddress reports whether list already holds an equal address. | containsAddress 报告 list
// 是否已包含相同地址。
func containsAddress(list []Address, want Address) bool {
	for i := range list {
		if strings.EqualFold(list[i].Formatted, want.Formatted) &&
			strings.EqualFold(list[i].StreetAddress, want.StreetAddress) &&
			strings.EqualFold(list[i].Locality, want.Locality) &&
			strings.EqualFold(list[i].Region, want.Region) &&
			strings.EqualFold(list[i].PostalCode, want.PostalCode) &&
			strings.EqualFold(list[i].Country, want.Country) &&
			strings.EqualFold(list[i].Type, want.Type) {
			return true
		}
	}
	return false
}

// patchAddresses applies one operation to a []Address attribute. | patchAddresses 对一个 []Address
// 属性应用一个操作。
func patchAddresses(list *[]Address, path *AttributePath, kind patchOpKind, value any) error {
	if path.ValueFilter == nil {
		if path.SubAttribute != "" {
			return errs.Detail(ErrInvalidPath, "a value filter is required for sub-attribute %q | 子属性 %q 需要值过滤器",
				path.SubAttribute, path.SubAttribute)
		}
		switch kind {
		case patchRemove:
			if len(*list) == 0 {
				return errs.Detail(ErrNoTarget, "attribute %q is absent | 属性 %q 不存在", path.Attribute, path.Attribute)
			}
			*list = nil
			return nil
		case patchReplace:
			entries, err := decodeAddresses(value)
			if err != nil {
				return err
			}
			*list = entries
			return nil
		case patchAdd:
			entries, err := decodeAddresses(value)
			if err != nil {
				return err
			}
			for _, entry := range entries {
				if !containsAddress(*list, entry) {
					*list = append(*list, entry)
				}
			}
			return nil
		}
	}
	indexes := matchedAddressIndexes(*list, path.ValueFilter)
	if len(indexes) == 0 {
		if kind == patchAdd {
			entries, err := decodeAddresses(value)
			if err != nil {
				return err
			}
			*list = append(*list, entries...)
			return nil
		}
		return errs.Detail(ErrNoTarget, "no %q entry matches the value filter | 没有 %q 条目匹配值过滤器",
			path.Attribute, path.Attribute)
	}
	if kind == patchRemove {
		if path.SubAttribute != "" {
			for _, index := range indexes {
				if err := setAddressSubField(&(*list)[index], path.SubAttribute, patchRemove, nil); err != nil {
					return err
				}
			}
			return nil
		}
		removeAddressIndexes(list, indexes)
		return nil
	}
	if path.SubAttribute != "" {
		for _, index := range indexes {
			if err := setAddressSubField(&(*list)[index], path.SubAttribute, kind, value); err != nil {
				return err
			}
		}
		return nil
	}
	object, err := asObject(value)
	if err != nil {
		return err
	}
	for _, index := range indexes {
		if err := mergeAddressFields(&(*list)[index], object); err != nil {
			return err
		}
	}
	return nil
}

// matchedAddressIndexes returns the indexes selected by filter. | matchedAddressIndexes 返回被
// filter 选中的索引。
func matchedAddressIndexes(list []Address, filter Filter) []int {
	if filter == nil {
		return nil
	}
	indexes := make([]int, 0, len(list))
	for i := range list {
		if filter.Match(&list[i]) {
			indexes = append(indexes, i)
		}
	}
	return indexes
}

// removeAddressIndexes removes the selected indexes from list. | removeAddressIndexes 从 list 移除
// 选中的索引。
func removeAddressIndexes(list *[]Address, indexes []int) {
	drop := make(map[int]bool, len(indexes))
	for _, index := range indexes {
		drop[index] = true
	}
	out := (*list)[:0]
	for i := range *list {
		if !drop[i] {
			out = append(out, (*list)[i])
		}
	}
	*list = out
}

// setAddressSubField sets or clears one sub-attribute of a. | setAddressSubField 设置或清除 a 的
// 一个子属性。
func setAddressSubField(a *Address, sub string, kind patchOpKind, value any) error {
	clearing := kind == patchRemove || value == nil
	text := func() (string, error) {
		if clearing {
			return "", nil
		}
		converted, ok := asString(value)
		if !ok {
			return "", errs.Detail(ErrInvalidValue, "sub-attribute %q must be a string | 子属性 %q 必须是字符串", sub, sub)
		}
		return converted, nil
	}
	switch strings.ToLower(sub) {
	case "formatted":
		converted, err := text()
		if err != nil {
			return err
		}
		a.Formatted = converted
	case "streetaddress":
		converted, err := text()
		if err != nil {
			return err
		}
		a.StreetAddress = converted
	case "locality":
		converted, err := text()
		if err != nil {
			return err
		}
		a.Locality = converted
	case "region":
		converted, err := text()
		if err != nil {
			return err
		}
		a.Region = converted
	case "postalcode":
		converted, err := text()
		if err != nil {
			return err
		}
		a.PostalCode = converted
	case "country":
		converted, err := text()
		if err != nil {
			return err
		}
		a.Country = converted
	case "type":
		converted, err := text()
		if err != nil {
			return err
		}
		a.Type = converted
	case "primary":
		if clearing {
			a.Primary = false
			return nil
		}
		converted, ok := asBool(value)
		if !ok {
			return errs.Detail(ErrInvalidValue, "sub-attribute primary must be a boolean | 子属性 primary 必须是布尔值")
		}
		a.Primary = converted
	default:
		return errs.Detail(ErrInvalidPath, "unknown sub-attribute %q | 未知的子属性 %q", sub, sub)
	}
	return nil
}

// mergeAddressFields merges object into a. | mergeAddressFields 把 object 合并到 a。
func mergeAddressFields(a *Address, object map[string]any) error {
	for key := range object {
		if err := setAddressSubField(a, key, patchReplace, object[key]); err != nil {
			return err
		}
	}
	return nil
}

// decodeGroupMembers decodes a scalar, object or array into group members. | decodeGroupMembers 把
// 标量、对象或数组解码为组成员。
func decodeGroupMembers(value any) ([]GroupMember, error) {
	switch items := value.(type) {
	case []GroupMember:
		out := make([]GroupMember, len(items))
		copy(out, items)
		return out, nil
	case []string:
		out := make([]GroupMember, 0, len(items))
		for _, item := range items {
			if item == "" {
				return nil, errs.Detail(ErrInvalidValue, "member value must not be empty | 成员值不能为空")
			}
			out = append(out, GroupMember{Value: item})
		}
		return out, nil
	case []any:
		out := make([]GroupMember, 0, len(items))
		for _, item := range items {
			entries, err := decodeGroupMembers(item)
			if err != nil {
				return nil, err
			}
			out = append(out, entries...)
		}
		return out, nil
	case string:
		if items == "" {
			return nil, errs.Detail(ErrInvalidValue, "member value must not be empty | 成员值不能为空")
		}
		return []GroupMember{{Value: items}}, nil
	case nil:
		return nil, errs.Detail(ErrInvalidValue, "missing members value | 缺少 members 值")
	}
	var single GroupMember
	if err := decodeInto(value, &single); err != nil {
		return nil, err
	}
	if single.Value == "" {
		return nil, errs.Detail(ErrInvalidValue, "member requires value | 成员需要 value")
	}
	return []GroupMember{single}, nil
}

// containsGroupMember reports whether list already holds an entry with the same value. |
// containsGroupMember 报告 list 是否已包含相同 value 的成员。
func containsGroupMember(list []GroupMember, want GroupMember) bool {
	for i := range list {
		if list[i].Value == want.Value {
			return true
		}
	}
	return false
}

// patchGroupMembers applies one operation to a []GroupMember attribute. | patchGroupMembers 对一个
// []GroupMember 属性应用一个操作。
func patchGroupMembers(list *[]GroupMember, path *AttributePath, kind patchOpKind, value any) error {
	if path.ValueFilter == nil {
		if path.SubAttribute != "" {
			return errs.Detail(ErrInvalidPath, "a value filter is required for sub-attribute %q | 子属性 %q 需要值过滤器",
				path.SubAttribute, path.SubAttribute)
		}
		switch kind {
		case patchRemove:
			if len(*list) == 0 {
				return errs.Detail(ErrNoTarget, "members is absent | members 不存在")
			}
			*list = nil
			return nil
		case patchReplace:
			entries, err := decodeGroupMembers(value)
			if err != nil {
				return err
			}
			*list = entries
			return nil
		case patchAdd:
			entries, err := decodeGroupMembers(value)
			if err != nil {
				return err
			}
			for _, entry := range entries {
				if !containsGroupMember(*list, entry) {
					*list = append(*list, entry)
				}
			}
			return nil
		}
	}
	indexes := matchedMemberIndexes(*list, path.ValueFilter)
	if len(indexes) == 0 {
		if kind == patchAdd {
			entries, err := decodeGroupMembers(value)
			if err != nil {
				return err
			}
			*list = append(*list, entries...)
			return nil
		}
		return errs.Detail(ErrNoTarget, "no member matches the value filter | 没有成员匹配值过滤器")
	}
	if kind == patchRemove {
		if path.SubAttribute != "" {
			for _, index := range indexes {
				if err := setMemberSubField(&(*list)[index], path.SubAttribute, patchRemove, nil); err != nil {
					return err
				}
			}
			return nil
		}
		removeMemberIndexes(list, indexes)
		return nil
	}
	if path.SubAttribute != "" {
		for _, index := range indexes {
			if err := setMemberSubField(&(*list)[index], path.SubAttribute, kind, value); err != nil {
				return err
			}
		}
		return nil
	}
	object, err := asObject(value)
	if err != nil {
		return err
	}
	for _, index := range indexes {
		if err := mergeMemberFields(&(*list)[index], object); err != nil {
			return err
		}
	}
	return nil
}

// matchedMemberIndexes returns the indexes selected by filter. | matchedMemberIndexes 返回被 filter
// 选中的索引。
func matchedMemberIndexes(list []GroupMember, filter Filter) []int {
	if filter == nil {
		return nil
	}
	indexes := make([]int, 0, len(list))
	for i := range list {
		if filter.Match(&list[i]) {
			indexes = append(indexes, i)
		}
	}
	return indexes
}

// removeMemberIndexes removes the selected indexes from list. | removeMemberIndexes 从 list 移除
// 选中的索引。
func removeMemberIndexes(list *[]GroupMember, indexes []int) {
	drop := make(map[int]bool, len(indexes))
	for _, index := range indexes {
		drop[index] = true
	}
	out := (*list)[:0]
	for i := range *list {
		if !drop[i] {
			out = append(out, (*list)[i])
		}
	}
	*list = out
}

// setMemberSubField sets or clears one sub-attribute of a member. | setMemberSubField 设置或清除
// 成员的一个子属性。
func setMemberSubField(m *GroupMember, sub string, kind patchOpKind, value any) error {
	if kind == patchRemove || value == nil {
		switch strings.ToLower(sub) {
		case "value":
			m.Value = ""
		case "display":
			m.Display = ""
		case "type":
			m.Type = ""
		case "$ref", "ref":
			m.Ref = ""
		default:
			return errs.Detail(ErrInvalidPath, "unknown member sub-attribute %q | 未知的成员子属性 %q", sub, sub)
		}
		return nil
	}
	text, ok := asString(value)
	if !ok {
		return errs.Detail(ErrInvalidValue, "member sub-attribute %q must be a string | 成员子属性 %q 必须是字符串", sub, sub)
	}
	switch strings.ToLower(sub) {
	case "value":
		m.Value = text
	case "display":
		m.Display = text
	case "type":
		m.Type = text
	case "$ref", "ref":
		m.Ref = text
	default:
		return errs.Detail(ErrInvalidPath, "unknown member sub-attribute %q | 未知的成员子属性 %q", sub, sub)
	}
	return nil
}

// mergeMemberFields merges object into a group member. | mergeMemberFields 把 object 合并到组成员。
func mergeMemberFields(m *GroupMember, object map[string]any) error {
	for key := range object {
		if err := setMemberSubField(m, key, patchReplace, object[key]); err != nil {
			return err
		}
	}
	return nil
}
