package scim

import (
	"sort"
	"strings"

	"github.com/shibingli/ydx/errs"
)

// PatchOperation is one RFC 7644 section 3.5.2 PATCH operation. | PatchOperation 是一个
// RFC 7644 第 3.5.2 节的 PATCH 操作。
type PatchOperation struct {
	// Value is the operation value: a scalar, object or array depending on the path. | Value 是
	// 操作值：依据路径不同可能是标量、对象或数组。
	Value any `json:"value,omitempty"`
	// Op is "add", "replace" or "remove", matched case-insensitively. | Op 取值为 "add"、
	// "replace" 或 "remove"，大小写不敏感。
	Op string `json:"op"`
	// Path is the optional target attribute path. | Path 是可选的目标属性路径。
	Path string `json:"path,omitempty"`
}

// patchOpKind classifies a parsed PATCH operation. | patchOpKind 对已解析的 PATCH 操作分类。
type patchOpKind uint8

const (
	// patchAdd appends to or replaces a target attribute value. | patchAdd 追加或替换目标属性值。
	patchAdd patchOpKind = iota
	// patchReplace replaces a target attribute value. | patchReplace 替换目标属性值。
	patchReplace
	// patchRemove removes a target attribute value. | patchRemove 移除目标属性值。
	patchRemove
)

// parsePatchOp parses an operation name case-insensitively. | parsePatchOp 以大小写不敏感方式解析
// 操作名。
func parsePatchOp(op string) (patchOpKind, error) {
	switch strings.ToLower(strings.TrimSpace(op)) {
	case "add":
		return patchAdd, nil
	case "replace":
		return patchReplace, nil
	case "remove":
		return patchRemove, nil
	}
	return 0, errs.Detail(ErrInvalidSyntax, "unsupported PATCH op %q | 不支持的 PATCH 操作 %q", op, op)
}

// ApplyPatch applies RFC 7644 section 3.5.2 PATCH operations to a copy of resource and returns
// the copy. Supported resource types are *User, User, *Group and Group. | ApplyPatch 对 resource
// 的副本应用 RFC 7644 第 3.5.2 节的 PATCH 操作并返回该副本。支持的资源类型为 *User、User、
// *Group 与 Group。
func ApplyPatch(resource any, operations []PatchOperation) (any, error) {
	switch value := resource.(type) {
	case *User:
		return ApplyUserPatch(value, operations)
	case User:
		return ApplyUserPatch(&value, operations)
	case *Group:
		return ApplyGroupPatch(value, operations)
	case Group:
		return ApplyGroupPatch(&value, operations)
	}
	return nil, errs.Detail(ErrUnsupported, "PATCH is not supported for %T | 不支持对 %T 执行 PATCH", resource, resource)
}

// ApplyUserPatch applies PATCH operations to a copy of user. The input value is never modified.
// | ApplyUserPatch 对 user 的副本应用 PATCH 操作，绝不修改输入值。
func ApplyUserPatch(user *User, operations []PatchOperation) (*User, error) {
	if user == nil {
		return nil, errs.Detail(ErrInvalidRequest, "nil User | User 为空")
	}
	out := user.Clone()
	for index := range operations {
		if err := applyUserOperation(out, operations[index]); err != nil {
			return nil, err
		}
	}
	normalizeUserMultiPrimary(out)
	pruneEnterpriseUser(out)
	out.EnsureSchemas()
	return out, nil
}

// ApplyGroupPatch applies PATCH operations to a copy of group. The input value is never modified.
// | ApplyGroupPatch 对 group 的副本应用 PATCH 操作，绝不修改输入值。
func ApplyGroupPatch(group *Group, operations []PatchOperation) (*Group, error) {
	if group == nil {
		return nil, errs.Detail(ErrInvalidRequest, "nil Group | Group 为空")
	}
	out := group.Clone()
	for index := range operations {
		if err := applyGroupOperation(out, operations[index]); err != nil {
			return nil, err
		}
	}
	out.EnsureSchemas()
	return out, nil
}

// applyUserOperation applies one operation to u. | applyUserOperation 对 u 应用一个操作。
func applyUserOperation(u *User, operation PatchOperation) error {
	kind, err := parsePatchOp(operation.Op)
	if err != nil {
		return err
	}
	text := strings.TrimSpace(operation.Path)
	if text == "" {
		if kind == patchRemove {
			return errs.Detail(ErrNoTarget, "remove requires a path | remove 需要 path")
		}
		if operation.Value == nil {
			return errs.Detail(ErrInvalidValue, "pathless operation requires an object value | 无路径操作需要对象值")
		}
		return patchUserObject(u, operation.Value, kind)
	}
	path, err := ParseAttributePath(text)
	if err != nil {
		return err
	}
	return applyUserPath(u, path, kind, operation.Value)
}

// applyGroupOperation applies one operation to g. | applyGroupOperation 对 g 应用一个操作。
func applyGroupOperation(g *Group, operation PatchOperation) error {
	kind, err := parsePatchOp(operation.Op)
	if err != nil {
		return err
	}
	text := strings.TrimSpace(operation.Path)
	if text == "" {
		if kind == patchRemove {
			return errs.Detail(ErrNoTarget, "remove requires a path | remove 需要 path")
		}
		if operation.Value == nil {
			return errs.Detail(ErrInvalidValue, "pathless operation requires an object value | 无路径操作需要对象值")
		}
		return patchGroupObject(g, operation.Value, kind)
	}
	path, err := ParseAttributePath(text)
	if err != nil {
		return err
	}
	return applyGroupPath(g, path, kind, operation.Value)
}

// patchUserObject applies a pathless operation value object to u. | patchUserObject 对 u 应用无路径
// 操作值对象。
func patchUserObject(u *User, value any, kind patchOpKind) error {
	object, err := asObject(value)
	if err != nil {
		return err
	}
	for _, key := range sortedObjectKeys(object) {
		path, err := ParseAttributePath(key)
		if err != nil {
			return err
		}
		if err := applyUserPath(u, path, kind, object[key]); err != nil {
			return err
		}
	}
	return nil
}

// patchGroupObject applies a pathless operation value object to g. | patchGroupObject 对 g 应用
// 无路径操作值对象。
func patchGroupObject(g *Group, value any, kind patchOpKind) error {
	object, err := asObject(value)
	if err != nil {
		return err
	}
	for _, key := range sortedObjectKeys(object) {
		path, err := ParseAttributePath(key)
		if err != nil {
			return err
		}
		if err := applyGroupPath(g, path, kind, object[key]); err != nil {
			return err
		}
	}
	return nil
}

// applyUserPath applies one operation to a User attribute path. | applyUserPath 对一个 User 属性
// 路径应用一个操作。
func applyUserPath(u *User, path *AttributePath, kind patchOpKind, value any) error {
	if path.Schema != "" && !isCoreUserSchema(path.Schema) && !isEnterpriseSchema(path.Schema) {
		return errs.Detail(ErrInvalidPath, "unknown User schema %q | 未知的 User Schema %q", path.Schema, path.Schema)
	}
	attribute := strings.ToLower(path.Attribute)
	if isEnterpriseSchema(path.Schema) {
		return applyEnterprisePath(u, path, kind, value)
	}
	if attribute == "" {
		// A bare core schema URN targets the whole resource. | 裸核心 Schema URN 作用于整个资源。
		if kind == patchRemove {
			return errs.Detail(ErrMutability, "cannot remove the core schema | 不能移除核心 Schema")
		}
		return patchUserObject(u, value, kind)
	}
	switch attribute {
	case "id", "groups", "meta", "schemas":
		return errs.Detail(ErrMutability, "attribute %q is read-only | 属性 %q 只读", path.Attribute, path.Attribute)
	case "username":
		if path.SubAttribute != "" {
			return errs.Detail(ErrInvalidPath, "userName has no sub-attribute %q | userName 没有子属性 %q", path.SubAttribute, path.SubAttribute)
		}
		return patchRequiredString(&u.UserName, path.Attribute, kind, value)
	case "externalid":
		return patchSimpleField(&u.ExternalID, path, kind, value)
	case "displayname":
		return patchSimpleField(&u.DisplayName, path, kind, value)
	case "nickname":
		return patchSimpleField(&u.NickName, path, kind, value)
	case "profileurl":
		return patchSimpleField(&u.ProfileURL, path, kind, value)
	case "title":
		return patchSimpleField(&u.Title, path, kind, value)
	case "usertype":
		return patchSimpleField(&u.UserType, path, kind, value)
	case "preferredlanguage":
		return patchSimpleField(&u.PreferredLanguage, path, kind, value)
	case "locale":
		return patchSimpleField(&u.Locale, path, kind, value)
	case "timezone":
		return patchSimpleField(&u.Timezone, path, kind, value)
	case "password":
		return patchSimpleField(&u.Password, path, kind, value)
	case "active":
		return patchActive(u, path, kind, value)
	case "name":
		return patchName(u, path, kind, value)
	case "emails":
		return patchMultiValues(&u.Emails, path, kind, value)
	case "phonenumbers":
		return patchMultiValues(&u.PhoneNumbers, path, kind, value)
	case "ims":
		return patchMultiValues(&u.IMs, path, kind, value)
	case "photos":
		return patchMultiValues(&u.Photos, path, kind, value)
	case "entitlements":
		return patchMultiValues(&u.Entitlements, path, kind, value)
	case "roles":
		return patchMultiValues(&u.Roles, path, kind, value)
	case "x509certificates":
		return patchMultiValues(&u.X509Certificates, path, kind, value)
	case "addresses":
		return patchAddresses(&u.Addresses, path, kind, value)
	}
	return errs.Detail(ErrInvalidPath, "unknown User attribute %q | 未知的 User 属性 %q", path.Attribute, path.Attribute)
}

// applyGroupPath applies one operation to a Group attribute path. | applyGroupPath 对一个 Group
// 属性路径应用一个操作。
func applyGroupPath(g *Group, path *AttributePath, kind patchOpKind, value any) error {
	if path.Schema != "" && !isCoreGroupSchema(path.Schema) {
		return errs.Detail(ErrInvalidPath, "unknown Group schema %q | 未知的 Group Schema %q", path.Schema, path.Schema)
	}
	attribute := strings.ToLower(path.Attribute)
	if attribute == "" {
		if kind == patchRemove {
			return errs.Detail(ErrMutability, "cannot remove the core schema | 不能移除核心 Schema")
		}
		return patchGroupObject(g, value, kind)
	}
	switch attribute {
	case "id", "meta", "schemas":
		return errs.Detail(ErrMutability, "attribute %q is read-only | 属性 %q 只读", path.Attribute, path.Attribute)
	case "externalid":
		return patchSimpleField(&g.ExternalID, path, kind, value)
	case "displayname":
		if path.SubAttribute != "" {
			return errs.Detail(ErrInvalidPath, "displayName has no sub-attribute %q | displayName 没有子属性 %q", path.SubAttribute, path.SubAttribute)
		}
		return patchRequiredString(&g.DisplayName, path.Attribute, kind, value)
	case "members":
		return patchGroupMembers(&g.Members, path, kind, value)
	}
	return errs.Detail(ErrInvalidPath, "unknown Group attribute %q | 未知的 Group 属性 %q", path.Attribute, path.Attribute)
}

// applyEnterprisePath applies one operation to the enterprise extension. | applyEnterprisePath 对
// 企业扩展应用一个操作。
func applyEnterprisePath(u *User, path *AttributePath, kind patchOpKind, value any) error {
	attribute := strings.ToLower(path.Attribute)
	if attribute == "" {
		switch kind {
		case patchRemove:
			if u.EnterpriseUser == nil {
				return errs.Detail(ErrNoTarget, "enterprise extension is absent | 企业扩展不存在")
			}
			u.EnterpriseUser = nil
			return nil
		case patchReplace:
			if value == nil {
				u.EnterpriseUser = nil
				return nil
			}
			replacement := &EnterpriseUser{}
			if err := decodeInto(value, replacement); err != nil {
				return err
			}
			u.EnterpriseUser = replacement
			return nil
		default:
			return patchEnterpriseObject(u, value)
		}
	}
	if u.EnterpriseUser == nil {
		if kind == patchRemove {
			return errs.Detail(ErrNoTarget, "enterprise extension is absent | 企业扩展不存在")
		}
		u.EnterpriseUser = &EnterpriseUser{}
	}
	switch attribute {
	case "employeenumber":
		return patchSimpleField(&u.EnterpriseUser.EmployeeNumber, path, kind, value)
	case "costcenter":
		return patchSimpleField(&u.EnterpriseUser.CostCenter, path, kind, value)
	case "organization":
		return patchSimpleField(&u.EnterpriseUser.Organization, path, kind, value)
	case "division":
		return patchSimpleField(&u.EnterpriseUser.Division, path, kind, value)
	case "department":
		return patchSimpleField(&u.EnterpriseUser.Department, path, kind, value)
	case "manager":
		return patchManager(&u.EnterpriseUser.Manager, path, kind, value)
	}
	return errs.Detail(ErrInvalidPath, "unknown enterprise attribute %q | 未知的企业扩展属性 %q", path.Attribute, path.Attribute)
}

// patchEnterpriseObject merges a pathless enterprise object into u. | patchEnterpriseObject 把无
// 路径企业对象合并到 u。
func patchEnterpriseObject(u *User, value any) error {
	object, err := asObject(value)
	if err != nil {
		return err
	}
	if u.EnterpriseUser == nil {
		u.EnterpriseUser = &EnterpriseUser{}
	}
	for _, key := range sortedObjectKeys(object) {
		path := &AttributePath{Schema: EnterpriseUserSchema, Attribute: key}
		if err := applyEnterprisePath(u, path, patchAdd, object[key]); err != nil {
			return err
		}
	}
	return nil
}

// patchSimpleField removes or replaces a scalar string sub-attribute path. | patchSimpleField 移除
// 或替换标量字符串子属性路径。
func patchSimpleField(dst *string, path *AttributePath, kind patchOpKind, value any) error {
	if path.SubAttribute != "" {
		return errs.Detail(ErrInvalidPath, "attribute %q has no sub-attribute %q | 属性 %q 没有子属性 %q",
			path.Attribute, path.SubAttribute, path.Attribute, path.SubAttribute)
	}
	return patchString(dst, kind, value)
}

// patchString removes or replaces a string field. | patchString 移除或替换字符串字段。
func patchString(dst *string, kind patchOpKind, value any) error {
	if kind == patchRemove || value == nil {
		*dst = ""
		return nil
	}
	text, ok := asString(value)
	if !ok {
		return errs.Detail(ErrInvalidValue, "expected a string value | 期望字符串值")
	}
	*dst = text
	return nil
}

// patchRequiredString replaces a required string attribute. Removing it, assigning nil or assigning
// an empty string would unassign a required attribute and is reported as ErrMutability per RFC 7644
// section 3.5.2. | patchRequiredString 替换必需字符串属性。移除、赋 nil 或赋空字符串都会取消必需
// 属性，按 RFC 7644 第 3.5.2 节报告 ErrMutability。
func patchRequiredString(dst *string, name string, kind patchOpKind, value any) error {
	if kind == patchRemove || value == nil {
		return errs.Detail(ErrMutability, "required attribute %q cannot be removed | 必需属性 %q 不可移除", name, name)
	}
	text, ok := asString(value)
	if !ok {
		return errs.Detail(ErrInvalidValue, "attribute %q must be a string | 属性 %q 必须是字符串", name, name)
	}
	if text == "" {
		return errs.Detail(ErrMutability, "required attribute %q cannot be unassigned | 必需属性 %q 不可置空", name, name)
	}
	*dst = text
	return nil
}

// patchActive removes or replaces the User active flag. | patchActive 移除或替换 User 的 active
// 标记。
func patchActive(u *User, path *AttributePath, kind patchOpKind, value any) error {
	if path.SubAttribute != "" {
		return errs.Detail(ErrInvalidPath, "active has no sub-attribute %q | active 没有子属性 %q", path.SubAttribute, path.SubAttribute)
	}
	if kind == patchRemove || value == nil {
		u.Active = nil
		return nil
	}
	active, ok := asBool(value)
	if !ok {
		return errs.Detail(ErrInvalidValue, "active must be a boolean | active 必须是布尔值")
	}
	u.SetActive(active)
	return nil
}

// patchName removes or modifies the User name attribute. | patchName 移除或修改 User 的 name 属性。
func patchName(u *User, path *AttributePath, kind patchOpKind, value any) error {
	if path.SubAttribute == "" {
		if kind == patchRemove || value == nil {
			if u.Name == nil && kind == patchRemove {
				return errs.Detail(ErrNoTarget, "name is absent | name 不存在")
			}
			u.Name = nil
			return nil
		}
		if kind == patchAdd {
			if u.Name == nil {
				u.Name = &Name{}
			}
			object, err := asObject(value)
			if err != nil {
				return err
			}
			return mergeNameFields(u.Name, object)
		}
		replacement := &Name{}
		if err := decodeInto(value, replacement); err != nil {
			return err
		}
		u.Name = replacement
		return nil
	}
	if u.Name == nil {
		if kind == patchRemove {
			return errs.Detail(ErrNoTarget, "name is absent | name 不存在")
		}
		u.Name = &Name{}
	}
	object := map[string]any{path.SubAttribute: value}
	if kind == patchRemove {
		object[path.SubAttribute] = ""
	}
	return mergeNameFields(u.Name, object)
}

// patchManager removes or modifies the enterprise manager attribute. | patchManager 移除或修改
// 企业扩展的 manager 属性。
func patchManager(dst **Manager, path *AttributePath, kind patchOpKind, value any) error {
	if path.SubAttribute == "" {
		if kind == patchRemove || value == nil {
			if *dst == nil && kind == patchRemove {
				return errs.Detail(ErrNoTarget, "manager is absent | manager 不存在")
			}
			*dst = nil
			return nil
		}
		if kind == patchAdd {
			if *dst == nil {
				*dst = &Manager{}
			}
			object, err := asObject(value)
			if err != nil {
				return err
			}
			return mergeManagerFields(*dst, object)
		}
		replacement := &Manager{}
		if err := decodeInto(value, replacement); err != nil {
			return err
		}
		*dst = replacement
		return nil
	}
	if *dst == nil {
		if kind == patchRemove {
			return errs.Detail(ErrNoTarget, "manager is absent | manager 不存在")
		}
		*dst = &Manager{}
	}
	object := map[string]any{path.SubAttribute: value}
	if kind == patchRemove {
		object[path.SubAttribute] = ""
	}
	return mergeManagerFields(*dst, object)
}

// normalizeUserMultiPrimary normalizes the primary flag of every multi-valued User attribute. |
// normalizeUserMultiPrimary 规范化 User 所有多值属性的 primary 标记。
func normalizeUserMultiPrimary(u *User) {
	normalizeMultiPrimary(u.Emails)
	normalizeMultiPrimary(u.PhoneNumbers)
	normalizeMultiPrimary(u.IMs)
	normalizeMultiPrimary(u.Photos)
	normalizeMultiPrimary(u.Entitlements)
	normalizeMultiPrimary(u.Roles)
	normalizeMultiPrimary(u.X509Certificates)
}

// pruneEnterpriseUser removes an empty enterprise extension. | pruneEnterpriseUser 移除空的企业扩展。
func pruneEnterpriseUser(u *User) {
	if u == nil || u.EnterpriseUser == nil {
		return
	}
	e := u.EnterpriseUser
	if e.EmployeeNumber == "" && e.CostCenter == "" && e.Organization == "" && e.Division == "" &&
		e.Department == "" && e.Manager == nil {
		u.EnterpriseUser = nil
	}
}

// sortedObjectKeys returns sorted map keys for deterministic processing. | sortedObjectKeys 返回
// 排序后的映射键，保证处理顺序确定。
func sortedObjectKeys(object map[string]any) []string {
	keys := make([]string, 0, len(object))
	for key := range object {
		keys = append(keys, key)
	}
	sort.Strings(keys)
	return keys
}
