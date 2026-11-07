package scim

import (
	"strings"

	"github.com/shibingli/ydx/errs"
	ydxjson "github.com/shibingli/ydx/json"
)

// selectionLeaf marks a fully selected attribute in a selection tree. | selectionLeaf 在选择树中
// 标记完整选择的属性。
type selectionLeaf struct{}

// buildSelection parses RFC 7644 attributes into a nested selection tree. | buildSelection 把
// RFC 7644 attributes 解析为嵌套选择树。
func buildSelection(paths []string) (map[string]any, error) {
	tree := make(map[string]any)
	for _, raw := range paths {
		raw = strings.TrimSpace(raw)
		if raw == "" {
			continue
		}
		path, err := ParseAttributePath(raw)
		if err != nil {
			return nil, errs.Detail(ErrInvalidValue, "invalid attribute path %q | 非法属性路径 %q", raw, raw)
		}
		if path.ValueFilter != nil {
			return nil, errs.Detail(ErrInvalidValue, "value filters are not allowed in attribute selection | 属性选择不允许值过滤器")
		}
		parts := attributeJSONPath(path)
		if len(parts) == 0 {
			continue
		}
		node := tree
		for _, part := range parts[:len(parts)-1] {
			child, ok := node[part].(map[string]any)
			if !ok {
				child = make(map[string]any)
				node[part] = child
			}
			node = child
		}
		node[parts[len(parts)-1]] = selectionLeaf{}
	}
	return tree, nil
}

// attributeJSONPath maps a parsed SCIM path onto JSON object keys. | attributeJSONPath 把已解析 SCIM
// 路径映射为 JSON 对象键。
func attributeJSONPath(path *AttributePath) []string {
	if path == nil {
		return nil
	}
	if isEnterpriseSchema(path.Schema) {
		parts := []string{EnterpriseUserSchema}
		if path.Attribute != "" {
			parts = append(parts, path.Attribute)
		}
		if path.SubAttribute != "" {
			parts = append(parts, path.SubAttribute)
		}
		return parts
	}
	if path.Schema != "" && !isCoreUserSchema(path.Schema) && !isCoreGroupSchema(path.Schema) {
		parts := []string{path.Schema}
		if path.Attribute != "" {
			parts = append(parts, path.Attribute)
		}
		if path.SubAttribute != "" {
			parts = append(parts, path.SubAttribute)
		}
		return parts
	}
	parts := make([]string, 0, 2)
	if path.Attribute != "" {
		parts = append(parts, path.Attribute)
	}
	if path.SubAttribute != "" {
		parts = append(parts, path.SubAttribute)
	}
	return parts
}

// projectResource applies attributes or excludedAttributes to a resource. | projectResource 对资源
// 应用 attributes 或 excludedAttributes。
func projectResource(resource any, attributes, excluded []string) (any, error) {
	if len(attributes) == 0 && len(excluded) == 0 {
		return resource, nil
	}
	data, err := ydxjson.Marshal(resource)
	if err != nil {
		return nil, errs.Detail(ErrInternal, "cannot encode resource | 无法编码资源")
	}
	var object map[string]any
	if err := ydxjson.Unmarshal(data, &object); err != nil {
		return nil, errs.Detail(ErrInternal, "cannot decode resource | 无法解码资源")
	}
	if len(attributes) > 0 {
		tree, err := buildSelection(attributes)
		if err != nil {
			return nil, err
		}
		selected := make(map[string]any)
		for _, name := range []string{"schemas", "id", "meta"} {
			if key, value, ok := ciMapEntry(object, name); ok {
				selected[key] = value
			}
		}
		mergeSelection(selected, object, tree)
		return selected, nil
	}
	tree, err := buildSelection(excluded)
	if err != nil {
		return nil, err
	}
	removeSelection(object, tree, true)
	return object, nil
}

// ciMapEntry returns the matching key and value under case-insensitive key matching. | ciMapEntry
// 在大小写不敏感的键匹配下返回匹配键与值。
func ciMapEntry(object map[string]any, name string) (string, any, bool) {
	if value, ok := object[name]; ok {
		return name, value, true
	}
	for key, value := range object {
		if strings.EqualFold(key, name) {
			return key, value, true
		}
	}
	return "", nil, false
}

// mergeSelection copies selected values from src into dst. | mergeSelection 把 src 中选中的值复制
// 到 dst。
func mergeSelection(dst, src map[string]any, tree map[string]any) {
	for name, child := range tree {
		key, value, ok := ciMapEntry(src, name)
		if !ok {
			continue
		}
		if _, leaf := child.(selectionLeaf); leaf {
			dst[key] = value
			continue
		}
		subtree, _ := child.(map[string]any)
		switch typed := value.(type) {
		case map[string]any:
			projected := make(map[string]any)
			mergeSelection(projected, typed, subtree)
			dst[key] = projected
		case []any:
			projected := make([]any, 0, len(typed))
			for _, item := range typed {
				entry, ok := item.(map[string]any)
				if !ok {
					projected = append(projected, item)
					continue
				}
				projectedEntry := make(map[string]any)
				mergeSelection(projectedEntry, entry, subtree)
				projected = append(projected, projectedEntry)
			}
			dst[key] = projected
		default:
			dst[key] = value
		}
	}
}

// removeSelection deletes selected values from object. Top-level id, schemas and meta are always
// retained. | removeSelection 从 object 删除选中的值。顶层 id、schemas 与 meta 始终保留。
func removeSelection(object map[string]any, tree map[string]any, root bool) {
	for name, child := range tree {
		if root && isAlwaysReturned(name) {
			continue
		}
		key, value, ok := ciMapEntry(object, name)
		if !ok {
			continue
		}
		if _, leaf := child.(selectionLeaf); leaf {
			delete(object, key)
			continue
		}
		subtree, _ := child.(map[string]any)
		switch typed := value.(type) {
		case map[string]any:
			removeSelection(typed, subtree, false)
		case []any:
			for _, item := range typed {
				if entry, ok := item.(map[string]any); ok {
					removeSelection(entry, subtree, false)
				}
			}
		}
	}
}

// isAlwaysReturned reports whether name is unconditionally returned at the resource root. |
// isAlwaysReturned 报告 name 是否在资源根上无条件返回。
func isAlwaysReturned(name string) bool {
	switch strings.ToLower(name) {
	case "id", "schemas", "meta":
		return true
	}
	return false
}
