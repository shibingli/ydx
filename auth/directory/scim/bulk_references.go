package scim

import (
	"bytes"
	"net/url"
	"sort"
	"strings"

	"github.com/shibingli/ydx/errs"
	ydxjson "github.com/shibingli/ydx/json"
)

// Bulk identifiers. | 批量标识。
//
// RFC 7644 section 3.7.2 defines a request-scoped reference as the string value "bulkId:<id>".
// It is a whole attribute value, not a token that may be embedded in a larger string, so
// substitution walks the decoded JSON tree and replaces only string values that equal a
// reference exactly. Object keys, substrings inside larger strings and non-string scalars are
// never rewritten. | RFC 7644 第 3.7.2 节把请求内引用定义为字符串值 "bulkId:<id>"。它是完整的属性
// 值，而不是可以嵌入更长字符串的标记，因此替换会遍历已解码的 JSON 树，只替换恰好等于引用的字符串值。
// 对象键、更长字符串中的子串与非字符串标量都不会被改写。

// bulkIDPrefix is the request-scoped reference prefix defined by RFC 7644 section 3.7.2. |
// bulkIDPrefix 是 RFC 7644 第 3.7.2 节定义的请求内引用前缀。
const bulkIDPrefix = "bulkId:"

// Bulk reference traversal guards. JSON cannot contain cycles, but nesting depth and container
// sizes are still bounded so a programmatic caller cannot force unbounded recursion or work
// before the configured payload limit applies. | 批量引用遍历上限。JSON 不可能包含环，但仍限制嵌套
// 深度与容器大小，避免程序化调用方在配置的负载上限生效前触发无界递归或工作量。
const (
	// bulkReferenceMaxDepth is the maximum object/array nesting depth. | bulkReferenceMaxDepth 是
	// 对象/数组的最大嵌套深度。
	bulkReferenceMaxDepth = 64
	// bulkReferenceMaxItems is the maximum number of entries in one object or array. |
	// bulkReferenceMaxItems 是单个对象或数组的最大条目数。
	bulkReferenceMaxItems = 1 << 16
	// bulkReferenceMaxNodes is the maximum number of values visited in one operation. |
	// bulkReferenceMaxNodes 是一次操作中访问的最大值数量。
	bulkReferenceMaxNodes = 1 << 20
)

// bulkIDReference reports whether value is exactly a bulkId reference and, if so, returns the
// referenced identifier. | bulkIDReference 报告 value 是否恰好是 bulkId 引用，若是则返回被引用的
// 标识。
func bulkIDReference(value string) (string, bool) {
	if !strings.HasPrefix(value, bulkIDPrefix) {
		return "", false
	}
	return value[len(bulkIDPrefix):], true
}

// bulkReferenceResolver resolves bulkId references in a decoded JSON tree. | bulkReferenceResolver
// 在已解码的 JSON 树中解析 bulkId 引用。
type bulkReferenceResolver struct {
	// ids maps bulk identifiers to created resource identifiers. | ids 把批量标识映射到已创建资源
	// 的标识。
	ids map[string]string
	// maxDepth bounds nesting. | maxDepth 限制嵌套深度。
	maxDepth int
	// maxItems bounds one container. | maxItems 限制单个容器大小。
	maxItems int
	// maxNodes bounds the whole traversal. | maxNodes 限制整体遍历规模。
	maxNodes int
	// nodes counts visited values. | nodes 统计已访问的值数量。
	nodes int
}

// resolveBulkReferences returns value with exact bulkId reference strings replaced by the
// identifiers created by earlier operations. It traverses objects in sorted key order, so
// errors and results are deterministic, and it never rewrites substrings. | resolveBulkReferences
// 用先前操作创建的标识替换恰好等于 bulkId 引用的字符串值。它按键排序遍历对象，因此错误与结果都是
// 确定的，并且绝不改写子串。
func resolveBulkReferences(value any, ids map[string]string) (any, error) {
	resolver := bulkReferenceResolver{
		ids:      ids,
		maxDepth: bulkReferenceMaxDepth,
		maxItems: bulkReferenceMaxItems,
		maxNodes: bulkReferenceMaxNodes,
	}
	return resolver.resolve(value, 0)
}

// resolve walks one value. | resolve 遍历一个值。
func (r *bulkReferenceResolver) resolve(value any, depth int) (any, error) {
	r.nodes++
	if r.nodes > r.maxNodes {
		return nil, errs.Detail(ErrTooMany, "bulkId references exceed %d values | bulkId 引用超过 %d 个值",
			r.maxNodes, r.maxNodes)
	}
	if depth > r.maxDepth {
		return nil, errs.Detail(ErrTooMany, "bulkId references exceed %d nesting levels | bulkId 引用超过 %d 层嵌套",
			r.maxDepth, r.maxDepth)
	}
	switch typed := value.(type) {
	case string:
		id, ok := bulkIDReference(typed)
		if !ok {
			return typed, nil
		}
		resolved, found := r.ids[id]
		if !found || resolved == "" {
			return nil, errs.Detail(ErrBulkIDUnresolved, "unresolved bulkId reference %q | 未解析的 bulkId 引用 %q",
				typed, typed)
		}
		return resolved, nil
	case map[string]any:
		if len(typed) > r.maxItems {
			return nil, errs.Detail(ErrTooMany, "bulkId object exceeds %d entries | bulkId 对象超过 %d 个条目",
				r.maxItems, r.maxItems)
		}
		keys := make([]string, 0, len(typed))
		for key := range typed {
			keys = append(keys, key)
		}
		sort.Strings(keys)
		for _, key := range keys {
			resolved, err := r.resolve(typed[key], depth+1)
			if err != nil {
				return nil, err
			}
			typed[key] = resolved
		}
		return typed, nil
	case []any:
		if len(typed) > r.maxItems {
			return nil, errs.Detail(ErrTooMany, "bulkId array exceeds %d elements | bulkId 数组超过 %d 个元素",
				r.maxItems, r.maxItems)
		}
		for i := range typed {
			resolved, err := r.resolve(typed[i], depth+1)
			if err != nil {
				return nil, err
			}
			typed[i] = resolved
		}
		return typed, nil
	default:
		return value, nil
	}
}

// resolveBulkPathReferences replaces path segments that are exactly bulkId references. A path is
// not a JSON document, so resolution is segment-wise rather than textual: a segment such as
// "user-bulkId:a" is a real identifier and stays untouched. | resolveBulkPathReferences 替换恰好为
// bulkId 引用的路径段。路径不是 JSON 文档，因此按段解析而非文本替换：像 "user-bulkId:a" 这样的段
// 是真实标识，保持原样。
func resolveBulkPathReferences(path string, ids map[string]string) (string, error) {
	if path == "" {
		return path, nil
	}
	target := path
	if parsed, err := url.Parse(path); err == nil && parsed.Path != "" {
		target = parsed.Path
	}
	segments := splitRequestPath(target)
	if len(segments) == 0 {
		return path, nil
	}
	for i, segment := range segments {
		id, ok := bulkIDReference(segment)
		if !ok {
			continue
		}
		resolved, found := ids[id]
		if !found || resolved == "" {
			return "", errs.Detail(ErrBulkIDUnresolved, "unresolved bulkId reference %q | 未解析的 bulkId 引用 %q",
				segment, segment)
		}
		segments[i] = resolved
	}
	return "/" + strings.Join(segments, "/"), nil
}

// decodeBulkData resolves bulkId references in data and decodes the result into target. Numbers
// are decoded through json.Number so the intermediate tree does not lose integer precision. |
// decodeBulkData 解析 data 中的 bulkId 引用并把结果解码到 target。数字经 json.Number 解码，避免
// 中间树丢失整数精度。
func decodeBulkData(data any, ids map[string]string, target any) error {
	if data == nil {
		return errs.Detail(ErrInvalidValue, "missing operation data | 缺少操作数据")
	}
	raw, err := ydxjson.Marshal(data)
	if err != nil {
		return errs.Detail(ErrInvalidValue, "invalid operation data | 非法操作数据")
	}
	decoder := ydxjson.NewDecoder(bytes.NewReader(raw))
	decoder.UseNumber()
	var decoded any
	if err := decoder.Decode(&decoded); err != nil {
		return errs.Detail(ErrInvalidValue, "invalid operation data | 非法操作数据")
	}
	resolved, err := resolveBulkReferences(decoded, ids)
	if err != nil {
		return err
	}
	if resolved == nil {
		return errs.Detail(ErrInvalidValue, "missing operation data | 缺少操作数据")
	}
	encoded, err := ydxjson.Marshal(resolved)
	if err != nil {
		return errs.Detail(ErrInvalidValue, "invalid operation data | 非法操作数据")
	}
	if err := ydxjson.Unmarshal(encoded, target); err != nil {
		return errs.Detail(ErrInvalidValue, "invalid operation data | 非法操作数据")
	}
	return nil
}

// substituteBulkIDs replaces bulkId tokens embedded in a plain text value. It backs the optional
// entity-tag precondition, where a reference may appear inside a quoted value; bulk operation
// data is resolved structurally by decodeBulkData and paths by resolveBulkPathReferences. Keys
// are applied longest first and in lexical order so a short key cannot corrupt a longer key that
// shares its prefix, and repeated runs are deterministic. | substituteBulkIDs 替换纯文本值中嵌入
// 的 bulkId 标记。它服务于可选的实体标签前置条件，其中引用可能出现在带引号的值内部；批量操作数据由
// decodeBulkData 结构化解析，路径由 resolveBulkPathReferences 解析。键按长度从长到短、同长按
// 字典序应用，因此短键不会破坏共享前缀的长键，重复运行结果一致。
func substituteBulkIDs(value string, ids map[string]string) string {
	if value == "" || len(ids) == 0 {
		return value
	}
	keys := make([]string, 0, len(ids))
	for key, id := range ids {
		if key != "" && id != "" {
			keys = append(keys, key)
		}
	}
	sort.Slice(keys, func(i, j int) bool {
		if len(keys[i]) != len(keys[j]) {
			return len(keys[i]) > len(keys[j])
		}
		return keys[i] < keys[j]
	})
	for _, key := range keys {
		value = strings.ReplaceAll(value, bulkIDPrefix+key, ids[key])
	}
	return value
}
