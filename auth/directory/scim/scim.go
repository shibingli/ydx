package scim

import (
	"crypto/rand"
	"encoding/hex"
	"strconv"
	"strings"
	"time"
)

// Schema URNs defined by RFC 7643 and RFC 7644. | RFC 7643 与 RFC 7644 定义的 Schema URN。
const (
	// UserSchema is the core User schema URN. | UserSchema 是核心 User Schema URN。
	UserSchema = "urn:ietf:params:scim:schemas:core:2.0:User"
	// GroupSchema is the core Group schema URN. | GroupSchema 是核心 Group Schema URN。
	GroupSchema = "urn:ietf:params:scim:schemas:core:2.0:Group"
	// EnterpriseUserSchema is the enterprise User extension schema URN. | EnterpriseUserSchema
	// 是企业 User 扩展 Schema URN。
	EnterpriseUserSchema = "urn:ietf:params:scim:schemas:extension:enterprise:2.0:User"
	// ListResponseSchema is the ListResponse message schema URN. | ListResponseSchema 是
	// ListResponse 消息 Schema URN。
	ListResponseSchema = "urn:ietf:params:scim:api:messages:2.0:ListResponse"
	// ErrorSchema is the Error message schema URN. | ErrorSchema 是 Error 消息 Schema URN。
	ErrorSchema = "urn:ietf:params:scim:api:messages:2.0:Error"
	// PatchOpSchema is the PATCH request message schema URN. | PatchOpSchema 是 PATCH 请求消息
	// Schema URN。
	PatchOpSchema = "urn:ietf:params:scim:api:messages:2.0:PatchOp"
	// BulkRequestSchema is the bulk request message schema URN. | BulkRequestSchema 是批量请求
	// 消息 Schema URN。
	BulkRequestSchema = "urn:ietf:params:scim:api:messages:2.0:BulkRequest"
	// BulkResponseSchema is the bulk response message schema URN. | BulkResponseSchema 是批量响应
	// 消息 Schema URN。
	BulkResponseSchema = "urn:ietf:params:scim:api:messages:2.0:BulkResponse"
	// SearchRequestSchema is the search request message schema URN. | SearchRequestSchema 是搜索
	// 请求消息 Schema URN。
	SearchRequestSchema = "urn:ietf:params:scim:api:messages:2.0:SearchRequest"
	// ServiceProviderConfigSchema is the service provider configuration schema URN. |
	// ServiceProviderConfigSchema 是服务提供方配置 Schema URN。
	ServiceProviderConfigSchema = "urn:ietf:params:scim:schemas:core:2.0:ServiceProviderConfig"
	// ResourceTypeSchema is the resource type schema URN. | ResourceTypeSchema 是资源类型 Schema URN。
	ResourceTypeSchema = "urn:ietf:params:scim:schemas:core:2.0:ResourceType"
	// SchemaSchema is the schema definition schema URN. | SchemaSchema 是 Schema 定义 Schema URN。
	SchemaSchema = "urn:ietf:params:scim:schemas:core:2.0:Schema"
)

// Media types used by SCIM. | SCIM 使用的媒体类型。
const (
	// ContentType is the SCIM JSON media type. | ContentType 是 SCIM JSON 媒体类型。
	ContentType = "application/scim+json"
	// ContentTypeJSON is the plain JSON media type accepted and emitted as a fallback. |
	// ContentTypeJSON 是作为兼容回退接受与输出的普通 JSON 媒体类型。
	ContentTypeJSON = "application/json"
)

// Default server limits. | 默认服务端限制。
const (
	// DefaultMaxResults is the default page size and the largest page a client may request. |
	// DefaultMaxResults 是默认分页大小，也是客户端可请求的最大分页大小。
	DefaultMaxResults = 200
	// DefaultBulkMaxOperations is the default maximum number of bulk operations per request. |
	// DefaultBulkMaxOperations 是单次批量请求默认的最大操作数。
	DefaultBulkMaxOperations = 1000
	// DefaultBulkMaxPayloadSize is the default maximum bulk request body size in bytes. |
	// DefaultBulkMaxPayloadSize 是批量请求体的默认最大字节数。
	DefaultBulkMaxPayloadSize = 1 << 20
	// DefaultBulkMaxUndoBytes is the default estimated memory bound of the atomic bulk undo log. |
	// DefaultBulkMaxUndoBytes 是原子批量撤销日志默认的估算内存上限。
	DefaultBulkMaxUndoBytes = 16 << 20
)

// Meta resource types returned by discovery and resource responses. | 发现与资源响应返回的 Meta
// 资源类型。
const (
	ResourceTypeNameUser   = "User"
	ResourceTypeNameGroup  = "Group"
	ResourceTypeNameBulk   = "Bulk"
	ResourceTypeNameSchema = "Schema"
	ResourceTypeNameType   = "ResourceType"
)

// Attribute type names defined by RFC 7643 section 2.2. | RFC 7643 第 2.2 节定义的属性类型名。
const (
	AttributeTypeString    = "string"
	AttributeTypeBoolean   = "boolean"
	AttributeTypeDecimal   = "decimal"
	AttributeTypeInteger   = "integer"
	AttributeTypeDateTime  = "dateTime"
	AttributeTypeBinary    = "binary"
	AttributeTypeReference = "reference"
	AttributeTypeComplex   = "complex"
)

// Attribute mutability values defined by RFC 7643 section 2.2. | RFC 7643 第 2.2 节定义的属性
// 可变性取值。
const (
	MutabilityReadOnly  = "readOnly"
	MutabilityReadWrite = "readWrite"
	MutabilityImmutable = "immutable"
	MutabilityWriteOnly = "writeOnly"
)

// Attribute returned values defined by RFC 7643 section 2.2. | RFC 7643 第 2.2 节定义的属性
// 返回策略取值。
const (
	ReturnedAlways  = "always"
	ReturnedNever   = "never"
	ReturnedDefault = "default"
	ReturnedRequest = "request"
)

// Attribute uniqueness values defined by RFC 7643 section 2.2. | RFC 7643 第 2.2 节定义的属性
// 唯一性取值。
const (
	UniquenessNone   = "none"
	UniquenessServer = "server"
	UniquenessGlobal = "global"
)

// knownSchemaURNs lists the schema URNs understood by this package. | knownSchemaURNs 列出本包
// 理解的 Schema URN。
var knownSchemaURNs = []string{
	UserSchema,
	GroupSchema,
	EnterpriseUserSchema,
	ServiceProviderConfigSchema,
	ResourceTypeSchema,
	SchemaSchema,
}

// timeLayout is the RFC 3339 layout used by SCIM dateTime values. | timeLayout 是 SCIM dateTime
// 取值使用的 RFC 3339 布局。
const timeLayout = time.RFC3339

// formatTime renders t in UTC RFC 3339 form. The zero time renders as an empty string. | formatTime
// 以 UTC RFC 3339 形式渲染 t。零值时间渲染为空字符串。
func formatTime(t time.Time) string {
	if t.IsZero() {
		return ""
	}
	return t.UTC().Format(timeLayout)
}

// parseTime parses a SCIM dateTime value; an empty or malformed value yields the zero time. |
// parseTime 解析 SCIM dateTime 取值；空值或非法值返回零值时间。
func parseTime(s string) time.Time {
	if s == "" {
		return time.Time{}
	}
	t, err := time.Parse(time.RFC3339, s)
	if err != nil {
		return time.Time{}
	}
	return t.UTC()
}

// newResourceID returns a random 128-bit hexadecimal identifier. | newResourceID 返回随机的
// 128 位十六进制标识。
func newResourceID() (string, error) {
	var buf [16]byte
	if _, err := rand.Read(buf[:]); err != nil {
		return "", err
	}
	return hex.EncodeToString(buf[:]), nil
}

// containsFold reports whether list contains want under Unicode case folding. | containsFold 报告
// list 在 Unicode 大小写折叠下是否包含 want。
func containsFold(list []string, want string) bool {
	for _, item := range list {
		if strings.EqualFold(item, want) {
			return true
		}
	}
	return false
}

// cloneStrings returns a copy of list. | cloneStrings 返回 list 的副本。
func cloneStrings(list []string) []string {
	if len(list) == 0 {
		return nil
	}
	return append([]string(nil), list...)
}

// isSchemaURN reports whether value is a known schema URN. | isSchemaURN 报告 value 是否为已知
// Schema URN。
func isSchemaURN(value string) bool {
	return containsFold(knownSchemaURNs, value)
}

// isCoreUserSchema reports whether value names the core User schema. | isCoreUserSchema 报告 value
// 是否命名核心 User Schema。
func isCoreUserSchema(value string) bool {
	return strings.EqualFold(value, UserSchema)
}

// isCoreGroupSchema reports whether value names the core Group schema. | isCoreGroupSchema 报告
// value 是否命名核心 Group Schema。
func isCoreGroupSchema(value string) bool {
	return strings.EqualFold(value, GroupSchema)
}

// isEnterpriseSchema reports whether value names the enterprise User extension schema. |
// isEnterpriseSchema 报告 value 是否命名企业 User 扩展 Schema。
func isEnterpriseSchema(value string) bool {
	return strings.EqualFold(value, EnterpriseUserSchema)
}

// boolPtr returns a pointer to value. | boolPtr 返回 value 的指针。
func boolPtr(value bool) *bool { return &value }

// intString renders an integer as a decimal string. | intString 把整数渲染为十进制字符串。
func intString(value int) string { return strconv.Itoa(value) }
