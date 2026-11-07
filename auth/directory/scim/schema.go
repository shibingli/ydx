package scim

// Meta is the common SCIM resource metadata as defined by RFC 7643 section 3.1. | Meta 是
// RFC 7643 第 3.1 节定义的通用 SCIM 资源元数据。
type Meta struct {
	// ResourceType is the resource type name, for example "User". | ResourceType 是资源类型名，
	// 例如 "User"。
	ResourceType string `json:"resourceType,omitempty"`
	// Created is the RFC 3339 creation timestamp. | Created 是 RFC 3339 创建时间戳。
	Created string `json:"created,omitempty"`
	// LastModified is the RFC 3339 last modification timestamp. | LastModified 是 RFC 3339 最后
	// 修改时间戳。
	LastModified string `json:"lastModified,omitempty"`
	// Location is the absolute URL of the resource. | Location 是资源的绝对 URL。
	Location string `json:"location,omitempty"`
	// Version is the entity tag of the resource. | Version 是资源的实体标签。
	Version string `json:"version,omitempty"`
}

// Clone returns a deep copy of m. | Clone 返回 m 的深拷贝。
func (m *Meta) Clone() *Meta {
	if m == nil {
		return nil
	}
	c := *m
	return &c
}

// SchemaDefinition is the SCIM schema representation returned by /Schemas. | SchemaDefinition 是
// /Schemas 返回的 SCIM Schema 表示。
type SchemaDefinition struct {
	// Meta is the resource metadata. | Meta 是资源元数据。
	Meta *Meta `json:"meta,omitempty"`
	// ID is the schema URN. | ID 是 Schema URN。
	ID string `json:"id,omitempty"`
	// Name is the human-readable schema name. | Name 是可读的 Schema 名称。
	Name string `json:"name"`
	// Description explains the schema. | Description 说明该 Schema。
	Description string `json:"description,omitempty"`
	// Schemas is the message schema list. | Schemas 是消息 Schema 列表。
	Schemas []string `json:"schemas"`
	// Attributes lists the schema attributes. | Attributes 列出 Schema 属性。
	Attributes []Attribute `json:"attributes"`
}

// Clone returns a deep copy of s. | Clone 返回 s 的深拷贝。
func (s *SchemaDefinition) Clone() *SchemaDefinition {
	if s == nil {
		return nil
	}
	c := *s
	c.Schemas = cloneStrings(s.Schemas)
	c.Attributes = cloneAttributes(s.Attributes)
	c.Meta = s.Meta.Clone()
	return &c
}

// Attribute describes one SCIM schema attribute as defined by RFC 7643 section 7. | Attribute
// 描述 RFC 7643 第 7 节定义的一个 SCIM Schema 属性。
type Attribute struct {
	// Name is the attribute name. | Name 是属性名。
	Name string `json:"name"`
	// Type is the attribute type: string, boolean, decimal, integer, dateTime, binary, reference
	// or complex. | Type 是属性类型：string、boolean、decimal、integer、dateTime、binary、reference
	// 或 complex。
	Type string `json:"type"`
	// Description explains the attribute. | Description 说明该属性。
	Description string `json:"description,omitempty"`
	// Mutability is readOnly, readWrite, immutable or writeOnly. | Mutability 取值为 readOnly、
	// readWrite、immutable 或 writeOnly。
	Mutability string `json:"mutability"`
	// Returned is always, never, default or request. | Returned 取值为 always、never、default 或
	// request。
	Returned string `json:"returned"`
	// Uniqueness is none, server or global. | Uniqueness 取值为 none、server 或 global。
	Uniqueness string `json:"uniqueness"`
	// SubAttributes describes the members of a complex attribute. | SubAttributes 描述复杂属性的
	// 成员。
	SubAttributes []Attribute `json:"subAttributes,omitempty"`
	// CanonicalValues lists the permitted values when the attribute is enumerated. | CanonicalValues
	// 在属性为枚举时列出允许值。
	CanonicalValues []string `json:"canonicalValues,omitempty"`
	// ReferenceTypes lists the resource types a reference may point to. | ReferenceTypes 列出引用
	// 可能指向的资源类型。
	ReferenceTypes []string `json:"referenceTypes,omitempty"`
	// MultiValued reports whether the attribute holds a list of values. | MultiValued 表示属性是否
	// 保存值列表。
	MultiValued bool `json:"multiValued"`
	// Required reports whether the attribute is required. | Required 表示属性是否必需。
	Required bool `json:"required"`
	// CaseExact reports whether string comparison is case-sensitive. | CaseExact 表示字符串比较
	// 是否区分大小写。
	CaseExact bool `json:"caseExact"`
}

// Clone returns a deep copy of a. | Clone 返回 a 的深拷贝。
func (a Attribute) Clone() Attribute {
	c := a
	c.SubAttributes = cloneAttributes(a.SubAttributes)
	c.CanonicalValues = cloneStrings(a.CanonicalValues)
	c.ReferenceTypes = cloneStrings(a.ReferenceTypes)
	return c
}

// cloneAttributes returns a deep copy of list. | cloneAttributes 返回 list 的深拷贝。
func cloneAttributes(list []Attribute) []Attribute {
	if len(list) == 0 {
		return nil
	}
	out := make([]Attribute, len(list))
	for i, item := range list {
		out[i] = item.Clone()
	}
	return out
}

// SchemaExtension names an extension schema of a resource type. | SchemaExtension 命名资源类型的
// 扩展 Schema。
type SchemaExtension struct {
	// Schema is the extension schema URN. | Schema 是扩展 Schema URN。
	Schema string `json:"schema"`
	// Required reports whether clients must understand the extension. | Required 表示客户端是否
	// 必须理解该扩展。
	Required bool `json:"required"`
}

// ResourceTypeDefinition is the SCIM resource type representation returned by /ResourceTypes. |
// ResourceTypeDefinition 是 /ResourceTypes 返回的 SCIM 资源类型表示。
type ResourceTypeDefinition struct {
	// Meta is the resource metadata. | Meta 是资源元数据。
	Meta *Meta `json:"meta,omitempty"`
	// ID is the resource type identifier. | ID 是资源类型标识。
	ID string `json:"id,omitempty"`
	// Name is the resource type name. | Name 是资源类型名称。
	Name string `json:"name"`
	// Endpoint is the relative endpoint of the resource, for example "/Users". | Endpoint 是资源的
	// 相对端点，例如 "/Users"。
	Endpoint string `json:"endpoint"`
	// Description explains the resource type. | Description 说明该资源类型。
	Description string `json:"description,omitempty"`
	// Schema is the core schema URN. | Schema 是核心 Schema URN。
	Schema string `json:"schema"`
	// Schemas is the message schema list. | Schemas 是消息 Schema 列表。
	Schemas []string `json:"schemas"`
	// SchemaExtensions lists optional extension schemas. | SchemaExtensions 列出可选扩展 Schema。
	SchemaExtensions []SchemaExtension `json:"schemaExtensions,omitempty"`
}

// Clone returns a deep copy of r. | Clone 返回 r 的深拷贝。
func (r *ResourceTypeDefinition) Clone() *ResourceTypeDefinition {
	if r == nil {
		return nil
	}
	c := *r
	c.Schemas = cloneStrings(r.Schemas)
	c.SchemaExtensions = append([]SchemaExtension(nil), r.SchemaExtensions...)
	c.Meta = r.Meta.Clone()
	return &c
}

// FeatureSupport is a boolean capability flag used by ServiceProviderConfig. | FeatureSupport 是
// ServiceProviderConfig 使用的布尔能力标记。
type FeatureSupport struct {
	// Supported reports whether the feature is available. | Supported 表示功能是否可用。
	Supported bool `json:"supported"`
}

// BulkSupport describes bulk capabilities. | BulkSupport 描述批量能力。
type BulkSupport struct {
	// Supported reports whether bulk is available. | Supported 表示批量操作是否可用。
	Supported bool `json:"supported"`
	// MaxOperations is the maximum number of operations in one request. | MaxOperations 是单次请求
	// 的最大操作数。
	MaxOperations int `json:"maxOperations"`
	// MaxPayloadSize is the maximum request body size in bytes. | MaxPayloadSize 是请求体的最大
	// 字节数。
	MaxPayloadSize int64 `json:"maxPayloadSize"`
}

// FilterSupport describes filter capabilities. | FilterSupport 描述过滤器能力。
type FilterSupport struct {
	// Supported reports whether filtering is available. | Supported 表示过滤是否可用。
	Supported bool `json:"supported"`
	// MaxResults is the maximum number of resources returned by one page. | MaxResults 是单页返回
	// 的最大资源数。
	MaxResults int `json:"maxResults"`
}

// AuthenticationScheme describes one supported authentication mechanism. | AuthenticationScheme
// 描述一种受支持的认证机制。
type AuthenticationScheme struct {
	// Type is the scheme type, for example "oauthbearertoken". | Type 是方案类型，例如
	// "oauthbearertoken"。
	Type string `json:"type"`
	// Name is the human-readable scheme name. | Name 是可读的方案名称。
	Name string `json:"name"`
	// Description explains the scheme. | Description 说明该方案。
	Description string `json:"description,omitempty"`
	// SpecURI points to the defining specification. | SpecURI 指向定义规范。
	SpecURI string `json:"specUri,omitempty"`
	// DocumentationURI points to local documentation. | DocumentationURI 指向本地文档。
	DocumentationURI string `json:"documentationUri,omitempty"`
	// Primary marks the preferred scheme. | Primary 标记首选方案。
	Primary bool `json:"primary,omitempty"`
}

// ServiceProviderConfig is the /ServiceProviderConfig response defined by RFC 7643 section 6. |
// ServiceProviderConfig 是 RFC 7643 第 6 节定义的 /ServiceProviderConfig 响应。
type ServiceProviderConfig struct {
	// Meta is the resource metadata. | Meta 是资源元数据。
	Meta *Meta `json:"meta,omitempty"`
	// DocumentationURI points to service documentation. | DocumentationURI 指向服务文档。
	DocumentationURI string `json:"documentationUri,omitempty"`
	// Schemas is the message schema list. | Schemas 是消息 Schema 列表。
	Schemas []string `json:"schemas"`
	// AuthenticationSchemes lists the supported authentication schemes. | AuthenticationSchemes
	// 列出受支持的认证方案。
	AuthenticationSchemes []AuthenticationScheme `json:"authenticationSchemes"`
	// Bulk describes bulk support. | Bulk 描述批量支持。
	Bulk BulkSupport `json:"bulk"`
	// Filter describes filter support. | Filter 描述过滤支持。
	Filter FilterSupport `json:"filter"`
	// Patch describes PATCH support. | Patch 描述 PATCH 支持。
	Patch FeatureSupport `json:"patch"`
	// ChangePassword describes password change support. | ChangePassword 描述口令修改支持。
	ChangePassword FeatureSupport `json:"changePassword"`
	// Sort describes sort support. | Sort 描述排序支持。
	Sort FeatureSupport `json:"sort"`
	// ETag describes entity tag support. | ETag 描述实体标签支持。
	ETag FeatureSupport `json:"etag"`
}

// Clone returns a deep copy of c. | Clone 返回 c 的深拷贝。
func (c *ServiceProviderConfig) Clone() *ServiceProviderConfig {
	if c == nil {
		return nil
	}
	out := *c
	out.Schemas = cloneStrings(c.Schemas)
	out.AuthenticationSchemes = append([]AuthenticationScheme(nil), c.AuthenticationSchemes...)
	out.Meta = c.Meta.Clone()
	return &out
}

// ListResponse is the RFC 7644 section 3.4.2 list envelope. | ListResponse 是 RFC 7644 第 3.4.2
// 节的列表信封。
type ListResponse struct {
	// Schemas is the message schema list. | Schemas 是消息 Schema 列表。
	Schemas []string `json:"schemas"`
	// Resources holds the page of resources. | Resources 保存本页资源。
	Resources []any `json:"Resources"`
	// TotalResults is the number of matching resources before pagination. | TotalResults 是分页前
	// 的匹配资源总数。
	TotalResults int `json:"totalResults"`
	// StartIndex is the 1-based index of the first returned resource. | StartIndex 是首个返回资源
	// 的 1 基索引。
	StartIndex int `json:"startIndex"`
	// ItemsPerPage is the number of resources in this response. | ItemsPerPage 是本响应中的资源数。
	ItemsPerPage int `json:"itemsPerPage"`
}

// Error is the RFC 7644 section 3.12 error response. | Error 是 RFC 7644 第 3.12 节的错误响应。
type Error struct {
	// Status is the HTTP status code rendered as a string. | Status 是渲染为字符串的 HTTP 状态码。
	Status string `json:"status,omitempty"`
	// ScimType is the machine-readable RFC 7644 error type. | ScimType 是机器可读的 RFC 7644 错误
	// 类型。
	ScimType string `json:"scimType,omitempty"`
	// Detail is a human-readable description that never contains secrets. | Detail 是可读描述，
	// 绝不包含密钥。
	Detail string `json:"detail,omitempty"`
	// Schemas is the message schema list. | Schemas 是消息 Schema 列表。
	Schemas []string `json:"schemas"`
}

// SearchRequest is the RFC 7644 section 3.4.3 POST .search body. | SearchRequest 是 RFC 7644
// 第 3.4.3 节 POST .search 的请求体。
type SearchRequest struct {
	// Filter is the RFC 7644 filter expression. | Filter 是 RFC 7644 过滤表达式。
	Filter string `json:"filter,omitempty"`
	// SortBy is the attribute path used for sorting. | SortBy 是用于排序的属性路径。
	SortBy string `json:"sortBy,omitempty"`
	// SortOrder is "ascending" or "descending". | SortOrder 取值为 "ascending" 或 "descending"。
	SortOrder string `json:"sortOrder,omitempty"`
	// Schemas is the message schema list. | Schemas 是消息 Schema 列表。
	Schemas []string `json:"schemas,omitempty"`
	// Attributes selects the returned attributes. | Attributes 选择返回的属性。
	Attributes []string `json:"attributes,omitempty"`
	// ExcludedAttributes removes attributes from the response. | ExcludedAttributes 从响应中移除
	// 属性。
	ExcludedAttributes []string `json:"excludedAttributes,omitempty"`
	// StartIndex is the 1-based first result index. | StartIndex 是 1 基的首个结果索引。
	StartIndex int `json:"startIndex,omitempty"`
	// Count is the requested page size. | Count 是请求的分页大小。
	Count int `json:"count,omitempty"`
}

// PatchRequest is the RFC 7644 section 3.5.2 PATCH body. | PatchRequest 是 RFC 7644 第 3.5.2 节
// 的 PATCH 请求体。
type PatchRequest struct {
	// Schemas is the message schema list; PatchOpSchema is required by the RFC. | Schemas 是消息
	// Schema 列表；RFC 要求包含 PatchOpSchema。
	Schemas []string `json:"schemas,omitempty"`
	// Operations is the ordered list of patch operations. | Operations 是有序的补丁操作列表。
	Operations []PatchOperation `json:"Operations"`
}
