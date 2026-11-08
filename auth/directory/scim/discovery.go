package scim

import (
	"net/http"
	"strings"

	"github.com/shibingli/ydx/errs"
)

// handleServiceProviderConfig serves GET /ServiceProviderConfig. | handleServiceProviderConfig 提供
// GET /ServiceProviderConfig。
func (s *Server) handleServiceProviderConfig(w http.ResponseWriter, r *http.Request) {
	if err := s.authorize(r, ActionRead, ResourceServiceProviderConfig); err != nil {
		writeError(w, err)
		return
	}
	writeSCIM(w, http.StatusOK, s.serviceProviderConfig(r))
}

// serviceProviderConfig builds the discovery document. | serviceProviderConfig 构建发现文档。
func (s *Server) serviceProviderConfig(r *http.Request) *ServiceProviderConfig {
	config := &ServiceProviderConfig{
		Schemas:          []string{ServiceProviderConfigSchema},
		DocumentationURI: s.documentationURI,
		Patch:            FeatureSupport{Supported: true},
		Bulk: BulkSupport{
			Supported:      true,
			MaxOperations:  s.bulkMaxOperations,
			MaxPayloadSize: s.bulkMaxPayloadSize,
		},
		Filter:         FilterSupport{Supported: true, MaxResults: s.maxResults},
		ChangePassword: FeatureSupport{Supported: s.passwordProvisioningConfigured()},
		Sort:           FeatureSupport{Supported: true},
		ETag:           FeatureSupport{Supported: true},
		AuthenticationSchemes: []AuthenticationScheme{
			{
				Type:             "oauthbearertoken",
				Name:             "OAuth Bearer Token",
				Description:      "Authentication using an OAuth 2.0 bearer token | 使用 OAuth 2.0 持有者令牌认证",
				SpecURI:          "https://www.rfc-editor.org/info/rfc6750",
				DocumentationURI: s.documentationURI,
				Primary:          true,
			},
		},
		Meta: &Meta{
			ResourceType: ResourceTypeNameType,
			Location:     s.baseURLFor(r) + "/ServiceProviderConfig",
		},
	}
	return config
}

// handleResourceTypes serves GET /ResourceTypes. | handleResourceTypes 提供 GET /ResourceTypes。
func (s *Server) handleResourceTypes(w http.ResponseWriter, r *http.Request) {
	if err := s.authorize(r, ActionRead, ResourceResourceType); err != nil {
		writeError(w, err)
		return
	}
	definitions := s.resourceTypes(r)
	resources := make([]any, 0, len(definitions))
	for _, definition := range definitions {
		resources = append(resources, definition)
	}
	writeSCIM(w, http.StatusOK, listEnvelope(resources))
}

// handleResourceType serves GET /ResourceTypes/{name}. | handleResourceType 提供
// GET /ResourceTypes/{name}。
func (s *Server) handleResourceType(w http.ResponseWriter, r *http.Request, name string) {
	if err := s.authorize(r, ActionRead, ResourceResourceType); err != nil {
		writeError(w, err)
		return
	}
	for _, definition := range s.resourceTypes(r) {
		if strings.EqualFold(definition.ID, name) || strings.EqualFold(definition.Name, name) {
			writeSCIM(w, http.StatusOK, definition)
			return
		}
	}
	writeError(w, errs.Detail(ErrNotFound, "unknown resource type %q | 未知资源类型 %q", name, name))
}

// handleSchemas serves GET /Schemas. | handleSchemas 提供 GET /Schemas。
func (s *Server) handleSchemas(w http.ResponseWriter, r *http.Request) {
	if err := s.authorize(r, ActionRead, ResourceSchemaDefinition); err != nil {
		writeError(w, err)
		return
	}
	definitions := s.schemaDefinitions(r)
	resources := make([]any, 0, len(definitions))
	for _, definition := range definitions {
		resources = append(resources, definition)
	}
	writeSCIM(w, http.StatusOK, listEnvelope(resources))
}

// handleSchema serves GET /Schemas/{urn}. | handleSchema 提供 GET /Schemas/{urn}。
func (s *Server) handleSchema(w http.ResponseWriter, r *http.Request, urn string) {
	if err := s.authorize(r, ActionRead, ResourceSchemaDefinition); err != nil {
		writeError(w, err)
		return
	}
	for _, definition := range s.schemaDefinitions(r) {
		if strings.EqualFold(definition.ID, urn) {
			writeSCIM(w, http.StatusOK, definition)
			return
		}
	}
	writeError(w, errs.Detail(ErrNotFound, "unknown schema %q | 未知 Schema %q", urn, urn))
}

// listEnvelope wraps resources in a discovery ListResponse. | listEnvelope 把资源包装为发现
// ListResponse。
func listEnvelope(resources []any) ListResponse {
	return ListResponse{
		Schemas:      []string{ListResponseSchema},
		TotalResults: len(resources),
		StartIndex:   1,
		ItemsPerPage: len(resources),
		Resources:    resources,
	}
}

// resourceTypes returns the User and Group resource type definitions. | resourceTypes 返回 User 与
// Group 资源类型定义。
func (s *Server) resourceTypes(r *http.Request) []*ResourceTypeDefinition {
	base := s.baseURLFor(r)
	return []*ResourceTypeDefinition{
		{
			Schemas:     []string{ResourceTypeSchema},
			ID:          ResourceTypeNameUser,
			Name:        ResourceTypeNameUser,
			Endpoint:    "/Users",
			Description: "User Account | 用户账号",
			Schema:      UserSchema,
			SchemaExtensions: []SchemaExtension{
				{Schema: EnterpriseUserSchema, Required: false},
			},
			Meta: &Meta{
				ResourceType: ResourceTypeNameType,
				Location:     base + "/ResourceTypes/" + ResourceTypeNameUser,
			},
		},
		{
			Schemas:     []string{ResourceTypeSchema},
			ID:          ResourceTypeNameGroup,
			Name:        ResourceTypeNameGroup,
			Endpoint:    "/Groups",
			Description: "Group | 组",
			Schema:      GroupSchema,
			Meta: &Meta{
				ResourceType: ResourceTypeNameType,
				Location:     base + "/ResourceTypes/" + ResourceTypeNameGroup,
			},
		},
	}
}

// schemaDefinitions returns the User, Group and EnterpriseUser schemas. | schemaDefinitions 返回
// User、Group 与 EnterpriseUser Schema。
func (s *Server) schemaDefinitions(r *http.Request) []*SchemaDefinition {
	base := s.baseURLFor(r)
	definitions := []*SchemaDefinition{
		{
			Schemas:     []string{SchemaSchema},
			ID:          UserSchema,
			Name:        ResourceTypeNameUser,
			Description: "User Account | 用户账号",
			Attributes:  userSchemaAttributes(),
		},
		{
			Schemas:     []string{SchemaSchema},
			ID:          EnterpriseUserSchema,
			Name:        "EnterpriseUser",
			Description: "Enterprise User Extension | 企业用户扩展",
			Attributes:  enterpriseUserSchemaAttributes(),
		},
		{
			Schemas:     []string{SchemaSchema},
			ID:          GroupSchema,
			Name:        ResourceTypeNameGroup,
			Description: "Group | 组",
			Attributes:  groupSchemaAttributes(),
		},
	}
	for _, definition := range definitions {
		definition.Meta = &Meta{
			ResourceType: ResourceTypeNameSchema,
			Location:     base + "/Schemas/" + definition.ID,
		}
	}
	return definitions
}

// schemaString returns a readWrite string attribute with the common defaults. | schemaString 返回带有
// 通用默认值的 readWrite 字符串属性。
func schemaString(name, description string) Attribute {
	return Attribute{
		Name:        name,
		Type:        AttributeTypeString,
		Description: description,
		Mutability:  MutabilityReadWrite,
		Returned:    ReturnedDefault,
		Uniqueness:  UniquenessNone,
	}
}

// schemaSubString returns a readWrite string sub-attribute. | schemaSubString 返回 readWrite 字符串
// 子属性。
func schemaSubString(name, description string) Attribute {
	sub := schemaString(name, description)
	sub.Description = description
	return sub
}

// userSchemaAttributes returns the core User attributes from RFC 7643 section 4.1. | userSchemaAttributes
// 返回 RFC 7643 第 4.1 节的核心 User 属性。
func userSchemaAttributes() []Attribute {
	return []Attribute{
		{
			Name:        "userName",
			Type:        AttributeTypeString,
			Description: "Unique user name | 唯一用户名",
			Required:    true,
			Mutability:  MutabilityReadWrite,
			Returned:    ReturnedDefault,
			Uniqueness:  UniquenessServer,
		},
		{
			Name:        "name",
			Type:        AttributeTypeComplex,
			Description: "Full name | 完整姓名",
			Mutability:  MutabilityReadWrite,
			Returned:    ReturnedDefault,
			Uniqueness:  UniquenessNone,
			SubAttributes: []Attribute{
				schemaSubString("formatted", "Formatted name | 格式化姓名"),
				schemaSubString("familyName", "Family name | 姓"),
				schemaSubString("givenName", "Given name | 名"),
				schemaSubString("middleName", "Middle name | 中间名"),
				schemaSubString("honorificPrefix", "Honorific prefix | 称谓前缀"),
				schemaSubString("honorificSuffix", "Honorific suffix | 称谓后缀"),
			},
		},
		schemaString("displayName", "Display name | 显示名"),
		schemaString("nickName", "Nickname | 昵称"),
		{
			Name:           "profileUrl",
			Type:           AttributeTypeReference,
			Description:    "Profile URL | 资料 URL",
			Mutability:     MutabilityReadWrite,
			Returned:       ReturnedDefault,
			Uniqueness:     UniquenessNone,
			ReferenceTypes: []string{"external"},
		},
		schemaString("title", "Title | 头衔"),
		schemaString("userType", "User type | 用户类型"),
		schemaString("preferredLanguage", "Preferred language | 首选语言"),
		schemaString("locale", "Locale | 区域设置"),
		schemaString("timezone", "Timezone | 时区"),
		{
			Name:        "active",
			Type:        AttributeTypeBoolean,
			Description: "Active status | 激活状态",
			Mutability:  MutabilityReadWrite,
			Returned:    ReturnedDefault,
			Uniqueness:  UniquenessNone,
		},
		{
			Name:        "password",
			Type:        AttributeTypeString,
			Description: "Write-only password | 只写口令",
			Mutability:  MutabilityWriteOnly,
			Returned:    ReturnedNever,
			Uniqueness:  UniquenessNone,
		},
		multiValueAttribute("emails", "Email addresses | 电子邮件地址",
			[]string{"work", "home", "other"}),
		multiValueAttribute("phoneNumbers", "Phone numbers | 电话号码",
			[]string{"work", "home", "mobile", "fax", "pager", "other"}),
		multiValueAttribute("ims", "Instant messaging addresses | 即时通讯地址",
			[]string{"aim", "gtalk", "icq", "xmpp", "msn", "skype", "qq"}),
		{
			Name:        "photos",
			Type:        AttributeTypeComplex,
			Description: "Photos | 照片",
			MultiValued: true,
			Mutability:  MutabilityReadWrite,
			Returned:    ReturnedDefault,
			Uniqueness:  UniquenessNone,
			SubAttributes: []Attribute{
				schemaSubString("value", "Photo URL | 照片 URL"),
				schemaSubString("display", "Display name | 显示名"),
				{
					Name:            "type",
					Type:            AttributeTypeString,
					Description:     "Photo type | 照片类型",
					Mutability:      MutabilityReadWrite,
					Returned:        ReturnedDefault,
					Uniqueness:      UniquenessNone,
					CanonicalValues: []string{"photo", "thumbnail"},
				},
				{
					Name:        "primary",
					Type:        AttributeTypeBoolean,
					Description: "Primary flag | 首选标记",
					Mutability:  MutabilityReadWrite,
					Returned:    ReturnedDefault,
					Uniqueness:  UniquenessNone,
				},
			},
		},
		{
			Name:        "addresses",
			Type:        AttributeTypeComplex,
			Description: "Addresses | 地址",
			MultiValued: true,
			Mutability:  MutabilityReadWrite,
			Returned:    ReturnedDefault,
			Uniqueness:  UniquenessNone,
			SubAttributes: []Attribute{
				schemaSubString("formatted", "Formatted address | 格式化地址"),
				schemaSubString("streetAddress", "Street address | 街道地址"),
				schemaSubString("locality", "Locality | 城市"),
				schemaSubString("region", "Region | 省/州"),
				schemaSubString("postalCode", "Postal code | 邮政编码"),
				schemaSubString("country", "Country | 国家"),
				{
					Name:            "type",
					Type:            AttributeTypeString,
					Description:     "Address type | 地址类型",
					Mutability:      MutabilityReadWrite,
					Returned:        ReturnedDefault,
					Uniqueness:      UniquenessNone,
					CanonicalValues: []string{"work", "home", "other"},
				},
				{
					Name:        "primary",
					Type:        AttributeTypeBoolean,
					Description: "Primary flag | 首选标记",
					Mutability:  MutabilityReadWrite,
					Returned:    ReturnedDefault,
					Uniqueness:  UniquenessNone,
				},
			},
		},
		{
			Name:        "groups",
			Type:        AttributeTypeComplex,
			Description: "Group memberships | 组隶属关系",
			MultiValued: true,
			Mutability:  MutabilityReadOnly,
			Returned:    ReturnedDefault,
			Uniqueness:  UniquenessNone,
			SubAttributes: []Attribute{
				schemaSubString("value", "Group identifier | 组标识"),
				{
					Name:           "$ref",
					Type:           AttributeTypeReference,
					Description:    "Group reference | 组引用",
					Mutability:     MutabilityReadWrite,
					Returned:       ReturnedDefault,
					Uniqueness:     UniquenessNone,
					ReferenceTypes: []string{ResourceTypeNameGroup},
				},
				schemaSubString("display", "Display name | 显示名"),
				{
					Name:            "type",
					Type:            AttributeTypeString,
					Description:     "Membership type | 隶属类型",
					Mutability:      MutabilityReadWrite,
					Returned:        ReturnedDefault,
					Uniqueness:      UniquenessNone,
					CanonicalValues: []string{"direct", "indirect"},
				},
			},
		},
		multiValueAttribute("entitlements", "Entitlements | 权限项", nil),
		multiValueAttribute("roles", "Roles | 角色", nil),
		{
			Name:        "x509Certificates",
			Type:        AttributeTypeComplex,
			Description: "X.509 certificates | X.509 证书",
			MultiValued: true,
			Mutability:  MutabilityReadWrite,
			Returned:    ReturnedDefault,
			Uniqueness:  UniquenessNone,
			SubAttributes: []Attribute{
				{
					Name:        "value",
					Type:        AttributeTypeBinary,
					Description: "Certificate value | 证书值",
					Mutability:  MutabilityReadWrite,
					Returned:    ReturnedDefault,
					Uniqueness:  UniquenessNone,
				},
				schemaSubString("display", "Display name | 显示名"),
				schemaSubString("type", "Certificate type | 证书类型"),
				{
					Name:        "primary",
					Type:        AttributeTypeBoolean,
					Description: "Primary flag | 首选标记",
					Mutability:  MutabilityReadWrite,
					Returned:    ReturnedDefault,
					Uniqueness:  UniquenessNone,
				},
			},
		},
		{
			Name:        "meta",
			Type:        AttributeTypeComplex,
			Description: "Resource metadata | 资源元数据",
			Mutability:  MutabilityReadOnly,
			Returned:    ReturnedDefault,
			Uniqueness:  UniquenessNone,
			SubAttributes: []Attribute{
				{
					Name:        "resourceType",
					Type:        AttributeTypeString,
					Description: "Resource type | 资源类型",
					Mutability:  MutabilityReadOnly,
					Returned:    ReturnedDefault,
					Uniqueness:  UniquenessNone,
				},
				{
					Name:        "created",
					Type:        AttributeTypeDateTime,
					Description: "Creation time | 创建时间",
					Mutability:  MutabilityReadOnly,
					Returned:    ReturnedDefault,
					Uniqueness:  UniquenessNone,
				},
				{
					Name:        "lastModified",
					Type:        AttributeTypeDateTime,
					Description: "Last modification time | 最后修改时间",
					Mutability:  MutabilityReadOnly,
					Returned:    ReturnedDefault,
					Uniqueness:  UniquenessNone,
				},
				{
					Name:        "location",
					Type:        AttributeTypeReference,
					Description: "Resource URL | 资源 URL",
					Mutability:  MutabilityReadOnly,
					Returned:    ReturnedDefault,
					Uniqueness:  UniquenessNone,
				},
				{
					Name:        "version",
					Type:        AttributeTypeString,
					Description: "Entity tag | 实体标签",
					Mutability:  MutabilityReadOnly,
					Returned:    ReturnedDefault,
					Uniqueness:  UniquenessNone,
				},
			},
		},
	}
}

// multiValueAttribute returns a readWrite multi-valued complex attribute with the standard SCIM
// sub-attributes. | multiValueAttribute 返回带标准 SCIM 子属性的 readWrite 多值复杂属性。
func multiValueAttribute(name, description string, canonical []string) Attribute {
	display := schemaSubString("display", "Display name | 显示名")
	// RFC 7643 section 4.1.2 defines display as readOnly for every multi-valued
	// attribute. | RFC 7643 第 4.1.2 节规定所有多值属性的 display 均为 readOnly。
	display.Mutability = MutabilityReadOnly
	return Attribute{
		Name:        name,
		Type:        AttributeTypeComplex,
		Description: description,
		MultiValued: true,
		Mutability:  MutabilityReadWrite,
		Returned:    ReturnedDefault,
		Uniqueness:  UniquenessNone,
		SubAttributes: []Attribute{
			{
				Name:        "value",
				Type:        AttributeTypeString,
				Description: "Value | 值",
				Required:    true,
				Mutability:  MutabilityReadWrite,
				Returned:    ReturnedDefault,
				Uniqueness:  UniquenessNone,
			},
			display,
			{
				Name:            "type",
				Type:            AttributeTypeString,
				Description:     "Value type | 值类型",
				Mutability:      MutabilityReadWrite,
				Returned:        ReturnedDefault,
				Uniqueness:      UniquenessNone,
				CanonicalValues: canonical,
			},
			{
				Name:        "primary",
				Type:        AttributeTypeBoolean,
				Description: "Primary flag | 首选标记",
				Mutability:  MutabilityReadWrite,
				Returned:    ReturnedDefault,
				Uniqueness:  UniquenessNone,
			},
		},
	}
}

// enterpriseUserSchemaAttributes returns the enterprise extension attributes from RFC 7643 section
// 4.3. | enterpriseUserSchemaAttributes 返回 RFC 7643 第 4.3 节的企业扩展属性。
func enterpriseUserSchemaAttributes() []Attribute {
	return []Attribute{
		schemaString("employeeNumber", "Employee number | 员工编号"),
		schemaString("costCenter", "Cost center | 成本中心"),
		schemaString("organization", "Organization | 组织"),
		schemaString("division", "Division | 部门"),
		schemaString("department", "Department | 部门"),
		{
			Name:        "manager",
			Type:        AttributeTypeComplex,
			Description: "Manager | 管理者",
			Mutability:  MutabilityReadWrite,
			Returned:    ReturnedDefault,
			Uniqueness:  UniquenessNone,
			SubAttributes: []Attribute{
				schemaSubString("value", "Manager identifier | 管理者标识"),
				{
					Name:           "$ref",
					Type:           AttributeTypeReference,
					Description:    "Manager reference | 管理者引用",
					Mutability:     MutabilityReadWrite,
					Returned:       ReturnedDefault,
					Uniqueness:     UniquenessNone,
					ReferenceTypes: []string{ResourceTypeNameUser},
				},
				schemaSubString("displayName", "Display name | 显示名"),
			},
		},
	}
}

// groupSchemaAttributes returns the core Group attributes from RFC 7643 section 4.2. |
// groupSchemaAttributes 返回 RFC 7643 第 4.2 节的核心 Group 属性。
func groupSchemaAttributes() []Attribute {
	return []Attribute{
		{
			Name:        "displayName",
			Type:        AttributeTypeString,
			Description: "Group display name | 组显示名",
			Required:    true,
			Mutability:  MutabilityReadWrite,
			Returned:    ReturnedDefault,
			Uniqueness:  UniquenessServer,
		},
		{
			Name:        "members",
			Type:        AttributeTypeComplex,
			Description: "Group members | 组成员",
			MultiValued: true,
			Mutability:  MutabilityReadWrite,
			Returned:    ReturnedDefault,
			Uniqueness:  UniquenessNone,
			SubAttributes: []Attribute{
				schemaSubString("value", "Member identifier | 成员标识"),
				{
					Name:           "$ref",
					Type:           AttributeTypeReference,
					Description:    "Member reference | 成员引用",
					Mutability:     MutabilityReadWrite,
					Returned:       ReturnedDefault,
					Uniqueness:     UniquenessNone,
					ReferenceTypes: []string{ResourceTypeNameUser, ResourceTypeNameGroup},
				},
				schemaSubString("display", "Display name | 显示名"),
				{
					Name:            "type",
					Type:            AttributeTypeString,
					Description:     "Member type | 成员类型",
					Mutability:      MutabilityReadWrite,
					Returned:        ReturnedDefault,
					Uniqueness:      UniquenessNone,
					CanonicalValues: []string{ResourceTypeNameUser, ResourceTypeNameGroup},
				},
			},
		},
		{
			Name:        "meta",
			Type:        AttributeTypeComplex,
			Description: "Resource metadata | 资源元数据",
			Mutability:  MutabilityReadOnly,
			Returned:    ReturnedDefault,
			Uniqueness:  UniquenessNone,
		},
	}
}
