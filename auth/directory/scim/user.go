package scim

// Name is the User name complex attribute defined by RFC 7643 section 4.1.1. | Name 是
// RFC 7643 第 4.1.1 节定义的 User name 复杂属性。
type Name struct {
	// Formatted is the complete formatted name. | Formatted 是完整的格式化姓名。
	Formatted string `json:"formatted,omitempty"`
	// FamilyName is the family or last name. | FamilyName 是姓。
	FamilyName string `json:"familyName,omitempty"`
	// GivenName is the given or first name. | GivenName 是名。
	GivenName string `json:"givenName,omitempty"`
	// MiddleName is the middle name. | MiddleName 是中间名。
	MiddleName string `json:"middleName,omitempty"`
	// HonorificPrefix is the honorific prefix. | HonorificPrefix 是称谓前缀。
	HonorificPrefix string `json:"honorificPrefix,omitempty"`
	// HonorificSuffix is the honorific suffix. | HonorificSuffix 是称谓后缀。
	HonorificSuffix string `json:"honorificSuffix,omitempty"`
}

// Clone returns a deep copy of n. | Clone 返回 n 的深拷贝。
func (n *Name) Clone() *Name {
	if n == nil {
		return nil
	}
	c := *n
	return &c
}

// MultiValue is a multi-valued attribute member with the RFC 7643 value / display / type /
// primary / $ref shape. | MultiValue 是具有 RFC 7643 value / display / type / primary / $ref
// 结构的多值属性成员。
type MultiValue struct {
	// Value is the attribute value. | Value 是属性值。
	Value string `json:"value"`
	// Display is the human-readable display form. | Display 是可读的展示形式。
	Display string `json:"display,omitempty"`
	// Type is the value type, for example "work" or "home". | Type 是值的类型，例如 "work" 或
	// "home"。
	Type string `json:"type,omitempty"`
	// Ref is the URI of the referenced value. | Ref 是引用值的 URI。
	Ref string `json:"$ref,omitempty"`
	// Primary marks the preferred value. | Primary 标记首选值。
	Primary bool `json:"primary,omitempty"`
}

// Clone returns a deep copy of m. | Clone 返回 m 的深拷贝。
func (m *MultiValue) Clone() *MultiValue {
	if m == nil {
		return nil
	}
	c := *m
	return &c
}

// Address is the User address complex attribute defined by RFC 7643 section 4.1.2. | Address 是
// RFC 7643 第 4.1.2 节定义的 User address 复杂属性。
type Address struct {
	// Formatted is the complete formatted address. | Formatted 是完整的格式化地址。
	Formatted string `json:"formatted,omitempty"`
	// StreetAddress is the street component. | StreetAddress 是街道部分。
	StreetAddress string `json:"streetAddress,omitempty"`
	// Locality is the city or locality. | Locality 是城市或地区。
	Locality string `json:"locality,omitempty"`
	// Region is the state or region. | Region 是州或省。
	Region string `json:"region,omitempty"`
	// PostalCode is the postal code. | PostalCode 是邮政编码。
	PostalCode string `json:"postalCode,omitempty"`
	// Country is the country name. | Country 是国家名。
	Country string `json:"country,omitempty"`
	// Type is the address type, for example "work" or "home". | Type 是地址类型，例如 "work" 或
	// "home"。
	Type string `json:"type,omitempty"`
	// Primary marks the preferred address. | Primary 标记首选地址。
	Primary bool `json:"primary,omitempty"`
}

// Clone returns a deep copy of a. | Clone 返回 a 的深拷贝。
func (a *Address) Clone() *Address {
	if a == nil {
		return nil
	}
	c := *a
	return &c
}

// GroupValue is the read-only groups attribute member of a User resource. | GroupValue 是 User
// 资源中只读 groups 属性的成员。
type GroupValue struct {
	// Value is the group identifier. | Value 是组标识。
	Value string `json:"value,omitempty"`
	// Display is the group display name. | Display 是组展示名。
	Display string `json:"display,omitempty"`
	// Type is the group type. | Type 是组类型。
	Type string `json:"type,omitempty"`
	// Ref is the absolute URI of the group resource. | Ref 是组资源的绝对 URI。
	Ref string `json:"$ref,omitempty"`
}

// Clone returns a deep copy of g. | Clone 返回 g 的深拷贝。
func (g *GroupValue) Clone() *GroupValue {
	if g == nil {
		return nil
	}
	c := *g
	return &c
}

// Manager is the enterprise User manager complex attribute. | Manager 是企业 User 的 manager
// 复杂属性。
type Manager struct {
	// Value is the manager user identifier. | Value 是经理用户标识。
	Value string `json:"value,omitempty"`
	// DisplayName is the manager display name. | DisplayName 是经理展示名。
	DisplayName string `json:"displayName,omitempty"`
	// Ref is the absolute URI of the manager resource. | Ref 是经理资源的绝对 URI。
	Ref string `json:"$ref,omitempty"`
}

// Clone returns a deep copy of m. | Clone 返回 m 的深拷贝。
func (m *Manager) Clone() *Manager {
	if m == nil {
		return nil
	}
	c := *m
	return &c
}

// EnterpriseUser is the enterprise User extension defined by RFC 7643 section 4.3. | EnterpriseUser
// 是 RFC 7643 第 4.3 节定义的企业 User 扩展。
type EnterpriseUser struct {
	// Manager is the direct manager. | Manager 是直属经理。
	Manager *Manager `json:"manager,omitempty"`
	// EmployeeNumber is the employee number. | EmployeeNumber 是员工编号。
	EmployeeNumber string `json:"employeeNumber,omitempty"`
	// CostCenter is the cost center. | CostCenter 是成本中心。
	CostCenter string `json:"costCenter,omitempty"`
	// Organization is the organization name. | Organization 是组织名称。
	Organization string `json:"organization,omitempty"`
	// Division is the division name. | Division 是部门名称。
	Division string `json:"division,omitempty"`
	// Department is the department name. | Department 是科室名称。
	Department string `json:"department,omitempty"`
}

// Clone returns a deep copy of e. | Clone 返回 e 的深拷贝。
func (e *EnterpriseUser) Clone() *EnterpriseUser {
	if e == nil {
		return nil
	}
	c := *e
	c.Manager = e.Manager.Clone()
	return &c
}

// User is the SCIM core User resource defined by RFC 7643 section 4.1. | User 是 RFC 7643
// 第 4.1 节定义的 SCIM 核心 User 资源。
type User struct {
	// Name is the structured name. | Name 是结构化姓名。
	Name *Name `json:"name,omitempty"`
	// Active reports whether the account may be used; nil means the RFC default true. | Active
	// 表示账号是否可用；nil 表示 RFC 默认值 true。
	Active *bool `json:"active,omitempty"`
	// EnterpriseUser is the enterprise extension value. | EnterpriseUser 是企业扩展值。
	EnterpriseUser *EnterpriseUser `json:"urn:ietf:params:scim:schemas:extension:enterprise:2.0:User,omitempty"`
	// Meta is the resource metadata. | Meta 是资源元数据。
	Meta *Meta `json:"meta,omitempty"`
	// ID is the immutable server-assigned identifier. | ID 是不可变的服务端分配标识。
	ID string `json:"id,omitempty"`
	// ExternalID is the provisioning identifier from an upstream directory. | ExternalID 是上级
	// 目录的预配标识。
	ExternalID string `json:"externalId,omitempty"`
	// UserName is the unique login name. | UserName 是唯一登录名。
	UserName string `json:"userName"`
	// DisplayName is the human-readable display name. | DisplayName 是可读展示名。
	DisplayName string `json:"displayName,omitempty"`
	// NickName is the casual name. | NickName 是昵称。
	NickName string `json:"nickName,omitempty"`
	// ProfileURL is the URI of a profile page. | ProfileURL 是资料页 URI。
	ProfileURL string `json:"profileUrl,omitempty"`
	// Title is the user's title. | Title 是用户头衔。
	Title string `json:"title,omitempty"`
	// UserType is the user type, for example "Employee". | UserType 是用户类型，例如 "Employee"。
	UserType string `json:"userType,omitempty"`
	// PreferredLanguage is the preferred language tag. | PreferredLanguage 是首选语言标签。
	PreferredLanguage string `json:"preferredLanguage,omitempty"`
	// Locale is the locale identifier. | Locale 是区域标识。
	Locale string `json:"locale,omitempty"`
	// Timezone is the IANA time zone name. | Timezone 是 IANA 时区名。
	Timezone string `json:"timezone,omitempty"`
	// Password is write-only and never appears in a response. | Password 只写，绝不出现在响应中。
	Password string `json:"password,omitempty"`
	// Schemas is the resource schema list, including the enterprise extension when present. |
	// Schemas 是资源 Schema 列表，存在企业扩展时包含该扩展。
	Schemas []string `json:"schemas"`
	// Emails lists email addresses. | Emails 列出邮箱地址。
	Emails []MultiValue `json:"emails,omitempty"`
	// PhoneNumbers lists phone numbers. | PhoneNumbers 列出电话号码。
	PhoneNumbers []MultiValue `json:"phoneNumbers,omitempty"`
	// IMs lists instant messaging addresses. | IMs 列出即时消息地址。
	IMs []MultiValue `json:"ims,omitempty"`
	// Photos lists photo URIs. | Photos 列出照片 URI。
	Photos []MultiValue `json:"photos,omitempty"`
	// Addresses lists postal addresses. | Addresses 列出邮政地址。
	Addresses []Address `json:"addresses,omitempty"`
	// Groups lists group memberships and is read-only. | Groups 列出组成员关系，只读。
	Groups []GroupValue `json:"groups,omitempty"`
	// Entitlements lists entitlements. | Entitlements 列出权益。
	Entitlements []MultiValue `json:"entitlements,omitempty"`
	// Roles lists roles. | Roles 列出角色。
	Roles []MultiValue `json:"roles,omitempty"`
	// X509Certificates lists X.509 certificates. | X509Certificates 列出 X.509 证书。
	X509Certificates []MultiValue `json:"x509Certificates,omitempty"`
}

// Clone returns a deep copy of u. | Clone 返回 u 的深拷贝。
func (u *User) Clone() *User {
	if u == nil {
		return nil
	}
	c := *u
	c.Schemas = cloneStrings(u.Schemas)
	c.Name = u.Name.Clone()
	c.Emails = cloneMultiValues(u.Emails)
	c.PhoneNumbers = cloneMultiValues(u.PhoneNumbers)
	c.IMs = cloneMultiValues(u.IMs)
	c.Photos = cloneMultiValues(u.Photos)
	c.Entitlements = cloneMultiValues(u.Entitlements)
	c.Roles = cloneMultiValues(u.Roles)
	c.X509Certificates = cloneMultiValues(u.X509Certificates)
	if len(u.Addresses) > 0 {
		c.Addresses = make([]Address, len(u.Addresses))
		for i := range u.Addresses {
			c.Addresses[i] = *u.Addresses[i].Clone()
		}
	}
	if len(u.Groups) > 0 {
		c.Groups = make([]GroupValue, len(u.Groups))
		for i := range u.Groups {
			c.Groups[i] = *u.Groups[i].Clone()
		}
	}
	c.EnterpriseUser = u.EnterpriseUser.Clone()
	c.Meta = u.Meta.Clone()
	if u.Active != nil {
		c.Active = boolPtr(*u.Active)
	}
	return &c
}

// ActiveValue returns the effective active flag, defaulting to true. | ActiveValue 返回有效的
// active 标记，默认 true。
func (u *User) ActiveValue() bool {
	if u == nil || u.Active == nil {
		return true
	}
	return *u.Active
}

// SetActive stores the active flag. | SetActive 保存 active 标记。
func (u *User) SetActive(active bool) {
	if u == nil {
		return
	}
	u.Active = boolPtr(active)
}

// PrimaryEmail returns the primary email value, falling back to the first email. | PrimaryEmail
// 返回首选邮箱值，缺失时回退到首个邮箱。
func (u *User) PrimaryEmail() string {
	if u == nil {
		return ""
	}
	for _, email := range u.Emails {
		if email.Primary && email.Value != "" {
			return email.Value
		}
	}
	for _, email := range u.Emails {
		if email.Value != "" {
			return email.Value
		}
	}
	return ""
}

// PrimaryPhone returns the primary phone value, falling back to the first phone number. |
// PrimaryPhone 返回首选电话值，缺失时回退到首个电话号码。
func (u *User) PrimaryPhone() string {
	if u == nil {
		return ""
	}
	for _, phone := range u.PhoneNumbers {
		if phone.Primary && phone.Value != "" {
			return phone.Value
		}
	}
	for _, phone := range u.PhoneNumbers {
		if phone.Value != "" {
			return phone.Value
		}
	}
	return ""
}

// Sanitize returns a copy safe to serialize: the write-only password is cleared. | Sanitize 返回
// 可安全序列化的副本：只写口令被清空。
func (u *User) Sanitize() *User {
	c := u.Clone()
	if c != nil {
		c.Password = ""
	}
	return c
}

// EnsureSchemas normalizes the schema list of u: the core User schema is always first and the
// enterprise extension appears exactly when EnterpriseUser is present. | EnsureSchemas 规范化 u
// 的 Schema 列表：核心 User Schema 始终在首位，企业扩展恰好在其值存在时出现。
func (u *User) EnsureSchemas() {
	if u == nil {
		return
	}
	list := []string{UserSchema}
	if u.EnterpriseUser != nil {
		list = append(list, EnterpriseUserSchema)
	}
	for _, schema := range u.Schemas {
		if schema == "" || containsFold(list, schema) {
			continue
		}
		// Preserve extension schemas the caller understands but this package does not model. |
		// 保留调用方理解但本包未建模的扩展 Schema。
		list = append(list, schema)
	}
	u.Schemas = list
}

// cloneMultiValues returns a deep copy of list. | cloneMultiValues 返回 list 的深拷贝。
func cloneMultiValues(list []MultiValue) []MultiValue {
	if len(list) == 0 {
		return nil
	}
	out := make([]MultiValue, len(list))
	copy(out, list)
	return out
}

// primaryMultiIndex returns the index of the entry marked primary, or -1. | primaryMultiIndex
// 返回标记为首选的条目索引，没有时返回 -1。
func primaryMultiIndex(list []MultiValue) int {
	for i := range list {
		if list[i].Primary {
			return i
		}
	}
	return -1
}

// normalizeMultiPrimary ensures at most one entry of list is primary. | normalizeMultiPrimary
// 确保 list 至多有一个首选条目。
func normalizeMultiPrimary(list []MultiValue) {
	seen := false
	for i := range list {
		if !list[i].Primary {
			continue
		}
		if seen {
			list[i].Primary = false
			continue
		}
		seen = true
	}
}
