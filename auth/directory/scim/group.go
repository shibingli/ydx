package scim

// GroupMember is one member of a Group resource as defined by RFC 7643 section 4.2. | GroupMember
// 是 RFC 7643 第 4.2 节定义的 Group 资源成员。
type GroupMember struct {
	// Value is the member resource identifier. | Value 是成员资源标识。
	Value string `json:"value"`
	// Display is the member display name. | Display 是成员展示名。
	Display string `json:"display,omitempty"`
	// Type is the member resource type, for example "User" or "Group". | Type 是成员资源类型，
	// 例如 "User" 或 "Group"。
	Type string `json:"type,omitempty"`
	// Ref is the absolute URI of the member resource. | Ref 是成员资源的绝对 URI。
	Ref string `json:"$ref,omitempty"`
}

// Clone returns a deep copy of m. | Clone 返回 m 的深拷贝。
func (m *GroupMember) Clone() *GroupMember {
	if m == nil {
		return nil
	}
	c := *m
	return &c
}

// Group is the SCIM core Group resource defined by RFC 7643 section 4.2. | Group 是 RFC 7643
// 第 4.2 节定义的 SCIM 核心 Group 资源。
type Group struct {
	// Meta is the resource metadata. | Meta 是资源元数据。
	Meta *Meta `json:"meta,omitempty"`
	// ID is the immutable server-assigned identifier. | ID 是不可变的服务端分配标识。
	ID string `json:"id,omitempty"`
	// ExternalID is the provisioning identifier from an upstream directory. | ExternalID 是上级
	// 目录的预配标识。
	ExternalID string `json:"externalId,omitempty"`
	// DisplayName is the unique group display name. | DisplayName 是唯一的组展示名。
	DisplayName string `json:"displayName"`
	// Schemas is the resource schema list. | Schemas 是资源 Schema 列表。
	Schemas []string `json:"schemas"`
	// Members lists the group members. | Members 列出组成员。
	Members []GroupMember `json:"members,omitempty"`
}

// Clone returns a deep copy of g. | Clone 返回 g 的深拷贝。
func (g *Group) Clone() *Group {
	if g == nil {
		return nil
	}
	c := *g
	c.Schemas = cloneStrings(g.Schemas)
	if len(g.Members) > 0 {
		c.Members = make([]GroupMember, len(g.Members))
		for i := range g.Members {
			c.Members[i] = *g.Members[i].Clone()
		}
	}
	c.Meta = g.Meta.Clone()
	return &c
}

// EnsureSchemas normalizes the schema list of g to exactly the core Group schema followed by any
// caller supplied extension schemas. | EnsureSchemas 把 g 的 Schema 列表规范化为核心 Group
// Schema 在前，随后是调用方提供的扩展 Schema。
func (g *Group) EnsureSchemas() {
	if g == nil {
		return
	}
	list := []string{GroupSchema}
	for _, schema := range g.Schemas {
		if schema == "" || containsFold(list, schema) {
			continue
		}
		list = append(list, schema)
	}
	g.Schemas = list
}
