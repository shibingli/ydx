package saml

import (
	"context"

	"github.com/shibingli/ydx/auth"
)

// NewAttribute returns an attribute with the basic name format. | NewAttribute 返回 basic 名称格式的属性。
func NewAttribute(name string, values ...string) Attribute {
	out := Attribute{Name: name, NameFormat: AttrNameFormatBasic}
	for _, value := range values {
		out.AttributeValue = append(out.AttributeValue, AttributeValue{Value: value})
	}
	return out
}

// AttributeValues returns the string values of an attribute. | AttributeValues 返回属性的字符串取值。
func AttributeValues(attribute Attribute) []string {
	out := make([]string, 0, len(attribute.AttributeValue))
	for _, value := range attribute.AttributeValue {
		out = append(out, value.Value)
	}
	return out
}

// AttributeMap converts attribute statements into a multi-value map. | AttributeMap 把属性语句转换为多值映射。
func AttributeMap(statements []AttributeStatement) map[string][]string {
	out := make(map[string][]string)
	for _, statement := range statements {
		for _, attribute := range statement.Attribute {
			key := attribute.Name
			if key == "" {
				key = attribute.FriendlyName
			}
			if key == "" {
				continue
			}
			out[key] = append(out[key], AttributeValues(attribute)...)
		}
	}
	return out
}

// FirstAttribute returns the first value of name. | FirstAttribute 返回 name 的第一个取值。
func FirstAttribute(attributes map[string][]string, name string) string {
	values := attributes[name]
	if len(values) == 0 {
		return ""
	}
	return values[0]
}

// AttributeMapper maps a principal to assertion attributes. | AttributeMapper 把主体映射为断言属性。
type AttributeMapper interface {
	// MapAttributes returns the attributes for principal. | MapAttributes 返回 principal 的属性。
	MapAttributes(ctx context.Context, principal *auth.Principal) ([]Attribute, error)
}

// AttributeMapperFunc adapts a function to AttributeMapper. | AttributeMapperFunc 把函数适配为 AttributeMapper。
type AttributeMapperFunc func(ctx context.Context, principal *auth.Principal) ([]Attribute, error)

// MapAttributes calls f. | MapAttributes 调用 f。
func (f AttributeMapperFunc) MapAttributes(ctx context.Context, principal *auth.Principal) ([]Attribute, error) {
	return f(ctx, principal)
}

// DefaultAttributeMapper maps the common principal fields. | DefaultAttributeMapper 映射常见主体字段。
type DefaultAttributeMapper struct{}

// MapAttributes returns email, username, display name and group attributes. | MapAttributes 返回邮箱、用户名、展示名与组属性。
func (DefaultAttributeMapper) MapAttributes(_ context.Context, principal *auth.Principal) ([]Attribute, error) {
	if principal == nil {
		return nil, nil
	}
	var attributes []Attribute
	if principal.Email != "" {
		attributes = append(attributes, NewAttribute("email", principal.Email))
		attributes = append(attributes, NewAttribute("urn:oid:0.9.2342.19200300.100.1.3", principal.Email))
	}
	if principal.Username != "" {
		attributes = append(attributes, NewAttribute("username", principal.Username))
	}
	if principal.DisplayName != "" {
		attributes = append(attributes, NewAttribute("displayName", principal.DisplayName))
	}
	if len(principal.Groups) > 0 {
		attributes = append(attributes, NewAttribute("groups", principal.Groups...))
	}
	return attributes, nil
}
