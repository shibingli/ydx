package oauth2

import (
	"sort"
	"strings"

	"github.com/shibingli/ydx/errs"
)

// Scope is a registered OAuth scope. | Scope 是已注册的 OAuth 作用域。
type Scope struct {
	// Name is the scope token. | Name 是作用域令牌。
	Name string `json:"name"`
	// Description is a human-readable explanation. | Description 是人类可读说明。
	Description string `json:"description,omitempty"`
	// Claims lists the claims or permissions the scope unlocks. | Claims 列出该作用域解锁的声明或权限。
	Claims []string `json:"claims,omitempty"`
	// OfflineAccess marks a scope that permits refresh tokens. | OfflineAccess 标记允许刷新令牌的作用域。
	OfflineAccess bool `json:"offline_access,omitempty"`
}

// Standard OIDC/OAuth scope names. | 标准 OIDC/OAuth 作用域名。
const (
	// ScopeOpenID requests OpenID Connect authentication. | ScopeOpenID 请求 OpenID Connect 认证。
	ScopeOpenID = "openid"
	// ScopeProfile requests profile claims. | ScopeProfile 请求 profile 声明。
	ScopeProfile = "profile"
	// ScopeEmail requests email claims. | ScopeEmail 请求 email 声明。
	ScopeEmail = "email"
	// ScopeAddress requests the address claim. | ScopeAddress 请求 address 声明。
	ScopeAddress = "address"
	// ScopePhone requests phone claims. | ScopePhone 请求 phone 声明。
	ScopePhone = "phone"
	// ScopeOfflineAccess requests a refresh token. | ScopeOfflineAccess 请求刷新令牌。
	ScopeOfflineAccess = "offline_access"
)

// ScopeRegistry validates and describes scopes. | ScopeRegistry 校验并描述作用域。
type ScopeRegistry interface {
	// Validate returns the deduplicated granted subset of requested. | Validate 返回 requested 的去重授予子集。
	Validate(requested []string, client *Client) ([]string, error)
	// List returns every registered scope name. | List 返回全部已注册作用域名。
	List() []string
	// Exists reports whether name is registered. | Exists 报告 name 是否已注册。
	Exists(name string) bool
}

// StaticScopes is an immutable ScopeRegistry. | StaticScopes 是不可变 ScopeRegistry。
type StaticScopes struct {
	// scopes indexes definitions by name. | scopes 按名称索引定义。
	scopes map[string]Scope
	// order preserves registration order. | order 保留注册顺序。
	order []string
}

// NewStaticScopes returns a registry from scopes. | NewStaticScopes 从 scopes 返回注册表。
func NewStaticScopes(scopes ...Scope) *StaticScopes {
	s := &StaticScopes{scopes: make(map[string]Scope, len(scopes))}
	for _, scope := range scopes {
		if scope.Name == "" {
			continue
		}
		if _, exists := s.scopes[scope.Name]; exists {
			continue
		}
		s.scopes[scope.Name] = scope
		s.order = append(s.order, scope.Name)
	}
	return s
}

// DefaultScopes returns the standard OpenID Connect scope set. | DefaultScopes 返回标准 OpenID Connect 作用域集。
func DefaultScopes() *StaticScopes {
	return NewStaticScopes(
		Scope{Name: ScopeOpenID, Description: "OpenID Connect authentication | OpenID Connect 认证"},
		Scope{Name: ScopeProfile, Description: "Profile claims | 资料声明", Claims: []string{"name", "family_name", "given_name", "middle_name", "nickname", "preferred_username", "profile", "picture", "website", "gender", "birthdate", "zoneinfo", "locale", "updated_at"}},
		Scope{Name: ScopeEmail, Description: "Email claims | 邮箱声明", Claims: []string{"email", "email_verified"}},
		Scope{Name: ScopeAddress, Description: "Address claim | 地址声明", Claims: []string{"address"}},
		Scope{Name: ScopePhone, Description: "Phone claims | 电话声明", Claims: []string{"phone_number", "phone_number_verified"}},
		Scope{Name: ScopeOfflineAccess, Description: "Offline access | 离线访问", OfflineAccess: true},
	)
}

// Validate returns the granted subset of requested. | Validate 返回 requested 的授予子集。
func (s *StaticScopes) Validate(requested []string, client *Client) ([]string, error) {
	if s == nil {
		return requested, nil
	}
	out := make([]string, 0, len(requested))
	seen := make(map[string]bool, len(requested))
	for _, name := range requested {
		name = strings.TrimSpace(name)
		if name == "" || seen[name] {
			continue
		}
		seen[name] = true
		if _, ok := s.scopes[name]; !ok {
			return nil, errs.Detail(ErrInvalidScope, "unknown scope %[1]q | 未知作用域 %[1]q", name)
		}
		if client != nil && !client.AllowsScope(name) {
			return nil, errs.Detail(ErrInvalidScope, "scope %[1]q is not allowed for this client | 客户端不允许作用域 %[1]q", name)
		}
		out = append(out, name)
	}
	if len(requested) > 0 && len(out) == 0 {
		return nil, ErrInvalidScope
	}
	return out, nil
}

// List returns every registered scope name in registration order. | List 按注册顺序返回全部已注册作用域名。
func (s *StaticScopes) List() []string {
	if s == nil {
		return nil
	}
	return append([]string(nil), s.order...)
}

// Exists reports whether name is registered. | Exists 报告 name 是否已注册。
func (s *StaticScopes) Exists(name string) bool {
	if s == nil {
		return false
	}
	_, ok := s.scopes[name]
	return ok
}

// Get returns the Scope definition. | Get 返回 Scope 定义。
func (s *StaticScopes) Get(name string) (Scope, bool) {
	if s == nil {
		return Scope{}, false
	}
	scope, ok := s.scopes[name]
	return scope, ok
}

// SortedScopes returns the registered names sorted lexically. | SortedScopes 返回按字典序排序的已注册名称。
func (s *StaticScopes) SortedScopes() []string {
	out := s.List()
	sort.Strings(out)
	return out
}

// ParseScope splits a space-delimited scope string. | ParseScope 拆分空格分隔的作用域字符串。
func ParseScope(raw string) []string {
	fields := strings.Fields(raw)
	out := make([]string, 0, len(fields))
	seen := make(map[string]bool, len(fields))
	for _, field := range fields {
		if !seen[field] {
			seen[field] = true
			out = append(out, field)
		}
	}
	return out
}

// ScopeString joins scopes with a single space. | ScopeString 用单个空格连接作用域。
func ScopeString(scopes []string) string { return strings.Join(scopes, " ") }

// HasScope reports whether scopes contains want. | HasScope 报告 scopes 是否包含 want。
func HasScope(scopes []string, want string) bool {
	for _, scope := range scopes {
		if scope == want {
			return true
		}
	}
	return false
}

// IntersectScopes returns the requested scopes that are also in allowed, preserving requested order. | IntersectScopes
// 返回同时存在于 allowed 中的 requested 作用域，保持 requested 顺序。
func IntersectScopes(requested, allowed []string) []string {
	allowedSet := make(map[string]bool, len(allowed))
	for _, scope := range allowed {
		allowedSet[scope] = true
	}
	out := make([]string, 0, len(requested))
	for _, scope := range requested {
		if allowedSet[scope] {
			out = append(out, scope)
		}
	}
	return out
}

// HasOfflineAccess reports whether scopes contains offline_access or a registered offline scope. | HasOfflineAccess
// 报告 scopes 是否包含 offline_access 或已注册的离线作用域。
func HasOfflineAccess(scopes []string, registry ScopeRegistry) bool {
	if HasScope(scopes, ScopeOfflineAccess) {
		return true
	}
	static, ok := registry.(*StaticScopes)
	if !ok {
		return false
	}
	for _, scope := range scopes {
		if definition, exists := static.Get(scope); exists && definition.OfflineAccess {
			return true
		}
	}
	return false
}
