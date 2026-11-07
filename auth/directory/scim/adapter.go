package scim

import (
	"context"
	"errors"
	"strings"
	"sync"

	"github.com/shibingli/ydx/auth"
	"github.com/shibingli/ydx/errs"
)

// UserStoreAdapter exposes an auth.UserStore as a SCIM Store. Users are delegated to the wrapped
// store; Groups are kept in an internal MemoryStore because auth.UserStore has no group concept. |
// UserStoreAdapter 把 auth.UserStore 暴露为 SCIM Store。User 委托给被包装的存储；由于
// auth.UserStore 没有组概念，Group 保存在内部 MemoryStore 中。
type UserStoreAdapter struct {
	// Users is the wrapped account store. | Users 是被包装的账号存储。
	Users auth.UserStore
	// groups holds SCIM groups. | groups 保存 SCIM 组。
	groups *MemoryStore
	// versions maps a user identifier to its last issued entity tag. | versions 把用户标识映射到最后
	// 签发的实体标签。
	versions map[string]string
	// revision produces new entity tags. | revision 生成新的实体标签。
	revision uint64
	// mu guards versions and revision. | mu 保护 versions 与 revision。
	mu sync.Mutex
}

// NewUserStoreAdapter wraps users as a SCIM Store. It returns ErrInvalidConfig when users is nil. |
// NewUserStoreAdapter 把 users 包装为 SCIM Store。users 为空时返回 ErrInvalidConfig。
func NewUserStoreAdapter(users auth.UserStore) (*UserStoreAdapter, error) {
	if users == nil {
		return nil, errs.Detail(ErrInvalidConfig, "nil auth.UserStore | auth.UserStore 为空")
	}
	return &UserStoreAdapter{
		Users:    users,
		groups:   NewMemoryStore(),
		versions: make(map[string]string),
	}, nil
}

// CreateUser maps user into auth.User, stores it and maps the result back. | CreateUser 把 user
// 映射为 auth.User，保存后映射回 SCIM 表示。
func (a *UserStoreAdapter) CreateUser(ctx context.Context, user *User) (*User, error) {
	account := authUserFromSCIM(user)
	if account == nil {
		return nil, errs.Detail(ErrInvalidValue, "nil User | User 为空")
	}
	account.ID = auth.NewID("usr")
	now := auth.Now(nil)
	account.CreatedAt = now
	account.UpdatedAt = now
	if err := a.Users.CreateUser(ctx, account); err != nil {
		return nil, translateAuthStoreError(err)
	}
	stored, err := a.Users.GetUser(ctx, account.ID)
	if err != nil {
		return nil, translateAuthStoreError(err)
	}
	version := a.nextVersion(stored.ID)
	return scimUserFromAuth(stored, version), nil
}

// GetUser returns the mapped User with the given identifier. | GetUser 返回指定标识的映射 User。
func (a *UserStoreAdapter) GetUser(ctx context.Context, id string) (*User, error) {
	account, err := a.Users.GetUser(ctx, id)
	if err != nil {
		return nil, translateAuthStoreError(err)
	}
	return scimUserFromAuth(account, a.versionFor(account.ID)), nil
}

// ReplaceUser updates the wrapped account with the mapped User. | ReplaceUser 用映射后的 User 更新
// 被包装的账号。
func (a *UserStoreAdapter) ReplaceUser(ctx context.Context, user *User) (*User, error) {
	if user == nil || user.ID == "" {
		return nil, errs.Detail(ErrInvalidValue, "User id is required | User 标识为必需")
	}
	account := authUserFromSCIM(user)
	if account == nil {
		return nil, errs.Detail(ErrInvalidValue, "nil User | User 为空")
	}
	existing, err := a.Users.GetUser(ctx, user.ID)
	if err != nil {
		return nil, translateAuthStoreError(err)
	}
	account.ID = user.ID
	preserveAuthAccount(existing, account)
	account.Metadata = mergeAuthMetadata(existing.Metadata, account.Metadata)
	if err := a.Users.UpdateUser(ctx, account); err != nil {
		return nil, translateAuthStoreError(err)
	}
	stored, err := a.Users.GetUser(ctx, user.ID)
	if err != nil {
		return nil, translateAuthStoreError(err)
	}
	return scimUserFromAuth(stored, a.nextVersion(stored.ID)), nil
}

// DeleteUser removes the wrapped account. | DeleteUser 移除被包装的账号。
func (a *UserStoreAdapter) DeleteUser(ctx context.Context, id string) error {
	if err := a.Users.DeleteUser(ctx, id); err != nil {
		return translateAuthStoreError(err)
	}
	a.mu.Lock()
	delete(a.versions, id)
	a.mu.Unlock()
	return nil
}

// ListUsers returns a filtered, sorted and paginated page of mapped users. | ListUsers 返回映射用户
// 经过滤、排序与分页后的一页。
func (a *UserStoreAdapter) ListUsers(ctx context.Context, query ListQuery) ([]*User, int, error) {
	accounts, _, err := a.Users.ListUsers(ctx, auth.UserQuery{})
	if err != nil {
		return nil, 0, translateAuthStoreError(err)
	}
	users := make([]*User, 0, len(accounts))
	for _, account := range accounts {
		users = append(users, scimUserFromAuth(account, a.versionFor(account.ID)))
	}
	if query.Filter != nil {
		matched := users[:0]
		for _, user := range users {
			if query.Filter.Match(user) {
				matched = append(matched, user)
			}
		}
		users = matched
	}
	SortUsers(users, query.SortBy, query.SortOrder)
	total := len(users)
	return pageUsers(users, query.StartIndex, query.Count), total, nil
}

// CreateGroup stores a new Group in the adapter's group store. | CreateGroup 在适配器的组存储中保存
// 新 Group。
func (a *UserStoreAdapter) CreateGroup(ctx context.Context, group *Group) (*Group, error) {
	return a.groups.CreateGroup(ctx, group)
}

// GetGroup returns a Group from the adapter's group store. | GetGroup 从适配器的组存储返回 Group。
func (a *UserStoreAdapter) GetGroup(ctx context.Context, id string) (*Group, error) {
	return a.groups.GetGroup(ctx, id)
}

// ReplaceGroup replaces a Group in the adapter's group store. | ReplaceGroup 在适配器的组存储中替换
// Group。
func (a *UserStoreAdapter) ReplaceGroup(ctx context.Context, group *Group) (*Group, error) {
	return a.groups.ReplaceGroup(ctx, group)
}

// DeleteGroup removes a Group from the adapter's group store. | DeleteGroup 从适配器的组存储移除
// Group。
func (a *UserStoreAdapter) DeleteGroup(ctx context.Context, id string) error {
	return a.groups.DeleteGroup(ctx, id)
}

// ListGroups returns a page from the adapter's group store. | ListGroups 从适配器的组存储返回一页。
func (a *UserStoreAdapter) ListGroups(ctx context.Context, query ListQuery) ([]*Group, int, error) {
	return a.groups.ListGroups(ctx, query)
}

// versionFor returns the current entity tag for id, allocating one when absent. | versionFor 返回 id
// 的当前实体标签，缺失时分配一个。
func (a *UserStoreAdapter) versionFor(id string) string {
	a.mu.Lock()
	defer a.mu.Unlock()
	if version, ok := a.versions[id]; ok {
		return version
	}
	a.revision++
	version := resourceVersion(ResourceTypeNameUser, id, a.revision)
	a.versions[id] = version
	return version
}

// nextVersion allocates a fresh entity tag for id. | nextVersion 为 id 分配新的实体标签。
func (a *UserStoreAdapter) nextVersion(id string) string {
	a.mu.Lock()
	defer a.mu.Unlock()
	a.revision++
	version := resourceVersion(ResourceTypeNameUser, id, a.revision)
	a.versions[id] = version
	return version
}

// preserveAuthAccount keeps canonical account state that SCIM does not expose. | preserveAuthAccount
// 保留 SCIM 未暴露的规范账号状态。
func preserveAuthAccount(existing, account *auth.User) {
	if existing == nil || account == nil {
		return
	}
	account.CreatedAt = existing.CreatedAt
	account.UpdatedAt = auth.Now(nil)
	account.PasswordHash = existing.PasswordHash
	account.PasswordChangedAt = existing.PasswordChangedAt
	account.PasswordHistory = append([]string(nil), existing.PasswordHistory...)
	account.MFAEnabled = existing.MFAEnabled
	account.FailedLoginAttempts = existing.FailedLoginAttempts
	account.LockedUntil = existing.LockedUntil
	account.LastLoginAt = existing.LastLoginAt
	account.LastLoginIP = existing.LastLoginIP
	account.EmailVerified = existing.EmailVerified
	account.PhoneVerified = existing.PhoneVerified
	account.Website = existing.Website
	account.Gender = existing.Gender
	account.Birthdate = existing.Birthdate
}

// mergeAuthMetadata preserves application metadata while replacing SCIM-managed keys. |
// mergeAuthMetadata 保留应用元数据并替换由 SCIM 管理的键。
func mergeAuthMetadata(existing, managed map[string]string) map[string]string {
	merged := make(map[string]string, len(existing)+len(managed))
	for key, value := range existing {
		merged[key] = value
	}
	for _, key := range []string{
		"title", "userType", "preferredLanguage", "employeeNumber", "costCenter",
		"organization", "division", "department",
	} {
		delete(merged, key)
	}
	for key, value := range managed {
		merged[key] = value
	}
	if len(merged) == 0 {
		return nil
	}
	return merged
}

// translateAuthStoreError maps auth sentinels onto SCIM sentinels. | translateAuthStoreError 把 auth
// 哨兵映射为 SCIM 哨兵。
func translateAuthStoreError(err error) error {
	switch {
	case err == nil:
		return nil
	case errors.Is(err, auth.ErrUserNotFound):
		return errs.WrapDetail(err, ErrNotFound, "auth user store | auth 用户存储")
	case errors.Is(err, auth.ErrUserExists), errors.Is(err, auth.ErrConflict):
		return errs.WrapDetail(err, ErrUniqueness, "auth user store | auth 用户存储")
	case errors.Is(err, auth.ErrInvalidRequest), errors.Is(err, auth.ErrInvalidConfig):
		return errs.WrapDetail(err, ErrInvalidValue, "auth user store | auth 用户存储")
	case errors.Is(err, auth.ErrNotSupported):
		return errs.WrapDetail(err, ErrUnsupported, "auth user store | auth 用户存储")
	default:
		return errs.WrapDetail(err, ErrStoreUnavailable, "auth user store | auth 用户存储")
	}
}

// authUserFromSCIM converts a SCIM User into the canonical account record. The write-only password
// is never copied: password provisioning belongs to the server PasswordSetter hook. | authUserFromSCIM
// 把 SCIM User 转换为规范账号记录。只写口令绝不会被复制：口令预配属于服务端 PasswordSetter 钩子。
func authUserFromSCIM(user *User) *auth.User {
	if user == nil {
		return nil
	}
	account := &auth.User{
		ID:          user.ID,
		Username:    user.UserName,
		ExternalID:  user.ExternalID,
		DisplayName: user.DisplayName,
		Nickname:    user.NickName,
		Profile:     user.ProfileURL,
		Locale:      user.Locale,
		Zoneinfo:    user.Timezone,
		Email:       user.PrimaryEmail(),
		Phone:       user.PrimaryPhone(),
		Status:      auth.UserActive,
	}
	if !user.ActiveValue() {
		account.Status = auth.UserDisabled
	}
	if user.Name != nil {
		account.GivenName = user.Name.GivenName
		account.FamilyName = user.Name.FamilyName
		account.MiddleName = user.Name.MiddleName
	}
	for i := range user.Photos {
		if user.Photos[i].Value != "" && (user.Photos[i].Primary || account.Picture == "") {
			account.Picture = user.Photos[i].Value
			if user.Photos[i].Primary {
				break
			}
		}
	}
	if len(user.Addresses) > 0 {
		index := primaryAddressIndex(user.Addresses)
		if index >= 0 {
			account.Address = authAddressFromSCIM(user.Addresses[index])
		}
	}
	metadata := map[string]string{}
	putMetadata(metadata, "title", user.Title)
	putMetadata(metadata, "userType", user.UserType)
	putMetadata(metadata, "preferredLanguage", user.PreferredLanguage)
	if user.EnterpriseUser != nil {
		putMetadata(metadata, "employeeNumber", user.EnterpriseUser.EmployeeNumber)
		putMetadata(metadata, "costCenter", user.EnterpriseUser.CostCenter)
		putMetadata(metadata, "organization", user.EnterpriseUser.Organization)
		putMetadata(metadata, "division", user.EnterpriseUser.Division)
		putMetadata(metadata, "department", user.EnterpriseUser.Department)
	}
	if len(metadata) > 0 {
		account.Metadata = metadata
	}
	return account
}

// scimUserFromAuth converts a canonical account record into a SCIM User. | scimUserFromAuth 把规范
// 账号记录转换为 SCIM User。
func scimUserFromAuth(account *auth.User, version string) *User {
	if account == nil {
		return nil
	}
	user := &User{
		ID:                account.ID,
		ExternalID:        account.ExternalID,
		UserName:          account.Username,
		DisplayName:       account.DisplayName,
		NickName:          account.Nickname,
		ProfileURL:        account.Profile,
		Locale:            account.Locale,
		Timezone:          account.Zoneinfo,
		PreferredLanguage: account.Metadata["preferredLanguage"],
		Title:             account.Metadata["title"],
		UserType:          account.Metadata["userType"],
	}
	user.SetActive(account.Status != auth.UserDisabled)
	if account.GivenName != "" || account.FamilyName != "" || account.MiddleName != "" {
		user.Name = &Name{
			GivenName:  account.GivenName,
			FamilyName: account.FamilyName,
			MiddleName: account.MiddleName,
		}
	}
	if account.Email != "" {
		user.Emails = []MultiValue{{Value: account.Email, Type: "work", Primary: true}}
	}
	if account.Phone != "" {
		user.PhoneNumbers = []MultiValue{{Value: account.Phone, Type: "work", Primary: true}}
	}
	if account.Picture != "" {
		user.Photos = []MultiValue{{Value: account.Picture, Type: "photo", Primary: true}}
	}
	if len(account.Address) > 0 {
		user.Addresses = []Address{scimAddressFromAuth(account.Address)}
	}
	if account.Metadata["employeeNumber"] != "" || account.Metadata["costCenter"] != "" ||
		account.Metadata["organization"] != "" || account.Metadata["division"] != "" ||
		account.Metadata["department"] != "" {
		user.EnterpriseUser = &EnterpriseUser{
			EmployeeNumber: account.Metadata["employeeNumber"],
			CostCenter:     account.Metadata["costCenter"],
			Organization:   account.Metadata["organization"],
			Division:       account.Metadata["division"],
			Department:     account.Metadata["department"],
		}
	}
	user.EnsureSchemas()
	user.Meta = &Meta{
		ResourceType: ResourceTypeNameUser,
		Created:      formatTime(account.CreatedAt),
		LastModified: formatTime(account.UpdatedAt),
		Version:      version,
	}
	if user.Meta.LastModified == "" {
		user.Meta.LastModified = user.Meta.Created
	}
	return user
}

// primaryAddressIndex returns the index of the primary address, or the first address. |
// primaryAddressIndex 返回首选地址索引，缺失时返回首个地址。
func primaryAddressIndex(addresses []Address) int {
	for i := range addresses {
		if addresses[i].Primary {
			return i
		}
	}
	if len(addresses) == 0 {
		return -1
	}
	return 0
}

// authAddressFromSCIM converts an Address into the OIDC address map. | authAddressFromSCIM 把 Address
// 转换为 OIDC 地址映射。
func authAddressFromSCIM(address Address) map[string]string {
	out := map[string]string{}
	putMetadata(out, "formatted", address.Formatted)
	putMetadata(out, "street_address", address.StreetAddress)
	putMetadata(out, "locality", address.Locality)
	putMetadata(out, "region", address.Region)
	putMetadata(out, "postal_code", address.PostalCode)
	putMetadata(out, "country", address.Country)
	if len(out) == 0 {
		return nil
	}
	return out
}

// scimAddressFromAuth converts an OIDC address map into an Address. | scimAddressFromAuth 把 OIDC
// 地址映射转换为 Address。
func scimAddressFromAuth(address map[string]string) Address {
	return Address{
		Formatted:     firstAddressValue(address, "formatted"),
		StreetAddress: firstAddressValue(address, "street_address", "streetAddress", "street"),
		Locality:      firstAddressValue(address, "locality", "city"),
		Region:        firstAddressValue(address, "region", "state"),
		PostalCode:    firstAddressValue(address, "postal_code", "postalCode", "zip"),
		Country:       firstAddressValue(address, "country"),
	}
}

// firstAddressValue returns the first non-empty value among keys. | firstAddressValue 返回 keys 中
// 首个非空值。
func firstAddressValue(address map[string]string, keys ...string) string {
	for _, key := range keys {
		if value := strings.TrimSpace(address[key]); value != "" {
			return value
		}
	}
	return ""
}

// putMetadata stores value under key when both are non-empty. | putMetadata 在 key 与 value 均非空时
// 保存 value。
func putMetadata(metadata map[string]string, key, value string) {
	if key != "" && value != "" {
		metadata[key] = value
	}
}
