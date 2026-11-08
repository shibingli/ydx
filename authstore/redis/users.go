package redis

import (
	"context"
	"errors"
	"sort"
	"strings"

	goredis "github.com/redis/go-redis/v9"

	"github.com/shibingli/ydx/auth"
	"github.com/shibingli/ydx/errs"
)

// userStore implements auth.UserStore on Redis. | userStore 在 Redis 上实现 auth.UserStore。
type userStore struct {
	base
}

// userStore satisfies auth.UserStore. | userStore 满足 auth.UserStore。
var _ auth.UserStore = (*userStore)(nil)

// CreateUser stores a new user and rejects duplicate identifiers atomically.
// | CreateUser 保存新用户并以原子方式拒绝重复标识。
func (s *userStore) CreateUser(ctx context.Context, user *auth.User) error {
	if user == nil || user.ID == "" {
		return errs.Detail(auth.ErrInvalidRequest, "user or id is empty | 用户或 ID 为空")
	}
	data, err := encodeUser(user)
	if err != nil {
		return err
	}
	username := auth.SanitizeIdentifier(user.Username)
	email := auth.SanitizeIdentifier(user.Email)
	phone, phoneOK := normalizePhone(user.Phone)
	userKey := s.keys.user(user.ID)
	usernameKey := userKey
	if username != "" {
		usernameKey = s.keys.userIndexUsername(username)
	}
	emailKey := userKey
	if email != "" {
		emailKey = s.keys.userIndexEmail(email)
	}
	phoneKey := userKey
	if phoneOK {
		phoneKey = s.keys.userIndexPhone(phone)
	}
	code, err := s.runInt(ctx, scriptUserCreate, "create user",
		[]string{s.keys.usersAll(), userKey, usernameKey, emailKey, phoneKey},
		string(data), username, email, phone, user.ID,
		flag(username != ""), flag(email != ""), flag(phoneOK),
	)
	if err != nil {
		return err
	}
	switch code {
	case 0:
		return nil
	case 1:
		return errs.Detail(auth.ErrUserExists, "id %[1]q | ID %[1]q", user.ID)
	case 2:
		return errs.Detail(auth.ErrUserExists, "username %[1]q | 用户名 %[1]q", username)
	case 3:
		return errs.Detail(auth.ErrUserExists, "email %[1]q | 邮箱 %[1]q", email)
	case 4:
		return errs.Detail(auth.ErrUserExists, "phone %[1]q | 手机号 %[1]q", phone)
	default:
		return errs.Detail(auth.ErrStoreUnavailable, "create user returned %d | 创建用户返回 %d", code, code)
	}
}

// GetUser returns a user by internal identifier. | GetUser 按内部标识返回用户。
func (s *userStore) GetUser(ctx context.Context, id string) (*auth.User, error) {
	data, err := s.client.HGet(ctx, s.keys.user(id), "data").Result()
	if errors.Is(err, goredis.Nil) {
		return nil, errs.Detail(auth.ErrUserNotFound, "id %[1]q | ID %[1]q", id)
	}
	if err != nil {
		return nil, s.backend("get user", err)
	}
	return decodeUser([]byte(data))
}

// GetUserByUsername returns a user by login name. | GetUserByUsername 按登录名返回用户。
func (s *userStore) GetUserByUsername(ctx context.Context, username string) (*auth.User, error) {
	return s.getByIndex(ctx, s.keys.userIndexUsername(auth.SanitizeIdentifier(username)),
		"username", username)
}

// GetUserByEmail returns a user by email address. | GetUserByEmail 按邮箱地址返回用户。
func (s *userStore) GetUserByEmail(ctx context.Context, email string) (*auth.User, error) {
	return s.getByIndex(ctx, s.keys.userIndexEmail(auth.SanitizeIdentifier(email)),
		"email", email)
}

// GetUserByPhone returns a user by phone number. | GetUserByPhone 按手机号返回用户。
func (s *userStore) GetUserByPhone(ctx context.Context, phone string) (*auth.User, error) {
	normalized, ok := normalizePhone(phone)
	if !ok {
		return nil, errs.Detail(auth.ErrUserNotFound, "phone %[1]q | 手机号 %[1]q", phone)
	}
	return s.getByIndex(ctx, s.keys.userIndexPhone(normalized), "phone", phone)
}

// getByIndex resolves one unique index to its user. | getByIndex 把单个唯一索引解析为其用户。
func (s *userStore) getByIndex(ctx context.Context, indexKey, kind, value string) (*auth.User, error) {
	id, err := s.client.Get(ctx, indexKey).Result()
	if errors.Is(err, goredis.Nil) {
		return nil, errs.Detail(auth.ErrUserNotFound, "%[1]s %[2]q | %[1]s %[2]q", kind, value)
	}
	if err != nil {
		return nil, s.backend("get user by "+kind, err)
	}
	user, err := s.GetUser(ctx, id)
	if err != nil {
		return nil, err
	}
	return user, nil
}

// UpdateUser replaces an existing user and reconciles its indexes atomically.
// | UpdateUser 原子替换已有用户并协调其索引。
func (s *userStore) UpdateUser(ctx context.Context, user *auth.User) error {
	if user == nil || user.ID == "" {
		return errs.Detail(auth.ErrInvalidRequest, "user or id is empty | 用户或 ID 为空")
	}
	data, err := encodeUser(user)
	if err != nil {
		return err
	}
	newUsername := auth.SanitizeIdentifier(user.Username)
	newEmail := auth.SanitizeIdentifier(user.Email)
	newPhone, newPhoneOK := normalizePhone(user.Phone)
	userKey := s.keys.user(user.ID)
	newUsernameKey := userKey
	if newUsername != "" {
		newUsernameKey = s.keys.userIndexUsername(newUsername)
	}
	newEmailKey := userKey
	if newEmail != "" {
		newEmailKey = s.keys.userIndexEmail(newEmail)
	}
	newPhoneKey := userKey
	if newPhoneOK {
		newPhoneKey = s.keys.userIndexPhone(newPhone)
	}
	for attempt := 0; attempt < maxCASRetries; attempt++ {
		values, err := s.client.HMGet(ctx, userKey, "username", "email", "phone").Result()
		if err != nil {
			return s.backend("update user", err)
		}
		oldUsername, oldEmail, oldPhone := fields(values)
		if oldUsername == "" && oldEmail == "" && oldPhone == "" && allNil(values) {
			return errs.Detail(auth.ErrUserNotFound, "id %[1]q | ID %[1]q", user.ID)
		}
		oldUsernameKey := userKey
		if oldUsername != "" {
			oldUsernameKey = s.keys.userIndexUsername(oldUsername)
		}
		oldEmailKey := userKey
		if oldEmail != "" {
			oldEmailKey = s.keys.userIndexEmail(oldEmail)
		}
		oldPhoneKey := userKey
		if oldPhone != "" {
			oldPhoneKey = s.keys.userIndexPhone(oldPhone)
		}
		code, err := s.runInt(ctx, scriptUserUpdate, "update user",
			[]string{userKey, newUsernameKey, newEmailKey, newPhoneKey, oldUsernameKey, oldEmailKey, oldPhoneKey},
			oldUsername, oldEmail, oldPhone, string(data), newUsername, newEmail, newPhone, user.ID,
			flag(newUsername != ""), flag(newEmail != ""), flag(newPhoneOK),
			flag(oldUsername != ""), flag(oldEmail != ""), flag(oldPhone != ""),
		)
		if err != nil {
			return err
		}
		switch code {
		case 0:
			return nil
		case 1:
			return errs.Detail(auth.ErrUserNotFound, "id %[1]q | ID %[1]q", user.ID)
		case 2:
			return errs.Detail(auth.ErrUserExists, "username %[1]q | 用户名 %[1]q", newUsername)
		case 3:
			return errs.Detail(auth.ErrUserExists, "email %[1]q | 邮箱 %[1]q", newEmail)
		case 4:
			return errs.Detail(auth.ErrUserExists, "phone %[1]q | 手机号 %[1]q", newPhone)
		case 5:
			continue
		default:
			return errs.Detail(auth.ErrStoreUnavailable, "update user returned %d | 更新用户返回 %d", code, code)
		}
	}
	return errs.Detail(auth.ErrConflict, "update user %[1]q is contended | 更新用户 %[1]q 存在竞争", user.ID)
}

// DeleteUser removes a user and its indexes atomically. | DeleteUser 原子删除用户及其索引。
func (s *userStore) DeleteUser(ctx context.Context, id string) error {
	userKey := s.keys.user(id)
	for attempt := 0; attempt < maxCASRetries; attempt++ {
		values, err := s.client.HMGet(ctx, userKey, "username", "email", "phone").Result()
		if err != nil {
			return s.backend("delete user", err)
		}
		if allNil(values) {
			return errs.Detail(auth.ErrUserNotFound, "id %[1]q | ID %[1]q", id)
		}
		oldUsername, oldEmail, oldPhone := fields(values)
		oldUsernameKey := userKey
		if oldUsername != "" {
			oldUsernameKey = s.keys.userIndexUsername(oldUsername)
		}
		oldEmailKey := userKey
		if oldEmail != "" {
			oldEmailKey = s.keys.userIndexEmail(oldEmail)
		}
		oldPhoneKey := userKey
		if oldPhone != "" {
			oldPhoneKey = s.keys.userIndexPhone(oldPhone)
		}
		code, err := s.runInt(ctx, scriptUserDelete, "delete user",
			[]string{userKey, s.keys.usersAll(), oldUsernameKey, oldEmailKey, oldPhoneKey},
			id, oldUsername, oldEmail, oldPhone,
			flag(oldUsername != ""), flag(oldEmail != ""), flag(oldPhone != ""),
		)
		if err != nil {
			return err
		}
		switch code {
		case 0:
			return nil
		case 1:
			return errs.Detail(auth.ErrUserNotFound, "id %[1]q | ID %[1]q", id)
		case 2:
			continue
		default:
			return errs.Detail(auth.ErrStoreUnavailable, "delete user returned %d | 删除用户返回 %d", code, code)
		}
	}
	return errs.Detail(auth.ErrConflict, "delete user %[1]q is contended | 删除用户 %[1]q 存在竞争", id)
}

// ListUsers returns a filtered page and the total matching count.
// | ListUsers 返回过滤后的一页与匹配总数。
func (s *userStore) ListUsers(ctx context.Context, query auth.UserQuery) ([]*auth.User, int, error) {
	ids, err := s.client.SMembers(ctx, s.keys.usersAll()).Result()
	if err != nil {
		return nil, 0, s.backend("list users", err)
	}
	users := make([]*auth.User, 0, len(ids))
	if len(ids) > 0 {
		cmds := make([]*goredis.StringCmd, len(ids))
		_, _ = s.client.Pipelined(ctx, func(pipe goredis.Pipeliner) error {
			for i, id := range ids {
				cmds[i] = pipe.HGet(ctx, s.keys.user(id), "data")
			}
			return nil
		})
		for i := range ids {
			data, err := cmds[i].Result()
			if errors.Is(err, goredis.Nil) {
				continue
			}
			if err != nil {
				return nil, 0, s.backend("list users", err)
			}
			user, err := decodeUser([]byte(data))
			if err != nil {
				return nil, 0, err
			}
			users = append(users, user)
		}
	}
	needle := strings.ToLower(strings.TrimSpace(query.Query))
	filtered := make([]*auth.User, 0, len(users))
	for _, user := range users {
		if query.Status != "" && user.Status != query.Status {
			continue
		}
		if needle != "" {
			haystack := strings.ToLower(user.Username + "\x00" + user.Email + "\x00" + user.DisplayName)
			if !strings.Contains(haystack, needle) {
				continue
			}
		}
		filtered = append(filtered, user)
	}
	sort.Slice(filtered, func(i, j int) bool {
		if filtered[i].CreatedAt.Equal(filtered[j].CreatedAt) {
			return filtered[i].ID < filtered[j].ID
		}
		return filtered[i].CreatedAt.Before(filtered[j].CreatedAt)
	})
	total := len(filtered)
	start, end := pageBounds(query.Offset, query.Limit, total)
	return filtered[start:end], total, nil
}

// fields extracts three multi-bulk string fields. | fields 提取三个多批量字符串字段。
func fields(values []any) (string, string, string) {
	for len(values) < 3 {
		values = append(values, nil)
	}
	return stringValue(values[0]), stringValue(values[1]), stringValue(values[2])
}

// allNil reports whether every multi-bulk element is nil, which means the key is absent.
// | allNil 报告所有多批量元素是否都为 nil，即键不存在。
func allNil(values []any) bool {
	for _, value := range values {
		if value != nil {
			return false
		}
	}
	return true
}
