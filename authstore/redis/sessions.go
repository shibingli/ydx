package redis

import (
	"context"
	"errors"
	"sort"
	"strconv"
	"time"

	goredis "github.com/redis/go-redis/v9"

	"github.com/shibingli/ydx/auth"
	"github.com/shibingli/ydx/errs"
)

// sessionStore implements auth.SessionStore on Redis. | sessionStore 在 Redis 上实现 auth.SessionStore。
type sessionStore struct {
	base
}

// sessionStore satisfies auth.SessionStore. | sessionStore 满足 auth.SessionStore。
var _ auth.SessionStore = (*sessionStore)(nil)

// CreateSession stores a new session and both set memberships atomically.
// | CreateSession 原子保存新会话与两个集合成员关系。
func (s *sessionStore) CreateSession(ctx context.Context, session *auth.Session) error {
	if session == nil || session.ID == "" {
		return errs.Detail(auth.ErrInvalidRequest, "session or id is empty | 会话或 ID 为空")
	}
	data, err := encodeSession(session)
	if err != nil {
		return err
	}
	hasExpiry, expireSec, expireNsec := expiryFields(session.ExpiresAt)
	code, err := s.runInt(ctx, scriptSessionCreate, "create session",
		[]string{s.keys.session(session.ID), s.keys.sessionsByUser(session.UserID), s.keys.sessionsAll()},
		string(data), session.UserID, hasExpiry, expireSec, expireNsec, session.ID,
	)
	if err != nil {
		return err
	}
	switch code {
	case 0:
		return nil
	case 1:
		return errs.Detail(auth.ErrConflict, "session id %[1]q | 会话 ID %[1]q", session.ID)
	default:
		return errs.Detail(auth.ErrStoreUnavailable, "create session returned %d | 创建会话返回 %d", code, code)
	}
}

// GetSession returns a session by identifier. | GetSession 按标识返回会话。
func (s *sessionStore) GetSession(ctx context.Context, id string) (*auth.Session, error) {
	data, err := s.client.HGet(ctx, s.keys.session(id), "data").Result()
	if errors.Is(err, goredis.Nil) {
		return nil, errs.Detail(auth.ErrSessionNotFound, "id %[1]q | ID %[1]q", id)
	}
	if err != nil {
		return nil, s.backend("get session", err)
	}
	return decodeSession([]byte(data))
}

// UpdateSession replaces an existing session and reindexes its owner atomically.
// | UpdateSession 原子替换已有会话并重建其属主索引。
func (s *sessionStore) UpdateSession(ctx context.Context, session *auth.Session) error {
	if session == nil || session.ID == "" {
		return errs.Detail(auth.ErrInvalidRequest, "session or id is empty | 会话或 ID 为空")
	}
	data, err := encodeSession(session)
	if err != nil {
		return err
	}
	hasExpiry, expireSec, expireNsec := expiryFields(session.ExpiresAt)
	sessionKey := s.keys.session(session.ID)
	for attempt := 0; attempt < maxCASRetries; attempt++ {
		oldUser, err := s.client.HGet(ctx, sessionKey, "user").Result()
		if errors.Is(err, goredis.Nil) {
			return errs.Detail(auth.ErrSessionNotFound, "id %[1]q | ID %[1]q", session.ID)
		}
		if err != nil {
			return s.backend("update session", err)
		}
		code, err := s.runInt(ctx, scriptSessionUpdate, "update session",
			[]string{sessionKey, s.keys.sessionsByUser(session.UserID), s.keys.sessionsByUser(oldUser), s.keys.sessionsAll()},
			string(data), session.UserID, oldUser, session.ID, hasExpiry, expireSec, expireNsec,
		)
		if err != nil {
			return err
		}
		switch code {
		case 0:
			return nil
		case 1:
			return errs.Detail(auth.ErrSessionNotFound, "id %[1]q | ID %[1]q", session.ID)
		case 2:
			continue
		default:
			return errs.Detail(auth.ErrStoreUnavailable, "update session returned %d | 更新会话返回 %d", code, code)
		}
	}
	return errs.Detail(auth.ErrConflict, "update session %[1]q is contended | 更新会话 %[1]q 存在竞争", session.ID)
}

// DeleteSession removes a session and its memberships atomically.
// | DeleteSession 原子删除会话及其成员关系。
func (s *sessionStore) DeleteSession(ctx context.Context, id string) error {
	sessionKey := s.keys.session(id)
	for attempt := 0; attempt < maxCASRetries; attempt++ {
		user, err := s.client.HGet(ctx, sessionKey, "user").Result()
		if errors.Is(err, goredis.Nil) {
			return errs.Detail(auth.ErrSessionNotFound, "id %[1]q | ID %[1]q", id)
		}
		if err != nil {
			return s.backend("delete session", err)
		}
		code, err := s.runInt(ctx, scriptSessionDelete, "delete session",
			[]string{sessionKey, s.keys.sessionsByUser(user), s.keys.sessionsAll()},
			user, id,
		)
		if err != nil {
			return err
		}
		switch code {
		case 0:
			return nil
		case 1:
			return errs.Detail(auth.ErrSessionNotFound, "id %[1]q | ID %[1]q", id)
		case 2:
			continue
		default:
			return errs.Detail(auth.ErrStoreUnavailable, "delete session returned %d | 删除会话返回 %d", code, code)
		}
	}
	return errs.Detail(auth.ErrConflict, "delete session %[1]q is contended | 删除会话 %[1]q 存在竞争", id)
}

// ListSessionsByUser returns every session of a user, including revoked ones.
// | ListSessionsByUser 返回用户的全部会话，包括已撤销的。
func (s *sessionStore) ListSessionsByUser(ctx context.Context, userID string) ([]*auth.Session, error) {
	ids, err := s.client.SMembers(ctx, s.keys.sessionsByUser(userID)).Result()
	if err != nil {
		return nil, s.backend("list sessions", err)
	}
	out := make([]*auth.Session, 0, len(ids))
	if len(ids) == 0 {
		return out, nil
	}
	cmds := make([]*goredis.SliceCmd, len(ids))
	_, _ = s.client.Pipelined(ctx, func(pipe goredis.Pipeliner) error {
		for i, id := range ids {
			cmds[i] = pipe.HMGet(ctx, s.keys.session(id), "data", "user")
		}
		return nil
	})
	for i := range ids {
		values, err := cmds[i].Result()
		if errors.Is(err, goredis.Nil) {
			continue
		}
		if err != nil {
			return nil, s.backend("list sessions", err)
		}
		if len(values) < 2 || values[0] == nil || stringValue(values[1]) != userID {
			continue
		}
		session, err := decodeSession([]byte(stringValue(values[0])))
		if err != nil {
			return nil, err
		}
		out = append(out, session)
	}
	sort.Slice(out, func(i, j int) bool {
		if out[i].CreatedAt.Equal(out[j].CreatedAt) {
			return out[i].ID < out[j].ID
		}
		return out[i].CreatedAt.After(out[j].CreatedAt)
	})
	return out, nil
}

// DeleteSessionsByUser removes every session owned by userID and returns the number removed.
// | DeleteSessionsByUser 删除 userID 的全部会话并返回删除数量。
func (s *sessionStore) DeleteSessionsByUser(ctx context.Context, userID string) (int, error) {
	ids, err := s.client.SMembers(ctx, s.keys.sessionsByUser(userID)).Result()
	if err != nil {
		return 0, s.backend("delete sessions by user", err)
	}
	if len(ids) == 0 {
		return 0, nil
	}
	cmds := make([]*goredis.StringCmd, len(ids))
	_, _ = s.client.Pipelined(ctx, func(pipe goredis.Pipeliner) error {
		for i, id := range ids {
			cmds[i] = pipe.HGet(ctx, s.keys.session(id), "user")
		}
		return nil
	})
	removed := 0
	for i, id := range ids {
		owner, err := cmds[i].Result()
		if errors.Is(err, goredis.Nil) {
			continue
		}
		if err != nil {
			return removed, s.backend("delete sessions by user", err)
		}
		code, err := s.runInt(ctx, scriptSessionDelete, "delete sessions by user",
			[]string{s.keys.session(id), s.keys.sessionsByUser(owner), s.keys.sessionsAll()},
			owner, id,
		)
		if err != nil {
			return removed, err
		}
		if code == 0 {
			removed++
		}
	}
	return removed, nil
}

// DeleteExpiredSessions removes sessions whose absolute deadline passed at now.
// | DeleteExpiredSessions 删除绝对期限已过的会话。
func (s *sessionStore) DeleteExpiredSessions(ctx context.Context, now time.Time) (int, error) {
	ids, err := s.client.SMembers(ctx, s.keys.sessionsAll()).Result()
	if err != nil {
		return 0, s.backend("delete expired sessions", err)
	}
	if len(ids) == 0 {
		return 0, nil
	}
	cmds := make([]*goredis.SliceCmd, len(ids))
	_, _ = s.client.Pipelined(ctx, func(pipe goredis.Pipeliner) error {
		for i, id := range ids {
			cmds[i] = pipe.HMGet(ctx, s.keys.session(id), "user", "hasExpiry", "expireSec", "expireNsec")
		}
		return nil
	})
	removed := 0
	for i, id := range ids {
		values, err := cmds[i].Result()
		if err != nil {
			return removed, s.backend("delete expired sessions", err)
		}
		if len(values) < 4 || allNil(values) {
			continue
		}
		owner := stringValue(values[0])
		hasExpiry := stringValue(values[1]) == "1"
		expireSec, secErr := strconv.ParseInt(stringValue(values[2]), 10, 64)
		expireNsec, nsecErr := strconv.ParseInt(stringValue(values[3]), 10, 64)
		if secErr != nil || nsecErr != nil {
			return removed, errs.Detail(auth.ErrStoreUnavailable, "stored session expiry is corrupt | 存储的会话期限损坏")
		}
		if !expired(hasExpiry, expireSec, expireNsec, now) {
			continue
		}
		code, err := s.runInt(ctx, scriptSessionDeleteExpired, "delete expired sessions",
			[]string{s.keys.session(id), s.keys.sessionsByUser(owner), s.keys.sessionsAll()},
			owner, stringValue(values[1]), stringValue(values[2]), stringValue(values[3]), id,
		)
		if err != nil {
			return removed, err
		}
		if code == 0 {
			removed++
		}
	}
	return removed, nil
}
