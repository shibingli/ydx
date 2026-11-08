package cas

import (
	"context"
	"errors"
	"sort"
	"strconv"
	"time"

	goredis "github.com/redis/go-redis/v9"

	authcas "github.com/shibingli/ydx/auth/protocol/cas"
	"github.com/shibingli/ydx/errs"
)

// sessionRegistry implements cas.ServiceSessionRegistry on Redis.
// | sessionRegistry 在 Redis 上实现 cas.ServiceSessionRegistry。
type sessionRegistry struct {
	base
}

// sessionRegistry satisfies cas.ServiceSessionRegistry. | sessionRegistry 满足 cas.ServiceSessionRegistry。
var _ authcas.ServiceSessionRegistry = (*sessionRegistry)(nil)

// sessionState is the hash view used by index reconciliation and deletion.
// | sessionState 是索引协调与删除使用的哈希视图。
type sessionState struct {
	data       string
	tgtKey     string
	userKeyOne string
	userKeyTwo string
	hasExpiry  bool
	expireSec  int64
	expireNsec int64
}

// Register stores a deep copy of session and reconciles its indexes atomically.
// | Register 保存 session 的深拷贝并原子协调其索引。
func (r *sessionRegistry) Register(ctx context.Context, session *authcas.ServiceSession) error {
	if session == nil || session.SessionIndex == "" {
		return errs.Detail(authcas.ErrInvalidRequest, "service session is nil or has no index | 服务会话为空或缺少索引")
	}
	stored := session.Clone()
	if stored.TicketID == "" {
		stored.TicketID = stored.SessionIndex
	}
	normalizeSessionTimes(stored)
	data, err := encodeSession(stored)
	if err != nil {
		return err
	}
	sessionKey := r.keys.session(stored.SessionIndex)
	newTGTKey := ""
	if stored.TGTID != "" {
		newTGTKey = r.keys.sessionsByTGT(stored.TGTID)
	}
	newUserKeys := make([]string, 0, 2)
	if stored.User != "" {
		newUserKeys = append(newUserKeys, r.keys.sessionsByUser(stored.User))
	}
	if stored.UserID != "" && stored.UserID != stored.User {
		newUserKeys = append(newUserKeys, r.keys.sessionsByUser(stored.UserID))
	}
	newUserKeyOne, newUserKeyTwo := "", ""
	if len(newUserKeys) > 0 {
		newUserKeyOne = newUserKeys[0]
	}
	if len(newUserKeys) > 1 {
		newUserKeyTwo = newUserKeys[1]
	}
	hasExpiry, expireSec, expireNsec, expiryScore := sessionExpiry(stored.ExpiresAt)
	for attempt := 0; attempt < maxCASRetries; attempt++ {
		state, exists, err := r.readSessionState(ctx, sessionKey)
		if err != nil {
			return err
		}
		code, err := r.runInt(ctx, scriptSessionSave, "register service session", []string{
			sessionKey,
			r.keys.sessionsAll(),
			keyOrDummy(r.keys, newTGTKey),
			keyOrDummy(r.keys, state.tgtKey),
			keyOrDummy(r.keys, newUserKeyOne),
			keyOrDummy(r.keys, state.userKeyOne),
			keyOrDummy(r.keys, newUserKeyTwo),
			keyOrDummy(r.keys, state.userKeyTwo),
			r.keys.sessionsExpiry(),
		},
			string(data), sessionKey, state.data, flag(exists),
			flag(newTGTKey != ""), flag(state.tgtKey != ""),
			flag(newUserKeyOne != ""), flag(state.userKeyOne != ""),
			flag(newUserKeyTwo != ""), flag(state.userKeyTwo != ""),
			flag(hasExpiry), intField(expireSec), intField(expireNsec), intField(expiryScore),
			newTGTKey, newUserKeyOne, newUserKeyTwo,
		)
		if err != nil {
			return err
		}
		switch code {
		case 0:
			return nil
		case 2:
			continue
		default:
			return errs.Detail(ErrStoreUnavailable, "register service session returned %d | 注册服务会话返回 %d", code, code)
		}
	}
	return errs.Detail(ErrConflict, "register service session %[1]q is contended | 注册服务会话 %[1]q 存在竞争", stored.SessionIndex)
}

// Get returns a deep copy of the session with the given index, or cas.ErrSessionNotFound.
// | Get 返回指定索引会话的深拷贝；不存在时返回 cas.ErrSessionNotFound。
func (r *sessionRegistry) Get(ctx context.Context, sessionIndex string) (*authcas.ServiceSession, error) {
	if sessionIndex == "" {
		return nil, authcas.ErrSessionNotFound
	}
	data, err := r.client.HGet(ctx, r.keys.session(sessionIndex), fieldData).Result()
	if errors.Is(err, goredis.Nil) {
		return nil, authcas.ErrSessionNotFound
	}
	if err != nil {
		return nil, r.backend("get service session", err)
	}
	return decodeSession(data)
}

// ListByTGT returns every session rooted at tgtID. | ListByTGT 返回以 tgtID 为根的全部会话。
func (r *sessionRegistry) ListByTGT(ctx context.Context, tgtID string) ([]*authcas.ServiceSession, error) {
	return r.loadByIndex(ctx, r.keys.sessionsByTGT(tgtID), func(session *authcas.ServiceSession) bool {
		return session.TGTID == tgtID
	})
}

// ListByUser returns every session of user. | ListByUser 返回用户的全部会话。
func (r *sessionRegistry) ListByUser(ctx context.Context, user string) ([]*authcas.ServiceSession, error) {
	return r.loadByIndex(ctx, r.keys.sessionsByUser(user), func(session *authcas.ServiceSession) bool {
		return matchesUserSession(session, user)
	})
}

// Delete removes one session; deleting an absent session succeeds. | Delete 删除一个会话；删除不存在
// 的会话视为成功。
func (r *sessionRegistry) Delete(ctx context.Context, sessionIndex string) error {
	if sessionIndex == "" {
		return nil
	}
	_, err := r.deleteKey(ctx, r.keys.session(sessionIndex))
	return err
}

// DeleteByTGT removes and returns every session rooted at tgtID. | DeleteByTGT 删除并返回以 tgtID 为
// 根的全部会话。
func (r *sessionRegistry) DeleteByTGT(ctx context.Context, tgtID string) ([]*authcas.ServiceSession, error) {
	if tgtID == "" {
		return []*authcas.ServiceSession{}, nil
	}
	return r.deleteIndex(ctx, r.keys.sessionsByTGT(tgtID))
}

// DeleteByUser removes and returns every session of user. | DeleteByUser 删除并返回用户的全部会话。
func (r *sessionRegistry) DeleteByUser(ctx context.Context, user string) ([]*authcas.ServiceSession, error) {
	if user == "" {
		return []*authcas.ServiceSession{}, nil
	}
	return r.deleteIndex(ctx, r.keys.sessionsByUser(user))
}

// DeleteExpired removes sessions whose deadline passed at now. | DeleteExpired 删除在 now 时刻已过期限的会话。
func (r *sessionRegistry) DeleteExpired(ctx context.Context, now time.Time) (int, error) {
	now = utcTime(now)
	candidates, err := r.client.ZRangeByScore(ctx, r.keys.sessionsExpiry(), &goredis.ZRangeBy{
		Min: "-inf",
		Max: strconv.FormatInt(now.Unix(), 10),
	}).Result()
	if err != nil {
		return 0, r.backend("delete expired service sessions", err)
	}
	removed := 0
	for _, sessionKey := range candidates {
		deleted, err := r.deleteExpiredKey(ctx, sessionKey, now)
		if err != nil {
			return removed, err
		}
		if deleted {
			removed++
		}
	}
	return removed, nil
}

// readSessionState reads the index and deadline fields owned by one session hash.
// | readSessionState 读取单个会话哈希拥有的索引与期限字段。
func (r *sessionRegistry) readSessionState(ctx context.Context, sessionKey string) (sessionState, bool, error) {
	values, err := r.client.HMGet(ctx, sessionKey,
		fieldData, fieldTGTKey, fieldUserKeyOne, fieldUserKeyTwo,
		fieldHasExpiry, fieldExpireSec, fieldExpireNsec).Result()
	if err != nil {
		return sessionState{}, false, r.backend("read service session", err)
	}
	if len(values) < 7 || allNil(values) {
		return sessionState{}, false, nil
	}
	state := sessionState{
		data:       stringValue(values[0]),
		tgtKey:     stringValue(values[1]),
		userKeyOne: stringValue(values[2]),
		userKeyTwo: stringValue(values[3]),
		hasExpiry:  stringValue(values[4]) == "1",
	}
	if state.expireSec, err = parseStoredInt(stringValue(values[5])); err != nil {
		return sessionState{}, false, err
	}
	if state.expireNsec, err = parseStoredInt(stringValue(values[6])); err != nil {
		return sessionState{}, false, err
	}
	return state, true, nil
}

// deleteKey removes one session hash by key and returns its last decoded value.
// | deleteKey 按键删除单个会话哈希并返回其最后解码值。
func (r *sessionRegistry) deleteKey(ctx context.Context, sessionKey string) (*authcas.ServiceSession, error) {
	for attempt := 0; attempt < maxCASRetries; attempt++ {
		state, exists, err := r.readSessionState(ctx, sessionKey)
		if err != nil {
			return nil, err
		}
		if !exists {
			return nil, nil
		}
		session, err := decodeSession(state.data)
		if err != nil {
			return nil, err
		}
		deleted, retry, err := r.runDelete(ctx, sessionKey, state, "delete service session")
		if err != nil {
			return nil, err
		}
		if !retry {
			if deleted {
				return session, nil
			}
			return nil, nil
		}
	}
	return nil, errs.Detail(ErrConflict, "delete service session %[1]q is contended | 删除服务会话 %[1]q 存在竞争", sessionKey)
}

// deleteExpiredKey removes one candidate when its exact deadline passed at now.
// | deleteExpiredKey 在候选会话的精确期限已过时将其删除。
func (r *sessionRegistry) deleteExpiredKey(ctx context.Context, sessionKey string, now time.Time) (bool, error) {
	for attempt := 0; attempt < maxCASRetries; attempt++ {
		state, exists, err := r.readSessionState(ctx, sessionKey)
		if err != nil {
			return false, err
		}
		if !exists || !state.hasExpiry {
			return false, nil
		}
		if now.Before(time.Unix(state.expireSec, state.expireNsec)) {
			return false, nil
		}
		deleted, retry, err := r.runDelete(ctx, sessionKey, state, "delete expired service sessions")
		if err != nil {
			return false, err
		}
		if !retry {
			return deleted, nil
		}
	}
	return false, errs.Detail(ErrConflict, "delete expired service session %[1]q is contended | 删除过期服务会话 %[1]q 存在竞争", sessionKey)
}

// runDelete executes the session delete script for one known state. | runDelete 针对已知状态执行会话
// 删除脚本。
func (r *sessionRegistry) runDelete(ctx context.Context, sessionKey string, state sessionState, op string) (bool, bool, error) {
	code, err := r.runInt(ctx, scriptSessionDelete, op, []string{
		sessionKey,
		r.keys.sessionsAll(),
		keyOrDummy(r.keys, state.tgtKey),
		keyOrDummy(r.keys, state.userKeyOne),
		keyOrDummy(r.keys, state.userKeyTwo),
		r.keys.sessionsExpiry(),
	},
		sessionKey, state.data,
		flag(state.tgtKey != ""), flag(state.userKeyOne != ""), flag(state.userKeyTwo != ""),
	)
	if err != nil {
		return false, false, err
	}
	switch code {
	case 1:
		return true, false, nil
	case 0:
		return false, false, nil
	case 2:
		return false, true, nil
	default:
		return false, false, errs.Detail(ErrStoreUnavailable, "delete service session returned %d | 删除服务会话返回 %d", code, code)
	}
}

// deleteIndex removes every session named by index and returns the removed sessions.
// | deleteIndex 删除 index 指定的全部会话并返回被删除的会话。
func (r *sessionRegistry) deleteIndex(ctx context.Context, index string) ([]*authcas.ServiceSession, error) {
	members, err := r.client.SMembers(ctx, index).Result()
	if err != nil {
		return nil, r.backend("delete service session index", err)
	}
	removed := make([]*authcas.ServiceSession, 0, len(members))
	for _, sessionKey := range members {
		session, err := r.deleteKey(ctx, sessionKey)
		if err != nil {
			return removed, err
		}
		if session != nil {
			removed = append(removed, session)
		}
	}
	sortSessions(removed)
	return removed, nil
}

// loadByIndex loads, filters and sorts the sessions named by one index set.
// | loadByIndex 加载、过滤并排序单个索引集合指定的会话。
func (r *sessionRegistry) loadByIndex(ctx context.Context, index string, match func(*authcas.ServiceSession) bool) ([]*authcas.ServiceSession, error) {
	members, err := r.client.SMembers(ctx, index).Result()
	if err != nil {
		return nil, r.backend("list service sessions", err)
	}
	return r.loadSessions(ctx, members, match)
}

// loadSessions loads the sessions named by members, filters them and sorts by issue time.
// | loadSessions 加载 members 指定的会话，进行过滤并按签发时间排序。
func (r *sessionRegistry) loadSessions(ctx context.Context, members []string, match func(*authcas.ServiceSession) bool) ([]*authcas.ServiceSession, error) {
	out := make([]*authcas.ServiceSession, 0, len(members))
	if len(members) == 0 {
		return out, nil
	}
	cmds := make([]*goredis.StringCmd, len(members))
	_, _ = r.client.Pipelined(ctx, func(pipe goredis.Pipeliner) error {
		for i, member := range members {
			cmds[i] = pipe.HGet(ctx, member, fieldData)
		}
		return nil
	})
	for i := range members {
		data, err := cmds[i].Result()
		if errors.Is(err, goredis.Nil) {
			continue
		}
		if err != nil {
			return nil, r.backend("load service sessions", err)
		}
		session, err := decodeSession(data)
		if err != nil {
			return nil, err
		}
		if match != nil && !match(session) {
			continue
		}
		out = append(out, session)
	}
	sortSessions(out)
	return out, nil
}

// sortSessions orders sessions by issue time and then index. | sortSessions 按签发时间与索引排序会话。
func sortSessions(sessions []*authcas.ServiceSession) {
	sort.Slice(sessions, func(i, j int) bool {
		if sessions[i].IssuedAt.Equal(sessions[j].IssuedAt) {
			return sessions[i].SessionIndex < sessions[j].SessionIndex
		}
		return sessions[i].IssuedAt.Before(sessions[j].IssuedAt)
	})
}

// matchesUserSession reports whether user names the session by protocol user or backend user ID.
// | matchesUserSession 报告 user 是否以协议用户或后端用户 ID 命名该会话。
func matchesUserSession(session *authcas.ServiceSession, user string) bool {
	return session.User == user || session.UserID == user
}
