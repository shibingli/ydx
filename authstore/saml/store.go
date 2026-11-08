package saml

import (
	"context"
	"errors"
	"sort"
	"time"

	goredis "github.com/redis/go-redis/v9"

	samlapi "github.com/shibingli/ydx/auth/protocol/saml"
	"github.com/shibingli/ydx/errs"
)

// SaveRequest stores an outstanding request. It reports saml.ErrReplay when the identifier is
// already present, including when the stored record has expired but has not been cleaned up. |
// SaveRequest 保存未完成请求。标识已存在时返回 saml.ErrReplay，包括已存记录已过期但尚未清理的情况。
func (s *Stores) SaveRequest(ctx context.Context, request *samlapi.RequestState) error {
	if err := s.ensure(); err != nil {
		return err
	}
	if request == nil || request.ID == "" {
		return errs.Detail(samlapi.ErrInvalidRequest, "request id is empty | 请求标识为空")
	}
	data, err := encodeRequest(request)
	if err != nil {
		return err
	}
	hasExpiry, expireSec, expireNsec := expiryFields(request.ExpiresAt)
	member := s.keys.request(request.ID)
	code, err := s.runInt(ctx, scriptRequestCreate, "save request",
		[]string{member, s.keys.requestsExpiry()},
		string(data), flag(request.Used), hasExpiry, expireSec, expireNsec, member)
	if err != nil {
		return err
	}
	switch code {
	case 0:
		return nil
	case 1:
		return errs.Detail(samlapi.ErrReplay, "request id already exists | 请求标识已存在")
	default:
		return errs.Detail(ErrStoreUnavailable, "save request returned %d | 保存请求返回 %d", code, code)
	}
}

// ConsumeRequest atomically consumes a request by ID and returns a deep copy. Unknown and
// already-used requests report saml.ErrInvalidRequest; expired requests report
// saml.ErrResponseExpired. | ConsumeRequest 按 ID 原子消费请求并返回深拷贝。未知与已用请求返回
// saml.ErrInvalidRequest；过期请求返回 saml.ErrResponseExpired。
func (s *Stores) ConsumeRequest(ctx context.Context, id string, now time.Time) (*samlapi.RequestState, error) {
	if err := s.ensure(); err != nil {
		return nil, err
	}
	nowSec, nowNsec := clockFields(now)
	reply, err := s.runSlice(ctx, scriptRequestConsume, "consume request",
		[]string{s.keys.request(id)}, nowSec, nowNsec)
	if err != nil {
		return nil, err
	}
	if len(reply) < 2 {
		return nil, errs.Detail(ErrStoreUnavailable, "consume request returned an invalid reply | 消费请求返回无效应答")
	}
	switch stringValue(reply[0]) {
	case "-1", "-2":
		return nil, errs.Detail(samlapi.ErrInvalidRequest, "unknown or used request %[1]q | 未知或已用请求 %[1]q", id)
	case "-3":
		return nil, errs.Detail(samlapi.ErrResponseExpired, "request expired | 请求已过期")
	case "0":
		request, decodeErr := decodeRequest([]byte(stringValue(reply[1])))
		if decodeErr != nil {
			return nil, decodeErr
		}
		request.Used = true
		return request, nil
	default:
		return nil, errs.Detail(ErrStoreUnavailable, "consume request returned an unknown status | 消费请求返回未知状态")
	}
}

// SeenAndStore atomically records assertionID until expiresAt and reports whether a live record
// already existed. Records whose expiry is at or before now may be replaced. An empty identifier
// reports saml.ErrInvalidResponse and a nil receiver reports saml.ErrInvalidConfig; any error means
// replay status is unknown and validation must fail closed. | SeenAndStore 原子记录 assertionID
// 直到 expiresAt，并报告是否已存在有效记录。过期时间等于或早于 now 的记录可被替换。标识为空返回
// saml.ErrInvalidResponse，接收者为空返回 saml.ErrInvalidConfig；任何错误都表示重放状态未知，校验
// 必须失败关闭。
func (s *Stores) SeenAndStore(ctx context.Context, assertionID string, expiresAt, now time.Time) (bool, error) {
	if err := s.ensure(); err != nil {
		return false, err
	}
	if assertionID == "" {
		return false, errs.Detail(samlapi.ErrInvalidResponse, "assertion id is empty | 断言标识为空")
	}
	hasExpiry, expireSec, expireNsec := expiryFields(expiresAt)
	nowSec, nowNsec := clockFields(now)
	member := s.keys.assertion(assertionID)
	code, err := s.runInt(ctx, scriptAssertionSeenAndStore, "record assertion",
		[]string{member, s.keys.assertionsExpiry()},
		expireSec, expireNsec, hasExpiry, nowSec, nowNsec, member, expireSec)
	if err != nil {
		return false, err
	}
	switch code {
	case 0:
		return false, nil
	case 1:
		return true, nil
	default:
		return false, errs.Detail(ErrStoreUnavailable, "record assertion returned %d | 记录断言返回 %d", code, code)
	}
}

// SaveAssertion records an assertion ID and reports whether it was fresh. It is the
// saml.Store view of SeenAndStore. | SaveAssertion 记录断言 ID 并报告是否新鲜。它是 SeenAndStore
// 的 saml.Store 视图。
func (s *Stores) SaveAssertion(ctx context.Context, id string, expiresAt, now time.Time) (bool, error) {
	seen, err := s.SeenAndStore(ctx, id, expiresAt, now)
	if err != nil {
		return false, err
	}
	return !seen, nil
}

// SaveSession stores an IdP session, replacing any record with the same ID and moving its subject
// membership. A nil session or empty ID reports saml.ErrInvalidRequest. | SaveSession 保存 IdP 会话，
// 替换相同 ID 的记录并迁移其主体成员关系。空会话或空标识返回 saml.ErrInvalidRequest。
func (s *Stores) SaveSession(ctx context.Context, session *samlapi.Session) error {
	if err := s.ensure(); err != nil {
		return err
	}
	if session == nil || session.ID == "" {
		return errs.Detail(samlapi.ErrInvalidRequest, "session id is empty | 会话标识为空")
	}
	data, err := encodeSession(session)
	if err != nil {
		return err
	}
	hasExpiry, expireSec, expireNsec := expiryFields(session.ExpiresAt)
	member := s.keys.session(session.ID)
	newSubject := s.keys.sessionsBySubject(session.NameID)
	index := s.keys.sessionsExpiry()
	for attempt := 0; attempt < maxCASRetries; attempt++ {
		oldNameID, readErr := s.client.HGet(ctx, member, "nameID").Result()
		if errors.Is(readErr, goredis.Nil) {
			oldNameID = ""
		} else if readErr != nil {
			return s.backend("save session", readErr)
		}
		code, runErr := s.runInt(ctx, scriptSessionSave, "save session",
			[]string{member, newSubject, s.keys.sessionsBySubject(oldNameID), index},
			string(data), session.NameID, oldNameID, hasExpiry, expireSec, expireNsec, member)
		if runErr != nil {
			return runErr
		}
		switch code {
		case 0:
			return nil
		case 1:
			continue
		default:
			return errs.Detail(ErrStoreUnavailable, "save session returned %d | 保存会话返回 %d", code, code)
		}
	}
	return errs.Detail(ErrConflict, "save session %[1]q is contended | 保存会话 %[1]q 存在竞争", session.ID)
}

// GetSession returns an IdP session as a deep copy. Unknown sessions report
// saml.ErrInvalidRequest. Expired sessions remain readable until Cleanup removes them, matching the
// in-memory store. | GetSession 返回 IdP 会话深拷贝。未知会话返回 saml.ErrInvalidRequest。过期会话
// 在被 Cleanup 删除前仍可读取，与内存存储一致。
func (s *Stores) GetSession(ctx context.Context, id string) (*samlapi.Session, error) {
	if err := s.ensure(); err != nil {
		return nil, err
	}
	data, err := s.client.HGet(ctx, s.keys.session(id), "data").Result()
	if errors.Is(err, goredis.Nil) {
		return nil, errs.Detail(samlapi.ErrInvalidRequest, "unknown session %[1]q | 未知会话 %[1]q", id)
	}
	if err != nil {
		return nil, s.backend("get session", err)
	}
	return decodeSession([]byte(data))
}

// DeleteSession removes an IdP session and its indexes. Deleting an unknown session succeeds, as
// in the in-memory store. | DeleteSession 删除 IdP 会话及其索引。删除未知会话会成功，与内存存储一致。
func (s *Stores) DeleteSession(ctx context.Context, id string) error {
	if err := s.ensure(); err != nil {
		return err
	}
	member := s.keys.session(id)
	index := s.keys.sessionsExpiry()
	for attempt := 0; attempt < maxCASRetries; attempt++ {
		nameID, readErr := s.client.HGet(ctx, member, "nameID").Result()
		if errors.Is(readErr, goredis.Nil) {
			nameID = ""
		} else if readErr != nil {
			return s.backend("delete session", readErr)
		}
		code, runErr := s.runInt(ctx, scriptSessionDelete, "delete session",
			[]string{member, s.keys.sessionsBySubject(nameID), index}, nameID, member)
		if runErr != nil {
			return runErr
		}
		switch code {
		case 0, 1:
			return nil
		case 2:
			continue
		default:
			return errs.Detail(ErrStoreUnavailable, "delete session returned %d | 删除会话返回 %d", code, code)
		}
	}
	return errs.Detail(ErrConflict, "delete session %[1]q is contended | 删除会话 %[1]q 存在竞争", id)
}

// ListSessions returns deep copies of every session of a subject. The subject set is paged with
// SSCAN, so a large subject does not require one unbounded Redis reply. | ListSessions 返回主体全部
// 会话的深拷贝。主体集合使用 SSCAN 分页，因此大型主体不需要单次无界 Redis 应答。
func (s *Stores) ListSessions(ctx context.Context, nameID string) ([]*samlapi.Session, error) {
	if err := s.ensure(); err != nil {
		return nil, err
	}
	subjectKey := s.keys.sessionsBySubject(nameID)
	cursor := uint64(0)
	seen := make(map[string]struct{}, 4)
	sessions := make([]*samlapi.Session, 0, 4)
	for {
		members, next, err := s.client.SScan(ctx, subjectKey, cursor, "", sessionScanBatch).Result()
		if err != nil {
			return nil, s.backend("list sessions", err)
		}
		pending := make([]string, 0, len(members))
		for _, member := range members {
			if _, ok := seen[member]; ok {
				continue
			}
			seen[member] = struct{}{}
			pending = append(pending, member)
		}
		if len(pending) > 0 {
			pipe := s.client.Pipeline()
			commands := make([]*goredis.StringCmd, len(pending))
			for position, member := range pending {
				commands[position] = pipe.HGet(ctx, member, "data")
			}
			_, _ = pipe.Exec(ctx)
			for _, command := range commands {
				data, commandErr := command.Result()
				if errors.Is(commandErr, goredis.Nil) {
					continue
				}
				if commandErr != nil {
					return nil, s.backend("list sessions", commandErr)
				}
				session, decodeErr := decodeSession([]byte(data))
				if decodeErr != nil {
					return nil, decodeErr
				}
				sessions = append(sessions, session)
			}
		}
		cursor = next
		if cursor == 0 {
			break
		}
	}
	sort.Slice(sessions, func(i, j int) bool { return sessions[i].ID < sessions[j].ID })
	return sessions, nil
}

// Cleanup removes expired requests, assertion replay records, sessions and artifacts. Records with
// no expiry are retained, except assertion records, whose zero expiry is treated as immediately
// expired like the in-memory store. Cleanup is safe to run concurrently with every other method. |
// Cleanup 删除过期请求、断言重放记录、会话与工件。无到期时间的记录会保留，断言记录除外，其零值期限
// 与内存存储一样被视为立即过期。Cleanup 可与其它所有方法并发安全运行。
func (s *Stores) Cleanup(ctx context.Context, now time.Time) error {
	if err := s.ensure(); err != nil {
		return err
	}
	if _, err := s.cleanupIndex(ctx, s.keys.requestsExpiry(), "cleanup requests", now); err != nil {
		return err
	}
	if _, err := s.cleanupIndex(ctx, s.keys.assertionsExpiry(), "cleanup assertions", now); err != nil {
		return err
	}
	if _, err := s.cleanupSessions(ctx, now); err != nil {
		return err
	}
	if _, err := s.cleanupIndex(ctx, s.keys.artifactsExpiry(), "cleanup artifacts", now); err != nil {
		return err
	}
	return nil
}

// CleanupAssertions removes expired assertion replay records and returns the removed count. It
// matches the optional saml.AssertionReplayCleaner surface. | CleanupAssertions 删除过期断言重放
// 记录并返回删除数量。它匹配可选的 saml.AssertionReplayCleaner 接口。
func (s *Stores) CleanupAssertions(ctx context.Context, now time.Time) (int, error) {
	if err := s.ensure(); err != nil {
		return 0, err
	}
	return s.cleanupIndex(ctx, s.keys.assertionsExpiry(), "cleanup assertions", now)
}

// cleanupIndex removes every expired record indexed by indexKey, paging the definitely-expired
// bucket and then handling records that expire during the boundary second.
// | cleanupIndex 删除 indexKey 索引的全部过期记录，先分页处理确定过期的桶，再处理边界秒内到期的记录。
func (s *Stores) cleanupIndex(ctx context.Context, indexKey, op string, now time.Time) (int, error) {
	nowSec, nowNsec := clockFields(now)
	total := 0
	for {
		processed, removed, err := s.cleanupCall(ctx, scriptCleanupBefore, op, []string{indexKey}, nowSec, cleanupBatch)
		if err != nil {
			return total, err
		}
		total += removed
		if processed < cleanupBatch {
			break
		}
	}
	_, removed, err := s.cleanupCall(ctx, scriptCleanupAt, op, []string{indexKey}, nowSec, nowNsec)
	if err != nil {
		return total, err
	}
	return total + removed, nil
}

// cleanupSessions removes expired sessions and their subject set membership.
// | cleanupSessions 删除过期会话及其主体集合成员关系。
func (s *Stores) cleanupSessions(ctx context.Context, now time.Time) (int, error) {
	nowSec, nowNsec := clockFields(now)
	subjectPrefix := s.keys.sessionSubjectPrefix()
	indexKey := s.keys.sessionsExpiry()
	total := 0
	for {
		processed, removed, err := s.cleanupCall(ctx, scriptSessionCleanupBefore, "cleanup sessions",
			[]string{indexKey}, nowSec, cleanupBatch, subjectPrefix)
		if err != nil {
			return total, err
		}
		total += removed
		if processed < cleanupBatch {
			break
		}
	}
	_, removed, err := s.cleanupCall(ctx, scriptSessionCleanupAt, "cleanup sessions",
		[]string{indexKey}, nowSec, nowNsec, subjectPrefix)
	if err != nil {
		return total, err
	}
	return total + removed, nil
}

// cleanupCall runs one cleanup script and decodes its {processed, removed} reply.
// | cleanupCall 运行单个清理脚本并解析其 {processed, removed} 应答。
func (s *Stores) cleanupCall(ctx context.Context, script *goredis.Script, op string, scriptKeys []string, args ...any) (int, int, error) {
	reply, err := s.runSlice(ctx, script, op, scriptKeys, args...)
	if err != nil {
		return 0, 0, err
	}
	if len(reply) != 2 {
		return 0, 0, errs.Detail(ErrStoreUnavailable, "cleanup returned an invalid reply | 清理返回无效应答")
	}
	processed, parseErr := intValue(reply[0])
	if parseErr != nil {
		return 0, 0, parseErr
	}
	removed, parseErr := intValue(reply[1])
	if parseErr != nil {
		return 0, 0, parseErr
	}
	if processed < 0 || removed < 0 || removed > processed {
		return 0, 0, errs.Detail(ErrStoreUnavailable, "cleanup returned an invalid count | 清理返回无效计数")
	}
	return int(processed), int(removed), nil
}
