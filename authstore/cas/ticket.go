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

// ticketStore implements cas.TicketStore on Redis. | ticketStore 在 Redis 上实现 cas.TicketStore。
type ticketStore struct {
	base
}

// ticketStore satisfies cas.TicketStore. | ticketStore 满足 cas.TicketStore。
var _ authcas.TicketStore = (*ticketStore)(nil)

// ticketState is the hash view used by index reconciliation and deletion. | ticketState 是索引协调与
// 删除使用的哈希视图。
type ticketState struct {
	data       string
	typ        authcas.TicketType
	serviceKey string
	rootKey    string
	userKey    string
	expireSec  int64
	expireNsec int64
}

// Save stores a deep copy of ticket and reconciles its indexes atomically.
// | Save 保存 ticket 的深拷贝并原子协调其索引。
func (s *ticketStore) Save(ctx context.Context, ticket *authcas.Ticket) error {
	if ticket == nil || ticket.ID == "" {
		return errs.Detail(authcas.ErrInvalidRequest, "ticket is nil or has no id | 票据为空或缺少 ID")
	}
	stored := ticket.Clone()
	normalizeTicketTimes(stored)
	data, err := encodeTicket(stored)
	if err != nil {
		return err
	}
	ticketKey := s.keys.ticket(stored.ID)
	newTypeKey := ""
	if stored.Type != "" {
		newTypeKey = s.keys.ticketsByType(stored.Type)
	}
	newServiceKey := ""
	if stored.Service != "" {
		newServiceKey = s.keys.ticketsByService(stored.Service)
	}
	newRootKey := ""
	if stored.RootTGTID != "" {
		newRootKey = s.keys.ticketsByRoot(stored.RootTGTID)
	}
	newUserKey := ""
	if stored.UserID != "" {
		newUserKey = s.keys.ticketsByUser(stored.UserID)
	}
	expireSec, expireNsec, expiryScore := ticketExpiry(stored.ExpiresAt)
	consumedSec, consumedNsec := consumedFields(stored.ConsumedAt)
	for attempt := 0; attempt < maxCASRetries; attempt++ {
		state, exists, err := s.readTicketState(ctx, ticketKey)
		if err != nil {
			return err
		}
		oldTypeKey := ""
		if exists && state.typ != "" {
			oldTypeKey = s.keys.ticketsByType(state.typ)
		}
		code, err := s.runInt(ctx, scriptTicketSave, "save ticket", []string{
			ticketKey,
			s.keys.ticketsAll(),
			keyOrDummy(s.keys, newTypeKey),
			keyOrDummy(s.keys, oldTypeKey),
			keyOrDummy(s.keys, newServiceKey),
			keyOrDummy(s.keys, state.serviceKey),
			keyOrDummy(s.keys, newRootKey),
			keyOrDummy(s.keys, state.rootKey),
			keyOrDummy(s.keys, newUserKey),
			keyOrDummy(s.keys, state.userKey),
			s.keys.ticketsExpiry(),
		},
			string(data), string(stored.Type),
			flag(newTypeKey != ""), flag(oldTypeKey != ""),
			flag(newServiceKey != ""), flag(state.serviceKey != ""),
			flag(newRootKey != ""), flag(state.rootKey != ""),
			flag(newUserKey != ""), flag(state.userKey != ""),
			intField(expireSec), intField(expireNsec), intField(expiryScore),
			ticketKey, state.data, flag(exists),
			flag(stored.Consumed()), intField(consumedSec), intField(consumedNsec),
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
			return errs.Detail(ErrStoreUnavailable, "save ticket returned %d | 保存票据返回 %d", code, code)
		}
	}
	return errs.Detail(ErrConflict, "save ticket %[1]q is contended | 保存票据 %[1]q 存在竞争", ticket.ID)
}

// Get returns a deep copy of the ticket with the given identifier. | Get 返回指定标识票据的深拷贝。
func (s *ticketStore) Get(ctx context.Context, id string) (*authcas.Ticket, error) {
	if id == "" {
		return nil, authcas.ErrTicketNotFound
	}
	values, err := s.client.HMGet(ctx, s.keys.ticket(id),
		fieldData, fieldConsumed, fieldConsumedSec, fieldConsumedNsec).Result()
	if err != nil {
		return nil, s.backend("get ticket", err)
	}
	if len(values) < 4 || allNil(values) {
		return nil, authcas.ErrTicketNotFound
	}
	ticket, err := decodeTicket(stringValue(values[0]))
	if err != nil {
		return nil, err
	}
	ticket.ConsumedAt = time.Time{}
	if stringValue(values[1]) == "1" {
		sec, err := parseStoredInt(stringValue(values[2]))
		if err != nil {
			return nil, err
		}
		nsec, err := parseStoredInt(stringValue(values[3]))
		if err != nil {
			return nil, err
		}
		ticket.ConsumedAt = utcTime(time.Unix(sec, nsec))
	}
	return ticket, nil
}

// Consume atomically checks type, expiry and single-use state, then marks the ticket consumed.
// | Consume 原子检查类型、有效期与单次使用状态，然后标记票据已消费。
func (s *ticketStore) Consume(ctx context.Context, id string, typ authcas.TicketType, now time.Time) (*authcas.Ticket, error) {
	if id == "" {
		return nil, authcas.ErrTicketNotFound
	}
	now = utcTime(now)
	nowSec, nowNsec := clockFields(now)
	reply, err := s.runSlice(ctx, scriptTicketConsume, "consume ticket",
		[]string{s.keys.ticket(id)}, string(typ), nowSec, nowNsec)
	if err != nil {
		return nil, err
	}
	if len(reply) < 2 {
		return nil, errs.Detail(ErrStoreUnavailable, "consume ticket returned an invalid reply | 消费票据返回无效应答")
	}
	switch stringValue(reply[0]) {
	case "-1":
		return nil, authcas.ErrTicketNotFound
	case "-2":
		return nil, errs.Detail(authcas.ErrTicketTypeMismatch, "ticket %[1]q has another type | 票据 %[1]q 的类型不符", id)
	case "-3":
		return nil, errs.Detail(authcas.ErrTicketUsed, "ticket %[1]q is consumed | 票据 %[1]q 已消费", id)
	case "-4":
		return nil, errs.Detail(authcas.ErrTicketExpired, "ticket %[1]q deadline passed | 票据 %[1]q 期限已过", id)
	case "0":
		ticket, err := decodeTicket(stringValue(reply[1]))
		if err != nil {
			return nil, err
		}
		ticket.ConsumedAt = now
		return ticket, nil
	default:
		return nil, errs.Detail(ErrStoreUnavailable, "consume ticket returned an unknown status | 消费票据返回未知状态")
	}
}

// Delete removes one ticket; deleting an absent ticket succeeds. | Delete 删除一张票据；删除不存在的
// 票据视为成功。
func (s *ticketStore) Delete(ctx context.Context, id string) error {
	if id == "" {
		return nil
	}
	_, err := s.deleteKey(ctx, s.keys.ticket(id))
	return err
}

// DeleteByRootTGT removes a TGT and every derived ticket. | DeleteByRootTGT 删除 TGT 及其派生的全部票据。
func (s *ticketStore) DeleteByRootTGT(ctx context.Context, tgtID string) (int, error) {
	if tgtID == "" {
		return 0, nil
	}
	return s.deleteIndex(ctx, s.keys.ticketsByRoot(tgtID))
}

// DeleteByUser removes every ticket of a user. | DeleteByUser 删除用户的全部票据。
func (s *ticketStore) DeleteByUser(ctx context.Context, userID string) (int, error) {
	if userID == "" {
		return 0, nil
	}
	return s.deleteIndex(ctx, s.keys.ticketsByUser(userID))
}

// DeleteExpired removes tickets whose deadline passed at now. | DeleteExpired 删除在 now 时刻已过期限的票据。
func (s *ticketStore) DeleteExpired(ctx context.Context, now time.Time) (int, error) {
	now = utcTime(now)
	candidates, err := s.client.ZRangeByScore(ctx, s.keys.ticketsExpiry(), &goredis.ZRangeBy{
		Min: "-inf",
		Max: strconv.FormatInt(now.Unix(), 10),
	}).Result()
	if err != nil {
		return 0, s.backend("delete expired tickets", err)
	}
	removed := 0
	for _, ticketKey := range candidates {
		deleted, err := s.deleteExpiredKey(ctx, ticketKey, now)
		if err != nil {
			return removed, err
		}
		if deleted {
			removed++
		}
	}
	return removed, nil
}

// ListByService returns every ticket currently bound to service. | ListByService 返回当前绑定到
// service 的全部票据。
func (s *ticketStore) ListByService(ctx context.Context, service string) ([]*authcas.Ticket, error) {
	return s.loadByIndex(ctx, s.keys.ticketsByService(service), func(ticket *authcas.Ticket) bool {
		return ticket.Service == service
	})
}

// ListByRootTGT returns the TGT and every derived ticket. | ListByRootTGT 返回 TGT 及其派生的全部票据。
func (s *ticketStore) ListByRootTGT(ctx context.Context, tgtID string) ([]*authcas.Ticket, error) {
	return s.loadByIndex(ctx, s.keys.ticketsByRoot(tgtID), func(ticket *authcas.Ticket) bool {
		return ticket.RootTGTID == tgtID
	})
}

// readTicketState reads the index and deadline fields owned by one ticket hash.
// | readTicketState 读取单张票据哈希拥有的索引与期限字段。
func (s *ticketStore) readTicketState(ctx context.Context, ticketKey string) (ticketState, bool, error) {
	values, err := s.client.HMGet(ctx, ticketKey,
		fieldData, fieldType, fieldServiceKey, fieldRootKey, fieldUserKey,
		fieldExpireSec, fieldExpireNsec).Result()
	if err != nil {
		return ticketState{}, false, s.backend("read ticket", err)
	}
	if len(values) < 7 || allNil(values) {
		return ticketState{}, false, nil
	}
	state := ticketState{
		data:       stringValue(values[0]),
		typ:        authcas.TicketType(stringValue(values[1])),
		serviceKey: stringValue(values[2]),
		rootKey:    stringValue(values[3]),
		userKey:    stringValue(values[4]),
	}
	if state.expireSec, err = parseStoredInt(stringValue(values[5])); err != nil {
		return ticketState{}, false, err
	}
	if state.expireNsec, err = parseStoredInt(stringValue(values[6])); err != nil {
		return ticketState{}, false, err
	}
	return state, true, nil
}

// deleteKey removes one ticket hash by key, retrying when a concurrent writer wins the guard.
// | deleteKey 按键删除单个票据哈希，在并发写入赢得守卫时重试。
func (s *ticketStore) deleteKey(ctx context.Context, ticketKey string) (bool, error) {
	for attempt := 0; attempt < maxCASRetries; attempt++ {
		state, exists, err := s.readTicketState(ctx, ticketKey)
		if err != nil {
			return false, err
		}
		if !exists {
			return false, nil
		}
		deleted, retry, err := s.runDelete(ctx, ticketKey, state, "delete ticket")
		if err != nil {
			return false, err
		}
		if !retry {
			return deleted, nil
		}
	}
	return false, errs.Detail(ErrConflict, "delete ticket %[1]q is contended | 删除票据 %[1]q 存在竞争", ticketKey)
}

// deleteExpiredKey removes one candidate when its exact deadline passed at now.
// | deleteExpiredKey 在候选票据的精确期限已过时将其删除。
func (s *ticketStore) deleteExpiredKey(ctx context.Context, ticketKey string, now time.Time) (bool, error) {
	for attempt := 0; attempt < maxCASRetries; attempt++ {
		state, exists, err := s.readTicketState(ctx, ticketKey)
		if err != nil {
			return false, err
		}
		if !exists {
			return false, nil
		}
		if now.Before(time.Unix(state.expireSec, state.expireNsec)) {
			return false, nil
		}
		deleted, retry, err := s.runDelete(ctx, ticketKey, state, "delete expired tickets")
		if err != nil {
			return false, err
		}
		if !retry {
			return deleted, nil
		}
	}
	return false, errs.Detail(ErrConflict, "delete expired ticket %[1]q is contended | 删除过期票据 %[1]q 存在竞争", ticketKey)
}

// runDelete executes the delete script for one known ticket state. The boolean result reports a
// deleted record and the retry result requests a fresh state read. | runDelete 针对已知票据状态执行
// 删除脚本。布尔结果报告是否删除记录，retry 结果要求重新读取状态。
func (s *ticketStore) runDelete(ctx context.Context, ticketKey string, state ticketState, op string) (bool, bool, error) {
	code, err := s.runInt(ctx, scriptTicketDelete, op, []string{
		ticketKey,
		s.keys.ticketsAll(),
		keyOrDummy(s.keys, typeKey(s.keys, state.typ)),
		keyOrDummy(s.keys, state.serviceKey),
		keyOrDummy(s.keys, state.rootKey),
		keyOrDummy(s.keys, state.userKey),
		s.keys.ticketsExpiry(),
	},
		ticketKey, state.data,
		flag(state.typ != ""), flag(state.serviceKey != ""),
		flag(state.rootKey != ""), flag(state.userKey != ""),
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
		return false, false, errs.Detail(ErrStoreUnavailable, "delete ticket returned %d | 删除票据返回 %d", code, code)
	}
}

// deleteIndex removes every ticket named by index and returns the number deleted.
// | deleteIndex 删除 index 指定的全部票据并返回删除数量。
func (s *ticketStore) deleteIndex(ctx context.Context, index string) (int, error) {
	members, err := s.client.SMembers(ctx, index).Result()
	if err != nil {
		return 0, s.backend("delete ticket index", err)
	}
	removed := 0
	for _, ticketKey := range members {
		deleted, err := s.deleteKey(ctx, ticketKey)
		if err != nil {
			return removed, err
		}
		if deleted {
			removed++
		}
	}
	return removed, nil
}

// loadByIndex loads, filters and sorts the tickets named by one index set.
// | loadByIndex 加载、过滤并排序单个索引集合指定的票据。
func (s *ticketStore) loadByIndex(ctx context.Context, index string, match func(*authcas.Ticket) bool) ([]*authcas.Ticket, error) {
	members, err := s.client.SMembers(ctx, index).Result()
	if err != nil {
		return nil, s.backend("list tickets", err)
	}
	return s.loadTickets(ctx, members, match)
}

// loadTickets loads the tickets named by members, filters them and sorts by issue time.
// | loadTickets 加载 members 指定的票据，进行过滤并按签发时间排序。
func (s *ticketStore) loadTickets(ctx context.Context, members []string, match func(*authcas.Ticket) bool) ([]*authcas.Ticket, error) {
	out := make([]*authcas.Ticket, 0, len(members))
	if len(members) == 0 {
		return out, nil
	}
	cmds := make([]*goredis.StringCmd, len(members))
	_, _ = s.client.Pipelined(ctx, func(pipe goredis.Pipeliner) error {
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
			return nil, s.backend("load tickets", err)
		}
		ticket, err := decodeTicket(data)
		if err != nil {
			return nil, err
		}
		if match != nil && !match(ticket) {
			continue
		}
		out = append(out, ticket)
	}
	sortTickets(out)
	return out, nil
}

// sortTickets orders tickets by issue time and then identifier. | sortTickets 按签发时间与标识排序票据。
func sortTickets(tickets []*authcas.Ticket) {
	sort.Slice(tickets, func(i, j int) bool {
		if tickets[i].IssuedAt.Equal(tickets[j].IssuedAt) {
			return tickets[i].ID < tickets[j].ID
		}
		return tickets[i].IssuedAt.Before(tickets[j].IssuedAt)
	})
}

// typeKey returns the type index key of typ, or an empty string for an unknown type.
// | typeKey 返回 typ 的类型索引键；未知类型返回空串。
func typeKey(k keys, typ authcas.TicketType) string {
	if typ == "" {
		return ""
	}
	return k.ticketsByType(typ)
}

// keyOrDummy returns key, or the shared dummy key when key is empty. | keyOrDummy 返回 key；key 为空
// 时返回共享占位键。
func keyOrDummy(k keys, key string) string {
	if key == "" {
		return k.dummy()
	}
	return key
}

// parseStoredInt parses one numeric hash field and maps corruption to ErrStoreUnavailable.
// | parseStoredInt 解析单个数字哈希字段，并把损坏映射为 ErrStoreUnavailable。
func parseStoredInt(value string) (int64, error) {
	if value == "" {
		return 0, nil
	}
	number, err := strconv.ParseInt(value, 10, 64)
	if err != nil {
		return 0, errs.Detail(ErrStoreUnavailable, "stored record deadline is corrupt | 存储的记录期限损坏")
	}
	return number, nil
}
