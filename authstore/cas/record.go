package cas

import (
	"strconv"
	"time"

	authcas "github.com/shibingli/ydx/auth/protocol/cas"
	"github.com/shibingli/ydx/errs"
	ydxjson "github.com/shibingli/ydx/json"
)

// Hash field names shared by the ticket and session scripts. | 票据与会话脚本共享的哈希字段名。
const (
	fieldData         = "data"
	fieldType         = "typ"
	fieldServiceKey   = "svcKey"
	fieldRootKey      = "rootKey"
	fieldUserKey      = "userKey"
	fieldTGTKey       = "tgtKey"
	fieldUserKeyOne   = "uk1"
	fieldUserKeyTwo   = "uk2"
	fieldExpireSec    = "expireSec"
	fieldExpireNsec   = "expireNsec"
	fieldHasExpiry    = "hasExpiry"
	fieldConsumed     = "consumed"
	fieldConsumedSec  = "consumedSec"
	fieldConsumedNsec = "consumedNsec"
)

// encodeTicket returns the JSON form of a normalized deep copy of ticket. | encodeTicket 返回 ticket
// 规范化深拷贝的 JSON 形式。
func encodeTicket(ticket *authcas.Ticket) ([]byte, error) {
	stored := ticket.Clone()
	normalizeTicketTimes(stored)
	data, err := ydxjson.Marshal(stored)
	if err != nil {
		return nil, errs.Detail(authcas.ErrInvalidRequest, "ticket cannot be encoded | 票据无法编码")
	}
	return data, nil
}

// decodeTicket parses one stored ticket. | decodeTicket 解析一张已存票据。
func decodeTicket(data string) (*authcas.Ticket, error) {
	if data == "" {
		return nil, errs.Detail(ErrStoreUnavailable, "stored ticket is empty | 存储的票据为空")
	}
	var ticket authcas.Ticket
	if err := ydxjson.Unmarshal([]byte(data), &ticket); err != nil {
		return nil, errs.Detail(ErrStoreUnavailable, "stored ticket is corrupt | 存储的票据数据损坏")
	}
	normalizeTicketTimes(&ticket)
	return &ticket, nil
}

// encodeSession returns the JSON form of a normalized deep copy of session. | encodeSession 返回
// session 规范化深拷贝的 JSON 形式。
func encodeSession(session *authcas.ServiceSession) ([]byte, error) {
	stored := session.Clone()
	normalizeSessionTimes(stored)
	data, err := ydxjson.Marshal(stored)
	if err != nil {
		return nil, errs.Detail(authcas.ErrInvalidRequest, "service session cannot be encoded | 服务会话无法编码")
	}
	return data, nil
}

// decodeSession parses one stored service session. | decodeSession 解析一个已存服务会话。
func decodeSession(data string) (*authcas.ServiceSession, error) {
	if data == "" {
		return nil, errs.Detail(ErrStoreUnavailable, "stored service session is empty | 存储的服务会话为空")
	}
	var session authcas.ServiceSession
	if err := ydxjson.Unmarshal([]byte(data), &session); err != nil {
		return nil, errs.Detail(ErrStoreUnavailable, "stored service session is corrupt | 存储的服务会话数据损坏")
	}
	normalizeSessionTimes(&session)
	return &session, nil
}

// normalizeTicketTimes converts every non-zero ticket and principal time to UTC.
// | normalizeTicketTimes 把票据与主体的每个非零时间转换为 UTC。
func normalizeTicketTimes(ticket *authcas.Ticket) {
	if ticket == nil {
		return
	}
	ticket.IssuedAt = utcTime(ticket.IssuedAt)
	ticket.ExpiresAt = utcTime(ticket.ExpiresAt)
	ticket.ConsumedAt = utcTime(ticket.ConsumedAt)
	if ticket.Principal == nil {
		return
	}
	ticket.Principal.AuthTime = utcTime(ticket.Principal.AuthTime)
	ticket.Principal.ExpiresAt = utcTime(ticket.Principal.ExpiresAt)
	ticket.Principal.IssuedAt = utcTime(ticket.Principal.IssuedAt)
}

// normalizeSessionTimes converts every non-zero session time to UTC.
// | normalizeSessionTimes 把会话的每个非零时间转换为 UTC。
func normalizeSessionTimes(session *authcas.ServiceSession) {
	if session == nil {
		return
	}
	session.IssuedAt = utcTime(session.IssuedAt)
	session.ExpiresAt = utcTime(session.ExpiresAt)
}

// utcTime normalizes non-zero times to UTC and keeps the zero value canonical.
// | utcTime 把非零时间规范化为 UTC，并保持零值的规范形态。
func utcTime(t time.Time) time.Time {
	if t.IsZero() {
		return time.Time{}
	}
	return t.UTC()
}

// ticketExpiry encodes a ticket deadline. A zero deadline is treated as already expired, matching
// the memory store, so it is scored at zero and selected by the next expiry sweep.
// | ticketExpiry 编码票据期限。零期限与内存存储一致地视为已经过期，因此评分为零并在下一次清理时被选中。
func ticketExpiry(t time.Time) (sec, nsec, score int64) {
	if t.IsZero() {
		return 0, 0, 0
	}
	t = t.UTC()
	return t.Unix(), int64(t.Nanosecond()), t.Unix()
}

// sessionExpiry encodes a service session deadline. A zero deadline means the session never expires,
// so hasExpiry is false and the expiry sorted set must not contain the session.
// | sessionExpiry 编码服务会话期限。零期限表示会话永不过期，因此 hasExpiry 为 false，过期有序集合
// 不得包含该会话。
func sessionExpiry(t time.Time) (hasExpiry bool, sec, nsec, score int64) {
	if t.IsZero() {
		return false, 0, 0, 0
	}
	t = t.UTC()
	return true, t.Unix(), int64(t.Nanosecond()), t.Unix()
}

// consumedFields encodes an optional consumption time. | consumedFields 编码可选的消费时间。
func consumedFields(t time.Time) (sec, nsec int64) {
	if t.IsZero() {
		return 0, 0
	}
	t = t.UTC()
	return t.Unix(), int64(t.Nanosecond())
}

// clockFields encodes an instant as whole seconds and nanoseconds. The split keeps exact nanosecond
// comparisons possible inside Redis Lua, whose numbers cannot represent a Unix nanosecond timestamp
// without precision loss. | clockFields 把时刻编码为整秒与纳秒。拆分使 Redis Lua 内可以进行精确纳秒
// 比较，因为 Lua 数字无法无损表示 Unix 纳秒时间戳。
func clockFields(t time.Time) (sec, nsec string) {
	t = t.UTC()
	return strconv.FormatInt(t.Unix(), 10), strconv.FormatInt(int64(t.Nanosecond()), 10)
}

// intField renders an integer hash or argument value. | intField 渲染整数字段或参数值。
func intField(value int64) string { return strconv.FormatInt(value, 10) }
