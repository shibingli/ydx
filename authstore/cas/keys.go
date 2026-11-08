package cas

import (
	"strconv"

	authcas "github.com/shibingli/ydx/auth/protocol/cas"
)

// keys builds every key below one configurable namespace. | keys 在一个可配置命名空间下构造所有键。
type keys struct {
	prefix string
}

// newKeys returns a key builder for prefix. | newKeys 返回 prefix 的键构造器。
func newKeys(prefix string) keys {
	return keys{prefix: prefix}
}

// namespaced returns one key carrying the shared cluster hash tag.
// | namespaced 返回携带共享集群哈希标签的单个键。
func (k keys) namespaced(suffix string) string {
	return k.prefix + redisTag + ":" + suffix
}

// segment length-prefixes an arbitrary value so concatenated segments stay unambiguous.
// | segment 为任意值添加长度前缀，使拼接后的段保持无歧义。
func segment(value string) string {
	return strconv.Itoa(len(value)) + ":" + value
}

// dummy is an unused key with the shared hash tag. Scripts receive it in place of an ignored key slot
// so no KEYS entry is ever empty. | dummy 是携带共享哈希标签的未使用键。脚本在忽略的键槽位置接收它，
// 因此 KEYS 中不会出现空字符串。
func (k keys) dummy() string { return k.namespaced("nil") }

// ticket is the hash holding one ticket record. | ticket 是保存单张票据记录的哈希。
func (k keys) ticket(id string) string { return k.namespaced("ticket:" + segment(id)) }

// ticketsAll is the set holding every ticket key. | ticketsAll 是保存全部票据键的集合。
func (k keys) ticketsAll() string { return k.namespaced("tickets") }

// ticketsByType is the set of ticket keys of one ticket type. | ticketsByType 是单一票据类型的票据键集合。
func (k keys) ticketsByType(typ authcas.TicketType) string {
	return k.namespaced("tickets:type:" + string(typ))
}

// ticketsByService is the set of ticket keys bound to one service. | ticketsByService 是绑定到单个服务的票据键集合。
func (k keys) ticketsByService(service string) string {
	return k.namespaced("tickets:idx:service:" + segment(service))
}

// ticketsByRoot is the set of ticket keys rooted at one TGT. | ticketsByRoot 是以单个 TGT 为根的票据键集合。
func (k keys) ticketsByRoot(tgtID string) string {
	return k.namespaced("tickets:idx:root:" + segment(tgtID))
}

// ticketsByUser is the set of ticket keys owned by one user. | ticketsByUser 是单个用户拥有的票据键集合。
func (k keys) ticketsByUser(userID string) string {
	return k.namespaced("tickets:idx:user:" + segment(userID))
}

// ticketsExpiry is the sorted set of ticket keys scored by deadline seconds.
// | ticketsExpiry 是按期限秒数评分的票据键有序集合。
func (k keys) ticketsExpiry() string { return k.namespaced("tickets:expiry") }

// session is the hash holding one service session record. | session 是保存单个服务会话记录的哈希。
func (k keys) session(index string) string { return k.namespaced("session:" + segment(index)) }

// sessionsAll is the set holding every session key. | sessionsAll 是保存全部会话键的集合。
func (k keys) sessionsAll() string { return k.namespaced("sessions") }

// sessionsByTGT is the set of session keys rooted at one TGT. | sessionsByTGT 是以单个 TGT 为根的会话键集合。
func (k keys) sessionsByTGT(tgtID string) string {
	return k.namespaced("sessions:idx:tgt:" + segment(tgtID))
}

// sessionsByUser is the set of session keys indexed under one user identifier.
// | sessionsByUser 是在单个用户标识下建立索引的会话键集合。
func (k keys) sessionsByUser(user string) string {
	return k.namespaced("sessions:idx:user:" + segment(user))
}

// sessionsExpiry is the sorted set of session keys scored by deadline seconds.
// | sessionsExpiry 是按期限秒数评分的会话键有序集合。
func (k keys) sessionsExpiry() string { return k.namespaced("sessions:expiry") }
