package redis

import "strconv"

// Hash tags keep every key touched by one script in the same Redis Cluster slot.
// | 哈希标签让单个脚本访问的所有键落在同一个 Redis Cluster 槽位。
const (
	usersTag       = "{authstore:users}"
	sessionsTag    = "{authstore:sessions}"
	identitiesTag  = "{authstore:identities}"
	credentialsTag = "{authstore:credentials}"
	auditsTag      = "{authstore:audits}"
	tokensTag      = "{authstore:tokens}"
)

// keys builds every key below one configurable namespace. | keys 在一个可配置命名空间下构造所有键。
type keys struct {
	prefix string
}

// newKeys returns a key builder for prefix. | newKeys 返回 prefix 的键构造器。
func newKeys(prefix string) keys {
	return keys{prefix: prefix}
}

// usersAll is the set holding every user ID. | usersAll 是保存全部用户 ID 的集合。
func (k keys) usersAll() string { return k.prefix + usersTag + ":all" }

// user is the hash holding one user record. | user 是保存单个用户记录的哈希。
func (k keys) user(id string) string { return k.prefix + usersTag + ":user:" + id }

// userIndexUsername is the unique normalized username index. | userIndexUsername 是规范化的用户名唯一索引。
func (k keys) userIndexUsername(name string) string {
	return k.prefix + usersTag + ":idx:username:" + name
}

// userIndexEmail is the unique normalized email index. | userIndexEmail 是规范化的邮箱唯一索引。
func (k keys) userIndexEmail(email string) string {
	return k.prefix + usersTag + ":idx:email:" + email
}

// userIndexPhone is the unique normalized phone index. | userIndexPhone 是规范化的手机号唯一索引。
func (k keys) userIndexPhone(phone string) string {
	return k.prefix + usersTag + ":idx:phone:" + phone
}

// sessionsAll is the set holding every session ID. | sessionsAll 是保存全部会话 ID 的集合。
func (k keys) sessionsAll() string { return k.prefix + sessionsTag + ":all" }

// session is the hash holding one session record. | session 是保存单个会话记录的哈希。
func (k keys) session(id string) string { return k.prefix + sessionsTag + ":session:" + id }

// sessionsByUser is the set of session IDs owned by one user. | sessionsByUser 是单个用户拥有的会话 ID 集合。
func (k keys) sessionsByUser(userID string) string {
	return k.prefix + sessionsTag + ":user:" + userID
}

// identity is the hash holding one provider/subject link. | identity 是保存单个 provider/subject 关联的哈希。
//
// The provider length makes the key injective for arbitrary provider and subject bytes.
// | provider 的长度前缀使键对任意 provider 与 subject 字节都无歧义。
func (k keys) identity(provider, subject string) string {
	return k.prefix + identitiesTag + ":identity:" + strconv.Itoa(len(provider)) + ":" + provider + subject
}

// identitiesByUser is the set of identity keys owned by one user. | identitiesByUser 是单个用户拥有的身份键集合。
func (k keys) identitiesByUser(userID string) string {
	return k.prefix + identitiesTag + ":user:" + userID
}

// credential is the hash holding one credential record. | credential 是保存单个凭据记录的哈希。
func (k keys) credential(id string) string {
	return k.prefix + credentialsTag + ":credential:" + id
}

// credentialsByUser is the set of credential IDs owned by one user. | credentialsByUser 是单个用户拥有的凭据 ID 集合。
func (k keys) credentialsByUser(userID string) string {
	return k.prefix + credentialsTag + ":user:" + userID
}

// auditSeq is the append-only sequence counter. | auditSeq 是只追加的序号计数器。
func (k keys) auditSeq() string { return k.prefix + auditsTag + ":seq" }

// auditEvents is the hash from sequence number to event JSON. | auditEvents 是从序号到事件 JSON 的哈希。
func (k keys) auditEvents() string { return k.prefix + auditsTag + ":events" }

// auditIndex is the sorted set of sequence numbers scored by event time. | auditIndex 是按事件时间评分的序号有序集合。
func (k keys) auditIndex() string { return k.prefix + auditsTag + ":index" }

// token is the hash holding one one-time token. | token 是保存单个一次性令牌的哈希。
func (k keys) token(purpose, hash string) string {
	return k.prefix + tokensTag + ":token:" + strconv.Itoa(len(purpose)) + ":" + purpose + hash
}

// tokensByUser is the set of token keys owned by one user and purpose.
// | tokensByUser 是单个用户与用途拥有的令牌键集合。
func (k keys) tokensByUser(userID, purpose string) string {
	return k.prefix + tokensTag + ":user:" + strconv.Itoa(len(purpose)) + ":" + purpose + userID
}
