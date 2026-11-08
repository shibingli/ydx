package saml

import "strconv"

// Hash tags keep every key touched by one script in the same Redis Cluster slot.
// | 哈希标签让单个脚本访问的所有键落在同一个 Redis Cluster 槽位。
const (
	requestsTag   = "{authstore:saml:requests}"
	assertionsTag = "{authstore:saml:assertions}"
	sessionsTag   = "{authstore:saml:sessions}"
	artifactsTag  = "{authstore:saml:artifacts}"
)

// keys builds every key below one configurable namespace. | keys 在一个可配置命名空间下构造所有键。
type keys struct {
	// prefix is the caller namespace placed before every hash tag. | prefix 是位于每个哈希标签之前
	// 的调用方命名空间。
	prefix string
}

// newKeys returns a key builder for prefix. | newKeys 返回 prefix 的键构造器。
func newKeys(prefix string) keys {
	return keys{prefix: prefix}
}

// segment length-prefixes a key segment so arbitrary bytes stay unambiguous.
// | segment 为键段添加长度前缀，使任意字节都无歧义。
func segment(value string) string {
	return strconv.Itoa(len(value)) + ":" + value
}

// request is the hash holding one outstanding request. | request 是保存单个未完成请求的哈希。
func (k keys) request(id string) string {
	return k.prefix + requestsTag + ":request:" + segment(id)
}

// requestsExpiry indexes request keys by expiry second. | requestsExpiry 按到期秒索引请求键。
func (k keys) requestsExpiry() string { return k.prefix + requestsTag + ":expiry" }

// assertion is the hash holding one assertion replay record. | assertion 是保存单条断言重放记录的哈希。
func (k keys) assertion(id string) string {
	return k.prefix + assertionsTag + ":assertion:" + segment(id)
}

// assertionsExpiry indexes assertion keys by expiry second. | assertionsExpiry 按到期秒索引断言键。
func (k keys) assertionsExpiry() string { return k.prefix + assertionsTag + ":expiry" }

// session is the hash holding one IdP session. | session 是保存单个 IdP 会话的哈希。
func (k keys) session(id string) string {
	return k.prefix + sessionsTag + ":session:" + segment(id)
}

// sessionsBySubject is the set of full session keys owned by one NameID.
// | sessionsBySubject 是单个 NameID 拥有的完整会话键集合。
func (k keys) sessionsBySubject(nameID string) string {
	return k.prefix + sessionsTag + ":subject:" + segment(nameID)
}

// sessionSubjectPrefix is the prefix from which Lua cleanup scripts build a subject set key.
// | sessionSubjectPrefix 是 Lua 清理脚本构造主体集合键所用的前缀。
func (k keys) sessionSubjectPrefix() string { return k.prefix + sessionsTag + ":subject:" }

// sessionsExpiry indexes session keys by expiry second. | sessionsExpiry 按到期秒索引会话键。
func (k keys) sessionsExpiry() string { return k.prefix + sessionsTag + ":expiry" }

// artifact is the hash holding one HTTP-Artifact record. | artifact 是保存单条 HTTP-Artifact 记录的哈希。
func (k keys) artifact(storeKey string) string {
	return k.prefix + artifactsTag + ":artifact:" + segment(storeKey)
}

// artifactsExpiry indexes artifact keys by expiry second. | artifactsExpiry 按到期秒索引工件键。
func (k keys) artifactsExpiry() string { return k.prefix + artifactsTag + ":expiry" }
