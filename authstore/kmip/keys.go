package kmip

import "strconv"

// redisTag is the hash tag shared by every key of the store. It keeps all keys touched by one Lua
// script inside one Redis Cluster slot. | redisTag 是存储全部键共享的哈希标签。它让单个 Lua
// 脚本访问的所有键落在同一个 Redis Cluster 槽位。
const redisTag = "{authstore:kmip}"

// keys builds every key below one configurable namespace. | keys 在一个可配置命名空间下构造所有键。
type keys struct {
	// prefix is the caller-visible namespace. | prefix 是调用方可见的命名空间。
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

// all returns the set holding the full key of every managed object.
// | all 返回保存每个受管对象完整键的集合。
func (k keys) all() string { return k.namespaced("all") }

// object returns the hash holding one managed object record.
// | object 返回保存单个受管对象记录的哈希。
func (k keys) object(uniqueIdentifier string) string {
	return k.namespaced("object:" + segment(uniqueIdentifier))
}
