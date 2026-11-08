package kms

import "strconv"

// The hash field names shared by the key scripts and record decoders. | 键脚本与记录解码器共享的
// 哈希字段名。
const (
	// fieldData holds the encoded key record. | fieldData 保存编码后的键记录。
	fieldData = "data"
	// fieldRevision holds the optimistic-concurrency revision as decimal text. | fieldRevision
	// 以十进制文本保存乐观并发修订号。
	fieldRevision = "revision"
	// fieldAlias holds the primary alias carried by the key. | fieldAlias 保存键携带的主别名。
	fieldAlias = "alias"
)

// redisTag is the hash tag shared by every key of the store. It keeps all keys touched by one Lua
// script inside one Redis Cluster slot. | redisTag 是存储全部键共享的哈希标签。它让单个 Lua
// 脚本访问的所有键落在同一个 Redis Cluster 槽位。
const redisTag = "{authstore:kms}"

// segment length-prefixes an arbitrary value so concatenated segments stay unambiguous.
// | segment 为任意值添加长度前缀，使拼接后的段保持无歧义。
func segment(value string) string {
	return strconv.Itoa(len(value)) + ":" + value
}

// keys builds every key below one configurable namespace. | keys 在一个可配置命名空间下构造所有键。
type keys struct {
	// prefix is the caller-configured namespace. | prefix 是调用方配置的命名空间。
	prefix string
}

// newKeys returns a key builder for prefix. | newKeys 返回 prefix 的键构造器。
func newKeys(prefix string) keys {
	return keys{prefix: prefix}
}

// namespaced returns one key carrying the shared cluster hash tag. | namespaced 返回携带共享集群
// 哈希标签的单个键。
func (k keys) namespaced(suffix string) string {
	return k.prefix + redisTag + ":" + suffix
}

// key is the hash holding one key record. | key 是保存单个密钥记录的哈希。
func (k keys) key(id string) string {
	return k.namespaced("key:" + segment(id))
}

// versions is the hash holding one version record per version number. | versions 是保存密钥各版本
// 记录的哈希，字段名为版本号。
func (k keys) versions(id string) string {
	return k.namespaced("versions:" + segment(id))
}

// aliases is the set of every alias bound to one key. | aliases 是绑定到单个密钥的全部别名集合。
func (k keys) aliases(id string) string {
	return k.namespaced("aliases:" + segment(id))
}

// alias is the string mapping one alias to a key identifier. | alias 是把单个别名映射到密钥标识的字符串键。
func (k keys) alias(alias string) string {
	return k.namespaced("alias:" + segment(alias))
}

// aliasPrefix is the literal prefix of every alias key, used by scripts that construct alias keys
// from set members. | aliasPrefix 是全部别名键的字面前缀，供从集合成员动态构造别名键的脚本使用。
func (k keys) aliasPrefix() string {
	return k.namespaced("alias:")
}

// keysAll is the sorted set of every key identifier scored by creation time.
// | keysAll 是全部密钥标识按创建时间评分的有序集合。
func (k keys) keysAll() string {
	return k.namespaced("keys")
}

// dummy is an unused key with the shared hash tag. Scripts receive it in place of an ignored key
// slot so no KEYS entry is ever empty. | dummy 是携带共享哈希标签的未使用键。脚本在忽略的键槽
// 位置接收它，因此 KEYS 中不会出现空字符串。
func (k keys) dummy() string {
	return k.namespaced("nil")
}

// auditSeq is the append-only audit sequence counter. | auditSeq 是只追加的审计序号计数器。
func (k keys) auditSeq() string {
	return k.namespaced("audit:seq")
}

// auditEvents is the hash from sequence number to event JSON. | auditEvents 是从序号到事件 JSON 的哈希。
func (k keys) auditEvents() string {
	return k.namespaced("audit:events")
}

// auditIndex is the sorted set of sequence numbers scored by event time.
// | auditIndex 是按事件时间评分的序号有序集合。
func (k keys) auditIndex() string {
	return k.namespaced("audit:index")
}
