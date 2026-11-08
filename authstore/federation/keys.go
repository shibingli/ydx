package federation

import "strconv"

// redisTag is the hash tag shared by every key of the store. It keeps the key touched by a Lua
// script in one Redis Cluster slot. | redisTag 是存储全部键共享的哈希标签。它让 Lua 脚本访问的
// 键落在同一个 Redis Cluster 槽位。
const redisTag = "{authstore:federation}"

// keys builds every key below one configurable namespace. | keys 在一个可配置命名空间下构造所有键。
type keys struct {
	// prefix is the caller-configured namespace. | prefix 是调用方配置的命名空间。
	prefix string
}

// newKeys returns a key builder for prefix. | newKeys 返回 prefix 的键构造器。
func newKeys(prefix string) keys {
	return keys{prefix: prefix}
}

// segment encodes one arbitrary string as a length-prefixed key segment. The length prefix makes
// concatenations injective even when values contain the separator byte. | segment 把任意字符串编码为
// 带长度前缀的键段。长度前缀使拼接即使值包含分隔字节也无歧义。
func segment(value string) string {
	return strconv.Itoa(len(value)) + ":" + value
}

// state is the hash holding one authorization state record. | state 是保存单个授权 state 记录的哈希。
func (k keys) state(value string) string {
	return k.prefix + redisTag + ":state:" + segment(value)
}
