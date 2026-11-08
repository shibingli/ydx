package scim

import "strconv"

// clusterHashTag is the single Redis Cluster hash tag used by every key, so every key touched by
// one script is routed to the same slot. | clusterHashTag 是所有键共用的唯一 Redis Cluster 哈希标签，
// 因此单个脚本访问的每个键都会路由到同一槽位。
const clusterHashTag = "{authstore:scim}"

// keys assembles every key under one configurable prefix. | keys 在同一个可配置前缀下组装每个键。
type keys struct {
	// prefix is the caller supplied namespace. | prefix 是调用方提供的命名空间。
	prefix string
}

// newKeys returns a key assembler for prefix. | newKeys 返回用于 prefix 的键组装器。
func newKeys(prefix string) keys {
	return keys{prefix: prefix}
}

// keySegment renders one length-prefixed key segment, which keeps values that contain ':' or any
// other byte unambiguous. | keySegment 渲染单个长度前缀键段，使包含 ':' 或任意其它字节的值无歧义。
func keySegment(value string) string {
	return strconv.Itoa(len(value)) + ":" + value
}

// tagged joins the prefix, the cluster hash tag and one suffix. | tagged 拼接前缀、集群哈希标签与单个后缀。
func (k keys) tagged(suffix string) string {
	return k.prefix + clusterHashTag + suffix
}

// usersOrder is the sorted set of user IDs scored by creation sequence.
// | usersOrder 是按创建序号计分的用户 ID 有序集合。
func (k keys) usersOrder() string { return k.tagged(":users:order") }

// usersSequence is the user creation sequence counter. | usersSequence 是用户创建序号计数器。
func (k keys) usersSequence() string { return k.tagged(":users:seq") }

// user is the hash holding one user record. | user 保存单条用户记录的哈希。
func (k keys) user(id string) string { return k.tagged(":user:" + keySegment(id)) }

// userNameIndex is the unique user name index. | userNameIndex 是唯一用户名索引。
func (k keys) userNameIndex(name string) string {
	return k.tagged(":uidx:name:" + keySegment(name))
}

// userExternalIndex is the non-unique externalId index for users.
// | userExternalIndex 是用户 externalId 的非唯一索引。
func (k keys) userExternalIndex(value string) string {
	return k.tagged(":uidx:external:" + keySegment(value))
}

// userDisplayIndex is the non-unique displayName index for users.
// | userDisplayIndex 是用户 displayName 的非唯一索引。
func (k keys) userDisplayIndex(value string) string {
	return k.tagged(":uidx:display:" + keySegment(value))
}

// groupsOrder is the sorted set of group IDs scored by creation sequence.
// | groupsOrder 是按创建序号计分的组 ID 有序集合。
func (k keys) groupsOrder() string { return k.tagged(":groups:order") }

// groupsSequence is the group creation sequence counter. | groupsSequence 是组创建序号计数器。
func (k keys) groupsSequence() string { return k.tagged(":groups:seq") }

// group is the hash holding one group record. | group 保存单条组记录的哈希。
func (k keys) group(id string) string { return k.tagged(":group:" + keySegment(id)) }

// groupDisplayIndex is the unique group display name index. | groupDisplayIndex 是唯一组显示名索引。
func (k keys) groupDisplayIndex(name string) string {
	return k.tagged(":gidx:display:" + keySegment(name))
}

// groupExternalIndex is the non-unique externalId index for groups.
// | groupExternalIndex 是组 externalId 的非唯一索引。
func (k keys) groupExternalIndex(value string) string {
	return k.tagged(":gidx:external:" + keySegment(value))
}

// revision is the Redis-global entity tag revision counter.
// | revision 是 Redis 全局实体标签修订计数器。
func (k keys) revision() string { return k.tagged(":revision") }
