package rbac

import "strconv"

// redisTag is the hash tag shared by every key of the store. It keeps all keys touched by one Lua
// script inside one Redis Cluster slot. | redisTag 是存储全部键共享的哈希标签。它让单个 Lua 脚本
// 访问的所有键落在同一个 Redis Cluster 槽位。
const redisTag = "{authstore:rbac}"

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

// roles is the hash from role name to role JSON. | roles 是从角色名称到角色 JSON 的哈希。
func (k keys) roles() string { return k.namespaced("roles") }

// roleParents is the hash from role name to its length-prefixed parent list. It exists separately
// from the role JSON so Lua scripts can traverse inheritance without a JSON parser.
// | roleParents 是从角色名称到其长度前缀父角色列表的哈希。它与角色 JSON 分开保存，使 Lua 脚本
// 无需 JSON 解析器即可遍历继承关系。
func (k keys) roleParents() string { return k.namespaced("roles:parents") }

// assignments is the hash from assignment identifier to assignment JSON.
// | assignments 是从分配标识到分配 JSON 的哈希。
func (k keys) assignments() string { return k.namespaced("assignments") }

// assignmentExpiry is the hash from assignment identifier to its encoded deadline.
// | assignmentExpiry 是从分配标识到编码期限的哈希。
func (k keys) assignmentExpiry() string { return k.namespaced("assignments:expiry") }

// assignmentSubjects is the set holding every subject name that owns at least one assignment.
// | assignmentSubjects 是保存至少拥有一条分配的全部主体名称的集合。
func (k keys) assignmentSubjects() string { return k.namespaced("assignments:subjects") }

// assignmentSubject is the set of assignment identifiers owned by one subject.
// | assignmentSubject 是单个主体拥有的分配标识集合。
func (k keys) assignmentSubject(subject string) string {
	return k.assignmentSubjectPrefix() + segment(subject)
}

// assignmentSubjectPrefix is the static part of every per-subject assignment index key. Lua
// scripts append the length-prefixed subject themselves when cascading a role removal or a reset.
// | assignmentSubjectPrefix 是每个按主体分配索引键的静态部分。Lua 脚本在级联删除角色或重置时
// 自行追加长度前缀的主体。
func (k keys) assignmentSubjectPrefix() string {
	return k.namespaced("assignments:subject:")
}

// policies is the hash from policy identifier to policy JSON.
// | policies 是从策略标识到策略 JSON 的哈希。
func (k keys) policies() string { return k.namespaced("policies") }
