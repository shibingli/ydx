package kmip

import goredis "github.com/redis/go-redis/v9"

// The scripts below are the atomicity boundary of the store. Every script touches only keys that
// share the "{authstore:kmip}" hash tag, so Redis Cluster routes them to a single slot. Each
// script lists its KEYS and ARGV contract in comments. | 下面的脚本是存储的原子性边界。每个脚本只
// 访问共享 "{authstore:kmip}" 哈希标签的键，因此 Redis Cluster 会把它们路由到单一槽位。每个
// 脚本在注释中列出 KEYS 与 ARGV 约定。

// scriptCreate atomically stores one new record and its index membership. The uniqueness check
// and both writes execute as one script, so two instances cannot both create the same identifier.
// KEYS: 1 object hash, 2 set of all object keys.
// ARGV: 1 record JSON, 2 fresh revision token.
// Returns 1 when the identifier already exists and 0 on success.
// | scriptCreate 原子保存一条新记录及其索引成员关系。唯一性检查与两次写入在同一脚本中执行，
// 因此两个实例不可能同时创建同一标识符。
var scriptCreate = goredis.NewScript(`
if redis.call('EXISTS', KEYS[1]) == 1 then return 1 end
redis.call('HSET', KEYS[1], 'data', ARGV[1], 'rev', ARGV[2])
redis.call('SADD', KEYS[2], KEYS[1])
return 0
`)

// scriptUpdate atomically replaces one record when its revision still matches the value the caller
// observed. A concurrent writer changes the revision, so the caller retries instead of writing
// over a state it has never seen. The replacement token is fresh, so an identifier that was
// deleted and created again can never match a stale token.
// KEYS: 1 object hash.
// ARGV: 1 record JSON, 2 expected revision, 3 fresh revision token.
// Returns 1 when the object is absent, 2 on a revision mismatch and 0 on success.
// | scriptUpdate 在修订号仍与调用方观测值一致时原子替换一条记录。并发写入会改变修订号，调用方
// 因而重试，而不会覆盖它从未见过的状态。替换令牌是全新的，因此被删除后重新创建的标识符绝不会匹配
// 陈旧令牌。
var scriptUpdate = goredis.NewScript(`
if redis.call('EXISTS', KEYS[1]) == 0 then return 1 end
if (redis.call('HGET', KEYS[1], 'rev') or '') ~= ARGV[2] then return 2 end
redis.call('HSET', KEYS[1], 'data', ARGV[1], 'rev', ARGV[3])
return 0
`)

// scriptDelete atomically removes one record and its index membership.
// KEYS: 1 object hash, 2 set of all object keys.
// Returns 1 when the object is absent and 0 on success.
// | scriptDelete 原子删除一条记录及其索引成员关系。
var scriptDelete = goredis.NewScript(`
if redis.call('EXISTS', KEYS[1]) == 0 then return 1 end
redis.call('DEL', KEYS[1])
redis.call('SREM', KEYS[2], KEYS[1])
return 0
`)

// scriptReset removes every object key passed by the caller and then the index set. Reset passes
// the current members as explicit KEYS, because Redis Cluster scripts may not compute or discover
// key names on their own.
// KEYS: 1 set of all object keys, 2..N object hashes to remove.
// Returns the number of object hashes actually removed.
// | scriptReset 删除调用方传入的每个对象键，然后删除索引集合。Reset 把当前成员作为显式 KEYS
// 传入，因为 Redis Cluster 脚本不得自行计算或发现键名。
var scriptReset = goredis.NewScript(`
local removed = 0
for i = 2, #KEYS do
  removed = removed + redis.call('DEL', KEYS[i])
end
redis.call('DEL', KEYS[1])
return removed
`)
