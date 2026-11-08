package scim

import goredis "github.com/redis/go-redis/v9"

// The scripts below are the atomicity boundary of the Redis-backed SCIM store. Every script
// touches only keys sharing the {authstore:scim} hash tag, so Redis Cluster routes all of them to
// one slot. Each script returns an array whose first element is a result code; 0 means success and
// the optional second element is the new global revision. | 下面的脚本是 Redis SCIM 存储的原子性边界。
// 每个脚本只访问共享 {authstore:scim} 哈希标签的键，因此 Redis Cluster 会把它们全部路由到同一槽位。
// 每个脚本返回数组，首元素是结果码；0 表示成功，可选的第二个元素是新的全局修订号。

// scriptUserCreate atomically creates one user, its creation order entry and its three indexes.
// KEYS: 1 order zset, 2 user hash, 3 userName index, 4 externalId zset, 5 displayName zset,
// 6 creation sequence, 7 global revision.
// ARGV: 1 data, 2 version base, 3 id, 4 userName, 5 externalId, 6 displayName, 7/8/9 presence
// flags for userName/externalId/displayName.
// Returns {1,...} for a duplicate ID, {2,...} for a duplicate userName and {0,rev} on success.
// | scriptUserCreate 原子创建单个用户、其创建顺序条目与三个索引。
var scriptUserCreate = goredis.NewScript(`
if redis.call('EXISTS', KEYS[2]) == 1 then return {1, 0} end
if ARGV[7] == '1' and redis.call('EXISTS', KEYS[3]) == 1 then return {2, 0} end
local seq = redis.call('INCR', KEYS[6])
local rev = redis.call('INCR', KEYS[7])
local tag = ARGV[2] .. '-' .. tostring(rev)
if ARGV[7] == '1' then redis.call('SET', KEYS[3], ARGV[3]) end
if ARGV[8] == '1' then redis.call('ZADD', KEYS[4], seq, ARGV[3]) end
if ARGV[9] == '1' then redis.call('ZADD', KEYS[5], seq, ARGV[3]) end
redis.call('ZADD', KEYS[1], seq, ARGV[3])
redis.call('HSET', KEYS[2], 'data', ARGV[1], 'version', 'W/"' .. tag .. '"', 'versionTag', tag,
  'username', ARGV[4], 'external', ARGV[5], 'display', ARGV[6], 'seq', seq)
return {0, rev}
`)

// scriptUserReplace atomically replaces one user and reconciles its three indexes. The stored
// version tag read before the call is the compare-and-set guard; an expected tag adds the
// conditional-replace precondition. | scriptUserReplace 原子替换单个用户并协调其三个索引。调用前读取
// 的存储版本标签是比较并交换守卫；期望标签额外提供条件替换前置条件。
// KEYS: 1 user hash, 2 global revision, 3/4 new/old userName index, 5/6 new/old externalId zset,
// 7/8 new/old displayName zset.
// ARGV: 1 expectedTag, 2 casTag, 3 data, 4 version base, 5 id, 6 userName, 7 externalId,
// 8 displayName, 9/10/11 changed flags, 12/13/14 old present flags.
// Returns 1 when absent, 2 on a compare-and-set mismatch, 3 on a failed precondition,
// 4 on a duplicate userName and {0,rev} on success.
var scriptUserReplace = goredis.NewScript(`
if redis.call('EXISTS', KEYS[1]) == 0 then return {1, 0} end
local tag = redis.call('HGET', KEYS[1], 'versionTag') or ''
if tag ~= ARGV[2] then return {2, 0} end
if ARGV[1] ~= '' and ARGV[1] ~= tag then return {3, 0} end
if ARGV[9] == '1' then
  local owner = redis.call('GET', KEYS[3])
  if owner and owner ~= ARGV[5] then return {4, 0} end
end
local seq = redis.call('HGET', KEYS[1], 'seq') or '0'
local rev = redis.call('INCR', KEYS[2])
local newtag = ARGV[4] .. '-' .. tostring(rev)
if ARGV[9] == '1' then
  if ARGV[12] == '1' then
    if redis.call('GET', KEYS[4]) == ARGV[5] then redis.call('DEL', KEYS[4]) end
  end
  redis.call('SET', KEYS[3], ARGV[5])
end
if ARGV[10] == '1' then
  if ARGV[13] == '1' then redis.call('ZREM', KEYS[6], ARGV[5]) end
  if ARGV[7] ~= '' then redis.call('ZADD', KEYS[5], seq, ARGV[5]) end
end
if ARGV[11] == '1' then
  if ARGV[14] == '1' then redis.call('ZREM', KEYS[8], ARGV[5]) end
  if ARGV[8] ~= '' then redis.call('ZADD', KEYS[7], seq, ARGV[5]) end
end
redis.call('HSET', KEYS[1], 'data', ARGV[3], 'version', 'W/"' .. newtag .. '"', 'versionTag', newtag,
  'username', ARGV[6], 'external', ARGV[7], 'display', ARGV[8])
return {0, rev}
`)

// scriptUserDelete atomically deletes one user, its order entry and its three indexes.
// KEYS: 1 user hash, 2 order zset, 3 userName index, 4 externalId zset, 5 displayName zset.
// ARGV: 1 id, 2 casTag, 3/4/5 present flags.
// Returns 1 when absent, 2 on a compare-and-set mismatch and {0,0} on success.
// | scriptUserDelete 原子删除单个用户、其顺序条目与三个索引。
var scriptUserDelete = goredis.NewScript(`
if redis.call('EXISTS', KEYS[1]) == 0 then return {1, 0} end
if (redis.call('HGET', KEYS[1], 'versionTag') or '') ~= ARGV[2] then return {2, 0} end
if ARGV[3] == '1' then
  if redis.call('GET', KEYS[3]) == ARGV[1] then redis.call('DEL', KEYS[3]) end
end
if ARGV[4] == '1' then redis.call('ZREM', KEYS[4], ARGV[1]) end
if ARGV[5] == '1' then redis.call('ZREM', KEYS[5], ARGV[1]) end
redis.call('DEL', KEYS[1])
redis.call('ZREM', KEYS[2], ARGV[1])
return {0, 0}
`)

// scriptGroupCreate atomically creates one group, its creation order entry and its two indexes.
// KEYS: 1 order zset, 2 group hash, 3 displayName index, 4 externalId zset, 5 creation sequence,
// 6 global revision.
// ARGV: 1 data, 2 version base, 3 id, 4 displayName, 5 externalId, 6/7 present flags.
// Returns {1,...} for a duplicate ID, {2,...} for a duplicate displayName and {0,rev} on success.
// | scriptGroupCreate 原子创建单个组、其创建顺序条目与两个索引。
var scriptGroupCreate = goredis.NewScript(`
if redis.call('EXISTS', KEYS[2]) == 1 then return {1, 0} end
if ARGV[6] == '1' and redis.call('EXISTS', KEYS[3]) == 1 then return {2, 0} end
local seq = redis.call('INCR', KEYS[5])
local rev = redis.call('INCR', KEYS[6])
local tag = ARGV[2] .. '-' .. tostring(rev)
if ARGV[6] == '1' then redis.call('SET', KEYS[3], ARGV[3]) end
if ARGV[7] == '1' then redis.call('ZADD', KEYS[4], seq, ARGV[3]) end
redis.call('ZADD', KEYS[1], seq, ARGV[3])
redis.call('HSET', KEYS[2], 'data', ARGV[1], 'version', 'W/"' .. tag .. '"', 'versionTag', tag,
  'display', ARGV[4], 'external', ARGV[5], 'seq', seq)
return {0, rev}
`)

// scriptGroupReplace atomically replaces one group and reconciles its two indexes.
// KEYS: 1 group hash, 2 global revision, 3/4 new/old displayName index, 5/6 new/old externalId zset.
// ARGV: 1 expectedTag, 2 casTag, 3 data, 4 version base, 5 id, 6 displayName, 7 externalId,
// 8/9 changed flags, 10/11 old present flags.
// Returns 1 when absent, 2 on a compare-and-set mismatch, 3 on a failed precondition,
// 4 on a duplicate displayName and {0,rev} on success.
// | scriptGroupReplace 原子替换单个组并协调其两个索引。
var scriptGroupReplace = goredis.NewScript(`
if redis.call('EXISTS', KEYS[1]) == 0 then return {1, 0} end
local tag = redis.call('HGET', KEYS[1], 'versionTag') or ''
if tag ~= ARGV[2] then return {2, 0} end
if ARGV[1] ~= '' and ARGV[1] ~= tag then return {3, 0} end
if ARGV[8] == '1' then
  local owner = redis.call('GET', KEYS[3])
  if owner and owner ~= ARGV[5] then return {4, 0} end
end
local seq = redis.call('HGET', KEYS[1], 'seq') or '0'
local rev = redis.call('INCR', KEYS[2])
local newtag = ARGV[4] .. '-' .. tostring(rev)
if ARGV[8] == '1' then
  if ARGV[10] == '1' then
    if redis.call('GET', KEYS[4]) == ARGV[5] then redis.call('DEL', KEYS[4]) end
  end
  redis.call('SET', KEYS[3], ARGV[5])
end
if ARGV[9] == '1' then
  if ARGV[11] == '1' then redis.call('ZREM', KEYS[6], ARGV[5]) end
  if ARGV[7] ~= '' then redis.call('ZADD', KEYS[5], seq, ARGV[5]) end
end
redis.call('HSET', KEYS[1], 'data', ARGV[3], 'version', 'W/"' .. newtag .. '"', 'versionTag', newtag,
  'display', ARGV[6], 'external', ARGV[7])
return {0, rev}
`)

// scriptGroupDelete atomically deletes one group, its order entry and its two indexes.
// KEYS: 1 group hash, 2 order zset, 3 displayName index, 4 externalId zset.
// ARGV: 1 id, 2 casTag, 3/4 present flags.
// Returns 1 when absent, 2 on a compare-and-set mismatch and {0,0} on success.
// | scriptGroupDelete 原子删除单个组、其顺序条目与两个索引。
var scriptGroupDelete = goredis.NewScript(`
if redis.call('EXISTS', KEYS[1]) == 0 then return {1, 0} end
if (redis.call('HGET', KEYS[1], 'versionTag') or '') ~= ARGV[2] then return {2, 0} end
if ARGV[3] == '1' then
  if redis.call('GET', KEYS[3]) == ARGV[1] then redis.call('DEL', KEYS[3]) end
end
if ARGV[4] == '1' then redis.call('ZREM', KEYS[4], ARGV[1]) end
redis.call('DEL', KEYS[1])
redis.call('ZREM', KEYS[2], ARGV[1])
return {0, 0}
`)
