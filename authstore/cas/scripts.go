package cas

import goredis "github.com/redis/go-redis/v9"

// The scripts below are the atomicity boundary of the CAS stores. Every key and every index member
// carries the same hash tag, so Redis Cluster routes the whole script to one slot. Comments in each
// script list the KEYS and ARGV contract. | 下面的脚本是 CAS 存储的原子性边界。每个键与每个索引
// 成员都携带相同的哈希标签，因此 Redis Cluster 会把整个脚本路由到单一槽位。每个脚本内的注释列出
// KEYS 与 ARGV 约定。

// scriptTicketSave atomically stores one ticket and reconciles its type, service, root and user
// indexes plus its expiry score. The previous data field acts as a compare-and-set guard.
// KEYS: 1 ticket hash, 2 all-tickets set, 3/4 new/old type set, 5/6 new/old service index,
// 7/8 new/old root index, 9/10 new/old user index, 11 expiry sorted set.
// ARGV: 1 data, 2 type, 3-10 new/old presence flags, 11/12 expiry seconds/nanoseconds,
// 13 expiry score, 14 member key, 15 expected data, 16 expected-exists flag, 17 consumed flag,
// 18/19 consumed seconds/nanoseconds.
// Returns 2 on a compare-and-set mismatch and 0 on success.
// | scriptTicketSave 原子保存一张票据，并协调其类型、服务、根与用户索引及期限评分。旧 data 字段
// 充当比较并交换守卫。比较并交换不匹配返回 2，成功返回 0。
var scriptTicketSave = goredis.NewScript(`
if ARGV[16] == '1' then
  if redis.call('EXISTS', KEYS[1]) == 0 then return 2 end
  if ARGV[15] ~= '' and (redis.call('HGET', KEYS[1], 'data') or '') ~= ARGV[15] then return 2 end
else
  if redis.call('EXISTS', KEYS[1]) == 1 then return 2 end
end
if ARGV[4] == '1' then redis.call('SREM', KEYS[4], ARGV[14]) end
if ARGV[6] == '1' then redis.call('SREM', KEYS[6], ARGV[14]) end
if ARGV[8] == '1' then redis.call('SREM', KEYS[8], ARGV[14]) end
if ARGV[10] == '1' then redis.call('SREM', KEYS[10], ARGV[14]) end
redis.call('HSET', KEYS[1], 'data', ARGV[1], 'typ', ARGV[2], 'expireSec', ARGV[11], 'expireNsec', ARGV[12], 'consumed', ARGV[17], 'consumedSec', ARGV[18], 'consumedNsec', ARGV[19])
redis.call('SADD', KEYS[2], ARGV[14])
if ARGV[3] == '1' then redis.call('SADD', KEYS[3], ARGV[14]) end
if ARGV[5] == '1' then redis.call('SADD', KEYS[5], ARGV[14]) end
if ARGV[7] == '1' then redis.call('SADD', KEYS[7], ARGV[14]) end
if ARGV[9] == '1' then redis.call('SADD', KEYS[9], ARGV[14]) end
redis.call('ZADD', KEYS[11], ARGV[13], ARGV[14])
return 0
`)

// scriptTicketConsume atomically marks one single-use ticket consumed.
// KEYS: 1 ticket hash.
// ARGV: 1 expected type (empty accepts every type), 2/3 now seconds/nanoseconds.
// Returns {'-1',”} when absent, {'-2',”} on a type mismatch, {'-3',”} when already consumed,
// {'-4',”} when expired and {'0', data} on success.
// | scriptTicketConsume 原子地把一张一次性票据标记为已消费。不存在返回 -1，类型不匹配返回 -2，
// 已消费返回 -3，已过期返回 -4，成功返回 0 与 data。
var scriptTicketConsume = goredis.NewScript(`
if redis.call('EXISTS', KEYS[1]) == 0 then return {'-1', ''} end
if ARGV[1] ~= '' and (redis.call('HGET', KEYS[1], 'typ') or '') ~= ARGV[1] then return {'-2', ''} end
if (redis.call('HGET', KEYS[1], 'consumed') or '0') == '1' then return {'-3', ''} end
local es = tonumber(redis.call('HGET', KEYS[1], 'expireSec') or '0')
local en = tonumber(redis.call('HGET', KEYS[1], 'expireNsec') or '0')
local ns = tonumber(ARGV[2])
local nn = tonumber(ARGV[3])
if es < ns or (es == ns and en <= nn) then return {'-4', ''} end
redis.call('HSET', KEYS[1], 'consumed', '1', 'consumedSec', ARGV[2], 'consumedNsec', ARGV[3])
return {'0', redis.call('HGET', KEYS[1], 'data') or ''}
`)

// scriptTicketDelete atomically deletes one ticket and every membership it owns.
// KEYS: 1 ticket hash, 2 all-tickets set, 3 type set, 4 service index, 5 root index, 6 user index,
// 7 expiry sorted set.
// ARGV: 1 member key, 2 expected data (empty skips the guard), 3-6 presence flags for the indexes.
// Returns 1 when a record was deleted, 0 when absent and 2 on a compare-and-set mismatch.
// | scriptTicketDelete 原子删除一张票据及其拥有的全部成员关系。删除返回 1，不存在返回 0，
// 比较并交换不匹配返回 2。
var scriptTicketDelete = goredis.NewScript(`
if redis.call('EXISTS', KEYS[1]) == 0 then return 0 end
if ARGV[2] ~= '' and (redis.call('HGET', KEYS[1], 'data') or '') ~= ARGV[2] then return 2 end
redis.call('DEL', KEYS[1])
redis.call('SREM', KEYS[2], ARGV[1])
if ARGV[3] == '1' then redis.call('SREM', KEYS[3], ARGV[1]) end
if ARGV[4] == '1' then redis.call('SREM', KEYS[4], ARGV[1]) end
if ARGV[5] == '1' then redis.call('SREM', KEYS[5], ARGV[1]) end
if ARGV[6] == '1' then redis.call('SREM', KEYS[6], ARGV[1]) end
redis.call('ZREM', KEYS[7], ARGV[1])
return 1
`)

// scriptSessionSave atomically stores one service session and reconciles its TGT and user indexes
// plus its expiry score. The previous data field acts as a compare-and-set guard.
// KEYS: 1 session hash, 2 all-sessions set, 3/4 new/old TGT index, 5/6 new/old first user index,
// 7/8 new/old second user index, 9 expiry sorted set.
// ARGV: 1 data, 2 member key, 3 expected data, 4 expected-exists flag, 5-10 new/old presence flags,
// 11 has-expiry flag, 12/13 expiry seconds/nanoseconds, 14 expiry score, 15-17 stored index key
// fields. Returns 2 on a compare-and-set mismatch and 0 on success.
// | scriptSessionSave 原子保存一个服务会话，并协调其 TGT、用户索引与期限评分。旧 data 字段充当
// 比较并交换守卫。比较并交换不匹配返回 2，成功返回 0。
var scriptSessionSave = goredis.NewScript(`
if ARGV[4] == '1' then
  if redis.call('EXISTS', KEYS[1]) == 0 then return 2 end
  if ARGV[3] ~= '' and (redis.call('HGET', KEYS[1], 'data') or '') ~= ARGV[3] then return 2 end
else
  if redis.call('EXISTS', KEYS[1]) == 1 then return 2 end
end
if ARGV[6] == '1' then redis.call('SREM', KEYS[4], ARGV[2]) end
if ARGV[8] == '1' then redis.call('SREM', KEYS[6], ARGV[2]) end
if ARGV[10] == '1' then redis.call('SREM', KEYS[8], ARGV[2]) end
redis.call('HSET', KEYS[1], 'data', ARGV[1], 'tgtKey', ARGV[15], 'uk1', ARGV[16], 'uk2', ARGV[17], 'hasExpiry', ARGV[11], 'expireSec', ARGV[12], 'expireNsec', ARGV[13])
redis.call('SADD', KEYS[2], ARGV[2])
if ARGV[5] == '1' then redis.call('SADD', KEYS[3], ARGV[2]) end
if ARGV[7] == '1' then redis.call('SADD', KEYS[5], ARGV[2]) end
if ARGV[9] == '1' then redis.call('SADD', KEYS[7], ARGV[2]) end
if ARGV[11] == '1' then
  redis.call('ZADD', KEYS[9], ARGV[14], ARGV[2])
else
  redis.call('ZREM', KEYS[9], ARGV[2])
end
return 0
`)

// scriptSessionDelete atomically deletes one service session and its memberships.
// KEYS: 1 session hash, 2 all-sessions set, 3 TGT index, 4 first user index, 5 second user index,
// 6 expiry sorted set.
// ARGV: 1 member key, 2 expected data (empty skips the guard), 3-5 presence flags for the indexes.
// Returns 1 when a record was deleted, 0 when absent and 2 on a compare-and-set mismatch.
// | scriptSessionDelete 原子删除一个服务会话及其成员关系。删除返回 1，不存在返回 0，比较并交换
// 不匹配返回 2。
var scriptSessionDelete = goredis.NewScript(`
if redis.call('EXISTS', KEYS[1]) == 0 then return 0 end
if ARGV[2] ~= '' and (redis.call('HGET', KEYS[1], 'data') or '') ~= ARGV[2] then return 2 end
redis.call('DEL', KEYS[1])
redis.call('SREM', KEYS[2], ARGV[1])
if ARGV[3] == '1' then redis.call('SREM', KEYS[3], ARGV[1]) end
if ARGV[4] == '1' then redis.call('SREM', KEYS[4], ARGV[1]) end
if ARGV[5] == '1' then redis.call('SREM', KEYS[5], ARGV[1]) end
redis.call('ZREM', KEYS[6], ARGV[1])
return 1
`)
