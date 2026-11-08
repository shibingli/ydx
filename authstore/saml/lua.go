package saml

import goredis "github.com/redis/go-redis/v9"

// The scripts below are the atomicity boundary of the Redis stores. Every script touches keys that
// share one hash tag, so Redis Cluster routes the whole script to a single slot. Comments in each
// script list the KEYS and ARGV contract. | 下面的脚本是 Redis 存储的原子性边界。每个脚本只访问
// 共享同一哈希标签的键，因此 Redis Cluster 会把整个脚本路由到单一槽位。每个脚本内的注释列出 KEYS
// 与 ARGV 约定。

// scriptRequestCreate atomically creates one request and indexes it by expiry.
// KEYS: 1 request hash, 2 expiry index.
// ARGV: 1 data, 2 used, 3 hasExpiry, 4 expireSec, 5 expireNsec, 6 member.
// Returns 1 when the request already exists and 0 on success.
// | scriptRequestCreate 原子创建单个请求并按到期时间建立索引。
var scriptRequestCreate = goredis.NewScript(`
if redis.call('EXISTS', KEYS[1]) == 1 then return 1 end
redis.call('HSET', KEYS[1], 'data', ARGV[1], 'used', ARGV[2], 'hasExpiry', ARGV[3], 'expireSec', ARGV[4], 'expireNsec', ARGV[5])
if ARGV[3] == '1' then redis.call('ZADD', KEYS[2], ARGV[4], ARGV[6]) end
return 0
`)

// scriptRequestConsume atomically marks one request used.
// KEYS: 1 request hash.
// ARGV: 1 now seconds, 2 now nanoseconds.
// Returns {'-1',”} for an unknown request, {'-2',”} for a used request, {'-3',”} for an expired
// request and {'0', data} on success. | scriptRequestConsume 原子地把单个请求标记为已用。
var scriptRequestConsume = goredis.NewScript(`
if redis.call('EXISTS', KEYS[1]) == 0 then return {'-1', ''} end
if (redis.call('HGET', KEYS[1], 'used') or '0') == '1' then return {'-2', ''} end
if (redis.call('HGET', KEYS[1], 'hasExpiry') or '0') == '1' then
  local es = tonumber(redis.call('HGET', KEYS[1], 'expireSec') or '0')
  local en = tonumber(redis.call('HGET', KEYS[1], 'expireNsec') or '0')
  local ns = tonumber(ARGV[1])
  local nn = tonumber(ARGV[2])
  if es < ns or (es == ns and en <= nn) then return {'-3', ''} end
end
redis.call('HSET', KEYS[1], 'used', '1')
return {'0', redis.call('HGET', KEYS[1], 'data') or ''}
`)

// scriptAssertionSeenAndStore atomically records an assertion identifier until its expiry.
// KEYS: 1 assertion hash, 2 expiry index.
// ARGV: 1 expireSec, 2 expireNsec, 3 hasExpiry, 4 nowSec, 5 nowNsec, 6 member, 7 index score.
// Returns 1 when a record live at now already exists and 0 when the new record was stored.
// | scriptAssertionSeenAndStore 原子记录断言标识直到其过期时间。
var scriptAssertionSeenAndStore = goredis.NewScript(`
if redis.call('EXISTS', KEYS[1]) == 1 then
  if (redis.call('HGET', KEYS[1], 'hasExpiry') or '0') == '1' then
    local es = tonumber(redis.call('HGET', KEYS[1], 'expireSec') or '0')
    local en = tonumber(redis.call('HGET', KEYS[1], 'expireNsec') or '0')
    local ns = tonumber(ARGV[4])
    local nn = tonumber(ARGV[5])
    if es > ns or (es == ns and en > nn) then return 1 end
  end
end
redis.call('HSET', KEYS[1], 'hasExpiry', ARGV[3], 'expireSec', ARGV[1], 'expireNsec', ARGV[2])
redis.call('ZADD', KEYS[2], ARGV[7], ARGV[6])
return 0
`)

// scriptSessionSave atomically stores one session, moves its subject membership and updates its
// expiry index. The expected old NameID acts as a compare-and-set guard.
// KEYS: 1 session hash, 2 new subject set, 3 old subject set, 4 expiry index.
// ARGV: 1 data, 2 new NameID, 3 expected old NameID, 4 hasExpiry, 5 expireSec, 6 expireNsec,
// 7 member. Returns 1 on a compare-and-set mismatch and 0 on success.
// | scriptSessionSave 原子保存单个会话、迁移其主体成员关系并更新到期索引。期望的旧 NameID 充当
// 比较并交换守卫。
var scriptSessionSave = goredis.NewScript(`
if (redis.call('HGET', KEYS[1], 'nameID') or '') ~= ARGV[3] then return 1 end
if ARGV[3] ~= ARGV[2] then redis.call('SREM', KEYS[3], ARGV[7]) end
redis.call('HSET', KEYS[1], 'data', ARGV[1], 'nameID', ARGV[2], 'hasExpiry', ARGV[4], 'expireSec', ARGV[5], 'expireNsec', ARGV[6])
redis.call('SADD', KEYS[2], ARGV[7])
if ARGV[4] == '1' then redis.call('ZADD', KEYS[4], ARGV[5], ARGV[7]) else redis.call('ZREM', KEYS[4], ARGV[7]) end
return 0
`)

// scriptSessionDelete atomically deletes one session and both indexes, guarded by its current
// NameID. KEYS: 1 session hash, 2 subject set, 3 expiry index.
// ARGV: 1 expected NameID, 2 member.
// Returns 1 when absent, 2 on a compare-and-set mismatch and 0 on success.
// | scriptSessionDelete 以当前 NameID 为守卫原子删除单个会话与两个索引。
var scriptSessionDelete = goredis.NewScript(`
if redis.call('EXISTS', KEYS[1]) == 0 then return 1 end
if (redis.call('HGET', KEYS[1], 'nameID') or '') ~= ARGV[1] then return 2 end
redis.call('DEL', KEYS[1])
redis.call('SREM', KEYS[2], ARGV[2])
redis.call('ZREM', KEYS[3], ARGV[2])
return 0
`)

// scriptCleanupBefore removes indexed records whose expiry second is below now, which makes them
// expired regardless of nanoseconds.
// KEYS: 1 expiry index.
// ARGV: 1 nowSec, 2 batch limit.
// Returns {processed, removed}.
// | scriptCleanupBefore 删除到期秒低于 now 的索引记录；这类记录无论纳秒如何均已过期。
var scriptCleanupBefore = goredis.NewScript(`
local members = redis.call('ZRANGEBYSCORE', KEYS[1], '-inf', '(' .. ARGV[1], 'LIMIT', 0, ARGV[2])
local removed = 0
for _, member in ipairs(members) do
  if redis.call('DEL', member) == 1 then removed = removed + 1 end
  redis.call('ZREM', KEYS[1], member)
end
return {#members, removed}
`)

// scriptCleanupAt removes indexed records that expire exactly during the second nowSec and drops
// stale index members whose data key disappeared. Records indexed without an expiry are removed
// because the in-memory store treats a zero assertion expiry as immediately expired.
// KEYS: 1 expiry index.
// ARGV: 1 nowSec, 2 nowNsec.
// Returns {processed, removed}.
// | scriptCleanupAt 删除恰在 nowSec 这一秒内到期的索引记录，并清除数据键已消失的陈旧索引成员。
// 无到期时间的索引记录也会被删除，因为内存存储把零值断言期限视为立即过期。
var scriptCleanupAt = goredis.NewScript(`
local members = redis.call('ZRANGEBYSCORE', KEYS[1], ARGV[1], ARGV[1])
local removed = 0
for _, member in ipairs(members) do
  if redis.call('EXISTS', member) == 0 then
    redis.call('ZREM', KEYS[1], member)
  elseif (redis.call('HGET', member, 'hasExpiry') or '0') ~= '1' then
    if redis.call('DEL', member) == 1 then removed = removed + 1 end
    redis.call('ZREM', KEYS[1], member)
  else
    local es = tonumber(redis.call('HGET', member, 'expireSec') or '0')
    local en = tonumber(redis.call('HGET', member, 'expireNsec') or '0')
    local ns = tonumber(ARGV[1])
    local nn = tonumber(ARGV[2])
    if es < ns or (es == ns and en <= nn) then
      if redis.call('DEL', member) == 1 then removed = removed + 1 end
      redis.call('ZREM', KEYS[1], member)
    end
  end
end
return {#members, removed}
`)

// scriptSessionCleanupBefore removes expired sessions below now and their subject membership.
// KEYS: 1 expiry index.
// ARGV: 1 nowSec, 2 batch limit, 3 subject key prefix.
// Returns {processed, removed}.
// | scriptSessionCleanupBefore 删除到期秒低于 now 的会话及其主体成员关系。
var scriptSessionCleanupBefore = goredis.NewScript(`
local members = redis.call('ZRANGEBYSCORE', KEYS[1], '-inf', '(' .. ARGV[1], 'LIMIT', 0, ARGV[2])
local removed = 0
for _, member in ipairs(members) do
  local nameID = redis.call('HGET', member, 'nameID')
  if nameID then
    local subject = ARGV[3] .. string.len(nameID) .. ':' .. nameID
    redis.call('SREM', subject, member)
  end
  if redis.call('DEL', member) == 1 then removed = removed + 1 end
  redis.call('ZREM', KEYS[1], member)
end
return {#members, removed}
`)

// scriptSessionCleanupAt removes sessions expiring exactly during the second nowSec and their
// subject membership. KEYS: 1 expiry index.
// ARGV: 1 nowSec, 2 nowNsec, 3 subject key prefix.
// Returns {processed, removed}.
// | scriptSessionCleanupAt 删除恰在 nowSec 这一秒内到期的会话及其主体成员关系。
var scriptSessionCleanupAt = goredis.NewScript(`
local members = redis.call('ZRANGEBYSCORE', KEYS[1], ARGV[1], ARGV[1])
local removed = 0
for _, member in ipairs(members) do
  if redis.call('EXISTS', member) == 0 then
    redis.call('ZREM', KEYS[1], member)
  else
    local expired = false
    if (redis.call('HGET', member, 'hasExpiry') or '0') ~= '1' then
      expired = true
    else
      local es = tonumber(redis.call('HGET', member, 'expireSec') or '0')
      local en = tonumber(redis.call('HGET', member, 'expireNsec') or '0')
      local ns = tonumber(ARGV[1])
      local nn = tonumber(ARGV[2])
      expired = es < ns or (es == ns and en <= nn)
    end
    if expired then
      local nameID = redis.call('HGET', member, 'nameID')
      if nameID then
        local subject = ARGV[3] .. string.len(nameID) .. ':' .. nameID
        redis.call('SREM', subject, member)
      end
      if redis.call('DEL', member) == 1 then removed = removed + 1 end
      redis.call('ZREM', KEYS[1], member)
    end
  end
end
return {#members, removed}
`)

// scriptArtifactSave atomically stores one artifact record and its expiry index. An existing
// record is a replay only while it has not expired.
// KEYS: 1 artifact hash, 2 expiry index.
// ARGV: 1 data, 2 used, 3 hasExpiry, 4 expireSec, 5 expireNsec, 6 nowSec, 7 nowNsec, 8 member.
// Returns 1 for a live duplicate and 0 on success.
// | scriptArtifactSave 原子保存单条工件记录及其到期索引。仅当已存记录尚未过期时才视为重放。
var scriptArtifactSave = goredis.NewScript(`
if redis.call('EXISTS', KEYS[1]) == 1 then
  local live = true
  if (redis.call('HGET', KEYS[1], 'hasExpiry') or '0') == '1' then
    local es = tonumber(redis.call('HGET', KEYS[1], 'expireSec') or '0')
    local en = tonumber(redis.call('HGET', KEYS[1], 'expireNsec') or '0')
    local ns = tonumber(ARGV[6])
    local nn = tonumber(ARGV[7])
    live = es > ns or (es == ns and en > nn)
  end
  if live then return 1 end
end
redis.call('HSET', KEYS[1], 'data', ARGV[1], 'used', ARGV[2], 'hasExpiry', ARGV[3], 'expireSec', ARGV[4], 'expireNsec', ARGV[5])
if ARGV[3] == '1' then redis.call('ZADD', KEYS[2], ARGV[4], ARGV[8]) else redis.call('ZREM', KEYS[2], ARGV[8]) end
return 0
`)

// scriptArtifactTake atomically consumes one artifact.
// KEYS: 1 artifact hash, 2 expiry index.
// ARGV: 1 nowSec, 2 nowNsec, 3 member.
// Returns {'-1',”} for an unknown artifact, {'-2',”} for a replay, {'-3',”} for an expired
// artifact and {'0', data} on success. Expired records are deleted on discovery.
// | scriptArtifactTake 原子消费单个工件。发现过期记录时将其删除。
var scriptArtifactTake = goredis.NewScript(`
if redis.call('EXISTS', KEYS[1]) == 0 then return {'-1', ''} end
if (redis.call('HGET', KEYS[1], 'hasExpiry') or '0') == '1' then
  local es = tonumber(redis.call('HGET', KEYS[1], 'expireSec') or '0')
  local en = tonumber(redis.call('HGET', KEYS[1], 'expireNsec') or '0')
  local ns = tonumber(ARGV[1])
  local nn = tonumber(ARGV[2])
  if es < ns or (es == ns and en <= nn) then
    redis.call('DEL', KEYS[1])
    redis.call('ZREM', KEYS[2], ARGV[3])
    return {'-3', ''}
  end
end
if (redis.call('HGET', KEYS[1], 'used') or '0') == '1' then return {'-2', ''} end
redis.call('HSET', KEYS[1], 'used', '1')
return {'0', redis.call('HGET', KEYS[1], 'data') or ''}
`)
