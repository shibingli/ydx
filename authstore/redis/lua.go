package redis

import goredis "github.com/redis/go-redis/v9"

// The scripts below are the atomicity boundary of the Redis stores. Every script touches only
// keys that share one hash tag, so Redis Cluster routes them to a single slot. Comments in each
// script list the KEYS and ARGV contract.
// | 下面的脚本是 Redis 存储的原子性边界。每个脚本只访问共享同一哈希标签的键，因此 Redis
// Cluster 会把它们路由到单一槽位。每个脚本内的注释列出 KEYS 与 ARGV 约定。

// scriptUserCreate atomically creates one user and its three unique indexes.
// KEYS: 1 all-users set, 2 user hash, 3 username index, 4 email index, 5 phone index.
// ARGV: 1 data, 2 username, 3 email, 4 phone, 5 id, 6/7/8 username/email/phone present flags.
// Returns 1 for a duplicate ID, 2/3/4 for a duplicate username/email/phone, 0 on success.
// | scriptUserCreate 原子创建单个用户及其三个唯一索引。
var scriptUserCreate = goredis.NewScript(`
if redis.call('EXISTS', KEYS[2]) == 1 then return 1 end
if ARGV[6] == '1' and redis.call('EXISTS', KEYS[3]) == 1 then return 2 end
if ARGV[7] == '1' and redis.call('EXISTS', KEYS[4]) == 1 then return 3 end
if ARGV[8] == '1' and redis.call('EXISTS', KEYS[5]) == 1 then return 4 end
redis.call('HSET', KEYS[2], 'data', ARGV[1], 'username', ARGV[2], 'email', ARGV[3], 'phone', ARGV[4])
if ARGV[6] == '1' then redis.call('SET', KEYS[3], ARGV[5]) end
if ARGV[7] == '1' then redis.call('SET', KEYS[4], ARGV[5]) end
if ARGV[8] == '1' then redis.call('SET', KEYS[5], ARGV[5]) end
redis.call('SADD', KEYS[1], ARGV[5])
return 0
`)

// scriptUserUpdate atomically replaces one user and reconciles its unique indexes. The old
// identifier fields act as a compare-and-set guard, so an interleaved writer forces a retry
// instead of leaving a stale index.
// KEYS: 1 user hash, 2/3/4 new username/email/phone indexes, 5/6/7 old indexes.
// ARGV: 1-3 old identifier fields, 4 data, 5-7 new identifiers, 8 id, 9-11 new flags, 12-14 old
// flags. Returns 1 when absent, 2/3/4 on conflict, 5 on a compare-and-set mismatch, 0 on success.
// | scriptUserUpdate 原子替换单个用户并协调其唯一索引。旧标识字段充当比较并交换守卫，
// 交错写入会触发重试，而不会留下陈旧索引。
var scriptUserUpdate = goredis.NewScript(`
if redis.call('EXISTS', KEYS[1]) == 0 then return 1 end
local ou = redis.call('HGET', KEYS[1], 'username') or ''
local oe = redis.call('HGET', KEYS[1], 'email') or ''
local op = redis.call('HGET', KEYS[1], 'phone') or ''
if ou ~= ARGV[1] or oe ~= ARGV[2] or op ~= ARGV[3] then return 5 end
if ARGV[9] == '1' then
  local owner = redis.call('GET', KEYS[2])
  if owner and owner ~= ARGV[8] then return 2 end
end
if ARGV[10] == '1' then
  local owner = redis.call('GET', KEYS[3])
  if owner and owner ~= ARGV[8] then return 3 end
end
if ARGV[11] == '1' then
  local owner = redis.call('GET', KEYS[4])
  if owner and owner ~= ARGV[8] then return 4 end
end
if ARGV[12] == '1' and KEYS[5] ~= KEYS[2] then
  local owner = redis.call('GET', KEYS[5])
  if owner == ARGV[8] then redis.call('DEL', KEYS[5]) end
end
if ARGV[13] == '1' and KEYS[6] ~= KEYS[3] then
  local owner = redis.call('GET', KEYS[6])
  if owner == ARGV[8] then redis.call('DEL', KEYS[6]) end
end
if ARGV[14] == '1' and KEYS[7] ~= KEYS[4] then
  local owner = redis.call('GET', KEYS[7])
  if owner == ARGV[8] then redis.call('DEL', KEYS[7]) end
end
if ARGV[9] == '1' then redis.call('SET', KEYS[2], ARGV[8]) end
if ARGV[10] == '1' then redis.call('SET', KEYS[3], ARGV[8]) end
if ARGV[11] == '1' then redis.call('SET', KEYS[4], ARGV[8]) end
redis.call('HSET', KEYS[1], 'data', ARGV[4], 'username', ARGV[5], 'email', ARGV[6], 'phone', ARGV[7])
return 0
`)

// scriptUserDelete atomically deletes one user, its indexes and its set membership.
// KEYS: 1 user hash, 2 all-users set, 3/4/5 old username/email/phone indexes.
// ARGV: 1 id, 2-4 old identifiers, 5-7 old present flags.
// Returns 1 when absent, 2 on a compare-and-set mismatch, 0 on success.
// | scriptUserDelete 原子删除单个用户、其索引与集合成员。
var scriptUserDelete = goredis.NewScript(`
if redis.call('EXISTS', KEYS[1]) == 0 then return 1 end
if (redis.call('HGET', KEYS[1], 'username') or '') ~= ARGV[2] then return 2 end
if (redis.call('HGET', KEYS[1], 'email') or '') ~= ARGV[3] then return 2 end
if (redis.call('HGET', KEYS[1], 'phone') or '') ~= ARGV[4] then return 2 end
if ARGV[5] == '1' then
  if redis.call('GET', KEYS[3]) == ARGV[1] then redis.call('DEL', KEYS[3]) end
end
if ARGV[6] == '1' then
  if redis.call('GET', KEYS[4]) == ARGV[1] then redis.call('DEL', KEYS[4]) end
end
if ARGV[7] == '1' then
  if redis.call('GET', KEYS[5]) == ARGV[1] then redis.call('DEL', KEYS[5]) end
end
redis.call('DEL', KEYS[1])
redis.call('SREM', KEYS[2], ARGV[1])
return 0
`)

// scriptSessionCreate atomically stores a session and both set memberships.
// KEYS: 1 session hash, 2 user set, 3 all-sessions set.
// ARGV: 1 data, 2 user, 3 hasExpiry, 4 expireSec, 5 expireNsec, 6 id.
// Returns 1 for a duplicate session ID and 0 on success.
// | scriptSessionCreate 原子保存会话与两个集合成员关系。
var scriptSessionCreate = goredis.NewScript(`
if redis.call('EXISTS', KEYS[1]) == 1 then return 1 end
redis.call('HSET', KEYS[1], 'data', ARGV[1], 'user', ARGV[2], 'hasExpiry', ARGV[3], 'expireSec', ARGV[4], 'expireNsec', ARGV[5])
redis.call('SADD', KEYS[2], ARGV[6])
redis.call('SADD', KEYS[3], ARGV[6])
return 0
`)

// scriptSessionUpdate atomically replaces a session and moves its user membership.
// KEYS: 1 session hash, 2 new user set, 3 old user set, 4 all-sessions set.
// ARGV: 1 data, 2 new user, 3 old user, 4 id, 5 hasExpiry, 6 expireSec, 7 expireNsec.
// Returns 1 when absent, 2 on a compare-and-set mismatch, 0 on success.
// | scriptSessionUpdate 原子替换会话并迁移其用户成员关系。
var scriptSessionUpdate = goredis.NewScript(`
if redis.call('EXISTS', KEYS[1]) == 0 then return 1 end
local u = redis.call('HGET', KEYS[1], 'user') or ''
if u ~= ARGV[3] then return 2 end
if u ~= ARGV[2] then
  redis.call('SREM', KEYS[3], ARGV[4])
  redis.call('SADD', KEYS[2], ARGV[4])
end
redis.call('HSET', KEYS[1], 'data', ARGV[1], 'user', ARGV[2], 'hasExpiry', ARGV[5], 'expireSec', ARGV[6], 'expireNsec', ARGV[7])
redis.call('SADD', KEYS[4], ARGV[4])
return 0
`)

// scriptSessionDelete atomically deletes a session guarded by its current owner.
// KEYS: 1 session hash, 2 user set, 3 all-sessions set.
// ARGV: 1 expected user, 2 id.
// Returns 1 when absent, 2 on a compare-and-set mismatch, 0 on success.
// | scriptSessionDelete 以当前属主为守卫原子删除会话。
var scriptSessionDelete = goredis.NewScript(`
if redis.call('EXISTS', KEYS[1]) == 0 then return 1 end
if (redis.call('HGET', KEYS[1], 'user') or '') ~= ARGV[1] then return 2 end
redis.call('DEL', KEYS[1])
redis.call('SREM', KEYS[2], ARGV[2])
redis.call('SREM', KEYS[3], ARGV[2])
return 0
`)

// scriptSessionDeleteExpired deletes one session only when owner and deadline are unchanged.
// KEYS: 1 session hash, 2 user set, 3 all-sessions set.
// ARGV: 1 expected user, 2 hasExpiry, 3 expireSec, 4 expireNsec, 5 id.
// Returns 1 when absent, 2/3 on compare-and-set mismatches, 0 on success.
// | scriptSessionDeleteExpired 仅在属主与期限未变时删除单个会话。
var scriptSessionDeleteExpired = goredis.NewScript(`
if redis.call('EXISTS', KEYS[1]) == 0 then return 1 end
if (redis.call('HGET', KEYS[1], 'user') or '') ~= ARGV[1] then return 2 end
if (redis.call('HGET', KEYS[1], 'hasExpiry') or '0') ~= ARGV[2] then return 3 end
if (redis.call('HGET', KEYS[1], 'expireSec') or '0') ~= ARGV[3] then return 3 end
if (redis.call('HGET', KEYS[1], 'expireNsec') or '0') ~= ARGV[4] then return 3 end
redis.call('DEL', KEYS[1])
redis.call('SREM', KEYS[2], ARGV[5])
redis.call('SREM', KEYS[3], ARGV[5])
return 0
`)

// scriptIdentityCreate atomically stores an identity link and its user membership.
// KEYS: 1 identity hash, 2 user set.
// ARGV: 1 data, 2 user, 3 identity key.
// Returns 1 for a duplicate provider/subject pair and 0 on success.
// | scriptIdentityCreate 原子保存身份关联与用户成员关系。
var scriptIdentityCreate = goredis.NewScript(`
if redis.call('EXISTS', KEYS[1]) == 1 then return 1 end
redis.call('HSET', KEYS[1], 'data', ARGV[1], 'user', ARGV[2])
redis.call('SADD', KEYS[2], ARGV[3])
return 0
`)

// scriptIdentityUpdate atomically replaces a link and moves its user membership.
// KEYS: 1 identity hash, 2 new user set, 3 old user set.
// ARGV: 1 data, 2 new user, 3 old user, 4 identity key.
// Returns 1 when absent, 2 on a compare-and-set mismatch, 0 on success.
// | scriptIdentityUpdate 原子替换关联并迁移其用户成员关系。
var scriptIdentityUpdate = goredis.NewScript(`
if redis.call('EXISTS', KEYS[1]) == 0 then return 1 end
local u = redis.call('HGET', KEYS[1], 'user') or ''
if u ~= ARGV[3] then return 2 end
if u ~= ARGV[2] then
  redis.call('SREM', KEYS[3], ARGV[4])
  redis.call('SADD', KEYS[2], ARGV[4])
end
redis.call('HSET', KEYS[1], 'data', ARGV[1], 'user', ARGV[2])
return 0
`)

// scriptIdentityDelete atomically deletes a link guarded by its current owner.
// KEYS: 1 identity hash, 2 user set.
// ARGV: 1 expected user, 2 identity key.
// Returns 1 when absent, 2 on a compare-and-set mismatch, 0 on success.
// | scriptIdentityDelete 以当前属主为守卫原子删除关联。
var scriptIdentityDelete = goredis.NewScript(`
if redis.call('EXISTS', KEYS[1]) == 0 then return 1 end
if (redis.call('HGET', KEYS[1], 'user') or '') ~= ARGV[1] then return 2 end
redis.call('DEL', KEYS[1])
redis.call('SREM', KEYS[2], ARGV[2])
return 0
`)

// scriptCredentialCreate atomically stores a credential and its user membership.
// KEYS: 1 credential hash, 2 user set.
// ARGV: 1 data, 2 user, 3 credential ID.
// Returns 1 for a duplicate credential ID and 0 on success.
// | scriptCredentialCreate 原子保存凭据与用户成员关系。
var scriptCredentialCreate = goredis.NewScript(`
if redis.call('EXISTS', KEYS[1]) == 1 then return 1 end
redis.call('HSET', KEYS[1], 'data', ARGV[1], 'user', ARGV[2])
redis.call('SADD', KEYS[2], ARGV[3])
return 0
`)

// scriptCredentialUpdate atomically replaces a credential and moves its user membership.
// KEYS: 1 credential hash, 2 new user set, 3 old user set.
// ARGV: 1 data, 2 new user, 3 old user, 4 credential ID.
// Returns 1 when absent, 2 on a compare-and-set mismatch, 0 on success.
// | scriptCredentialUpdate 原子替换凭据并迁移其用户成员关系。
var scriptCredentialUpdate = goredis.NewScript(`
if redis.call('EXISTS', KEYS[1]) == 0 then return 1 end
local u = redis.call('HGET', KEYS[1], 'user') or ''
if u ~= ARGV[3] then return 2 end
if u ~= ARGV[2] then
  redis.call('SREM', KEYS[3], ARGV[4])
  redis.call('SADD', KEYS[2], ARGV[4])
end
redis.call('HSET', KEYS[1], 'data', ARGV[1], 'user', ARGV[2])
return 0
`)

// scriptCredentialDelete atomically deletes a credential guarded by its current owner.
// KEYS: 1 credential hash, 2 user set.
// ARGV: 1 expected user, 2 credential ID.
// Returns 1 when absent, 2 on a compare-and-set mismatch, 0 on success.
// | scriptCredentialDelete 以当前属主为守卫原子删除凭据。
var scriptCredentialDelete = goredis.NewScript(`
if redis.call('EXISTS', KEYS[1]) == 0 then return 1 end
if (redis.call('HGET', KEYS[1], 'user') or '') ~= ARGV[1] then return 2 end
redis.call('DEL', KEYS[1])
redis.call('SREM', KEYS[2], ARGV[2])
return 0
`)

// scriptAuditAppend allocates a sequence number, stores the event and indexes it by time.
// KEYS: 1 sequence counter, 2 event hash, 3 time sorted set.
// ARGV: 1 event data, 2 score.
// | scriptAuditAppend 分配序号、保存事件并按时间建立索引。
var scriptAuditAppend = goredis.NewScript(`
local seq = redis.call('INCR', KEYS[1])
redis.call('HSET', KEYS[2], tostring(seq), ARGV[1])
redis.call('ZADD', KEYS[3], ARGV[2], tostring(seq))
return seq
`)

// scriptTokenCreate atomically stores a token, preserves its consumed state and reconciles the
// per-user membership.
// KEYS: 1 token hash, 2 new user set, 3 old user set.
// ARGV: 1 data, 2 new user, 3 old user, 4 token key, 5 used, 6 hasExpiry, 7 expireSec,
// 8 expireNsec. Returns 1 on a compare-and-set mismatch, 0 on success.
// | scriptTokenCreate 原子保存令牌、保留其消费状态并协调用户成员关系。
var scriptTokenCreate = goredis.NewScript(`
local u = redis.call('HGET', KEYS[1], 'user') or ''
if u ~= ARGV[3] then return 1 end
if u ~= ARGV[2] then
  redis.call('SREM', KEYS[3], ARGV[4])
  redis.call('SADD', KEYS[2], ARGV[4])
end
redis.call('HSET', KEYS[1], 'data', ARGV[1], 'user', ARGV[2], 'used', ARGV[5], 'hasExpiry', ARGV[6], 'expireSec', ARGV[7], 'expireNsec', ARGV[8])
redis.call('SADD', KEYS[2], ARGV[4])
return 0
`)

// scriptTokenConsume atomically marks one token used.
// KEYS: 1 token hash.
// ARGV: 1 now seconds, 2 now nanoseconds.
// Returns {'-1',”} for an unknown token, {'-2',”} for an already used token, {'-3',”} for an
// expired token and {'0', data} on success.
// | scriptTokenConsume 原子地把单个令牌标记为已用。
var scriptTokenConsume = goredis.NewScript(`
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

// scriptTokensDeleteByUser atomically removes every token key in one user/purpose set.
// KEYS: 1 user set whose members are full token keys in the same hash tag.
// | scriptTokensDeleteByUser 原子删除单个用户/用途集合中的全部令牌键。
var scriptTokensDeleteByUser = goredis.NewScript(`
local members = redis.call('SMEMBERS', KEYS[1])
local n = 0
for _, m in ipairs(members) do
  if redis.call('EXISTS', m) == 1 then n = n + 1 end
  redis.call('DEL', m)
end
redis.call('DEL', KEYS[1])
return n
`)
