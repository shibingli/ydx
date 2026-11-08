package oauth2

import goredis "github.com/redis/go-redis/v9"

// The scripts below are the atomicity boundary of the Redis stores. Every script touches only
// keys that share one hash tag, so Redis Cluster routes them to a single slot. Comments in each
// script list the KEYS and ARGV contract. | 下面的脚本是 Redis 存储的原子性边界。每个脚本只访问
// 共享同一哈希标签的键，因此 Redis Cluster 会把它们路由到单一槽位。每个脚本内的注释列出
// KEYS 与 ARGV 约定。

// scriptCodeSave atomically stores one authorization code.
// KEYS: 1 code hash, 2 all-codes set.
// ARGV: 1 data, 2 hasExp, 3 expSec, 4 expNsec, 5 used.
// Returns 1 for a duplicate hash and 0 on success. | scriptCodeSave 原子保存单个授权码。
var scriptCodeSave = goredis.NewScript(`
if redis.call('EXISTS', KEYS[1]) == 1 then return 1 end
redis.call('HSET', KEYS[1], 'data', ARGV[1], 'used', ARGV[5], 'hasExp', ARGV[2], 'expSec', ARGV[3], 'expNsec', ARGV[4])
redis.call('SADD', KEYS[2], KEYS[1])
return 0
`)

// scriptCodeConsume atomically consumes one authorization code.
// KEYS: 1 code hash.
// ARGV: 1 now seconds, 2 now nanoseconds.
// Returns {'-1',”} for unknown, {'-2',”} for used, {'-3',”} for expired and {'0',data}.
// | scriptCodeConsume 原子消费单个授权码。
var scriptCodeConsume = goredis.NewScript(`
if redis.call('EXISTS', KEYS[1]) == 0 then return {'-1', ''} end
if (redis.call('HGET', KEYS[1], 'used') or '0') == '1' then return {'-2', ''} end
if (redis.call('HGET', KEYS[1], 'hasExp') or '0') == '1' then
  local es = tonumber(redis.call('HGET', KEYS[1], 'expSec') or '0')
  local en = tonumber(redis.call('HGET', KEYS[1], 'expNsec') or '0')
  local ns = tonumber(ARGV[1])
  local nn = tonumber(ARGV[2])
  if es < ns or (es == ns and en <= nn) then return {'-3', ''} end
end
redis.call('HSET', KEYS[1], 'used', '1')
return {'0', redis.call('HGET', KEYS[1], 'data') or ''}
`)

// scriptPARSave atomically stores one pushed authorization request.
// KEYS: 1 request hash, 2 all-requests set.
// ARGV: 1 data, 2 hasExp, 3 expSec, 4 expNsec, 5 used.
// Returns 1 for a duplicate request URI and 0 on success. | scriptPARSave 原子保存单个推送授权请求。
var scriptPARSave = goredis.NewScript(`
if redis.call('EXISTS', KEYS[1]) == 1 then return 1 end
redis.call('HSET', KEYS[1], 'data', ARGV[1], 'used', ARGV[5], 'hasExp', ARGV[2], 'expSec', ARGV[3], 'expNsec', ARGV[4])
redis.call('SADD', KEYS[2], KEYS[1])
return 0
`)

// scriptPARConsume atomically consumes one pushed authorization request.
// KEYS: 1 request hash.
// ARGV: 1 now seconds, 2 now nanoseconds.
// Returns {'-1'} for unknown or used, {'-2'} for expired and {'0',data} on success.
// | scriptPARConsume 原子消费单个推送授权请求。
var scriptPARConsume = goredis.NewScript(`
if redis.call('EXISTS', KEYS[1]) == 0 then return {'-1', ''} end
if (redis.call('HGET', KEYS[1], 'used') or '0') == '1' then return {'-1', ''} end
if (redis.call('HGET', KEYS[1], 'hasExp') or '0') == '1' then
  local es = tonumber(redis.call('HGET', KEYS[1], 'expSec') or '0')
  local en = tonumber(redis.call('HGET', KEYS[1], 'expNsec') or '0')
  local ns = tonumber(ARGV[1])
  local nn = tonumber(ARGV[2])
  if es < ns or (es == ns and en <= nn) then return {'-2', ''} end
end
redis.call('HSET', KEYS[1], 'used', '1')
return {'0', redis.call('HGET', KEYS[1], 'data') or ''}
`)

// scriptRefreshSave atomically stores one refresh token and both secondary indexes.
// KEYS: 1 token hash, 2 all-tokens set, 3 family set, 4 subject set.
// ARGV: 1 data, 2 used, 3 revoked, 4 hasExp, 5 expSec, 6 expNsec.
// Returns 1 for a duplicate hash and 0 on success. | scriptRefreshSave 原子保存单个刷新令牌与两个二级索引。
var scriptRefreshSave = goredis.NewScript(`
if redis.call('EXISTS', KEYS[1]) == 1 then return 1 end
redis.call('HSET', KEYS[1], 'data', ARGV[1], 'used', ARGV[2], 'revoked', ARGV[3],
  'hasExp', ARGV[4], 'expSec', ARGV[5], 'expNsec', ARGV[6],
  'familySet', KEYS[3], 'subjectSet', KEYS[4])
redis.call('SADD', KEYS[2], KEYS[1])
redis.call('SADD', KEYS[3], KEYS[1])
redis.call('SADD', KEYS[4], KEYS[1])
return 0
`)

// scriptRefreshRotate atomically consumes oldHash and stores replacement.
// KEYS: 1 old token hash, 2 replacement hash, 3 all-tokens set, 4 replacement family set,
// 5 replacement subject set.
// ARGV: 1 now seconds, 2 now nanoseconds, 3 data, 4 used, 5 revoked, 6 hasExp, 7 expSec,
// 8 expNsec.
// Returns 1 when the old token is absent, used, revoked or expired; 2 on a replacement hash
// collision; 0 on success. | scriptRefreshRotate 原子消费 oldHash 并保存 replacement。
var scriptRefreshRotate = goredis.NewScript(`
if redis.call('EXISTS', KEYS[1]) == 0 then return 1 end
if (redis.call('HGET', KEYS[1], 'used') or '0') == '1' then return 1 end
if (redis.call('HGET', KEYS[1], 'revoked') or '0') == '1' then return 1 end
if (redis.call('HGET', KEYS[1], 'hasExp') or '0') == '1' then
  local es = tonumber(redis.call('HGET', KEYS[1], 'expSec') or '0')
  local en = tonumber(redis.call('HGET', KEYS[1], 'expNsec') or '0')
  local ns = tonumber(ARGV[1])
  local nn = tonumber(ARGV[2])
  if es < ns or (es == ns and en <= nn) then return 1 end
end
if redis.call('EXISTS', KEYS[2]) == 1 then return 2 end
redis.call('HSET', KEYS[1], 'used', '1')
redis.call('HSET', KEYS[2], 'data', ARGV[3], 'used', ARGV[4], 'revoked', ARGV[5],
  'hasExp', ARGV[6], 'expSec', ARGV[7], 'expNsec', ARGV[8],
  'familySet', KEYS[4], 'subjectSet', KEYS[5])
redis.call('SADD', KEYS[3], KEYS[2])
redis.call('SADD', KEYS[4], KEYS[2])
redis.call('SADD', KEYS[5], KEYS[2])
return 0
`)

// scriptRefreshRevoke atomically revokes one refresh token or its whole family.
// KEYS: 1 token hash.
// ARGV: 1 revokeFamily flag.
// Returns 1 when the token is absent and 0 on success. | scriptRefreshRevoke 原子撤销单个刷新令牌或其整个家族。
var scriptRefreshRevoke = goredis.NewScript(`
if redis.call('EXISTS', KEYS[1]) == 0 then return 1 end
redis.call('HSET', KEYS[1], 'revoked', '1')
if ARGV[1] == '1' then
  local familyKey = redis.call('HGET', KEYS[1], 'familySet')
  if familyKey and familyKey ~= '' then
    local members = redis.call('SMEMBERS', familyKey)
    for _, member in ipairs(members) do
      if redis.call('EXISTS', member) == 1 then
        redis.call('HSET', member, 'revoked', '1')
      end
    end
  end
end
return 0
`)

// scriptRefreshRevokeSubject atomically revokes every live token of one subject index.
// KEYS: 1 subject set whose members are full token keys in the same hash tag.
// Returns the number of newly revoked tokens. | scriptRefreshRevokeSubject 原子撤销单个主体索引中的全部有效令牌。
var scriptRefreshRevokeSubject = goredis.NewScript(`
local members = redis.call('SMEMBERS', KEYS[1])
local n = 0
for _, member in ipairs(members) do
  if redis.call('EXISTS', member) == 1 then
    if (redis.call('HGET', member, 'revoked') or '0') ~= '1' then
      redis.call('HSET', member, 'revoked', '1')
      n = n + 1
    end
  end
end
return n
`)

// scriptAccessSave atomically stores one opaque access token.
// KEYS: 1 token hash, 2 all-tokens set.
// ARGV: 1 data, 2 revoked, 3 hasExp, 4 expSec, 5 expNsec.
// Returns 1 for a duplicate hash and 0 on success. | scriptAccessSave 原子保存单个不透明访问令牌。
var scriptAccessSave = goredis.NewScript(`
if redis.call('EXISTS', KEYS[1]) == 1 then return 1 end
redis.call('HSET', KEYS[1], 'data', ARGV[1], 'revoked', ARGV[2],
  'hasExp', ARGV[3], 'expSec', ARGV[4], 'expNsec', ARGV[5])
redis.call('SADD', KEYS[2], KEYS[1])
return 0
`)

// scriptAccessRevoke atomically revokes one access token.
// KEYS: 1 token hash.
// Returns 1 when the token is absent and 0 on success. | scriptAccessRevoke 原子撤销单个访问令牌。
var scriptAccessRevoke = goredis.NewScript(`
if redis.call('EXISTS', KEYS[1]) == 0 then return 1 end
redis.call('HSET', KEYS[1], 'revoked', '1')
return 0
`)

// scriptDeviceSave atomically stores one device grant and its user-code index.
// KEYS: 1 device hash, 2 all-devices set, 3 user-code index.
// ARGV: flat field/value pairs ending with the userIndex field.
// Returns 1 for a duplicate device hash, 2 for a duplicate user code and 0 on success.
// | scriptDeviceSave 原子保存单个设备许可及其用户码索引。
var scriptDeviceSave = goredis.NewScript(`
if redis.call('EXISTS', KEYS[1]) == 1 then return 1 end
if redis.call('EXISTS', KEYS[3]) == 1 then return 2 end
local i = 1
while i <= #ARGV do
  redis.call('HSET', KEYS[1], ARGV[i], ARGV[i + 1])
  i = i + 2
end
redis.call('SET', KEYS[3], KEYS[1])
redis.call('SADD', KEYS[2], KEYS[1])
return 0
`)

// scriptDeviceUpdate atomically replaces a device grant without touching its user-code index.
// KEYS: 1 device hash.
// ARGV: flat field/value pairs.
// Returns 1 when the device is absent and 0 on success. | scriptDeviceUpdate 原子替换设备许可且不触碰用户码索引。
var scriptDeviceUpdate = goredis.NewScript(`
if redis.call('EXISTS', KEYS[1]) == 0 then return 1 end
local i = 1
while i <= #ARGV do
  redis.call('HSET', KEYS[1], ARGV[i], ARGV[i + 1])
  i = i + 2
end
return 0
`)

// scriptDeviceByUser atomically resolves a user code and returns the device hash fields.
// KEYS: 1 user-code index.
// Returns an empty array for an unknown user code and a flat field/value array otherwise.
// | scriptDeviceByUser 原子解析用户码并返回设备哈希字段。
var scriptDeviceByUser = goredis.NewScript(`
local key = redis.call('GET', KEYS[1])
if not key then return {} end
if redis.call('EXISTS', key) == 0 then return {} end
return redis.call('HGETALL', key)
`)

// scriptDevicePoll atomically applies RFC 8628 token-endpoint polling.
// KEYS: 1 device hash.
// ARGV: 1 client ID, 2 now seconds, 3 now nanoseconds.
// Returns {'-1'} for an unknown device, {'-2'} for a foreign client, and otherwise
// {'0', reportStatus, accepted, flat field/value pairs}. | scriptDevicePoll 原子应用 RFC 8628 令牌端点轮询。
var scriptDevicePoll = goredis.NewScript(`
if redis.call('EXISTS', KEYS[1]) == 0 then return {'-1'} end
if (redis.call('HGET', KEYS[1], 'client') or '') ~= ARGV[1] then return {'-2'} end
local ns = tonumber(ARGV[2])
local nn = tonumber(ARGV[3])
local report = redis.call('HGET', KEYS[1], 'status') or ''
local accepted = '1'
if (redis.call('HGET', KEYS[1], 'hasExp') or '0') == '1' then
  local es = tonumber(redis.call('HGET', KEYS[1], 'expSec') or '0')
  local en = tonumber(redis.call('HGET', KEYS[1], 'expNsec') or '0')
  if es < ns or (es == ns and en <= nn) then
    redis.call('HSET', KEYS[1], 'status', 'expired')
    report = 'expired'
    accepted = '0'
  end
end
if report == 'pending' then
  local interval = tonumber(redis.call('HGET', KEYS[1], 'interval') or '0')
  if not interval or interval <= 0 then interval = 5000000000 end
  local hasLast = redis.call('HGET', KEYS[1], 'hasLast') or '0'
  if hasLast == '1' then
    local ls = tonumber(redis.call('HGET', KEYS[1], 'lastSec') or '0')
    local ln = tonumber(redis.call('HGET', KEYS[1], 'lastNsec') or '0')
    local diff = (ns - ls) * 1000000000 + (nn - ln)
    if diff < interval then
      interval = interval + 5000000000
      redis.call('HSET', KEYS[1], 'interval', tostring(interval))
      accepted = '0'
    end
  end
  if accepted == '1' then
    redis.call('HSET', KEYS[1], 'lastSec', ARGV[2], 'lastNsec', ARGV[3], 'hasLast', '1')
  end
elseif report == 'approved' then
  redis.call('HSET', KEYS[1], 'status', 'used')
end
local out = {'0', report, accepted}
local flat = redis.call('HGETALL', KEYS[1])
for i = 1, #flat do out[#out + 1] = flat[i] end
return out
`)

// scriptDeviceSetStatus atomically approves or denies a pending device grant.
// KEYS: 1 user-code index.
// ARGV: 1 status, 2 now seconds, 3 now nanoseconds, 4 subject, 5 principal JSON,
// 6 DPoP key thumbprint, 7 whether to record the thumbprint.
// Returns {'-1'} for unknown, {'-2'} for expired and {'-3'} when not pending; otherwise
// {'0', flat field/value pairs}. | scriptDeviceSetStatus 原子批准或拒绝等待中的设备许可。
var scriptDeviceSetStatus = goredis.NewScript(`
local key = redis.call('GET', KEYS[1])
if not key then return {'-1'} end
if redis.call('EXISTS', key) == 0 then return {'-1'} end
if (redis.call('HGET', key, 'hasExp') or '0') == '1' then
  local es = tonumber(redis.call('HGET', key, 'expSec') or '0')
  local en = tonumber(redis.call('HGET', key, 'expNsec') or '0')
  local ns = tonumber(ARGV[2])
  local nn = tonumber(ARGV[3])
  if es < ns or (es == ns and en <= nn) then
    redis.call('HSET', key, 'status', 'expired')
    return {'-2'}
  end
end
if (redis.call('HGET', key, 'status') or '') ~= 'pending' then return {'-3'} end
redis.call('HSET', key, 'status', ARGV[1])
if ARGV[1] == 'approved' then
  redis.call('HSET', key, 'userID', ARGV[4], 'subject', ARGV[4], 'principal', ARGV[5])
  if ARGV[7] == '1' then redis.call('HSET', key, 'dpopJKT', ARGV[6]) end
end
local out = {'0'}
local flat = redis.call('HGETALL', key)
for i = 1, #flat do out[#out + 1] = flat[i] end
return out
`)

// scriptCleanupExpiring removes expired records from one set of full record keys.
// KEYS: 1 set whose members are full record keys in the same hash tag.
// ARGV: 1 now seconds, 2 now nanoseconds.
// Returns the number of removed records. | scriptCleanupExpiring 从记录键集合中删除过期记录。
var scriptCleanupExpiring = goredis.NewScript(`
local members = redis.call('SMEMBERS', KEYS[1])
local ns = tonumber(ARGV[1])
local nn = tonumber(ARGV[2])
local removed = 0
for _, key in ipairs(members) do
  if redis.call('EXISTS', key) == 0 then
    redis.call('SREM', KEYS[1], key)
  elseif (redis.call('HGET', key, 'hasExp') or '0') == '1' then
    local es = tonumber(redis.call('HGET', key, 'expSec') or '0')
    local en = tonumber(redis.call('HGET', key, 'expNsec') or '0')
    if es < ns or (es == ns and en <= nn) then
      redis.call('DEL', key)
      redis.call('SREM', KEYS[1], key)
      removed = removed + 1
    end
  end
end
return removed
`)

// scriptCleanupRefresh removes expired refresh tokens and their secondary index entries.
// KEYS: 1 all-tokens set.
// ARGV: 1 now seconds, 2 now nanoseconds.
// Returns the number of removed tokens. | scriptCleanupRefresh 删除过期刷新令牌及其二级索引条目。
var scriptCleanupRefresh = goredis.NewScript(`
local members = redis.call('SMEMBERS', KEYS[1])
local ns = tonumber(ARGV[1])
local nn = tonumber(ARGV[2])
local removed = 0
for _, key in ipairs(members) do
  if redis.call('EXISTS', key) == 0 then
    redis.call('SREM', KEYS[1], key)
  elseif (redis.call('HGET', key, 'hasExp') or '0') == '1' then
    local es = tonumber(redis.call('HGET', key, 'expSec') or '0')
    local en = tonumber(redis.call('HGET', key, 'expNsec') or '0')
    if es < ns or (es == ns and en <= nn) then
      local familyKey = redis.call('HGET', key, 'familySet')
      local subjectKey = redis.call('HGET', key, 'subjectSet')
      redis.call('DEL', key)
      redis.call('SREM', KEYS[1], key)
      if familyKey and familyKey ~= '' then redis.call('SREM', familyKey, key) end
      if subjectKey and subjectKey ~= '' then redis.call('SREM', subjectKey, key) end
      removed = removed + 1
    end
  end
end
return removed
`)

// scriptCleanupDevices removes expired device grants, their user-code index and set membership.
// KEYS: 1 all-devices set.
// ARGV: 1 now seconds, 2 now nanoseconds.
// Returns the number of removed grants. | scriptCleanupDevices 删除过期设备许可、用户码索引与集合成员。
var scriptCleanupDevices = goredis.NewScript(`
local members = redis.call('SMEMBERS', KEYS[1])
local ns = tonumber(ARGV[1])
local nn = tonumber(ARGV[2])
local removed = 0
for _, key in ipairs(members) do
  if redis.call('EXISTS', key) == 0 then
    redis.call('SREM', KEYS[1], key)
  elseif (redis.call('HGET', key, 'hasExp') or '0') == '1' then
    local es = tonumber(redis.call('HGET', key, 'expSec') or '0')
    local en = tonumber(redis.call('HGET', key, 'expNsec') or '0')
    if es < ns or (es == ns and en <= nn) then
      local indexKey = redis.call('HGET', key, 'userIndex')
      if indexKey and indexKey ~= '' then
        if redis.call('GET', indexKey) == key then redis.call('DEL', indexKey) end
      end
      redis.call('DEL', key)
      redis.call('SREM', KEYS[1], key)
      removed = removed + 1
    end
  end
end
return removed
`)

// scriptNonceIssue stores one DPoP nonce and enforces the configured capacity.
// KEYS: 1 nonce expiry hash, 2 expiry sorted set.
// ARGV: 1 nonce, 2 expSec, 3 expNsec, 4 nowSec, 5 nowNsec, 6 capacity.
// Returns 1 on success. | scriptNonceIssue 保存单个 DPoP nonce 并执行配置的容量上限。
var scriptNonceIssue = goredis.NewScript(`
local cap = tonumber(ARGV[6])
if cap and cap > 0 and redis.call('ZCARD', KEYS[2]) >= cap then
  local ns = tonumber(ARGV[4])
  local nn = tonumber(ARGV[5])
  local candidates = redis.call('ZRANGEBYSCORE', KEYS[2], '-inf', ns)
  for _, nonce in ipairs(candidates) do
    local value = redis.call('HGET', KEYS[1], nonce)
    if not value then
      redis.call('ZREM', KEYS[2], nonce)
    else
      local sep = string.find(value, ':')
      local es = tonumber(string.sub(value, 1, sep - 1))
      local en = tonumber(string.sub(value, sep + 1))
      if es < ns or (es == ns and en <= nn) then
        redis.call('HDEL', KEYS[1], nonce)
        redis.call('ZREM', KEYS[2], nonce)
      end
    end
  end
  while redis.call('ZCARD', KEYS[2]) >= cap do
    local popped = redis.call('ZPOPMIN', KEYS[2])
    if #popped == 0 then break end
    redis.call('HDEL', KEYS[1], popped[1])
  end
end
redis.call('HSET', KEYS[1], ARGV[1], ARGV[2] .. ':' .. ARGV[3])
redis.call('ZADD', KEYS[2], ARGV[2], ARGV[1])
return 1
`)

// scriptNonceAccept validates one DPoP nonce at an exact instant.
// KEYS: 1 nonce expiry hash, 2 expiry sorted set.
// ARGV: 1 nonce, 2 now seconds, 3 now nanoseconds.
// Returns 1 when valid and 0 when unknown or expired. | scriptNonceAccept 在精确时刻校验单个 DPoP nonce。
var scriptNonceAccept = goredis.NewScript(`
local value = redis.call('HGET', KEYS[1], ARGV[1])
if not value then return 0 end
local sep = string.find(value, ':')
local es = tonumber(string.sub(value, 1, sep - 1))
local en = tonumber(string.sub(value, sep + 1))
local ns = tonumber(ARGV[2])
local nn = tonumber(ARGV[3])
if es < ns or (es == ns and en <= nn) then
  redis.call('HDEL', KEYS[1], ARGV[1])
  redis.call('ZREM', KEYS[2], ARGV[1])
  return 0
end
return 1
`)

// scriptNoncePrune removes expired DPoP nonces.
// KEYS: 1 nonce expiry hash, 2 expiry sorted set.
// ARGV: 1 now seconds, 2 now nanoseconds.
// Returns the number of removed nonces. | scriptNoncePrune 删除过期 DPoP nonce。
var scriptNoncePrune = goredis.NewScript(`
local ns = tonumber(ARGV[1])
local nn = tonumber(ARGV[2])
local candidates = redis.call('ZRANGEBYSCORE', KEYS[2], '-inf', ns)
local removed = 0
for _, nonce in ipairs(candidates) do
  local value = redis.call('HGET', KEYS[1], nonce)
  if not value then
    redis.call('ZREM', KEYS[2], nonce)
  else
    local sep = string.find(value, ':')
    local es = tonumber(string.sub(value, 1, sep - 1))
    local en = tonumber(string.sub(value, sep + 1))
    if es < ns or (es == ns and en <= nn) then
      redis.call('HDEL', KEYS[1], nonce)
      redis.call('ZREM', KEYS[2], nonce)
      removed = removed + 1
    end
  end
end
return removed
`)

// scriptReplayAccept records one DPoP proof identifier until its expiry.
// KEYS: 1 jti key.
// ARGV: 1 expSec, 2 expNsec, 3 nowSec, 4 nowNsec, 5 ttl milliseconds.
// Returns 1 when the identifier is fresh and 0 on replay. | scriptReplayAccept 记录 DPoP 证明标识直到其过期。
var scriptReplayAccept = goredis.NewScript(`
local ns = tonumber(ARGV[3])
local nn = tonumber(ARGV[4])
local existing = redis.call('GET', KEYS[1])
if existing then
  local sep = string.find(existing, ':')
  local vs = tonumber(string.sub(existing, 1, sep - 1))
  local vn = tonumber(string.sub(existing, sep + 1))
  if vs > ns or (vs == ns and vn > nn) then return 0 end
  redis.call('DEL', KEYS[1])
end
local es = tonumber(ARGV[1])
local en = tonumber(ARGV[2])
if es > ns or (es == ns and en > nn) then
  local ttl = tonumber(ARGV[5])
  if not ttl or ttl < 1 then ttl = 1 end
  redis.call('SET', KEYS[1], ARGV[1] .. ':' .. ARGV[2], 'PX', ttl)
end
return 1
`)

// scriptScopeRegister atomically registers scopes whose names are not present yet.
// KEYS: 1 scope definitions hash, 2 registration-order list.
// ARGV: flat name/JSON pairs.
// Returns the number of newly registered scopes. | scriptScopeRegister 原子注册尚不存在的作用域。
var scriptScopeRegister = goredis.NewScript(`
local added = 0
local i = 1
while i <= #ARGV do
  if redis.call('HEXISTS', KEYS[1], ARGV[i]) == 0 then
    redis.call('HSET', KEYS[1], ARGV[i], ARGV[i + 1])
    redis.call('RPUSH', KEYS[2], ARGV[i])
    added = added + 1
  end
  i = i + 2
end
return added
`)

// scriptScopeReplace atomically replaces the whole scope registry.
// KEYS: 1 scope definitions hash, 2 registration-order list.
// ARGV: flat name/JSON pairs.
// Returns the number of registered scopes. | scriptScopeReplace 原子替换整个作用域注册表。
var scriptScopeReplace = goredis.NewScript(`
redis.call('DEL', KEYS[1], KEYS[2])
local i = 1
local added = 0
while i <= #ARGV do
  redis.call('HSET', KEYS[1], ARGV[i], ARGV[i + 1])
  redis.call('RPUSH', KEYS[2], ARGV[i])
  added = added + 1
  i = i + 2
end
return added
`)

// scriptScopeDelete atomically removes one scope definition and its order entry.
// KEYS: 1 scope definitions hash, 2 registration-order list.
// ARGV: 1 scope name.
// Returns 1 when the scope existed and 0 otherwise. | scriptScopeDelete 原子删除单个作用域定义及其顺序项。
var scriptScopeDelete = goredis.NewScript(`
if redis.call('HEXISTS', KEYS[1], ARGV[1]) == 0 then return 0 end
redis.call('HDEL', KEYS[1], ARGV[1])
redis.call('LREM', KEYS[2], 0, ARGV[1])
return 1
`)

// scriptScopeList atomically returns every scope definition in registration order.
// KEYS: 1 scope definitions hash, 2 registration-order list.
// Returns an array of definition JSON values. | scriptScopeList 按注册顺序原子返回全部作用域定义。
var scriptScopeList = goredis.NewScript(`
local names = redis.call('LRANGE', KEYS[2], 0, -1)
local out = {}
for _, name in ipairs(names) do
  local value = redis.call('HGET', KEYS[1], name)
  if value then out[#out + 1] = value end
end
return out
`)

// scriptClientCreate atomically creates one client registration.
// KEYS: 1 client hash, 2 all-clients set.
// ARGV: 1 data, 2 client ID.
// Returns 1 for a duplicate ID and 0 on success. | scriptClientCreate 原子创建单个客户端注册。
var scriptClientCreate = goredis.NewScript(`
if redis.call('EXISTS', KEYS[1]) == 1 then return 1 end
redis.call('HSET', KEYS[1], 'data', ARGV[1])
redis.call('SADD', KEYS[2], ARGV[2])
return 0
`)

// scriptClientUpdate atomically replaces one client registration.
// KEYS: 1 client hash.
// ARGV: 1 data.
// Returns 1 when the client is absent and 0 on success. | scriptClientUpdate 原子替换单个客户端注册。
var scriptClientUpdate = goredis.NewScript(`
if redis.call('EXISTS', KEYS[1]) == 0 then return 1 end
redis.call('HSET', KEYS[1], 'data', ARGV[1])
return 0
`)

// scriptClientDelete atomically removes one client registration and its set membership.
// KEYS: 1 client hash, 2 all-clients set.
// ARGV: 1 client ID.
// Returns 1 when the client is absent and 0 on success. | scriptClientDelete 原子删除单个客户端注册及其集合成员。
var scriptClientDelete = goredis.NewScript(`
if redis.call('EXISTS', KEYS[1]) == 0 then return 1 end
redis.call('DEL', KEYS[1])
redis.call('SREM', KEYS[2], ARGV[1])
return 0
`)

// scriptClientList atomically returns every client registration JSON value.
// KEYS: 1 all-clients set.
// ARGV: 1 length-prefixed client key prefix.
// Returns an array of registration JSON values. | scriptClientList 原子返回全部客户端注册 JSON 值。
var scriptClientList = goredis.NewScript(`
local ids = redis.call('SMEMBERS', KEYS[1])
local out = {}
for _, id in ipairs(ids) do
  local key = ARGV[1] .. string.len(id) .. ':' .. id
  local value = redis.call('HGET', key, 'data')
  if value then out[#out + 1] = value end
end
return out
`)
