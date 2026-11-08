package federation

import goredis "github.com/redis/go-redis/v9"

// The scripts below are the atomicity boundary of the federation state store. Every script touches a
// single key carrying the shared hash tag, so Redis Cluster routes it to one slot. Comments list the
// KEYS and ARGV contract. | 下面的脚本是联合登录 state 存储的原子性边界。每个脚本只访问一个携带
// 共享哈希标签的键，因此 Redis Cluster 会把它路由到单一槽位。注释列出 KEYS 与 ARGV 约定。

// scriptSave atomically stores one live state record.
// KEYS: 1 state hash.
// ARGV: 1 data, 2 expiry second, 3 expiry nanosecond, 4 absolute key deadline in Unix milliseconds.
// Returns 0 for a live duplicate, -1 when the new record is already expired at the Redis clock and
// 1 on success. The live duplicate check precedes the new-record expiry check, matching
// MemoryStateStore's error precedence. An existing record whose logical deadline passed may be
// replaced even though its key is still present for error classification.
// | scriptSave 原子保存单个有效 state 记录。
var scriptSave = goredis.NewScript(`
local now = redis.call('TIME')
local nowSec = tonumber(now[1])
local nowNsec = tonumber(now[2]) * 1000
local expSec = tonumber(ARGV[2])
local expNsec = tonumber(ARGV[3])
if redis.call('EXISTS', KEYS[1]) == 1 then
  local oldSec = tonumber(redis.call('HGET', KEYS[1], 'expSec') or '0')
  local oldNsec = tonumber(redis.call('HGET', KEYS[1], 'expNsec') or '0')
  if oldSec > nowSec or (oldSec == nowSec and oldNsec > nowNsec) then return 0 end
end
if expSec < nowSec or (expSec == nowSec and expNsec <= nowNsec) then return -1 end
redis.call('HSET', KEYS[1],
  'data', ARGV[1], 'expSec', ARGV[2], 'expNsec', ARGV[3])
redis.call('PEXPIREAT', KEYS[1], ARGV[4])
return 1
`)

// scriptConsume atomically removes and returns one state record.
// KEYS: 1 state hash.
// Returns status -1 for an unknown state, -2 for an expired state and 0 with the record data on
// success.
// Expired records are deleted on discovery.
// | scriptConsume 原子删除并返回单个 state 记录。发现过期记录时将其删除。
var scriptConsume = goredis.NewScript(`
local data = redis.call('HGET', KEYS[1], 'data')
if not data then
  if redis.call('EXISTS', KEYS[1]) == 1 then redis.call('DEL', KEYS[1]) end
  return {'-1', ''}
end
local now = redis.call('TIME')
local nowSec = tonumber(now[1])
local nowNsec = tonumber(now[2]) * 1000
local expSec = tonumber(redis.call('HGET', KEYS[1], 'expSec') or '0')
local expNsec = tonumber(redis.call('HGET', KEYS[1], 'expNsec') or '0')
redis.call('DEL', KEYS[1])
if expSec < nowSec or (expSec == nowSec and expNsec <= nowNsec) then
  return {'-2', ''}
end
return {'0', data}
`)
