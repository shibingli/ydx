package oidc

import goredis "github.com/redis/go-redis/v9"

// The scripts below are the atomicity boundary of the logout replay store. Every script touches a
// single key carrying the shared hash tag, so Redis Cluster routes it to one slot. Comments list the
// KEYS and ARGV contract. | 下面的脚本是登出重放存储的原子性边界。每个脚本只访问一个携带共享
// 哈希标签的键，因此 Redis Cluster 会把它路由到单一槽位。注释列出 KEYS 与 ARGV 约定。

// scriptAccept atomically records one logout-token identifier until its deadline.
// KEYS: 1 replay key.
// ARGV: 1 absolute deadline in Unix milliseconds, 2 fallback lifetime in milliseconds.
// Returns 1 for a fresh identifier and 0 for a live replay. If the supplied deadline already
// elapsed at the Redis clock, the script stores the Redis clock plus the fallback lifetime instead,
// so application clock skew cannot create an immediately vanished replay record. The stored value
// is the deadline, so an identifier whose TTL was removed administratively still expires at the
// intended instant. | scriptAccept 原子记录单个登出令牌标识直至其期限。
var scriptAccept = goredis.NewScript(`
local now = redis.call('TIME')
local nowMillis = tonumber(now[1]) * 1000 + math.floor(tonumber(now[2]) / 1000)
local current = redis.call('GET', KEYS[1])
if current then
  local deadline = tonumber(current)
  if deadline and deadline > nowMillis then return 0 end
end
local value = ARGV[1]
local deadline = tonumber(ARGV[1])
if not deadline or deadline <= nowMillis then
  value = string.format('%.0f', nowMillis + tonumber(ARGV[2]))
end
redis.call('SET', KEYS[1], value)
redis.call('PEXPIREAT', KEYS[1], value)
return 1
`)
