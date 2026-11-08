package rbac

import goredis "github.com/redis/go-redis/v9"

// The scripts below are the atomicity boundary of the Redis store. Every script touches only keys
// that share one hash tag, so Redis Cluster routes them to a single slot. Comments in each script
// list the KEYS and ARGV contract. | 下面的脚本是 Redis 存储的原子性边界。每个脚本只访问共享同一
// 哈希标签的键，因此 Redis Cluster 会把它们路由到单一槽位。每个脚本内的注释列出 KEYS 与 ARGV 约定。

// luaHelpers defines the length-prefixed list codec shared by the scripts. The same encoding is
// produced by encodeList in Go, so values written by either side remain readable by the other.
// | luaHelpers 定义脚本共享的长度前缀列表编解码器。Go 侧的 encodeList 产生相同编码，因此任一侧写入
// 的值都可被另一侧读取。
const luaHelpers = `
local function parseList(encoded)
  local out = {}
  local pos = 1
  local size = #encoded
  while pos <= size do
    local colon = string.find(encoded, ':', pos, true)
    if not colon then break end
    local length = tonumber(string.sub(encoded, pos, colon - 1))
    if not length or length < 0 then break end
    out[#out + 1] = string.sub(encoded, colon + 1, colon + length)
    pos = colon + 1 + length
  end
  return out
end

local function encodeList(items)
  local parts = {}
  for _, item in ipairs(items) do
    parts[#parts + 1] = tostring(#item) .. ':' .. item
  end
  return table.concat(parts)
end

local function parseExpiry(encoded)
  local first = string.find(encoded, ':', 1, true)
  if not first then return '0', 0, 0 end
  local second = string.find(encoded, ':', first + 1, true)
  if not second then return '0', 0, 0 end
  return string.sub(encoded, 1, first - 1),
    tonumber(string.sub(encoded, first + 1, second - 1)) or 0,
    tonumber(string.sub(encoded, second + 1)) or 0
end
`

// scriptRoleAdd atomically stores one role after checking its name and inheritance graph.
// KEYS: 1 roles hash, 2 role-parents hash.
// ARGV: 1 name, 2 data, 3 encoded parent list.
// Returns 1 for a duplicate name, 2 for an inheritance cycle and 0 on success.
// | scriptRoleAdd 在校验名称与继承图后原子保存单个角色。
var scriptRoleAdd = goredis.NewScript(luaHelpers + `
if redis.call('HEXISTS', KEYS[1], ARGV[1]) == 1 then return 1 end
local stack = parseList(ARGV[3])
local visited = {}
while #stack > 0 do
  local current = table.remove(stack)
  if current == ARGV[1] then return 2 end
  if not visited[current] then
    visited[current] = true
    local encoded = redis.call('HGET', KEYS[2], current)
    if encoded then
      for _, parent in ipairs(parseList(encoded)) do
        stack[#stack + 1] = parent
      end
    end
  end
end
redis.call('HSET', KEYS[1], ARGV[1], ARGV[2])
if ARGV[3] == '' then
  redis.call('HDEL', KEYS[2], ARGV[1])
else
  redis.call('HSET', KEYS[2], ARGV[1], ARGV[3])
end
return 0
`)

// scriptRoleRemove atomically removes one role, its assignments and every parent reference to it.
// KEYS: 1 roles hash, 2 role-parents hash, 3 assignments hash, 4 assignment-expiry hash,
// 5 assignment-subjects set.
// ARGV: 1 name, 2 per-subject assignment index key prefix.
// Returns 1 when the role is absent and 0 on success.
// | scriptRoleRemove 原子删除单个角色、其分配以及所有指向它的父角色引用。
var scriptRoleRemove = goredis.NewScript(luaHelpers + `
if redis.call('HEXISTS', KEYS[1], ARGV[1]) == 0 then return 1 end
redis.call('HDEL', KEYS[1], ARGV[1])
redis.call('HDEL', KEYS[2], ARGV[1])
local roles = redis.call('HKEYS', KEYS[2])
for _, role in ipairs(roles) do
  local encoded = redis.call('HGET', KEYS[2], role)
  if encoded then
    local parents = parseList(encoded)
    local kept = {}
    local changed = false
    for _, parent in ipairs(parents) do
      if parent == ARGV[1] then
        changed = true
      else
        kept[#kept + 1] = parent
      end
    end
    if changed then
      if #kept == 0 then
        redis.call('HDEL', KEYS[2], role)
      else
        redis.call('HSET', KEYS[2], role, encodeList(kept))
      end
    end
  end
end
local identifiers = redis.call('HKEYS', KEYS[3])
for _, identifier in ipairs(identifiers) do
  local parts = parseList(identifier)
  if #parts >= 2 and parts[2] == ARGV[1] then
    redis.call('HDEL', KEYS[3], identifier)
    redis.call('HDEL', KEYS[4], identifier)
    local subject = parts[1]
    local indexKey = ARGV[2] .. #subject .. ':' .. subject
    redis.call('SREM', indexKey, identifier)
    if redis.call('SCARD', indexKey) == 0 then
      redis.call('DEL', indexKey)
      redis.call('SREM', KEYS[5], subject)
    end
  end
end
return 0
`)

// scriptAssignmentAdd atomically stores one assignment, replacing an expired duplicate.
// KEYS: 1 assignments hash, 2 assignment-expiry hash, 3 per-subject index set,
// 4 assignment-subjects set, 5 roles hash.
// ARGV: 1 identifier, 2 data, 3 role, 4 encoded deadline, 5 subject, 6 now seconds,
// 7 now nanoseconds.
// Returns 1 for an active duplicate, 2 for an unknown role and 0 on success.
// | scriptAssignmentAdd 原子保存单条分配，并替换已过期的重复项。
var scriptAssignmentAdd = goredis.NewScript(luaHelpers + `
if redis.call('HEXISTS', KEYS[5], ARGV[3]) == 0 then return 2 end
if redis.call('HEXISTS', KEYS[1], ARGV[1]) == 1 then
  local encoded = redis.call('HGET', KEYS[2], ARGV[1])
  if not encoded then return 1 end
  local hasExpiry, seconds, nanoseconds = parseExpiry(encoded)
  if hasExpiry ~= '1' then return 1 end
  local nowSeconds = tonumber(ARGV[6])
  local nowNanoseconds = tonumber(ARGV[7])
  if not (seconds < nowSeconds or (seconds == nowSeconds and nanoseconds <= nowNanoseconds)) then
    return 1
  end
end
redis.call('HSET', KEYS[1], ARGV[1], ARGV[2])
redis.call('HSET', KEYS[2], ARGV[1], ARGV[4])
redis.call('SADD', KEYS[3], ARGV[1])
redis.call('SADD', KEYS[4], ARGV[5])
return 0
`)

// scriptAssignmentRemove atomically removes one exact assignment and its index memberships.
// KEYS: 1 assignments hash, 2 assignment-expiry hash, 3 per-subject index set,
// 4 assignment-subjects set.
// ARGV: 1 identifier, 2 subject.
// Returns 1 when the assignment is absent and 0 on success.
// | scriptAssignmentRemove 原子删除一条完全匹配的分配及其索引成员关系。
var scriptAssignmentRemove = goredis.NewScript(`
if redis.call('HEXISTS', KEYS[1], ARGV[1]) == 0 then return 1 end
redis.call('HDEL', KEYS[1], ARGV[1])
redis.call('HDEL', KEYS[2], ARGV[1])
redis.call('SREM', KEYS[3], ARGV[1])
if redis.call('SCARD', KEYS[3]) == 0 then
  redis.call('DEL', KEYS[3])
  redis.call('SREM', KEYS[4], ARGV[2])
end
return 0
`)

// scriptSubjectAssignments atomically reads every assignment of one subject.
// KEYS: 1 per-subject index set, 2 assignments hash.
// Returns a flat array of identifier, data pairs in unspecified order.
// | scriptSubjectAssignments 原子读取单个主体的全部角色分配。
var scriptSubjectAssignments = goredis.NewScript(`
local identifiers = redis.call('SMEMBERS', KEYS[1])
local out = {}
for _, identifier in ipairs(identifiers) do
  local data = redis.call('HGET', KEYS[2], identifier)
  if data then
    out[#out + 1] = identifier
    out[#out + 1] = data
  end
end
return out
`)

// scriptPolicyAdd atomically stores one policy.
// KEYS: 1 policies hash.
// ARGV: 1 identifier, 2 data.
// Returns 1 for a duplicate identifier and 0 on success.
// | scriptPolicyAdd 原子保存单条策略。
var scriptPolicyAdd = goredis.NewScript(`
if redis.call('HEXISTS', KEYS[1], ARGV[1]) == 1 then return 1 end
redis.call('HSET', KEYS[1], ARGV[1], ARGV[2])
return 0
`)

// scriptPolicyRemove atomically removes one policy.
// KEYS: 1 policies hash.
// ARGV: 1 identifier.
// Returns 1 when the policy is absent and 0 on success.
// | scriptPolicyRemove 原子删除单条策略。
var scriptPolicyRemove = goredis.NewScript(`
if redis.call('HEXISTS', KEYS[1], ARGV[1]) == 0 then return 1 end
redis.call('HDEL', KEYS[1], ARGV[1])
return 0
`)

// scriptReset atomically removes every role, assignment and policy, including the per-subject
// index keys. KEYS: 1 roles hash, 2 role-parents hash, 3 assignments hash, 4 assignment-expiry
// hash, 5 assignment-subjects set, 6 policies hash.
// ARGV: 1 per-subject assignment index key prefix.
// Returns the number of removed subject index sets.
// | scriptReset 原子删除所有角色、分配与策略，包括按主体的索引键。
var scriptReset = goredis.NewScript(`
local subjects = redis.call('SMEMBERS', KEYS[5])
for _, subject in ipairs(subjects) do
  redis.call('DEL', ARGV[1] .. #subject .. ':' .. subject)
end
redis.call('DEL', KEYS[1], KEYS[2], KEYS[3], KEYS[4], KEYS[5], KEYS[6])
return #subjects
`)
