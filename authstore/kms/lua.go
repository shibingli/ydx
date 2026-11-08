package kms

import goredis "github.com/redis/go-redis/v9"

// The scripts below are the atomicity boundary of the Redis store. Every key of the store shares
// one hash tag, so Redis Cluster routes every script to a single slot, including alias keys that
// the delete scripts build from set members. Comments in each script list the KEYS and ARGV
// contract. | 下面的脚本是 Redis 存储的原子性边界。存储的每个键共享同一个哈希标签，因此 Redis
// Cluster 会把每个脚本路由到单一槽位，包括删除脚本从集合成员动态构造的别名键。每个脚本内的注释
// 列出 KEYS 与 ARGV 约定。

// scriptKeyCreate atomically creates one key, its versions, its primary alias and its all-keys
// index entry. | scriptKeyCreate 原子创建单个密钥、其版本、主别名与全部键索引条目。
//
// KEYS: 1 key hash, 2 versions hash, 3 all-keys sorted set, 4 primary alias key (or dummy),
// 5 alias reverse set.
// ARGV: 1 id, 2 key data, 3 revision, 4 creation score, 5 primary alias, 6 has-alias flag,
// 7 version count, then version/version-data pairs from 8.
// Returns 1 for a duplicate key, 2 for an alias bound to another key, 0 on success.
// | KEYS：1 密钥哈希，2 版本哈希，3 全部键有序集合，4 主别名键（或 dummy），5 别名反向集合。
// ARGV：1 标识，2 密钥数据，3 修订号，4 创建评分，5 主别名，6 别名存在标志，7 版本数量，从 8 起
// 为版本号/版本数据对。重复密钥返回 1，别名绑定到其它密钥返回 2，成功返回 0。
var scriptKeyCreate = goredis.NewScript(`
if redis.call('EXISTS', KEYS[1]) == 1 then return 1 end
if ARGV[6] == '1' then
  local owner = redis.call('GET', KEYS[4])
  if owner and owner ~= ARGV[1] then return 2 end
end
redis.call('HSET', KEYS[1], 'data', ARGV[2], 'revision', ARGV[3], 'alias', ARGV[5], 'createdAt', ARGV[4])
local count = tonumber(ARGV[7])
for i = 1, count do
  redis.call('HSET', KEYS[2], ARGV[7 + i * 2 - 1], ARGV[7 + i * 2])
end
redis.call('ZADD', KEYS[3], ARGV[4], ARGV[1])
if ARGV[6] == '1' then
  redis.call('SET', KEYS[4], ARGV[1])
  redis.call('SADD', KEYS[5], ARGV[5])
end
return 0
`)

// scriptKeyUpdate atomically replaces one key and its versions, using the stored revision and
// primary alias as compare-and-set guards. | scriptKeyUpdate 原子替换单个密钥及其版本，并以已存
// 修订号与主别名作为比较并交换守卫。
//
// KEYS: 1 key hash, 2 versions hash, 3 all-keys sorted set, 4 alias reverse set,
// 5 new primary alias key (or dummy), 6 old primary alias key (or dummy).
// ARGV: 1 id, 2 expected revision, 3 new revision, 4 key data, 5 creation score, 6 new alias,
// 7 has-new-alias flag, 8 old alias, 9 has-old-alias flag, 10 version count, then
// version/version-data pairs from 11.
// Returns 1 when absent, 2 on a compare-and-set mismatch, 3 on a conflicting alias, 0 on success.
// | KEYS：1 密钥哈希，2 版本哈希，3 全部键有序集合，4 别名反向集合，5 新主别名键（或 dummy），
// 6 旧主别名键（或 dummy）。ARGV：1 标识，2 期望修订号，3 新修订号，4 密钥数据，5 创建评分，
// 6 新别名，7 新别名存在标志，8 旧别名，9 旧别名存在标志，10 版本数量，从 11 起为版本号/版本
// 数据对。缺失返回 1，比较并交换不匹配返回 2，别名冲突返回 3，成功返回 0。
var scriptKeyUpdate = goredis.NewScript(`
if redis.call('EXISTS', KEYS[1]) == 0 then return 1 end
if (redis.call('HGET', KEYS[1], 'revision') or '') ~= ARGV[2] then return 2 end
if (redis.call('HGET', KEYS[1], 'alias') or '') ~= ARGV[8] then return 2 end
local aliasChanged = ARGV[6] ~= ARGV[8]
if aliasChanged and ARGV[7] == '1' then
  local owner = redis.call('GET', KEYS[5])
  if owner and owner ~= ARGV[1] then return 3 end
end
if aliasChanged and ARGV[9] == '1' then
  local owner = redis.call('GET', KEYS[6])
  if owner == ARGV[1] then
    redis.call('DEL', KEYS[6])
    redis.call('SREM', KEYS[4], ARGV[8])
  end
end
redis.call('DEL', KEYS[2])
local count = tonumber(ARGV[10])
for i = 1, count do
  redis.call('HSET', KEYS[2], ARGV[10 + i * 2 - 1], ARGV[10 + i * 2])
end
redis.call('HSET', KEYS[1], 'data', ARGV[4], 'revision', ARGV[3], 'alias', ARGV[6], 'createdAt', ARGV[5])
redis.call('ZADD', KEYS[3], ARGV[5], ARGV[1])
if aliasChanged and ARGV[7] == '1' then
  redis.call('SET', KEYS[5], ARGV[1])
  redis.call('SADD', KEYS[4], ARGV[6])
end
return 0
`)

// scriptKeyDelete atomically removes one key, its versions, every alias bound to it and its
// all-keys index entry. | scriptKeyDelete 原子删除单个密钥、其版本、绑定到它的全部别名与全部键
// 索引条目。
//
// KEYS: 1 key hash, 2 versions hash, 3 all-keys sorted set, 4 alias reverse set.
// ARGV: 1 alias key prefix, 2 id.
// Returns 1 when absent and 0 on success.
// | KEYS：1 密钥哈希，2 版本哈希，3 全部键有序集合，4 别名反向集合。ARGV：1 别名键前缀，2 标识。
// 缺失返回 1，成功返回 0。
var scriptKeyDelete = goredis.NewScript(`
if redis.call('EXISTS', KEYS[1]) == 0 then return 1 end
local aliases = redis.call('SMEMBERS', KEYS[4])
for _, alias in ipairs(aliases) do
  local aliasKey = ARGV[1] .. string.len(alias) .. ':' .. alias
  if redis.call('GET', aliasKey) == ARGV[2] then redis.call('DEL', aliasKey) end
end
redis.call('DEL', KEYS[1], KEYS[2], KEYS[4])
redis.call('ZREM', KEYS[3], ARGV[2])
return 0
`)

// scriptSetAlias atomically binds one alias to an existing key. | scriptSetAlias 原子地把单个别名
// 绑定到已存在的密钥。
//
// KEYS: 1 key hash, 2 alias key, 3 alias reverse set.
// ARGV: 1 alias, 2 id.
// Returns 1 when the key is absent, 2 when the alias is bound to another key, 0 on success.
// | KEYS：1 密钥哈希，2 别名键，3 别名反向集合。ARGV：1 别名，2 标识。密钥缺失返回 1，别名
// 已绑定到其它密钥返回 2，成功返回 0。
var scriptSetAlias = goredis.NewScript(`
if redis.call('EXISTS', KEYS[1]) == 0 then return 1 end
local owner = redis.call('GET', KEYS[2])
if owner and owner ~= ARGV[2] then return 2 end
redis.call('SET', KEYS[2], ARGV[2])
redis.call('SADD', KEYS[3], ARGV[1])
return 0
`)

// scriptDeleteAlias atomically removes one alias and its reverse index membership.
// | scriptDeleteAlias 原子删除单个别名及其反向索引成员关系。
//
// KEYS: 1 alias key.
// ARGV: 1 alias key prefix, 2 alias.
// Returns 1 when the alias is absent and 0 on success.
// | KEYS：1 别名键。ARGV：1 别名键前缀，2 别名。别名缺失返回 1，成功返回 0。
var scriptDeleteAlias = goredis.NewScript(`
local id = redis.call('GET', KEYS[1])
if not id then return 1 end
redis.call('DEL', KEYS[1])
local reverseKey = ARGV[1] .. string.len(id) .. ':' .. id
redis.call('SREM', reverseKey, ARGV[2])
return 0
`)

// scriptSaveVersion atomically appends one version and increments the key revision.
// | scriptSaveVersion 原子追加单个版本并递增密钥修订号。
//
// KEYS: 1 key hash, 2 versions hash.
// ARGV: 1 version field, 2 version data.
// Returns 1 when the key is absent, 2 when the version already exists, 0 on success.
// | KEYS：1 密钥哈希，2 版本哈希。ARGV：1 版本字段，2 版本数据。密钥缺失返回 1，版本已存在
// 返回 2，成功返回 0。
var scriptSaveVersion = goredis.NewScript(`
if redis.call('EXISTS', KEYS[1]) == 0 then return 1 end
if redis.call('HEXISTS', KEYS[2], ARGV[1]) == 1 then return 2 end
redis.call('HSET', KEYS[2], ARGV[1], ARGV[2])
redis.call('HINCRBY', KEYS[1], 'revision', 1)
return 0
`)

// scriptAuditAppend allocates a sequence number, stores the event and indexes it by time.
// | scriptAuditAppend 分配序号、保存事件并按时间建立索引。
//
// KEYS: 1 sequence counter, 2 event hash, 3 time sorted set.
// ARGV: 1 event data, 2 score.
// | KEYS：1 序号计数器，2 事件哈希，3 时间有序集合。ARGV：1 事件数据，2 评分。
var scriptAuditAppend = goredis.NewScript(`
local seq = redis.call('INCR', KEYS[1])
redis.call('HSET', KEYS[2], tostring(seq), ARGV[1])
redis.call('ZADD', KEYS[3], ARGV[2], tostring(seq))
return seq
`)
