package webauthn

import goredis "github.com/redis/go-redis/v9"

// scriptConsumeChallenge atomically reads and deletes one ceremony. Redis executes the script as
// one unit, so exactly one concurrent caller can observe a stored ceremony. | scriptConsumeChallenge
// 原子读取并删除单个流程。Redis 以单元方式执行脚本，因此并发调用中只有一个能观察到已存流程。
//
// KEYS: 1 challenge string.
// Returns {0} when absent and {1, value} when a ceremony was consumed.
// | KEYS：1 为挑战字符串。不存在返回 {0}，消费成功返回 {1, value}。
var scriptConsumeChallenge = goredis.NewScript(`
local value = redis.call('GET', KEYS[1])
if not value then return {0} end
redis.call('DEL', KEYS[1])
return {1, value}
`)

// scriptSaveCredential atomically creates one credential hash and its user index membership.
// KEYS: 1 credential hash, 2 user index set.
// ARGV: 1 data, 2 sign count, 3 backup-state flag, 4 credential member key.
// Returns 1 when created and 0 when the credential ID already exists.
// | scriptSaveCredential 原子创建单个凭据哈希及其用户索引成员。创建返回 1，凭据 ID 已存在返回 0。
var scriptSaveCredential = goredis.NewScript(`
if redis.call('EXISTS', KEYS[1]) == 1 then return 0 end
redis.call('HSET', KEYS[1], 'data', ARGV[1], 'signCount', ARGV[2], 'backupState', ARGV[3])
redis.call('SADD', KEYS[2], ARGV[4])
return 1
`)

// scriptUpdateSignCount atomically replaces the authoritative signature counter.
// KEYS: 1 credential hash. ARGV: 1 sign count.
// Returns 1 when updated and 0 when the credential is absent.
// | scriptUpdateSignCount 原子替换权威签名计数器。更新返回 1，凭据不存在返回 0。
var scriptUpdateSignCount = goredis.NewScript(`
if redis.call('EXISTS', KEYS[1]) == 0 then return 0 end
redis.call('HSET', KEYS[1], 'signCount', ARGV[1])
return 1
`)

// scriptUpdateBackupState atomically replaces the authoritative BS flag.
// KEYS: 1 credential hash. ARGV: 1 backup-state flag.
// Returns 1 when updated and 0 when the credential is absent.
// | scriptUpdateBackupState 原子替换权威 BS 标志。更新返回 1，凭据不存在返回 0。
var scriptUpdateBackupState = goredis.NewScript(`
if redis.call('EXISTS', KEYS[1]) == 0 then return 0 end
redis.call('HSET', KEYS[1], 'backupState', ARGV[1])
return 1
`)
