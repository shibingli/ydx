package wsfed

import goredis "github.com/redis/go-redis/v9"

// scriptTakeRequest atomically reads and deletes one request record. Redis executes the script as
// one unit, so exactly one concurrent caller can observe a stored request. | scriptTakeRequest
// 原子读取并删除单条请求记录。Redis 以单元方式执行脚本，因此并发调用中只有一个能观察到已存请求。
//
// KEYS: 1 request string.
// Returns {0} when absent and {1, value} when a record was consumed.
// | KEYS：1 为请求字符串。不存在返回 {0}，消费成功返回 {1, value}。
var scriptTakeRequest = goredis.NewScript(`
local value = redis.call('GET', KEYS[1])
if not value then return {0} end
redis.call('DEL', KEYS[1])
return {1, value}
`)
