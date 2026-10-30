// Package redis adapts Redis to the cron module's distributed Locker and
// shared Store, so a cluster of schedulers can coordinate without any other
// dependency. | Package redis 把 Redis 适配为 cron 模块的分布式 Locker 与共享 Store，
// 使调度器集群无需其它依赖即可协调。
//
// Locker claims one key per scheduled fire with SET NX PX; the key is refreshed
// while the run is in flight and deliberately left to expire afterwards so its
// TTL doubles as the deduplication window. Store keeps every definition in one
// hash, serialized with github.com/shibingli/ydx/json. Both accept any
// go-redis UniversalClient, including one built by github.com/shibingli/ydx/redis. |
// Locker 用 SET NX PX 为每次计划触发抢占一个键；运行期间自动续租，结束后刻意保留到 TTL
// 过期，使 TTL 同时充当去重窗口。Store 用一个哈希保存全部定义，并由
// github.com/shibingli/ydx/json 序列化。两者都接受任意 go-redis UniversalClient，
// 包括 github.com/shibingli/ydx/redis 构建的客户端。
//
// Usage | 用法：
//
//	client, err := redisx.Open(redisx.Options{Addr: "127.0.0.1:6379"})
//	if err != nil { return err }
//	scheduler := cron.New(cron.Options{
//		Namespace: "billing",
//		Locker:    cronredis.NewLocker(client),
//		Store:     cronredis.NewStore(client, "billing"),
//	})
package redis

import (
	"crypto/rand"
	"encoding/hex"
	"time"

	"github.com/shibingli/ydx/errs"
)

// ErrNilClient indicates a nil Redis client was passed to an adapter. |
// ErrNilClient 表示传给适配器的 Redis 客户端为 nil。
var ErrNilClient = errs.New("cron redis: nil redis client | cron redis：Redis 客户端为 nil")

// defaultLockTTL is used when a claim carries a non-positive TTL. |
// defaultLockTTL 在锁 TTL 非正时使用。
const defaultLockTTL = 30 * time.Second

// newToken returns a random 128-bit owner token. | newToken 返回 128 位随机持有者令牌。
func newToken() (string, error) {
	var raw [16]byte
	if _, err := rand.Read(raw[:]); err != nil {
		return "", err
	}
	return hex.EncodeToString(raw[:]), nil
}
