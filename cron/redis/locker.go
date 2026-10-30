package redis

import (
	"context"
	"time"

	goredis "github.com/redis/go-redis/v9"

	"github.com/shibingli/ydx/cron"
	"github.com/shibingli/ydx/errs"
)

// unlockLua releases the key only when the caller still owns it. |
// unlockLua 仅当调用方仍持有时释放键。
const unlockLua = `
if redis.call("GET", KEYS[1]) == ARGV[1] then
	return redis.call("DEL", KEYS[1])
end
return 0
`

// refreshLua extends the key only when the caller still owns it. |
// refreshLua 仅当调用方仍持有时延长键。
const refreshLua = `
if redis.call("GET", KEYS[1]) == ARGV[1] then
	return redis.call("PEXPIRE", KEYS[1], ARGV[2])
end
return 0
`

// Locker implements cron.Locker with Redis SET NX PX claims. |
// Locker 用 Redis SET NX PX 实现 cron.Locker。
type Locker struct {
	client goredis.UniversalClient
}

// NewLocker wraps a Redis client as a cron Locker. | NewLocker 把 Redis 客户端包装为 cron Locker。
func NewLocker(client goredis.UniversalClient) *Locker { return &Locker{client: client} }

// TryLock claims key with SET NX PX. | TryLock 用 SET NX PX 抢占 key。
func (l *Locker) TryLock(ctx context.Context, key string, ttl time.Duration) (cron.Lock, bool, error) {
	if l == nil || l.client == nil {
		return nil, false, ErrNilClient
	}
	if ctx == nil {
		ctx = context.Background()
	}
	if ttl <= 0 {
		ttl = defaultLockTTL
	}
	if ttl < time.Millisecond {
		ttl = time.Millisecond
	}
	token, err := newToken()
	if err != nil {
		return nil, false, errs.WrapDetail(err, cron.ErrLockFailed, "%q", key)
	}
	acquired, err := l.client.SetNX(ctx, key, token, ttl).Result()
	if err != nil {
		return nil, false, errs.WrapDetail(err, cron.ErrLockFailed, "%q", key)
	}
	if !acquired {
		return nil, false, nil
	}
	return &lock{client: l.client, key: key, token: token}, true, nil
}

// lock is one Redis-backed claim. | lock 是一个 Redis 支撑的锁。
type lock struct {
	client goredis.UniversalClient
	key    string
	token  string
}

// Unlock deletes the key only when this owner still holds it. |
// Unlock 仅在本持有者仍持有时删除键。
func (l *lock) Unlock(ctx context.Context) error {
	if l == nil || l.client == nil {
		return ErrNilClient
	}
	if ctx == nil {
		ctx = context.Background()
	}
	if err := l.client.Eval(ctx, unlockLua, []string{l.key}, l.token).Err(); err != nil {
		return errs.WrapDetail(err, cron.ErrLockFailed, "%q", l.key)
	}
	return nil
}

// Refresh extends the key only when this owner still holds it. |
// Refresh 仅在本持有者仍持有时延长键。
func (l *lock) Refresh(ctx context.Context, ttl time.Duration) (bool, error) {
	if l == nil || l.client == nil {
		return false, ErrNilClient
	}
	if ctx == nil {
		ctx = context.Background()
	}
	if ttl <= 0 {
		ttl = defaultLockTTL
	}
	if ttl < time.Millisecond {
		ttl = time.Millisecond
	}
	extended, err := l.client.Eval(ctx, refreshLua, []string{l.key}, l.token, ttl.Milliseconds()).Int()
	if err != nil {
		return false, errs.WrapDetail(err, cron.ErrLockFailed, "%q", l.key)
	}
	return extended == 1, nil
}

// compile-time assertions for the Redis implementations. | Redis 实现的编译期断言。
var (
	_ cron.Locker        = (*Locker)(nil)
	_ cron.Lock          = (*lock)(nil)
	_ cron.LockRefresher = (*lock)(nil)
)
