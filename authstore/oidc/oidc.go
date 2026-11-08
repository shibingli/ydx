package oidc

import (
	"context"
	"errors"
	"strconv"
	"strings"
	"time"

	goredis "github.com/redis/go-redis/v9"

	"github.com/shibingli/ydx/auth"
	authoidc "github.com/shibingli/ydx/auth/protocol/oidc"
	"github.com/shibingli/ydx/errs"
)

// DefaultKeyPrefix is the key namespace used when Options.KeyPrefix is empty.
// | DefaultKeyPrefix 是 Options.KeyPrefix 为空时使用的键命名空间。
const DefaultKeyPrefix = "ydx:authstore:oidc:"

// defaultReplayTTL is used when Accept receives an absent or already elapsed deadline, matching
// MemoryLogoutReplayStore. | defaultReplayTTL 在 Accept 收到缺失或已经过去的期限时使用，与
// MemoryLogoutReplayStore 一致。
const defaultReplayTTL = 5 * time.Minute

// ErrStoreUnavailable reports a Redis backend failure. The error deliberately carries no address,
// DSN or credential text. | ErrStoreUnavailable 表示 Redis 后端故障。该错误有意不携带地址、DSN
// 或凭据文本。
var ErrStoreUnavailable = errs.New("authstore/oidc: store unavailable | authstore/oidc：存储不可用")

// Options configures the Redis-backed logout replay store. | Options 配置 Redis 支持的登出重放存储。
type Options struct {
	// KeyPrefix is the namespace prepended to every key. An empty value uses DefaultKeyPrefix.
	// The value must not contain '{' or '}', because the store places the cluster hash tag
	// immediately after the prefix. | KeyPrefix 是添加到每个键前的命名空间；空值使用
	// DefaultKeyPrefix。该值不得包含 '{' 或 '}'，因为存储会在前缀之后立即放置集群哈希标签。
	KeyPrefix string
}

// Store implements oidc.LogoutReplayStore on Redis. | Store 在 Redis 上实现 oidc.LogoutReplayStore。
//
// A Store is safe for concurrent use by several goroutines and by several application instances
// that share one Redis deployment. Accept records an identifier with one Lua script, so exactly one
// concurrent caller observes a fresh identifier. The client passed to New belongs to the caller and
// is never closed by the store. | Store 可供多个 goroutine 以及共享同一 Redis 部署的多个应用实例
// 并发使用。Accept 使用单个 Lua 脚本记录标识，因此并发调用中恰好只有一个观察到新鲜标识。传给
// New 的客户端归调用方所有，存储从不关闭它。
type Store struct {
	// client is the shared universal client. | client 是共享的通用客户端。
	client goredis.UniversalClient
	// keys builds every key below the configured namespace. | keys 在配置的命名空间下构造所有键。
	keys keys
}

// Store satisfies the OIDC logout replay port. | Store 满足 OIDC 登出重放端口。
var _ authoidc.LogoutReplayStore = (*Store)(nil)

// New returns a logout replay store backed by client. | New 返回由 client 支持的登出重放存储。
//
// It performs no network round trip, so callers that need a liveness check should probe the client
// separately. A nil client, or a prefix containing '{' or '}', reports auth.ErrInvalidConfig. The
// caller keeps ownership of client. | 它不进行网络往返，因此需要探活的调用方应自行探测客户端。nil
// 客户端或包含 '{' 或 '}' 的前缀会返回 auth.ErrInvalidConfig。client 的所有权仍属于调用方。
func New(client goredis.UniversalClient, options Options) (*Store, error) {
	if client == nil {
		return nil, errs.Detail(auth.ErrInvalidConfig, "redis client is nil | Redis 客户端为 nil")
	}
	prefix := options.KeyPrefix
	if prefix == "" {
		prefix = DefaultKeyPrefix
	}
	if strings.ContainsAny(prefix, "{}") {
		return nil, errs.Detail(auth.ErrInvalidConfig, "key prefix must not contain braces | 键前缀不得包含花括号")
	}
	return &Store{client: client, keys: newKeys(prefix)}, nil
}

// Accept records jti until expiresAt and reports whether it was previously unseen. | Accept 记录
// jti 至 expiresAt，并报告该标识此前是否未见。
//
// An empty identifier reports oidc.ErrInvalidToken and a nil receiver reports
// oidc.ErrInvalidToken. A zero or already elapsed expiresAt is replaced by five minutes from now,
// matching MemoryLogoutReplayStore, so a retained identifier always outlives the current acceptance
// window. If that deadline has already elapsed at the Redis clock, the script substitutes five
// minutes from the Redis clock, so application clock skew cannot create an immediately vanished
// replay record. Redis executes the read, expiry comparison and write in one Lua script; the key
// itself carries a millisecond TTL as well, so an expired identifier cannot be mistaken for a replay
// even if its physical deletion is deferred. All non-zero times are normalized to UTC. Backend
// failures report ErrStoreUnavailable without address text; context cancellation and deadline
// errors are returned unchanged. | 空标识返回 oidc.ErrInvalidToken，接收者为空也返回
// oidc.ErrInvalidToken。零值或已经过去的 expiresAt 会被替换为从当前起五分钟，与
// MemoryLogoutReplayStore 一致，因此保留的标识总是长于当前接受窗口。若该期限在 Redis 时钟下也
// 已经过去，脚本会改用 Redis 时钟加五分钟，因此应用时钟偏差不会产生立即消失的重放记录。Redis
// 在单个 Lua 脚本内完成读取、期限比较与写入；键本身也带有毫秒 TTL，因此即使物理删除被延迟，
// 过期标识也不会被误判为重放。所有非零时间统一规范化为 UTC。后端故障以 ErrStoreUnavailable
// 返回且不携带地址文本；上下文取消与超时错误原样返回。
func (s *Store) Accept(ctx context.Context, jti string, expiresAt time.Time) (bool, error) {
	if s == nil {
		return false, errs.Detail(authoidc.ErrInvalidToken, "logout replay store is nil | 登出重放存储为空")
	}
	if jti == "" {
		return false, errs.Detail(authoidc.ErrInvalidToken, "logout replay jti is empty | 登出重放 jti 为空")
	}
	if err := ctx.Err(); err != nil {
		return false, err
	}
	now := time.Now().UTC()
	if expiresAt.IsZero() || !expiresAt.After(now) {
		expiresAt = now.Add(defaultReplayTTL)
	} else {
		expiresAt = expiresAt.UTC()
	}
	deadlineMillis := strconv.FormatInt(unixMilliCeil(expiresAt), 10)
	fallbackMillis := strconv.FormatInt(defaultReplayTTL.Milliseconds(), 10)
	status, err := s.runInt(ctx, scriptAccept, "accept logout replay",
		[]string{s.keys.replay(jti)}, deadlineMillis, fallbackMillis)
	if err != nil {
		return false, err
	}
	switch status {
	case 0:
		return false, nil
	case 1:
		return true, nil
	default:
		return false, errs.Detail(ErrStoreUnavailable, "accept logout replay returned %d | 接受登出重放返回 %d", status, status)
	}
}

// runInt runs a Lua script and returns its integer reply. | runInt 运行 Lua 脚本并返回整数应答。
func (s *Store) runInt(ctx context.Context, script *goredis.Script, op string, scriptKeys []string, args ...any) (int64, error) {
	value, err := script.Run(ctx, s.client, scriptKeys, args...).Int64()
	if err != nil {
		return 0, backendError(op, err)
	}
	return value, nil
}

// backendError maps one backend failure without copying address or credential text.
// | backendError 映射一次后端故障，且不复制地址或凭据文本。
func backendError(op string, err error) error {
	if err == nil {
		return nil
	}
	if errors.Is(err, context.Canceled) || errors.Is(err, context.DeadlineExceeded) {
		return err
	}
	return errs.Detail(ErrStoreUnavailable, "redis operation %s failed | Redis 操作 %s 失败", op, op)
}

// unixMilliCeil converts one instant to Unix milliseconds, rounding up so a Redis deadline never
// precedes the requested instant. | unixMilliCeil 把单个时刻转换为 Unix 毫秒，并向未来取整，使
// Redis 期限绝早于请求的时刻。
func unixMilliCeil(at time.Time) int64 {
	at = at.UTC()
	milliseconds := at.Unix()*1000 + int64(at.Nanosecond())/int64(time.Millisecond)
	if at.Nanosecond()%int(time.Millisecond) != 0 {
		milliseconds++
	}
	return milliseconds
}
