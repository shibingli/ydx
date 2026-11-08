package otp

import (
	"context"
	"errors"
	"strings"
	"time"

	goredis "github.com/redis/go-redis/v9"

	authotp "github.com/shibingli/ydx/auth/mfa/otp"
	"github.com/shibingli/ydx/errs"
)

// DefaultKeyPrefix is the key namespace used when Options.KeyPrefix is empty.
// | DefaultKeyPrefix 是 Options.KeyPrefix 为空时使用的键命名空间。
const DefaultKeyPrefix = "ydx:authstore:otp:"

const (
	// redisTag is the hash tag shared by every key of the replay guard. It keeps all keys touched
	// by one operation inside one Redis Cluster slot. | redisTag 是重放保护器全部键共享的哈希标签。
	// 它让单个操作访问的所有键落在同一个 Redis Cluster 槽位。
	redisTag = "{authstore:otp}"
	// minimumTTL is the smallest Redis expiry the guard writes, because SET PX cannot represent
	// a duration below one millisecond. | minimumTTL 是保护器写入的最小 Redis 期限，因为 SET PX
	// 无法表示小于一毫秒的时长。
	minimumTTL = time.Millisecond
)

// Options configures the Redis-backed replay guard. | Options 配置 Redis 支持的重放保护器。
type Options struct {
	// KeyPrefix is the namespace prepended to every key. An empty value uses DefaultKeyPrefix.
	// The value must not contain '{' or '}', because the guard places the cluster hash tag
	// immediately after the prefix. | KeyPrefix 是添加到每个键前的命名空间；空值使用
	// DefaultKeyPrefix。该值不得包含 '{' 或 '}'，因为保护器会在前缀之后立即放置集群哈希标签。
	KeyPrefix string
}

// ReplayGuard is a Redis-backed otp.ReplayGuard shared by every application instance. | ReplayGuard
// 是供所有应用实例共享的 Redis 支持 otp.ReplayGuard。
//
// Each accepted (key, step) pair is recorded with a Redis SET NX PX, which is a single atomic
// command, so exactly one concurrent caller for a fresh pair can receive true across all
// instances. The TTL matches the in-memory guard: the pair may be accepted again once the TTL
// elapses. ReplayGuard owns no client; the caller passes one to New and must close it. |
// 每个已接受的 (key, step) 对都用 Redis SET NX PX 记录，这是一条原子命令，因此在所有实例的并发
// 调用中，全新键值对只能有一个调用得到 true。TTL 与内存保护器一致：TTL 经过后该键值对可再次被
// 接受。ReplayGuard 不拥有客户端；调用方把客户端传给 New，并必须自行关闭。
type ReplayGuard struct {
	// client is the shared Redis client. | client 是共享的 Redis 客户端。
	client goredis.UniversalClient
	// keys builds the key namespace of the guard. | keys 构造保护器的键命名空间。
	keys keys
}

// Ensure ReplayGuard implements the OTP replay port. | 确保 ReplayGuard 实现 OTP 重放端口。
var _ authotp.ReplayGuard = (*ReplayGuard)(nil)

// New returns a Redis-backed OTP replay guard. | New 返回 Redis 支持的 OTP 重放保护器。
//
// New performs no network round trip, so callers that need a liveness check should probe the
// client themselves. A nil client, or a prefix containing '{' or '}', reports otp.ErrInvalidConfig.
// The caller keeps ownership of client. | New 不进行网络往返，因此需要探活的调用方应自行探测
// 客户端。nil 客户端或包含 '{' 或 '}' 的前缀会返回 otp.ErrInvalidConfig。client 的所有权仍属于
// 调用方。
func New(client goredis.UniversalClient, options Options) (*ReplayGuard, error) {
	if client == nil {
		return nil, errs.Detail(authotp.ErrInvalidConfig, "redis client is nil | Redis 客户端为 nil")
	}
	prefix := options.KeyPrefix
	if prefix == "" {
		prefix = DefaultKeyPrefix
	}
	if strings.ContainsAny(prefix, "{}") {
		return nil, errs.Detail(authotp.ErrInvalidConfig,
			"key prefix must not contain braces | 键前缀不得包含花括号")
	}
	return &ReplayGuard{client: client, keys: newKeys(prefix)}, nil
}

// Accept records (key, step) for ttl and reports whether it was fresh. | Accept 记录 (key, step)
// 并报告它是否全新。
//
// The write is a single SET NX PX, so the pair is either created with the full TTL or observed as
// already present; there is no window in which two instances both succeed. An expired pair is
// atomic with respect to Redis expiry and can be accepted again, matching the in-memory guard.
// The method returns otp.ErrInvalidRequest for a nil context or empty key and otp.ErrInvalidConfig
// for a non-positive ttl; backend failures are reported as otp.ErrReplayStore without exposing the
// Redis address. | 写入是单条 SET NX PX，因此键值对要么以完整 TTL 创建，要么被观察为已存在；不存在
// 两个实例同时成功的窗口。过期的键值对相对 Redis 期限是原子的，可再次被接受，与内存保护器一致。
// 方法对 nil 上下文或空键返回 otp.ErrInvalidRequest，对非正 ttl 返回 otp.ErrInvalidConfig；后端
// 故障以 otp.ErrReplayStore 报告，且不暴露 Redis 地址。
func (g *ReplayGuard) Accept(ctx context.Context, key string, step int64, ttl time.Duration) (bool, error) {
	if ctx == nil {
		return false, errs.Detail(authotp.ErrInvalidRequest, "nil context | 上下文为空")
	}
	if err := ctx.Err(); err != nil {
		return false, err
	}
	if key == "" {
		return false, errs.Detail(authotp.ErrInvalidRequest, "replay key is empty | 重放保护键为空")
	}
	if ttl <= 0 {
		return false, errs.Detail(authotp.ErrInvalidConfig,
			"replay TTL %s is not positive | 重放保护 TTL %s 非正", ttl, ttl)
	}
	if ttl < minimumTTL {
		ttl = minimumTTL
	}
	fresh, err := g.client.SetNX(ctx, g.keys.replay(key, step), "1", ttl).Result()
	if err != nil {
		return false, g.backend("accept replay", err)
	}
	return fresh, nil
}

// backend maps one backend failure without copying address or credential text.
// | backend 映射一次后端故障，且不复制地址或凭据文本。
func (g *ReplayGuard) backend(op string, err error) error {
	if errors.Is(err, context.Canceled) || errors.Is(err, context.DeadlineExceeded) {
		return err
	}
	return errs.Detail(authotp.ErrReplayStore, "redis operation %s failed | Redis 操作 %s 失败", op, op)
}
