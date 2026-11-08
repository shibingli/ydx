package federation

import (
	"context"
	"errors"
	"strconv"
	"strings"
	"time"

	goredis "github.com/redis/go-redis/v9"

	authfederation "github.com/shibingli/ydx/auth/protocol/federation"
	"github.com/shibingli/ydx/errs"
)

// DefaultKeyPrefix is the key namespace used when Options.KeyPrefix is empty.
// | DefaultKeyPrefix 是 Options.KeyPrefix 为空时使用的键命名空间。
const DefaultKeyPrefix = "ydx:authstore:federation:"

// expiredStateRetention keeps an expired state key in Redis for a short classification window.
// Consume can then report federation.ErrStateExpired instead of federation.ErrStateMismatch, and
// Save can replace the expired record, matching MemoryStateStore. The logical deadline is always
// enforced; Redis removes the physical key at the deadline plus this retention. |
// expiredStateRetention 让过期 state 键在 Redis 中短暂保留，用于错误分类。Consume 因此可以返回
// federation.ErrStateExpired 而不是 federation.ErrStateMismatch，Save 也可以替换过期记录，与
// MemoryStateStore 一致。逻辑期限始终强制执行；Redis 在期限加此保留时长后删除物理键。
const expiredStateRetention = 5 * time.Minute

// ErrStoreUnavailable reports a Redis backend failure. The error deliberately carries no address,
// DSN, state value or credential text. | ErrStoreUnavailable 表示 Redis 后端故障。该错误有意不
// 携带地址、DSN、state 值或凭据文本。
var ErrStoreUnavailable = errs.New("authstore/federation: store unavailable | authstore/federation：存储不可用")

// Options configures the Redis-backed federation state store. | Options 配置 Redis 支持的联合登录
// state 存储。
type Options struct {
	// KeyPrefix is the namespace prepended to every key. An empty value uses DefaultKeyPrefix.
	// The value must not contain '{' or '}', because the store places the cluster hash tag
	// immediately after the prefix. | KeyPrefix 是添加到每个键前的命名空间；空值使用
	// DefaultKeyPrefix。该值不得包含 '{' 或 '}'，因为存储会在前缀之后立即放置集群哈希标签。
	KeyPrefix string
	// TTL is the lifetime applied when a record has no ExpiresAt. A zero or negative value uses
	// federation.DefaultStateTTL, as NewMemoryStateStore does. | TTL 是记录没有 ExpiresAt 时应用的
	// 有效期。零值或负值使用 federation.DefaultStateTTL，与 NewMemoryStateStore 一致。
	TTL time.Duration
}

// Store implements federation.StateStore on Redis. | Store 在 Redis 上实现 federation.StateStore。
//
// A Store is safe for concurrent use by several goroutines and by several application instances
// that share one Redis deployment. Save and Consume each run one Lua script, so exactly one
// concurrent Consume call consumes a live state and every other caller reports a mismatch. Every
// record is serialized at the store boundary, so a returned StateRecord is always a fresh deep copy.
// The client passed to New belongs to the caller and is never closed by the store. | Store 可供多个
// goroutine 以及共享同一 Redis 部署的多个应用实例并发使用。Save 与 Consume 各运行一个 Lua 脚本，
// 因此并发 Consume 调用中恰好一个消费有效 state，其余调用方报告不匹配。每条记录都在存储边界
// 序列化，因此返回的 StateRecord 始终是全新的深拷贝。传给 New 的客户端归调用方所有，存储从不
// 关闭它。
type Store struct {
	// client is the shared universal client. | client 是共享的通用客户端。
	client goredis.UniversalClient
	// keys builds every key below the configured namespace. | keys 在配置的命名空间下构造所有键。
	keys keys
	// ttl is the default record lifetime. | ttl 是记录默认有效期。
	ttl time.Duration
}

// Store satisfies the federation state port. | Store 满足联合登录 state 端口。
var _ authfederation.StateStore = (*Store)(nil)

// New returns a federation state store backed by client. | New 返回由 client 支持的联合登录 state
// 存储。
//
// It performs no network round trip, so callers that need a liveness check should probe the client
// separately. A nil client, or a prefix containing '{' or '}', reports
// federation.ErrInvalidConfig. The caller keeps ownership of client. | 它不进行网络往返，因此需要
// 探活的调用方应自行探测客户端。nil 客户端或包含 '{' 或 '}' 的前缀会返回
// federation.ErrInvalidConfig。client 的所有权仍属于调用方。
func New(client goredis.UniversalClient, options Options) (*Store, error) {
	if client == nil {
		return nil, errs.Detail(authfederation.ErrInvalidConfig, "redis client is nil | Redis 客户端为 nil")
	}
	prefix := options.KeyPrefix
	if prefix == "" {
		prefix = DefaultKeyPrefix
	}
	if strings.ContainsAny(prefix, "{}") {
		return nil, errs.Detail(authfederation.ErrInvalidConfig, "key prefix must not contain braces | 键前缀不得包含花括号")
	}
	ttl := options.TTL
	if ttl <= 0 {
		ttl = authfederation.DefaultStateTTL
	}
	return &Store{client: client, keys: newKeys(prefix), ttl: ttl}, nil
}

// runInt runs a Lua script and returns its integer reply. | runInt 运行 Lua 脚本并返回整数应答。
func (s *Store) runInt(ctx context.Context, script *goredis.Script, op string, scriptKeys []string, args ...any) (int64, error) {
	value, err := script.Run(ctx, s.client, scriptKeys, args...).Int64()
	if err != nil {
		return 0, backendError(op, err)
	}
	return value, nil
}

// runSlice runs a Lua script and returns its array reply. | runSlice 运行 Lua 脚本并返回数组应答。
func (s *Store) runSlice(ctx context.Context, script *goredis.Script, op string, scriptKeys []string, args ...any) ([]any, error) {
	value, err := script.Run(ctx, s.client, scriptKeys, args...).Slice()
	if err != nil {
		return nil, backendError(op, err)
	}
	return value, nil
}

// backendError maps one backend failure without copying address, state or credential text.
// | backendError 映射一次后端故障，且不复制地址、state 或凭据文本。
func backendError(op string, err error) error {
	if err == nil {
		return nil
	}
	if errors.Is(err, context.Canceled) || errors.Is(err, context.DeadlineExceeded) {
		return err
	}
	return errs.Detail(ErrStoreUnavailable, "redis operation %s failed | Redis 操作 %s 失败", op, op)
}

// stringValue converts one Redis multi-bulk element to a string. | stringValue 把单个 Redis 多批量
// 元素转换为字符串。
func stringValue(value any) string {
	switch typed := value.(type) {
	case nil:
		return ""
	case string:
		return typed
	case []byte:
		return string(typed)
	case int64:
		return strconv.FormatInt(typed, 10)
	default:
		return ""
	}
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
