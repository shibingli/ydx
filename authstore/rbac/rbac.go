package rbac

import (
	"context"
	"errors"
	"strings"

	goredis "github.com/redis/go-redis/v9"

	authrbac "github.com/shibingli/ydx/auth/authz/rbac"
	"github.com/shibingli/ydx/errs"
)

// DefaultKeyPrefix is the key namespace used when Options.KeyPrefix is empty.
// | DefaultKeyPrefix 是 Options.KeyPrefix 为空时使用的键命名空间。
const DefaultKeyPrefix = "ydx:authstore:rbac:"

var (
	// ErrStoreUnavailable reports a Redis backend failure. The error deliberately carries no
	// address, DSN or credential text. | ErrStoreUnavailable 表示 Redis 后端故障。该错误有意不
	// 携带地址、DSN 或凭据文本。
	ErrStoreUnavailable = errs.New("rbacstore: store unavailable | rbacstore：存储不可用")
	// ErrInvalidConfig reports an unusable client or key prefix. | ErrInvalidConfig 表示客户端或
	// 键前缀不可用。
	ErrInvalidConfig = errs.New("rbacstore: invalid configuration | rbacstore：配置非法")
)

// Options configures the Redis-backed RBAC store. | Options 配置 Redis 支持的 RBAC 存储。
type Options struct {
	// KeyPrefix is the namespace prepended to every key. An empty value uses DefaultKeyPrefix. The
	// value must not contain '{' or '}', because the store itself places the cluster hash tag
	// immediately after the prefix. | KeyPrefix 是添加到每个键前的命名空间；空值使用
	// DefaultKeyPrefix。该值不得包含 '{' 或 '}'，因为存储会在前缀之后立即放置集群哈希标签。
	KeyPrefix string
}

// Store implements rbac.Store on Redis. | Store 在 Redis 上实现 rbac.Store。
//
// It is safe for concurrent use by several goroutines and by several application instances that
// share one Redis deployment. Uniqueness checks, inheritance-cycle detection, expired-assignment
// replacement, role cascades and resets execute as Lua scripts, so Redis's single-threaded script
// execution supplies the atomicity the in-memory store obtains from a mutex. Every read returns a
// fresh deep copy and all non-zero times cross the boundary as UTC. | 它可供多个 goroutine 以及共享
// 同一 Redis 部署的多个应用实例并发使用。唯一性检查、继承环检测、过期分配替换、角色级联删除与重置
// 都以 Lua 脚本执行，因此内存存储用互斥锁获得的原子性由 Redis 的脚本单线程执行提供。每次读取都返回
// 全新的深拷贝，所有非零时间以 UTC 跨越存储边界。
//
// The client passed to New belongs to the caller and is never closed by the store.
// | 传给 New 的客户端归调用方所有，存储从不关闭它。
type Store struct {
	// client is the shared universal client. | client 是共享的通用客户端。
	client goredis.UniversalClient
	// keys builds every key below the configured namespace. | keys 在配置的命名空间下构造所有键。
	keys keys
}

// Compile-time check that Store implements the rbac persistence port.
// | 编译期检查 Store 实现 rbac 持久化端口。
var _ authrbac.Store = (*Store)(nil)

// New returns an RBAC store backed by client. | New 返回由 client 支持的 RBAC 存储。
//
// It performs no network round trip, so callers that need a liveness check should probe the
// client themselves. A nil client, or a prefix containing '{' or '}', reports ErrInvalidConfig.
// The caller keeps ownership of client. | 它不进行网络往返，因此需要探活的调用方应自行探测客户端。
// nil 客户端或包含 '{' 或 '}' 的前缀会返回 ErrInvalidConfig。client 的所有权仍属于调用方。
func New(client goredis.UniversalClient, options Options) (*Store, error) {
	if client == nil {
		return nil, errs.Detail(ErrInvalidConfig, "redis client is nil | Redis 客户端为 nil")
	}
	prefix := options.KeyPrefix
	if prefix == "" {
		prefix = DefaultKeyPrefix
	}
	if strings.ContainsAny(prefix, "{}") {
		return nil, errs.Detail(ErrInvalidConfig, "key prefix must not contain braces | 键前缀不得包含花括号")
	}
	return &Store{client: client, keys: newKeys(prefix)}, nil
}

// ensure verifies that the receiver is usable and fails closed instead of panicking.
// | ensure 校验接收者可用，并以失败关闭代替 panic。
func (s *Store) ensure() error {
	if s == nil || s.client == nil {
		return errs.Detail(ErrInvalidConfig, "store is nil | 存储为空")
	}
	return nil
}

// normalizeContext replaces a nil context with context.Background, matching the in-memory store.
// | normalizeContext 把空上下文替换为 context.Background，与内存存储一致。
func normalizeContext(ctx context.Context) context.Context {
	if ctx == nil {
		return context.Background()
	}
	return ctx
}

// checkContext reports a canceled or expired context as rbac.ErrCanceled, matching the in-memory
// store. | checkContext 把已取消或超时的上下文报告为 rbac.ErrCanceled，与内存存储一致。
func checkContext(ctx context.Context) error {
	if err := normalizeContext(ctx).Err(); err != nil {
		return errs.Wrap(err, authrbac.ErrCanceled)
	}
	return nil
}

// backend maps one backend failure without copying address or credential text. Context
// cancellation and deadline errors keep the rbac.ErrCanceled sentinel used by the in-memory store.
// | backend 映射一次后端故障，且不复制地址或凭据文本。上下文取消与超时错误保留内存存储使用的
// rbac.ErrCanceled 哨兵。
func (s *Store) backend(op string, err error) error {
	if err == nil {
		return nil
	}
	if errors.Is(err, context.Canceled) || errors.Is(err, context.DeadlineExceeded) {
		return errs.Wrap(err, authrbac.ErrCanceled)
	}
	return errs.Detail(ErrStoreUnavailable, "redis operation %s failed | Redis 操作 %s 失败", op, op)
}

// runInt runs a Lua script and returns its integer reply. | runInt 运行 Lua 脚本并返回整数应答。
func (s *Store) runInt(ctx context.Context, script *goredis.Script, op string, scriptKeys []string, args ...any) (int64, error) {
	value, err := script.Run(ctx, s.client, scriptKeys, args...).Int64()
	if err != nil {
		return 0, s.backend(op, err)
	}
	return value, nil
}

// runSlice runs a Lua script and returns its array reply. | runSlice 运行 Lua 脚本并返回数组应答。
func (s *Store) runSlice(ctx context.Context, script *goredis.Script, op string, scriptKeys []string, args ...any) ([]any, error) {
	value, err := script.Run(ctx, s.client, scriptKeys, args...).Slice()
	if err != nil {
		return nil, s.backend(op, err)
	}
	return value, nil
}
