// Package redis implements the auth persistence ports on Redis. | Package redis 在 Redis 上实现 auth 持久化端口。
//
// New accepts a go-redis universal client and returns an auth.Stores-compatible set. Every store
// is safe for concurrent use by several goroutines and by several application instances that
// share one Redis deployment. Uniqueness checks, single-use token consumption and audit appends
// run as Lua scripts, so Redis's single-threaded script execution supplies the atomicity the
// in-memory stores obtain from a mutex. | New 接受 go-redis 通用客户端并返回兼容 auth.Stores 的
// 集合。每个存储都可供多个 goroutine 与多个共享同一 Redis 部署的应用实例并发使用。唯一性检查、
// 一次性令牌消费与审计追加以 Lua 脚本执行，因此内存存储用互斥锁获得的原子性由 Redis 的脚本
// 单线程执行提供。
//
// The caller owns a client passed to New and must close it. NewFromOptions opens the client with
// ydx/redis, owns it, and closes it through Stores.Close. | 传给 New 的客户端由调用方拥有并负责
// 关闭。NewFromOptions 通过 ydx/redis 打开客户端、拥有它，并通过 Stores.Close 关闭。
//
// Backend failures are reported as auth.ErrStoreUnavailable with a fixed bilingual detail; the
// underlying go-redis error text is deliberately not attached because it can contain addresses
// or credentials. Context cancellation and deadline errors are returned unchanged. | 后端故障以
// auth.ErrStoreUnavailable 加固定中英双语细节返回；底层 go-redis 错误文本会被有意丢弃，因为它
// 可能包含地址或凭据。上下文取消与超时错误原样返回。
package redis

import (
	"context"
	"errors"
	"strings"

	goredis "github.com/redis/go-redis/v9"

	"github.com/shibingli/ydx/auth"
	"github.com/shibingli/ydx/errs"
	ydxredis "github.com/shibingli/ydx/redis"
)

// DefaultKeyPrefix is the key namespace used when Options.KeyPrefix is empty.
// | DefaultKeyPrefix 是 Options.KeyPrefix 为空时使用的键命名空间。
const DefaultKeyPrefix = "ydx:authstore:"

// Options configures the Redis-backed stores. | Options 配置 Redis 支持的存储。
type Options struct {
	// KeyPrefix is the namespace prepended to every key. An empty value uses DefaultKeyPrefix.
	// The value must not contain '{' or '}', because the store itself places the cluster hash tag
	// immediately after the prefix. | KeyPrefix 是添加到每个键前的命名空间；空值使用
	// DefaultKeyPrefix。该值不得包含 '{' 或 '}'，因为存储会在前缀之后立即放置集群哈希标签。
	KeyPrefix string
}

// Stores groups the Redis implementations of every auth persistence port.
// | Stores 汇总 auth 各持久化端口的 Redis 实现。
//
// The embedded auth.Stores can be passed directly to auth.New. A Stores value returned by New
// does not own the client; one returned by NewFromOptions does and must be closed.
// | 内嵌的 auth.Stores 可直接传给 auth.New。New 返回的 Stores 不拥有客户端；
// NewFromOptions 返回的 Stores 拥有客户端，必须关闭。
type Stores struct {
	auth.Stores
	// client is the shared universal client. | client 是共享的通用客户端。
	client goredis.UniversalClient
	// owned reports whether Close must close the client. | owned 表示 Close 是否需要关闭客户端。
	owned bool
}

// New returns stores backed by client. | New 返回由 client 支持的存储。
//
// It performs no network round trip, so callers that need a liveness check should use
// ydxredis.Health or NewFromOptions. A nil client, or a prefix containing '{' or '}', reports
// auth.ErrInvalidConfig. The caller keeps ownership of client. | 它不进行网络往返，因此需要探活的
// 调用方应使用 ydxredis.Health 或 NewFromOptions。nil 客户端或包含 '{' 或 '}' 的前缀会返回
// auth.ErrInvalidConfig。client 的所有权仍属于调用方。
func New(client goredis.UniversalClient, options Options) (*Stores, error) {
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
	keySet := newKeys(prefix)
	base := base{client: client, keys: keySet}
	return &Stores{
		Stores: auth.Stores{
			Users:       &userStore{base: base},
			Sessions:    &sessionStore{base: base},
			Identities:  &identityStore{base: base},
			Credentials: &credentialStore{base: base},
			Audits:      &auditStore{base: base},
			Tokens:      &tokenStore{base: base},
		},
		client: client,
	}, nil
}

// NewFromOptions opens a client with ydx/redis, probes it, and returns owned stores.
// | NewFromOptions 用 ydx/redis 打开客户端、进行探活，并返回拥有客户端的存储。
//
// The connection parameters are not implemented here; ydx/redis owns single, sentinel and
// cluster construction. On any failure the partially opened client is closed. The returned
// Stores must be closed with Stores.Close. | 连接参数不在这里重新实现；单机、哨兵与集群的构造由
// ydx/redis 负责。任一步失败都会关闭已部分打开的客户端。返回的 Stores 必须通过 Stores.Close
// 关闭。
func NewFromOptions(ctx context.Context, conn ydxredis.Options, options Options) (*Stores, error) {
	client, err := ydxredis.Open(conn)
	if err != nil {
		return nil, err
	}
	if err := ydxredis.Health(ctx, client); err != nil {
		_ = client.Close()
		return nil, errs.Detail(auth.ErrStoreUnavailable, "redis health check failed | Redis 探活失败")
	}
	stores, err := New(client, options)
	if err != nil {
		_ = client.Close()
		return nil, err
	}
	stores.owned = true
	return stores, nil
}

// Auth returns the embedded auth.Stores value. | Auth 返回内嵌的 auth.Stores 值。
func (s *Stores) Auth() auth.Stores {
	if s == nil {
		return auth.Stores{}
	}
	return s.Stores
}

// Close releases a client opened by NewFromOptions. | Close 释放由 NewFromOptions 打开的客户端。
//
// A client passed to New belongs to the caller, so Close is a no-op for those stores. Close is
// idempotent and is not safe to race with concurrent store operations. | 传给 New 的客户端属于
// 调用方，因此这些存储的 Close 是空操作。Close 是幂等的，且不得与并发存储操作竞争。
func (s *Stores) Close() error {
	if s == nil || !s.owned || s.client == nil {
		return nil
	}
	s.owned = false
	client := s.client
	s.client = nil
	if err := client.Close(); err != nil {
		return errs.Detail(auth.ErrStoreUnavailable, "close redis client failed | 关闭 Redis 客户端失败")
	}
	return nil
}

// maxCASRetries bounds optimistic compare-and-set retries for multi-key updates.
// | maxCASRetries 限定多键更新的乐观比较并交换重试次数。
const maxCASRetries = 8

// base carries the client and key namespace shared by every store.
// | base 承载所有存储共享的客户端与键命名空间。
type base struct {
	client goredis.UniversalClient
	keys   keys
}

// backend maps one backend failure without copying address or credential text.
// | backend 映射一次后端故障，且不复制地址或凭据文本。
func (b *base) backend(op string, err error) error {
	if err == nil {
		return nil
	}
	if errors.Is(err, context.Canceled) || errors.Is(err, context.DeadlineExceeded) {
		return err
	}
	return errs.Detail(auth.ErrStoreUnavailable, "redis operation %s failed | Redis 操作 %s 失败", op, op)
}

// runInt runs a Lua script and returns its integer reply. | runInt 运行 Lua 脚本并返回整数应答。
func (b *base) runInt(ctx context.Context, script *goredis.Script, op string, keys []string, args ...any) (int64, error) {
	value, err := script.Run(ctx, b.client, keys, args...).Int64()
	if err != nil {
		return 0, b.backend(op, err)
	}
	return value, nil
}

// runSlice runs a Lua script and returns its array reply. | runSlice 运行 Lua 脚本并返回数组应答。
func (b *base) runSlice(ctx context.Context, script *goredis.Script, op string, keys []string, args ...any) ([]any, error) {
	value, err := script.Run(ctx, b.client, keys, args...).Slice()
	if err != nil {
		return nil, b.backend(op, err)
	}
	return value, nil
}
