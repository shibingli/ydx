package saml

import (
	"context"
	"errors"
	"strings"
	"time"

	goredis "github.com/redis/go-redis/v9"

	samlapi "github.com/shibingli/ydx/auth/protocol/saml"
	"github.com/shibingli/ydx/errs"
)

// DefaultKeyPrefix is the key namespace used when Options.KeyPrefix is empty.
// | DefaultKeyPrefix 是 Options.KeyPrefix 为空时使用的键命名空间。
const DefaultKeyPrefix = "ydx:authstore:saml:"

// cleanupBatch is the maximum number of indexed records removed by one cleanup script call.
// | cleanupBatch 是单次清理脚本调用最多删除的索引记录数。
const cleanupBatch = 128

// sessionScanBatch is the SSCAN page size used while listing a subject's sessions.
// | sessionScanBatch 是列出主体会话时使用的 SSCAN 分页大小。
const sessionScanBatch = 256

// maxCASRetries bounds optimistic compare-and-set retries for session updates and deletes.
// | maxCASRetries 限定会话更新与删除的乐观比较并交换重试次数。
const maxCASRetries = 8

// Options configures the Redis-backed SAML stores. | Options 配置 Redis 支持的 SAML 存储。
type Options struct {
	// KeyPrefix is the namespace prepended to every key. An empty value uses DefaultKeyPrefix.
	// The value must not contain '{' or '}', because the store places its own cluster hash tags
	// immediately after the prefix. | KeyPrefix 是添加到每个键前的命名空间；空值使用
	// DefaultKeyPrefix。该值不得包含 '{' 或 '}'，因为存储会在前缀之后立即放置自己的集群哈希标签。
	KeyPrefix string
}

// Stores implements the SAML persistence ports on Redis. | Stores 在 Redis 上实现 SAML 持久化端口。
//
// A single Stores value satisfies saml.Store, saml.ArtifactStore and
// saml.AssertionReplayStore, and its CleanupAssertions method matches
// saml.AssertionReplayCleaner. It is safe for concurrent use by several goroutines and by several
// application instances that share one Redis deployment. The client passed to New belongs to the
// caller and is never closed by the store. | 单个 Stores 值满足 saml.Store、saml.ArtifactStore 与
// saml.AssertionReplayStore，其 CleanupAssertions 方法匹配 saml.AssertionReplayCleaner。它可供多个
// goroutine 以及共享同一 Redis 部署的多个应用实例并发使用。传给 New 的客户端归调用方所有，存储
// 从不关闭它。
type Stores struct {
	// client is the shared universal client. | client 是共享的通用客户端。
	client goredis.UniversalClient
	// keys builds every key below the configured namespace. | keys 在配置的命名空间下构造所有键。
	keys keys
}

// Compile-time checks that Stores covers the published SAML persistence ports.
// | 编译期检查 Stores 覆盖已发布的 SAML 持久化端口。
var (
	_ samlapi.Store                = (*Stores)(nil)
	_ samlapi.ArtifactStore        = (*Stores)(nil)
	_ samlapi.AssertionReplayStore = (*Stores)(nil)
	_ assertionReplayCleaner       = (*Stores)(nil)
)

// assertionReplayCleaner mirrors saml.AssertionReplayCleaner from auth versions that publish it.
// The method set is identical, so Stores satisfies that optional interface when consumers update.
// | assertionReplayCleaner 对应发布该接口的 auth 版本中的 saml.AssertionReplayCleaner。方法集完全
// 相同，因此消费方升级后 Stores 即满足该可选接口。
type assertionReplayCleaner interface {
	// CleanupAssertions removes expired assertion records and returns the removed count. |
	// CleanupAssertions 删除过期断言记录并返回删除数量。
	CleanupAssertions(ctx context.Context, now time.Time) (int, error)
}

// New returns SAML stores backed by client. | New 返回由 client 支持的 SAML 存储。
//
// It performs no network round trip, so a caller that needs a liveness check should probe the
// client separately. A nil client, or a prefix containing '{' or '}', reports
// saml.ErrInvalidConfig. The caller keeps ownership of client. | 它不进行网络往返，因此需要探活的
// 调用方应单独探测客户端。nil 客户端或包含 '{' 或 '}' 的前缀会返回 saml.ErrInvalidConfig。client
// 的所有权仍属于调用方。
func New(client goredis.UniversalClient, options Options) (*Stores, error) {
	if client == nil {
		return nil, errs.Detail(samlapi.ErrInvalidConfig, "redis client is nil | Redis 客户端为 nil")
	}
	prefix := options.KeyPrefix
	if prefix == "" {
		prefix = DefaultKeyPrefix
	}
	if strings.ContainsAny(prefix, "{}") {
		return nil, errs.Detail(samlapi.ErrInvalidConfig, "key prefix must not contain braces | 键前缀不得包含花括号")
	}
	return &Stores{client: client, keys: newKeys(prefix)}, nil
}

// ensure verifies that the receiver is usable and fails closed instead of panicking.
// | ensure 校验接收者可用，并以失败关闭代替 panic。
func (s *Stores) ensure() error {
	if s == nil || s.client == nil {
		return errs.Detail(samlapi.ErrInvalidConfig, "SAML store is nil | SAML 存储为空")
	}
	return nil
}

// backend maps one backend failure without copying address or credential text. Context
// cancellation and deadline errors are returned unchanged. | backend 映射一次后端故障，且不复制
// 地址或凭据文本。上下文取消与超时错误原样返回。
func (s *Stores) backend(op string, err error) error {
	if err == nil {
		return nil
	}
	if errors.Is(err, context.Canceled) || errors.Is(err, context.DeadlineExceeded) {
		return err
	}
	return errs.Detail(ErrStoreUnavailable, "redis operation %s failed | Redis 操作 %s 失败", op, op)
}

// runInt runs a Lua script and returns its integer reply. | runInt 运行 Lua 脚本并返回整数应答。
func (s *Stores) runInt(ctx context.Context, script *goredis.Script, op string, scriptKeys []string, args ...any) (int64, error) {
	value, err := script.Run(ctx, s.client, scriptKeys, args...).Int64()
	if err != nil {
		return 0, s.backend(op, err)
	}
	return value, nil
}

// runSlice runs a Lua script and returns its array reply. | runSlice 运行 Lua 脚本并返回数组应答。
func (s *Stores) runSlice(ctx context.Context, script *goredis.Script, op string, scriptKeys []string, args ...any) ([]any, error) {
	value, err := script.Run(ctx, s.client, scriptKeys, args...).Slice()
	if err != nil {
		return nil, s.backend(op, err)
	}
	return value, nil
}
