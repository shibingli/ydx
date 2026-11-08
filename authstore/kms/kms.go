package kms

import (
	"context"
	"errors"
	"strings"

	goredis "github.com/redis/go-redis/v9"

	authkms "github.com/shibingli/ydx/auth/keymgmt/kms"
	"github.com/shibingli/ydx/errs"
)

// DefaultKeyPrefix is the key namespace used when Options.KeyPrefix is empty.
// | DefaultKeyPrefix 是 Options.KeyPrefix 为空时使用的键命名空间。
const DefaultKeyPrefix = "ydx:authstore:kms:"

// maxCASRetries bounds compare-and-set retries for key updates whose alias or revision changed
// between the read and the script. | maxCASRetries 限定键更新在读取与脚本执行之间别名或修订号
// 发生变化时的比较并交换重试次数。
const maxCASRetries = 8

// Options configures the Redis-backed KMS store. | Options 配置 Redis 支持的 KMS 存储。
type Options struct {
	// KeyPrefix is the namespace prepended to every key. An empty value uses DefaultKeyPrefix.
	// The value must not contain '{' or '}', because the store itself places the cluster hash tag
	// immediately after the prefix. | KeyPrefix 是添加到每个键前的命名空间；空值使用
	// DefaultKeyPrefix。该值不得包含 '{' 或 '}'，因为存储会在前缀之后立即放置集群哈希标签。
	KeyPrefix string
}

// Store is a Redis implementation of auth/keymgmt/kms.Store. | Store 是 auth/keymgmt/kms.Store
// 的 Redis 实现。
//
// A Store is safe for concurrent use by several goroutines and by several application instances
// that share one Redis deployment. Every operation stores and returns deep copies; the caller owns
// the go-redis client passed to New and must close it. | Store 可供多个 goroutine 与多个共享同一
// Redis 部署的应用实例并发使用。每个操作都保存并返回深拷贝；传给 New 的 go-redis 客户端由调用方
// 拥有并负责关闭。
type Store struct {
	// client is the shared go-redis universal client. | client 是共享的 go-redis 通用客户端。
	client goredis.UniversalClient
	// keys builds every namespaced Redis key. | keys 构造全部带命名空间的 Redis 键。
	keys keys
}

// Store implements the kms persistence port. | Store 实现 kms 持久化端口。
var _ authkms.Store = (*Store)(nil)

// New returns a KMS store backed by client. | New 返回由 client 支持的 KMS 存储。
//
// It performs no network round trip, so callers that need a liveness check should probe the client
// themselves. A nil client, or a prefix containing '{' or '}', reports kms.ErrInvalidConfig. The
// caller keeps ownership of client. | 它不进行网络往返，因此需要探活的调用方应自行探测客户端。nil
// 客户端或包含 '{' 或 '}' 的前缀会返回 kms.ErrInvalidConfig。client 的所有权仍属于调用方。
func New(client goredis.UniversalClient, options Options) (*Store, error) {
	if client == nil {
		return nil, errs.Detail(authkms.ErrInvalidConfig, "redis client is nil | Redis 客户端为 nil")
	}
	prefix := options.KeyPrefix
	if prefix == "" {
		prefix = DefaultKeyPrefix
	}
	if strings.ContainsAny(prefix, "{}") {
		return nil, errs.Detail(authkms.ErrInvalidConfig, "key prefix must not contain braces | 键前缀不得包含花括号")
	}
	return &Store{client: client, keys: newKeys(prefix)}, nil
}

// ready reports whether the store carries a usable client. | ready 报告存储是否携带可用客户端。
func (s *Store) ready() error {
	if s == nil || s.client == nil {
		return authkms.ErrStoreUnavailable
	}
	return nil
}

// backend maps one go-redis failure without copying address or credential text. | backend 映射一次
// go-redis 故障，且不复制地址或凭据文本。
func backend(op string, err error) error {
	if err == nil {
		return nil
	}
	if errors.Is(err, context.Canceled) || errors.Is(err, context.DeadlineExceeded) {
		return err
	}
	return errs.Detail(authkms.ErrStoreUnavailable, "redis operation %s failed | Redis 操作 %s 失败", op, op)
}

// runInt runs a Lua script and returns its integer reply. | runInt 运行 Lua 脚本并返回整数应答。
func (s *Store) runInt(ctx context.Context, script *goredis.Script, op string, scriptKeys []string, args ...any) (int64, error) {
	value, err := script.Run(ctx, s.client, scriptKeys, args...).Int64()
	if err != nil {
		return 0, backend(op, err)
	}
	return value, nil
}
