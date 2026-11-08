package wsfed

import (
	"context"
	"errors"
	"strconv"
	"strings"
	"time"

	goredis "github.com/redis/go-redis/v9"

	authwsfed "github.com/shibingli/ydx/auth/protocol/wsfed"
	"github.com/shibingli/ydx/errs"
)

// DefaultKeyPrefix is the key namespace used when Options.KeyPrefix is empty.
// | DefaultKeyPrefix 是 Options.KeyPrefix 为空时使用的键命名空间。
const DefaultKeyPrefix = "ydx:authstore:wsfed:"

const (
	// redisTag is the hash tag shared by every key of the request store. It keeps all keys
	// touched by one Lua script inside one Redis Cluster slot. | redisTag 是请求存储全部键共享的
	// 哈希标签。它让单个 Lua 脚本访问的所有键落在同一个 Redis Cluster 槽位。
	redisTag = "{authstore:wsfed}"
	// defaultRequestTTL mirrors the relying party default correlation lifetime.
	// | defaultRequestTTL 与依赖方的默认关联寿命一致。
	defaultRequestTTL = 10 * time.Minute
	// minimumTTL is the smallest Redis expiry the store writes. | minimumTTL 是存储写入的最小 Redis 期限。
	minimumTTL = time.Millisecond
)

var (
	// ErrStoreUnavailable reports a Redis backend failure. The error deliberately carries no
	// address, DSN or credential text. | ErrStoreUnavailable 表示 Redis 后端故障。该错误有意不
	// 携带地址、DSN 或凭据文本。
	ErrStoreUnavailable = errs.New("wsfedstore: store unavailable | wsfedstore：存储不可用")
	// ErrCorruptRecord reports a stored request that cannot be decoded. | ErrCorruptRecord 表示
	// 无法解码的已存请求。
	ErrCorruptRecord = errs.New("wsfedstore: corrupt stored record | wsfedstore：存储记录损坏")
)

// Options configures the Redis-backed WS-Federation request store. | Options 配置 Redis 支持的
// WS-Federation 请求存储。
type Options struct {
	// KeyPrefix is the namespace prepended to every key. An empty value uses DefaultKeyPrefix.
	// The value must not contain '{' or '}', because the store places the cluster hash tag
	// immediately after the prefix. | KeyPrefix 是添加到每个键前的命名空间；空值使用
	// DefaultKeyPrefix。该值不得包含 '{' 或 '}'，因为存储会在前缀之后立即放置集群哈希标签。
	KeyPrefix string
}

// Store is a Redis-backed wsfed.RequestStore shared by every application instance. | Store 是
// 供所有应用实例共享的 Redis 支持 wsfed.RequestStore。
//
// Store owns no client; the caller passes one to New and must close it. Store is safe for
// concurrent use by several goroutines and by several processes that share one Redis deployment.
// | Store 不拥有客户端；调用方把客户端传给 New，并必须自行关闭。Store 可被多个 goroutine 与
// 多个共享同一 Redis 部署的进程并发使用。
type Store struct {
	// client is the shared Redis client. | client 是共享的 Redis 客户端。
	client goredis.UniversalClient
	// keys builds the key namespace of the store. | keys 构造存储的键命名空间。
	keys keys
}

// RequestStore verifies that Store implements the WS-Federation request port.
// | RequestStore 校验 Store 实现了 WS-Federation 请求端口。
var _ authwsfed.RequestStore = (*Store)(nil)

// New returns a Redis-backed WS-Federation request store. | New 返回 Redis 支持的 WS-Federation
// 请求存储。
//
// New performs no network round trip, so callers that need a liveness check should probe the
// client themselves. A nil client, or a prefix containing '{' or '}', reports
// wsfed.ErrInvalidConfig. The caller keeps ownership of client. | New 不进行网络往返，因此需要
// 探活的调用方应自行探测客户端。nil 客户端或包含 '{' 或 '}' 的前缀会返回 wsfed.ErrInvalidConfig。
// client 的所有权仍属于调用方。
func New(client goredis.UniversalClient, options Options) (*Store, error) {
	if client == nil {
		return nil, errs.Detail(authwsfed.ErrInvalidConfig, "redis client is nil | Redis 客户端为 nil")
	}
	prefix := options.KeyPrefix
	if prefix == "" {
		prefix = DefaultKeyPrefix
	}
	if strings.ContainsAny(prefix, "{}") {
		return nil, errs.Detail(authwsfed.ErrInvalidConfig,
			"key prefix must not contain braces | 键前缀不得包含花括号")
	}
	return &Store{client: client, keys: newKeys(prefix)}, nil
}

// backend maps one backend failure without copying address or credential text.
// | backend 映射一次后端故障，且不复制地址或凭据文本。
func (s *Store) backend(op string, err error) error {
	if err == nil {
		return nil
	}
	if errors.Is(err, context.Canceled) || errors.Is(err, context.DeadlineExceeded) {
		return err
	}
	return errs.Detail(ErrStoreUnavailable, "redis operation %s failed | Redis 操作 %s 失败", op, op)
}

// normalizeContext accepts a nil context like the in-memory store and reports cancellation.
// | normalizeContext 像内存存储一样接受 nil 上下文，并报告取消。
func normalizeContext(ctx context.Context) (context.Context, error) {
	if ctx == nil {
		return context.Background(), nil
	}
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	return ctx, nil
}

// stringValue converts one Redis reply element to a string. | stringValue 把单个 Redis 应答元素
// 转换为字符串。
func stringValue(value any) string {
	switch typed := value.(type) {
	case nil:
		return ""
	case string:
		return typed
	case []byte:
		return string(typed)
	default:
		return ""
	}
}

// intValue converts one Redis reply element to an int64. | intValue 把单个 Redis 应答元素转换为
// int64。
func intValue(value any) int64 {
	switch typed := value.(type) {
	case int64:
		return typed
	case int:
		return int64(typed)
	case string:
		parsed, err := strconv.ParseInt(typed, 10, 64)
		if err != nil {
			return 0
		}
		return parsed
	case []byte:
		parsed, err := strconv.ParseInt(string(typed), 10, 64)
		if err != nil {
			return 0
		}
		return parsed
	case float64:
		return int64(typed)
	default:
		return 0
	}
}
