package cas

import (
	"context"
	"errors"
	"strconv"
	"strings"

	goredis "github.com/redis/go-redis/v9"

	authcas "github.com/shibingli/ydx/auth/protocol/cas"
	"github.com/shibingli/ydx/errs"
)

// DefaultKeyPrefix is the key namespace used when Options.KeyPrefix is empty.
// | DefaultKeyPrefix 是 Options.KeyPrefix 为空时使用的键命名空间。
const DefaultKeyPrefix = "ydx:authstore:cas:"

// redisTag is the hash tag shared by every key of the CAS stores. It keeps all keys touched by one
// Lua script inside one Redis Cluster slot. | redisTag 是 CAS 存储全部键共享的哈希标签。它让单个
// Lua 脚本访问的所有键落在同一个 Redis Cluster 槽位。
const redisTag = "{authstore:cas}"

// maxCASRetries bounds optimistic compare-and-set retries for multi-key updates.
// | maxCASRetries 限定多键更新的乐观比较并交换重试次数。
const maxCASRetries = 8

var (
	// ErrStoreUnavailable reports a Redis backend failure. The error deliberately carries no address,
	// DSN or credential text. | ErrStoreUnavailable 表示 Redis 后端故障。该错误有意不携带地址、DSN
	// 或凭据文本。
	ErrStoreUnavailable = errs.New("casstore: store unavailable | casstore：存储不可用")
	// ErrConflict reports that a multi-key update kept losing its compare-and-set race after the
	// configured retries. | ErrConflict 表示多键更新在配置的重试次数内持续输掉比较并交换竞争。
	ErrConflict = errs.New("casstore: concurrent update conflict | casstore：并发更新冲突")
)

// Options configures the Redis-backed CAS stores. | Options 配置 Redis 支持的 CAS 存储。
type Options struct {
	// KeyPrefix is the namespace prepended to every key. An empty value uses DefaultKeyPrefix. The
	// value must not contain '{' or '}', because the store itself places the cluster hash tag
	// immediately after the prefix. | KeyPrefix 是添加到每个键前的命名空间；空值使用
	// DefaultKeyPrefix。该值不得包含 '{' 或 '}'，因为存储会在前缀之后立即放置集群哈希标签。
	KeyPrefix string
}

// Stores groups the Redis implementations of the CAS persistence ports.
// | Stores 汇总 CAS 持久化端口的 Redis 实现。
//
// Tickets can be passed to cas.ServerConfig.TicketStore and Sessions to
// cas.ServerConfig.SessionRegistry. A Stores value returned by New does not own the client; the
// caller must close it. | Tickets 可传给 cas.ServerConfig.TicketStore，Sessions 可传给
// cas.ServerConfig.SessionRegistry。New 返回的 Stores 不拥有客户端，调用方必须自行关闭。
type Stores struct {
	// Tickets is the Redis implementation of cas.TicketStore. | Tickets 是 cas.TicketStore 的 Redis 实现。
	Tickets authcas.TicketStore
	// Sessions is the Redis implementation of cas.ServiceSessionRegistry. |
	// Sessions 是 cas.ServiceSessionRegistry 的 Redis 实现。
	Sessions authcas.ServiceSessionRegistry
	// tickets is the concrete ticket store used by extension methods. |
	// tickets 是扩展方法使用的具体票据存储。
	tickets *ticketStore
	// sessions is the concrete session registry used by extension methods. |
	// sessions 是扩展方法使用的具体会话注册表。
	sessions *sessionRegistry
}

// New returns CAS stores backed by client. | New 返回由 client 支持的 CAS 存储。
//
// It performs no network round trip, so callers that need a liveness check should probe the client
// themselves. A nil client, or a prefix containing '{' or '}', reports cas.ErrInvalidConfig. The
// caller keeps ownership of client. | 它不进行网络往返，因此需要探活的调用方应自行探测客户端。nil
// 客户端或包含 '{' 或 '}' 的前缀会返回 cas.ErrInvalidConfig。client 的所有权仍属于调用方。
func New(client goredis.UniversalClient, options Options) (*Stores, error) {
	if client == nil {
		return nil, errs.Detail(authcas.ErrInvalidConfig, "redis client is nil | Redis 客户端为 nil")
	}
	prefix := options.KeyPrefix
	if prefix == "" {
		prefix = DefaultKeyPrefix
	}
	if strings.ContainsAny(prefix, "{}") {
		return nil, errs.Detail(authcas.ErrInvalidConfig, "key prefix must not contain braces | 键前缀不得包含花括号")
	}
	shared := base{client: client, keys: newKeys(prefix)}
	tickets := &ticketStore{base: shared}
	sessions := &sessionRegistry{base: shared}
	return &Stores{
		Tickets:  tickets,
		Sessions: sessions,
		tickets:  tickets,
		sessions: sessions,
	}, nil
}

// TicketStore returns the ticket store as the cas.TicketStore interface.
// | TicketStore 以 cas.TicketStore 接口返回票据存储。
func (s *Stores) TicketStore() authcas.TicketStore {
	if s == nil {
		return nil
	}
	return s.Tickets
}

// SessionRegistry returns the session registry as the cas.ServiceSessionRegistry interface.
// | SessionRegistry 以 cas.ServiceSessionRegistry 接口返回会话注册表。
func (s *Stores) SessionRegistry() authcas.ServiceSessionRegistry {
	if s == nil {
		return nil
	}
	return s.Sessions
}

// base carries the client and key namespace shared by both stores.
// | base 承载两个存储共享的客户端与键命名空间。
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
	return errs.Detail(ErrStoreUnavailable, "redis operation %s failed | Redis 操作 %s 失败", op, op)
}

// runInt runs a Lua script and returns its integer reply. | runInt 运行 Lua 脚本并返回整数应答。
func (b *base) runInt(ctx context.Context, script *goredis.Script, op string, scriptKeys []string, args ...any) (int64, error) {
	value, err := script.Run(ctx, b.client, scriptKeys, args...).Int64()
	if err != nil {
		return 0, b.backend(op, err)
	}
	return value, nil
}

// runSlice runs a Lua script and returns its array reply. | runSlice 运行 Lua 脚本并返回数组应答。
func (b *base) runSlice(ctx context.Context, script *goredis.Script, op string, scriptKeys []string, args ...any) ([]any, error) {
	value, err := script.Run(ctx, b.client, scriptKeys, args...).Slice()
	if err != nil {
		return nil, b.backend(op, err)
	}
	return value, nil
}

// stringValue converts a go-redis reply element to a string. | stringValue 把 go-redis 应答元素转换为字符串。
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
	case uint64:
		return strconv.FormatUint(typed, 10)
	case float64:
		return strconv.FormatFloat(typed, 'f', -1, 64)
	default:
		return ""
	}
}

// allNil reports whether every element of a multi-get reply is nil, which means the key is absent.
// | allNil 报告多键读取应答是否全部为 nil，即键不存在。
func allNil(values []any) bool {
	for _, value := range values {
		if value != nil {
			return false
		}
	}
	return true
}

// flag renders a boolean as the "1"/"0" flag Lua scripts expect. | flag 把布尔值渲染为 Lua 脚本使用的 "1"/"0" 标志。
func flag(value bool) string {
	if value {
		return "1"
	}
	return "0"
}
