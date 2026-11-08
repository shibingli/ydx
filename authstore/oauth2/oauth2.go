package oauth2

import (
	"context"
	"errors"
	"strconv"
	"strings"
	"time"

	goredis "github.com/redis/go-redis/v9"

	"github.com/shibingli/ydx/auth"
	authoauth2 "github.com/shibingli/ydx/auth/protocol/oauth2"
	"github.com/shibingli/ydx/errs"
)

// DefaultKeyPrefix is the key namespace used when Options.KeyPrefix is empty.
// | DefaultKeyPrefix 是 Options.KeyPrefix 为空时使用的键命名空间。
const DefaultKeyPrefix = "ydx:authstore:oauth2:"

// ErrConflict reports that a multi-key compare-and-set update stayed contended after every retry.
// The Redis implementation performs every state transition inside one Lua script, so this error is
// reserved for helpers that must read, modify and compare outside a script. | ErrConflict 表示多键
// 比较并交换更新在全部重试后仍存在竞争。Redis 实现把每次状态转换放在单个 Lua 脚本内，因此该错误
// 只保留给必须在脚本外读取、修改与比较的辅助路径。
var ErrConflict = errs.New("authstore/oauth2: concurrent modification conflict | authstore/oauth2：并发修改冲突")

// Constants shared by the Redis-backed stores. | Redis 存储共享的常量。
const (
	// defaultScopeCacheTTL bounds how long a scope snapshot may be reused before a lazy refresh.
	// | defaultScopeCacheTTL 限定作用域快照在惰性刷新前可复用的时长。
	defaultScopeCacheTTL = 5 * time.Second
	// scopeReloadTimeout bounds one background scope reload. | scopeReloadTimeout 限定一次后台作用域重载。
	scopeReloadTimeout = 5 * time.Second
	// defaultMaxDPoPNonces bounds the stored DPoP nonce population. | defaultMaxDPoPNonces 限定已存 DPoP nonce 数量。
	defaultMaxDPoPNonces = 8192
	// pruneTimeout bounds the context-free DPoP nonce Prune call. | pruneTimeout 限定无上下文 DPoP nonce Prune 调用。
	pruneTimeout = 5 * time.Second
	// defaultClientPageSize is the page size used when ListClientsPage receives a non-positive limit.
	// | defaultClientPageSize 是 ListClientsPage 收到非正数上限时使用的页大小。
	defaultClientPageSize = 100
	// maxClientPageSize clamps one client page. | maxClientPageSize 限制单页客户端数量。
	maxClientPageSize = 1000
)

// Options configures the Redis-backed oauth2 stores. | Options 配置 Redis 支持的 oauth2 存储。
type Options struct {
	// KeyPrefix is the namespace prepended to every key. An empty value uses DefaultKeyPrefix.
	// The value must not contain '{' or '}', because each store places a cluster hash tag
	// immediately after the prefix. | KeyPrefix 是添加到每个键前的命名空间；空值使用
	// DefaultKeyPrefix。该值不得包含 '{' 或 '}'，因为每个存储会在前缀之后立即放置集群哈希标签。
	KeyPrefix string
	// ScopeCacheTTL bounds how long the in-process scope snapshot may be reused. Zero uses
	// defaultScopeCacheTTL; a negative value disables lazy refresh so callers rely on Reload. A
	// registry never loaded through Reload stays empty when lazy refresh is disabled. |
	// ScopeCacheTTL 限定进程内作用域快照可复用的时长。零值使用 defaultScopeCacheTTL；负值关闭
	// 惰性刷新，调用方需显式调用 Reload。关闭惰性刷新后，从未经 Reload 加载的注册表保持为空。
	ScopeCacheTTL time.Duration
	// MaxDPoPNonces bounds the stored DPoP nonce population. Zero or a negative value uses
	// defaultMaxDPoPNonces. At the bound the store reclaims expired nonces and then evicts the
	// soonest-expiring live nonce. | MaxDPoPNonces 限定已存 DPoP nonce 数量。零值或负值使用
	// defaultMaxDPoPNonces。到达上限时先回收过期 nonce，再淘汰最早过期的有效 nonce。
	MaxDPoPNonces int
}

// Stores groups the Redis implementations of the oauth2 persistence ports.
// | Stores 汇总 oauth2 各持久化端口的 Redis 实现。
//
// Every field is safe for concurrent use by several goroutines and by several application
// instances that share one Redis deployment. The client passed to New stays owned by the caller.
// | 每个字段都可供多个 goroutine 与多个共享同一 Redis 部署的应用实例并发使用。传给 New 的客户端
// 始终归调用方所有。
type Stores struct {
	// Store persists grants, tokens, device codes and pushed authorization requests.
	// | Store 持久化许可、令牌、设备码与推送授权请求。
	Store authoauth2.Store
	// Clients persists client registrations. | Clients 持久化客户端注册。
	Clients ClientPager
	// DPoPNonces issues and validates RFC 9449 DPoP nonces. | DPoPNonces 签发并校验 RFC 9449 DPoP nonce。
	DPoPNonces authoauth2.DPoPNonceStore
	// DPoPReplay rejects replayed DPoP proof identifiers across instances.
	// | DPoPReplay 跨实例拒绝重放的 DPoP 证明标识。
	DPoPReplay authoauth2.DPoPReplayStore
	// Scopes is the Redis-shared scope registry. | Scopes 是 Redis 共享的作用域注册表。
	Scopes *ScopeRegistry
	// client is the shared universal client. | client 是共享的通用客户端。
	client goredis.UniversalClient
	// keys builds the key namespace shared by every store. | keys 构造所有存储共享的键命名空间。
	keys keys
}

// New returns Redis-backed oauth2 stores. | New 返回 Redis 支持的 oauth2 存储。
//
// It performs no network round trip, so callers that need a liveness check should probe the client
// themselves. New validates the client and prefix, then builds every store; the scope snapshot is
// loaded lazily on the first registry read or by an explicit Reload. A nil client or a prefix
// containing '{' or '}' reports auth.ErrInvalidConfig. The caller keeps ownership of client and
// must close it. | 它不进行网络往返，因此需要探活的调用方应自行探测客户端。New 校验客户端与前缀并
// 构造全部存储；作用域快照在第一次读取注册表时惰性加载，或由显式 Reload 加载。nil 客户端或包含
// '{' 或 '}' 的前缀会返回 auth.ErrInvalidConfig。client 的所有权仍属于调用方，调用方必须关闭它。
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
	maxNonces := options.MaxDPoPNonces
	if maxNonces <= 0 {
		maxNonces = defaultMaxDPoPNonces
	}
	scopeTTL := options.ScopeCacheTTL
	switch {
	case scopeTTL == 0:
		scopeTTL = defaultScopeCacheTTL
	case scopeTTL < 0:
		scopeTTL = 0
	}
	scopes := &ScopeRegistry{base: base, ttl: scopeTTL}
	return &Stores{
		Store:      &store{base: base},
		Clients:    &clientStore{base: base},
		DPoPNonces: &DPoPNonceStore{base: base, capacity: maxNonces},
		DPoPReplay: &DPoPReplayStore{base: base},
		Scopes:     scopes,
		client:     client,
		keys:       keySet,
	}, nil
}

// base carries the client and key namespace shared by every store.
// | base 承载所有存储共享的客户端与键命名空间。
type base struct {
	// client is the shared universal client. | client 是共享的通用客户端。
	client goredis.UniversalClient
	// keys builds the key namespace. | keys 构造键命名空间。
	keys keys
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
func (b *base) runInt(ctx context.Context, script *goredis.Script, op string, keyList []string, args ...any) (int64, error) {
	value, err := script.Run(ctx, b.client, keyList, args...).Int64()
	if err != nil {
		return 0, b.backend(op, err)
	}
	return value, nil
}

// runSlice runs a Lua script and returns its array reply. | runSlice 运行 Lua 脚本并返回数组应答。
func (b *base) runSlice(ctx context.Context, script *goredis.Script, op string, keyList []string, args ...any) ([]any, error) {
	value, err := script.Run(ctx, b.client, keyList, args...).Slice()
	if err != nil {
		return nil, b.backend(op, err)
	}
	return value, nil
}

// runStrings runs a Lua script and converts its array reply to strings.
// | runStrings 运行 Lua 脚本并把数组应答转换为字符串。
func (b *base) runStrings(ctx context.Context, script *goredis.Script, op string, keyList []string, args ...any) ([]string, error) {
	reply, err := b.runSlice(ctx, script, op, keyList, args...)
	if err != nil {
		return nil, err
	}
	out := make([]string, 0, len(reply))
	for _, value := range reply {
		out = append(out, stringValue(value))
	}
	return out, nil
}

// hashFields loads every field of one hash and maps backend failures. A missing key returns an
// empty map without an error, matching Redis HGETALL. | hashFields 读取单个哈希的全部字段并映射
// 后端故障。键不存在时返回空映射且不报错，与 Redis HGETALL 一致。
func (b *base) hashFields(ctx context.Context, key, op string) (map[string]string, error) {
	fields, err := b.client.HGetAll(ctx, key).Result()
	if err != nil {
		return nil, b.backend(op, err)
	}
	return fields, nil
}

// pairsToFields converts a flat field/value array from a Lua reply into a map.
// | pairsToFields 把 Lua 应答中的扁平字段/值数组转换为映射。
func pairsToFields(values []string) (map[string]string, error) {
	if len(values)%2 != 0 {
		return nil, errs.Detail(authoauth2.ErrServerError, "redis reply carries an odd field array | Redis 应答携带奇数长度字段数组")
	}
	fields := make(map[string]string, len(values)/2)
	for i := 0; i < len(values); i += 2 {
		fields[values[i]] = values[i+1]
	}
	return fields, nil
}

// stringValue converts one Redis multi-bulk element to a string. | stringValue 把单个 Redis 多批量元素转换为字符串。
func stringValue(value any) string {
	switch typed := value.(type) {
	case nil:
		return ""
	case string:
		return typed
	case []byte:
		return string(typed)
	case int64:
		return strconvFormatInt(typed)
	default:
		return ""
	}
}

// strconvFormatInt formats one int64 without importing strconv at every call site.
// | strconvFormatInt 格式化单个 int64，避免在每个调用点导入 strconv。
func strconvFormatInt(value int64) string {
	return strconv.FormatInt(value, 10)
}

// flag encodes a boolean as the Lua-facing "1"/"0" string. | flag 把布尔值编码为面向 Lua 的 "1"/"0" 字符串。
func flag(value bool) string {
	if value {
		return "1"
	}
	return "0"
}

// clockFields encodes an instant as whole seconds and nanoseconds, both safe for Lua numbers.
// | clockFields 把时刻编码为整秒与纳秒，两者都可安全表示为 Lua 数字。
func clockFields(at time.Time) (string, string) {
	at = at.UTC()
	return strconv.FormatInt(at.Unix(), 10), strconv.FormatInt(int64(at.Nanosecond()), 10)
}

// expiryFields encodes an optional deadline as a flag plus whole seconds and nanoseconds.
// | expiryFields 把可选期限编码为标志、整秒与纳秒。
func expiryFields(at time.Time) (string, string, string) {
	if at.IsZero() {
		return "0", "0", "0"
	}
	at = at.UTC()
	return "1", strconv.FormatInt(at.Unix(), 10), strconv.FormatInt(int64(at.Nanosecond()), 10)
}
