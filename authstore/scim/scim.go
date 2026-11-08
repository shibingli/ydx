package scim

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"hash/fnv"
	"strconv"
	"strings"
	"time"

	goredis "github.com/redis/go-redis/v9"

	scimlib "github.com/shibingli/ydx/auth/directory/scim"
	"github.com/shibingli/ydx/errs"
)

// DefaultKeyPrefix is the key namespace used when Options.KeyPrefix is empty.
// | DefaultKeyPrefix 是 Options.KeyPrefix 为空时使用的键命名空间。
const DefaultKeyPrefix = "ydx:authstore:scim:"

// maxCASRetries bounds optimistic compare-and-set retries for multi-key replacements.
// | maxCASRetries 限定多键替换的乐观比较并交换重试次数。
const maxCASRetries = 8

// Compile-time interface checks. | 编译期接口检查。
var (
	_ scimlib.Store                = (*Store)(nil)
	_ scimlib.UserVersionReplacer  = (*Store)(nil)
	_ scimlib.GroupVersionReplacer = (*Store)(nil)
)

// Options configures the Redis-backed SCIM store. | Options 配置 Redis 支持的 SCIM 存储。
type Options struct {
	// KeyPrefix is the namespace prepended to every key. An empty value uses DefaultKeyPrefix.
	// The value must not contain '{' or '}', because the store itself places the cluster hash tag
	// immediately after the prefix. | KeyPrefix 是添加到每个键前的命名空间；空值使用
	// DefaultKeyPrefix。该值不得包含 '{' 或 '}'，因为存储会在前缀之后立即放置集群哈希标签。
	KeyPrefix string
}

// Store is the Redis implementation of scim.Store and scim.UserVersionReplacer.
// | Store 是 scim.Store 与 scim.UserVersionReplacer 的 Redis 实现。
//
// Store is safe for concurrent use by several goroutines and by several application instances
// that share one Redis deployment. A Store does not own the client passed to New; the caller must
// close it when the store is no longer used. | Store 可供多个 goroutine 与多个共享同一 Redis 部署的
// 应用实例并发使用。Store 不拥有传给 New 的客户端；不再使用存储时调用方必须关闭客户端。
type Store struct {
	// client is the shared universal client. | client 是共享的通用客户端。
	client goredis.UniversalClient
	// keys assembles every key under the configured prefix. | keys 在配置前缀下组装每个键。
	keys keys
	// now supplies the current instant and is replaceable in tests. | now 提供当前时刻，可在测试中替换。
	now func() time.Time
}

var (
	_ scimlib.Store               = (*Store)(nil)
	_ scimlib.UserVersionReplacer = (*Store)(nil)
)

// New returns a SCIM store backed by client. | New 返回由 client 支持的 SCIM 存储。
//
// It performs no network round trip, so a wrong address is reported by the first operation as
// scim.ErrStoreUnavailable. A nil client, or a prefix containing '{' or '}', reports
// scim.ErrInvalidConfig. | 它不进行网络往返，因此错误地址会在第一个操作时以
// scim.ErrStoreUnavailable 报告。nil 客户端或包含 '{' 或 '}' 的前缀会返回 scim.ErrInvalidConfig。
func New(client goredis.UniversalClient, options Options) (*Store, error) {
	if client == nil {
		return nil, errs.Detail(scimlib.ErrInvalidConfig, "redis client is nil | Redis 客户端为 nil")
	}
	prefix := options.KeyPrefix
	if prefix == "" {
		prefix = DefaultKeyPrefix
	}
	if strings.ContainsAny(prefix, "{}") {
		return nil, errs.Detail(scimlib.ErrInvalidConfig, "key prefix must not contain braces | 键前缀不得包含花括号")
	}
	return &Store{client: client, keys: newKeys(prefix), now: time.Now}, nil
}

// contextOrBackground returns ctx or a background context when ctx is nil.
// | contextOrBackground 返回 ctx，或在 ctx 为 nil 时返回后台上下文。
func contextOrBackground(ctx context.Context) context.Context {
	if ctx == nil {
		return context.Background()
	}
	return ctx
}

// contextError reports an ended request context as scim.ErrStoreUnavailable so callers see the
// same sentinel as any other backend failure while errors.Is still finds context.Canceled.
// | contextError 把已结束的请求上下文报告为 scim.ErrStoreUnavailable，使调用方看到与其它后端故障
// 相同的哨兵，同时 errors.Is 仍能找到 context.Canceled。
func (s *Store) contextError(ctx context.Context) error {
	if err := ctx.Err(); err != nil {
		return errs.WrapDetail(err, scimlib.ErrStoreUnavailable, "request context ended | 请求上下文已结束")
	}
	return nil
}

// backend maps one backend failure without copying address or credential text.
// | backend 映射一次后端故障，且不复制地址或凭据文本。
func (s *Store) backend(op string, err error) error {
	if err == nil {
		return nil
	}
	if errors.Is(err, context.Canceled) || errors.Is(err, context.DeadlineExceeded) {
		return errs.WrapDetail(err, scimlib.ErrStoreUnavailable, "redis operation %s interrupted | Redis 操作 %s 被中断", op, op)
	}
	return errs.Detail(scimlib.ErrStoreUnavailable, "redis operation %s failed | Redis 操作 %s 失败", op, op)
}

// run executes a Lua script and returns its array reply. | run 执行 Lua 脚本并返回其数组应答。
func (s *Store) run(ctx context.Context, script *goredis.Script, op string, scriptKeys []string, args ...any) ([]any, error) {
	value, err := script.Run(ctx, s.client, scriptKeys, args...).Slice()
	if err != nil {
		return nil, s.backend(op, err)
	}
	return value, nil
}

// timestamp returns the current UTC instant in RFC3339 form.
// | timestamp 返回 RFC3339 形式的当前 UTC 时刻。
func (s *Store) timestamp() string {
	return s.now().UTC().Format(time.RFC3339)
}

// newResourceID returns a random 32-character hexadecimal identifier.
// | newResourceID 返回随机的 32 字符十六进制标识。
func newResourceID() (string, error) {
	var buffer [16]byte
	if _, err := rand.Read(buffer[:]); err != nil {
		return "", err
	}
	return hex.EncodeToString(buffer[:]), nil
}

// normalizeETag strips whitespace, a weak prefix and surrounding quotes so stored and caller
// supplied entity tags compare in one canonical form. | normalizeETag 去除空白、弱前缀与外围引号，
// 使存储的与调用方提供的实体标签以统一形式比较。
func normalizeETag(value string) string {
	value = strings.TrimSpace(value)
	value = strings.TrimPrefix(value, "W/")
	value = strings.TrimPrefix(value, "w/")
	value = strings.TrimSpace(value)
	value = strings.TrimPrefix(value, `"`)
	value = strings.TrimSuffix(value, `"`)
	return strings.TrimSpace(value)
}

// versionBase derives the stable part of a resource entity tag from its type and identifier.
// | versionBase 由资源类型与标识派生资源实体标签的稳定部分。
func versionBase(resourceType, id string) string {
	hasher := fnv.New64a()
	_, _ = hasher.Write([]byte(resourceType))
	_, _ = hasher.Write([]byte{0})
	_, _ = hasher.Write([]byte(id))
	_, _ = hasher.Write([]byte{0})
	return strconv.FormatUint(hasher.Sum64(), 16)
}

// tagFor combines a version base and a revision number into the bare entity tag.
// | tagFor 把版本基与修订号组合为裸实体标签。
func tagFor(base string, revision int64) string {
	return base + "-" + strconv.FormatInt(revision, 10)
}

// etagFor renders a bare entity tag as a weak HTTP entity tag.
// | etagFor 把裸实体标签渲染为弱 HTTP 实体标签。
func etagFor(tag string) string {
	return `W/"` + tag + `"`
}

// normalizeIndexValue canonicalizes a value for case-insensitive unique or secondary indexes.
// | normalizeIndexValue 规范化用于大小写不敏感唯一或次要索引的值。
func normalizeIndexValue(value string) string {
	return strings.ToLower(strings.TrimSpace(value))
}

// flag renders a boolean as the "1" or "0" string expected by the Lua scripts.
// | flag 把布尔值渲染为 Lua 脚本期望的 "1" 或 "0" 字符串。
func flag(value bool) string {
	if value {
		return "1"
	}
	return "0"
}

// replyInt reads the integer at index from a script reply. | replyInt 从脚本应答中读取指定下标的整数。
func replyInt(reply []any, index int) int64 {
	if index < 0 || index >= len(reply) {
		return -1
	}
	switch value := reply[index].(type) {
	case int64:
		return value
	case int:
		return int64(value)
	case string:
		parsed, err := strconv.ParseInt(value, 10, 64)
		if err != nil {
			return -1
		}
		return parsed
	default:
		return -1
	}
}

// anyString converts a go-redis field value to a string. | anyString 把 go-redis 字段值转换为字符串。
func anyString(value any) string {
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

// pageBounds converts SCIM StartIndex and Count into a slice range using the same rules as
// scim.MemoryStore. | pageBounds 使用与 scim.MemoryStore 相同的规则把 SCIM StartIndex 与 Count
// 转换为切片范围。
func pageBounds(total, startIndex, count int) (int, int) {
	if startIndex < 1 {
		startIndex = 1
	}
	start := startIndex - 1
	if start > total {
		start = total
	}
	if count < 0 {
		return start, total
	}
	end := start + count
	if end > total {
		end = total
	}
	return start, end
}
