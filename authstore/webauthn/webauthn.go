package webauthn

import (
	"context"
	"errors"
	"strconv"
	"strings"
	"time"

	goredis "github.com/redis/go-redis/v9"

	authwebauthn "github.com/shibingli/ydx/auth/mfa/webauthn"
	"github.com/shibingli/ydx/errs"
)

// DefaultKeyPrefix is the key namespace used when Options.KeyPrefix is empty.
// | DefaultKeyPrefix 是 Options.KeyPrefix 为空时使用的键命名空间。
const DefaultKeyPrefix = "ydx:authstore:webauthn:"

const (
	// redisTag is the hash tag shared by every key of the WebAuthn stores. It keeps all keys
	// touched by one Lua script inside one Redis Cluster slot. | redisTag 是 WebAuthn 存储全部键
	// 共享的哈希标签。它让单个 Lua 脚本访问的所有键落在同一个 Redis Cluster 槽位。
	redisTag = "{authstore:webauthn}"
	// minimumTTL is the smallest Redis expiry the stores write. | minimumTTL 是存储写入的最小 Redis 期限。
	minimumTTL = time.Millisecond
	// expiredChallengeRetention keeps a consumed-but-expired ceremony long enough for Consume to
	// report ErrChallengeExpired instead of ErrChallengeNotFound, matching the in-memory store.
	// | expiredChallengeRetention 让已到期但未消费的流程保留足够长时间，使 Consume 能返回
	// ErrChallengeExpired 而不是 ErrChallengeNotFound，与内存存储一致。
	expiredChallengeRetention = time.Hour
	// maxCredentialIDLength mirrors the WebAuthn credential ID upper bound.
	// | maxCredentialIDLength 与 WebAuthn 凭据 ID 上限一致。
	maxCredentialIDLength = 1023
	// fieldData carries the JSON credential record. | fieldData 携带 JSON 凭据记录。
	fieldData = "data"
	// fieldSignCount carries the authoritative signature counter. | fieldSignCount 携带权威签名计数器。
	fieldSignCount = "signCount"
	// fieldBackupState carries the authoritative BE/BS backup state flag.
	// | fieldBackupState 携带权威 BE/BS 备份状态标志。
	fieldBackupState = "backupState"
)

var (
	// ErrStoreUnavailable reports a Redis backend failure. The error deliberately carries no
	// address, DSN or credential text. | ErrStoreUnavailable 表示 Redis 后端故障。该错误有意不
	// 携带地址、DSN 或凭据文本。
	ErrStoreUnavailable = errs.New("webauthnstore: store unavailable | webauthnstore：存储不可用")
	// ErrCorruptRecord reports a stored ceremony that cannot be decoded. | ErrCorruptRecord 表示
	// 无法解码的已存流程。
	ErrCorruptRecord = errs.New("webauthnstore: corrupt stored record | webauthnstore：存储记录损坏")
)

// Options configures the Redis-backed WebAuthn stores. | Options 配置 Redis 支持的 WebAuthn 存储。
type Options struct {
	// KeyPrefix is the namespace prepended to every key. An empty value uses DefaultKeyPrefix.
	// The value must not contain '{' or '}', because the stores place the cluster hash tag
	// immediately after the prefix. | KeyPrefix 是添加到每个键前的命名空间；空值使用
	// DefaultKeyPrefix。该值不得包含 '{' 或 '}'，因为存储会在前缀之后立即放置集群哈希标签。
	KeyPrefix string
}

// Store is a Redis-backed webauthn.ChallengeStore and webauthn.CredentialStore. | Store 是 Redis
// 支持的 webauthn.ChallengeStore 与 webauthn.CredentialStore。
//
// The same value can be assigned to webauthn.Config.ChallengeStore and
// webauthn.Config.CredentialStore. It also implements webauthn.BackupStateUpdater, so a successful
// assertion persists the current BS flag. Store is safe for concurrent use by several goroutines
// and by several application instances that share one Redis deployment. Store owns no client; the
// caller passes one to New and must close it. | 同一个值可赋给 webauthn.Config.ChallengeStore 与
// webauthn.Config.CredentialStore。它还实现 webauthn.BackupStateUpdater，因此成功断言会持久化当前
// BS 标志。Store 可被多个 goroutine 与多个共享同一 Redis 部署的应用实例并发使用。Store 不拥有
// 客户端；调用方把客户端传给 New，并必须自行关闭。
type Store struct {
	// client is the shared Redis client. | client 是共享的 Redis 客户端。
	client goredis.UniversalClient
	// keys builds the key namespace of the stores. | keys 构造存储的键命名空间。
	keys keys
}

// Ensure Store implements every WebAuthn persistence port. | 确保 Store 实现全部 WebAuthn 持久化端口。
var (
	_ authwebauthn.ChallengeStore     = (*Store)(nil)
	_ authwebauthn.CredentialStore    = (*Store)(nil)
	_ authwebauthn.BackupStateUpdater = (*Store)(nil)
)

// New returns Redis-backed WebAuthn stores. | New 返回 Redis 支持的 WebAuthn 存储。
//
// New performs no network round trip, so callers that need a liveness check should probe the
// client themselves. A nil client, or a prefix containing '{' or '}', reports
// webauthn.ErrInvalidConfig. The caller keeps ownership of client. | New 不进行网络往返，因此需要
// 探活的调用方应自行探测客户端。nil 客户端或包含 '{' 或 '}' 的前缀会返回 webauthn.ErrInvalidConfig。
// client 的所有权仍属于调用方。
func New(client goredis.UniversalClient, options Options) (*Store, error) {
	if client == nil {
		return nil, errs.Detail(authwebauthn.ErrInvalidConfig, "redis client is nil | Redis 客户端为 nil")
	}
	prefix := options.KeyPrefix
	if prefix == "" {
		prefix = DefaultKeyPrefix
	}
	if strings.ContainsAny(prefix, "{}") {
		return nil, errs.Detail(authwebauthn.ErrInvalidConfig,
			"key prefix must not contain braces | 键前缀不得包含花括号")
	}
	return &Store{client: client, keys: newKeys(prefix)}, nil
}

// checkContext rejects a nil context and reports cancellation unchanged.
// | checkContext 拒绝 nil 上下文并原样报告取消。
func checkContext(ctx context.Context) error {
	if ctx == nil {
		return errs.Detail(authwebauthn.ErrInvalidRequest, "nil context | 上下文为空")
	}
	return ctx.Err()
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

// flag renders a boolean as the "1"/"0" field the stores write. | flag 把布尔值渲染为存储写入的
// "1"/"0" 字段。
func flag(value bool) string {
	if value {
		return "1"
	}
	return "0"
}
