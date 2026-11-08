package kmip

import (
	"context"
	cryptorand "crypto/rand"
	"errors"
	"strconv"
	"strings"
	"sync/atomic"

	goredis "github.com/redis/go-redis/v9"

	kmipcore "github.com/shibingli/ydx/auth/keymgmt/kmip"
	"github.com/shibingli/ydx/errs"
)

// DefaultKeyPrefix is the key namespace used when Options.KeyPrefix is empty.
// | DefaultKeyPrefix 是 Options.KeyPrefix 为空时使用的键命名空间。
const DefaultKeyPrefix = "ydx:authstore:kmip:"

// maxCASRetries bounds optimistic compare-and-set retries for Update. | maxCASRetries 限定 Update 的
// 乐观比较并交换重试次数。
const maxCASRetries = 32

// maxResetPasses bounds the number of index snapshots Reset processes before it deletes the index
// for the last time. | maxResetPasses 限定 Reset 删除索引成员并最终删除索引的轮数上限。
const maxResetPasses = 8

// Options configures the Redis-backed KMIP store. | Options 配置 Redis 支持的 KMIP 存储。
type Options struct {
	// KeyPrefix is the namespace prepended to every key. An empty value uses DefaultKeyPrefix. The
	// value must not contain '{' or '}', because the store places its own cluster hash tag
	// immediately after the prefix. | KeyPrefix 是添加到每个键前的命名空间；空值使用
	// DefaultKeyPrefix。该值不得包含 '{' 或 '}'，因为存储会在前缀之后立即放置自己的集群哈希标签。
	KeyPrefix string
}

// Store implements kmip.Store on Redis. It is safe for concurrent use by several goroutines and
// by several application instances that share one Redis deployment. | Store 在 Redis 上实现
// kmip.Store。它可供多个 goroutine 与多个共享同一 Redis 部署的应用实例并发使用。
type Store struct {
	// client is the universal client shared by every method. | client 是每个方法共享的通用客户端。
	client goredis.UniversalClient
	// keys builds every key below the configured namespace. | keys 在配置的命名空间下构造所有键。
	keys keys
	// nonce makes revision tokens unique to this store instance. | nonce 使修订令牌在本存储实例内唯一。
	nonce string
	// sequence orders revision tokens within this store instance. | sequence 在本存储实例内为修订令牌排序。
	sequence atomic.Uint64
}

// Store satisfies the KMIP persistence port. | Store 满足 KMIP 持久化端口。
var _ kmipcore.Store = (*Store)(nil)

// New returns a KMIP store backed by client. | New 返回由 client 支持的 KMIP 存储。
//
// It performs no network round trip, so callers that need a liveness check should probe the
// client themselves. A nil client, or a prefix containing '{' or '}', reports
// kmip.ErrInvalidRequest. The caller keeps ownership of client and must close it. | 它不进行网络
// 往返，因此需要探活的调用方应自行探测客户端。nil 客户端或包含 '{' 或 '}' 的前缀会返回
// kmip.ErrInvalidRequest。client 的所有权属于调用方，必须由调用方关闭。
func New(client goredis.UniversalClient, options Options) (*Store, error) {
	if client == nil {
		return nil, errs.Detail(kmipcore.ErrInvalidRequest, "redis client is nil | Redis 客户端为 nil")
	}
	prefix := options.KeyPrefix
	if prefix == "" {
		prefix = DefaultKeyPrefix
	}
	if strings.ContainsAny(prefix, "{}") {
		return nil, errs.Detail(kmipcore.ErrInvalidRequest, "key prefix must not contain braces | 键前缀不得包含花括号")
	}
	return &Store{client: client, keys: newKeys(prefix), nonce: cryptorand.Text()}, nil
}

// nextRevision returns a fresh compare-and-set revision token. Tokens embed a random per-store
// nonce and a monotonically increasing sequence, so a token is never reused, not even when an
// identifier is deleted and created again. That prevents a stale Update from matching a recreated
// record. | nextRevision 返回新的比较并交换修订令牌。令牌包含每存储随机 nonce 与单调递增序号，因此
// 令牌绝不会重复，即使标识符被删除后重新创建也不会；这防止陈旧 Update 匹配到重建的记录。
func (s *Store) nextRevision() string {
	return s.nonce + "-" + strconv.FormatUint(s.sequence.Add(1), 10)
}

// validRevision reports whether revision has the token shape produced by nextRevision.
// | validRevision 报告 revision 是否具有 nextRevision 产生的令牌形态。
func validRevision(revision string) bool {
	dash := strings.IndexByte(revision, '-')
	if dash <= 0 || dash == len(revision)-1 {
		return false
	}
	for i := dash + 1; i < len(revision); i++ {
		if revision[i] < '0' || revision[i] > '9' {
			return false
		}
	}
	return true
}

// ensure verifies that the receiver is usable and fails closed instead of panicking.
// | ensure 校验接收者可用，并以失败关闭代替 panic。
func (s *Store) ensure() error {
	if s == nil || s.client == nil {
		return errs.Detail(kmipcore.ErrInvalidRequest, "KMIP store is nil | KMIP 存储为空")
	}
	return nil
}

// backend maps one backend failure without copying address, DSN or credential text. Context
// cancellation and deadline errors are returned unchanged. | backend 映射一次后端故障，且不复制
// 地址、DSN 或凭据文本。上下文取消与超时错误原样返回。
func (s *Store) backend(op string, err error) error {
	if err == nil {
		return nil
	}
	if errors.Is(err, context.Canceled) || errors.Is(err, context.DeadlineExceeded) {
		return err
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
