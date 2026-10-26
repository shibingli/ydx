// Package redisstore provides shared session, image and policy state for multi-instance captcha deployments. | Package redisstore 为多机验证码部署提供共享会话、图片与策略状态。
//
// The core captcha module stays single-process and dependency-light. Import this
// package only when several replicas must share challenge state, one-time token
// markers, images and rate limits. | 核心验证码模块保持单进程与轻依赖。仅当多个副本需要
// 共享挑战状态、一次性令牌标记、图片与限流时导入本包。
package redisstore

import (
	"context"
	"time"

	goredis "github.com/redis/go-redis/v9"

	"github.com/shibingli/ydx/captcha/core"
	"github.com/shibingli/ydx/errs"
	"github.com/shibingli/ydx/json"
	"github.com/shibingli/ydx/middleware/ratelimit"
)

// DefaultPolicyKey is the Redis key used by PolicyProvider. | DefaultPolicyKey 是 PolicyProvider 使用的 Redis 键。
const DefaultPolicyKey = "yd:captcha:policy"

var (
	// ErrInvalidOptions indicates unusable Redis store options. | ErrInvalidOptions 表示 Redis 存储选项不可用。
	ErrInvalidOptions = errs.New("redisstore: invalid options | redisstore：非法选项")
	// ErrPolicy indicates an unreadable policy payload. | ErrPolicy 表示策略载荷无法读取。
	ErrPolicy = errs.New("redisstore: invalid policy | redisstore：非法策略")
)

// takeScript atomically returns and deletes a value. | takeScript 原子地返回并删除值。
const takeScript = `
local value = redis.call('GET', KEYS[1])
if value then
  redis.call('DEL', KEYS[1])
end
return value
`

// deleteIfScript deletes a key only when its value still matches. | deleteIfScript 仅在值仍匹配时删除键。
const deleteIfScript = `
if redis.call('GET', KEYS[1]) == ARGV[1] then
  return redis.call('DEL', KEYS[1])
end
return 0
`

// StoreOptions configures the Redis session store. | StoreOptions 配置 Redis 会话存储。
type StoreOptions struct {
	// Client is the Redis client shared by every replica. | Client 是各副本共享的 Redis 客户端。
	Client goredis.UniversalClient
	// Prefix is prepended to every key; empty means none. | Prefix 加到每个键之前；空值表示不加。
	Prefix string
}

// Store is a core.Store backed by one Redis. | Store 是由同一个 Redis 支撑的 core.Store。
type Store struct {
	client goredis.UniversalClient
	prefix string
}

// NewStore builds a shared session store. | NewStore 构建共享会话存储。
func NewStore(o StoreOptions) (*Store, error) {
	if o.Client == nil {
		return nil, errs.Detail(ErrInvalidOptions, "nil Redis client | Redis 客户端为 nil")
	}
	return &Store{client: o.Client, prefix: o.Prefix}, nil
}

// Put implements core.Store. | Put 实现 core.Store。
func (s *Store) Put(ctx context.Context, key string, value []byte, ttl time.Duration) error {
	if key == "" {
		return errs.Detail(ErrInvalidOptions, "empty key | 空键")
	}
	if ttl <= 0 {
		ttl = time.Minute
	}
	return s.client.Set(ctx, s.prefix+key, value, ttl).Err()
}

// PutIfAbsent implements core.Store with SET NX. | PutIfAbsent 使用 SET NX 实现 core.Store。
func (s *Store) PutIfAbsent(ctx context.Context, key string, value []byte, ttl time.Duration) (bool, error) {
	if key == "" {
		return false, errs.Detail(ErrInvalidOptions, "empty key | 空键")
	}
	if ttl <= 0 {
		ttl = time.Minute
	}
	return s.client.SetNX(ctx, s.prefix+key, value, ttl).Result()
}

// DeleteIf implements compare-and-delete for cooldown reservations. | DeleteIf 为冷却预占实现比较删除。
func (s *Store) DeleteIf(ctx context.Context, key string, value []byte) (bool, error) {
	deleted, err := s.client.Eval(ctx, deleteIfScript, []string{s.prefix + key}, value).Int()
	if err != nil {
		return false, err
	}
	return deleted == 1, nil
}

// Get implements core.Store and copies the Redis reply. | Get 实现 core.Store 并复制 Redis 回复。
func (s *Store) Get(ctx context.Context, key string) ([]byte, bool, error) {
	value, err := s.client.Get(ctx, s.prefix+key).Bytes()
	if err == goredis.Nil {
		return nil, false, nil
	}
	if err != nil {
		return nil, false, err
	}
	return append([]byte(nil), value...), true, nil
}

// Take implements core.Store with one atomic Lua script. | Take 用一个原子 Lua 脚本实现 core.Store。
func (s *Store) Take(ctx context.Context, key string) ([]byte, bool, error) {
	value, err := s.client.Eval(ctx, takeScript, []string{s.prefix + key}).Result()
	if err == goredis.Nil {
		return nil, false, nil
	}
	if err != nil {
		return nil, false, err
	}
	if value == nil {
		return nil, false, nil
	}
	switch typed := value.(type) {
	case string:
		return []byte(typed), true, nil
	case []byte:
		return append([]byte(nil), typed...), true, nil
	default:
		return nil, false, errs.Detail(ErrInvalidOptions, "unexpected Redis value type | 非预期的 Redis 值类型")
	}
}

// Delete implements core.Store. | Delete 实现 core.Store。
func (s *Store) Delete(ctx context.Context, key string) error {
	return s.client.Del(ctx, s.prefix+key).Err()
}

// NewRateLimitStore returns the shared token-bucket backend from ydx/middleware/ratelimit. | NewRateLimitStore 返回 ydx/middleware/ratelimit 的共享令牌桶后端。
//
// Pass it as Options.Limits.Store so challenge, verify and send limits are
// enforced across replicas. | 把它作为 Options.Limits.Store，使创建、验证与发送限流跨副本生效。
func NewRateLimitStore(client goredis.UniversalClient, prefix string) (*ratelimit.RedisStore, error) {
	if prefix == "" {
		prefix = "yd:captcha:rl:"
	}
	return ratelimit.NewRedisStore(ratelimit.RedisStoreOptions{Client: client, Prefix: prefix})
}

// ImageStoreOptions configures the Redis image store. | ImageStoreOptions 配置 Redis 图片存储。
type ImageStoreOptions struct {
	// Client is the Redis client shared by every replica. | Client 是各副本共享的 Redis 客户端。
	Client goredis.UniversalClient
	// Prefix is prepended to every key; empty means none. | Prefix 加到每个键之前；空值表示不加。
	Prefix string
}

// ImageStore is a core.ImageStore backed by Redis hashes. | ImageStore 是由 Redis 哈希支撑的 core.ImageStore。
type ImageStore struct {
	client goredis.UniversalClient
	prefix string
}

// NewImageStore builds a shared image store. | NewImageStore 构建共享图片存储。
func NewImageStore(o ImageStoreOptions) (*ImageStore, error) {
	if o.Client == nil {
		return nil, errs.Detail(ErrInvalidOptions, "nil Redis client | Redis 客户端为 nil")
	}
	return &ImageStore{client: o.Client, prefix: o.Prefix}, nil
}

// Put implements core.ImageStore. | Put 实现 core.ImageStore。
func (s *ImageStore) Put(ctx context.Context, key string, data []byte, mime string, ttl time.Duration) error {
	if key == "" {
		return errs.Detail(ErrInvalidOptions, "empty image key | 空图片键")
	}
	if ttl <= 0 {
		ttl = time.Minute
	}
	pipe := s.client.TxPipeline()
	pipe.HSet(ctx, s.prefix+key, "mime", mime, "data", data)
	pipe.PExpire(ctx, s.prefix+key, ttl)
	_, err := pipe.Exec(ctx)
	return err
}

// Get implements core.ImageStore. | Get 实现 core.ImageStore。
func (s *ImageStore) Get(ctx context.Context, key string) ([]byte, string, bool, error) {
	values, err := s.client.HGetAll(ctx, s.prefix+key).Result()
	if err != nil {
		return nil, "", false, err
	}
	if len(values) == 0 {
		return nil, "", false, nil
	}
	data, ok := values["data"]
	if !ok {
		return nil, "", false, nil
	}
	return []byte(data), values["mime"], true, nil
}

// Delete implements core.ImageStore. | Delete 实现 core.ImageStore。
func (s *ImageStore) Delete(ctx context.Context, key string) error {
	return s.client.Del(ctx, s.prefix+key).Err()
}

// PolicyProvider loads the dynamic policy from a Redis key. | PolicyProvider 从 Redis 键加载动态策略。
type PolicyProvider struct {
	client goredis.UniversalClient
	key    string
}

// NewPolicyProvider builds a policy provider. | NewPolicyProvider 构建策略提供器。
func NewPolicyProvider(client goredis.UniversalClient, key string) (*PolicyProvider, error) {
	if client == nil {
		return nil, errs.Detail(ErrInvalidOptions, "nil Redis client | Redis 客户端为 nil")
	}
	if key == "" {
		key = DefaultPolicyKey
	}
	return &PolicyProvider{client: client, key: key}, nil
}

// LoadPolicy implements core.PolicyProvider. | LoadPolicy 实现 core.PolicyProvider。
func (p *PolicyProvider) LoadPolicy(ctx context.Context) (*core.Policy, error) {
	payload, err := p.client.Get(ctx, p.key).Bytes()
	if err == goredis.Nil {
		return nil, errs.Detail(ErrPolicy, "policy key %q is missing | 策略键 %q 不存在", p.key, p.key)
	}
	if err != nil {
		return nil, err
	}
	var policy core.Policy
	if err := json.Unmarshal(payload, &policy); err != nil {
		return nil, errs.Wrap(err, ErrPolicy)
	}
	return &policy, nil
}

// StorePolicy writes a policy snapshot for all replicas. | StorePolicy 为所有副本写入策略快照。
func (p *PolicyProvider) StorePolicy(ctx context.Context, policy *core.Policy) error {
	if policy == nil {
		policy = &core.Policy{}
	}
	payload, err := json.Marshal(policy)
	if err != nil {
		return errs.Wrap(err, ErrPolicy)
	}
	return p.client.Set(ctx, p.key, payload, 0).Err()
}
