package redis

import (
	"context"
	"sort"
	"strings"

	goredis "github.com/redis/go-redis/v9"

	"github.com/shibingli/ydx/cron"
	"github.com/shibingli/ydx/errs"
	"github.com/shibingli/ydx/json"
)

// Store implements cron.Store on one Redis hash. | Store 用一个 Redis 哈希实现 cron.Store。
type Store struct {
	client goredis.UniversalClient
	key    string
}

// NewStore wraps a Redis client as a cron Store under namespace. A blank
// namespace uses "cron". | NewStore 把 Redis 客户端包装为 namespace 下的 cron Store；
// 空命名空间使用 "cron"。
func NewStore(client goredis.UniversalClient, namespace string) *Store {
	prefix := strings.TrimSpace(namespace)
	if prefix == "" {
		prefix = "cron"
	}
	return &Store{client: client, key: prefix + ":jobs"}
}

// Save inserts or replaces a definition. | Save 插入或替换定义。
func (s *Store) Save(ctx context.Context, definition cron.Definition) error {
	if s == nil || s.client == nil {
		return ErrNilClient
	}
	if ctx == nil {
		ctx = context.Background()
	}
	if definition.ID == "" {
		return errs.Detail(cron.ErrInvalidDefinition, "empty id")
	}
	raw, err := json.Marshal(definition)
	if err != nil {
		return errs.WrapDetail(err, cron.ErrStoreFailed, "%q", definition.ID)
	}
	if err := s.client.HSet(ctx, s.key, definition.ID, raw).Err(); err != nil {
		return errs.WrapDetail(err, cron.ErrStoreFailed, "%q", definition.ID)
	}
	return nil
}

// Delete removes a definition; a missing id is not an error. | Delete 删除定义；不存在不报错。
func (s *Store) Delete(ctx context.Context, id string) error {
	if s == nil || s.client == nil {
		return ErrNilClient
	}
	if ctx == nil {
		ctx = context.Background()
	}
	if err := s.client.HDel(ctx, s.key, id).Err(); err != nil {
		return errs.WrapDetail(err, cron.ErrStoreFailed, "%q", id)
	}
	return nil
}

// List returns every definition ordered by id. | List 按 ID 排序返回全部定义。
func (s *Store) List(ctx context.Context) ([]cron.Definition, error) {
	if s == nil || s.client == nil {
		return nil, ErrNilClient
	}
	if ctx == nil {
		ctx = context.Background()
	}
	stored, err := s.client.HGetAll(ctx, s.key).Result()
	if err != nil {
		return nil, errs.Wrap(err, cron.ErrStoreFailed)
	}
	definitions := make([]cron.Definition, 0, len(stored))
	for id, raw := range stored {
		var definition cron.Definition
		if err := json.Unmarshal([]byte(raw), &definition); err != nil {
			return nil, errs.WrapDetail(err, cron.ErrStoreFailed, "%q", id)
		}
		definitions = append(definitions, definition)
	}
	sort.Slice(definitions, func(i, j int) bool { return definitions[i].ID < definitions[j].ID })
	return definitions, nil
}

// compile-time assertion for the Redis Store. | Redis Store 的编译期断言。
var _ cron.Store = (*Store)(nil)
