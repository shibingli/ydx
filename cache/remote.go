package cache

import (
	"context"
	"time"
)

// Item is one value read from L2. | Item 是从 L2 读到的一个值。
type Item struct {
	// Raw is the full wire envelope, including the version and flag header. | Raw 是完整线路信封，含版本与标志头。
	// The slice is owned by the caller until the next Remote call. | 该切片归调用方所有，直到下一次 Remote 调用。
	Raw []byte
	// TTL is the remaining lifetime; 0 means the entry has no expiry. | TTL 是剩余存活时间；0 表示条目不过期。
	TTL time.Duration
}

// Remote is the L2 contract. Keys are logical keys without the deployment prefix; an | Remote 是 L2 契约。键是不含部署前缀的逻辑键；
// implementation applies its own prefix. Implementations must be safe for concurrent use. | 实现自行施加前缀。实现必须可并发使用。
//
// Every stored payload carries the wire envelope, so a Remote never interprets values. | 每个存储载荷都携带线路信封，因此 Remote 从不解释值本身。
// Store and StoreIf return the new version; StoreIf only writes when the current version | Store 与 StoreIf 返回新版本；StoreIf 只在当前版本
// equals expect, which is how cachex prevents a slow loader from overwriting a newer write. | 等于 expect 时写入，cachex 借此防止慢加载覆盖更新的写入。
type Remote interface {
	// Load returns one key; found is false when the key is absent. | Load 返回一个键；键不存在时 found 为 false。
	Load(ctx context.Context, key string) (item Item, found bool, err error)
	// LoadMany returns the keys that exist; missing keys are omitted. | LoadMany 返回存在的键；缺失的键不出现在结果中。
	LoadMany(ctx context.Context, keys []string) (map[string]Item, error)
	// Store writes one value and returns its new version. | Store 写入一个值并返回其新版本。
	Store(ctx context.Context, key string, data []byte, flags uint8, ttl time.Duration) (version uint64, err error)
	// StoreIf writes only when the current version equals expect; stored reports whether it wrote. | StoreIf 仅在当前版本等于 expect 时写入；stored 报告是否写入。
	StoreIf(ctx context.Context, key string, data []byte, flags uint8, ttl time.Duration, expect uint64) (version uint64, stored bool, err error)
	// Remove writes a tombstone or negative marker and returns its new version. | Remove 写入墓碑或负缓存标记并返回其新版本。
	Remove(ctx context.Context, key string, flags uint8, ttl time.Duration) (version uint64, err error)
	// Publish broadcasts an invalidation event. | Publish 广播失效事件。
	Publish(ctx context.Context, ev Event) error
	// Subscribe blocks, delivering events until ctx is cancelled or the subscription fails. | Subscribe 阻塞投递事件，直到 ctx 取消或订阅失败。
	Subscribe(ctx context.Context, handler func(Event)) error
	// Close releases subscription resources; the underlying client remains caller-owned. | Close 释放订阅资源；底层客户端仍归调用方所有。
	Close() error
}

// DeploymentScoper is implemented by remotes that can isolate one deployment's
// keys and event channel. Manager applies it with Options.DeploymentID before
// the remote is used. | DeploymentScoper 由能够隔离单个部署键与事件频道的远端实现。
// Manager 在使用远端前用 Options.DeploymentID 调用它。
type DeploymentScoper interface {
	// ScopeDeployment returns a remote scoped to deployment. | ScopeDeployment 返回
	// 限定到 deployment 的远端。
	ScopeDeployment(deployment string) Remote
}

// deploymentRemote adapts a Remote that cannot scope itself: logical keys gain
// a deployment prefix and events from other deployments are discarded. |
// deploymentRemote 适配无法自行限定的 Remote：逻辑键加部署前缀，并丢弃其它部署的事件。
type deploymentRemote struct {
	Remote
	deployment string
}

// scopedKey prefixes one logical key with the deployment. | scopedKey 给一个逻辑键加部署前缀。
func (d *deploymentRemote) scopedKey(key string) string { return d.deployment + ":" + key }

// Load implements Remote. | Load 实现 Remote。
func (d *deploymentRemote) Load(ctx context.Context, key string) (Item, bool, error) {
	return d.Remote.Load(ctx, d.scopedKey(key))
}

// LoadMany implements Remote. | LoadMany 实现 Remote。
func (d *deploymentRemote) LoadMany(ctx context.Context, keys []string) (map[string]Item, error) {
	scoped := make([]string, len(keys))
	for i, key := range keys {
		scoped[i] = d.scopedKey(key)
	}
	out, err := d.Remote.LoadMany(ctx, scoped)
	if err != nil || len(out) == 0 {
		return out, err
	}
	unscoped := make(map[string]Item, len(out))
	for _, key := range keys {
		if item, ok := out[d.scopedKey(key)]; ok {
			unscoped[key] = item
		}
	}
	return unscoped, nil
}

// Store implements Remote. | Store 实现 Remote。
func (d *deploymentRemote) Store(ctx context.Context, key string, data []byte, flags uint8, ttl time.Duration) (uint64, error) {
	return d.Remote.Store(ctx, d.scopedKey(key), data, flags, ttl)
}

// StoreIf implements Remote. | StoreIf 实现 Remote。
func (d *deploymentRemote) StoreIf(ctx context.Context, key string, data []byte, flags uint8, ttl time.Duration, expect uint64) (uint64, bool, error) {
	return d.Remote.StoreIf(ctx, d.scopedKey(key), data, flags, ttl, expect)
}

// Remove implements Remote. | Remove 实现 Remote。
func (d *deploymentRemote) Remove(ctx context.Context, key string, flags uint8, ttl time.Duration) (uint64, error) {
	return d.Remote.Remove(ctx, d.scopedKey(key), flags, ttl)
}

// Publish implements Remote. | Publish 实现 Remote。
func (d *deploymentRemote) Publish(ctx context.Context, ev Event) error {
	if ev.Deployment == "" {
		ev.Deployment = d.deployment
	}
	return d.Remote.Publish(ctx, ev)
}

// Subscribe implements Remote. | Subscribe 实现 Remote。
func (d *deploymentRemote) Subscribe(ctx context.Context, handler func(Event)) error {
	return d.Remote.Subscribe(ctx, func(ev Event) {
		if ev.Deployment != "" && ev.Deployment != d.deployment {
			return
		}
		handler(ev)
	})
}
