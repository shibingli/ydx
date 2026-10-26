package redisstore

import (
	"context"

	goredis "github.com/redis/go-redis/v9"

	"github.com/shibingli/ydx/captcha/core"
	"github.com/shibingli/ydx/errs"
	"github.com/shibingli/ydx/json"
)

// DefaultPolicyChannel is the Redis Pub/Sub channel used by PolicyBus. | DefaultPolicyChannel 是 PolicyBus 使用的 Redis Pub/Sub 通道。
const DefaultPolicyChannel = "yd:captcha:policy:events"

// PolicyBus propagates policy snapshots to every replica through Redis Pub/Sub. | PolicyBus 通过 Redis Pub/Sub 把策略快照传播到每个副本。
type PolicyBus struct {
	client    goredis.UniversalClient
	channel   string
	policyKey string
}

// NewPolicyBus builds a policy bus that also persists snapshots to DefaultPolicyKey. | NewPolicyBus 构建策略总线，并把快照持久化到 DefaultPolicyKey。
func NewPolicyBus(client goredis.UniversalClient, channel string) (*PolicyBus, error) {
	return NewPolicyBusWithKey(client, channel, DefaultPolicyKey)
}

// NewPolicyBusWithKey builds a policy bus for a custom provider key. | NewPolicyBusWithKey 为自定义策略键构建总线。
//
// Pass the same key as NewPolicyProvider so a refresh can never overwrite a
// newer broadcast with an older stored snapshot. | 传入与 NewPolicyProvider
// 相同的键，避免刷新用旧快照覆盖较新的广播。
func NewPolicyBusWithKey(client goredis.UniversalClient, channel, policyKey string) (*PolicyBus, error) {
	if client == nil {
		return nil, errs.Detail(ErrInvalidOptions, "nil Redis client | Redis 客户端为 nil")
	}
	if channel == "" {
		channel = DefaultPolicyChannel
	}
	if policyKey == "" {
		policyKey = DefaultPolicyKey
	}
	return &PolicyBus{client: client, channel: channel, policyKey: policyKey}, nil
}

// Publish sends a policy snapshot to all subscribers. | Publish 把策略快照发送给所有订阅者。
func (b *PolicyBus) Publish(ctx context.Context, policy *core.Policy) error {
	if policy == nil {
		policy = &core.Policy{}
	}
	payload, err := json.Marshal(policy)
	if err != nil {
		return errs.Wrap(err, ErrPolicy)
	}
	if err := b.client.Set(ctx, b.policyKey, payload, 0).Err(); err != nil {
		return err
	}
	return b.client.Publish(ctx, b.channel, payload).Err()
}

// PolicyApplier accepts policy snapshots. | PolicyApplier 接收策略快照。
type PolicyApplier interface {
	SetPolicy(*core.Policy) error
}

// Watch applies published policy snapshots to a Manager until ctx is cancelled. | Watch 把已发布策略快照应用到 Manager，直到 ctx 取消。
//
// Run it in a goroutine owned by the host; Watch returns when ctx is done. Use
// either Watch, a PolicyProvider refresh loop, or both. | 由宿主在协程中运行；ctx 结束时
// Watch 返回。可只用 Watch、只用 PolicyProvider 刷新，或两者并用。
func (b *PolicyBus) Watch(ctx context.Context, manager PolicyApplier) error {
	if manager == nil {
		return errs.Detail(ErrInvalidOptions, "nil manager | Manager 为 nil")
	}
	subscription := b.client.Subscribe(ctx, b.channel)
	defer subscription.Close()
	channel := subscription.Channel()
	for {
		select {
		case <-ctx.Done():
			return ctx.Err()
		case message, ok := <-channel:
			if !ok {
				return nil
			}
			var policy core.Policy
			if err := json.Unmarshal([]byte(message.Payload), &policy); err != nil {
				continue
			}
			_ = manager.SetPolicy(&policy)
		}
	}
}
