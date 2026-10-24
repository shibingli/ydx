package realtime

import (
	"github.com/shibingli/ydx/config"
)

// OptionsFromConfig reads the realtime section of the layered configuration. |
// OptionsFromConfig 读取分层配置的 realtime 段。
//
// Keys: | 配置键：
//
//	realtime.node_id            this node's id (empty derives one) | 本节点 id（空值自动推导）
//	realtime.queue_size         per-subscription queue length (default 256) | 每个订阅的队列长度
//	realtime.max_message_bytes  one message limit (default 1 MiB) | 单条消息上限
//	realtime.slow_policy        drop | close (default drop) | 慢消费者策略
//	realtime.authorize          reserved; authorization is wired in code | 保留；授权在代码中接线
//
// A nil Config yields default options. | Config 为 nil 时返回默认选项。
func OptionsFromConfig(c *config.Config) Options {
	if c == nil {
		return Options{}
	}
	policy, err := ParseSlowPolicy(c.GetString("realtime.slow_policy"))
	if err != nil {
		policy = SlowDrop
	}
	return Options{
		NodeID:          c.GetString("realtime.node_id"),
		QueueSize:       c.GetInt("realtime.queue_size"),
		MaxMessageBytes: c.GetInt("realtime.max_message_bytes"),
		SlowPolicy:      policy,
	}
}

// RedisOptionsFromConfig reads the Redis channel settings. | RedisOptionsFromConfig 读取
// Redis 频道设置。
//
// Keys: | 配置键：
//
//	realtime.channel_prefix      channel namespace (default yd:rt:) | 频道命名空间
//	realtime.queue_size          per-topic Redis delivery buffer | 每个主题的 Redis 投递缓冲
//	realtime.max_message_bytes   one remote payload limit | 单条远端载荷上限
func RedisOptionsFromConfig(c *config.Config) RedisOptions {
	if c == nil {
		return RedisOptions{}
	}
	return RedisOptions{
		ChannelPrefix:   c.GetString("realtime.channel_prefix"),
		QueueSize:       c.GetInt("realtime.queue_size"),
		MaxMessageBytes: c.GetInt("realtime.max_message_bytes"),
	}
}
