package realtime

import (
	"strings"

	"github.com/shibingli/ydx/config"
)

// OptionsFromConfig reads the realtime section of the layered configuration. |
// OptionsFromConfig 读取分层配置的 realtime 段。
//
// Keys: | 配置键：
//
//	realtime.node_id            this node's id (empty falls back to node.id, then the
//	                            nodeid identity file) | 本节点 id（空值回退到 node.id，
//	                            再回退到 nodeid 身份文件）
//	realtime.queue_size         per-subscription queue length (default 256) | 每个订阅的队列长度
//	realtime.max_message_bytes  one message limit (default 1 MiB) | 单条消息上限
//	realtime.slow_policy        drop | close (default drop) | 慢消费者策略
//	realtime.authorize          reserved; authorization is wired in code | 保留；授权在代码中接线
//
// A nil Config yields default options. | Config 为 nil 时返回默认选项。
//
// The hub itself resolves an empty NodeID from nodeid when it is constructed,
// so a caller that builds Options directly still gets a persistent identity when
// the application has created the file. | Hub 在构造时会经 nodeid 解析空的 NodeID，因此
// 直接构造 Options 的调用方在应用已创建身份文件时仍能拿到持久身份。
func OptionsFromConfig(c *config.Config) Options {
	if c == nil {
		return Options{}
	}
	policy, err := ParseSlowPolicy(c.GetString("realtime.slow_policy"))
	if err != nil {
		policy = SlowDrop
	}
	return Options{
		NodeID:          firstNonEmpty(c.GetString("realtime.node_id"), c.GetString("node.id")),
		QueueSize:       c.GetInt("realtime.queue_size"),
		MaxMessageBytes: c.GetInt("realtime.max_message_bytes"),
		SlowPolicy:      policy,
	}
}

// firstNonEmpty returns the first non-blank value. | firstNonEmpty 返回第一个非空白值。
func firstNonEmpty(values ...string) string {
	for _, value := range values {
		if trimmed := strings.TrimSpace(value); trimmed != "" {
			return trimmed
		}
	}
	return ""
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
