package cron

import "github.com/shibingli/ydx/config"

// OptionsFromConfig maps the cron section of the framework config onto Options. |
// OptionsFromConfig 把框架配置的 cron 段映射为 Options。
//
// Keys (all optional; zero values fall back to the New defaults): |
// 配置键（全部可选；零值回落到 New 的默认值）：
//
//	cron.concurrency        number of workers | 工作协程数
//	cron.queue_size         pending-run buffer | 待运行队列容量
//	cron.node_id            node identity in lock keys | 锁键中的节点标识
//	cron.namespace          lock and store key prefix | 锁与存储键前缀
//	cron.lock_ttl           claim lifetime and fire deduplication window | 锁有效期与触发去重窗口
//	cron.lock_timeout       one TryLock budget | 单次加锁预算
//	cron.shutdown_timeout   graceful-shutdown budget | 优雅关闭预算
//	cron.history_limit      per-job run-record ring size; negative disables | 每任务运行记录环大小，负数关闭
//
// Store, Locker, Logger and Hooks are intentionally not read here: they are
// process collaborators an application wires itself (for example a Redis
// implementation from cron/redis). A nil c yields the zero Options. |
// 这里刻意不读取 Store、Locker、Logger 与 Hooks：它们是应用自行装配的进程内协作者
// （例如 cron/redis 提供的 Redis 实现）。c 为 nil 时返回零值 Options。
func OptionsFromConfig(c *config.Config) Options {
	if c == nil {
		return Options{}
	}
	return Options{
		Concurrency:     c.GetInt("cron.concurrency"),
		QueueSize:       c.GetInt("cron.queue_size"),
		NodeID:          c.GetString("cron.node_id"),
		Namespace:       c.GetString("cron.namespace"),
		LockTTL:         c.Duration("cron.lock_ttl"),
		LockTimeout:     c.Duration("cron.lock_timeout"),
		ShutdownTimeout: c.Duration("cron.shutdown_timeout"),
		HistoryLimit:    c.GetInt("cron.history_limit"),
	}
}
