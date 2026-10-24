package gormcache

import (
	"github.com/shibingli/ydx/cache"
	"github.com/shibingli/ydx/config"
)

// OptionsFromConfig maps cache.gorm.* into plugin options. | OptionsFromConfig 把 cache.gorm.* 映射为插件选项。
//
// The manager is passed explicitly because the plugin never opens a cache on its own. | 管理器显式传入，因为插件从不自行打开缓存。
func OptionsFromConfig(c *config.Config, m *cache.Manager) Options {
	o := Options{Manager: m}
	if c == nil {
		return o
	}
	o.Namespace = c.GetString("cache.gorm.namespace")
	o.TTL = c.GetDuration("cache.gorm.ttl")
	o.Tables = c.GetStringSlice("cache.gorm.tables")
	o.IgnoreTables = c.GetStringSlice("cache.gorm.ignore_tables")
	o.SensitiveTables = c.GetStringSlice("cache.gorm.sensitive_tables")
	o.SensitiveNamespace = c.GetString("cache.gorm.sensitive_namespace")
	o.SensitiveTTL = c.GetDuration("cache.gorm.sensitive_ttl")
	return o
}

// EnabledFromConfig reports whether cache.gorm.enabled is true. | EnabledFromConfig 报告 cache.gorm.enabled 是否为真。
func EnabledFromConfig(c *config.Config) bool {
	if c == nil {
		return false
	}
	return c.GetBool("cache.gorm.enabled")
}
