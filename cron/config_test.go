package cron

import (
	"path/filepath"
	"testing"
	"time"

	"github.com/shibingli/ydx/config"
)

// TestOptionsFromConfig maps the cron section through viper accessors. |
// TestOptionsFromConfig 经 viper 访问器映射 cron 配置段。
func TestOptionsFromConfig(t *testing.T) {
	dir := t.TempDir()
	loaded, err := config.Load(config.Options{
		ConfigDir:  dir,
		ConfigName: "config",
		EnvFile:    filepath.Join(dir, "absent.env"),
	})
	if err != nil {
		t.Fatalf("config.Load: %v | 加载配置失败", err)
	}
	t.Setenv("YD_CRON_CONCURRENCY", "7")
	t.Setenv("YD_CRON_QUEUE_SIZE", "2048")
	t.Setenv("YD_CRON_NODE_ID", "node-a")
	t.Setenv("YD_CRON_NAMESPACE", "billing")
	t.Setenv("YD_CRON_LOCK_TTL", "45s")
	t.Setenv("YD_CRON_LOCK_TIMEOUT", "3s")
	t.Setenv("YD_CRON_SHUTDOWN_TIMEOUT", "12s")
	t.Setenv("YD_CRON_HISTORY_LIMIT", "20")

	options := OptionsFromConfig(loaded)
	if options.Concurrency != 7 || options.QueueSize != 2048 {
		t.Fatalf("size options = %+v | 并发与队列配置不符", options)
	}
	if options.NodeID != "node-a" || options.Namespace != "billing" {
		t.Fatalf("identity options = %+v | 节点与命名空间配置不符", options)
	}
	if options.LockTTL != 45*time.Second || options.LockTimeout != 3*time.Second {
		t.Fatalf("lock options = %+v | 锁配置不符", options)
	}
	if options.ShutdownTimeout != 12*time.Second || options.HistoryLimit != 20 {
		t.Fatalf("lifecycle options = %+v | 生命周期配置不符", options)
	}
	if options.Store != nil || options.Locker != nil || options.Logger != nil {
		t.Fatalf("external collaborators must be wired by the application | 外部协作者应由应用装配")
	}
	zero := OptionsFromConfig(nil)
	if zero.Concurrency != 0 || zero.QueueSize != 0 || zero.NodeID != "" ||
		zero.Namespace != "" || zero.LockTTL != 0 || zero.HistoryLimit != 0 ||
		zero.Store != nil || zero.Locker != nil || zero.Logger != nil || zero.Now != nil {
		t.Fatalf("OptionsFromConfig(nil) = %+v | nil 配置应返回零值", zero)
	}
}
