package cache

import (
	"context"
	"strings"
	"testing"
	"time"

	"github.com/alicebob/miniredis/v2"
	"github.com/redis/go-redis/v9"
)

// newDeploymentManager builds a Redis-backed manager scoped to deployment. | newDeploymentManager
// 构造限定到 deployment 的 Redis 管理器。
func newDeploymentManager(t *testing.T, mr *miniredis.Miniredis, deployment string) *Manager {
	t.Helper()
	cli := redis.NewClient(&redis.Options{Addr: mr.Addr()})
	t.Cleanup(func() { _ = cli.Close() })
	remote, err := NewRedisRemote(cli, RedisOptions{Prefix: "dep:", HealthInterval: 50 * time.Millisecond})
	if err != nil {
		t.Fatalf("NewRedisRemote: %v | 构造远端失败", err)
	}
	opts := []Option{
		WithRemote(remote),
		WithLocalOptions(testLocal()),
		WithLogger(testLogger()),
		WithLease(time.Minute),
	}
	if deployment != "" {
		opts = append(opts, WithDeploymentID(deployment))
	}
	m, err := NewManager(opts...)
	if err != nil {
		t.Fatalf("NewManager: %v | 构造管理器失败", err)
	}
	t.Cleanup(func() { _ = m.Close() })
	return m
}

// waitDeploymentChannels blocks until both deployment channels have a subscriber. |
// waitDeploymentChannels 阻塞到两个部署频道都有订阅者。
func waitDeploymentChannels(t *testing.T, mr *miniredis.Miniredis, channels ...string) {
	t.Helper()
	deadline := time.Now().Add(3 * time.Second)
	for time.Now().Before(deadline) {
		counts := mr.PubSubNumSub(channels...)
		ready := true
		for _, ch := range channels {
			if counts[ch] < 1 {
				ready = false
				break
			}
		}
		if ready {
			return
		}
		time.Sleep(10 * time.Millisecond)
	}
	t.Fatalf("等待部署频道订阅超时: %v", mr.PubSubChannels("dep:*"))
}

// TestDeploymentIsolation asserts managers with different deployment IDs share
// neither keys nor events even when they use the same Redis prefix. |
// TestDeploymentIsolation 断言不同部署 ID 的管理器即使使用相同 Redis 前缀，也不共享
// 键与事件。
func TestDeploymentIsolation(t *testing.T) {
	mr := miniredis.RunT(t)
	mgrA := newDeploymentManager(t, mr, "staging")
	mgrB := newDeploymentManager(t, mr, "prod")
	rawA, err := mgrA.Raw("shared")
	if err != nil {
		t.Fatalf("Raw A: %v", err)
	}
	rawB, err := mgrB.Raw("shared")
	if err != nil {
		t.Fatalf("Raw B: %v", err)
	}
	ctx := context.Background()
	if err := rawA.Set(ctx, "k", []byte("a")); err != nil {
		t.Fatalf("A Set: %v", err)
	}
	if _, ok, err := rawB.Get(ctx, "k"); err != nil || ok {
		t.Fatalf("B 读到了 A 的键: ok=%v err=%v", ok, err)
	}
	keys := mr.Keys()
	if !containsKey(keys, "dep:staging:shared:k") {
		t.Fatalf("缺少 staging 键: %v", keys)
	}
	if containsKey(keys, "dep:shared:k") {
		t.Fatalf("出现未限定部署的键: %v", keys)
	}
	if err := rawB.Set(ctx, "k", []byte("b")); err != nil {
		t.Fatalf("B Set: %v", err)
	}
	if got, ok, err := rawB.Get(ctx, "k"); err != nil || !ok || string(got) != "b" {
		t.Fatalf("B 读到 %q ok=%v err=%v, 期望 b", got, ok, err)
	}

	waitDeploymentChannels(t, mr, "dep:staging:events", "dep:prod:events")
	events := make(chan Event, 4)
	unsub, err := mgrB.Subscribe(func(ev Event) {
		// B's own writes are delivered on its local bus; only remote events matter here. |
		// B 自己的写入会经本地总线投递；这里只关心远端事件。
		if ev.Source == mgrB.NodeID() {
			return
		}
		events <- ev
	})
	if err != nil {
		t.Fatalf("Subscribe: %v", err)
	}
	defer unsub()
	if err := rawA.Set(ctx, "k2", []byte("a2")); err != nil {
		t.Fatalf("A Set: %v", err)
	}
	select {
	case ev := <-events:
		t.Fatalf("跨部署收到事件: %+v", ev)
	case <-time.After(150 * time.Millisecond):
	}
}

// TestDeploymentIsolationForGenericRemote asserts an explicit deployment ID also
// isolates custom remotes that do not implement DeploymentScoper. |
// TestDeploymentIsolationForGenericRemote 断言显式部署 ID 同样能隔离未实现
// DeploymentScoper 的自定义远端。
func TestDeploymentIsolationForGenericRemote(t *testing.T) {
	f := newFakeRemote()
	mgrA := newTestManager(t, f, WithDeploymentID("staging"))
	mgrB := newTestManager(t, f, WithDeploymentID("prod"))
	rawA, err := mgrA.Raw("shared")
	if err != nil {
		t.Fatalf("Raw A: %v", err)
	}
	rawB, err := mgrB.Raw("shared")
	if err != nil {
		t.Fatalf("Raw B: %v", err)
	}
	ctx := context.Background()
	if err := rawA.Set(ctx, "k", []byte("a")); err != nil {
		t.Fatalf("A Set: %v", err)
	}
	if _, ok, err := rawB.Get(ctx, "k"); err != nil || ok {
		t.Fatalf("B 读到了 A 的键: ok=%v err=%v", ok, err)
	}
	if data, _, ok := f.value("staging:shared:k"); !ok || string(data) != "a" {
		t.Fatalf("自定义远端缺少 staging 键: %q,%v", data, ok)
	}
	waitSubscribed(t, f, 2)
	events := make(chan Event, 4)
	unsub, err := mgrB.Subscribe(func(ev Event) {
		if ev.Source == mgrB.NodeID() {
			return
		}
		events <- ev
	})
	if err != nil {
		t.Fatalf("Subscribe: %v", err)
	}
	defer unsub()
	if err := rawA.Set(ctx, "k2", []byte("a2")); err != nil {
		t.Fatalf("A Set: %v", err)
	}
	select {
	case ev := <-events:
		t.Fatalf("自定义远端跨部署收到事件: %+v", ev)
	case <-time.After(100 * time.Millisecond):
	}
}

// containsKey reports whether keys contains want. | containsKey 报告 keys 是否包含 want。
func containsKey(keys []string, want string) bool {
	for _, key := range keys {
		if key == want {
			return true
		}
	}
	return false
}

// TestDefaultDeploymentIDIncludesEnvironment asserts the default identifier is
// derived from the binary name plus YD_ENV and is safe for a key prefix. |
// TestDefaultDeploymentIDIncludesEnvironment 断言默认标识由二进制名与 YD_ENV
// 推导，且可安全用作键前缀。
func TestDefaultDeploymentIDIncludesEnvironment(t *testing.T) {
	t.Setenv("YD_ENV", "staging")
	id := defaultDeploymentID()
	if id == "" {
		t.Fatal("默认部署 ID 为空")
	}
	if !strings.Contains(id, "staging") {
		t.Fatalf("默认部署 ID = %q, 未包含 YD_ENV", id)
	}
	if strings.ContainsAny(id, ":\x00\r\n\t ") {
		t.Fatalf("默认部署 ID = %q, 含有不安全字符", id)
	}
}

// TestDefaultDeploymentScopesManagerKeys asserts a manager without an explicit
// deployment ID still writes deployment-scoped keys. | TestDefaultDeploymentScopesManagerKeys
// 断言未显式配置部署 ID 的管理器仍写入带部署前缀的键。
func TestDefaultDeploymentScopesManagerKeys(t *testing.T) {
	mr := miniredis.RunT(t)
	mgr := newDeploymentManager(t, mr, "")
	raw, err := mgr.Raw("shared")
	if err != nil {
		t.Fatalf("Raw: %v", err)
	}
	if err := raw.Set(context.Background(), "k", []byte("v")); err != nil {
		t.Fatalf("Set: %v", err)
	}
	keys := mr.Keys()
	if containsKey(keys, "dep:shared:k") {
		t.Fatalf("未限定部署的键仍然存在: %v", keys)
	}
	found := false
	for _, key := range keys {
		if strings.HasPrefix(key, "dep:") && strings.HasSuffix(key, ":shared:k") {
			found = true
		}
	}
	if !found {
		t.Fatalf("缺少部署限定键: %v", keys)
	}
}
