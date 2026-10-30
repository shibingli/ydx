package redis

import (
	"context"
	"errors"
	"sync/atomic"
	"testing"
	"time"

	"github.com/alicebob/miniredis/v2"
	goredis "github.com/redis/go-redis/v9"

	"github.com/shibingli/ydx/cron"
)

// newClient starts a miniredis instance and returns a client bound to it. |
// newClient 启动 miniredis 实例并返回绑定它的客户端。
func newClient(t *testing.T) (*miniredis.Miniredis, *goredis.Client) {
	t.Helper()
	server := miniredis.RunT(t)
	client := goredis.NewClient(&goredis.Options{Addr: server.Addr()})
	t.Cleanup(func() { _ = client.Close() })
	return server, client
}

// TestLocker covers exclusivity, refresh, unlock and expiry. |
// TestLocker 覆盖互斥、续租、释放与过期。
func TestLocker(t *testing.T) {
	server, client := newClient(t)
	first := NewLocker(client)
	second := NewLocker(client)
	ctx := context.Background()

	claim, ok, err := first.TryLock(ctx, "lock", time.Minute)
	if err != nil || !ok {
		t.Fatalf("TryLock = %v, %v | 首次加锁失败", ok, err)
	}
	if other, ok, _ := second.TryLock(ctx, "lock", time.Minute); ok {
		_ = other.Unlock(ctx)
		t.Fatal("second claim succeeded | 第二次加锁不应成功")
	}
	refresher, ok := claim.(cron.LockRefresher)
	if !ok {
		t.Fatal("redis lock does not implement LockRefresher | Redis 锁未实现续租")
	}
	if refreshed, err := refresher.Refresh(ctx, time.Minute); err != nil || !refreshed {
		t.Fatalf("Refresh = %v, %v | 续租失败", refreshed, err)
	}
	if err := claim.Unlock(ctx); err != nil {
		t.Fatalf("Unlock: %v | 释放失败", err)
	}
	reclaimed, ok, _ := second.TryLock(ctx, "lock", time.Minute)
	if !ok {
		t.Fatal("claim after Unlock failed | 释放后加锁失败")
	}
	_ = reclaimed.Unlock(ctx)

	stale, ok, _ := first.TryLock(ctx, "expiring", time.Second)
	if !ok {
		t.Fatal("TryLock(expiring) failed | 加锁失败")
	}
	server.FastForward(2 * time.Second)
	replacement, ok, _ := second.TryLock(ctx, "expiring", time.Minute)
	if !ok {
		t.Fatal("expired claim was not reclaimable | 过期锁未被回收")
	}
	if err := stale.Unlock(ctx); err != nil {
		t.Fatalf("stale Unlock: %v | 旧锁释放出错", err)
	}
	if other, ok, _ := first.TryLock(ctx, "expiring", time.Minute); ok {
		_ = other.Unlock(ctx)
		t.Fatal("stale Unlock removed the replacement | 旧锁释放影响了新锁")
	}
	_ = replacement.Unlock(ctx)
}

// TestSubMillisecondTTL verifies sub-millisecond durations are rounded up
// instead of producing an invalid Redis expiry. | TestSubMillisecondTTL 验证亚毫秒时长向上取整，
// 而不是生成非法的 Redis 过期时间。
func TestSubMillisecondTTL(t *testing.T) {
	_, client := newClient(t)
	locker := NewLocker(client)
	ctx := context.Background()
	claim, ok, err := locker.TryLock(ctx, "tiny", time.Microsecond)
	if err != nil || !ok {
		t.Fatalf("TryLock(tiny) = %v, %v | 亚毫秒加锁失败", ok, err)
	}
	if other, held, _ := NewLocker(client).TryLock(ctx, "tiny", time.Minute); held {
		_ = other.Unlock(ctx)
		t.Fatal("sub-millisecond claim vanished | 亚毫秒锁立即消失")
	}
	refreshed, err := claim.(cron.LockRefresher).Refresh(ctx, time.Microsecond)
	if err != nil || !refreshed {
		t.Fatalf("Refresh(tiny) = %v, %v | 亚毫秒续租失败", refreshed, err)
	}
	if other, held, _ := NewLocker(client).TryLock(ctx, "tiny", time.Minute); held {
		_ = other.Unlock(ctx)
		t.Fatal("sub-millisecond refresh dropped the claim | 亚毫秒续租丢失锁")
	}
	if err := claim.Unlock(ctx); err != nil {
		t.Fatalf("Unlock: %v | 释放失败", err)
	}
}

// TestStore covers JSON round trip, replacement, ordering and deletion. |
// TestStore 覆盖 JSON 往返、替换、排序与删除。
func TestStore(t *testing.T) {
	_, client := newClient(t)
	store := NewStore(client, "test")
	ctx := context.Background()

	first := cron.Definition{ID: "alpha", Name: "alpha", Task: "tick", Expression: "0 0 * * *"}
	second := cron.Definition{ID: "beta", Name: "beta", Task: "tick", Expression: "@every 1m0s"}
	if err := store.Save(ctx, second); err != nil {
		t.Fatalf("Save second: %v | 保存失败", err)
	}
	if err := store.Save(ctx, first); err != nil {
		t.Fatalf("Save first: %v | 保存失败", err)
	}
	definitions, err := store.List(ctx)
	if err != nil {
		t.Fatalf("List: %v | 列举失败", err)
	}
	if len(definitions) != 2 || definitions[0].ID != "alpha" || definitions[1].ID != "beta" {
		t.Fatalf("List = %+v | 列表不符", definitions)
	}

	first.Name = "renamed"
	first.Expression = "@every 2h0m0s"
	if err := store.Save(ctx, first); err != nil {
		t.Fatalf("Save replacement: %v | 替换失败", err)
	}
	definitions, _ = store.List(ctx)
	if definitions[0].Name != "renamed" || definitions[0].Expression != "@every 2h0m0s" {
		t.Fatalf("replacement = %+v | 替换未生效", definitions[0])
	}

	if err := store.Delete(ctx, "alpha"); err != nil {
		t.Fatalf("Delete: %v | 删除失败", err)
	}
	if err := store.Delete(ctx, "missing"); err != nil {
		t.Fatalf("Delete(missing) = %v, want nil | 删除不存在项应无错误", err)
	}
	definitions, _ = store.List(ctx)
	if len(definitions) != 1 || definitions[0].ID != "beta" {
		t.Fatalf("List after Delete = %+v | 删除后列表不符", definitions)
	}

	if err := store.Save(ctx, cron.Definition{Expression: "0 0 * * *"}); !errors.Is(err, cron.ErrInvalidDefinition) {
		t.Fatalf("Save(empty id) = %v, want ErrInvalidDefinition | 空 ID 错误不符", err)
	}
}

// TestNilClient verifies both adapters reject a nil client. |
// TestNilClient 验证两个适配器都拒绝 nil 客户端。
func TestNilClient(t *testing.T) {
	ctx := context.Background()
	if _, _, err := NewLocker(nil).TryLock(ctx, "key", time.Second); !errors.Is(err, ErrNilClient) {
		t.Fatalf("nil locker TryLock = %v, want ErrNilClient | nil 客户端锁错误不符", err)
	}
	if _, err := NewStore(nil, "").List(ctx); !errors.Is(err, ErrNilClient) {
		t.Fatalf("nil store List = %v, want ErrNilClient | nil 客户端存储错误不符", err)
	}
}

// TestRedisBackedSingleton proves two schedulers sharing Redis run one fire. |
// TestRedisBackedSingleton 证明共享 Redis 的两个调度器只执行一次触发。
func TestRedisBackedSingleton(t *testing.T) {
	_, client := newClient(t)
	locker := NewLocker(client)
	at := time.Now().Add(120 * time.Millisecond)
	var calls atomic.Int32
	handler := func(context.Context, *cron.Job) error {
		calls.Add(1)
		return nil
	}
	options := cron.Options{Concurrency: 2, Locker: locker, Namespace: "cluster", LockTTL: time.Second}
	first := cron.New(options)
	second := cron.New(options)
	for _, sch := range []*cron.Scheduler{first, second} {
		job := &cron.Job{ID: "shared", Schedule: cron.Once(at), Handler: handler, Singleton: true}
		if err := sch.Add(context.Background(), job); err != nil {
			t.Fatalf("Add: %v | 新增失败", err)
		}
		if err := sch.Start(context.Background()); err != nil {
			t.Fatalf("Start: %v | 启动失败", err)
		}
	}
	deadline := time.Now().Add(3 * time.Second)
	for calls.Load() == 0 && time.Now().Before(deadline) {
		time.Sleep(time.Millisecond)
	}
	time.Sleep(200 * time.Millisecond)
	if got := calls.Load(); got != 1 {
		t.Fatalf("singleton ran %d times, want 1 | Singleton 运行次数不符", got)
	}
	stop(t, first)
	stop(t, second)
}

// TestRedisStoreRestart proves definitions survive a scheduler restart. |
// TestRedisStoreRestart 证明定义跨调度器重启保留。
func TestRedisStoreRestart(t *testing.T) {
	_, client := newClient(t)
	store := NewStore(client, "restart")
	var calls atomic.Int32
	handler := func(context.Context, *cron.Job) error {
		calls.Add(1)
		return nil
	}

	first := cron.New(cron.Options{Store: store, Concurrency: 1, HistoryLimit: -1})
	if err := first.Register("tick", handler); err != nil {
		t.Fatalf("Register: %v | 注册失败", err)
	}
	job := &cron.Job{ID: "persisted", Task: "tick", Schedule: cron.Interval(20 * time.Millisecond)}
	if err := first.Add(context.Background(), job); err != nil {
		t.Fatalf("Add: %v | 新增失败", err)
	}
	if err := first.Start(context.Background()); err != nil {
		t.Fatalf("Start: %v | 启动失败", err)
	}
	deadline := time.Now().Add(3 * time.Second)
	for calls.Load() == 0 && time.Now().Before(deadline) {
		time.Sleep(time.Millisecond)
	}
	stop(t, first)

	second := cron.New(cron.Options{Store: store, Concurrency: 1, HistoryLimit: -1})
	if err := second.Register("tick", handler); err != nil {
		t.Fatalf("Register: %v | 注册失败", err)
	}
	if err := second.Start(context.Background()); err != nil {
		t.Fatalf("restore Start: %v | 恢复启动失败", err)
	}
	if _, ok := second.Get("persisted"); !ok {
		t.Fatal("job was not restored | 任务未恢复")
	}
	deadline = time.Now().Add(3 * time.Second)
	for calls.Load() < 2 && time.Now().Before(deadline) {
		time.Sleep(time.Millisecond)
	}
	if calls.Load() < 2 {
		t.Fatalf("restored job did not run: %d | 恢复的任务未运行", calls.Load())
	}
	stop(t, second)
}

// stop stops a scheduler with a bounded context. | stop 用带超时的上下文停止调度器。
func stop(t *testing.T, sch *cron.Scheduler) {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	if err := sch.Stop(ctx); err != nil {
		t.Fatalf("Stop: %v | 停止失败", err)
	}
}
