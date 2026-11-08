package wsfed_test

import (
	"context"
	"errors"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/alicebob/miniredis/v2"
	goredis "github.com/redis/go-redis/v9"

	authwsfed "github.com/shibingli/ydx/auth/protocol/wsfed"
	wsfedstore "github.com/shibingli/ydx/authstore/wsfed"
)

// TestRequestLifecycle covers save, consume, defaults, expiry and context handling.
// | TestRequestLifecycle 覆盖保存、消费、默认值、过期与上下文处理。
func TestRequestLifecycle(t *testing.T) {
	server := miniredis.RunT(t)
	first := newStoresOn(t, server, "")
	second := newStoresOn(t, server, "")
	zone := time.FixedZone("CST", 8*60*60)
	created := time.Now().Add(time.Hour).In(zone)
	expires := created.Add(time.Hour)
	state := authwsfed.RequestState{
		Wctx:      "w-1",
		Realm:     "https://app.example.com",
		ReplyURL:  "https://app.example.com/reply",
		CreatedAt: created,
		ExpiresAt: expires,
	}
	if err := first.SaveRequest(testContext, state); err != nil {
		t.Fatalf("save: %v | 保存失败", err)
	}
	taken, ok, err := second.TakeRequest(testContext, "w-1")
	if err != nil || !ok {
		t.Fatalf("take across instances: ok=%v err=%v | 跨实例消费失败", ok, err)
	}
	if taken.Wctx != state.Wctx || taken.Realm != state.Realm || taken.ReplyURL != state.ReplyURL {
		t.Fatalf("fields = %+v | 字段不一致", taken)
	}
	if !taken.CreatedAt.Equal(created) || !taken.ExpiresAt.Equal(expires) {
		t.Fatalf("times = %v/%v | 时间不一致", taken.CreatedAt, taken.ExpiresAt)
	}
	if taken.CreatedAt.Location() != time.UTC || taken.ExpiresAt.Location() != time.UTC {
		t.Fatalf("times not UTC: %v/%v | 时间未规范化为 UTC", taken.CreatedAt, taken.ExpiresAt)
	}
	if _, ok, err := first.TakeRequest(testContext, "w-1"); err != nil || ok {
		t.Fatalf("second take = %v/%v, want consumed | 二次消费未返回不存在", ok, err)
	}

	defaultStart := time.Now().Add(-time.Second)
	if err := first.SaveRequest(testContext, authwsfed.RequestState{Wctx: "w-default"}); err != nil {
		t.Fatalf("save defaults: %v | 保存默认请求失败", err)
	}
	taken, ok, err = second.TakeRequest(testContext, "w-default")
	if err != nil || !ok {
		t.Fatalf("take defaults: ok=%v err=%v | 消费默认请求失败", ok, err)
	}
	if taken.CreatedAt.Before(defaultStart) || taken.CreatedAt.After(time.Now().Add(time.Second)) {
		t.Fatalf("default CreatedAt = %v | 默认创建时间不正确", taken.CreatedAt)
	}
	if delta := taken.ExpiresAt.Sub(taken.CreatedAt); delta < 9*time.Minute || delta > 11*time.Minute {
		t.Fatalf("default lifetime = %s | 默认寿命不正确", delta)
	}
	if taken.CreatedAt.Location() != time.UTC || taken.ExpiresAt.Location() != time.UTC {
		t.Fatalf("default times not UTC | 默认时间未规范化为 UTC")
	}

	if err := first.SaveRequest(testContext, authwsfed.RequestState{Wctx: "  w-trim  "}); err != nil {
		t.Fatalf("save padded wctx: %v | 保存带空格 wctx 失败", err)
	}
	if _, ok, err := second.TakeRequest(testContext, " w-trim "); err != nil || !ok {
		t.Fatalf("trimmed take: ok=%v err=%v | 去空格消费失败", ok, err)
	}
}

// TestRequestExpired covers an already-expired record, which is consumed and reported absent.
// | TestRequestExpired 覆盖已过期记录：它会被消费并按不存在报告。
func TestRequestExpired(t *testing.T) {
	first, second := newPair(t)
	if err := first.SaveRequest(testContext, authwsfed.RequestState{
		Wctx:      "w-expired",
		ExpiresAt: time.Now().Add(-time.Minute),
	}); err != nil {
		t.Fatalf("save expired: %v | 保存已过期请求失败", err)
	}
	if _, ok, err := second.TakeRequest(testContext, "w-expired"); err != nil || ok {
		t.Fatalf("expired take = %v/%v, want false | 过期请求未被拒绝", ok, err)
	}
	if _, ok, err := first.TakeRequest(testContext, "w-expired"); err != nil || ok {
		t.Fatalf("expired take twice = %v/%v, want false | 过期请求未被删除", ok, err)
	}
}

// TestRequestValidation covers empty keys, contexts and corrupt records.
// | TestRequestValidation 覆盖空键、上下文与损坏记录。
func TestRequestValidation(t *testing.T) {
	server := miniredis.RunT(t)
	store := newStoresOn(t, server, "")
	if err := store.SaveRequest(testContext, authwsfed.RequestState{Wctx: "   "}); !errors.Is(err, authwsfed.ErrInvalidRequest) {
		t.Fatalf("empty wctx save = %v, want ErrInvalidRequest | 空 wctx 保存错误不符", err)
	}
	if _, ok, err := store.TakeRequest(testContext, "  "); err != nil || ok {
		t.Fatalf("empty wctx take = %v/%v | 空 wctx 消费错误不符", ok, err)
	}
	var nilContext context.Context
	if err := store.SaveRequest(nilContext, authwsfed.RequestState{Wctx: "w-nil", ExpiresAt: time.Now().Add(time.Minute)}); err != nil {
		t.Fatalf("nil context save = %v | nil 上下文保存失败", err)
	}
	if _, ok, err := store.TakeRequest(nilContext, "w-nil"); err != nil || !ok {
		t.Fatalf("nil context take = %v/%v | nil 上下文消费失败", ok, err)
	}

	cancelled, cancel := context.WithCancel(testContext)
	cancel()
	if err := store.SaveRequest(cancelled, authwsfed.RequestState{Wctx: "w-cancel"}); !errors.Is(err, context.Canceled) {
		t.Fatalf("cancelled save = %v, want context.Canceled | 取消上下文保存错误不符", err)
	}
	if _, _, err := store.TakeRequest(cancelled, "w-cancel"); !errors.Is(err, context.Canceled) {
		t.Fatalf("cancelled take = %v, want context.Canceled | 取消上下文消费错误不符", err)
	}

	wctx := "w-corrupt"
	if err := store.SaveRequest(testContext, authwsfed.RequestState{
		Wctx:      wctx,
		ExpiresAt: time.Now().Add(time.Minute),
	}); err != nil {
		t.Fatalf("save corrupt fixture: %v | 保存损坏记录夹具失败", err)
	}
	raw := goredis.NewClient(&goredis.Options{Addr: server.Addr()})
	t.Cleanup(func() {
		_ = raw.Close()
	})
	key := wsfedstore.DefaultKeyPrefix + "{authstore:wsfed}:request:" +
		strconv.Itoa(len(wctx)) + ":" + wctx
	if err := raw.Set(testContext, key, "not-json", 0).Err(); err != nil {
		t.Fatalf("overwrite request: %v | 覆盖请求失败", err)
	}
	if _, ok, err := store.TakeRequest(testContext, wctx); ok || !errors.Is(err, wsfedstore.ErrCorruptRecord) {
		t.Fatalf("corrupt take = %v/%v, want ErrCorruptRecord | 损坏记录错误不符", ok, err)
	}
}

// TestRequestConcurrentTakeExactlyOnce models many instances racing for one record.
// | TestRequestConcurrentTakeExactlyOnce 模拟多实例争抢同一条记录。
func TestRequestConcurrentTakeExactlyOnce(t *testing.T) {
	first, second := newPair(t)
	if err := first.SaveRequest(testContext, authwsfed.RequestState{
		Wctx:      "w-race",
		ExpiresAt: time.Now().Add(time.Hour),
	}); err != nil {
		t.Fatalf("save: %v | 保存失败", err)
	}
	var successes atomic.Int64
	var failures atomic.Int64
	var wg sync.WaitGroup
	for i := 0; i < 64; i++ {
		store := first
		if i%2 == 1 {
			store = second
		}
		wg.Add(1)
		go func(store *wsfedstore.Store) {
			defer wg.Done()
			_, ok, err := store.TakeRequest(testContext, "w-race")
			if err != nil {
				failures.Add(1)
				return
			}
			if ok {
				successes.Add(1)
			}
		}(store)
	}
	wg.Wait()
	if failures.Load() != 0 {
		t.Fatalf("take failures = %d | 消费失败次数非零", failures.Load())
	}
	if successes.Load() != 1 {
		t.Fatalf("take successes = %d, want 1 | 成功消费次数不为 1", successes.Load())
	}
}

// TestRequestRedisExpiry checks that the Redis key lifetime mirrors ExpiresAt. | TestRequestRedisExpiry
// 检查 Redis 键寿命与 ExpiresAt 对应。
func TestRequestRedisExpiry(t *testing.T) {
	server := miniredis.RunT(t)
	store := newStoresOn(t, server, "")
	if err := store.SaveRequest(testContext, authwsfed.RequestState{
		Wctx:      "w-ttl",
		ExpiresAt: time.Now().Add(5 * time.Minute),
	}); err != nil {
		t.Fatalf("save: %v | 保存失败", err)
	}
	keys := server.Keys()
	if len(keys) != 1 {
		t.Fatalf("keys = %v | 键数量不正确", keys)
	}
	ttl := server.TTL(keys[0])
	if ttl < 4*time.Minute || ttl > 6*time.Minute {
		t.Fatalf("TTL = %s, want about 5m | TTL 与 ExpiresAt 不对应", ttl)
	}
	if strings.Contains(keys[0], "w-ttl") == false {
		t.Fatalf("unexpected key %q | 键内容异常", keys[0])
	}
}
