package kerberos

import (
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

// TestReplayCacheAdd verifies duplicate rejection and expiry. | TestReplayCacheAdd 校验
// 重复拒绝与过期。
func TestReplayCacheAdd(t *testing.T) {
	now := time.Unix(1700000000, 0).UTC()
	cache := NewReplayCache(time.Minute)
	if cache.ttl != time.Minute {
		t.Fatalf("ttl = %v, want 1m", cache.ttl)
	}
	if !cache.Add("first", now, now.Add(time.Minute)) {
		t.Fatal("first Add = false, want true")
	}
	if cache.Add("first", now, now.Add(time.Minute)) {
		t.Fatal("duplicate Add = true, want false")
	}
	if cache.Len() != 1 {
		t.Fatalf("Len = %d, want 1", cache.Len())
	}
	if !cache.Add("first", now.Add(time.Minute+time.Second), now.Add(2*time.Minute)) {
		t.Fatal("Add after expiry = false, want true")
	}
	if !cache.Add("second", now, now.Add(-time.Second)) {
		t.Fatal("Add with past expiry = false, want true")
	}
	if cache.Add("second", now.Add(30*time.Second), now.Add(time.Minute)) {
		t.Fatal("Add within ttl after past expiry = true, want false")
	}
	if !cache.Add("second", now.Add(2*time.Minute), now.Add(3*time.Minute)) {
		t.Fatal("Add after ttl = false, want true")
	}
	var nilCache *ReplayCache
	if !nilCache.Add("x", now, now) {
		t.Fatal("nil cache Add = false, want true")
	}
	if nilCache.Len() != 0 {
		t.Fatal("nil cache Len != 0")
	}
	if NewReplayCache(0).ttl != DefaultReplayCacheTTL {
		t.Fatal("NewReplayCache(0) did not select the default ttl")
	}
	if NewReplayCache(-time.Second).ttl != DefaultReplayCacheTTL {
		t.Fatal("NewReplayCache(negative) did not select the default ttl")
	}
}

// TestReplayCacheEviction verifies the earliest-expiring entry is evicted at
// capacity. | TestReplayCacheEviction 校验容量满时淘汰最早过期的条目。
func TestReplayCacheEviction(t *testing.T) {
	now := time.Unix(1700000000, 0).UTC()
	cache := NewReplayCache(time.Minute)
	cache.max = 2
	if !cache.Add("a", now, now.Add(10*time.Second)) {
		t.Fatal("Add a")
	}
	if !cache.Add("b", now, now.Add(20*time.Second)) {
		t.Fatal("Add b")
	}
	if !cache.Add("c", now, now.Add(30*time.Second)) {
		t.Fatal("Add c")
	}
	if cache.Len() != 2 {
		t.Fatalf("Len = %d, want 2", cache.Len())
	}
	if !cache.Add("a", now, now.Add(10*time.Second)) {
		t.Fatal("evicted entry was still retained")
	}
}

// TestReplayCacheConcurrent verifies concurrent use under the race detector. |
// TestReplayCacheConcurrent 校验竞态检测器下的并发使用。
func TestReplayCacheConcurrent(t *testing.T) {
	now := time.Unix(1700000000, 0).UTC()
	cache := NewReplayCache(time.Minute)
	var accepted atomic.Int64
	var wg sync.WaitGroup
	for i := 0; i < 32; i++ {
		wg.Add(1)
		go func(index int) {
			defer wg.Done()
			key := string(rune('A' + index%8))
			if cache.Add(key, now, now.Add(time.Minute)) {
				accepted.Add(1)
			}
			_ = cache.Len()
		}(i)
	}
	wg.Wait()
	if got := accepted.Load(); got != 8 {
		t.Fatalf("accepted = %d, want 8 distinct keys", got)
	}
	if cache.Len() != 8 {
		t.Fatalf("Len = %d, want 8", cache.Len())
	}
}
