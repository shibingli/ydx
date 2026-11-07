package radius

import (
	"bytes"
	"errors"
	"sync"
	"testing"
	"time"
)

// testDynamicKey returns a key for cache tests. | testDynamicKey 返回缓存测试用的键。
func testDynamicKey(identifier uint8, source string) DynamicDuplicateKey {
	return DynamicDuplicateKey{
		Source:        source,
		Code:          CodeCoARequest,
		Identifier:    identifier,
		Authenticator: [16]byte{identifier, 0xaa},
	}
}

func TestNewDynamicDuplicateCacheValidation(t *testing.T) {
	cases := []struct {
		name   string
		config DynamicDuplicateCacheConfig
	}{
		{name: "negative capacity", config: DynamicDuplicateCacheConfig{Capacity: -1}},
		{name: "negative ttl", config: DynamicDuplicateCacheConfig{TTL: -time.Second}},
	}
	for _, testCase := range cases {
		t.Run(testCase.name, func(t *testing.T) {
			if _, err := NewDynamicDuplicateCache(testCase.config); !errors.Is(err, ErrInvalidConfig) {
				t.Fatalf("error = %v, want ErrInvalidConfig", err)
			}
		})
	}

	cache, err := NewDynamicDuplicateCache(DynamicDuplicateCacheConfig{})
	if err != nil {
		t.Fatalf("NewDynamicDuplicateCache: %v", err)
	}
	if cache.capacity != DefaultDynamicDuplicateCapacity {
		t.Fatalf("capacity = %d, want %d", cache.capacity, DefaultDynamicDuplicateCapacity)
	}
	if cache.ttl != DefaultDynamicDuplicateTTL {
		t.Fatalf("ttl = %s, want %s", cache.ttl, DefaultDynamicDuplicateTTL)
	}
	if cache.Len() != 0 {
		t.Fatalf("new cache length = %d", cache.Len())
	}
	if _, ok := cache.Get(testDynamicKey(1, "192.0.2.1:1234")); ok {
		t.Fatal("empty cache reported a hit")
	}
}

func TestDynamicDuplicateCacheHitAndExpiry(t *testing.T) {
	now := time.Unix(1_700_000_000, 0)
	cache, err := NewDynamicDuplicateCache(DynamicDuplicateCacheConfig{
		Capacity: 4,
		TTL:      10 * time.Second,
		Clock:    func() time.Time { return now },
	})
	if err != nil {
		t.Fatalf("NewDynamicDuplicateCache: %v", err)
	}
	key := testDynamicKey(7, "192.0.2.1:1234")
	cache.Put(key, []byte("ack-bytes"))
	if cache.Len() != 1 {
		t.Fatalf("Len = %d, want 1", cache.Len())
	}
	response, ok := cache.Get(key)
	if !ok || !bytes.Equal(response, []byte("ack-bytes")) {
		t.Fatalf("Get = %q, %v", response, ok)
	}
	// The returned slice is a copy, so mutating it cannot corrupt the cache. | 返回的是副本，
	// 修改它不会破坏缓存。
	response[0] = 'X'
	response, ok = cache.Get(key)
	if !ok || !bytes.Equal(response, []byte("ack-bytes")) {
		t.Fatalf("cached response changed through Get: %q, %v", response, ok)
	}

	now = now.Add(10 * time.Second)
	if _, ok := cache.Get(key); ok {
		t.Fatal("entry did not expire at the TTL boundary")
	}
	if cache.Len() != 0 {
		t.Fatalf("Len after expiry = %d", cache.Len())
	}

	cache.Put(key, []byte("fresh"))
	now = now.Add(9 * time.Second)
	if _, ok := cache.Get(key); !ok {
		t.Fatal("entry expired before its TTL")
	}
}

func TestDynamicDuplicateCacheEvictionAndReset(t *testing.T) {
	now := time.Unix(1_700_000_000, 0)
	cache, err := NewDynamicDuplicateCache(DynamicDuplicateCacheConfig{
		Capacity: 2,
		TTL:      time.Minute,
		Clock:    func() time.Time { return now },
	})
	if err != nil {
		t.Fatalf("NewDynamicDuplicateCache: %v", err)
	}
	first := testDynamicKey(1, "192.0.2.1:1000")
	second := testDynamicKey(2, "192.0.2.1:1001")
	third := testDynamicKey(3, "192.0.2.1:1002")
	cache.Put(first, []byte("first"))
	cache.Put(second, []byte("second"))
	// Refreshing the first entry makes the second entry the oldest. | 刷新第一条后，第二条成为最旧条目。
	cache.Put(first, []byte("first-updated"))
	cache.Put(third, []byte("third"))

	if _, ok := cache.Get(second); ok {
		t.Fatal("oldest entry was not evicted")
	}
	if response, ok := cache.Get(first); !ok || !bytes.Equal(response, []byte("first-updated")) {
		t.Fatalf("refreshed entry = %q, %v", response, ok)
	}
	if _, ok := cache.Get(third); !ok {
		t.Fatal("newest entry was evicted")
	}
	if cache.Len() != 2 {
		t.Fatalf("Len = %d, want 2", cache.Len())
	}

	cache.Reset()
	if cache.Len() != 0 {
		t.Fatalf("Len after Reset = %d", cache.Len())
	}
	if _, ok := cache.Get(first); ok {
		t.Fatal("Reset did not remove the entry")
	}
}

func TestDynamicDuplicateCacheConcurrentDuplicates(t *testing.T) {
	cache, err := NewDynamicDuplicateCache(DynamicDuplicateCacheConfig{Capacity: 8, TTL: time.Minute})
	if err != nil {
		t.Fatalf("NewDynamicDuplicateCache: %v", err)
	}
	const workers = 16
	const iterations = 200
	keys := []DynamicDuplicateKey{
		testDynamicKey(1, "192.0.2.1:1000"),
		testDynamicKey(1, "192.0.2.1:1001"),
		testDynamicKey(2, "192.0.2.1:1000"),
	}
	var waitGroup sync.WaitGroup
	for worker := 0; worker < workers; worker++ {
		waitGroup.Add(1)
		go func(worker int) {
			defer waitGroup.Done()
			for i := 0; i < iterations; i++ {
				key := keys[(worker+i)%len(keys)]
				cache.Put(key, []byte("response"))
				if response, ok := cache.Get(key); ok && !bytes.Equal(response, []byte("response")) {
					t.Errorf("Get returned %q", response)
					return
				}
				_ = cache.Len()
			}
		}(worker)
	}
	waitGroup.Wait()
	if cache.Len() > 8 {
		t.Fatalf("Len = %d exceeds capacity", cache.Len())
	}
	key := keys[0]
	cache.Put(key, []byte("final"))
	if response, ok := cache.Get(key); !ok || !bytes.Equal(response, []byte("final")) {
		t.Fatalf("final Get = %q, %v", response, ok)
	}
}
