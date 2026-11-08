package wsfed_test

import (
	"context"
	"errors"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/alicebob/miniredis/v2"
	goredis "github.com/redis/go-redis/v9"

	authwsfed "github.com/shibingli/ydx/auth/protocol/wsfed"
	wsfedstore "github.com/shibingli/ydx/authstore/wsfed"
)

// testContext is the context shared by the store tests. | testContext 是存储测试共享的上下文。
var testContext = context.Background()

// newStoresOn creates one independent store client against an existing miniredis. | newStoresOn
// 针对已有 miniredis 创建一个独立的存储客户端。
func newStoresOn(t *testing.T, server *miniredis.Miniredis, prefix string) *wsfedstore.Store {
	t.Helper()
	client := goredis.NewClient(&goredis.Options{Addr: server.Addr()})
	t.Cleanup(func() {
		_ = client.Close()
	})
	store, err := wsfedstore.New(client, wsfedstore.Options{KeyPrefix: prefix})
	if err != nil {
		t.Fatalf("new store: %v | 创建存储失败", err)
	}
	return store
}

// newPair returns two independent stores sharing one miniredis, which models two application
// instances. | newPair 返回共享同一 miniredis 的两套独立存储，用于模拟两个应用实例。
func newPair(t *testing.T) (*wsfedstore.Store, *wsfedstore.Store) {
	t.Helper()
	server := miniredis.RunT(t)
	return newStoresOn(t, server, ""), newStoresOn(t, server, "")
}

// TestNewValidation covers constructor validation, the default prefix and interface conformance.
// | TestNewValidation 覆盖构造校验、默认前缀与接口符合性。
func TestNewValidation(t *testing.T) {
	if wsfedstore.DefaultKeyPrefix != "ydx:authstore:wsfed:" {
		t.Fatalf("DefaultKeyPrefix = %q | 默认前缀不正确", wsfedstore.DefaultKeyPrefix)
	}
	if _, err := wsfedstore.New(nil, wsfedstore.Options{}); !errors.Is(err, authwsfed.ErrInvalidConfig) {
		t.Fatalf("nil client error = %v, want ErrInvalidConfig | nil 客户端错误不符", err)
	}
	server := miniredis.RunT(t)
	client := goredis.NewClient(&goredis.Options{Addr: server.Addr()})
	t.Cleanup(func() {
		_ = client.Close()
	})
	if _, err := wsfedstore.New(client, wsfedstore.Options{KeyPrefix: "bad{prefix"}); !errors.Is(err, authwsfed.ErrInvalidConfig) {
		t.Fatalf("brace prefix error = %v, want ErrInvalidConfig | 花括号前缀错误不符", err)
	}
	store, err := wsfedstore.New(client, wsfedstore.Options{})
	if err != nil {
		t.Fatalf("new store: %v | 创建存储失败", err)
	}
	var port authwsfed.RequestStore = store
	if port == nil {
		t.Fatal("New returned a nil port | New 返回了空端口")
	}
}

// TestNewDoesNotDial verifies that New performs no network round trip.
// | TestNewDoesNotDial 验证 New 不进行网络往返。
func TestNewDoesNotDial(t *testing.T) {
	client := goredis.NewClient(&goredis.Options{
		Addr:        "127.0.0.1:1",
		MaxRetries:  -1,
		DialTimeout: 20 * time.Millisecond,
	})
	t.Cleanup(func() {
		_ = client.Close()
	})
	if _, err := wsfedstore.New(client, wsfedstore.Options{}); err != nil {
		t.Fatalf("New dialed: %v | New 不应连接网络", err)
	}
}

// TestPrefixIsolation runs two stores with distinct prefixes on one server.
// | TestPrefixIsolation 在同一服务器上运行两套不同前缀的存储。
func TestPrefixIsolation(t *testing.T) {
	server := miniredis.RunT(t)
	first := newStoresOn(t, server, "one:")
	second := newStoresOn(t, server, "two:")
	state := authwsfed.RequestState{
		Wctx:      "w-1",
		Realm:     "https://app.example.com",
		ReplyURL:  "https://app.example.com/reply",
		ExpiresAt: time.Now().Add(time.Hour),
	}
	if err := first.SaveRequest(testContext, state); err != nil {
		t.Fatalf("save first: %v | 第一套保存失败", err)
	}
	if _, ok, err := second.TakeRequest(testContext, "w-1"); err != nil || ok {
		t.Fatalf("second prefix saw first request: %v, %v | 第二前缀看到了第一前缀的请求", ok, err)
	}
	if _, ok, err := first.TakeRequest(testContext, "w-1"); err != nil || !ok {
		t.Fatalf("first prefix lost its request: %v, %v | 第一前缀丢失了请求", ok, err)
	}
}

// TestKeyLayout verifies the default prefix, the shared hash tag and the length-prefixed segment.
// | TestKeyLayout 验证默认前缀、共享哈希标签与长度前缀段。
func TestKeyLayout(t *testing.T) {
	server := miniredis.RunT(t)
	store := newStoresOn(t, server, wsfedstore.DefaultKeyPrefix)
	wctx := "w-abc"
	if err := store.SaveRequest(testContext, authwsfed.RequestState{
		Wctx:      wctx,
		ExpiresAt: time.Now().Add(time.Hour),
	}); err != nil {
		t.Fatalf("save request: %v | 保存请求失败", err)
	}
	keys := server.Keys()
	if len(keys) == 0 {
		t.Fatal("no keys written | 未写入任何键")
	}
	suffix := ":request:" + strconv.Itoa(len(wctx)) + ":" + wctx
	seen := false
	for _, key := range keys {
		if !strings.HasPrefix(key, wsfedstore.DefaultKeyPrefix) {
			t.Fatalf("key %q lacks the default prefix | 键缺少默认前缀", key)
		}
		if !strings.Contains(key, "{authstore:wsfed}") {
			t.Fatalf("key %q lacks the shared hash tag | 键缺少共享哈希标签", key)
		}
		if strings.HasSuffix(key, suffix) {
			seen = true
		}
	}
	if !seen {
		t.Fatalf("length-prefixed request key missing: %q | 长度前缀请求键缺失", suffix)
	}
}

// TestBackendErrorsAreRedacted verifies classification and the absence of addresses.
// | TestBackendErrorsAreRedacted 验证错误分类且不泄露地址。
func TestBackendErrorsAreRedacted(t *testing.T) {
	client := goredis.NewClient(&goredis.Options{
		Addr:        "127.0.0.1:1",
		MaxRetries:  -1,
		DialTimeout: 50 * time.Millisecond,
	})
	t.Cleanup(func() {
		_ = client.Close()
	})
	store, err := wsfedstore.New(client, wsfedstore.Options{})
	if err != nil {
		t.Fatalf("new store: %v | 创建存储失败", err)
	}
	err = store.SaveRequest(testContext, authwsfed.RequestState{
		Wctx:      "w-1",
		ExpiresAt: time.Now().Add(time.Hour),
	})
	if !errors.Is(err, wsfedstore.ErrStoreUnavailable) {
		t.Fatalf("save error = %v, want ErrStoreUnavailable | 保存错误未映射为存储不可用", err)
	}
	if strings.Contains(err.Error(), "127.0.0.1") || strings.Contains(err.Error(), ":1") {
		t.Fatalf("error leaked the address: %v | 错误泄露了地址", err)
	}
	if _, _, err := store.TakeRequest(testContext, "w-1"); !errors.Is(err, wsfedstore.ErrStoreUnavailable) {
		t.Fatalf("take error = %v, want ErrStoreUnavailable | 消费错误未映射为存储不可用", err)
	}
}
