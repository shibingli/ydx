package rbac_test

import (
	"context"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/alicebob/miniredis/v2"
	goredis "github.com/redis/go-redis/v9"

	authrbac "github.com/shibingli/ydx/auth/authz/rbac"
	rbacstore "github.com/shibingli/ydx/authstore/rbac"
)

// testContext is the background context shared by tests. | testContext 是测试共享的后台上下文。
var testContext = context.Background()

// newStore starts a private miniredis and returns a store using prefix.
// | newStore 启动私有 miniredis 并返回使用 prefix 的存储。
func newStore(t *testing.T, prefix string) (*rbacstore.Store, *miniredis.Miniredis) {
	t.Helper()
	server := miniredis.RunT(t)
	return newStoreOn(t, server, prefix), server
}

// newStoreOn creates one independent client against an existing miniredis.
// | newStoreOn 针对已有 miniredis 创建一个独立客户端。
func newStoreOn(t *testing.T, server *miniredis.Miniredis, prefix string) *rbacstore.Store {
	t.Helper()
	client := goredis.NewClient(&goredis.Options{Addr: server.Addr()})
	t.Cleanup(func() {
		_ = client.Close()
	})
	store, err := rbacstore.New(client, rbacstore.Options{KeyPrefix: prefix})
	if err != nil {
		t.Fatalf("new store: %v | 创建存储失败", err)
	}
	return store
}

// newPair returns two independent stores sharing one miniredis, which models two application
// instances. | newPair 返回共享同一 miniredis 的两个独立存储，用于模拟两个应用实例。
func newPair(t *testing.T) (*rbacstore.Store, *rbacstore.Store) {
	t.Helper()
	server := miniredis.RunT(t)
	return newStoreOn(t, server, ""), newStoreOn(t, server, "")
}

// testTime returns a fixed UTC instant. | testTime 返回固定的 UTC 时刻。
func testTime(year int, month time.Month, day, hour, minute, second int) time.Time {
	return time.Date(year, month, day, hour, minute, second, 0, time.UTC)
}

// requireError fails unless err matches want. | requireError 在 err 不匹配 want 时失败。
func requireError(t *testing.T, err, want error, label string) {
	t.Helper()
	if !errors.Is(err, want) {
		t.Fatalf("%s error = %v, want %v | %s 错误不符", label, err, want, label)
	}
}

// TestNewValidation covers constructor validation, the default prefix and nil receivers.
// | TestNewValidation 覆盖构造校验、默认前缀与空接收者。
func TestNewValidation(t *testing.T) {
	if rbacstore.DefaultKeyPrefix != "ydx:authstore:rbac:" {
		t.Fatalf("DefaultKeyPrefix = %q | 默认前缀不正确", rbacstore.DefaultKeyPrefix)
	}
	if _, err := rbacstore.New(nil, rbacstore.Options{}); !errors.Is(err, rbacstore.ErrInvalidConfig) {
		t.Fatalf("nil client error = %v, want ErrInvalidConfig | nil 客户端错误不符", err)
	}
	server := miniredis.RunT(t)
	client := goredis.NewClient(&goredis.Options{Addr: server.Addr()})
	t.Cleanup(func() {
		_ = client.Close()
	})
	if _, err := rbacstore.New(client, rbacstore.Options{KeyPrefix: "bad{prefix"}); !errors.Is(err, rbacstore.ErrInvalidConfig) {
		t.Fatalf("brace prefix error = %v, want ErrInvalidConfig | 花括号前缀错误不符", err)
	}
	if _, err := rbacstore.New(client, rbacstore.Options{KeyPrefix: "bad}prefix"}); !errors.Is(err, rbacstore.ErrInvalidConfig) {
		t.Fatalf("closing brace prefix error = %v, want ErrInvalidConfig | 右花括号前缀错误不符", err)
	}
	store, err := rbacstore.New(client, rbacstore.Options{})
	if err != nil {
		t.Fatalf("new store: %v | 创建存储失败", err)
	}
	if err := store.AddRole(testContext, authrbac.Role{Name: "viewer"}); err != nil {
		t.Fatalf("add role: %v | 添加角色失败", err)
	}

	var nilStore *rbacstore.Store
	if err := nilStore.AddRole(testContext, authrbac.Role{Name: "viewer"}); !errors.Is(err, rbacstore.ErrInvalidConfig) {
		t.Fatalf("nil store AddRole error = %v | 空存储添加角色错误不符", err)
	}
	if _, err := nilStore.GetRole(testContext, "viewer"); !errors.Is(err, rbacstore.ErrInvalidConfig) {
		t.Fatalf("nil store GetRole error = %v | 空存储读取角色错误不符", err)
	}
	if err := nilStore.Reset(testContext); !errors.Is(err, rbacstore.ErrInvalidConfig) {
		t.Fatalf("nil store Reset error = %v | 空存储重置错误不符", err)
	}
}

// TestKeyLayoutAndDefaultPrefix verifies the documented key names and hash tag.
// | TestKeyLayoutAndDefaultPrefix 验证文档化的键名与哈希标签。
func TestKeyLayoutAndDefaultPrefix(t *testing.T) {
	store, server := newStore(t, "")
	if err := store.AddRole(testContext, authrbac.Role{Name: "viewer", Permissions: []string{"post:read"}}); err != nil {
		t.Fatalf("add role: %v | 添加角色失败", err)
	}
	if err := store.AddPolicy(testContext, authrbac.Policy{ID: "allow", Effect: authrbac.EffectPermit}); err != nil {
		t.Fatalf("add policy: %v | 添加策略失败", err)
	}
	if err := store.Assign(testContext, authrbac.Assignment{Subject: "alice", Role: "viewer"}); err != nil {
		t.Fatalf("assign: %v | 分配角色失败", err)
	}
	keys := server.Keys()
	want := map[string]bool{
		"ydx:authstore:rbac:{authstore:rbac}:roles":                false,
		"ydx:authstore:rbac:{authstore:rbac}:assignments":          false,
		"ydx:authstore:rbac:{authstore:rbac}:assignments:subjects": false,
		"ydx:authstore:rbac:{authstore:rbac}:policies":             false,
	}
	for _, key := range keys {
		if _, ok := want[key]; ok {
			want[key] = true
		}
	}
	for key, found := range want {
		if !found {
			t.Fatalf("key %q missing from %v | 键 %q 不存在", key, keys, key)
		}
	}
	for _, key := range keys {
		if !strings.HasPrefix(key, rbacstore.DefaultKeyPrefix) {
			t.Fatalf("key %q does not use the default prefix | 键 %q 未使用默认前缀", key, key)
		}
	}
}

// TestPrefixIsolation proves that two prefixes never see each other's data.
// | TestPrefixIsolation 证明两个前缀互不可见。
func TestPrefixIsolation(t *testing.T) {
	server := miniredis.RunT(t)
	first := newStoreOn(t, server, "app-a:")
	second := newStoreOn(t, server, "app-b:")
	if err := first.AddRole(testContext, authrbac.Role{Name: "viewer", Permissions: []string{"post:read"}}); err != nil {
		t.Fatalf("first add role: %v | 第一个存储添加角色失败", err)
	}
	if _, err := second.GetRole(testContext, "viewer"); !errors.Is(err, authrbac.ErrRoleNotFound) {
		t.Fatalf("second GetRole error = %v, want ErrRoleNotFound | 第二个存储读取角色错误不符", err)
	}
	if err := second.AddRole(testContext, authrbac.Role{Name: "viewer"}); err != nil {
		t.Fatalf("second add role: %v | 第二个存储添加角色失败", err)
	}
	keys := server.Keys()
	if !containsKey(keys, "app-a:{authstore:rbac}:roles") || !containsKey(keys, "app-b:{authstore:rbac}:roles") {
		t.Fatalf("keys = %v, want both namespaces | 键 %v 未包含两个命名空间", keys, keys)
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

// TestContextHandling covers nil, canceled and expired contexts.
// | TestContextHandling 覆盖空、已取消与已超时的上下文。
func TestContextHandling(t *testing.T) {
	store, _ := newStore(t, "")
	//lint:ignore SA1012 nil context is intentionally exercised to mirror the in-memory store.
	if err := store.AddRole(nil, authrbac.Role{Name: "viewer"}); err != nil {
		t.Fatalf("nil context AddRole: %v | 空上下文添加角色失败", err)
	}
	if _, err := store.GetRole(nil, "viewer"); err != nil {
		t.Fatalf("nil context GetRole: %v | 空上下文读取角色失败", err)
	}

	canceled, cancel := context.WithCancel(context.Background())
	cancel()
	err := store.AddRole(canceled, authrbac.Role{Name: "other"})
	requireError(t, err, authrbac.ErrCanceled, "canceled AddRole")
	requireError(t, err, context.Canceled, "canceled AddRole")
	if _, err := store.ListRoles(canceled); !errors.Is(err, authrbac.ErrCanceled) {
		t.Fatalf("canceled ListRoles error = %v | 已取消列表错误不符", err)
	}

	expired, expire := context.WithDeadline(context.Background(), time.Now().Add(-time.Second))
	defer expire()
	err = store.Assign(expired, authrbac.Assignment{Subject: "alice", Role: "viewer"})
	requireError(t, err, authrbac.ErrCanceled, "expired Assign")
	requireError(t, err, context.DeadlineExceeded, "expired Assign")
}

// TestBackendUnavailable covers fixed backend error mapping without leaking connection details.
// | TestBackendUnavailable 覆盖固定后端错误映射，且不泄露连接细节。
func TestBackendUnavailable(t *testing.T) {
	server := miniredis.RunT(t)
	client := goredis.NewClient(&goredis.Options{
		Addr:        server.Addr(),
		MaxRetries:  -1,
		DialTimeout: 200 * time.Millisecond,
		ReadTimeout: 200 * time.Millisecond,
	})
	t.Cleanup(func() {
		_ = client.Close()
	})
	store, err := rbacstore.New(client, rbacstore.Options{})
	if err != nil {
		t.Fatalf("new store: %v | 创建存储失败", err)
	}
	server.Close()
	if _, err := store.GetRole(testContext, "viewer"); !errors.Is(err, rbacstore.ErrStoreUnavailable) {
		t.Fatalf("GetRole on closed server error = %v | 关闭服务后读取角色错误不符", err)
	}
	addErr := store.AddRole(testContext, authrbac.Role{Name: "viewer"})
	if !errors.Is(addErr, rbacstore.ErrStoreUnavailable) {
		t.Fatalf("AddRole on closed server error = %v | 关闭服务后添加角色错误不符", addErr)
	}
	if strings.Contains(addErr.Error(), "127.0.0.1") {
		t.Fatalf("backend error leaks address: %v | 后端错误泄露地址", addErr)
	}
}

// TestCorruptRecords maps stored corruption to ErrStoreUnavailable.
// | TestCorruptRecords 把存储损坏映射为 ErrStoreUnavailable。
func TestCorruptRecords(t *testing.T) {
	server := miniredis.RunT(t)
	client := goredis.NewClient(&goredis.Options{Addr: server.Addr()})
	t.Cleanup(func() {
		_ = client.Close()
	})
	store, err := rbacstore.New(client, rbacstore.Options{})
	if err != nil {
		t.Fatalf("new store: %v | 创建存储失败", err)
	}
	prefix := rbacstore.DefaultKeyPrefix + "{authstore:rbac}:"
	if err := client.HSet(testContext, prefix+"roles", "broken", "{not-json").Err(); err != nil {
		t.Fatalf("seed corrupt role: %v | 写入损坏角色失败", err)
	}
	if _, err := store.GetRole(testContext, "broken"); !errors.Is(err, rbacstore.ErrStoreUnavailable) {
		t.Fatalf("corrupt role error = %v | 损坏角色错误不符", err)
	}
	if _, err := store.ListRoles(testContext); !errors.Is(err, rbacstore.ErrStoreUnavailable) {
		t.Fatalf("corrupt list error = %v | 损坏列表错误不符", err)
	}
	if err := client.HSet(testContext, prefix+"policies", "empty", "").Err(); err != nil {
		t.Fatalf("seed empty policy: %v | 写入空策略失败", err)
	}
	if _, err := store.GetPolicy(testContext, "empty"); !errors.Is(err, rbacstore.ErrStoreUnavailable) {
		t.Fatalf("empty policy error = %v | 空策略错误不符", err)
	}
}
