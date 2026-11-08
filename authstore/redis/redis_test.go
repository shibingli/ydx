package redis_test

import (
	"context"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/alicebob/miniredis/v2"
	goredis "github.com/redis/go-redis/v9"

	"github.com/shibingli/ydx/auth"
	authredis "github.com/shibingli/ydx/authstore/redis"
	ydxredis "github.com/shibingli/ydx/redis"
)

// testContext is the background context shared by tests. | testContext 是测试共享的后台上下文。
var testContext = context.Background()

// newStores starts a private miniredis and returns stores using prefix.
// | newStores 启动私有 miniredis 并返回使用 prefix 的存储。
func newStores(t *testing.T, prefix string) *authredis.Stores {
	t.Helper()
	server := miniredis.RunT(t)
	return newStoresOn(t, server, prefix)
}

// newStoresOn creates one more independent client against an existing miniredis.
// | newStoresOn 针对已有 miniredis 创建一个独立客户端。
func newStoresOn(t *testing.T, server *miniredis.Miniredis, prefix string) *authredis.Stores {
	t.Helper()
	client := goredis.NewClient(&goredis.Options{Addr: server.Addr()})
	t.Cleanup(func() {
		_ = client.Close()
	})
	stores, err := authredis.New(client, authredis.Options{KeyPrefix: prefix})
	if err != nil {
		t.Fatalf("new stores: %v | 创建存储失败", err)
	}
	return stores
}

// newPair returns two independent store sets sharing one miniredis, which models two
// application instances. | newPair 返回共享同一 miniredis 的两套独立存储，用于模拟两个应用实例。
func newPair(t *testing.T) (*authredis.Stores, *authredis.Stores) {
	t.Helper()
	server := miniredis.RunT(t)
	return newStoresOn(t, server, ""), newStoresOn(t, server, "")
}

// testTime returns a fixed UTC instant. | testTime 返回固定的 UTC 时刻。
func testTime(year int, month time.Month, day, hour, minute, second int) time.Time {
	return time.Date(year, month, day, hour, minute, second, 0, time.UTC)
}

// sampleUser returns a fully populated user. | sampleUser 返回字段完整的用户。
func sampleUser(id, username, email string, created time.Time) *auth.User {
	return &auth.User{
		ID:                  id,
		Username:            username,
		Email:               email,
		EmailVerified:       true,
		DisplayName:         username,
		Status:              auth.UserActive,
		PasswordHash:        "encoded-hash-" + id,
		PasswordHistory:     []string{"old-hash-" + id},
		FailedLoginAttempts: 3,
		Address:             map[string]string{"locality": "Shanghai"},
		Metadata:            map[string]string{"tenant": "t1"},
		CreatedAt:           created,
		UpdatedAt:           created,
	}
}

// TestNewValidation covers constructor validation and the default prefix.
// | TestNewValidation 覆盖构造校验与默认前缀。
func TestNewValidation(t *testing.T) {
	if authredis.DefaultKeyPrefix != "ydx:authstore:" {
		t.Fatalf("DefaultKeyPrefix = %q | 默认前缀不正确", authredis.DefaultKeyPrefix)
	}
	if _, err := authredis.New(nil, authredis.Options{}); !errors.Is(err, auth.ErrInvalidConfig) {
		t.Fatalf("nil client error = %v, want ErrInvalidConfig | nil 客户端错误不符", err)
	}
	server := miniredis.RunT(t)
	client := goredis.NewClient(&goredis.Options{Addr: server.Addr()})
	t.Cleanup(func() {
		_ = client.Close()
	})
	if _, err := authredis.New(client, authredis.Options{KeyPrefix: "bad{prefix"}); !errors.Is(err, auth.ErrInvalidConfig) {
		t.Fatalf("brace prefix error = %v, want ErrInvalidConfig | 花括号前缀错误不符", err)
	}
	stores, err := authredis.New(client, authredis.Options{})
	if err != nil {
		t.Fatalf("new stores: %v | 创建存储失败", err)
	}
	ports := stores.Auth()
	if err := ports.Validate(); err != nil {
		t.Fatalf("Validate: %v | 端口校验失败", err)
	}
	if service, err := auth.New(auth.Config{Stores: ports}); err != nil || service == nil {
		t.Fatalf("auth.New rejected the ports: %v | auth.New 拒绝了端口", err)
	}
	if ports.Users == nil || ports.Sessions == nil || ports.Identities == nil ||
		ports.Credentials == nil || ports.Audits == nil || ports.Tokens == nil {
		t.Fatal("Auth returned a nil port | Auth 返回了空端口")
	}
	if err := stores.Close(); err != nil {
		t.Fatalf("Close caller-owned client: %v | 关闭调用方客户端不应出错", err)
	}
	// The caller-owned client must still work after the no-op Close.
	if err := stores.Users.CreateUser(testContext, sampleUser("u1", "alice", "alice@example.com", testTime(2026, time.January, 1, 0, 0, 0))); err != nil {
		t.Fatalf("caller-owned client was closed: %v | 调用方客户端被误关闭", err)
	}
	var nilStores *authredis.Stores
	if err := nilStores.Close(); err != nil {
		t.Fatalf("nil Close: %v | nil Close 出错", err)
	}
	if got := nilStores.Auth(); got.Users != nil {
		t.Fatal("nil Auth returned ports | nil Auth 返回了端口")
	}
}

// TestNewDoesNotDial verifies that New performs no network round trip.
// | TestNewDoesNotDial 验证 New 不进行网络往返。
func TestNewDoesNotDial(t *testing.T) {
	client := goredis.NewClient(&goredis.Options{Addr: "127.0.0.1:1", MaxRetries: -1})
	t.Cleanup(func() {
		_ = client.Close()
	})
	if _, err := authredis.New(client, authredis.Options{}); err != nil {
		t.Fatalf("New dialed: %v | New 不应连接网络", err)
	}
}

// TestNewFromOptions covers ydx/redis integration and owned-client Close.
// | TestNewFromOptions 覆盖 ydx/redis 集成与自有客户端关闭。
func TestNewFromOptions(t *testing.T) {
	server := miniredis.RunT(t)
	stores, err := authredis.NewFromOptions(testContext, ydxredis.Options{Addr: server.Addr()}, authredis.Options{})
	if err != nil {
		t.Fatalf("NewFromOptions: %v | NewFromOptions 失败", err)
	}
	user := sampleUser("u1", "alice", "alice@example.com", testTime(2026, time.January, 1, 0, 0, 0))
	if err := stores.Users.CreateUser(testContext, user); err != nil {
		t.Fatalf("create: %v | 创建失败", err)
	}
	if _, err := stores.Users.GetUser(testContext, "u1"); err != nil {
		t.Fatalf("get: %v | 读取失败", err)
	}
	if err := stores.Close(); err != nil {
		t.Fatalf("close: %v | 关闭失败", err)
	}
	if err := stores.Close(); err != nil {
		t.Fatalf("second close: %v | 二次关闭失败", err)
	}
	if _, err := stores.Users.GetUser(testContext, "u1"); !errors.Is(err, auth.ErrStoreUnavailable) {
		t.Fatalf("get after close = %v, want ErrStoreUnavailable | 关闭后读取错误不符", err)
	}
}

// TestPrefixIsolation runs two store sets with distinct prefixes on one server.
// | TestPrefixIsolation 在同一服务器上运行两套不同前缀的存储。
func TestPrefixIsolation(t *testing.T) {
	server := miniredis.RunT(t)
	first := newStoresOn(t, server, "one:")
	second := newStoresOn(t, server, "two:")
	user := sampleUser("u1", "alice", "alice@example.com", testTime(2026, time.January, 1, 0, 0, 0))
	if err := first.Users.CreateUser(testContext, user); err != nil {
		t.Fatalf("create first: %v | 第一套创建失败", err)
	}
	if _, err := second.Users.GetUser(testContext, "u1"); !errors.Is(err, auth.ErrUserNotFound) {
		t.Fatalf("second prefix saw first user: %v | 第二前缀看到了第一前缀的用户", err)
	}
	other := sampleUser("u1", "alice", "alice@example.com", testTime(2026, time.January, 2, 0, 0, 0))
	if err := second.Users.CreateUser(testContext, other); err != nil {
		t.Fatalf("create second: %v | 第二套创建失败", err)
	}
	if got, err := first.Users.GetUser(testContext, "u1"); err != nil || !got.CreatedAt.Equal(user.CreatedAt) {
		t.Fatalf("first user changed: %v | 第一套用户被改写", err)
	}
}

// TestBackendErrorsAreRedacted verifies that a backend failure is classified and carries no
// address or DSN. | TestBackendErrorsAreRedacted 验证后端故障被分类且不携带地址或 DSN。
func TestBackendErrorsAreRedacted(t *testing.T) {
	client := goredis.NewClient(&goredis.Options{Addr: "127.0.0.1:1", MaxRetries: -1, DialTimeout: 50 * time.Millisecond})
	t.Cleanup(func() {
		_ = client.Close()
	})
	stores, err := authredis.New(client, authredis.Options{})
	if err != nil {
		t.Fatalf("new stores: %v | 创建存储失败", err)
	}
	_, err = stores.Users.GetUser(testContext, "u1")
	if !errors.Is(err, auth.ErrStoreUnavailable) {
		t.Fatalf("error = %v, want ErrStoreUnavailable | 错误未映射为存储不可用", err)
	}
	if strings.Contains(err.Error(), "127.0.0.1") || strings.Contains(err.Error(), ":1") {
		t.Fatalf("error leaked the address: %v | 错误泄露了地址", err)
	}
}

// TestAllStoresMapBackendErrors verifies that every port classifies a closed backend as
// ErrStoreUnavailable. | TestAllStoresMapBackendErrors 验证每个端口都把已关闭后端归类为
// ErrStoreUnavailable。
func TestAllStoresMapBackendErrors(t *testing.T) {
	server := miniredis.RunT(t)
	client := goredis.NewClient(&goredis.Options{Addr: server.Addr(), MaxRetries: -1})
	stores, err := authredis.New(client, authredis.Options{})
	if err != nil {
		t.Fatalf("new stores: %v | 创建存储失败", err)
	}
	if err := client.Close(); err != nil {
		t.Fatalf("close client: %v | 关闭客户端失败", err)
	}
	base := testTime(2026, time.December, 1, 0, 0, 0)
	user := sampleUser("u1", "alice", "alice@example.com", base)
	user.Phone = "13800138000"
	session := sampleSession("s1", "u1", base)
	identity := sampleIdentity("google", "sub", "u1", base)
	credential := sampleCredential("c1", "u1", auth.CredentialTOTP, base)
	event := sampleAudit("e1", "login.succeeded", "u1", "a1", "success", base)
	token := sampleToken("hash-1", "u1", "reset_password", base)
	operations := []struct {
		name string
		call func() error
	}{
		{"users.create", func() error { return stores.Users.CreateUser(testContext, user) }},
		{"users.get", func() error { _, err := stores.Users.GetUser(testContext, "u1"); return err }},
		{"users.get-by-username", func() error { _, err := stores.Users.GetUserByUsername(testContext, "alice"); return err }},
		{"users.get-by-email", func() error { _, err := stores.Users.GetUserByEmail(testContext, "alice@example.com"); return err }},
		{"users.get-by-phone", func() error { _, err := stores.Users.GetUserByPhone(testContext, "13800138000"); return err }},
		{"users.update", func() error { return stores.Users.UpdateUser(testContext, user) }},
		{"users.delete", func() error { return stores.Users.DeleteUser(testContext, "u1") }},
		{"users.list", func() error { _, _, err := stores.Users.ListUsers(testContext, auth.UserQuery{}); return err }},
		{"sessions.create", func() error { return stores.Sessions.CreateSession(testContext, session) }},
		{"sessions.get", func() error { _, err := stores.Sessions.GetSession(testContext, "s1"); return err }},
		{"sessions.update", func() error { return stores.Sessions.UpdateSession(testContext, session) }},
		{"sessions.delete", func() error { return stores.Sessions.DeleteSession(testContext, "s1") }},
		{"sessions.list", func() error { _, err := stores.Sessions.ListSessionsByUser(testContext, "u1"); return err }},
		{"sessions.delete-by-user", func() error { _, err := stores.Sessions.DeleteSessionsByUser(testContext, "u1"); return err }},
		{"sessions.delete-expired", func() error { _, err := stores.Sessions.DeleteExpiredSessions(testContext, base); return err }},
		{"identities.create", func() error { return stores.Identities.CreateIdentity(testContext, identity) }},
		{"identities.get", func() error { _, err := stores.Identities.GetIdentity(testContext, "google", "sub"); return err }},
		{"identities.list", func() error { _, err := stores.Identities.ListIdentitiesByUser(testContext, "u1"); return err }},
		{"identities.update", func() error { return stores.Identities.UpdateIdentity(testContext, identity) }},
		{"identities.delete", func() error { return stores.Identities.DeleteIdentity(testContext, "google", "sub") }},
		{"credentials.create", func() error { return stores.Credentials.CreateCredential(testContext, credential) }},
		{"credentials.get", func() error { _, err := stores.Credentials.GetCredential(testContext, "c1"); return err }},
		{"credentials.update", func() error { return stores.Credentials.UpdateCredential(testContext, credential) }},
		{"credentials.delete", func() error { return stores.Credentials.DeleteCredential(testContext, "c1") }},
		{"credentials.list", func() error { _, err := stores.Credentials.ListCredentialsByUser(testContext, "u1"); return err }},
		{"credentials.list-type", func() error {
			_, err := stores.Credentials.ListCredentialsByUserType(testContext, "u1", auth.CredentialTOTP)
			return err
		}},
		{"audits.record", func() error { return stores.Audits.RecordAudit(testContext, event) }},
		{"audits.list", func() error { _, _, err := stores.Audits.ListAudit(testContext, auth.AuditQuery{}); return err }},
		{"tokens.create", func() error { return stores.Tokens.CreateToken(testContext, token) }},
		{"tokens.consume", func() error {
			_, err := stores.Tokens.ConsumeToken(testContext, "hash-1", "reset_password", base)
			return err
		}},
		{"tokens.peek", func() error {
			_, err := stores.Tokens.PeekToken(testContext, "hash-1", "reset_password", base)
			return err
		}},
		{"tokens.delete-by-user", func() error {
			_, err := stores.Tokens.DeleteTokensByUser(testContext, "u1", "reset_password")
			return err
		}},
	}
	for _, operation := range operations {
		if err := operation.call(); !errors.Is(err, auth.ErrStoreUnavailable) {
			t.Fatalf("%s error = %v, want ErrStoreUnavailable | %s 错误未映射为存储不可用", operation.name, err, operation.name)
		}
	}
}

// TestContextCancellation verifies that a canceled context is returned unchanged.
// | TestContextCancellation 验证取消的上下文被原样返回。
func TestContextCancellation(t *testing.T) {
	stores := newStores(t, "")
	canceled, cancel := context.WithCancel(testContext)
	cancel()
	_, err := stores.Users.GetUser(canceled, "u1")
	if !errors.Is(err, context.Canceled) {
		t.Fatalf("error = %v, want context.Canceled | 错误未返回上下文取消", err)
	}
}

// TestTwoInstancesShareState covers cross-instance reads and writes.
// | TestTwoInstancesShareState 覆盖跨实例读写。
func TestTwoInstancesShareState(t *testing.T) {
	first, second := newPair(t)
	user := sampleUser("u1", "alice", "alice@example.com", testTime(2026, time.January, 1, 0, 0, 0))
	if err := first.Users.CreateUser(testContext, user); err != nil {
		t.Fatalf("create: %v | 创建失败", err)
	}
	got, err := second.Users.GetUserByUsername(testContext, "ALICE")
	if err != nil {
		t.Fatalf("cross-instance get: %v | 跨实例读取失败", err)
	}
	if got.ID != "u1" {
		t.Fatalf("id = %q | ID 不符", got.ID)
	}
	got.DisplayName = "Alice Updated"
	got.UpdatedAt = testTime(2026, time.January, 3, 0, 0, 0)
	if err := second.Users.UpdateUser(testContext, got); err != nil {
		t.Fatalf("cross-instance update: %v | 跨实例更新失败", err)
	}
	back, err := first.Users.GetUser(testContext, "u1")
	if err != nil {
		t.Fatalf("get after update: %v | 更新后读取失败", err)
	}
	if back.DisplayName != "Alice Updated" {
		t.Fatalf("display name = %q | 展示名未同步", back.DisplayName)
	}
}
