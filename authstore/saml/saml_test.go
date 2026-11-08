package saml_test

import (
	"context"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/alicebob/miniredis/v2"
	goredis "github.com/redis/go-redis/v9"

	samlapi "github.com/shibingli/ydx/auth/protocol/saml"
	authsaml "github.com/shibingli/ydx/authstore/saml"
)

// testContext is the background context shared by tests. | testContext 是测试共享的后台上下文。
var testContext = context.Background()

// newStoreOn creates an independent stores value against an existing miniredis.
// | newStoreOn 针对已有 miniredis 创建独立的存储值。
func newStoreOn(t *testing.T, server *miniredis.Miniredis, prefix string) *authsaml.Stores {
	t.Helper()
	client := goredis.NewClient(&goredis.Options{Addr: server.Addr()})
	t.Cleanup(func() {
		_ = client.Close()
	})
	stores, err := authsaml.New(client, authsaml.Options{KeyPrefix: prefix})
	if err != nil {
		t.Fatalf("new stores: %v | 创建存储失败", err)
	}
	return stores
}

// newStore starts a private miniredis and returns one stores value using prefix.
// | newStore 启动私有 miniredis 并返回使用 prefix 的单个存储值。
func newStore(t *testing.T, prefix string) *authsaml.Stores {
	t.Helper()
	return newStoreOn(t, miniredis.RunT(t), prefix)
}

// newPair returns two independent stores values sharing one miniredis, which models two
// application instances. | newPair 返回共享同一 miniredis 的两个独立存储值，用于模拟两个应用实例。
func newPair(t *testing.T) (*authsaml.Stores, *authsaml.Stores) {
	t.Helper()
	server := miniredis.RunT(t)
	return newStoreOn(t, server, ""), newStoreOn(t, server, "")
}

// testTime returns a fixed UTC instant. | testTime 返回固定的 UTC 时刻。
func testTime(year int, month time.Month, day, hour, minute, second int) time.Time {
	return time.Date(year, month, day, hour, minute, second, 0, time.UTC)
}

// sampleRequest returns a populated request. | sampleRequest 返回字段完整的请求。
func sampleRequest(id string, created, expires time.Time) *samlapi.RequestState {
	return &samlapi.RequestState{
		ID:           id,
		SPEntityID:   "https://sp.example.com/saml/metadata",
		IDPEntityID:  "https://idp.example.com/saml/metadata",
		ACSURL:       "https://sp.example.com/saml/acs",
		RelayState:   "state-" + id,
		NameIDFormat: "urn:oasis:names:tc:SAML:2.0:nameid-format:persistent",
		CreatedAt:    created,
		ExpiresAt:    expires,
	}
}

// sampleSession returns a populated session. | sampleSession 返回字段完整的会话。
func sampleSession(id, nameID string, created, expires time.Time) *samlapi.Session {
	return &samlapi.Session{
		ID:          id,
		NameID:      nameID,
		SPEntityID:  "https://sp.example.com/saml/metadata",
		IDPEntityID: "https://idp.example.com/saml/metadata",
		CreatedAt:   created,
		ExpiresAt:   expires,
		Attributes: map[string][]string{
			"role":  {"admin", "operator"},
			"email": {nameID + "@example.com"},
		},
	}
}

// sampleArtifact returns a deterministic type-0x0004 artifact. | sampleArtifact 返回确定性的
// 类型 0x0004 工件。
func sampleArtifact(handle byte, endpoint uint16) samlapi.Artifact {
	var sourceID [samlapi.ArtifactSourceIDSize]byte
	var messageHandle [samlapi.ArtifactMessageHandleSize]byte
	for index := range sourceID {
		sourceID[index] = 0xA0 + byte(index)
	}
	for index := range messageHandle {
		messageHandle[index] = handle + byte(index)
	}
	return samlapi.Artifact{
		Type:          samlapi.ArtifactTypeHTTP,
		EndpointIndex: endpoint,
		SourceID:      sourceID,
		MessageHandle: messageHandle,
	}
}

// sampleRecord returns an artifact record carrying message. | sampleRecord 返回携带 message 的工件记录。
func sampleRecord(artifact samlapi.Artifact, message string, issued, expires time.Time) *samlapi.ArtifactRecord {
	return &samlapi.ArtifactRecord{
		Artifact:    artifact,
		Message:     []byte(message),
		SPEntityID:  "https://sp.example.com/saml/metadata",
		IDPEntityID: "https://idp.example.com/saml/metadata",
		IssuedAt:    issued,
		ExpiresAt:   expires,
	}
}

// TestNewValidation covers constructor validation, the default prefix and the interface surface.
// | TestNewValidation 覆盖构造校验、默认前缀与接口面。
func TestNewValidation(t *testing.T) {
	if authsaml.DefaultKeyPrefix != "ydx:authstore:saml:" {
		t.Fatalf("DefaultKeyPrefix = %q | 默认前缀不正确", authsaml.DefaultKeyPrefix)
	}
	if _, err := authsaml.New(nil, authsaml.Options{}); !errors.Is(err, samlapi.ErrInvalidConfig) {
		t.Fatalf("nil client error = %v, want ErrInvalidConfig | nil 客户端错误不符", err)
	}
	server := miniredis.RunT(t)
	client := goredis.NewClient(&goredis.Options{Addr: server.Addr()})
	t.Cleanup(func() {
		_ = client.Close()
	})
	if _, err := authsaml.New(client, authsaml.Options{KeyPrefix: "bad{prefix"}); !errors.Is(err, samlapi.ErrInvalidConfig) {
		t.Fatalf("brace prefix error = %v, want ErrInvalidConfig | 花括号前缀错误不符", err)
	}
	if _, err := authsaml.New(client, authsaml.Options{KeyPrefix: "bad}prefix"}); !errors.Is(err, samlapi.ErrInvalidConfig) {
		t.Fatalf("closing brace prefix error = %v, want ErrInvalidConfig | 右花括号前缀错误不符", err)
	}
	stores, err := authsaml.New(client, authsaml.Options{})
	if err != nil {
		t.Fatalf("new stores: %v | 创建存储失败", err)
	}
	var store samlapi.Store = stores
	if _, ok := store.(samlapi.ArtifactStore); !ok {
		t.Fatal("stores does not implement ArtifactStore | 存储未实现 ArtifactStore")
	}
	if _, ok := store.(samlapi.AssertionReplayStore); !ok {
		t.Fatal("stores does not implement AssertionReplayStore | 存储未实现 AssertionReplayStore")
	}
	if _, ok := any(stores).(interface {
		CleanupAssertions(context.Context, time.Time) (int, error)
	}); !ok {
		t.Fatal("stores does not implement the assertion cleaner method | 存储未实现断言清理方法")
	}
}

// TestNewDoesNotDial verifies that New performs no network round trip.
// | TestNewDoesNotDial 验证 New 不进行网络往返。
func TestNewDoesNotDial(t *testing.T) {
	client := goredis.NewClient(&goredis.Options{Addr: "127.0.0.1:1", MaxRetries: -1})
	t.Cleanup(func() {
		_ = client.Close()
	})
	if _, err := authsaml.New(client, authsaml.Options{}); err != nil {
		t.Fatalf("New dialed: %v | New 不应连接网络", err)
	}
}

// TestPrefixIsolation verifies that two prefixes never observe each other's records.
// | TestPrefixIsolation 验证两个前缀永远不会看到彼此的记录。
func TestPrefixIsolation(t *testing.T) {
	server := miniredis.RunT(t)
	first := newStoreOn(t, server, "one:")
	second := newStoreOn(t, server, "two:")
	base := testTime(2026, time.January, 1, 12, 0, 0)
	expires := base.Add(time.Hour)

	if err := first.SaveRequest(testContext, sampleRequest("req-1", base, expires)); err != nil {
		t.Fatalf("save request: %v | 保存请求失败", err)
	}
	if _, err := second.ConsumeRequest(testContext, "req-1", base); !errors.Is(err, samlapi.ErrInvalidRequest) {
		t.Fatalf("second prefix saw first request: %v | 第二前缀看到了第一前缀的请求", err)
	}
	if err := first.SaveSession(testContext, sampleSession("sess-1", "alice", base, expires)); err != nil {
		t.Fatalf("save session: %v | 保存会话失败", err)
	}
	if _, err := second.GetSession(testContext, "sess-1"); !errors.Is(err, samlapi.ErrInvalidRequest) {
		t.Fatalf("second prefix saw first session: %v | 第二前缀看到了第一前缀的会话", err)
	}
	artifact := sampleArtifact(1, 0)
	if err := first.SaveArtifact(testContext, sampleRecord(artifact, "payload", base, expires), base); err != nil {
		t.Fatalf("save artifact: %v | 保存工件失败", err)
	}
	if _, err := second.TakeArtifact(testContext, artifact, base); !errors.Is(err, samlapi.ErrArtifactInvalid) {
		t.Fatalf("second prefix saw first artifact: %v | 第二前缀看到了第一前缀的工件", err)
	}
	freshSecond, err := second.SaveAssertion(testContext, "assertion-1", expires, base)
	if err != nil || !freshSecond {
		t.Fatalf("second prefix assertion = %v, %v, want fresh | 第二前缀断言不应看到第一前缀记录", freshSecond, err)
	}
	seenFirst, err := first.SeenAndStore(testContext, "assertion-1", expires, base)
	if err != nil {
		t.Fatalf("first prefix SeenAndStore: %v | 第一前缀 SeenAndStore 失败", err)
	}
	if seenFirst {
		t.Fatal("first prefix saw the second prefix assertion | 第一前缀看到了第二前缀的断言")
	}
	seenSecond, err := second.SeenAndStore(testContext, "assertion-1", expires, base)
	if err != nil || !seenSecond {
		t.Fatalf("second prefix assertion = %v, %v, want seen | 第二前缀应看到自身断言", seenSecond, err)
	}
}

// TestBackendErrorsAreRedacted verifies that backend failures are classified and carry no address.
// | TestBackendErrorsAreRedacted 验证后端故障被分类且不携带地址。
func TestBackendErrorsAreRedacted(t *testing.T) {
	client := goredis.NewClient(&goredis.Options{Addr: "127.0.0.1:1", MaxRetries: -1, DialTimeout: 50 * time.Millisecond})
	t.Cleanup(func() {
		_ = client.Close()
	})
	stores, err := authsaml.New(client, authsaml.Options{})
	if err != nil {
		t.Fatalf("new stores: %v | 创建存储失败", err)
	}
	base := testTime(2026, time.January, 1, 12, 0, 0)
	_, err = stores.GetSession(testContext, "sess-1")
	if !errors.Is(err, authsaml.ErrStoreUnavailable) {
		t.Fatalf("error = %v, want ErrStoreUnavailable | 错误未映射为存储不可用", err)
	}
	if strings.Contains(err.Error(), "127.0.0.1") {
		t.Fatalf("error leaked the address: %v | 错误泄露了地址", err)
	}
	if _, err := stores.SaveAssertion(testContext, "assertion-1", base.Add(time.Hour), base); !errors.Is(err, authsaml.ErrStoreUnavailable) {
		t.Fatalf("assertion error = %v, want ErrStoreUnavailable | 断言错误未映射", err)
	}
}

// TestAllMethodsMapBackendErrors verifies that every operation classifies a closed backend as
// ErrStoreUnavailable. | TestAllMethodsMapBackendErrors 验证每个操作都把已关闭后端归类为
// ErrStoreUnavailable。
func TestAllMethodsMapBackendErrors(t *testing.T) {
	server := miniredis.RunT(t)
	client := goredis.NewClient(&goredis.Options{Addr: server.Addr(), MaxRetries: -1})
	stores, err := authsaml.New(client, authsaml.Options{})
	if err != nil {
		t.Fatalf("new stores: %v | 创建存储失败", err)
	}
	if err := client.Close(); err != nil {
		t.Fatalf("close client: %v | 关闭客户端失败", err)
	}
	base := testTime(2026, time.December, 1, 0, 0, 0)
	expires := base.Add(time.Hour)
	request := sampleRequest("req-1", base, expires)
	session := sampleSession("sess-1", "alice", base, expires)
	artifact := sampleArtifact(1, 0)
	record := sampleRecord(artifact, "payload", base, expires)
	operations := []struct {
		name string
		call func() error
	}{
		{"request.save", func() error { return stores.SaveRequest(testContext, request) }},
		{"request.consume", func() error { _, err := stores.ConsumeRequest(testContext, "req-1", base); return err }},
		{"assertion.save", func() error { _, err := stores.SaveAssertion(testContext, "assertion-1", expires, base); return err }},
		{"assertion.seen", func() error {
			_, err := stores.SeenAndStore(testContext, "assertion-1", expires, base)
			return err
		}},
		{"session.save", func() error { return stores.SaveSession(testContext, session) }},
		{"session.get", func() error { _, err := stores.GetSession(testContext, "sess-1"); return err }},
		{"session.delete", func() error { return stores.DeleteSession(testContext, "sess-1") }},
		{"session.list", func() error { _, err := stores.ListSessions(testContext, "alice"); return err }},
		{"artifact.save", func() error { return stores.SaveArtifact(testContext, record, base) }},
		{"artifact.take", func() error { _, err := stores.TakeArtifact(testContext, artifact, base); return err }},
		{"cleanup", func() error { return stores.Cleanup(testContext, base) }},
		{"cleanup.assertions", func() error { _, err := stores.CleanupAssertions(testContext, base); return err }},
	}
	for _, operation := range operations {
		if err := operation.call(); !errors.Is(err, authsaml.ErrStoreUnavailable) {
			t.Fatalf("%s error = %v, want ErrStoreUnavailable | %s 错误未映射为存储不可用", operation.name, err, operation.name)
		}
	}
}

// TestContextCancellation verifies that cancellation is returned unchanged by every category.
// | TestContextCancellation 验证每个类别都原样返回上下文取消。
func TestContextCancellation(t *testing.T) {
	stores := newStore(t, "")
	base := testTime(2026, time.January, 1, 12, 0, 0)
	expires := base.Add(time.Hour)
	canceled, cancel := context.WithCancel(testContext)
	cancel()
	artifact := sampleArtifact(1, 0)
	operations := []struct {
		name string
		call func() error
	}{
		{"request.save", func() error { return stores.SaveRequest(canceled, sampleRequest("req-1", base, expires)) }},
		{"request.consume", func() error { _, err := stores.ConsumeRequest(canceled, "req-1", base); return err }},
		{"assertion.seen", func() error { _, err := stores.SeenAndStore(canceled, "assertion-1", expires, base); return err }},
		{"session.save", func() error { return stores.SaveSession(canceled, sampleSession("sess-1", "alice", base, expires)) }},
		{"session.get", func() error { _, err := stores.GetSession(canceled, "sess-1"); return err }},
		{"session.delete", func() error { return stores.DeleteSession(canceled, "sess-1") }},
		{"session.list", func() error { _, err := stores.ListSessions(canceled, "alice"); return err }},
		{"artifact.save", func() error {
			return stores.SaveArtifact(canceled, sampleRecord(artifact, "payload", base, expires), base)
		}},
		{"artifact.take", func() error { _, err := stores.TakeArtifact(canceled, artifact, base); return err }},
		{"cleanup", func() error { return stores.Cleanup(canceled, base) }},
		{"cleanup.assertions", func() error { _, err := stores.CleanupAssertions(canceled, base); return err }},
	}
	for _, operation := range operations {
		if err := operation.call(); !errors.Is(err, context.Canceled) {
			t.Fatalf("%s error = %v, want context.Canceled | %s 错误未返回上下文取消", operation.name, err, operation.name)
		}
	}
}

// TestNilReceiverFailsClosed verifies that a nil stores value never panics and fails closed.
// | TestNilReceiverFailsClosed 验证空存储值绝不 panic 且失败关闭。
func TestNilReceiverFailsClosed(t *testing.T) {
	var stores *authsaml.Stores
	base := testTime(2026, time.January, 1, 12, 0, 0)
	expires := base.Add(time.Hour)
	artifact := sampleArtifact(1, 0)
	operations := []struct {
		name string
		call func() error
	}{
		{"request.save", func() error { return stores.SaveRequest(testContext, sampleRequest("req-1", base, expires)) }},
		{"request.consume", func() error { _, err := stores.ConsumeRequest(testContext, "req-1", base); return err }},
		{"assertion.save", func() error { _, err := stores.SaveAssertion(testContext, "assertion-1", expires, base); return err }},
		{"assertion.seen", func() error {
			_, err := stores.SeenAndStore(testContext, "assertion-1", expires, base)
			return err
		}},
		{"session.save", func() error { return stores.SaveSession(testContext, sampleSession("sess-1", "alice", base, expires)) }},
		{"session.get", func() error { _, err := stores.GetSession(testContext, "sess-1"); return err }},
		{"session.delete", func() error { return stores.DeleteSession(testContext, "sess-1") }},
		{"session.list", func() error { _, err := stores.ListSessions(testContext, "alice"); return err }},
		{"artifact.save", func() error {
			return stores.SaveArtifact(testContext, sampleRecord(artifact, "payload", base, expires), base)
		}},
		{"artifact.take", func() error { _, err := stores.TakeArtifact(testContext, artifact, base); return err }},
		{"cleanup", func() error { return stores.Cleanup(testContext, base) }},
		{"cleanup.assertions", func() error { _, err := stores.CleanupAssertions(testContext, base); return err }},
	}
	for _, operation := range operations {
		if err := operation.call(); !errors.Is(err, samlapi.ErrInvalidConfig) {
			t.Fatalf("%s error = %v, want ErrInvalidConfig | %s 错误未失败关闭", operation.name, err, operation.name)
		}
	}
}
