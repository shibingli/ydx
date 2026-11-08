package saml_test

import (
	"context"
	"errors"
	"fmt"
	"sort"
	"testing"
	"time"

	samlapi "github.com/shibingli/ydx/auth/protocol/saml"
	authsaml "github.com/shibingli/ydx/authstore/saml"
)

// TestRequestLifecycle covers request creation, single use and deep copies.
// | TestRequestLifecycle 覆盖请求创建、单次使用与深拷贝。
func TestRequestLifecycle(t *testing.T) {
	first, second := newPair(t)
	base := testTime(2026, time.January, 1, 12, 0, 0)
	expires := base.Add(time.Hour)
	request := sampleRequest("req-1", base, expires)
	if err := first.SaveRequest(testContext, request); err != nil {
		t.Fatalf("save request: %v | 保存请求失败", err)
	}
	// Mutating the caller value after the save must not change the stored record.
	request.SPEntityID = "mutated"
	if err := first.SaveRequest(testContext, request); !errors.Is(err, samlapi.ErrReplay) {
		t.Fatalf("duplicate request error = %v, want ErrReplay | 重复请求错误不符", err)
	}
	consumed, err := second.ConsumeRequest(testContext, "req-1", base.Add(30*time.Minute))
	if err != nil {
		t.Fatalf("consume request: %v | 消费请求失败", err)
	}
	if !consumed.Used {
		t.Fatal("consumed request is not marked used | 已消费请求未标记已用")
	}
	if consumed.SPEntityID != "https://sp.example.com/saml/metadata" {
		t.Fatalf("stored request was not a deep copy: %q | 存储请求不是深拷贝", consumed.SPEntityID)
	}
	if _, err := first.ConsumeRequest(testContext, "req-1", base.Add(30*time.Minute)); !errors.Is(err, samlapi.ErrInvalidRequest) {
		t.Fatalf("second consume error = %v, want ErrInvalidRequest | 二次消费错误不符", err)
	}
	if _, err := second.ConsumeRequest(testContext, "missing", base); !errors.Is(err, samlapi.ErrInvalidRequest) {
		t.Fatalf("unknown consume error = %v, want ErrInvalidRequest | 未知请求消费错误不符", err)
	}
	if err := first.SaveRequest(testContext, nil); !errors.Is(err, samlapi.ErrInvalidRequest) {
		t.Fatalf("nil request error = %v, want ErrInvalidRequest | 空请求错误不符", err)
	}
	if err := first.SaveRequest(testContext, &samlapi.RequestState{}); !errors.Is(err, samlapi.ErrInvalidRequest) {
		t.Fatalf("empty request id error = %v, want ErrInvalidRequest | 空请求标识错误不符", err)
	}
}

// TestRequestExpiryAndCleanup covers expiry rejection and cleanup of expired requests.
// | TestRequestExpiryAndCleanup 覆盖过期拒绝与过期请求清理。
func TestRequestExpiryAndCleanup(t *testing.T) {
	stores := newStore(t, "")
	base := testTime(2026, time.February, 1, 0, 0, 0)
	expires := base.Add(time.Hour)
	if err := stores.SaveRequest(testContext, sampleRequest("req-expired", base, expires)); err != nil {
		t.Fatalf("save request: %v | 保存请求失败", err)
	}
	if _, err := stores.ConsumeRequest(testContext, "req-expired", expires); !errors.Is(err, samlapi.ErrResponseExpired) {
		t.Fatalf("consume at expiry error = %v, want ErrResponseExpired | 到期时消费错误不符", err)
	}
	if _, err := stores.ConsumeRequest(testContext, "req-expired", expires.Add(-time.Nanosecond)); err != nil {
		t.Fatalf("consume before expiry: %v | 到期前消费失败", err)
	}
	if err := stores.SaveRequest(testContext, sampleRequest("req-stale", base, expires)); err != nil {
		t.Fatalf("save stale request: %v | 保存陈旧请求失败", err)
	}
	if err := stores.Cleanup(testContext, expires); err != nil {
		t.Fatalf("cleanup: %v | 清理失败", err)
	}
	if _, err := stores.ConsumeRequest(testContext, "req-stale", expires); !errors.Is(err, samlapi.ErrInvalidRequest) {
		t.Fatalf("consume after cleanup error = %v, want ErrInvalidRequest | 清理后消费错误不符", err)
	}
}

// TestRequestUTCNormalization verifies that stored request times come back in UTC.
// | TestRequestUTCNormalization 验证存储的请求时间以 UTC 返回。
func TestRequestUTCNormalization(t *testing.T) {
	stores := newStore(t, "")
	zone := time.FixedZone("UTC+8", 8*60*60)
	created := time.Date(2026, time.March, 1, 20, 0, 0, 0, zone)
	expires := created.Add(time.Hour)
	if err := stores.SaveRequest(testContext, sampleRequest("req-utc", created, expires)); err != nil {
		t.Fatalf("save request: %v | 保存请求失败", err)
	}
	consumed, err := stores.ConsumeRequest(testContext, "req-utc", created)
	if err != nil {
		t.Fatalf("consume request: %v | 消费请求失败", err)
	}
	if !consumed.CreatedAt.Equal(created) || consumed.CreatedAt.Location() != time.UTC {
		t.Fatalf("created time = %v, want UTC %v | 创建时间未规范化为 UTC", consumed.CreatedAt, created.UTC())
	}
	if !consumed.ExpiresAt.Equal(expires) || consumed.ExpiresAt.Location() != time.UTC {
		t.Fatalf("expiry time = %v, want UTC %v | 到期时间未规范化为 UTC", consumed.ExpiresAt, expires.UTC())
	}
}

// TestAssertionReplay covers fresh/replay reporting, cross-instance visibility and expiry
// replacement. | TestAssertionReplay 覆盖新鲜/重放报告、跨实例可见性与过期替换。
func TestAssertionReplay(t *testing.T) {
	first, second := newPair(t)
	base := testTime(2026, time.April, 1, 0, 0, 0)
	expires := base.Add(time.Hour)
	if _, err := first.SaveAssertion(testContext, "", expires, base); !errors.Is(err, samlapi.ErrInvalidResponse) {
		t.Fatalf("empty assertion error = %v, want ErrInvalidResponse | 空断言错误不符", err)
	}
	if _, err := first.SeenAndStore(testContext, "", expires, base); !errors.Is(err, samlapi.ErrInvalidResponse) {
		t.Fatalf("empty SeenAndStore error = %v, want ErrInvalidResponse | 空断言 SeenAndStore 错误不符", err)
	}
	fresh, err := first.SaveAssertion(testContext, "assertion-1", expires, base)
	if err != nil || !fresh {
		t.Fatalf("first SaveAssertion = %v, %v, want fresh | 首次保存断言应新鲜", fresh, err)
	}
	replay, err := second.SaveAssertion(testContext, "assertion-1", expires, base)
	if err != nil || replay {
		t.Fatalf("second SaveAssertion = %v, %v, want replay | 二次保存断言应重放", replay, err)
	}
	seen, err := second.SeenAndStore(testContext, "assertion-1", expires, base)
	if err != nil || !seen {
		t.Fatalf("SeenAndStore = %v, %v, want seen | SeenAndStore 应报告已见", seen, err)
	}
	if seen, err := first.SeenAndStore(testContext, "assertion-1", expires.Add(time.Hour), expires); err != nil || seen {
		t.Fatalf("SeenAndStore at expiry = %v, %v, want replaceable | 到期时应可替换", seen, err)
	}
	if seen, err := first.SeenAndStore(testContext, "assertion-1", expires.Add(time.Hour), expires.Add(time.Minute)); err != nil || !seen {
		t.Fatalf("SeenAndStore after replacement = %v, %v, want seen | 替换后应报告已见", seen, err)
	}
	if fresh, err := second.SaveAssertion(testContext, "assertion-2", base.Add(-time.Minute), base); err != nil || !fresh {
		t.Fatalf("already-expired assertion = %v, %v, want fresh | 已过期断言应报告新鲜", fresh, err)
	}
}

// TestCleanupAssertionsPagination removes more than one cleanup batch and checks the exact
// boundary second. | TestCleanupAssertionsPagination 删除超过一个清理批次并检查精确边界秒。
func TestCleanupAssertionsPagination(t *testing.T) {
	stores := newStore(t, "")
	base := testTime(2026, time.May, 1, 0, 0, 0)
	expiredAt := base.Add(-time.Second)
	for index := 0; index < 300; index++ {
		id := fmt.Sprintf("expired-%03d", index)
		if seen, err := stores.SeenAndStore(testContext, id, expiredAt, base.Add(-time.Hour)); err != nil || seen {
			t.Fatalf("seed %s = %v, %v | 预置断言失败", id, seen, err)
		}
	}
	if seen, err := stores.SeenAndStore(testContext, "boundary", base, base.Add(-time.Hour)); err != nil || seen {
		t.Fatalf("seed boundary = %v, %v | 预置边界断言失败", seen, err)
	}
	if seen, err := stores.SeenAndStore(testContext, "live", base.Add(time.Second), base.Add(-time.Hour)); err != nil || seen {
		t.Fatalf("seed live = %v, %v | 预置有效断言失败", seen, err)
	}
	removed, err := stores.CleanupAssertions(testContext, base)
	if err != nil {
		t.Fatalf("cleanup assertions: %v | 清理断言失败", err)
	}
	if removed != 301 {
		t.Fatalf("removed = %d, want 301 | 删除数量不符", removed)
	}
	if seen, err := stores.SeenAndStore(testContext, "live", base.Add(time.Second), base); err != nil || !seen {
		t.Fatalf("live assertion = %v, %v, want seen | 有效断言应仍存在", seen, err)
	}
	if seen, err := stores.SeenAndStore(testContext, "expired-000", base.Add(time.Hour), base); err != nil || seen {
		t.Fatalf("expired assertion = %v, %v, want fresh | 过期断言应已删除", seen, err)
	}
	if seen, err := stores.SeenAndStore(testContext, "boundary", base.Add(time.Hour), base); err != nil || seen {
		t.Fatalf("boundary assertion = %v, %v, want fresh | 边界断言应已删除", seen, err)
	}
}

// TestZeroExpiryAssertionCleanup treats a zero assertion expiry like the in-memory store.
// | TestZeroExpiryAssertionCleanup 与内存存储一样处理零值断言期限。
func TestZeroExpiryAssertionCleanup(t *testing.T) {
	stores := newStore(t, "")
	base := testTime(2026, time.June, 1, 0, 0, 0)
	if seen, err := stores.SeenAndStore(testContext, "zero", time.Time{}, base); err != nil || seen {
		t.Fatalf("zero expiry SeenAndStore = %v, %v | 零期限断言存储失败", seen, err)
	}
	if seen, err := stores.SeenAndStore(testContext, "zero", time.Time{}, base); err != nil || seen {
		t.Fatalf("zero expiry is not replaceable: %v, %v | 零期限断言应可替换", seen, err)
	}
	if removed, err := stores.CleanupAssertions(testContext, base); err != nil || removed != 1 {
		t.Fatalf("cleanup zero expiry = %d, %v, want 1 | 零期限断言清理数量不符", removed, err)
	}
}

// TestSessionLifecycle covers save, cross-instance get, deep copies, subject moves and delete.
// | TestSessionLifecycle 覆盖保存、跨实例读取、深拷贝、主体迁移与删除。
func TestSessionLifecycle(t *testing.T) {
	first, second := newPair(t)
	base := testTime(2026, time.July, 1, 0, 0, 0)
	expires := base.Add(time.Hour)
	zone := time.FixedZone("UTC+8", 8*60*60)
	created := time.Date(2026, time.July, 1, 8, 0, 0, 0, zone)
	session := sampleSession("sess-1", "alice", created, expires)
	if err := first.SaveSession(testContext, session); err != nil {
		t.Fatalf("save session: %v | 保存会话失败", err)
	}
	got, err := second.GetSession(testContext, "sess-1")
	if err != nil {
		t.Fatalf("cross-instance get: %v | 跨实例读取会话失败", err)
	}
	if !got.CreatedAt.Equal(created) || got.CreatedAt.Location() != time.UTC {
		t.Fatalf("created time = %v, want UTC %v | 创建时间未规范化为 UTC", got.CreatedAt, created.UTC())
	}
	got.Attributes["role"][0] = "mutated"
	got.Attributes["extra"] = []string{"value"}
	back, err := first.GetSession(testContext, "sess-1")
	if err != nil {
		t.Fatalf("get after mutation: %v | 变更后读取会话失败", err)
	}
	if back.Attributes["role"][0] != "admin" {
		t.Fatalf("session attributes are shared: %v | 会话属性被共享", back.Attributes)
	}
	if _, ok := back.Attributes["extra"]; ok {
		t.Fatal("map insertion leaked into the store | 映射写入泄露到存储")
	}
	moved := sampleSession("sess-1", "bob", created, expires)
	moved.SPEntityID = "https://sp2.example.com/saml/metadata"
	if err := second.SaveSession(testContext, moved); err != nil {
		t.Fatalf("move session: %v | 迁移会话失败", err)
	}
	aliceSessions, err := first.ListSessions(testContext, "alice")
	if err != nil {
		t.Fatalf("list alice: %v | 列出 alice 会话失败", err)
	}
	if len(aliceSessions) != 0 {
		t.Fatalf("alice sessions = %d, want 0 | 旧主体仍有会话", len(aliceSessions))
	}
	bobSessions, err := first.ListSessions(testContext, "bob")
	if err != nil {
		t.Fatalf("list bob: %v | 列出 bob 会话失败", err)
	}
	if len(bobSessions) != 1 || bobSessions[0].SPEntityID != moved.SPEntityID {
		t.Fatalf("bob sessions = %+v | 新主体会话不符", bobSessions)
	}
	if err := first.DeleteSession(testContext, "sess-1"); err != nil {
		t.Fatalf("delete session: %v | 删除会话失败", err)
	}
	if _, err := second.GetSession(testContext, "sess-1"); !errors.Is(err, samlapi.ErrInvalidRequest) {
		t.Fatalf("get deleted session error = %v, want ErrInvalidRequest | 已删会话错误不符", err)
	}
	if remaining, err := second.ListSessions(testContext, "bob"); err != nil || len(remaining) != 0 {
		t.Fatalf("list after delete = %d, %v, want 0 | 删除后仍列出会话", len(remaining), err)
	}
	if err := second.DeleteSession(testContext, "sess-1"); err != nil {
		t.Fatalf("delete absent session: %v | 删除不存在会话失败", err)
	}
	if _, err := first.GetSession(testContext, "missing"); !errors.Is(err, samlapi.ErrInvalidRequest) {
		t.Fatalf("unknown session error = %v, want ErrInvalidRequest | 未知会话错误不符", err)
	}
	if err := first.SaveSession(testContext, nil); !errors.Is(err, samlapi.ErrInvalidRequest) {
		t.Fatalf("nil session error = %v, want ErrInvalidRequest | 空会话错误不符", err)
	}
	if err := first.SaveSession(testContext, &samlapi.Session{}); !errors.Is(err, samlapi.ErrInvalidRequest) {
		t.Fatalf("empty session id error = %v, want ErrInvalidRequest | 空会话标识错误不符", err)
	}
}

// TestSessionCleanup removes expired sessions and their subject membership, including the exact
// boundary second, while retaining sessions without expiry. | TestSessionCleanup 删除过期会话及其
// 主体成员关系（包括精确边界秒），并保留无到期时间的会话。
func TestSessionCleanup(t *testing.T) {
	stores := newStore(t, "")
	base := testTime(2026, time.August, 1, 0, 0, 0)
	for _, session := range []*samlapi.Session{
		sampleSession("early", "alice", base, base.Add(time.Hour)),
		sampleSession("boundary", "alice", base, base.Add(2*time.Hour)),
		sampleSession("live", "alice", base, base.Add(3*time.Hour)),
		sampleSession("forever", "alice", base, time.Time{}),
	} {
		if err := stores.SaveSession(testContext, session); err != nil {
			t.Fatalf("save %s: %v | 保存会话 %s 失败", session.ID, err, session.ID)
		}
	}
	if err := stores.Cleanup(testContext, base.Add(2*time.Hour)); err != nil {
		t.Fatalf("cleanup: %v | 清理失败", err)
	}
	sessions, err := stores.ListSessions(testContext, "alice")
	if err != nil {
		t.Fatalf("list sessions: %v | 列出会话失败", err)
	}
	if len(sessions) != 2 {
		t.Fatalf("sessions = %d, want 2 | 剩余会话数量不符", len(sessions))
	}
	ids := []string{sessions[0].ID, sessions[1].ID}
	sort.Strings(ids)
	if ids[0] != "forever" || ids[1] != "live" {
		t.Fatalf("remaining ids = %v | 剩余会话标识不符", ids)
	}
	if _, err := stores.GetSession(testContext, "early"); !errors.Is(err, samlapi.ErrInvalidRequest) {
		t.Fatalf("early session error = %v | 早期会话未删除", err)
	}
	if _, err := stores.GetSession(testContext, "boundary"); !errors.Is(err, samlapi.ErrInvalidRequest) {
		t.Fatalf("boundary session error = %v | 边界会话未删除", err)
	}
	if _, err := stores.GetSession(testContext, "live"); err != nil {
		t.Fatalf("live session: %v | 有效会话被误删", err)
	}
	if _, err := stores.GetSession(testContext, "forever"); err != nil {
		t.Fatalf("zero-expiry session: %v | 零期限会话被误删", err)
	}
}

// TestListSessionsPagination lists more sessions than one scan page, written by two instances.
// | TestListSessionsPagination 列出超过一个扫描页的会话，且由两个实例写入。
func TestListSessionsPagination(t *testing.T) {
	first, second := newPair(t)
	base := testTime(2026, time.September, 1, 0, 0, 0)
	expires := base.Add(24 * time.Hour)
	const total = 300
	for index := 0; index < total; index++ {
		stores := first
		if index%2 == 1 {
			stores = second
		}
		session := sampleSession(fmt.Sprintf("sess-%04d", index), "bob", base, expires)
		if err := stores.SaveSession(testContext, session); err != nil {
			t.Fatalf("save session %d: %v | 保存会话 %d 失败", index, err, index)
		}
	}
	if err := first.SaveSession(testContext, sampleSession("other", "carol", base, expires)); err != nil {
		t.Fatalf("save other session: %v | 保存其它会话失败", err)
	}
	sessions, err := second.ListSessions(testContext, "bob")
	if err != nil {
		t.Fatalf("list sessions: %v | 列出会话失败", err)
	}
	if len(sessions) != total {
		t.Fatalf("sessions = %d, want %d | 会话数量不符", len(sessions), total)
	}
	unique := make(map[string]struct{}, total)
	for index, session := range sessions {
		unique[session.ID] = struct{}{}
		expected := fmt.Sprintf("sess-%04d", index)
		if session.ID != expected {
			t.Fatalf("session[%d] = %q, want %q | 会话顺序或标识不符", index, session.ID, expected)
		}
	}
	if len(unique) != total {
		t.Fatalf("unique sessions = %d, want %d | 会话存在重复", len(unique), total)
	}
}

// TestCleanupAllTypes removes expired records of every category and keeps live ones.
// | TestCleanupAllTypes 删除每个类别的过期记录并保留有效记录。
func TestCleanupAllTypes(t *testing.T) {
	stores := newStore(t, "")
	base := testTime(2026, time.October, 1, 0, 0, 0)
	expired := base.Add(-time.Hour)
	live := base.Add(time.Hour)
	if err := stores.SaveRequest(testContext, sampleRequest("req-old", base.Add(-2*time.Hour), expired)); err != nil {
		t.Fatalf("save stale request: %v | 保存过期请求失败", err)
	}
	if err := stores.SaveRequest(testContext, sampleRequest("req-live", base, live)); err != nil {
		t.Fatalf("save live request: %v | 保存有效请求失败", err)
	}
	if seen, err := stores.SeenAndStore(testContext, "assertion-old", expired, base.Add(-2*time.Hour)); err != nil || seen {
		t.Fatalf("seed stale assertion = %v, %v | 预置过期断言失败", seen, err)
	}
	if seen, err := stores.SeenAndStore(testContext, "assertion-live", live, base); err != nil || seen {
		t.Fatalf("seed live assertion = %v, %v | 预置有效断言失败", seen, err)
	}
	if err := stores.SaveSession(testContext, sampleSession("sess-old", "alice", base.Add(-2*time.Hour), expired)); err != nil {
		t.Fatalf("save stale session: %v | 保存过期会话失败", err)
	}
	if err := stores.SaveSession(testContext, sampleSession("sess-live", "alice", base, live)); err != nil {
		t.Fatalf("save live session: %v | 保存有效会话失败", err)
	}
	oldArtifact := sampleArtifact(1, 0)
	liveArtifact := sampleArtifact(2, 0)
	if err := stores.SaveArtifact(testContext, sampleRecord(oldArtifact, "old", base.Add(-2*time.Hour), expired), base.Add(-2*time.Hour)); err != nil {
		t.Fatalf("save stale artifact: %v | 保存过期工件失败", err)
	}
	if err := stores.SaveArtifact(testContext, sampleRecord(liveArtifact, "live", base, live), base); err != nil {
		t.Fatalf("save live artifact: %v | 保存有效工件失败", err)
	}
	if err := stores.Cleanup(testContext, base); err != nil {
		t.Fatalf("cleanup: %v | 清理失败", err)
	}
	if _, err := stores.ConsumeRequest(testContext, "req-old", base); !errors.Is(err, samlapi.ErrInvalidRequest) {
		t.Fatalf("stale request error = %v | 过期请求未删除", err)
	}
	if _, err := stores.ConsumeRequest(testContext, "req-live", base); err != nil {
		t.Fatalf("live request: %v | 有效请求被误删", err)
	}
	if seen, err := stores.SeenAndStore(testContext, "assertion-old", live, base); err != nil || seen {
		t.Fatalf("stale assertion = %v, %v, want fresh | 过期断言未删除", seen, err)
	}
	if seen, err := stores.SeenAndStore(testContext, "assertion-live", live, base); err != nil || !seen {
		t.Fatalf("live assertion = %v, %v, want seen | 有效断言被误删", seen, err)
	}
	if _, err := stores.GetSession(testContext, "sess-old"); !errors.Is(err, samlapi.ErrInvalidRequest) {
		t.Fatalf("stale session error = %v | 过期会话未删除", err)
	}
	if _, err := stores.GetSession(testContext, "sess-live"); err != nil {
		t.Fatalf("live session: %v | 有效会话被误删", err)
	}
	if _, err := stores.TakeArtifact(testContext, oldArtifact, base); !errors.Is(err, samlapi.ErrArtifactInvalid) {
		t.Fatalf("stale artifact error = %v | 过期工件未删除", err)
	}
	if _, err := stores.TakeArtifact(testContext, liveArtifact, base); err != nil {
		t.Fatalf("live artifact: %v | 有效工件被误删", err)
	}
}

// TestSaveSessionConflictRetriesDoNotLeak verifies that repeated moves keep both indexes
// consistent. | TestSaveSessionConflictRetriesDoNotLeak 验证反复迁移保持两个索引一致。
func TestSaveSessionConflictRetriesDoNotLeak(t *testing.T) {
	stores := newStore(t, "")
	base := testTime(2026, time.November, 1, 0, 0, 0)
	expires := base.Add(time.Hour)
	for index := 0; index < 20; index++ {
		nameID := "alice"
		if index%2 == 1 {
			nameID = "bob"
		}
		if err := stores.SaveSession(testContext, sampleSession("sess-1", nameID, base, expires)); err != nil {
			t.Fatalf("save %d: %v | 第 %d 次保存失败", index, err, index)
		}
	}
	bobSessions, err := stores.ListSessions(testContext, "bob")
	if err != nil {
		t.Fatalf("list bob: %v | 列出 bob 失败", err)
	}
	if len(bobSessions) != 1 || bobSessions[0].NameID != "bob" {
		t.Fatalf("bob sessions = %+v | bob 会话不符", bobSessions)
	}
	aliceSessions, err := stores.ListSessions(testContext, "alice")
	if err != nil {
		t.Fatalf("list alice: %v | 列出 alice 失败", err)
	}
	if len(aliceSessions) != 0 {
		t.Fatalf("alice sessions = %d, want 0 | alice 集合残留", len(aliceSessions))
	}
}

// TestSessionsWithoutExpirySurviveCleanup verifies the in-memory zero-expiry rule.
// | TestSessionsWithoutExpirySurviveCleanup 验证内存存储的零期限规则。
func TestSessionsWithoutExpirySurviveCleanup(t *testing.T) {
	stores := newStore(t, "")
	base := testTime(2026, time.December, 1, 0, 0, 0)
	if err := stores.SaveSession(testContext, sampleSession("forever", "alice", base, time.Time{})); err != nil {
		t.Fatalf("save session: %v | 保存会话失败", err)
	}
	if err := stores.Cleanup(testContext, base.Add(1000*time.Hour)); err != nil {
		t.Fatalf("cleanup: %v | 清理失败", err)
	}
	if _, err := stores.GetSession(testContext, "forever"); err != nil {
		t.Fatalf("zero-expiry session: %v | 零期限会话被误删", err)
	}
}

// TestStoresTypeSurface asserts the optional cleaner method on a concrete stores value.
// | TestStoresTypeSurface 断言具体存储值的可选清理方法。
func TestStoresTypeSurface(t *testing.T) {
	stores := newStore(t, "")
	var cleaner interface {
		CleanupAssertions(ctx context.Context, now time.Time) (int, error)
	} = stores
	if removed, err := cleaner.CleanupAssertions(testContext, testTime(2026, time.January, 1, 0, 0, 0)); err != nil || removed != 0 {
		t.Fatalf("empty cleanup = %d, %v | 空清理结果不符", removed, err)
	}
	_ = authsaml.DefaultKeyPrefix
}
