package cas_test

import (
	"errors"
	"testing"
	"time"

	authcas "github.com/shibingli/ydx/auth/protocol/cas"
)

// TestSessionLifecycle registers a session on one instance and reads it from another.
// | TestSessionLifecycle 在一个实例上注册会话并从另一个实例读取。
func TestSessionLifecycle(t *testing.T) {
	first, second := newPair(t)
	zone := time.FixedZone("CST", 8*3600)
	base := time.Date(2026, time.March, 2, 9, 15, 0, 0, zone)
	session := sampleSession("ST-1", "TGT-1", "alice", "user-1", "https://app.example.com", base, time.Hour)
	if err := first.Sessions.Register(testContext, session); err != nil {
		t.Fatalf("register: %v | 注册失败", err)
	}
	stored, err := second.Sessions.Get(testContext, "ST-1")
	if err != nil {
		t.Fatalf("get: %v | 查询失败", err)
	}
	if stored.SessionIndex != "ST-1" || stored.TicketID != "ST-1" {
		t.Fatalf("TicketID = %q, want ST-1 | 票据标识默认值不符", stored.TicketID)
	}
	if stored.User != "alice" || stored.UserID != "user-1" || stored.TGTID != "TGT-1" {
		t.Fatalf("stored session = %#v | 已存会话不符", stored)
	}
	if stored.IssuedAt.Location() != time.UTC || !stored.IssuedAt.Equal(base) {
		t.Fatalf("IssuedAt = %v | 签发时间未规范化为 UTC", stored.IssuedAt)
	}
	if stored.ExpiresAt.Location() != time.UTC {
		t.Fatalf("ExpiresAt zone = %v | 期限未规范化为 UTC", stored.ExpiresAt.Location())
	}
	byTGT, err := second.Sessions.ListByTGT(testContext, "TGT-1")
	if err != nil || len(byTGT) != 1 || byTGT[0].SessionIndex != "ST-1" {
		t.Fatalf("ListByTGT = %v, %v | 按 TGT 查询不符", sessionIndexes(byTGT), err)
	}
	for _, user := range []string{"alice", "user-1"} {
		list, err := first.Sessions.ListByUser(testContext, user)
		if err != nil || len(list) != 1 || list[0].SessionIndex != "ST-1" {
			t.Fatalf("ListByUser(%q) = %v, %v | 按用户查询不符", user, sessionIndexes(list), err)
		}
	}
	if list, err := second.Sessions.ListByUser(testContext, "unknown"); err != nil || len(list) != 0 {
		t.Fatalf("ListByUser(unknown) = %v, %v | 未知用户查询不符", sessionIndexes(list), err)
	}
	if list, err := second.Sessions.ListByTGT(testContext, "unknown"); err != nil || len(list) != 0 {
		t.Fatalf("ListByTGT(unknown) = %v, %v | 未知 TGT 查询不符", sessionIndexes(list), err)
	}
	stored.User = "changed"
	stored.TicketID = "changed"
	again, err := second.Sessions.Get(testContext, "ST-1")
	if err != nil {
		t.Fatalf("get again: %v | 再次查询失败", err)
	}
	if again.User != "alice" || again.TicketID != "ST-1" {
		t.Fatalf("returned copy aliased stored memory | 返回副本别名了已存内存")
	}
}

// TestSessionValidation covers invalid registration and missing lookups.
// | TestSessionValidation 覆盖非法注册与缺失查询。
func TestSessionValidation(t *testing.T) {
	stores := newStores(t, "")
	if err := stores.Sessions.Register(testContext, nil); !errors.Is(err, authcas.ErrInvalidRequest) {
		t.Fatalf("nil register error = %v, want ErrInvalidRequest | 空会话注册错误不符", err)
	}
	if err := stores.Sessions.Register(testContext, &authcas.ServiceSession{User: "alice"}); !errors.Is(err, authcas.ErrInvalidRequest) {
		t.Fatalf("empty index register error = %v, want ErrInvalidRequest | 空索引注册错误不符", err)
	}
	if _, err := stores.Sessions.Get(testContext, ""); !errors.Is(err, authcas.ErrSessionNotFound) {
		t.Fatalf("empty index get error = %v, want ErrSessionNotFound | 空索引查询错误不符", err)
	}
	if _, err := stores.Sessions.Get(testContext, "missing"); !errors.Is(err, authcas.ErrSessionNotFound) {
		t.Fatalf("missing get error = %v, want ErrSessionNotFound | 缺失会话错误不符", err)
	}
}

// TestSessionDeletes verifies individual, per-TGT and per-user removal.
// | TestSessionDeletes 验证单条、按 TGT 与按用户删除。
func TestSessionDeletes(t *testing.T) {
	first, second := newPair(t)
	base := testTime(2026, time.April, 2, 0, 0, 0)
	one := sampleSession("ST-1", "TGT-1", "alice", "user-1", "https://one.example.com", base, time.Hour)
	two := sampleSession("ST-2", "TGT-1", "bob", "user-2", "https://two.example.com", base.Add(time.Minute), time.Hour)
	three := sampleSession("ST-3", "TGT-2", "alice", "user-1", "https://three.example.com", base.Add(2*time.Minute), time.Hour)
	for _, session := range []*authcas.ServiceSession{one, two, three} {
		if err := first.Sessions.Register(testContext, session); err != nil {
			t.Fatalf("register %s: %v | 注册失败", session.SessionIndex, err)
		}
	}
	if err := second.Sessions.Delete(testContext, "ST-3"); err != nil {
		t.Fatalf("delete ST-3: %v | 删除失败", err)
	}
	if err := second.Sessions.Delete(testContext, "ST-3"); err != nil {
		t.Fatalf("delete ST-3 twice: %v | 二次删除失败", err)
	}
	if err := second.Sessions.Delete(testContext, ""); err != nil {
		t.Fatalf("delete empty: %v | 删除空索引失败", err)
	}
	if _, err := first.Sessions.Get(testContext, "ST-3"); !errors.Is(err, authcas.ErrSessionNotFound) {
		t.Fatalf("ST-3 still present: %v | ST-3 仍存在", err)
	}
	removed, err := second.Sessions.DeleteByTGT(testContext, "TGT-1")
	if err != nil {
		t.Fatalf("delete by tgt: %v | 按 TGT 删除失败", err)
	}
	if len(removed) != 2 || removed[0].SessionIndex != "ST-1" || removed[1].SessionIndex != "ST-2" {
		t.Fatalf("delete by tgt = %v | 按 TGT 删除结果不符", sessionIndexes(removed))
	}
	if list, err := second.Sessions.ListByTGT(testContext, "TGT-1"); err != nil || len(list) != 0 {
		t.Fatalf("TGT-1 after delete = %v, %v | 按 TGT 删除后索引未清理", sessionIndexes(list), err)
	}
	if removed, err := second.Sessions.DeleteByTGT(testContext, "TGT-1"); err != nil || len(removed) != 0 {
		t.Fatalf("delete empty tgt = %v, %v | 空 TGT 删除不符", sessionIndexes(removed), err)
	}
	if removed, err := second.Sessions.DeleteByTGT(testContext, ""); err != nil || len(removed) != 0 {
		t.Fatalf("delete blank tgt = %v, %v | 空白 TGT 删除不符", sessionIndexes(removed), err)
	}

	if err := first.Sessions.Register(testContext, one); err != nil {
		t.Fatalf("re-register one: %v | 重新注册失败", err)
	}
	if err := first.Sessions.Register(testContext, two); err != nil {
		t.Fatalf("re-register two: %v | 重新注册失败", err)
	}
	removed, err = second.Sessions.DeleteByUser(testContext, "user-1")
	if err != nil {
		t.Fatalf("delete by user: %v | 按用户删除失败", err)
	}
	if len(removed) != 1 || removed[0].SessionIndex != "ST-1" {
		t.Fatalf("delete by user = %v | 按用户删除结果不符", sessionIndexes(removed))
	}
	if list, err := first.Sessions.ListByUser(testContext, "alice"); err != nil || len(list) != 0 {
		t.Fatalf("alice after delete = %v, %v | 按用户删除后索引未清理", sessionIndexes(list), err)
	}
	if list, err := first.Sessions.ListByUser(testContext, "user-1"); err != nil || len(list) != 0 {
		t.Fatalf("user-1 after delete = %v, %v | 后端用户索引未清理", sessionIndexes(list), err)
	}
	if _, err := second.Sessions.Get(testContext, "ST-2"); err != nil {
		t.Fatalf("ST-2 should remain: %v | ST-2 被误删", err)
	}
	if removed, err := second.Sessions.DeleteByUser(testContext, ""); err != nil || len(removed) != 0 {
		t.Fatalf("delete blank user = %v, %v | 空白用户删除不符", sessionIndexes(removed), err)
	}
}

// TestSessionExpiry verifies that cleanup honors exact deadlines, zero-expiry sessions survive and
// re-registration updates the expiry index. | TestSessionExpiry 验证清理遵循精确期限、零期限会话
// 继续存活，且重新注册会更新期限索引。
func TestSessionExpiry(t *testing.T) {
	first, second := newPair(t)
	base := testTime(2026, time.May, 2, 0, 0, 0)
	expired := sampleSession("ST-expired", "TGT-1", "alice", "user-1", "https://svc.example.com", base, time.Hour)
	active := sampleSession("ST-active", "TGT-1", "alice", "user-1", "https://svc.example.com", base, 2*time.Hour)
	forever := sampleSession("ST-forever", "TGT-1", "alice", "user-1", "https://svc.example.com", base, 0)
	for _, session := range []*authcas.ServiceSession{expired, active, forever} {
		if err := first.Sessions.Register(testContext, session); err != nil {
			t.Fatalf("register %s: %v | 注册失败", session.SessionIndex, err)
		}
	}
	now := base.Add(time.Hour)
	removed, err := second.Sessions.DeleteExpired(testContext, now)
	if err != nil {
		t.Fatalf("delete expired: %v | 清理过期失败", err)
	}
	if removed != 1 {
		t.Fatalf("removed = %d, want 1 | 清理数量不符", removed)
	}
	if _, err := second.Sessions.Get(testContext, "ST-expired"); !errors.Is(err, authcas.ErrSessionNotFound) {
		t.Fatalf("expired session remains: %v | 过期会话仍存在", err)
	}
	if _, err := second.Sessions.Get(testContext, "ST-forever"); err != nil {
		t.Fatalf("zero-expiry session removed: %v | 零期限会话被误删", err)
	}
	removed, err = second.Sessions.DeleteExpired(testContext, now.Add(100*365*24*time.Hour))
	if err != nil {
		t.Fatalf("delete far future: %v | 远期清理失败", err)
	}
	if removed != 1 {
		t.Fatalf("far future removed = %d, want 1 | 远期清理数量不符", removed)
	}
	if _, err := second.Sessions.Get(testContext, "ST-forever"); err != nil {
		t.Fatalf("zero-expiry session should never expire: %v | 零期限会话不应过期", err)
	}

	bounded := sampleSession("ST-bounded", "TGT-2", "bob", "user-2", "https://svc.example.com", base, time.Hour)
	if err := first.Sessions.Register(testContext, bounded); err != nil {
		t.Fatalf("register bounded: %v | 注册失败", err)
	}
	bounded.ExpiresAt = time.Time{}
	if err := first.Sessions.Register(testContext, bounded); err != nil {
		t.Fatalf("register forever: %v | 注册永不过期失败", err)
	}
	if removed, err := second.Sessions.DeleteExpired(testContext, base.Add(50*time.Hour)); err != nil || removed != 0 {
		t.Fatalf("cleared expiry removed = %d, %v | 已清除期限仍被清理", removed, err)
	}
	bounded.ExpiresAt = base.Add(2 * time.Hour)
	if err := second.Sessions.Register(testContext, bounded); err != nil {
		t.Fatalf("register renewed: %v | 重新注册期限失败", err)
	}
	if removed, err := first.Sessions.DeleteExpired(testContext, base.Add(90*time.Minute)); err != nil || removed != 0 {
		t.Fatalf("renewed removed early = %d, %v | 续期会话被提前清理", removed, err)
	}
	if removed, err := first.Sessions.DeleteExpired(testContext, base.Add(2*time.Hour)); err != nil || removed != 1 {
		t.Fatalf("renewed removed = %d, %v, want 1 | 续期会话清理不符", removed, err)
	}
}

// TestSessionIndexReconciliation verifies that replacing a session moves it between TGT and user
// indexes. | TestSessionIndexReconciliation 验证替换会话会在 TGT 与用户索引之间移动。
func TestSessionIndexReconciliation(t *testing.T) {
	first, second := newPair(t)
	base := testTime(2026, time.June, 2, 0, 0, 0)
	original := sampleSession("ST-1", "TGT-1", "alice", "user-1", "https://one.example.com", base, time.Hour)
	if err := first.Sessions.Register(testContext, original); err != nil {
		t.Fatalf("register original: %v | 注册原始会话失败", err)
	}
	replacement := sampleSession("ST-1", "TGT-2", "bob", "user-2", "https://two.example.com", base.Add(time.Minute), time.Hour)
	if err := second.Sessions.Register(testContext, replacement); err != nil {
		t.Fatalf("register replacement: %v | 注册替换会话失败", err)
	}
	for _, tgt := range []string{"TGT-1"} {
		if list, err := second.Sessions.ListByTGT(testContext, tgt); err != nil || len(list) != 0 {
			t.Fatalf("old TGT index = %v, %v | 旧 TGT 索引未清理", sessionIndexes(list), err)
		}
	}
	for _, user := range []string{"alice", "user-1"} {
		if list, err := second.Sessions.ListByUser(testContext, user); err != nil || len(list) != 0 {
			t.Fatalf("old user index %q = %v, %v | 旧用户索引未清理", user, sessionIndexes(list), err)
		}
	}
	if list, err := first.Sessions.ListByTGT(testContext, "TGT-2"); err != nil || len(list) != 1 {
		t.Fatalf("new TGT index = %v, %v | 新 TGT 索引不符", sessionIndexes(list), err)
	}
	for _, user := range []string{"bob", "user-2"} {
		if list, err := first.Sessions.ListByUser(testContext, user); err != nil || len(list) != 1 {
			t.Fatalf("new user index %q = %v, %v | 新用户索引不符", user, sessionIndexes(list), err)
		}
	}

	same := sampleSession("ST-2", "", "same", "same", "https://three.example.com", base, 0)
	if err := first.Sessions.Register(testContext, same); err != nil {
		t.Fatalf("register same user: %v | 注册同名用户失败", err)
	}
	if list, err := second.Sessions.ListByUser(testContext, "same"); err != nil || len(list) != 1 {
		t.Fatalf("same user index = %v, %v | 同名用户索引不符", sessionIndexes(list), err)
	}
	unindexed := sampleSession("ST-3", "", "", "", "https://four.example.com", base, 0)
	if err := first.Sessions.Register(testContext, unindexed); err != nil {
		t.Fatalf("register unindexed: %v | 注册无索引会话失败", err)
	}
	stored, err := second.Sessions.Get(testContext, "ST-3")
	if err != nil || stored.Service != "https://four.example.com" {
		t.Fatalf("unindexed session = %#v, %v | 无索引会话不符", stored, err)
	}
}

// sessionIndexes projects session indexes for failure messages. | sessionIndexes 为失败消息投影会话索引。
func sessionIndexes(sessions []*authcas.ServiceSession) []string {
	indexes := make([]string, len(sessions))
	for i, session := range sessions {
		indexes[i] = session.SessionIndex
	}
	return indexes
}
