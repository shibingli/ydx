package redis_test

import (
	"errors"
	"fmt"
	"sync"
	"testing"
	"time"

	"github.com/shibingli/ydx/auth"
)

// sampleSession returns a fully populated session. | sampleSession 返回字段完整的会话。
func sampleSession(id, userID string, created time.Time) *auth.Session {
	revoked := created.Add(time.Hour)
	return &auth.Session{
		ID:              id,
		UserID:          userID,
		ClientID:        "client-1",
		DeviceID:        "device-1",
		IP:              "192.0.2.10",
		UserAgent:       "test-agent",
		CreatedAt:       created,
		AuthenticatedAt: created,
		UpdatedAt:       created,
		LastSeenAt:      created,
		IdleExpiresAt:   created.Add(30 * time.Minute),
		ExpiresAt:       created.Add(24 * time.Hour),
		RevokedAt:       &revoked,
		RevokeReason:    "logout",
		AMR:             []string{"pwd", "otp"},
		ACR:             "aal2",
		CSRFSecret:      "csrf-" + id,
		Data:            map[string]string{"tenant": "t1"},
	}
}

// TestSessionCreateAndGet covers creation, duplicate detection and every read path.
// | TestSessionCreateAndGet 覆盖创建、重复检测与全部读取路径。
func TestSessionCreateAndGet(t *testing.T) {
	first, second := newPair(t)
	created := testTime(2026, time.July, 1, 8, 0, 0)
	session := sampleSession("s1", "u1", created)
	if err := first.Sessions.CreateSession(testContext, session); err != nil {
		t.Fatalf("create: %v | 创建失败", err)
	}
	got, err := second.Sessions.GetSession(testContext, "s1")
	if err != nil {
		t.Fatalf("cross-instance get: %v | 跨实例读取失败", err)
	}
	if got.CSRFSecret != "csrf-s1" || got.Data["tenant"] != "t1" || len(got.AMR) != 2 {
		t.Fatalf("hidden or collection fields lost: %#v | 隐藏或集合字段丢失", got)
	}
	if got.RevokedAt == nil || !got.RevokedAt.Equal(created.Add(time.Hour)) {
		t.Fatalf("revokedAt = %v | 撤销时间不符", got.RevokedAt)
	}
	if err := second.Sessions.CreateSession(testContext, sampleSession("s1", "u2", created)); !errors.Is(err, auth.ErrConflict) {
		t.Fatalf("duplicate error = %v, want ErrConflict | 重复会话错误不符", err)
	}
	if err := first.Sessions.CreateSession(testContext, nil); !errors.Is(err, auth.ErrInvalidRequest) {
		t.Fatalf("nil error = %v | nil 会话错误不符", err)
	}
	if err := first.Sessions.CreateSession(testContext, &auth.Session{}); !errors.Is(err, auth.ErrInvalidRequest) {
		t.Fatalf("empty id error = %v | 空 ID 错误不符", err)
	}
	if _, err := first.Sessions.GetSession(testContext, "missing"); !errors.Is(err, auth.ErrSessionNotFound) {
		t.Fatalf("missing error = %v | 不存在会话错误不符", err)
	}
	all, err := first.Sessions.ListSessionsByUser(testContext, "u1")
	if err != nil || len(all) != 1 || all[0].ID != "s1" {
		t.Fatalf("list = %v, %v | 用户会话列表不符", all, err)
	}
	empty, err := first.Sessions.ListSessionsByUser(testContext, "nobody")
	if err != nil || empty == nil || len(empty) != 0 {
		t.Fatalf("empty list = %#v, %v | 空列表应为非 nil 空切片", empty, err)
	}
}

// TestSessionListOrder covers revoked inclusion and creation-time ordering with ID ties.
// | TestSessionListOrder 覆盖已撤销会话的包含与创建时间排序及 ID 并列规则。
func TestSessionListOrder(t *testing.T) {
	stores := newStores(t, "")
	base := testTime(2026, time.July, 2, 0, 0, 0)
	sessions := []*auth.Session{
		sampleSession("s2", "u1", base.Add(2*time.Hour)),
		sampleSession("s1", "u1", base.Add(1*time.Hour)),
		sampleSession("s3", "u1", base.Add(1*time.Hour)),
		sampleSession("s4", "u2", base.Add(3*time.Hour)),
	}
	sessions[0].RevokedAt = nil
	for _, session := range sessions {
		if err := stores.Sessions.CreateSession(testContext, session); err != nil {
			t.Fatalf("create %s: %v | 创建会话失败", session.ID, err)
		}
	}
	list, err := stores.Sessions.ListSessionsByUser(testContext, "u1")
	if err != nil {
		t.Fatalf("list: %v | 列表失败", err)
	}
	want := []string{"s2", "s1", "s3"}
	if len(list) != len(want) {
		t.Fatalf("len = %d | 会话数量不符", len(list))
	}
	for i, id := range want {
		if list[i].ID != id {
			t.Fatalf("order[%d] = %q, want %q | 会话排序不符", i, list[i].ID, id)
		}
	}
	if list[2].RevokedAt == nil {
		t.Fatal("revoked session was hidden | 已撤销会话被隐藏")
	}
}

// TestSessionUpdateReindexes covers the owner move, CAS success and not-found reporting.
// | TestSessionUpdateReindexes 覆盖属主迁移、CAS 成功与不存在报告。
func TestSessionUpdateReindexes(t *testing.T) {
	first, second := newPair(t)
	base := testTime(2026, time.July, 3, 0, 0, 0)
	if err := first.Sessions.CreateSession(testContext, sampleSession("s1", "u1", base)); err != nil {
		t.Fatalf("create: %v | 创建失败", err)
	}
	moved := sampleSession("s1", "u2", base)
	moved.LastSeenAt = base.Add(time.Hour)
	moved.RevokedAt = nil
	moved.Data = map[string]string{"tenant": "t2"}
	if err := second.Sessions.UpdateSession(testContext, moved); err != nil {
		t.Fatalf("update: %v | 更新失败", err)
	}
	oldList, err := first.Sessions.ListSessionsByUser(testContext, "u1")
	if err != nil || len(oldList) != 0 {
		t.Fatalf("old owner list = %v, %v | 旧属主列表未清空", oldList, err)
	}
	newList, err := first.Sessions.ListSessionsByUser(testContext, "u2")
	if err != nil || len(newList) != 1 || newList[0].Data["tenant"] != "t2" || newList[0].RevokedAt != nil {
		t.Fatalf("new owner list = %v, %v | 新属主列表不符", newList, err)
	}
	inPlace := sampleSession("s1", "u2", base)
	inPlace.RevokeReason = "rotated"
	if err := first.Sessions.UpdateSession(testContext, inPlace); err != nil {
		t.Fatalf("same-owner update: %v | 同属主更新失败", err)
	}
	got, err := second.Sessions.GetSession(testContext, "s1")
	if err != nil || got.RevokeReason != "rotated" {
		t.Fatalf("updated session = %v, %v | 更新结果不符", got, err)
	}
	missing := sampleSession("absent", "u1", base)
	if err := first.Sessions.UpdateSession(testContext, missing); !errors.Is(err, auth.ErrSessionNotFound) {
		t.Fatalf("update missing error = %v | 更新不存在会话错误不符", err)
	}
	if err := first.Sessions.UpdateSession(testContext, nil); !errors.Is(err, auth.ErrInvalidRequest) {
		t.Fatalf("update nil error = %v | 更新 nil 错误不符", err)
	}
	if err := first.Sessions.UpdateSession(testContext, &auth.Session{}); !errors.Is(err, auth.ErrInvalidRequest) {
		t.Fatalf("update empty id error = %v | 更新空 ID 错误不符", err)
	}
}

// TestSessionDelete covers single deletion, bulk deletion and not-found results.
// | TestSessionDelete 覆盖单个删除、批量删除与不存在结果。
func TestSessionDelete(t *testing.T) {
	first, second := newPair(t)
	base := testTime(2026, time.July, 4, 0, 0, 0)
	for _, session := range []*auth.Session{
		sampleSession("s1", "u1", base),
		sampleSession("s2", "u1", base.Add(time.Minute)),
		sampleSession("s3", "u2", base.Add(2*time.Minute)),
	} {
		if err := first.Sessions.CreateSession(testContext, session); err != nil {
			t.Fatalf("create %s: %v | 创建会话失败", session.ID, err)
		}
	}
	if err := second.Sessions.DeleteSession(testContext, "s2"); err != nil {
		t.Fatalf("cross-instance delete: %v | 跨实例删除失败", err)
	}
	if _, err := first.Sessions.GetSession(testContext, "s2"); !errors.Is(err, auth.ErrSessionNotFound) {
		t.Fatalf("get deleted: %v | 删除后读取错误不符", err)
	}
	if err := first.Sessions.DeleteSession(testContext, "s2"); !errors.Is(err, auth.ErrSessionNotFound) {
		t.Fatalf("delete missing: %v | 删除不存在会话错误不符", err)
	}
	removed, err := second.Sessions.DeleteSessionsByUser(testContext, "u1")
	if err != nil || removed != 1 {
		t.Fatalf("bulk removed=%d err=%v | 批量删除数量不符", removed, err)
	}
	if list, err := first.Sessions.ListSessionsByUser(testContext, "u1"); err != nil || len(list) != 0 {
		t.Fatalf("u1 list = %v, %v | u1 会话未清空", list, err)
	}
	if _, err := first.Sessions.GetSession(testContext, "s3"); err != nil {
		t.Fatalf("u2 session removed: %v | 误删其它用户会话", err)
	}
	removed, err = first.Sessions.DeleteSessionsByUser(testContext, "nobody")
	if err != nil || removed != 0 {
		t.Fatalf("empty bulk removed=%d err=%v | 空批量删除结果不符", removed, err)
	}
}

// TestSessionDeleteExpired covers absolute-deadline deletion at exact boundaries and multiple owners.
// | TestSessionDeleteExpired 覆盖绝对期限删除的精确边界与多属主。
func TestSessionDeleteExpired(t *testing.T) {
	stores := newStores(t, "")
	now := testTime(2026, time.July, 5, 12, 0, 0)
	expired := sampleSession("s-expired", "u1", now.Add(-2*time.Hour))
	expired.ExpiresAt = now.Add(-time.Second)
	exact := sampleSession("s-exact", "u1", now.Add(-time.Hour))
	exact.ExpiresAt = now
	live := sampleSession("s-live", "u1", now)
	live.ExpiresAt = now.Add(time.Second)
	noExpiry := sampleSession("s-no-expiry", "u1", now.Add(-time.Hour))
	noExpiry.ExpiresAt = time.Time{}
	noExpiry.IdleExpiresAt = now.Add(-time.Hour)
	other := sampleSession("s-other", "u2", now.Add(-time.Hour))
	other.ExpiresAt = now.Add(-time.Minute)
	for _, session := range []*auth.Session{expired, exact, live, noExpiry, other} {
		if err := stores.Sessions.CreateSession(testContext, session); err != nil {
			t.Fatalf("create %s: %v | 创建会话失败", session.ID, err)
		}
	}
	removed, err := stores.Sessions.DeleteExpiredSessions(testContext, now)
	if err != nil || removed != 3 {
		t.Fatalf("removed=%d err=%v, want 3 | 过期删除数量不符", removed, err)
	}
	for _, id := range []string{"s-expired", "s-exact", "s-other"} {
		if _, err := stores.Sessions.GetSession(testContext, id); !errors.Is(err, auth.ErrSessionNotFound) {
			t.Fatalf("%s still exists: %v | 过期会话未删除", id, err)
		}
	}
	for _, id := range []string{"s-live", "s-no-expiry"} {
		if _, err := stores.Sessions.GetSession(testContext, id); err != nil {
			t.Fatalf("%s was removed: %v | 有效会话被误删", id, err)
		}
	}
	if u1, err := stores.Sessions.ListSessionsByUser(testContext, "u1"); err != nil || len(u1) != 2 {
		t.Fatalf("u1 sessions = %v, %v | u1 剩余会话不符", u1, err)
	}
	removed, err = stores.Sessions.DeleteExpiredSessions(testContext, now)
	if err != nil || removed != 0 {
		t.Fatalf("second sweep removed=%d err=%v | 二次清理结果不符", removed, err)
	}
}

// TestSessionDeepCopy verifies deep copies and UTC normalization.
// | TestSessionDeepCopy 验证深拷贝与 UTC 规范化。
func TestSessionDeepCopy(t *testing.T) {
	stores := newStores(t, "")
	zone := time.FixedZone("UTC-7", -7*3600)
	created := time.Date(2026, time.July, 6, 9, 30, 0, 0, zone)
	session := sampleSession("s1", "u1", created)
	if err := stores.Sessions.CreateSession(testContext, session); err != nil {
		t.Fatalf("create: %v | 创建失败", err)
	}
	session.Data["tenant"] = "mutated"
	session.AMR[0] = "mutated"
	*session.RevokedAt = created.Add(99 * time.Hour)
	session.CSRFSecret = "mutated"
	got, err := stores.Sessions.GetSession(testContext, "s1")
	if err != nil {
		t.Fatalf("get: %v | 读取失败", err)
	}
	if got.Data["tenant"] != "t1" || got.AMR[0] != "pwd" || got.CSRFSecret != "csrf-s1" ||
		!got.RevokedAt.Equal(created.Add(time.Hour)) {
		t.Fatalf("input mutation leaked: %#v | 输入修改泄露到存储", got)
	}
	if got.CreatedAt.Location() != time.UTC || !got.CreatedAt.Equal(created) {
		t.Fatalf("createdAt = %v | 创建时间未规范化为 UTC", got.CreatedAt)
	}
	got.Data["tenant"] = "returned-mutation"
	got.AMR[0] = "returned-mutation"
	*got.RevokedAt = created.Add(98 * time.Hour)
	again, err := stores.Sessions.GetSession(testContext, "s1")
	if err != nil {
		t.Fatalf("get again: %v | 再次读取失败", err)
	}
	if again.Data["tenant"] != "t1" || again.AMR[0] != "pwd" || !again.RevokedAt.Equal(created.Add(time.Hour)) {
		t.Fatalf("returned mutation persisted: %#v | 返回值修改影响了存储", again)
	}
}

// TestSessionConcurrentCreate verifies exactly one creator wins for a duplicate session ID.
// | TestSessionConcurrentCreate 验证重复会话 ID 并发创建时恰好一个成功。
func TestSessionConcurrentCreate(t *testing.T) {
	first, second := newPair(t)
	const workers = 12
	base := testTime(2026, time.July, 7, 0, 0, 0)
	errsCh := make(chan error, workers)
	var wg sync.WaitGroup
	for i := 0; i < workers; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			stores := first
			if i%2 == 1 {
				stores = second
			}
			errsCh <- stores.Sessions.CreateSession(testContext, sampleSession("same", fmt.Sprintf("u%d", i), base))
		}(i)
	}
	wg.Wait()
	close(errsCh)
	successes := 0
	conflicts := 0
	for err := range errsCh {
		switch {
		case err == nil:
			successes++
		case errors.Is(err, auth.ErrConflict):
			conflicts++
		default:
			t.Fatalf("unexpected error: %v | 意外错误", err)
		}
	}
	if successes != 1 || conflicts != workers-1 {
		t.Fatalf("successes=%d conflicts=%d | 并发会话创建结果不符", successes, conflicts)
	}
}
