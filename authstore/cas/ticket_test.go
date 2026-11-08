package cas_test

import (
	"errors"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	authcas "github.com/shibingli/ydx/auth/protocol/cas"
)

// TestTicketLifecycleAllTypes stores each ticket class and exercises Get, Consume and Delete across
// two store sets that model two application instances. | TestTicketLifecycleAllTypes 保存每种票据
// 类别，并通过模拟两个应用实例的两套存储验证 Get、Consume 与 Delete。
func TestTicketLifecycleAllTypes(t *testing.T) {
	first, second := newPair(t)
	base := testTime(2026, time.March, 1, 12, 0, 0)
	types := []authcas.TicketType{authcas.TicketTGT, authcas.TicketST, authcas.TicketPGT, authcas.TicketPT}
	for i, typ := range types {
		issued := base.Add(time.Duration(i) * time.Minute)
		ticket := sampleTicket(string(typ)+"-1", typ, "user-1", "https://svc.example.com", string(typ)+"-1", issued, time.Hour)
		if err := first.Tickets.Save(testContext, ticket); err != nil {
			t.Fatalf("save %s: %v | 保存失败", typ, err)
		}
		stored, err := second.Tickets.Get(testContext, ticket.ID)
		if err != nil {
			t.Fatalf("get %s: %v | 查询失败", typ, err)
		}
		if stored.Type != typ || stored.UserID != "user-1" || stored.Service != "https://svc.example.com" {
			t.Fatalf("stored %s = %#v | 已存票据不符", typ, stored)
		}
		if stored.Principal == nil || stored.Principal.Subject != "user-1" {
			t.Fatalf("stored %s lost its principal | 已存票据丢失主体", typ)
		}
		if stored.Principal.Attributes["tenant"] != "t1" || len(stored.ProxyChain) != 1 {
			t.Fatalf("stored %s lost slices or maps | 已存票据丢失切片或映射", typ)
		}
		now := issued.Add(30 * time.Second)
		consumed, err := second.Tickets.Consume(testContext, ticket.ID, typ, now)
		if err != nil {
			t.Fatalf("consume %s: %v | 消费失败", typ, err)
		}
		if consumed.ConsumedAt.IsZero() || !consumed.ConsumedAt.Equal(now) {
			t.Fatalf("consumed %s at %v, want %v | 消费时间不符", typ, consumed.ConsumedAt, now)
		}
		if _, err := first.Tickets.Consume(testContext, ticket.ID, typ, now); !errors.Is(err, authcas.ErrTicketUsed) {
			t.Fatalf("second consume %s error = %v, want ErrTicketUsed | 二次消费错误不符", typ, err)
		}
		after, err := first.Tickets.Get(testContext, ticket.ID)
		if err != nil {
			t.Fatalf("get consumed %s: %v | 查询已消费票据失败", typ, err)
		}
		if !after.ConsumedAt.Equal(now) {
			t.Fatalf("stored ConsumedAt = %v, want %v | 已存消费时间不符", after.ConsumedAt, now)
		}
		if err := first.Tickets.Delete(testContext, ticket.ID); err != nil {
			t.Fatalf("delete %s: %v | 删除失败", typ, err)
		}
		if _, err := second.Tickets.Get(testContext, ticket.ID); !errors.Is(err, authcas.ErrTicketNotFound) {
			t.Fatalf("get after delete %s error = %v, want ErrTicketNotFound | 删除后查询错误不符", typ, err)
		}
	}
	if _, err := first.Tickets.Get(testContext, ""); !errors.Is(err, authcas.ErrTicketNotFound) {
		t.Fatalf("empty id error = %v, want ErrTicketNotFound | 空标识错误不符", err)
	}
	if _, err := first.Tickets.Get(testContext, "unknown"); !errors.Is(err, authcas.ErrTicketNotFound) {
		t.Fatalf("unknown id error = %v, want ErrTicketNotFound | 未知标识错误不符", err)
	}
	if err := first.Tickets.Delete(testContext, "unknown"); err != nil {
		t.Fatalf("delete absent: %v | 删除不存在票据失败", err)
	}
	if err := first.Tickets.Delete(testContext, ""); err != nil {
		t.Fatalf("delete empty: %v | 删除空标识失败", err)
	}
}

// TestTicketConsumeValidation covers type mismatch, expiry and prior consumption.
// | TestTicketConsumeValidation 覆盖类型不符、过期与已消费。
func TestTicketConsumeValidation(t *testing.T) {
	stores := newStores(t, "")
	base := testTime(2026, time.April, 1, 0, 0, 0)
	ticket := sampleTicket("ST-1", authcas.TicketST, "u1", "https://svc.example.com", "TGT-1", base, time.Hour)
	if err := stores.Tickets.Save(testContext, ticket); err != nil {
		t.Fatalf("save: %v | 保存失败", err)
	}
	if _, err := stores.Tickets.Consume(testContext, "ST-1", authcas.TicketPT, base.Add(time.Minute)); !errors.Is(err, authcas.ErrTicketTypeMismatch) {
		t.Fatalf("mismatch error = %v, want ErrTicketTypeMismatch | 类型不符错误不符", err)
	}
	if _, err := stores.Tickets.Consume(testContext, "ST-1", "", base.Add(time.Minute)); err != nil {
		t.Fatalf("empty type should accept: %v | 空类型应接受", err)
	}
	if _, err := stores.Tickets.Consume(testContext, "missing", authcas.TicketST, base); !errors.Is(err, authcas.ErrTicketNotFound) {
		t.Fatalf("missing error = %v, want ErrTicketNotFound | 不存在错误不符", err)
	}

	expired := sampleTicket("ST-2", authcas.TicketST, "u1", "https://svc.example.com", "TGT-1", base, time.Minute)
	if err := stores.Tickets.Save(testContext, expired); err != nil {
		t.Fatalf("save expired: %v | 保存过期票据失败", err)
	}
	if _, err := stores.Tickets.Consume(testContext, "ST-2", authcas.TicketST, base.Add(time.Minute)); !errors.Is(err, authcas.ErrTicketExpired) {
		t.Fatalf("boundary error = %v, want ErrTicketExpired | 边界消费错误不符", err)
	}
	if _, err := stores.Tickets.Get(testContext, "ST-2"); err != nil {
		t.Fatalf("expired record should remain: %v | 过期记录应保留", err)
	}

	noDeadline := sampleTicket("ST-3", authcas.TicketST, "u1", "https://svc.example.com", "TGT-1", base, time.Hour)
	noDeadline.ExpiresAt = time.Time{}
	if err := stores.Tickets.Save(testContext, noDeadline); err != nil {
		t.Fatalf("save no deadline: %v | 保存零期限票据失败", err)
	}
	if _, err := stores.Tickets.Consume(testContext, "ST-3", authcas.TicketST, base); !errors.Is(err, authcas.ErrTicketExpired) {
		t.Fatalf("zero deadline error = %v, want ErrTicketExpired | 零期限错误不符", err)
	}

	used := sampleTicket("ST-4", authcas.TicketST, "u1", "https://svc.example.com", "TGT-1", base, time.Hour)
	used.ConsumedAt = base.Add(time.Second)
	if err := stores.Tickets.Save(testContext, used); err != nil {
		t.Fatalf("save consumed: %v | 保存已消费票据失败", err)
	}
	stored, err := stores.Tickets.Get(testContext, "ST-4")
	if err != nil {
		t.Fatalf("get consumed: %v | 查询已消费票据失败", err)
	}
	if !stored.Consumed() || !stored.ConsumedAt.Equal(base.Add(time.Second)) {
		t.Fatalf("consumed state = %v | 已消费状态不符", stored.ConsumedAt)
	}
	if _, err := stores.Tickets.Consume(testContext, "ST-4", authcas.TicketST, base.Add(2*time.Second)); !errors.Is(err, authcas.ErrTicketUsed) {
		t.Fatalf("stored consumed error = %v, want ErrTicketUsed | 已存消费状态错误不符", err)
	}
}

// TestTicketConsumeExactlyOnce fails unless concurrent consumers on two instances produce exactly one
// winner. | TestTicketConsumeExactlyOnce 要求两个实例上的并发消费者恰好产生一个成功者。
func TestTicketConsumeExactlyOnce(t *testing.T) {
	first, second := newPair(t)
	base := testTime(2026, time.May, 1, 0, 0, 0)
	if err := first.Tickets.Save(testContext, sampleTicket("ST-race", authcas.TicketST, "u1", "https://svc.example.com", "TGT-1", base, time.Hour)); err != nil {
		t.Fatalf("save: %v | 保存失败", err)
	}
	const workers = 48
	now := base.Add(time.Minute)
	errCh := make(chan error, workers)
	var wins atomic.Int64
	var wait sync.WaitGroup
	wait.Add(workers)
	for i := 0; i < workers; i++ {
		stores := first
		if i%2 == 1 {
			stores = second
		}
		go func() {
			defer wait.Done()
			if _, err := stores.Tickets.Consume(testContext, "ST-race", authcas.TicketST, now); err != nil {
				errCh <- err
				return
			}
			wins.Add(1)
		}()
	}
	wait.Wait()
	close(errCh)
	if wins.Load() != 1 {
		t.Fatalf("winners = %d, want 1 | 成功次数不符", wins.Load())
	}
	for err := range errCh {
		if !errors.Is(err, authcas.ErrTicketUsed) {
			t.Fatalf("loser error = %v, want ErrTicketUsed | 失败者错误不符", err)
		}
	}
	stored, err := second.Tickets.Get(testContext, "ST-race")
	if err != nil {
		t.Fatalf("get after race: %v | 竞争后查询失败", err)
	}
	if !stored.ConsumedAt.Equal(now) {
		t.Fatalf("ConsumedAt = %v, want %v | 竞争后消费时间不符", stored.ConsumedAt, now)
	}
}

// TestTicketIndexesAndBulkDelete verifies service, root and user indexes plus the bulk deletes.
// | TestTicketIndexesAndBulkDelete 验证服务、根与用户索引以及批量删除。
func TestTicketIndexesAndBulkDelete(t *testing.T) {
	first, second := newPair(t)
	base := testTime(2026, time.June, 1, 0, 0, 0)
	tgt := sampleTicket("TGT-1", authcas.TicketTGT, "u1", "", "TGT-1", base, time.Hour)
	st := sampleTicket("ST-1", authcas.TicketST, "u1", "https://app.example.com", "TGT-1", base.Add(time.Minute), time.Hour)
	pgt := sampleTicket("PGT-1", authcas.TicketPGT, "u1", "https://proxy.example.com/pgt", "TGT-1", base.Add(2*time.Minute), time.Hour)
	pt := sampleTicket("PT-1", authcas.TicketPT, "u1", "https://backend.example.com", "TGT-1", base.Add(3*time.Minute), time.Hour)
	other := sampleTicket("ST-2", authcas.TicketST, "u2", "https://app.example.com", "TGT-2", base.Add(4*time.Minute), time.Hour)
	for _, ticket := range []*authcas.Ticket{tgt, st, pgt, pt, other} {
		if err := first.Tickets.Save(testContext, ticket); err != nil {
			t.Fatalf("save %s: %v | 保存失败", ticket.ID, err)
		}
	}

	byService, err := second.Tickets.ListByService(testContext, "https://app.example.com")
	if err != nil {
		t.Fatalf("list service: %v | 按服务查询失败", err)
	}
	if len(byService) != 2 || byService[0].ID != "ST-1" || byService[1].ID != "ST-2" {
		t.Fatalf("by service = %v | 按服务结果不符", ticketIDs(byService))
	}
	byRoot, err := second.Tickets.ListByRootTGT(testContext, "TGT-1")
	if err != nil {
		t.Fatalf("list root: %v | 按根查询失败", err)
	}
	if len(byRoot) != 4 || byRoot[0].ID != "TGT-1" || byRoot[3].ID != "PT-1" {
		t.Fatalf("by root = %v | 按根结果不符", ticketIDs(byRoot))
	}
	if got, err := second.Tickets.ListByService(testContext, "https://none.example.com"); err != nil || len(got) != 0 {
		t.Fatalf("empty service = %v, %v | 空服务结果不符", ticketIDs(got), err)
	}
	if got, err := second.Tickets.ListByRootTGT(testContext, "TGT-unknown"); err != nil || len(got) != 0 {
		t.Fatalf("unknown root = %v, %v | 未知根结果不符", ticketIDs(got), err)
	}

	if err := second.Tickets.Delete(testContext, "ST-1"); err != nil {
		t.Fatalf("delete ST: %v | 删除服务票据失败", err)
	}
	if err := second.Tickets.Delete(testContext, "ST-1"); err != nil {
		t.Fatalf("delete ST twice: %v | 二次删除失败", err)
	}
	byRoot, err = second.Tickets.ListByRootTGT(testContext, "TGT-1")
	if err != nil || len(byRoot) != 3 {
		t.Fatalf("after delete root = %v, %v | 删除后按根结果不符", ticketIDs(byRoot), err)
	}
	removed, err := second.Tickets.DeleteByRootTGT(testContext, "TGT-1")
	if err != nil {
		t.Fatalf("delete root: %v | 按根删除失败", err)
	}
	if removed != 3 {
		t.Fatalf("delete root removed = %d, want 3 | 按根删除数量不符", removed)
	}
	if got, err := first.Tickets.ListByRootTGT(testContext, "TGT-1"); err != nil || len(got) != 0 {
		t.Fatalf("root after bulk delete = %v, %v | 批量删除后按根结果不符", ticketIDs(got), err)
	}
	if _, err := first.Tickets.Get(testContext, "TGT-1"); !errors.Is(err, authcas.ErrTicketNotFound) {
		t.Fatalf("TGT after bulk delete error = %v | 批量删除后 TGT 仍存在", err)
	}
	if remaining, err := second.Tickets.DeleteByUser(testContext, "u2"); err != nil || remaining != 1 {
		t.Fatalf("delete user = %d, %v, want 1 | 按用户删除数量不符", remaining, err)
	}
	if remaining, err := second.Tickets.DeleteByRootTGT(testContext, ""); err != nil || remaining != 0 {
		t.Fatalf("delete empty root = %d, %v | 空根删除不符", remaining, err)
	}
	if remaining, err := second.Tickets.DeleteByUser(testContext, ""); err != nil || remaining != 0 {
		t.Fatalf("delete empty user = %d, %v | 空用户删除不符", remaining, err)
	}
}

// TestTicketDeleteExpired verifies deadline-selective cleanup and index removal.
// | TestTicketDeleteExpired 验证按期限清理以及索引移除。
func TestTicketDeleteExpired(t *testing.T) {
	first, second := newPair(t)
	base := testTime(2026, time.July, 1, 0, 0, 0)
	active := sampleTicket("ST-active", authcas.TicketST, "u1", "https://svc.example.com", "TGT-1", base, 2*time.Hour)
	boundary := sampleTicket("ST-boundary", authcas.TicketST, "u1", "https://svc.example.com", "TGT-1", base, time.Hour)
	noDeadline := sampleTicket("ST-zero", authcas.TicketST, "u1", "https://svc.example.com", "TGT-1", base, time.Hour)
	noDeadline.ExpiresAt = time.Time{}
	consumed := sampleTicket("ST-consumed", authcas.TicketST, "u1", "https://svc.example.com", "TGT-1", base, 3*time.Hour)
	consumed.ConsumedAt = base.Add(time.Minute)
	for _, ticket := range []*authcas.Ticket{active, boundary, noDeadline, consumed} {
		if err := first.Tickets.Save(testContext, ticket); err != nil {
			t.Fatalf("save %s: %v | 保存失败", ticket.ID, err)
		}
	}
	now := base.Add(time.Hour)
	removed, err := second.Tickets.DeleteExpired(testContext, now)
	if err != nil {
		t.Fatalf("delete expired: %v | 清理过期失败", err)
	}
	if removed != 2 {
		t.Fatalf("removed = %d, want 2 | 清理数量不符", removed)
	}
	for _, id := range []string{"ST-boundary", "ST-zero"} {
		if _, err := second.Tickets.Get(testContext, id); !errors.Is(err, authcas.ErrTicketNotFound) {
			t.Fatalf("%s should be gone: %v | 过期票据仍存在", id, err)
		}
	}
	for _, id := range []string{"ST-active", "ST-consumed"} {
		if _, err := second.Tickets.Get(testContext, id); err != nil {
			t.Fatalf("%s should remain: %v | 未过期票据被误删", id, err)
		}
	}
	if list, err := second.Tickets.ListByService(testContext, "https://svc.example.com"); err != nil || len(list) != 2 {
		t.Fatalf("service index after cleanup = %v, %v | 清理后服务索引不符", ticketIDs(list), err)
	}
}

// TestTicketSaveReconcilesIndexes verifies that replacing a record moves it between index sets and
// updates the consumable type. | TestTicketSaveReconcilesIndexes 验证替换记录会移动索引集合并更新可
// 消费类型。
func TestTicketSaveReconcilesIndexes(t *testing.T) {
	first, second := newPair(t)
	base := testTime(2026, time.August, 1, 0, 0, 0)
	original := sampleTicket("ST-1", authcas.TicketST, "u1", "https://one.example.com", "TGT-1", base, time.Hour)
	if err := first.Tickets.Save(testContext, original); err != nil {
		t.Fatalf("save original: %v | 保存原始票据失败", err)
	}
	replacement := sampleTicket("ST-1", authcas.TicketPT, "u2", "https://two.example.com", "TGT-2", base.Add(time.Minute), time.Hour)
	if err := second.Tickets.Save(testContext, replacement); err != nil {
		t.Fatalf("save replacement: %v | 保存替换票据失败", err)
	}
	if list, err := second.Tickets.ListByService(testContext, "https://one.example.com"); err != nil || len(list) != 0 {
		t.Fatalf("old service index = %v, %v | 旧服务索引未清理", ticketIDs(list), err)
	}
	if list, err := second.Tickets.ListByRootTGT(testContext, "TGT-1"); err != nil || len(list) != 0 {
		t.Fatalf("old root index = %v, %v | 旧根索引未清理", ticketIDs(list), err)
	}
	if list, err := first.Tickets.ListByService(testContext, "https://two.example.com"); err != nil || len(list) != 1 || list[0].UserID != "u2" {
		t.Fatalf("new service index = %v, %v | 新服务索引不符", ticketIDs(list), err)
	}
	if _, err := first.Tickets.Consume(testContext, "ST-1", authcas.TicketST, base.Add(2*time.Minute)); !errors.Is(err, authcas.ErrTicketTypeMismatch) {
		t.Fatalf("old type error = %v, want ErrTicketTypeMismatch | 旧类型错误不符", err)
	}
	if _, err := first.Tickets.Consume(testContext, "ST-1", authcas.TicketPT, base.Add(2*time.Minute)); err != nil {
		t.Fatalf("new type consume: %v | 新类型消费失败", err)
	}
}

// TestTicketSaveValidation rejects nil and identifier-less tickets.
// | TestTicketSaveValidation 拒绝空票据与缺少标识的票据。
func TestTicketSaveValidation(t *testing.T) {
	stores := newStores(t, "")
	if err := stores.Tickets.Save(testContext, nil); !errors.Is(err, authcas.ErrInvalidRequest) {
		t.Fatalf("nil save error = %v, want ErrInvalidRequest | 空票据保存错误不符", err)
	}
	if err := stores.Tickets.Save(testContext, &authcas.Ticket{Type: authcas.TicketST}); !errors.Is(err, authcas.ErrInvalidRequest) {
		t.Fatalf("empty id save error = %v, want ErrInvalidRequest | 空标识保存错误不符", err)
	}
}

// TestTicketDeepCopy verifies that stored records never alias caller memory.
// | TestTicketDeepCopy 验证已存记录绝不别名调用方内存。
func TestTicketDeepCopy(t *testing.T) {
	stores := newStores(t, "")
	base := testTime(2026, time.September, 1, 0, 0, 0)
	ticket := sampleTicket("ST-1", authcas.TicketST, "u1", "https://svc.example.com", "TGT-1", base, time.Hour)
	if err := stores.Tickets.Save(testContext, ticket); err != nil {
		t.Fatalf("save: %v | 保存失败", err)
	}
	ticket.ProxyChain[0] = "mutated"
	ticket.Principal.Attributes["tenant"] = "mutated"
	ticket.Principal.Roles[0] = "mutated"
	ticket.ExpiresAt = base.Add(100 * time.Hour)
	stored, err := stores.Tickets.Get(testContext, "ST-1")
	if err != nil {
		t.Fatalf("get: %v | 查询失败", err)
	}
	if stored.ProxyChain[0] != "https://proxy.example.com/callback" ||
		stored.Principal.Attributes["tenant"] != "t1" ||
		stored.Principal.Roles[0] != "admin" ||
		!stored.ExpiresAt.Equal(base.Add(time.Hour)) {
		t.Fatalf("stored record aliased caller memory: %#v | 已存记录别名了调用方内存", stored)
	}
	stored.Principal.Attributes["tenant"] = "changed"
	stored.Principal.Roles[0] = "changed"
	stored.ProxyChain[0] = "changed"
	stored.UserID = "changed"
	again, err := stores.Tickets.Get(testContext, "ST-1")
	if err != nil {
		t.Fatalf("get again: %v | 再次查询失败", err)
	}
	if again.UserID != "u1" || again.Principal.Attributes["tenant"] != "t1" ||
		again.Principal.Roles[0] != "admin" || again.ProxyChain[0] != "https://proxy.example.com/callback" {
		t.Fatalf("returned copy aliased stored memory: %#v | 返回副本别名了已存内存", again)
	}
	consumed, err := stores.Tickets.Consume(testContext, "ST-1", authcas.TicketST, base.Add(time.Minute))
	if err != nil {
		t.Fatalf("consume: %v | 消费失败", err)
	}
	consumed.Principal.Roles[0] = "changed"
	after, err := stores.Tickets.Get(testContext, "ST-1")
	if err != nil {
		t.Fatalf("get consumed: %v | 查询已消费票据失败", err)
	}
	if after.Principal.Roles[0] != "admin" {
		t.Fatalf("consumed copy aliased stored memory | 消费副本别名了已存内存")
	}
}

// TestTicketUTC verifies that stored and returned times are normalized to UTC.
// | TestTicketUTC 验证存取时间规范化为 UTC。
func TestTicketUTC(t *testing.T) {
	stores := newStores(t, "")
	zone := time.FixedZone("CST", 8*3600)
	issued := time.Date(2026, time.October, 1, 8, 30, 0, 123456789, zone)
	ticket := sampleTicket("ST-1", authcas.TicketST, "u1", "https://svc.example.com", "TGT-1", issued, time.Hour)
	if err := stores.Tickets.Save(testContext, ticket); err != nil {
		t.Fatalf("save: %v | 保存失败", err)
	}
	stored, err := stores.Tickets.Get(testContext, "ST-1")
	if err != nil {
		t.Fatalf("get: %v | 查询失败", err)
	}
	if stored.IssuedAt.Location() != time.UTC || !stored.IssuedAt.Equal(issued) {
		t.Fatalf("IssuedAt = %v | 签发时间未规范化为 UTC", stored.IssuedAt)
	}
	if stored.ExpiresAt.Location() != time.UTC {
		t.Fatalf("ExpiresAt zone = %v | 期限未规范化为 UTC", stored.ExpiresAt.Location())
	}
	if stored.Principal.AuthTime.Location() != time.UTC || !stored.Principal.AuthTime.Equal(issued) {
		t.Fatalf("Principal.AuthTime = %v | 主体认证时间未规范化为 UTC", stored.Principal.AuthTime)
	}
	now := issued.Add(time.Minute)
	consumed, err := stores.Tickets.Consume(testContext, "ST-1", authcas.TicketST, now)
	if err != nil {
		t.Fatalf("consume: %v | 消费失败", err)
	}
	if consumed.ConsumedAt.Location() != time.UTC || !consumed.ConsumedAt.Equal(now) {
		t.Fatalf("ConsumedAt = %v | 消费时间未规范化为 UTC", consumed.ConsumedAt)
	}
}

// TestTicketListOrdering verifies deterministic ordering by issue time and identifier.
// | TestTicketListOrdering 验证按签发时间与标识的确定性排序。
func TestTicketListOrdering(t *testing.T) {
	stores := newStores(t, "")
	base := testTime(2026, time.November, 1, 0, 0, 0)
	order := []string{"ST-d", "ST-b", "ST-a", "ST-c"}
	times := map[string]time.Duration{
		"ST-a": 0,
		"ST-b": 0,
		"ST-c": time.Minute,
		"ST-d": 2 * time.Minute,
	}
	for _, id := range order {
		ticket := sampleTicket(id, authcas.TicketST, "u1", "https://svc.example.com", "TGT-1", base.Add(times[id]), time.Hour)
		if err := stores.Tickets.Save(testContext, ticket); err != nil {
			t.Fatalf("save %s: %v | 保存失败", id, err)
		}
	}
	list, err := stores.Tickets.ListByService(testContext, "https://svc.example.com")
	if err != nil {
		t.Fatalf("list: %v | 查询失败", err)
	}
	want := []string{"ST-a", "ST-b", "ST-c", "ST-d"}
	got := ticketIDs(list)
	if len(got) != len(want) {
		t.Fatalf("ids = %v, want %v | 排序结果不符", got, want)
	}
	for i := range want {
		if got[i] != want[i] {
			t.Fatalf("ids = %v, want %v | 排序结果不符", got, want)
		}
	}
}

// ticketIDs projects ticket identifiers for failure messages. | ticketIDs 为失败消息投影票据标识。
func ticketIDs(tickets []*authcas.Ticket) []string {
	ids := make([]string, len(tickets))
	for i, ticket := range tickets {
		ids[i] = ticket.ID
	}
	return ids
}
