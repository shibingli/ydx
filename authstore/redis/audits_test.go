package redis_test

import (
	"errors"
	"fmt"
	"sync"
	"testing"
	"time"

	"github.com/shibingli/ydx/auth"
	authredis "github.com/shibingli/ydx/authstore/redis"
)

// sampleAudit returns one audit event. | sampleAudit 返回单个审计事件。
func sampleAudit(id, typ, userID, actorID, outcome string, at time.Time) *auth.AuditEvent {
	return &auth.AuditEvent{
		ID:        id,
		Type:      typ,
		ActorID:   actorID,
		UserID:    userID,
		SessionID: "session-" + id,
		ClientID:  "client-1",
		IP:        "192.0.2.20",
		UserAgent: "test-agent",
		Outcome:   outcome,
		Detail:    map[string]string{"reason": outcome},
		At:        at,
	}
}

// auditFixture appends a fixed event set for the listing tests. | auditFixture 为列表测试追加固定事件集。
func auditFixture(t *testing.T, stores *authredis.Stores) []*auth.AuditEvent {
	t.Helper()
	base := testTime(2026, time.October, 1, 0, 0, 0)
	events := []*auth.AuditEvent{
		sampleAudit("e1", "login.succeeded", "u1", "a1", "success", base.Add(1*time.Hour)),
		sampleAudit("e2", "login.failed", "u1", "a2", "failure", base.Add(2*time.Hour)),
		sampleAudit("e6", "login.succeeded", "u3", "a1", "success", base.Add(2*time.Hour)),
		sampleAudit("e3", "login.succeeded", "u2", "a1", "success", base.Add(3*time.Hour)),
		sampleAudit("e4", "logout", "u2", "u2", "success", base.Add(4*time.Hour)),
		sampleAudit("e5", "login.succeeded", "u1", "a1", "denied", base.Add(5*time.Hour)),
	}
	for _, event := range events {
		if err := stores.Audits.RecordAudit(testContext, event); err != nil {
			t.Fatalf("record %s: %v | 追加审计失败", event.ID, err)
		}
	}
	return events
}

// TestAuditRecordAndList covers append, ordering, duplicates and total.
// | TestAuditRecordAndList 覆盖追加、排序、重复与总数。
func TestAuditRecordAndList(t *testing.T) {
	first, second := newPair(t)
	auditFixture(t, first)
	events, total, err := second.Audits.ListAudit(testContext, auth.AuditQuery{})
	if err != nil {
		t.Fatalf("list: %v | 列表失败", err)
	}
	want := []string{"e1", "e2", "e6", "e3", "e4", "e5"}
	if total != len(want) || len(events) != len(want) {
		t.Fatalf("total=%d len=%d | 总数或长度不符", total, len(events))
	}
	for i, id := range want {
		if events[i].ID != id {
			t.Fatalf("order[%d] = %q, want %q | 审计排序不符", i, events[i].ID, id)
		}
	}
	if events[0].Detail["reason"] != "success" || events[0].SessionID != "session-e1" {
		t.Fatalf("audit fields lost: %#v | 审计字段丢失", events[0])
	}
	if err := first.Audits.RecordAudit(testContext, nil); !errors.Is(err, auth.ErrInvalidRequest) {
		t.Fatalf("nil event error = %v | nil 事件错误不符", err)
	}
}

// TestAuditDuplicateID verifies append-only behavior for a repeated event ID.
// | TestAuditDuplicateID 验证重复事件 ID 的只追加行为。
func TestAuditDuplicateID(t *testing.T) {
	stores := newStores(t, "")
	first := sampleAudit("same", "login.failed", "u1", "a1", "failure", testTime(2026, time.October, 2, 0, 0, 0))
	second := sampleAudit("same", "login.failed", "u1", "a1", "failure", testTime(2026, time.October, 2, 1, 0, 0))
	if err := stores.Audits.RecordAudit(testContext, first); err != nil {
		t.Fatalf("record first: %v | 追加第一条失败", err)
	}
	if err := stores.Audits.RecordAudit(testContext, second); err != nil {
		t.Fatalf("record second: %v | 追加第二条失败", err)
	}
	events, total, err := stores.Audits.ListAudit(testContext, auth.AuditQuery{})
	if err != nil || total != 2 || len(events) != 2 {
		t.Fatalf("total=%d len=%d err=%v | 重复 ID 未保留两条", total, len(events), err)
	}
	if !events[0].At.Before(events[1].At) {
		t.Fatalf("order = %v | 重复 ID 事件排序不符", events)
	}
}

// TestAuditFilters covers every filter and the inclusive time bounds.
// | TestAuditFilters 覆盖全部过滤器与包含式时间边界。
func TestAuditFilters(t *testing.T) {
	stores := newStores(t, "")
	auditFixture(t, stores)
	base := testTime(2026, time.October, 1, 0, 0, 0)
	cases := []struct {
		name  string
		query auth.AuditQuery
		want  []string
	}{
		{"type", auth.AuditQuery{Type: "login.succeeded"}, []string{"e1", "e6", "e3", "e5"}},
		{"user", auth.AuditQuery{UserID: "u1"}, []string{"e1", "e2", "e5"}},
		{"actor", auth.AuditQuery{ActorID: "a1"}, []string{"e1", "e6", "e3", "e5"}},
		{"outcome", auth.AuditQuery{Outcome: "success"}, []string{"e1", "e6", "e3", "e4"}},
		{"since inclusive", auth.AuditQuery{Since: base.Add(2 * time.Hour)}, []string{"e2", "e6", "e3", "e4", "e5"}},
		{"until inclusive", auth.AuditQuery{Until: base.Add(3 * time.Hour)}, []string{"e1", "e2", "e6", "e3"}},
		{"window", auth.AuditQuery{Since: base.Add(2 * time.Hour), Until: base.Add(3 * time.Hour)}, []string{"e2", "e6", "e3"}},
		{"combined", auth.AuditQuery{Type: "login.succeeded", UserID: "u1", ActorID: "a1", Outcome: "success"}, []string{"e1"}},
		{"none", auth.AuditQuery{Type: "missing"}, []string{}},
	}
	for _, tc := range cases {
		events, total, err := stores.Audits.ListAudit(testContext, tc.query)
		if err != nil {
			t.Fatalf("%s: %v | 过滤失败", tc.name, err)
		}
		if total != len(tc.want) || len(events) != len(tc.want) {
			t.Fatalf("%s total=%d len=%d want=%v | 过滤数量不符", tc.name, total, len(events), tc.want)
		}
		for i, id := range tc.want {
			if events[i].ID != id {
				t.Fatalf("%s[%d] = %q, want %q | 过滤结果不符", tc.name, i, events[i].ID, id)
			}
		}
	}
}

// TestAuditPagination covers ascending and descending pages with totals.
// | TestAuditPagination 覆盖升序与降序分页及总数。
func TestAuditPagination(t *testing.T) {
	stores := newStores(t, "")
	auditFixture(t, stores)
	asc, total, err := stores.Audits.ListAudit(testContext, auth.AuditQuery{Offset: 1, Limit: 2})
	if err != nil || total != 6 || len(asc) != 2 || asc[0].ID != "e2" || asc[1].ID != "e6" {
		t.Fatalf("asc page = %v total=%d err=%v | 升序分页不符", auditIDs(asc), total, err)
	}
	desc, total, err := stores.Audits.ListAudit(testContext, auth.AuditQuery{Descending: true})
	if err != nil || total != 6 || len(desc) != 6 {
		t.Fatalf("desc all = %v total=%d err=%v | 降序全量不符", auditIDs(desc), total, err)
	}
	wantDesc := []string{"e5", "e4", "e3", "e6", "e2", "e1"}
	for i, id := range wantDesc {
		if desc[i].ID != id {
			t.Fatalf("desc[%d] = %q, want %q | 降序排序不符", i, desc[i].ID, id)
		}
	}
	descPage, total, err := stores.Audits.ListAudit(testContext, auth.AuditQuery{Descending: true, Offset: 1, Limit: 2})
	if err != nil || total != 6 || len(descPage) != 2 || descPage[0].ID != "e4" || descPage[1].ID != "e3" {
		t.Fatalf("desc page = %v total=%d err=%v | 降序分页不符", auditIDs(descPage), total, err)
	}
	out, total, err := stores.Audits.ListAudit(testContext, auth.AuditQuery{Offset: 99, Limit: 2})
	if err != nil || total != 6 || len(out) != 0 {
		t.Fatalf("out-of-range = %v total=%d err=%v | 越界分页不符", auditIDs(out), total, err)
	}
	unlimited, total, err := stores.Audits.ListAudit(testContext, auth.AuditQuery{Offset: 4, Limit: 0})
	if err != nil || total != 6 || len(unlimited) != 2 || unlimited[0].ID != "e4" {
		t.Fatalf("unlimited = %v total=%d err=%v | 无上限分页不符", auditIDs(unlimited), total, err)
	}
}

// TestAuditDeepCopy verifies detail isolation and UTC normalization.
// | TestAuditDeepCopy 验证明细隔离与 UTC 规范化。
func TestAuditDeepCopy(t *testing.T) {
	stores := newStores(t, "")
	zone := time.FixedZone("UTC+2", 2*3600)
	at := time.Date(2026, time.October, 3, 10, 0, 0, 0, zone)
	event := sampleAudit("e1", "login.succeeded", "u1", "a1", "success", at)
	if err := stores.Audits.RecordAudit(testContext, event); err != nil {
		t.Fatalf("record: %v | 追加失败", err)
	}
	event.Detail["reason"] = "mutated"
	event.UserAgent = "mutated"
	events, _, err := stores.Audits.ListAudit(testContext, auth.AuditQuery{})
	if err != nil || len(events) != 1 {
		t.Fatalf("list = %v, %v | 列表失败", events, err)
	}
	if events[0].Detail["reason"] != "success" || events[0].UserAgent != "test-agent" {
		t.Fatalf("input mutation leaked: %#v | 输入修改泄露到存储", events[0])
	}
	if events[0].At.Location() != time.UTC || !events[0].At.Equal(at) {
		t.Fatalf("at = %v | 事件时间未规范化为 UTC", events[0].At)
	}
	events[0].Detail["reason"] = "returned-mutation"
	again, _, err := stores.Audits.ListAudit(testContext, auth.AuditQuery{})
	if err != nil || again[0].Detail["reason"] != "success" {
		t.Fatalf("returned mutation persisted: %v, %v | 返回值修改影响了存储", again, err)
	}
}

// TestAuditConcurrentAppend verifies that no event is lost under concurrent appends.
// | TestAuditConcurrentAppend 验证并发追加不丢失任何事件。
func TestAuditConcurrentAppend(t *testing.T) {
	first, second := newPair(t)
	const workers = 32
	base := testTime(2026, time.October, 4, 0, 0, 0)
	var wg sync.WaitGroup
	for i := 0; i < workers; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			stores := first
			if i%2 == 1 {
				stores = second
			}
			event := sampleAudit(fmt.Sprintf("c%02d", i), "concurrent", "u1", "a1", "success",
				base.Add(time.Duration(i)*time.Second))
			if err := stores.Audits.RecordAudit(testContext, event); err != nil {
				t.Errorf("record %d: %v | 并发追加失败", i, err)
			}
		}(i)
	}
	wg.Wait()
	events, total, err := first.Audits.ListAudit(testContext, auth.AuditQuery{Type: "concurrent", Limit: 0})
	if err != nil || total != workers || len(events) != workers {
		t.Fatalf("total=%d len=%d err=%v | 并发追加丢失事件", total, len(events), err)
	}
	seen := make(map[string]bool, workers)
	for _, event := range events {
		if seen[event.ID] {
			t.Fatalf("duplicate event %q | 事件重复", event.ID)
		}
		seen[event.ID] = true
	}
	for i := 0; i < workers; i++ {
		id := fmt.Sprintf("c%02d", i)
		if !seen[id] {
			t.Fatalf("missing event %q | 缺失事件", id)
		}
	}
}

// auditIDs extracts audit IDs for failure messages. | auditIDs 提取审计 ID 以便失败时输出。
func auditIDs(events []*auth.AuditEvent) []string {
	out := make([]string, len(events))
	for i, event := range events {
		out[i] = event.ID
	}
	return out
}
