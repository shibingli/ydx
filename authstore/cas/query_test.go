package cas_test

import (
	"testing"
	"time"

	authcas "github.com/shibingli/ydx/auth/protocol/cas"
	casstore "github.com/shibingli/ydx/authstore/cas"
)

// TestStats verifies the index-derived record counts. | TestStats 验证由索引推导的记录数量。
func TestStats(t *testing.T) {
	first, second := newPair(t)
	base := testTime(2026, time.July, 2, 0, 0, 0)
	tickets := []*authcas.Ticket{
		sampleTicket("TGT-1", authcas.TicketTGT, "u1", "", "TGT-1", base, time.Hour),
		sampleTicket("ST-1", authcas.TicketST, "u1", "https://app.example.com", "TGT-1", base.Add(time.Minute), time.Hour),
		sampleTicket("ST-2", authcas.TicketST, "u2", "https://app.example.com", "TGT-1", base.Add(2*time.Minute), time.Hour),
		sampleTicket("PGT-1", authcas.TicketPGT, "u1", "https://proxy.example.com/pgt", "TGT-1", base.Add(3*time.Minute), time.Hour),
		sampleTicket("PT-1", authcas.TicketPT, "u1", "https://backend.example.com", "TGT-1", base.Add(4*time.Minute), time.Hour),
	}
	for _, ticket := range tickets {
		if err := first.Tickets.Save(testContext, ticket); err != nil {
			t.Fatalf("save %s: %v | 保存失败", ticket.ID, err)
		}
	}
	for i := 0; i < 2; i++ {
		session := sampleSession("ST-s"+string(rune('1'+i)), "TGT-1", "alice", "u1", "https://app.example.com", base, time.Hour)
		if err := first.Sessions.Register(testContext, session); err != nil {
			t.Fatalf("register session: %v | 注册会话失败", err)
		}
	}
	stats, err := second.Stats(testContext)
	if err != nil {
		t.Fatalf("stats: %v | 统计失败", err)
	}
	want := casstore.Stats{Tickets: 5, TGT: 1, ST: 2, PGT: 1, PT: 1, Sessions: 2}
	if stats != want {
		t.Fatalf("stats = %#v, want %#v | 统计结果不符", stats, want)
	}
	if err := second.Tickets.Delete(testContext, "ST-2"); err != nil {
		t.Fatalf("delete ST-2: %v | 删除失败", err)
	}
	if err := second.Sessions.Delete(testContext, "ST-s1"); err != nil {
		t.Fatalf("delete session: %v | 删除会话失败", err)
	}
	stats, err = first.Stats(testContext)
	if err != nil {
		t.Fatalf("stats after delete: %v | 删除后统计失败", err)
	}
	want = casstore.Stats{Tickets: 4, TGT: 1, ST: 1, PGT: 1, PT: 1, Sessions: 1}
	if stats != want {
		t.Fatalf("stats after delete = %#v, want %#v | 删除后统计不符", stats, want)
	}
}

// TestListTicketsQuery verifies selector intersection and pagination ordering.
// | TestListTicketsQuery 验证选择器交集与分页排序。
func TestListTicketsQuery(t *testing.T) {
	first, second := newPair(t)
	base := testTime(2026, time.August, 2, 0, 0, 0)
	ids := []string{"ST-a", "ST-b", "ST-c", "ST-d"}
	for i, id := range ids {
		ticket := sampleTicket(id, authcas.TicketST, "u1", "https://app.example.com", "TGT-1", base.Add(time.Duration(i)*time.Minute), time.Hour)
		if err := first.Tickets.Save(testContext, ticket); err != nil {
			t.Fatalf("save %s: %v | 保存失败", id, err)
		}
	}
	pt := sampleTicket("PT-a", authcas.TicketPT, "u1", "https://app.example.com", "TGT-1", base.Add(10*time.Minute), time.Hour)
	other := sampleTicket("ST-z", authcas.TicketST, "u2", "https://other.example.com", "TGT-2", base.Add(11*time.Minute), time.Hour)
	for _, ticket := range []*authcas.Ticket{pt, other} {
		if err := first.Tickets.Save(testContext, ticket); err != nil {
			t.Fatalf("save %s: %v | 保存失败", ticket.ID, err)
		}
	}

	page, total, err := second.ListTickets(testContext, casstore.TicketQuery{
		Type:    authcas.TicketST,
		Service: "https://app.example.com",
		UserID:  "u1",
		Limit:   2,
	})
	if err != nil {
		t.Fatalf("page one: %v | 第一页查询失败", err)
	}
	if total != 4 {
		t.Fatalf("total = %d, want 4 | 总数不符", total)
	}
	if got := ticketIDs(page); len(got) != 2 || got[0] != "ST-a" || got[1] != "ST-b" {
		t.Fatalf("page one = %v | 第一页不符", got)
	}
	page, total, err = second.ListTickets(testContext, casstore.TicketQuery{
		Type:    authcas.TicketST,
		Service: "https://app.example.com",
		UserID:  "u1",
		Offset:  2,
		Limit:   2,
	})
	if err != nil {
		t.Fatalf("page two: %v | 第二页查询失败", err)
	}
	if total != 4 {
		t.Fatalf("page two total = %d, want 4 | 第二页总数不符", total)
	}
	if got := ticketIDs(page); len(got) != 2 || got[0] != "ST-c" || got[1] != "ST-d" {
		t.Fatalf("page two = %v | 第二页不符", got)
	}
	page, total, err = second.ListTickets(testContext, casstore.TicketQuery{
		Type:    authcas.TicketST,
		Service: "https://app.example.com",
		UserID:  "u1",
		Offset:  10,
	})
	if err != nil || total != 4 || len(page) != 0 {
		t.Fatalf("beyond page = %v, %d, %v | 越界分页不符", ticketIDs(page), total, err)
	}
	page, total, err = second.ListTickets(testContext, casstore.TicketQuery{
		Service: "https://app.example.com",
		UserID:  "u1",
		Offset:  -3,
	})
	if err != nil || total != 5 || len(page) != 5 {
		t.Fatalf("negative offset = %v, %d, %v | 负偏移处理不符", ticketIDs(page), total, err)
	}
	page, total, err = second.ListTickets(testContext, casstore.TicketQuery{UserID: "u1"})
	if err != nil || total != 5 || len(page) != 5 {
		t.Fatalf("user query = %v, %d, %v | 用户查询不符", ticketIDs(page), total, err)
	}
	page, total, err = second.ListTickets(testContext, casstore.TicketQuery{})
	if err != nil || total != 6 || len(page) != 6 {
		t.Fatalf("all query = %v, %d, %v | 全量查询不符", ticketIDs(page), total, err)
	}
	page, total, err = second.ListTickets(testContext, casstore.TicketQuery{Type: authcas.TicketTGT})
	if err != nil || total != 0 || len(page) != 0 {
		t.Fatalf("empty query = %v, %d, %v | 空结果查询不符", ticketIDs(page), total, err)
	}
}

// TestListSessionsQuery verifies selector intersection and pagination ordering.
// | TestListSessionsQuery 验证选择器交集与分页排序。
func TestListSessionsQuery(t *testing.T) {
	first, second := newPair(t)
	base := testTime(2026, time.September, 2, 0, 0, 0)
	sessions := []*authcas.ServiceSession{
		sampleSession("ST-1", "TGT-1", "alice", "user-a", "https://one.example.com", base, time.Hour),
		sampleSession("ST-2", "TGT-1", "alice", "user-a", "https://two.example.com", base.Add(time.Minute), time.Hour),
		sampleSession("ST-3", "TGT-1", "alice", "user-a", "https://three.example.com", base.Add(2*time.Minute), time.Hour),
		sampleSession("ST-4", "TGT-1", "bob", "user-b", "https://four.example.com", base.Add(3*time.Minute), time.Hour),
		sampleSession("ST-5", "TGT-2", "alice", "user-c", "https://five.example.com", base.Add(4*time.Minute), time.Hour),
	}
	for _, session := range sessions {
		if err := first.Sessions.Register(testContext, session); err != nil {
			t.Fatalf("register %s: %v | 注册失败", session.SessionIndex, err)
		}
	}
	page, total, err := second.ListSessions(testContext, casstore.SessionQuery{TGTID: "TGT-1", Limit: 2})
	if err != nil {
		t.Fatalf("tgt page: %v | 按 TGT 分页失败", err)
	}
	if total != 4 {
		t.Fatalf("tgt total = %d, want 4 | TGT 总数不符", total)
	}
	if got := sessionIndexes(page); len(got) != 2 || got[0] != "ST-1" || got[1] != "ST-2" {
		t.Fatalf("tgt page = %v | TGT 分页不符", got)
	}
	page, total, err = second.ListSessions(testContext, casstore.SessionQuery{TGTID: "TGT-1", Offset: 1, Limit: 2})
	if err != nil || total != 4 || len(page) != 2 || page[0].SessionIndex != "ST-2" || page[1].SessionIndex != "ST-3" {
		t.Fatalf("tgt offset page = %v, %d, %v | TGT 偏移分页不符", sessionIndexes(page), total, err)
	}
	page, total, err = second.ListSessions(testContext, casstore.SessionQuery{User: "alice"})
	if err != nil || total != 4 || len(page) != 4 {
		t.Fatalf("user query = %v, %d, %v | 用户查询不符", sessionIndexes(page), total, err)
	}
	page, total, err = second.ListSessions(testContext, casstore.SessionQuery{User: "user-a"})
	if err != nil || total != 3 || len(page) != 3 {
		t.Fatalf("backend user query = %v, %d, %v | 后端用户查询不符", sessionIndexes(page), total, err)
	}
	page, total, err = second.ListSessions(testContext, casstore.SessionQuery{TGTID: "TGT-1", User: "alice"})
	if err != nil || total != 3 || len(page) != 3 {
		t.Fatalf("intersection query = %v, %d, %v | 交集查询不符", sessionIndexes(page), total, err)
	}
	page, total, err = second.ListSessions(testContext, casstore.SessionQuery{})
	if err != nil || total != 5 || len(page) != 5 {
		t.Fatalf("all query = %v, %d, %v | 全量查询不符", sessionIndexes(page), total, err)
	}
	page, total, err = second.ListSessions(testContext, casstore.SessionQuery{TGTID: "TGT-1", User: "user-c"})
	if err != nil || total != 0 || len(page) != 0 {
		t.Fatalf("empty intersection = %v, %d, %v | 空交集查询不符", sessionIndexes(page), total, err)
	}
	page, total, err = second.ListSessions(testContext, casstore.SessionQuery{Offset: 99})
	if err != nil || total != 5 || len(page) != 0 {
		t.Fatalf("beyond page = %v, %d, %v | 越界会话分页不符", sessionIndexes(page), total, err)
	}
}

// TestListDeepCopies verifies that query results are deep copies. | TestListDeepCopies 验证查询结果是深
// 拷贝。
func TestListDeepCopies(t *testing.T) {
	stores := newStores(t, "")
	base := testTime(2026, time.October, 2, 0, 0, 0)
	if err := stores.Tickets.Save(testContext, sampleTicket("ST-1", authcas.TicketST, "u1", "https://svc.example.com", "TGT-1", base, time.Hour)); err != nil {
		t.Fatalf("save ticket: %v | 保存票据失败", err)
	}
	if err := stores.Sessions.Register(testContext, sampleSession("ST-1", "TGT-1", "alice", "u1", "https://svc.example.com", base, time.Hour)); err != nil {
		t.Fatalf("register session: %v | 注册会话失败", err)
	}
	tickets, _, err := stores.ListTickets(testContext, casstore.TicketQuery{})
	if err != nil {
		t.Fatalf("list tickets: %v | 查询票据失败", err)
	}
	tickets[0].Principal.Attributes["tenant"] = "changed"
	tickets[0].ID = "changed"
	if stored, err := stores.Tickets.Get(testContext, "ST-1"); err != nil || stored.Principal.Attributes["tenant"] != "t1" {
		t.Fatalf("query result aliased stored ticket: %v | 查询结果别名了已存票据", err)
	}
	sessions, _, err := stores.ListSessions(testContext, casstore.SessionQuery{})
	if err != nil {
		t.Fatalf("list sessions: %v | 查询会话失败", err)
	}
	sessions[0].User = "changed"
	if stored, err := stores.Sessions.Get(testContext, "ST-1"); err != nil || stored.User != "alice" {
		t.Fatalf("query result aliased stored session: %v | 查询结果别名了已存会话", err)
	}
}
