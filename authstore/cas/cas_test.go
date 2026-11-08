package cas_test

import (
	"context"
	"errors"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/alicebob/miniredis/v2"
	goredis "github.com/redis/go-redis/v9"

	"github.com/shibingli/ydx/auth"
	authcas "github.com/shibingli/ydx/auth/protocol/cas"
	casstore "github.com/shibingli/ydx/authstore/cas"
)

// testContext is the context shared by the store tests. | testContext 是存储测试共享的上下文。
var testContext = context.Background()

// newStores starts a private miniredis and returns stores using prefix.
// | newStores 启动私有 miniredis 并返回使用 prefix 的存储。
func newStores(t *testing.T, prefix string) *casstore.Stores {
	t.Helper()
	server := miniredis.RunT(t)
	return newStoresOn(t, server, prefix)
}

// newStoresOn creates one more independent client against an existing miniredis.
// | newStoresOn 针对已有 miniredis 创建一个独立客户端。
func newStoresOn(t *testing.T, server *miniredis.Miniredis, prefix string) *casstore.Stores {
	t.Helper()
	client := goredis.NewClient(&goredis.Options{Addr: server.Addr()})
	t.Cleanup(func() {
		_ = client.Close()
	})
	stores, err := casstore.New(client, casstore.Options{KeyPrefix: prefix})
	if err != nil {
		t.Fatalf("new stores: %v | 创建存储失败", err)
	}
	return stores
}

// newPair returns two independent store sets sharing one miniredis, which models two application
// instances. | newPair 返回共享同一 miniredis 的两套独立存储，用于模拟两个应用实例。
func newPair(t *testing.T) (*casstore.Stores, *casstore.Stores) {
	t.Helper()
	server := miniredis.RunT(t)
	return newStoresOn(t, server, ""), newStoresOn(t, server, "")
}

// testTime returns a fixed UTC instant. | testTime 返回固定的 UTC 时刻。
func testTime(year int, month time.Month, day, hour, minute, second int) time.Time {
	return time.Date(year, month, day, hour, minute, second, 0, time.UTC)
}

// samplePrincipal returns a fully populated authentication snapshot.
// | samplePrincipal 返回字段完整的认证快照。
func samplePrincipal(userID string, at time.Time) *auth.Principal {
	return &auth.Principal{
		Subject:     userID,
		Issuer:      "https://cas.example.com",
		Audience:    []string{"https://app.example.com"},
		Scopes:      []string{"profile", "email"},
		Roles:       []string{"admin"},
		Permissions: []string{"read", "write"},
		Groups:      []string{"staff"},
		Attributes:  map[string]string{"tenant": "t1"},
		AuthTime:    at,
		IssuedAt:    at,
		Email:       userID + "@example.com",
		Username:    userID,
		DisplayName: userID,
	}
}

// sampleTicket returns a ticket with the given binding. | sampleTicket 返回具有指定绑定的票据。
func sampleTicket(id string, typ authcas.TicketType, userID, service, root string, issued time.Time, ttl time.Duration) *authcas.Ticket {
	ticket := &authcas.Ticket{
		ID:         id,
		Type:       typ,
		UserID:     userID,
		Service:    service,
		RootTGTID:  root,
		IssuedAt:   issued,
		ExpiresAt:  issued.Add(ttl),
		Principal:  samplePrincipal(userID, issued),
		ProxyChain: []string{"https://proxy.example.com/callback"},
	}
	if typ == authcas.TicketST || typ == authcas.TicketPT {
		ticket.ParentID = root
	}
	return ticket
}

// sampleSession returns a service session with the given binding. A non-positive ttl means the
// session never expires. | sampleSession 返回具有指定绑定的服务会话。非正 ttl 表示会话永不过期。
func sampleSession(index, tgt, user, userID, service string, issued time.Time, ttl time.Duration) *authcas.ServiceSession {
	session := &authcas.ServiceSession{
		SessionIndex: index,
		User:         user,
		UserID:       userID,
		Service:      service,
		TGTID:        tgt,
		IssuedAt:     issued,
	}
	if ttl > 0 {
		session.ExpiresAt = issued.Add(ttl)
	}
	return session
}

// TestNewValidation covers constructor validation, the default prefix and interface views.
// | TestNewValidation 覆盖构造校验、默认前缀与接口视图。
func TestNewValidation(t *testing.T) {
	if casstore.DefaultKeyPrefix != "ydx:authstore:cas:" {
		t.Fatalf("DefaultKeyPrefix = %q | 默认前缀不正确", casstore.DefaultKeyPrefix)
	}
	if _, err := casstore.New(nil, casstore.Options{}); !errors.Is(err, authcas.ErrInvalidConfig) {
		t.Fatalf("nil client error = %v, want ErrInvalidConfig | nil 客户端错误不符", err)
	}
	server := miniredis.RunT(t)
	client := goredis.NewClient(&goredis.Options{Addr: server.Addr()})
	t.Cleanup(func() {
		_ = client.Close()
	})
	if _, err := casstore.New(client, casstore.Options{KeyPrefix: "bad{prefix"}); !errors.Is(err, authcas.ErrInvalidConfig) {
		t.Fatalf("brace prefix error = %v, want ErrInvalidConfig | 花括号前缀错误不符", err)
	}
	stores, err := casstore.New(client, casstore.Options{})
	if err != nil {
		t.Fatalf("new stores: %v | 创建存储失败", err)
	}
	var ticketStore authcas.TicketStore = stores.Tickets
	var registry authcas.ServiceSessionRegistry = stores.Sessions
	if ticketStore == nil || registry == nil {
		t.Fatal("New returned a nil port | New 返回了空端口")
	}
	if stores.TicketStore() != ticketStore {
		t.Fatal("TicketStore view differs | TicketStore 视图不一致")
	}
	if stores.SessionRegistry() != registry {
		t.Fatal("SessionRegistry view differs | SessionRegistry 视图不一致")
	}
	var nilStores *casstore.Stores
	if nilStores.TicketStore() != nil || nilStores.SessionRegistry() != nil {
		t.Fatal("nil Stores returned a port | nil Stores 返回了端口")
	}
	if stats, err := nilStores.Stats(testContext); err != nil || stats != (casstore.Stats{}) {
		t.Fatalf("nil Stats = %#v, %v | nil Stats 不符", stats, err)
	}
	if tickets, total, err := nilStores.ListTickets(testContext, casstore.TicketQuery{}); err != nil || len(tickets) != 0 || total != 0 {
		t.Fatalf("nil ListTickets = %d, %d, %v | nil ListTickets 不符", len(tickets), total, err)
	}
	if sessions, total, err := nilStores.ListSessions(testContext, casstore.SessionQuery{}); err != nil || len(sessions) != 0 || total != 0 {
		t.Fatalf("nil ListSessions = %d, %d, %v | nil ListSessions 不符", len(sessions), total, err)
	}
	if stats, err := stores.Stats(testContext); err != nil || stats != (casstore.Stats{}) {
		t.Fatalf("empty Stats = %#v, %v | 空 Stats 不符", stats, err)
	}
}

// TestNewDoesNotDial verifies that New performs no network round trip.
// | TestNewDoesNotDial 验证 New 不进行网络往返。
func TestNewDoesNotDial(t *testing.T) {
	client := goredis.NewClient(&goredis.Options{Addr: "127.0.0.1:1", MaxRetries: -1})
	t.Cleanup(func() {
		_ = client.Close()
	})
	if _, err := casstore.New(client, casstore.Options{}); err != nil {
		t.Fatalf("New dialed: %v | New 不应连接网络", err)
	}
}

// TestPrefixIsolation runs two store sets with distinct prefixes on one server.
// | TestPrefixIsolation 在同一服务器上运行两套不同前缀的存储。
func TestPrefixIsolation(t *testing.T) {
	server := miniredis.RunT(t)
	first := newStoresOn(t, server, "one:")
	second := newStoresOn(t, server, "two:")
	base := testTime(2026, time.January, 1, 0, 0, 0)
	ticket := sampleTicket("ST-1", authcas.TicketST, "u1", "https://app.example.com", "TGT-1", base, time.Hour)
	if err := first.Tickets.Save(testContext, ticket); err != nil {
		t.Fatalf("save first: %v | 第一套保存失败", err)
	}
	if _, err := second.Tickets.Get(testContext, "ST-1"); !errors.Is(err, authcas.ErrTicketNotFound) {
		t.Fatalf("second prefix saw first ticket: %v | 第二前缀看到了第一前缀的票据", err)
	}
	session := sampleSession("ST-1", "TGT-1", "alice", "u1", "https://app.example.com", base, time.Hour)
	if err := first.Sessions.Register(testContext, session); err != nil {
		t.Fatalf("register first: %v | 第一套注册失败", err)
	}
	if _, err := second.Sessions.Get(testContext, "ST-1"); !errors.Is(err, authcas.ErrSessionNotFound) {
		t.Fatalf("second prefix saw first session: %v | 第二前缀看到了第一前缀的会话", err)
	}
	other := sampleTicket("ST-1", authcas.TicketST, "u2", "https://app.example.com", "TGT-2", base.Add(time.Hour), time.Hour)
	if err := second.Tickets.Save(testContext, other); err != nil {
		t.Fatalf("save second: %v | 第二套保存失败", err)
	}
	stored, err := first.Tickets.Get(testContext, "ST-1")
	if err != nil || stored.UserID != "u1" {
		t.Fatalf("first ticket changed: %v | 第一套票据被改写", err)
	}
}

// TestKeyLayout verifies the default prefix, the shared hash tag and the length-prefixed segments.
// | TestKeyLayout 验证默认前缀、共享哈希标签与长度前缀段。
func TestKeyLayout(t *testing.T) {
	server := miniredis.RunT(t)
	stores := newStoresOn(t, server, casstore.DefaultKeyPrefix)
	base := testTime(2026, time.February, 1, 0, 0, 0)
	ticket := sampleTicket("ST-abc", authcas.TicketST, "user-1", "https://app.example.com/cb", "TGT-abc", base, time.Hour)
	if err := stores.Tickets.Save(testContext, ticket); err != nil {
		t.Fatalf("save ticket: %v | 保存票据失败", err)
	}
	session := sampleSession("ST-abc", "TGT-abc", "alice", "user-1", "https://app.example.com/cb", base, time.Hour)
	if err := stores.Sessions.Register(testContext, session); err != nil {
		t.Fatalf("register session: %v | 注册会话失败", err)
	}
	keys := server.Keys()
	if len(keys) == 0 {
		t.Fatal("no keys written | 未写入任何键")
	}
	ticketKey := ":" + "ticket:" + strconv.Itoa(len(ticket.ID)) + ":" + ticket.ID
	sessionKey := ":" + "session:" + strconv.Itoa(len(session.SessionIndex)) + ":" + session.SessionIndex
	seenTicket, seenSession := false, false
	for _, key := range keys {
		if !strings.HasPrefix(key, casstore.DefaultKeyPrefix) {
			t.Fatalf("key %q lacks the default prefix | 键缺少默认前缀", key)
		}
		if !strings.Contains(key, "{authstore:cas}") {
			t.Fatalf("key %q lacks the shared hash tag | 键缺少共享哈希标签", key)
		}
		if strings.Contains(key, ticketKey) {
			seenTicket = true
		}
		if strings.Contains(key, sessionKey) {
			seenSession = true
		}
	}
	if !seenTicket || !seenSession {
		t.Fatalf("length-prefixed keys missing: ticket=%v session=%v | 长度前缀键缺失", seenTicket, seenSession)
	}
}

// TestBackendErrorsAreRedacted verifies classification and the absence of addresses.
// | TestBackendErrorsAreRedacted 验证错误分类且不泄露地址。
func TestBackendErrorsAreRedacted(t *testing.T) {
	client := goredis.NewClient(&goredis.Options{Addr: "127.0.0.1:1", MaxRetries: -1, DialTimeout: 50 * time.Millisecond})
	t.Cleanup(func() {
		_ = client.Close()
	})
	stores, err := casstore.New(client, casstore.Options{})
	if err != nil {
		t.Fatalf("new stores: %v | 创建存储失败", err)
	}
	_, err = stores.Tickets.Get(testContext, "missing")
	if !errors.Is(err, casstore.ErrStoreUnavailable) {
		t.Fatalf("error = %v, want ErrStoreUnavailable | 错误未映射为存储不可用", err)
	}
	if strings.Contains(err.Error(), "127.0.0.1") || strings.Contains(err.Error(), ":1") {
		t.Fatalf("error leaked the address: %v | 错误泄露了地址", err)
	}
	if _, err := stores.Sessions.Get(testContext, "missing"); !errors.Is(err, casstore.ErrStoreUnavailable) {
		t.Fatalf("session error = %v, want ErrStoreUnavailable | 会话错误未映射为存储不可用", err)
	}
	if _, err := stores.Stats(testContext); !errors.Is(err, casstore.ErrStoreUnavailable) {
		t.Fatalf("stats error = %v, want ErrStoreUnavailable | 统计错误未映射为存储不可用", err)
	}
	if _, _, err := stores.ListTickets(testContext, casstore.TicketQuery{}); !errors.Is(err, casstore.ErrStoreUnavailable) {
		t.Fatalf("query error = %v, want ErrStoreUnavailable | 查询错误未映射为存储不可用", err)
	}
}

// TestContextCancellation verifies that context cancellation is returned unchanged.
// | TestContextCancellation 验证上下文取消原样返回。
func TestContextCancellation(t *testing.T) {
	stores := newStores(t, "")
	ctx, cancel := context.WithCancel(testContext)
	cancel()
	if _, err := stores.Tickets.Get(ctx, "missing"); !errors.Is(err, context.Canceled) {
		t.Fatalf("Get error = %v, want context.Canceled | Get 错误未保留取消", err)
	}
	if _, err := stores.Sessions.Get(ctx, "missing"); !errors.Is(err, context.Canceled) {
		t.Fatalf("Get session error = %v, want context.Canceled | 会话 Get 错误未保留取消", err)
	}
	if _, err := stores.Tickets.DeleteExpired(ctx, time.Now()); !errors.Is(err, context.Canceled) {
		t.Fatalf("DeleteExpired error = %v, want context.Canceled | DeleteExpired 错误未保留取消", err)
	}
}
