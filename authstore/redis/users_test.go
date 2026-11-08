package redis_test

import (
	"errors"
	"fmt"
	"sync"
	"testing"
	"time"

	"github.com/shibingli/ydx/auth"
)

// TestUserCreateAndGet covers creation, identifier normalization and every lookup path.
// | TestUserCreateAndGet 覆盖创建、标识规范化与全部查找路径。
func TestUserCreateAndGet(t *testing.T) {
	stores := newStores(t, "")
	created := testTime(2026, time.February, 2, 3, 4, 5)
	user := sampleUser("u1", " Alice ", "Alice@Example.COM", created)
	user.Phone = "+86 138-0013-8000"
	if err := stores.Users.CreateUser(testContext, user); err != nil {
		t.Fatalf("create: %v | 创建失败", err)
	}
	byID, err := stores.Users.GetUser(testContext, "u1")
	if err != nil {
		t.Fatalf("get by id: %v | 按 ID 读取失败", err)
	}
	if byID.PasswordHash != "encoded-hash-u1" {
		t.Fatalf("password hash = %q | 口令哈希未持久化", byID.PasswordHash)
	}
	if len(byID.PasswordHistory) != 1 || byID.PasswordHistory[0] != "old-hash-u1" {
		t.Fatalf("password history = %#v | 口令历史未持久化", byID.PasswordHistory)
	}
	if byID.FailedLoginAttempts != 3 {
		t.Fatalf("failed login attempts = %d | 失败登录次数未持久化", byID.FailedLoginAttempts)
	}
	if byID.Address["locality"] != "Shanghai" || byID.Metadata["tenant"] != "t1" {
		t.Fatalf("maps not persisted: %#v %#v | 映射未持久化", byID.Address, byID.Metadata)
	}
	byName, err := stores.Users.GetUserByUsername(testContext, " ALICE\t")
	if err != nil {
		t.Fatalf("get by username: %v | 按用户名读取失败", err)
	}
	if byName.ID != "u1" {
		t.Fatalf("username lookup id = %q | 用户名查找 ID 不符", byName.ID)
	}
	byEmail, err := stores.Users.GetUserByEmail(testContext, "alice@example.com")
	if err != nil {
		t.Fatalf("get by email: %v | 按邮箱读取失败", err)
	}
	if byEmail.ID != "u1" {
		t.Fatalf("email lookup id = %q | 邮箱查找 ID 不符", byEmail.ID)
	}
	for _, phone := range []string{"+86 138-0013-8000", "008613800138000", "13800138000"} {
		byPhone, err := stores.Users.GetUserByPhone(testContext, phone)
		if err != nil {
			t.Fatalf("get by phone %q: %v | 按手机号读取失败", phone, err)
		}
		if byPhone.ID != "u1" {
			t.Fatalf("phone lookup id = %q | 手机号查找 ID 不符", byPhone.ID)
		}
	}
	if _, err := stores.Users.GetUserByPhone(testContext, "not-a-phone"); !errors.Is(err, auth.ErrUserNotFound) {
		t.Fatalf("invalid phone error = %v | 非法手机号错误不符", err)
	}
	for _, lookup := range []struct {
		name string
		call func() error
	}{
		{"id", func() error {
			_, err := stores.Users.GetUser(testContext, "missing")
			return err
		}},
		{"username", func() error {
			_, err := stores.Users.GetUserByUsername(testContext, "missing")
			return err
		}},
		{"email", func() error {
			_, err := stores.Users.GetUserByEmail(testContext, "missing@example.com")
			return err
		}},
		{"phone", func() error {
			_, err := stores.Users.GetUserByPhone(testContext, "13900139000")
			return err
		}},
	} {
		if err := lookup.call(); !errors.Is(err, auth.ErrUserNotFound) {
			t.Fatalf("%s lookup error = %v, want ErrUserNotFound | %s 查找错误不符", lookup.name, err, lookup.name)
		}
	}
}

// TestUserUniqueness covers every unique identifier, both within one store and across instances.
// | TestUserUniqueness 覆盖每种唯一标识，包括单存储与跨实例冲突。
func TestUserUniqueness(t *testing.T) {
	first, second := newPair(t)
	base := testTime(2026, time.March, 1, 0, 0, 0)
	user := sampleUser("u1", "alice", "alice@example.com", base)
	user.Phone = "13800138000"
	if err := first.Users.CreateUser(testContext, user); err != nil {
		t.Fatalf("create: %v | 创建失败", err)
	}
	cases := []struct {
		name string
		user *auth.User
		want error
	}{
		{"duplicate id", sampleUser("u1", "other", "other@example.com", base), auth.ErrUserExists},
		{"duplicate username", sampleUser("u2", "ALICE", "other@example.com", base), auth.ErrUserExists},
		{"duplicate email", sampleUser("u3", "other", " Alice@Example.com ", base), auth.ErrUserExists},
	}
	phoneUser := sampleUser("u4", "other", "other@example.com", base)
	phoneUser.Phone = "+86 138 0013 8000"
	cases = append(cases, struct {
		name string
		user *auth.User
		want error
	}{"duplicate phone", phoneUser, auth.ErrUserExists})
	for _, tc := range cases {
		if err := second.Users.CreateUser(testContext, tc.user); !errors.Is(err, tc.want) {
			t.Fatalf("%s error = %v, want %v | %s 错误不符", tc.name, err, tc.want, tc.name)
		}
	}
	if _, err := second.Users.GetUser(testContext, "u2"); !errors.Is(err, auth.ErrUserNotFound) {
		t.Fatalf("failed create left a user: %v | 失败创建留下了用户", err)
	}
	if err := first.Users.CreateUser(testContext, nil); !errors.Is(err, auth.ErrInvalidRequest) {
		t.Fatalf("nil user error = %v | nil 用户错误不符", err)
	}
	if err := first.Users.CreateUser(testContext, &auth.User{}); !errors.Is(err, auth.ErrInvalidRequest) {
		t.Fatalf("empty id error = %v | 空 ID 错误不符", err)
	}
}

// TestUserUpdateReindexes covers identifier changes, cleared identifiers and conflicts.
// | TestUserUpdateReindexes 覆盖标识变更、清空标识与冲突。
func TestUserUpdateReindexes(t *testing.T) {
	first, second := newPair(t)
	base := testTime(2026, time.March, 2, 0, 0, 0)
	user := sampleUser("u1", "alice", "alice@example.com", base)
	user.Phone = "13800138000"
	if err := first.Users.CreateUser(testContext, user); err != nil {
		t.Fatalf("create: %v | 创建失败", err)
	}
	if err := first.Users.CreateUser(testContext, sampleUser("u2", "bob", "bob@example.com", base)); err != nil {
		t.Fatalf("create second: %v | 创建第二个用户失败", err)
	}
	updated := sampleUser("u1", "alice2", "alice2@example.com", base)
	updated.Phone = "13900139000"
	updated.DisplayName = "Alice Two"
	updated.UpdatedAt = testTime(2026, time.March, 3, 0, 0, 0)
	if err := second.Users.UpdateUser(testContext, updated); err != nil {
		t.Fatalf("update: %v | 更新失败", err)
	}
	for _, lookup := range []struct {
		name string
		call func() (*auth.User, error)
	}{
		{"new username", func() (*auth.User, error) { return first.Users.GetUserByUsername(testContext, "alice2") }},
		{"new email", func() (*auth.User, error) { return first.Users.GetUserByEmail(testContext, "alice2@example.com") }},
		{"new phone", func() (*auth.User, error) { return first.Users.GetUserByPhone(testContext, "13900139000") }},
	} {
		if got, err := lookup.call(); err != nil || got.ID != "u1" {
			t.Fatalf("%s lookup = %v, %v | 新标识查找失败", lookup.name, got, err)
		}
	}
	for _, lookup := range []struct {
		name string
		call func() (*auth.User, error)
	}{
		{"old username", func() (*auth.User, error) { return first.Users.GetUserByUsername(testContext, "alice") }},
		{"old email", func() (*auth.User, error) { return first.Users.GetUserByEmail(testContext, "alice@example.com") }},
		{"old phone", func() (*auth.User, error) { return first.Users.GetUserByPhone(testContext, "13800138000") }},
	} {
		if _, err := lookup.call(); !errors.Is(err, auth.ErrUserNotFound) {
			t.Fatalf("%s lookup error = %v, want ErrUserNotFound | 旧标识未释放", lookup.name, err)
		}
	}
	conflicting := sampleUser("u1", "bob", "alice2@example.com", base)
	if err := first.Users.UpdateUser(testContext, conflicting); !errors.Is(err, auth.ErrUserExists) {
		t.Fatalf("conflicting update error = %v, want ErrUserExists | 冲突更新错误不符", err)
	}
	cleared := &auth.User{ID: "u1", DisplayName: "No Identifiers", CreatedAt: base, UpdatedAt: base}
	if err := first.Users.UpdateUser(testContext, cleared); err != nil {
		t.Fatalf("clear identifiers: %v | 清空标识失败", err)
	}
	if got, err := first.Users.GetUser(testContext, "u1"); err != nil || got.DisplayName != "No Identifiers" {
		t.Fatalf("cleared user = %v, %v | 清空标识后用户不符", got, err)
	}
	if _, err := first.Users.GetUserByUsername(testContext, "alice2"); !errors.Is(err, auth.ErrUserNotFound) {
		t.Fatalf("cleared username still indexed: %v | 已清空用户名仍被索引", err)
	}
	reused := sampleUser("u3", "alice2", "alice2@example.com", base)
	if err := first.Users.CreateUser(testContext, reused); err != nil {
		t.Fatalf("reuse cleared identifiers: %v | 复用已清空标识失败", err)
	}
	missing := sampleUser("absent", "x", "x@example.com", base)
	if err := first.Users.UpdateUser(testContext, missing); !errors.Is(err, auth.ErrUserNotFound) {
		t.Fatalf("update missing error = %v | 更新不存在用户错误不符", err)
	}
	if err := first.Users.UpdateUser(testContext, nil); !errors.Is(err, auth.ErrInvalidRequest) {
		t.Fatalf("update nil error = %v | 更新 nil 错误不符", err)
	}
}

// TestUserDelete covers removal, index release and not-found reporting, including across instances.
// | TestUserDelete 覆盖删除、索引释放与不存在报告，包括跨实例。
func TestUserDelete(t *testing.T) {
	first, second := newPair(t)
	base := testTime(2026, time.March, 4, 0, 0, 0)
	user := sampleUser("u1", "alice", "alice@example.com", base)
	user.Phone = "13800138000"
	if err := first.Users.CreateUser(testContext, user); err != nil {
		t.Fatalf("create: %v | 创建失败", err)
	}
	if err := second.Users.DeleteUser(testContext, "u1"); err != nil {
		t.Fatalf("cross-instance delete: %v | 跨实例删除失败", err)
	}
	if _, err := first.Users.GetUser(testContext, "u1"); !errors.Is(err, auth.ErrUserNotFound) {
		t.Fatalf("get after delete: %v | 删除后读取错误不符", err)
	}
	for _, call := range []func() error{
		func() error { _, err := first.Users.GetUserByUsername(testContext, "alice"); return err },
		func() error { _, err := first.Users.GetUserByEmail(testContext, "alice@example.com"); return err },
		func() error { _, err := first.Users.GetUserByPhone(testContext, "13800138000"); return err },
		func() error { return first.Users.DeleteUser(testContext, "u1") },
	} {
		if err := call(); !errors.Is(err, auth.ErrUserNotFound) {
			t.Fatalf("after delete error = %v, want ErrUserNotFound | 删除后错误不符", err)
		}
	}
	reused := sampleUser("u2", "alice", "alice@example.com", base)
	reused.Phone = "13800138000"
	if err := second.Users.CreateUser(testContext, reused); err != nil {
		t.Fatalf("reuse identifiers: %v | 复用标识失败", err)
	}
}

// TestUserList covers query filtering, status filtering, ordering, pagination and total.
// | TestUserList 覆盖查询过滤、状态过滤、排序、分页与总数。
func TestUserList(t *testing.T) {
	stores := newStores(t, "")
	base := testTime(2026, time.April, 1, 0, 0, 0)
	users := []*auth.User{
		sampleUser("u3", "carol", "carol@example.com", base.Add(3*time.Hour)),
		sampleUser("u1", "alice", "alice@example.org", base.Add(1*time.Hour)),
		sampleUser("u2", "bob", "bob@example.com", base.Add(2*time.Hour)),
		sampleUser("u0", "dave", "dave@example.com", base.Add(2*time.Hour)),
	}
	users[0].DisplayName = "Carol Smith"
	users[1].DisplayName = "Alice Zhang"
	users[2].DisplayName = "Bob Li"
	users[2].Status = auth.UserDisabled
	users[3].Status = auth.UserDisabled
	for _, user := range users {
		if err := stores.Users.CreateUser(testContext, user); err != nil {
			t.Fatalf("create %s: %v | 创建用户失败", user.ID, err)
		}
	}
	all, total, err := stores.Users.ListUsers(testContext, auth.UserQuery{})
	if err != nil {
		t.Fatalf("list: %v | 列表失败", err)
	}
	if total != 4 || len(all) != 4 {
		t.Fatalf("total=%d len=%d | 总数或长度不符", total, len(all))
	}
	wantOrder := []string{"u1", "u0", "u2", "u3"}
	for i, id := range wantOrder {
		if all[i].ID != id {
			t.Fatalf("order[%d] = %q, want %q | 排序不符", i, all[i].ID, id)
		}
	}
	page, total, err := stores.Users.ListUsers(testContext, auth.UserQuery{Offset: 1, Limit: 2})
	if err != nil || total != 4 || len(page) != 2 || page[0].ID != "u0" || page[1].ID != "u2" {
		t.Fatalf("page = %v total=%d err=%v | 分页不符", ids(page), total, err)
	}
	past, total, err := stores.Users.ListUsers(testContext, auth.UserQuery{Offset: 99, Limit: 2})
	if err != nil || total != 4 || len(past) != 0 {
		t.Fatalf("out-of-range page = %v total=%d err=%v | 越界分页不符", ids(past), total, err)
	}
	unlimited, total, err := stores.Users.ListUsers(testContext, auth.UserQuery{Offset: 2, Limit: 0})
	if err != nil || total != 4 || len(unlimited) != 2 || unlimited[0].ID != "u2" {
		t.Fatalf("unlimited page = %v total=%d err=%v | 无上限分页不符", ids(unlimited), total, err)
	}
	search, total, err := stores.Users.ListUsers(testContext, auth.UserQuery{Query: "  SMITH "})
	if err != nil || total != 1 || len(search) != 1 || search[0].ID != "u3" {
		t.Fatalf("display name search = %v total=%d err=%v | 展示名搜索不符", ids(search), total, err)
	}
	emailSearch, total, err := stores.Users.ListUsers(testContext, auth.UserQuery{Query: "EXAMPLE.ORG"})
	if err != nil || total != 1 || emailSearch[0].ID != "u1" {
		t.Fatalf("email search = %v total=%d err=%v | 邮箱搜索不符", ids(emailSearch), total, err)
	}
	disabled, total, err := stores.Users.ListUsers(testContext, auth.UserQuery{Status: auth.UserDisabled})
	if err != nil || total != 2 || len(disabled) != 2 || disabled[0].ID != "u0" || disabled[1].ID != "u2" {
		t.Fatalf("status filter = %v total=%d err=%v | 状态过滤不符", ids(disabled), total, err)
	}
	none, total, err := stores.Users.ListUsers(testContext, auth.UserQuery{Query: "nobody"})
	if err != nil || total != 0 || len(none) != 0 {
		t.Fatalf("empty filter = %v total=%d err=%v | 空结果不符", ids(none), total, err)
	}
}

// TestUserDeepCopy verifies that mutation on either side never crosses the store boundary and that
// UTC normalization is applied. | TestUserDeepCopy 验证两侧修改都不会越过存储边界，并检查 UTC 规范化。
func TestUserDeepCopy(t *testing.T) {
	stores := newStores(t, "")
	zone := time.FixedZone("UTC+5:30", 5*3600+1800)
	created := time.Date(2026, time.May, 5, 10, 0, 0, 0, zone)
	user := sampleUser("u1", "alice", "alice@example.com", created)
	if err := stores.Users.CreateUser(testContext, user); err != nil {
		t.Fatalf("create: %v | 创建失败", err)
	}
	user.Address["locality"] = "mutated"
	user.Metadata["tenant"] = "mutated"
	user.PasswordHistory[0] = "mutated"
	user.PasswordHash = "mutated"
	got, err := stores.Users.GetUser(testContext, "u1")
	if err != nil {
		t.Fatalf("get: %v | 读取失败", err)
	}
	if got.Address["locality"] != "Shanghai" || got.Metadata["tenant"] != "t1" ||
		got.PasswordHistory[0] != "old-hash-u1" || got.PasswordHash != "encoded-hash-u1" {
		t.Fatalf("input mutation leaked: %#v | 输入修改泄露到存储", got)
	}
	if got.CreatedAt.Location() != time.UTC || !got.CreatedAt.Equal(created) {
		t.Fatalf("createdAt = %v loc=%v | 时间未规范化为 UTC", got.CreatedAt, got.CreatedAt.Location())
	}
	got.Address["locality"] = "returned-mutation"
	got.Metadata["tenant"] = "returned-mutation"
	got.PasswordHistory[0] = "returned-mutation"
	again, err := stores.Users.GetUserByUsername(testContext, "alice")
	if err != nil {
		t.Fatalf("get again: %v | 再次读取失败", err)
	}
	if again.Address["locality"] != "Shanghai" || again.Metadata["tenant"] != "t1" ||
		again.PasswordHistory[0] != "old-hash-u1" {
		t.Fatalf("returned mutation persisted: %#v | 返回值修改影响了存储", again)
	}
	if !again.UpdatedAt.Equal(created) || again.UpdatedAt.Location() != time.UTC {
		t.Fatalf("updatedAt = %v | 更新时间不符", again.UpdatedAt)
	}
}

// TestUserConcurrentCreate verifies that concurrent creators of the same username through
// independent instances produce exactly one success. | TestUserConcurrentCreate 验证通过独立实例并发
// 创建相同用户名时恰好一个成功。
func TestUserConcurrentCreate(t *testing.T) {
	first, second := newPair(t)
	const workers = 16
	base := testTime(2026, time.June, 1, 0, 0, 0)
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
			errsCh <- stores.Users.CreateUser(testContext,
				sampleUser(fmt.Sprintf("u%d", i), "shared-name", "shared@example.com", base))
		}(i)
	}
	wg.Wait()
	close(errsCh)
	successes := 0
	duplicates := 0
	for err := range errsCh {
		switch {
		case err == nil:
			successes++
		case errors.Is(err, auth.ErrUserExists):
			duplicates++
		default:
			t.Fatalf("unexpected create error: %v | 意外创建错误", err)
		}
	}
	if successes != 1 || duplicates != workers-1 {
		t.Fatalf("successes=%d duplicates=%d | 并发唯一性结果不符", successes, duplicates)
	}
	if _, total, err := second.Users.ListUsers(testContext, auth.UserQuery{}); err != nil || total != 1 {
		t.Fatalf("total=%d err=%v | 并发后用户总数不符", total, err)
	}
}

// ids extracts user IDs for failure messages. | ids 提取用户 ID 以便失败时输出。
func ids(users []*auth.User) []string {
	out := make([]string, len(users))
	for i, user := range users {
		out[i] = user.ID
	}
	return out
}
