package scim_test

import (
	"slices"
	"strings"
	"testing"

	scimlib "github.com/shibingli/ydx/auth/directory/scim"
	scimstore "github.com/shibingli/ydx/authstore/scim"
)

// seedListUsers creates five users with distinct filterable attributes.
// | seedListUsers 创建五个具有不同可过滤属性的用户。
func seedListUsers(t *testing.T, store *scimstore.Store) {
	t.Helper()
	seed := []struct {
		userName    string
		displayName string
		title       string
		externalID  string
	}{
		{"alice", "Alice", "Engineer", "e1"},
		{"bob", "Bob", "Engineer", "e2"},
		{"carol", "Carol", "Manager", "e3"},
		{"dave", "Dave", "Engineer", "e1"},
		{"eve", "Eve", "Manager", "e2"},
	}
	for _, item := range seed {
		user := sampleUser(item.userName)
		user.DisplayName = item.displayName
		user.Title = item.title
		user.ExternalID = item.externalID
		if _, err := store.CreateUser(testContext, user); err != nil {
			t.Fatalf("seed user %q: %v | 初始化用户 %q 失败", item.userName, err, item.userName)
		}
	}
}

// userNameList returns the user names in order. | userNameList 按顺序返回用户名。
func userNameList(users []*scimlib.User) []string {
	names := make([]string, 0, len(users))
	for _, user := range users {
		names = append(names, user.UserName)
	}
	return names
}

// groupNameList returns the group display names in order. | groupNameList 按顺序返回组展示名。
func groupNameList(groups []*scimlib.Group) []string {
	names := make([]string, 0, len(groups))
	for _, group := range groups {
		names = append(names, group.DisplayName)
	}
	return names
}

// mustFilter parses a filter expression or fails the test. | mustFilter 解析过滤器表达式，失败时终止测试。
func mustFilter(t *testing.T, expression string) scimlib.Filter {
	t.Helper()
	filter, err := scimlib.ParseFilter(expression)
	if err != nil {
		t.Fatalf("parse filter %q: %v | 解析过滤器 %q 失败", expression, err, expression)
	}
	return filter
}

// TestListUsersFilterSortPage covers filter, sort and pagination semantics against Redis.
// | TestListUsersFilterSortPage 覆盖 Redis 上的过滤、排序与分页语义。
func TestListUsersFilterSortPage(t *testing.T) {
	store := newTestStore(t)
	seedListUsers(t, store)
	tests := []struct {
		name      string
		query     scimlib.ListQuery
		wantNames []string
		wantTotal int
	}{
		{
			name:      "creation order by default",
			query:     scimlib.ListQuery{Count: -1},
			wantNames: []string{"alice", "bob", "carol", "dave", "eve"},
			wantTotal: 5,
		},
		{
			name:      "filter equality",
			query:     scimlib.ListQuery{Filter: mustFilter(t, `title eq "Engineer"`), Count: -1},
			wantNames: []string{"alice", "bob", "dave"},
			wantTotal: 3,
		},
		{
			name: "filter with conjunction",
			query: scimlib.ListQuery{
				Filter: mustFilter(t, `title eq "Engineer" and userName sw "a"`),
				Count:  -1,
			},
			wantNames: []string{"alice"},
			wantTotal: 1,
		},
		{
			name:      "filter on externalId",
			query:     scimlib.ListQuery{Filter: mustFilter(t, `externalId eq "e1"`), Count: -1},
			wantNames: []string{"alice", "dave"},
			wantTotal: 2,
		},
		{
			name: "descending sort after filter",
			query: scimlib.ListQuery{
				Filter:    mustFilter(t, `title eq "Engineer"`),
				SortBy:    "userName",
				SortOrder: scimlib.SortDescending,
				Count:     -1,
			},
			wantNames: []string{"dave", "bob", "alice"},
			wantTotal: 3,
		},
		{
			name: "sort by displayName",
			query: scimlib.ListQuery{
				Filter: mustFilter(t, `title eq "Manager"`),
				SortBy: "displayName",
				Count:  -1,
			},
			wantNames: []string{"carol", "eve"},
			wantTotal: 2,
		},
		{
			name:      "second page",
			query:     scimlib.ListQuery{StartIndex: 2, Count: 2},
			wantNames: []string{"bob", "carol"},
			wantTotal: 5,
		},
		{
			name:      "start index below one clamps",
			query:     scimlib.ListQuery{StartIndex: 0, Count: 2},
			wantNames: []string{"alice", "bob"},
			wantTotal: 5,
		},
		{
			name:      "negative count returns the rest",
			query:     scimlib.ListQuery{StartIndex: 4, Count: -1},
			wantNames: []string{"dave", "eve"},
			wantTotal: 5,
		},
		{
			name:      "zero count returns an empty page",
			query:     scimlib.ListQuery{StartIndex: 1, Count: 0},
			wantNames: []string{},
			wantTotal: 5,
		},
		{
			name:      "out of range returns an empty page",
			query:     scimlib.ListQuery{StartIndex: 99, Count: 10},
			wantNames: []string{},
			wantTotal: 5,
		},
		{
			name:      "filter without matches",
			query:     scimlib.ListQuery{Filter: mustFilter(t, `title eq "Nobody"`)},
			wantNames: []string{},
			wantTotal: 0,
		},
	}
	for _, test := range tests {
		users, total, err := store.ListUsers(testContext, test.query)
		if err != nil {
			t.Fatalf("%s: %v | %s 失败", test.name, err, test.name)
		}
		if users == nil {
			t.Fatalf("%s returned a nil page | %s 返回 nil 页", test.name, test.name)
		}
		if total != test.wantTotal {
			t.Fatalf("%s total = %d, want %d | %s 总数不符", test.name, total, test.wantTotal, test.name)
		}
		if names := userNameList(users); !slices.Equal(names, test.wantNames) {
			t.Fatalf("%s names = %v, want %v | %s 用户名顺序不符", test.name, names, test.wantNames, test.name)
		}
	}
}

// TestListGroupsFilterSortPage covers filter, sort and pagination semantics for groups.
// | TestListGroupsFilterSortPage 覆盖组的过滤、排序与分页语义。
func TestListGroupsFilterSortPage(t *testing.T) {
	store := newTestStore(t)
	seed := []struct {
		displayName string
		externalID  string
	}{
		{"engineering", "dept-1"},
		{"platform", "dept-2"},
		{"product", "dept-2"},
		{"security", "dept-3"},
	}
	for _, item := range seed {
		group := sampleGroup(item.displayName)
		group.ExternalID = item.externalID
		if _, err := store.CreateGroup(testContext, group); err != nil {
			t.Fatalf("seed group %q: %v | 初始化组 %q 失败", item.displayName, err, item.displayName)
		}
	}
	tests := []struct {
		name      string
		query     scimlib.ListQuery
		wantNames []string
		wantTotal int
	}{
		{
			name:      "default order",
			query:     scimlib.ListQuery{Count: -1},
			wantNames: []string{"engineering", "platform", "product", "security"},
			wantTotal: 4,
		},
		{
			name:      "filter externalId",
			query:     scimlib.ListQuery{Filter: mustFilter(t, `externalId eq "dept-2"`), Count: -1},
			wantNames: []string{"platform", "product"},
			wantTotal: 2,
		},
		{
			name:      "filter prefix",
			query:     scimlib.ListQuery{Filter: mustFilter(t, `displayName sw "p"`), Count: -1},
			wantNames: []string{"platform", "product"},
			wantTotal: 2,
		},
		{
			name:      "descending sort",
			query:     scimlib.ListQuery{SortBy: "displayName", SortOrder: scimlib.SortDescending, Count: -1},
			wantNames: []string{"security", "product", "platform", "engineering"},
			wantTotal: 4,
		},
		{
			name:      "second page",
			query:     scimlib.ListQuery{StartIndex: 2, Count: 2},
			wantNames: []string{"platform", "product"},
			wantTotal: 4,
		},
		{
			name:      "zero count",
			query:     scimlib.ListQuery{Count: 0},
			wantNames: []string{},
			wantTotal: 4,
		},
		{
			name:      "out of range",
			query:     scimlib.ListQuery{StartIndex: 99},
			wantNames: []string{},
			wantTotal: 4,
		},
		{
			name:      "no matches",
			query:     scimlib.ListQuery{Filter: mustFilter(t, `displayName eq "missing"`)},
			wantNames: []string{},
			wantTotal: 0,
		},
	}
	for _, test := range tests {
		groups, total, err := store.ListGroups(testContext, test.query)
		if err != nil {
			t.Fatalf("%s: %v | %s 失败", test.name, err, test.name)
		}
		if groups == nil {
			t.Fatalf("%s returned a nil page | %s 返回 nil 页", test.name, test.name)
		}
		if total != test.wantTotal {
			t.Fatalf("%s total = %d, want %d | %s 总数不符", test.name, total, test.wantTotal, test.name)
		}
		if names := groupNameList(groups); !slices.Equal(names, test.wantNames) {
			t.Fatalf("%s names = %v, want %v | %s 组名顺序不符", test.name, names, test.wantNames, test.name)
		}
	}
}

// TestSecondaryIndexOrder verifies that non-unique indexes return the oldest match and that a
// replacement keeps the original creation position while a recreation appends a new one.
// | TestSecondaryIndexOrder 验证非唯一索引返回最早匹配，替换保持原创建位置，重建追加新位置。
func TestSecondaryIndexOrder(t *testing.T) {
	store := newTestStore(t)
	alice := sampleUser("alice")
	alice.ExternalID = "shared"
	alice.DisplayName = "Shared"
	createdAlice, err := store.CreateUser(testContext, alice)
	if err != nil {
		t.Fatalf("create alice: %v | 创建 alice 失败", err)
	}
	bob := sampleUser("bob")
	bob.ExternalID = "shared"
	bob.DisplayName = "Shared"
	createdBob, err := store.CreateUser(testContext, bob)
	if err != nil {
		t.Fatalf("create bob: %v | 创建 bob 失败", err)
	}
	if oldest, err := store.GetUserByExternalID(testContext, "shared"); err != nil || oldest.ID != createdAlice.ID {
		t.Fatalf("external order = %v | externalId 排序不符", err)
	}
	if oldest, err := store.GetUserByDisplayName(testContext, "shared"); err != nil || oldest.ID != createdAlice.ID {
		t.Fatalf("display order = %v | displayName 排序不符", err)
	}
	moved := createdAlice.Clone()
	moved.ExternalID = "elsewhere"
	if _, err := store.ReplaceUser(testContext, moved); err != nil {
		t.Fatalf("move external: %v | 移动 externalId 失败", err)
	}
	if oldest, err := store.GetUserByExternalID(testContext, "shared"); err != nil || oldest.ID != createdBob.ID {
		t.Fatalf("external order after move = %v | 移动后 externalId 排序不符", err)
	}
	movedBack := moved.Clone()
	movedBack.ExternalID = "shared"
	if _, err := store.ReplaceUser(testContext, movedBack); err != nil {
		t.Fatalf("move external back: %v | 移回 externalId 失败", err)
	}
	if oldest, err := store.GetUserByExternalID(testContext, "shared"); err != nil || oldest.ID != createdAlice.ID {
		t.Fatalf("external order after move back = %v | 移回后 externalId 排序不符", err)
	}
	if err := store.DeleteUser(testContext, createdAlice.ID); err != nil {
		t.Fatalf("delete alice: %v | 删除 alice 失败", err)
	}
	recreated := sampleUser("alice-2")
	recreated.ExternalID = "shared"
	recreated.DisplayName = "Shared"
	createdAgain, err := store.CreateUser(testContext, recreated)
	if err != nil {
		t.Fatalf("recreate: %v | 重建失败", err)
	}
	if oldest, err := store.GetUserByExternalID(testContext, "shared"); err != nil || oldest.ID != createdBob.ID {
		t.Fatalf("external order after recreate = %v | 重建后 externalId 排序不符", err)
	}
	if oldest, err := store.GetUserByDisplayName(testContext, "shared"); err != nil || oldest.ID != createdBob.ID {
		t.Fatalf("display order after recreate = %v | 重建后 displayName 排序不符", err)
	}
	if strings.TrimSpace(createdAgain.ID) == "" {
		t.Fatal("recreated user has no id | 重建用户缺少标识")
	}
}
