package scim_test

import (
	"errors"
	"fmt"
	"strings"
	"sync"
	"testing"

	scimlib "github.com/shibingli/ydx/auth/directory/scim"
)

// TestUserLifecycle covers creation, lookups, replacement, index reconciliation and deletion.
// | TestUserLifecycle 覆盖创建、查询、替换、索引协调与删除。
func TestUserLifecycle(t *testing.T) {
	store := newTestStore(t)
	callerTime := "2000-01-01T00:00:00+08:00"
	user, err := store.CreateUser(testContext, &scimlib.User{
		ID:          "user-1",
		ExternalID:  "ext-1",
		UserName:    "Alice",
		DisplayName: "Alice Doe",
		Meta: &scimlib.Meta{
			ResourceType: "ignored",
			Created:      callerTime,
			LastModified: callerTime,
			Location:     "https://example.test/ignored",
			Version:      `W/"caller"`,
		},
	})
	if err != nil {
		t.Fatalf("create: %v | 创建失败", err)
	}
	if user.ID != "user-1" {
		t.Fatalf("id = %q | 标识未保留", user.ID)
	}
	if user.Meta == nil {
		t.Fatal("meta is nil | 元数据为空")
	}
	if user.Meta.ResourceType != scimlib.ResourceTypeNameUser {
		t.Fatalf("resourceType = %q | 资源类型不符", user.Meta.ResourceType)
	}
	if user.Meta.Created == callerTime || user.Meta.LastModified == callerTime {
		t.Fatal("caller metadata was kept | 调用方元数据被保留")
	}
	if user.Meta.Location != "" {
		t.Fatalf("location = %q, want empty | 位置应为空", user.Meta.Location)
	}
	if user.Meta.Version == "" || user.Meta.Version == `W/"caller"` {
		t.Fatalf("version = %q | 版本未重建", user.Meta.Version)
	}
	if !user.ActiveValue() {
		t.Fatal("active default is false | active 默认值不是 true")
	}
	if len(user.Schemas) != 1 || user.Schemas[0] != scimlib.UserSchema {
		t.Fatalf("schemas = %v | Schema 不符", user.Schemas)
	}
	got, err := store.GetUser(testContext, "user-1")
	if err != nil {
		t.Fatalf("get: %v | 读取失败", err)
	}
	if got.UserName != "Alice" || got.ExternalID != "ext-1" || got.DisplayName != "Alice Doe" {
		t.Fatalf("get returned %+v | 读取结果不符", got)
	}
	if byName, err := store.GetUserByUserName(testContext, "  ALICE  "); err != nil || byName.ID != "user-1" {
		t.Fatalf("userName lookup = %v | 用户名查询不符", err)
	}
	if byExternal, err := store.GetUserByExternalID(testContext, " EXT-1 "); err != nil || byExternal.ID != "user-1" {
		t.Fatalf("externalId lookup = %v | 外部标识查询不符", err)
	}
	if byDisplay, err := store.GetUserByDisplayName(testContext, "alice doe"); err != nil || byDisplay.ID != "user-1" {
		t.Fatalf("displayName lookup = %v | 展示名查询不符", err)
	}
	replacement := got.Clone()
	replacement.UserName = "Alice2"
	replacement.ExternalID = "ext-2"
	replacement.DisplayName = "Alice Two"
	replacement.SetActive(false)
	replaced, err := store.ReplaceUser(testContext, replacement)
	if err != nil {
		t.Fatalf("replace: %v | 替换失败", err)
	}
	if replaced.ID != got.ID {
		t.Fatalf("replace changed id: %q | 替换改变了标识", replaced.ID)
	}
	if replaced.Meta.Created != got.Meta.Created {
		t.Fatalf("created = %q, want %q | 创建时间未保留", replaced.Meta.Created, got.Meta.Created)
	}
	if replaced.Meta.Version == got.Meta.Version {
		t.Fatal("replace did not change the version | 替换未改变版本")
	}
	if replaced.ActiveValue() {
		t.Fatal("replace did not store active=false | 替换未保存 active=false")
	}
	if _, err := store.GetUserByUserName(testContext, "alice"); !errors.Is(err, scimlib.ErrNotFound) {
		t.Fatalf("old userName still indexed: %v | 旧用户名索引未清理", err)
	}
	if _, err := store.GetUserByExternalID(testContext, "ext-1"); !errors.Is(err, scimlib.ErrNotFound) {
		t.Fatalf("old externalId still indexed: %v | 旧外部标识索引未清理", err)
	}
	if _, err := store.GetUserByDisplayName(testContext, "alice doe"); !errors.Is(err, scimlib.ErrNotFound) {
		t.Fatalf("old displayName still indexed: %v | 旧展示名索引未清理", err)
	}
	if byName, err := store.GetUserByUserName(testContext, "alice2"); err != nil || byName.ID != got.ID {
		t.Fatalf("new userName lookup = %v | 新用户名查询不符", err)
	}
	if byExternal, err := store.GetUserByExternalID(testContext, "ext-2"); err != nil || byExternal.ID != got.ID {
		t.Fatalf("new externalId lookup = %v | 新外部标识查询不符", err)
	}
	if byDisplay, err := store.GetUserByDisplayName(testContext, "alice two"); err != nil || byDisplay.ID != got.ID {
		t.Fatalf("new displayName lookup = %v | 新展示名查询不符", err)
	}
	if err := store.DeleteUser(testContext, got.ID); err != nil {
		t.Fatalf("delete: %v | 删除失败", err)
	}
	if _, err := store.GetUser(testContext, got.ID); !errors.Is(err, scimlib.ErrNotFound) {
		t.Fatalf("get after delete = %v | 删除后读取不符", err)
	}
	if _, err := store.GetUserByUserName(testContext, "alice2"); !errors.Is(err, scimlib.ErrNotFound) {
		t.Fatalf("userName after delete = %v | 删除后用户名索引未清理", err)
	}
	if err := store.DeleteUser(testContext, got.ID); !errors.Is(err, scimlib.ErrNotFound) {
		t.Fatalf("second delete = %v | 二次删除错误不符", err)
	}
	recreated, err := store.CreateUser(testContext, &scimlib.User{UserName: "alice2"})
	if err != nil {
		t.Fatalf("recreate deleted userName: %v | 重建已删除用户名失败", err)
	}
	if recreated.ID == got.ID {
		t.Fatal("recreated user kept the deleted id | 重建用户复用了已删除标识")
	}
}

// TestUserValidation covers invalid values, duplicate identifiers and uniqueness.
// | TestUserValidation 覆盖非法值、重复标识与唯一性。
func TestUserValidation(t *testing.T) {
	store := newTestStore(t)
	if _, err := store.CreateUser(testContext, nil); !errors.Is(err, scimlib.ErrInvalidValue) {
		t.Fatalf("nil user = %v | nil 用户错误不符", err)
	}
	if _, err := store.CreateUser(testContext, &scimlib.User{UserName: "   "}); !errors.Is(err, scimlib.ErrInvalidValue) {
		t.Fatalf("empty userName = %v | 空用户名错误不符", err)
	}
	first, err := store.CreateUser(testContext, &scimlib.User{ID: "dup-id", UserName: "Alice"})
	if err != nil {
		t.Fatalf("create first: %v | 创建首个用户失败", err)
	}
	if _, err := store.CreateUser(testContext, &scimlib.User{ID: "dup-id", UserName: "Other"}); !errors.Is(err, scimlib.ErrConflict) {
		t.Fatalf("duplicate id = %v | 重复标识错误不符", err)
	}
	if _, err := store.CreateUser(testContext, &scimlib.User{UserName: "  ALICE "}); !errors.Is(err, scimlib.ErrUniqueness) {
		t.Fatalf("duplicate userName = %v | 重复用户名错误不符", err)
	}
	if _, err := store.CreateUser(testContext, &scimlib.User{UserName: "Bob"}); err != nil {
		t.Fatalf("create after rejected duplicates: %v | 重复失败后创建用户出错", err)
	}
	if _, err := store.ReplaceUser(testContext, nil); !errors.Is(err, scimlib.ErrInvalidValue) {
		t.Fatalf("replace nil = %v | 替换 nil 错误不符", err)
	}
	if _, err := store.ReplaceUser(testContext, &scimlib.User{UserName: "Alice"}); !errors.Is(err, scimlib.ErrInvalidValue) {
		t.Fatalf("replace without id = %v | 缺少标识错误不符", err)
	}
	if _, err := store.ReplaceUser(testContext, &scimlib.User{ID: first.ID, UserName: " "}); !errors.Is(err, scimlib.ErrInvalidValue) {
		t.Fatalf("replace empty userName = %v | 替换空用户名错误不符", err)
	}
	if _, err := store.ReplaceUser(testContext, &scimlib.User{ID: "missing", UserName: "Ghost"}); !errors.Is(err, scimlib.ErrNotFound) {
		t.Fatalf("replace missing = %v | 替换不存在用户错误不符", err)
	}
	if err := store.DeleteUser(testContext, "missing"); !errors.Is(err, scimlib.ErrNotFound) {
		t.Fatalf("delete missing = %v | 删除不存在用户错误不符", err)
	}
	if _, err := store.GetUserByUserName(testContext, "  "); !errors.Is(err, scimlib.ErrNotFound) {
		t.Fatalf("empty userName lookup = %v | 空用户名查询错误不符", err)
	}
	if _, err := store.GetUserByExternalID(testContext, ""); !errors.Is(err, scimlib.ErrNotFound) {
		t.Fatalf("empty externalId lookup = %v | 空外部标识查询错误不符", err)
	}
	if _, err := store.GetUserByDisplayName(testContext, ""); !errors.Is(err, scimlib.ErrNotFound) {
		t.Fatalf("empty displayName lookup = %v | 空展示名查询错误不符", err)
	}
}

// TestUserUniquenessExcludesSelf verifies that replacing a user with its own userName is allowed
// while taking another user's userName is rejected. | TestUserUniquenessExcludesSelf 验证用户以自身
// userName 替换被允许，而占用他人 userName 被拒绝。
func TestUserUniquenessExcludesSelf(t *testing.T) {
	store := newTestStore(t)
	alice := createUser(t, store, "alice")
	bob := createUser(t, store, "bob")
	self := alice.Clone()
	self.DisplayName = "Alice Self"
	if _, err := store.ReplaceUser(testContext, self); err != nil {
		t.Fatalf("replace with own userName: %v | 以自身用户名替换失败", err)
	}
	steal := bob.Clone()
	steal.UserName = "ALICE"
	if _, err := store.ReplaceUser(testContext, steal); !errors.Is(err, scimlib.ErrUniqueness) {
		t.Fatalf("replace with foreign userName = %v | 占用他人用户名错误不符", err)
	}
	if current, err := store.GetUser(testContext, bob.ID); err != nil || current.UserName != "bob" {
		t.Fatalf("failed replace changed bob: %v | 失败的替换改变了 bob", err)
	}
}

// TestUserDeepCopy verifies that returned resources never share mutable state with the store.
// | TestUserDeepCopy 验证返回资源绝不与存储共享可变状态。
func TestUserDeepCopy(t *testing.T) {
	store := newTestStore(t)
	created := createUser(t, store, "alice")
	created.Name.GivenName = "Mutated Created"
	created.Emails[0].Value = "mutated-created@example.test"
	created.Schemas[0] = "mutated"
	created.SetActive(false)
	fetched, err := store.GetUser(testContext, created.ID)
	if err != nil {
		t.Fatalf("get: %v | 读取失败", err)
	}
	if fetched.Name.GivenName != "Given" {
		t.Fatalf("created mutation leaked: %q | 创建返回值修改泄漏", fetched.Name.GivenName)
	}
	if fetched.Emails[0].Value == "mutated-created@example.test" {
		t.Fatal("created email mutation leaked | 创建返回值邮箱修改泄漏")
	}
	if fetched.Schemas[0] != scimlib.UserSchema || !fetched.ActiveValue() {
		t.Fatal("created schema or active mutation leaked | 创建返回值 Schema 或 active 修改泄漏")
	}
	fetched.Name.GivenName = "Mutated Fetched"
	fetched.Emails[0].Value = "mutated-fetched@example.test"
	fetched.SetActive(false)
	again, err := store.GetUser(testContext, created.ID)
	if err != nil {
		t.Fatalf("second get: %v | 二次读取失败", err)
	}
	if again.Name.GivenName != "Given" || again.Emails[0].Value != "alice@example.test" || !again.ActiveValue() {
		t.Fatalf("fetched mutation leaked: %+v | 读取返回值修改泄漏", again)
	}
	listed, _, err := store.ListUsers(testContext, scimlib.ListQuery{Count: -1})
	if err != nil || len(listed) != 1 {
		t.Fatalf("list = %v | 列出用户失败", err)
	}
	listed[0].Name.GivenName = "Mutated Listed"
	again, err = store.GetUser(testContext, created.ID)
	if err != nil || again.Name.GivenName != "Given" {
		t.Fatalf("listed mutation leaked: %v | 列表返回值修改泄漏", err)
	}
}

// TestUserVersionAndConditionalReplace covers entity tag allocation and If-Match semantics.
// | TestUserVersionAndConditionalReplace 覆盖实体标签分配与 If-Match 语义。
func TestUserVersionAndConditionalReplace(t *testing.T) {
	store := newTestStore(t)
	user := createUser(t, store, "alice")
	firstVersion := user.Meta.Version
	if firstVersion == "" {
		t.Fatal("create returned no version | 创建未返回版本")
	}
	updated := user.Clone()
	updated.DisplayName = "Alice One"
	replaced, err := store.ReplaceUser(testContext, updated)
	if err != nil {
		t.Fatalf("replace: %v | 替换失败", err)
	}
	secondVersion := replaced.Meta.Version
	if secondVersion == firstVersion {
		t.Fatal("replace did not change the version | 替换未改变版本")
	}
	stale := replaced.Clone()
	stale.DisplayName = "Stale"
	if _, err := store.ReplaceUserIfVersion(testContext, stale, firstVersion); !errors.Is(err, scimlib.ErrPreconditionFailed) {
		t.Fatalf("stale expected version = %v | 过期版本错误不符", err)
	}
	current, err := store.GetUser(testContext, replaced.ID)
	if err != nil {
		t.Fatalf("get after rejected replace: %v | 拒绝替换后读取失败", err)
	}
	if current.DisplayName != "Alice One" || current.Meta.Version != secondVersion {
		t.Fatalf("rejected replace changed state: %+v | 拒绝的替换改变了状态", current)
	}
	quoted := `W/"` + strings.TrimSuffix(strings.TrimPrefix(secondVersion, `W/"`), `"`) + `"`
	tagged := current.Clone()
	tagged.DisplayName = "Alice Two"
	if _, err := store.ReplaceUserIfVersion(testContext, tagged, quoted); err != nil {
		t.Fatalf("quoted If-Match: %v | 带引号 If-Match 失败", err)
	}
	current, err = store.GetUser(testContext, tagged.ID)
	if err != nil {
		t.Fatalf("get after quoted replace: %v | 带引号替换后读取失败", err)
	}
	bare := current.Meta.Version
	bare = strings.TrimSuffix(strings.TrimPrefix(bare, `W/"`), `"`)
	unconditional := current.Clone()
	unconditional.DisplayName = "Alice Three"
	if _, err := store.ReplaceUserIfVersion(testContext, unconditional, bare); err != nil {
		t.Fatalf("bare If-Match: %v | 裸标签 If-Match 失败", err)
	}
	current, err = store.GetUser(testContext, unconditional.ID)
	if err != nil {
		t.Fatalf("get after bare replace: %v | 裸标签替换后读取失败", err)
	}
	if current.DisplayName != "Alice Three" {
		t.Fatalf("displayName = %q | 展示名不符", current.DisplayName)
	}
	last := current.Clone()
	last.DisplayName = "Alice Four"
	if _, err := store.ReplaceUserIfVersion(testContext, last, ""); err != nil {
		t.Fatalf("empty expected version: %v | 空期望版本失败", err)
	}
}

// TestConcurrentUserUniqueness proves that two independent stores cannot both create the same
// userName. | TestConcurrentUserUniqueness 证明两个独立存储不能同时创建相同 userName。
func TestConcurrentUserUniqueness(t *testing.T) {
	first, second := newPair(t)
	const workers = 10
	var wait sync.WaitGroup
	results := make(chan error, workers)
	for i := 0; i < workers; i++ {
		wait.Add(1)
		go func(index int) {
			defer wait.Done()
			store := first
			if index%2 == 1 {
				store = second
			}
			_, err := store.CreateUser(testContext, &scimlib.User{
				ID:       fmt.Sprintf("user-%d", index),
				UserName: "shared-user",
			})
			results <- err
		}(i)
	}
	wait.Wait()
	close(results)
	successes := 0
	for err := range results {
		switch {
		case err == nil:
			successes++
		case errors.Is(err, scimlib.ErrUniqueness):
		default:
			t.Fatalf("unexpected create error: %v | 意外的创建错误", err)
		}
	}
	if successes != 1 {
		t.Fatalf("successes = %d, want 1 | 成功次数应为 1", successes)
	}
	users, total, err := first.ListUsers(testContext, scimlib.ListQuery{Count: -1})
	if err != nil || total != 1 || len(users) != 1 {
		t.Fatalf("list total = %d, users = %d, err = %v | 并发创建后列表不符", total, len(users), err)
	}
}

// TestConcurrentConditionalReplace proves that only one If-Match replacement wins.
// | TestConcurrentConditionalReplace 证明只有一个 If-Match 替换成功。
func TestConcurrentConditionalReplace(t *testing.T) {
	first, second := newPair(t)
	user := createUser(t, first, "alice")
	version := user.Meta.Version
	const workers = 8
	var wait sync.WaitGroup
	results := make(chan error, workers)
	for i := 0; i < workers; i++ {
		wait.Add(1)
		go func(index int) {
			defer wait.Done()
			store := first
			if index%2 == 1 {
				store = second
			}
			replacement := user.Clone()
			replacement.DisplayName = fmt.Sprintf("Alice %d", index)
			_, err := store.ReplaceUserIfVersion(testContext, replacement, version)
			results <- err
		}(i)
	}
	wait.Wait()
	close(results)
	successes := 0
	for err := range results {
		switch {
		case err == nil:
			successes++
		case errors.Is(err, scimlib.ErrPreconditionFailed):
		default:
			t.Fatalf("unexpected replace error: %v | 意外的替换错误", err)
		}
	}
	if successes != 1 {
		t.Fatalf("successes = %d, want 1 | 成功次数应为 1", successes)
	}
	current, err := first.GetUser(testContext, user.ID)
	if err != nil {
		t.Fatalf("get after concurrent replace: %v | 并发替换后读取失败", err)
	}
	if current.Meta.Version == version {
		t.Fatal("version did not change | 版本未变化")
	}
}

// TestStoreLevelUndoPrimitives exercises the store operations that the SCIM bulk undo log
// depends on: retrieving a snapshot, replacing it, recreating a deleted resource with its
// original identifier, and detecting a concurrent change through the entity tag.
// | TestStoreLevelUndoPrimitives 演练 SCIM 批量撤销日志依赖的存储操作：读取快照、替换快照、用原标识
// 重建已删除资源，以及通过实体标签发现并发变更。
func TestStoreLevelUndoPrimitives(t *testing.T) {
	store := newTestStore(t)
	user := createUser(t, store, "alice")
	group := createGroup(t, store, "engineering")
	userSnapshot, err := store.GetUser(testContext, user.ID)
	if err != nil {
		t.Fatalf("snapshot user: %v | 读取用户快照失败", err)
	}
	groupSnapshot, err := store.GetGroup(testContext, group.ID)
	if err != nil {
		t.Fatalf("snapshot group: %v | 读取组快照失败", err)
	}
	changedUser := userSnapshot.Clone()
	changedUser.DisplayName = "Changed"
	appliedUser, err := store.ReplaceUser(testContext, changedUser)
	if err != nil {
		t.Fatalf("mutate user: %v | 修改用户失败", err)
	}
	changedGroup := groupSnapshot.Clone()
	changedGroup.DisplayName = "changed-group"
	if _, err := store.ReplaceGroup(testContext, changedGroup); err != nil {
		t.Fatalf("mutate group: %v | 修改组失败", err)
	}
	restoredUser := userSnapshot.Clone()
	restoredUser.Password = ""
	if _, err := store.ReplaceUserIfVersion(testContext, restoredUser, appliedUser.Meta.Version); err != nil {
		t.Fatalf("restore user: %v | 恢复用户失败", err)
	}
	if _, err := store.ReplaceGroup(testContext, groupSnapshot); err != nil {
		t.Fatalf("restore group: %v | 恢复组失败", err)
	}
	backUser, err := store.GetUser(testContext, user.ID)
	if err != nil || backUser.DisplayName != userSnapshot.DisplayName {
		t.Fatalf("restored user = %+v, err = %v | 恢复后的用户不符", backUser, err)
	}
	backGroup, err := store.GetGroup(testContext, group.ID)
	if err != nil || backGroup.DisplayName != groupSnapshot.DisplayName {
		t.Fatalf("restored group = %+v, err = %v | 恢复后的组不符", backGroup, err)
	}
	if _, err := store.ReplaceUserIfVersion(testContext, restoredUser, appliedUser.Meta.Version); !errors.Is(err, scimlib.ErrPreconditionFailed) {
		t.Fatalf("stale restore = %v | 过期恢复错误不符", err)
	}
	if err := store.DeleteUser(testContext, user.ID); err != nil {
		t.Fatalf("delete user: %v | 删除用户失败", err)
	}
	if _, err := store.GetUser(testContext, user.ID); !errors.Is(err, scimlib.ErrNotFound) {
		t.Fatalf("recreate precondition missing: %v | 重建前置条件不符", err)
	}
	recreated := userSnapshot.Clone()
	recreated.Password = ""
	if _, err := store.CreateUser(testContext, recreated); err != nil {
		t.Fatalf("recreate user: %v | 重建用户失败", err)
	}
	backUser, err = store.GetUser(testContext, user.ID)
	if err != nil || backUser.DisplayName != userSnapshot.DisplayName {
		t.Fatalf("recreated user = %+v, err = %v | 重建后的用户不符", backUser, err)
	}
	if err := store.DeleteGroup(testContext, group.ID); err != nil {
		t.Fatalf("delete group: %v | 删除组失败", err)
	}
	recreatedGroup := groupSnapshot.Clone()
	if _, err := store.CreateGroup(testContext, recreatedGroup); err != nil {
		t.Fatalf("recreate group: %v | 重建组失败", err)
	}
	backGroup, err = store.GetGroup(testContext, group.ID)
	if err != nil || backGroup.DisplayName != groupSnapshot.DisplayName {
		t.Fatalf("recreated group = %+v, err = %v | 重建后的组不符", backGroup, err)
	}
}
