package scim_test

import (
	"errors"
	"fmt"
	"sync"
	"testing"

	scimlib "github.com/shibingli/ydx/auth/directory/scim"
)

// TestGroupLifecycle covers creation, lookups, replacement, index reconciliation and deletion.
// | TestGroupLifecycle 覆盖创建、查询、替换、索引协调与删除。
func TestGroupLifecycle(t *testing.T) {
	store := newTestStore(t)
	callerTime := "2000-01-01T00:00:00+08:00"
	group, err := store.CreateGroup(testContext, &scimlib.Group{
		ID:          "group-1",
		ExternalID:  "g-ext-1",
		DisplayName: "Engineering",
		Members: []scimlib.GroupMember{
			{Value: "user-1", Display: "Alice", Type: "User"},
			{Value: "user-2", Display: "Bob", Type: "User"},
		},
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
	if group.ID != "group-1" {
		t.Fatalf("id = %q | 标识未保留", group.ID)
	}
	if group.Meta == nil || group.Meta.ResourceType != scimlib.ResourceTypeNameGroup {
		t.Fatalf("meta = %+v | 元数据不符", group.Meta)
	}
	if group.Meta.Created == callerTime || group.Meta.Location != "" {
		t.Fatalf("caller metadata was kept: %+v | 调用方元数据被保留", group.Meta)
	}
	if len(group.Schemas) != 1 || group.Schemas[0] != scimlib.GroupSchema {
		t.Fatalf("schemas = %v | Schema 不符", group.Schemas)
	}
	got, err := store.GetGroup(testContext, "group-1")
	if err != nil {
		t.Fatalf("get: %v | 读取失败", err)
	}
	if got.DisplayName != "Engineering" || got.ExternalID != "g-ext-1" || len(got.Members) != 2 {
		t.Fatalf("get returned %+v | 读取结果不符", got)
	}
	if byName, err := store.GetGroupByDisplayName(testContext, "  ENGINEERING  "); err != nil || byName.ID != "group-1" {
		t.Fatalf("displayName lookup = %v | 展示名查询不符", err)
	}
	if byExternal, err := store.GetGroupByExternalID(testContext, " G-EXT-1 "); err != nil || byExternal.ID != "group-1" {
		t.Fatalf("externalId lookup = %v | 外部标识查询不符", err)
	}
	replacement := got.Clone()
	replacement.DisplayName = "Platform"
	replacement.ExternalID = ""
	replacement.Members = []scimlib.GroupMember{{Value: "user-2", Display: "Bob", Type: "User"}}
	replaced, err := store.ReplaceGroup(testContext, replacement)
	if err != nil {
		t.Fatalf("replace: %v | 替换失败", err)
	}
	if replaced.Meta.Created != got.Meta.Created {
		t.Fatalf("created = %q, want %q | 创建时间未保留", replaced.Meta.Created, got.Meta.Created)
	}
	if replaced.Meta.Version == got.Meta.Version {
		t.Fatal("replace did not change the version | 替换未改变版本")
	}
	if len(replaced.Members) != 1 || replaced.Members[0].Value != "user-2" {
		t.Fatalf("members = %+v | 成员未替换", replaced.Members)
	}
	if _, err := store.GetGroupByDisplayName(testContext, "engineering"); !errors.Is(err, scimlib.ErrNotFound) {
		t.Fatalf("old displayName still indexed: %v | 旧展示名索引未清理", err)
	}
	if _, err := store.GetGroupByExternalID(testContext, "g-ext-1"); !errors.Is(err, scimlib.ErrNotFound) {
		t.Fatalf("old externalId still indexed: %v | 旧外部标识索引未清理", err)
	}
	if byName, err := store.GetGroupByDisplayName(testContext, "platform"); err != nil || byName.ID != "group-1" {
		t.Fatalf("new displayName lookup = %v | 新展示名查询不符", err)
	}
	if err := store.DeleteGroup(testContext, "group-1"); err != nil {
		t.Fatalf("delete: %v | 删除失败", err)
	}
	if _, err := store.GetGroup(testContext, "group-1"); !errors.Is(err, scimlib.ErrNotFound) {
		t.Fatalf("get after delete = %v | 删除后读取不符", err)
	}
	if _, err := store.GetGroupByDisplayName(testContext, "platform"); !errors.Is(err, scimlib.ErrNotFound) {
		t.Fatalf("displayName after delete = %v | 删除后展示名索引未清理", err)
	}
	if err := store.DeleteGroup(testContext, "group-1"); !errors.Is(err, scimlib.ErrNotFound) {
		t.Fatalf("second delete = %v | 二次删除错误不符", err)
	}
	recreated, err := store.CreateGroup(testContext, &scimlib.Group{DisplayName: "platform"})
	if err != nil {
		t.Fatalf("recreate deleted displayName: %v | 重建已删除展示名失败", err)
	}
	if recreated.ID == "group-1" {
		t.Fatal("recreated group kept the deleted id | 重建组复用了已删除标识")
	}
}

// TestGroupValidation covers invalid values, duplicate identifiers and uniqueness.
// | TestGroupValidation 覆盖非法值、重复标识与唯一性。
func TestGroupValidation(t *testing.T) {
	store := newTestStore(t)
	if _, err := store.CreateGroup(testContext, nil); !errors.Is(err, scimlib.ErrInvalidValue) {
		t.Fatalf("nil group = %v | nil 组错误不符", err)
	}
	if _, err := store.CreateGroup(testContext, &scimlib.Group{DisplayName: "   "}); !errors.Is(err, scimlib.ErrInvalidValue) {
		t.Fatalf("empty displayName = %v | 空展示名错误不符", err)
	}
	if _, err := store.CreateGroup(testContext, &scimlib.Group{
		DisplayName: "Empty Member",
		Members:     []scimlib.GroupMember{{Value: "  "}},
	}); !errors.Is(err, scimlib.ErrInvalidValue) {
		t.Fatalf("empty member = %v | 空成员错误不符", err)
	}
	if _, err := store.CreateGroup(testContext, &scimlib.Group{
		DisplayName: "Duplicate Member",
		Members:     []scimlib.GroupMember{{Value: "u1"}, {Value: "u1"}},
	}); !errors.Is(err, scimlib.ErrInvalidValue) {
		t.Fatalf("duplicate member = %v | 重复成员错误不符", err)
	}
	first, err := store.CreateGroup(testContext, &scimlib.Group{ID: "dup-group", DisplayName: "Engineering"})
	if err != nil {
		t.Fatalf("create first: %v | 创建首个组失败", err)
	}
	if _, err := store.CreateGroup(testContext, &scimlib.Group{ID: "dup-group", DisplayName: "Other"}); !errors.Is(err, scimlib.ErrConflict) {
		t.Fatalf("duplicate id = %v | 重复标识错误不符", err)
	}
	if _, err := store.CreateGroup(testContext, &scimlib.Group{DisplayName: " ENGINEERING "}); !errors.Is(err, scimlib.ErrUniqueness) {
		t.Fatalf("duplicate displayName = %v | 重复展示名错误不符", err)
	}
	if _, err := store.CreateGroup(testContext, &scimlib.Group{DisplayName: "Product"}); err != nil {
		t.Fatalf("create after rejected duplicates: %v | 重复失败后创建组出错", err)
	}
	if _, err := store.ReplaceGroup(testContext, nil); !errors.Is(err, scimlib.ErrInvalidValue) {
		t.Fatalf("replace nil = %v | 替换 nil 错误不符", err)
	}
	if _, err := store.ReplaceGroup(testContext, &scimlib.Group{DisplayName: "Engineering"}); !errors.Is(err, scimlib.ErrInvalidValue) {
		t.Fatalf("replace without id = %v | 缺少标识错误不符", err)
	}
	if _, err := store.ReplaceGroup(testContext, &scimlib.Group{ID: first.ID, DisplayName: " "}); !errors.Is(err, scimlib.ErrInvalidValue) {
		t.Fatalf("replace empty displayName = %v | 替换空展示名错误不符", err)
	}
	if _, err := store.ReplaceGroup(testContext, &scimlib.Group{
		ID:          first.ID,
		DisplayName: "Engineering",
		Members:     []scimlib.GroupMember{{Value: "u1"}, {Value: "u1"}},
	}); !errors.Is(err, scimlib.ErrInvalidValue) {
		t.Fatalf("replace duplicate member = %v | 替换重复成员错误不符", err)
	}
	if _, err := store.ReplaceGroup(testContext, &scimlib.Group{ID: "missing", DisplayName: "Ghost"}); !errors.Is(err, scimlib.ErrNotFound) {
		t.Fatalf("replace missing = %v | 替换不存在组错误不符", err)
	}
	if err := store.DeleteGroup(testContext, "missing"); !errors.Is(err, scimlib.ErrNotFound) {
		t.Fatalf("delete missing = %v | 删除不存在组错误不符", err)
	}
	if _, err := store.GetGroupByDisplayName(testContext, "  "); !errors.Is(err, scimlib.ErrNotFound) {
		t.Fatalf("empty displayName lookup = %v | 空展示名查询错误不符", err)
	}
	if _, err := store.GetGroupByExternalID(testContext, ""); !errors.Is(err, scimlib.ErrNotFound) {
		t.Fatalf("empty externalId lookup = %v | 空外部标识查询错误不符", err)
	}
	if _, err := store.GetGroup(testContext, "missing"); !errors.Is(err, scimlib.ErrNotFound) {
		t.Fatalf("get missing = %v | 读取不存在组错误不符", err)
	}
}

// TestGroupUniquenessExcludesSelf verifies that replacing a group with its own displayName is
// allowed while taking another group's displayName is rejected.
// | TestGroupUniquenessExcludesSelf 验证组以自身展示名替换被允许，而占用他人展示名被拒绝。
func TestGroupUniquenessExcludesSelf(t *testing.T) {
	store := newTestStore(t)
	first := createGroup(t, store, "engineering")
	second := createGroup(t, store, "platform")
	self := first.Clone()
	self.ExternalID = "self"
	if _, err := store.ReplaceGroup(testContext, self); err != nil {
		t.Fatalf("replace with own displayName: %v | 以自身展示名替换失败", err)
	}
	steal := second.Clone()
	steal.DisplayName = "ENGINEERING"
	if _, err := store.ReplaceGroup(testContext, steal); !errors.Is(err, scimlib.ErrUniqueness) {
		t.Fatalf("replace with foreign displayName = %v | 占用他人展示名错误不符", err)
	}
	current, err := store.GetGroup(testContext, second.ID)
	if err != nil || current.DisplayName != "platform" {
		t.Fatalf("failed replace changed the group: %v | 失败的替换改变了组", err)
	}
}

// TestGroupDeepCopyAndVersion verifies deep copies and entity tag changes on replacement.
// | TestGroupDeepCopyAndVersion 验证深拷贝与替换时的实体标签变化。
func TestGroupDeepCopyAndVersion(t *testing.T) {
	store := newTestStore(t)
	created := createGroup(t, store, "engineering")
	created.Members[0].Value = "mutated"
	created.Schemas[0] = "mutated"
	fetched, err := store.GetGroup(testContext, created.ID)
	if err != nil {
		t.Fatalf("get: %v | 读取失败", err)
	}
	if fetched.Members[0].Value != "member-1" || fetched.Schemas[0] != scimlib.GroupSchema {
		t.Fatal("created mutation leaked | 创建返回值修改泄漏")
	}
	firstVersion := fetched.Meta.Version
	replacement := fetched.Clone()
	replacement.DisplayName = "platform"
	replaced, err := store.ReplaceGroup(testContext, replacement)
	if err != nil {
		t.Fatalf("replace: %v | 替换失败", err)
	}
	if replaced.Meta.Version == firstVersion {
		t.Fatal("replace did not change the version | 替换未改变版本")
	}
	fetched.Members[1].Value = "mutated-fetched"
	again, err := store.GetGroup(testContext, created.ID)
	if err != nil {
		t.Fatalf("second get: %v | 二次读取失败", err)
	}
	if again.Members[1].Value == "mutated-fetched" {
		t.Fatal("fetched mutation leaked | 读取返回值修改泄漏")
	}
	listed, _, err := store.ListGroups(testContext, scimlib.ListQuery{Count: -1})
	if err != nil || len(listed) != 1 {
		t.Fatalf("list = %v | 列出组失败", err)
	}
	listed[0].Members[0].Value = "mutated-listed"
	again, err = store.GetGroup(testContext, created.ID)
	if err != nil || again.Members[0].Value == "mutated-listed" {
		t.Fatalf("listed mutation leaked: %v | 列表返回值修改泄漏", err)
	}
}

// TestConcurrentGroupUniqueness proves that two independent stores cannot both create the same
// displayName. | TestConcurrentGroupUniqueness 证明两个独立存储不能同时创建相同 displayName。
func TestConcurrentGroupUniqueness(t *testing.T) {
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
			_, err := store.CreateGroup(testContext, &scimlib.Group{
				ID:          fmt.Sprintf("group-%d", index),
				DisplayName: "shared-group",
				Members:     []scimlib.GroupMember{{Value: fmt.Sprintf("member-%d", index)}},
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
	groups, total, err := first.ListGroups(testContext, scimlib.ListQuery{Count: -1})
	if err != nil || total != 1 || len(groups) != 1 {
		t.Fatalf("list total = %d, groups = %d, err = %v | 并发创建后列表不符", total, len(groups), err)
	}
}

// TestReplaceGroupIfVersion covers conditional group replacement used by atomic bulk rollback.
// | TestReplaceGroupIfVersion 覆盖原子批量回滚使用的条件 Group 替换。
func TestReplaceGroupIfVersion(t *testing.T) {
	store := newTestStore(t)
	group, err := store.CreateGroup(testContext, &scimlib.Group{
		ID:          "group-cas",
		DisplayName: "Original",
	})
	if err != nil {
		t.Fatalf("create: %v", err)
	}
	stale := group.Meta.Version
	group.DisplayName = "Current"
	current, err := store.ReplaceGroup(testContext, group)
	if err != nil {
		t.Fatalf("replace: %v", err)
	}
	staleUpdate := current.Clone()
	staleUpdate.DisplayName = "Stale"
	if _, err := store.ReplaceGroupIfVersion(testContext, staleUpdate, stale); !errors.Is(err, scimlib.ErrPreconditionFailed) {
		t.Fatalf("stale replace = %v, want ErrPreconditionFailed", err)
	}
	unchanged, err := store.GetGroup(testContext, "group-cas")
	if err != nil || unchanged.DisplayName != "Current" {
		t.Fatalf("stale replace changed group: %+v, %v", unchanged, err)
	}
	update := current.Clone()
	update.DisplayName = "Restored"
	restored, err := store.ReplaceGroupIfVersion(testContext, update, current.Meta.Version)
	if err != nil {
		t.Fatalf("conditional replace: %v", err)
	}
	if restored.DisplayName != "Restored" {
		t.Fatalf("displayName = %q", restored.DisplayName)
	}
	if _, err := store.GetGroupByDisplayName(testContext, "Original"); !errors.Is(err, scimlib.ErrNotFound) {
		t.Fatalf("old displayName index = %v", err)
	}
	if got, err := store.GetGroupByDisplayName(testContext, "Restored"); err != nil || got.ID != "group-cas" {
		t.Fatalf("new displayName index = %v, %v", got, err)
	}
}
