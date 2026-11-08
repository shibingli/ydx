package scim_test

import (
	"context"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/alicebob/miniredis/v2"
	goredis "github.com/redis/go-redis/v9"

	scimlib "github.com/shibingli/ydx/auth/directory/scim"
	scimstore "github.com/shibingli/ydx/authstore/scim"
)

// testContext is the background context shared by tests. | testContext 是测试共享的后台上下文。
var testContext = context.Background()

// newStoreOn creates one independent client against server and returns a store using prefix.
// | newStoreOn 针对 server 创建独立客户端，并返回使用 prefix 的存储。
func newStoreOn(t *testing.T, server *miniredis.Miniredis, prefix string) *scimstore.Store {
	t.Helper()
	client := goredis.NewClient(&goredis.Options{Addr: server.Addr()})
	t.Cleanup(func() {
		_ = client.Close()
	})
	store, err := scimstore.New(client, scimstore.Options{KeyPrefix: prefix})
	if err != nil {
		t.Fatalf("new store: %v | 创建存储失败", err)
	}
	return store
}

// newTestStore starts a private miniredis and returns a store. | newTestStore 启动私有 miniredis 并返回存储。
func newTestStore(t *testing.T) *scimstore.Store {
	t.Helper()
	return newStoreOn(t, miniredis.RunT(t), "")
}

// newPair returns two stores sharing one miniredis, which models two application instances.
// | newPair 返回共享同一 miniredis 的两个存储，用于模拟两个应用实例。
func newPair(t *testing.T) (*scimstore.Store, *scimstore.Store) {
	t.Helper()
	server := miniredis.RunT(t)
	return newStoreOn(t, server, ""), newStoreOn(t, server, "")
}

// sampleUser returns a User with nested attributes. | sampleUser 返回带嵌套属性的 User。
func sampleUser(userName string) *scimlib.User {
	return &scimlib.User{
		UserName: userName,
		Name: &scimlib.Name{
			Formatted:  "Formatted " + userName,
			FamilyName: "Family",
			GivenName:  "Given",
		},
		Emails: []scimlib.MultiValue{{Value: userName + "@example.test", Type: "work", Primary: true}},
	}
}

// sampleGroup returns a Group with two members. | sampleGroup 返回带两个成员的 Group。
func sampleGroup(displayName string) *scimlib.Group {
	return &scimlib.Group{
		DisplayName: displayName,
		Members: []scimlib.GroupMember{
			{Value: "member-1", Display: "Member One", Type: "User"},
			{Value: "member-2", Display: "Member Two", Type: "User"},
		},
	}
}

// createUser stores sampleUser and fails the test on error. | createUser 保存 sampleUser，出错时终止测试。
func createUser(t *testing.T, store *scimstore.Store, userName string) *scimlib.User {
	t.Helper()
	user, err := store.CreateUser(testContext, sampleUser(userName))
	if err != nil {
		t.Fatalf("create user %q: %v | 创建用户 %q 失败", userName, err, userName)
	}
	return user
}

// createGroup stores sampleGroup and fails the test on error. | createGroup 保存 sampleGroup，出错时终止测试。
func createGroup(t *testing.T, store *scimstore.Store, displayName string) *scimlib.Group {
	t.Helper()
	group, err := store.CreateGroup(testContext, sampleGroup(displayName))
	if err != nil {
		t.Fatalf("create group %q: %v | 创建组 %q 失败", displayName, err, displayName)
	}
	return group
}

// TestNewValidation covers constructor validation, the default prefix and interface conformance.
// | TestNewValidation 覆盖构造校验、默认前缀与接口一致性。
func TestNewValidation(t *testing.T) {
	if scimstore.DefaultKeyPrefix != "ydx:authstore:scim:" {
		t.Fatalf("DefaultKeyPrefix = %q | 默认前缀不正确", scimstore.DefaultKeyPrefix)
	}
	if _, err := scimstore.New(nil, scimstore.Options{}); !errors.Is(err, scimlib.ErrInvalidConfig) {
		t.Fatalf("nil client error = %v, want ErrInvalidConfig | nil 客户端错误不符", err)
	}
	server := miniredis.RunT(t)
	client := goredis.NewClient(&goredis.Options{Addr: server.Addr()})
	t.Cleanup(func() {
		_ = client.Close()
	})
	for _, prefix := range []string{"bad{prefix", "bad}prefix", "bad{}prefix"} {
		if _, err := scimstore.New(client, scimstore.Options{KeyPrefix: prefix}); !errors.Is(err, scimlib.ErrInvalidConfig) {
			t.Fatalf("prefix %q error = %v, want ErrInvalidConfig | 前缀 %q 错误不符", prefix, err, prefix)
		}
	}
	store, err := scimstore.New(client, scimstore.Options{})
	if err != nil {
		t.Fatalf("new store: %v | 创建存储失败", err)
	}
	var _ scimlib.Store = store
	var _ scimlib.UserVersionReplacer = store
	closed := goredis.NewClient(&goredis.Options{Addr: "127.0.0.1:1", MaxRetries: -1})
	t.Cleanup(func() {
		_ = closed.Close()
	})
	if _, err := scimstore.New(closed, scimstore.Options{}); err != nil {
		t.Fatalf("New dialed: %v | New 不应连接网络", err)
	}
}

// TestPrefixIsolationAndKeyLayout runs two stores with distinct prefixes on one server and
// verifies that every key carries the prefix and the single cluster hash tag. It also covers
// length-prefixed segments with names and identifiers containing a colon.
// | TestPrefixIsolationAndKeyLayout 在同一服务器上运行两个不同前缀的存储，验证每个键都携带前缀与唯一
// 集群哈希标签，并覆盖名称与标识包含冒号时的长度前缀段。
func TestPrefixIsolationAndKeyLayout(t *testing.T) {
	server := miniredis.RunT(t)
	first := newStoreOn(t, server, "one:")
	second := newStoreOn(t, server, "two:")
	createUser(t, first, "alice")
	createGroup(t, first, "engineering")
	if _, err := second.GetUserByUserName(testContext, "alice"); !errors.Is(err, scimlib.ErrNotFound) {
		t.Fatalf("second prefix saw first user: %v | 第二前缀看到了第一前缀的用户", err)
	}
	if _, err := second.GetGroupByDisplayName(testContext, "engineering"); !errors.Is(err, scimlib.ErrNotFound) {
		t.Fatalf("second prefix saw first group: %v | 第二前缀看到了第一前缀的组", err)
	}
	if _, total, err := second.ListUsers(testContext, scimlib.ListQuery{}); err != nil || total != 0 {
		t.Fatalf("second ListUsers total = %d, err = %v | 第二前缀用户列表不符", total, err)
	}
	if _, total, err := second.ListGroups(testContext, scimlib.ListQuery{}); err != nil || total != 0 {
		t.Fatalf("second ListGroups total = %d, err = %v | 第二前缀组列表不符", total, err)
	}
	keys := server.Keys()
	if len(keys) == 0 {
		t.Fatal("no keys written | 未写入任何键")
	}
	for _, key := range keys {
		if !strings.HasPrefix(key, "one:") {
			t.Fatalf("key %q lacks the configured prefix | 键 %q 缺少配置前缀", key, key)
		}
		if !strings.Contains(key, "{authstore:scim}") {
			t.Fatalf("key %q lacks the cluster hash tag | 键 %q 缺少集群哈希标签", key, key)
		}
		if strings.Contains(key, "two:") {
			t.Fatalf("key %q belongs to the wrong prefix | 键 %q 属于错误前缀", key, key)
		}
	}
	colonUser, err := first.CreateUser(testContext, &scimlib.User{ID: "x:y", UserName: "a:b"})
	if err != nil {
		t.Fatalf("create colon user: %v | 创建含冒号用户失败", err)
	}
	plainUser, err := first.CreateUser(testContext, &scimlib.User{ID: "x", UserName: "a"})
	if err != nil {
		t.Fatalf("create plain user: %v | 创建普通用户失败", err)
	}
	gotColon, err := first.GetUser(testContext, "x:y")
	if err != nil || gotColon.ID != colonUser.ID {
		t.Fatalf("colon id lookup = %v | 含冒号标识查询不符", err)
	}
	gotPlain, err := first.GetUser(testContext, "x")
	if err != nil || gotPlain.ID != plainUser.ID {
		t.Fatalf("plain id lookup = %v | 普通标识查询不符", err)
	}
	if byName, err := first.GetUserByUserName(testContext, "a:b"); err != nil || byName.ID != "x:y" {
		t.Fatalf("colon userName lookup = %v | 含冒号用户名查询不符", err)
	}
	if byName, err := first.GetUserByUserName(testContext, "a"); err != nil || byName.ID != "x" {
		t.Fatalf("plain userName lookup = %v | 普通用户名查询不符", err)
	}
}

// TestTwoInstancesShareState covers cross-instance reads, writes, versions and deletes.
// | TestTwoInstancesShareState 覆盖跨实例读写、版本与删除。
func TestTwoInstancesShareState(t *testing.T) {
	first, second := newPair(t)
	user := createUser(t, first, "alice")
	got, err := second.GetUser(testContext, user.ID)
	if err != nil {
		t.Fatalf("cross-instance get: %v | 跨实例读取失败", err)
	}
	if got.Meta == nil || got.Meta.Version != user.Meta.Version {
		t.Fatalf("version = %v, want %v | 版本不符", got.Meta, user.Meta)
	}
	if byName, err := second.GetUserByUserName(testContext, " ALICE "); err != nil || byName.ID != user.ID {
		t.Fatalf("cross-instance userName lookup = %v | 跨实例用户名查询不符", err)
	}
	replacement := got.Clone()
	replacement.DisplayName = "Alice Updated"
	updated, err := second.ReplaceUser(testContext, replacement)
	if err != nil {
		t.Fatalf("cross-instance replace: %v | 跨实例替换失败", err)
	}
	if updated.Meta.Version == user.Meta.Version {
		t.Fatal("replace did not allocate a new version | 替换未分配新版本")
	}
	back, err := first.GetUser(testContext, user.ID)
	if err != nil || back.DisplayName != "Alice Updated" {
		t.Fatalf("read after cross-instance replace = %v | 跨实例替换后读取不符", err)
	}
	group := createGroup(t, first, "engineering")
	replacedGroup := group.Clone()
	replacedGroup.DisplayName = "platform"
	if _, err := second.ReplaceGroup(testContext, replacedGroup); err != nil {
		t.Fatalf("cross-instance group replace: %v | 跨实例组替换失败", err)
	}
	if byName, err := first.GetGroupByDisplayName(testContext, "platform"); err != nil || byName.ID != group.ID {
		t.Fatalf("group lookup after cross-instance replace = %v | 组替换后查询不符", err)
	}
	if err := first.DeleteUser(testContext, user.ID); err != nil {
		t.Fatalf("delete: %v | 删除失败", err)
	}
	if _, err := second.GetUser(testContext, user.ID); !errors.Is(err, scimlib.ErrNotFound) {
		t.Fatalf("cross-instance read after delete = %v | 删除后跨实例读取不符", err)
	}
	if err := second.DeleteGroup(testContext, group.ID); err != nil {
		t.Fatalf("cross-instance group delete: %v | 跨实例组删除失败", err)
	}
	if _, err := first.GetGroup(testContext, group.ID); !errors.Is(err, scimlib.ErrNotFound) {
		t.Fatalf("read after cross-instance group delete = %v | 组删除后读取不符", err)
	}
}

// TestBackendErrorsAreRedacted verifies that every store method maps a closed backend to
// scim.ErrStoreUnavailable without exposing an address.
// | TestBackendErrorsAreRedacted 验证每个存储方法都把已关闭后端映射为 scim.ErrStoreUnavailable 且
// 不暴露地址。
func TestBackendErrorsAreRedacted(t *testing.T) {
	server := miniredis.RunT(t)
	client := goredis.NewClient(&goredis.Options{Addr: server.Addr(), MaxRetries: -1})
	store, err := scimstore.New(client, scimstore.Options{})
	if err != nil {
		t.Fatalf("new store: %v | 创建存储失败", err)
	}
	if err := client.Close(); err != nil {
		t.Fatalf("close client: %v | 关闭客户端失败", err)
	}
	baseUser := sampleUser("alice")
	baseUser.ID = "u1"
	baseGroup := sampleGroup("engineering")
	baseGroup.ID = "g1"
	operations := []struct {
		name string
		call func() error
	}{
		{"users.create", func() error { _, err := store.CreateUser(testContext, baseUser); return err }},
		{"users.get", func() error { _, err := store.GetUser(testContext, "u1"); return err }},
		{"users.get-by-username", func() error { _, err := store.GetUserByUserName(testContext, "alice"); return err }},
		{"users.get-by-external", func() error { _, err := store.GetUserByExternalID(testContext, "ext"); return err }},
		{"users.get-by-display", func() error { _, err := store.GetUserByDisplayName(testContext, "Alice"); return err }},
		{"users.replace", func() error { _, err := store.ReplaceUser(testContext, baseUser); return err }},
		{"users.replace-if-version", func() error {
			_, err := store.ReplaceUserIfVersion(testContext, baseUser, "v")
			return err
		}},
		{"users.delete", func() error { return store.DeleteUser(testContext, "u1") }},
		{"users.list", func() error { _, _, err := store.ListUsers(testContext, scimlib.ListQuery{}); return err }},
		{"groups.create", func() error { _, err := store.CreateGroup(testContext, baseGroup); return err }},
		{"groups.get", func() error { _, err := store.GetGroup(testContext, "g1"); return err }},
		{"groups.get-by-display", func() error { _, err := store.GetGroupByDisplayName(testContext, "engineering"); return err }},
		{"groups.get-by-external", func() error { _, err := store.GetGroupByExternalID(testContext, "ext"); return err }},
		{"groups.replace", func() error { _, err := store.ReplaceGroup(testContext, baseGroup); return err }},
		{"groups.delete", func() error { return store.DeleteGroup(testContext, "g1") }},
		{"groups.list", func() error { _, _, err := store.ListGroups(testContext, scimlib.ListQuery{}); return err }},
	}
	for _, operation := range operations {
		err := operation.call()
		if !errors.Is(err, scimlib.ErrStoreUnavailable) {
			t.Fatalf("%s error = %v, want ErrStoreUnavailable | %s 错误未映射为存储不可用", operation.name, err, operation.name)
		}
		if err != nil && (strings.Contains(err.Error(), "127.0.0.1") || strings.Contains(err.Error(), ":1")) {
			t.Fatalf("%s leaked the address: %v | %s 错误泄露了地址", operation.name, err, operation.name)
		}
	}
	unreachable := goredis.NewClient(&goredis.Options{
		Addr:        "127.0.0.1:1",
		MaxRetries:  -1,
		DialTimeout: 50 * time.Millisecond,
	})
	t.Cleanup(func() {
		_ = unreachable.Close()
	})
	unreachableStore, err := scimstore.New(unreachable, scimstore.Options{})
	if err != nil {
		t.Fatalf("new unreachable store: %v | 创建不可达存储失败", err)
	}
	_, err = unreachableStore.GetUser(testContext, "u1")
	if !errors.Is(err, scimlib.ErrStoreUnavailable) {
		t.Fatalf("unreachable error = %v, want ErrStoreUnavailable | 不可达错误未映射", err)
	}
	if strings.Contains(err.Error(), "127.0.0.1") || strings.Contains(err.Error(), ":1") {
		t.Fatalf("unreachable error leaked the address: %v | 不可达错误泄露了地址", err)
	}
}

// TestContextCancellation verifies that every method reports a canceled context as
// scim.ErrStoreUnavailable while errors.Is still finds context.Canceled.
// | TestContextCancellation 验证每个方法把取消的上下文报告为 scim.ErrStoreUnavailable，同时 errors.Is
// 仍能找到 context.Canceled。
func TestContextCancellation(t *testing.T) {
	store := newTestStore(t)
	canceled, cancel := context.WithCancel(testContext)
	cancel()
	baseUser := sampleUser("alice")
	baseUser.ID = "u1"
	baseGroup := sampleGroup("engineering")
	baseGroup.ID = "g1"
	operations := []struct {
		name string
		call func() error
	}{
		{"users.create", func() error { _, err := store.CreateUser(canceled, baseUser); return err }},
		{"users.get", func() error { _, err := store.GetUser(canceled, "u1"); return err }},
		{"users.get-by-username", func() error { _, err := store.GetUserByUserName(canceled, "alice"); return err }},
		{"users.get-by-external", func() error { _, err := store.GetUserByExternalID(canceled, "ext"); return err }},
		{"users.get-by-display", func() error { _, err := store.GetUserByDisplayName(canceled, "Alice"); return err }},
		{"users.replace", func() error { _, err := store.ReplaceUser(canceled, baseUser); return err }},
		{"users.delete", func() error { return store.DeleteUser(canceled, "u1") }},
		{"users.list", func() error { _, _, err := store.ListUsers(canceled, scimlib.ListQuery{}); return err }},
		{"groups.create", func() error { _, err := store.CreateGroup(canceled, baseGroup); return err }},
		{"groups.get", func() error { _, err := store.GetGroup(canceled, "g1"); return err }},
		{"groups.get-by-display", func() error { _, err := store.GetGroupByDisplayName(canceled, "engineering"); return err }},
		{"groups.get-by-external", func() error { _, err := store.GetGroupByExternalID(canceled, "ext"); return err }},
		{"groups.replace", func() error { _, err := store.ReplaceGroup(canceled, baseGroup); return err }},
		{"groups.delete", func() error { return store.DeleteGroup(canceled, "g1") }},
		{"groups.list", func() error { _, _, err := store.ListGroups(canceled, scimlib.ListQuery{}); return err }},
	}
	for _, operation := range operations {
		err := operation.call()
		if !errors.Is(err, context.Canceled) {
			t.Fatalf("%s error = %v, want context.Canceled | %s 未返回上下文取消", operation.name, err, operation.name)
		}
		if !errors.Is(err, scimlib.ErrStoreUnavailable) {
			t.Fatalf("%s error = %v, want ErrStoreUnavailable | %s 错误未映射为存储不可用", operation.name, err, operation.name)
		}
	}
}

// TestMetadataIsUTC verifies that metadata timestamps are UTC RFC3339 and entity tags have the
// weak form. | TestMetadataIsUTC 验证元数据时间戳是 UTC RFC3339 且实体标签为弱形式。
func TestMetadataIsUTC(t *testing.T) {
	store := newTestStore(t)
	user := createUser(t, store, "alice")
	group := createGroup(t, store, "engineering")
	for _, meta := range []*scimlib.Meta{user.Meta, group.Meta} {
		if meta == nil {
			t.Fatal("metadata is nil | 元数据为空")
		}
		if !strings.HasPrefix(meta.Version, `W/"`) || !strings.HasSuffix(meta.Version, `"`) {
			t.Fatalf("version %q is not a weak entity tag | 版本 %q 不是弱实体标签", meta.Version, meta.Version)
		}
		if !strings.HasSuffix(meta.Created, "Z") || !strings.HasSuffix(meta.LastModified, "Z") {
			t.Fatalf("timestamps are not UTC: %q / %q | 时间戳不是 UTC", meta.Created, meta.LastModified)
		}
		created, err := time.Parse(time.RFC3339, meta.Created)
		if err != nil {
			t.Fatalf("parse created: %v | 解析创建时间失败", err)
		}
		if created.Location() != time.UTC {
			t.Fatalf("created location = %v | 创建时间位置不符", created.Location())
		}
	}
	if user.Meta.ResourceType != scimlib.ResourceTypeNameUser {
		t.Fatalf("user resourceType = %q | 用户资源类型不符", user.Meta.ResourceType)
	}
	if group.Meta.ResourceType != scimlib.ResourceTypeNameGroup {
		t.Fatalf("group resourceType = %q | 组资源类型不符", group.Meta.ResourceType)
	}
}
