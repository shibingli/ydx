package kms_test

import (
	"bytes"
	"context"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/alicebob/miniredis/v2"
	goredis "github.com/redis/go-redis/v9"

	authkms "github.com/shibingli/ydx/auth/keymgmt/kms"
	kmsstore "github.com/shibingli/ydx/authstore/kms"
)

// testContext is the background context shared by tests. | testContext 是测试共享的后台上下文。
var testContext = context.Background()

// testTime returns a fixed UTC instant. | testTime 返回固定的 UTC 时刻。
func testTime(year int, month time.Month, day, hour, minute, second int) time.Time {
	return time.Date(year, month, day, hour, minute, second, 0, time.UTC)
}

// newStore starts a private miniredis and returns a store using prefix.
// | newStore 启动私有 miniredis 并返回使用 prefix 的存储。
func newStore(t *testing.T, prefix string) *kmsstore.Store {
	t.Helper()
	return newStoreOn(t, miniredis.RunT(t), prefix)
}

// newStoreOn creates one independent client against an existing miniredis.
// | newStoreOn 针对已有 miniredis 创建一个独立客户端。
func newStoreOn(t *testing.T, server *miniredis.Miniredis, prefix string) *kmsstore.Store {
	t.Helper()
	client := goredis.NewClient(&goredis.Options{Addr: server.Addr()})
	t.Cleanup(func() {
		_ = client.Close()
	})
	store, err := kmsstore.New(client, kmsstore.Options{KeyPrefix: prefix})
	if err != nil {
		t.Fatalf("new store: %v | 创建存储失败", err)
	}
	return store
}

// newPair returns two independent stores sharing one miniredis, which models two application
// instances. | newPair 返回共享同一 miniredis 的两套独立存储，用于模拟两个应用实例。
func newPair(t *testing.T) (*kmsstore.Store, *kmsstore.Store) {
	t.Helper()
	server := miniredis.RunT(t)
	return newStoreOn(t, server, ""), newStoreOn(t, server, "")
}

// sampleKey returns a populated AES key. | sampleKey 返回字段完整的 AES 密钥。
func sampleKey(id, alias string, created time.Time) *authkms.Key {
	return &authkms.Key{
		ID:             id,
		Alias:          alias,
		Type:           authkms.KeyTypeAES,
		Algorithm:      "AES-256-GCM",
		Bits:           256,
		Version:        1,
		State:          authkms.StateActive,
		UsageMask:      authkms.MaskEncrypt | authkms.MaskDecrypt,
		CreatedAt:      created,
		ActivatedAt:    created,
		Material:       []byte{1, 2, 3, 4},
		PublicMaterial: []byte{8, 9},
		Metadata:       map[string]string{"team": "crypto"},
		Tags:           []string{"prod"},
		Exportable:     true,
	}
}

// TestNewValidation covers constructor validation and the default prefix.
// | TestNewValidation 覆盖构造校验与默认前缀。
func TestNewValidation(t *testing.T) {
	if kmsstore.DefaultKeyPrefix != "ydx:authstore:kms:" {
		t.Fatalf("DefaultKeyPrefix = %q | 默认前缀不正确", kmsstore.DefaultKeyPrefix)
	}
	if _, err := kmsstore.New(nil, kmsstore.Options{}); !errors.Is(err, authkms.ErrInvalidConfig) {
		t.Fatalf("nil client error = %v, want ErrInvalidConfig | nil 客户端错误不符", err)
	}
	server := miniredis.RunT(t)
	client := goredis.NewClient(&goredis.Options{Addr: server.Addr()})
	t.Cleanup(func() {
		_ = client.Close()
	})
	if _, err := kmsstore.New(client, kmsstore.Options{KeyPrefix: "bad{prefix"}); !errors.Is(err, authkms.ErrInvalidConfig) {
		t.Fatalf("brace prefix error = %v, want ErrInvalidConfig | 花括号前缀错误不符", err)
	}
	store, err := kmsstore.New(client, kmsstore.Options{})
	if err != nil {
		t.Fatalf("new store: %v | 创建存储失败", err)
	}
	var port authkms.Store = store
	if port == nil {
		t.Fatal("store does not implement kms.Store | 存储未实现 kms.Store")
	}
}

// TestNewDoesNotDial verifies that New performs no network round trip.
// | TestNewDoesNotDial 验证 New 不进行网络往返。
func TestNewDoesNotDial(t *testing.T) {
	client := goredis.NewClient(&goredis.Options{Addr: "127.0.0.1:1", MaxRetries: -1})
	t.Cleanup(func() {
		_ = client.Close()
	})
	if _, err := kmsstore.New(client, kmsstore.Options{}); err != nil {
		t.Fatalf("New dialed: %v | New 不应连接网络", err)
	}
}

// TestCreateGetDeepCopyAndUTC covers creation, revision assignment, deep copies and UTC
// normalization. | TestCreateGetDeepCopyAndUTC 覆盖创建、修订号赋值、深拷贝与 UTC 规范化。
func TestCreateGetDeepCopyAndUTC(t *testing.T) {
	store := newStore(t, "")
	created := time.Date(2026, time.January, 2, 3, 4, 5, 0, time.FixedZone("UTC+8", 8*3600))
	key := sampleKey("k1", "alias-1", created)
	version := &authkms.KeyVersion{
		Version:        1,
		State:          authkms.StateActive,
		Material:       []byte{5, 6},
		PublicMaterial: []byte{7},
		CreatedAt:      created,
	}
	key.Versions = []*authkms.KeyVersion{version}
	if err := store.CreateKey(testContext, key); err != nil {
		t.Fatalf("CreateKey: %v | 创建失败", err)
	}
	key.Material[0] = 99
	key.Metadata["team"] = "mutated"
	key.Tags[0] = "mutated"
	version.Material[0] = 99
	got, err := store.GetKey(testContext, "k1")
	if err != nil {
		t.Fatalf("GetKey: %v | 读取失败", err)
	}
	if got.Revision != 1 {
		t.Fatalf("revision = %d, want 1 | 修订号不符", got.Revision)
	}
	if !bytes.Equal(got.Material, []byte{1, 2, 3, 4}) {
		t.Fatalf("material = %v | 材料不是创建时的深拷贝", got.Material)
	}
	if !bytes.Equal(got.PublicMaterial, []byte{8, 9}) {
		t.Fatalf("public material = %v | 公钥材料不符", got.PublicMaterial)
	}
	if got.Metadata["team"] != "crypto" || got.Tags[0] != "prod" {
		t.Fatalf("metadata/tags changed: %+v | 元数据或标签被输入修改污染", got)
	}
	if len(got.Versions) != 1 || !bytes.Equal(got.Versions[0].Material, []byte{5, 6}) {
		t.Fatalf("versions = %+v | 版本材料不符", got.Versions)
	}
	if !got.CreatedAt.Equal(created) || got.CreatedAt.Location() != time.UTC {
		t.Fatalf("createdAt = %v (%v) | 创建时间未规范化为 UTC", got.CreatedAt, got.CreatedAt.Location())
	}
	if !got.ActivatedAt.Equal(created) || got.ActivatedAt.Location() != time.UTC {
		t.Fatalf("activatedAt = %v | 激活时间未规范化为 UTC", got.ActivatedAt)
	}
	got.Material[0] = 42
	got.Metadata["team"] = "changed"
	got.Tags[0] = "changed"
	got.Versions[0].Material[0] = 42
	again, err := store.GetKey(testContext, "k1")
	if err != nil {
		t.Fatalf("GetKey again: %v | 再次读取失败", err)
	}
	if again.Material[0] != 1 || again.Metadata["team"] != "crypto" || again.Tags[0] != "prod" ||
		again.Versions[0].Material[0] != 5 {
		t.Fatal("store returned shared data | 存储返回了共享数据")
	}
	if err := store.CreateKey(testContext, sampleKey("k1", "other", created)); !errors.Is(err, authkms.ErrKeyExists) {
		t.Fatalf("duplicate CreateKey err = %v, want ErrKeyExists | 重复创建错误不符", err)
	}
	if err := store.CreateKey(testContext, sampleKey("k2", "alias-1", created)); !errors.Is(err, authkms.ErrAliasExists) {
		t.Fatalf("duplicate alias err = %v, want ErrAliasExists | 重复别名错误不符", err)
	}
}

// TestKeyLifecycleAndAliases covers updates, conflicts, alias reconciliation and deletion.
// | TestKeyLifecycleAndAliases 覆盖更新、冲突、别名协调与删除。
func TestKeyLifecycleAndAliases(t *testing.T) {
	store := newStore(t, "")
	base := testTime(2026, time.February, 1, 0, 0, 0)
	if err := store.CreateKey(testContext, sampleKey("k1", "old", base)); err != nil {
		t.Fatalf("CreateKey k1: %v | 创建 k1 失败", err)
	}
	if err := store.CreateKey(testContext, sampleKey("k2", "", base)); err != nil {
		t.Fatalf("CreateKey k2: %v | 创建 k2 失败", err)
	}
	if id, err := store.ResolveAlias(testContext, "old"); err != nil || id != "k1" {
		t.Fatalf("ResolveAlias = %q, %v | 别名解析失败", id, err)
	}
	if err := store.SetAlias(testContext, "new", "k1"); err != nil {
		t.Fatalf("SetAlias: %v | 设置别名失败", err)
	}
	if id, err := store.ResolveAlias(testContext, "new"); err != nil || id != "k1" {
		t.Fatalf("ResolveAlias new = %q, %v | 新别名解析失败", id, err)
	}
	if err := store.SetAlias(testContext, "old", "k2"); !errors.Is(err, authkms.ErrAliasExists) {
		t.Fatalf("conflicting SetAlias err = %v, want ErrAliasExists | 别名冲突错误不符", err)
	}
	if err := store.SetAlias(testContext, "", "k1"); !errors.Is(err, authkms.ErrInvalidRequest) {
		t.Fatalf("empty SetAlias err = %v, want ErrInvalidRequest | 空别名错误不符", err)
	}
	if err := store.SetAlias(testContext, "x", "missing"); !errors.Is(err, authkms.ErrNotFound) {
		t.Fatalf("missing SetAlias err = %v, want ErrNotFound | 缺失密钥错误不符", err)
	}
	if err := store.DeleteAlias(testContext, "missing"); !errors.Is(err, authkms.ErrAliasNotFound) {
		t.Fatalf("DeleteAlias err = %v, want ErrAliasNotFound | 删除缺失别名错误不符", err)
	}

	first, err := store.GetKey(testContext, "k1")
	if err != nil {
		t.Fatalf("GetKey: %v | 读取失败", err)
	}
	second, err := store.GetKey(testContext, "k1")
	if err != nil {
		t.Fatalf("GetKey second: %v | 再次读取失败", err)
	}
	first.Metadata = map[string]string{"owner": "first"}
	if err := store.UpdateKey(testContext, first); err != nil {
		t.Fatalf("UpdateKey: %v | 更新失败", err)
	}
	stored, err := store.GetKey(testContext, "k1")
	if err != nil {
		t.Fatalf("GetKey after update: %v | 更新后读取失败", err)
	}
	if stored.Revision != 2 || stored.Metadata["owner"] != "first" {
		t.Fatalf("stored = %+v | 更新未生效", stored)
	}
	second.Metadata = map[string]string{"owner": "second"}
	if err := store.UpdateKey(testContext, second); !errors.Is(err, authkms.ErrConflict) {
		t.Fatalf("stale UpdateKey err = %v, want ErrConflict | 过期更新错误不符", err)
	}
	if err := store.UpdateKey(testContext, sampleKey("missing", "", base)); !errors.Is(err, authkms.ErrNotFound) {
		t.Fatalf("missing UpdateKey err = %v, want ErrNotFound | 缺失更新错误不符", err)
	}
	if err := store.UpdateKey(testContext, nil); !errors.Is(err, authkms.ErrInvalidRequest) {
		t.Fatalf("nil UpdateKey err = %v, want ErrInvalidRequest | nil 更新错误不符", err)
	}

	stored.Alias = "renamed"
	if err := store.UpdateKey(testContext, stored); err != nil {
		t.Fatalf("UpdateKey alias: %v | 更新别名失败", err)
	}
	if _, err := store.ResolveAlias(testContext, "old"); !errors.Is(err, authkms.ErrAliasNotFound) {
		t.Fatalf("old alias survived update: %v | 旧别名未被移除", err)
	}
	if id, err := store.ResolveAlias(testContext, "renamed"); err != nil || id != "k1" {
		t.Fatalf("renamed alias = %q, %v | 新主别名未生效", id, err)
	}
	if id, err := store.ResolveAlias(testContext, "new"); err != nil || id != "k1" {
		t.Fatalf("secondary alias = %q, %v | 次要别名被更新破坏", id, err)
	}
	if err := store.DeleteKey(testContext, "k1"); err != nil {
		t.Fatalf("DeleteKey: %v | 删除失败", err)
	}
	if _, err := store.GetKey(testContext, "k1"); !errors.Is(err, authkms.ErrNotFound) {
		t.Fatalf("GetKey after delete err = %v, want ErrNotFound | 删除后仍可读取", err)
	}
	for _, alias := range []string{"new", "renamed"} {
		if _, err := store.ResolveAlias(testContext, alias); !errors.Is(err, authkms.ErrAliasNotFound) {
			t.Fatalf("alias %[1]q survived deletion: %[2]v | 别名 %[1]q 在删除后仍存在", alias, err)
		}
	}
	if err := store.DeleteKey(testContext, "k1"); !errors.Is(err, authkms.ErrNotFound) {
		t.Fatalf("second DeleteKey err = %v, want ErrNotFound | 二次删除错误不符", err)
	}
}

// TestPrimaryAliasLifecycle covers direct primary alias cleanup and the unchanged-alias update
// path. | TestPrimaryAliasLifecycle 覆盖主别名的直接清理与别名未变的更新路径。
func TestPrimaryAliasLifecycle(t *testing.T) {
	store := newStore(t, "")
	base := testTime(2026, time.February, 2, 0, 0, 0)
	if err := store.CreateKey(testContext, sampleKey("k1", "primary", base)); err != nil {
		t.Fatalf("CreateKey: %v | 创建失败", err)
	}
	if _, err := store.GetKey(testContext, "k1"); err != nil {
		t.Fatalf("GetKey: %v | 读取失败", err)
	}
	if err := store.DeleteKey(testContext, "k1"); err != nil {
		t.Fatalf("DeleteKey: %v | 删除失败", err)
	}
	if _, err := store.ResolveAlias(testContext, "primary"); !errors.Is(err, authkms.ErrAliasNotFound) {
		t.Fatalf("primary alias survived direct deletion: %v | 主别名在直接删除后仍存在", err)
	}

	if err := store.CreateKey(testContext, sampleKey("k2", "kept", base)); err != nil {
		t.Fatalf("CreateKey k2: %v | 创建 k2 失败", err)
	}
	if err := store.DeleteAlias(testContext, "kept"); err != nil {
		t.Fatalf("DeleteAlias: %v | 删除别名失败", err)
	}
	key, err := store.GetKey(testContext, "k2")
	if err != nil {
		t.Fatalf("GetKey k2: %v | 读取 k2 失败", err)
	}
	key.Metadata = map[string]string{"updated": "yes"}
	if err := store.UpdateKey(testContext, key); err != nil {
		t.Fatalf("UpdateKey with unchanged alias: %v | 别名未变的更新失败", err)
	}
	if _, err := store.ResolveAlias(testContext, "kept"); !errors.Is(err, authkms.ErrAliasNotFound) {
		t.Fatalf("unchanged update resurrected a deleted alias: %v | 别名未变的更新复活了已删别名", err)
	}
	updated, err := store.GetKey(testContext, "k2")
	if err != nil || updated.Metadata["updated"] != "yes" || updated.Revision != 2 {
		t.Fatalf("updated = %+v, %v | 更新结果不符", updated, err)
	}
}

// TestListKeysFiltersAndPagination covers every filter field, ordering and paging.
// | TestListKeysFiltersAndPagination 覆盖全部过滤字段、排序与分页。
func TestListKeysFiltersAndPagination(t *testing.T) {
	store := newStore(t, "")
	base := testTime(2026, time.March, 1, 0, 0, 0)
	one := sampleKey("a1", "alpha", base)
	two := sampleKey("b2", "beta", base.Add(time.Second))
	two.State = authkms.StateDeactivated
	two.Type = authkms.KeyTypeSM4
	two.UsageMask = authkms.MaskSign | authkms.MaskVerify
	two.Tags = []string{"stage"}
	two.Metadata = map[string]string{"team": "platform"}
	three := sampleKey("c3", "gamma", base.Add(2*time.Second))
	three.ParentID = "a1"
	four := sampleKey("d4", "delta", base.Add(2*time.Second))
	four.Tags = []string{"stage"}
	for _, key := range []*authkms.Key{one, two, three, four} {
		if err := store.CreateKey(testContext, key); err != nil {
			t.Fatalf("CreateKey %s: %v | 创建 %s 失败", key.ID, err, key.ID)
		}
	}
	assertIDs := func(name string, filter authkms.KeyFilter, want ...string) {
		t.Helper()
		keys, err := store.ListKeys(testContext, filter)
		if err != nil {
			t.Fatalf("%s: %v | %s 列表失败", name, err, name)
		}
		if len(keys) != len(want) {
			t.Fatalf("%s returned %d keys, want %d | %s 返回数量不符", name, len(keys), len(want), name)
		}
		for i, id := range want {
			if keys[i].ID != id {
				t.Fatalf("%s[%d] = %q, want %q | %s 顺序不符", name, i, keys[i].ID, id, name)
			}
		}
	}
	assertIDs("all", authkms.KeyFilter{}, "a1", "b2", "c3", "d4")
	assertIDs("tag", authkms.KeyFilter{Tag: "prod"}, "a1", "c3")
	assertIDs("query-alias", authkms.KeyFilter{Query: "ALPHA"}, "a1")
	assertIDs("query-metadata", authkms.KeyFilter{Query: "PLATFORM"}, "b2")
	assertIDs("state-type", authkms.KeyFilter{State: authkms.StateDeactivated, Type: authkms.KeyTypeSM4}, "b2")
	assertIDs("usage", authkms.KeyFilter{Usage: authkms.UsageSign}, "b2")
	assertIDs("parent", authkms.KeyFilter{ParentID: "a1"}, "c3")
	assertIDs("limit", authkms.KeyFilter{Limit: 2}, "a1", "b2")
	assertIDs("offset", authkms.KeyFilter{Offset: 1, Limit: 2}, "b2", "c3")
	assertIDs("combined", authkms.KeyFilter{State: authkms.StateActive, Tag: "prod"}, "a1", "c3")
	assertIDs("none", authkms.KeyFilter{Query: "no-such-value"})
	empty, err := store.ListKeys(testContext, authkms.KeyFilter{Offset: 99})
	if err != nil {
		t.Fatalf("offset past end: %v | 越界分页失败", err)
	}
	if empty == nil || len(empty) != 0 {
		t.Fatalf("offset past end = %#v, want empty non-nil slice | 越界分页未返回空切片", empty)
	}
	keys, err := store.ListKeys(testContext, authkms.KeyFilter{})
	if err != nil || len(keys) != 4 {
		t.Fatalf("list = %d, %v | 列表数量不符", len(keys), err)
	}
	if !bytes.Equal(keys[0].Material, []byte{1, 2, 3, 4}) {
		t.Fatal("ListKeys dropped key material | ListKeys 丢失了密钥材料")
	}
}

// TestVersionLifecycle covers append ordering, uniqueness, material copies and deletion.
// | TestVersionLifecycle 覆盖追加顺序、唯一性、材料拷贝与删除。
func TestVersionLifecycle(t *testing.T) {
	store := newStore(t, "")
	base := testTime(2026, time.April, 1, 0, 0, 0)
	if err := store.CreateKey(testContext, sampleKey("k1", "", base)); err != nil {
		t.Fatalf("CreateKey: %v | 创建失败", err)
	}
	for _, number := range []uint32{3, 1, 2} {
		version := &authkms.KeyVersion{
			Version: number,
			State:   authkms.StateActive,
			Material: []byte{
				byte(number), 0xAA,
			},
			CreatedAt: base.Add(time.Duration(number) * time.Minute),
		}
		if err := store.SaveVersion(testContext, "k1", version); err != nil {
			t.Fatalf("SaveVersion %d: %v | 保存版本 %d 失败", number, err, number)
		}
		version.Material[0] = 0xFF
	}
	versions, err := store.ListVersions(testContext, "k1")
	if err != nil {
		t.Fatalf("ListVersions: %v | 列出版本失败", err)
	}
	if len(versions) != 3 || versions[0].Version != 1 || versions[1].Version != 2 || versions[2].Version != 3 {
		t.Fatalf("versions = %+v | 版本顺序不符", versions)
	}
	if !bytes.Equal(versions[0].Material, []byte{1, 0xAA}) {
		t.Fatalf("version material = %v | 版本材料不是深拷贝", versions[0].Material)
	}
	versions[0].Material[0] = 0xEE
	again, err := store.GetVersion(testContext, "k1", 1)
	if err != nil {
		t.Fatalf("GetVersion: %v | 读取版本失败", err)
	}
	if again.Material[0] != 1 {
		t.Fatal("store returned shared version material | 存储返回了共享版本材料")
	}
	if !again.CreatedAt.Equal(base.Add(time.Minute)) || again.CreatedAt.Location() != time.UTC {
		t.Fatalf("version time = %v | 版本时间未规范化为 UTC", again.CreatedAt)
	}
	if err := store.SaveVersion(testContext, "k1", &authkms.KeyVersion{Version: 2}); !errors.Is(err, authkms.ErrVersionExists) {
		t.Fatalf("duplicate SaveVersion err = %v, want ErrVersionExists | 重复版本错误不符", err)
	}
	if err := store.SaveVersion(testContext, "missing", &authkms.KeyVersion{Version: 1}); !errors.Is(err, authkms.ErrNotFound) {
		t.Fatalf("missing SaveVersion err = %v, want ErrNotFound | 缺失密钥版本错误不符", err)
	}
	if err := store.SaveVersion(testContext, "k1", nil); !errors.Is(err, authkms.ErrInvalidRequest) {
		t.Fatalf("nil SaveVersion err = %v, want ErrInvalidRequest | nil 版本错误不符", err)
	}
	if _, err := store.GetVersion(testContext, "k1", 9); !errors.Is(err, authkms.ErrVersionNotFound) {
		t.Fatalf("GetVersion err = %v, want ErrVersionNotFound | 缺失版本错误不符", err)
	}
	if _, err := store.GetVersion(testContext, "missing", 1); !errors.Is(err, authkms.ErrNotFound) {
		t.Fatalf("GetVersion missing key err = %v, want ErrNotFound | 缺失密钥读取版本错误不符", err)
	}
	if _, err := store.ListVersions(testContext, "missing"); !errors.Is(err, authkms.ErrNotFound) {
		t.Fatalf("ListVersions missing key err = %v, want ErrNotFound | 缺失密钥列出版本错误不符", err)
	}
	stored, err := store.GetKey(testContext, "k1")
	if err != nil {
		t.Fatalf("GetKey: %v | 读取失败", err)
	}
	if stored.Revision != 4 {
		t.Fatalf("revision = %d, want 4 | 保存版本未递增修订号", stored.Revision)
	}
	if len(stored.Versions) != 3 {
		t.Fatalf("GetKey versions = %d, want 3 | GetKey 未返回版本", len(stored.Versions))
	}
	if err := store.DeleteKey(testContext, "k1"); err != nil {
		t.Fatalf("DeleteKey: %v | 删除失败", err)
	}
	if _, err := store.GetVersion(testContext, "k1", 1); !errors.Is(err, authkms.ErrNotFound) {
		t.Fatalf("GetVersion after delete err = %v, want ErrNotFound | 删除后版本仍存在", err)
	}
}

// TestAuditLifecycle covers append, filtering, ordering, pagination and deep copies.
// | TestAuditLifecycle 覆盖追加、过滤、排序、分页与深拷贝。
func TestAuditLifecycle(t *testing.T) {
	first, second := newPair(t)
	base := testTime(2026, time.May, 1, 0, 0, 0)
	for i := 0; i < 5; i++ {
		event := &authkms.AuditEvent{
			Operation: authkms.OperationEncrypt,
			KeyID:     "k1",
			Actor:     "alice",
			Outcome:   authkms.OutcomeSuccess,
			Detail:    map[string]string{"index": string(rune('0' + i))},
			At:        base.Add(time.Duration(i) * time.Second),
		}
		store := first
		if i%2 == 1 {
			store = second
		}
		if err := store.AppendAudit(testContext, event); err != nil {
			t.Fatalf("AppendAudit(%d): %v | 追加审计 %d 失败", i, err, i)
		}
		if event.ID != "" {
			t.Fatal("AppendAudit mutated the caller event ID | AppendAudit 修改了调用方事件 ID")
		}
	}
	page, err := first.ListAudit(testContext, authkms.AuditFilter{Limit: 2, Offset: 1, Descending: true})
	if err != nil {
		t.Fatalf("ListAudit: %v | 列出审计失败", err)
	}
	if len(page) != 2 || page[0].Detail["index"] != "3" || page[1].Detail["index"] != "2" {
		t.Fatalf("page = %+v | 审计分页不符", page)
	}
	if page[0].ID == "" || page[0].At.IsZero() {
		t.Fatal("AppendAudit did not assign ID and At | AppendAudit 未赋值 ID 与 At")
	}
	page[0].Detail["index"] = "mutated"
	again, err := first.ListAudit(testContext, authkms.AuditFilter{Limit: 2, Offset: 1, Descending: true})
	if err != nil {
		t.Fatalf("ListAudit again: %v | 再次列出审计失败", err)
	}
	if again[0].Detail["index"] != "3" {
		t.Fatal("returned audit event shares the store map | 返回的审计事件与存储共享映射")
	}
	filtered, err := second.ListAudit(testContext, authkms.AuditFilter{Actor: "alice", Outcome: authkms.OutcomeSuccess})
	if err != nil || len(filtered) != 5 {
		t.Fatalf("filtered audits = %d, %v | 过滤审计数量不符", len(filtered), err)
	}
	since, err := first.ListAudit(testContext, authkms.AuditFilter{Since: base.Add(3 * time.Second)})
	if err != nil || len(since) != 2 {
		t.Fatalf("since audits = %d, %v | 时间下界过滤不符", len(since), err)
	}
	until, err := first.ListAudit(testContext, authkms.AuditFilter{Until: base.Add(time.Second)})
	if err != nil || len(until) != 2 {
		t.Fatalf("until audits = %d, %v | 时间上界过滤不符", len(until), err)
	}
	if err := first.AppendAudit(testContext, nil); !errors.Is(err, authkms.ErrInvalidRequest) {
		t.Fatalf("nil AppendAudit err = %v, want ErrInvalidRequest | nil 审计事件错误不符", err)
	}
	empty, err := first.ListAudit(testContext, authkms.AuditFilter{Offset: 99})
	if err != nil || empty == nil || len(empty) != 0 {
		t.Fatalf("offset past end = %#v, %v | 越界审计分页不符", empty, err)
	}
}

// TestTwoInstancesShareState covers cross-instance reads and writes.
// | TestTwoInstancesShareState 覆盖跨实例读写。
func TestTwoInstancesShareState(t *testing.T) {
	first, second := newPair(t)
	base := testTime(2026, time.June, 1, 0, 0, 0)
	if err := first.CreateKey(testContext, sampleKey("k1", "shared", base)); err != nil {
		t.Fatalf("CreateKey: %v | 创建失败", err)
	}
	got, err := second.GetKey(testContext, "k1")
	if err != nil {
		t.Fatalf("cross-instance GetKey: %v | 跨实例读取失败", err)
	}
	if got.ID != "k1" || got.Revision != 1 {
		t.Fatalf("got = %+v | 跨实例记录不符", got)
	}
	if id, err := second.ResolveAlias(testContext, "shared"); err != nil || id != "k1" {
		t.Fatalf("cross-instance alias = %q, %v | 跨实例别名失败", id, err)
	}
	got.Metadata["owner"] = "second"
	if err := second.UpdateKey(testContext, got); err != nil {
		t.Fatalf("cross-instance UpdateKey: %v | 跨实例更新失败", err)
	}
	back, err := first.GetKey(testContext, "k1")
	if err != nil {
		t.Fatalf("GetKey after cross update: %v | 跨实例更新后读取失败", err)
	}
	if back.Revision != 2 || back.Metadata["owner"] != "second" {
		t.Fatalf("back = %+v | 跨实例更新未同步", back)
	}
	if err := second.SaveVersion(testContext, "k1", &authkms.KeyVersion{Version: 2, Material: []byte{2}}); err != nil {
		t.Fatalf("cross-instance SaveVersion: %v | 跨实例保存版本失败", err)
	}
	versions, err := first.ListVersions(testContext, "k1")
	if err != nil || len(versions) != 1 || versions[0].Version != 2 {
		t.Fatalf("cross-instance versions = %+v, %v | 跨实例版本失败", versions, err)
	}
}

// TestPrefixIsolation runs two stores with distinct prefixes on one server.
// | TestPrefixIsolation 在同一服务器上运行两套不同前缀的存储。
func TestPrefixIsolation(t *testing.T) {
	server := miniredis.RunT(t)
	first := newStoreOn(t, server, "one:")
	second := newStoreOn(t, server, "two:")
	base := testTime(2026, time.July, 1, 0, 0, 0)
	if err := first.CreateKey(testContext, sampleKey("k1", "shared", base)); err != nil {
		t.Fatalf("create first: %v | 第一套创建失败", err)
	}
	if _, err := second.GetKey(testContext, "k1"); !errors.Is(err, authkms.ErrNotFound) {
		t.Fatalf("second prefix saw first key: %v | 第二前缀看到了第一前缀的密钥", err)
	}
	if err := second.CreateKey(testContext, sampleKey("k1", "shared", base)); err != nil {
		t.Fatalf("create second: %v | 第二套创建失败", err)
	}
	if id, err := second.ResolveAlias(testContext, "shared"); err != nil || id != "k1" {
		t.Fatalf("second alias = %q, %v | 第二套别名失败", id, err)
	}
}

// TestKeysShareClusterHashTag verifies that every stored key carries exactly one shared hash tag.
// | TestKeysShareClusterHashTag 验证每个已存键恰好携带一个共享哈希标签。
func TestKeysShareClusterHashTag(t *testing.T) {
	server := miniredis.RunT(t)
	store := newStoreOn(t, server, "one:")
	base := testTime(2026, time.August, 1, 0, 0, 0)
	if err := store.CreateKey(testContext, sampleKey("k1", "alias", base)); err != nil {
		t.Fatalf("CreateKey: %v | 创建失败", err)
	}
	if err := store.SaveVersion(testContext, "k1", &authkms.KeyVersion{Version: 2}); err != nil {
		t.Fatalf("SaveVersion: %v | 保存版本失败", err)
	}
	if err := store.SetAlias(testContext, "extra", "k1"); err != nil {
		t.Fatalf("SetAlias: %v | 设置别名失败", err)
	}
	if err := store.AppendAudit(testContext, &authkms.AuditEvent{Operation: authkms.OperationKeyCreate}); err != nil {
		t.Fatalf("AppendAudit: %v | 追加审计失败", err)
	}
	stored := server.Keys()
	if len(stored) == 0 {
		t.Fatal("no keys were stored | 没有已存键")
	}
	for _, key := range stored {
		if !strings.HasPrefix(key, "one:{authstore:kms}:") {
			t.Fatalf("key %[1]q does not use the shared prefix | 键 %[1]q 未使用共享前缀", key)
		}
		if strings.Count(key, "{authstore:kms}") != 1 {
			t.Fatalf("key %q carries %d hash tags | 键 %q 的哈希标签数量不符", key, strings.Count(key, "{authstore:kms}"), key)
		}
	}
}

// TestKeyLengthPrefixUnambiguous checks that identifiers and aliases containing separators do not
// collide. | TestKeyLengthPrefixUnambiguous 检查包含分隔符的标识与别名不会碰撞。
func TestKeyLengthPrefixUnambiguous(t *testing.T) {
	store := newStore(t, "")
	base := testTime(2026, time.September, 1, 0, 0, 0)
	cases := []struct{ id, alias string }{
		{"a", "x"},
		{"a:b", "x:1"},
		{"a:b:c", "1:x"},
	}
	for _, item := range cases {
		if err := store.CreateKey(testContext, sampleKey(item.id, item.alias, base)); err != nil {
			t.Fatalf("CreateKey %q: %v | 创建 %q 失败", item.id, err, item.id)
		}
	}
	for _, item := range cases {
		got, err := store.GetKey(testContext, item.id)
		if err != nil || got.ID != item.id {
			t.Fatalf("GetKey %q = %+v, %v | 读取 %q 失败", item.id, got, err, item.id)
		}
		if id, err := store.ResolveAlias(testContext, item.alias); err != nil || id != item.id {
			t.Fatalf("ResolveAlias %q = %q, %v | 别名 %q 解析失败", item.alias, id, err, item.alias)
		}
	}
	if err := store.DeleteKey(testContext, "a"); err != nil {
		t.Fatalf("DeleteKey a: %v | 删除 a 失败", err)
	}
	if _, err := store.GetKey(testContext, "a:b"); err != nil {
		t.Fatalf("DeleteKey a removed a:b: %v | 删除 a 影响了 a:b", err)
	}
	if _, err := store.GetKey(testContext, "a:b:c"); err != nil {
		t.Fatalf("DeleteKey a removed a:b:c: %v | 删除 a 影响了 a:b:c", err)
	}
}

// TestBackendErrorsAreRedacted verifies that every operation classifies a closed backend as
// ErrStoreUnavailable without leaking the address. | TestBackendErrorsAreRedacted 验证每个操作把
// 已关闭后端归类为 ErrStoreUnavailable 且不泄露地址。
func TestBackendErrorsAreRedacted(t *testing.T) {
	server := miniredis.RunT(t)
	client := goredis.NewClient(&goredis.Options{Addr: server.Addr(), MaxRetries: -1})
	store, err := kmsstore.New(client, kmsstore.Options{})
	if err != nil {
		t.Fatalf("new store: %v | 创建存储失败", err)
	}
	if err := client.Close(); err != nil {
		t.Fatalf("close client: %v | 关闭客户端失败", err)
	}
	base := testTime(2026, time.October, 1, 0, 0, 0)
	key := sampleKey("k1", "alias", base)
	operations := []struct {
		name string
		call func() error
	}{
		{"create", func() error { return store.CreateKey(testContext, key) }},
		{"get", func() error { _, err := store.GetKey(testContext, "k1"); return err }},
		{"update", func() error { return store.UpdateKey(testContext, key) }},
		{"delete", func() error { return store.DeleteKey(testContext, "k1") }},
		{"list", func() error { _, err := store.ListKeys(testContext, authkms.KeyFilter{}); return err }},
		{"resolve-alias", func() error { _, err := store.ResolveAlias(testContext, "alias"); return err }},
		{"set-alias", func() error { return store.SetAlias(testContext, "alias", "k1") }},
		{"delete-alias", func() error { return store.DeleteAlias(testContext, "alias") }},
		{"save-version", func() error {
			return store.SaveVersion(testContext, "k1", &authkms.KeyVersion{Version: 2})
		}},
		{"get-version", func() error { _, err := store.GetVersion(testContext, "k1", 1); return err }},
		{"list-versions", func() error { _, err := store.ListVersions(testContext, "k1"); return err }},
		{"append-audit", func() error {
			return store.AppendAudit(testContext, &authkms.AuditEvent{Operation: authkms.OperationEncrypt})
		}},
		{"list-audit", func() error { _, err := store.ListAudit(testContext, authkms.AuditFilter{}); return err }},
	}
	for _, operation := range operations {
		err := operation.call()
		if !errors.Is(err, authkms.ErrStoreUnavailable) {
			t.Fatalf("%s error = %v, want ErrStoreUnavailable | %s 错误未映射为存储不可用", operation.name, err, operation.name)
		}
		if strings.Contains(err.Error(), server.Addr()) || strings.Contains(err.Error(), "127.0.0.1") {
			t.Fatalf("%s error leaked the address: %v | %s 错误泄露了地址", operation.name, err, operation.name)
		}
	}
}

// TestContextCancellation verifies that a canceled context is returned unchanged.
// | TestContextCancellation 验证取消的上下文被原样返回。
func TestContextCancellation(t *testing.T) {
	store := newStore(t, "")
	canceled, cancel := context.WithCancel(testContext)
	cancel()
	if _, err := store.GetKey(canceled, "k1"); !errors.Is(err, context.Canceled) {
		t.Fatalf("get error = %v, want context.Canceled | 读取错误未返回上下文取消", err)
	}
	if err := store.CreateKey(canceled, sampleKey("k1", "", testTime(2026, time.November, 1, 0, 0, 0))); !errors.Is(err, context.Canceled) {
		t.Fatalf("create error = %v, want context.Canceled | 创建错误未返回上下文取消", err)
	}
}

// TestNilStore verifies that every method fails with ErrStoreUnavailable instead of panicking.
// | TestNilStore 验证每个方法返回 ErrStoreUnavailable 而不是 panic。
func TestNilStore(t *testing.T) {
	var store *kmsstore.Store
	base := testTime(2026, time.December, 1, 0, 0, 0)
	key := sampleKey("k1", "alias", base)
	checks := []struct {
		name string
		call func() error
	}{
		{"create", func() error { return store.CreateKey(testContext, key) }},
		{"get", func() error { _, err := store.GetKey(testContext, "k1"); return err }},
		{"update", func() error { return store.UpdateKey(testContext, key) }},
		{"delete", func() error { return store.DeleteKey(testContext, "k1") }},
		{"list", func() error { _, err := store.ListKeys(testContext, authkms.KeyFilter{}); return err }},
		{"resolve-alias", func() error { _, err := store.ResolveAlias(testContext, "alias"); return err }},
		{"set-alias", func() error { return store.SetAlias(testContext, "alias", "k1") }},
		{"delete-alias", func() error { return store.DeleteAlias(testContext, "alias") }},
		{"save-version", func() error {
			return store.SaveVersion(testContext, "k1", &authkms.KeyVersion{Version: 1})
		}},
		{"get-version", func() error { _, err := store.GetVersion(testContext, "k1", 1); return err }},
		{"list-versions", func() error { _, err := store.ListVersions(testContext, "k1"); return err }},
		{"append-audit", func() error {
			return store.AppendAudit(testContext, &authkms.AuditEvent{Operation: authkms.OperationEncrypt})
		}},
		{"list-audit", func() error { _, err := store.ListAudit(testContext, authkms.AuditFilter{}); return err }},
	}
	for _, check := range checks {
		if err := check.call(); !errors.Is(err, authkms.ErrStoreUnavailable) {
			t.Fatalf("%s error = %v, want ErrStoreUnavailable | %s 错误不符", check.name, err, check.name)
		}
	}
}

// TestMaterialNotInErrors verifies that key material never appears in an error message.
// | TestMaterialNotInErrors 验证密钥材料绝不出现在错误文案中。
func TestMaterialNotInErrors(t *testing.T) {
	store := newStore(t, "")
	base := testTime(2026, time.December, 2, 0, 0, 0)
	secret := "material-secret-value"
	key := sampleKey("k1", "alias", base)
	key.Material = []byte(secret)
	if err := store.CreateKey(testContext, key); err != nil {
		t.Fatalf("CreateKey: %v | 创建失败", err)
	}
	duplicate := sampleKey("k1", "alias", base)
	duplicate.Material = []byte(secret)
	err := store.CreateKey(testContext, duplicate)
	if !errors.Is(err, authkms.ErrKeyExists) {
		t.Fatalf("duplicate error = %v, want ErrKeyExists | 重复错误不符", err)
	}
	if strings.Contains(err.Error(), secret) {
		t.Fatalf("error leaked key material: %v | 错误泄露了密钥材料", err)
	}
	conflict := sampleKey("k2", "alias", base)
	conflict.Material = []byte(secret)
	err = store.CreateKey(testContext, conflict)
	if !errors.Is(err, authkms.ErrAliasExists) {
		t.Fatalf("alias error = %v, want ErrAliasExists | 别名错误不符", err)
	}
	if strings.Contains(err.Error(), secret) {
		t.Fatalf("alias error leaked key material: %v | 别名错误泄露了密钥材料", err)
	}
}
