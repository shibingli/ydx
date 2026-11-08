package kmip

import (
	"bytes"
	"context"
	"errors"
	"strings"
	"testing"
	"time"

	kmipcore "github.com/shibingli/ydx/auth/keymgmt/kmip"
)

// TestCreateAndGetAcrossInstances verifies that a record written by one instance is readable by
// another with the exact same contents. | TestCreateAndGetAcrossInstances 验证一个实例写入的记录
// 可被另一个实例读取且内容完全一致。
func TestCreateAndGetAcrossInstances(t *testing.T) {
	env := newTestEnv(t, "")
	record := testRecord("object-1")
	if err := env.storeA.Create(context.Background(), record); err != nil {
		t.Fatalf("Create: %v", err)
	}
	got, err := env.storeB.Get(context.Background(), record.UniqueIdentifier)
	if err != nil {
		t.Fatalf("Get: %v", err)
	}
	requireRecordEqual(t, record, got)
}

// TestCreateDuplicate verifies that a duplicate identifier is rejected without overwriting the
// existing record. | TestCreateDuplicate 验证重复标识符被拒绝且不覆盖既有记录。
func TestCreateDuplicate(t *testing.T) {
	env := newTestEnv(t, "")
	original := testRecord("duplicate")
	if err := env.storeA.Create(context.Background(), original); err != nil {
		t.Fatalf("Create: %v", err)
	}
	replacement := testRecord("duplicate")
	replacement.Owner = "other-owner"
	replacement.Object.SymmetricKey.KeyBlock.Value.Material = kmipcore.NewByteString(kmipcore.TagKeyMaterial, []byte("ffffffffffffffff"))
	err := env.storeB.Create(context.Background(), replacement)
	requireErrorIs(t, err, kmipcore.ErrObjectExists, "duplicate Create")
	got, err := env.storeA.Get(context.Background(), "duplicate")
	if err != nil {
		t.Fatalf("Get: %v", err)
	}
	requireRecordEqual(t, original, got)
}

// TestCreateEmptyIdentifier verifies that an empty unique identifier is rejected.
// | TestCreateEmptyIdentifier 验证空唯一标识符被拒绝。
func TestCreateEmptyIdentifier(t *testing.T) {
	env := newTestEnv(t, "")
	requireErrorIs(t, env.storeA.Create(context.Background(), testRecord("")),
		kmipcore.ErrInvalidRequest, "Create empty identifier")
}

// TestGetMissing verifies the not-found sentinel. | TestGetMissing 验证未找到哨兵。
func TestGetMissing(t *testing.T) {
	env := newTestEnv(t, "")
	_, err := env.storeA.Get(context.Background(), "does-not-exist")
	requireErrorIs(t, err, kmipcore.ErrItemNotFound, "Get missing")
}

// TestUpdateAcrossInstances verifies that an update written by one instance is visible to another.
// | TestUpdateAcrossInstances 验证一个实例写入的更新可被另一个实例看到。
func TestUpdateAcrossInstances(t *testing.T) {
	env := newTestEnv(t, "")
	record := testRecord("update-object")
	if err := env.storeA.Create(context.Background(), record); err != nil {
		t.Fatalf("Create: %v", err)
	}
	updated, err := env.storeA.Get(context.Background(), record.UniqueIdentifier)
	if err != nil {
		t.Fatalf("Get: %v", err)
	}
	updated.Owner = "owner-2"
	updated.State = kmipcore.StateActive
	updated.ActivationDate = time.Date(2026, time.November, 9, 1, 2, 3, 4, time.UTC)
	updated.Object.SymmetricKey.KeyBlock.Value.Material = kmipcore.NewByteString(kmipcore.TagKeyMaterial, []byte("fedcba9876543210"))
	if err := env.storeB.Update(context.Background(), updated); err != nil {
		t.Fatalf("Update: %v", err)
	}
	got, err := env.storeA.Get(context.Background(), record.UniqueIdentifier)
	if err != nil {
		t.Fatalf("Get after update: %v", err)
	}
	requireRecordEqual(t, updated, got)
}

// TestUpdateMissing verifies that updating an absent object reports not found.
// | TestUpdateMissing 验证更新不存在的对象报告未找到。
func TestUpdateMissing(t *testing.T) {
	env := newTestEnv(t, "")
	requireErrorIs(t, env.storeA.Update(context.Background(), testRecord("missing")),
		kmipcore.ErrItemNotFound, "Update missing")
}

// TestDelete verifies deletion and the not-found sentinel on repeated deletion.
// | TestDelete 验证删除以及重复删除时的未找到哨兵。
func TestDelete(t *testing.T) {
	env := newTestEnv(t, "")
	record := testRecord("delete-object")
	if err := env.storeA.Create(context.Background(), record); err != nil {
		t.Fatalf("Create: %v", err)
	}
	if err := env.storeB.Delete(context.Background(), record.UniqueIdentifier); err != nil {
		t.Fatalf("Delete: %v", err)
	}
	_, err := env.storeA.Get(context.Background(), record.UniqueIdentifier)
	requireErrorIs(t, err, kmipcore.ErrItemNotFound, "Get after delete")
	requireErrorIs(t, env.storeA.Delete(context.Background(), record.UniqueIdentifier),
		kmipcore.ErrItemNotFound, "second Delete")
	list, err := env.storeA.List(context.Background())
	if err != nil {
		t.Fatalf("List: %v", err)
	}
	if len(list) != 0 {
		t.Fatalf("List after delete returned %d records", len(list))
	}
}

// TestListSorted verifies identifier ordering across instances. | TestListSorted 验证跨实例的标识符排序。
func TestListSorted(t *testing.T) {
	env := newTestEnv(t, "")
	for _, identifier := range []string{"b-object", "a-object", "c-object"} {
		if err := env.storeA.Create(context.Background(), testRecord(identifier)); err != nil {
			t.Fatalf("Create %q: %v", identifier, err)
		}
	}
	list, err := env.storeB.List(context.Background())
	if err != nil {
		t.Fatalf("List: %v", err)
	}
	want := []string{"a-object", "b-object", "c-object"}
	if len(list) != len(want) {
		t.Fatalf("List returned %d records, want %d", len(list), len(want))
	}
	for i := range want {
		if list[i].UniqueIdentifier != want[i] {
			t.Fatalf("List[%d] = %q, want %q", i, list[i].UniqueIdentifier, want[i])
		}
		requireRecordEqual(t, testRecord(want[i]), list[i])
	}
}

// TestListEmpty verifies that an empty store returns an allocated empty slice.
// | TestListEmpty 验证空存储返回已分配的空切片。
func TestListEmpty(t *testing.T) {
	env := newTestEnv(t, "")
	list, err := env.storeA.List(context.Background())
	if err != nil {
		t.Fatalf("List: %v", err)
	}
	if list == nil {
		t.Fatal("List returned a nil slice")
	}
	if len(list) != 0 {
		t.Fatalf("List returned %d records", len(list))
	}
}

// TestListSkipsOrphanIndexEntries verifies that an index member without a record is ignored.
// | TestListSkipsOrphanIndexEntries 验证没有对应记录的索引成员会被忽略。
func TestListSkipsOrphanIndexEntries(t *testing.T) {
	env := newTestEnv(t, "")
	if err := env.storeA.Create(context.Background(), testRecord("present")); err != nil {
		t.Fatalf("Create: %v", err)
	}
	ghostKey := env.storeA.keys.object("ghost")
	if err := env.clientA.SAdd(context.Background(), env.storeA.keys.all(), ghostKey).Err(); err != nil {
		t.Fatalf("SAdd orphan: %v", err)
	}
	list, err := env.storeA.List(context.Background())
	if err != nil {
		t.Fatalf("List: %v", err)
	}
	if len(list) != 1 || list[0].UniqueIdentifier != "present" {
		t.Fatalf("List returned %#v", list)
	}
}

// TestReset verifies that Reset removes every record and is idempotent.
// | TestReset 验证 Reset 删除全部记录且可重复调用。
func TestReset(t *testing.T) {
	env := newTestEnv(t, "")
	for _, identifier := range []string{"reset-a", "reset-b", "reset-c"} {
		if err := env.storeA.Create(context.Background(), testRecord(identifier)); err != nil {
			t.Fatalf("Create %q: %v", identifier, err)
		}
	}
	if err := env.storeA.Reset(context.Background()); err != nil {
		t.Fatalf("Reset: %v", err)
	}
	list, err := env.storeB.List(context.Background())
	if err != nil {
		t.Fatalf("List: %v", err)
	}
	if len(list) != 0 {
		t.Fatalf("List after Reset returned %d records", len(list))
	}
	if keys := env.mr.Keys(); len(keys) != 0 {
		t.Fatalf("Reset left %d keys: %v", len(keys), keys)
	}
	if err := env.storeA.Reset(context.Background()); err != nil {
		t.Fatalf("second Reset: %v", err)
	}
}

// TestPrefixIsolation verifies that two stores with different prefixes do not see each other's
// records and that Reset only clears its own namespace. | TestPrefixIsolation 验证不同前缀的两个
// 存储互不可见，且 Reset 仅清理自己的命名空间。
func TestPrefixIsolation(t *testing.T) {
	server := newTestServer(t)
	clientA := newTestClient(t, server)
	clientB := newTestClient(t, server)
	storeA, err := New(clientA, Options{KeyPrefix: "app-a:"})
	if err != nil {
		t.Fatalf("New A: %v", err)
	}
	storeB, err := New(clientB, Options{KeyPrefix: "app-b:"})
	if err != nil {
		t.Fatalf("New B: %v", err)
	}
	recordA := testRecord("shared")
	recordA.Owner = "owner-a"
	recordB := testRecord("shared")
	recordB.Owner = "owner-b"
	if err := storeA.Create(context.Background(), recordA); err != nil {
		t.Fatalf("Create A: %v", err)
	}
	if err := storeB.Create(context.Background(), recordB); err != nil {
		t.Fatalf("Create B: %v", err)
	}
	gotA, err := storeA.Get(context.Background(), "shared")
	if err != nil {
		t.Fatalf("Get A: %v", err)
	}
	gotB, err := storeB.Get(context.Background(), "shared")
	if err != nil {
		t.Fatalf("Get B: %v", err)
	}
	if gotA.Owner != "owner-a" || gotB.Owner != "owner-b" {
		t.Fatalf("prefix isolation failed: A=%q B=%q", gotA.Owner, gotB.Owner)
	}
	listA, err := storeA.List(context.Background())
	if err != nil {
		t.Fatalf("List A: %v", err)
	}
	listB, err := storeB.List(context.Background())
	if err != nil {
		t.Fatalf("List B: %v", err)
	}
	if len(listA) != 1 || len(listB) != 1 {
		t.Fatalf("List isolation failed: A=%d B=%d", len(listA), len(listB))
	}
	if err := storeA.Reset(context.Background()); err != nil {
		t.Fatalf("Reset A: %v", err)
	}
	if _, err := storeB.Get(context.Background(), "shared"); err != nil {
		t.Fatalf("Reset A removed B's record: %v", err)
	}
	keys := server.Keys()
	for _, key := range keys {
		if len(key) == 0 || key[0] != 'a' && key[0] != 'y' {
			t.Fatalf("unexpected key after Reset A: %q", key)
		}
	}
}

// TestDefaultKeyPrefix verifies the documented default namespace and key shape.
// | TestDefaultKeyPrefix 验证文档化的默认命名空间与键形态。
func TestDefaultKeyPrefix(t *testing.T) {
	env := newTestEnv(t, "")
	if err := env.storeA.Create(context.Background(), testRecord("obj")); err != nil {
		t.Fatalf("Create: %v", err)
	}
	wantObject := "ydx:authstore:kmip:{authstore:kmip}:object:3:obj"
	keys := env.mr.Keys()
	foundObject := false
	for _, key := range keys {
		if key == wantObject {
			foundObject = true
		}
	}
	if !foundObject {
		t.Fatalf("default key %q not found among %v", wantObject, keys)
	}
	if !containsKey(keys, "ydx:authstore:kmip:{authstore:kmip}:all") {
		t.Fatalf("default index key not found among %v", keys)
	}
}

// containsKey reports whether keys contains want. | containsKey 报告 keys 是否包含 want。
func containsKey(keys []string, want string) bool {
	for _, key := range keys {
		if key == want {
			return true
		}
	}
	return false
}

// TestUTCNormalization verifies that every non-zero time is stored and returned in UTC, zero
// times stay zero, and encoding does not mutate the caller's record.
// | TestUTCNormalization 验证每个非零时间以 UTC 存储并返回、零时间保持零值，且编码不修改调用方
// 的记录。
func TestUTCNormalization(t *testing.T) {
	env := newTestEnv(t, "")
	record := testRecord("utc-object")
	if err := env.storeA.Create(context.Background(), record); err != nil {
		t.Fatalf("Create: %v", err)
	}
	if record.InitialDate.Location() == time.UTC {
		t.Fatal("Create mutated the caller's time zone")
	}
	got, err := env.storeB.Get(context.Background(), "utc-object")
	if err != nil {
		t.Fatalf("Get: %v", err)
	}
	times := map[string]time.Time{
		"InitialDate":              got.InitialDate,
		"OriginalCreationDate":     got.OriginalCreationDate,
		"ActivationDate":           got.ActivationDate,
		"DeactivationDate":         got.DeactivationDate,
		"CompromiseDate":           got.CompromiseDate,
		"CompromiseOccurrenceDate": got.CompromiseOccurrenceDate,
		"DestroyDate":              got.DestroyDate,
		"ArchiveDate":              got.ArchiveDate,
		"LastChangeDate":           got.LastChangeDate,
	}
	for name, value := range times {
		if value.IsZero() {
			continue
		}
		if value.Location() != time.UTC {
			t.Fatalf("%s location = %v, want UTC", name, value.Location())
		}
	}
	if !got.InitialDate.Equal(record.InitialDate) {
		t.Fatalf("InitialDate instant changed: got %v want %v", got.InitialDate, record.InitialDate)
	}
	if got.InitialDate.Nanosecond() != record.InitialDate.Nanosecond() {
		t.Fatalf("InitialDate nanoseconds changed: got %d want %d", got.InitialDate.Nanosecond(), record.InitialDate.Nanosecond())
	}
	for name, value := range map[string]time.Time{
		"DeactivationDate":         got.DeactivationDate,
		"CompromiseDate":           got.CompromiseDate,
		"CompromiseOccurrenceDate": got.CompromiseOccurrenceDate,
		"DestroyDate":              got.DestroyDate,
		"ArchiveDate":              got.ArchiveDate,
	} {
		if !value.IsZero() {
			t.Fatalf("%s = %v, want zero", name, value)
		}
	}
}

// TestDeepCopyIsolation verifies that neither the caller's slices nor the values returned by Get
// and List alias the stored record. | TestDeepCopyIsolation 验证调用方的切片以及 Get 与 List 返回的
// 值都不与已存记录共享底层数组。
func TestDeepCopyIsolation(t *testing.T) {
	env := newTestEnv(t, "")
	original := testRecord("deep-copy")
	if err := env.storeA.Create(context.Background(), original); err != nil {
		t.Fatalf("Create: %v", err)
	}
	baseline, err := env.storeA.Get(context.Background(), "deep-copy")
	if err != nil {
		t.Fatalf("Get baseline: %v", err)
	}
	requireRecordEqual(t, original, baseline)

	original.Names[0].Value = "mutated-caller-name"
	original.ObjectGroups[0] = "mutated-caller-group"
	original.Attributes[0].Value.Value[0] ^= 0xff
	original.Attributes[1].Value.Children[1].Value[0] ^= 0xff
	original.Object.SymmetricKey.KeyBlock.Value.Material.Value[0] ^= 0xff
	afterCallerMutation, err := env.storeA.Get(context.Background(), "deep-copy")
	if err != nil {
		t.Fatalf("Get after caller mutation: %v", err)
	}
	requireRecordEqual(t, baseline, afterCallerMutation)

	afterCallerMutation.Names[0].Value = "mutated-result-name"
	afterCallerMutation.ObjectGroups[0] = "mutated-result-group"
	afterCallerMutation.Attributes[0].Value.Value[0] ^= 0xff
	afterCallerMutation.Attributes[1].Value.Children[1].Value[0] ^= 0xff
	afterCallerMutation.Object.SymmetricKey.KeyBlock.Value.Material.Value[0] ^= 0xff
	afterResultMutation, err := env.storeA.Get(context.Background(), "deep-copy")
	if err != nil {
		t.Fatalf("Get after result mutation: %v", err)
	}
	requireRecordEqual(t, baseline, afterResultMutation)

	list, err := env.storeA.List(context.Background())
	if err != nil {
		t.Fatalf("List: %v", err)
	}
	if len(list) != 1 {
		t.Fatalf("List returned %d records", len(list))
	}
	list[0].Names[0].Value = "mutated-list-name"
	list[0].Object.SymmetricKey.KeyBlock.Value.Material.Value[0] ^= 0xff
	listAgain, err := env.storeA.List(context.Background())
	if err != nil {
		t.Fatalf("List again: %v", err)
	}
	requireRecordEqual(t, baseline, listAgain[0])
}

// TestLifecycleTransitions verifies that every lifecycle state and its dates round-trip and that a
// destroyed object becomes a tombstone without key material. | TestLifecycleTransitions 验证每个生命
// 周期状态及其日期都能原样往返，且被销毁的对象变成不含密钥材料的墓碑。
func TestLifecycleTransitions(t *testing.T) {
	env := newTestEnv(t, "")
	record := testRecord("lifecycle")
	record.State = kmipcore.StatePreActive
	record.ActivationDate = time.Time{}
	record.RevocationReason = kmipcore.RevocationReason{}
	if err := env.storeA.Create(context.Background(), record); err != nil {
		t.Fatalf("Create: %v", err)
	}
	activation := time.Date(2026, time.November, 9, 1, 0, 0, 5, time.FixedZone("CST", 8*60*60))
	deactivation := activation.Add(2 * time.Hour)
	compromise := deactivation.Add(time.Hour)
	destroyDate := compromise.Add(time.Hour)

	record.State = kmipcore.StateActive
	record.ActivationDate = activation
	if err := env.storeB.Update(context.Background(), record); err != nil {
		t.Fatalf("Update Active: %v", err)
	}
	got, err := env.storeA.Get(context.Background(), "lifecycle")
	if err != nil {
		t.Fatalf("Get Active: %v", err)
	}
	if got.State != kmipcore.StateActive || !got.ActivationDate.Equal(activation) {
		t.Fatalf("Active state = %v at %v", got.State, got.ActivationDate)
	}

	record.State = kmipcore.StateDeactivated
	record.DeactivationDate = deactivation
	if err := env.storeB.Update(context.Background(), record); err != nil {
		t.Fatalf("Update Deactivated: %v", err)
	}
	got, err = env.storeA.Get(context.Background(), "lifecycle")
	if err != nil {
		t.Fatalf("Get Deactivated: %v", err)
	}
	if got.State != kmipcore.StateDeactivated || !got.DeactivationDate.Equal(deactivation) {
		t.Fatalf("Deactivated state = %v at %v", got.State, got.DeactivationDate)
	}

	record.State = kmipcore.StateCompromised
	record.CompromiseDate = compromise
	record.CompromiseOccurrenceDate = compromise.Add(-time.Minute)
	record.RevocationReason = kmipcore.RevocationReason{
		Code:    kmipcore.RevocationKeyCompromise,
		Message: "compromised in transit",
	}
	if err := env.storeB.Update(context.Background(), record); err != nil {
		t.Fatalf("Update Compromised: %v", err)
	}
	got, err = env.storeA.Get(context.Background(), "lifecycle")
	if err != nil {
		t.Fatalf("Get Compromised: %v", err)
	}
	if got.State != kmipcore.StateCompromised ||
		!got.CompromiseDate.Equal(compromise) ||
		!got.CompromiseOccurrenceDate.Equal(compromise.Add(-time.Minute)) ||
		got.RevocationReason.Code != kmipcore.RevocationKeyCompromise ||
		got.RevocationReason.Message != "compromised in transit" {
		t.Fatalf("Compromised state did not round-trip: %#v", got)
	}

	// Destroy zeroizes the live object, drops the material and keeps the metadata as a tombstone.
	record.Object.Zeroize()
	record.Object = nil
	record.State = kmipcore.StateDestroyed
	record.DestroyDate = destroyDate
	record.LastChangeDate = destroyDate
	if err := env.storeB.Update(context.Background(), record); err != nil {
		t.Fatalf("Update Destroyed: %v", err)
	}
	got, err = env.storeA.Get(context.Background(), "lifecycle")
	if err != nil {
		t.Fatalf("Get Destroyed: %v", err)
	}
	if got.Object != nil {
		t.Fatalf("tombstone retained an object: %#v", got.Object)
	}
	if got.State != kmipcore.StateDestroyed || !got.DestroyDate.Equal(destroyDate) {
		t.Fatalf("Destroyed state = %v at %v", got.State, got.DestroyDate)
	}
	if len(got.Names) != len(record.Names) || len(got.Attributes) != len(record.Attributes) {
		t.Fatalf("tombstone lost metadata: names=%d attributes=%d", len(got.Names), len(got.Attributes))
	}
	if err := env.storeA.Delete(context.Background(), "lifecycle"); err != nil {
		t.Fatalf("Delete tombstone: %v", err)
	}
	_, err = env.storeA.Get(context.Background(), "lifecycle")
	requireErrorIs(t, err, kmipcore.ErrItemNotFound, "Get after tombstone delete")
}

// TestTombstoneDoesNotRetainMaterial verifies that destroying an object removes its key material
// from every stored value and key name. | TestTombstoneDoesNotRetainMaterial 验证销毁对象会从所有
// 已存值与键名中移除密钥材料。
func TestTombstoneDoesNotRetainMaterial(t *testing.T) {
	env := newTestEnv(t, "")
	ctx := context.Background()
	secret := []byte("tombstone-material-must-disappear")
	record := testRecord("tombstone-material")
	record.Object.SymmetricKey.KeyBlock.Value.Material =
		kmipcore.NewByteString(kmipcore.TagKeyMaterial, secret)
	if err := env.storeA.Create(ctx, record); err != nil {
		t.Fatalf("Create: %v", err)
	}
	destroy := time.Date(2026, time.November, 9, 0, 0, 0, 0, time.UTC)
	record.Object.Zeroize()
	record.Object = nil
	record.State = kmipcore.StateDestroyed
	record.DestroyDate = destroy
	record.LastChangeDate = destroy
	if err := env.storeB.Update(ctx, record); err != nil {
		t.Fatalf("Update tombstone: %v", err)
	}
	for _, key := range env.mr.Keys() {
		if strings.Contains(key, string(secret)) {
			t.Fatalf("key name retains material: %q", key)
		}
		data, err := env.clientA.HGet(ctx, key, fieldData).Result()
		if err != nil {
			continue
		}
		if bytes.Contains([]byte(data), secret) {
			t.Fatalf("stored value under %q retains key material", key)
		}
	}
	got, err := env.storeA.Get(ctx, "tombstone-material")
	if err != nil {
		t.Fatalf("Get tombstone: %v", err)
	}
	if got.Object != nil {
		t.Fatalf("tombstone retained an object: %#v", got.Object)
	}
	list, err := env.storeB.List(ctx)
	if err != nil {
		t.Fatalf("List: %v", err)
	}
	if len(list) != 1 || list[0].Object != nil {
		t.Fatalf("List tombstone = %#v", list)
	}
}

// TestBatchUndoSnapshotSemantics verifies the exact rollback patterns used by the KMIP Batch Undo
// journal: a Get snapshot restores an updated or deleted object, and Create/Update fall back to
// the counterpart when the object already exists or is already gone.
// | TestBatchUndoSnapshotSemantics 验证 KMIP Batch Undo 日志使用的精确回滚模式：Get 快照可恢复被
// 更新或删除的对象，且 Create/Update 在对象已存在或已消失时回退到对应操作。
func TestBatchUndoSnapshotSemantics(t *testing.T) {
	env := newTestEnv(t, "")
	ctx := context.Background()

	t.Run("update rollback", func(t *testing.T) {
		record := testRecord("undo-update")
		if err := env.storeA.Create(ctx, record); err != nil {
			t.Fatalf("Create: %v", err)
		}
		previous, err := env.storeB.Get(ctx, "undo-update")
		if err != nil {
			t.Fatalf("snapshot: %v", err)
		}
		live, err := env.storeA.Get(ctx, "undo-update")
		if err != nil {
			t.Fatalf("live copy: %v", err)
		}
		live.State = kmipcore.StateActive
		live.Owner = "changed-owner"
		live.Object.SymmetricKey.KeyBlock.Value.Material = kmipcore.NewByteString(kmipcore.TagKeyMaterial, []byte("zzzzzzzzzzzzzzzz"))
		if err := env.storeA.Update(ctx, live); err != nil {
			t.Fatalf("Update: %v", err)
		}
		if err := env.storeB.Update(ctx, previous); err != nil {
			t.Fatalf("rollback Update: %v", err)
		}
		got, err := env.storeB.Get(ctx, "undo-update")
		if err != nil {
			t.Fatalf("Get after rollback: %v", err)
		}
		requireRecordEqual(t, previous, got)
	})

	t.Run("delete rollback", func(t *testing.T) {
		record := testRecord("undo-delete")
		if err := env.storeA.Create(ctx, record); err != nil {
			t.Fatalf("Create: %v", err)
		}
		previous, err := env.storeB.Get(ctx, "undo-delete")
		if err != nil {
			t.Fatalf("snapshot: %v", err)
		}
		if err := env.storeA.Delete(ctx, "undo-delete"); err != nil {
			t.Fatalf("Delete: %v", err)
		}
		if err := env.storeB.Create(ctx, previous); err != nil {
			t.Fatalf("rollback Create: %v", err)
		}
		got, err := env.storeA.Get(ctx, "undo-delete")
		if err != nil {
			t.Fatalf("Get after rollback: %v", err)
		}
		requireRecordEqual(t, previous, got)
	})

	t.Run("create rollback", func(t *testing.T) {
		record := testRecord("undo-create")
		if err := env.storeA.Create(ctx, record); err != nil {
			t.Fatalf("Create: %v", err)
		}
		if err := env.storeB.Delete(ctx, "undo-create"); err != nil {
			t.Fatalf("rollback Delete: %v", err)
		}
		_, err := env.storeA.Get(ctx, "undo-create")
		requireErrorIs(t, err, kmipcore.ErrItemNotFound, "Get after create rollback")
	})

	t.Run("update fallback to create", func(t *testing.T) {
		record := testRecord("undo-fallback")
		if err := env.storeA.Create(ctx, record); err != nil {
			t.Fatalf("Create: %v", err)
		}
		previous, err := env.storeB.Get(ctx, "undo-fallback")
		if err != nil {
			t.Fatalf("snapshot: %v", err)
		}
		if err := env.storeA.Delete(ctx, "undo-fallback"); err != nil {
			t.Fatalf("Delete: %v", err)
		}
		err = env.storeB.Update(ctx, previous)
		requireErrorIs(t, err, kmipcore.ErrItemNotFound, "Update after delete")
		if err := env.storeB.Create(ctx, previous); err != nil {
			t.Fatalf("fallback Create: %v", err)
		}
		got, err := env.storeA.Get(ctx, "undo-fallback")
		if err != nil {
			t.Fatalf("Get after fallback: %v", err)
		}
		requireRecordEqual(t, previous, got)
	})

	t.Run("create fallback to update", func(t *testing.T) {
		record := testRecord("undo-existing")
		if err := env.storeA.Create(ctx, record); err != nil {
			t.Fatalf("Create: %v", err)
		}
		previous, err := env.storeB.Get(ctx, "undo-existing")
		if err != nil {
			t.Fatalf("snapshot: %v", err)
		}
		err = env.storeA.Create(ctx, previous)
		requireErrorIs(t, err, kmipcore.ErrObjectExists, "Create existing")
		if err := env.storeA.Update(ctx, previous); err != nil {
			t.Fatalf("fallback Update: %v", err)
		}
		got, err := env.storeB.Get(ctx, "undo-existing")
		if err != nil {
			t.Fatalf("Get after fallback: %v", err)
		}
		requireRecordEqual(t, previous, got)
	})
}

// TestCorruptStoredRecords verifies that damaged values and missing revision metadata map to
// ErrStoreUnavailable instead of leaking decoder or Redis errors. | TestCorruptStoredRecords 验证
// 损坏的值与缺失的修订元数据映射为 ErrStoreUnavailable，而不是泄露解码器或 Redis 错误。
func TestCorruptStoredRecords(t *testing.T) {
	env := newTestEnv(t, "")
	ctx := context.Background()

	corruptKey := env.storeA.keys.object("corrupt-json")
	if err := env.clientA.HSet(ctx, corruptKey, fieldData, "{not json", fieldRevision, "1").Err(); err != nil {
		t.Fatalf("HSet corrupt JSON: %v", err)
	}
	if err := env.clientA.SAdd(ctx, env.storeA.keys.all(), corruptKey).Err(); err != nil {
		t.Fatalf("SAdd corrupt record: %v", err)
	}
	_, err := env.storeA.Get(ctx, "corrupt-json")
	requireErrorIs(t, err, ErrStoreUnavailable, "Get corrupt JSON")
	_, err = env.storeA.List(ctx)
	requireErrorIs(t, err, ErrStoreUnavailable, "List corrupt JSON")

	if err := env.clientA.HSet(ctx, env.storeA.keys.object("empty-data"), fieldData, "", fieldRevision, "1").Err(); err != nil {
		t.Fatalf("HSet empty data: %v", err)
	}
	_, err = env.storeA.Get(ctx, "empty-data")
	requireErrorIs(t, err, ErrStoreUnavailable, "Get empty data")

	data, err := encodeRecord(testRecord("no-revision"))
	if err != nil {
		t.Fatalf("encodeRecord: %v", err)
	}
	if err := env.clientA.HSet(ctx, env.storeA.keys.object("no-revision"), fieldData, string(data)).Err(); err != nil {
		t.Fatalf("HSet no revision: %v", err)
	}
	requireErrorIs(t, env.storeA.Update(ctx, testRecord("no-revision")),
		ErrStoreUnavailable, "Update without revision")
	requireRecordEqual(t, testRecord("no-revision"), mustGet(t, env.storeA, "no-revision"))

	if err := env.clientA.HSet(ctx, env.storeA.keys.object("bad-revision"), fieldRevision, "not-a-number").Err(); err != nil {
		t.Fatalf("HSet bad revision: %v", err)
	}
	requireErrorIs(t, env.storeA.Update(ctx, testRecord("bad-revision")),
		ErrStoreUnavailable, "Update with invalid revision")
}

// TestRevisionTokensAreNeverReused verifies that create, delete plus recreate, and update each
// install a new compare-and-set token, which prevents a stale update from matching a recreated
// record. | TestRevisionTokensAreNeverReused 验证创建、删除后重建与更新都会安装新的比较并交换令牌，
// 从而防止陈旧更新匹配到重建的记录。
func TestRevisionTokensAreNeverReused(t *testing.T) {
	env := newTestEnv(t, "")
	ctx := context.Background()
	record := testRecord("revision-token")
	if err := env.storeA.Create(ctx, record); err != nil {
		t.Fatalf("Create: %v", err)
	}
	first, err := env.storeA.client.HGet(ctx, env.storeA.keys.object("revision-token"), fieldRevision).Result()
	if err != nil {
		t.Fatalf("HGet first revision: %v", err)
	}
	if !validRevision(first) {
		t.Fatalf("first revision token %q is invalid", first)
	}
	if err := env.storeB.Delete(ctx, "revision-token"); err != nil {
		t.Fatalf("Delete: %v", err)
	}
	if err := env.storeB.Create(ctx, record); err != nil {
		t.Fatalf("recreate: %v", err)
	}
	second, err := env.storeB.client.HGet(ctx, env.storeB.keys.object("revision-token"), fieldRevision).Result()
	if err != nil {
		t.Fatalf("HGet second revision: %v", err)
	}
	if !validRevision(second) {
		t.Fatalf("second revision token %q is invalid", second)
	}
	if first == second {
		t.Fatalf("recreated identifier reused revision token %q", first)
	}
	if err := env.storeA.Update(ctx, record); err != nil {
		t.Fatalf("Update: %v", err)
	}
	third, err := env.storeA.client.HGet(ctx, env.storeA.keys.object("revision-token"), fieldRevision).Result()
	if err != nil {
		t.Fatalf("HGet third revision: %v", err)
	}
	if third == first || third == second {
		t.Fatalf("Update reused revision token %q", third)
	}
	if !validRevision(third) {
		t.Fatalf("third revision token %q is invalid", third)
	}
}

// mustGet loads a record or fails the test. | mustGet 加载记录或在失败时终止测试。
func mustGet(t *testing.T, store *Store, uniqueIdentifier string) kmipcore.ObjectRecord {
	t.Helper()
	record, err := store.Get(context.Background(), uniqueIdentifier)
	if err != nil {
		t.Fatalf("Get %q: %v", uniqueIdentifier, err)
	}
	return record
}

// TestErrorSentinels verifies the sentinel mapping for every missing-object path.
// | TestErrorSentinels 验证每个对象缺失路径的哨兵映射。
func TestErrorSentinels(t *testing.T) {
	env := newTestEnv(t, "")
	ctx := context.Background()
	_, err := env.storeA.Get(ctx, "absent")
	requireErrorIs(t, err, kmipcore.ErrItemNotFound, "Get absent")
	requireErrorIs(t, env.storeA.Update(ctx, testRecord("absent")), kmipcore.ErrItemNotFound, "Update absent")
	requireErrorIs(t, env.storeA.Delete(ctx, "absent"), kmipcore.ErrItemNotFound, "Delete absent")
	requireErrorIs(t, env.storeA.Create(ctx, testRecord("")), kmipcore.ErrInvalidRequest, "Create empty")
	if err := env.storeA.Create(ctx, testRecord("present")); err != nil {
		t.Fatalf("Create: %v", err)
	}
	duplicateErr := env.storeA.Create(ctx, testRecord("present"))
	requireErrorIs(t, duplicateErr, kmipcore.ErrObjectExists, "Create duplicate")
	if errors.Is(duplicateErr, kmipcore.ErrItemNotFound) {
		t.Fatal("ErrObjectExists matched ErrItemNotFound")
	}
}
