package kms_test

import (
	"errors"
	"fmt"
	"sync"
	"testing"
	"time"

	authkms "github.com/shibingli/ydx/auth/keymgmt/kms"
)

// runConcurrently starts n goroutines that wait for a common start signal and returns their errors
// in start order. | runConcurrently 启动 n 个等待统一起跑信号的 goroutine，并按启动顺序返回错误。
func runConcurrently(n int, call func(index int) error) []error {
	start := make(chan struct{})
	results := make([]error, n)
	var group sync.WaitGroup
	group.Add(n)
	for i := 0; i < n; i++ {
		go func(index int) {
			defer group.Done()
			<-start
			results[index] = call(index)
		}(i)
	}
	close(start)
	group.Wait()
	return results
}

// TestConcurrentUpdateConflict verifies that two instances holding the same revision produce one
// winner and one ErrConflict. | TestConcurrentUpdateConflict 验证两个持有相同修订号的实例产生一个
// 成功者与一个 ErrConflict。
func TestConcurrentUpdateConflict(t *testing.T) {
	first, second := newPair(t)
	base := testTime(2026, time.January, 10, 0, 0, 0)
	if err := first.CreateKey(testContext, sampleKey("k1", "", base)); err != nil {
		t.Fatalf("CreateKey: %v | 创建失败", err)
	}
	one, err := first.GetKey(testContext, "k1")
	if err != nil {
		t.Fatalf("GetKey first: %v | 读取失败", err)
	}
	two, err := second.GetKey(testContext, "k1")
	if err != nil {
		t.Fatalf("GetKey second: %v | 读取失败", err)
	}
	results := runConcurrently(2, func(index int) error {
		if index == 0 {
			one.Metadata = map[string]string{"writer": "first"}
			return first.UpdateKey(testContext, one)
		}
		two.Metadata = map[string]string{"writer": "second"}
		return second.UpdateKey(testContext, two)
	})
	successes, conflicts := 0, 0
	for i, result := range results {
		switch {
		case result == nil:
			successes++
		case errors.Is(result, authkms.ErrConflict):
			conflicts++
		default:
			t.Fatalf("writer %d returned %v | 写入者 %d 返回了意外错误", i, result, i)
		}
	}
	if successes != 1 || conflicts != 1 {
		t.Fatalf("successes = %d, conflicts = %d, want 1 and 1 | 并发更新结果不符", successes, conflicts)
	}
	stored, err := first.GetKey(testContext, "k1")
	if err != nil {
		t.Fatalf("GetKey: %v | 读取失败", err)
	}
	if stored.Revision != 2 {
		t.Fatalf("revision = %d, want 2 | 并发更新后修订号不符", stored.Revision)
	}
}

// TestConcurrentCreateSameID verifies that only one instance can create a given identifier.
// | TestConcurrentCreateSameID 验证只有一个实例能创建指定标识。
func TestConcurrentCreateSameID(t *testing.T) {
	first, second := newPair(t)
	base := testTime(2026, time.January, 11, 0, 0, 0)
	results := runConcurrently(8, func(index int) error {
		store := first
		if index%2 == 1 {
			store = second
		}
		return store.CreateKey(testContext, sampleKey("dup", "", base))
	})
	successes, duplicates := 0, 0
	for i, result := range results {
		switch {
		case result == nil:
			successes++
		case errors.Is(result, authkms.ErrKeyExists):
			duplicates++
		default:
			t.Fatalf("creator %d returned %v | 创建者 %d 返回了意外错误", i, result, i)
		}
	}
	if successes != 1 || duplicates != 7 {
		t.Fatalf("successes = %d, duplicates = %d | 并发创建结果不符", successes, duplicates)
	}
	stored, err := first.GetKey(testContext, "dup")
	if err != nil || stored.Revision != 1 {
		t.Fatalf("stored = %+v, %v | 并发创建后记录不符", stored, err)
	}
}

// TestConcurrentAliasUniqueness verifies that one alias can bind to only one key across instances.
// | TestConcurrentAliasUniqueness 验证跨实例时一个别名只能绑定一个密钥。
func TestConcurrentAliasUniqueness(t *testing.T) {
	first, second := newPair(t)
	base := testTime(2026, time.January, 12, 0, 0, 0)
	results := runConcurrently(8, func(index int) error {
		store := first
		if index%2 == 1 {
			store = second
		}
		key := sampleKey(fmt.Sprintf("k%d", index), "shared", base)
		return store.CreateKey(testContext, key)
	})
	winner := -1
	for i, result := range results {
		switch {
		case result == nil:
			if winner >= 0 {
				t.Fatalf("two alias winners: %d and %d | 两个别名成功者", winner, i)
			}
			winner = i
		case errors.Is(result, authkms.ErrAliasExists):
		default:
			t.Fatalf("creator %d returned %v | 创建者 %d 返回了意外错误", i, result, i)
		}
	}
	if winner < 0 {
		t.Fatal("no alias winner | 没有别名成功者")
	}
	id, err := first.ResolveAlias(testContext, "shared")
	if err != nil || id != fmt.Sprintf("k%d", winner) {
		t.Fatalf("alias resolves to %q, %v, want k%d | 别名解析结果不符", id, err, winner)
	}
}

// TestConcurrentSaveVersion verifies that concurrent appends of one version number yield exactly
// one winner. | TestConcurrentSaveVersion 验证并发追加同一版本号时只有一个成功者。
func TestConcurrentSaveVersion(t *testing.T) {
	first, second := newPair(t)
	base := testTime(2026, time.January, 13, 0, 0, 0)
	if err := first.CreateKey(testContext, sampleKey("k1", "", base)); err != nil {
		t.Fatalf("CreateKey: %v | 创建失败", err)
	}
	results := runConcurrently(8, func(index int) error {
		store := first
		if index%2 == 1 {
			store = second
		}
		version := &authkms.KeyVersion{Version: 2, Material: []byte{byte(index)}}
		return store.SaveVersion(testContext, "k1", version)
	})
	winner := -1
	for i, result := range results {
		switch {
		case result == nil:
			if winner >= 0 {
				t.Fatalf("two version winners: %d and %d | 两个版本成功者", winner, i)
			}
			winner = i
		case errors.Is(result, authkms.ErrVersionExists):
		default:
			t.Fatalf("saver %d returned %v | 保存者 %d 返回了意外错误", i, result, i)
		}
	}
	if winner < 0 {
		t.Fatal("no version winner | 没有版本成功者")
	}
	stored, err := first.GetVersion(testContext, "k1", 2)
	if err != nil {
		t.Fatalf("GetVersion: %v | 读取版本失败", err)
	}
	if len(stored.Material) != 1 || stored.Material[0] != byte(winner) {
		t.Fatalf("stored material = %v, want %d | 存储版本材料不符", stored.Material, byte(winner))
	}
	key, err := second.GetKey(testContext, "k1")
	if err != nil || key.Revision != 2 {
		t.Fatalf("key = %+v, %v | 并发保存版本后修订号不符", key, err)
	}
}

// TestConcurrentUpdateRetryEventuallyApplies verifies that retrying readers all apply their update.
// | TestConcurrentUpdateRetryEventuallyApplies 验证重试的读取者最终都能应用更新。
func TestConcurrentUpdateRetryEventuallyApplies(t *testing.T) {
	first, second := newPair(t)
	base := testTime(2026, time.January, 14, 0, 0, 0)
	if err := first.CreateKey(testContext, sampleKey("k1", "", base)); err != nil {
		t.Fatalf("CreateKey: %v | 创建失败", err)
	}
	const writers = 8
	results := runConcurrently(writers, func(index int) error {
		store := first
		if index%2 == 1 {
			store = second
		}
		field := fmt.Sprintf("writer%d", index)
		for attempt := 0; attempt < 1000; attempt++ {
			key, err := store.GetKey(testContext, "k1")
			if err != nil {
				return err
			}
			if key.Metadata == nil {
				key.Metadata = make(map[string]string)
			}
			key.Metadata[field] = "applied"
			err = store.UpdateKey(testContext, key)
			if err == nil {
				return nil
			}
			if !errors.Is(err, authkms.ErrConflict) {
				return err
			}
		}
		return errors.New("retry budget exhausted | 重试预算耗尽")
	})
	for i, result := range results {
		if result != nil {
			t.Fatalf("writer %d failed: %v | 写入者 %d 失败", i, result, i)
		}
	}
	stored, err := first.GetKey(testContext, "k1")
	if err != nil {
		t.Fatalf("GetKey: %v | 读取失败", err)
	}
	if stored.Revision != 1+writers {
		t.Fatalf("revision = %d, want %d | 重试更新后修订号不符", stored.Revision, 1+writers)
	}
	for i := 0; i < writers; i++ {
		if stored.Metadata[fmt.Sprintf("writer%d", i)] != "applied" {
			t.Fatalf("writer%d update lost: %+v | writer%d 更新丢失", i, stored.Metadata, i)
		}
	}
}

// TestConcurrentDeleteAndUpdate verifies that a delete and an update across instances never leave
// a half-written record. | TestConcurrentDeleteAndUpdate 验证跨实例删除与更新不会留下半写记录。
func TestConcurrentDeleteAndUpdate(t *testing.T) {
	first, second := newPair(t)
	base := testTime(2026, time.January, 15, 0, 0, 0)
	if err := first.CreateKey(testContext, sampleKey("k1", "alias", base)); err != nil {
		t.Fatalf("CreateKey: %v | 创建失败", err)
	}
	key, err := first.GetKey(testContext, "k1")
	if err != nil {
		t.Fatalf("GetKey: %v | 读取失败", err)
	}
	key.Metadata = map[string]string{"updated": "yes"}
	results := runConcurrently(2, func(index int) error {
		if index == 0 {
			return second.DeleteKey(testContext, "k1")
		}
		return first.UpdateKey(testContext, key)
	})
	deleteErr, updateErr := results[0], results[1]
	if deleteErr != nil && !errors.Is(deleteErr, authkms.ErrNotFound) {
		t.Fatalf("delete error = %v | 删除错误不符", deleteErr)
	}
	if updateErr != nil && !errors.Is(updateErr, authkms.ErrNotFound) && !errors.Is(updateErr, authkms.ErrConflict) {
		t.Fatalf("update error = %v | 更新错误不符", updateErr)
	}
	stored, err := first.GetKey(testContext, "k1")
	switch {
	case err == nil:
		if stored.Metadata["updated"] != "yes" || stored.Revision != 2 {
			t.Fatalf("record = %+v | 更新胜出但记录不完整", stored)
		}
		if id, resolveErr := first.ResolveAlias(testContext, "alias"); resolveErr != nil || id != "k1" {
			t.Fatalf("alias = %q, %v | 更新胜出但别名缺失", id, resolveErr)
		}
	case errors.Is(err, authkms.ErrNotFound):
		if _, resolveErr := first.ResolveAlias(testContext, "alias"); !errors.Is(resolveErr, authkms.ErrAliasNotFound) {
			t.Fatalf("alias survived deletion: %v | 删除胜出但别名仍存在", resolveErr)
		}
	default:
		t.Fatalf("GetKey after race: %v | 竞争后读取失败", err)
	}
}

// TestStoreSharedAcrossGoroutines exercises one store from many goroutines without external
// serialization. | TestStoreSharedAcrossGoroutines 让一个存储在无外部串行化的情况下被多个
// goroutine 使用。
func TestStoreSharedAcrossGoroutines(t *testing.T) {
	store := newStore(t, "")
	base := testTime(2026, time.January, 16, 0, 0, 0)
	const workers = 16
	results := runConcurrently(workers, func(index int) error {
		id := fmt.Sprintf("k%d", index)
		if err := store.CreateKey(testContext, sampleKey(id, id+"-alias", base)); err != nil {
			return err
		}
		if err := store.SetAlias(testContext, "extra-"+id, id); err != nil {
			return err
		}
		if err := store.SaveVersion(testContext, id, &authkms.KeyVersion{Version: 2, Material: []byte{byte(index)}}); err != nil {
			return err
		}
		if _, err := store.ListKeys(testContext, authkms.KeyFilter{Query: id}); err != nil {
			return err
		}
		return store.AppendAudit(testContext, &authkms.AuditEvent{KeyID: id, Operation: authkms.OperationKeyCreate})
	})
	for i, result := range results {
		if result != nil {
			t.Fatalf("worker %d failed: %v | 工作者 %d 失败", i, result, i)
		}
	}
	keys, err := store.ListKeys(testContext, authkms.KeyFilter{})
	if err != nil || len(keys) != workers {
		t.Fatalf("keys = %d, %v | 并发写入后密钥数量不符", len(keys), err)
	}
	events, err := store.ListAudit(testContext, authkms.AuditFilter{})
	if err != nil || len(events) != workers {
		t.Fatalf("audits = %d, %v | 并发写入后审计数量不符", len(events), err)
	}
}
