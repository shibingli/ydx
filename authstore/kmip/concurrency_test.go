package kmip

import (
	"context"
	"errors"
	"strconv"
	"sync"
	"sync/atomic"
	"testing"

	kmipcore "github.com/shibingli/ydx/auth/keymgmt/kmip"
)

// TestConcurrentCreateSameIdentifier verifies that two instances racing on one identifier produce
// exactly one record. | TestConcurrentCreateSameIdentifier 验证两个实例争用同一标识符时恰好产生
// 一条记录。
func TestConcurrentCreateSameIdentifier(t *testing.T) {
	env := newTestEnv(t, "")
	const writers = 16
	var wg sync.WaitGroup
	var created atomic.Int64
	var duplicates atomic.Int64
	unexpected := make(chan error, writers)
	start := make(chan struct{})
	for i := 0; i < writers; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			record := testRecord("contended-create")
			record.Owner = "writer-" + strconv.Itoa(i)
			store := env.storeA
			if i%2 == 1 {
				store = env.storeB
			}
			<-start
			err := store.Create(context.Background(), record)
			switch {
			case err == nil:
				created.Add(1)
			case errors.Is(err, kmipcore.ErrObjectExists):
				duplicates.Add(1)
			default:
				unexpected <- err
			}
		}(i)
	}
	close(start)
	wg.Wait()
	close(unexpected)
	for err := range unexpected {
		t.Fatalf("unexpected Create error: %v", err)
	}
	if got := created.Load(); got != 1 {
		t.Fatalf("successful Create count = %d, want 1", got)
	}
	if got := duplicates.Load(); got != writers-1 {
		t.Fatalf("duplicate Create count = %d, want %d", got, writers-1)
	}
	got := mustGet(t, env.storeB, "contended-create")
	if len(got.Owner) < len("writer-") || got.Owner[:len("writer-")] != "writer-" {
		t.Fatalf("stored record owner = %q, want one of the writers", got.Owner)
	}
}

// TestConcurrentCreateDistinctIdentifiers verifies that concurrent creates of different identifiers
// are all recorded exactly once in the index. | TestConcurrentCreateDistinctIdentifiers 验证并发创建
// 不同标识符时全部恰好记录一次并进入索引。
func TestConcurrentCreateDistinctIdentifiers(t *testing.T) {
	env := newTestEnv(t, "")
	const writers = 24
	var wg sync.WaitGroup
	errsCh := make(chan error, writers)
	for i := 0; i < writers; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			record := testRecord("distinct-" + strconv.Itoa(i))
			store := env.storeA
			if i%2 == 1 {
				store = env.storeB
			}
			if err := store.Create(context.Background(), record); err != nil {
				errsCh <- err
			}
		}(i)
	}
	wg.Wait()
	close(errsCh)
	for err := range errsCh {
		t.Fatalf("Create: %v", err)
	}
	list, err := env.storeA.List(context.Background())
	if err != nil {
		t.Fatalf("List: %v", err)
	}
	if len(list) != writers {
		t.Fatalf("List returned %d records, want %d", len(list), writers)
	}
	seen := make(map[string]bool, writers)
	for _, record := range list {
		if seen[record.UniqueIdentifier] {
			t.Fatalf("duplicate identifier %q in List", record.UniqueIdentifier)
		}
		seen[record.UniqueIdentifier] = true
	}
}

// TestConcurrentUpdates verifies that every successful update is a whole record from one writer and
// that contention is reported as nil or ErrConflict rather than a torn write.
// | TestConcurrentUpdates 验证每次成功的更新都是某个写入方的完整记录，竞争被报告为 nil 或
// ErrConflict，而不是撕裂写入。
func TestConcurrentUpdates(t *testing.T) {
	env := newTestEnv(t, "")
	const writers = 8
	ctx := context.Background()
	if err := env.storeA.Create(ctx, testRecord("contended-update")); err != nil {
		t.Fatalf("Create: %v", err)
	}
	var wg sync.WaitGroup
	var mu sync.Mutex
	succeeded := make(map[string]bool, writers)
	errsCh := make(chan error, writers)
	start := make(chan struct{})
	for i := 0; i < writers; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			owner := "writer-" + strconv.Itoa(i)
			store := env.storeA
			if i%2 == 1 {
				store = env.storeB
			}
			<-start
			record, err := store.Get(ctx, "contended-update")
			if err != nil {
				errsCh <- err
				return
			}
			record.Owner = owner
			record.State = kmipcore.StateActive
			record.Object.SymmetricKey.KeyBlock.Value.Material =
				kmipcore.NewByteString(kmipcore.TagKeyMaterial, []byte(owner))
			err = store.Update(ctx, record)
			switch {
			case err == nil:
				mu.Lock()
				succeeded[owner] = true
				mu.Unlock()
			case errors.Is(err, ErrConflict):
				// A bounded compare-and-set retry budget may legitimately be exhausted.
			default:
				errsCh <- err
			}
		}(i)
	}
	close(start)
	wg.Wait()
	close(errsCh)
	for err := range errsCh {
		t.Fatalf("unexpected update error: %v", err)
	}
	mu.Lock()
	defer mu.Unlock()
	if len(succeeded) == 0 {
		t.Fatal("no concurrent Update succeeded")
	}
	final := mustGet(t, env.storeA, "contended-update")
	if !succeeded[final.Owner] {
		t.Fatalf("final owner %q is not a successful writer", final.Owner)
	}
	want := testRecord("contended-update")
	want.Owner = final.Owner
	want.State = kmipcore.StateActive
	want.Object.SymmetricKey.KeyBlock.Value.Material =
		kmipcore.NewByteString(kmipcore.TagKeyMaterial, []byte(final.Owner))
	requireRecordEqual(t, want, final)
}

// TestConcurrentDeleteAndUpdate verifies that a delete racing with updates always wins the final
// state and that no update recreates the record. | TestConcurrentDeleteAndUpdate 验证与更新竞争的删除
// 始终取得最终状态，且任何更新都不会重建记录。
func TestConcurrentDeleteAndUpdate(t *testing.T) {
	env := newTestEnv(t, "")
	const updaters = 8
	ctx := context.Background()
	if err := env.storeA.Create(ctx, testRecord("delete-race")); err != nil {
		t.Fatalf("Create: %v", err)
	}
	var wg sync.WaitGroup
	var deleteErr error
	errsCh := make(chan error, updaters+1)
	start := make(chan struct{})
	wg.Add(1)
	go func() {
		defer wg.Done()
		<-start
		deleteErr = env.storeB.Delete(ctx, "delete-race")
	}()
	for i := 0; i < updaters; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			store := env.storeA
			if i%2 == 1 {
				store = env.storeB
			}
			<-start
			record, err := store.Get(ctx, "delete-race")
			if err != nil {
				if !errors.Is(err, kmipcore.ErrItemNotFound) {
					errsCh <- err
				}
				return
			}
			record.Owner = "updater-" + strconv.Itoa(i)
			err = store.Update(ctx, record)
			if err != nil &&
				!errors.Is(err, kmipcore.ErrItemNotFound) &&
				!errors.Is(err, ErrConflict) {
				errsCh <- err
			}
		}(i)
	}
	close(start)
	wg.Wait()
	close(errsCh)
	for err := range errsCh {
		t.Fatalf("unexpected error: %v", err)
	}
	if deleteErr != nil {
		t.Fatalf("Delete: %v", deleteErr)
	}
	_, err := env.storeA.Get(ctx, "delete-race")
	requireErrorIs(t, err, kmipcore.ErrItemNotFound, "Get after delete race")
	list, err := env.storeA.List(ctx)
	if err != nil {
		t.Fatalf("List: %v", err)
	}
	if len(list) != 0 {
		t.Fatalf("List after delete race returned %d records", len(list))
	}
}

// TestConcurrentCreateDeleteSameIdentifier verifies that Create and Delete racing on one identifier
// end in one of the two legal states and never leave an index entry without a record.
// | TestConcurrentCreateDeleteSameIdentifier 验证针对同一标识符竞争的 Create 与 Delete 最终处于两种
// 合法状态之一，且绝不会留下没有记录的索引成员。
func TestConcurrentCreateDeleteSameIdentifier(t *testing.T) {
	env := newTestEnv(t, "")
	ctx := context.Background()
	const rounds = 20
	for round := 0; round < rounds; round++ {
		identifier := "create-delete-" + strconv.Itoa(round)
		var wg sync.WaitGroup
		errsCh := make(chan error, 2)
		start := make(chan struct{})
		wg.Add(2)
		go func() {
			defer wg.Done()
			<-start
			if err := env.storeA.Create(ctx, testRecord(identifier)); err != nil &&
				!errors.Is(err, kmipcore.ErrObjectExists) {
				errsCh <- err
			}
		}()
		go func() {
			defer wg.Done()
			<-start
			if err := env.storeB.Delete(ctx, identifier); err != nil &&
				!errors.Is(err, kmipcore.ErrItemNotFound) {
				errsCh <- err
			}
		}()
		close(start)
		wg.Wait()
		close(errsCh)
		for err := range errsCh {
			t.Fatalf("round %d: %v", round, err)
		}
		record, err := env.storeA.Get(ctx, identifier)
		switch {
		case err == nil:
			requireRecordEqual(t, testRecord(identifier), record)
		case errors.Is(err, kmipcore.ErrItemNotFound):
		default:
			t.Fatalf("round %d Get: %v", round, err)
		}
	}
	list, err := env.storeA.List(ctx)
	if err != nil {
		t.Fatalf("List: %v", err)
	}
	for _, record := range list {
		got, err := env.storeA.Get(ctx, record.UniqueIdentifier)
		if err != nil {
			t.Fatalf("List member %q is not readable: %v", record.UniqueIdentifier, err)
		}
		requireRecordEqual(t, record, got)
	}
}
