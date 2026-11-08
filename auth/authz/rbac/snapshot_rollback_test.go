package rbac

import (
	"context"
	"errors"
	"testing"
)

// errInjectedStoreFailure is the deterministic failure returned by faultSnapshotStore. |
// errInjectedStoreFailure 是 faultSnapshotStore 返回的确定性失败。
var errInjectedStoreFailure = errors.New("injected store failure")

// faultSnapshotStore injects Reset and AddRole failures. | faultSnapshotStore 注入 Reset 与 AddRole 失败。
type faultSnapshotStore struct {
	*MemoryStore
	resetFailures      int
	addRoleFailAt      int
	addRoleCalls       int
	addRoleFailForever bool
}

// Reset implements Store. A negative resetFailures fails every call; a positive value fails that
// many calls and then delegates. | Reset 实现 Store。负值表示每次调用都失败；正值表示失败该次数后委托。
func (s *faultSnapshotStore) Reset(ctx context.Context) error {
	if s.resetFailures < 0 || s.resetFailures > 0 {
		if s.resetFailures > 0 {
			s.resetFailures--
		}
		return errInjectedStoreFailure
	}
	return s.MemoryStore.Reset(ctx)
}

// AddRole implements Store. | AddRole 实现 Store。
func (s *faultSnapshotStore) AddRole(ctx context.Context, role Role) error {
	s.addRoleCalls++
	if s.addRoleFailForever || (s.addRoleFailAt > 0 && s.addRoleCalls == s.addRoleFailAt) {
		return errInjectedStoreFailure
	}
	return s.MemoryStore.AddRole(ctx, role)
}

// newRollbackFixture returns an engine backed by a fault store holding one role, assignment and
// policy. | newRollbackFixture 返回由持有角色、分配与策略的故障存储支撑的引擎。
func newRollbackFixture(t *testing.T, store *faultSnapshotStore) *Engine {
	t.Helper()
	ctx := context.Background()
	if err := store.MemoryStore.AddRole(ctx, Role{Name: "old", Permissions: []string{"old:read"}}); err != nil {
		t.Fatalf("AddRole old: %v", err)
	}
	if err := store.MemoryStore.Assign(ctx, Assignment{Subject: "alice", Role: "old", Scope: "tenant:1"}); err != nil {
		t.Fatalf("Assign old: %v", err)
	}
	if err := store.MemoryStore.AddPolicy(ctx, Policy{ID: "old-policy", Effect: EffectPermit, Action: "old:read"}); err != nil {
		t.Fatalf("AddPolicy old: %v", err)
	}
	return New(WithStore(store))
}

// assertOldStateRestored checks that the fixture state survived a failed load. | assertOldStateRestored
// 检查夹具状态在装载失败后仍然存在。
func assertOldStateRestored(t *testing.T, engine *Engine) {
	t.Helper()
	ctx := context.Background()
	role, err := engine.GetRole(ctx, "old")
	if err != nil {
		t.Fatalf("old role is missing after rollback: %v", err)
	}
	if role.Permissions[0] != "old:read" {
		t.Fatalf("old role = %+v", role)
	}
	if _, err := engine.GetRole(ctx, "new"); !errors.Is(err, ErrRoleNotFound) {
		t.Fatalf("partially loaded new role survived rollback: %v", err)
	}
	assignments, err := engine.Assignments(ctx, "alice")
	if err != nil {
		t.Fatalf("Assignments: %v", err)
	}
	if len(assignments) != 1 || assignments[0].Role != "old" {
		t.Fatalf("assignments after rollback = %+v", assignments)
	}
	if _, err := engine.GetPolicy(ctx, "old-policy"); err != nil {
		t.Fatalf("old policy is missing after rollback: %v", err)
	}
}

// replacementSnapshot returns a snapshot replacing the fixture state with role new. |
// replacementSnapshot 返回把夹具状态替换为角色 new 的快照。
func replacementSnapshot() Snapshot {
	return Snapshot{
		Version: SnapshotVersion,
		Roles: []Role{
			{Name: "new", Permissions: []string{"new:read"}},
			{Name: "new-child", Parents: []string{"new"}},
		},
	}
}

// TestLoadSnapshotResetFailureRestoresPrevious covers a failing Reset with a successful restore. |
// TestLoadSnapshotResetFailureRestoresPrevious 覆盖 Reset 失败但恢复成功。
func TestLoadSnapshotResetFailureRestoresPrevious(t *testing.T) {
	store := &faultSnapshotStore{MemoryStore: NewMemoryStore(), resetFailures: 1}
	engine := newRollbackFixture(t, store)
	err := engine.LoadSnapshot(context.Background(), replacementSnapshot())
	if !errors.Is(err, errInjectedStoreFailure) {
		t.Fatalf("error = %v, want the injected Reset failure", err)
	}
	if errors.Is(err, ErrSnapshotRestore) {
		t.Fatalf("successful restore reported ErrSnapshotRestore: %v", err)
	}
	assertOldStateRestored(t, engine)
}

// TestLoadSnapshotAddRoleFailureRestoresPrevious covers a mid-load AddRole failure with a successful
// restore. | TestLoadSnapshotAddRoleFailureRestoresPrevious 覆盖装载中途 AddRole 失败但恢复成功。
func TestLoadSnapshotAddRoleFailureRestoresPrevious(t *testing.T) {
	store := &faultSnapshotStore{MemoryStore: NewMemoryStore(), addRoleFailAt: 2}
	engine := newRollbackFixture(t, store)
	err := engine.LoadSnapshot(context.Background(), replacementSnapshot())
	if !errors.Is(err, errInjectedStoreFailure) {
		t.Fatalf("error = %v, want the injected AddRole failure", err)
	}
	if errors.Is(err, ErrSnapshotRestore) {
		t.Fatalf("successful restore reported ErrSnapshotRestore: %v", err)
	}
	assertOldStateRestored(t, engine)
}

// TestLoadSnapshotRestoreFailureJoinsErrors covers a failed load followed by a failed restore. |
// TestLoadSnapshotRestoreFailureJoinsErrors 覆盖装载失败后恢复也失败。
func TestLoadSnapshotRestoreFailureJoinsErrors(t *testing.T) {
	store := &faultSnapshotStore{MemoryStore: NewMemoryStore(), addRoleFailForever: true}
	engine := newRollbackFixture(t, store)
	err := engine.LoadSnapshot(context.Background(), replacementSnapshot())
	if !errors.Is(err, ErrSnapshotRestore) {
		t.Fatalf("error = %v, want ErrSnapshotRestore", err)
	}
	if !errors.Is(err, errInjectedStoreFailure) {
		t.Fatalf("error = %v, want the injected store failure", err)
	}
}

// TestLoadSnapshotResetAndRestoreFailure covers failing Reset and failing restore. |
// TestLoadSnapshotResetAndRestoreFailure 覆盖 Reset 失败且恢复失败。
func TestLoadSnapshotResetAndRestoreFailure(t *testing.T) {
	store := &faultSnapshotStore{MemoryStore: NewMemoryStore(), resetFailures: -1}
	engine := newRollbackFixture(t, store)
	err := engine.LoadSnapshot(context.Background(), replacementSnapshot())
	if !errors.Is(err, ErrSnapshotRestore) {
		t.Fatalf("error = %v, want ErrSnapshotRestore", err)
	}
	if !errors.Is(err, errInjectedStoreFailure) {
		t.Fatalf("error = %v, want the injected store failure", err)
	}
}
