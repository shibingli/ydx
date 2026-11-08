package rbac

import (
	"context"
	"errors"

	"github.com/shibingli/ydx/errs"
	"github.com/shibingli/ydx/json"
)

// SnapshotVersion is the snapshot schema version written by MarshalSnapshot and accepted by
// LoadSnapshot. | SnapshotVersion 是 MarshalSnapshot 写入且 LoadSnapshot 接受的快照模式版本。
const SnapshotVersion = 1

// Snapshot is the complete serializable state of an Engine. | Snapshot 是 Engine 的完整可序列化状态。
type Snapshot struct {
	// Version is the schema version; it must equal SnapshotVersion on load. | Version 是模式版本；加载时必须等于 SnapshotVersion。
	Version int `json:"version"`
	// Roles is the stored role set. | Roles 是已存角色集合。
	Roles []Role `json:"roles,omitempty"`
	// Assignments is the stored subject-role-scope assignment set. | Assignments 是已存的主体、角色与作用域分配集合。
	Assignments []Assignment `json:"assignments,omitempty"`
	// Policies is the stored policy set. | Policies 是已存策略集合。
	Policies []Policy `json:"policies,omitempty"`
}

// Snapshot returns the complete state of the engine. | Snapshot 返回引擎的完整状态。
func (e *Engine) Snapshot(ctx context.Context) (Snapshot, error) {
	ctx = normalizeContext(ctx)
	if err := checkContext(ctx); err != nil {
		return Snapshot{}, err
	}
	e.stateMu.RLock()
	roles, err := e.store.ListRoles(ctx)
	var assignments []Assignment
	if err == nil {
		assignments, err = e.store.ListAssignments(ctx)
	}
	var policies []Policy
	if err == nil {
		policies, err = e.store.ListPolicies(ctx)
	}
	e.stateMu.RUnlock()
	if err != nil {
		return Snapshot{}, err
	}
	return Snapshot{
		Version:     SnapshotVersion,
		Roles:       roles,
		Assignments: assignments,
		Policies:    policies,
	}, nil
}

// LoadSnapshot replaces the engine state with snapshot. | LoadSnapshot 用 snapshot 替换引擎状态。
//
// The snapshot is validated in a temporary in-memory store before the active store is touched, so an
// invalid snapshot leaves the engine unchanged. A version other than SnapshotVersion is rejected
// with ErrUnsupportedVersion. The Reset and reload run under the engine's exclusive state lock, so
// concurrent Engine methods never observe the empty or partially loaded state. Before touching the
// store, LoadSnapshot captures the previous state; if Reset or the reload fails, it attempts to
// restore that state. A failed restore returns an error that joins the load and restore failures and
// matches ErrSnapshotRestore; a successful restore returns the original load error. | 快照先在临时内存
// 存储中校验，再触碰活动存储，因此非法快照不会改变引擎。版本不等于 SnapshotVersion 时以
// ErrUnsupportedVersion 拒绝。Reset 与重新加载在引擎排他状态锁内执行，因此并发 Engine 方法绝不会
// 观察到空状态或部分加载状态。触碰存储前，LoadSnapshot 会捕获先前状态；若 Reset 或重新加载失败，
// 它会尝试恢复该状态。恢复失败返回合并装载与恢复失败的错误并匹配 ErrSnapshotRestore；恢复成功则
// 返回原始装载错误。
func (e *Engine) LoadSnapshot(ctx context.Context, snapshot Snapshot) error {
	ctx = normalizeContext(ctx)
	if err := checkContext(ctx); err != nil {
		return err
	}
	if snapshot.Version != SnapshotVersion {
		return errs.Detail(ErrUnsupportedVersion, "got %d want %d | 得到 %d 需要 %d",
			snapshot.Version, SnapshotVersion, snapshot.Version, SnapshotVersion)
	}
	probe := NewMemoryStore()
	if err := loadInto(ctx, probe, snapshot); err != nil {
		return errs.Wrap(err, ErrInvalidSnapshot)
	}
	e.stateMu.Lock()
	defer e.stateMu.Unlock()
	previous, err := captureSnapshot(ctx, e.store)
	if err != nil {
		return err
	}
	if err := e.store.Reset(ctx); err != nil {
		return e.restoreAfterFailure(ctx, previous, err)
	}
	if err := loadInto(ctx, e.store, snapshot); err != nil {
		return e.restoreAfterFailure(ctx, previous, err)
	}
	return nil
}

// captureSnapshot reads the complete current state while the caller holds the engine state lock. |
// captureSnapshot 在调用方持有引擎状态锁时读取完整的当前状态。
func captureSnapshot(ctx context.Context, store Store) (Snapshot, error) {
	roles, err := store.ListRoles(ctx)
	if err != nil {
		return Snapshot{}, err
	}
	assignments, err := store.ListAssignments(ctx)
	if err != nil {
		return Snapshot{}, err
	}
	policies, err := store.ListPolicies(ctx)
	if err != nil {
		return Snapshot{}, err
	}
	return Snapshot{
		Version:     SnapshotVersion,
		Roles:       roles,
		Assignments: assignments,
		Policies:    policies,
	}, nil
}

// restoreAfterFailure resets the store and reloads previous. If either step fails it returns an
// error joining the load and restore failures and matching ErrSnapshotRestore. | restoreAfterFailure
// 重置存储并重新加载 previous。任一步骤失败时返回合并装载与恢复失败并匹配 ErrSnapshotRestore 的错误。
func (e *Engine) restoreAfterFailure(ctx context.Context, previous Snapshot, loadErr error) error {
	restoreErr := e.store.Reset(ctx)
	if restoreErr == nil {
		restoreErr = loadInto(ctx, e.store, previous)
	}
	if restoreErr == nil {
		return loadErr
	}
	return errs.WrapDetail(errors.Join(loadErr, restoreErr), ErrSnapshotRestore,
		"snapshot load failed and the previous state could not be restored | 快照装载失败且无法恢复先前状态")
}

// loadInto writes a snapshot into a store. | loadInto 把快照写入存储。
func loadInto(ctx context.Context, store Store, snapshot Snapshot) error {
	for _, role := range snapshot.Roles {
		if err := store.AddRole(ctx, role); err != nil {
			return err
		}
	}
	for _, policy := range snapshot.Policies {
		if err := store.AddPolicy(ctx, policy); err != nil {
			return err
		}
	}
	for _, assignment := range snapshot.Assignments {
		if err := store.Assign(ctx, assignment); err != nil {
			return err
		}
	}
	return nil
}

// MarshalSnapshot encodes the current state with ydx/json. | MarshalSnapshot 使用 ydx/json 编码当前状态。
func (e *Engine) MarshalSnapshot(ctx context.Context) ([]byte, error) {
	snapshot, err := e.Snapshot(ctx)
	if err != nil {
		return nil, err
	}
	data, err := json.Marshal(snapshot)
	if err != nil {
		return nil, errs.Wrap(err, ErrInvalidSnapshot)
	}
	return data, nil
}

// UnmarshalSnapshot decodes data with ydx/json and loads it as the engine state. | UnmarshalSnapshot
// 使用 ydx/json 解码 data 并作为引擎状态加载。
func (e *Engine) UnmarshalSnapshot(ctx context.Context, data []byte) error {
	var snapshot Snapshot
	if err := json.Unmarshal(data, &snapshot); err != nil {
		return errs.Wrap(err, ErrInvalidSnapshot)
	}
	return e.LoadSnapshot(ctx, snapshot)
}
