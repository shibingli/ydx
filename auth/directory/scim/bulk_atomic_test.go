package scim

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"sort"
	"strings"
	"testing"

	"github.com/shibingli/ydx/errs"
	"github.com/shibingli/ydx/router"
)

// bulkFaults injects failures into a faultStore. Each callback runs before the embedded store
// operation and returns an error to fail the call. | bulkFaults 向 faultStore 注入故障。每个回调在
// 内嵌存储操作之前运行，返回错误即使该调用失败。
type bulkFaults struct {
	// getUser fails GetUser. | getUser 使 GetUser 失败。
	getUser func(ctx context.Context, id string) error
	// createUser fails CreateUser. | createUser 使 CreateUser 失败。
	createUser func(ctx context.Context, user *User) error
	// replaceUser fails ReplaceUser. | replaceUser 使 ReplaceUser 失败。
	replaceUser func(ctx context.Context, user *User) error
	// deleteUser fails DeleteUser. | deleteUser 使 DeleteUser 失败。
	deleteUser func(ctx context.Context, id string) error
	// getGroup fails GetGroup. | getGroup 使 GetGroup 失败。
	getGroup func(ctx context.Context, id string) error
	// createGroup fails CreateGroup. | createGroup 使 CreateGroup 失败。
	createGroup func(ctx context.Context, group *Group) error
	// replaceGroup fails ReplaceGroup. | replaceGroup 使 ReplaceGroup 失败。
	replaceGroup func(ctx context.Context, group *Group) error
	// deleteGroup fails DeleteGroup. | deleteGroup 使 DeleteGroup 失败。
	deleteGroup func(ctx context.Context, id string) error
}

// faultStore wraps a Store and injects per-call failures. | faultStore 包装 Store 并按调用注入故障。
type faultStore struct {
	// Store is the backing store. | Store 是底层存储。
	Store
	// faults carries the failure callbacks. | faults 承载失败回调。
	faults bulkFaults
}

// GetUser injects a failure and delegates to the backing store. | GetUser 注入失败并委托给底层存储。
func (s *faultStore) GetUser(ctx context.Context, id string) (*User, error) {
	if s.faults.getUser != nil {
		if err := s.faults.getUser(ctx, id); err != nil {
			return nil, err
		}
	}
	return s.Store.GetUser(ctx, id)
}

// CreateUser injects a failure and delegates to the backing store. | CreateUser 注入失败并委托给底层
// 存储。
func (s *faultStore) CreateUser(ctx context.Context, user *User) (*User, error) {
	if s.faults.createUser != nil {
		if err := s.faults.createUser(ctx, user); err != nil {
			return nil, err
		}
	}
	return s.Store.CreateUser(ctx, user)
}

// ReplaceUser injects a failure and delegates to the backing store. | ReplaceUser 注入失败并委托给
// 底层存储。
func (s *faultStore) ReplaceUser(ctx context.Context, user *User) (*User, error) {
	if s.faults.replaceUser != nil {
		if err := s.faults.replaceUser(ctx, user); err != nil {
			return nil, err
		}
	}
	return s.Store.ReplaceUser(ctx, user)
}

// DeleteUser injects a failure and delegates to the backing store. | DeleteUser 注入失败并委托给底层
// 存储。
func (s *faultStore) DeleteUser(ctx context.Context, id string) error {
	if s.faults.deleteUser != nil {
		if err := s.faults.deleteUser(ctx, id); err != nil {
			return err
		}
	}
	return s.Store.DeleteUser(ctx, id)
}

// GetGroup injects a failure and delegates to the backing store. | GetGroup 注入失败并委托给底层存储。
func (s *faultStore) GetGroup(ctx context.Context, id string) (*Group, error) {
	if s.faults.getGroup != nil {
		if err := s.faults.getGroup(ctx, id); err != nil {
			return nil, err
		}
	}
	return s.Store.GetGroup(ctx, id)
}

// CreateGroup injects a failure and delegates to the backing store. | CreateGroup 注入失败并委托给
// 底层存储。
func (s *faultStore) CreateGroup(ctx context.Context, group *Group) (*Group, error) {
	if s.faults.createGroup != nil {
		if err := s.faults.createGroup(ctx, group); err != nil {
			return nil, err
		}
	}
	return s.Store.CreateGroup(ctx, group)
}

// ReplaceGroup injects a failure and delegates to the backing store. | ReplaceGroup 注入失败并委托给
// 底层存储。
func (s *faultStore) ReplaceGroup(ctx context.Context, group *Group) (*Group, error) {
	if s.faults.replaceGroup != nil {
		if err := s.faults.replaceGroup(ctx, group); err != nil {
			return nil, err
		}
	}
	return s.Store.ReplaceGroup(ctx, group)
}

// DeleteGroup injects a failure and delegates to the backing store. | DeleteGroup 注入失败并委托给
// 底层存储。
func (s *faultStore) DeleteGroup(ctx context.Context, id string) error {
	if s.faults.deleteGroup != nil {
		if err := s.faults.deleteGroup(ctx, id); err != nil {
			return err
		}
	}
	return s.Store.DeleteGroup(ctx, id)
}

// newBulkStoreEnv creates a test environment over an arbitrary Store. | newBulkStoreEnv 在任意 Store
// 之上创建测试环境。
func newBulkStoreEnv(t *testing.T, store Store, options Options) *testEnv {
	t.Helper()
	options.Store = store
	server, err := New(options)
	if err != nil {
		t.Fatalf("New() error = %v", err)
	}
	engine := router.New()
	server.Register(engine, "/scim")
	return &testEnv{t: t, server: server, engine: engine, prefix: "/scim"}
}

// patchDisplayName builds a PatchOp body replacing displayName. | patchDisplayName 构建替换
// displayName 的 PatchOp 请求体。
func patchDisplayName(value string) map[string]any {
	return map[string]any{
		"schemas":    []string{PatchOpSchema},
		"Operations": []any{map[string]any{"op": "replace", "path": "displayName", "value": value}},
	}
}

// listUserNames returns the stored user names sorted for stable comparison. |
// listUserNames 按排序返回已存储用户名，便于稳定比较。
func listUserNames(t *testing.T, store Store) []string {
	t.Helper()
	users, _, err := store.ListUsers(context.Background(), ListQuery{Count: -1})
	if err != nil {
		t.Fatalf("ListUsers error = %v", err)
	}
	names := make([]string, 0, len(users))
	for _, user := range users {
		names = append(names, user.UserName)
	}
	sort.Strings(names)
	return names
}

// TestBulkAtomicSuccessUserAndGroupOperations verifies every atomic mutation kind commits when the
// whole transaction succeeds. | TestBulkAtomicSuccessUserAndGroupOperations 校验整个事务成功时每种
// 原子变更都能提交。
func TestBulkAtomicSuccessUserAndGroupOperations(t *testing.T) {
	env := newBulkStoreEnv(t, NewMemoryStore(), Options{BulkAtomic: true})
	userForPut := env.mustCreateUser(map[string]any{"userName": "atomic-put"})
	userForPatch := env.mustCreateUser(map[string]any{"userName": "atomic-patch"})
	userForDelete := env.mustCreateUser(map[string]any{"userName": "atomic-delete"})
	groupForPut := env.mustCreateGroup(map[string]any{"displayName": "atomic-put-group"})
	groupForPatch := env.mustCreateGroup(map[string]any{"displayName": "atomic-patch-group"})
	groupForDelete := env.mustCreateGroup(map[string]any{"displayName": "atomic-delete-group"})

	recorder := env.do(http.MethodPost, "/Bulk", BulkRequest{
		Operations: []BulkOperation{
			{BulkID: "created-user", Method: "POST", Path: "/Users", Data: map[string]any{
				"userName": "atomic-created", "displayName": "created",
			}},
			{Method: "PUT", Path: "/Users/" + userForPut.ID, Data: map[string]any{
				"userName": "atomic-put", "displayName": "put-updated",
			}},
			{Method: "PATCH", Path: "/Users/" + userForPatch.ID, Data: patchDisplayName("patch-updated")},
			{Method: "DELETE", Path: "/Users/" + userForDelete.ID},
			{BulkID: "created-group", Method: "POST", Path: "/Groups", Data: map[string]any{
				"displayName": "atomic-created-group",
				"members":     []any{map[string]any{"value": "bulkId:created-user", "type": "User"}},
			}},
			{Method: "PUT", Path: "/Groups/" + groupForPut.ID, Data: map[string]any{
				"displayName": "put-updated-group",
			}},
			{Method: "PATCH", Path: "/Groups/" + groupForPatch.ID, Data: patchDisplayName("patch-updated-group")},
			{Method: "DELETE", Path: "/Groups/" + groupForDelete.ID},
		},
	}, nil)
	requireStatus(t, recorder, http.StatusOK)
	response := decodeResponse[BulkResponse](t, recorder)
	wantStatuses := []string{"201", "200", "200", "204", "201", "200", "200", "204"}
	if len(response.Operations) != len(wantStatuses) {
		t.Fatalf("operations = %+v", response.Operations)
	}
	for i, want := range wantStatuses {
		if response.Operations[i].Status != want {
			t.Fatalf("operation %d = %+v, want status %s", i, response.Operations[i], want)
		}
	}

	createdUser := bulkOperationResource[User](t, response.Operations[0])
	createdGroup := bulkOperationResource[Group](t, response.Operations[4])
	if len(createdGroup.Members) != 1 || createdGroup.Members[0].Value != createdUser.ID {
		t.Fatalf("created group members = %+v, created user = %q", createdGroup.Members, createdUser.ID)
	}
	storedPut, err := env.server.store.GetUser(t.Context(), userForPut.ID)
	if err != nil || storedPut.DisplayName != "put-updated" {
		t.Fatalf("PUT user = %+v, %v", storedPut, err)
	}
	storedPatch, err := env.server.store.GetUser(t.Context(), userForPatch.ID)
	if err != nil || storedPatch.DisplayName != "patch-updated" {
		t.Fatalf("PATCH user = %+v, %v", storedPatch, err)
	}
	if _, err := env.server.store.GetUser(t.Context(), userForDelete.ID); !errors.Is(err, ErrNotFound) {
		t.Fatalf("deleted user error = %v, want ErrNotFound", err)
	}
	storedGroupPut, err := env.server.store.GetGroup(t.Context(), groupForPut.ID)
	if err != nil || storedGroupPut.DisplayName != "put-updated-group" {
		t.Fatalf("PUT group = %+v, %v", storedGroupPut, err)
	}
	storedGroupPatch, err := env.server.store.GetGroup(t.Context(), groupForPatch.ID)
	if err != nil || storedGroupPatch.DisplayName != "patch-updated-group" {
		t.Fatalf("PATCH group = %+v, %v", storedGroupPatch, err)
	}
	if _, err := env.server.store.GetGroup(t.Context(), groupForDelete.ID); !errors.Is(err, ErrNotFound) {
		t.Fatalf("deleted group error = %v, want ErrNotFound", err)
	}
}

// TestBulkAtomicRollbackRestoresAllPriorState verifies a mid-transaction failure undoes every
// mutation kind in reverse order. | TestBulkAtomicRollbackRestoresAllPriorState 校验事务中途失败会
// 按逆序撤销每种变更。
func TestBulkAtomicRollbackRestoresAllPriorState(t *testing.T) {
	env := newBulkStoreEnv(t, NewMemoryStore(), Options{BulkAtomic: true})
	user := env.mustCreateUser(map[string]any{"userName": "rollback-user", "displayName": "before"})
	group := env.mustCreateGroup(map[string]any{"displayName": "before-group"})
	removedGroup := env.mustCreateGroup(map[string]any{"displayName": "gone-group"})

	recorder := env.do(http.MethodPost, "/Bulk", BulkRequest{
		Operations: []BulkOperation{
			{Method: "PUT", Path: "/Users/" + user.ID, Data: map[string]any{
				"userName": "rollback-user", "displayName": "after",
			}},
			{Method: "PATCH", Path: "/Groups/" + group.ID, Data: patchDisplayName("after-group")},
			{BulkID: "new-user", Method: "POST", Path: "/Users", Data: map[string]any{"userName": "rollback-created"}},
			{BulkID: "new-group", Method: "POST", Path: "/Groups", Data: map[string]any{"displayName": "rollback-created-group"}},
			{Method: "DELETE", Path: "/Groups/" + removedGroup.ID},
			{Method: "POST", Path: "/Users", Data: map[string]any{"userName": "rollback-user"}},
		},
	}, nil)
	requireError(t, recorder, http.StatusConflict, "uniqueness")

	storedUser, err := env.server.store.GetUser(t.Context(), user.ID)
	if err != nil || storedUser.DisplayName != "before" {
		t.Fatalf("restored user = %+v, %v", storedUser, err)
	}
	storedGroup, err := env.server.store.GetGroup(t.Context(), group.ID)
	if err != nil || storedGroup.DisplayName != "before-group" {
		t.Fatalf("restored group = %+v, %v", storedGroup, err)
	}
	restoredRemoved, err := env.server.store.GetGroup(t.Context(), removedGroup.ID)
	if err != nil || restoredRemoved.DisplayName != "gone-group" {
		t.Fatalf("recreated group = %+v, %v", restoredRemoved, err)
	}
	names := listUserNames(t, env.server.store)
	if len(names) != 1 || names[0] != "rollback-user" {
		t.Fatalf("users after rollback = %v", names)
	}
	groups, total, err := env.server.store.ListGroups(t.Context(), ListQuery{Count: -1})
	if err != nil || total != 2 {
		t.Fatalf("groups after rollback = %d, %v", total, err)
	}
	for _, stored := range groups {
		if strings.HasPrefix(stored.DisplayName, "rollback-created") {
			t.Fatalf("created group survived rollback: %+v", stored)
		}
	}
}

// TestBulkAtomicBulkIDMappingsRemoved verifies rollback removes request-scoped bulkId mappings for
// every rolled-back entry, applied or not. | TestBulkAtomicBulkIDMappingsRemoved 校验回滚会移除每个
// 已回滚条目的请求内 bulkId 映射，无论该条目是否已应用。
func TestBulkAtomicBulkIDMappingsRemoved(t *testing.T) {
	ctx := context.Background()
	store := NewMemoryStore()
	user, err := store.CreateUser(ctx, &User{UserName: "undo-map", DisplayName: "before"})
	if err != nil {
		t.Fatalf("CreateUser error = %v", err)
	}
	undo := newBulkUndoLog(DefaultBulkMaxUndoBytes)
	handle, err := undo.prepareUserRestore(user, "applied")
	if err != nil {
		t.Fatalf("prepareUserRestore error = %v", err)
	}
	changed := user.Clone()
	changed.DisplayName = "after"
	stored, err := store.ReplaceUser(ctx, changed)
	if err != nil {
		t.Fatalf("ReplaceUser error = %v", err)
	}
	handle.markApplied(userVersion(stored))
	if _, err := undo.prepareUserRestore(user, "unapplied"); err != nil {
		t.Fatalf("prepareUserRestore error = %v", err)
	}
	ids := map[string]string{"applied": user.ID, "unapplied": "never-created", "other": "kept"}
	result := undo.rollback(ctx, store, ids)
	if result.err != nil || result.conflicts != 0 || result.failures != 0 {
		t.Fatalf("rollback result = %+v", result)
	}
	if _, ok := ids["applied"]; ok {
		t.Fatalf("applied bulkId mapping survived rollback: %v", ids)
	}
	if _, ok := ids["unapplied"]; ok {
		t.Fatalf("unapplied bulkId mapping survived rollback: %v", ids)
	}
	if ids["other"] != "kept" {
		t.Fatalf("unrelated bulkId mapping removed: %v", ids)
	}
	restored, err := store.GetUser(ctx, user.ID)
	if err != nil || restored.DisplayName != "before" {
		t.Fatalf("restored user = %+v, %v", restored, err)
	}
}

// TestBulkAtomicPasswordSetterFailureRollsBackCreates verifies a rejected password does not leave
// the created resource or earlier operations behind. | TestBulkAtomicPasswordSetterFailureRollsBackCreates
// 校验口令被拒绝时不会留下已创建资源或先前操作。
func TestBulkAtomicPasswordSetterFailureRollsBackCreates(t *testing.T) {
	env := newBulkStoreEnv(t, NewMemoryStore(), Options{
		BulkAtomic: true,
		PasswordSetter: func(ctx context.Context, user *User, password string) error {
			return errors.New("rejected by hook")
		},
	})
	recorder := env.do(http.MethodPost, "/Bulk", BulkRequest{
		Operations: []BulkOperation{
			{Method: "POST", Path: "/Users", Data: map[string]any{"userName": "hook-kept"}},
			{Method: "POST", Path: "/Users", Data: map[string]any{
				"userName": "hook-rejected", "password": "test-password",
			}},
			{Method: "POST", Path: "/Users", Data: map[string]any{"userName": "hook-skipped"}},
		},
	}, nil)
	requireError(t, recorder, http.StatusBadRequest, "invalidValue")
	if names := listUserNames(t, env.server.store); len(names) != 0 {
		t.Fatalf("users after password failure = %v", names)
	}
}

// TestBulkAtomicPatchPasswordFailureRestoresPriorUser verifies a password hook failure after the
// store committed a PATCH restores the pre-transaction resource. | TestBulkAtomicPatchPasswordFailureRestoresPriorUser
// 校验存储已提交 PATCH 后口令钩子失败会恢复事务前资源。
func TestBulkAtomicPatchPasswordFailureRestoresPriorUser(t *testing.T) {
	env := newBulkStoreEnv(t, NewMemoryStore(), Options{
		BulkAtomic: true,
		PasswordSetter: func(ctx context.Context, user *User, password string) error {
			return errors.New("rejected by hook")
		},
	})
	user := env.mustCreateUser(map[string]any{"userName": "patch-hook", "displayName": "before"})
	recorder := env.do(http.MethodPost, "/Bulk", BulkRequest{
		Operations: []BulkOperation{
			{Method: "PATCH", Path: "/Users/" + user.ID, Data: map[string]any{
				"schemas": []string{PatchOpSchema},
				"Operations": []any{
					map[string]any{"op": "replace", "path": "displayName", "value": "after"},
					map[string]any{"op": "replace", "path": "password", "value": "test-password"},
				},
			}},
		},
	}, nil)
	requireError(t, recorder, http.StatusBadRequest, "invalidValue")
	stored, err := env.server.store.GetUser(t.Context(), user.ID)
	if err != nil || stored.DisplayName != "before" {
		t.Fatalf("restored user = %+v, %v", stored, err)
	}
}

// TestBulkAtomicStoreFailureDuringApplyRollsBack verifies an injected store failure in the middle
// of a transaction rolls back prior operations and hides backend text. |
// TestBulkAtomicStoreFailureDuringApplyRollsBack 校验事务中途注入的存储故障会回滚先前操作并隐藏后端
// 文本。
func TestBulkAtomicStoreFailureDuringApplyRollsBack(t *testing.T) {
	base := NewMemoryStore()
	faults := &faultStore{Store: base}
	env := newBulkStoreEnv(t, faults, Options{BulkAtomic: true})
	user := env.mustCreateUser(map[string]any{"userName": "apply-fault", "displayName": "before"})
	faults.faults.replaceUser = func(ctx context.Context, incoming *User) error {
		if incoming.ID == user.ID {
			return errors.New("injected apply failure super-secret-token")
		}
		return nil
	}
	recorder := env.do(http.MethodPost, "/Bulk", BulkRequest{
		Operations: []BulkOperation{
			{Method: "POST", Path: "/Users", Data: map[string]any{"userName": "apply-created"}},
			{Method: "PATCH", Path: "/Users/" + user.ID, Data: patchDisplayName("after")},
		},
	}, nil)
	requireStatus(t, recorder, http.StatusInternalServerError)
	if body := recorder.Body.String(); strings.Contains(body, "super-secret-token") {
		t.Fatalf("response leaked backend text: %s", body)
	}
	stored, err := env.server.store.GetUser(t.Context(), user.ID)
	if err != nil || stored.DisplayName != "before" {
		t.Fatalf("user after apply failure = %+v, %v", stored, err)
	}
	if names := listUserNames(t, env.server.store); len(names) != 1 || names[0] != "apply-fault" {
		t.Fatalf("users after apply failure = %v", names)
	}
}

// TestBulkAtomicStoreFailureDuringRollbackReportsCombinedError verifies a rollback store failure
// produces a generic 500 without exposing the backend message or secret. |
// TestBulkAtomicStoreFailureDuringRollbackReportsCombinedError 校验回滚存储故障产生通用 500，且不
// 暴露后端消息或密钥。
func TestBulkAtomicStoreFailureDuringRollbackReportsCombinedError(t *testing.T) {
	base := NewMemoryStore()
	faults := &faultStore{Store: base}
	env := newBulkStoreEnv(t, faults, Options{BulkAtomic: true})
	faults.faults.deleteUser = func(ctx context.Context, id string) error {
		return errors.New("rollback backend super-secret-token")
	}
	recorder := env.do(http.MethodPost, "/Bulk", BulkRequest{
		Operations: []BulkOperation{
			{Method: "POST", Path: "/Users", Data: map[string]any{"userName": "rollback-store-a"}},
			{Method: "POST", Path: "/Users", Data: map[string]any{"userName": "rollback-store-a"}},
		},
	}, nil)
	requireStatus(t, recorder, http.StatusInternalServerError)
	body := decodeResponse[Error](t, recorder)
	if body.Detail != "scim: internal error | scim：内部错误" {
		t.Fatalf("rollback failure detail = %q", body.Detail)
	}
	if strings.Contains(recorder.Body.String(), "super-secret-token") {
		t.Fatalf("response leaked backend text: %s", recorder.Body.String())
	}
	names := listUserNames(t, env.server.store)
	if len(names) != 1 || names[0] != "rollback-store-a" {
		t.Fatalf("users after rollback failure = %v", names)
	}
}

// TestBulkAtomicRollbackConflictSurfacesConcurrentChange verifies rollback reports a conflict and
// refuses to overwrite a resource changed between apply and rollback. |
// TestBulkAtomicRollbackConflictSurfacesConcurrentChange 校验回滚报告冲突并拒绝覆盖应用与回滚之间
// 被修改的资源。
func TestBulkAtomicRollbackConflictSurfacesConcurrentChange(t *testing.T) {
	base := NewMemoryStore()
	env := newBulkStoreEnv(t, base, Options{
		BulkAtomic: true,
		PasswordSetter: func(ctx context.Context, user *User, password string) error {
			external := user.Clone()
			external.DisplayName = "external"
			if _, err := base.ReplaceUser(ctx, external); err != nil {
				return err
			}
			return errors.New("hook rejected after external change")
		},
	})
	recorder := env.do(http.MethodPost, "/Bulk", BulkRequest{
		Operations: []BulkOperation{
			{BulkID: "conflict", Method: "POST", Path: "/Users", Data: map[string]any{"userName": "conflict-user"}},
			{Method: "PATCH", Path: "/Users/bulkId:conflict", Data: map[string]any{
				"schemas": []string{PatchOpSchema},
				"Operations": []any{
					map[string]any{"op": "replace", "path": "displayName", "value": "patched"},
					map[string]any{"op": "replace", "path": "password", "value": "test-password"},
				},
			}},
		},
	}, nil)
	requireError(t, recorder, http.StatusConflict, "")
	users, total, err := env.server.store.ListUsers(t.Context(), ListQuery{Count: -1})
	if err != nil || total != 1 {
		t.Fatalf("users after conflict = %d, %v", total, err)
	}
	if users[0].DisplayName != "external" {
		t.Fatalf("conflicting user was overwritten: %+v", users[0])
	}
}

// TestBulkAtomicValidationRejectsBeforeMutation verifies duplicate bulkIds and operation bounds
// fail before any operation runs in atomic mode. | TestBulkAtomicValidationRejectsBeforeMutation 校验
// 原子模式下重复 bulkId 与操作数上限会在任何操作运行前失败。
func TestBulkAtomicValidationRejectsBeforeMutation(t *testing.T) {
	env := newBulkStoreEnv(t, NewMemoryStore(), Options{BulkAtomic: true})
	recorder := env.do(http.MethodPost, "/Bulk", BulkRequest{
		Operations: []BulkOperation{
			{BulkID: "dup", Method: "POST", Path: "/Users", Data: map[string]any{"userName": "atomic-dup-1"}},
			{BulkID: "dup", Method: "POST", Path: "/Users", Data: map[string]any{"userName": "atomic-dup-2"}},
		},
	}, nil)
	requireError(t, recorder, http.StatusBadRequest, "invalidValue")
	if names := listUserNames(t, env.server.store); len(names) != 0 {
		t.Fatalf("duplicate bulkIds mutated store: %v", names)
	}

	limited := newBulkStoreEnv(t, NewMemoryStore(), Options{BulkAtomic: true, BulkMaxOperations: 2})
	recorder = limited.do(http.MethodPost, "/Bulk", BulkRequest{
		Operations: []BulkOperation{
			{Method: "POST", Path: "/Users", Data: map[string]any{"userName": "bound-1"}},
			{Method: "POST", Path: "/Users", Data: map[string]any{"userName": "bound-2"}},
			{Method: "POST", Path: "/Users", Data: map[string]any{"userName": "bound-3"}},
		},
	}, nil)
	requireError(t, recorder, http.StatusBadRequest, "tooMany")
	if names := listUserNames(t, limited.server.store); len(names) != 0 {
		t.Fatalf("operation bound mutated store: %v", names)
	}
}

// TestBulkAtomicUndoLogBoundRollsBack verifies the undo memory bound fails the overflowing
// operation before it applies and restores earlier operations. |
// TestBulkAtomicUndoLogBoundRollsBack 校验撤销内存上限会在溢出操作应用前使其失败并恢复先前操作。
func TestBulkAtomicUndoLogBoundRollsBack(t *testing.T) {
	ctx := context.Background()
	store := NewMemoryStore()
	first, err := store.CreateUser(ctx, &User{UserName: "undo-bound-1"})
	if err != nil {
		t.Fatalf("CreateUser error = %v", err)
	}
	second, err := store.CreateUser(ctx, &User{UserName: "undo-bound-2"})
	if err != nil {
		t.Fatalf("CreateUser error = %v", err)
	}
	firstBytes, err := bulkUserSnapshotBytes(first)
	if err != nil {
		t.Fatalf("bulkUserSnapshotBytes error = %v", err)
	}
	secondBytes, err := bulkUserSnapshotBytes(second)
	if err != nil {
		t.Fatalf("bulkUserSnapshotBytes error = %v", err)
	}
	env := newBulkStoreEnv(t, store, Options{BulkAtomic: true, BulkMaxUndoBytes: firstBytes + secondBytes - 1})
	recorder := env.do(http.MethodPost, "/Bulk", BulkRequest{
		Operations: []BulkOperation{
			{Method: "PATCH", Path: "/Users/" + first.ID, Data: patchDisplayName("after-1")},
			{Method: "PATCH", Path: "/Users/" + second.ID, Data: patchDisplayName("after-2")},
		},
	}, nil)
	requireError(t, recorder, http.StatusBadRequest, "tooMany")
	storedFirst, err := store.GetUser(ctx, first.ID)
	if err != nil || storedFirst.DisplayName != "" {
		t.Fatalf("first user after bound failure = %+v, %v", storedFirst, err)
	}
	storedSecond, err := store.GetUser(ctx, second.ID)
	if err != nil || storedSecond.DisplayName != "" {
		t.Fatalf("second user after bound failure = %+v, %v", storedSecond, err)
	}

	tiny := newBulkStoreEnv(t, NewMemoryStore(), Options{BulkAtomic: true, BulkMaxUndoBytes: 1})
	recorder = tiny.do(http.MethodPost, "/Bulk", BulkRequest{
		Operations: []BulkOperation{
			{Method: "POST", Path: "/Users", Data: map[string]any{"userName": "tiny-undo"}},
		},
	}, nil)
	requireError(t, recorder, http.StatusBadRequest, "tooMany")
	if names := listUserNames(t, tiny.server.store); len(names) != 0 {
		t.Fatalf("undo bound left a created user: %v", names)
	}
}

// TestBulkAtomicCreateUndoLimitCompensation verifies a create whose undo entry cannot be recorded
// is compensated immediately, and that a failing compensation surfaces as a rollback failure. |
// TestBulkAtomicCreateUndoLimitCompensation 校验无法记录撤销条目的创建会被立即补偿，且补偿失败会
// 表现为回滚失败。
func TestBulkAtomicCreateUndoLimitCompensation(t *testing.T) {
	base := NewMemoryStore()
	faults := &faultStore{Store: base}
	env := newBulkStoreEnv(t, faults, Options{BulkAtomic: true, BulkMaxUndoBytes: 1})
	recorder := env.do(http.MethodPost, "/Bulk", BulkRequest{
		Operations: []BulkOperation{
			{Method: "POST", Path: "/Users", Data: map[string]any{"userName": "compensation-created"}},
		},
	}, nil)
	requireError(t, recorder, http.StatusBadRequest, "tooMany")
	if names := listUserNames(t, base); len(names) != 0 {
		t.Fatalf("failed undo record left a created user: %v", names)
	}

	broken := &faultStore{Store: NewMemoryStore()}
	broken.faults.deleteUser = func(ctx context.Context, id string) error {
		return errors.New("delete compensation super-secret-token")
	}
	brokenEnv := newBulkStoreEnv(t, broken, Options{BulkAtomic: true, BulkMaxUndoBytes: 1})
	recorder = brokenEnv.do(http.MethodPost, "/Bulk", BulkRequest{
		Operations: []BulkOperation{
			{Method: "POST", Path: "/Users", Data: map[string]any{"userName": "compensation-broken"}},
		},
	}, nil)
	requireStatus(t, recorder, http.StatusInternalServerError)
	body := decodeResponse[Error](t, recorder)
	if body.Detail != "scim: internal error | scim：内部错误" {
		t.Fatalf("broken compensation detail = %q", body.Detail)
	}
	if strings.Contains(recorder.Body.String(), "super-secret-token") {
		t.Fatalf("response leaked backend text: %s", recorder.Body.String())
	}
	if names := listUserNames(t, broken.Store); len(names) != 1 {
		t.Fatalf("broken compensation users = %v", names)
	}
}

// TestBulkAtomicAuthorizationFailureRollsBack verifies an authorization failure in the middle of a
// transaction behaves like any other failure. | TestBulkAtomicAuthorizationFailureRollsBack 校验事务
// 中途的授权失败与其他失败行为一致。
func TestBulkAtomicAuthorizationFailureRollsBack(t *testing.T) {
	env := newBulkStoreEnv(t, NewMemoryStore(), Options{
		BulkAtomic: true,
		Authorizer: func(ctx context.Context, r *http.Request, action, resource string) error {
			if action == ActionDelete {
				return errs.Detail(ErrForbidden, "delete denied")
			}
			return nil
		},
	})
	user := env.mustCreateUser(map[string]any{"userName": "auth-kept"})
	recorder := env.do(http.MethodPost, "/Bulk", BulkRequest{
		Operations: []BulkOperation{
			{Method: "POST", Path: "/Users", Data: map[string]any{"userName": "auth-created"}},
			{Method: "DELETE", Path: "/Users/" + user.ID},
		},
	}, nil)
	requireError(t, recorder, http.StatusForbidden, "")
	names := listUserNames(t, env.server.store)
	if len(names) != 1 || names[0] != "auth-kept" {
		t.Fatalf("users after authorization failure = %v", names)
	}
}

// TestBulkAtomicDisabledKeepsNonTransactionalBehavior verifies the default mode still reports
// failures in place and keeps earlier committed operations. |
// TestBulkAtomicDisabledKeepsNonTransactionalBehavior 校验默认模式仍在原位报告失败并保留先前已提交
// 操作。
func TestBulkAtomicDisabledKeepsNonTransactionalBehavior(t *testing.T) {
	env := newTestEnv(t, Options{}, "/scim")
	recorder := env.do(http.MethodPost, "/Bulk", BulkRequest{
		Operations: []BulkOperation{
			{Method: "POST", Path: "/Users", Data: map[string]any{"userName": "nontx-user"}},
			{Method: "POST", Path: "/Users", Data: map[string]any{"userName": "nontx-user"}},
			{Method: "POST", Path: "/Users", Data: map[string]any{"userName": "nontx-third"}},
		},
	}, nil)
	requireStatus(t, recorder, http.StatusOK)
	response := decodeResponse[BulkResponse](t, recorder)
	wantStatuses := []string{"201", "409", "201"}
	if len(response.Operations) != len(wantStatuses) {
		t.Fatalf("operations = %+v", response.Operations)
	}
	for i, want := range wantStatuses {
		if response.Operations[i].Status != want {
			t.Fatalf("operation %d = %+v, want %s", i, response.Operations[i], want)
		}
	}
	names := listUserNames(t, env.store)
	if len(names) != 2 || names[0] != "nontx-third" || names[1] != "nontx-user" {
		t.Fatalf("non-transactional users = %v", names)
	}
}

// TestBulkAtomicLargeTransaction verifies a large successful transaction stays within the default
// operation and undo bounds. | TestBulkAtomicLargeTransaction 校验大型成功事务保持在默认操作与撤销
// 上限内。
func TestBulkAtomicLargeTransaction(t *testing.T) {
	env := newBulkStoreEnv(t, NewMemoryStore(), Options{BulkAtomic: true})
	operations := make([]BulkOperation, 0, 32)
	for i := 0; i < 32; i++ {
		operations = append(operations, BulkOperation{
			Method: "POST",
			Path:   "/Users",
			Data:   map[string]any{"userName": "large-" + intString(i), "displayName": "large user"},
		})
	}
	recorder := env.do(http.MethodPost, "/Bulk", BulkRequest{Operations: operations}, nil)
	requireStatus(t, recorder, http.StatusOK)
	response := decodeResponse[BulkResponse](t, recorder)
	if len(response.Operations) != len(operations) {
		t.Fatalf("operations = %d, want %d", len(response.Operations), len(operations))
	}
	for i, result := range response.Operations {
		if result.Status != "201" {
			t.Fatalf("operation %d = %+v", i, result)
		}
	}
	if _, total, err := env.server.store.ListUsers(t.Context(), ListQuery{}); err != nil || total != len(operations) {
		t.Fatalf("large transaction users = %d, %v", total, err)
	}
}

// TestBulkUndoLogValidation verifies defensive branches of the undo log helpers. |
// TestBulkUndoLogValidation 校验撤销日志辅助函数的防御性分支。
func TestBulkUndoLogValidation(t *testing.T) {
	ctx := context.Background()
	var nilLog *bulkUndoLog
	if handle, err := nilLog.prepareUserRestore(nil, ""); handle != nil || err != nil {
		t.Fatalf("nil log prepare = %v, %v", handle, err)
	}
	log := newBulkUndoLog(1 << 20)
	if _, err := log.prepareUserRestore(nil, ""); !errors.Is(err, ErrInvalidValue) {
		t.Fatalf("nil user error = %v", err)
	}
	if _, err := log.prepareUserRestore(&User{}, ""); !errors.Is(err, ErrInvalidValue) {
		t.Fatalf("empty user id error = %v", err)
	}
	if _, err := log.prepareUserRecreate(nil, ""); !errors.Is(err, ErrInvalidValue) {
		t.Fatalf("nil recreate user error = %v", err)
	}
	if _, err := log.prepareGroupRestore(nil, ""); !errors.Is(err, ErrInvalidValue) {
		t.Fatalf("nil group error = %v", err)
	}
	if _, err := log.prepareGroupRestore(&Group{}, ""); !errors.Is(err, ErrInvalidValue) {
		t.Fatalf("empty group id error = %v", err)
	}
	if _, err := log.prepareGroupRecreate(nil, ""); !errors.Is(err, ErrInvalidValue) {
		t.Fatalf("nil recreate group error = %v", err)
	}
	if err := log.recordCreatedUser(nil, ""); !errors.Is(err, ErrInternal) {
		t.Fatalf("nil created user error = %v", err)
	}
	if err := log.recordCreatedUser(&User{}, ""); !errors.Is(err, ErrInternal) {
		t.Fatalf("id-less created user error = %v", err)
	}
	if err := log.recordCreatedGroup(nil, ""); !errors.Is(err, ErrInternal) {
		t.Fatalf("nil created group error = %v", err)
	}
	if err := log.recordCreatedGroup(&Group{}, ""); !errors.Is(err, ErrInternal) {
		t.Fatalf("id-less created group error = %v", err)
	}
	var nilHandle *bulkUndoHandle
	nilHandle.markApplied("W/\"x\"")
	unknown := &bulkUndoEntry{kind: bulkUndoKind(99), applied: true, id: "unknown"}
	if err := unknown.rollback(ctx, NewMemoryStore()); !errors.Is(err, ErrInternal) {
		t.Fatalf("unknown kind error = %v", err)
	}

	store := NewMemoryStore()
	user, err := store.CreateUser(ctx, &User{UserName: "no-snapshot"})
	if err != nil {
		t.Fatalf("CreateUser error = %v", err)
	}
	noSnapshot := &bulkUndoEntry{kind: bulkUndoRestoreUser, applied: true, id: user.ID}
	if err := noSnapshot.rollback(ctx, store); !errors.Is(err, ErrInternal) {
		t.Fatalf("missing user snapshot error = %v", err)
	}
	group, err := store.CreateGroup(ctx, &Group{DisplayName: "no-snapshot-group"})
	if err != nil {
		t.Fatalf("CreateGroup error = %v", err)
	}
	noGroupSnapshot := &bulkUndoEntry{kind: bulkUndoRestoreGroup, applied: true, id: group.ID}
	if err := noGroupSnapshot.rollback(ctx, store); !errors.Is(err, ErrInternal) {
		t.Fatalf("missing group snapshot error = %v", err)
	}
	missingUser := &bulkUndoEntry{kind: bulkUndoRecreateUser, applied: true, id: "missing-recreate-user"}
	if err := missingUser.rollback(ctx, store); !errors.Is(err, ErrInternal) {
		t.Fatalf("missing user recreate snapshot error = %v", err)
	}
	missingGroup := &bulkUndoEntry{kind: bulkUndoRecreateGroup, applied: true, id: "missing-recreate-group"}
	if err := missingGroup.rollback(ctx, store); !errors.Is(err, ErrInternal) {
		t.Fatalf("missing group recreate snapshot error = %v", err)
	}
}

// TestBulkUndoLogRollbackConflicts verifies conflict detection for vanished, modified and
// recreated resources. | TestBulkUndoLogRollbackConflicts 校验资源消失、被修改与重现时的冲突检测。
func TestBulkUndoLogRollbackConflicts(t *testing.T) {
	ctx := context.Background()
	store := NewMemoryStore()

	vanished, err := store.CreateUser(ctx, &User{UserName: "vanished"})
	if err != nil {
		t.Fatalf("CreateUser error = %v", err)
	}
	undo := newBulkUndoLog(DefaultBulkMaxUndoBytes)
	handle, err := undo.prepareUserRestore(vanished, "v")
	if err != nil {
		t.Fatalf("prepareUserRestore error = %v", err)
	}
	handle.markApplied(userVersion(vanished))
	if err := store.DeleteUser(ctx, vanished.ID); err != nil {
		t.Fatalf("DeleteUser error = %v", err)
	}
	result := undo.rollback(ctx, store, nil)
	if result.conflicts != 1 || result.failures != 0 || !errors.Is(result.err, ErrBulkRollbackConflict) {
		t.Fatalf("vanished rollback = %+v", result)
	}

	recreated, err := store.CreateGroup(ctx, &Group{DisplayName: "recreated-group"})
	if err != nil {
		t.Fatalf("CreateGroup error = %v", err)
	}
	groupUndo := newBulkUndoLog(DefaultBulkMaxUndoBytes)
	groupHandle, err := groupUndo.prepareGroupRecreate(recreated, "g")
	if err != nil {
		t.Fatalf("prepareGroupRecreate error = %v", err)
	}
	if err := store.DeleteGroup(ctx, recreated.ID); err != nil {
		t.Fatalf("DeleteGroup error = %v", err)
	}
	groupHandle.markApplied("")
	external := recreated.Clone()
	external.DisplayName = "external-group"
	if _, err := store.CreateGroup(ctx, external); err != nil {
		t.Fatalf("recreate externally error = %v", err)
	}
	ids := map[string]string{"g": recreated.ID}
	result = groupUndo.rollback(ctx, store, ids)
	if result.conflicts != 1 || result.failures != 0 || !errors.Is(result.err, ErrBulkRollbackConflict) {
		t.Fatalf("recreated group rollback = %+v", result)
	}
	if _, ok := ids["g"]; ok {
		t.Fatalf("conflicting group bulkId survived: %v", ids)
	}
	stored, err := store.GetGroup(ctx, recreated.ID)
	if err != nil || stored.DisplayName != "external-group" {
		t.Fatalf("conflicting group overwritten = %+v, %v", stored, err)
	}

	if rollbackVersionMismatch("", "") || rollbackVersionMismatch("", `W/"x"`) {
		t.Fatalf("empty applied version reported a conflict")
	}
	if !rollbackVersionMismatch(`W/"a"`, `W/"b"`) {
		t.Fatalf("different versions did not report a conflict")
	}
	if rollbackVersionMismatch(`W/"a"`, `"a"`) {
		t.Fatalf("normalized equal versions reported a conflict")
	}
}

// TestBulkUndoLogRollbackStoreFailure verifies store failures during rollback are counted as
// failures rather than conflicts. | TestBulkUndoLogRollbackStoreFailure 校验回滚期间的存储故障被
// 计为失败而非冲突。
func TestBulkUndoLogRollbackStoreFailure(t *testing.T) {
	ctx := context.Background()
	base := NewMemoryStore()
	user, err := base.CreateUser(ctx, &User{UserName: "rollback-fault"})
	if err != nil {
		t.Fatalf("CreateUser error = %v", err)
	}
	undo := newBulkUndoLog(DefaultBulkMaxUndoBytes)
	handle, err := undo.prepareUserRestore(user, "")
	if err != nil {
		t.Fatalf("prepareUserRestore error = %v", err)
	}
	changed := user.Clone()
	changed.DisplayName = "after"
	stored, err := base.ReplaceUser(ctx, changed)
	if err != nil {
		t.Fatalf("ReplaceUser error = %v", err)
	}
	handle.markApplied(userVersion(stored))
	faults := &faultStore{Store: base}
	faults.faults.getUser = func(ctx context.Context, id string) error {
		return errors.New("get failed")
	}
	result := undo.rollback(ctx, faults, nil)
	if result.failures != 1 || result.conflicts != 0 || !errors.Is(result.err, ErrStoreUnavailable) {
		t.Fatalf("store failure rollback = %+v", result)
	}
}

// TestBulkAtomicNewRejectsNegativeUndoBound verifies configuration validation. |
// TestBulkAtomicNewRejectsNegativeUndoBound 校验配置校验。
func TestBulkAtomicNewRejectsNegativeUndoBound(t *testing.T) {
	if _, err := New(Options{BulkMaxUndoBytes: -1}); !errors.Is(err, ErrInvalidConfig) {
		t.Fatalf("negative undo bound error = %v", err)
	}
	if _, err := New(Options{BulkAtomic: true}); err != nil {
		t.Fatalf("atomic server error = %v", err)
	}
}

// TestClassifyAtomicErrors verifies the HTTP classification of every sentinel touched by atomic
// bulk. | TestClassifyAtomicErrors 校验原子批量涉及的每个哨兵的 HTTP 分类。
func TestClassifyAtomicErrors(t *testing.T) {
	cases := []struct {
		name     string
		err      error
		status   int
		scimType string
	}{
		{"nil", nil, http.StatusOK, ""},
		{"rollback failed", errs.Detail(ErrBulkRollbackFailed, "failed"), http.StatusInternalServerError, ""},
		{"rollback conflict", errs.Detail(ErrBulkRollbackConflict, "conflict"), http.StatusConflict, ""},
		{"undo limit", errs.Detail(ErrBulkUndoLimit, "limit"), http.StatusBadRequest, "tooMany"},
		{"conflict", ErrConflict, http.StatusConflict, "uniqueness"},
		{"unsupported", ErrUnsupported, http.StatusNotImplemented, ""},
		{"invalid config", ErrInvalidConfig, http.StatusInternalServerError, ""},
		{"join", errors.Join(ErrNotFound, ErrUnauthorized), http.StatusNotFound, ""},
	}
	for _, testCase := range cases {
		t.Run(testCase.name, func(t *testing.T) {
			got := classifyError(testCase.err)
			if got.status != testCase.status || got.scimType != testCase.scimType {
				t.Fatalf("classifyError(%v) = %+v, want %d/%s", testCase.err, got, testCase.status, testCase.scimType)
			}
		})
	}
}

// TestBulkUndoLogRecordBounds verifies record clamping, nil handling and the byte bound. |
// TestBulkUndoLogRecordBounds 校验 record 的钳制、nil 处理与字节上限。
func TestBulkUndoLogRecordBounds(t *testing.T) {
	var nilLog *bulkUndoLog
	if handle, err := nilLog.record(bulkUndoEntry{}); handle != nil || err != nil {
		t.Fatalf("nil log record = %v, %v", handle, err)
	}
	if result := nilLog.rollback(context.Background(), NewMemoryStore(), nil); result.err != nil {
		t.Fatalf("nil log rollback = %+v", result)
	}
	log := newBulkUndoLog(0)
	if log.maxBytes != DefaultBulkMaxUndoBytes {
		t.Fatalf("default maxBytes = %d", log.maxBytes)
	}
	handle, err := log.record(bulkUndoEntry{bytes: -1})
	if err != nil || handle == nil || log.bytes != 0 {
		t.Fatalf("negative bytes record = %v, %v, bytes %d", handle, err, log.bytes)
	}
	handle.index = len(log.entries) + 3
	handle.markApplied("W/\"x\"")
	var nilHandle *bulkUndoHandle
	nilHandle.markApplied("W/\"x\"")
	(&bulkUndoHandle{}).markApplied("W/\"x\"")

	bounded := newBulkUndoLog(10)
	if _, err := bounded.record(bulkUndoEntry{bytes: 6}); err != nil {
		t.Fatalf("first record error = %v", err)
	}
	if _, err := bounded.record(bulkUndoEntry{bytes: 5}); !errors.Is(err, ErrBulkUndoLimit) {
		t.Fatalf("overflow record error = %v", err)
	}
	if result := bounded.rollback(context.Background(), nil, nil); result.err != nil {
		t.Fatalf("nil store rollback = %+v", result)
	}
}

// TestBulkUndoEntryRollbackBranches exercises the compensating rollback paths not reached by
// end-to-end tests: missing resources, store failures and recreate failures. |
// TestBulkUndoEntryRollbackBranches 覆盖端到端测试未触及的补偿回滚路径：资源消失、存储故障与重建失败。
func TestBulkUndoEntryRollbackBranches(t *testing.T) {
	ctx := context.Background()
	base := NewMemoryStore()
	faults := &faultStore{Store: base}

	faults.faults.getUser = func(ctx context.Context, id string) error {
		return errors.New("get user failed")
	}
	if err := (&bulkUndoEntry{kind: bulkUndoDeleteUser, id: "missing"}).rollback(ctx, faults); !errors.Is(err, ErrStoreUnavailable) {
		t.Fatalf("delete user get failure = %v", err)
	}
	if err := (&bulkUndoEntry{kind: bulkUndoRestoreUser, id: "missing"}).rollback(ctx, faults); !errors.Is(err, ErrStoreUnavailable) {
		t.Fatalf("restore user get failure = %v", err)
	}
	if err := (&bulkUndoEntry{kind: bulkUndoRecreateUser, id: "missing"}).rollback(ctx, faults); !errors.Is(err, ErrStoreUnavailable) {
		t.Fatalf("recreate user get failure = %v", err)
	}
	faults.faults.getGroup = func(ctx context.Context, id string) error {
		return errors.New("get group failed")
	}
	if err := (&bulkUndoEntry{kind: bulkUndoDeleteGroup, id: "missing"}).rollback(ctx, faults); !errors.Is(err, ErrStoreUnavailable) {
		t.Fatalf("delete group get failure = %v", err)
	}
	if err := (&bulkUndoEntry{kind: bulkUndoRestoreGroup, id: "missing"}).rollback(ctx, faults); !errors.Is(err, ErrStoreUnavailable) {
		t.Fatalf("restore group get failure = %v", err)
	}
	if err := (&bulkUndoEntry{kind: bulkUndoRecreateGroup, id: "missing"}).rollback(ctx, faults); !errors.Is(err, ErrStoreUnavailable) {
		t.Fatalf("recreate group get failure = %v", err)
	}
	faults.faults = bulkFaults{}

	user, err := base.CreateUser(ctx, &User{UserName: "branch-user"})
	if err != nil {
		t.Fatalf("CreateUser error = %v", err)
	}
	group, err := base.CreateGroup(ctx, &Group{DisplayName: "branch-group"})
	if err != nil {
		t.Fatalf("CreateGroup error = %v", err)
	}
	if err := (&bulkUndoEntry{kind: bulkUndoDeleteUser, id: "never-created-user"}).rollback(ctx, base); err != nil {
		t.Fatalf("idempotent delete user = %v", err)
	}
	if err := (&bulkUndoEntry{kind: bulkUndoDeleteGroup, id: "never-created-group"}).rollback(ctx, base); err != nil {
		t.Fatalf("idempotent delete group = %v", err)
	}
	if err := (&bulkUndoEntry{kind: bulkUndoDeleteUser, id: user.ID, appliedVersion: `W/"stale"`}).rollback(ctx, base); !errors.Is(err, ErrBulkRollbackConflict) {
		t.Fatalf("delete user version conflict = %v", err)
	}
	if err := (&bulkUndoEntry{kind: bulkUndoDeleteGroup, id: group.ID, appliedVersion: `W/"stale"`}).rollback(ctx, base); !errors.Is(err, ErrBulkRollbackConflict) {
		t.Fatalf("delete group version conflict = %v", err)
	}
	if err := (&bulkUndoEntry{kind: bulkUndoRestoreGroup, id: "gone", priorGroup: group.Clone()}).rollback(ctx, base); !errors.Is(err, ErrBulkRollbackConflict) {
		t.Fatalf("restore vanished group = %v", err)
	}
	if err := (&bulkUndoEntry{kind: bulkUndoRecreateUser, id: user.ID, priorUser: user.Clone()}).rollback(ctx, base); !errors.Is(err, ErrBulkRollbackConflict) {
		t.Fatalf("recreate existing user = %v", err)
	}
	if err := (&bulkUndoEntry{kind: bulkUndoRecreateGroup, id: group.ID, priorGroup: group.Clone()}).rollback(ctx, base); !errors.Is(err, ErrBulkRollbackConflict) {
		t.Fatalf("recreate existing group = %v", err)
	}

	replaceUser := &bulkUndoEntry{
		kind: bulkUndoRestoreUser, id: user.ID, priorUser: user.Clone(), appliedVersion: userVersion(user),
	}
	faults.faults.replaceUser = func(ctx context.Context, incoming *User) error {
		return errors.New("replace user failed")
	}
	if err := replaceUser.rollback(ctx, faults); !errors.Is(err, ErrStoreUnavailable) {
		t.Fatalf("restore user replace failure = %v", err)
	}
	replaceGroup := &bulkUndoEntry{
		kind: bulkUndoRestoreGroup, id: group.ID, priorGroup: group.Clone(), appliedVersion: groupVersion(group),
	}
	faults.faults.replaceGroup = func(ctx context.Context, incoming *Group) error {
		return errors.New("replace group failed")
	}
	if err := replaceGroup.rollback(ctx, faults); !errors.Is(err, ErrStoreUnavailable) {
		t.Fatalf("restore group replace failure = %v", err)
	}
	faults.faults.deleteUser = func(ctx context.Context, id string) error {
		return errors.New("delete user failed")
	}
	if err := (&bulkUndoEntry{kind: bulkUndoDeleteUser, id: user.ID, appliedVersion: userVersion(user)}).rollback(ctx, faults); !errors.Is(err, ErrStoreUnavailable) {
		t.Fatalf("delete user failure = %v", err)
	}
	faults.faults.deleteGroup = func(ctx context.Context, id string) error {
		return errors.New("delete group failed")
	}
	if err := (&bulkUndoEntry{kind: bulkUndoDeleteGroup, id: group.ID, appliedVersion: groupVersion(group)}).rollback(ctx, faults); !errors.Is(err, ErrStoreUnavailable) {
		t.Fatalf("delete group failure = %v", err)
	}
	faults.faults = bulkFaults{}
	if err := base.DeleteUser(ctx, user.ID); err != nil {
		t.Fatalf("DeleteUser error = %v", err)
	}
	if err := base.DeleteGroup(ctx, group.ID); err != nil {
		t.Fatalf("DeleteGroup error = %v", err)
	}
	faults.faults.createUser = func(ctx context.Context, incoming *User) error {
		return errors.New("create user failed")
	}
	if err := (&bulkUndoEntry{kind: bulkUndoRecreateUser, id: user.ID, priorUser: user.Clone()}).rollback(ctx, faults); !errors.Is(err, ErrStoreUnavailable) {
		t.Fatalf("recreate user failure = %v", err)
	}
	faults.faults.createGroup = func(ctx context.Context, incoming *Group) error {
		return errors.New("create group failed")
	}
	if err := (&bulkUndoEntry{kind: bulkUndoRecreateGroup, id: group.ID, priorGroup: group.Clone()}).rollback(ctx, faults); !errors.Is(err, ErrStoreUnavailable) {
		t.Fatalf("recreate group failure = %v", err)
	}
}

// TestCombineBulkAtomicFailureModes verifies the merge rules for rollback failures and conflicts. |
// TestCombineBulkAtomicFailureModes 校验回滚失败与冲突的合并规则。
func TestCombineBulkAtomicFailureModes(t *testing.T) {
	original := errs.Detail(ErrInvalidValue, "original")
	if got := combineBulkAtomicFailure(original, bulkRollbackResult{}); !errors.Is(got, ErrInvalidValue) {
		t.Fatalf("clean combine = %v", got)
	}
	conflictOnly := combineBulkAtomicFailure(original, bulkRollbackResult{
		err: errs.Detail(ErrBulkRollbackConflict, "conflict"), conflicts: 1,
	})
	if !errors.Is(conflictOnly, ErrBulkRollbackConflict) || !errors.Is(conflictOnly, ErrInvalidValue) {
		t.Fatalf("conflict combine = %v", conflictOnly)
	}
	if got := classifyError(conflictOnly); got.status != http.StatusConflict {
		t.Fatalf("conflict combine status = %d", got.status)
	}
	incomplete := combineBulkAtomicFailure(original, bulkRollbackResult{
		err: errors.New("rollback broke"), failures: 1,
	})
	if !errors.Is(incomplete, ErrBulkRollbackFailed) || !errors.Is(incomplete, ErrInvalidValue) {
		t.Fatalf("failure combine = %v", incomplete)
	}
	if got := classifyError(incomplete); got.status != http.StatusInternalServerError {
		t.Fatalf("failure combine status = %d", got.status)
	}
	serverOriginal := combineBulkAtomicFailure(ErrStoreUnavailable, bulkRollbackResult{
		err: errs.Detail(ErrBulkRollbackConflict, "conflict"), conflicts: 1,
	})
	if !errors.Is(serverOriginal, ErrBulkRollbackFailed) {
		t.Fatalf("server original combine = %v", serverOriginal)
	}
}

// TestBulkMalformedOperationsReportInPlace verifies non-transactional decoding, path, method and
// version failures become per-operation errors without stopping the request. |
// TestBulkMalformedOperationsReportInPlace 校验非事务解码、路径、方法与版本失败会转为逐操作错误且
// 不中断请求。
func TestBulkMalformedOperationsReportInPlace(t *testing.T) {
	env := newTestEnv(t, Options{}, "/scim")
	user := env.mustCreateUser(map[string]any{"userName": "malformed-user"})
	group := env.mustCreateGroup(map[string]any{"displayName": "malformed-group"})
	recorder := env.do(http.MethodPost, "/Bulk", BulkRequest{
		Operations: []BulkOperation{
			{Method: "", Path: "/Users"},
			{Method: "BREW", Path: "/Users"},
			{Method: "POST", Path: ""},
			{Method: "POST", Path: "/Widgets"},
			{Method: "POST", Path: "/Users/extra/segments"},
			{Method: "POST", Path: "/Users/" + user.ID},
			{Method: "PUT", Path: "/Users"},
			{Method: "PUT", Path: "/Users/missing-user"},
			{Method: "PUT", Path: "/Users/" + user.ID, Version: `W/"stale"`, Data: map[string]any{"userName": "malformed-user"}},
			{Method: "PUT", Path: "/Users/" + user.ID, Data: "not-an-object"},
			{Method: "PATCH", Path: "/Users"},
			{Method: "PATCH", Path: "/Users/missing-user"},
			{Method: "PATCH", Path: "/Users/" + user.ID, Version: `W/"stale"`, Data: patchDisplayName("x")},
			{Method: "PATCH", Path: "/Users/" + user.ID, Data: map[string]any{"schemas": []string{PatchOpSchema}}},
			{Method: "DELETE", Path: "/Users"},
			{Method: "DELETE", Path: "/Users/missing-user"},
			{Method: "DELETE", Path: "/Users/" + user.ID, Version: `W/"stale"`},
			{Method: "POST", Path: "/Groups/" + group.ID},
			{Method: "PUT", Path: "/Groups"},
			{Method: "PUT", Path: "/Groups/missing-group"},
			{Method: "PUT", Path: "/Groups/" + group.ID, Version: `W/"stale"`, Data: map[string]any{"displayName": "malformed-group"}},
			{Method: "PUT", Path: "/Groups/" + group.ID, Data: "not-an-object"},
			{Method: "PATCH", Path: "/Groups"},
			{Method: "PATCH", Path: "/Groups/missing-group"},
			{Method: "PATCH", Path: "/Groups/" + group.ID, Version: `W/"stale"`, Data: patchDisplayName("x")},
			{Method: "PATCH", Path: "/Groups/" + group.ID, Data: map[string]any{"schemas": []string{PatchOpSchema}}},
			{Method: "DELETE", Path: "/Groups"},
			{Method: "DELETE", Path: "/Groups/missing-group"},
			{Method: "DELETE", Path: "/Groups/" + group.ID, Version: `W/"stale"`},
			{Method: "GET", Path: "/Users"},
		},
	}, nil)
	requireStatus(t, recorder, http.StatusOK)
	response := decodeResponse[BulkResponse](t, recorder)
	if len(response.Operations) != 30 {
		t.Fatalf("operations = %d, want 30", len(response.Operations))
	}
	for index, result := range response.Operations {
		if !isFailureStatus(result.Status) {
			t.Fatalf("operation %d = %+v, want failure status", index, result)
		}
	}
	if response.Operations[4].Status != "400" || response.Operations[7].Status != "404" {
		t.Fatalf("unexpected statuses = %+v", response.Operations)
	}
	names := listUserNames(t, env.store)
	if len(names) != 1 || names[0] != "malformed-user" {
		t.Fatalf("malformed bulk mutated users = %v", names)
	}
}

// TestDiscoveryAuthorizationFailures verifies every discovery handler reports an authorization
// failure before rendering a document. | TestDiscoveryAuthorizationFailures 校验每个发现处理器在渲染
// 文档前报告授权失败。
func TestDiscoveryAuthorizationFailures(t *testing.T) {
	env := newTestEnv(t, Options{
		Authorizer: func(ctx context.Context, r *http.Request, action, resource string) error {
			return errs.Detail(ErrForbidden, "read denied")
		},
	}, "/scim")
	for _, path := range []string{
		"/ServiceProviderConfig",
		"/ResourceTypes",
		"/ResourceTypes/User",
		"/Schemas",
		"/Schemas/" + UserSchema,
	} {
		recorder := env.do(http.MethodGet, path, nil, nil)
		requireError(t, recorder, http.StatusForbidden, "")
	}
}

// TestNewRejectsNegativeLimits verifies configuration validation for every numeric limit. |
// TestNewRejectsNegativeLimits 校验每个数值上限的配置校验。
func TestNewRejectsNegativeLimits(t *testing.T) {
	cases := []Options{
		{MaxResults: -1},
		{BulkMaxOperations: -1},
		{BulkMaxPayloadSize: -1},
		{BulkMaxUndoBytes: -1},
	}
	for _, options := range cases {
		if _, err := New(options); !errors.Is(err, ErrInvalidConfig) {
			t.Fatalf("New(%+v) error = %v", options, err)
		}
	}
}

// TestNormalizePrefixAndNilRequests verifies nil-safe request helpers and prefix normalization. |
// TestNormalizePrefixAndNilRequests 校验空安全请求辅助函数与前缀规范化。
func TestNormalizePrefixAndNilRequests(t *testing.T) {
	if withRequestPrefix(nil, "/scim") != nil {
		t.Fatal("withRequestPrefix(nil) != nil")
	}
	if requestPrefix(nil) != "" {
		t.Fatal("requestPrefix(nil) != empty")
	}
	if got := normalizePrefix(" /scim/v2/ "); got != "/scim/v2" {
		t.Fatalf("normalizePrefix = %q", got)
	}
	if got := normalizePrefix("/"); got != "" {
		t.Fatalf("normalizePrefix(/) = %q", got)
	}
	if got := normalizePrefix("scim"); got != "/scim" {
		t.Fatalf("normalizePrefix(scim) = %q", got)
	}
	request := httptest.NewRequest(http.MethodGet, "/scim/Users", nil)
	prefixed := withRequestPrefix(request, "scim/")
	if got := requestPrefix(prefixed); got != "/scim" {
		t.Fatalf("requestPrefix = %q", got)
	}
}
