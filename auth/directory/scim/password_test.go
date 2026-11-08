package scim

import (
	"context"
	"errors"
	"net/http"
	"strings"
	"testing"

	"github.com/shibingli/ydx/auth"
)

// rejectPassword is a placeholder password hook error that must never reach a client response. |
// rejectPassword 是占位口令钩子错误，绝不能出现在客户端响应中。
var rejectPassword = errors.New("password hook rejected secret material")

// TestPasswordPrecheckRejectsBeforeCommit verifies the precheck hook runs before any store mutation
// on create, replace and patch. | TestPasswordPrecheckRejectsBeforeCommit 校验预检钩子在创建、替换
// 与补丁的任何存储变更之前运行。
func TestPasswordPrecheckRejectsBeforeCommit(t *testing.T) {
	var (
		setterCalls   int
		precheckCalls int
		precheckID    string
	)
	env := newTestEnv(t, Options{
		PasswordSetter: func(ctx context.Context, user *User, password string) error {
			setterCalls++
			return nil
		},
		PasswordPrecheck: PasswordValidator(func(ctx context.Context, user *User, password string) error {
			precheckCalls++
			precheckID = user.ID
			if password == "weak" {
				return errors.New("password too weak")
			}
			return nil
		}),
	}, "/scim")

	recorder := env.do(http.MethodPost, "/Users", map[string]any{
		"userName": "precheck-create",
		"password": "weak",
	}, nil)
	requireError(t, recorder, http.StatusBadRequest, "invalidValue")
	if setterCalls != 0 || precheckCalls != 1 {
		t.Fatalf("setter calls = %d, precheck calls = %d", setterCalls, precheckCalls)
	}
	if precheckID != "" {
		t.Fatalf("precheck create user id = %q", precheckID)
	}
	if names := listUserNames(t, env.store); len(names) != 0 {
		t.Fatalf("user was persisted despite precheck rejection: %v", names)
	}

	user := env.mustCreateUser(map[string]any{"userName": "precheck-target", "displayName": "Original"})
	recorder = env.do(http.MethodPut, "/Users/"+user.ID, map[string]any{
		"userName":    "precheck-target",
		"displayName": "Changed",
		"password":    "weak",
	}, nil)
	requireError(t, recorder, http.StatusBadRequest, "invalidValue")
	if precheckID != user.ID {
		t.Fatalf("precheck replace user id = %q, want %q", precheckID, user.ID)
	}
	if setterCalls != 0 {
		t.Fatalf("setter ran despite precheck rejection: %d", setterCalls)
	}
	stored, err := env.store.GetUser(context.Background(), user.ID)
	if err != nil {
		t.Fatalf("GetUser error = %v", err)
	}
	if stored.DisplayName != "Original" {
		t.Fatalf("replace committed despite precheck rejection: %q", stored.DisplayName)
	}

	recorder = env.do(http.MethodPatch, "/Users/"+user.ID, PatchRequest{Operations: []PatchOperation{
		{Op: "replace", Path: "displayName", Value: "Patched"},
		{Op: "replace", Path: "password", Value: "weak"},
	}}, nil)
	requireError(t, recorder, http.StatusBadRequest, "invalidValue")
	if setterCalls != 0 {
		t.Fatalf("setter ran despite patch precheck rejection: %d", setterCalls)
	}
	stored, err = env.store.GetUser(context.Background(), user.ID)
	if err != nil {
		t.Fatalf("GetUser after patch error = %v", err)
	}
	if stored.DisplayName != "Original" {
		t.Fatalf("patch committed despite precheck rejection: %q", stored.DisplayName)
	}

	recorder = env.do(http.MethodPut, "/Users/"+user.ID, map[string]any{
		"userName":    "precheck-target",
		"displayName": "Accepted",
		"password":    "strong",
	}, nil)
	requireStatus(t, recorder, http.StatusOK)
	if setterCalls != 1 {
		t.Fatalf("setter calls = %d, want 1", setterCalls)
	}
}

// TestPasswordFailureRestoresPriorProfile verifies a rejected post-commit password restores the
// profile on PUT, PATCH and the /Me routes. | TestPasswordFailureRestoresPriorProfile 校验提交后
// 遭拒的口令在 PUT、PATCH 与 /Me 路由上恢复资料。
func TestPasswordFailureRestoresPriorProfile(t *testing.T) {
	var setterUser *User
	env := newTestEnv(t, Options{PasswordSetter: func(ctx context.Context, user *User, password string) error {
		setterUser = user
		return rejectPassword
	}}, "/scim")
	user := env.mustCreateUser(map[string]any{
		"userName":    "rollback-user",
		"displayName": "Original",
		"title":       "Original Title",
	})
	assertOriginal := func(step string) {
		t.Helper()
		stored, err := env.store.GetUser(context.Background(), user.ID)
		if err != nil {
			t.Fatalf("%s GetUser error = %v", step, err)
		}
		if stored.DisplayName != "Original" || stored.Title != "Original Title" {
			t.Fatalf("%s profile was not restored: %+v", step, stored)
		}
		if stored.Password != "" {
			t.Fatalf("%s plain password was persisted: %q", step, stored.Password)
		}
	}

	recorder := env.do(http.MethodPut, "/Users/"+user.ID, map[string]any{
		"userName":    "rollback-user",
		"displayName": "Changed",
		"title":       "Changed Title",
		"password":    "secret",
	}, nil)
	requireError(t, recorder, http.StatusBadRequest, "invalidValue")
	if setterUser == nil || setterUser.DisplayName != "Changed" {
		t.Fatalf("setter user = %+v", setterUser)
	}
	assertOriginal("PUT")

	recorder = env.do(http.MethodPatch, "/Users/"+user.ID, PatchRequest{Operations: []PatchOperation{
		{Op: "replace", Path: "displayName", Value: "Patched"},
		{Op: "replace", Path: "title", Value: "Patched Title"},
		{Op: "replace", Path: "password", Value: "secret"},
	}}, nil)
	requireError(t, recorder, http.StatusBadRequest, "invalidValue")
	assertOriginal("PATCH")

	ctx := auth.ContextWithPrincipal(context.Background(), &auth.Principal{Subject: user.ID})
	recorder = env.doContext(ctx, http.MethodPut, "/Me", map[string]any{
		"userName":    "rollback-user",
		"displayName": "Me Changed",
		"password":    "secret",
	}, nil)
	requireError(t, recorder, http.StatusBadRequest, "invalidValue")
	assertOriginal("PUT /Me")

	recorder = env.doContext(ctx, http.MethodPatch, "/Me", PatchRequest{Operations: []PatchOperation{
		{Op: "replace", Path: "title", Value: "Me Patched"},
		{Op: "replace", Path: "password", Value: "secret"},
	}}, nil)
	requireError(t, recorder, http.StatusBadRequest, "invalidValue")
	assertOriginal("PATCH /Me")

	if setterUser == nil || setterUser.Password != "" {
		t.Fatalf("setter received a stored password: %+v", setterUser)
	}
}

// TestPasswordFailureKeepsConcurrentProfile verifies a concurrent change during compensation is
// reported as a conflict and is never overwritten. | TestPasswordFailureKeepsConcurrentProfile 校验
// 补偿期间的并发修改报告为冲突且绝不被覆盖。
func TestPasswordFailureKeepsConcurrentProfile(t *testing.T) {
	base := NewMemoryStore()
	var concurrentErr error
	env := newBulkStoreEnv(t, base, Options{PasswordSetter: func(ctx context.Context, user *User, password string) error {
		updated := user.Clone()
		updated.DisplayName = "Concurrent"
		_, concurrentErr = base.ReplaceUser(context.Background(), updated)
		return rejectPassword
	}})
	user := env.mustCreateUser(map[string]any{"userName": "conflict-user", "displayName": "Original"})

	recorder := env.do(http.MethodPut, "/Users/"+user.ID, map[string]any{
		"userName":    "conflict-user",
		"displayName": "Changed",
		"password":    "secret",
	}, nil)
	body := requireError(t, recorder, http.StatusConflict, "")
	if concurrentErr != nil {
		t.Fatalf("concurrent ReplaceUser error = %v", concurrentErr)
	}
	if strings.Contains(body.Detail, "secret") || strings.Contains(body.Detail, "password hook") {
		t.Fatalf("conflict detail leaked hook text: %q", body.Detail)
	}
	stored, err := base.GetUser(context.Background(), user.ID)
	if err != nil {
		t.Fatalf("GetUser error = %v", err)
	}
	if stored.DisplayName != "Concurrent" {
		t.Fatalf("concurrent profile was overwritten: %q", stored.DisplayName)
	}
}

// TestPasswordRollbackStoreFailureIsGeneric verifies a failed compensation is reported as an
// internal error without echoing backend or hook text. | TestPasswordRollbackStoreFailureIsGeneric
// 校验失败的补偿报告为内部错误，且不回显后端或钩子文本。
func TestPasswordRollbackStoreFailureIsGeneric(t *testing.T) {
	base := NewMemoryStore()
	faults := &faultStore{Store: base}
	replaceCalls := 0
	faults.faults.replaceUser = func(ctx context.Context, user *User) error {
		replaceCalls++
		if replaceCalls == 2 {
			return errors.New("backend secret unavailable")
		}
		return nil
	}
	env := newBulkStoreEnv(t, faults, Options{PasswordSetter: func(ctx context.Context, user *User, password string) error {
		return rejectPassword
	}})
	user := env.mustCreateUser(map[string]any{"userName": "rollback-fault", "displayName": "Original"})

	recorder := env.do(http.MethodPut, "/Users/"+user.ID, map[string]any{
		"userName":    "rollback-fault",
		"displayName": "Changed",
		"password":    "secret",
	}, nil)
	body := requireError(t, recorder, http.StatusInternalServerError, "")
	if strings.Contains(body.Detail, "backend") || strings.Contains(body.Detail, "password hook") {
		t.Fatalf("internal detail leaked text: %q", body.Detail)
	}
	if replaceCalls != 2 {
		t.Fatalf("ReplaceUser calls = %d, want 2", replaceCalls)
	}
	stored, err := base.GetUser(context.Background(), user.ID)
	if err != nil {
		t.Fatalf("GetUser error = %v", err)
	}
	if stored.DisplayName != "Changed" {
		t.Fatalf("profile = %q, want the un-restored change", stored.DisplayName)
	}
}

// TestBulkNonAtomicPasswordFailureRestoresProfile verifies non-atomic bulk PUT and PATCH restore
// the profile of the failing operation only. | TestBulkNonAtomicPasswordFailureRestoresProfile 校验
// 非事务批量 PUT 与 PATCH 只恢复失败操作自身的资料。
func TestBulkNonAtomicPasswordFailureRestoresProfile(t *testing.T) {
	base := NewMemoryStore()
	env := newBulkStoreEnv(t, base, Options{PasswordSetter: func(ctx context.Context, user *User, password string) error {
		return rejectPassword
	}})
	user := env.mustCreateUser(map[string]any{"userName": "bulk-password", "displayName": "Original"})

	recorder := env.do(http.MethodPost, "/Bulk", BulkRequest{Operations: []BulkOperation{
		{
			Method: "PUT",
			Path:   "/Users/" + user.ID,
			Data: map[string]any{
				"userName":    "bulk-password",
				"displayName": "Put Changed",
				"password":    "secret",
			},
		},
		{
			Method: "PATCH",
			Path:   "/Users/" + user.ID,
			Data: map[string]any{
				"schemas": []string{PatchOpSchema},
				"Operations": []any{
					map[string]any{"op": "replace", "path": "displayName", "value": "Patched"},
					map[string]any{"op": "replace", "path": "password", "value": "secret"},
				},
			},
		},
	}}, nil)
	requireStatus(t, recorder, http.StatusOK)
	response := decodeResponse[BulkResponse](t, recorder)
	if len(response.Operations) != 2 {
		t.Fatalf("operations = %d", len(response.Operations))
	}
	for index, operation := range response.Operations {
		if operation.Status != intString(http.StatusBadRequest) {
			t.Fatalf("operation %d status = %q", index, operation.Status)
		}
	}
	stored, err := base.GetUser(context.Background(), user.ID)
	if err != nil {
		t.Fatalf("GetUser error = %v", err)
	}
	if stored.DisplayName != "Original" {
		t.Fatalf("non-atomic bulk left a modified profile: %q", stored.DisplayName)
	}
}

// TestBulkAtomicPasswordPrecheckRollsBack verifies an atomic bulk precheck rejection rolls back
// earlier operations. | TestBulkAtomicPasswordPrecheckRollsBack 校验原子批量预检拒绝会回滚更早的
// 操作。
func TestBulkAtomicPasswordPrecheckRollsBack(t *testing.T) {
	env := newTestEnv(t, Options{
		BulkAtomic: true,
		PasswordSetter: func(ctx context.Context, user *User, password string) error {
			return nil
		},
		PasswordPrecheck: PasswordValidator(func(ctx context.Context, user *User, password string) error {
			if password == "weak" {
				return errors.New("password too weak")
			}
			return nil
		}),
	}, "/scim")
	recorder := env.do(http.MethodPost, "/Bulk", BulkRequest{Operations: []BulkOperation{
		{Method: "POST", Path: "/Users", Data: map[string]any{"userName": "atomic-first"}},
		{Method: "POST", Path: "/Users", Data: map[string]any{"userName": "atomic-weak", "password": "weak"}},
	}}, nil)
	requireError(t, recorder, http.StatusBadRequest, "invalidValue")
	if names := listUserNames(t, env.store); len(names) != 0 {
		t.Fatalf("atomic bulk did not roll back precheck rejection: %v", names)
	}
}
