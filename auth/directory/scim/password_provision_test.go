package scim

import (
	"context"
	"errors"
	"net/http"
	"strings"
	"sync"
	"testing"
)

// provisionTx is a concurrency-safe PasswordTransaction for tests. | provisionTx 是测试用并发安全
// PasswordTransaction。
type provisionTx struct {
	// mu guards the counters and callbacks. | mu 保护计数器与回调。
	mu sync.Mutex
	// commitErr is returned by Commit. | commitErr 由 Commit 返回。
	commitErr error
	// rollbackErr is returned by Rollback. | rollbackErr 由 Rollback 返回。
	rollbackErr error
	// onCommit runs before Commit returns. | onCommit 在 Commit 返回前运行。
	onCommit func()
	// commitCalls counts Commit calls. | commitCalls 统计 Commit 调用。
	commitCalls int
	// rollbackCalls counts Rollback calls. | rollbackCalls 统计 Rollback 调用。
	rollbackCalls int
	// cancelledRollback reports a Rollback that received a cancelled context. |
	// cancelledRollback 表示 Rollback 收到了已取消上下文。
	cancelledRollback bool
}

// Commit records the call and returns commitErr. | Commit 记录调用并返回 commitErr。
func (t *provisionTx) Commit(_ context.Context) error {
	t.mu.Lock()
	t.commitCalls++
	callback := t.onCommit
	err := t.commitErr
	t.mu.Unlock()
	if callback != nil {
		callback()
	}
	return err
}

// Rollback records the call and returns rollbackErr. | Rollback 记录调用并返回 rollbackErr。
func (t *provisionTx) Rollback(ctx context.Context) error {
	t.mu.Lock()
	defer t.mu.Unlock()
	t.rollbackCalls++
	if ctx != nil && ctx.Err() != nil {
		t.cancelledRollback = true
	}
	return t.rollbackErr
}

// provisionCounts returns the Commit and Rollback call counts. | provisionCounts 返回 Commit 与
// Rollback 调用次数。
func (t *provisionTx) provisionCounts() (int, int) {
	t.mu.Lock()
	defer t.mu.Unlock()
	return t.commitCalls, t.rollbackCalls
}

// provisionCall records one BeginPassword invocation. | provisionCall 记录一次 BeginPassword 调用。
type provisionCall struct {
	// user is the clone passed at Begin. | user 是 Begin 收到的克隆。
	user *User
	// password is the plain password passed at Begin. | password 是 Begin 收到的明文口令。
	password string
	// tx is the transaction returned to the server. | tx 是返回给服务端的事务。
	tx *provisionTx
}

// provisionRecorder is a concurrency-safe PasswordProvisioner for tests. | provisionRecorder 是测试用
// 并发安全 PasswordProvisioner。
type provisionRecorder struct {
	// mu guards calls. | mu 保护 calls。
	mu sync.Mutex
	// calls records every Begin. | calls 记录每次 Begin。
	calls []*provisionCall
	// beginErr is returned by Begin. | beginErr 由 Begin 返回。
	beginErr error
	// commitErr is copied into each transaction. | commitErr 复制到每个事务。
	commitErr error
	// rollbackErr is copied into each transaction. | rollbackErr 复制到每个事务。
	rollbackErr error
	// onCommit is copied into each transaction. | onCommit 复制到每个事务。
	onCommit func()
}

// BeginPassword records the call and returns a configured transaction. | BeginPassword 记录调用并
// 返回已配置事务。
func (r *provisionRecorder) BeginPassword(_ context.Context, user *User, password string) (PasswordTransaction, error) {
	call := &provisionCall{
		user:     user.Clone(),
		password: password,
		tx:       &provisionTx{commitErr: r.commitErr, rollbackErr: r.rollbackErr, onCommit: r.onCommit},
	}
	r.mu.Lock()
	r.calls = append(r.calls, call)
	err := r.beginErr
	r.mu.Unlock()
	return call.tx, err
}

// snapshot returns the recorded calls. | snapshot 返回记录的调用。
func (r *provisionRecorder) snapshot() []*provisionCall {
	r.mu.Lock()
	defer r.mu.Unlock()
	return append([]*provisionCall(nil), r.calls...)
}

// callCount returns the number of Begin calls. | callCount 返回 Begin 调用次数。
func (r *provisionRecorder) callCount() int {
	return len(r.snapshot())
}

// TestPasswordProvisionerSuccess covers create, replace and patch ordering, provisioner precedence
// over the legacy setter and discovery. | TestPasswordProvisionerSuccess 覆盖创建、替换与补丁顺序，
// 预配器相对旧版 setter 的优先级以及发现配置。
func TestPasswordProvisionerSuccess(t *testing.T) {
	recorder := &provisionRecorder{}
	setterCalls := 0
	env := newTestEnv(t, Options{
		PasswordSetter: func(ctx context.Context, user *User, password string) error {
			setterCalls++
			return nil
		},
		PasswordProvisioner: recorder,
	}, "/scim")

	createdRecorder := env.do(http.MethodPost, "/Users", map[string]any{
		"userName": "provision-create",
		"password": "create-secret",
	}, nil)
	requireStatus(t, createdRecorder, http.StatusCreated)
	created := decodeResponse[User](t, createdRecorder)

	replaceRecorder := env.do(http.MethodPut, "/Users/"+created.ID, map[string]any{
		"userName":    "provision-create",
		"displayName": "Replaced",
		"password":    "replace-secret",
	}, nil)
	requireStatus(t, replaceRecorder, http.StatusOK)

	patchRecorder := env.do(http.MethodPatch, "/Users/"+created.ID, PatchRequest{Operations: []PatchOperation{
		{Op: "replace", Path: "displayName", Value: "Patched"},
		{Op: "replace", Path: "password", Value: "patch-secret"},
	}}, nil)
	requireStatus(t, patchRecorder, http.StatusOK)

	calls := recorder.snapshot()
	if len(calls) != 3 {
		t.Fatalf("Begin calls = %d, want 3", len(calls))
	}
	wantIDs := []string{"", created.ID, created.ID}
	wantPasswords := []string{"create-secret", "replace-secret", "patch-secret"}
	for index, call := range calls {
		if call.user == nil || call.user.ID != wantIDs[index] {
			t.Fatalf("call %d user = %+v, want id %q", index, call.user, wantIDs[index])
		}
		if call.password != wantPasswords[index] {
			t.Fatalf("call %d password = %q, want %q", index, call.password, wantPasswords[index])
		}
		if call.user.Password != "" {
			t.Fatalf("call %d received a stored password: %q", index, call.user.Password)
		}
		commits, rollbacks := call.tx.provisionCounts()
		if commits != 1 || rollbacks != 0 {
			t.Fatalf("call %d commits = %d, rollbacks = %d", index, commits, rollbacks)
		}
	}
	if setterCalls != 0 {
		t.Fatalf("legacy setter calls = %d, want 0 when a provisioner is set", setterCalls)
	}
	stored, err := env.store.GetUser(context.Background(), created.ID)
	if err != nil {
		t.Fatalf("GetUser error = %v", err)
	}
	if stored.Password != "" || stored.DisplayName != "Patched" {
		t.Fatalf("stored user = %+v", stored)
	}

	discoveryRecorder := env.do(http.MethodGet, "/ServiceProviderConfig", nil, nil)
	requireStatus(t, discoveryRecorder, http.StatusOK)
	config := decodeResponse[ServiceProviderConfig](t, discoveryRecorder)
	if !config.ChangePassword.Supported {
		t.Fatalf("ChangePassword not supported with a provisioner")
	}
}

// TestPasswordProvisionerBeginFailure checks that a Begin rejection prevents every profile write
// and that the precheck still runs first. | TestPasswordProvisionerBeginFailure 校验 Begin 拒绝会
// 阻止所有资料写入，且预检仍然先运行。
func TestPasswordProvisionerBeginFailure(t *testing.T) {
	recorder := &provisionRecorder{beginErr: rejectPassword}
	env := newTestEnv(t, Options{PasswordProvisioner: recorder}, "/scim")

	createResponse := env.do(http.MethodPost, "/Users", map[string]any{
		"userName": "begin-reject",
		"password": "secret",
	}, nil)
	requireError(t, createResponse, http.StatusBadRequest, "invalidValue")
	if names := listUserNames(t, env.store); len(names) != 0 {
		t.Fatalf("Begin failure committed a profile: %v", names)
	}
	if calls := recorder.snapshot(); len(calls) != 1 || calls[0].user.ID != "" {
		t.Fatalf("create Begin calls = %+v", calls)
	}

	user := env.mustCreateUser(map[string]any{"userName": "begin-target", "displayName": "Original"})
	putRecorder := env.do(http.MethodPut, "/Users/"+user.ID, map[string]any{
		"userName":    "begin-target",
		"displayName": "Changed",
		"password":    "secret",
	}, nil)
	requireError(t, putRecorder, http.StatusBadRequest, "invalidValue")
	patchRecorder := env.do(http.MethodPatch, "/Users/"+user.ID, PatchRequest{Operations: []PatchOperation{
		{Op: "replace", Path: "displayName", Value: "Patched"},
		{Op: "replace", Path: "password", Value: "secret"},
	}}, nil)
	requireError(t, patchRecorder, http.StatusBadRequest, "invalidValue")
	stored, err := env.store.GetUser(context.Background(), user.ID)
	if err != nil {
		t.Fatalf("GetUser error = %v", err)
	}
	if stored.DisplayName != "Original" {
		t.Fatalf("Begin failure changed the profile: %q", stored.DisplayName)
	}
	calls := recorder.snapshot()
	if len(calls) != 3 {
		t.Fatalf("Begin calls = %d, want 3", len(calls))
	}
	for index := 1; index < len(calls); index++ {
		if calls[index].user.ID != user.ID {
			t.Fatalf("call %d user id = %q, want %q", index, calls[index].user.ID, user.ID)
		}
		if commits, rollbacks := calls[index].tx.provisionCounts(); commits != 0 || rollbacks != 0 {
			t.Fatalf("rejected call %d commits = %d, rollbacks = %d", index, commits, rollbacks)
		}
	}

	precheckRecorder := &provisionRecorder{}
	precheckEnv := newTestEnv(t, Options{
		PasswordProvisioner: precheckRecorder,
		PasswordPrecheck: PasswordValidator(func(ctx context.Context, user *User, password string) error {
			return errors.New("too weak")
		}),
	}, "/scim")
	precheckResponse := precheckEnv.do(http.MethodPost, "/Users", map[string]any{
		"userName": "precheck-before-begin",
		"password": "weak",
	}, nil)
	requireError(t, precheckResponse, http.StatusBadRequest, "invalidValue")
	if calls := precheckRecorder.callCount(); calls != 0 {
		t.Fatalf("Begin ran after a precheck rejection: %d", calls)
	}
}

// TestPasswordProvisionerCommitFailure checks that a Commit failure rolls back both the external
// transaction and the profile on create, replace and patch. |
// TestPasswordProvisionerCommitFailure 校验 Commit 失败会在创建、替换与补丁上同时回滚外部事务与资料。
func TestPasswordProvisionerCommitFailure(t *testing.T) {
	recorder := &provisionRecorder{commitErr: rejectPassword}
	env := newTestEnv(t, Options{PasswordProvisioner: recorder}, "/scim")

	createRecorder := env.do(http.MethodPost, "/Users", map[string]any{
		"userName": "commit-reject",
		"password": "secret",
	}, nil)
	requireError(t, createRecorder, http.StatusBadRequest, "invalidValue")
	if names := listUserNames(t, env.store); len(names) != 0 {
		t.Fatalf("Commit failure left a created profile: %v", names)
	}

	user := env.mustCreateUser(map[string]any{"userName": "commit-target", "displayName": "Original"})
	putRecorder := env.do(http.MethodPut, "/Users/"+user.ID, map[string]any{
		"userName":    "commit-target",
		"displayName": "Changed",
		"password":    "secret",
	}, nil)
	requireError(t, putRecorder, http.StatusBadRequest, "invalidValue")
	patchRecorder := env.do(http.MethodPatch, "/Users/"+user.ID, PatchRequest{Operations: []PatchOperation{
		{Op: "replace", Path: "displayName", Value: "Patched"},
		{Op: "replace", Path: "password", Value: "secret"},
	}}, nil)
	requireError(t, patchRecorder, http.StatusBadRequest, "invalidValue")
	stored, err := env.store.GetUser(context.Background(), user.ID)
	if err != nil {
		t.Fatalf("GetUser error = %v", err)
	}
	if stored.DisplayName != "Original" {
		t.Fatalf("Commit failure did not restore the profile: %q", stored.DisplayName)
	}
	for index, call := range recorder.snapshot() {
		commits, rollbacks := call.tx.provisionCounts()
		if commits != 1 || rollbacks != 1 {
			t.Fatalf("call %d commits = %d, rollbacks = %d", index, commits, rollbacks)
		}
		if call.tx.cancelledRollback {
			t.Fatalf("call %d rollback received a cancelled context", index)
		}
	}
}

// TestPasswordProvisionerRollbackFailure checks explicit combined errors when external rollback or
// profile compensation fails. | TestPasswordProvisionerRollbackFailure 校验外部回滚或资料补偿失败
// 时的明确组合错误。
func TestPasswordProvisionerRollbackFailure(t *testing.T) {
	rollbackErr := errors.New("external rollback unavailable")
	t.Run("create external rollback and delete failures", func(t *testing.T) {
		base := NewMemoryStore()
		deleteErr := errors.New("delete backend secret")
		faults := &faultStore{Store: base}
		faults.faults.deleteUser = func(ctx context.Context, id string) error { return deleteErr }
		recorder := &provisionRecorder{commitErr: rejectPassword, rollbackErr: rollbackErr}
		env := newBulkStoreEnv(t, faults, Options{PasswordProvisioner: recorder})
		_, err := env.server.createUser(context.Background(), &User{UserName: "rollback-fail"}, "secret", nil, "")
		for _, want := range []error{ErrPasswordRollbackFailed, rejectPassword, rollbackErr, deleteErr} {
			if !errors.Is(err, want) {
				t.Fatalf("error = %v, want errors.Is(%v)", err, want)
			}
		}
		if names := listUserNames(t, base); len(names) != 1 {
			t.Fatalf("created profile = %v, want the un-deletable user", names)
		}
		calls := recorder.snapshot()
		if len(calls) != 1 {
			t.Fatalf("Begin calls = %d", len(calls))
		}
		if commits, rollbacks := calls[0].tx.provisionCounts(); commits != 1 || rollbacks != 1 {
			t.Fatalf("commits = %d, rollbacks = %d", commits, rollbacks)
		}
	})

	t.Run("replace external rollback failure restores profile", func(t *testing.T) {
		base := NewMemoryStore()
		recorder := &provisionRecorder{commitErr: rejectPassword, rollbackErr: rollbackErr}
		env := newBulkStoreEnv(t, base, Options{PasswordProvisioner: recorder})
		user := env.mustCreateUser(map[string]any{"userName": "rollback-replace", "displayName": "Original"})
		response := env.do(http.MethodPut, "/Users/"+user.ID, map[string]any{
			"userName":    "rollback-replace",
			"displayName": "Changed",
			"password":    "secret",
		}, nil)
		body := requireError(t, response, http.StatusInternalServerError, "")
		if strings.Contains(body.Detail, "external") || strings.Contains(body.Detail, "secret") {
			t.Fatalf("internal detail leaked external text: %q", body.Detail)
		}
		stored, err := base.GetUser(context.Background(), user.ID)
		if err != nil {
			t.Fatalf("GetUser error = %v", err)
		}
		if stored.DisplayName != "Original" {
			t.Fatalf("profile was not restored: %q", stored.DisplayName)
		}
		calls := recorder.snapshot()
		if commits, rollbacks := calls[0].tx.provisionCounts(); commits != 1 || rollbacks != 1 {
			t.Fatalf("commits = %d, rollbacks = %d", commits, rollbacks)
		}
	})

	t.Run("profile compensation failure", func(t *testing.T) {
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
		recorder := &provisionRecorder{commitErr: rejectPassword}
		env := newBulkStoreEnv(t, faults, Options{PasswordProvisioner: recorder})
		user := env.mustCreateUser(map[string]any{"userName": "rollback-profile", "displayName": "Original"})
		response := env.do(http.MethodPut, "/Users/"+user.ID, map[string]any{
			"userName":    "rollback-profile",
			"displayName": "Changed",
			"password":    "secret",
		}, nil)
		body := requireError(t, response, http.StatusInternalServerError, "")
		if strings.Contains(body.Detail, "backend") || strings.Contains(body.Detail, "secret") {
			t.Fatalf("internal detail leaked backend text: %q", body.Detail)
		}
		stored, err := base.GetUser(context.Background(), user.ID)
		if err != nil {
			t.Fatalf("GetUser error = %v", err)
		}
		if stored.DisplayName != "Changed" {
			t.Fatalf("profile = %q, want the un-restored change", stored.DisplayName)
		}
	})
}

// TestCreatePasswordDeleteFailureIsExplicit verifies a failed cleanup of a created user joins the
// password cause and the delete failure instead of being ignored. |
// TestCreatePasswordDeleteFailureIsExplicit 校验创建用户清理失败会合并口令原因与删除失败，而不是
// 静默忽略。
func TestCreatePasswordDeleteFailureIsExplicit(t *testing.T) {
	base := NewMemoryStore()
	deleteErr := errors.New("delete backend secret")
	faults := &faultStore{Store: base}
	faults.faults.deleteUser = func(ctx context.Context, id string) error { return deleteErr }
	env := newBulkStoreEnv(t, faults, Options{PasswordSetter: func(ctx context.Context, user *User, password string) error {
		return rejectPassword
	}})
	response := env.do(http.MethodPost, "/Users", map[string]any{
		"userName": "delete-failure",
		"password": "secret",
	}, nil)
	requireError(t, response, http.StatusInternalServerError, "")

	_, err := env.server.createUser(context.Background(), &User{UserName: "delete-failure-direct"}, "secret", nil, "")
	if !errors.Is(err, ErrPasswordRollbackFailed) {
		t.Fatalf("createUser error = %v, want ErrPasswordRollbackFailed", err)
	}
	if !errors.Is(err, rejectPassword) || !errors.Is(err, deleteErr) {
		t.Fatalf("combined error = %v, want password cause and delete failure", err)
	}
	if names := listUserNames(t, base); len(names) != 2 {
		t.Fatalf("stored users = %v, want both un-deletable users", names)
	}
}

// TestPasswordProvisionerCommitConflict verifies a concurrent profile change during compensation is
// reported as a conflict and never overwritten. | TestPasswordProvisionerCommitConflict 校验补偿
// 期间的并发资料修改报告为冲突且绝不被覆盖。
func TestPasswordProvisionerCommitConflict(t *testing.T) {
	base := NewMemoryStore()
	var concurrentErr error
	recorder := &provisionRecorder{commitErr: rejectPassword}
	recorder.onCommit = func() {
		users, _, listErr := base.ListUsers(context.Background(), ListQuery{Count: -1})
		if listErr != nil || len(users) != 1 {
			concurrentErr = listErr
			return
		}
		updated := users[0].Clone()
		updated.DisplayName = "Concurrent"
		_, concurrentErr = base.ReplaceUser(context.Background(), updated)
	}
	env := newBulkStoreEnv(t, base, Options{PasswordProvisioner: recorder})
	user := env.mustCreateUser(map[string]any{"userName": "commit-conflict", "displayName": "Original"})
	response := env.do(http.MethodPut, "/Users/"+user.ID, map[string]any{
		"userName":    "commit-conflict",
		"displayName": "Changed",
		"password":    "secret",
	}, nil)
	requireError(t, response, http.StatusConflict, "")
	if concurrentErr != nil {
		t.Fatalf("concurrent ReplaceUser error = %v", concurrentErr)
	}
	stored, err := base.GetUser(context.Background(), user.ID)
	if err != nil {
		t.Fatalf("GetUser error = %v", err)
	}
	if stored.DisplayName != "Concurrent" {
		t.Fatalf("concurrent profile was overwritten: %q", stored.DisplayName)
	}
	calls := recorder.snapshot()
	if commits, rollbacks := calls[0].tx.provisionCounts(); commits != 1 || rollbacks != 1 {
		t.Fatalf("commits = %d, rollbacks = %d", commits, rollbacks)
	}
}

// TestPasswordProvisionerConcurrent checks that concurrent requests each receive and commit an
// independent transaction. | TestPasswordProvisionerConcurrent 校验并发请求各自获得并提交独立事务。
func TestPasswordProvisionerConcurrent(t *testing.T) {
	recorder := &provisionRecorder{}
	env := newTestEnv(t, Options{PasswordProvisioner: recorder}, "/scim")
	const goroutines = 8
	start := make(chan struct{})
	statuses := make(chan int, goroutines)
	var wg sync.WaitGroup
	for index := 0; index < goroutines; index++ {
		wg.Add(1)
		go func(index int) {
			defer wg.Done()
			<-start
			response := env.do(http.MethodPost, "/Users", map[string]any{
				"userName": "concurrent-" + string(rune('a'+index)),
				"password": "secret",
			}, nil)
			statuses <- response.Code
		}(index)
	}
	close(start)
	wg.Wait()
	close(statuses)
	for status := range statuses {
		if status != http.StatusCreated {
			t.Fatalf("concurrent create status = %d, want 201", status)
		}
	}
	if names := listUserNames(t, env.store); len(names) != goroutines {
		t.Fatalf("stored users = %d, want %d", len(names), goroutines)
	}
	calls := recorder.snapshot()
	if len(calls) != goroutines {
		t.Fatalf("Begin calls = %d, want %d", len(calls), goroutines)
	}
	for index, call := range calls {
		commits, rollbacks := call.tx.provisionCounts()
		if commits != 1 || rollbacks != 0 {
			t.Fatalf("call %d commits = %d, rollbacks = %d", index, commits, rollbacks)
		}
	}
}

// TestPasswordProvisionerNilTransaction verifies a provisioner that returns no transaction cannot
// silently lose the password. | TestPasswordProvisionerNilTransaction 校验预配器未返回事务时不能
// 静默丢失口令。
func TestPasswordProvisionerNilTransaction(t *testing.T) {
	env := newTestEnv(t, Options{PasswordProvisioner: PasswordProvisionerFunc(func(ctx context.Context, user *User, password string) (PasswordTransaction, error) {
		return nil, nil
	})}, "/scim")
	response := env.do(http.MethodPost, "/Users", map[string]any{
		"userName": "nil-transaction",
		"password": "secret",
	}, nil)
	requireError(t, response, http.StatusInternalServerError, "")
	if names := listUserNames(t, env.store); len(names) != 0 {
		t.Fatalf("nil transaction committed a profile: %v", names)
	}
}
