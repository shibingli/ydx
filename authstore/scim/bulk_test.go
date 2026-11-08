package scim_test

import (
	"bytes"
	"errors"
	"net/http"
	"net/http/httptest"
	"slices"
	"strings"
	"testing"

	scimlib "github.com/shibingli/ydx/auth/directory/scim"
	scimstore "github.com/shibingli/ydx/authstore/scim"
	ydxjson "github.com/shibingli/ydx/json"
)

// newAtomicServer returns a SCIM server with transactional bulk enabled.
// | newAtomicServer 返回启用事务性批量的 SCIM 服务端。
func newAtomicServer(t *testing.T, store *scimstore.Store) *scimlib.Server {
	t.Helper()
	server, err := scimlib.New(scimlib.Options{Store: store, BulkAtomic: true})
	if err != nil {
		t.Fatalf("new server: %v | 创建服务端失败", err)
	}
	return server
}

// postBulk sends request to the server and returns the recorder.
// | postBulk 把 request 发送给服务端并返回记录器。
func postBulk(t *testing.T, server *scimlib.Server, request scimlib.BulkRequest) *httptest.ResponseRecorder {
	t.Helper()
	if len(request.Schemas) == 0 {
		request.Schemas = []string{scimlib.BulkRequestSchema}
	}
	body, err := ydxjson.Marshal(request)
	if err != nil {
		t.Fatalf("encode bulk request: %v | 编码批量请求失败", err)
	}
	httpRequest := httptest.NewRequest(http.MethodPost, "/Bulk", bytes.NewReader(body))
	httpRequest.Header.Set("Content-Type", scimlib.ContentType)
	recorder := httptest.NewRecorder()
	server.HTTPHandler("").ServeHTTP(recorder, httpRequest)
	return recorder
}

// TestBulkAtomicRollbackEndToEnd proves that a failed atomic bulk request restores every prior
// resource through the Redis store: updated users and groups, created resources and a deleted
// group are all compensated. | TestBulkAtomicRollbackEndToEnd 证明失败的原子批量请求会通过 Redis 存储
// 恢复每个先前资源：被更新的用户与组、被创建的资源与被删除的组都会得到补偿。
func TestBulkAtomicRollbackEndToEnd(t *testing.T) {
	store := newTestStore(t)
	user := sampleUser("rollback-user")
	user.DisplayName = "before"
	createdUser, err := store.CreateUser(testContext, user)
	if err != nil {
		t.Fatalf("create user: %v | 创建用户失败", err)
	}
	group := sampleGroup("before-group")
	createdGroup, err := store.CreateGroup(testContext, group)
	if err != nil {
		t.Fatalf("create group: %v | 创建组失败", err)
	}
	goneGroup := sampleGroup("gone-group")
	createdGone, err := store.CreateGroup(testContext, goneGroup)
	if err != nil {
		t.Fatalf("create gone group: %v | 创建待删除组失败", err)
	}
	server := newAtomicServer(t, store)
	request := scimlib.BulkRequest{
		Operations: []scimlib.BulkOperation{
			{
				Method: http.MethodPut,
				Path:   "/Users/" + createdUser.ID,
				Data: map[string]any{
					"userName":    "rollback-user",
					"displayName": "after",
				},
			},
			{
				Method: http.MethodPatch,
				Path:   "/Groups/" + createdGroup.ID,
				Data: map[string]any{
					"schemas": []string{scimlib.PatchOpSchema},
					"Operations": []map[string]any{
						{"op": "replace", "path": "displayName", "value": "after-group"},
					},
				},
			},
			{
				BulkID: "new-user",
				Method: http.MethodPost,
				Path:   "/Users",
				Data:   map[string]any{"userName": "rollback-created"},
			},
			{
				BulkID: "new-group",
				Method: http.MethodPost,
				Path:   "/Groups",
				Data:   map[string]any{"displayName": "rollback-created-group"},
			},
			{
				Method: http.MethodDelete,
				Path:   "/Groups/" + createdGone.ID,
			},
			{
				Method: http.MethodPost,
				Path:   "/Users",
				Data:   map[string]any{"userName": "rollback-user"},
			},
		},
	}
	recorder := postBulk(t, server, request)
	if recorder.Code != http.StatusConflict {
		t.Fatalf("status = %d, body = %s | 状态码不符", recorder.Code, recorder.Body.String())
	}
	if !strings.Contains(recorder.Body.String(), "uniqueness") {
		t.Fatalf("body lacks the uniqueness scimType: %s | 响应缺少 uniqueness 类型", recorder.Body.String())
	}
	restoredUser, err := store.GetUser(testContext, createdUser.ID)
	if err != nil {
		t.Fatalf("get restored user: %v | 读取恢复用户失败", err)
	}
	if restoredUser.DisplayName != "before" {
		t.Fatalf("user displayName = %q, want before | 用户展示名未恢复", restoredUser.DisplayName)
	}
	restoredGroup, err := store.GetGroup(testContext, createdGroup.ID)
	if err != nil {
		t.Fatalf("get restored group: %v | 读取恢复组失败", err)
	}
	if restoredGroup.DisplayName != "before-group" {
		t.Fatalf("group displayName = %q, want before-group | 组展示名未恢复", restoredGroup.DisplayName)
	}
	recreatedGone, err := store.GetGroup(testContext, createdGone.ID)
	if err != nil {
		t.Fatalf("get recreated group: %v | 读取重建组失败", err)
	}
	if recreatedGone.DisplayName != "gone-group" {
		t.Fatalf("recreated displayName = %q | 重建组展示名不符", recreatedGone.DisplayName)
	}
	if _, err := store.GetUserByUserName(testContext, "rollback-created"); !errors.Is(err, scimlib.ErrNotFound) {
		t.Fatalf("created user survived rollback: %v | 创建的用戶在回滚后仍存在", err)
	}
	if _, err := store.GetGroupByDisplayName(testContext, "rollback-created-group"); !errors.Is(err, scimlib.ErrNotFound) {
		t.Fatalf("created group survived rollback: %v | 创建的组在回滚后仍存在", err)
	}
	if _, err := store.GetGroupByDisplayName(testContext, "after-group"); !errors.Is(err, scimlib.ErrNotFound) {
		t.Fatalf("patched group name survived rollback: %v | 补丁组名在回滚后仍存在", err)
	}
	users, totalUsers, err := store.ListUsers(testContext, scimlib.ListQuery{Count: -1})
	if err != nil || totalUsers != 1 || len(users) != 1 || users[0].UserName != "rollback-user" {
		t.Fatalf("users after rollback = %d, err = %v | 回滚后用户列表不符", totalUsers, err)
	}
	groups, totalGroups, err := store.ListGroups(testContext, scimlib.ListQuery{Count: -1})
	if err != nil || totalGroups != 2 || len(groups) != 2 {
		t.Fatalf("groups after rollback = %d, err = %v | 回滚后组列表不符", totalGroups, err)
	}
	names := groupNameList(groups)
	slices.Sort(names)
	if !slices.Equal(names, []string{"before-group", "gone-group"}) {
		t.Fatalf("group names = %v | 回滚后组名不符", names)
	}
}

// TestBulkAtomicSuccess covers a successful transactional bulk request with creates, an update
// and a delete. | TestBulkAtomicSuccess 覆盖包含创建、更新与删除的成功事务性批量请求。
func TestBulkAtomicSuccess(t *testing.T) {
	store := newTestStore(t)
	existing := sampleUser("existing")
	existing.DisplayName = "original"
	createdExisting, err := store.CreateUser(testContext, existing)
	if err != nil {
		t.Fatalf("create existing: %v | 创建既有用户失败", err)
	}
	removable := sampleGroup("removable")
	createdRemovable, err := store.CreateGroup(testContext, removable)
	if err != nil {
		t.Fatalf("create removable: %v | 创建待删除组失败", err)
	}
	server := newAtomicServer(t, store)
	request := scimlib.BulkRequest{
		Operations: []scimlib.BulkOperation{
			{
				BulkID: "new-user",
				Method: http.MethodPost,
				Path:   "/Users",
				Data:   map[string]any{"userName": "created-user"},
			},
			{
				BulkID: "new-group",
				Method: http.MethodPost,
				Path:   "/Groups",
				Data:   map[string]any{"displayName": "created-group"},
			},
			{
				Method: http.MethodPut,
				Path:   "/Users/" + createdExisting.ID,
				Data: map[string]any{
					"userName":    "existing",
					"displayName": "updated",
				},
			},
			{
				Method: http.MethodDelete,
				Path:   "/Groups/" + createdRemovable.ID,
			},
		},
	}
	recorder := postBulk(t, server, request)
	if recorder.Code != http.StatusOK {
		t.Fatalf("status = %d, body = %s | 状态码不符", recorder.Code, recorder.Body.String())
	}
	var response scimlib.BulkResponse
	if err := ydxjson.Unmarshal(recorder.Body.Bytes(), &response); err != nil {
		t.Fatalf("decode bulk response: %v | 解码批量响应失败", err)
	}
	if len(response.Operations) != 4 {
		t.Fatalf("operations = %d, want 4 | 响应操作数不符", len(response.Operations))
	}
	wantStatuses := []string{"201", "201", "200", "204"}
	gotStatuses := make([]string, 0, len(response.Operations))
	for _, operation := range response.Operations {
		gotStatuses = append(gotStatuses, operation.Status)
	}
	if !slices.Equal(gotStatuses, wantStatuses) {
		t.Fatalf("statuses = %v, want %v | 操作状态不符", gotStatuses, wantStatuses)
	}
	if _, err := store.GetUserByUserName(testContext, "created-user"); err != nil {
		t.Fatalf("created user missing: %v | 创建的用户缺失", err)
	}
	if _, err := store.GetGroupByDisplayName(testContext, "created-group"); err != nil {
		t.Fatalf("created group missing: %v | 创建的组缺失", err)
	}
	updated, err := store.GetUser(testContext, createdExisting.ID)
	if err != nil || updated.DisplayName != "updated" {
		t.Fatalf("updated user = %+v, err = %v | 更新的用户不符", updated, err)
	}
	if _, err := store.GetGroup(testContext, createdRemovable.ID); !errors.Is(err, scimlib.ErrNotFound) {
		t.Fatalf("deleted group still exists: %v | 删除的组仍存在", err)
	}
}

// TestBulkVersionPrecondition verifies that a stale bulk If-Match aborts the request before any
// mutation and classifies as HTTP 412. | TestBulkVersionPrecondition 验证过期的批量 If-Match 会在任何
// 变更前中止请求并归类为 HTTP 412。
func TestBulkVersionPrecondition(t *testing.T) {
	store := newTestStore(t)
	user := createUser(t, store, "alice")
	server := newAtomicServer(t, store)
	request := scimlib.BulkRequest{
		Operations: []scimlib.BulkOperation{
			{
				Method:  http.MethodPut,
				Path:    "/Users/" + user.ID,
				Version: `W/"stale-version"`,
				Data: map[string]any{
					"userName":    "alice",
					"displayName": "changed",
				},
			},
		},
	}
	recorder := postBulk(t, server, request)
	if recorder.Code != http.StatusPreconditionFailed {
		t.Fatalf("status = %d, body = %s | 状态码不符", recorder.Code, recorder.Body.String())
	}
	current, err := store.GetUser(testContext, user.ID)
	if err != nil {
		t.Fatalf("get after rejected bulk: %v | 拒绝批量后读取失败", err)
	}
	if current.DisplayName == "changed" {
		t.Fatal("rejected bulk changed the user | 拒绝的批量改变了用户")
	}
	if current.Meta.Version != user.Meta.Version {
		t.Fatalf("version changed: %q -> %q | 版本发生了变化", user.Meta.Version, current.Meta.Version)
	}
}
