package rbac_test

import (
	"context"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/alicebob/miniredis/v2"

	authrbac "github.com/shibingli/ydx/auth/authz/rbac"
	rbacstore "github.com/shibingli/ydx/authstore/rbac"
)

// TestReset removes every record and every per-subject index in one call.
// | TestReset 在一次调用中删除所有记录与全部按主体索引。
func TestReset(t *testing.T) {
	store, server := newStore(t, "")
	if err := store.AddRole(testContext, authrbac.Role{Name: "base"}); err != nil {
		t.Fatalf("add base: %v | 添加基础角色失败", err)
	}
	if err := store.AddRole(testContext, authrbac.Role{Name: "child", Parents: []string{"base"}}); err != nil {
		t.Fatalf("add child: %v | 添加子角色失败", err)
	}
	for _, subject := range []string{"alice", "bob"} {
		if err := store.Assign(testContext, authrbac.Assignment{Subject: subject, Role: "child", Scope: "tenant:1"}); err != nil {
			t.Fatalf("assign %s: %v | 分配 %s 失败", subject, err, subject)
		}
	}
	if err := store.AddPolicy(testContext, authrbac.Policy{ID: "allow", Effect: authrbac.EffectPermit}); err != nil {
		t.Fatalf("add policy: %v | 添加策略失败", err)
	}

	indexKeys := []string{
		rbacstore.DefaultKeyPrefix + "{authstore:rbac}:assignments:subject:5:alice",
		rbacstore.DefaultKeyPrefix + "{authstore:rbac}:assignments:subject:3:bob",
	}
	before := server.Keys()
	for _, key := range indexKeys {
		if !containsKey(before, key) {
			t.Fatalf("index key %q missing before reset: %v | 重置前索引键缺失", key, before)
		}
	}

	if err := store.Reset(testContext); err != nil {
		t.Fatalf("reset: %v | 重置存储失败", err)
	}
	if keys := server.Keys(); len(keys) != 0 {
		t.Fatalf("keys after reset = %v, want none | 重置后仍有键残留", keys)
	}
	roles, err := store.ListRoles(testContext)
	if err != nil {
		t.Fatalf("list roles after reset: %v | 重置后列出角色失败", err)
	}
	if len(roles) != 0 {
		t.Fatalf("roles after reset = %+v | 重置后角色残留", roles)
	}
	if assignments, err := store.ListAssignments(testContext); err != nil || len(assignments) != 0 {
		t.Fatalf("assignments after reset = %+v, %v | 重置后分配残留", assignments, err)
	}
	if policies, err := store.ListPolicies(testContext); err != nil || len(policies) != 0 {
		t.Fatalf("policies after reset = %+v, %v | 重置后策略残留", policies, err)
	}
	if _, err := store.GetRole(testContext, "child"); !errors.Is(err, authrbac.ErrRoleNotFound) {
		t.Fatalf("get role after reset error = %v | 重置后角色仍存在", err)
	}
	if _, err := store.GetPolicy(testContext, "allow"); !errors.Is(err, authrbac.ErrPolicyNotFound) {
		t.Fatalf("get policy after reset error = %v | 重置后策略仍存在", err)
	}

	if err := store.Reset(testContext); err != nil {
		t.Fatalf("second reset: %v | 第二次重置失败", err)
	}
	if err := store.AddRole(testContext, authrbac.Role{Name: "child"}); err != nil {
		t.Fatalf("add role after reset: %v | 重置后添加角色失败", err)
	}
	roles, err = store.ListRoles(testContext)
	if err != nil {
		t.Fatalf("list roles after reuse: %v | 复用后列出角色失败", err)
	}
	if len(roles) != 1 || roles[0].Name != "child" {
		t.Fatalf("roles after reuse = %+v | 重置后复用角色不符", roles)
	}
}

// TestResetPrefixIsolation proves Reset only clears its own namespace.
// | TestResetPrefixIsolation 证明 Reset 只清除自己的命名空间。
func TestResetPrefixIsolation(t *testing.T) {
	server := miniredis.RunT(t)
	first := newStoreOn(t, server, "app-a:")
	second := newStoreOn(t, server, "app-b:")
	if err := first.AddRole(testContext, authrbac.Role{Name: "viewer"}); err != nil {
		t.Fatalf("first add role: %v | 第一命名空间添加角色失败", err)
	}
	if err := second.AddRole(testContext, authrbac.Role{Name: "viewer"}); err != nil {
		t.Fatalf("second add role: %v | 第二命名空间添加角色失败", err)
	}
	if err := first.Reset(testContext); err != nil {
		t.Fatalf("first reset: %v | 第一命名空间重置失败", err)
	}
	if _, err := first.GetRole(testContext, "viewer"); !errors.Is(err, authrbac.ErrRoleNotFound) {
		t.Fatalf("first role after reset error = %v | 重置后第一命名空间角色残留", err)
	}
	if _, err := second.GetRole(testContext, "viewer"); err != nil {
		t.Fatalf("second role after first reset: %v | 第一命名空间重置影响了第二命名空间", err)
	}
}

// TestResetCanceledContext keeps the canceled-context sentinel on the reset path.
// | TestResetCanceledContext 在重置路径上保留已取消上下文哨兵。
func TestResetCanceledContext(t *testing.T) {
	store, _ := newStore(t, "")
	if err := store.AddRole(testContext, authrbac.Role{Name: "viewer"}); err != nil {
		t.Fatalf("add role: %v | 添加角色失败", err)
	}
	ctx, cancel := context.WithDeadline(context.Background(), time.Now().Add(-time.Second))
	defer cancel()
	err := store.Reset(ctx)
	requireError(t, err, authrbac.ErrCanceled, "canceled Reset")
	requireError(t, err, context.DeadlineExceeded, "canceled Reset")
	roles, listErr := store.ListRoles(testContext)
	if listErr != nil {
		t.Fatalf("list roles after canceled reset: %v | 取消失败后列出角色失败", listErr)
	}
	if len(roles) != 1 {
		t.Fatalf("canceled Reset changed state: %+v | 取消的重置改变了状态", roles)
	}
	if !strings.Contains(err.Error(), "canceled") && !strings.Contains(err.Error(), "deadline") {
		t.Fatalf("canceled Reset error text = %q | 取消重置错误文本不符", err.Error())
	}
}
