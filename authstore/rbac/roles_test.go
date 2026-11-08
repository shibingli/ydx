package rbac_test

import (
	"errors"
	"testing"

	authrbac "github.com/shibingli/ydx/auth/authz/rbac"
)

// TestRoleLifecycle covers add, get, list, duplicate rejection and deep copies.
// | TestRoleLifecycle 覆盖添加、读取、列表、重复拒绝与深拷贝。
func TestRoleLifecycle(t *testing.T) {
	store, _ := newStore(t, "")
	role := authrbac.Role{
		Name:        "viewer",
		Description: "read only",
		Permissions: []string{"post:read", "comment:read"},
		Parents:     []string{"base"},
		Scope:       "tenant:*",
		Metadata:    map[string]string{"team": "eng"},
	}
	if err := store.AddRole(testContext, authrbac.Role{Name: "base"}); err != nil {
		t.Fatalf("add base: %v | 添加基础角色失败", err)
	}
	if err := store.AddRole(testContext, role); err != nil {
		t.Fatalf("add role: %v | 添加角色失败", err)
	}

	role.Permissions[0] = "mutated"
	role.Parents[0] = "mutated"
	role.Metadata["team"] = "mutated"

	stored, err := store.GetRole(testContext, "viewer")
	if err != nil {
		t.Fatalf("get role: %v | 读取角色失败", err)
	}
	if stored.Description != "read only" || stored.Scope != "tenant:*" {
		t.Fatalf("stored role = %+v | 存储角色字段不符", stored)
	}
	if stored.Permissions[0] != "post:read" || stored.Parents[0] != "base" || stored.Metadata["team"] != "eng" {
		t.Fatalf("stored role aliased caller input: %+v | 存储角色别名了调用方输入", stored)
	}

	stored.Permissions[0] = "mutated"
	stored.Parents[0] = "mutated"
	stored.Metadata["team"] = "mutated"
	again, err := store.GetRole(testContext, "viewer")
	if err != nil {
		t.Fatalf("get role again: %v | 再次读取角色失败", err)
	}
	if again.Permissions[0] != "post:read" || again.Parents[0] != "base" || again.Metadata["team"] != "eng" {
		t.Fatalf("GetRole aliased stored value: %+v | GetRole 别名了存储值", again)
	}

	if err := store.AddRole(testContext, authrbac.Role{Name: "viewer"}); !errors.Is(err, authrbac.ErrRoleExists) {
		t.Fatalf("duplicate role error = %v | 重复角色错误不符", err)
	}
	if _, err := store.GetRole(testContext, "missing"); !errors.Is(err, authrbac.ErrRoleNotFound) {
		t.Fatalf("missing role error = %v | 缺失角色错误不符", err)
	}

	roles, err := store.ListRoles(testContext)
	if err != nil {
		t.Fatalf("list roles: %v | 列出角色失败", err)
	}
	if len(roles) != 2 || roles[0].Name != "base" || roles[1].Name != "viewer" {
		t.Fatalf("roles = %+v | 角色顺序不符", roles)
	}
	roles[1].Metadata["team"] = "mutated"
	again, err = store.GetRole(testContext, "viewer")
	if err != nil {
		t.Fatalf("get role after list: %v | 列表后读取角色失败", err)
	}
	if again.Metadata["team"] != "eng" {
		t.Fatalf("ListRoles aliased stored value: %+v | ListRoles 别名了存储值", again)
	}
}

// TestRoleValidationAndCycles covers invalid definitions and every cycle shape.
// | TestRoleValidationAndCycles 覆盖非法定义与各种继承环形态。
func TestRoleValidationAndCycles(t *testing.T) {
	store, _ := newStore(t, "")

	for _, role := range []authrbac.Role{
		{Name: " "},
		{Name: "empty-permission", Permissions: []string{""}},
		{Name: "space-permission", Permissions: []string{"  "}},
		{Name: "empty-parent", Parents: []string{""}},
		{Name: "space-parent", Parents: []string{"  "}},
	} {
		if err := store.AddRole(testContext, role); !errors.Is(err, authrbac.ErrInvalidRole) {
			t.Fatalf("invalid role %q error = %v | 非法角色错误不符", role.Name, err)
		}
	}

	if err := store.AddRole(testContext, authrbac.Role{Name: "a", Parents: []string{"b"}}); err != nil {
		t.Fatalf("add a: %v | 添加角色 a 失败", err)
	}
	if err := store.AddRole(testContext, authrbac.Role{Name: "b", Parents: []string{"a"}}); !errors.Is(err, authrbac.ErrRoleCycle) {
		t.Fatalf("direct cycle error = %v | 直接环错误不符", err)
	}
	if err := store.AddRole(testContext, authrbac.Role{Name: "self", Parents: []string{"self"}}); !errors.Is(err, authrbac.ErrRoleCycle) {
		t.Fatalf("self cycle error = %v | 自环错误不符", err)
	}
	if err := store.AddRole(testContext, authrbac.Role{Name: "c", Parents: []string{"a"}}); err != nil {
		t.Fatalf("add c: %v | 添加角色 c 失败", err)
	}
	if err := store.AddRole(testContext, authrbac.Role{Name: "b", Parents: []string{"c"}}); !errors.Is(err, authrbac.ErrRoleCycle) {
		t.Fatalf("transitive cycle error = %v | 传递环错误不符", err)
	}
	if err := store.AddRole(testContext, authrbac.Role{Name: "d", Parents: []string{"missing"}}); err != nil {
		t.Fatalf("missing parent should be ignored: %v | 缺失父角色应被忽略", err)
	}
}

// TestRoleRemoveCascade covers assignment removal and parent-reference cleanup.
// | TestRoleRemoveCascade 覆盖分配删除与父角色引用清理。
func TestRoleRemoveCascade(t *testing.T) {
	first, second := newPair(t)
	if err := first.AddRole(testContext, authrbac.Role{Name: "base", Permissions: []string{"read"}}); err != nil {
		t.Fatalf("add base: %v | 添加基础角色失败", err)
	}
	if err := first.AddRole(testContext, authrbac.Role{Name: "child", Parents: []string{"base"}}); err != nil {
		t.Fatalf("add child: %v | 添加子角色失败", err)
	}
	if err := first.AddRole(testContext, authrbac.Role{Name: "grandchild", Parents: []string{"child"}}); err != nil {
		t.Fatalf("add grandchild: %v | 添加孙角色失败", err)
	}
	if err := first.AddRole(testContext, authrbac.Role{Name: "unrelated"}); err != nil {
		t.Fatalf("add unrelated: %v | 添加无关角色失败", err)
	}
	if err := first.Assign(testContext, authrbac.Assignment{Subject: "alice", Role: "base", Scope: "tenant:1"}); err != nil {
		t.Fatalf("assign base: %v | 分配基础角色失败", err)
	}
	if err := first.Assign(testContext, authrbac.Assignment{Subject: "alice", Role: "child", Scope: "tenant:1"}); err != nil {
		t.Fatalf("assign child: %v | 分配子角色失败", err)
	}

	if err := second.RemoveRole(testContext, "base"); err != nil {
		t.Fatalf("remove base via second instance: %v | 第二实例删除基础角色失败", err)
	}
	if _, err := first.GetRole(testContext, "base"); !errors.Is(err, authrbac.ErrRoleNotFound) {
		t.Fatalf("removed role error = %v | 已删除角色错误不符", err)
	}
	child, err := second.GetRole(testContext, "child")
	if err != nil {
		t.Fatalf("get child: %v | 读取子角色失败", err)
	}
	if len(child.Parents) != 0 {
		t.Fatalf("child parents = %v, want none | 子角色父角色未清理", child.Parents)
	}
	grandchild, err := second.GetRole(testContext, "grandchild")
	if err != nil {
		t.Fatalf("get grandchild: %v | 读取孙角色失败", err)
	}
	if len(grandchild.Parents) != 1 || grandchild.Parents[0] != "child" {
		t.Fatalf("grandchild parents = %v | 孙角色父角色被误改", grandchild.Parents)
	}
	assignments, err := first.Assignments(testContext, "alice")
	if err != nil {
		t.Fatalf("assignments after remove: %v | 删除后列出分配失败", err)
	}
	if len(assignments) != 1 || assignments[0].Role != "child" {
		t.Fatalf("assignments after remove = %+v | 删除角色后分配残留", assignments)
	}
	all, err := first.ListAssignments(testContext)
	if err != nil {
		t.Fatalf("list assignments after remove: %v | 删除后列出全部失败", err)
	}
	if len(all) != 1 {
		t.Fatalf("all assignments after remove = %+v | 删除角色后分配索引残留", all)
	}
	if err := first.RemoveRole(testContext, "base"); !errors.Is(err, authrbac.ErrRoleNotFound) {
		t.Fatalf("double remove error = %v | 重复删除错误不符", err)
	}
	roles, err := first.ListRoles(testContext)
	if err != nil {
		t.Fatalf("list roles after remove: %v | 删除后列出角色失败", err)
	}
	if len(roles) != 3 {
		t.Fatalf("roles after remove = %+v | 删除后角色数量不符", roles)
	}
	for _, role := range roles {
		switch role.Name {
		case "child":
			if len(role.Parents) != 0 {
				t.Fatalf("listed child parents = %v, want none | 列表中的子角色父角色未清理", role.Parents)
			}
		case "grandchild":
			if len(role.Parents) != 1 || role.Parents[0] != "child" {
				t.Fatalf("listed grandchild parents = %v | 列表中的孙角色父角色被误改", role.Parents)
			}
		}
	}
}

// TestRoleCrossInstance covers visibility and uniqueness between two instances.
// | TestRoleCrossInstance 覆盖两个实例之间的可见性与唯一性。
func TestRoleCrossInstance(t *testing.T) {
	first, second := newPair(t)
	role := authrbac.Role{Name: "viewer", Permissions: []string{"post:read"}, Metadata: map[string]string{"team": "eng"}}
	if err := first.AddRole(testContext, role); err != nil {
		t.Fatalf("first add role: %v | 第一实例添加角色失败", err)
	}
	stored, err := second.GetRole(testContext, "viewer")
	if err != nil {
		t.Fatalf("second get role: %v | 第二实例读取角色失败", err)
	}
	if stored.Permissions[0] != "post:read" || stored.Metadata["team"] != "eng" {
		t.Fatalf("second stored role = %+v | 第二实例角色内容不符", stored)
	}
	if err := second.AddRole(testContext, authrbac.Role{Name: "viewer"}); !errors.Is(err, authrbac.ErrRoleExists) {
		t.Fatalf("cross-instance duplicate error = %v | 跨实例重复角色错误不符", err)
	}
	if err := second.AddRole(testContext, authrbac.Role{Name: "editor", Parents: []string{"viewer"}}); err != nil {
		t.Fatalf("second add editor: %v | 第二实例添加编辑角色失败", err)
	}
	if _, err := first.GetRole(testContext, "editor"); err != nil {
		t.Fatalf("first get editor: %v | 第一实例读取编辑角色失败", err)
	}
}
