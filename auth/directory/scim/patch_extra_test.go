package scim

import (
	"errors"
	"testing"
)

// pathFor parses a path or fails the test. | pathFor 解析路径，失败时终止测试。
func pathFor(t *testing.T, text string) *AttributePath {
	t.Helper()
	path, err := ParseAttributePath(text)
	if err != nil {
		t.Fatalf("ParseAttributePath(%q): %v", text, err)
	}
	return path
}

// TestApplyGroupOperationPaths verifies Group PATCH dispatch and validation. |
// TestApplyGroupOperationPaths 校验 Group PATCH 分发与校验。
func TestApplyGroupOperationPaths(t *testing.T) {
	group := &Group{DisplayName: "staff", Members: []GroupMember{{Value: "u1"}}}
	if err := applyGroupOperation(group, PatchOperation{Op: "invalid", Path: "displayName"}); err == nil || !errors.Is(err, ErrInvalidSyntax) {
		t.Fatalf("invalid op error = %v", err)
	}
	if err := applyGroupOperation(group, PatchOperation{Op: "remove"}); err == nil || !errors.Is(err, ErrNoTarget) {
		t.Fatalf("pathless remove error = %v", err)
	}
	if err := applyGroupOperation(group, PatchOperation{Op: "add"}); err == nil || !errors.Is(err, ErrInvalidValue) {
		t.Fatalf("pathless nil value error = %v", err)
	}
	err := applyGroupOperation(group, PatchOperation{Op: "add", Value: map[string]any{
		"displayName": "renamed",
		"externalId":  "ext",
		"members":     []any{map[string]any{"value": "u2"}},
	}})
	if err != nil {
		t.Fatalf("pathless add: %v", err)
	}
	if group.DisplayName != "renamed" || group.ExternalID != "ext" || len(group.Members) != 2 {
		t.Fatalf("pathless add = %+v", group)
	}
	if err := applyGroupOperation(group, PatchOperation{Op: "add", Value: "not-an-object"}); err == nil || !errors.Is(err, ErrInvalidValue) {
		t.Fatalf("pathless non-object error = %v", err)
	}
	if err := applyGroupOperation(group, PatchOperation{Op: "replace", Value: map[string]any{"unknown": "x"}}); err == nil || !errors.Is(err, ErrInvalidPath) {
		t.Fatalf("pathless unknown key error = %v", err)
	}
	if err := applyGroupOperation(group, PatchOperation{Op: "add", Path: "bad attribute!", Value: "x"}); err == nil || !errors.Is(err, ErrInvalidPath) {
		t.Fatalf("invalid path error = %v", err)
	}
}

// TestApplyGroupPathAttributes verifies Group attribute mutation rules. |
// TestApplyGroupPathAttributes 校验 Group 属性修改规则。
func TestApplyGroupPathAttributes(t *testing.T) {
	group := &Group{DisplayName: "staff"}
	cases := []struct {
		path  string
		op    string
		value any
		want  error
	}{
		{"urn:example:unknown:2.0:Group", "add", map[string]any{}, ErrInvalidPath},
		{"id", "replace", "x", ErrMutability},
		{"meta", "replace", map[string]any{}, ErrMutability},
		{"schemas", "replace", []any{}, ErrMutability},
		{GroupSchema, "remove", nil, ErrMutability},
		{"displayName.sub", "replace", "x", ErrInvalidPath},
		{"displayName", "remove", nil, ErrMutability},
		{"unknown", "replace", "x", ErrInvalidPath},
	}
	for _, testCase := range cases {
		err := applyGroupPath(group, pathFor(t, testCase.path), parseOp(t, testCase.op), testCase.value)
		if !errors.Is(err, testCase.want) {
			t.Fatalf("path %q op %q error = %v, want %v", testCase.path, testCase.op, err, testCase.want)
		}
	}
	if err := applyGroupPath(group, pathFor(t, "externalId"), patchReplace, "e"); err != nil || group.ExternalID != "e" {
		t.Fatalf("externalId = %q, %v", group.ExternalID, err)
	}
	if err := applyGroupPath(group, pathFor(t, "externalId"), patchRemove, nil); err != nil || group.ExternalID != "" {
		t.Fatalf("externalId remove = %q, %v", group.ExternalID, err)
	}
	if err := applyGroupPath(group, pathFor(t, "displayName"), patchAdd, "next"); err != nil || group.DisplayName != "next" {
		t.Fatalf("displayName = %q, %v", group.DisplayName, err)
	}
	if err := applyGroupPath(group, pathFor(t, "displayName"), patchReplace, true); err == nil || !errors.Is(err, ErrInvalidValue) {
		t.Fatalf("displayName non-string error = %v", err)
	}
	if err := applyGroupPath(group, pathFor(t, GroupSchema), patchReplace, map[string]any{"displayName": "bare"}); err != nil || group.DisplayName != "bare" {
		t.Fatalf("bare schema = %q, %v", group.DisplayName, err)
	}
	if err := applyGroupPath(group, pathFor(t, GroupSchema), patchReplace, "not-an-object"); err == nil || !errors.Is(err, ErrInvalidValue) {
		t.Fatalf("bare schema non-object error = %v", err)
	}
	if err := applyGroupPath(group, pathFor(t, "members"), patchAdd, []any{map[string]any{"value": "u3"}}); err != nil || len(group.Members) != 1 {
		t.Fatalf("members = %+v, %v", group.Members, err)
	}
}

// parseOp converts an operation name for direct path tests. | parseOp 为路径直测转换操作名。
func parseOp(t *testing.T, text string) patchOpKind {
	t.Helper()
	kind, err := parsePatchOp(text)
	if err != nil {
		t.Fatalf("parsePatchOp(%q): %v", text, err)
	}
	return kind
}

// TestPatchUserObjectBranches verifies pathless User object patching. |
// TestPatchUserObjectBranches 校验无路径 User 对象补丁。
func TestPatchUserObjectBranches(t *testing.T) {
	user := &User{}
	if err := patchUserObject(user, "not-an-object", patchAdd); err == nil || !errors.Is(err, ErrInvalidValue) {
		t.Fatalf("non-object error = %v", err)
	}
	if err := patchUserObject(user, map[string]any{"bad attribute!": "x"}, patchAdd); err == nil || !errors.Is(err, ErrInvalidPath) {
		t.Fatalf("invalid key error = %v", err)
	}
	if err := patchUserObject(user, map[string]any{"displayName": "Alice", "active": false}, patchAdd); err != nil {
		t.Fatalf("object add: %v", err)
	}
	if user.DisplayName != "Alice" || user.ActiveValue() {
		t.Fatalf("object add = %+v", user)
	}
	if err := applyUserPath(user, pathFor(t, UserSchema), patchRemove, nil); err == nil || !errors.Is(err, ErrMutability) {
		t.Fatalf("bare remove error = %v", err)
	}
	if err := applyUserPath(user, pathFor(t, UserSchema), patchReplace, map[string]any{"title": "T"}); err != nil || user.Title != "T" {
		t.Fatalf("bare replace = %+v, %v", user, err)
	}
	if err := applyUserPath(user, pathFor(t, EnterpriseUserSchema), patchReplace, map[string]any{"department": "D"}); err != nil || user.EnterpriseUser == nil || user.EnterpriseUser.Department != "D" {
		t.Fatalf("bare enterprise replace = %+v, %v", user, err)
	}
	if err := applyUserPath(user, pathFor(t, "urn:example:unknown:2.0:User"), patchReplace, "x"); err == nil || !errors.Is(err, ErrInvalidPath) {
		t.Fatalf("unknown user schema error = %v", err)
	}
	if err := applyUserPath(user, pathFor(t, "userName.sub"), patchReplace, "x"); err == nil || !errors.Is(err, ErrInvalidPath) {
		t.Fatalf("userName sub error = %v", err)
	}
	if err := applyUserPath(user, pathFor(t, "active.sub"), patchReplace, true); err == nil || !errors.Is(err, ErrInvalidPath) {
		t.Fatalf("active sub error = %v", err)
	}
	if err := applyUserPath(user, pathFor(t, "active"), patchReplace, "maybe"); err == nil || !errors.Is(err, ErrInvalidValue) {
		t.Fatalf("active invalid error = %v", err)
	}
	if err := applyUserPath(user, pathFor(t, "active"), patchRemove, nil); err != nil || user.Active != nil {
		t.Fatalf("active remove = %+v, %v", user.Active, err)
	}
	if err := applyUserPath(user, pathFor(t, "unknown"), patchReplace, "x"); err == nil || !errors.Is(err, ErrInvalidPath) {
		t.Fatalf("unknown attribute error = %v", err)
	}
	if err := applyUserPath(user, pathFor(t, "externalId.sub"), patchReplace, "x"); err == nil || !errors.Is(err, ErrInvalidPath) {
		t.Fatalf("simple field sub error = %v", err)
	}
	if err := applyUserPath(user, pathFor(t, "externalId"), patchReplace, true); err == nil || !errors.Is(err, ErrInvalidValue) {
		t.Fatalf("simple field non-string error = %v", err)
	}
}

// TestPatchNameBranches verifies every User name PATCH branch. | TestPatchNameBranches 校验每个
// User name PATCH 分支。
func TestPatchNameBranches(t *testing.T) {
	user := &User{}
	if err := patchName(user, pathFor(t, "name"), patchRemove, nil); err == nil || !errors.Is(err, ErrNoTarget) {
		t.Fatalf("remove absent error = %v", err)
	}
	if err := patchName(user, pathFor(t, "name"), patchAdd, map[string]any{"givenName": "Alice"}); err != nil || user.Name == nil || user.Name.GivenName != "Alice" {
		t.Fatalf("add absent = %+v, %v", user.Name, err)
	}
	if err := patchName(user, pathFor(t, "name"), patchAdd, map[string]any{"familyName": "Liddell"}); err != nil || user.Name.FamilyName != "Liddell" {
		t.Fatalf("add merge = %+v, %v", user.Name, err)
	}
	if err := patchName(user, pathFor(t, "name"), patchAdd, "not-an-object"); err == nil || !errors.Is(err, ErrInvalidValue) {
		t.Fatalf("add invalid object error = %v", err)
	}
	if err := patchName(user, pathFor(t, "name"), patchReplace, map[string]any{"formatted": "Alice Liddell"}); err != nil {
		t.Fatalf("replace: %v", err)
	}
	if user.Name.GivenName != "" || user.Name.Formatted != "Alice Liddell" {
		t.Fatalf("replace = %+v", user.Name)
	}
	if err := patchName(user, pathFor(t, "name"), patchReplace, "not-an-object"); err == nil || !errors.Is(err, ErrInvalidValue) {
		t.Fatalf("replace invalid error = %v", err)
	}
	if err := patchName(user, pathFor(t, "name"), patchReplace, nil); err != nil || user.Name != nil {
		t.Fatalf("replace nil = %+v, %v", user.Name, err)
	}
	if err := patchName(user, pathFor(t, "name.givenName"), patchRemove, nil); err == nil || !errors.Is(err, ErrNoTarget) {
		t.Fatalf("sub remove absent error = %v", err)
	}
	if err := patchName(user, pathFor(t, "name.givenName"), patchAdd, "Alice"); err != nil || user.Name == nil || user.Name.GivenName != "Alice" {
		t.Fatalf("sub add = %+v, %v", user.Name, err)
	}
	if err := patchName(user, pathFor(t, "name.givenName"), patchRemove, nil); err != nil || user.Name.GivenName != "" {
		t.Fatalf("sub remove = %+v, %v", user.Name, err)
	}
	if err := patchName(user, pathFor(t, "name.unknown"), patchReplace, "x"); err == nil || !errors.Is(err, ErrInvalidPath) {
		t.Fatalf("unknown sub error = %v", err)
	}
	if err := patchName(user, pathFor(t, "name.givenName"), patchReplace, true); err == nil || !errors.Is(err, ErrInvalidValue) {
		t.Fatalf("non-string sub error = %v", err)
	}
}

// TestPatchManagerBranches verifies every enterprise manager PATCH branch. |
// TestPatchManagerBranches 校验每个企业 manager PATCH 分支。
func TestPatchManagerBranches(t *testing.T) {
	user := &User{EnterpriseUser: &EnterpriseUser{}}
	manager := &user.EnterpriseUser.Manager
	if err := patchManager(manager, pathFor(t, "manager"), patchRemove, nil); err == nil || !errors.Is(err, ErrNoTarget) {
		t.Fatalf("remove absent error = %v", err)
	}
	if err := patchManager(manager, pathFor(t, "manager"), patchAdd, map[string]any{"value": "m1", "displayName": "Manager"}); err != nil || *manager == nil || (*manager).Value != "m1" {
		t.Fatalf("add = %+v, %v", *manager, err)
	}
	if err := patchManager(manager, pathFor(t, "manager"), patchAdd, map[string]any{"$ref": "r"}); err != nil || (*manager).Ref != "r" {
		t.Fatalf("add merge = %+v, %v", *manager, err)
	}
	if err := patchManager(manager, pathFor(t, "manager"), patchAdd, "not-an-object"); err == nil || !errors.Is(err, ErrInvalidValue) {
		t.Fatalf("add invalid error = %v", err)
	}
	if err := patchManager(manager, pathFor(t, "manager"), patchReplace, map[string]any{"value": "m2"}); err != nil || (*manager).Value != "m2" || (*manager).Ref != "" {
		t.Fatalf("replace = %+v, %v", *manager, err)
	}
	if err := patchManager(manager, pathFor(t, "manager"), patchReplace, "not-an-object"); err == nil || !errors.Is(err, ErrInvalidValue) {
		t.Fatalf("replace invalid error = %v", err)
	}
	if err := patchManager(manager, pathFor(t, "manager"), patchReplace, nil); err != nil || *manager != nil {
		t.Fatalf("replace nil = %+v, %v", *manager, err)
	}
	if err := patchManager(manager, pathFor(t, "manager.value"), patchRemove, nil); err == nil || !errors.Is(err, ErrNoTarget) {
		t.Fatalf("sub remove absent error = %v", err)
	}
	if err := patchManager(manager, pathFor(t, "manager.value"), patchAdd, "m3"); err != nil || *manager == nil || (*manager).Value != "m3" {
		t.Fatalf("sub add = %+v, %v", *manager, err)
	}
	if err := patchManager(manager, pathFor(t, "manager.displayName"), patchReplace, "D"); err != nil || (*manager).DisplayName != "D" {
		t.Fatalf("sub replace = %+v, %v", *manager, err)
	}
	if err := patchManager(manager, pathFor(t, "manager.displayName"), patchRemove, nil); err != nil || (*manager).DisplayName != "" {
		t.Fatalf("sub remove = %+v, %v", *manager, err)
	}
	if err := patchManager(manager, pathFor(t, "manager.unknown"), patchReplace, "x"); err == nil || !errors.Is(err, ErrInvalidPath) {
		t.Fatalf("unknown sub error = %v", err)
	}
}

// TestEnterprisePatchBranches verifies enterprise extension PATCH dispatch. |
// TestEnterprisePatchBranches 校验企业扩展 PATCH 分发。
func TestEnterprisePatchBranches(t *testing.T) {
	user := &User{}
	enterprisePath := pathFor(t, EnterpriseUserSchema)
	if err := applyEnterprisePath(user, enterprisePath, patchRemove, nil); err == nil || !errors.Is(err, ErrNoTarget) {
		t.Fatalf("pathless remove absent error = %v", err)
	}
	if err := applyEnterprisePath(user, enterprisePath, patchReplace, nil); err != nil || user.EnterpriseUser != nil {
		t.Fatalf("pathless replace nil = %+v, %v", user.EnterpriseUser, err)
	}
	if err := applyEnterprisePath(user, enterprisePath, patchReplace, map[string]any{"employeeNumber": "E1", "manager": map[string]any{"value": "m1"}}); err != nil {
		t.Fatalf("pathless replace: %v", err)
	}
	if user.EnterpriseUser == nil || user.EnterpriseUser.EmployeeNumber != "E1" || user.EnterpriseUser.Manager == nil || user.EnterpriseUser.Manager.Value != "m1" {
		t.Fatalf("pathless replace = %+v", user.EnterpriseUser)
	}
	if err := applyEnterprisePath(user, enterprisePath, patchReplace, "not-an-object"); err == nil || !errors.Is(err, ErrInvalidValue) {
		t.Fatalf("pathless replace invalid error = %v", err)
	}
	if err := applyEnterprisePath(user, enterprisePath, patchAdd, map[string]any{"costCenter": "C1", "division": "D1"}); err != nil || user.EnterpriseUser.CostCenter != "C1" || user.EnterpriseUser.Division != "D1" {
		t.Fatalf("pathless add = %+v, %v", user.EnterpriseUser, err)
	}
	if err := applyEnterprisePath(user, enterprisePath, patchAdd, "not-an-object"); err == nil || !errors.Is(err, ErrInvalidValue) {
		t.Fatalf("pathless add invalid error = %v", err)
	}
	if err := applyEnterprisePath(user, enterprisePath, patchAdd, map[string]any{"unknown": "x"}); err == nil || !errors.Is(err, ErrInvalidPath) {
		t.Fatalf("pathless add unknown error = %v", err)
	}
	if err := applyEnterprisePath(user, enterprisePath, patchRemove, nil); err != nil || user.EnterpriseUser != nil {
		t.Fatalf("pathless remove = %+v, %v", user.EnterpriseUser, err)
	}

	user = &User{}
	absent := pathFor(t, EnterpriseUserSchema+":department")
	if err := applyEnterprisePath(user, absent, patchRemove, nil); err == nil || !errors.Is(err, ErrNoTarget) {
		t.Fatalf("sub remove absent error = %v", err)
	}
	if err := applyEnterprisePath(user, absent, patchReplace, "D"); err != nil || user.EnterpriseUser == nil || user.EnterpriseUser.Department != "D" {
		t.Fatalf("sub replace absent = %+v, %v", user.EnterpriseUser, err)
	}
	fields := map[string]*string{
		"employeeNumber": &user.EnterpriseUser.EmployeeNumber,
		"costCenter":     &user.EnterpriseUser.CostCenter,
		"organization":   &user.EnterpriseUser.Organization,
		"division":       &user.EnterpriseUser.Division,
		"department":     &user.EnterpriseUser.Department,
	}
	for name, dst := range fields {
		path := pathFor(t, EnterpriseUserSchema+":"+name)
		if err := applyEnterprisePath(user, path, patchReplace, name); err != nil || *dst != name {
			t.Fatalf("%s replace = %q, %v", name, *dst, err)
		}
		if err := applyEnterprisePath(user, path, patchRemove, nil); err != nil || *dst != "" {
			t.Fatalf("%s remove = %q, %v", name, *dst, err)
		}
	}
	managerPath := pathFor(t, EnterpriseUserSchema+":manager")
	if err := applyEnterprisePath(user, managerPath, patchReplace, map[string]any{"value": "m"}); err != nil || user.EnterpriseUser.Manager == nil {
		t.Fatalf("manager replace = %+v, %v", user.EnterpriseUser, err)
	}
	if err := applyEnterprisePath(user, managerPath, patchRemove, nil); err != nil || user.EnterpriseUser.Manager != nil {
		t.Fatalf("manager remove = %+v, %v", user.EnterpriseUser, err)
	}
	if err := applyEnterprisePath(user, pathFor(t, EnterpriseUserSchema+":unknown"), patchReplace, "x"); err == nil || !errors.Is(err, ErrInvalidPath) {
		t.Fatalf("unknown enterprise attribute error = %v", err)
	}
	pruneEnterpriseUser(user)
	if user.EnterpriseUser != nil {
		t.Fatalf("empty enterprise not pruned: %+v", user.EnterpriseUser)
	}
	user.EnterpriseUser = &EnterpriseUser{Department: "D"}
	pruneEnterpriseUser(user)
	if user.EnterpriseUser == nil {
		t.Fatalf("non-empty enterprise pruned")
	}
	if err := patchActive(user, pathFor(t, "active"), patchReplace, true); err != nil || !user.ActiveValue() {
		t.Fatalf("active set = %+v, %v", user.Active, err)
	}
	if err := patchActive(user, pathFor(t, "active"), patchAdd, nil); err != nil || user.Active != nil {
		t.Fatalf("active nil = %+v, %v", user.Active, err)
	}
}
