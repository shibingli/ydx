package rbac_test

import (
	"errors"
	"testing"
	"time"

	authrbac "github.com/shibingli/ydx/auth/authz/rbac"
)

// TestAssignmentLifecycle covers creation, duplicate rules, scope separation, reads and removal.
// | TestAssignmentLifecycle 覆盖创建、重复规则、作用域隔离、读取与删除。
func TestAssignmentLifecycle(t *testing.T) {
	store, _ := newStore(t, "")
	for _, name := range []string{"viewer", "editor"} {
		if err := store.AddRole(testContext, authrbac.Role{Name: name}); err != nil {
			t.Fatalf("add role %q: %v | 添加角色失败", name, err)
		}
	}
	deadline := testTime(2030, time.January, 2, 3, 4, 5)
	assignment := authrbac.Assignment{
		Subject:    "alice",
		Role:       "viewer",
		Scope:      "tenant:1",
		Conditions: map[string]string{"subject.department": "eng"},
		ExpiresAt:  deadline,
	}
	if err := store.Assign(testContext, assignment); err != nil {
		t.Fatalf("assign: %v | 分配角色失败", err)
	}
	if err := store.Assign(testContext, authrbac.Assignment{Subject: "alice", Role: "editor"}); err != nil {
		t.Fatalf("assign editor: %v | 分配编辑角色失败", err)
	}
	if err := store.Assign(testContext, authrbac.Assignment{Subject: "alice", Role: "viewer", Scope: "tenant:2"}); err != nil {
		t.Fatalf("assign second scope: %v | 分配第二作用域失败", err)
	}
	if err := store.Assign(testContext, assignment); !errors.Is(err, authrbac.ErrAssignmentExists) {
		t.Fatalf("duplicate assignment error = %v | 重复分配错误不符", err)
	}

	assignments, err := store.Assignments(testContext, "alice")
	if err != nil {
		t.Fatalf("assignments: %v | 列出主体分配失败", err)
	}
	if len(assignments) != 3 {
		t.Fatalf("assignments = %+v | 主体分配数量不符", assignments)
	}
	if assignments[0].Role != "editor" || assignments[0].Subject != "alice" {
		t.Fatalf("first assignment = %+v | 分配排序不符", assignments[0])
	}
	if assignments[1].Scope != "tenant:1" || assignments[2].Scope != "tenant:2" {
		t.Fatalf("scope ordering = %+v | 作用域排序不符", assignments)
	}
	viewer := assignments[1]
	if viewer.Conditions["subject.department"] != "eng" {
		t.Fatalf("conditions = %v | 分配条件未持久化", viewer.Conditions)
	}
	if !viewer.ExpiresAt.Equal(deadline) {
		t.Fatalf("expiresAt = %v, want %v | 分配期限不符", viewer.ExpiresAt, deadline)
	}
	if viewer.CreatedAt.IsZero() || viewer.CreatedAt.Location() != time.UTC {
		t.Fatalf("createdAt = %v | 创建时间未填充为 UTC", viewer.CreatedAt)
	}

	if err := store.Unassign(testContext, "alice", "viewer", "tenant:1"); err != nil {
		t.Fatalf("unassign: %v | 解除分配失败", err)
	}
	if err := store.Unassign(testContext, "alice", "viewer", "tenant:1"); !errors.Is(err, authrbac.ErrAssignmentNotFound) {
		t.Fatalf("double unassign error = %v | 重复解除分配错误不符", err)
	}
	if err := store.Unassign(testContext, "alice", "viewer", "tenant:missing"); !errors.Is(err, authrbac.ErrAssignmentNotFound) {
		t.Fatalf("wrong scope unassign error = %v | 错误作用域解除错误不符", err)
	}
	if err := store.Assign(testContext, authrbac.Assignment{Subject: "alice", Role: "missing"}); !errors.Is(err, authrbac.ErrRoleNotFound) {
		t.Fatalf("unknown role assignment error = %v | 未知角色分配错误不符", err)
	}
	for _, invalid := range []authrbac.Assignment{
		{Subject: "", Role: "viewer"},
		{Subject: "  ", Role: "viewer"},
		{Subject: "alice", Role: ""},
		{Subject: "alice", Role: "viewer", Conditions: map[string]string{"": "x"}},
	} {
		if err := store.Assign(testContext, invalid); !errors.Is(err, authrbac.ErrInvalidAssignment) {
			t.Fatalf("invalid assignment %+v error = %v | 非法分配错误不符", invalid, err)
		}
	}
	if err := store.Unassign(testContext, "", "viewer", ""); !errors.Is(err, authrbac.ErrInvalidAssignment) {
		t.Fatalf("empty unassign error = %v | 空解除分配错误不符", err)
	}

	if err := store.Assign(testContext, authrbac.Assignment{Subject: "bob", Role: "viewer"}); err != nil {
		t.Fatalf("assign bob: %v | 分配 bob 失败", err)
	}
	all, err := store.ListAssignments(testContext)
	if err != nil {
		t.Fatalf("list assignments: %v | 列出全部分配失败", err)
	}
	if len(all) != 3 {
		t.Fatalf("all assignments = %+v | 全部分配数量不符", all)
	}
	if all[0].Subject != "alice" || all[1].Subject != "alice" || all[2].Subject != "bob" {
		t.Fatalf("assignment ordering = %+v | 全部分配排序不符", all)
	}
}

// TestAssignmentExpiry covers expiry comparison, replacement and UTC normalization.
// | TestAssignmentExpiry 覆盖过期比较、替换与 UTC 规范化。
func TestAssignmentExpiry(t *testing.T) {
	store, _ := newStore(t, "")
	if err := store.AddRole(testContext, authrbac.Role{Name: "viewer"}); err != nil {
		t.Fatalf("add role: %v | 添加角色失败", err)
	}

	now := time.Now().UTC()
	if err := store.Assign(testContext, authrbac.Assignment{
		Subject: "alice", Role: "viewer", ExpiresAt: now.Add(-time.Hour),
	}); err != nil {
		t.Fatalf("assign expired: %v | 分配过期角色失败", err)
	}
	if err := store.Assign(testContext, authrbac.Assignment{Subject: "alice", Role: "viewer"}); err != nil {
		t.Fatalf("replace expired assignment: %v | 替换过期分配失败", err)
	}
	if err := store.Assign(testContext, authrbac.Assignment{Subject: "alice", Role: "viewer"}); !errors.Is(err, authrbac.ErrAssignmentExists) {
		t.Fatalf("duplicate non-expiring error = %v | 无期限重复错误不符", err)
	}
	if err := store.Assign(testContext, authrbac.Assignment{
		Subject: "alice", Role: "viewer", ExpiresAt: now.Add(time.Hour),
	}); !errors.Is(err, authrbac.ErrAssignmentExists) {
		t.Fatalf("duplicate before replacement error = %v | 未到期重复错误不符", err)
	}

	if err := store.Assign(testContext, authrbac.Assignment{
		Subject: "bob", Role: "viewer", ExpiresAt: now.Add(-time.Nanosecond),
	}); err != nil {
		t.Fatalf("assign nanosecond-expired: %v | 分配纳秒过期项失败", err)
	}
	if err := store.Assign(testContext, authrbac.Assignment{
		Subject: "bob", Role: "viewer", ExpiresAt: now.Add(time.Hour),
	}); err != nil {
		t.Fatalf("replace nanosecond-expired: %v | 替换纳秒过期项失败", err)
	}
	if err := store.Assign(testContext, authrbac.Assignment{
		Subject: "bob", Role: "viewer", ExpiresAt: now.Add(-time.Hour),
	}); !errors.Is(err, authrbac.ErrAssignmentExists) {
		t.Fatalf("duplicate future assignment error = %v | 未到期分配重复错误不符", err)
	}

	if err := store.Assign(testContext, authrbac.Assignment{
		Subject: "carol", Role: "viewer", ExpiresAt: now.Add(-time.Hour),
	}); err != nil {
		t.Fatalf("assign expired carol: %v | 分配过期 carol 失败", err)
	}
	expired, err := store.Assignments(testContext, "carol")
	if err != nil {
		t.Fatalf("assignments carol: %v | 列出 carol 分配失败", err)
	}
	if len(expired) != 1 {
		t.Fatalf("expired assignments = %+v | 过期分配应仍被列出", expired)
	}

	zone := time.FixedZone("CST", 8*60*60)
	deadline := time.Date(2031, time.March, 4, 5, 6, 7, 123456789, zone)
	created := time.Date(2030, time.March, 4, 5, 6, 7, 987654321, zone)
	if err := store.Assign(testContext, authrbac.Assignment{
		Subject: "dave", Role: "viewer", ExpiresAt: deadline, CreatedAt: created,
	}); err != nil {
		t.Fatalf("assign zoned times: %v | 分配带时区时间失败", err)
	}
	zoned, err := store.Assignments(testContext, "dave")
	if err != nil {
		t.Fatalf("assignments dave: %v | 列出 dave 分配失败", err)
	}
	if len(zoned) != 1 {
		t.Fatalf("zoned assignments = %+v | 带时区分配数量不符", zoned)
	}
	if zoned[0].ExpiresAt.Location() != time.UTC || zoned[0].CreatedAt.Location() != time.UTC {
		t.Fatalf("times not normalized to UTC: %+v | 时间未规范化为 UTC", zoned[0])
	}
	if !zoned[0].ExpiresAt.Equal(deadline) || !zoned[0].CreatedAt.Equal(created) {
		t.Fatalf("time instants changed: %+v | 时间点被改变", zoned[0])
	}
}

// TestAssignmentDeepCopy proves that conditions maps never alias caller or stored values.
// | TestAssignmentDeepCopy 证明条件映射从不与调用方或存储值共享。
func TestAssignmentDeepCopy(t *testing.T) {
	store, _ := newStore(t, "")
	if err := store.AddRole(testContext, authrbac.Role{Name: "viewer"}); err != nil {
		t.Fatalf("add role: %v | 添加角色失败", err)
	}
	assignment := authrbac.Assignment{
		Subject:    "alice",
		Role:       "viewer",
		Conditions: map[string]string{"subject.department": "eng"},
	}
	if err := store.Assign(testContext, assignment); err != nil {
		t.Fatalf("assign: %v | 分配角色失败", err)
	}
	assignment.Conditions["subject.department"] = "mutated"

	assignments, err := store.Assignments(testContext, "alice")
	if err != nil {
		t.Fatalf("assignments: %v | 列出分配失败", err)
	}
	if len(assignments) != 1 || assignments[0].Conditions["subject.department"] != "eng" {
		t.Fatalf("stored assignment aliased caller input: %+v | 存储分配别名了调用方输入", assignments)
	}
	assignments[0].Conditions["subject.department"] = "mutated"
	again, err := store.Assignments(testContext, "alice")
	if err != nil {
		t.Fatalf("assignments again: %v | 再次列出分配失败", err)
	}
	if again[0].Conditions["subject.department"] != "eng" {
		t.Fatalf("Assignments aliased stored value: %+v | Assignments 别名了存储值", again)
	}
	all, err := store.ListAssignments(testContext)
	if err != nil {
		t.Fatalf("list assignments: %v | 列出全部分配失败", err)
	}
	all[0].Conditions["subject.department"] = "mutated"
	again, err = store.Assignments(testContext, "alice")
	if err != nil {
		t.Fatalf("assignments after list: %v | 列表后列出分配失败", err)
	}
	if again[0].Conditions["subject.department"] != "eng" {
		t.Fatalf("ListAssignments aliased stored value: %+v | ListAssignments 别名了存储值", again)
	}
}

// TestAssignmentCrossInstance covers visibility, uniqueness and removal between instances.
// | TestAssignmentCrossInstance 覆盖实例之间的可见性、唯一性与删除。
func TestAssignmentCrossInstance(t *testing.T) {
	first, second := newPair(t)
	if err := first.AddRole(testContext, authrbac.Role{Name: "viewer"}); err != nil {
		t.Fatalf("add role: %v | 添加角色失败", err)
	}
	if err := first.Assign(testContext, authrbac.Assignment{Subject: "alice", Role: "viewer", Scope: "tenant:1"}); err != nil {
		t.Fatalf("first assign: %v | 第一实例分配失败", err)
	}
	assignments, err := second.Assignments(testContext, "alice")
	if err != nil {
		t.Fatalf("second assignments: %v | 第二实例列出分配失败", err)
	}
	if len(assignments) != 1 || assignments[0].Scope != "tenant:1" {
		t.Fatalf("second assignments = %+v | 第二实例分配不符", assignments)
	}
	if err := second.Assign(testContext, authrbac.Assignment{Subject: "alice", Role: "viewer", Scope: "tenant:1"}); !errors.Is(err, authrbac.ErrAssignmentExists) {
		t.Fatalf("cross-instance duplicate error = %v | 跨实例重复分配错误不符", err)
	}
	if err := second.Unassign(testContext, "alice", "viewer", "tenant:1"); err != nil {
		t.Fatalf("second unassign: %v | 第二实例解除分配失败", err)
	}
	assignments, err = first.Assignments(testContext, "alice")
	if err != nil {
		t.Fatalf("first assignments after unassign: %v | 解除后第一实例列出失败", err)
	}
	if len(assignments) != 0 {
		t.Fatalf("assignments after unassign = %+v | 解除后分配残留", assignments)
	}
}

// TestAssignmentIdentifierUniqueness proves length prefixes keep similar identifiers apart.
// | TestAssignmentIdentifierUniqueness 证明长度前缀使相似标识互不冲突。
func TestAssignmentIdentifierUniqueness(t *testing.T) {
	store, _ := newStore(t, "")
	for _, name := range []string{"c", "bc", "viewer:global"} {
		if err := store.AddRole(testContext, authrbac.Role{Name: name}); err != nil {
			t.Fatalf("add role %q: %v | 添加角色失败", name, err)
		}
	}
	if err := store.Assign(testContext, authrbac.Assignment{Subject: "ab", Role: "c"}); err != nil {
		t.Fatalf("assign ab/c: %v | 分配 ab/c 失败", err)
	}
	if err := store.Assign(testContext, authrbac.Assignment{Subject: "a", Role: "bc"}); err != nil {
		t.Fatalf("assign a/bc: %v | 分配 a/bc 失败", err)
	}
	if err := store.Assign(testContext, authrbac.Assignment{Subject: "a:1", Role: "viewer:global", Scope: "tenant:1:blue"}); err != nil {
		t.Fatalf("assign colon identifiers: %v | 分配含冒号标识失败", err)
	}
	ab, err := store.Assignments(testContext, "ab")
	if err != nil {
		t.Fatalf("assignments ab: %v", err)
	}
	if len(ab) != 1 || ab[0].Role != "c" {
		t.Fatalf("assignments ab = %+v | 相似标识串扰", ab)
	}
	a, err := store.Assignments(testContext, "a")
	if err != nil {
		t.Fatalf("assignments a: %v", err)
	}
	if len(a) != 1 || a[0].Role != "bc" {
		t.Fatalf("assignments a = %+v | 相似标识串扰", a)
	}
	colon, err := store.Assignments(testContext, "a:1")
	if err != nil {
		t.Fatalf("assignments a:1: %v", err)
	}
	if len(colon) != 1 || colon[0].Scope != "tenant:1:blue" {
		t.Fatalf("assignments a:1 = %+v | 含冒号标识不符", colon)
	}
	if err := store.Unassign(testContext, "ab", "c", ""); err != nil {
		t.Fatalf("unassign ab/c: %v | 解除 ab/c 失败", err)
	}
	if _, err := store.Assignments(testContext, "ab"); err != nil {
		t.Fatalf("assignments ab after unassign: %v", err)
	}
	remaining, err := store.ListAssignments(testContext)
	if err != nil {
		t.Fatalf("list assignments: %v", err)
	}
	if len(remaining) != 2 {
		t.Fatalf("remaining assignments = %+v | 剩余分配数量不符", remaining)
	}
}
