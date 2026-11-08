package rbac_test

import (
	"errors"
	"strconv"
	"sync"
	"testing"
	"time"

	authrbac "github.com/shibingli/ydx/auth/authz/rbac"
	rbacstore "github.com/shibingli/ydx/authstore/rbac"
)

// concurrentWorkers bounds every concurrency scenario in this file.
// | concurrentWorkers 限定本文件每个并发场景的工作协程数。
const concurrentWorkers = 16

// runConcurrently invokes work once per worker through alternating stores and checks each error.
// | runConcurrently 通过交替的存储为每个工作协程调用 work，并校验每个错误。
func runConcurrently(t *testing.T, first, second *rbacstore.Store, work func(store *rbacstore.Store) error, allowed ...error) []error {
	t.Helper()
	results := make([]error, concurrentWorkers)
	var wg sync.WaitGroup
	wg.Add(concurrentWorkers)
	for index := 0; index < concurrentWorkers; index++ {
		go func(index int) {
			defer wg.Done()
			store := first
			if index%2 == 1 {
				store = second
			}
			results[index] = work(store)
		}(index)
	}
	wg.Wait()
	for index, err := range results {
		if err == nil {
			continue
		}
		matched := false
		for _, want := range allowed {
			if errors.Is(err, want) {
				matched = true
				break
			}
		}
		if !matched {
			t.Fatalf("worker %d error = %v | 工作协程 %d 错误不符", index, err, index)
		}
	}
	return results
}

// countSuccess reports how many results are nil. | countSuccess 统计 nil 结果的数量。
func countSuccess(results []error) int {
	successes := 0
	for _, err := range results {
		if err == nil {
			successes++
		}
	}
	return successes
}

// TestConcurrentRoleUniqueness proves only one instance can create a role name.
// | TestConcurrentRoleUniqueness 证明只有一个实例能创建同一角色名。
func TestConcurrentRoleUniqueness(t *testing.T) {
	first, second := newPair(t)
	results := runConcurrently(t, first, second, func(store *rbacstore.Store) error {
		return store.AddRole(testContext, authrbac.Role{Name: "viewer", Permissions: []string{"post:read"}})
	}, authrbac.ErrRoleExists)
	if got := countSuccess(results); got != 1 {
		t.Fatalf("successful role creates = %d, want 1 | 成功创建角色数应为 1", got)
	}
	roles, err := first.ListRoles(testContext)
	if err != nil {
		t.Fatalf("list roles: %v | 列出角色失败", err)
	}
	if len(roles) != 1 || roles[0].Name != "viewer" {
		t.Fatalf("roles = %+v | 并发创建后角色不符", roles)
	}
}

// TestConcurrentAssignmentUniqueness proves only one instance can create an active assignment.
// | TestConcurrentAssignmentUniqueness 证明只有一个实例能创建有效分配。
func TestConcurrentAssignmentUniqueness(t *testing.T) {
	first, second := newPair(t)
	if err := first.AddRole(testContext, authrbac.Role{Name: "viewer"}); err != nil {
		t.Fatalf("add role: %v | 添加角色失败", err)
	}
	results := runConcurrently(t, first, second, func(store *rbacstore.Store) error {
		return store.Assign(testContext, authrbac.Assignment{
			Subject: "alice", Role: "viewer", Scope: "tenant:1",
		})
	}, authrbac.ErrAssignmentExists)
	if got := countSuccess(results); got != 1 {
		t.Fatalf("successful assignments = %d, want 1 | 成功分配数应为 1", got)
	}
	assignments, err := second.Assignments(testContext, "alice")
	if err != nil {
		t.Fatalf("assignments: %v | 列出分配失败", err)
	}
	if len(assignments) != 1 || assignments[0].Scope != "tenant:1" {
		t.Fatalf("assignments = %+v | 并发分配后记录不符", assignments)
	}
}

// TestConcurrentPolicyUniqueness proves only one instance can create a policy identifier.
// | TestConcurrentPolicyUniqueness 证明只有一个实例能创建同一策略标识。
func TestConcurrentPolicyUniqueness(t *testing.T) {
	first, second := newPair(t)
	results := runConcurrently(t, first, second, func(store *rbacstore.Store) error {
		return store.AddPolicy(testContext, authrbac.Policy{ID: "allow", Effect: authrbac.EffectPermit})
	}, authrbac.ErrPolicyExists)
	if got := countSuccess(results); got != 1 {
		t.Fatalf("successful policy creates = %d, want 1 | 成功创建策略数应为 1", got)
	}
	policies, err := second.ListPolicies(testContext)
	if err != nil {
		t.Fatalf("list policies: %v | 列出策略失败", err)
	}
	if len(policies) != 1 || policies[0].ID != "allow" {
		t.Fatalf("policies = %+v | 并发创建后策略不符", policies)
	}
}

// TestConcurrentDistinctAssignments proves independent assignments all persist.
// | TestConcurrentDistinctAssignments 证明互不相同的并发分配全部持久化。
func TestConcurrentDistinctAssignments(t *testing.T) {
	first, second := newPair(t)
	if err := first.AddRole(testContext, authrbac.Role{Name: "viewer"}); err != nil {
		t.Fatalf("add role: %v | 添加角色失败", err)
	}
	subjects := make([]string, concurrentWorkers)
	for index := range subjects {
		subjects[index] = "subject-" + strconv.Itoa(index)
	}
	// Each worker uses its own subject, so runConcurrently cannot express this scenario.
	results := make([]error, concurrentWorkers)
	var wg sync.WaitGroup
	wg.Add(concurrentWorkers)
	for index := 0; index < concurrentWorkers; index++ {
		go func(index int) {
			defer wg.Done()
			store := first
			if index%2 == 1 {
				store = second
			}
			results[index] = store.Assign(testContext, authrbac.Assignment{Subject: subjects[index], Role: "viewer"})
		}(index)
	}
	wg.Wait()
	for index, err := range results {
		if err != nil {
			t.Fatalf("worker %d assign error = %v | 工作协程 %d 分配错误", index, err, index)
		}
	}
	all, err := first.ListAssignments(testContext)
	if err != nil {
		t.Fatalf("list assignments: %v | 列出分配失败", err)
	}
	if len(all) != concurrentWorkers {
		t.Fatalf("assignments = %d, want %d | 并发分配数量不符", len(all), concurrentWorkers)
	}
	for _, subject := range subjects {
		owned, err := second.Assignments(testContext, subject)
		if err != nil {
			t.Fatalf("assignments %q: %v | 列出主体分配失败", subject, err)
		}
		if len(owned) != 1 || owned[0].Role != "viewer" {
			t.Fatalf("assignments %q = %+v | 主体分配不符", subject, owned)
		}
	}
}

// TestConcurrentExpiredReplacement proves an expired duplicate is replaced exactly once.
// | TestConcurrentExpiredReplacement 证明过期重复项只被替换一次。
func TestConcurrentExpiredReplacement(t *testing.T) {
	first, second := newPair(t)
	if err := first.AddRole(testContext, authrbac.Role{Name: "viewer"}); err != nil {
		t.Fatalf("add role: %v | 添加角色失败", err)
	}
	if err := first.Assign(testContext, authrbac.Assignment{
		Subject: "alice", Role: "viewer", ExpiresAt: time.Now().UTC().Add(-time.Hour),
	}); err != nil {
		t.Fatalf("seed expired assignment: %v | 写入过期分配失败", err)
	}
	results := runConcurrently(t, first, second, func(store *rbacstore.Store) error {
		return store.Assign(testContext, authrbac.Assignment{Subject: "alice", Role: "viewer"})
	}, authrbac.ErrAssignmentExists)
	if got := countSuccess(results); got != 1 {
		t.Fatalf("successful replacements = %d, want 1 | 成功替换数应为 1", got)
	}
	assignments, err := second.Assignments(testContext, "alice")
	if err != nil {
		t.Fatalf("assignments: %v | 列出分配失败", err)
	}
	if len(assignments) != 1 {
		t.Fatalf("assignments = %+v | 替换后分配数量不符", assignments)
	}
	if !assignments[0].ExpiresAt.IsZero() {
		t.Fatalf("expiresAt = %v, want zero | 替换后期限应为零", assignments[0].ExpiresAt)
	}
}

// TestConcurrentRoleRemoveAndAssign proves a removed role never keeps assignments.
// | TestConcurrentRoleRemoveAndAssign 证明被删除角色不会保留分配。
func TestConcurrentRoleRemoveAndAssign(t *testing.T) {
	first, second := newPair(t)
	if err := first.AddRole(testContext, authrbac.Role{Name: "base"}); err != nil {
		t.Fatalf("add role: %v | 添加角色失败", err)
	}
	if err := first.Assign(testContext, authrbac.Assignment{Subject: "alice", Role: "base"}); err != nil {
		t.Fatalf("seed assignment: %v | 写入初始分配失败", err)
	}
	var wg sync.WaitGroup
	wg.Add(concurrentWorkers)
	results := make([]error, concurrentWorkers)
	for index := 0; index < concurrentWorkers; index++ {
		go func(index int) {
			defer wg.Done()
			store := first
			if index%2 == 1 {
				store = second
			}
			if index%3 == 0 {
				results[index] = store.RemoveRole(testContext, "base")
				return
			}
			results[index] = store.Assign(testContext, authrbac.Assignment{
				Subject: "subject-" + strconv.Itoa(index), Role: "base",
			})
		}(index)
	}
	wg.Wait()
	for index, err := range results {
		if err == nil {
			continue
		}
		if !errors.Is(err, authrbac.ErrRoleNotFound) {
			t.Fatalf("worker %d error = %v | 工作协程 %d 错误不符", index, err, index)
		}
	}
	if _, err := first.GetRole(testContext, "base"); !errors.Is(err, authrbac.ErrRoleNotFound) {
		t.Fatalf("role after concurrent removal error = %v | 并发删除后角色仍存在", err)
	}
	assignments, err := first.ListAssignments(testContext)
	if err != nil {
		t.Fatalf("list assignments: %v | 列出分配失败", err)
	}
	if len(assignments) != 0 {
		t.Fatalf("assignments after concurrent removal = %+v | 删除角色后分配残留", assignments)
	}
}
