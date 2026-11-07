package rbac

import (
	"context"
	"errors"
	"strconv"
	"sync"
	"testing"
	"time"
)

func TestMemoryStoreDuplicateAndCycleErrors(t *testing.T) {
	ctx := context.Background()
	store := NewMemoryStore()

	if err := store.AddRole(ctx, Role{Name: "a", Parents: []string{"b"}}); err != nil {
		t.Fatalf("AddRole a: %v", err)
	}
	if err := store.AddRole(ctx, Role{Name: "a"}); !errors.Is(err, ErrRoleExists) {
		t.Fatalf("duplicate role error = %v", err)
	}
	if err := store.AddRole(ctx, Role{Name: "b", Parents: []string{"a"}}); !errors.Is(err, ErrRoleCycle) {
		t.Fatalf("cycle error = %v", err)
	}
	if err := store.AddRole(ctx, Role{Name: "self", Parents: []string{"self"}}); !errors.Is(err, ErrRoleCycle) {
		t.Fatalf("self cycle error = %v", err)
	}
	if err := store.AddRole(ctx, Role{Name: " "}); !errors.Is(err, ErrInvalidRole) {
		t.Fatalf("empty role error = %v", err)
	}
	if err := store.AddRole(ctx, Role{Name: "empty-perm", Permissions: []string{""}}); !errors.Is(err, ErrInvalidRole) {
		t.Fatalf("empty permission error = %v", err)
	}

	if err := store.AddPolicy(ctx, Policy{ID: "p", Effect: EffectPermit}); err != nil {
		t.Fatalf("AddPolicy: %v", err)
	}
	if err := store.AddPolicy(ctx, Policy{ID: "p", Effect: EffectDeny}); !errors.Is(err, ErrPolicyExists) {
		t.Fatalf("duplicate policy error = %v", err)
	}
	if err := store.AddPolicy(ctx, Policy{ID: "bad", Effect: "maybe"}); !errors.Is(err, ErrInvalidPolicy) {
		t.Fatalf("invalid effect error = %v", err)
	}
	if err := store.AddPolicy(ctx, Policy{ID: "bad-condition", Effect: EffectPermit, Conditions: []Condition{{Operator: OperatorEquals}}}); !errors.Is(err, ErrInvalidCondition) || !errors.Is(err, ErrInvalidPolicy) {
		t.Fatalf("invalid condition error = %v", err)
	}
	if _, err := store.GetPolicy(ctx, "missing"); !errors.Is(err, ErrPolicyNotFound) {
		t.Fatalf("missing policy error = %v", err)
	}

	if err := store.Assign(ctx, Assignment{Subject: "alice", Role: "missing"}); !errors.Is(err, ErrRoleNotFound) {
		t.Fatalf("unknown role assignment error = %v", err)
	}
	if err := store.Assign(ctx, Assignment{Subject: "", Role: "a"}); !errors.Is(err, ErrInvalidAssignment) {
		t.Fatalf("empty subject error = %v", err)
	}
	if err := store.Assign(ctx, Assignment{Subject: "alice", Role: "a", Conditions: map[string]string{"": "x"}}); !errors.Is(err, ErrInvalidAssignment) {
		t.Fatalf("empty condition key error = %v", err)
	}
	if err := store.Assign(ctx, Assignment{Subject: "alice", Role: "a"}); err != nil {
		t.Fatalf("Assign: %v", err)
	}
	if err := store.Assign(ctx, Assignment{Subject: "alice", Role: "a"}); !errors.Is(err, ErrAssignmentExists) {
		t.Fatalf("duplicate assignment error = %v", err)
	}
	if err := store.Unassign(ctx, "alice", "missing", ""); !errors.Is(err, ErrAssignmentNotFound) {
		t.Fatalf("missing assignment error = %v", err)
	}
	if err := store.Unassign(ctx, "alice", "a", ""); err != nil {
		t.Fatalf("Unassign: %v", err)
	}

	expired := Assignment{Subject: "bob", Role: "a", ExpiresAt: time.Now().UTC().Add(-time.Hour)}
	if err := store.Assign(ctx, expired); err != nil {
		t.Fatalf("Assign expired: %v", err)
	}
	if err := store.Assign(ctx, Assignment{Subject: "bob", Role: "a"}); err != nil {
		t.Fatalf("expired assignment should be replaceable: %v", err)
	}
	if err := store.Assign(ctx, Assignment{Subject: "bob", Role: "a"}); !errors.Is(err, ErrAssignmentExists) {
		t.Fatalf("active duplicate after replacement error = %v", err)
	}

	if err := store.AddRole(ctx, Role{Name: "child", Parents: []string{"a"}}); err != nil {
		t.Fatalf("AddRole child: %v", err)
	}
	if err := store.RemoveRole(ctx, "a"); err != nil {
		t.Fatalf("RemoveRole: %v", err)
	}
	if _, err := store.GetRole(ctx, "a"); !errors.Is(err, ErrRoleNotFound) {
		t.Fatalf("removed role error = %v", err)
	}
	child, err := store.GetRole(ctx, "child")
	if err != nil {
		t.Fatalf("GetRole child: %v", err)
	}
	if len(child.Parents) != 0 {
		t.Fatalf("child parents = %v, want none", child.Parents)
	}
	assignments, err := store.Assignments(ctx, "bob")
	if err != nil {
		t.Fatalf("Assignments bob: %v", err)
	}
	if len(assignments) != 0 {
		t.Fatalf("assignments for removed role = %v", assignments)
	}
	if err := store.RemoveRole(ctx, "a"); !errors.Is(err, ErrRoleNotFound) {
		t.Fatalf("double remove error = %v", err)
	}
	if err := store.RemovePolicy(ctx, "missing"); !errors.Is(err, ErrPolicyNotFound) {
		t.Fatalf("missing remove policy error = %v", err)
	}
}

func TestMemoryStoreDeepCopies(t *testing.T) {
	ctx := context.Background()
	store := NewMemoryStore()

	role := Role{
		Name:        "viewer",
		Permissions: []string{"post:read"},
		Parents:     []string{"base"},
		Metadata:    map[string]string{"team": "eng"},
	}
	if err := store.AddRole(ctx, role); err != nil {
		t.Fatalf("AddRole: %v", err)
	}
	role.Permissions[0] = "mutated"
	role.Parents[0] = "mutated"
	role.Metadata["team"] = "mutated"

	stored, err := store.GetRole(ctx, "viewer")
	if err != nil {
		t.Fatalf("GetRole: %v", err)
	}
	if stored.Permissions[0] != "post:read" || stored.Parents[0] != "base" || stored.Metadata["team"] != "eng" {
		t.Fatalf("stored role aliased caller input: %+v", stored)
	}
	stored.Permissions[0] = "mutated"
	stored.Metadata["team"] = "mutated"
	again, err := store.GetRole(ctx, "viewer")
	if err != nil {
		t.Fatalf("GetRole again: %v", err)
	}
	if again.Permissions[0] != "post:read" || again.Metadata["team"] != "eng" {
		t.Fatalf("GetRole aliased stored value: %+v", again)
	}

	roles, err := store.ListRoles(ctx)
	if err != nil {
		t.Fatalf("ListRoles: %v", err)
	}
	roles[0].Metadata["team"] = "mutated"
	again, err = store.GetRole(ctx, "viewer")
	if err != nil {
		t.Fatalf("GetRole after ListRoles: %v", err)
	}
	if again.Metadata["team"] != "eng" {
		t.Fatalf("ListRoles aliased stored value: %+v", again)
	}

	policy := Policy{ID: "p", Effect: EffectPermit, Conditions: []Condition{{Key: "subject", Operator: OperatorEquals, Value: "alice"}}}
	if err := store.AddPolicy(ctx, policy); err != nil {
		t.Fatalf("AddPolicy: %v", err)
	}
	policy.Conditions[0].Value = "mutated"
	storedPolicy, err := store.GetPolicy(ctx, "p")
	if err != nil {
		t.Fatalf("GetPolicy: %v", err)
	}
	if storedPolicy.Conditions[0].Value != "alice" {
		t.Fatalf("stored policy aliased caller input: %+v", storedPolicy)
	}
	storedPolicy.Conditions[0].Value = "mutated"
	storedPolicy, err = store.GetPolicy(ctx, "p")
	if err != nil {
		t.Fatalf("GetPolicy again: %v", err)
	}
	if storedPolicy.Conditions[0].Value != "alice" {
		t.Fatalf("GetPolicy aliased stored value: %+v", storedPolicy)
	}

	assignment := Assignment{Subject: "alice", Role: "viewer", Conditions: map[string]string{"subject.department": "eng"}}
	if err := store.Assign(ctx, assignment); err != nil {
		t.Fatalf("Assign: %v", err)
	}
	assignment.Conditions["subject.department"] = "mutated"
	assignments, err := store.Assignments(ctx, "alice")
	if err != nil {
		t.Fatalf("Assignments: %v", err)
	}
	if len(assignments) != 1 || assignments[0].Conditions["subject.department"] != "eng" {
		t.Fatalf("stored assignment aliased caller input: %+v", assignments)
	}
	assignments[0].Conditions["subject.department"] = "mutated"
	assignments, err = store.Assignments(ctx, "alice")
	if err != nil {
		t.Fatalf("Assignments again: %v", err)
	}
	if assignments[0].Conditions["subject.department"] != "eng" {
		t.Fatalf("Assignments aliased stored value: %+v", assignments)
	}
}

func TestMemoryStoreZeroValueAndReset(t *testing.T) {
	var store MemoryStore
	ctx := context.Background()
	if err := store.AddRole(ctx, Role{Name: "viewer", Permissions: []string{"post:read"}}); err != nil {
		t.Fatalf("zero value AddRole: %v", err)
	}
	if err := store.AddPolicy(ctx, Policy{ID: "p", Effect: EffectPermit}); err != nil {
		t.Fatalf("zero value AddPolicy: %v", err)
	}
	if err := store.Assign(ctx, Assignment{Subject: "alice", Role: "viewer"}); err != nil {
		t.Fatalf("zero value Assign: %v", err)
	}
	if err := store.Reset(ctx); err != nil {
		t.Fatalf("Reset: %v", err)
	}
	roles, err := store.ListRoles(ctx)
	if err != nil {
		t.Fatalf("ListRoles after reset: %v", err)
	}
	if len(roles) != 0 {
		t.Fatalf("roles after reset = %v", roles)
	}
	policies, err := store.ListPolicies(ctx)
	if err != nil {
		t.Fatalf("ListPolicies after reset: %v", err)
	}
	if len(policies) != 0 {
		t.Fatalf("policies after reset = %v", policies)
	}
	assignments, err := store.ListAssignments(ctx)
	if err != nil {
		t.Fatalf("ListAssignments after reset: %v", err)
	}
	if len(assignments) != 0 {
		t.Fatalf("assignments after reset = %v", assignments)
	}
}

func TestMemoryStoreConcurrentAccess(t *testing.T) {
	ctx := context.Background()
	engine := New()
	mustAddRole(t, engine, Role{Name: "viewer", Permissions: []string{"post:read"}})
	mustAddPolicy(t, engine, Policy{ID: "allow", Effect: EffectPermit, Action: "post:*"})

	const workers = 16
	var wait sync.WaitGroup
	for worker := 0; worker < workers; worker++ {
		subject := "user-" + strconv.Itoa(worker)
		wait.Add(1)
		go func() {
			defer wait.Done()
			for iteration := 0; iteration < 25; iteration++ {
				_ = engine.Assign(ctx, Assignment{Subject: subject, Role: "viewer", Scope: "tenant:1"})
				_, _ = engine.Authorize(ctx, Request{Subject: subject, Action: "post:read", Scope: "tenant:1"})
				_, _ = engine.Permissions(ctx, subject, "tenant:1")
				_ = engine.Unassign(ctx, subject, "viewer", "tenant:1")
			}
		}()
	}
	wait.Wait()
}
