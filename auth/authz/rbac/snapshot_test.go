package rbac

import (
	"context"
	"errors"
	"strings"
	"testing"
	"time"
)

func TestSnapshotJSONRoundTrip(t *testing.T) {
	ctx := context.Background()
	expires := time.Date(2031, 5, 1, 0, 0, 0, 0, time.UTC)
	engine := New()
	mustAddRole(t, engine, Role{
		Name:        "editor",
		Permissions: []string{"post:read", "post:write"},
		Metadata:    map[string]string{"team": "eng"},
	})
	mustAssign(t, engine, Assignment{
		Subject:    "alice",
		Role:       "editor",
		Scope:      "tenant:1",
		Conditions: map[string]string{"subject.department": "eng"},
		ExpiresAt:  expires,
		CreatedAt:  time.Date(2030, 1, 1, 0, 0, 0, 0, time.UTC),
	})
	mustAddPolicy(t, engine, Policy{
		ID:       "office",
		Effect:   EffectPermit,
		Subject:  "user:*",
		Action:   "post:*",
		Scope:    "tenant:*",
		Priority: 3,
		Conditions: []Condition{
			{Key: "env.ip", Operator: OperatorEquals, Value: "10.0.0.1"},
		},
	})

	data, err := engine.MarshalSnapshot(ctx)
	if err != nil {
		t.Fatalf("MarshalSnapshot: %v", err)
	}
	if !strings.Contains(string(data), `"version":1`) {
		t.Fatalf("snapshot JSON missing version: %s", data)
	}
	if !strings.Contains(string(data), `"expiresAt"`) {
		t.Fatalf("snapshot JSON missing expiresAt: %s", data)
	}

	restored := New()
	if err := restored.UnmarshalSnapshot(ctx, data); err != nil {
		t.Fatalf("UnmarshalSnapshot: %v", err)
	}
	role, err := restored.GetRole(ctx, "editor")
	if err != nil {
		t.Fatalf("restored GetRole: %v", err)
	}
	if role.Metadata["team"] != "eng" {
		t.Fatalf("restored role metadata = %v", role.Metadata)
	}
	policy, err := restored.GetPolicy(ctx, "office")
	if err != nil {
		t.Fatalf("restored GetPolicy: %v", err)
	}
	if policy.Priority != 3 || len(policy.Conditions) != 1 {
		t.Fatalf("restored policy = %+v", policy)
	}
	assignments, err := restored.Assignments(ctx, "alice")
	if err != nil {
		t.Fatalf("restored Assignments: %v", err)
	}
	if len(assignments) != 1 || !assignments[0].ExpiresAt.Equal(expires) {
		t.Fatalf("restored assignments = %+v", assignments)
	}

	request := Request{
		Subject:     "alice",
		Action:      "post:write",
		Scope:       "tenant:1",
		Attributes:  map[string]string{"department": "eng"},
		Environment: map[string]string{"ip": "10.0.0.1"},
	}
	decision, err := restored.Authorize(ctx, request)
	if err != nil {
		t.Fatalf("restored Authorize: %v", err)
	}
	if !decision.Allowed {
		t.Fatalf("restored engine denied: %s", decision.Reason)
	}
}

func TestSnapshotVersionAndInvalidData(t *testing.T) {
	ctx := context.Background()
	engine := New()
	mustAddRole(t, engine, Role{Name: "keep", Permissions: []string{"post:read"}})

	if err := engine.LoadSnapshot(ctx, Snapshot{Version: SnapshotVersion + 1}); !errors.Is(err, ErrUnsupportedVersion) {
		t.Fatalf("version error = %v", err)
	}
	if err := engine.UnmarshalSnapshot(ctx, []byte("{")); !errors.Is(err, ErrInvalidSnapshot) {
		t.Fatalf("invalid JSON error = %v", err)
	}

	invalid := Snapshot{
		Version: SnapshotVersion,
		Roles: []Role{
			{Name: "a", Parents: []string{"b"}},
			{Name: "b", Parents: []string{"a"}},
		},
	}
	if err := engine.LoadSnapshot(ctx, invalid); !errors.Is(err, ErrInvalidSnapshot) || !errors.Is(err, ErrRoleCycle) {
		t.Fatalf("cycle snapshot error = %v", err)
	}
	if _, err := engine.GetRole(ctx, "keep"); err != nil {
		t.Fatalf("failed load mutated engine: %v", err)
	}
	if _, err := engine.GetRole(ctx, "a"); !errors.Is(err, ErrRoleNotFound) {
		t.Fatalf("invalid snapshot partially loaded: %v", err)
	}

	missingRole := Snapshot{
		Version:     SnapshotVersion,
		Assignments: []Assignment{{Subject: "alice", Role: "missing"}},
	}
	if err := engine.LoadSnapshot(ctx, missingRole); !errors.Is(err, ErrInvalidSnapshot) || !errors.Is(err, ErrRoleNotFound) {
		t.Fatalf("missing role snapshot error = %v", err)
	}
	if _, err := engine.GetRole(ctx, "keep"); err != nil {
		t.Fatalf("failed load mutated engine: %v", err)
	}
}

func TestLoadSnapshotReplacesState(t *testing.T) {
	ctx := context.Background()
	engine := New()
	mustAddRole(t, engine, Role{Name: "old", Permissions: []string{"old:read"}})
	mustAssign(t, engine, Assignment{Subject: "alice", Role: "old"})

	replacement := Snapshot{
		Version: SnapshotVersion,
		Roles:   []Role{{Name: "new", Permissions: []string{"new:read"}}},
		Assignments: []Assignment{{
			Subject: "alice",
			Role:    "new",
		}},
	}
	if err := engine.LoadSnapshot(ctx, replacement); err != nil {
		t.Fatalf("LoadSnapshot: %v", err)
	}
	if _, err := engine.GetRole(ctx, "old"); !errors.Is(err, ErrRoleNotFound) {
		t.Fatalf("old role survived replacement: %v", err)
	}
	decision := authorize(t, engine, Request{Subject: "alice", Action: "new:read"})
	if !decision.Allowed {
		t.Fatalf("replacement state denied: %s", decision.Reason)
	}
	if decision := authorize(t, engine, Request{Subject: "alice", Action: "old:read"}); decision.Allowed {
		t.Fatal("old permission survived replacement")
	}
}

func TestSnapshotDeepCopy(t *testing.T) {
	ctx := context.Background()
	engine := New()
	mustAddRole(t, engine, Role{Name: "viewer", Permissions: []string{"post:read"}, Metadata: map[string]string{"team": "eng"}})

	snapshot, err := engine.Snapshot(ctx)
	if err != nil {
		t.Fatalf("Snapshot: %v", err)
	}
	snapshot.Roles[0].Permissions[0] = "mutated"
	snapshot.Roles[0].Metadata["team"] = "mutated"

	roles, err := engine.Roles(ctx)
	if err != nil {
		t.Fatalf("Roles: %v", err)
	}
	if roles[0].Permissions[0] != "post:read" || roles[0].Metadata["team"] != "eng" {
		t.Fatalf("Snapshot aliased engine state: %+v", roles[0])
	}
}
