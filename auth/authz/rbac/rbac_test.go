package rbac

import (
	"context"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/shibingli/ydx/auth"
)

// mustAddRole adds role or fails the test. | mustAddRole 添加角色，失败时终止测试。
func mustAddRole(t *testing.T, engine *Engine, role Role) {
	t.Helper()
	if err := engine.AddRole(context.Background(), role); err != nil {
		t.Fatalf("AddRole(%q): %v", role.Name, err)
	}
}

// mustAssign adds an assignment or fails the test. | mustAssign 添加分配，失败时终止测试。
func mustAssign(t *testing.T, engine *Engine, assignment Assignment) {
	t.Helper()
	if err := engine.Assign(context.Background(), assignment); err != nil {
		t.Fatalf("Assign(%q, %q): %v", assignment.Subject, assignment.Role, err)
	}
}

// mustAddPolicy adds a policy or fails the test. | mustAddPolicy 添加策略，失败时终止测试。
func mustAddPolicy(t *testing.T, engine *Engine, policy Policy) {
	t.Helper()
	if err := engine.AddPolicy(context.Background(), policy); err != nil {
		t.Fatalf("AddPolicy(%q): %v", policy.ID, err)
	}
}

// authorize runs one authorization call or fails the test. | authorize 执行一次授权调用，失败时终止测试。
func authorize(t *testing.T, engine *Engine, request Request) Decision {
	t.Helper()
	decision, err := engine.Authorize(context.Background(), request)
	if err != nil {
		t.Fatalf("Authorize(%+v): %v", request, err)
	}
	return decision
}

func TestRoleInheritance(t *testing.T) {
	engine := New()
	mustAddRole(t, engine, Role{Name: "viewer", Permissions: []string{"post:read"}})
	mustAddRole(t, engine, Role{Name: "editor", Permissions: []string{"post:write"}, Parents: []string{"viewer"}})
	mustAddRole(t, engine, Role{Name: "admin", Permissions: []string{"post:delete"}, Parents: []string{"editor"}})
	mustAssign(t, engine, Assignment{Subject: "alice", Role: "admin"})

	decision := authorize(t, engine, Request{Subject: "alice", Action: "post:read"})
	if !decision.Allowed {
		t.Fatalf("inherited permission denied: %s", decision.Reason)
	}
	if got, want := strings.Join(decision.MatchedRoles, ","), "admin,editor,viewer"; got != want {
		t.Fatalf("matched roles = %q want %q", got, want)
	}

	permissions, err := engine.Permissions(context.Background(), "alice", "")
	if err != nil {
		t.Fatalf("Permissions: %v", err)
	}
	if got, want := strings.Join(permissions, ","), "post:delete,post:read,post:write"; got != want {
		t.Fatalf("permissions = %q want %q", got, want)
	}

	denied := authorize(t, engine, Request{Subject: "bob", Action: "post:read"})
	if denied.Allowed {
		t.Fatal("unknown subject should be denied")
	}
}

func TestRolePermissionWildcard(t *testing.T) {
	engine := New()
	mustAddRole(t, engine, Role{Name: "author", Permissions: []string{"post:*"}})
	mustAssign(t, engine, Assignment{Subject: "alice", Role: "author"})

	if decision := authorize(t, engine, Request{Subject: "alice", Action: "post:read"}); !decision.Allowed {
		t.Fatalf("post:* should grant post:read: %s", decision.Reason)
	}
	if decision := authorize(t, engine, Request{Subject: "alice", Action: "user:read"}); decision.Allowed {
		t.Fatal("post:* must not grant user:read")
	}
}

func TestGlobMatching(t *testing.T) {
	cases := []struct {
		name    string
		pattern string
		value   string
		want    bool
	}{
		{name: "star matches empty", pattern: "*", value: "", want: true},
		{name: "star matches value", pattern: "*", value: "anything", want: true},
		{name: "namespace wildcard", pattern: "user:*", value: "user:read", want: true},
		{name: "namespace wildcard needs colon", pattern: "user:*", value: "user", want: false},
		{name: "namespace wildcard rejects other prefix", pattern: "user:*", value: "users:read", want: false},
		{name: "path wildcard", pattern: "/api/*", value: "/api/posts", want: true},
		{name: "path wildcard rejects other path", pattern: "/api/*", value: "/other", want: false},
		{name: "exact match", pattern: "post:read", value: "post:read", want: true},
		{name: "exact mismatch", pattern: "post:read", value: "Post:read", want: false},
		{name: "empty matches empty", pattern: "", value: "", want: true},
		{name: "empty rejects value", pattern: "", value: "x", want: false},
	}
	for _, testCase := range cases {
		t.Run(testCase.name, func(t *testing.T) {
			if got := globMatch(testCase.pattern, testCase.value); got != testCase.want {
				t.Fatalf("globMatch(%q, %q) = %v want %v", testCase.pattern, testCase.value, got, testCase.want)
			}
		})
	}
}

func TestPolicyGlobsAndRoleSubjects(t *testing.T) {
	engine := New()
	mustAddPolicy(t, engine, Policy{
		ID:       "api-read",
		Effect:   EffectPermit,
		Subject:  "user:*",
		Resource: "/api/*",
		Action:   "read:*",
	})
	mustAddPolicy(t, engine, Policy{
		ID:      "editor-write",
		Effect:  EffectPermit,
		Subject: "editor",
		Action:  "post:write",
	})

	decision := authorize(t, engine, Request{
		Subject:  "user:42",
		Action:   "read:post",
		Resource: "/api/posts",
	})
	if !decision.Allowed {
		t.Fatalf("subject/resource/action globs did not match: %s", decision.Reason)
	}
	if got, want := strings.Join(decision.MatchedPolicies, ","), "api-read"; got != want {
		t.Fatalf("matched policies = %q want %q", got, want)
	}

	wrongResource := authorize(t, engine, Request{
		Subject:  "user:42",
		Action:   "read:post",
		Resource: "/other",
	})
	if wrongResource.Allowed {
		t.Fatal("resource glob should not match /other")
	}

	roleSubject := authorize(t, engine, Request{
		Subject: "alice",
		Roles:   []string{"editor"},
		Action:  "post:write",
	})
	if !roleSubject.Allowed {
		t.Fatalf("role subject pattern did not match: %s", roleSubject.Reason)
	}
	if got, want := strings.Join(roleSubject.MatchedRoles, ","), "editor"; got != want {
		t.Fatalf("matched roles = %q want %q", got, want)
	}
}

func TestDenyOverrides(t *testing.T) {
	engine := New()
	mustAddRole(t, engine, Role{Name: "writer", Permissions: []string{"post:write"}})
	mustAssign(t, engine, Assignment{Subject: "alice", Role: "writer"})
	mustAddPolicy(t, engine, Policy{ID: "allow-posts", Effect: EffectPermit, Subject: "*", Action: "post:*"})
	mustAddPolicy(t, engine, Policy{ID: "deny-delete", Effect: EffectDeny, Subject: "alice", Action: "post:delete", Priority: 10})

	denied := authorize(t, engine, Request{Subject: "alice", Action: "post:delete"})
	if denied.Allowed {
		t.Fatal("deny policy must override the role permission")
	}
	if !strings.Contains(denied.Reason, "deny-delete") {
		t.Fatalf("reason = %q, want mention of deny-delete", denied.Reason)
	}
	if got, want := strings.Join(denied.MatchedPolicies, ","), "allow-posts,deny-delete"; got != want {
		t.Fatalf("matched policies = %q want %q", got, want)
	}

	allowed := authorize(t, engine, Request{Subject: "alice", Action: "post:write"})
	if !allowed.Allowed {
		t.Fatalf("permit should win without a deny: %s", allowed.Reason)
	}
}

func TestCombiningAlgorithms(t *testing.T) {
	permit := Policy{ID: "permit", Effect: EffectPermit, Subject: "*", Action: "post:*"}
	deny := Policy{ID: "deny", Effect: EffectDeny, Subject: "*", Action: "post:*"}

	cases := []struct {
		name      string
		algorithm CombiningAlgorithm
		policies  []Policy
		want      bool
		wantErr   error
	}{
		{name: "deny overrides", algorithm: DenyOverrides, policies: []Policy{permit, deny}, want: false},
		{name: "permit overrides", algorithm: PermitOverrides, policies: []Policy{deny, permit}, want: true},
		{name: "first applicable permit", algorithm: FirstApplicable, policies: []Policy{
			{ID: "permit", Effect: EffectPermit, Subject: "*", Action: "post:*", Priority: 10},
			{ID: "deny", Effect: EffectDeny, Subject: "*", Action: "post:*", Priority: 5},
		}, want: true},
		{name: "first applicable deny", algorithm: FirstApplicable, policies: []Policy{
			{ID: "deny", Effect: EffectDeny, Subject: "*", Action: "post:*", Priority: 10},
			{ID: "permit", Effect: EffectPermit, Subject: "*", Action: "post:*", Priority: 5},
		}, want: false},
		{name: "only one permits", algorithm: OnlyOneApplicable, policies: []Policy{permit}, want: true},
		{name: "only one denies", algorithm: OnlyOneApplicable, policies: []Policy{deny}, want: false},
		{name: "only one conflict", algorithm: OnlyOneApplicable, policies: []Policy{permit, deny}, want: false, wantErr: ErrMultiplePolicies},
		{name: "first applicable no match", algorithm: FirstApplicable, want: false},
	}
	for _, testCase := range cases {
		t.Run(testCase.name, func(t *testing.T) {
			engine := New(WithCombiningAlgorithm(testCase.algorithm))
			for _, policy := range testCase.policies {
				mustAddPolicy(t, engine, policy)
			}
			decision, err := engine.Authorize(context.Background(), Request{Subject: "alice", Action: "post:read"})
			if testCase.wantErr != nil {
				if !errors.Is(err, testCase.wantErr) {
					t.Fatalf("error = %v want %v", err, testCase.wantErr)
				}
				if decision.Allowed {
					t.Fatal("conflict must deny")
				}
				return
			}
			if err != nil {
				t.Fatalf("Authorize: %v", err)
			}
			if decision.Allowed != testCase.want {
				t.Fatalf("allowed = %v want %v (reason %q)", decision.Allowed, testCase.want, decision.Reason)
			}
		})
	}
}

func TestOnlyOneApplicableFallsBackToRoles(t *testing.T) {
	engine := New(WithCombiningAlgorithm(OnlyOneApplicable))
	mustAddRole(t, engine, Role{Name: "viewer", Permissions: []string{"post:read"}})
	mustAssign(t, engine, Assignment{Subject: "alice", Role: "viewer"})

	if decision := authorize(t, engine, Request{Subject: "alice", Action: "post:read"}); !decision.Allowed {
		t.Fatalf("role fallback denied: %s", decision.Reason)
	}
}

func TestScopes(t *testing.T) {
	engine := New()
	mustAddRole(t, engine, Role{Name: "viewer", Permissions: []string{"post:read"}})
	mustAddRole(t, engine, Role{Name: "editor", Permissions: []string{"post:write"}, Parents: []string{"viewer"}})
	mustAddRole(t, engine, Role{Name: "scoped", Permissions: []string{"doc:read"}, Scope: "org:*"})

	mustAssign(t, engine, Assignment{Subject: "alice", Role: "viewer", Scope: "tenant:1"})
	mustAssign(t, engine, Assignment{Subject: "alice", Role: "editor", Scope: "tenant:2"})
	mustAssign(t, engine, Assignment{Subject: "bob", Role: "viewer", Scope: "tenant:*"})
	mustAssign(t, engine, Assignment{Subject: "carol", Role: "scoped"})

	cases := []struct {
		name    string
		request Request
		want    bool
	}{
		{name: "exact scope read", request: Request{Subject: "alice", Action: "post:read", Scope: "tenant:1"}, want: true},
		{name: "exact scope write denied", request: Request{Subject: "alice", Action: "post:write", Scope: "tenant:1"}, want: false},
		{name: "other scope write", request: Request{Subject: "alice", Action: "post:write", Scope: "tenant:2"}, want: true},
		{name: "other scope inherited read", request: Request{Subject: "alice", Action: "post:read", Scope: "tenant:2"}, want: true},
		{name: "unknown scope denied", request: Request{Subject: "alice", Action: "post:read", Scope: "tenant:3"}, want: false},
		{name: "empty scope denied", request: Request{Subject: "alice", Action: "post:read"}, want: false},
		{name: "wildcard assignment", request: Request{Subject: "bob", Action: "post:read", Scope: "tenant:9"}, want: true},
		{name: "wildcard assignment global denied", request: Request{Subject: "bob", Action: "post:read"}, want: false},
		{name: "role scope matches", request: Request{Subject: "carol", Action: "doc:read", Scope: "org:1"}, want: true},
		{name: "role scope mismatch", request: Request{Subject: "carol", Action: "doc:read", Scope: "tenant:1"}, want: false},
		{name: "role scope empty request", request: Request{Subject: "carol", Action: "doc:read"}, want: false},
		{name: "direct role scope mismatch", request: Request{Subject: "dave", Roles: []string{"scoped"}, Action: "doc:read", Scope: "tenant:1"}, want: false},
	}
	for _, testCase := range cases {
		t.Run(testCase.name, func(t *testing.T) {
			decision := authorize(t, engine, testCase.request)
			if decision.Allowed != testCase.want {
				t.Fatalf("allowed = %v want %v (reason %q)", decision.Allowed, testCase.want, decision.Reason)
			}
		})
	}

	permissions, err := engine.Permissions(context.Background(), "alice", "tenant:1")
	if err != nil {
		t.Fatalf("Permissions tenant:1: %v", err)
	}
	if got, want := strings.Join(permissions, ","), "post:read"; got != want {
		t.Fatalf("tenant:1 permissions = %q want %q", got, want)
	}
	permissions, err = engine.Permissions(context.Background(), "alice", "tenant:2")
	if err != nil {
		t.Fatalf("Permissions tenant:2: %v", err)
	}
	if got, want := strings.Join(permissions, ","), "post:read,post:write"; got != want {
		t.Fatalf("tenant:2 permissions = %q want %q", got, want)
	}
	permissions, err = engine.Permissions(context.Background(), "alice", "")
	if err != nil {
		t.Fatalf("Permissions all: %v", err)
	}
	if got, want := strings.Join(permissions, ","), "post:read,post:write"; got != want {
		t.Fatalf("all permissions = %q want %q", got, want)
	}
}

func TestAssignmentConditions(t *testing.T) {
	engine := New()
	mustAddRole(t, engine, Role{Name: "viewer", Permissions: []string{"doc:read"}})
	mustAssign(t, engine, Assignment{
		Subject:    "alice",
		Role:       "viewer",
		Conditions: map[string]string{"subject.department": "eng"},
	})
	mustAssign(t, engine, Assignment{
		Subject:    "bob",
		Role:       "viewer",
		Conditions: map[string]string{"env.ip": "10.0.0.1"},
	})
	mustAssign(t, engine, Assignment{
		Subject:    "carol",
		Role:       "viewer",
		Conditions: map[string]string{"resource.owner": "carol"},
	})

	cases := []struct {
		name    string
		request Request
		want    bool
	}{
		{
			name:    "subject attribute matches",
			request: Request{Subject: "alice", Action: "doc:read", Attributes: map[string]string{"department": "eng"}},
			want:    true,
		},
		{
			name:    "subject attribute mismatch",
			request: Request{Subject: "alice", Action: "doc:read", Attributes: map[string]string{"department": "sales"}},
			want:    false,
		},
		{
			name:    "subject attribute missing",
			request: Request{Subject: "alice", Action: "doc:read"},
			want:    false,
		},
		{
			name:    "environment matches",
			request: Request{Subject: "bob", Action: "doc:read", Environment: map[string]string{"ip": "10.0.0.1"}},
			want:    true,
		},
		{
			name:    "environment mismatch",
			request: Request{Subject: "bob", Action: "doc:read", Environment: map[string]string{"ip": "10.0.0.2"}},
			want:    false,
		},
		{
			name:    "exact dotted attribute",
			request: Request{Subject: "carol", Action: "doc:read", Attributes: map[string]string{"resource.owner": "carol"}},
			want:    true,
		},
		{
			name:    "stripped dotted attribute",
			request: Request{Subject: "carol", Action: "doc:read", Attributes: map[string]string{"owner": "carol"}},
			want:    true,
		},
		{
			name:    "other owner",
			request: Request{Subject: "carol", Action: "doc:read", Attributes: map[string]string{"resource.owner": "dave"}},
			want:    false,
		},
	}
	for _, testCase := range cases {
		t.Run(testCase.name, func(t *testing.T) {
			decision := authorize(t, engine, testCase.request)
			if decision.Allowed != testCase.want {
				t.Fatalf("allowed = %v want %v (reason %q)", decision.Allowed, testCase.want, decision.Reason)
			}
		})
	}
}

func TestAssignmentExpiration(t *testing.T) {
	now := time.Date(2030, 1, 1, 12, 0, 0, 0, time.UTC)
	engine := New(WithClock(func() time.Time { return now }))
	mustAddRole(t, engine, Role{Name: "viewer", Permissions: []string{"doc:read"}})
	mustAssign(t, engine, Assignment{Subject: "alice", Role: "viewer", ExpiresAt: now.Add(time.Hour)})
	mustAssign(t, engine, Assignment{Subject: "bob", Role: "viewer", ExpiresAt: now})
	mustAssign(t, engine, Assignment{Subject: "carol", Role: "viewer", ExpiresAt: now.Add(-time.Hour)})
	mustAssign(t, engine, Assignment{Subject: "dave", Role: "viewer"})

	cases := []struct {
		subject string
		want    bool
	}{
		{subject: "alice", want: true},
		{subject: "bob", want: false},
		{subject: "carol", want: false},
		{subject: "dave", want: true},
	}
	for _, testCase := range cases {
		decision := authorize(t, engine, Request{Subject: testCase.subject, Action: "doc:read"})
		if decision.Allowed != testCase.want {
			t.Fatalf("%s allowed = %v want %v", testCase.subject, decision.Allowed, testCase.want)
		}
	}

	permissions, err := engine.Permissions(context.Background(), "carol", "")
	if err != nil {
		t.Fatalf("Permissions: %v", err)
	}
	if len(permissions) != 0 {
		t.Fatalf("expired assignment returned permissions %v", permissions)
	}
}

func TestPolicyConditionsIntegration(t *testing.T) {
	engine := New()
	mustAddPolicy(t, engine, Policy{
		ID:     "office-read",
		Effect: EffectPermit,
		Action: "doc:read",
		Conditions: []Condition{
			{Key: "env.ip", Operator: OperatorEquals, Value: "10.0.0.1"},
			{Key: "subject.department", Operator: OperatorIn, Value: "eng, ops"},
		},
	})

	allowed := authorize(t, engine, Request{
		Subject:     "alice",
		Action:      "doc:read",
		Attributes:  map[string]string{"department": "eng"},
		Environment: map[string]string{"ip": "10.0.0.1"},
	})
	if !allowed.Allowed {
		t.Fatalf("conditions should match: %s", allowed.Reason)
	}

	denied := authorize(t, engine, Request{
		Subject:     "alice",
		Action:      "doc:read",
		Attributes:  map[string]string{"department": "eng"},
		Environment: map[string]string{"ip": "10.0.0.2"},
	})
	if denied.Allowed {
		t.Fatal("environment mismatch should deny")
	}

	if err := engine.AddPolicy(context.Background(), Policy{ID: "bad", Effect: EffectPermit, Conditions: []Condition{{Key: "x", Operator: "bogus"}}}); !errors.Is(err, ErrInvalidCondition) || !errors.Is(err, ErrInvalidPolicy) {
		t.Fatalf("invalid condition error = %v", err)
	}
	if err := engine.AddPolicy(context.Background(), Policy{ID: "bad-effect", Effect: "maybe"}); !errors.Is(err, ErrInvalidPolicy) {
		t.Fatalf("invalid effect error = %v", err)
	}
}

func TestAuthorizeInputAndAlgorithmErrors(t *testing.T) {
	engine := New()
	if _, err := engine.Authorize(context.Background(), Request{Action: "post:read"}); !errors.Is(err, ErrInvalidRequest) {
		t.Fatalf("empty subject error = %v", err)
	}
	if _, err := engine.Authorize(context.Background(), Request{Subject: "alice"}); !errors.Is(err, ErrInvalidRequest) {
		t.Fatalf("empty action error = %v", err)
	}
	if _, err := engine.Permissions(context.Background(), "", ""); !errors.Is(err, ErrInvalidRequest) {
		t.Fatalf("empty permissions subject error = %v", err)
	}

	bad := New(WithCombiningAlgorithm(CombiningAlgorithm("bogus")))
	if _, err := bad.Authorize(context.Background(), Request{Subject: "alice", Action: "post:read"}); !errors.Is(err, ErrInvalidAlgorithm) {
		t.Fatalf("invalid algorithm error = %v", err)
	}
}

func TestAuthorizeCanceledContext(t *testing.T) {
	engine := New()
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err := engine.Authorize(ctx, Request{Subject: "alice", Action: "post:read"}); !errors.Is(err, ErrCanceled) {
		t.Fatalf("canceled context error = %v", err)
	}
	if _, err := engine.Permissions(ctx, "alice", ""); !errors.Is(err, ErrCanceled) {
		t.Fatalf("canceled permissions error = %v", err)
	}
}

func TestDecisionReasonAndRoleGrant(t *testing.T) {
	engine := New()
	mustAddRole(t, engine, Role{Name: "viewer", Permissions: []string{"post:read"}})
	mustAssign(t, engine, Assignment{Subject: "alice", Role: "viewer"})
	decision := authorize(t, engine, Request{Subject: "alice", Action: "post:read"})
	if !strings.Contains(decision.Reason, `role "viewer"`) {
		t.Fatalf("reason = %q, want role grant", decision.Reason)
	}

	denied := authorize(t, engine, Request{Subject: "alice", Action: "post:write"})
	if denied.Allowed || denied.Reason != "no matching role permission or policy" {
		t.Fatalf("unexpected no-match decision %+v", denied)
	}
}

func TestPrincipalRoleNameMatchesPolicy(t *testing.T) {
	engine := New()
	mustAddPolicy(t, engine, Policy{ID: "admin-all", Effect: EffectPermit, Subject: "admin", Action: "*"})
	decision := authorize(t, engine, Request{Subject: "alice", Roles: []string{"admin"}, Action: "anything"})
	if !decision.Allowed {
		t.Fatalf("admin role policy did not match: %s", decision.Reason)
	}
	if got, want := strings.Join(decision.MatchedPolicies, ","), "admin-all"; got != want {
		t.Fatalf("matched policies = %q want %q", got, want)
	}
}

func TestAuthPrincipalHasPermissionCompatibility(t *testing.T) {
	// The engine uses auth.MatchPermission, so role permissions follow the auth package wildcard
	// rules. | 引擎使用 auth.MatchPermission，因此角色权限遵循 auth 包的通配规则。
	if !auth.MatchPermission("post:*", "post:read") {
		t.Fatal("auth.MatchPermission contract changed")
	}
}
