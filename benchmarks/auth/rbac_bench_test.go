package auth

import (
	"context"
	"testing"

	"github.com/casbin/casbin/v2"
	"github.com/casbin/casbin/v2/model"
	ydrbac "github.com/shibingli/ydx/auth/authz/rbac"
)

// casbinModel is a minimal RBAC model equivalent to the ydx role/assignment pair. |
// casbinModel 是与 ydx 角色/分配等价的最小 RBAC 模型。
const casbinModel = `
[request_definition]
r = sub, obj, act

[policy_definition]
p = sub, obj, act

[role_definition]
g = _, _

[policy_effect]
e = some(where (p.eft == allow))

[matchers]
m = g(r.sub, p.sub) && r.obj == p.obj && r.act == p.act
`

// newYDRBAC builds a ydx engine with one role, one assignment and one policy. | newYDRBAC 构建带一个
// 角色、一个分配与一条策略的 ydx 引擎。
func newYDRBAC(b testing.TB) *ydrbac.Engine {
	b.Helper()
	ctx := context.Background()
	engine := ydrbac.New()
	if err := engine.AddRole(ctx, ydrbac.Role{Name: "reader", Permissions: []string{"read"}}); err != nil {
		b.Fatalf("AddRole: %v", err)
	}
	if err := engine.AddPolicy(ctx, ydrbac.Policy{
		ID: "reader-doc", Effect: ydrbac.EffectPermit, Subject: "reader", Resource: "doc1", Action: "read",
	}); err != nil {
		b.Fatalf("AddPolicy: %v", err)
	}
	if err := engine.Assign(ctx, ydrbac.Assignment{Subject: "alice", Role: "reader"}); err != nil {
		b.Fatalf("Assign: %v", err)
	}
	return engine
}

// newCasbin builds the equivalent casbin enforcer. | newCasbin 构建等价的 casbin 执行器。
func newCasbin(b testing.TB) *casbin.Enforcer {
	b.Helper()
	m, err := model.NewModelFromString(casbinModel)
	if err != nil {
		b.Fatalf("model: %v", err)
	}
	e, err := casbin.NewEnforcer(m)
	if err != nil {
		b.Fatalf("enforcer: %v", err)
	}
	if _, err := e.AddRoleForUser("alice", "reader"); err != nil {
		b.Fatalf("AddRoleForUser: %v", err)
	}
	if _, err := e.AddPolicy("reader", "doc1", "read"); err != nil {
		b.Fatalf("AddPolicy: %v", err)
	}
	return e
}

// BenchmarkRBACAuthorize compares one authorization decision with casbin. |
// BenchmarkRBACAuthorize 对比一次授权决策与 casbin。
func BenchmarkRBACAuthorize(b *testing.B) {
	ctx := context.Background()
	engine := newYDRBAC(b)
	enforcer := newCasbin(b)
	request := ydrbac.Request{Subject: "alice", Action: "read", Resource: "doc1"}
	b.Run("ydx", func(b *testing.B) {
		b.ReportAllocs()
		for i := 0; i < b.N; i++ {
			decision, err := engine.Authorize(ctx, request)
			if err != nil || !decision.Allowed {
				b.Fatalf("decision=%+v err=%v", decision, err)
			}
		}
	})
	b.Run("casbin", func(b *testing.B) {
		b.ReportAllocs()
		for i := 0; i < b.N; i++ {
			ok, err := enforcer.Enforce("alice", "doc1", "read")
			if err != nil || !ok {
				b.Fatalf("ok=%v err=%v", ok, err)
			}
		}
	})
}

// TestRBACDecisionMatchesCasbin checks both engines reach the same decision for permit and deny. |
// TestRBACDecisionMatchesCasbin 检查两个引擎在许可与拒绝场景下给出相同决策。
func TestRBACDecisionMatchesCasbin(t *testing.T) {
	ctx := context.Background()
	engine := newYDRBAC(t)
	enforcer := newCasbin(t)
	cases := []struct {
		subject, resource, action string
	}{
		{"alice", "doc1", "read"},
		{"alice", "doc1", "write"},
		{"bob", "doc1", "read"},
	}
	for _, tc := range cases {
		decision, err := engine.Authorize(ctx, ydrbac.Request{Subject: tc.subject, Action: tc.action, Resource: tc.resource})
		if err != nil {
			t.Fatalf("ydx Authorize(%+v): %v", tc, err)
		}
		ok, err := enforcer.Enforce(tc.subject, tc.resource, tc.action)
		if err != nil {
			t.Fatalf("casbin Enforce(%+v): %v", tc, err)
		}
		if decision.Allowed != ok {
			t.Errorf("decision mismatch for %+v: ydx=%v casbin=%v | 决策不一致", tc, decision.Allowed, ok)
		}
	}
}
