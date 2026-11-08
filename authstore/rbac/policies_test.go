package rbac_test

import (
	"errors"
	"testing"

	authrbac "github.com/shibingli/ydx/auth/authz/rbac"
)

// TestPolicyLifecycle covers normalization, duplicate rules, reads, removal and deep copies.
// | TestPolicyLifecycle 覆盖规范化、重复规则、读取、删除与深拷贝。
func TestPolicyLifecycle(t *testing.T) {
	store, _ := newStore(t, "")
	policy := authrbac.Policy{
		ID:          "allow-editors",
		Effect:      " PERMIT ",
		Subject:     "alice",
		Resource:    "post:*",
		Action:      "post:write",
		Scope:       "tenant:1",
		Priority:    10,
		Description: "editors may write posts",
		Conditions: []authrbac.Condition{
			{Key: "subject.department", Operator: " EQ ", Value: "eng"},
			{Key: "env.ip", Operator: "starts_with", Value: "10."},
		},
	}
	if err := store.AddPolicy(testContext, policy); err != nil {
		t.Fatalf("add policy: %v | 添加策略失败", err)
	}
	policy.Conditions[0].Value = "mutated"

	stored, err := store.GetPolicy(testContext, "allow-editors")
	if err != nil {
		t.Fatalf("get policy: %v | 读取策略失败", err)
	}
	if stored.Effect != authrbac.EffectPermit {
		t.Fatalf("effect = %q, want permit | 效果未规范化为 permit", stored.Effect)
	}
	if stored.Conditions[0].Operator != authrbac.OperatorEquals || stored.Conditions[1].Operator != authrbac.OperatorStartsWith {
		t.Fatalf("operators = %+v | 运算符未规范化", stored.Conditions)
	}
	if stored.Conditions[0].Value != "eng" {
		t.Fatalf("conditions aliased caller input: %+v | 策略条件别名了调用方输入", stored.Conditions)
	}
	if stored.Priority != 10 || stored.Subject != "alice" || stored.Resource != "post:*" {
		t.Fatalf("stored policy = %+v | 存储策略字段不符", stored)
	}

	stored.Conditions[0].Value = "mutated"
	again, err := store.GetPolicy(testContext, "allow-editors")
	if err != nil {
		t.Fatalf("get policy again: %v | 再次读取策略失败", err)
	}
	if again.Conditions[0].Value != "eng" {
		t.Fatalf("GetPolicy aliased stored value: %+v | GetPolicy 别名了存储值", again)
	}

	if err := store.AddPolicy(testContext, policy); !errors.Is(err, authrbac.ErrPolicyExists) {
		t.Fatalf("duplicate policy error = %v | 重复策略错误不符", err)
	}
	if err := store.AddPolicy(testContext, authrbac.Policy{ID: "allow-editors", Effect: authrbac.EffectDeny}); !errors.Is(err, authrbac.ErrPolicyExists) {
		t.Fatalf("duplicate normalized policy error = %v | 规范化重复策略错误不符", err)
	}

	if err := store.AddPolicy(testContext, authrbac.Policy{ID: "a-first", Effect: authrbac.EffectDeny}); err != nil {
		t.Fatalf("add policy a-first: %v | 添加策略 a-first 失败", err)
	}
	if err := store.AddPolicy(testContext, authrbac.Policy{ID: "z-last", Effect: authrbac.EffectPermit}); err != nil {
		t.Fatalf("add policy z-last: %v | 添加策略 z-last 失败", err)
	}
	policies, err := store.ListPolicies(testContext)
	if err != nil {
		t.Fatalf("list policies: %v | 列出策略失败", err)
	}
	if len(policies) != 3 || policies[0].ID != "a-first" || policies[1].ID != "allow-editors" || policies[2].ID != "z-last" {
		t.Fatalf("policies = %+v | 策略排序不符", policies)
	}
	policies[1].Conditions[0].Value = "mutated"
	again, err = store.GetPolicy(testContext, "allow-editors")
	if err != nil {
		t.Fatalf("get policy after list: %v | 列表后读取策略失败", err)
	}
	if again.Conditions[0].Value != "eng" {
		t.Fatalf("ListPolicies aliased stored value: %+v | ListPolicies 别名了存储值", again)
	}

	if err := store.RemovePolicy(testContext, "a-first"); err != nil {
		t.Fatalf("remove policy: %v | 删除策略失败", err)
	}
	if _, err := store.GetPolicy(testContext, "a-first"); !errors.Is(err, authrbac.ErrPolicyNotFound) {
		t.Fatalf("removed policy error = %v | 已删除策略错误不符", err)
	}
	if err := store.RemovePolicy(testContext, "a-first"); !errors.Is(err, authrbac.ErrPolicyNotFound) {
		t.Fatalf("double remove error = %v | 重复删除策略错误不符", err)
	}
	policies, err = store.ListPolicies(testContext)
	if err != nil {
		t.Fatalf("list policies after remove: %v | 删除后列出策略失败", err)
	}
	if len(policies) != 2 {
		t.Fatalf("policies after remove = %+v | 删除后策略数量不符", policies)
	}
}

// TestPolicyValidation covers invalid identifiers, effects and conditions.
// | TestPolicyValidation 覆盖非法标识、效果与条件。
func TestPolicyValidation(t *testing.T) {
	store, _ := newStore(t, "")
	invalid := []authrbac.Policy{
		{Effect: authrbac.EffectPermit},
		{ID: "   ", Effect: authrbac.EffectPermit},
		{ID: "bad-effect", Effect: "allow"},
		{ID: "bad-effect-empty", Effect: ""},
		{ID: "bad-key", Effect: authrbac.EffectPermit, Conditions: []authrbac.Condition{{Operator: authrbac.OperatorEquals, Value: "x"}}},
		{ID: "bad-operator", Effect: authrbac.EffectPermit, Conditions: []authrbac.Condition{{Key: "subject.id", Operator: "matches", Value: "x"}}},
	}
	for _, policy := range invalid {
		err := store.AddPolicy(testContext, policy)
		requireError(t, err, authrbac.ErrInvalidPolicy, "invalid policy "+policy.ID)
	}
	err := store.AddPolicy(testContext, authrbac.Policy{
		ID: "bad-condition", Effect: authrbac.EffectPermit,
		Conditions: []authrbac.Condition{{Key: "subject.id", Operator: "unknown"}},
	})
	requireError(t, err, authrbac.ErrInvalidCondition, "unknown operator")
	if _, err := store.GetPolicy(testContext, "missing"); !errors.Is(err, authrbac.ErrPolicyNotFound) {
		t.Fatalf("missing policy error = %v | 缺失策略错误不符", err)
	}
}

// TestPolicyCrossInstance covers visibility, uniqueness and removal between instances.
// | TestPolicyCrossInstance 覆盖实例之间的可见性、唯一性与删除。
func TestPolicyCrossInstance(t *testing.T) {
	first, second := newPair(t)
	policy := authrbac.Policy{
		ID:       "allow",
		Effect:   authrbac.EffectPermit,
		Action:   "post:read",
		Priority: 3,
		Conditions: []authrbac.Condition{
			{Key: "subject.department", Operator: authrbac.OperatorEquals, Value: "eng"},
		},
	}
	if err := first.AddPolicy(testContext, policy); err != nil {
		t.Fatalf("first add policy: %v | 第一实例添加策略失败", err)
	}
	stored, err := second.GetPolicy(testContext, "allow")
	if err != nil {
		t.Fatalf("second get policy: %v | 第二实例读取策略失败", err)
	}
	if stored.Priority != 3 || stored.Conditions[0].Value != "eng" {
		t.Fatalf("second stored policy = %+v | 第二实例策略内容不符", stored)
	}
	if err := second.AddPolicy(testContext, authrbac.Policy{ID: "allow", Effect: authrbac.EffectDeny}); !errors.Is(err, authrbac.ErrPolicyExists) {
		t.Fatalf("cross-instance duplicate error = %v | 跨实例重复策略错误不符", err)
	}
	if err := second.RemovePolicy(testContext, "allow"); err != nil {
		t.Fatalf("second remove policy: %v | 第二实例删除策略失败", err)
	}
	if _, err := first.GetPolicy(testContext, "allow"); !errors.Is(err, authrbac.ErrPolicyNotFound) {
		t.Fatalf("first policy after remove error = %v | 删除后第一实例策略错误不符", err)
	}
}
