package workflow_test

import (
	"fmt"
	"testing"

	"github.com/shibingli/ydx/workflow"
)

// TestConditionEvaluation covers the supported expression language. | TestConditionEvaluation
// 覆盖受支持的表达式语言。
func TestConditionEvaluation(t *testing.T) {
	vars := map[string]any{
		"amount":  120.5,
		"count":   3,
		"name":    "leave request",
		"ok":      true,
		"missing": nil,
		"user":    map[string]any{"role": "manager", "level": 2},
		"tags":    []any{"urgent", "finance"},
	}
	cases := []struct {
		expr string
		want bool
	}{
		{"", true},
		{"amount > 100", true},
		{"amount >= 120.5", true},
		{"amount < 100", false},
		{"count == 3", true},
		{"count != 3", false},
		{"name == 'leave request'", true},
		{"name contains 'leave'", true},
		{"name startsWith 'leave'", true},
		{"name endsWith 'request'", true},
		{"user.role == 'manager'", true},
		{"user.level >= 2 && ok", true},
		{"user.level > 5 || amount < 100", false},
		{"!ok", false},
		{"(amount > 100 || count > 5) && ok", true},
		{"count in [1, 2, 3]", true},
		{"'urgent' in tags", true},
		{"tags contains 'finance'", true},
		{"missing == null", true},
		{"missing != null", false},
		{"", true},
		{"amount = 120.5", true},
	}
	for _, tc := range cases {
		t.Run(tc.expr, func(t *testing.T) {
			got, err := workflow.EvaluateCondition(tc.expr, vars)
			if err != nil {
				t.Fatalf("求值 %q 失败: %v", tc.expr, err)
			}
			if got != tc.want {
				t.Fatalf("求值 %q = %v, 期望 %v", tc.expr, got, tc.want)
			}
		})
	}
}

// TestConditionErrors covers syntax and runtime failures. | TestConditionErrors 覆盖语法与运行时失败。
func TestConditionErrors(t *testing.T) {
	vars := map[string]any{"amount": nil, "text": "abc"}
	for _, expr := range []string{
		"amount >",
		"(amount > 1",
		"amount > 1 &&",
		"amount === 1",
		"'unterminated",
		"[1, 2",
		"amount @ 1",
		"foo(1)",
	} {
		if err := workflow.ValidateCondition(expr); err == nil {
			t.Errorf("期望 %q 校验失败", expr)
		}
	}
	if _, err := workflow.EvaluateCondition("amount > 10", vars); err == nil {
		t.Fatal("对 nil 使用排序运算符应失败关闭")
	}
	if _, err := workflow.EvaluateCondition("text + 1", vars); err == nil {
		t.Fatal("不支持算术运算符，应报错")
	}
	if err := workflow.ValidateCondition("amount > 100 && user.role == 'manager'"); err != nil {
		t.Fatalf("合法表达式被拒绝: %v", err)
	}
}

// TestConditionCacheSurvivesEviction proves the bounded cache stays correct once it starts
// evicting: the oldest expression is reparsed and still yields the same result. |
// TestConditionCacheSurvivesEviction 证明有界缓存开始淘汰后仍然正确：最旧的表达式会被重新解析并
// 得到相同结果。
func TestConditionCacheSurvivesEviction(t *testing.T) {
	vars := map[string]any{"value": 0.0}
	if ok, err := workflow.EvaluateCondition("value == 0", vars); err != nil || !ok {
		t.Fatalf("首次求值 = %v, %v", ok, err)
	}
	for i := 0; i < 700; i++ {
		expr := fmt.Sprintf("value == %d", i+1)
		if ok, err := workflow.EvaluateCondition(expr, vars); err != nil || ok {
			t.Fatalf("%q 求值 = %v, %v", expr, ok, err)
		}
	}
	if ok, err := workflow.EvaluateCondition("value == 0", vars); err != nil || !ok {
		t.Fatalf("淘汰后重新解析 = %v, %v", ok, err)
	}
}
