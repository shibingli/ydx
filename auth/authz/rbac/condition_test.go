package rbac

import "testing"

func TestConditionOperators(t *testing.T) {
	request := &Request{
		Subject:  "alice",
		Action:   "post:read",
		Resource: "post:1",
		Scope:    "tenant:1",
		Attributes: map[string]string{
			"department":         "eng",
			"subject.department": "eng",
			"resource.owner":     "alice",
			"count":              "10",
			"empty":              "",
		},
		Environment: map[string]string{
			"ip": "10.0.0.1",
		},
	}
	resolver := attributeResolver{req: request}

	cases := []struct {
		name      string
		condition Condition
		want      bool
	}{
		{name: "eq match", condition: Condition{Key: "subject.department", Operator: OperatorEquals, Value: "eng"}, want: true},
		{name: "eq mismatch", condition: Condition{Key: "subject.department", Operator: OperatorEquals, Value: "sales"}, want: false},
		{name: "eq missing", condition: Condition{Key: "missing", Operator: OperatorEquals, Value: "x"}, want: false},
		{name: "eq builtin subject", condition: Condition{Key: "subject", Operator: OperatorEquals, Value: "alice"}, want: true},
		{name: "eq builtin resource", condition: Condition{Key: "resource", Operator: OperatorEquals, Value: "post:1"}, want: true},
		{name: "eq subject id", condition: Condition{Key: "subject.id", Operator: OperatorEquals, Value: "alice"}, want: true},
		{name: "eq resource id", condition: Condition{Key: "resource.id", Operator: OperatorEquals, Value: "post:1"}, want: true},
		{name: "ne match", condition: Condition{Key: "subject.department", Operator: OperatorNotEquals, Value: "sales"}, want: true},
		{name: "ne mismatch", condition: Condition{Key: "subject.department", Operator: OperatorNotEquals, Value: "eng"}, want: false},
		{name: "ne missing", condition: Condition{Key: "missing", Operator: OperatorNotEquals, Value: "x"}, want: false},
		{name: "in match", condition: Condition{Key: "scope", Operator: OperatorIn, Value: "tenant:1, tenant:2"}, want: true},
		{name: "in mismatch", condition: Condition{Key: "scope", Operator: OperatorIn, Value: "tenant:2,tenant:3"}, want: false},
		{name: "in missing", condition: Condition{Key: "missing", Operator: OperatorIn, Value: "x"}, want: false},
		{name: "not in match", condition: Condition{Key: "scope", Operator: OperatorNotIn, Value: "tenant:2,tenant:3"}, want: true},
		{name: "not in mismatch", condition: Condition{Key: "scope", Operator: OperatorNotIn, Value: "tenant:1,tenant:2"}, want: false},
		{name: "not in missing", condition: Condition{Key: "missing", Operator: OperatorNotIn, Value: "x"}, want: false},
		{name: "contains", condition: Condition{Key: "resource", Operator: OperatorContains, Value: "post"}, want: true},
		{name: "contains missing", condition: Condition{Key: "missing", Operator: OperatorContains, Value: "x"}, want: false},
		{name: "starts with", condition: Condition{Key: "resource", Operator: OperatorStartsWith, Value: "post"}, want: true},
		{name: "starts with mismatch", condition: Condition{Key: "resource", Operator: OperatorStartsWith, Value: "user"}, want: false},
		{name: "ends with", condition: Condition{Key: "resource", Operator: OperatorEndsWith, Value: "1"}, want: true},
		{name: "ends with mismatch", condition: Condition{Key: "resource", Operator: OperatorEndsWith, Value: "2"}, want: false},
		{name: "greater than", condition: Condition{Key: "count", Operator: OperatorGreaterThan, Value: "9"}, want: true},
		{name: "greater than equal", condition: Condition{Key: "count", Operator: OperatorGreaterThan, Value: "10"}, want: false},
		{name: "greater or equal", condition: Condition{Key: "count", Operator: OperatorGreaterOrEqual, Value: "10"}, want: true},
		{name: "less than", condition: Condition{Key: "count", Operator: OperatorLessThan, Value: "11"}, want: true},
		{name: "less or equal", condition: Condition{Key: "count", Operator: OperatorLessOrEqual, Value: "10"}, want: true},
		{name: "numeric mismatch", condition: Condition{Key: "count", Operator: OperatorGreaterThan, Value: "abc"}, want: false},
		{name: "numeric missing", condition: Condition{Key: "missing", Operator: OperatorLessThan, Value: "10"}, want: false},
		{name: "present builtin", condition: Condition{Key: "subject", Operator: OperatorPresent}, want: true},
		{name: "present empty value", condition: Condition{Key: "empty", Operator: OperatorPresent}, want: true},
		{name: "present missing", condition: Condition{Key: "missing", Operator: OperatorPresent}, want: false},
		{name: "absent missing", condition: Condition{Key: "missing", Operator: OperatorAbsent}, want: true},
		{name: "absent builtin", condition: Condition{Key: "subject", Operator: OperatorAbsent}, want: false},
		{name: "absent empty scope", condition: Condition{Key: "scope", Operator: OperatorAbsent}, want: false},
		{name: "env prefix", condition: Condition{Key: "env.ip", Operator: OperatorEquals, Value: "10.0.0.1"}, want: true},
		{name: "environment prefix", condition: Condition{Key: "environment.ip", Operator: OperatorEquals, Value: "10.0.0.1"}, want: true},
		{name: "exact dotted attribute", condition: Condition{Key: "resource.owner", Operator: OperatorEquals, Value: "alice"}, want: true},
		{name: "unknown operator", condition: Condition{Key: "subject", Operator: "bogus", Value: "alice"}, want: false},
		{name: "empty key", condition: Condition{Key: "", Operator: OperatorEquals, Value: "x"}, want: false},
	}
	for _, testCase := range cases {
		t.Run(testCase.name, func(t *testing.T) {
			if got := evaluateCondition(testCase.condition, resolver); got != testCase.want {
				t.Fatalf("evaluateCondition(%+v) = %v want %v", testCase.condition, got, testCase.want)
			}
		})
	}
}

func TestEmptyScopeIsAbsent(t *testing.T) {
	resolver := attributeResolver{req: &Request{Subject: "alice", Action: "read"}}
	if _, ok := resolver.lookup("scope"); ok {
		t.Fatal("empty scope should be absent")
	}
	if _, ok := resolver.lookup("resource"); ok {
		t.Fatal("empty resource should be absent")
	}
	if _, ok := resolver.lookup("action"); !ok {
		t.Fatal("non-empty action should be present")
	}
}

func TestConditionValidation(t *testing.T) {
	cases := []struct {
		name      string
		condition Condition
		wantErr   bool
	}{
		{name: "valid operator", condition: Condition{Key: "subject", Operator: OperatorEquals}},
		{name: "valid normalized operator", condition: Condition{Key: "subject", Operator: " EQ "}},
		{name: "empty key", condition: Condition{Key: " ", Operator: OperatorEquals}, wantErr: true},
		{name: "unknown operator", condition: Condition{Key: "subject", Operator: "nope"}, wantErr: true},
		{name: "empty operator", condition: Condition{Key: "subject"}, wantErr: true},
	}
	for _, testCase := range cases {
		t.Run(testCase.name, func(t *testing.T) {
			condition := normalizeCondition(testCase.condition)
			err := validateCondition(condition)
			if (err != nil) != testCase.wantErr {
				t.Fatalf("validateCondition(%+v) error = %v wantErr %v", testCase.condition, err, testCase.wantErr)
			}
		})
	}
}

func TestOperatorConstants(t *testing.T) {
	operators := []string{
		OperatorEquals, OperatorNotEquals, OperatorIn, OperatorNotIn, OperatorContains,
		OperatorStartsWith, OperatorEndsWith, OperatorGreaterThan, OperatorGreaterOrEqual,
		OperatorLessThan, OperatorLessOrEqual, OperatorPresent, OperatorAbsent,
	}
	seen := make(map[string]struct{}, len(operators))
	for _, operator := range operators {
		if !supportedOperator(operator) {
			t.Fatalf("declared operator %q is not supported", operator)
		}
		if _, duplicate := seen[operator]; duplicate {
			t.Fatalf("duplicate operator constant %q", operator)
		}
		seen[operator] = struct{}{}
	}
}
