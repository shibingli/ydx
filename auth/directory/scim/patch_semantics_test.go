package scim

import (
	"errors"
	"testing"
)

// TestPatchPathlessRemoveReportsNoTarget verifies RFC 7644 section 3.5.2.2: remove without a path
// fails with noTarget. | TestPatchPathlessRemoveReportsNoTarget 校验 RFC 7644 第 3.5.2.2 节：无路径
// 的 remove 以 noTarget 失败。
func TestPatchPathlessRemoveReportsNoTarget(t *testing.T) {
	if _, err := ApplyUserPatch(&User{UserName: "alice"}, []PatchOperation{{Op: "remove"}}); err == nil || !errors.Is(err, ErrNoTarget) {
		t.Fatalf("user pathless remove error = %v", err)
	}
	if _, err := ApplyGroupPatch(&Group{DisplayName: "staff"}, []PatchOperation{{Op: "remove"}}); err == nil || !errors.Is(err, ErrNoTarget) {
		t.Fatalf("group pathless remove error = %v", err)
	}
}

// TestPatchRequiredAttributeMutability verifies that removing or unassigning a required attribute
// reports mutability instead of a generic invalid value. | TestPatchRequiredAttributeMutability
// 校验移除或置空必需属性时报告 mutability，而不是通用取值错误。
func TestPatchRequiredAttributeMutability(t *testing.T) {
	userOperations := []PatchOperation{
		{Op: "remove", Path: "userName"},
		{Op: "replace", Path: "userName", Value: ""},
		{Op: "replace", Path: "userName", Value: nil},
	}
	for _, operation := range userOperations {
		user := &User{UserName: "alice"}
		if _, err := ApplyUserPatch(user, []PatchOperation{operation}); err == nil || !errors.Is(err, ErrMutability) {
			t.Fatalf("user %s %v error = %v", operation.Op, operation.Value, err)
		}
	}
	groupOperations := []PatchOperation{
		{Op: "remove", Path: "displayName"},
		{Op: "replace", Path: "displayName", Value: ""},
		{Op: "replace", Path: "displayName", Value: nil},
	}
	for _, operation := range groupOperations {
		group := &Group{DisplayName: "staff"}
		if _, err := ApplyGroupPatch(group, []PatchOperation{operation}); err == nil || !errors.Is(err, ErrMutability) {
			t.Fatalf("group %s %v error = %v", operation.Op, operation.Value, err)
		}
		if group.DisplayName != "staff" {
			t.Fatalf("rejected group patch changed displayName to %q", group.DisplayName)
		}
	}
}

// TestPatchFilteredAddDerivesConstraints verifies that add through a value filter which matches no
// entry creates an entry carrying the filter's equality constraints and the requested sub-attribute.
// | TestPatchFilteredAddDerivesConstraints 校验值过滤器未匹配任何条目时的 add 会创建携带过滤器
// 相等约束与目标子属性的条目。
func TestPatchFilteredAddDerivesConstraints(t *testing.T) {
	user := &User{
		Emails: []MultiValue{{Value: "home@example.com", Type: "home"}},
		Addresses: []Address{
			{Locality: "Paris", Type: "home"},
		},
	}
	patched, err := ApplyUserPatch(user, []PatchOperation{
		{Op: "add", Path: `emails[type eq "work"].value`, Value: "work@example.com"},
	})
	if err != nil {
		t.Fatalf("sub-attribute add error = %v", err)
	}
	if len(patched.Emails) != 2 {
		t.Fatalf("emails = %+v", patched.Emails)
	}
	added := patched.Emails[1]
	if added.Type != "work" || added.Value != "work@example.com" {
		t.Fatalf("derived email = %+v", added)
	}
	if user.Emails[0].Type != "home" || len(user.Emails) != 1 {
		t.Fatalf("input user was mutated: %+v", user)
	}

	patched, err = ApplyUserPatch(user, []PatchOperation{
		{Op: "add", Path: `emails[type eq "work"]`, Value: "second@example.com"},
	})
	if err != nil {
		t.Fatalf("attribute add error = %v", err)
	}
	if len(patched.Emails) != 2 || patched.Emails[1].Type != "work" || patched.Emails[1].Value != "second@example.com" {
		t.Fatalf("derived attribute email = %+v", patched.Emails)
	}

	patched, err = ApplyUserPatch(user, []PatchOperation{
		{Op: "add", Path: `emails[type eq "work"]`, Value: map[string]any{"value": "explicit@example.com", "type": "home"}},
	})
	if err != nil {
		t.Fatalf("explicit object add error = %v", err)
	}
	if len(patched.Emails) != 2 || patched.Emails[1].Type != "home" || patched.Emails[1].Value != "explicit@example.com" {
		t.Fatalf("explicit object add = %+v", patched.Emails)
	}

	patched, err = ApplyUserPatch(user, []PatchOperation{
		{Op: "add", Path: `emails[type eq "work" and value ew "@example.com"].value`, Value: "and@example.com"},
	})
	if err != nil {
		t.Fatalf("and filter add error = %v", err)
	}
	if len(patched.Emails) != 2 || patched.Emails[1].Type != "work" || patched.Emails[1].Value != "and@example.com" {
		t.Fatalf("and filter add = %+v", patched.Emails)
	}

	patched, err = ApplyUserPatch(user, []PatchOperation{
		{Op: "add", Path: `emails[type ne "home"].value`, Value: "no-constraint@example.com"},
	})
	if err != nil {
		t.Fatalf("non-equality filter add error = %v", err)
	}
	if len(patched.Emails) != 2 || patched.Emails[1].Type != "" || patched.Emails[1].Value != "no-constraint@example.com" {
		t.Fatalf("non-equality filter add = %+v", patched.Emails)
	}

	patched, err = ApplyUserPatch(user, []PatchOperation{
		{Op: "add", Path: `emails[type eq "work"].primary`, Value: true},
	})
	if err != nil {
		t.Fatalf("boolean sub-attribute add error = %v", err)
	}
	if len(patched.Emails) != 2 || patched.Emails[1].Type != "work" || !patched.Emails[1].Primary {
		t.Fatalf("boolean derived email = %+v", patched.Emails)
	}

	patched, err = ApplyUserPatch(user, []PatchOperation{
		{Op: "add", Path: `addresses[type eq "work"].locality`, Value: "Lyon"},
	})
	if err != nil {
		t.Fatalf("address sub-attribute add error = %v", err)
	}
	if len(patched.Addresses) != 2 || patched.Addresses[1].Type != "work" || patched.Addresses[1].Locality != "Lyon" {
		t.Fatalf("derived address = %+v", patched.Addresses)
	}

	patched, err = ApplyUserPatch(user, []PatchOperation{
		{Op: "add", Path: `addresses[type eq "work"].primary`, Value: true},
	})
	if err != nil {
		t.Fatalf("boolean address sub-attribute add error = %v", err)
	}
	if len(patched.Addresses) != 2 || patched.Addresses[1].Type != "work" || !patched.Addresses[1].Primary {
		t.Fatalf("boolean derived address = %+v", patched.Addresses)
	}

	group := &Group{DisplayName: "staff", Members: []GroupMember{{Value: "u1"}}}
	groupPatched, err := ApplyGroupPatch(group, []PatchOperation{
		{Op: "add", Path: `members[value eq "u99"].display`, Value: "Bob"},
	})
	if err != nil {
		t.Fatalf("member sub-attribute add error = %v", err)
	}
	if len(groupPatched.Members) != 2 {
		t.Fatalf("members = %+v", groupPatched.Members)
	}
	member := groupPatched.Members[1]
	if member.Value != "u99" || member.Display != "Bob" {
		t.Fatalf("derived member = %+v", member)
	}
	if len(group.Members) != 1 || group.Members[0].Display != "" {
		t.Fatalf("input group was mutated: %+v", group)
	}
}

// TestPatchFilteredAddStillReplacesMatches verifies that a value filter which does match keeps the
// RFC 7644 replacement behavior instead of appending a new entry. | TestPatchFilteredAddStillReplacesMatches
// 校验命中值过滤器时仍保持 RFC 7644 的替换行为，而不是追加新条目。
func TestPatchFilteredAddStillReplacesMatches(t *testing.T) {
	user := &User{Emails: []MultiValue{{Value: "work@example.com", Type: "work"}}}
	patched, err := ApplyUserPatch(user, []PatchOperation{
		{Op: "add", Path: `emails[type eq "work"].value`, Value: "new@example.com"},
	})
	if err != nil {
		t.Fatalf("matched add error = %v", err)
	}
	if len(patched.Emails) != 1 || patched.Emails[0].Value != "new@example.com" || patched.Emails[0].Type != "work" {
		t.Fatalf("matched add = %+v", patched.Emails)
	}
}
