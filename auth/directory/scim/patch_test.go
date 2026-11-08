package scim

import (
	"errors"
	"testing"
)

// patchBaseUser returns a User fixture for PATCH tests. | patchBaseUser 返回用于 PATCH 测试的 User
// 测试数据。
func patchBaseUser() *User {
	return &User{
		Schemas:     []string{UserSchema},
		ID:          "u1",
		UserName:    "alice",
		DisplayName: "Alice",
		Title:       "Engineer",
		Active:      boolPtr(true),
		Name:        &Name{GivenName: "Alice", FamilyName: "Smith"},
		Emails: []MultiValue{
			{Value: "alice@example.com", Type: "work", Primary: true},
			{Value: "alice@home.example", Type: "home"},
		},
		Addresses: []Address{
			{Locality: "Springfield", Type: "work", Primary: true},
			{Locality: "Paris", Type: "home"},
		},
		EnterpriseUser: &EnterpriseUser{Department: "Engineering", Organization: "Acme"},
	}
}

func TestApplyUserPatchReplaceAndAdd(t *testing.T) {
	base := patchBaseUser()
	patched, err := ApplyUserPatch(base, []PatchOperation{
		{Op: "replace", Path: "displayName", Value: "Alice Smith"},
		{Op: "add", Path: "nickName", Value: "Ali"},
		{Op: "replace", Path: "active", Value: false},
	})
	if err != nil {
		t.Fatalf("ApplyUserPatch error = %v", err)
	}
	if patched.DisplayName != "Alice Smith" || patched.NickName != "Ali" || patched.ActiveValue() {
		t.Fatalf("patched user = %+v", patched)
	}
	if base.DisplayName != "Alice" || base.NickName != "" || !base.ActiveValue() {
		t.Fatalf("input user was mutated: %+v", base)
	}
	if patched == base {
		t.Fatalf("ApplyUserPatch returned the input pointer")
	}
}

func TestApplyUserPatchPathlessOperations(t *testing.T) {
	base := patchBaseUser()
	patched, err := ApplyUserPatch(base, []PatchOperation{
		{Op: "replace", Value: map[string]any{
			"displayName": "Updated",
			"title":       "Manager",
			"active":      true,
		}},
	})
	if err != nil {
		t.Fatalf("pathless replace error = %v", err)
	}
	if patched.DisplayName != "Updated" || patched.Title != "Manager" || !patched.ActiveValue() {
		t.Fatalf("patched = %+v", patched)
	}
	patched, err = ApplyUserPatch(base, []PatchOperation{
		{Op: "add", Value: map[string]any{
			"name": map[string]any{"middleName": "B"},
		}},
	})
	if err != nil {
		t.Fatalf("pathless add error = %v", err)
	}
	if patched.Name == nil || patched.Name.MiddleName != "B" || patched.Name.GivenName != "Alice" {
		t.Fatalf("name = %+v", patched.Name)
	}
	if _, err := ApplyUserPatch(base, []PatchOperation{{Op: "add", Path: "", Value: "text"}}); err == nil || !errors.Is(err, ErrInvalidValue) {
		t.Fatalf("pathless scalar error = %v", err)
	}
	if _, err := ApplyUserPatch(base, []PatchOperation{{Op: "remove", Path: "", Value: map[string]any{}}}); err == nil || !errors.Is(err, ErrNoTarget) {
		t.Fatalf("pathless remove error = %v", err)
	}
}

func TestApplyUserPatchNameAndManagerSubAttributes(t *testing.T) {
	base := patchBaseUser()
	patched, err := ApplyUserPatch(base, []PatchOperation{
		{Op: "add", Path: "name.middleName", Value: "Q"},
		{Op: "replace", Path: "name.familyName", Value: "Jones"},
		{Op: "remove", Path: "name.givenName"},
	})
	if err != nil {
		t.Fatalf("name patch error = %v", err)
	}
	if patched.Name.MiddleName != "Q" || patched.Name.FamilyName != "Jones" || patched.Name.GivenName != "" {
		t.Fatalf("name = %+v", patched.Name)
	}
	if _, err := ApplyUserPatch(base, []PatchOperation{{Op: "add", Path: "name.unknown", Value: "x"}}); err == nil || !errors.Is(err, ErrInvalidPath) {
		t.Fatalf("unknown name sub-attribute error = %v", err)
	}
}

func TestApplyUserPatchFilteredMultiValues(t *testing.T) {
	base := patchBaseUser()
	patched, err := ApplyUserPatch(base, []PatchOperation{
		{Op: "replace", Path: `emails[type eq "work"].primary`, Value: false},
		{Op: "replace", Path: `emails[type eq "home"].primary`, Value: true},
	})
	if err != nil {
		t.Fatalf("filtered replace error = %v", err)
	}
	if patched.Emails[0].Value != "alice@example.com" || !patched.Emails[1].Primary {
		t.Fatalf("emails = %+v", patched.Emails)
	}
	if patched.Emails[0].Primary {
		t.Fatalf("work primary was not cleared: %+v", patched.Emails)
	}
	patched, err = ApplyUserPatch(base, []PatchOperation{
		{Op: "remove", Path: `emails[type eq "home"]`},
	})
	if err != nil {
		t.Fatalf("filtered remove error = %v", err)
	}
	if len(patched.Emails) != 1 || patched.Emails[0].Type != "work" {
		t.Fatalf("emails after remove = %+v", patched.Emails)
	}
	if len(base.Emails) != 2 {
		t.Fatalf("input emails were mutated: %+v", base.Emails)
	}
	patched, err = ApplyUserPatch(base, []PatchOperation{
		{Op: "add", Path: `phoneNumbers[type eq "work"].value`, Value: "+1-555-0199"},
	})
	if err != nil {
		t.Fatalf("filtered add no match error = %v", err)
	}
	if len(patched.PhoneNumbers) != 1 || patched.PhoneNumbers[0].Value != "+1-555-0199" {
		t.Fatalf("phoneNumbers = %+v", patched.PhoneNumbers)
	}
	patched, err = ApplyUserPatch(base, []PatchOperation{
		{Op: "add", Path: `emails`, Value: []any{
			map[string]any{"value": "new@example.com", "type": "other"},
			map[string]any{"value": "ALICE@example.com", "type": "duplicate"},
		}},
	})
	if err != nil {
		t.Fatalf("multi-value add error = %v", err)
	}
	if len(patched.Emails) != 3 {
		t.Fatalf("emails after add = %+v", patched.Emails)
	}
	if _, err := ApplyUserPatch(base, []PatchOperation{{Op: "remove", Path: `emails[type eq "missing"]`}}); err == nil || !errors.Is(err, ErrNoTarget) {
		t.Fatalf("no-target remove error = %v", err)
	}
}

func TestApplyUserPatchAddresses(t *testing.T) {
	base := patchBaseUser()
	patched, err := ApplyUserPatch(base, []PatchOperation{
		{Op: "replace", Path: `addresses[type eq "home"].locality`, Value: "Lyon"},
		{Op: "remove", Path: `addresses[type eq "work"]`},
	})
	if err != nil {
		t.Fatalf("address patch error = %v", err)
	}
	if len(patched.Addresses) != 1 || patched.Addresses[0].Locality != "Lyon" {
		t.Fatalf("addresses = %+v", patched.Addresses)
	}
}

func TestApplyUserPatchPrimaryNormalization(t *testing.T) {
	base := patchBaseUser()
	patched, err := ApplyUserPatch(base, []PatchOperation{
		{Op: "add", Path: "emails", Value: map[string]any{"value": "third@example.com", "primary": true}},
	})
	if err != nil {
		t.Fatalf("primary patch error = %v", err)
	}
	primaryCount := 0
	for _, email := range patched.Emails {
		if email.Primary {
			primaryCount++
		}
	}
	if primaryCount != 1 {
		t.Fatalf("primary count = %d, emails = %+v", primaryCount, patched.Emails)
	}
}

func TestApplyUserPatchEnterpriseExtension(t *testing.T) {
	base := patchBaseUser()
	patched, err := ApplyUserPatch(base, []PatchOperation{
		{Op: "replace", Path: EnterpriseUserSchema + ":department", Value: "Sales"},
		{Op: "replace", Path: EnterpriseUserSchema + ":manager.value", Value: "m1"},
	})
	if err != nil {
		t.Fatalf("enterprise patch error = %v", err)
	}
	if patched.EnterpriseUser.Department != "Sales" || patched.EnterpriseUser.Manager == nil || patched.EnterpriseUser.Manager.Value != "m1" {
		t.Fatalf("enterprise = %+v", patched.EnterpriseUser)
	}
	if !containsFold(patched.Schemas, EnterpriseUserSchema) {
		t.Fatalf("schemas = %v", patched.Schemas)
	}
	patched, err = ApplyUserPatch(base, []PatchOperation{
		{Op: "remove", Path: EnterpriseUserSchema},
	})
	if err != nil {
		t.Fatalf("enterprise remove error = %v", err)
	}
	if patched.EnterpriseUser != nil {
		t.Fatalf("enterprise = %+v", patched.EnterpriseUser)
	}
	if containsFold(patched.Schemas, EnterpriseUserSchema) {
		t.Fatalf("schemas = %v", patched.Schemas)
	}
	patched, err = ApplyUserPatch(base, []PatchOperation{
		{Op: "add", Value: map[string]any{
			EnterpriseUserSchema: map[string]any{"department": "Support", "manager": map[string]any{"value": "m2"}},
		}},
	})
	if err != nil {
		t.Fatalf("pathless enterprise add error = %v", err)
	}
	if patched.EnterpriseUser.Department != "Support" || patched.EnterpriseUser.Manager.Value != "m2" {
		t.Fatalf("enterprise = %+v", patched.EnterpriseUser)
	}
}

func TestApplyUserPatchErrors(t *testing.T) {
	base := patchBaseUser()
	cases := []struct {
		name string
		op   PatchOperation
		want error
	}{
		{"unknown op", PatchOperation{Op: "move", Path: "displayName", Value: "x"}, ErrInvalidSyntax},
		{"missing op", PatchOperation{Path: "displayName", Value: "x"}, ErrInvalidSyntax},
		{"read-only id", PatchOperation{Op: "replace", Path: "id", Value: "x"}, ErrMutability},
		{"read-only groups", PatchOperation{Op: "replace", Path: "groups"}, ErrMutability},
		{"read-only meta", PatchOperation{Op: "replace", Path: "meta"}, ErrMutability},
		{"unknown attribute", PatchOperation{Op: "replace", Path: "unknown", Value: "x"}, ErrInvalidPath},
		{"unknown schema", PatchOperation{Op: "replace", Path: "urn:example:2.0:User:userName", Value: "x"}, ErrInvalidPath},
		{"bad active", PatchOperation{Op: "replace", Path: "active", Value: "maybe"}, ErrInvalidValue},
		{"bad string", PatchOperation{Op: "replace", Path: "displayName", Value: []string{"x"}}, ErrInvalidValue},
		{"empty email", PatchOperation{Op: "add", Path: "emails", Value: []any{""}}, ErrInvalidValue},
		{"remove absent", PatchOperation{Op: "remove", Path: "emails", Value: nil}, nil},
	}
	for _, testCase := range cases {
		t.Run(testCase.name, func(t *testing.T) {
			_, err := ApplyUserPatch(base, []PatchOperation{testCase.op})
			if testCase.want == nil {
				if err != nil {
					t.Fatalf("ApplyUserPatch error = %v", err)
				}
				return
			}
			if err == nil || !errors.Is(err, testCase.want) {
				t.Fatalf("ApplyUserPatch error = %v, want %v", err, testCase.want)
			}
		})
	}
}

func TestApplyUserPatchAtomicity(t *testing.T) {
	base := patchBaseUser()
	_, err := ApplyUserPatch(base, []PatchOperation{
		{Op: "replace", Path: "displayName", Value: "Changed"},
		{Op: "replace", Path: "unknown", Value: "x"},
	})
	if err == nil {
		t.Fatalf("ApplyUserPatch succeeded, want error")
	}
	if base.DisplayName != "Alice" {
		t.Fatalf("input was mutated after failed patch: %q", base.DisplayName)
	}
}

func TestApplyGroupPatch(t *testing.T) {
	base := &Group{
		Schemas:     []string{GroupSchema},
		ID:          "g1",
		DisplayName: "Admins",
		Members: []GroupMember{
			{Value: "u1", Display: "Alice"},
			{Value: "u2", Display: "Bob"},
		},
	}
	patched, err := ApplyGroupPatch(base, []PatchOperation{
		{Op: "replace", Path: "displayName", Value: "Operators"},
		{Op: "remove", Path: `members[value eq "u2"]`},
		{Op: "add", Path: "members", Value: map[string]any{"value": "u3", "display": "Carol"}},
	})
	if err != nil {
		t.Fatalf("ApplyGroupPatch error = %v", err)
	}
	if patched.DisplayName != "Operators" || len(patched.Members) != 2 {
		t.Fatalf("patched group = %+v", patched)
	}
	if patched.Members[0].Value != "u1" || patched.Members[1].Value != "u3" {
		t.Fatalf("members = %+v", patched.Members)
	}
	if len(base.Members) != 2 || base.DisplayName != "Admins" {
		t.Fatalf("input group was mutated: %+v", base)
	}
	if _, err := ApplyGroupPatch(base, []PatchOperation{{Op: "remove", Path: "displayName"}}); err == nil || !errors.Is(err, ErrMutability) {
		t.Fatalf("remove displayName error = %v", err)
	}
	if _, err := ApplyGroupPatch(base, []PatchOperation{{Op: "replace", Path: "id", Value: "g2"}}); err == nil || !errors.Is(err, ErrMutability) {
		t.Fatalf("replace id error = %v", err)
	}
	if _, err := ApplyGroupPatch(base, []PatchOperation{{Op: "replace", Path: "members[value eq \"u9\"].display", Value: "Nobody"}}); err == nil || !errors.Is(err, ErrNoTarget) {
		t.Fatalf("missing member error = %v", err)
	}
}

func TestApplyPatchDispatch(t *testing.T) {
	value, err := ApplyPatch(User{UserName: "alice"}, []PatchOperation{{Op: "replace", Path: "title", Value: "x"}})
	if err != nil {
		t.Fatalf("ApplyPatch value error = %v", err)
	}
	user, ok := value.(*User)
	if !ok || user.Title != "x" {
		t.Fatalf("ApplyPatch value = %#v", value)
	}
	groupValue, err := ApplyPatch(&Group{DisplayName: "g"}, []PatchOperation{{Op: "replace", Path: "displayName", Value: "h"}})
	if err != nil {
		t.Fatalf("ApplyPatch group error = %v", err)
	}
	if groupValue.(*Group).DisplayName != "h" {
		t.Fatalf("ApplyPatch group = %#v", groupValue)
	}
	if _, err := ApplyPatch(42, nil); err == nil || !errors.Is(err, ErrUnsupported) {
		t.Fatalf("ApplyPatch int error = %v", err)
	}
	if _, err := ApplyUserPatch(nil, nil); err == nil || !errors.Is(err, ErrInvalidRequest) {
		t.Fatalf("ApplyUserPatch nil error = %v", err)
	}
}
