package scim

import (
	"context"
	"errors"
	"testing"
)

func TestMemoryStoreUserLifecycle(t *testing.T) {
	ctx := context.Background()
	store := NewMemoryStore()
	user, err := store.CreateUser(ctx, &User{UserName: "Alice", DisplayName: "Alice"})
	if err != nil {
		t.Fatalf("CreateUser error = %v", err)
	}
	if user.ID == "" {
		t.Fatalf("generated ID is empty")
	}
	if !user.ActiveValue() {
		t.Fatalf("new user is not active")
	}
	if user.Meta == nil || user.Meta.ResourceType != ResourceTypeNameUser || user.Meta.Version == "" || user.Meta.Created == "" {
		t.Fatalf("meta = %+v", user.Meta)
	}
	if !containsFold(user.Schemas, UserSchema) {
		t.Fatalf("schemas = %v", user.Schemas)
	}
	created := user.Meta.Created
	got, err := store.GetUser(ctx, user.ID)
	if err != nil {
		t.Fatalf("GetUser error = %v", err)
	}
	if got.UserName != "Alice" {
		t.Fatalf("userName = %q", got.UserName)
	}
	got.UserName = "mutated"
	again, err := store.GetUser(ctx, user.ID)
	if err != nil {
		t.Fatalf("GetUser second error = %v", err)
	}
	if again.UserName != "Alice" {
		t.Fatalf("store returned shared state: %q", again.UserName)
	}
	oldVersion := again.Meta.Version
	replaced, err := store.ReplaceUser(ctx, &User{ID: user.ID, UserName: "alice2", DisplayName: "Alice Two"})
	if err != nil {
		t.Fatalf("ReplaceUser error = %v", err)
	}
	if replaced.UserName != "alice2" || replaced.Meta.Created != created {
		t.Fatalf("replaced = %+v", replaced)
	}
	if replaced.Meta.Version == oldVersion {
		t.Fatalf("version did not change: %q", oldVersion)
	}
	if err := store.DeleteUser(ctx, user.ID); err != nil {
		t.Fatalf("DeleteUser error = %v", err)
	}
	if _, err := store.GetUser(ctx, user.ID); !errors.Is(err, ErrNotFound) {
		t.Fatalf("GetUser deleted error = %v", err)
	}
	if err := store.DeleteUser(ctx, user.ID); !errors.Is(err, ErrNotFound) {
		t.Fatalf("DeleteUser twice error = %v", err)
	}
}

func TestMemoryStoreUserValidationAndUniqueness(t *testing.T) {
	ctx := context.Background()
	store := NewMemoryStore()
	if _, err := store.CreateUser(ctx, nil); !errors.Is(err, ErrInvalidValue) {
		t.Fatalf("nil user error = %v", err)
	}
	if _, err := store.CreateUser(ctx, &User{}); !errors.Is(err, ErrInvalidValue) {
		t.Fatalf("empty userName error = %v", err)
	}
	if _, err := store.CreateUser(ctx, &User{UserName: "Alice"}); err != nil {
		t.Fatalf("CreateUser error = %v", err)
	}
	if _, err := store.CreateUser(ctx, &User{UserName: "alice"}); !errors.Is(err, ErrUniqueness) {
		t.Fatalf("duplicate userName error = %v", err)
	}
	first, err := store.CreateUser(ctx, &User{UserName: "bob"})
	if err != nil {
		t.Fatalf("CreateUser bob error = %v", err)
	}
	if _, err := store.CreateUser(ctx, &User{ID: first.ID, UserName: "bob2"}); !errors.Is(err, ErrConflict) {
		t.Fatalf("duplicate id error = %v", err)
	}
	if _, err := store.ReplaceUser(ctx, &User{ID: "missing", UserName: "x"}); !errors.Is(err, ErrNotFound) {
		t.Fatalf("replace missing error = %v", err)
	}
	if _, err := store.ReplaceUser(ctx, &User{UserName: "x"}); !errors.Is(err, ErrInvalidValue) {
		t.Fatalf("replace without id error = %v", err)
	}
	other, err := store.CreateUser(ctx, &User{UserName: "carol"})
	if err != nil {
		t.Fatalf("CreateUser carol error = %v", err)
	}
	if _, err := store.ReplaceUser(ctx, &User{ID: other.ID, UserName: "Alice"}); !errors.Is(err, ErrUniqueness) {
		t.Fatalf("replace duplicate error = %v", err)
	}
}

func TestMemoryStoreListUsers(t *testing.T) {
	ctx := context.Background()
	store := NewMemoryStore()
	for _, name := range []string{"carol", "alice", "bob", "dave", "eve"} {
		if _, err := store.CreateUser(ctx, &User{UserName: name, Title: "Engineer"}); err != nil {
			t.Fatalf("CreateUser %s error = %v", name, err)
		}
	}
	page, total, err := store.ListUsers(ctx, ListQuery{StartIndex: 2, Count: 2})
	if err != nil {
		t.Fatalf("ListUsers error = %v", err)
	}
	if total != 5 || len(page) != 2 || page[0].UserName != "bob" || page[1].UserName != "carol" {
		t.Fatalf("page = %v, total = %d", userNames(page), total)
	}
	page, total, err = store.ListUsers(ctx, ListQuery{SortBy: "userName", SortOrder: SortDescending, Count: 2})
	if err != nil {
		t.Fatalf("ListUsers descending error = %v", err)
	}
	if total != 5 || page[0].UserName != "eve" || page[1].UserName != "dave" {
		t.Fatalf("descending page = %v", userNames(page))
	}
	page, total, err = store.ListUsers(ctx, ListQuery{StartIndex: 99, Count: 2})
	if err != nil {
		t.Fatalf("ListUsers out of range error = %v", err)
	}
	if total != 5 || len(page) != 0 {
		t.Fatalf("out of range page = %v, total = %d", userNames(page), total)
	}
	page, total, err = store.ListUsers(ctx, ListQuery{StartIndex: 1, Count: 0})
	if err != nil {
		t.Fatalf("ListUsers zero count error = %v", err)
	}
	if total != 5 || len(page) != 0 {
		t.Fatalf("zero count page = %v, total = %d", userNames(page), total)
	}
	page, total, err = store.ListUsers(ctx, ListQuery{Count: -1})
	if err != nil {
		t.Fatalf("ListUsers negative count error = %v", err)
	}
	if total != 5 || len(page) != 5 {
		t.Fatalf("negative count page = %v, total = %d", userNames(page), total)
	}
	filter, err := ParseFilter(`title eq "Engineer" and userName sw "a"`)
	if err != nil {
		t.Fatalf("ParseFilter error = %v", err)
	}
	page, total, err = store.ListUsers(ctx, ListQuery{Filter: filter, Count: -1})
	if err != nil {
		t.Fatalf("ListUsers filtered error = %v", err)
	}
	if total != 1 || len(page) != 1 || page[0].UserName != "alice" {
		t.Fatalf("filtered page = %v, total = %d", userNames(page), total)
	}
}

func TestMemoryStoreGroupLifecycle(t *testing.T) {
	ctx := context.Background()
	store := NewMemoryStore()
	group, err := store.CreateGroup(ctx, &Group{
		DisplayName: "Admins",
		Members:     []GroupMember{{Value: "u1", Display: "Alice"}},
	})
	if err != nil {
		t.Fatalf("CreateGroup error = %v", err)
	}
	if group.ID == "" || group.Meta.ResourceType != ResourceTypeNameGroup {
		t.Fatalf("group = %+v", group)
	}
	if _, err := store.CreateGroup(ctx, &Group{DisplayName: "admins"}); !errors.Is(err, ErrUniqueness) {
		t.Fatalf("duplicate displayName error = %v", err)
	}
	if _, err := store.CreateGroup(ctx, &Group{DisplayName: "Bad", Members: []GroupMember{{Value: "u1"}, {Value: "u1"}}}); !errors.Is(err, ErrInvalidValue) {
		t.Fatalf("duplicate member error = %v", err)
	}
	if _, err := store.CreateGroup(ctx, &Group{DisplayName: "Bad", Members: []GroupMember{{Display: "x"}}}); !errors.Is(err, ErrInvalidValue) {
		t.Fatalf("empty member value error = %v", err)
	}
	if _, err := store.CreateGroup(ctx, &Group{}); !errors.Is(err, ErrInvalidValue) {
		t.Fatalf("empty displayName error = %v", err)
	}
	got, err := store.GetGroup(ctx, group.ID)
	if err != nil {
		t.Fatalf("GetGroup error = %v", err)
	}
	if got.DisplayName != "Admins" || len(got.Members) != 1 {
		t.Fatalf("group = %+v", got)
	}
	replaced, err := store.ReplaceGroup(ctx, &Group{ID: group.ID, DisplayName: "Operators"})
	if err != nil {
		t.Fatalf("ReplaceGroup error = %v", err)
	}
	if replaced.DisplayName != "Operators" || len(replaced.Members) != 0 {
		t.Fatalf("replaced = %+v", replaced)
	}
	groups, total, err := store.ListGroups(ctx, ListQuery{Count: -1})
	if err != nil {
		t.Fatalf("ListGroups error = %v", err)
	}
	if total != 1 || len(groups) != 1 || groups[0].DisplayName != "Operators" {
		t.Fatalf("groups = %+v, total = %d", groups, total)
	}
	if err := store.DeleteGroup(ctx, group.ID); err != nil {
		t.Fatalf("DeleteGroup error = %v", err)
	}
	if _, err := store.GetGroup(ctx, group.ID); !errors.Is(err, ErrNotFound) {
		t.Fatalf("GetGroup deleted error = %v", err)
	}
	if _, err := store.ReplaceGroup(ctx, &Group{ID: group.ID, DisplayName: "X"}); !errors.Is(err, ErrNotFound) {
		t.Fatalf("replace missing group error = %v", err)
	}
}

func TestMemoryStoreContextCancellation(t *testing.T) {
	store := NewMemoryStore()
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err := store.CreateUser(ctx, &User{UserName: "x"}); !errors.Is(err, ErrStoreUnavailable) {
		t.Fatalf("CreateUser canceled error = %v", err)
	}
	if _, err := store.GetUser(ctx, "x"); !errors.Is(err, ErrStoreUnavailable) {
		t.Fatalf("GetUser canceled error = %v", err)
	}
	if _, _, err := store.ListUsers(ctx, ListQuery{}); !errors.Is(err, ErrStoreUnavailable) {
		t.Fatalf("ListUsers canceled error = %v", err)
	}
	if _, err := store.CreateGroup(ctx, &Group{DisplayName: "x"}); !errors.Is(err, ErrStoreUnavailable) {
		t.Fatalf("CreateGroup canceled error = %v", err)
	}
}

func TestMemoryStoreConcurrentAccess(t *testing.T) {
	ctx := context.Background()
	store := NewMemoryStore()
	done := make(chan struct{})
	for i := 0; i < 8; i++ {
		go func(index int) {
			defer func() { done <- struct{}{} }()
			for j := 0; j < 20; j++ {
				name := "user-" + intString(index) + "-" + intString(j)
				user, err := store.CreateUser(ctx, &User{UserName: name})
				if err != nil {
					continue
				}
				if _, err := store.GetUser(ctx, user.ID); err == nil {
					user.DisplayName = name
					_, _ = store.ReplaceUser(ctx, user)
				}
				_, _, _ = store.ListUsers(ctx, ListQuery{Count: 5})
			}
		}(i)
	}
	for i := 0; i < 8; i++ {
		<-done
	}
	_, total, err := store.ListUsers(ctx, ListQuery{Count: 0})
	if err != nil {
		t.Fatalf("ListUsers error = %v", err)
	}
	if total != 160 {
		t.Fatalf("total = %d", total)
	}
}

func userNames(users []*User) []string {
	out := make([]string, len(users))
	for i, user := range users {
		out[i] = user.UserName
	}
	return out
}
