package scim

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/shibingli/ydx/auth"
	"github.com/shibingli/ydx/errs"
)

// newAdapter returns a UserStoreAdapter backed by an empty memory account store. |
// newAdapter 返回由空内存账号存储支撑的 UserStoreAdapter。
func newAdapter(t *testing.T) (*UserStoreAdapter, *auth.MemoryUserStore) {
	t.Helper()
	users := auth.NewMemoryUserStore()
	adapter, err := NewUserStoreAdapter(users)
	if err != nil {
		t.Fatalf("NewUserStoreAdapter error = %v", err)
	}
	return adapter, users
}

func TestNewUserStoreAdapterValidation(t *testing.T) {
	if _, err := NewUserStoreAdapter(nil); !errors.Is(err, ErrInvalidConfig) {
		t.Fatalf("NewUserStoreAdapter(nil) error = %v, want ErrInvalidConfig", err)
	}
	adapter, users := newAdapter(t)
	if adapter.Users != users {
		t.Fatalf("adapter.Users = %v", adapter.Users)
	}
	if adapter.groups == nil {
		t.Fatalf("adapter.groups is nil")
	}
}

func TestUserStoreAdapterCreateUser(t *testing.T) {
	adapter, users := newAdapter(t)
	ctx := context.Background()
	created, err := adapter.CreateUser(ctx, &User{
		UserName:          "Alice",
		ExternalID:        "ext-1",
		DisplayName:       "Alice Smith",
		NickName:          "Ali",
		ProfileURL:        "https://example.com/alice",
		Title:             "Engineer",
		UserType:          "Employee",
		PreferredLanguage: "en-US",
		Locale:            "en-US",
		Timezone:          "UTC",
		Password:          "s3cret-test-value",
		Name:              &Name{GivenName: "Alice", FamilyName: "Smith", MiddleName: "Q"},
		Emails:            []MultiValue{{Value: "alice@example.com", Primary: true}, {Value: "alice@home.example"}},
		PhoneNumbers:      []MultiValue{{Value: "+15550100", Primary: true}},
		Photos:            []MultiValue{{Value: "https://example.com/alice.png", Primary: true}},
		Addresses: []Address{{
			Formatted:     "1 Main St",
			StreetAddress: "1 Main St",
			Locality:      "Springfield",
			Region:        "IL",
			PostalCode:    "62701",
			Country:       "US",
			Primary:       true,
		}},
		EnterpriseUser: &EnterpriseUser{
			EmployeeNumber: "E-42",
			CostCenter:     "CC-1",
			Organization:   "Acme",
			Division:       "R&D",
			Department:     "Engineering",
		},
		Active: boolPtr(true),
	})
	if err != nil {
		t.Fatalf("CreateUser error = %v", err)
	}
	if created.ID == "" {
		t.Fatalf("created ID is empty")
	}
	if created.Meta == nil || created.Meta.ResourceType != ResourceTypeNameUser || created.Meta.Version == "" ||
		created.Meta.Created == "" {
		t.Fatalf("created meta = %+v", created.Meta)
	}
	if created.UserName != "Alice" || created.ExternalID != "ext-1" || created.Password != "" {
		t.Fatalf("created user = %+v", created)
	}
	account, err := users.GetUser(ctx, created.ID)
	if err != nil {
		t.Fatalf("underlying GetUser error = %v", err)
	}
	if account.Username != "Alice" || account.Email != "alice@example.com" || account.Phone != "+15550100" {
		t.Fatalf("account identities = %+v", account)
	}
	if account.Status != auth.UserActive {
		t.Fatalf("account status = %q", account.Status)
	}
	if account.PasswordHash != "" {
		t.Fatalf("SCIM password leaked into PasswordHash: %q", account.PasswordHash)
	}
	if account.GivenName != "Alice" || account.FamilyName != "Smith" || account.MiddleName != "Q" {
		t.Fatalf("account name = %+v", account)
	}
	if account.DisplayName != "Alice Smith" || account.Nickname != "Ali" ||
		account.Profile != "https://example.com/alice" || account.Locale != "en-US" || account.Zoneinfo != "UTC" {
		t.Fatalf("account profile = %+v", account)
	}
	if account.Picture != "https://example.com/alice.png" {
		t.Fatalf("account picture = %q", account.Picture)
	}
	if account.Address["locality"] != "Springfield" || account.Address["country"] != "US" ||
		account.Address["street_address"] != "1 Main St" || account.Address["postal_code"] != "62701" {
		t.Fatalf("account address = %+v", account.Address)
	}
	if account.Metadata["title"] != "Engineer" || account.Metadata["userType"] != "Employee" ||
		account.Metadata["preferredLanguage"] != "en-US" || account.Metadata["employeeNumber"] != "E-42" ||
		account.Metadata["costCenter"] != "CC-1" || account.Metadata["organization"] != "Acme" ||
		account.Metadata["division"] != "R&D" || account.Metadata["department"] != "Engineering" {
		t.Fatalf("account metadata = %+v", account.Metadata)
	}
	if account.CreatedAt.IsZero() || account.UpdatedAt.IsZero() {
		t.Fatalf("account timestamps = %+v", account)
	}

	if _, err := adapter.CreateUser(ctx, nil); !errors.Is(err, ErrInvalidValue) {
		t.Fatalf("CreateUser(nil) error = %v, want ErrInvalidValue", err)
	}
	if _, err := adapter.CreateUser(ctx, &User{UserName: "alice"}); !errors.Is(err, ErrUniqueness) {
		t.Fatalf("duplicate CreateUser error = %v, want ErrUniqueness", err)
	}
}

func TestUserStoreAdapterGetAndListUsers(t *testing.T) {
	adapter, _ := newAdapter(t)
	ctx := context.Background()
	for _, fixture := range []struct {
		name  string
		title string
	}{
		{"alice", "Engineer"},
		{"bob", "Manager"},
		{"carol", "Engineer"},
	} {
		if _, err := adapter.CreateUser(ctx, &User{UserName: fixture.name, Title: fixture.title}); err != nil {
			t.Fatalf("CreateUser %s error = %v", fixture.name, err)
		}
	}
	filter, err := ParseFilter(`title eq "Engineer" and userName sw "a"`)
	if err != nil {
		t.Fatalf("ParseFilter error = %v", err)
	}
	page, total, err := adapter.ListUsers(ctx, ListQuery{Filter: filter, Count: -1})
	if err != nil {
		t.Fatalf("ListUsers filtered error = %v", err)
	}
	if total != 1 || len(page) != 1 || page[0].UserName != "alice" {
		t.Fatalf("filtered page = %v, total = %d", userNames(page), total)
	}
	page, total, err = adapter.ListUsers(ctx, ListQuery{
		SortBy:     "userName",
		SortOrder:  SortDescending,
		StartIndex: 1,
		Count:      2,
	})
	if err != nil {
		t.Fatalf("ListUsers sorted error = %v", err)
	}
	if total != 3 || len(page) != 2 || page[0].UserName != "carol" || page[1].UserName != "bob" {
		t.Fatalf("sorted page = %v, total = %d", userNames(page), total)
	}
	page, total, err = adapter.ListUsers(ctx, ListQuery{StartIndex: 1, Count: 0})
	if err != nil {
		t.Fatalf("ListUsers zero count error = %v", err)
	}
	if total != 3 || len(page) != 0 {
		t.Fatalf("zero count page = %v, total = %d", userNames(page), total)
	}
	page, total, err = adapter.ListUsers(ctx, ListQuery{StartIndex: 99, Count: 10})
	if err != nil {
		t.Fatalf("ListUsers out of range error = %v", err)
	}
	if total != 3 || len(page) != 0 {
		t.Fatalf("out of range page = %v, total = %d", userNames(page), total)
	}
	if _, err := adapter.GetUser(ctx, "missing"); !errors.Is(err, ErrNotFound) {
		t.Fatalf("GetUser missing error = %v, want ErrNotFound", err)
	}
}

func TestUserStoreAdapterReplacePreservesAccountState(t *testing.T) {
	adapter, users := newAdapter(t)
	ctx := context.Background()
	createdAt := time.Date(2024, 1, 2, 3, 4, 5, 0, time.UTC)
	updatedAt := createdAt.Add(time.Hour)
	seed := &auth.User{
		ID:                  "usr-seed",
		Username:            "alice",
		Email:               "alice@example.com",
		EmailVerified:       true,
		Phone:               "+15550100",
		PhoneVerified:       true,
		DisplayName:         "Alice",
		Picture:             "https://example.com/old.png",
		Website:             "https://alice.example",
		Gender:              "female",
		Birthdate:           "1990-01-01",
		Status:              auth.UserActive,
		PasswordHash:        "$test$hash",
		PasswordChangedAt:   createdAt,
		PasswordHistory:     []string{"$test$old"},
		MFAEnabled:          true,
		FailedLoginAttempts: 2,
		LockedUntil:         createdAt.Add(time.Minute),
		LastLoginAt:         createdAt,
		LastLoginIP:         "192.0.2.10",
		CreatedAt:           createdAt,
		UpdatedAt:           updatedAt,
		Metadata:            map[string]string{"app": "keep", "title": "Old", "department": "Old"},
	}
	if err := users.CreateUser(ctx, seed); err != nil {
		t.Fatalf("seed CreateUser error = %v", err)
	}
	before, err := adapter.GetUser(ctx, seed.ID)
	if err != nil {
		t.Fatalf("GetUser before replace error = %v", err)
	}
	replaced, err := adapter.ReplaceUser(ctx, &User{
		ID:          seed.ID,
		UserName:    "alice2",
		DisplayName: "Alice Two",
		Title:       "Lead",
		Active:      boolPtr(false),
		Emails:      []MultiValue{{Value: "alice@example.com", Primary: true}},
		PhoneNumbers: []MultiValue{
			{Value: "+15550100", Primary: true},
		},
		EnterpriseUser: &EnterpriseUser{Department: "Platform"},
	})
	if err != nil {
		t.Fatalf("ReplaceUser error = %v", err)
	}
	if replaced.UserName != "alice2" || replaced.ActiveValue() || replaced.Title != "Lead" {
		t.Fatalf("replaced user = %+v", replaced)
	}
	if replaced.EnterpriseUser == nil || replaced.EnterpriseUser.Department != "Platform" {
		t.Fatalf("replaced enterprise = %+v", replaced.EnterpriseUser)
	}
	if replaced.Meta == nil || replaced.Meta.Version == "" || replaced.Meta.Version == before.Meta.Version {
		t.Fatalf("versions before = %q after = %+v", before.Meta.Version, replaced.Meta)
	}
	if replaced.Meta.Created != formatTime(createdAt) {
		t.Fatalf("meta created = %q, want %q", replaced.Meta.Created, formatTime(createdAt))
	}
	account, err := users.GetUser(ctx, seed.ID)
	if err != nil {
		t.Fatalf("underlying GetUser error = %v", err)
	}
	if account.Status != auth.UserDisabled {
		t.Fatalf("account status = %q, want disabled", account.Status)
	}
	if account.PasswordHash != "$test$hash" || account.PasswordChangedAt != createdAt {
		t.Fatalf("password state was not preserved: %+v", account)
	}
	if len(account.PasswordHistory) != 1 || account.PasswordHistory[0] != "$test$old" {
		t.Fatalf("password history = %v", account.PasswordHistory)
	}
	if !account.EmailVerified || !account.PhoneVerified || !account.MFAEnabled {
		t.Fatalf("verification or MFA state was not preserved: %+v", account)
	}
	if account.FailedLoginAttempts != 2 || account.LastLoginIP != "192.0.2.10" || !account.LastLoginAt.Equal(createdAt) {
		t.Fatalf("login state was not preserved: %+v", account)
	}
	if account.Website != "https://alice.example" || account.Gender != "female" || account.Birthdate != "1990-01-01" {
		t.Fatalf("profile-only state was not preserved: %+v", account)
	}
	if !account.CreatedAt.Equal(createdAt) {
		t.Fatalf("created time = %v, want %v", account.CreatedAt, createdAt)
	}
	if !account.UpdatedAt.After(updatedAt) {
		t.Fatalf("updated time = %v, want after %v", account.UpdatedAt, updatedAt)
	}
	if account.Metadata["app"] != "keep" || account.Metadata["title"] != "Lead" ||
		account.Metadata["department"] != "Platform" {
		t.Fatalf("metadata = %+v", account.Metadata)
	}
	if _, ok := account.Metadata["organization"]; ok {
		t.Fatalf("stale managed metadata survived: %+v", account.Metadata)
	}
	if _, err := adapter.ReplaceUser(ctx, &User{ID: "missing", UserName: "x"}); !errors.Is(err, ErrNotFound) {
		t.Fatalf("ReplaceUser missing error = %v, want ErrNotFound", err)
	}
	if _, err := adapter.ReplaceUser(ctx, &User{UserName: "x"}); !errors.Is(err, ErrInvalidValue) {
		t.Fatalf("ReplaceUser without ID error = %v, want ErrInvalidValue", err)
	}
	if _, err := adapter.ReplaceUser(ctx, nil); !errors.Is(err, ErrInvalidValue) {
		t.Fatalf("ReplaceUser nil error = %v, want ErrInvalidValue", err)
	}
}

func TestUserStoreAdapterDeleteAndGroups(t *testing.T) {
	adapter, _ := newAdapter(t)
	ctx := context.Background()
	user, err := adapter.CreateUser(ctx, &User{UserName: "alice"})
	if err != nil {
		t.Fatalf("CreateUser error = %v", err)
	}
	if err := adapter.DeleteUser(ctx, user.ID); err != nil {
		t.Fatalf("DeleteUser error = %v", err)
	}
	if _, err := adapter.GetUser(ctx, user.ID); !errors.Is(err, ErrNotFound) {
		t.Fatalf("GetUser after delete error = %v", err)
	}
	if err := adapter.DeleteUser(ctx, user.ID); !errors.Is(err, ErrNotFound) {
		t.Fatalf("DeleteUser twice error = %v, want ErrNotFound", err)
	}

	group, err := adapter.CreateGroup(ctx, &Group{
		DisplayName: "Admins",
		Members:     []GroupMember{{Value: "u1", Display: "Alice"}},
	})
	if err != nil {
		t.Fatalf("CreateGroup error = %v", err)
	}
	if group.ID == "" || group.Meta == nil || group.Meta.ResourceType != ResourceTypeNameGroup {
		t.Fatalf("group = %+v", group)
	}
	if _, err := adapter.CreateGroup(ctx, &Group{DisplayName: "admins"}); !errors.Is(err, ErrUniqueness) {
		t.Fatalf("duplicate group error = %v, want ErrUniqueness", err)
	}
	got, err := adapter.GetGroup(ctx, group.ID)
	if err != nil {
		t.Fatalf("GetGroup error = %v", err)
	}
	if got.DisplayName != "Admins" || len(got.Members) != 1 {
		t.Fatalf("group = %+v", got)
	}
	replaced, err := adapter.ReplaceGroup(ctx, &Group{ID: group.ID, DisplayName: "Operators"})
	if err != nil {
		t.Fatalf("ReplaceGroup error = %v", err)
	}
	if replaced.DisplayName != "Operators" || len(replaced.Members) != 0 {
		t.Fatalf("replaced group = %+v", replaced)
	}
	groups, total, err := adapter.ListGroups(ctx, ListQuery{Count: -1})
	if err != nil {
		t.Fatalf("ListGroups error = %v", err)
	}
	if total != 1 || len(groups) != 1 || groups[0].DisplayName != "Operators" {
		t.Fatalf("groups = %+v, total = %d", groups, total)
	}
	if err := adapter.DeleteGroup(ctx, group.ID); err != nil {
		t.Fatalf("DeleteGroup error = %v", err)
	}
	if _, err := adapter.GetGroup(ctx, group.ID); !errors.Is(err, ErrNotFound) {
		t.Fatalf("GetGroup after delete error = %v", err)
	}
}

func TestTranslateAuthStoreError(t *testing.T) {
	cases := []struct {
		err  error
		want error
	}{
		{auth.ErrUserNotFound, ErrNotFound},
		{auth.ErrUserExists, ErrUniqueness},
		{auth.ErrConflict, ErrUniqueness},
		{auth.ErrInvalidRequest, ErrInvalidValue},
		{auth.ErrInvalidConfig, ErrInvalidValue},
		{auth.ErrNotSupported, ErrUnsupported},
		{errs.Detail(auth.ErrUserExists, "duplicate | 重复"), ErrUniqueness},
		{errs.Detail(auth.ErrInvalidRequest, "bad | 非法"), ErrInvalidValue},
		{errors.New("storage exploded"), ErrStoreUnavailable},
	}
	for _, testCase := range cases {
		got := translateAuthStoreError(testCase.err)
		if !errors.Is(got, testCase.want) {
			t.Fatalf("translateAuthStoreError(%v) = %v, want %v", testCase.err, got, testCase.want)
		}
	}
	if got := translateAuthStoreError(nil); got != nil {
		t.Fatalf("translateAuthStoreError(nil) = %v", got)
	}
}
