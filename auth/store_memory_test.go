package auth

import (
	"context"
	"errors"
	"testing"
	"time"
)

func mustCreateMemoryUser(t *testing.T, store *MemoryUserStore, user *User) *User {
	t.Helper()
	if err := store.CreateUser(context.Background(), user); err != nil {
		t.Fatalf("CreateUser(%q): %v", user.ID, err)
	}
	return user
}

func TestNewMemoryStores(t *testing.T) {
	stores := NewMemoryStores()
	if stores.Users == nil || stores.Sessions == nil || stores.Identities == nil ||
		stores.Credentials == nil || stores.Audits == nil || stores.Tokens == nil {
		t.Fatalf("incomplete stores: %+v", stores)
	}
}

func TestMemoryUserStoreLifecycle(t *testing.T) {
	store := NewMemoryUserStore()
	ctx := context.Background()
	if err := store.CreateUser(ctx, nil); !errors.Is(err, ErrInvalidRequest) {
		t.Fatalf("nil user = %v", err)
	}
	if err := store.CreateUser(ctx, &User{}); !errors.Is(err, ErrInvalidRequest) {
		t.Fatalf("empty id = %v", err)
	}

	base := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
	alice := mustCreateMemoryUser(t, store, &User{
		ID: "u1", Username: " Alice ", Email: "Alice@Example.COM", Phone: "+86 138-0000-0000",
		Status: UserActive, CreatedAt: base, Metadata: map[string]string{"key": "value"},
	})
	if got, err := store.GetUser(ctx, "u1"); err != nil || got.Username != " Alice " {
		t.Fatalf("GetUser = %+v %v", got, err)
	}
	for _, lookup := range []struct {
		name string
		fn   func() (*User, error)
	}{
		{"username", func() (*User, error) { return store.GetUserByUsername(ctx, "ALICE") }},
		{"email", func() (*User, error) { return store.GetUserByEmail(ctx, " alice@example.com ") }},
		{"phone", func() (*User, error) { return store.GetUserByPhone(ctx, "+86 138 0000 0000") }},
	} {
		got, err := lookup.fn()
		if err != nil || got.ID != "u1" {
			t.Fatalf("%s lookup = %+v %v", lookup.name, got, err)
		}
	}
	if _, err := store.GetUser(ctx, "missing"); !errors.Is(err, ErrUserNotFound) {
		t.Fatalf("missing user = %v", err)
	}
	if _, err := store.GetUserByUsername(ctx, "missing"); !errors.Is(err, ErrUserNotFound) {
		t.Fatalf("missing username = %v", err)
	}
	if _, err := store.GetUserByEmail(ctx, "missing@example.com"); !errors.Is(err, ErrUserNotFound) {
		t.Fatalf("missing email = %v", err)
	}
	if _, err := store.GetUserByPhone(ctx, "10086"); !errors.Is(err, ErrUserNotFound) {
		t.Fatalf("missing phone = %v", err)
	}

	// Returned records are deep copies. | 返回的记录是深拷贝。
	alice.Metadata["key"] = "mutated"
	stored, _ := store.GetUser(ctx, "u1")
	if stored.Metadata["key"] != "value" {
		t.Fatal("store retained caller's map")
	}
	stored.Metadata["key"] = "mutated"
	again, _ := store.GetUser(ctx, "u1")
	if again.Metadata["key"] != "value" {
		t.Fatal("returned user mutation reached the store")
	}

	if err := store.CreateUser(ctx, &User{ID: "u1", Username: "other"}); !errors.Is(err, ErrUserExists) {
		t.Fatalf("duplicate id = %v", err)
	}
	for _, duplicate := range []*User{
		{ID: "u2", Username: "alice"},
		{ID: "u3", Email: "ALICE@example.com"},
		{ID: "u4", Phone: "+8613800000000"},
	} {
		if err := store.CreateUser(ctx, duplicate); !errors.Is(err, ErrUserExists) {
			t.Fatalf("duplicate %+v = %v", duplicate, err)
		}
	}

	if err := store.UpdateUser(ctx, nil); !errors.Is(err, ErrInvalidRequest) {
		t.Fatalf("nil update = %v", err)
	}
	if err := store.UpdateUser(ctx, &User{ID: "missing"}); !errors.Is(err, ErrUserNotFound) {
		t.Fatalf("missing update = %v", err)
	}

	bob := mustCreateMemoryUser(t, store, &User{ID: "u2", Username: "bob", Email: "bob@example.com", CreatedAt: base.Add(time.Hour)})
	conflict := bob.Clone()
	conflict.Username = "ALICE"
	if err := store.UpdateUser(ctx, conflict); !errors.Is(err, ErrUserExists) {
		t.Fatalf("username conflict = %v", err)
	}
	conflict = bob.Clone()
	conflict.Email = "alice@example.com"
	if err := store.UpdateUser(ctx, conflict); !errors.Is(err, ErrUserExists) {
		t.Fatalf("email conflict = %v", err)
	}
	conflict = bob.Clone()
	conflict.Phone = "+8613800000000"
	if err := store.UpdateUser(ctx, conflict); !errors.Is(err, ErrUserExists) {
		t.Fatalf("phone conflict = %v", err)
	}

	renamed := alice.Clone()
	renamed.Username = "alice-new"
	renamed.Email = "alice-new@example.com"
	renamed.Phone = ""
	renamed.DisplayName = "Alice"
	renamed.Status = UserDisabled
	if err := store.UpdateUser(ctx, renamed); err != nil {
		t.Fatalf("rename: %v", err)
	}
	if _, err := store.GetUserByUsername(ctx, "alice"); !errors.Is(err, ErrUserNotFound) {
		t.Fatalf("old username still indexed = %v", err)
	}
	if got, err := store.GetUserByUsername(ctx, "alice-new"); err != nil || got.ID != "u1" {
		t.Fatalf("new username = %+v %v", got, err)
	}
	if _, err := store.GetUserByEmail(ctx, "alice@example.com"); !errors.Is(err, ErrUserNotFound) {
		t.Fatalf("old email still indexed = %v", err)
	}

	if _, total, err := store.ListUsers(ctx, UserQuery{Query: "ALICE"}); err != nil || total != 1 {
		t.Fatalf("query total = %d %v", total, err)
	}
	if users, total, err := store.ListUsers(ctx, UserQuery{Status: UserDisabled}); err != nil || total != 1 || users[0].ID != "u1" {
		t.Fatalf("status filter = %+v %d %v", users, total, err)
	}
	if users, total, err := store.ListUsers(ctx, UserQuery{Limit: 1, Offset: 1}); err != nil || total != 2 || len(users) != 1 {
		t.Fatalf("pagination = %d %d %v", len(users), total, err)
	}
	if users, total, err := store.ListUsers(ctx, UserQuery{Offset: -5, Limit: 100}); err != nil || total != 2 || len(users) != 2 {
		t.Fatalf("negative offset = %d %d %v", len(users), total, err)
	}
	if users, total, err := store.ListUsers(ctx, UserQuery{Offset: 100}); err != nil || total != 2 || len(users) != 0 {
		t.Fatalf("offset beyond total = %d %d %v", len(users), total, err)
	}

	if err := store.DeleteUser(ctx, "missing"); !errors.Is(err, ErrUserNotFound) {
		t.Fatalf("delete missing = %v", err)
	}
	if err := store.DeleteUser(ctx, "u1"); err != nil {
		t.Fatalf("delete: %v", err)
	}
	if _, err := store.GetUser(ctx, "u1"); !errors.Is(err, ErrUserNotFound) {
		t.Fatalf("deleted user = %v", err)
	}
	if err := store.CreateUser(ctx, &User{ID: "u9", Username: "alice-new"}); err != nil {
		t.Fatalf("reuse deleted username: %v", err)
	}
}

func TestMemorySessionStore(t *testing.T) {
	store := NewMemorySessionStore()
	ctx := context.Background()
	now := time.Date(2026, 2, 1, 0, 0, 0, 0, time.UTC)
	if err := store.CreateSession(ctx, nil); !errors.Is(err, ErrInvalidRequest) {
		t.Fatalf("nil session = %v", err)
	}
	if err := store.CreateSession(ctx, &Session{}); !errors.Is(err, ErrInvalidRequest) {
		t.Fatalf("empty id = %v", err)
	}
	first := &Session{ID: "s1", UserID: "u1", CreatedAt: now, Data: map[string]string{"k": "v"}}
	if err := store.CreateSession(ctx, first); err != nil {
		t.Fatalf("create: %v", err)
	}
	if err := store.CreateSession(ctx, &Session{ID: "s1", UserID: "u1"}); !errors.Is(err, ErrConflict) {
		t.Fatalf("duplicate = %v", err)
	}
	first.Data["k"] = "mutated"
	stored, err := store.GetSession(ctx, "s1")
	if err != nil || stored.Data["k"] != "v" {
		t.Fatalf("deep copy = %+v %v", stored, err)
	}
	stored.Data["k"] = "mutated"
	stored, _ = store.GetSession(ctx, "s1")
	if stored.Data["k"] != "v" {
		t.Fatal("returned session mutation reached the store")
	}
	if _, err := store.GetSession(ctx, "missing"); !errors.Is(err, ErrSessionNotFound) {
		t.Fatalf("missing get = %v", err)
	}
	if err := store.UpdateSession(ctx, nil); !errors.Is(err, ErrInvalidRequest) {
		t.Fatalf("nil update = %v", err)
	}
	if err := store.UpdateSession(ctx, &Session{ID: "missing"}); !errors.Is(err, ErrSessionNotFound) {
		t.Fatalf("missing update = %v", err)
	}
	update := stored.Clone()
	update.UserAgent = "agent"
	if err := store.UpdateSession(ctx, update); err != nil {
		t.Fatalf("update: %v", err)
	}
	stored, _ = store.GetSession(ctx, "s1")
	if stored.UserAgent != "agent" {
		t.Fatal("update not stored")
	}

	second := &Session{ID: "s2", UserID: "u1", CreatedAt: now.Add(time.Minute)}
	older := &Session{ID: "s0", UserID: "u1", CreatedAt: now.Add(-time.Minute)}
	other := &Session{ID: "s3", UserID: "u2", CreatedAt: now}
	for _, session := range []*Session{second, older, other} {
		if err := store.CreateSession(ctx, session); err != nil {
			t.Fatalf("create %s: %v", session.ID, err)
		}
	}
	sessions, err := store.ListSessionsByUser(ctx, "u1")
	if err != nil || len(sessions) != 3 || sessions[0].ID != "s2" || sessions[2].ID != "s0" {
		t.Fatalf("list = %+v %v", sessions, err)
	}
	if n, err := store.DeleteSessionsByUser(ctx, "u1"); err != nil || n != 3 {
		t.Fatalf("delete by user = %d %v", n, err)
	}
	if n, err := store.DeleteSessionsByUser(ctx, "u1"); err != nil || n != 0 {
		t.Fatalf("second delete by user = %d %v", n, err)
	}

	if err := store.DeleteSession(ctx, "missing"); !errors.Is(err, ErrSessionNotFound) {
		t.Fatalf("delete missing = %v", err)
	}
	if err := store.DeleteSession(ctx, "s3"); err != nil {
		t.Fatalf("delete existing = %v", err)
	}
	for _, session := range []*Session{
		{ID: "expired", UserID: "u3", ExpiresAt: now},
		{ID: "future", UserID: "u3", ExpiresAt: now.Add(time.Hour)},
		{ID: "forever", UserID: "u3"},
	} {
		if err := store.CreateSession(ctx, session); err != nil {
			t.Fatalf("create expiry fixture: %v", err)
		}
	}
	if n, err := store.DeleteExpiredSessions(ctx, now); err != nil || n != 1 {
		t.Fatalf("delete expired = %d %v", n, err)
	}
	if _, err := store.GetSession(ctx, "forever"); err != nil {
		t.Fatalf("session without deadline deleted: %v", err)
	}
}

func TestMemoryIdentityStore(t *testing.T) {
	store := NewMemoryIdentityStore()
	ctx := context.Background()
	if err := store.CreateIdentity(ctx, nil); !errors.Is(err, ErrInvalidRequest) {
		t.Fatalf("nil identity = %v", err)
	}
	for _, bad := range []*Identity{{}, {Provider: "p"}, {Provider: "p", Subject: "s"}, {UserID: "u"}} {
		if err := store.CreateIdentity(ctx, bad); !errors.Is(err, ErrInvalidRequest) {
			t.Fatalf("bad identity %+v = %v", bad, err)
		}
	}
	identity := &Identity{Provider: "google", Subject: "sub-1", UserID: "u1", Raw: map[string]string{"k": "v"}}
	if err := store.CreateIdentity(ctx, identity); err != nil {
		t.Fatalf("create: %v", err)
	}
	if err := store.CreateIdentity(ctx, identity.Clone()); !errors.Is(err, ErrIdentityExists) {
		t.Fatalf("duplicate = %v", err)
	}
	identity.Raw["k"] = "mutated"
	got, err := store.GetIdentity(ctx, "google", "sub-1")
	if err != nil || got.Raw["k"] != "v" {
		t.Fatalf("get = %+v %v", got, err)
	}
	if _, err := store.GetIdentity(ctx, "missing", "sub"); !errors.Is(err, ErrIdentityNotFound) {
		t.Fatalf("missing = %v", err)
	}
	if err := store.CreateIdentity(ctx, &Identity{Provider: "github", Subject: "sub-2", UserID: "u1"}); err != nil {
		t.Fatalf("create second: %v", err)
	}
	if err := store.CreateIdentity(ctx, &Identity{Provider: "google", Subject: "sub-3", UserID: "u2"}); err != nil {
		t.Fatalf("create other user: %v", err)
	}
	list, err := store.ListIdentitiesByUser(ctx, "u1")
	if err != nil || len(list) != 2 || list[0].Provider != "github" || list[1].Provider != "google" {
		t.Fatalf("list = %+v %v", list, err)
	}
	if err := store.UpdateIdentity(ctx, nil); !errors.Is(err, ErrInvalidRequest) {
		t.Fatalf("nil update = %v", err)
	}
	if err := store.UpdateIdentity(ctx, &Identity{Provider: "missing", Subject: "sub"}); !errors.Is(err, ErrIdentityNotFound) {
		t.Fatalf("missing update = %v", err)
	}
	update := got.Clone()
	update.Email = "new@example.com"
	if err := store.UpdateIdentity(ctx, update); err != nil {
		t.Fatalf("update: %v", err)
	}
	got, _ = store.GetIdentity(ctx, "google", "sub-1")
	if got.Email != "new@example.com" {
		t.Fatal("identity update not stored")
	}
	if err := store.DeleteIdentity(ctx, "missing", "sub"); !errors.Is(err, ErrIdentityNotFound) {
		t.Fatalf("delete missing = %v", err)
	}
	if err := store.DeleteIdentity(ctx, "google", "sub-1"); err != nil {
		t.Fatalf("delete: %v", err)
	}
	if _, err := store.GetIdentity(ctx, "google", "sub-1"); !errors.Is(err, ErrIdentityNotFound) {
		t.Fatalf("deleted identity = %v", err)
	}
}

func TestMemoryCredentialStore(t *testing.T) {
	store := NewMemoryCredentialStore()
	ctx := context.Background()
	now := time.Date(2026, 3, 1, 0, 0, 0, 0, time.UTC)
	if err := store.CreateCredential(ctx, nil); !errors.Is(err, ErrInvalidRequest) {
		t.Fatalf("nil credential = %v", err)
	}
	for _, bad := range []*Credential{{}, {ID: "id"}, {UserID: "user"}} {
		if err := store.CreateCredential(ctx, bad); !errors.Is(err, ErrInvalidRequest) {
			t.Fatalf("bad credential %+v = %v", bad, err)
		}
	}
	first := &Credential{ID: "c1", UserID: "u1", Type: CredentialTOTP, CreatedAt: now, Data: map[string]string{"k": "v"}}
	if err := store.CreateCredential(ctx, first); err != nil {
		t.Fatalf("create: %v", err)
	}
	if err := store.CreateCredential(ctx, first.Clone()); !errors.Is(err, ErrCredentialExists) {
		t.Fatalf("duplicate = %v", err)
	}
	first.Data["k"] = "mutated"
	got, err := store.GetCredential(ctx, "c1")
	if err != nil || got.Data["k"] != "v" {
		t.Fatalf("get = %+v %v", got, err)
	}
	if _, err := store.GetCredential(ctx, "missing"); !errors.Is(err, ErrCredentialNotFound) {
		t.Fatalf("missing = %v", err)
	}
	if err := store.CreateCredential(ctx, &Credential{ID: "c2", UserID: "u1", Type: CredentialWebAuthn, CreatedAt: now.Add(time.Minute)}); err != nil {
		t.Fatalf("create second: %v", err)
	}
	if err := store.CreateCredential(ctx, &Credential{ID: "c3", UserID: "u2", Type: CredentialTOTP, CreatedAt: now}); err != nil {
		t.Fatalf("create other: %v", err)
	}
	list, err := store.ListCredentialsByUser(ctx, "u1")
	if err != nil || len(list) != 2 || list[0].ID != "c1" || list[1].ID != "c2" {
		t.Fatalf("list user = %+v %v", list, err)
	}
	list, err = store.ListCredentialsByUserType(ctx, "u1", CredentialTOTP)
	if err != nil || len(list) != 1 || list[0].ID != "c1" {
		t.Fatalf("list type = %+v %v", list, err)
	}
	if err := store.UpdateCredential(ctx, nil); !errors.Is(err, ErrInvalidRequest) {
		t.Fatalf("nil update = %v", err)
	}
	if err := store.UpdateCredential(ctx, &Credential{ID: "missing"}); !errors.Is(err, ErrCredentialNotFound) {
		t.Fatalf("missing update = %v", err)
	}
	update := got.Clone()
	update.Name = "phone"
	if err := store.UpdateCredential(ctx, update); err != nil {
		t.Fatalf("update: %v", err)
	}
	got, _ = store.GetCredential(ctx, "c1")
	if got.Name != "phone" {
		t.Fatal("credential update not stored")
	}
	if err := store.DeleteCredential(ctx, "missing"); !errors.Is(err, ErrCredentialNotFound) {
		t.Fatalf("delete missing = %v", err)
	}
	if err := store.DeleteCredential(ctx, "c1"); err != nil {
		t.Fatalf("delete: %v", err)
	}
	if _, err := store.GetCredential(ctx, "c1"); !errors.Is(err, ErrCredentialNotFound) {
		t.Fatalf("deleted credential = %v", err)
	}
}

func TestMemoryAuditStore(t *testing.T) {
	store := NewMemoryAuditStore()
	ctx := context.Background()
	if err := store.RecordAudit(ctx, nil); !errors.Is(err, ErrInvalidRequest) {
		t.Fatalf("nil event = %v", err)
	}
	base := time.Date(2026, 4, 1, 0, 0, 0, 0, time.UTC)
	events := []*AuditEvent{
		{ID: "e1", Type: "login", ActorID: "a1", UserID: "u1", Outcome: "success", At: base, Detail: map[string]string{"k": "v"}},
		{ID: "e2", Type: "login", ActorID: "a2", UserID: "u1", Outcome: "failure", At: base.Add(time.Minute)},
		{ID: "e3", Type: "logout", ActorID: "a1", UserID: "u2", Outcome: "success", At: base.Add(2 * time.Minute)},
	}
	for _, event := range events {
		if err := store.RecordAudit(ctx, event); err != nil {
			t.Fatalf("record %s: %v", event.ID, err)
		}
	}
	events[0].Detail["k"] = "mutated"
	list, total, err := store.ListAudit(ctx, AuditQuery{})
	if err != nil || total != 3 || len(list) != 3 || list[0].ID != "e1" {
		t.Fatalf("list all = %+v %d %v", list, total, err)
	}
	if list[0].Detail["k"] != "v" {
		t.Fatal("audit input map alias")
	}
	list[0].Detail["k"] = "mutated"
	list, _, _ = store.ListAudit(ctx, AuditQuery{})
	if list[0].Detail["k"] != "v" {
		t.Fatal("audit output mutation reached the store")
	}

	cases := []struct {
		query AuditQuery
		total int
	}{
		{AuditQuery{Type: "login"}, 2},
		{AuditQuery{UserID: "u1"}, 2},
		{AuditQuery{ActorID: "a1"}, 2},
		{AuditQuery{Outcome: "failure"}, 1},
		{AuditQuery{Since: base.Add(time.Minute)}, 2},
		{AuditQuery{Until: base.Add(time.Minute)}, 2},
		{AuditQuery{Since: base.Add(time.Minute), Until: base.Add(time.Minute)}, 1},
		{AuditQuery{Type: "missing"}, 0},
		{AuditQuery{Descending: true}, 3},
		{AuditQuery{Limit: 1, Offset: 1}, 3},
		{AuditQuery{Offset: 100}, 3},
	}
	for _, tc := range cases {
		list, total, err := store.ListAudit(ctx, tc.query)
		if err != nil || total != tc.total {
			t.Fatalf("query %+v = total %d %v", tc.query, total, err)
		}
		if tc.query.Descending && len(list) > 0 && list[0].ID != "e3" {
			t.Fatalf("descending first = %q", list[0].ID)
		}
		if tc.query.Limit == 1 && len(list) != 1 {
			t.Fatalf("limit not applied: %d", len(list))
		}
	}
}

func TestMemoryTokenStore(t *testing.T) {
	store := NewMemoryTokenStore()
	ctx := context.Background()
	now := time.Date(2026, 5, 1, 0, 0, 0, 0, time.UTC)
	if err := store.CreateToken(ctx, nil); !errors.Is(err, ErrInvalidRequest) {
		t.Fatalf("nil token = %v", err)
	}
	for _, bad := range []*OneTimeToken{{}, {Hash: "hash"}, {Purpose: "purpose"}} {
		if err := store.CreateToken(ctx, bad); !errors.Is(err, ErrInvalidRequest) {
			t.Fatalf("bad token %+v = %v", bad, err)
		}
	}
	if _, err := store.ConsumeToken(ctx, "missing", "purpose", now); !errors.Is(err, ErrTokenInvalid) {
		t.Fatalf("missing consume = %v", err)
	}
	if _, err := store.PeekToken(ctx, "missing", "purpose", now); !errors.Is(err, ErrTokenInvalid) {
		t.Fatalf("missing peek = %v", err)
	}
	token := &OneTimeToken{Hash: "hash", Purpose: "purpose", UserID: "u1", ExpiresAt: now.Add(time.Hour), Metadata: map[string]string{"k": "v"}}
	if err := store.CreateToken(ctx, token); err != nil {
		t.Fatalf("create: %v", err)
	}
	token.Metadata["k"] = "mutated"
	peeked, err := store.PeekToken(ctx, "hash", "purpose", now)
	if err != nil || peeked.Metadata["k"] != "v" || !peeked.UsedAt.IsZero() {
		t.Fatalf("peek = %+v %v", peeked, err)
	}
	peeked.Metadata["k"] = "mutated"
	peeked, _ = store.PeekToken(ctx, "hash", "purpose", now)
	if peeked.Metadata["k"] != "v" {
		t.Fatal("peek clone shares state")
	}
	consumed, err := store.ConsumeToken(ctx, "hash", "purpose", now)
	if err != nil || !consumed.UsedAt.Equal(now) {
		t.Fatalf("consume = %+v %v", consumed, err)
	}
	if _, err := store.ConsumeToken(ctx, "hash", "purpose", now); !errors.Is(err, ErrTokenUsed) {
		t.Fatalf("second consume = %v", err)
	}
	if _, err := store.PeekToken(ctx, "hash", "purpose", now); !errors.Is(err, ErrTokenUsed) {
		t.Fatalf("peek used = %v", err)
	}

	for _, fixture := range []*OneTimeToken{
		{Hash: "expired", Purpose: "purpose", UserID: "u1", ExpiresAt: now},
		{Hash: "alive", Purpose: "purpose", UserID: "u1", ExpiresAt: now.Add(time.Hour)},
		{Hash: "forever", Purpose: "purpose", UserID: "u1"},
		{Hash: "other-purpose", Purpose: "reset", UserID: "u1"},
		{Hash: "other-user", Purpose: "purpose", UserID: "u2"},
	} {
		if err := store.CreateToken(ctx, fixture); err != nil {
			t.Fatalf("create fixture %s: %v", fixture.Hash, err)
		}
	}
	if _, err := store.PeekToken(ctx, "expired", "purpose", now); !errors.Is(err, ErrTokenExpired) {
		t.Fatalf("expired peek = %v", err)
	}
	if _, err := store.ConsumeToken(ctx, "expired", "purpose", now); !errors.Is(err, ErrTokenExpired) {
		t.Fatalf("expired consume = %v", err)
	}
	if _, err := store.PeekToken(ctx, "forever", "purpose", now.Add(100*365*24*time.Hour)); err != nil {
		t.Fatalf("token without expiry = %v", err)
	}
	if n, err := store.DeleteTokensByUser(ctx, "u1", "purpose"); err != nil || n != 4 {
		t.Fatalf("delete tokens = %d %v", n, err)
	}
	if _, err := store.PeekToken(ctx, "other-purpose", "reset", now); err != nil {
		t.Fatalf("other purpose deleted: %v", err)
	}
	if _, err := store.PeekToken(ctx, "other-user", "purpose", now); err != nil {
		t.Fatalf("other user deleted: %v", err)
	}
}

func TestPageBounds(t *testing.T) {
	cases := []struct {
		offset, limit, total, start, end int
	}{
		{0, 10, 5, 0, 5},
		{-5, 10, 5, 0, 5},
		{100, 10, 5, 5, 5},
		{1, 0, 5, 1, 5},
		{1, -3, 5, 1, 5},
		{2, 2, 5, 2, 4},
		{0, 0, 0, 0, 0},
	}
	for _, tc := range cases {
		start, end := pageBounds(tc.offset, tc.limit, tc.total)
		if start != tc.start || end != tc.end {
			t.Fatalf("pageBounds(%d,%d,%d) = %d,%d", tc.offset, tc.limit, tc.total, start, end)
		}
	}
}
