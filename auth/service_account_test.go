package auth

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

// failingCredentialStore injects failures into a CredentialStore. | failingCredentialStore 向 CredentialStore 注入故障。
type failingCredentialStore struct {
	CredentialStore
	createErr error
	listErr   error
}

func (s *failingCredentialStore) CreateCredential(ctx context.Context, credential *Credential) error {
	if s.createErr != nil {
		return s.createErr
	}
	return s.CredentialStore.CreateCredential(ctx, credential)
}

func (s *failingCredentialStore) ListCredentialsByUser(ctx context.Context, userID string) ([]*Credential, error) {
	if s.listErr != nil {
		return nil, s.listErr
	}
	return s.CredentialStore.ListCredentialsByUser(ctx, userID)
}

// failingIdentityStore injects failures into an IdentityStore. | failingIdentityStore 向 IdentityStore 注入故障。
type failingIdentityStore struct {
	IdentityStore
	createErr error
	getErr    error
}

func (s *failingIdentityStore) CreateIdentity(ctx context.Context, identity *Identity) error {
	if s.createErr != nil {
		return s.createErr
	}
	return s.IdentityStore.CreateIdentity(ctx, identity)
}

func (s *failingIdentityStore) GetIdentity(ctx context.Context, provider, subject string) (*Identity, error) {
	if s.getErr != nil {
		return nil, s.getErr
	}
	return s.IdentityStore.GetIdentity(ctx, provider, subject)
}

// failingAuditStore injects failures into an AuditStore. | failingAuditStore 向 AuditStore 注入故障。
type failingAuditStore struct {
	AuditStore
	recordErr error
}

func (s *failingAuditStore) RecordAudit(ctx context.Context, event *AuditEvent) error {
	if s.recordErr != nil {
		return s.recordErr
	}
	return s.AuditStore.RecordAudit(ctx, event)
}

func TestServiceChangePassword(t *testing.T) {
	harness := newTestService(t, func(config *Config) { config.Policy.History = 3 })
	ctx := context.Background()
	user := harness.register(t, "alice")
	newPassword := "An0ther-Secret-Passphrase"

	if err := harness.service.ChangePassword(ctx, "missing", testServicePassword, newPassword); !errors.Is(err, ErrUserNotFound) {
		t.Fatalf("missing user = %v", err)
	}
	if err := harness.service.ChangePassword(ctx, user.ID, "wrong-password", newPassword); !errors.Is(err, ErrInvalidCredentials) {
		t.Fatalf("wrong password = %v", err)
	}
	if err := harness.service.ChangePassword(ctx, user.ID, testServicePassword, "short"); !errors.Is(err, ErrPasswordPolicy) {
		t.Fatalf("weak password = %v", err)
	}
	if err := harness.service.ChangePassword(ctx, user.ID, testServicePassword, testServicePassword); !errors.Is(err, ErrPasswordReused) {
		t.Fatalf("current password reuse = %v", err)
	}
	if err := harness.service.ChangePassword(ctx, user.ID, testServicePassword, newPassword); err != nil {
		t.Fatalf("ChangePassword: %v", err)
	}
	stored, _ := harness.stores.Users.GetUser(ctx, user.ID)
	if stored.PasswordHash != "fake$"+newPassword || len(stored.PasswordHistory) != 1 ||
		stored.PasswordHistory[0] != "fake$"+testServicePassword ||
		!stored.PasswordChangedAt.Equal(harness.clock.Now()) {
		t.Fatalf("changed user = %+v", stored)
	}
	if total := auditCount(t, harness.stores, AuditQuery{Type: "password.changed"}); total != 1 {
		t.Fatalf("change audit = %d", total)
	}
	if err := harness.service.ChangePassword(ctx, user.ID, newPassword, testServicePassword); !errors.Is(err, ErrPasswordReused) {
		t.Fatalf("history reuse = %v", err)
	}

	injected := errors.New("injected")
	harness.hasher.verifyErr = injected
	if err := harness.service.ChangePassword(ctx, user.ID, newPassword, "Third-Secret-Passphrase"); !errors.Is(err, ErrInvalidCredentials) {
		t.Fatalf("verify error = %v", err)
	}
	harness.hasher.verifyErr = nil
	harness.hasher.hashErr = injected
	if err := harness.service.ChangePassword(ctx, user.ID, newPassword, "Third-Secret-Passphrase"); !errors.Is(err, injected) {
		t.Fatalf("hash error = %v", err)
	}
	harness.hasher.hashErr = nil

	wrapped := &failingUserStore{UserStore: harness.stores.Users, updateErr: injected}
	harness.service.stores.Users = wrapped
	if err := harness.service.ChangePassword(ctx, user.ID, newPassword, "Third-Secret-Passphrase"); !errors.Is(err, injected) {
		t.Fatalf("update error = %v", err)
	}
}

func TestServicePasswordResetFlow(t *testing.T) {
	harness := newTestService(t, func(config *Config) { config.Policy.History = 3 })
	ctx := context.Background()
	user := harness.register(t, "alice")

	if _, _, err := harness.service.RequestPasswordReset(ctx, "ghost@example.com"); !errors.Is(err, ErrUserNotFound) {
		t.Fatalf("unknown login = %v", err)
	}
	first, returned, err := harness.service.RequestPasswordReset(ctx, " alice@example.com ")
	if err != nil || returned.ID != user.ID || first == "" {
		t.Fatalf("request reset = %q %+v %v", first, returned, err)
	}
	second, _, err := harness.service.RequestPasswordReset(ctx, "alice")
	if err != nil {
		t.Fatalf("second request: %v", err)
	}
	if _, err := harness.stores.Tokens.PeekToken(ctx, HashToken(first), PurposeResetPassword, harness.clock.Now()); !errors.Is(err, ErrTokenInvalid) {
		t.Fatalf("first token not invalidated = %v", err)
	}
	if err := harness.service.ResetPassword(ctx, "bogus-token", "Brand-New-Secret-Passphrase"); !errors.Is(err, ErrTokenInvalid) {
		t.Fatalf("invalid token = %v", err)
	}

	newPassword := "Brand-New-Secret-Passphrase"
	if err := harness.service.ResetPassword(ctx, second, "short"); !errors.Is(err, ErrPasswordPolicy) {
		t.Fatalf("weak reset = %v", err)
	}
	if err := harness.service.ResetPassword(ctx, second, testServicePassword); !errors.Is(err, ErrPasswordReused) {
		t.Fatalf("reused reset = %v", err)
	}
	login, err := harness.service.Authenticate(ctx, AuthenticateInput{Login: "alice", Password: testServicePassword})
	if err != nil || login.Session == nil {
		t.Fatalf("pre-reset login = %+v %v", login, err)
	}
	if err := harness.service.ResetPassword(ctx, second, newPassword); err != nil {
		t.Fatalf("ResetPassword: %v", err)
	}
	if _, err := harness.service.Sessions().Validate(ctx, login.Session.ID); !errors.Is(err, ErrSessionRevoked) {
		t.Fatalf("old session after reset = %v", err)
	}
	if _, err := harness.service.Authenticate(ctx, AuthenticateInput{Login: "alice", Password: testServicePassword}); !errors.Is(err, ErrInvalidCredentials) {
		t.Fatalf("old password still works = %v", err)
	}
	if _, err := harness.service.Authenticate(ctx, AuthenticateInput{Login: "alice", Password: newPassword}); err != nil {
		t.Fatalf("new password login: %v", err)
	}
	if err := harness.service.ResetPassword(ctx, second, "Another-Secret-Passphrase"); !errors.Is(err, ErrTokenUsed) {
		t.Fatalf("token reuse = %v", err)
	}
	stored, _ := harness.stores.Users.GetUser(ctx, user.ID)
	if stored.PasswordHistory[0] != "fake$"+testServicePassword || stored.FailedLoginAttempts != 0 {
		t.Fatalf("reset state = %+v", stored)
	}
	if total := auditCount(t, harness.stores, AuditQuery{Type: "password.reset"}); total != 1 {
		t.Fatalf("reset audit = %d", total)
	}
}

func TestServiceResetPreservesAdministrativeLock(t *testing.T) {
	harness := newTestService(t, nil)
	ctx := context.Background()
	user := harness.register(t, "alice")
	until := harness.clock.Now().Add(time.Hour)
	if err := harness.service.LockUser(ctx, user.ID, until); err != nil {
		t.Fatalf("LockUser: %v", err)
	}
	token, _, err := harness.service.RequestPasswordReset(ctx, "alice")
	if err != nil {
		t.Fatalf("RequestPasswordReset: %v", err)
	}
	if err := harness.service.ResetPassword(ctx, token, "Brand-New-Secret-Passphrase"); err != nil {
		t.Fatalf("ResetPassword: %v", err)
	}
	stored, _ := harness.stores.Users.GetUser(ctx, user.ID)
	if stored.Status != UserLocked || !stored.LockedUntil.Equal(until) || stored.FailedLoginAttempts != 0 {
		t.Fatalf("administrative lock not preserved: %+v", stored)
	}
}

func TestServiceResetClearsTemporaryLockout(t *testing.T) {
	harness := newTestService(t, func(config *Config) {
		config.Lockout = LockoutPolicy{MaxAttempts: 2, BaseLockout: time.Minute, MaxLockout: time.Hour}
	})
	ctx := context.Background()
	user := harness.register(t, "alice")
	for i := 0; i < 2; i++ {
		_, _ = harness.service.Authenticate(ctx, AuthenticateInput{Login: "alice", Password: "wrong"})
	}
	token, _, err := harness.service.RequestPasswordReset(ctx, "alice")
	if err != nil {
		t.Fatalf("RequestPasswordReset: %v", err)
	}
	if err := harness.service.ResetPassword(ctx, token, "Brand-New-Secret-Passphrase"); err != nil {
		t.Fatalf("ResetPassword: %v", err)
	}
	stored, _ := harness.stores.Users.GetUser(ctx, user.ID)
	if stored.Status != UserActive || !stored.LockedUntil.IsZero() || stored.FailedLoginAttempts != 0 {
		t.Fatalf("lockout not cleared: %+v", stored)
	}
}

func TestServiceResetDeletedUser(t *testing.T) {
	harness := newTestService(t, nil)
	ctx := context.Background()
	user := harness.register(t, "alice")
	token, _, err := harness.service.RequestPasswordReset(ctx, "alice")
	if err != nil {
		t.Fatalf("RequestPasswordReset: %v", err)
	}
	if err := harness.stores.Users.DeleteUser(ctx, user.ID); err != nil {
		t.Fatalf("DeleteUser: %v", err)
	}
	if err := harness.service.ResetPassword(ctx, token, "Brand-New-Secret-Passphrase"); !errors.Is(err, ErrUserNotFound) {
		t.Fatalf("deleted user reset = %v", err)
	}
}

func TestServiceEmailVerification(t *testing.T) {
	ctx := context.Background()
	harness := newTestService(t, func(config *Config) { config.RequireEmailVerification = true })
	user := harness.register(t, "alice")

	if _, err := harness.service.RequestEmailVerification(ctx, "missing"); !errors.Is(err, ErrUserNotFound) {
		t.Fatalf("missing user = %v", err)
	}
	noEmail, err := harness.service.Register(ctx, RegisterInput{Username: "noemail", Password: testServicePassword})
	if err != nil {
		t.Fatalf("register without email: %v", err)
	}
	if _, err := harness.service.RequestEmailVerification(ctx, noEmail.ID); !errors.Is(err, ErrInvalidRequest) {
		t.Fatalf("no email = %v", err)
	}

	if _, err := harness.service.Authenticate(ctx, AuthenticateInput{Login: "alice", Password: testServicePassword}); !errors.Is(err, ErrAccountPending) {
		t.Fatalf("pending login = %v", err)
	}
	token, err := harness.service.RequestEmailVerification(ctx, user.ID)
	if err != nil {
		t.Fatalf("RequestEmailVerification: %v", err)
	}
	verified, err := harness.service.VerifyEmail(ctx, token)
	if err != nil || !verified.EmailVerified || verified.Status != UserActive {
		t.Fatalf("VerifyEmail = %+v %v", verified, err)
	}
	if _, err := harness.service.VerifyEmail(ctx, token); !errors.Is(err, ErrTokenUsed) {
		t.Fatalf("token reuse = %v", err)
	}
	if _, err := harness.service.RequestEmailVerification(ctx, user.ID); !errors.Is(err, ErrInvalidRequest) {
		t.Fatalf("already verified = %v", err)
	}
	if _, err := harness.service.VerifyEmail(ctx, "bogus"); !errors.Is(err, ErrTokenInvalid) {
		t.Fatalf("invalid token = %v", err)
	}
	if total := auditCount(t, harness.stores, AuditQuery{Type: "email.verified"}); total != 1 {
		t.Fatalf("verify audit = %d", total)
	}

	expiring := harness.register(t, "expiring")
	token, err = harness.service.RequestEmailVerification(ctx, expiring.ID)
	if err != nil {
		t.Fatalf("RequestEmailVerification: %v", err)
	}
	harness.clock.Advance(25 * time.Hour)
	if _, err := harness.service.VerifyEmail(ctx, token); !errors.Is(err, ErrTokenExpired) {
		t.Fatalf("expired token = %v", err)
	}

	injected := errors.New("injected")
	updating := harness.register(t, "updating")
	token, err = harness.service.RequestEmailVerification(ctx, updating.ID)
	if err != nil {
		t.Fatalf("RequestEmailVerification: %v", err)
	}
	harness.service.stores.Users = &failingUserStore{UserStore: harness.stores.Users, updateErr: injected}
	if _, err := harness.service.VerifyEmail(ctx, token); !errors.Is(err, injected) {
		t.Fatalf("update error = %v", err)
	}
}

func TestServiceCredentials(t *testing.T) {
	harness := newTestService(t, nil)
	ctx := context.Background()
	user := harness.register(t, "alice")

	if _, err := harness.service.RegisterCredential(ctx, nil); !errors.Is(err, ErrInvalidRequest) {
		t.Fatalf("nil credential = %v", err)
	}
	if _, err := harness.service.RegisterCredential(ctx, &Credential{Type: CredentialTOTP}); !errors.Is(err, ErrInvalidRequest) {
		t.Fatalf("empty user = %v", err)
	}
	if _, err := harness.service.RegisterCredential(ctx, &Credential{UserID: "missing", Type: CredentialTOTP}); !errors.Is(err, ErrUserNotFound) {
		t.Fatalf("missing user = %v", err)
	}

	input := &Credential{UserID: user.ID, Type: CredentialTOTP, Name: "app", Secret: "s3cret", Data: map[string]string{"digits": "6"}}
	stored, err := harness.service.RegisterCredential(ctx, input)
	if err != nil {
		t.Fatalf("RegisterCredential: %v", err)
	}
	if stored.ID == "" || !strings.HasPrefix(stored.ID, "cred_") || stored.CreatedAt.IsZero() ||
		stored.UpdatedAt.IsZero() || stored.Secret != "s3cret" {
		t.Fatalf("stored credential = %+v", stored)
	}
	if input.ID != "" {
		t.Fatalf("caller credential mutated: %+v", input)
	}
	u, _ := harness.stores.Users.GetUser(ctx, user.ID)
	if !u.MFAEnabled {
		t.Fatal("MFAEnabled not set")
	}
	if total := auditCount(t, harness.stores, AuditQuery{Type: "credential.registered"}); total != 1 {
		t.Fatalf("register audit = %d", total)
	}

	// Password and disabled factors do not enable MFA. | 口令与禁用因素不会启用多因素。
	other := harness.register(t, "bob")
	if _, err := harness.service.RegisterCredential(ctx, &Credential{UserID: other.ID, Type: CredentialPassword}); err != nil {
		t.Fatalf("password credential: %v", err)
	}
	if _, err := harness.service.RegisterCredential(ctx, &Credential{UserID: other.ID, Type: CredentialHOTP, Disabled: true}); err != nil {
		t.Fatalf("disabled credential: %v", err)
	}
	u, _ = harness.stores.Users.GetUser(ctx, other.ID)
	if u.MFAEnabled {
		t.Fatal("password or disabled factor enabled MFA")
	}

	list, err := harness.service.ListCredentials(ctx, user.ID)
	if err != nil || len(list) != 1 || list[0].ID != stored.ID {
		t.Fatalf("ListCredentials = %+v %v", list, err)
	}
	if err := harness.service.RemoveCredential(ctx, "missing", stored.ID); !errors.Is(err, ErrCredentialNotFound) {
		t.Fatalf("missing credential = %v", err)
	}
	if err := harness.service.RemoveCredential(ctx, other.ID, stored.ID); !errors.Is(err, ErrCredentialNotFound) {
		t.Fatalf("wrong user = %v", err)
	}
	if err := harness.service.RemoveCredential(ctx, user.ID, stored.ID); err != nil {
		t.Fatalf("RemoveCredential: %v", err)
	}
	u, _ = harness.stores.Users.GetUser(ctx, user.ID)
	if u.MFAEnabled {
		t.Fatal("MFAEnabled not cleared")
	}
	if total := auditCount(t, harness.stores, AuditQuery{Type: "credential.removed"}); total != 1 {
		t.Fatalf("remove audit = %d", total)
	}
}

func TestServiceCredentialFailures(t *testing.T) {
	injected := errors.New("injected")
	harness := newTestService(t, nil)
	ctx := context.Background()
	user := harness.register(t, "alice")

	creds := &failingCredentialStore{CredentialStore: harness.stores.Credentials, createErr: injected}
	harness.service.stores.Credentials = creds
	if _, err := harness.service.RegisterCredential(ctx, &Credential{UserID: user.ID, Type: CredentialTOTP}); !errors.Is(err, injected) {
		t.Fatalf("create error = %v", err)
	}
	creds.createErr = nil
	stored, err := harness.service.RegisterCredential(ctx, &Credential{UserID: user.ID, Type: CredentialTOTP})
	if err != nil {
		t.Fatalf("RegisterCredential: %v", err)
	}
	creds.listErr = injected
	if _, err := harness.service.ListCredentials(ctx, user.ID); !errors.Is(err, injected) {
		t.Fatalf("list error = %v", err)
	}
	if err := harness.service.RemoveCredential(ctx, user.ID, stored.ID); !errors.Is(err, injected) {
		t.Fatalf("remove list error = %v", err)
	}

	harness.service.stores.Credentials = harness.stores.Credentials
	wrapped := &failingUserStore{UserStore: harness.stores.Users, updateErr: injected}
	harness.service.stores.Users = wrapped
	if _, err := harness.service.RegisterCredential(ctx, &Credential{UserID: user.ID, Type: CredentialTOTP}); !errors.Is(err, injected) {
		t.Fatalf("user update error = %v", err)
	}
}

func TestServiceIdentityLinking(t *testing.T) {
	harness := newTestService(t, nil)
	ctx := context.Background()
	user := harness.register(t, "alice")

	if _, err := harness.service.LinkIdentity(ctx, user.ID, nil); !errors.Is(err, ErrInvalidRequest) {
		t.Fatalf("nil identity = %v", err)
	}
	if _, err := harness.service.LinkIdentity(ctx, user.ID, &Identity{Provider: "google"}); !errors.Is(err, ErrInvalidRequest) {
		t.Fatalf("empty subject = %v", err)
	}
	if _, err := harness.service.LinkIdentity(ctx, "missing", &Identity{Provider: "google", Subject: "g-1"}); !errors.Is(err, ErrUserNotFound) {
		t.Fatalf("missing user = %v", err)
	}

	input := &Identity{Provider: "google", Subject: "g-1", Email: "alice@example.com", EmailVerified: true, Raw: map[string]string{"hd": "example.com"}}
	linked, err := harness.service.LinkIdentity(ctx, user.ID, input)
	if err != nil {
		t.Fatalf("LinkIdentity: %v", err)
	}
	if linked.UserID != user.ID || linked.CreatedAt.IsZero() || linked.UpdatedAt.IsZero() || input.UserID != "" {
		t.Fatalf("linked identity = %+v input=%+v", linked, input)
	}
	if _, err := harness.service.LinkIdentity(ctx, user.ID, input); !errors.Is(err, ErrIdentityExists) {
		t.Fatalf("duplicate link = %v", err)
	}
	got, err := harness.service.UserByIdentity(ctx, "google", "g-1")
	if err != nil || got.ID != user.ID {
		t.Fatalf("UserByIdentity = %+v %v", got, err)
	}
	if _, err := harness.service.UserByIdentity(ctx, "google", "missing"); !errors.Is(err, ErrIdentityNotFound) {
		t.Fatalf("missing identity = %v", err)
	}
	if total := auditCount(t, harness.stores, AuditQuery{Type: "identity.linked"}); total != 1 {
		t.Fatalf("link audit = %d", total)
	}

	if err := harness.service.UnlinkIdentity(ctx, "google", "missing"); !errors.Is(err, ErrIdentityNotFound) {
		t.Fatalf("unlink missing = %v", err)
	}
	if err := harness.service.UnlinkIdentity(ctx, "google", "g-1"); err != nil {
		t.Fatalf("UnlinkIdentity: %v", err)
	}
	if _, err := harness.stores.Identities.GetIdentity(ctx, "google", "g-1"); !errors.Is(err, ErrIdentityNotFound) {
		t.Fatalf("identity not removed = %v", err)
	}
	if total := auditCount(t, harness.stores, AuditQuery{Type: "identity.unlinked"}); total != 1 {
		t.Fatalf("unlink audit = %d", total)
	}
}

func TestServiceEnsureUserFromIdentity(t *testing.T) {
	harness := newTestService(t, nil)
	ctx := context.Background()
	alice := harness.register(t, "alice")

	if _, err := harness.service.EnsureUserFromIdentity(ctx, nil, false); !errors.Is(err, ErrInvalidRequest) {
		t.Fatalf("nil identity = %v", err)
	}
	existing := &Identity{Provider: "google", Subject: "g-1", Username: "oauth-carol"}
	provisioned, err := harness.service.EnsureUserFromIdentity(ctx, existing, false)
	if err != nil {
		t.Fatalf("provision: %v", err)
	}
	if provisioned.Username != "oauth-carol" || provisioned.Status != UserActive {
		t.Fatalf("provisioned user = %+v", provisioned)
	}
	again, err := harness.service.EnsureUserFromIdentity(ctx, existing, false)
	if err != nil || again.ID != provisioned.ID {
		t.Fatalf("repeat provision = %+v %v", again, err)
	}
	if total := auditCount(t, harness.stores, AuditQuery{Type: "user.provisioned"}); total != 1 {
		t.Fatalf("provision audit = %d", total)
	}

	// Verified email linking is opt-in. | 已验证邮箱关联需显式开启。
	byEmail := &Identity{Provider: "github", Subject: "gh-1", Email: "alice@example.com", EmailVerified: true}
	linked, err := harness.service.EnsureUserFromIdentity(ctx, byEmail, true)
	if err != nil || linked.ID != alice.ID {
		t.Fatalf("link by email = %+v %v", linked, err)
	}
	if _, err := harness.stores.Identities.GetIdentity(ctx, "github", "gh-1"); err != nil {
		t.Fatalf("identity not linked: %v", err)
	}

	unverified := &Identity{Provider: "github", Subject: "gh-2", Email: "bob@example.com", Username: "bob"}
	created, err := harness.service.EnsureUserFromIdentity(ctx, unverified, true)
	if err != nil || created.ID == alice.ID || created.EmailVerified {
		t.Fatalf("unverified email = %+v %v", created, err)
	}

	generated := &Identity{Provider: "github", Subject: "GitHub|123?x"}
	generatedUser, err := harness.service.EnsureUserFromIdentity(ctx, generated, false)
	if err != nil || generatedUser.Username != "github_GitHub123x" {
		t.Fatalf("generated username = %+v %v", generatedUser, err)
	}
	if total := auditCount(t, harness.stores, AuditQuery{Type: "user.provisioned"}); total != 3 {
		t.Fatalf("provision audit = %d", total)
	}

	// A failed identity write rolls back the provisioned user. | 身份写入失败会回滚预配用户。
	failing := &failingIdentityStore{IdentityStore: harness.stores.Identities, createErr: errors.New("injected")}
	harness.service.stores.Identities = failing
	if _, err := harness.service.EnsureUserFromIdentity(ctx, &Identity{Provider: "github", Subject: "gh-rollback"}, false); err == nil {
		t.Fatal("failed link accepted")
	}
	if _, err := harness.stores.Users.GetUserByUsername(ctx, "github_gh-rollback"); !errors.Is(err, ErrUserNotFound) {
		t.Fatalf("orphan user not rolled back: %v", err)
	}

	failing.createErr = nil
	failing.getErr = errors.New("injected")
	if _, err := harness.service.EnsureUserFromIdentity(ctx, &Identity{Provider: "github", Subject: "gh-3"}, false); err == nil {
		t.Fatal("identity lookup failure swallowed")
	}
	if _, err := harness.service.UserByIdentity(ctx, "github", "gh-3"); err == nil {
		t.Fatal("identity lookup failure swallowed by UserByIdentity")
	}
}

func TestServiceAccountLifecycle(t *testing.T) {
	harness := newTestService(t, nil)
	ctx := context.Background()
	user := harness.register(t, "alice")
	harness.service.RegisterMFAVerifier(CredentialTOTP, &fakeMFAVerifier{code: "123456"})
	credential, err := harness.service.RegisterCredential(ctx, &Credential{UserID: user.ID, Type: CredentialTOTP})
	if err != nil {
		t.Fatalf("RegisterCredential: %v", err)
	}
	if _, err := harness.service.LinkIdentity(ctx, user.ID, &Identity{Provider: "google", Subject: "g-1"}); err != nil {
		t.Fatalf("LinkIdentity: %v", err)
	}
	if _, err := harness.service.RegisterCredential(ctx, &Credential{UserID: user.ID}); err == nil {
		t.Fatal("credential without type accepted")
	}
	mfa, err := harness.service.Authenticate(ctx, AuthenticateInput{Login: "alice", Password: testServicePassword})
	if err != nil || !mfa.MFARequired {
		t.Fatalf("MFA phase = %+v %v", mfa, err)
	}
	completed, err := harness.service.CompleteMFA(ctx, CompleteMFAInput{UserID: user.ID, MFAToken: mfa.MFAToken, Response: "123456"})
	if err != nil || completed.Session == nil {
		t.Fatalf("CompleteMFA = %+v %v", completed, err)
	}
	resetToken, _, err := harness.service.RequestPasswordReset(ctx, "alice")
	if err != nil {
		t.Fatalf("RequestPasswordReset: %v", err)
	}

	if err := harness.service.LockUser(ctx, "missing", time.Time{}); !errors.Is(err, ErrUserNotFound) {
		t.Fatalf("lock missing = %v", err)
	}
	until := harness.clock.Now().Add(2 * time.Hour)
	if err := harness.service.LockUser(ctx, user.ID, until); err != nil {
		t.Fatalf("LockUser: %v", err)
	}
	stored, _ := harness.stores.Users.GetUser(ctx, user.ID)
	if stored.Status != UserLocked || !stored.LockedUntil.Equal(until) {
		t.Fatalf("locked user = %+v", stored)
	}
	if _, err := harness.service.Sessions().Validate(ctx, completed.Session.ID); !errors.Is(err, ErrSessionRevoked) {
		t.Fatalf("session after lock = %v", err)
	}
	if err := harness.service.UnlockUser(ctx, "missing"); !errors.Is(err, ErrUserNotFound) {
		t.Fatalf("unlock missing = %v", err)
	}
	if err := harness.service.UnlockUser(ctx, user.ID); err != nil {
		t.Fatalf("UnlockUser: %v", err)
	}
	stored, _ = harness.stores.Users.GetUser(ctx, user.ID)
	if stored.Status != UserActive || !stored.LockedUntil.IsZero() || stored.FailedLoginAttempts != 0 {
		t.Fatalf("unlocked user = %+v", stored)
	}
	if err := harness.service.UnlockUser(ctx, user.ID); err != nil {
		t.Fatalf("unlock active user: %v", err)
	}

	if err := harness.service.DisableUser(ctx, "missing"); !errors.Is(err, ErrUserNotFound) {
		t.Fatalf("disable missing = %v", err)
	}
	if err := harness.service.DisableUser(ctx, user.ID); err != nil {
		t.Fatalf("DisableUser: %v", err)
	}
	stored, _ = harness.stores.Users.GetUser(ctx, user.ID)
	if stored.Status != UserDisabled {
		t.Fatalf("disabled user = %+v", stored)
	}
	if err := harness.service.EnableUser(ctx, "missing"); !errors.Is(err, ErrUserNotFound) {
		t.Fatalf("enable missing = %v", err)
	}
	if err := harness.service.EnableUser(ctx, user.ID); err != nil {
		t.Fatalf("EnableUser: %v", err)
	}
	stored, _ = harness.stores.Users.GetUser(ctx, user.ID)
	if stored.Status != UserActive {
		t.Fatalf("enabled user = %+v", stored)
	}
	if total := auditCount(t, harness.stores, AuditQuery{UserID: user.ID}); total < 4 {
		t.Fatalf("lifecycle audit count = %d", total)
	}

	principal := harness.service.PrincipalForUser(stored)
	if principal.Subject != user.ID || principal.Username != "alice" || principal.Email != "alice@example.com" {
		t.Fatalf("principal = %+v", principal)
	}

	if err := harness.service.DeleteUser(ctx, "missing"); !errors.Is(err, ErrUserNotFound) {
		t.Fatalf("delete missing = %v", err)
	}
	if err := harness.service.DeleteUser(ctx, user.ID); err != nil {
		t.Fatalf("DeleteUser: %v", err)
	}
	if _, err := harness.stores.Users.GetUser(ctx, user.ID); !errors.Is(err, ErrUserNotFound) {
		t.Fatalf("user survived delete: %v", err)
	}
	if _, err := harness.stores.Sessions.GetSession(ctx, completed.Session.ID); !errors.Is(err, ErrSessionNotFound) {
		t.Fatalf("session survived delete: %v", err)
	}
	if _, err := harness.stores.Identities.GetIdentity(ctx, "google", "g-1"); !errors.Is(err, ErrIdentityNotFound) {
		t.Fatalf("identity survived delete: %v", err)
	}
	if _, err := harness.stores.Credentials.GetCredential(ctx, credential.ID); !errors.Is(err, ErrCredentialNotFound) {
		t.Fatalf("credential survived delete: %v", err)
	}
	if _, err := harness.stores.Tokens.PeekToken(ctx, HashToken(resetToken), PurposeResetPassword, harness.clock.Now()); !errors.Is(err, ErrTokenInvalid) {
		t.Fatalf("reset token survived delete: %v", err)
	}
	if _, err := harness.stores.Tokens.PeekToken(ctx, HashToken(mfa.MFAToken), PurposeMFALogin, harness.clock.Now()); !errors.Is(err, ErrTokenInvalid) {
		t.Fatalf("MFA token survived delete: %v", err)
	}
	if total := auditCount(t, harness.stores, AuditQuery{Type: "user.deleted"}); total != 1 {
		t.Fatalf("delete audit = %d", total)
	}
}

func TestServiceAuditHelper(t *testing.T) {
	harness := newTestService(t, nil)
	ctx := context.Background()
	var audited *AuditEvent
	harness.service.config.Hooks.AfterAudit = func(_ context.Context, event *AuditEvent) { audited = event }
	event := &AuditEvent{Type: "custom.event", Outcome: "success"}
	harness.service.Audit(ctx, event)
	if event.ID == "" || event.At.IsZero() || audited != event {
		t.Fatalf("audit normalization = %+v", event)
	}
	harness.service.Audit(ctx, nil)

	injected := errors.New("injected")
	harness.service.stores.Audits = &failingAuditStore{AuditStore: harness.stores.Audits, recordErr: injected}
	harness.service.Audit(ctx, &AuditEvent{Type: "lost.event"})
}

func TestLockoutPolicyLockDuration(t *testing.T) {
	var zero LockoutPolicy
	if got := zero.lockDuration(0); got != time.Minute {
		t.Fatalf("zero policy = %v", got)
	}
	policy := LockoutPolicy{MaxAttempts: 3, BaseLockout: time.Second, MaxLockout: time.Minute}
	if got := policy.lockDuration(1); got != time.Second {
		t.Fatalf("below max = %v", got)
	}
	if got := policy.lockDuration(3); got != time.Second {
		t.Fatalf("at max = %v", got)
	}
	if got := policy.lockDuration(5); got != 4*time.Second {
		t.Fatalf("backoff = %v", got)
	}
	if got := policy.lockDuration(100); got != time.Minute {
		t.Fatalf("clamp = %v", got)
	}
	overflow := LockoutPolicy{MaxAttempts: 1, BaseLockout: time.Hour, MaxLockout: time.Hour}
	if got := overflow.lockDuration(2); got != time.Hour {
		t.Fatalf("overflow = %v", got)
	}
}

func TestServiceHelpers(t *testing.T) {
	if got := pushPasswordHistory("", []string{"a"}, 3); len(got) != 1 || got[0] != "a" {
		t.Fatalf("empty old = %v", got)
	}
	if got := pushPasswordHistory("a", []string{"b"}, 0); len(got) != 1 || got[0] != "b" {
		t.Fatalf("zero limit = %v", got)
	}
	got := pushPasswordHistory("a", []string{"a", "b", "c"}, 2)
	if len(got) != 2 || got[0] != "a" || got[1] != "b" {
		t.Fatalf("trim = %v", got)
	}
	if err := checkPasswordReuse(context.Background(), nil, "x", "current", []string{"history"}); err != nil {
		t.Fatalf("nil hasher = %v", err)
	}
	if got := cloneStrings(nil); got != nil {
		t.Fatalf("nil clone = %v", got)
	}
	source := map[string]string{"a": "b"}
	cloned := cloneStrings(source)
	cloned["a"] = "c"
	if source["a"] != "b" {
		t.Fatal("cloneStrings shares state")
	}
	if minInt(1, 2) != 1 || minInt(2, 1) != 1 {
		t.Fatal("minInt")
	}
	if userAgent(nil) != "" {
		t.Fatal("nil request user agent")
	}
	request := httptest.NewRequest(http.MethodGet, "/", nil)
	request.Header.Set("User-Agent", "agent")
	if userAgent(request) != "agent" {
		t.Fatal("request user agent")
	}

	if got := sanitizeUsername("abcXYZ09._-!?|"); got != "abcXYZ09._-" {
		t.Fatalf("sanitizeUsername = %q", got)
	}
	long := strings.Repeat("a", 40)
	if got := sanitizeUsername(long); len(got) != 32 {
		t.Fatalf("long username = %q", got)
	}
	if got := sanitizeUsername("!!!"); !strings.HasPrefix(got, "u_") {
		t.Fatalf("fallback username = %q", got)
	}

	phoneCases := []struct {
		input string
		want  string
		ok    bool
	}{
		{"+86 138-0013-8000", "13800138000", true},
		{"0086 13800138000", "13800138000", true},
		{"8613800138000", "13800138000", true},
		{"13800138000", "13800138000", true},
		{"+1 (415) 555-2671", "14155552671", true},
		{"　138 0013 8000　", "13800138000", true},
		{"", "", false},
		{"1234", "", false},
		{"+", "", false},
		{"00", "", false},
		{"13800138000x", "", false},
		{"+8613800138000+", "", false},
	}
	for _, tc := range phoneCases {
		got, ok := normalizePhone(tc.input)
		if got != tc.want || ok != tc.ok {
			t.Fatalf("normalizePhone(%q) = %q %v, want %q %v", tc.input, got, ok, tc.want, tc.ok)
		}
		if looksLikePhone(tc.input) != tc.ok {
			t.Fatalf("looksLikePhone(%q) = %v", tc.input, !tc.ok)
		}
	}
}
