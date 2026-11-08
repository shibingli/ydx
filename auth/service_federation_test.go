package auth

import (
	"context"
	"errors"
	"testing"
)

func TestEnsureUserFromIdentityUnverifiedEmailPolicy(t *testing.T) {
	harness := newTestService(t, func(config *Config) { config.RequireEmailVerification = true })
	ctx := context.Background()

	pending, err := harness.service.EnsureUserFromIdentity(ctx, &Identity{
		Provider: "github", Subject: "gh-pending", Email: "pending@example.com",
	}, false)
	if err != nil {
		t.Fatalf("EnsureUserFromIdentity: %v", err)
	}
	if pending.Status != UserPending || pending.EmailVerified {
		t.Fatalf("unverified federated user = %+v", pending)
	}
	token, err := harness.service.RequestEmailVerification(ctx, pending.ID)
	if err != nil {
		t.Fatalf("RequestEmailVerification: %v", err)
	}
	verified, err := harness.service.VerifyEmail(ctx, token)
	if err != nil {
		t.Fatalf("VerifyEmail: %v", err)
	}
	if verified.Status != UserActive || !verified.EmailVerified {
		t.Fatalf("verified user = %+v", verified)
	}

	active, err := harness.service.EnsureUserFromIdentity(ctx, &Identity{
		Provider: "github", Subject: "gh-verified", Email: "verified@example.com", EmailVerified: true,
	}, false)
	if err != nil || active.Status != UserActive || !active.EmailVerified {
		t.Fatalf("verified federated user = %+v %v", active, err)
	}

	noEmail, err := harness.service.EnsureUserFromIdentity(ctx, &Identity{
		Provider: "github", Subject: "gh-no-email",
	}, false)
	if err != nil || noEmail.Status != UserActive || noEmail.EmailVerified {
		t.Fatalf("identity without email = %+v %v", noEmail, err)
	}
}

func TestEnsureUserFromIdentityUnverifiedEmailPolicyDisabled(t *testing.T) {
	harness := newTestService(t, nil)
	user, err := harness.service.EnsureUserFromIdentity(context.Background(), &Identity{
		Provider: "github", Subject: "gh-unverified", Email: "unverified@example.com",
	}, false)
	if err != nil {
		t.Fatalf("EnsureUserFromIdentity: %v", err)
	}
	if user.Status != UserActive || user.EmailVerified {
		t.Fatalf("policy-off user = %+v", user)
	}
}

func TestEnsureUserFromIdentityKeepsExistingUsers(t *testing.T) {
	harness := newTestService(t, func(config *Config) { config.RequireEmailVerification = true })
	ctx := context.Background()
	existing := &User{
		ID: NewID("usr"), Username: "existing", Email: "existing@example.com",
		Status: UserActive, CreatedAt: harness.clock.Now(), UpdatedAt: harness.clock.Now(),
	}
	if err := harness.stores.Users.CreateUser(ctx, existing); err != nil {
		t.Fatalf("CreateUser: %v", err)
	}
	identity := &Identity{Provider: "github", Subject: "gh-existing", Email: existing.Email}
	if _, err := harness.service.LinkIdentity(ctx, existing.ID, identity); err != nil {
		t.Fatalf("LinkIdentity: %v", err)
	}
	got, err := harness.service.EnsureUserFromIdentity(ctx, identity, false)
	if err != nil {
		t.Fatalf("EnsureUserFromIdentity: %v", err)
	}
	if got.ID != existing.ID || got.Status != UserActive || got.EmailVerified {
		t.Fatalf("existing user was changed: %+v", got)
	}
	if total := auditCount(t, harness.stores, AuditQuery{Type: "user.provisioned"}); total != 0 {
		t.Fatalf("existing user was provisioned again: %d audits", total)
	}

	// An unverified email matching an existing account must not link and must not modify it. |
	// 未验证邮箱与既有账号相同时不得关联，也不得修改既有账号。
	collision := &Identity{Provider: "github", Subject: "gh-collision", Email: existing.Email}
	if _, err := harness.service.EnsureUserFromIdentity(ctx, collision, true); !errors.Is(err, ErrUserExists) {
		t.Fatalf("unverified email collision = %v, want ErrUserExists", err)
	}
	if _, err := harness.stores.Identities.GetIdentity(ctx, "github", "gh-collision"); !errors.Is(err, ErrIdentityNotFound) {
		t.Fatalf("unverified identity was linked: %v", err)
	}
	unchanged, err := harness.stores.Users.GetUser(ctx, existing.ID)
	if err != nil || unchanged.Status != UserActive {
		t.Fatalf("existing user after collision = %+v %v", unchanged, err)
	}
}

func TestServiceRequireMFAToken(t *testing.T) {
	harness := newTestService(t, func(config *Config) { config.RequireMFAToken = true })
	ctx := context.Background()
	user := harness.register(t, "alice")
	if _, err := harness.service.RegisterCredential(ctx, &Credential{UserID: user.ID, Type: CredentialTOTP}); err != nil {
		t.Fatalf("RegisterCredential: %v", err)
	}
	harness.service.RegisterMFAVerifier(CredentialTOTP, &fakeMFAVerifier{code: "123456"})

	if _, err := harness.service.CompleteMFA(ctx, CompleteMFAInput{UserID: user.ID, Response: "123456"}); !errors.Is(err, ErrInvalidRequest) {
		t.Fatalf("empty MFAToken = %v, want ErrInvalidRequest", err)
	}
	pending, err := harness.service.Authenticate(ctx, AuthenticateInput{Login: "alice", Password: testServicePassword})
	if err != nil || !pending.MFARequired || pending.MFAToken == "" {
		t.Fatalf("password phase = %+v %v", pending, err)
	}
	completed, err := harness.service.CompleteMFA(ctx, CompleteMFAInput{
		UserID: user.ID, MFAToken: pending.MFAToken, Response: "123456",
	})
	if err != nil || completed.Session == nil {
		t.Fatalf("CompleteMFA with token = %+v %v", completed, err)
	}
}
