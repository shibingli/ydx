package auth

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/shibingli/ydx/router"
)

// testService returns a Service with fast Argon2id parameters for tests. | testService 返回使用快速 Argon2id 参数的测试服务。
func testService(t *testing.T) *Service {
	t.Helper()
	hasher, err := NewArgon2idHasher(Argon2idConfig{Time: 1, Memory: 8 * 1024, Threads: 1, KeyLength: 32, SaltLength: 16})
	if err != nil {
		t.Fatalf("hasher: %v", err)
	}
	svc, err := New(Config{
		Stores:    NewMemoryStores(),
		Passwords: hasher,
		Session: SessionConfig{
			CookieName:      "test_session",
			Path:            "/",
			IdleTimeout:     time.Hour,
			AbsoluteTimeout: time.Hour,
		},
		Lockout:       LockoutPolicy{MaxAttempts: 3, BaseLockout: time.Second, MaxLockout: time.Minute},
		ResetTokenTTL: time.Hour,
	})
	if err != nil {
		t.Fatalf("new service: %v", err)
	}
	return svc
}

func TestRegisterAuthenticateSessionLifecycle(t *testing.T) {
	svc := testService(t)
	ctx := context.Background()
	user, err := svc.Register(ctx, RegisterInput{
		Username: "alice",
		Email:    "alice@example.com",
		Password: "correct horse battery",
	})
	if err != nil {
		t.Fatalf("register: %v", err)
	}
	if user.Status != UserActive {
		t.Fatalf("status = %q, want active", user.Status)
	}

	req := httptest.NewRequest(http.MethodPost, "/login", nil)
	req.RemoteAddr = "203.0.113.9:1234"
	req.Header.Set("User-Agent", "test-agent")
	result, err := svc.Authenticate(ctx, AuthenticateInput{
		Login: "alice", Password: "correct horse battery", ClientID: "app", Request: req,
	})
	if err != nil {
		t.Fatalf("authenticate: %v", err)
	}
	if result.Session == nil || result.MFARequired {
		t.Fatalf("unexpected result: %+v", result)
	}
	session, err := svc.Sessions().Validate(ctx, result.Session.ID)
	if err != nil {
		t.Fatalf("validate: %v", err)
	}
	if session.IP != "203.0.113.9" || session.UserAgent != "test-agent" {
		t.Fatalf("session metadata = %+v", session)
	}
	principal, err := svc.Sessions().Principal(ctx, session)
	if err != nil {
		t.Fatalf("principal: %v", err)
	}
	if principal.Subject != user.ID || principal.Username != "alice" {
		t.Fatalf("principal = %+v", principal)
	}
	if err := svc.Sessions().Revoke(ctx, session.ID, "test"); err != nil {
		t.Fatalf("revoke: %v", err)
	}
	if _, err := svc.Sessions().Validate(ctx, session.ID); !errors.Is(err, ErrSessionRevoked) {
		t.Fatalf("validate after revoke = %v, want ErrSessionRevoked", err)
	}
}

func TestLockoutAndUnlock(t *testing.T) {
	svc := testService(t)
	ctx := context.Background()
	if _, err := svc.Register(ctx, RegisterInput{Username: "bob", Password: "a long password"}); err != nil {
		t.Fatalf("register: %v", err)
	}
	for i := 0; i < 3; i++ {
		if _, err := svc.Authenticate(ctx, AuthenticateInput{Login: "bob", Password: "wrong"}); !errors.Is(err, ErrInvalidCredentials) {
			t.Fatalf("attempt %d = %v, want ErrInvalidCredentials", i, err)
		}
	}
	if _, err := svc.Authenticate(ctx, AuthenticateInput{Login: "bob", Password: "a long password"}); !errors.Is(err, ErrAccountLocked) {
		t.Fatalf("locked login = %v, want ErrAccountLocked", err)
	}
	user, err := svc.Stores().Users.GetUserByUsername(ctx, "bob")
	if err != nil {
		t.Fatalf("get user: %v", err)
	}
	if err := svc.UnlockUser(ctx, user.ID); err != nil {
		t.Fatalf("unlock: %v", err)
	}
	if _, err := svc.Authenticate(ctx, AuthenticateInput{Login: "bob", Password: "a long password"}); err != nil {
		t.Fatalf("login after unlock: %v", err)
	}
}

func TestPasswordResetAndHistory(t *testing.T) {
	svc := testService(t)
	ctx := context.Background()
	user, err := svc.Register(ctx, RegisterInput{Username: "carol", Email: "carol@example.com", Password: "first password"})
	if err != nil {
		t.Fatalf("register: %v", err)
	}
	token, gotUser, err := svc.RequestPasswordReset(ctx, "carol@example.com")
	if err != nil {
		t.Fatalf("request reset: %v", err)
	}
	if gotUser.ID != user.ID || token == "" {
		t.Fatalf("reset request = %q %+v", token, gotUser)
	}
	if err := svc.ResetPassword(ctx, token, "first password"); !errors.Is(err, ErrPasswordReused) {
		t.Fatalf("reused reset = %v, want ErrPasswordReused", err)
	}
	// The failed policy check must not consume the token; a later valid reset still works. | 失败的口令策略检查不得消费令牌；后续有效重置仍可用。
	if err := svc.ResetPassword(ctx, token, "second password"); err != nil {
		t.Fatalf("second reset: %v", err)
	}
	if _, err := svc.Authenticate(ctx, AuthenticateInput{Login: "carol", Password: "second password"}); err != nil {
		t.Fatalf("login with new password: %v", err)
	}
	if _, err := svc.Authenticate(ctx, AuthenticateInput{Login: "carol", Password: "first password"}); !errors.Is(err, ErrInvalidCredentials) {
		t.Fatalf("old password login = %v, want ErrInvalidCredentials", err)
	}
}

func TestEmailVerificationActivatesPendingAccount(t *testing.T) {
	svc := testService(t)
	svc.config.RequireEmailVerification = true
	ctx := context.Background()
	user, err := svc.Register(ctx, RegisterInput{Username: "dave", Email: "dave@example.com", Password: "pending password"})
	if err != nil {
		t.Fatalf("register: %v", err)
	}
	if user.Status != UserPending {
		t.Fatalf("status = %q, want pending", user.Status)
	}
	if _, err := svc.Authenticate(ctx, AuthenticateInput{Login: "dave", Password: "pending password"}); !errors.Is(err, ErrAccountPending) {
		t.Fatalf("pending login = %v, want ErrAccountPending", err)
	}
	token, err := svc.RequestEmailVerification(ctx, user.ID)
	if err != nil {
		t.Fatalf("request verification: %v", err)
	}
	verified, err := svc.VerifyEmail(ctx, token)
	if err != nil {
		t.Fatalf("verify: %v", err)
	}
	if verified.Status != UserActive || !verified.EmailVerified {
		t.Fatalf("verified user = %+v", verified)
	}
	if _, err := svc.Authenticate(ctx, AuthenticateInput{Login: "dave", Password: "pending password"}); err != nil {
		t.Fatalf("login after verify: %v", err)
	}
}

func TestMFAFlow(t *testing.T) {
	svc := testService(t)
	svc.RegisterMFAVerifier(CredentialTOTP, totpVerifier{code: "123456"})
	ctx := context.Background()
	user, err := svc.Register(ctx, RegisterInput{Username: "erin", Password: "mfa password"})
	if err != nil {
		t.Fatalf("register: %v", err)
	}
	if _, err := svc.RegisterCredential(ctx, &Credential{UserID: user.ID, Type: CredentialTOTP, Secret: "secret"}); err != nil {
		t.Fatalf("register credential: %v", err)
	}
	result, err := svc.Authenticate(ctx, AuthenticateInput{Login: "erin", Password: "mfa password"})
	if err != nil {
		t.Fatalf("authenticate: %v", err)
	}
	if !result.MFARequired || result.Session != nil {
		t.Fatalf("result = %+v", result)
	}
	if _, err := svc.CompleteMFA(ctx, CompleteMFAInput{UserID: user.ID, Response: "bad"}); !errors.Is(err, ErrMFAInvalid) {
		t.Fatalf("bad mfa = %v, want ErrMFAInvalid", err)
	}
	done, err := svc.CompleteMFA(ctx, CompleteMFAInput{UserID: user.ID, Response: "123456"})
	if err != nil {
		t.Fatalf("complete mfa: %v", err)
	}
	if done.Session == nil {
		t.Fatalf("session is nil")
	}
	if len(done.Session.AMR) != 2 || done.Session.AMR[1] != string(CredentialTOTP) {
		t.Fatalf("AMR = %v", done.Session.AMR)
	}
}

// totpVerifier is a deterministic test factor. | totpVerifier 是确定性的测试因素。
type totpVerifier struct{ code string }

func (v totpVerifier) Verify(_ context.Context, _ *User, _ *Credential, response string) (bool, error) {
	return response == v.code, nil
}

func TestIdentityLinkingAndProvisioning(t *testing.T) {
	svc := testService(t)
	ctx := context.Background()
	user, err := svc.Register(ctx, RegisterInput{Username: "frank", Email: "frank@example.com", Password: "identity password"})
	if err != nil {
		t.Fatalf("register: %v", err)
	}
	identity := &Identity{Provider: "google", Subject: "google-1", Email: "frank@example.com", EmailVerified: true}
	if _, err := svc.LinkIdentity(ctx, user.ID, identity); err != nil {
		t.Fatalf("link: %v", err)
	}
	got, err := svc.UserByIdentity(ctx, "google", "google-1")
	if err != nil || got.ID != user.ID {
		t.Fatalf("user by identity = %+v %v", got, err)
	}
	provisioned, err := svc.EnsureUserFromIdentity(ctx, &Identity{
		Provider: "github", Subject: "octocat", Username: "octocat", Email: "octo@example.com", EmailVerified: true,
	}, false)
	if err != nil {
		t.Fatalf("provision: %v", err)
	}
	if provisioned.ID == "" || provisioned.Username != "octocat" {
		t.Fatalf("provisioned = %+v", provisioned)
	}
}

func TestSessionMiddlewareRouterAndNetHTTP(t *testing.T) {
	svc := testService(t)
	ctx := context.Background()
	user, err := svc.Register(ctx, RegisterInput{Username: "grace", Password: "session password"})
	if err != nil {
		t.Fatalf("register: %v", err)
	}
	session, err := svc.Sessions().Create(ctx, user.ID, "app", nil, []string{"pwd"}, "")
	if err != nil {
		t.Fatalf("create session: %v", err)
	}
	r := router.New()
	r.Use(svc.Sessions().Middleware(SessionMiddlewareOptions{RequireSession: true}))
	r.GET("/me", func(c *router.Ctx) {
		principal, ok := PrincipalFromCtx(c)
		if !ok {
			_ = c.JSON(http.StatusInternalServerError, "missing principal")
			return
		}
		_ = c.JSON(http.StatusOK, map[string]string{"sub": principal.Subject})
	})
	req := httptest.NewRequest(http.MethodGet, "/me", nil)
	req.AddCookie(svc.Sessions().Cookie(session))
	w := httptest.NewRecorder()
	r.ServeHTTP(w, req)
	if w.Code != http.StatusOK {
		t.Fatalf("router status = %d body=%s", w.Code, w.Body.String())
	}

	mux := http.NewServeMux()
	mux.HandleFunc("/me", func(w http.ResponseWriter, req *http.Request) {
		principal, ok := PrincipalFromRequest(req)
		if !ok {
			w.WriteHeader(http.StatusInternalServerError)
			return
		}
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(principal.Subject))
	})
	handler := svc.Sessions().HTTPMiddleware(SessionMiddlewareOptions{RequireSession: true})(mux)
	req = httptest.NewRequest(http.MethodGet, "/me", nil)
	req.AddCookie(svc.Sessions().Cookie(session))
	w = httptest.NewRecorder()
	handler.ServeHTTP(w, req)
	if w.Code != http.StatusOK || w.Body.String() != user.ID {
		t.Fatalf("http status = %d body=%s", w.Code, w.Body.String())
	}
}

func TestPermissionMatching(t *testing.T) {
	p := &Principal{Permissions: []string{"user:read", "admin:*"}}
	if !p.HasPermission("user:read") || !p.HasPermission("admin:write") {
		t.Fatal("expected permissions to match")
	}
	if p.HasPermission("billing:read") {
		t.Fatal("unexpected permission match")
	}
	if !MatchPermission("*", "anything") {
		t.Fatal("* should grant anything")
	}
}

func TestPasswordHashers(t *testing.T) {
	cases := []PasswordHasher{}
	argon, err := NewArgon2idHasher(Argon2idConfig{Time: 1, Memory: 8 * 1024, Threads: 1, KeyLength: 32, SaltLength: 16})
	if err != nil {
		t.Fatal(err)
	}
	cases = append(cases, argon)
	bcrypt, err := NewBcryptHasher(BcryptConfig{Cost: 10})
	if err != nil {
		t.Fatal(err)
	}
	cases = append(cases, bcrypt)
	scrypt, err := NewScryptHasher(ScryptConfig{N: 1 << 14, R: 8, P: 1, KeyLength: 32, SaltLength: 16})
	if err != nil {
		t.Fatal(err)
	}
	cases = append(cases, scrypt)
	pbkdf2, err := NewPBKDF2Hasher(PBKDF2Config{Iterations: 100000, SaltLength: 16, KeyLength: 32, Hash: "sha256"})
	if err != nil {
		t.Fatal(err)
	}
	cases = append(cases, pbkdf2)
	for _, hasher := range cases {
		encoded, err := hasher.Hash("correct horse battery staple")
		if err != nil {
			t.Fatalf("%s hash: %v", hasher.Algorithm(), err)
		}
		ok, err := hasher.Verify("correct horse battery staple", encoded)
		if err != nil || !ok {
			t.Fatalf("%s verify = %v %v", hasher.Algorithm(), ok, err)
		}
		ok, err = hasher.Verify("wrong", encoded)
		if err != nil || ok {
			t.Fatalf("%s wrong verify = %v %v", hasher.Algorithm(), ok, err)
		}
	}
}

func TestCSRF(t *testing.T) {
	svc := testService(t)
	ctx := context.Background()
	user, err := svc.Register(ctx, RegisterInput{Username: "heidi", Password: "csrf password"})
	if err != nil {
		t.Fatal(err)
	}
	session, err := svc.Sessions().Create(ctx, user.ID, "", nil, nil, "")
	if err != nil {
		t.Fatal(err)
	}
	token := svc.Sessions().CSRFToken(session)
	if token == "" || !svc.Sessions().VerifyCSRF(session, token) {
		t.Fatal("csrf token did not verify")
	}
	if svc.Sessions().VerifyCSRF(session, token+"x") {
		t.Fatal("tampered csrf token verified")
	}
}

func TestUserHelpersAndCanLogin(t *testing.T) {
	now := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
	var nilUser *User
	if !errors.Is(nilUser.CanLogin(now), ErrUserNotFound) {
		t.Fatal("nil user did not return ErrUserNotFound")
	}
	cases := []struct {
		name string
		user *User
		want error
	}{
		{"active", &User{Status: UserActive}, nil},
		{"disabled", &User{Status: UserDisabled}, ErrAccountDisabled},
		{"pending", &User{Status: UserPending}, ErrAccountPending},
		{"locked without deadline", &User{Status: UserLocked}, ErrAccountLocked},
		{"locked until future", &User{Status: UserLocked, LockedUntil: now.Add(time.Minute)}, ErrAccountLocked},
		{"locked until past", &User{Status: UserLocked, LockedUntil: now.Add(-time.Minute)}, nil},
		{"unknown status", &User{Status: UserStatus("weird")}, ErrAccountDisabled},
		{"active but future lock", &User{Status: UserActive, LockedUntil: now.Add(time.Minute)}, ErrAccountLocked},
		{"active and past lock", &User{Status: UserActive, LockedUntil: now.Add(-time.Minute)}, nil},
	}
	for _, tc := range cases {
		err := tc.user.CanLogin(now)
		if tc.want == nil && err != nil {
			t.Fatalf("%s: %v", tc.name, err)
		}
		if tc.want != nil && !errors.Is(err, tc.want) {
			t.Fatalf("%s: %v, want %v", tc.name, err, tc.want)
		}
	}

	if nilUser.DisplayNameOrUsername() != "" {
		t.Fatal("nil display name")
	}
	if (&User{DisplayName: "Display", Username: "user", Email: "e@example.com"}).DisplayNameOrUsername() != "Display" ||
		(&User{Username: "user", Email: "e@example.com"}).DisplayNameOrUsername() != "user" ||
		(&User{Email: "e@example.com"}).DisplayNameOrUsername() != "e@example.com" {
		t.Fatal("display name fallback")
	}
}

func TestUserCloneDeepCopies(t *testing.T) {
	if (*User)(nil).Clone() != nil {
		t.Fatal("nil user clone")
	}
	user := &User{
		Address:         map[string]string{"city": "Beijing"},
		Metadata:        map[string]string{"role": "admin"},
		PasswordHistory: []string{"hash-1"},
	}
	clone := user.Clone()
	clone.Address["city"] = "Shanghai"
	clone.Metadata["role"] = "user"
	clone.PasswordHistory[0] = "changed"
	if user.Address["city"] != "Beijing" || user.Metadata["role"] != "admin" || user.PasswordHistory[0] != "hash-1" {
		t.Fatal("user clone shares mutable state")
	}
}

func TestPrincipalHelpers(t *testing.T) {
	now := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
	var nilPrincipal *Principal
	if nilPrincipal.HasScope("x") || nilPrincipal.HasRole("x") || nilPrincipal.HasPermission("x") || !nilPrincipal.Expired(now) {
		t.Fatal("nil principal helpers")
	}
	principal := &Principal{
		Scopes: []string{"profile", "email"}, Roles: []string{"admin"},
		Permissions: []string{"user:read", "billing:*"}, ExpiresAt: now.Add(time.Minute),
		Audience: []string{"api"}, Groups: []string{"staff"}, AMR: []string{"pwd"},
		Attributes: map[string]string{"tenant": "one"},
	}
	if !principal.HasScope("profile") || principal.HasScope("missing") {
		t.Fatal("HasScope")
	}
	if !principal.HasRole("admin") || principal.HasRole("missing") {
		t.Fatal("HasRole")
	}
	if !principal.HasPermission("user:read") || !principal.HasPermission("billing:write") || principal.HasPermission("user:write") {
		t.Fatal("HasPermission")
	}
	if principal.Expired(now) || !principal.Expired(now.Add(time.Minute)) {
		t.Fatal("Expired")
	}
	clone := principal.Clone()
	clone.Scopes[0] = "changed"
	clone.Audience[0] = "changed"
	clone.Groups[0] = "changed"
	clone.AMR[0] = "changed"
	clone.Attributes["tenant"] = "two"
	if principal.Scopes[0] != "profile" || principal.Audience[0] != "api" || principal.Groups[0] != "staff" ||
		principal.AMR[0] != "pwd" || principal.Attributes["tenant"] != "one" {
		t.Fatal("principal clone shares mutable state")
	}
	if (*Principal)(nil).Clone() != nil {
		t.Fatal("nil principal clone")
	}
}

func TestMatchPermission(t *testing.T) {
	cases := []struct {
		held, want string
		ok         bool
	}{
		{"", "user:read", false},
		{"user:read", "", false},
		{"user:read", "user:read", true},
		{"*", "anything", true},
		{"admin:*", "admin:write", true},
		{"admin:*", "administrator", false},
		{"user*", "user:read", true},
		{"user*", "admin", false},
		{"user:*", "user", false},
	}
	for _, tc := range cases {
		if got := MatchPermission(tc.held, tc.want); got != tc.ok {
			t.Fatalf("MatchPermission(%q, %q) = %v", tc.held, tc.want, got)
		}
	}
}

func TestModelClones(t *testing.T) {
	if (*Identity)(nil).Clone() != nil || (*Session)(nil).Clone() != nil ||
		(*Credential)(nil).Clone() != nil || (*AuditEvent)(nil).Clone() != nil {
		t.Fatal("nil model clone")
	}
	identity := &Identity{Raw: map[string]string{"k": "v"}}
	identityClone := identity.Clone()
	identityClone.Raw["k"] = "changed"
	if identity.Raw["k"] != "v" {
		t.Fatal("identity clone shares state")
	}

	revoked := time.Now().UTC()
	session := &Session{AMR: []string{"pwd"}, Data: map[string]string{"k": "v"}, RevokedAt: &revoked}
	sessionClone := session.Clone()
	sessionClone.AMR[0] = "otp"
	sessionClone.Data["k"] = "changed"
	*sessionClone.RevokedAt = revoked.Add(time.Hour)
	if session.AMR[0] != "pwd" || session.Data["k"] != "v" || !session.RevokedAt.Equal(revoked) {
		t.Fatal("session clone shares state")
	}

	credential := &Credential{Data: map[string]string{"k": "v"}}
	credentialClone := credential.Clone()
	credentialClone.Data["k"] = "changed"
	if credential.Data["k"] != "v" {
		t.Fatal("credential clone shares state")
	}

	event := &AuditEvent{Detail: map[string]string{"k": "v"}}
	eventClone := event.Clone()
	eventClone.Detail["k"] = "changed"
	if event.Detail["k"] != "v" {
		t.Fatal("audit clone shares state")
	}
}

func TestContextPrincipal(t *testing.T) {
	ctx := context.Background()
	if _, ok := PrincipalFromContext(ctx); ok {
		t.Fatal("background context reported a principal")
	}
	if _, ok := PrincipalFromRequest(nil); ok {
		t.Fatal("nil request reported a principal")
	}
	principal := &Principal{Subject: "user-context"}
	ctx = ContextWithPrincipal(ctx, principal)
	got, ok := PrincipalFromContext(ctx)
	if !ok || got.Subject != "user-context" {
		t.Fatalf("context principal = %+v %v", got, ok)
	}
	if _, ok := PrincipalFromContext(ContextWithPrincipal(context.Background(), nil)); ok {
		t.Fatal("nil principal reported")
	}
	req := httptest.NewRequest(http.MethodGet, "/", nil)
	if _, ok := PrincipalFromRequest(req); ok {
		t.Fatal("plain request reported a principal")
	}
	req = req.WithContext(ContextWithPrincipal(req.Context(), principal))
	if got, ok := PrincipalFromRequest(req); !ok || got.Subject != "user-context" {
		t.Fatalf("request principal = %+v %v", got, ok)
	}
}
