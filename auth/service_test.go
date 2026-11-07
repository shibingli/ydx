package auth

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"
)

// fakePasswordHasher is a fast deterministic PasswordHasher for lifecycle tests. Cryptographic
// behavior is covered by password_test.go. | fakePasswordHasher 是生命周期测试用的快速确定性
// PasswordHasher；密码学行为由 password_test.go 覆盖。
type fakePasswordHasher struct {
	needsRehash bool
	hashErr     error
	verifyErr   error
	hashCalls   int
	verifyCalls int
}

func (h *fakePasswordHasher) Hash(password string) (string, error) {
	h.hashCalls++
	if h.hashErr != nil {
		return "", h.hashErr
	}
	return "fake$" + password, nil
}

func (h *fakePasswordHasher) Verify(password, encoded string) (bool, error) {
	h.verifyCalls++
	if h.verifyErr != nil {
		return false, h.verifyErr
	}
	return encoded == "fake$"+password, nil
}

func (h *fakePasswordHasher) NeedsRehash(string) bool { return h.needsRehash }
func (h *fakePasswordHasher) Algorithm() string       { return "fake" }

// fakeMFAVerifier accepts one fixed response. | fakeMFAVerifier 接受一个固定响应。
type fakeMFAVerifier struct {
	code string
	err  error
}

func (v *fakeMFAVerifier) Verify(_ context.Context, _ *User, _ *Credential, response string) (bool, error) {
	if v.err != nil {
		return false, v.err
	}
	return response == v.code, nil
}

// failingUserStore injects failures into a UserStore. | failingUserStore 向 UserStore 注入故障。
type failingUserStore struct {
	UserStore
	createErr     error
	updateErr     error
	getErr        error
	getByEmailErr error
}

func (s *failingUserStore) CreateUser(ctx context.Context, user *User) error {
	if s.createErr != nil {
		return s.createErr
	}
	return s.UserStore.CreateUser(ctx, user)
}

func (s *failingUserStore) UpdateUser(ctx context.Context, user *User) error {
	if s.updateErr != nil {
		return s.updateErr
	}
	return s.UserStore.UpdateUser(ctx, user)
}

func (s *failingUserStore) GetUser(ctx context.Context, id string) (*User, error) {
	if s.getErr != nil {
		return nil, s.getErr
	}
	return s.UserStore.GetUser(ctx, id)
}

func (s *failingUserStore) GetUserByEmail(ctx context.Context, email string) (*User, error) {
	if s.getByEmailErr != nil {
		return nil, s.getByEmailErr
	}
	return s.UserStore.GetUserByEmail(ctx, email)
}

// serviceHarness bundles a Service with its fake clock and hasher. | serviceHarness 组合 Service 与其假时钟、哈希器。
type serviceHarness struct {
	service *Service
	clock   *testClock
	hasher  *fakePasswordHasher
	stores  Stores
}

func newTestService(t *testing.T, mutate func(*Config)) *serviceHarness {
	t.Helper()
	clock := &testClock{now: time.Date(2026, 6, 1, 10, 0, 0, 0, time.UTC)}
	hasher := &fakePasswordHasher{}
	config := Config{
		Stores:    NewMemoryStores(),
		Passwords: hasher,
		Policy:    PasswordPolicy{MinLength: 8, MaxLength: 128},
		Clock:     clock.Now,
	}
	if mutate != nil {
		mutate(&config)
	}
	service, err := New(config)
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	return &serviceHarness{service: service, clock: clock, hasher: hasher, stores: service.Stores()}
}

const testServicePassword = "Sup3r-Secret-Passphrase"

func (h *serviceHarness) register(t *testing.T, username string) *User {
	t.Helper()
	user, err := h.service.Register(context.Background(), RegisterInput{
		Username: username,
		Email:    username + "@example.com",
		Password: testServicePassword,
	})
	if err != nil {
		t.Fatalf("Register(%q): %v", username, err)
	}
	return user
}

func auditCount(t *testing.T, stores Stores, query AuditQuery) int {
	t.Helper()
	_, total, err := stores.Audits.ListAudit(context.Background(), query)
	if err != nil {
		t.Fatalf("ListAudit: %v", err)
	}
	return total
}

func TestNewServiceValidationAndDefaults(t *testing.T) {
	if _, err := New(Config{}); !errors.Is(err, ErrInvalidConfig) {
		t.Fatalf("empty config = %v", err)
	}
	stores := NewMemoryStores()
	stores.Tokens = nil
	if _, err := New(Config{Stores: stores}); !errors.Is(err, ErrInvalidConfig) {
		t.Fatalf("missing token store = %v", err)
	}

	service, err := New(Config{Stores: NewMemoryStores()})
	if err != nil {
		t.Fatalf("default service: %v", err)
	}
	if got := service.PasswordHasher(); got == nil || got.Algorithm() != "argon2id" {
		t.Fatalf("default hasher = %v", got)
	}
	if service.Policy().MinLength != DefaultPasswordPolicy().MinLength {
		t.Fatalf("default policy = %+v", service.Policy())
	}
	if service.Sessions() == nil || service.Stores().Users == nil {
		t.Fatal("accessors returned nil")
	}
	if service.config.ResetTokenTTL != time.Hour || service.config.VerifyTokenTTL != 24*time.Hour ||
		service.config.MFATokenTTL != 5*time.Minute || service.mfaTokenTTL != 5*time.Minute {
		t.Fatalf("token TTL defaults = %+v", service.config)
	}
	if service.lockout != DefaultLockoutPolicy() {
		t.Fatalf("lockout defaults = %+v", service.lockout)
	}

	harness := newTestService(t, func(config *Config) {
		config.Lockout = LockoutPolicy{MaxAttempts: 3}
		config.ResetTokenTTL = time.Minute
		config.VerifyTokenTTL = time.Hour
		config.MFATokenTTL = time.Second
	})
	if harness.service.lockout.MaxAttempts != 3 || harness.service.config.ResetTokenTTL != time.Minute ||
		harness.service.config.VerifyTokenTTL != time.Hour || harness.service.config.MFATokenTTL != time.Second {
		t.Fatalf("explicit config not preserved: %+v", harness.service.config)
	}
	verifier := &fakeMFAVerifier{code: "1"}
	harness.service.RegisterMFAVerifier(CredentialTOTP, verifier)
	if harness.service.mfaVerifier(CredentialTOTP) != verifier || harness.service.mfaVerifier(CredentialHOTP) != nil {
		t.Fatal("MFA verifier registry mismatch")
	}
}

func TestServiceRegister(t *testing.T) {
	harness := newTestService(t, nil)
	ctx := context.Background()

	cases := []struct {
		name  string
		input RegisterInput
		want  error
	}{
		{"no identifier", RegisterInput{Password: testServicePassword}, ErrInvalidRequest},
		{"no password", RegisterInput{Username: "user"}, ErrInvalidRequest},
		{"weak password", RegisterInput{Username: "user", Password: "short"}, ErrPasswordPolicy},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if _, err := harness.service.Register(ctx, tc.input); !errors.Is(err, tc.want) {
				t.Fatalf("Register = %v, want %v", err, tc.want)
			}
		})
	}

	metadata := map[string]string{"tenant": "acme"}
	user, err := harness.service.Register(ctx, RegisterInput{
		Username:    "  alice  ",
		Email:       " Alice@Example.COM ",
		Phone:       "+86 138-0013-8000",
		Password:    testServicePassword,
		DisplayName: "  Alice  ",
		Metadata:    metadata,
		ExternalID:  "ext-1",
	})
	if err != nil {
		t.Fatalf("Register: %v", err)
	}
	if user.Username != "alice" || user.Email != "Alice@Example.COM" || user.DisplayName != "Alice" ||
		user.Phone != "+86 138-0013-8000" || user.ExternalID != "ext-1" {
		t.Fatalf("registered user = %+v", user)
	}
	if user.Status != UserActive || user.PasswordHash != "fake$"+testServicePassword ||
		!user.PasswordChangedAt.Equal(harness.clock.Now()) {
		t.Fatalf("registered state = %+v", user)
	}
	metadata["tenant"] = "mutated"
	stored, err := harness.stores.Users.GetUser(ctx, user.ID)
	if err != nil || stored.Metadata["tenant"] != "acme" {
		t.Fatalf("stored metadata = %+v %v", stored, err)
	}
	if total := auditCount(t, harness.stores, AuditQuery{Type: "user.registered"}); total != 1 {
		t.Fatalf("registered audit = %d", total)
	}

	if _, err := harness.service.Register(ctx, RegisterInput{Username: "ALICE", Password: testServicePassword}); !errors.Is(err, ErrUserExists) {
		t.Fatalf("duplicate username = %v", err)
	}
	if _, err := harness.service.Register(ctx, RegisterInput{Username: "bob", Phone: "13800138000", Password: testServicePassword}); !errors.Is(err, ErrUserExists) {
		t.Fatalf("duplicate normalized phone = %v", err)
	}
}

func TestServiceRegisterHooksAndVerification(t *testing.T) {
	ctx := context.Background()
	injected := errors.New("injected register failure")

	harness := newTestService(t, func(config *Config) {
		config.Hooks.BeforeRegister = func(context.Context, *User) error { return injected }
	})
	if _, err := harness.service.Register(ctx, RegisterInput{Username: "alice", Password: testServicePassword}); !errors.Is(err, injected) {
		t.Fatalf("before hook = %v", err)
	}
	if _, err := harness.stores.Users.GetUserByUsername(ctx, "alice"); !errors.Is(err, ErrUserNotFound) {
		t.Fatalf("user persisted after before hook: %v", err)
	}

	harness = newTestService(t, func(config *Config) {
		config.Hooks.AfterRegister = func(context.Context, *User) error { return injected }
	})
	user, err := harness.service.Register(ctx, RegisterInput{Username: "alice", Password: testServicePassword})
	if !errors.Is(err, injected) || user != nil {
		t.Fatalf("after hook = %+v %v", user, err)
	}
	if _, err := harness.stores.Users.GetUserByUsername(ctx, "alice"); err != nil {
		t.Fatalf("after hook should keep the user: %v", err)
	}

	harness = newTestService(t, func(config *Config) {
		config.RequireEmailVerification = true
	})
	pending := harness.register(t, "pending")
	if pending.Status != UserPending {
		t.Fatalf("pending status = %s", pending.Status)
	}
	active, err := harness.service.Register(ctx, RegisterInput{Username: "active", Password: testServicePassword, Active: true})
	if err != nil || active.Status != UserActive {
		t.Fatalf("active override = %+v %v", active, err)
	}

	harness = newTestService(t, func(config *Config) {
		config.Hooks.AfterRegister = func(context.Context, *User) error { return injected }
	})
	harness.hasher.hashErr = injected
	if _, err := harness.service.Register(ctx, RegisterInput{Username: "carol", Password: testServicePassword}); !errors.Is(err, injected) {
		t.Fatalf("hash failure = %v", err)
	}
}

func TestServiceRegisterStoreFailure(t *testing.T) {
	injected := errors.New("store down")
	harness := newTestService(t, func(config *Config) {
		config.Stores.Users = &failingUserStore{UserStore: config.Stores.Users, createErr: injected}
	})
	if _, err := harness.service.Register(context.Background(), RegisterInput{Username: "alice", Password: testServicePassword}); !errors.Is(err, injected) {
		t.Fatalf("create failure = %v", err)
	}
}

func TestServiceAuthenticate(t *testing.T) {
	harness := newTestService(t, func(config *Config) { config.LoginSnapshot = true })
	ctx := context.Background()
	user := harness.register(t, "alice")

	if _, err := harness.service.Authenticate(ctx, AuthenticateInput{Login: "ghost", Password: testServicePassword}); !errors.Is(err, ErrInvalidCredentials) {
		t.Fatalf("unknown login = %v", err)
	}
	if harness.hasher.verifyCalls == 0 {
		t.Fatal("unknown login did not spend dummy verification work")
	}
	if total := auditCount(t, harness.stores, AuditQuery{Type: "login.failed"}); total != 1 {
		t.Fatalf("unknown login audit = %d", total)
	}

	if _, err := harness.service.Authenticate(ctx, AuthenticateInput{Login: "alice", Password: "wrong-password"}); !errors.Is(err, ErrInvalidCredentials) {
		t.Fatalf("wrong password = %v", err)
	}
	stored, _ := harness.stores.Users.GetUser(ctx, user.ID)
	if stored.FailedLoginAttempts != 1 {
		t.Fatalf("failed attempts = %d", stored.FailedLoginAttempts)
	}

	request := httptest.NewRequest(http.MethodPost, "/login", nil)
	request.RemoteAddr = "192.0.2.10:1234"
	request.Header.Set("User-Agent", "test-agent")
	result, err := harness.service.Authenticate(ctx, AuthenticateInput{
		Login: "ALICE", Password: testServicePassword, ClientID: "web", Request: request, ACR: "urn:acr:1",
	})
	if err != nil {
		t.Fatalf("Authenticate: %v", err)
	}
	if result.Session == nil || result.MFARequired || result.Rehashed || result.PasswordExpired {
		t.Fatalf("result = %+v", result)
	}
	if result.Session.ClientID != "web" || result.Session.ACR != "urn:acr:1" ||
		result.Session.IP != "192.0.2.10" || result.Session.UserAgent != "test-agent" {
		t.Fatalf("session metadata = %+v", result.Session)
	}
	if len(result.Session.AMR) != 1 || result.Session.AMR[0] != "pwd" {
		t.Fatalf("default AMR = %v", result.Session.AMR)
	}
	stored, _ = harness.stores.Users.GetUser(ctx, user.ID)
	if stored.FailedLoginAttempts != 0 || !stored.LastLoginAt.Equal(harness.clock.Now()) || stored.LastLoginIP != "192.0.2.10" {
		t.Fatalf("successful login snapshot = %+v", stored)
	}
	if total := auditCount(t, harness.stores, AuditQuery{Type: "login.succeeded"}); total != 1 {
		t.Fatalf("success audit = %d", total)
	}

	// Email and formatted phone both resolve to the same account. | 邮箱与带格式的手机号都解析到同一账号。
	phoneUser, _ := harness.stores.Users.GetUser(ctx, user.ID)
	phoneUser.Phone = "+86 138-0013-8000"
	if err := harness.stores.Users.UpdateUser(ctx, phoneUser); err != nil {
		t.Fatalf("set phone: %v", err)
	}
	for _, login := range []string{"alice@example.com", "+86 138 0013 8000", "008613800138000", "8613800138000", "13800138000"} {
		result, err := harness.service.Authenticate(ctx, AuthenticateInput{Login: login, Password: testServicePassword})
		if err != nil {
			t.Fatalf("login %q: %v", login, err)
		}
		if result.User.ID != user.ID {
			t.Fatalf("login %q resolved to %s", login, result.User.ID)
		}
	}
}

func TestServiceAuthenticateStatusDenials(t *testing.T) {
	ctx := context.Background()
	harness := newTestService(t, nil)
	user := harness.register(t, "alice")

	for _, status := range []UserStatus{UserPending, UserDisabled} {
		stored, _ := harness.stores.Users.GetUser(ctx, user.ID)
		stored.Status = status
		if err := harness.stores.Users.UpdateUser(ctx, stored); err != nil {
			t.Fatalf("update status: %v", err)
		}
		want := ErrAccountPending
		if status == UserDisabled {
			want = ErrAccountDisabled
		}
		if _, err := harness.service.Authenticate(ctx, AuthenticateInput{Login: "alice", Password: testServicePassword}); !errors.Is(err, want) {
			t.Fatalf("status %s = %v", status, err)
		}
	}
	if total := auditCount(t, harness.stores, AuditQuery{Type: "login.denied"}); total != 2 {
		t.Fatalf("denied audits = %d", total)
	}

	stored, _ := harness.stores.Users.GetUser(ctx, user.ID)
	stored.Status = UserLocked
	stored.LockedUntil = harness.clock.Now().Add(time.Hour)
	if err := harness.stores.Users.UpdateUser(ctx, stored); err != nil {
		t.Fatalf("lock: %v", err)
	}
	if _, err := harness.service.Authenticate(ctx, AuthenticateInput{Login: "alice", Password: testServicePassword}); !errors.Is(err, ErrAccountLocked) {
		t.Fatalf("locked = %v", err)
	}

	// An expired temporary administrative lock is healed by the next successful login. | 已到期的临时
	// 管理锁定会在下次成功登录时恢复。
	stored.LockedUntil = harness.clock.Now().Add(-time.Minute)
	if err := harness.stores.Users.UpdateUser(ctx, stored); err != nil {
		t.Fatalf("expire lock: %v", err)
	}
	result, err := harness.service.Authenticate(ctx, AuthenticateInput{Login: "alice", Password: testServicePassword})
	if err != nil {
		t.Fatalf("expired lock login: %v", err)
	}
	if result.User.Status != UserActive {
		t.Fatalf("status after expired lock = %s", result.User.Status)
	}
}

func TestServiceAuthenticateLockout(t *testing.T) {
	harness := newTestService(t, func(config *Config) {
		config.Lockout = LockoutPolicy{MaxAttempts: 2, BaseLockout: time.Minute, MaxLockout: time.Hour}
	})
	ctx := context.Background()
	user := harness.register(t, "alice")

	for i := 0; i < 2; i++ {
		if _, err := harness.service.Authenticate(ctx, AuthenticateInput{Login: "alice", Password: "wrong"}); !errors.Is(err, ErrInvalidCredentials) {
			t.Fatalf("failure %d = %v", i, err)
		}
	}
	stored, _ := harness.stores.Users.GetUser(ctx, user.ID)
	if stored.FailedLoginAttempts != 2 || !stored.LockedUntil.Equal(harness.clock.Now().Add(time.Minute)) {
		t.Fatalf("lockout state = %+v", stored)
	}
	if _, err := harness.service.Authenticate(ctx, AuthenticateInput{Login: "alice", Password: testServicePassword}); !errors.Is(err, ErrAccountLocked) {
		t.Fatalf("locked login = %v", err)
	}

	harness.clock.Advance(2 * time.Minute)
	result, err := harness.service.Authenticate(ctx, AuthenticateInput{Login: "alice", Password: testServicePassword})
	if err != nil || result.User.FailedLoginAttempts != 0 || !result.User.LockedUntil.IsZero() {
		t.Fatalf("after lock expiry = %+v %v", result, err)
	}
}

func TestServiceAuthenticateRehashAndExpiry(t *testing.T) {
	harness := newTestService(t, func(config *Config) {
		config.Policy.MaxAge = time.Hour
		config.Policy.History = 3
	})
	ctx := context.Background()
	user := harness.register(t, "alice")

	harness.hasher.needsRehash = true
	result, err := harness.service.Authenticate(ctx, AuthenticateInput{Login: "alice", Password: testServicePassword})
	if err != nil {
		t.Fatalf("rehash login: %v", err)
	}
	if !result.Rehashed || result.PasswordExpired {
		t.Fatalf("rehash result = %+v", result)
	}
	stored, _ := harness.stores.Users.GetUser(ctx, user.ID)
	if len(stored.PasswordHistory) != 1 || stored.PasswordHistory[0] != "fake$"+testServicePassword {
		t.Fatalf("password history = %v", stored.PasswordHistory)
	}
	if !stored.PasswordChangedAt.Equal(user.PasswordChangedAt) {
		t.Fatalf("rehash extended password age: %v -> %v", user.PasswordChangedAt, stored.PasswordChangedAt)
	}

	harness.clock.Advance(2 * time.Hour)
	result, err = harness.service.Authenticate(ctx, AuthenticateInput{Login: "alice", Password: testServicePassword})
	if err != nil {
		t.Fatalf("expired login: %v", err)
	}
	if !result.PasswordExpired {
		t.Fatal("expired password not reported")
	}
}

func TestServiceAuthenticateMFAFlow(t *testing.T) {
	harness := newTestService(t, nil)
	ctx := context.Background()
	user := harness.register(t, "alice")
	credential, err := harness.service.RegisterCredential(ctx, &Credential{UserID: user.ID, Type: CredentialTOTP, Name: "app"})
	if err != nil {
		t.Fatalf("RegisterCredential: %v", err)
	}
	harness.service.RegisterMFAVerifier(CredentialTOTP, &fakeMFAVerifier{code: "123456"})

	result, err := harness.service.Authenticate(ctx, AuthenticateInput{Login: "alice", Password: testServicePassword})
	if err != nil {
		t.Fatalf("password phase: %v", err)
	}
	if !result.MFARequired || result.Session != nil || result.MFAToken == "" {
		t.Fatalf("MFA phase result = %+v", result)
	}
	if total := auditCount(t, harness.stores, AuditQuery{Type: "login.mfa_required"}); total != 1 {
		t.Fatalf("mfa required audit = %d", total)
	}

	if _, err := harness.service.CompleteMFA(ctx, CompleteMFAInput{UserID: user.ID, MFAToken: result.MFAToken, Response: "000000"}); !errors.Is(err, ErrMFAInvalid) {
		t.Fatalf("wrong code = %v", err)
	}
	if total := auditCount(t, harness.stores, AuditQuery{Type: "mfa.failed"}); total != 1 {
		t.Fatalf("mfa failed audit = %d", total)
	}
	completed, err := harness.service.CompleteMFA(ctx, CompleteMFAInput{
		UserID: user.ID, MFAToken: result.MFAToken, Response: "123456", ClientID: "web", ACR: "urn:acr:1",
	})
	if err != nil {
		t.Fatalf("CompleteMFA: %v", err)
	}
	if completed.Session == nil || len(completed.Session.AMR) != 2 ||
		completed.Session.AMR[0] != "pwd" || completed.Session.AMR[1] != string(CredentialTOTP) {
		t.Fatalf("MFA session = %+v", completed.Session)
	}
	used, err := harness.stores.Credentials.GetCredential(ctx, credential.ID)
	if err != nil || !used.LastUsedAt.Equal(harness.clock.Now()) {
		t.Fatalf("credential use = %+v %v", used, err)
	}
	if _, err := harness.service.CompleteMFA(ctx, CompleteMFAInput{UserID: user.ID, MFAToken: result.MFAToken, Response: "123456"}); !errors.Is(err, ErrTokenUsed) {
		t.Fatalf("token reuse = %v", err)
	}

	// SkipMFA bypasses the challenge for trusted callers. | 可信调用方可用 SkipMFA 跳过挑战。
	result, err = harness.service.Authenticate(ctx, AuthenticateInput{Login: "alice", Password: testServicePassword, SkipMFA: true})
	if err != nil || result.Session == nil || result.MFARequired {
		t.Fatalf("SkipMFA = %+v %v", result, err)
	}
}

func TestServiceCompleteMFAValidation(t *testing.T) {
	harness := newTestService(t, nil)
	ctx := context.Background()
	user := harness.register(t, "alice")

	if _, err := harness.service.CompleteMFA(ctx, CompleteMFAInput{}); !errors.Is(err, ErrInvalidRequest) {
		t.Fatalf("empty user = %v", err)
	}
	if _, err := harness.service.CompleteMFA(ctx, CompleteMFAInput{UserID: "missing"}); !errors.Is(err, ErrUserNotFound) {
		t.Fatalf("missing user = %v", err)
	}
	if _, err := harness.service.CompleteMFA(ctx, CompleteMFAInput{UserID: user.ID}); !errors.Is(err, ErrMFAInvalid) {
		t.Fatalf("no factor = %v", err)
	}

	if _, err := harness.service.RegisterCredential(ctx, &Credential{UserID: user.ID, Type: CredentialTOTP}); err != nil {
		t.Fatalf("RegisterCredential: %v", err)
	}
	harness.service.RegisterMFAVerifier(CredentialTOTP, &fakeMFAVerifier{code: "123456"})

	// Legacy callers may omit MFAToken. | 旧调用方可省略 MFAToken。
	if _, err := harness.service.CompleteMFA(ctx, CompleteMFAInput{UserID: user.ID, Response: "123456"}); err != nil {
		t.Fatalf("legacy CompleteMFA: %v", err)
	}

	// A challenge issued to one user cannot complete another user's login. | 签发给一个用户的挑战不能完成另一用户的登录。
	other := harness.register(t, "bob")
	if _, err := harness.service.RegisterCredential(ctx, &Credential{UserID: other.ID, Type: CredentialTOTP}); err != nil {
		t.Fatalf("RegisterCredential bob: %v", err)
	}
	first, err := harness.service.Authenticate(ctx, AuthenticateInput{Login: "alice", Password: testServicePassword})
	if err != nil || !first.MFARequired {
		t.Fatalf("alice MFA phase = %+v %v", first, err)
	}
	if _, err := harness.service.CompleteMFA(ctx, CompleteMFAInput{UserID: other.ID, MFAToken: first.MFAToken, Response: "123456"}); !errors.Is(err, ErrTokenInvalid) {
		t.Fatalf("cross-user challenge = %v", err)
	}
	// A valid challenge still completes the right user afterwards. | 有效挑战随后仍能完成正确用户。
	if _, err := harness.service.CompleteMFA(ctx, CompleteMFAInput{UserID: user.ID, MFAToken: first.MFAToken, Response: "123456"}); err != nil {
		t.Fatalf("challenge after cross-user attempt: %v", err)
	}

	// Expired challenges are rejected. | 过期挑战会被拒绝。
	pending, err := harness.service.Authenticate(ctx, AuthenticateInput{Login: "alice", Password: testServicePassword})
	if err != nil || !pending.MFARequired {
		t.Fatalf("second MFA phase = %+v %v", pending, err)
	}
	harness.clock.Advance(6 * time.Minute)
	if _, err := harness.service.CompleteMFA(ctx, CompleteMFAInput{UserID: user.ID, MFAToken: pending.MFAToken, Response: "123456"}); !errors.Is(err, ErrTokenExpired) {
		t.Fatalf("expired challenge = %v", err)
	}

	disabled, _ := harness.stores.Users.GetUser(ctx, user.ID)
	disabled.Status = UserDisabled
	if err := harness.stores.Users.UpdateUser(ctx, disabled); err != nil {
		t.Fatalf("disable user: %v", err)
	}
	if _, err := harness.service.CompleteMFA(ctx, CompleteMFAInput{UserID: user.ID, Response: "123456"}); !errors.Is(err, ErrAccountDisabled) {
		t.Fatalf("disabled user = %v", err)
	}
}

func TestServiceCompleteMFACredentialSelectionAndLockout(t *testing.T) {
	harness := newTestService(t, func(config *Config) {
		config.Lockout = LockoutPolicy{MaxAttempts: 3, BaseLockout: time.Minute, MaxLockout: time.Hour}
	})
	ctx := context.Background()
	user := harness.register(t, "alice")
	totp, err := harness.service.RegisterCredential(ctx, &Credential{UserID: user.ID, Type: CredentialTOTP})
	if err != nil {
		t.Fatalf("RegisterCredential totp: %v", err)
	}
	hotp, err := harness.service.RegisterCredential(ctx, &Credential{UserID: user.ID, Type: CredentialHOTP})
	if err != nil {
		t.Fatalf("RegisterCredential hotp: %v", err)
	}
	harness.service.RegisterMFAVerifier(CredentialTOTP, &fakeMFAVerifier{code: "111111"})
	harness.service.RegisterMFAVerifier(CredentialHOTP, &fakeMFAVerifier{code: "222222"})

	if _, err := harness.service.CompleteMFA(ctx, CompleteMFAInput{UserID: user.ID, CredentialID: hotp.ID, Response: "222222"}); err != nil {
		t.Fatalf("selected HOTP: %v", err)
	}
	if _, err := harness.service.CompleteMFA(ctx, CompleteMFAInput{UserID: user.ID, CredentialID: totp.ID, Response: "222222"}); !errors.Is(err, ErrMFAInvalid) {
		t.Fatalf("wrong selected factor = %v", err)
	}

	// A verifier error is a failed factor, not a successful one. | 校验器错误视为失败因素而非成功。
	harness.service.RegisterMFAVerifier(CredentialTOTP, &fakeMFAVerifier{err: errors.New("backend down")})
	if _, err := harness.service.CompleteMFA(ctx, CompleteMFAInput{UserID: user.ID, CredentialID: totp.ID, Response: "111111"}); !errors.Is(err, ErrMFAInvalid) {
		t.Fatalf("verifier error = %v", err)
	}

	if _, err := harness.service.CompleteMFA(ctx, CompleteMFAInput{UserID: user.ID, Response: "000000"}); !errors.Is(err, ErrMFAInvalid) {
		t.Fatalf("second failure = %v", err)
	}
	stored, _ := harness.stores.Users.GetUser(ctx, user.ID)
	if stored.FailedLoginAttempts != 3 || stored.LockedUntil.IsZero() {
		t.Fatalf("shared lockout = %+v", stored)
	}
	if _, err := harness.service.CompleteMFA(ctx, CompleteMFAInput{UserID: user.ID, Response: "111111"}); !errors.Is(err, ErrAccountLocked) {
		t.Fatalf("locked MFA = %v", err)
	}

	disabled, _ := harness.stores.Credentials.GetCredential(ctx, totp.ID)
	disabled.Disabled = true
	if err := harness.stores.Credentials.UpdateCredential(ctx, disabled); err != nil {
		t.Fatalf("disable credential: %v", err)
	}
	harness.clock.Advance(2 * time.Minute)
	harness.service.RegisterMFAVerifier(CredentialTOTP, &fakeMFAVerifier{code: "111111"})
	if _, err := harness.service.CompleteMFA(ctx, CompleteMFAInput{UserID: user.ID, CredentialID: totp.ID, Response: "111111"}); !errors.Is(err, ErrMFAInvalid) {
		t.Fatalf("disabled credential = %v", err)
	}
}

func TestServiceAuthenticateHooksAndStoreFailures(t *testing.T) {
	injected := errors.New("injected")
	ctx := context.Background()

	harness := newTestService(t, func(config *Config) {
		config.Hooks.BeforeLogin = func(context.Context, *User) error { return injected }
	})
	beforeLoginUser := harness.register(t, "alice")
	if _, err := harness.service.Authenticate(ctx, AuthenticateInput{Login: "alice", Password: testServicePassword}); !errors.Is(err, injected) {
		t.Fatalf("before login hook = %v", err)
	}
	if sessions, err := harness.stores.Sessions.ListSessionsByUser(ctx, beforeLoginUser.ID); err != nil || len(sessions) != 0 {
		t.Fatalf("session after hook = %v %v", sessions, err)
	}

	harness = newTestService(t, func(config *Config) {
		config.Hooks.AfterLogin = func(context.Context, *User, *Session) error { return injected }
	})
	harness.register(t, "alice")
	if _, err := harness.service.Authenticate(ctx, AuthenticateInput{Login: "alice", Password: testServicePassword}); !errors.Is(err, injected) {
		t.Fatalf("after login hook = %v", err)
	}

	harness = newTestService(t, nil)
	harness.hasher.verifyErr = injected
	harness.register(t, "alice")
	if _, err := harness.service.Authenticate(ctx, AuthenticateInput{Login: "alice", Password: testServicePassword}); !errors.Is(err, ErrInvalidCredentials) {
		t.Fatalf("verify error = %v", err)
	}

	harness = newTestService(t, func(config *Config) {
		config.Stores.Users = &failingUserStore{UserStore: config.Stores.Users}
	})
	harness.register(t, "alice")
	failing := harness.stores.Users.(*failingUserStore)
	failing.getByEmailErr = injected
	if _, err := harness.service.Authenticate(ctx, AuthenticateInput{Login: "alice@example.com", Password: testServicePassword}); !errors.Is(err, injected) {
		t.Fatalf("email store error = %v", err)
	}
	failing.getByEmailErr = nil
	failing.updateErr = injected
	if _, err := harness.service.Authenticate(ctx, AuthenticateInput{Login: "alice", Password: testServicePassword}); !errors.Is(err, injected) {
		t.Fatalf("update store error = %v", err)
	}
}
