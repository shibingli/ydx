package webauthn

import (
	"context"
	"errors"
	"sync"
	"testing"

	"github.com/shibingli/ydx/auth"
	"github.com/shibingli/ydx/json"
)

// TestCounterAcceptedPolicyMatrix exercises the pure sign-counter policy. | TestCounterAcceptedPolicyMatrix
// 覆盖纯签名计数器策略。
func TestCounterAcceptedPolicyMatrix(t *testing.T) {
	backup := FlagUserPresent | FlagBackupEligible | FlagBackupState
	eligibleNotBackedUp := FlagUserPresent | FlagBackupEligible
	notEligible := FlagUserPresent
	cases := []struct {
		name   string
		policy CounterPolicy
		stored uint32
		count  uint32
		flags  Flags
		want   bool
	}{
		{name: "strict increase", policy: CounterStrict, stored: 5, count: 6, flags: notEligible, want: true},
		{name: "strict equal", policy: CounterStrict, stored: 5, count: 5, flags: notEligible, want: false},
		{name: "strict decrease", policy: CounterStrict, stored: 5, count: 4, flags: notEligible, want: false},
		{name: "strict zero stored accepts zero", policy: CounterStrict, stored: 0, count: 0, flags: notEligible, want: true},
		{name: "strict backup reset", policy: CounterStrict, stored: 5, count: 4, flags: backup, want: false},
		{name: "backup reset accepted", policy: CounterAllowBackupEligibleReset, stored: 5, count: 4, flags: backup, want: true},
		{name: "backup reset eligible but not backed up", policy: CounterAllowBackupEligibleReset, stored: 5, count: 4, flags: eligibleNotBackedUp, want: false},
		{name: "backup reset not eligible", policy: CounterAllowBackupEligibleReset, stored: 5, count: 4, flags: notEligible, want: false},
		{name: "backup reset increase still accepted", policy: CounterAllowBackupEligibleReset, stored: 5, count: 6, flags: eligibleNotBackedUp, want: true},
		{name: "allow any decrease", policy: CounterAllowAny, stored: 5, count: 4, flags: notEligible, want: true},
		{name: "allow any zero", policy: CounterAllowAny, stored: 5, count: 0, flags: notEligible, want: true},
		{name: "allow any zero stored", policy: CounterAllowAny, stored: 0, count: 0, flags: notEligible, want: true},
	}
	for _, test := range cases {
		t.Run(test.name, func(t *testing.T) {
			authData := &AuthenticatorData{Flags: test.flags, SignCount: test.count}
			if got := counterAccepted(test.policy, test.stored, authData); got != test.want {
				t.Fatalf("counterAccepted(%q, %d, flags=%#x) = %v, want %v",
					test.policy, test.stored, test.flags, got, test.want)
			}
		})
	}
	if counterAccepted(CounterAllowAny, 0, nil) {
		t.Fatal("nil authenticator data was accepted")
	}
}

// TestCounterPolicyServiceConfig checks policy validation and the accessor. |
// TestCounterPolicyServiceConfig 检查策略校验与访问器。
func TestCounterPolicyServiceConfig(t *testing.T) {
	if policy := newTestService(t, nil).CounterPolicy(); policy != CounterStrict {
		t.Fatalf("default policy = %q, want %q", policy, CounterStrict)
	}
	var nilService *Service
	if policy := nilService.CounterPolicy(); policy != CounterStrict {
		t.Fatalf("nil service policy = %q, want %q", policy, CounterStrict)
	}
	for _, policy := range []CounterPolicy{CounterStrict, CounterAllowBackupEligibleReset, CounterAllowAny} {
		service := newTestService(t, func(config *Config) { config.CounterPolicy = policy })
		if service.CounterPolicy() != policy {
			t.Fatalf("policy = %q, want %q", service.CounterPolicy(), policy)
		}
	}
	if _, err := New(Config{
		RPDisplayName: "Example RP",
		RPID:          testRPID,
		RPOrigins:     []string{testOrigin},
		CounterPolicy: CounterPolicy("sometimes"),
	}); !errors.Is(err, ErrInvalidConfig) {
		t.Fatalf("invalid policy error = %v, want ErrInvalidConfig", err)
	}
}

// loginWithCounterPolicy registers fixture, then returns the stored credential and the result of one
// login carrying loginFlags and loginCount. | loginWithCounterPolicy 注册 fixture，然后返回已存凭据与
// 携带 loginFlags、loginCount 的一次登录结果。
func loginWithCounterPolicy(t *testing.T, policy CounterPolicy, registerFlags, loginFlags Flags, registerCount, loginCount uint32) (*Service, *Credential, error) {
	t.Helper()
	service := newTestService(t, func(config *Config) {
		config.CounterPolicy = policy
	})
	signer := newECSigner(t)
	fixture := defaultRegistrationFixture(t, signer)
	fixture.flags = registerFlags | FlagAttestedCredentialData
	fixture.signCount = registerCount
	fixture.register(t, service, testUser(), RegistrationOptions{})

	options, ceremony, err := service.BeginLogin(context.Background(), testUser(), LoginOptions{})
	if err != nil {
		t.Fatalf("BeginLogin: %v", err)
	}
	login := defaultAssertionFixture(signer, fixture.credID)
	login.flags = loginFlags
	login.signCount = loginCount
	stored, err := service.FinishLogin(context.Background(), ceremony, login.assertionResponse(t, options))
	if err != nil {
		return service, nil, err
	}
	return service, stored, nil
}

// TestServiceLoginCounterPolicyMatrix exercises counter policies end to end. |
// TestServiceLoginCounterPolicyMatrix 端到端覆盖计数器策略。
func TestServiceLoginCounterPolicyMatrix(t *testing.T) {
	backup := FlagUserPresent | FlagBackupEligible | FlagBackupState
	eligibleNotBackedUp := FlagUserPresent | FlagBackupEligible
	notEligible := FlagUserPresent
	cases := []struct {
		name          string
		policy        CounterPolicy
		registerFlags Flags
		loginFlags    Flags
		registerCount uint32
		loginCount    uint32
		wantClone     bool
		wantCount     uint32
	}{
		{
			name: "strict rejects backup reset", policy: CounterStrict,
			registerFlags: backup, loginFlags: backup, registerCount: 10, loginCount: 3,
			wantClone: true, wantCount: 10,
		},
		{
			name: "backup reset accepted", policy: CounterAllowBackupEligibleReset,
			registerFlags: backup, loginFlags: backup, registerCount: 10, loginCount: 3,
			wantCount: 3,
		},
		{
			name: "backup reset rejects BE without BS", policy: CounterAllowBackupEligibleReset,
			registerFlags: backup, loginFlags: eligibleNotBackedUp, registerCount: 10, loginCount: 3,
			wantClone: true, wantCount: 10,
		},
		{
			name: "backup reset rejects non-eligible", policy: CounterAllowBackupEligibleReset,
			registerFlags: notEligible, loginFlags: notEligible, registerCount: 10, loginCount: 3,
			wantClone: true, wantCount: 10,
		},
		{
			name: "allow any accepts non-eligible reset", policy: CounterAllowAny,
			registerFlags: notEligible, loginFlags: notEligible, registerCount: 10, loginCount: 3,
			wantCount: 3,
		},
		{
			name: "strict accepts two zero counters", policy: CounterStrict,
			registerFlags: notEligible, loginFlags: notEligible, registerCount: 0, loginCount: 0,
			wantCount: 0,
		},
		{
			name: "backup policy accepts zero stored", policy: CounterAllowBackupEligibleReset,
			registerFlags: notEligible, loginFlags: notEligible, registerCount: 0, loginCount: 0,
			wantCount: 0,
		},
	}
	for _, test := range cases {
		t.Run(test.name, func(t *testing.T) {
			service, credential, err := loginWithCounterPolicy(t, test.policy, test.registerFlags, test.loginFlags, test.registerCount, test.loginCount)
			if test.wantClone {
				if !errors.Is(err, ErrCloneDetected) {
					t.Fatalf("login error = %v, want ErrCloneDetected", err)
				}
				credential, err = service.credentials.GetByCredentialID(context.Background(), []byte("test-credential-id"))
				if err != nil {
					t.Fatalf("GetByCredentialID: %v", err)
				}
			} else if err != nil {
				t.Fatalf("FinishLogin: %v", err)
			}
			if credential.SignCount != test.wantCount {
				t.Fatalf("sign count = %d, want %d", credential.SignCount, test.wantCount)
			}
		})
	}
}

// TestServiceCounterPolicyPermissiveConcurrentUpdates verifies that permissive policies allow
// concurrent assertions and that backup-state writes remain race free. |
// TestServiceCounterPolicyPermissiveConcurrentUpdates 验证宽松策略允许并发断言，且备份状态写入无竞态。
func TestServiceCounterPolicyPermissiveConcurrentUpdates(t *testing.T) {
	const attempts = 8
	t.Run("counter", func(t *testing.T) {
		service := newTestService(t, func(config *Config) {
			config.CounterPolicy = CounterAllowAny
		})
		signer := newECSigner(t)
		fixture := defaultRegistrationFixture(t, signer)
		fixture.signCount = 10
		fixture.register(t, service, testUser(), RegistrationOptions{})

		responses := makeConcurrentResponses(t, service, signer, fixture.credID, 11, FlagUserPresent)
		errsCh := make(chan error, attempts)
		var wg sync.WaitGroup
		for _, attempt := range responses {
			wg.Add(1)
			go func(attempt loginAttempt) {
				defer wg.Done()
				_, err := service.FinishLogin(context.Background(), attempt.ceremony, attempt.response)
				errsCh <- err
			}(attempt)
		}
		wg.Wait()
		close(errsCh)
		for err := range errsCh {
			if err != nil {
				t.Fatalf("concurrent FinishLogin: %v", err)
			}
		}
		stored, err := service.credentials.GetByCredentialID(context.Background(), fixture.credID)
		if err != nil {
			t.Fatalf("GetByCredentialID: %v", err)
		}
		if stored.SignCount != 11 {
			t.Fatalf("sign count = %d, want 11", stored.SignCount)
		}
	})
	t.Run("backup state", func(t *testing.T) {
		service := newTestService(t, func(config *Config) {
			config.CounterPolicy = CounterAllowAny
		})
		signer := newECSigner(t)
		fixture := defaultRegistrationFixture(t, signer)
		fixture.flags = FlagUserPresent | FlagBackupEligible | FlagAttestedCredentialData
		fixture.signCount = 10
		fixture.register(t, service, testUser(), RegistrationOptions{})

		responses := makeConcurrentResponses(t, service, signer, fixture.credID, 11, FlagUserPresent|FlagBackupEligible|FlagBackupState)
		errsCh := make(chan error, attempts)
		var wg sync.WaitGroup
		for _, attempt := range responses {
			wg.Add(1)
			go func(attempt loginAttempt) {
				defer wg.Done()
				_, err := service.FinishLogin(context.Background(), attempt.ceremony, attempt.response)
				errsCh <- err
			}(attempt)
		}
		wg.Wait()
		close(errsCh)
		for err := range errsCh {
			if err != nil {
				t.Fatalf("concurrent FinishLogin: %v", err)
			}
		}
		stored, err := service.credentials.GetByCredentialID(context.Background(), fixture.credID)
		if err != nil {
			t.Fatalf("GetByCredentialID: %v", err)
		}
		if !stored.BackupState {
			t.Fatal("backup state was not persisted")
		}
		if stored.SignCount != 11 {
			t.Fatalf("sign count = %d, want 11", stored.SignCount)
		}
	})
}

// loginAttempt couples a ceremony with its serialized assertion response. | loginAttempt 把流程与其序列化断言响应配对。
type loginAttempt struct {
	ceremony *Ceremony
	response *CredentialAssertionResponse
}

// makeConcurrentResponses builds attempts independent login responses for one assertion. |
// makeConcurrentResponses 为同一断言构建 attempts 个独立登录响应。
func makeConcurrentResponses(t *testing.T, service *Service, signer testSigner, credentialID []byte, signCount uint32, flags Flags) []loginAttempt {
	t.Helper()
	attempts := make([]loginAttempt, 0, 8)
	for i := 0; i < 8; i++ {
		options, ceremony, err := service.BeginLogin(context.Background(), testUser(), LoginOptions{})
		if err != nil {
			t.Fatalf("BeginLogin: %v", err)
		}
		login := defaultAssertionFixture(signer, credentialID)
		login.flags = flags
		login.signCount = signCount
		attempts = append(attempts, loginAttempt{
			ceremony: ceremony,
			response: login.assertionResponse(t, options),
		})
	}
	return attempts
}

// TestServiceBackupStatePersistence checks BS persistence for the built-in stores. |
// TestServiceBackupStatePersistence 检查内置存储的 BS 持久化。
func TestServiceBackupStatePersistence(t *testing.T) {
	registerFlags := FlagUserPresent | FlagBackupEligible | FlagAttestedCredentialData
	loginFlags := FlagUserPresent | FlagBackupEligible | FlagBackupState
	t.Run("memory store", func(t *testing.T) {
		service := newTestService(t, nil)
		signer := newECSigner(t)
		fixture := defaultRegistrationFixture(t, signer)
		fixture.flags = registerFlags
		credential := fixture.register(t, service, testUser(), RegistrationOptions{})
		if !credential.BackupEligible || credential.BackupState {
			t.Fatalf("registered flags = %v/%v", credential.BackupEligible, credential.BackupState)
		}
		options, ceremony, err := service.BeginLogin(context.Background(), testUser(), LoginOptions{})
		if err != nil {
			t.Fatalf("BeginLogin: %v", err)
		}
		login := defaultAssertionFixture(signer, fixture.credID)
		login.flags = loginFlags
		login.signCount = 1
		used, err := service.FinishLogin(context.Background(), ceremony, login.assertionResponse(t, options))
		if err != nil {
			t.Fatalf("FinishLogin: %v", err)
		}
		if !used.BackupState {
			t.Fatal("returned credential did not report BS")
		}
		stored, err := service.credentials.GetByCredentialID(context.Background(), fixture.credID)
		if err != nil {
			t.Fatalf("GetByCredentialID: %v", err)
		}
		if !stored.BackupState {
			t.Fatal("memory store did not persist BS")
		}
	})
	t.Run("auth credential store", func(t *testing.T) {
		stores := auth.NewMemoryStores()
		service, _ := newAuthStoreService(t, stores)
		signer := newECSigner(t)
		fixture := defaultRegistrationFixture(t, signer)
		fixture.flags = registerFlags
		fixture.register(t, service, testUser(), RegistrationOptions{})
		options, ceremony, err := service.BeginLogin(context.Background(), testUser(), LoginOptions{})
		if err != nil {
			t.Fatalf("BeginLogin: %v", err)
		}
		login := defaultAssertionFixture(signer, fixture.credID)
		login.flags = loginFlags
		login.signCount = 1
		if _, err := service.FinishLogin(context.Background(), ceremony, login.assertionResponse(t, options)); err != nil {
			t.Fatalf("FinishLogin: %v", err)
		}
		record := loadAuthCredential(t, stores, fixture.credID)
		if record.Data[CredentialDataBackupState] != "true" {
			t.Fatalf("%s = %q, want true", CredentialDataBackupState, record.Data[CredentialDataBackupState])
		}
		if record.Data[CredentialDataSignCount] != "1" {
			t.Fatalf("%s = %q, want 1", CredentialDataSignCount, record.Data[CredentialDataSignCount])
		}
	})
}

// credentialStoreWithoutBackupState hides BackupStateUpdater behind the plain CredentialStore
// interface. | credentialStoreWithoutBackupState 通过普通 CredentialStore 接口隐藏 BackupStateUpdater。
type credentialStoreWithoutBackupState struct {
	CredentialStore
}

// failingBackupStateStore fails UpdateBackupState while err is non-nil. | failingBackupStateStore 在 err
// 非空时使 UpdateBackupState 失败。
type failingBackupStateStore struct {
	CredentialStore
	err error
}

// UpdateBackupState implements BackupStateUpdater. | UpdateBackupState 实现 BackupStateUpdater。
func (s *failingBackupStateStore) UpdateBackupState(context.Context, []byte, bool) error {
	return s.err
}

// TestServiceBackupStateOptionalUpdater verifies stores without the optional interface keep working
// and that updater failures abort the login before the sign count is written. |
// TestServiceBackupStateOptionalUpdater 验证未实现可选接口的存储仍可工作，且更新失败会在写入签名计数器
// 之前中止登录。
func TestServiceBackupStateOptionalUpdater(t *testing.T) {
	base := NewMemoryCredentialStore()
	wrapped := &credentialStoreWithoutBackupState{CredentialStore: base}
	service := newTestService(t, func(config *Config) {
		config.CredentialStore = wrapped
	})
	signer := newECSigner(t)
	fixture := defaultRegistrationFixture(t, signer)
	fixture.flags = FlagUserPresent | FlagBackupEligible | FlagAttestedCredentialData
	fixture.signCount = 5
	fixture.register(t, service, testUser(), RegistrationOptions{})

	options, ceremony, err := service.BeginLogin(context.Background(), testUser(), LoginOptions{})
	if err != nil {
		t.Fatalf("BeginLogin: %v", err)
	}
	login := defaultAssertionFixture(signer, fixture.credID)
	login.flags = FlagUserPresent | FlagBackupEligible | FlagBackupState
	login.signCount = 6
	used, err := service.FinishLogin(context.Background(), ceremony, login.assertionResponse(t, options))
	if err != nil {
		t.Fatalf("FinishLogin: %v", err)
	}
	if !used.BackupState {
		t.Fatal("returned credential did not report BS")
	}
	stored, err := base.GetByCredentialID(context.Background(), fixture.credID)
	if err != nil {
		t.Fatalf("GetByCredentialID: %v", err)
	}
	if stored.BackupState {
		t.Fatal("store without BackupStateUpdater unexpectedly persisted BS")
	}
	if stored.SignCount != 6 {
		t.Fatalf("sign count = %d, want 6", stored.SignCount)
	}

	failingBase := NewMemoryCredentialStore()
	failing := &failingBackupStateStore{CredentialStore: failingBase}
	service = newTestService(t, func(config *Config) {
		config.CredentialStore = failing
	})
	// Re-register in a fresh store because the previous service already persisted the credential.
	signer = newECSigner(t)
	fixture = defaultRegistrationFixture(t, signer)
	fixture.flags = FlagUserPresent | FlagBackupEligible | FlagAttestedCredentialData
	fixture.signCount = 5
	fixture.register(t, service, testUser(), RegistrationOptions{})
	sentinel := errors.New("backup state unavailable")
	failing.err = sentinel

	options, ceremony, err = service.BeginLogin(context.Background(), testUser(), LoginOptions{})
	if err != nil {
		t.Fatalf("BeginLogin: %v", err)
	}
	login = defaultAssertionFixture(signer, fixture.credID)
	login.flags = FlagUserPresent | FlagBackupEligible | FlagBackupState
	login.signCount = 6
	_, err = service.FinishLogin(context.Background(), ceremony, login.assertionResponse(t, options))
	if !errors.Is(err, sentinel) || !errors.Is(err, ErrInvalidCredential) {
		t.Fatalf("FinishLogin error = %v, want sentinel and ErrInvalidCredential", err)
	}
	stored, err = failingBase.GetByCredentialID(context.Background(), fixture.credID)
	if err != nil {
		t.Fatalf("GetByCredentialID: %v", err)
	}
	if stored.BackupState {
		t.Fatal("failed backup-state update was partially applied")
	}
	if stored.SignCount != 5 {
		t.Fatalf("sign count = %d after failed update, want 5", stored.SignCount)
	}
}

// TestVerifierCounterPolicyAndBackupState verifies that Verifier applies the service counter policy
// and writes both signCount and backupState. | TestVerifierCounterPolicyAndBackupState 验证 Verifier
// 应用服务计数器策略并写入 signCount 与 backupState。
func TestVerifierCounterPolicyAndBackupState(t *testing.T) {
	stores := auth.NewMemoryStores()
	adapter, err := NewAuthCredentialStore(stores.Credentials)
	if err != nil {
		t.Fatalf("NewAuthCredentialStore: %v", err)
	}
	permissive := newTestService(t, func(config *Config) {
		config.CredentialStore = adapter
		config.CounterPolicy = CounterAllowBackupEligibleReset
	})
	signer := newECSigner(t)
	fixture := defaultRegistrationFixture(t, signer)
	fixture.flags = FlagUserPresent | FlagBackupEligible | FlagBackupState | FlagAttestedCredentialData
	fixture.signCount = 10
	fixture.register(t, permissive, testUser(), RegistrationOptions{})

	verifier, err := NewVerifier(permissive)
	if err != nil {
		t.Fatalf("NewVerifier: %v", err)
	}
	options, _, err := permissive.BeginLogin(context.Background(), testUser(), LoginOptions{})
	if err != nil {
		t.Fatalf("BeginLogin: %v", err)
	}
	login := defaultAssertionFixture(signer, fixture.credID)
	login.flags = FlagUserPresent | FlagBackupEligible | FlagBackupState
	login.signCount = 2
	encoded, err := json.Marshal(login.assertionResponse(t, options))
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	record := loadAuthCredential(t, stores, fixture.credID)
	ok, err := verifier.Verify(context.Background(), testUser(), record, string(encoded))
	if err != nil || !ok {
		t.Fatalf("Verify = %v, %v", ok, err)
	}
	if record.Data[CredentialDataSignCount] != "2" {
		t.Fatalf("%s = %q, want 2", CredentialDataSignCount, record.Data[CredentialDataSignCount])
	}
	if record.Data[CredentialDataBackupState] != "true" {
		t.Fatalf("%s = %q, want true", CredentialDataBackupState, record.Data[CredentialDataBackupState])
	}

	strict := newTestService(t, func(config *Config) {
		config.CredentialStore = adapter
	})
	strictVerifier, err := NewVerifier(strict)
	if err != nil {
		t.Fatalf("NewVerifier: %v", err)
	}
	options, _, err = strict.BeginLogin(context.Background(), testUser(), LoginOptions{})
	if err != nil {
		t.Fatalf("BeginLogin: %v", err)
	}
	login.signCount = 2
	encoded, err = json.Marshal(login.assertionResponse(t, options))
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	ok, err = strictVerifier.Verify(context.Background(), testUser(), record, string(encoded))
	if ok || !errors.Is(err, auth.ErrMFAInvalid) {
		t.Fatalf("strict Verify = %v, %v, want false and auth.ErrMFAInvalid", ok, err)
	}
}
