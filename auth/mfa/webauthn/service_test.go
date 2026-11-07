package webauthn

import (
	"context"
	"errors"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/shibingli/ydx/auth"
)

func testUser() *auth.User {
	return &auth.User{ID: "user-1", Username: "alice", DisplayName: "Alice"}
}

func TestServiceRegistrationAndLoginES256(t *testing.T) {
	service := newTestService(t, nil)
	signer := newECSigner(t)
	fixture := defaultRegistrationFixture(t, signer)
	fixture.signCount = 4
	credential := fixture.register(t, service, testUser(), RegistrationOptions{Name: "  My key  "})

	if string(credential.ID) != string(fixture.credID) {
		t.Fatalf("credential ID = %x", credential.ID)
	}
	if credential.UserID != "user-1" || credential.Username != "alice" || credential.UserDisplayName != "Alice" {
		t.Fatalf("credential owner = %#v", credential)
	}
	if string(credential.UserHandle) != "user-1" {
		t.Fatalf("user handle = %q", credential.UserHandle)
	}
	if credential.PublicKey == nil || credential.PublicKey.Alg != AlgES256 {
		t.Fatalf("public key = %#v", credential.PublicKey)
	}
	if credential.SignCount != 4 || credential.Name != "My key" || credential.AttestationType != AttestationTypeNone {
		t.Fatalf("credential = %#v", credential)
	}
	if len(credential.Transports) != 1 || credential.Transports[0] != "internal" {
		t.Fatalf("transports = %v", credential.Transports)
	}
	if credential.BackupEligible || credential.BackupState || credential.Discoverable {
		t.Fatalf("backup flags = %v/%v, discoverable = %v", credential.BackupEligible, credential.BackupState, credential.Discoverable)
	}
	if !credential.CreatedAt.Equal(testNow) {
		t.Fatalf("CreatedAt = %v", credential.CreatedAt)
	}

	options, ceremony, err := service.BeginLogin(context.Background(), testUser(), LoginOptions{})
	if err != nil {
		t.Fatalf("BeginLogin: %v", err)
	}
	if len(options.PublicKey.AllowCredentials) != 1 || options.PublicKey.AllowCredentials[0].ID != b64(fixture.credID) {
		t.Fatalf("allowCredentials = %#v", options.PublicKey.AllowCredentials)
	}
	if options.PublicKey.RPID != testRPID || options.PublicKey.UserVerification != string(UserVerificationPreferred) {
		t.Fatalf("request options = %#v", options.PublicKey)
	}
	if ceremony.Kind != CeremonyAuthentication || ceremony.UserID != "user-1" {
		t.Fatalf("ceremony = %#v", ceremony)
	}

	login := defaultAssertionFixture(signer, fixture.credID)
	login.signCount = 5
	used, err := service.FinishLogin(context.Background(), ceremony, login.assertionResponse(t, options))
	if err != nil {
		t.Fatalf("FinishLogin: %v", err)
	}
	if used.SignCount != 5 || !used.LastUsedAt.Equal(testNow) {
		t.Fatalf("used credential = %#v", used)
	}
	stored, err := service.credentials.GetByCredentialID(context.Background(), fixture.credID)
	if err != nil {
		t.Fatalf("GetByCredentialID: %v", err)
	}
	if stored.SignCount != 5 {
		t.Fatalf("persisted sign count = %d", stored.SignCount)
	}
}

func TestServiceRegistrationAndLoginEd25519(t *testing.T) {
	service := newTestService(t, nil)
	signer := newEdSigner(t)
	fixture := defaultRegistrationFixture(t, signer)
	credential := fixture.register(t, service, testUser(), RegistrationOptions{})

	if credential.PublicKey == nil || credential.PublicKey.Alg != AlgEdDSA || credential.PublicKey.Kty != KeyTypeOKP {
		t.Fatalf("public key = %#v", credential.PublicKey)
	}
	login := defaultAssertionFixture(signer, fixture.credID)
	login.signCount = 1
	used := login.login(t, service, testUser())
	if used.SignCount != 1 {
		t.Fatalf("sign count = %d", used.SignCount)
	}
}

func TestServiceRegistrationPackedSelf(t *testing.T) {
	service := newTestService(t, nil)
	signer := newECSigner(t)
	fixture := defaultRegistrationFixture(t, signer)
	fixture.format = FormatPacked
	fixture.statement = packedSelfStatement(signer)
	credential := fixture.register(t, service, testUser(), RegistrationOptions{Attestation: ConveyanceDirect})
	if credential.AttestationType != AttestationTypeSelf {
		t.Fatalf("attestation type = %q", credential.AttestationType)
	}
}

func TestServiceRegistrationChallengeIsSingleUse(t *testing.T) {
	service := newTestService(t, nil)
	signer := newECSigner(t)
	fixture := defaultRegistrationFixture(t, signer)
	options, ceremony, err := service.BeginRegistration(context.Background(), testUser(), RegistrationOptions{})
	if err != nil {
		t.Fatalf("BeginRegistration: %v", err)
	}
	response := fixture.creationResponse(t, options)
	if _, err := service.FinishRegistration(context.Background(), ceremony, response); err != nil {
		t.Fatalf("first FinishRegistration: %v", err)
	}
	if _, err := service.FinishRegistration(context.Background(), ceremony, response); !errors.Is(err, ErrChallengeNotFound) {
		t.Fatalf("replayed registration error = %v, want ErrChallengeNotFound", err)
	}
}

func TestServiceLoginChallengeIsSingleUse(t *testing.T) {
	service := newTestService(t, nil)
	signer := newECSigner(t)
	fixture := defaultRegistrationFixture(t, signer)
	fixture.register(t, service, testUser(), RegistrationOptions{})

	options, ceremony, err := service.BeginLogin(context.Background(), testUser(), LoginOptions{})
	if err != nil {
		t.Fatalf("BeginLogin: %v", err)
	}
	login := defaultAssertionFixture(signer, fixture.credID)
	login.signCount = 1
	response := login.assertionResponse(t, options)
	if _, err := service.FinishLogin(context.Background(), ceremony, response); err != nil {
		t.Fatalf("first FinishLogin: %v", err)
	}
	if _, err := service.FinishLogin(context.Background(), ceremony, response); !errors.Is(err, ErrChallengeNotFound) {
		t.Fatalf("replayed login error = %v, want ErrChallengeNotFound", err)
	}
}

func TestServiceLoginOriginMismatchConsumesChallenge(t *testing.T) {
	service := newTestService(t, nil)
	signer := newECSigner(t)
	fixture := defaultRegistrationFixture(t, signer)
	fixture.register(t, service, testUser(), RegistrationOptions{})

	options, ceremony, err := service.BeginLogin(context.Background(), testUser(), LoginOptions{})
	if err != nil {
		t.Fatalf("BeginLogin: %v", err)
	}
	bad := defaultAssertionFixture(signer, fixture.credID)
	bad.origin = "https://evil.test"
	if _, err := service.FinishLogin(context.Background(), ceremony, bad.assertionResponse(t, options)); !errors.Is(err, ErrOriginMismatch) {
		t.Fatalf("origin mismatch error = %v, want ErrOriginMismatch", err)
	}
	good := defaultAssertionFixture(signer, fixture.credID)
	if _, err := service.FinishLogin(context.Background(), ceremony, good.assertionResponse(t, options)); !errors.Is(err, ErrChallengeNotFound) {
		t.Fatalf("challenge survived a failed attempt: %v", err)
	}
}

func TestServiceLoginRPIDMismatch(t *testing.T) {
	service := newTestService(t, nil)
	signer := newECSigner(t)
	fixture := defaultRegistrationFixture(t, signer)
	fixture.register(t, service, testUser(), RegistrationOptions{})

	options, ceremony, err := service.BeginLogin(context.Background(), testUser(), LoginOptions{})
	if err != nil {
		t.Fatalf("BeginLogin: %v", err)
	}
	login := defaultAssertionFixture(signer, fixture.credID)
	login.rpID = "evil.test"
	if _, err := service.FinishLogin(context.Background(), ceremony, login.assertionResponse(t, options)); !errors.Is(err, ErrRPIDMismatch) {
		t.Fatalf("RP ID mismatch error = %v, want ErrRPIDMismatch", err)
	}
}

func TestServiceLoginSignCountRegression(t *testing.T) {
	service := newTestService(t, nil)
	signer := newECSigner(t)
	fixture := defaultRegistrationFixture(t, signer)
	fixture.signCount = 5
	fixture.register(t, service, testUser(), RegistrationOptions{})

	options, ceremony, err := service.BeginLogin(context.Background(), testUser(), LoginOptions{})
	if err != nil {
		t.Fatalf("BeginLogin: %v", err)
	}
	login := defaultAssertionFixture(signer, fixture.credID)
	login.signCount = 5
	if _, err := service.FinishLogin(context.Background(), ceremony, login.assertionResponse(t, options)); !errors.Is(err, ErrCloneDetected) {
		t.Fatalf("clone error = %v, want ErrCloneDetected", err)
	}
	stored, err := service.credentials.GetByCredentialID(context.Background(), fixture.credID)
	if err != nil {
		t.Fatalf("GetByCredentialID: %v", err)
	}
	if stored.SignCount != 5 {
		t.Fatalf("sign count changed to %d after a rejected assertion", stored.SignCount)
	}

	options, ceremony, err = service.BeginLogin(context.Background(), testUser(), LoginOptions{})
	if err != nil {
		t.Fatalf("BeginLogin: %v", err)
	}
	login.signCount = 6
	if _, err := service.FinishLogin(context.Background(), ceremony, login.assertionResponse(t, options)); err != nil {
		t.Fatalf("FinishLogin after regression: %v", err)
	}
}

func TestServiceLoginUserVerification(t *testing.T) {
	service := newTestService(t, nil)
	signer := newECSigner(t)
	fixture := defaultRegistrationFixture(t, signer)
	fixture.flags |= FlagUserVerified
	fixture.register(t, service, testUser(), RegistrationOptions{})

	options, ceremony, err := service.BeginLogin(context.Background(), testUser(), LoginOptions{UserVerification: UserVerificationRequired})
	if err != nil {
		t.Fatalf("BeginLogin: %v", err)
	}
	login := defaultAssertionFixture(signer, fixture.credID)
	if _, err := service.FinishLogin(context.Background(), ceremony, login.assertionResponse(t, options)); !errors.Is(err, ErrUserVerificationRequired) {
		t.Fatalf("UV error = %v, want ErrUserVerificationRequired", err)
	}

	options, ceremony, err = service.BeginLogin(context.Background(), testUser(), LoginOptions{UserVerification: UserVerificationRequired})
	if err != nil {
		t.Fatalf("BeginLogin: %v", err)
	}
	login.flags |= FlagUserVerified
	login.signCount = 1
	if _, err := service.FinishLogin(context.Background(), ceremony, login.assertionResponse(t, options)); err != nil {
		t.Fatalf("FinishLogin with UV: %v", err)
	}
}

func TestServiceRegistrationUserVerificationRequired(t *testing.T) {
	service := newTestService(t, nil)
	signer := newECSigner(t)
	fixture := defaultRegistrationFixture(t, signer)
	options, ceremony, err := service.BeginRegistration(context.Background(), testUser(), RegistrationOptions{UserVerification: UserVerificationRequired})
	if err != nil {
		t.Fatalf("BeginRegistration: %v", err)
	}
	if options.PublicKey.AuthenticatorSelection.UserVerification != string(UserVerificationRequired) {
		t.Fatalf("authenticatorSelection = %#v", options.PublicKey.AuthenticatorSelection)
	}
	if _, err := service.FinishRegistration(context.Background(), ceremony, fixture.creationResponse(t, options)); !errors.Is(err, ErrUserVerificationRequired) {
		t.Fatalf("UV error = %v, want ErrUserVerificationRequired", err)
	}

	options, ceremony, err = service.BeginRegistration(context.Background(), testUser(), RegistrationOptions{UserVerification: UserVerificationRequired})
	if err != nil {
		t.Fatalf("BeginRegistration: %v", err)
	}
	fixture.flags |= FlagUserVerified
	credential, err := service.FinishRegistration(context.Background(), ceremony, fixture.creationResponse(t, options))
	if err != nil {
		t.Fatalf("FinishRegistration with UV: %v", err)
	}
	if credential.SignCount != 0 {
		t.Fatalf("sign count = %d", credential.SignCount)
	}
}

func TestServiceLoginBadSignature(t *testing.T) {
	service := newTestService(t, nil)
	signer := newECSigner(t)
	fixture := defaultRegistrationFixture(t, signer)
	fixture.register(t, service, testUser(), RegistrationOptions{})

	options, ceremony, err := service.BeginLogin(context.Background(), testUser(), LoginOptions{})
	if err != nil {
		t.Fatalf("BeginLogin: %v", err)
	}
	login := defaultAssertionFixture(newECSigner(t), fixture.credID)
	login.signCount = 1
	if _, err := service.FinishLogin(context.Background(), ceremony, login.assertionResponse(t, options)); !errors.Is(err, ErrSignatureInvalid) {
		t.Fatalf("bad signature error = %v, want ErrSignatureInvalid", err)
	}
}

func TestServiceLoginUnknownCredential(t *testing.T) {
	service := newTestService(t, nil)
	signer := newECSigner(t)
	fixture := defaultRegistrationFixture(t, signer)
	fixture.register(t, service, testUser(), RegistrationOptions{})

	options, ceremony, err := service.BeginLogin(context.Background(), testUser(), LoginOptions{})
	if err != nil {
		t.Fatalf("BeginLogin: %v", err)
	}
	login := defaultAssertionFixture(signer, []byte("unknown-credential"))
	if _, err := service.FinishLogin(context.Background(), ceremony, login.assertionResponse(t, options)); !errors.Is(err, ErrCredentialNotFound) {
		t.Fatalf("unknown credential error = %v, want ErrCredentialNotFound", err)
	}
}

func TestServiceLoginCredentialOwnedByAnotherUser(t *testing.T) {
	service := newTestService(t, nil)
	signer := newECSigner(t)
	fixture := defaultRegistrationFixture(t, signer)
	credential := fixture.register(t, service, testUser(), RegistrationOptions{})

	other := &auth.User{ID: "user-2", Username: "bob"}
	options, ceremony, err := service.BeginLogin(context.Background(), other, LoginOptions{
		AllowCredentials: []CredentialDescriptor{credential.Descriptor()},
	})
	if err != nil {
		t.Fatalf("BeginLogin: %v", err)
	}
	login := defaultAssertionFixture(signer, fixture.credID)
	login.signCount = 1
	if _, err := service.FinishLogin(context.Background(), ceremony, login.assertionResponse(t, options)); !errors.Is(err, ErrUserHandleMismatch) {
		t.Fatalf("cross-user error = %v, want ErrUserHandleMismatch", err)
	}
}

func TestServiceDiscoverableLogin(t *testing.T) {
	service := newTestService(t, nil)
	signer := newECSigner(t)
	fixture := defaultRegistrationFixture(t, signer)
	credential := fixture.register(t, service, testUser(), RegistrationOptions{ResidentKey: ResidentKeyRequired})
	if !credential.Discoverable {
		t.Fatal("required resident key was not marked discoverable")
	}

	options, ceremony, err := service.BeginDiscoverableLogin(context.Background(), DiscoverableLoginOptions{})
	if err != nil {
		t.Fatalf("BeginDiscoverableLogin: %v", err)
	}
	if len(options.PublicKey.AllowCredentials) != 0 {
		t.Fatalf("allowCredentials = %#v", options.PublicKey.AllowCredentials)
	}
	login := defaultAssertionFixture(signer, fixture.credID)
	login.userHandle = []byte("user-1")
	login.signCount = 1
	used, handle, err := service.FinishDiscoverableLogin(context.Background(), ceremony, login.assertionResponse(t, options))
	if err != nil {
		t.Fatalf("FinishDiscoverableLogin: %v", err)
	}
	if string(handle) != "user-1" || used.UserID != "user-1" {
		t.Fatalf("handle = %q, credential = %#v", handle, used)
	}

	options, ceremony, err = service.BeginDiscoverableLogin(context.Background(), DiscoverableLoginOptions{})
	if err != nil {
		t.Fatalf("BeginDiscoverableLogin: %v", err)
	}
	missing := defaultAssertionFixture(signer, fixture.credID)
	if _, _, err := service.FinishDiscoverableLogin(context.Background(), ceremony, missing.assertionResponse(t, options)); !errors.Is(err, ErrUserHandleMismatch) {
		t.Fatalf("missing handle error = %v, want ErrUserHandleMismatch", err)
	}

	options, ceremony, err = service.BeginDiscoverableLogin(context.Background(), DiscoverableLoginOptions{})
	if err != nil {
		t.Fatalf("BeginDiscoverableLogin: %v", err)
	}
	wrong := defaultAssertionFixture(signer, fixture.credID)
	wrong.userHandle = []byte("user-2")
	if _, _, err := service.FinishDiscoverableLogin(context.Background(), ceremony, wrong.assertionResponse(t, options)); !errors.Is(err, ErrUserHandleMismatch) {
		t.Fatalf("wrong handle error = %v, want ErrUserHandleMismatch", err)
	}
}

// TestServiceDiscoverableLoginAcceptsCredentialWithoutDiscoverableFlag documents that the ceremony
// cannot infer the resident-key property from the stored flag: a credential created with
// residentKey "preferred" may be discoverable even when credProps was not requested. |
// TestServiceDiscoverableLoginAcceptsCredentialWithoutDiscoverableFlag 说明流程不能根据存储标志推断
// 常驻密钥属性：以 residentKey "preferred" 创建且未请求 credProps 的凭据仍可能是可发现的。
func TestServiceDiscoverableLoginAcceptsCredentialWithoutDiscoverableFlag(t *testing.T) {
	service := newTestService(t, nil)
	signer := newECSigner(t)
	fixture := defaultRegistrationFixture(t, signer)
	credential := fixture.register(t, service, testUser(), RegistrationOptions{ResidentKey: ResidentKeyDiscouraged})
	if credential.Discoverable {
		t.Fatal("discouraged resident key was marked discoverable")
	}
	options, ceremony, err := service.BeginDiscoverableLogin(context.Background(), DiscoverableLoginOptions{})
	if err != nil {
		t.Fatalf("BeginDiscoverableLogin: %v", err)
	}
	login := defaultAssertionFixture(signer, fixture.credID)
	login.userHandle = []byte("user-1")
	if _, _, err := service.FinishDiscoverableLogin(context.Background(), ceremony, login.assertionResponse(t, options)); err != nil {
		t.Fatalf("discoverable login does not require the stored discoverable flag: %v", err)
	}
}

func TestServiceDiscoverableAndUserBoundCeremoniesAreNotInterchangeable(t *testing.T) {
	service := newTestService(t, nil)
	signer := newECSigner(t)
	fixture := defaultRegistrationFixture(t, signer)
	fixture.register(t, service, testUser(), RegistrationOptions{ResidentKey: ResidentKeyRequired})

	options, ceremony, err := service.BeginDiscoverableLogin(context.Background(), DiscoverableLoginOptions{})
	if err != nil {
		t.Fatalf("BeginDiscoverableLogin: %v", err)
	}
	login := defaultAssertionFixture(signer, fixture.credID)
	login.userHandle = []byte("user-1")
	if _, err := service.FinishLogin(context.Background(), ceremony, login.assertionResponse(t, options)); !errors.Is(err, ErrCeremonyMismatch) {
		t.Fatalf("discoverable as user-bound error = %v, want ErrCeremonyMismatch", err)
	}

	options, ceremony, err = service.BeginLogin(context.Background(), testUser(), LoginOptions{})
	if err != nil {
		t.Fatalf("BeginLogin: %v", err)
	}
	if _, _, err := service.FinishDiscoverableLogin(context.Background(), ceremony, login.assertionResponse(t, options)); !errors.Is(err, ErrCeremonyMismatch) {
		t.Fatalf("user-bound as discoverable error = %v, want ErrCeremonyMismatch", err)
	}
}

func TestServiceRegistrationExcludedCredential(t *testing.T) {
	service := newTestService(t, nil)
	signer := newECSigner(t)
	fixture := defaultRegistrationFixture(t, signer)
	fixture.register(t, service, testUser(), RegistrationOptions{})

	options, ceremony, err := service.BeginRegistration(context.Background(), testUser(), RegistrationOptions{})
	if err != nil {
		t.Fatalf("BeginRegistration: %v", err)
	}
	if len(options.PublicKey.ExcludeCredentials) != 1 {
		t.Fatalf("excludeCredentials = %#v", options.PublicKey.ExcludeCredentials)
	}
	if _, err := service.FinishRegistration(context.Background(), ceremony, fixture.creationResponse(t, options)); !errors.Is(err, ErrCredentialExists) {
		t.Fatalf("excluded credential error = %v, want ErrCredentialExists", err)
	}
}

func TestServiceRegistrationResidentKeyRequiredCredPropsFalse(t *testing.T) {
	service := newTestService(t, nil)
	signer := newECSigner(t)
	fixture := defaultRegistrationFixture(t, signer)
	fixture.extension.CredProps = &CredPropsResult{RK: false}
	options, ceremony, err := service.BeginRegistration(context.Background(), testUser(), RegistrationOptions{ResidentKey: ResidentKeyRequired})
	if err != nil {
		t.Fatalf("BeginRegistration: %v", err)
	}
	if options.PublicKey.Extensions == nil || !options.PublicKey.Extensions.CredProps {
		t.Fatalf("credProps was not requested: %#v", options.PublicKey.Extensions)
	}
	if _, err := service.FinishRegistration(context.Background(), ceremony, fixture.creationResponse(t, options)); !errors.Is(err, ErrResidentKeyRequired) {
		t.Fatalf("error = %v, want ErrResidentKeyRequired", err)
	}

	options, ceremony, err = service.BeginRegistration(context.Background(), testUser(), RegistrationOptions{ResidentKey: ResidentKeyRequired})
	if err != nil {
		t.Fatalf("BeginRegistration: %v", err)
	}
	fixture.extension.CredProps = &CredPropsResult{RK: true}
	credential, err := service.FinishRegistration(context.Background(), ceremony, fixture.creationResponse(t, options))
	if err != nil {
		t.Fatalf("FinishRegistration: %v", err)
	}
	if !credential.Discoverable {
		t.Fatal("credProps rk=true was not persisted")
	}
}

func TestServiceRegistrationCredentialIDMismatch(t *testing.T) {
	service := newTestService(t, nil)
	signer := newECSigner(t)
	fixture := defaultRegistrationFixture(t, signer)
	options, ceremony, err := service.BeginRegistration(context.Background(), testUser(), RegistrationOptions{})
	if err != nil {
		t.Fatalf("BeginRegistration: %v", err)
	}
	response := fixture.creationResponse(t, options)
	other := []byte("other-credential")
	response.ID = b64(other)
	response.RawID = b64(other)
	if _, err := service.FinishRegistration(context.Background(), ceremony, response); !errors.Is(err, ErrCredentialIDMismatch) {
		t.Fatalf("error = %v, want ErrCredentialIDMismatch", err)
	}
}

func TestServiceRegistrationRPIDMismatch(t *testing.T) {
	service := newTestService(t, nil)
	signer := newECSigner(t)
	options, ceremony, err := service.BeginRegistration(context.Background(), testUser(), RegistrationOptions{})
	if err != nil {
		t.Fatalf("BeginRegistration: %v", err)
	}
	fixture := defaultRegistrationFixture(t, signer)
	authData := buildAuthData(t, "evil.test", fixture.flags, 0, [16]byte{1}, fixture.credID, signer.coseKey(t), nil)
	clientData := &ClientData{Type: ClientDataTypeCreate, Challenge: options.PublicKey.Challenge, Origin: testOrigin}
	clientDataJSON := mustMarshal(t, clientData)
	response := &CredentialCreationResponse{
		ID:    b64(fixture.credID),
		RawID: b64(fixture.credID),
		Type:  "public-key",
		Response: AuthenticatorAttestationResponse{
			ClientDataJSON:    b64(clientDataJSON),
			AttestationObject: b64(makeAttestationObject(t, FormatNone, nil, authData)),
		},
	}
	if _, err := service.FinishRegistration(context.Background(), ceremony, response); !errors.Is(err, ErrRPIDMismatch) {
		t.Fatalf("error = %v, want ErrRPIDMismatch", err)
	}
}

func TestServiceRegistrationCeremonyCopyMismatch(t *testing.T) {
	service := newTestService(t, nil)
	signer := newECSigner(t)
	fixture := defaultRegistrationFixture(t, signer)
	options, ceremony, err := service.BeginRegistration(context.Background(), testUser(), RegistrationOptions{})
	if err != nil {
		t.Fatalf("BeginRegistration: %v", err)
	}
	response := fixture.creationResponse(t, options)
	swapped := *ceremony
	swapped.UserID = "user-2"
	if _, err := service.FinishRegistration(context.Background(), &swapped, response); !errors.Is(err, ErrCeremonyMismatch) {
		t.Fatalf("swapped ceremony error = %v, want ErrCeremonyMismatch", err)
	}
}

func TestServiceRegistrationInvalidOptions(t *testing.T) {
	service := newTestService(t, nil)
	longID := strings.Repeat("x", maxUserHandleLength+1)
	cases := []struct {
		name string
		user *auth.User
		opts RegistrationOptions
		want error
	}{
		{name: "nil user", user: nil, want: ErrInvalidRequest},
		{name: "empty user ID", user: &auth.User{}, want: ErrInvalidRequest},
		{name: "user ID too long", user: &auth.User{ID: longID}, want: ErrInvalidRequest},
		{name: "invalid user verification", user: testUser(), opts: RegistrationOptions{UserVerification: "sometimes"}, want: ErrInvalidRequest},
		{name: "invalid attestation", user: testUser(), opts: RegistrationOptions{Attestation: "maybe"}, want: ErrInvalidRequest},
		{name: "invalid attachment", user: testUser(), opts: RegistrationOptions{AuthenticatorAttachment: "usb"}, want: ErrInvalidRequest},
		{name: "invalid resident key", user: testUser(), opts: RegistrationOptions{ResidentKey: "always"}, want: ErrInvalidRequest},
		{name: "invalid algorithm", user: testUser(), opts: RegistrationOptions{Algorithms: []int{9999}}, want: ErrUnsupportedAlgorithm},
		{name: "empty algorithm list", user: testUser(), opts: RegistrationOptions{Algorithms: []int{}}, want: ErrInvalidConfig},
		{name: "credProtect without policy", user: testUser(), opts: RegistrationOptions{Extensions: &RegistrationExtensions{EnforceCredentialProtectionPolicy: true}}, want: ErrInvalidRequest},
		{name: "unknown credProtect policy", user: testUser(), opts: RegistrationOptions{Extensions: &RegistrationExtensions{CredentialProtectionPolicy: "high"}}, want: ErrInvalidRequest},
	}
	for _, test := range cases {
		t.Run(test.name, func(t *testing.T) {
			if _, _, err := service.BeginRegistration(context.Background(), test.user, test.opts); !errors.Is(err, test.want) {
				t.Fatalf("error = %v, want %v", err, test.want)
			}
		})
	}
}

func TestServiceLoginInvalidOptions(t *testing.T) {
	service := newTestService(t, nil)
	user := testUser()
	if _, _, err := service.BeginLogin(context.Background(), user, LoginOptions{}); !errors.Is(err, ErrCredentialNotFound) {
		t.Fatalf("empty store error = %v, want ErrCredentialNotFound", err)
	}
	if _, _, err := service.BeginLogin(context.Background(), user, LoginOptions{UserVerification: "sometimes"}); !errors.Is(err, ErrInvalidRequest) {
		t.Fatalf("invalid UV error = %v", err)
	}
	if _, _, err := service.BeginLogin(context.Background(), nil, LoginOptions{}); !errors.Is(err, ErrInvalidRequest) {
		t.Fatalf("nil user error = %v", err)
	}
	if _, _, err := service.BeginLogin(context.Background(), user, LoginOptions{
		AllowCredentials: []CredentialDescriptor{{Type: "public-key", ID: "!!!"}},
	}); !errors.Is(err, ErrInvalidRequest) {
		t.Fatalf("invalid descriptor error = %v", err)
	}
	if _, _, err := service.BeginDiscoverableLogin(context.Background(), DiscoverableLoginOptions{UserVerification: "sometimes"}); !errors.Is(err, ErrInvalidRequest) {
		t.Fatalf("invalid discoverable UV error = %v", err)
	}
}

func TestServiceCeremonyExpiry(t *testing.T) {
	now := testNow
	clock := func() time.Time { return now }
	service := newTestService(t, func(config *Config) {
		config.Clock = clock
		config.ChallengeStore = NewMemoryChallengeStoreWithClock(clock)
	})
	signer := newECSigner(t)
	fixture := defaultRegistrationFixture(t, signer)
	fixture.register(t, service, testUser(), RegistrationOptions{})
	options, ceremony, err := service.BeginLogin(context.Background(), testUser(), LoginOptions{Timeout: time.Minute})
	if err != nil {
		t.Fatalf("BeginLogin: %v", err)
	}
	login := defaultAssertionFixture(signer, fixture.credID)
	response := login.assertionResponse(t, options)
	now = testNow.Add(2 * time.Minute)
	if _, err := service.FinishLogin(context.Background(), ceremony, response); !errors.Is(err, ErrChallengeExpired) {
		t.Fatalf("expired ceremony error = %v, want ErrChallengeExpired", err)
	}
	if _, err := service.FinishLogin(context.Background(), ceremony, response); !errors.Is(err, ErrChallengeNotFound) {
		t.Fatalf("expired challenge was not discarded: %v", err)
	}
}

func TestServiceTokenBindingPolicy(t *testing.T) {
	service := newTestService(t, func(config *Config) {
		config.RequireTokenBinding = true
		config.TokenBindingID = "bound-id"
	})
	signer := newECSigner(t)
	fixture := defaultRegistrationFixture(t, signer)
	options, ceremony, err := service.BeginRegistration(context.Background(), testUser(), RegistrationOptions{})
	if err != nil {
		t.Fatalf("BeginRegistration: %v", err)
	}
	response := fixture.creationResponse(t, options)
	if _, err := service.FinishRegistration(context.Background(), ceremony, response); !errors.Is(err, ErrTokenBindingMismatch) {
		t.Fatalf("missing token binding error = %v, want ErrTokenBindingMismatch", err)
	}

	options, ceremony, err = service.BeginRegistration(context.Background(), testUser(), RegistrationOptions{})
	if err != nil {
		t.Fatalf("BeginRegistration: %v", err)
	}
	authData := buildAuthData(t, testRPID, fixture.flags, 0, [16]byte{1}, fixture.credID, signer.coseKey(t), nil)
	clientData := &ClientData{
		Type:         ClientDataTypeCreate,
		Challenge:    options.PublicKey.Challenge,
		Origin:       testOrigin,
		TokenBinding: &TokenBinding{Status: "present", ID: "bound-id"},
	}
	clientDataJSON := mustMarshal(t, clientData)
	response = &CredentialCreationResponse{
		ID:    b64(fixture.credID),
		RawID: b64(fixture.credID),
		Type:  "public-key",
		Response: AuthenticatorAttestationResponse{
			ClientDataJSON:    b64(clientDataJSON),
			AttestationObject: b64(makeAttestationObject(t, FormatNone, nil, authData)),
		},
	}
	if _, err := service.FinishRegistration(context.Background(), ceremony, response); err != nil {
		t.Fatalf("FinishRegistration with token binding: %v", err)
	}
}

func TestServiceContextCancellation(t *testing.T) {
	service := newTestService(t, nil)
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, _, err := service.BeginRegistration(ctx, testUser(), RegistrationOptions{}); !errors.Is(err, context.Canceled) {
		t.Fatalf("BeginRegistration error = %v", err)
	}
	if _, _, err := service.BeginLogin(ctx, testUser(), LoginOptions{}); !errors.Is(err, context.Canceled) {
		t.Fatalf("BeginLogin error = %v", err)
	}
	if _, _, err := service.BeginDiscoverableLogin(ctx, DiscoverableLoginOptions{}); !errors.Is(err, context.Canceled) {
		t.Fatalf("BeginDiscoverableLogin error = %v", err)
	}
}

func TestServiceCredentialCloneIsolation(t *testing.T) {
	service := newTestService(t, nil)
	signer := newECSigner(t)
	fixture := defaultRegistrationFixture(t, signer)
	credential := fixture.register(t, service, testUser(), RegistrationOptions{})
	credential.PublicKey.X[0] ^= 0xff
	stored, err := service.credentials.GetByCredentialID(context.Background(), fixture.credID)
	if err != nil {
		t.Fatalf("GetByCredentialID: %v", err)
	}
	if stored.PublicKey.X[0] == credential.PublicKey.X[0] {
		t.Fatal("stored credential shares the COSE key with the caller")
	}
}

// TestServiceLoginConcurrentSameSignCount verifies that concurrent assertions carrying the same sign
// count cannot all pass clone detection. | TestServiceLoginConcurrentSameSignCount 验证携带相同签名
// 计数器的并发断言不会全部通过克隆检测。
func TestServiceLoginConcurrentSameSignCount(t *testing.T) {
	service := newTestService(t, nil)
	signer := newECSigner(t)
	fixture := defaultRegistrationFixture(t, signer)
	fixture.signCount = 10
	fixture.register(t, service, testUser(), RegistrationOptions{})

	const attempts = 8
	type loginAttempt struct {
		ceremony *Ceremony
		response *CredentialAssertionResponse
	}
	attemptsList := make([]loginAttempt, 0, attempts)
	for i := 0; i < attempts; i++ {
		options, ceremony, err := service.BeginLogin(context.Background(), testUser(), LoginOptions{})
		if err != nil {
			t.Fatalf("BeginLogin: %v", err)
		}
		login := defaultAssertionFixture(signer, fixture.credID)
		login.signCount = 11
		attemptsList = append(attemptsList, loginAttempt{
			ceremony: ceremony,
			response: login.assertionResponse(t, options),
		})
	}
	results := make(chan error, attempts)
	var wg sync.WaitGroup
	for _, attempt := range attemptsList {
		wg.Add(1)
		go func(attempt loginAttempt) {
			defer wg.Done()
			_, err := service.FinishLogin(context.Background(), attempt.ceremony, attempt.response)
			results <- err
		}(attempt)
	}
	wg.Wait()
	close(results)
	successes, clones := 0, 0
	for err := range results {
		switch {
		case err == nil:
			successes++
		case errors.Is(err, ErrCloneDetected):
			clones++
		default:
			t.Fatalf("unexpected FinishLogin error: %v", err)
		}
	}
	if successes != 1 || clones != attempts-1 {
		t.Fatalf("successes = %d, clone errors = %d, want 1 and %d", successes, clones, attempts-1)
	}
}

func TestServiceRPIDAndDisplayName(t *testing.T) {
	service := newTestService(t, nil)
	if service.RPID() != testRPID {
		t.Fatalf("RPID = %q", service.RPID())
	}
	if service.RPDisplayName() != "Example RP" {
		t.Fatalf("RPDisplayName = %q", service.RPDisplayName())
	}
}
