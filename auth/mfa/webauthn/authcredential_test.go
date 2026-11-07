package webauthn

import (
	"context"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/shibingli/ydx/auth"
	"github.com/shibingli/ydx/base64"
	"github.com/shibingli/ydx/json"
)

func newAuthStoreService(t *testing.T, stores auth.Stores) (*Service, *AuthCredentialStore) {
	t.Helper()
	adapter, err := NewAuthCredentialStore(stores.Credentials)
	if err != nil {
		t.Fatalf("NewAuthCredentialStore: %v", err)
	}
	service := newTestService(t, func(config *Config) {
		config.CredentialStore = adapter
	})
	return service, adapter
}

func loadAuthCredential(t *testing.T, stores auth.Stores, credentialID []byte) *auth.Credential {
	t.Helper()
	record, err := stores.Credentials.GetCredential(context.Background(), b64(credentialID))
	if err != nil {
		t.Fatalf("GetCredential: %v", err)
	}
	return record
}

func TestNewAuthCredentialStoreValidation(t *testing.T) {
	if _, err := NewAuthCredentialStore(nil); !errors.Is(err, ErrInvalidConfig) {
		t.Fatalf("nil store error = %v", err)
	}
	var nilAdapter *AuthCredentialStore
	if _, err := nilAdapter.GetByCredentialID(context.Background(), []byte("id")); !errors.Is(err, ErrInvalidConfig) {
		t.Fatalf("nil adapter Get error = %v", err)
	}
	if err := nilAdapter.Save(context.Background(), &Credential{}); !errors.Is(err, ErrInvalidConfig) {
		t.Fatalf("nil adapter Save error = %v", err)
	}
	if err := nilAdapter.UpdateSignCount(context.Background(), []byte("id"), 1); !errors.Is(err, ErrInvalidConfig) {
		t.Fatalf("nil adapter UpdateSignCount error = %v", err)
	}
	if _, err := nilAdapter.ListByUser(context.Background(), "user"); !errors.Is(err, ErrInvalidConfig) {
		t.Fatalf("nil adapter ListByUser error = %v", err)
	}
}

func TestAuthCredentialStoreRoundTrip(t *testing.T) {
	stores := auth.NewMemoryStores()
	service, adapter := newAuthStoreService(t, stores)
	signer := newECSigner(t)
	fixture := defaultRegistrationFixture(t, signer)
	fixture.signCount = 3
	credential := fixture.register(t, service, testUser(), RegistrationOptions{Name: "Passkey"})

	record := loadAuthCredential(t, stores, fixture.credID)
	if record.Type != auth.CredentialWebAuthn {
		t.Fatalf("auth credential type = %q", record.Type)
	}
	if record.ID != b64(fixture.credID) || record.UserID != "user-1" || record.Name != "Passkey" {
		t.Fatalf("auth credential = %#v", record)
	}
	if record.Data[CredentialDataCredentialID] != b64(fixture.credID) {
		t.Fatalf("%s = %q", CredentialDataCredentialID, record.Data[CredentialDataCredentialID])
	}
	if record.Data[CredentialDataSignCount] != "3" {
		t.Fatalf("%s = %q", CredentialDataSignCount, record.Data[CredentialDataSignCount])
	}
	if record.Data[CredentialDataAAGUID] != b64([]byte{1, 2, 3, 4, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0}) {
		t.Fatalf("%s = %q", CredentialDataAAGUID, record.Data[CredentialDataAAGUID])
	}
	if record.Data[CredentialDataTransports] != "internal" {
		t.Fatalf("%s = %q", CredentialDataTransports, record.Data[CredentialDataTransports])
	}
	if record.Data[CredentialDataBackupEligible] != "false" || record.Data[CredentialDataBackupState] != "false" {
		t.Fatalf("backup flags = %q/%q", record.Data[CredentialDataBackupEligible], record.Data[CredentialDataBackupState])
	}
	if record.Data[CredentialDataDiscoverable] != "false" {
		t.Fatalf("%s = %q", CredentialDataDiscoverable, record.Data[CredentialDataDiscoverable])
	}
	if record.Data[CredentialDataAttestationType] != string(AttestationTypeNone) {
		t.Fatalf("%s = %q", CredentialDataAttestationType, record.Data[CredentialDataAttestationType])
	}
	if record.Data[CredentialDataUserHandle] != b64([]byte("user-1")) {
		t.Fatalf("%s = %q", CredentialDataUserHandle, record.Data[CredentialDataUserHandle])
	}
	encodedKey := record.Data[CredentialDataPublicKey]
	keyBytes, err := base64.RawURLEncoding.DecodeString(encodedKey)
	if err != nil {
		t.Fatalf("decode %s: %v", CredentialDataPublicKey, err)
	}
	key, err := ParseCOSEKey(keyBytes)
	if err != nil {
		t.Fatalf("ParseCOSEKey: %v", err)
	}
	if key.Alg != AlgES256 {
		t.Fatalf("stored key algorithm = %d", key.Alg)
	}

	loaded, err := adapter.GetByCredentialID(context.Background(), fixture.credID)
	if err != nil {
		t.Fatalf("GetByCredentialID: %v", err)
	}
	if loaded.UserID != credential.UserID || loaded.SignCount != 3 || loaded.Name != "Passkey" {
		t.Fatalf("loaded credential = %#v", loaded)
	}
	if loaded.PublicKey == nil || loaded.PublicKey.Alg != AlgES256 {
		t.Fatalf("loaded public key = %#v", loaded.PublicKey)
	}
	if !loaded.CreatedAt.Equal(testNow) {
		t.Fatalf("loaded CreatedAt = %v", loaded.CreatedAt)
	}
	if len(loaded.Transports) != 1 || loaded.Transports[0] != "internal" {
		t.Fatalf("loaded transports = %v", loaded.Transports)
	}

	if err := adapter.Save(context.Background(), loaded); !errors.Is(err, ErrCredentialExists) {
		t.Fatalf("duplicate Save error = %v, want ErrCredentialExists", err)
	}
	if _, err := adapter.GetByCredentialID(context.Background(), []byte("missing")); !errors.Is(err, ErrCredentialNotFound) {
		t.Fatalf("missing Get error = %v, want ErrCredentialNotFound", err)
	}
	if err := adapter.Save(context.Background(), &Credential{}); !errors.Is(err, ErrInvalidCredential) {
		t.Fatalf("invalid Save error = %v", err)
	}
}

func TestAuthCredentialStoreUpdateAndList(t *testing.T) {
	stores := auth.NewMemoryStores()
	service, adapter := newAuthStoreService(t, stores)
	signer := newECSigner(t)
	fixture := defaultRegistrationFixture(t, signer)
	fixture.register(t, service, testUser(), RegistrationOptions{})

	other := &auth.Credential{ID: "otp-1", UserID: "user-1", Type: auth.CredentialTOTP}
	if err := stores.Credentials.CreateCredential(context.Background(), other); err != nil {
		t.Fatalf("CreateCredential: %v", err)
	}

	if err := adapter.UpdateSignCount(context.Background(), fixture.credID, 42); err != nil {
		t.Fatalf("UpdateSignCount: %v", err)
	}
	record := loadAuthCredential(t, stores, fixture.credID)
	if record.Data[CredentialDataSignCount] != "42" {
		t.Fatalf("%s = %q", CredentialDataSignCount, record.Data[CredentialDataSignCount])
	}
	if record.LastUsedAt.IsZero() || record.UpdatedAt.IsZero() {
		t.Fatalf("timestamps were not updated: %#v", record)
	}
	if err := adapter.UpdateSignCount(context.Background(), []byte("missing"), 1); !errors.Is(err, ErrCredentialNotFound) {
		t.Fatalf("missing UpdateSignCount error = %v", err)
	}

	list, err := adapter.ListByUser(context.Background(), "user-1")
	if err != nil {
		t.Fatalf("ListByUser: %v", err)
	}
	if len(list) != 1 || string(list[0].ID) != string(fixture.credID) {
		t.Fatalf("ListByUser = %#v", list)
	}
	if list[0].SignCount != 42 {
		t.Fatalf("ListByUser sign count = %d", list[0].SignCount)
	}
	empty, err := adapter.ListByUser(context.Background(), "user-2")
	if err != nil {
		t.Fatalf("ListByUser(user-2): %v", err)
	}
	if len(empty) != 0 {
		t.Fatalf("ListByUser(user-2) = %#v", empty)
	}
}

func TestAuthCredentialStoreRejectsNonWebAuthn(t *testing.T) {
	stores := auth.NewMemoryStores()
	_, adapter := newAuthStoreService(t, stores)
	rawID := []byte("otp-1")
	record := &auth.Credential{ID: b64(rawID), UserID: "user-1", Type: auth.CredentialTOTP}
	if err := stores.Credentials.CreateCredential(context.Background(), record); err != nil {
		t.Fatalf("CreateCredential: %v", err)
	}
	if _, err := adapter.GetByCredentialID(context.Background(), rawID); !errors.Is(err, ErrInvalidCredential) {
		t.Fatalf("non-webauthn Get error = %v, want ErrInvalidCredential", err)
	}
}

func TestAuthCredentialStoreMalformedData(t *testing.T) {
	signer := newECSigner(t)
	validKey, err := signer.coseKey(t).Encode()
	if err != nil {
		t.Fatalf("Encode: %v", err)
	}
	rawID := []byte("id")
	validData := func() map[string]string {
		return map[string]string{
			CredentialDataPublicKey:       b64(validKey),
			CredentialDataCredentialID:    b64(rawID),
			CredentialDataSignCount:       "1",
			CredentialDataAAGUID:          b64(make([]byte, 16)),
			CredentialDataTransports:      "internal",
			CredentialDataBackupEligible:  "false",
			CredentialDataBackupState:     "false",
			CredentialDataDiscoverable:    "false",
			CredentialDataAttestationType: string(AttestationTypeNone),
			CredentialDataUserHandle:      b64([]byte("user")),
		}
	}
	cases := []struct {
		name   string
		check  error
		mutate func(data map[string]string)
	}{
		{name: "nil data", check: ErrInvalidCredential, mutate: func(data map[string]string) {}},
		{name: "missing public key", check: ErrInvalidCredential, mutate: func(data map[string]string) { delete(data, CredentialDataPublicKey) }},
		{name: "invalid public key", check: ErrInvalidCredential, mutate: func(data map[string]string) { data[CredentialDataPublicKey] = "!!!" }},
		{name: "mismatched credential ID", check: ErrCredentialIDMismatch, mutate: func(data map[string]string) { data[CredentialDataCredentialID] = b64([]byte("other")) }},
		{name: "invalid sign count", check: ErrInvalidCredential, mutate: func(data map[string]string) { data[CredentialDataSignCount] = "many" }},
		{name: "invalid AAGUID", check: ErrInvalidCredential, mutate: func(data map[string]string) { data[CredentialDataAAGUID] = b64([]byte("short")) }},
		{name: "invalid backup flag", check: ErrInvalidCredential, mutate: func(data map[string]string) { data[CredentialDataBackupEligible] = "maybe" }},
		{name: "invalid discoverable flag", check: ErrInvalidCredential, mutate: func(data map[string]string) { data[CredentialDataDiscoverable] = "maybe" }},
		{name: "invalid user handle", check: ErrInvalidCredential, mutate: func(data map[string]string) { data[CredentialDataUserHandle] = "!!!" }},
		{name: "invalid attestation type", check: ErrInvalidCredential, mutate: func(data map[string]string) { data[CredentialDataAttestationType] = "quantum" }},
	}
	for _, test := range cases {
		t.Run(test.name, func(t *testing.T) {
			stores := auth.NewMemoryStores()
			_, adapter := newAuthStoreService(t, stores)
			data := validData()
			if test.name == "nil data" {
				data = nil
			} else {
				test.mutate(data)
			}
			record := &auth.Credential{ID: b64(rawID), UserID: "user", Type: auth.CredentialWebAuthn, Data: data}
			if err := stores.Credentials.CreateCredential(context.Background(), record); err != nil {
				t.Fatalf("CreateCredential: %v", err)
			}
			if _, err := adapter.GetByCredentialID(context.Background(), rawID); !errors.Is(err, test.check) {
				t.Fatalf("error = %v, want %v", err, test.check)
			}
		})
	}

	stores := auth.NewMemoryStores()
	_, adapter := newAuthStoreService(t, stores)
	record := &auth.Credential{ID: b64(rawID), UserID: "user", Type: auth.CredentialWebAuthn, Data: validData()}
	if err := stores.Credentials.CreateCredential(context.Background(), record); err != nil {
		t.Fatalf("CreateCredential: %v", err)
	}
	if _, err := adapter.GetByCredentialID(context.Background(), rawID); err != nil {
		t.Fatalf("valid record rejected: %v", err)
	}
}

func TestAuthCredentialStoreDataLayoutDocs(t *testing.T) {
	keys := []string{
		CredentialDataCredentialID,
		CredentialDataPublicKey,
		CredentialDataSignCount,
		CredentialDataAAGUID,
		CredentialDataTransports,
		CredentialDataBackupEligible,
		CredentialDataBackupState,
		CredentialDataUserHandle,
		CredentialDataDiscoverable,
		CredentialDataAttestationType,
	}
	want := []string{"credentialId", "publicKey", "signCount", "aaguid", "transports", "backupEligible", "backupState", "userHandle", "discoverable", "attestationType"}
	for i := range want {
		if keys[i] != want[i] {
			t.Fatalf("CredentialData key %d = %q, want %q", i, keys[i], want[i])
		}
	}
}

func newVerifierPair(t *testing.T) (*Service, *Verifier, auth.Stores, *registrationFixture, *Credential) {
	t.Helper()
	stores := auth.NewMemoryStores()
	service, _ := newAuthStoreService(t, stores)
	signer := newECSigner(t)
	fixture := defaultRegistrationFixture(t, signer)
	credential := fixture.register(t, service, testUser(), RegistrationOptions{})
	verifier, err := NewVerifier(service)
	if err != nil {
		t.Fatalf("NewVerifier: %v", err)
	}
	return service, verifier, stores, fixture, credential
}

func TestNewVerifierValidation(t *testing.T) {
	if _, err := NewVerifier(nil); !errors.Is(err, ErrInvalidConfig) {
		t.Fatalf("nil service error = %v", err)
	}
	var nilVerifier *Verifier
	if ok, err := nilVerifier.Verify(context.Background(), testUser(), &auth.Credential{}, "{}"); ok || !errors.Is(err, auth.ErrMFAInvalid) {
		t.Fatalf("nil verifier = %v, %v", ok, err)
	}
	verifier := &Verifier{}
	if ok, err := verifier.Verify(context.Background(), testUser(), &auth.Credential{}, "{}"); ok || !errors.Is(err, auth.ErrMFAInvalid) {
		t.Fatalf("zero verifier = %v, %v", ok, err)
	}
}

func TestVerifierSuccess(t *testing.T) {
	service, verifier, stores, fixture, _ := newVerifierPair(t)
	options, _, err := service.BeginLogin(context.Background(), testUser(), LoginOptions{})
	if err != nil {
		t.Fatalf("BeginLogin: %v", err)
	}
	login := defaultAssertionFixture(fixture.signer, fixture.credID)
	login.signCount = 2
	response := login.assertionResponse(t, options)
	encoded, err := json.Marshal(response)
	if err != nil {
		t.Fatalf("marshal response: %v", err)
	}
	record := loadAuthCredential(t, stores, fixture.credID)
	ok, err := verifier.Verify(context.Background(), testUser(), record, string(encoded))
	if err != nil || !ok {
		t.Fatalf("Verify = %v, %v", ok, err)
	}
	if record.Data[CredentialDataSignCount] != "2" {
		t.Fatalf("%s = %q", CredentialDataSignCount, record.Data[CredentialDataSignCount])
	}
	if record.Data[CredentialDataBackupState] != "false" {
		t.Fatalf("%s = %q", CredentialDataBackupState, record.Data[CredentialDataBackupState])
	}

	ok, err = verifier.Verify(context.Background(), testUser(), record, string(encoded))
	if ok || !errors.Is(err, auth.ErrMFAInvalid) {
		t.Fatalf("replayed Verify = %v, %v", ok, err)
	}
}

func TestVerifierEmptyAndMalformed(t *testing.T) {
	_, verifier, stores, fixture, _ := newVerifierPair(t)
	record := loadAuthCredential(t, stores, fixture.credID)
	if ok, err := verifier.Verify(context.Background(), testUser(), record, "   "); ok || err != nil {
		t.Fatalf("empty response = %v, %v", ok, err)
	}
	if ok, err := verifier.Verify(context.Background(), testUser(), record, "{"); ok || !errors.Is(err, auth.ErrMFAInvalid) {
		t.Fatalf("malformed response = %v, %v", ok, err)
	}
	if ok, err := verifier.Verify(context.Background(), testUser(), nil, "{}"); ok || !errors.Is(err, auth.ErrCredentialNotFound) {
		t.Fatalf("nil credential = %v, %v", ok, err)
	}
}

func TestVerifierPreconditions(t *testing.T) {
	_, verifier, stores, fixture, _ := newVerifierPair(t)
	record := loadAuthCredential(t, stores, fixture.credID)

	disabled := record.Clone()
	disabled.Disabled = true
	if ok, err := verifier.Verify(context.Background(), testUser(), disabled, "{}"); ok || !errors.Is(err, auth.ErrMFAInvalid) {
		t.Fatalf("disabled credential = %v, %v", ok, err)
	}
	otherType := record.Clone()
	otherType.Type = auth.CredentialTOTP
	if ok, err := verifier.Verify(context.Background(), testUser(), otherType, "{}"); ok || !errors.Is(err, auth.ErrMFAInvalid) {
		t.Fatalf("wrong type = %v, %v", ok, err)
	}
	otherUser := &auth.User{ID: "user-2"}
	if ok, err := verifier.Verify(context.Background(), otherUser, record, "{}"); ok || !errors.Is(err, auth.ErrMFAInvalid) {
		t.Fatalf("wrong user = %v, %v", ok, err)
	}
	emptyUser := &auth.User{}
	if ok, err := verifier.Verify(context.Background(), emptyUser, record, "{}"); ok || !errors.Is(err, auth.ErrMFAInvalid) {
		t.Fatalf("empty user = %v, %v", ok, err)
	}
}

func TestVerifierRejectsBadAssertions(t *testing.T) {
	service, verifier, stores, fixture, _ := newVerifierPair(t)
	record := loadAuthCredential(t, stores, fixture.credID)

	options, _, err := service.BeginLogin(context.Background(), testUser(), LoginOptions{})
	if err != nil {
		t.Fatalf("BeginLogin: %v", err)
	}
	bad := defaultAssertionFixture(newECSigner(t), fixture.credID)
	encoded, err := json.Marshal(bad.assertionResponse(t, options))
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	if ok, err := verifier.Verify(context.Background(), testUser(), record, string(encoded)); ok || !errors.Is(err, auth.ErrMFAInvalid) {
		t.Fatalf("bad signature = %v, %v", ok, err)
	}

	options, _, err = service.BeginLogin(context.Background(), testUser(), LoginOptions{})
	if err != nil {
		t.Fatalf("BeginLogin: %v", err)
	}
	wrongID := defaultAssertionFixture(fixture.signer, []byte("other-credential"))
	encoded, err = json.Marshal(wrongID.assertionResponse(t, options))
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	if ok, err := verifier.Verify(context.Background(), testUser(), record, string(encoded)); ok || !errors.Is(err, auth.ErrMFAInvalid) {
		t.Fatalf("credential ID mismatch = %v, %v", ok, err)
	}

	options, _, err = service.BeginLogin(context.Background(), testUser(), LoginOptions{})
	if err != nil {
		t.Fatalf("BeginLogin: %v", err)
	}
	badOrigin := defaultAssertionFixture(fixture.signer, fixture.credID)
	badOrigin.origin = "https://evil.test"
	encoded, err = json.Marshal(badOrigin.assertionResponse(t, options))
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	if ok, err := verifier.Verify(context.Background(), testUser(), record, string(encoded)); ok || !errors.Is(err, auth.ErrMFAInvalid) {
		t.Fatalf("origin mismatch = %v, %v", ok, err)
	}

	options, _, err = service.BeginDiscoverableLogin(context.Background(), DiscoverableLoginOptions{})
	if err != nil {
		t.Fatalf("BeginDiscoverableLogin: %v", err)
	}
	discoverable := defaultAssertionFixture(fixture.signer, fixture.credID)
	discoverable.userHandle = []byte("user-1")
	encoded, err = json.Marshal(discoverable.assertionResponse(t, options))
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	ok, err := verifier.Verify(context.Background(), testUser(), record.Clone(), string(encoded))
	if err != nil || !ok {
		t.Fatalf("discoverable Verify = %v, %v", ok, err)
	}
}

func TestVerifierInvalidStoredCredential(t *testing.T) {
	_, verifier, stores, fixture, _ := newVerifierPair(t)
	record := loadAuthCredential(t, stores, fixture.credID)
	broken := record.Clone()
	broken.Data = map[string]string{CredentialDataPublicKey: "!!!"}
	if ok, err := verifier.Verify(context.Background(), testUser(), broken, `{"id":"x","rawId":"x","type":"public-key"}`); ok || !errors.Is(err, auth.ErrMFAInvalid) {
		t.Fatalf("broken stored credential = %v, %v", ok, err)
	}
}

func TestAuthCredentialStoreTimestamps(t *testing.T) {
	stores := auth.NewMemoryStores()
	service, _ := newAuthStoreService(t, stores)
	signer := newECSigner(t)
	fixture := defaultRegistrationFixture(t, signer)
	fixture.register(t, service, testUser(), RegistrationOptions{})
	record := loadAuthCredential(t, stores, fixture.credID)
	if record.CreatedAt.IsZero() || record.UpdatedAt.IsZero() {
		t.Fatalf("timestamps = %#v", record)
	}
	if time.Since(record.UpdatedAt) < 0 {
		t.Fatalf("UpdatedAt is in the future: %v", record.UpdatedAt)
	}
	if strings.Contains(record.Data[CredentialDataAttestationType], "none") == false {
		t.Fatalf("%s = %q", CredentialDataAttestationType, record.Data[CredentialDataAttestationType])
	}
}
