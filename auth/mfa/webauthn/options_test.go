package webauthn

import (
	"context"
	"errors"
	"math"
	"strings"
	"testing"
	"time"

	"github.com/shibingli/ydx/auth"
	"github.com/shibingli/ydx/json"
)

func validConfig() Config {
	return Config{
		RPDisplayName: "Example RP",
		RPID:          "example.com",
		RPOrigins:     []string{"https://example.com"},
	}
}

func TestTimeoutMillis(t *testing.T) {
	cases := []struct {
		name string
		in   time.Duration
		want uint32
	}{
		{name: "zero", in: 0, want: 0},
		{name: "negative", in: -time.Second, want: 0},
		{name: "sub-millisecond", in: 500 * time.Microsecond, want: 1},
		{name: "milliseconds", in: 1500 * time.Millisecond, want: 1500},
		{name: "clamped", in: time.Duration(math.MaxUint32+1) * time.Millisecond, want: math.MaxUint32},
	}
	for _, test := range cases {
		t.Run(test.name, func(t *testing.T) {
			if got := timeoutMillis(test.in); got != test.want {
				t.Fatalf("timeoutMillis(%v) = %d, want %d", test.in, got, test.want)
			}
		})
	}
}

func TestValidAlgorithms(t *testing.T) {
	got, err := validAlgorithms([]int{AlgES256, AlgEdDSA, AlgES256, AlgES384})
	if err != nil {
		t.Fatalf("validAlgorithms: %v", err)
	}
	want := []int{AlgES256, AlgEdDSA, AlgES384}
	if len(got) != len(want) {
		t.Fatalf("validAlgorithms = %v", got)
	}
	for i := range want {
		if got[i] != want[i] {
			t.Fatalf("validAlgorithms = %v", got)
		}
	}
	if _, err := validAlgorithms(nil); !errors.Is(err, ErrInvalidConfig) {
		t.Fatalf("nil algorithms error = %v", err)
	}
	if _, err := validAlgorithms([]int{AlgES256, 4242}); !errors.Is(err, ErrUnsupportedAlgorithm) {
		t.Fatalf("unsupported algorithm error = %v", err)
	}
	if defaults := DefaultAlgorithms(); len(defaults) == 0 || defaults[0] != AlgES256 {
		t.Fatalf("DefaultAlgorithms = %v", defaults)
	}
}

func TestNewDefaults(t *testing.T) {
	config := validConfig()
	config.RPDisplayName = " Example RP "
	config.RPID = "Example.COM"
	config.RPOrigins = []string{" HTTPS://Example.COM:443/ ", "https://example.com"}
	service, err := New(config)
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	if service.RPDisplayName() != "Example RP" {
		t.Fatalf("RPDisplayName = %q", service.RPDisplayName())
	}
	if service.RPID() != "example.com" {
		t.Fatalf("RPID = %q", service.RPID())
	}
	if len(service.origins) != 1 || service.origins[0] != "https://example.com" {
		t.Fatalf("origins = %v", service.origins)
	}
	if service.challengeLen != DefaultChallengeLength {
		t.Fatalf("challenge length = %d", service.challengeLen)
	}
	if service.timeout != DefaultTimeout {
		t.Fatalf("timeout = %v", service.timeout)
	}
	if service.userVerif != UserVerificationPreferred {
		t.Fatalf("user verification = %q", service.userVerif)
	}
	if service.attestation != ConveyanceNone {
		t.Fatalf("attestation = %q", service.attestation)
	}
	if len(service.algorithms) != len(DefaultAlgorithms()) {
		t.Fatalf("algorithms = %v", service.algorithms)
	}
	if service.challenges == nil || service.credentials == nil || service.clock == nil {
		t.Fatal("New left a required dependency nil")
	}
	if service.roots != nil || service.allowCross || len(service.topOrigins) != 0 {
		t.Fatalf("unexpected optional state: roots=%v cross=%v top=%v", service.roots, service.allowCross, service.topOrigins)
	}
}

func TestNewConfigValidation(t *testing.T) {
	cases := []struct {
		name   string
		mutate func(*Config)
		want   error
	}{
		{name: "empty display name", mutate: func(c *Config) { c.RPDisplayName = "" }, want: ErrInvalidConfig},
		{name: "blank display name", mutate: func(c *Config) { c.RPDisplayName = "   " }, want: ErrInvalidConfig},
		{name: "empty RP ID", mutate: func(c *Config) { c.RPID = "" }, want: ErrInvalidConfig},
		{name: "padded RP ID", mutate: func(c *Config) { c.RPID = " example.com" }, want: ErrInvalidConfig},
		{name: "RP ID with scheme", mutate: func(c *Config) { c.RPID = "https://example.com" }, want: ErrInvalidConfig},
		{name: "RP ID with port", mutate: func(c *Config) { c.RPID = "example.com:443" }, want: ErrInvalidConfig},
		{name: "RP ID with path", mutate: func(c *Config) { c.RPID = "example.com/login" }, want: ErrInvalidConfig},
		{name: "RP ID with empty label", mutate: func(c *Config) { c.RPID = "example..com" }, want: ErrInvalidConfig},
		{name: "RP ID trailing dot", mutate: func(c *Config) { c.RPID = "example.com." }, want: ErrInvalidConfig},
		{name: "empty origins", mutate: func(c *Config) { c.RPOrigins = nil }, want: ErrInvalidConfig},
		{name: "empty origin", mutate: func(c *Config) { c.RPOrigins = []string{""} }, want: ErrInvalidConfig},
		{name: "origin with path", mutate: func(c *Config) { c.RPOrigins = []string{"https://example.com/login"} }, want: ErrInvalidConfig},
		{name: "origin with user info", mutate: func(c *Config) { c.RPOrigins = []string{"https://user@example.com"} }, want: ErrInvalidConfig},
		{name: "origin with query", mutate: func(c *Config) { c.RPOrigins = []string{"https://example.com?a=b"} }, want: ErrInvalidConfig},
		{name: "origin with fragment", mutate: func(c *Config) { c.RPOrigins = []string{"https://example.com#x"} }, want: ErrInvalidConfig},
		{name: "origin with unsupported scheme", mutate: func(c *Config) { c.RPOrigins = []string{"ftp://example.com"} }, want: ErrInvalidConfig},
		{name: "origin outside RP ID", mutate: func(c *Config) { c.RPOrigins = []string{"https://evil.test"} }, want: ErrInvalidConfig},
		{name: "challenge too short", mutate: func(c *Config) { c.ChallengeLength = MinChallengeLength - 1 }, want: ErrInvalidConfig},
		{name: "challenge too long", mutate: func(c *Config) { c.ChallengeLength = MaxChallengeLength + 1 }, want: ErrInvalidConfig},
		{name: "negative timeout", mutate: func(c *Config) { c.Timeout = -time.Second }, want: ErrInvalidConfig},
		{name: "invalid user verification", mutate: func(c *Config) { c.UserVerification = "sometimes" }, want: ErrInvalidConfig},
		{name: "invalid attestation", mutate: func(c *Config) { c.Attestation = "always" }, want: ErrInvalidConfig},
		{name: "empty algorithm list", mutate: func(c *Config) { c.Algorithms = []int{} }, want: ErrInvalidConfig},
		{name: "unsupported algorithm", mutate: func(c *Config) { c.Algorithms = []int{4242} }, want: ErrUnsupportedAlgorithm},
		{name: "cross-origin without top origins", mutate: func(c *Config) { c.AllowCrossOrigin = true }, want: ErrInvalidConfig},
		{name: "cross-origin with invalid top origin", mutate: func(c *Config) {
			c.AllowCrossOrigin = true
			c.AllowedTopOrigins = []string{"not an origin"}
		}, want: ErrInvalidConfig},
	}
	for _, test := range cases {
		t.Run(test.name, func(t *testing.T) {
			config := validConfig()
			test.mutate(&config)
			if _, err := New(config); !errors.Is(err, test.want) {
				t.Fatalf("New error = %v, want %v", err, test.want)
			}
		})
	}
}

func TestNewAcceptsBoundaries(t *testing.T) {
	config := validConfig()
	config.ChallengeLength = MinChallengeLength
	config.RPID = "example.com"
	config.RPOrigins = []string{"https://login.example.com", "http://example.com:80", "https://example.com:8443"}
	service, err := New(config)
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	if len(service.origins) != 3 {
		t.Fatalf("origins = %v", service.origins)
	}
	if service.origins[0] != "https://login.example.com" || service.origins[1] != "http://example.com" {
		t.Fatalf("origins = %v", service.origins)
	}

	config = validConfig()
	config.ChallengeLength = MaxChallengeLength
	config.AllowCrossOrigin = true
	config.AllowedTopOrigins = []string{"HTTPS://Example.COM:443/"}
	service, err = New(config)
	if err != nil {
		t.Fatalf("New cross-origin: %v", err)
	}
	if !service.allowCross || len(service.topOrigins) != 1 || service.topOrigins[0] != "https://example.com" {
		t.Fatalf("top origins = %v", service.topOrigins)
	}
}

func TestBeginRegistrationJSONShape(t *testing.T) {
	service := newTestService(t, nil)
	user := testUser()
	options, ceremony, err := service.BeginRegistration(context.Background(), user, RegistrationOptions{
		Extensions: &RegistrationExtensions{CredProps: true},
	})
	if err != nil {
		t.Fatalf("BeginRegistration: %v", err)
	}
	encoded := mustMarshal(t, options)
	text := string(encoded)
	for _, key := range []string{
		`"publicKey"`, `"challenge"`, `"rp"`, `"user"`, `"pubKeyCredParams"`,
		`"timeout"`, `"authenticatorSelection"`, `"attestation"`, `"credProps"`,
	} {
		if !strings.Contains(text, key) {
			t.Fatalf("creation options JSON lacks %s: %s", key, text)
		}
	}
	var decoded CredentialCreationOptions
	if err := json.Unmarshal(encoded, &decoded); err != nil {
		t.Fatalf("unmarshal creation options: %v", err)
	}
	publicKey := decoded.PublicKey
	if publicKey.Challenge != b64(ceremony.Challenge) || publicKey.Challenge != options.PublicKey.Challenge {
		t.Fatalf("challenge = %q", publicKey.Challenge)
	}
	if publicKey.RP.ID != testRPID || publicKey.RP.Name != "Example RP" {
		t.Fatalf("rp = %#v", publicKey.RP)
	}
	if publicKey.User.ID != b64([]byte(user.ID)) || publicKey.User.Name != user.Username {
		t.Fatalf("user = %#v", publicKey.User)
	}
	if publicKey.Timeout != uint32(DefaultTimeout/time.Millisecond) {
		t.Fatalf("timeout = %d", publicKey.Timeout)
	}
	if len(publicKey.PubKeyCredParams) != len(DefaultAlgorithms()) {
		t.Fatalf("pubKeyCredParams = %v", publicKey.PubKeyCredParams)
	}
	for i, parameter := range publicKey.PubKeyCredParams {
		if parameter.Type != "public-key" || parameter.Alg != DefaultAlgorithms()[i] {
			t.Fatalf("pubKeyCredParams[%d] = %#v", i, parameter)
		}
	}
	if publicKey.AuthenticatorSelection == nil {
		t.Fatal("authenticatorSelection is nil")
	}
	selection := publicKey.AuthenticatorSelection
	if selection.ResidentKey != string(ResidentKeyPreferred) || selection.RequireResidentKey {
		t.Fatalf("authenticatorSelection = %#v", selection)
	}
	if selection.UserVerification != string(UserVerificationPreferred) {
		t.Fatalf("userVerification = %q", selection.UserVerification)
	}
	if publicKey.Attestation != string(ConveyanceNone) {
		t.Fatalf("attestation = %q", publicKey.Attestation)
	}
	if publicKey.Extensions == nil || !publicKey.Extensions.CredProps {
		t.Fatalf("extensions = %#v", publicKey.Extensions)
	}
	if len(publicKey.ExcludeCredentials) != 0 {
		t.Fatalf("excludeCredentials = %v", publicKey.ExcludeCredentials)
	}
}

func TestBeginRegistrationResidentKey(t *testing.T) {
	service := newTestService(t, nil)
	options, ceremony, err := service.BeginRegistration(context.Background(), testUser(), RegistrationOptions{
		ResidentKey: ResidentKeyRequired,
	})
	if err != nil {
		t.Fatalf("BeginRegistration: %v", err)
	}
	selection := options.PublicKey.AuthenticatorSelection
	if selection == nil || !selection.RequireResidentKey || selection.ResidentKey != string(ResidentKeyRequired) {
		t.Fatalf("authenticatorSelection = %#v", selection)
	}
	if options.PublicKey.Extensions == nil || !options.PublicKey.Extensions.CredProps {
		t.Fatalf("credProps was not forced: %#v", options.PublicKey.Extensions)
	}
	if ceremony.ResidentKey != ResidentKeyRequired {
		t.Fatalf("ceremony residentKey = %q", ceremony.ResidentKey)
	}

	no := false
	options, _, err = service.BeginRegistration(context.Background(), testUser(), RegistrationOptions{
		ResidentKey:        ResidentKeyRequired,
		RequireResidentKey: &no,
	})
	if err != nil {
		t.Fatalf("BeginRegistration: %v", err)
	}
	if options.PublicKey.AuthenticatorSelection.RequireResidentKey || options.PublicKey.AuthenticatorSelection.ResidentKey != string(ResidentKeyDiscouraged) {
		t.Fatalf("legacy override = %#v", options.PublicKey.AuthenticatorSelection)
	}

	options, _, err = service.BeginRegistration(context.Background(), testUser(), RegistrationOptions{
		AuthenticatorAttachment: AuthenticatorPlatform,
		Extensions:              &RegistrationExtensions{UVM: true},
	})
	if err != nil {
		t.Fatalf("BeginRegistration: %v", err)
	}
	if options.PublicKey.AuthenticatorSelection.AuthenticatorAttachment != string(AuthenticatorPlatform) {
		t.Fatalf("attachment = %q", options.PublicKey.AuthenticatorSelection.AuthenticatorAttachment)
	}
	if options.PublicKey.Extensions == nil || !options.PublicKey.Extensions.UVM || options.PublicKey.Extensions.CredProps {
		t.Fatalf("extensions = %#v", options.PublicKey.Extensions)
	}
}

func TestBeginRegistrationInvalidOptions(t *testing.T) {
	service := newTestService(t, nil)
	cases := []struct {
		name string
		opts RegistrationOptions
		want error
	}{
		{name: "invalid attachment", opts: RegistrationOptions{AuthenticatorAttachment: "usb"}, want: ErrInvalidRequest},
		{name: "invalid resident key", opts: RegistrationOptions{ResidentKey: "always"}, want: ErrInvalidRequest},
		{name: "invalid user verification", opts: RegistrationOptions{UserVerification: "always"}, want: ErrInvalidRequest},
		{name: "invalid attestation", opts: RegistrationOptions{Attestation: "always"}, want: ErrInvalidRequest},
		{name: "invalid algorithm", opts: RegistrationOptions{Algorithms: []int{4242}}, want: ErrUnsupportedAlgorithm},
	}
	for _, test := range cases {
		t.Run(test.name, func(t *testing.T) {
			if _, _, err := service.BeginRegistration(context.Background(), testUser(), test.opts); !errors.Is(err, test.want) {
				t.Fatalf("error = %v, want %v", err, test.want)
			}
		})
	}
	if _, _, err := service.BeginRegistration(context.Background(), nil, RegistrationOptions{}); !errors.Is(err, ErrInvalidRequest) {
		t.Fatalf("nil user error = %v", err)
	}
	if _, _, err := service.BeginRegistration(context.Background(), &auth.User{}, RegistrationOptions{}); !errors.Is(err, ErrInvalidRequest) {
		t.Fatalf("empty user error = %v", err)
	}
	long := &auth.User{ID: strings.Repeat("u", maxUserHandleLength+1)}
	if _, _, err := service.BeginRegistration(context.Background(), long, RegistrationOptions{}); !errors.Is(err, ErrInvalidRequest) {
		t.Fatalf("long user handle error = %v", err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, _, err := service.BeginRegistration(ctx, testUser(), RegistrationOptions{}); !errors.Is(err, context.Canceled) {
		t.Fatalf("canceled context error = %v", err)
	}
}

func TestBeginLoginJSONShape(t *testing.T) {
	service := newTestService(t, nil)
	signer := newECSigner(t)
	fixture := defaultRegistrationFixture(t, signer)
	fixture.register(t, service, testUser(), RegistrationOptions{})

	options, ceremony, err := service.BeginLogin(context.Background(), testUser(), LoginOptions{})
	if err != nil {
		t.Fatalf("BeginLogin: %v", err)
	}
	encoded := mustMarshal(t, options)
	text := string(encoded)
	for _, key := range []string{`"publicKey"`, `"challenge"`, `"rpId"`, `"allowCredentials"`, `"userVerification"`, `"timeout"`} {
		if !strings.Contains(text, key) {
			t.Fatalf("request options JSON lacks %s: %s", key, text)
		}
	}
	var decoded CredentialRequestOptions
	if err := json.Unmarshal(encoded, &decoded); err != nil {
		t.Fatalf("unmarshal request options: %v", err)
	}
	publicKey := decoded.PublicKey
	if publicKey.Challenge != b64(ceremony.Challenge) {
		t.Fatalf("challenge = %q", publicKey.Challenge)
	}
	if publicKey.RPID != testRPID || publicKey.UserVerification != string(UserVerificationPreferred) {
		t.Fatalf("request options = %#v", publicKey)
	}
	if len(publicKey.AllowCredentials) != 1 {
		t.Fatalf("allowCredentials = %v", publicKey.AllowCredentials)
	}
	descriptor := publicKey.AllowCredentials[0]
	if descriptor.Type != "public-key" || descriptor.ID != b64(fixture.credID) {
		t.Fatalf("descriptor = %#v", descriptor)
	}
	if len(descriptor.Transports) != 1 || descriptor.Transports[0] != "internal" {
		t.Fatalf("transports = %v", descriptor.Transports)
	}
	if publicKey.Timeout != uint32(DefaultTimeout/time.Millisecond) {
		t.Fatalf("timeout = %d", publicKey.Timeout)
	}

	discoverable, _, err := service.BeginDiscoverableLogin(context.Background(), DiscoverableLoginOptions{})
	if err != nil {
		t.Fatalf("BeginDiscoverableLogin: %v", err)
	}
	discoverableJSON := string(mustMarshal(t, discoverable))
	if strings.Contains(discoverableJSON, `"allowCredentials"`) {
		t.Fatalf("discoverable options contain allowCredentials: %s", discoverableJSON)
	}
	if !strings.Contains(discoverableJSON, `"rpId"`) {
		t.Fatalf("discoverable options lack rpId: %s", discoverableJSON)
	}
	if len(discoverable.PublicKey.AllowCredentials) != 0 {
		t.Fatalf("discoverable allowCredentials = %v", discoverable.PublicKey.AllowCredentials)
	}
}

func TestBeginLoginOverrideOptions(t *testing.T) {
	service := newTestService(t, nil)
	signer := newECSigner(t)
	fixture := defaultRegistrationFixture(t, signer)
	fixture.register(t, service, testUser(), RegistrationOptions{})

	custom := []CredentialDescriptor{{Type: "public-key", ID: b64([]byte("custom")), Transports: []string{"usb"}}}
	options, ceremony, err := service.BeginLogin(context.Background(), testUser(), LoginOptions{
		AllowCredentials: custom,
		UserVerification: UserVerificationRequired,
		Timeout:          90 * time.Second,
	})
	if err != nil {
		t.Fatalf("BeginLogin: %v", err)
	}
	if len(options.PublicKey.AllowCredentials) != 1 || options.PublicKey.AllowCredentials[0].ID != b64([]byte("custom")) {
		t.Fatalf("allowCredentials = %v", options.PublicKey.AllowCredentials)
	}
	if options.PublicKey.UserVerification != string(UserVerificationRequired) {
		t.Fatalf("userVerification = %q", options.PublicKey.UserVerification)
	}
	if options.PublicKey.Timeout != uint32((90*time.Second)/time.Millisecond) {
		t.Fatalf("timeout = %d", options.PublicKey.Timeout)
	}
	if ceremony.UserVerification != UserVerificationRequired {
		t.Fatalf("ceremony userVerification = %q", ceremony.UserVerification)
	}

	if _, _, err := service.BeginLogin(context.Background(), testUser(), LoginOptions{
		AllowCredentials: []CredentialDescriptor{{Type: "bogus", ID: b64([]byte("x"))}},
	}); !errors.Is(err, ErrInvalidRequest) {
		t.Fatalf("invalid descriptor error = %v", err)
	}
	if _, _, err := service.BeginDiscoverableLogin(context.Background(), DiscoverableLoginOptions{
		UserVerification: "sometimes",
	}); !errors.Is(err, ErrInvalidRequest) {
		t.Fatalf("invalid discoverable UV error = %v", err)
	}
	if _, _, err := service.BeginLogin(context.Background(), &auth.User{ID: "nobody"}, LoginOptions{}); !errors.Is(err, ErrCredentialNotFound) {
		t.Fatalf("user without credentials error = %v", err)
	}
}

func TestCeremonyJSONRoundTrip(t *testing.T) {
	service := newTestService(t, func(config *Config) {
		config.TokenBindingID = "bound"
		config.RequireTokenBinding = true
	})
	_, ceremony, err := service.BeginRegistration(context.Background(), testUser(), RegistrationOptions{
		Name:        "Laptop",
		ResidentKey: ResidentKeyRequired,
	})
	if err != nil {
		t.Fatalf("BeginRegistration: %v", err)
	}
	encoded := mustMarshal(t, ceremony)
	if !strings.Contains(string(encoded), `"kind":"registration"`) || !strings.Contains(string(encoded), `"rpId":"example.com"`) {
		t.Fatalf("ceremony JSON = %s", encoded)
	}
	var decoded Ceremony
	if err := json.Unmarshal(encoded, &decoded); err != nil {
		t.Fatalf("unmarshal ceremony: %v", err)
	}
	if decoded.ID != ceremony.ID || decoded.Kind != ceremony.Kind {
		t.Fatalf("decoded identity = %q/%q", decoded.ID, decoded.Kind)
	}
	if string(decoded.Challenge) != string(ceremony.Challenge) {
		t.Fatalf("challenge was not preserved")
	}
	if string(decoded.UserHandle) != string(ceremony.UserHandle) || decoded.UserID != ceremony.UserID {
		t.Fatalf("user was not preserved: %#v", decoded.UserID)
	}
	if len(decoded.Origins) != 1 || decoded.Origins[0] != testOrigin {
		t.Fatalf("origins = %v", decoded.Origins)
	}
	if decoded.ResidentKey != ResidentKeyRequired || decoded.CredentialName != "Laptop" {
		t.Fatalf("registration state = %#v", decoded)
	}
	if decoded.RegistrationExtensions == nil || !decoded.RegistrationExtensions.CredProps {
		t.Fatalf("extensions = %#v", decoded.RegistrationExtensions)
	}
	if !decoded.CreatedAt.Equal(ceremony.CreatedAt) || !decoded.ExpiresAt.Equal(ceremony.ExpiresAt) {
		t.Fatalf("timestamps = %v/%v", decoded.CreatedAt, decoded.ExpiresAt)
	}
	if decoded.TokenBindingID != "bound" || !decoded.RequireTokenBinding {
		t.Fatalf("token binding state = %#v", decoded)
	}
}

func TestAuthenticationExtensionsCloning(t *testing.T) {
	service := newTestService(t, nil)
	signer := newECSigner(t)
	fixture := defaultRegistrationFixture(t, signer)
	fixture.register(t, service, testUser(), RegistrationOptions{})

	input := &HMACGetSecretInput{Salt1: b64([]byte("salt-one")), Salt2: b64([]byte("salt-two"))}
	options, ceremony, err := service.BeginLogin(context.Background(), testUser(), LoginOptions{
		Extensions: &AuthenticationExtensions{HMACGetSecret: input, UVM: true},
	})
	if err != nil {
		t.Fatalf("BeginLogin: %v", err)
	}
	if options.PublicKey.Extensions == nil || options.PublicKey.Extensions.HMACGetSecret == nil {
		t.Fatalf("extensions = %#v", options.PublicKey.Extensions)
	}
	input.Salt1 = "mutated"
	if options.PublicKey.Extensions.HMACGetSecret.Salt1 != b64([]byte("salt-one")) {
		t.Fatal("request options share the caller extension input")
	}
	if ceremony.AuthenticationExtensions == nil || ceremony.AuthenticationExtensions.HMACGetSecret == nil {
		t.Fatalf("ceremony extensions = %#v", ceremony.AuthenticationExtensions)
	}
	if ceremony.AuthenticationExtensions.HMACGetSecret.Salt1 != b64([]byte("salt-one")) {
		t.Fatal("ceremony shares the caller extension input")
	}
}
