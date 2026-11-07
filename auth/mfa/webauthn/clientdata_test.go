package webauthn

import (
	"bytes"
	"errors"
	"testing"
)

func validClientDataJSON(t *testing.T) ([]byte, []byte) {
	t.Helper()
	challenge := []byte("challenge-bytes")
	cd := &ClientData{
		Type:      ClientDataTypeGet,
		Challenge: b64(challenge),
		Origin:    testOrigin,
	}
	return mustMarshal(t, cd), challenge
}

func clientDataOptions(challenge []byte) ClientDataVerifyOptions {
	return ClientDataVerifyOptions{
		Type:      ClientDataTypeGet,
		Challenge: challenge,
		Origins:   []string{testOrigin},
		RPID:      testRPID,
	}
}

func TestParseClientData(t *testing.T) {
	raw, challenge := validClientDataJSON(t)
	cd, err := ParseClientData(raw)
	if err != nil {
		t.Fatalf("ParseClientData: %v", err)
	}
	if cd.Type != ClientDataTypeGet || cd.Challenge != b64(challenge) || cd.Origin != testOrigin {
		t.Fatalf("parsed = %#v", cd)
	}
	if !bytes.Equal(cd.Raw, raw) {
		t.Fatal("Raw does not preserve the exact JSON")
	}
	if cd.CrossOrigin || cd.TopOrigin != "" || cd.TokenBinding != nil {
		t.Fatalf("unexpected optional fields: %#v", cd)
	}

	apple := mustMarshal(t, map[string]any{
		"type":      ClientDataTypeCreate,
		"challenge": b64(challenge),
		"origin":    testOrigin,
		"apple":     map[string]any{"foo": "bar"},
	})
	parsedApple, err := ParseClientData(apple)
	if err != nil {
		t.Fatalf("ParseClientData apple: %v", err)
	}
	if parsedApple.Apple == nil {
		t.Fatal("apple extension was not recorded")
	}
}

func TestParseClientDataInvalid(t *testing.T) {
	cases := []struct {
		name string
		raw  []byte
	}{
		{name: "empty", raw: nil},
		{name: "invalid JSON", raw: []byte("{")},
		{name: "not an object", raw: []byte(`"text"`)},
		{name: "missing type", raw: []byte(`{"challenge":"AA","origin":"https://example.com"}`)},
		{name: "missing challenge", raw: []byte(`{"type":"webauthn.get","origin":"https://example.com"}`)},
		{name: "missing origin", raw: []byte(`{"type":"webauthn.get","challenge":"AA"}`)},
		{name: "oversized", raw: bytes.Repeat([]byte("a"), maxClientDataBytes+1)},
	}
	for _, test := range cases {
		t.Run(test.name, func(t *testing.T) {
			if _, err := ParseClientData(test.raw); !errors.Is(err, ErrInvalidClientData) {
				t.Fatalf("error = %v, want ErrInvalidClientData", err)
			}
		})
	}
}

func TestVerifyClientDataSuccess(t *testing.T) {
	raw, challenge := validClientDataJSON(t)
	cd, err := VerifyClientData(raw, clientDataOptions(challenge))
	if err != nil {
		t.Fatalf("VerifyClientData: %v", err)
	}
	if cd == nil || cd.Origin != testOrigin {
		t.Fatalf("client data = %#v", cd)
	}
}

func TestVerifyClientDataTypeAndChallenge(t *testing.T) {
	raw, challenge := validClientDataJSON(t)
	options := clientDataOptions(challenge)
	options.Type = ClientDataTypeCreate
	if _, err := VerifyClientData(raw, options); !errors.Is(err, ErrInvalidClientData) {
		t.Fatalf("type mismatch error = %v", err)
	}
	options = clientDataOptions([]byte("another-challenge"))
	if _, err := VerifyClientData(raw, options); !errors.Is(err, ErrChallengeMismatch) {
		t.Fatalf("challenge mismatch error = %v", err)
	}
	bad := mustMarshal(t, &ClientData{Type: ClientDataTypeGet, Challenge: "!!!", Origin: testOrigin})
	if _, err := VerifyClientData(bad, clientDataOptions(challenge)); !errors.Is(err, ErrInvalidClientData) {
		t.Fatalf("malformed challenge error = %v", err)
	}
}

func TestVerifyClientDataOrigin(t *testing.T) {
	challenge := []byte("challenge-bytes")
	cases := []struct {
		name    string
		origin  string
		origins []string
		rpID    string
		want    error
	}{
		{name: "default port", origin: "https://example.com:443", origins: []string{"https://example.com"}, rpID: testRPID},
		{name: "subdomain", origin: "https://login.example.com", origins: []string{"https://login.example.com"}, rpID: testRPID},
		{name: "configured with port", origin: "https://example.com", origins: []string{"https://example.com:443/"}, rpID: testRPID},
		{name: "localhost http", origin: "http://localhost:8080", origins: []string{"http://localhost:8080"}, rpID: "localhost"},
		{name: "insecure http origin", origin: "http://example.com", origins: []string{"http://example.com"}, want: ErrOriginMismatch},
		{name: "outside RP ID", origin: "https://evil.test", origins: []string{"https://evil.test"}, rpID: testRPID, want: ErrRPIDMismatch},
		{name: "unconfigured origin", origin: "https://other.example", origins: []string{testOrigin}, rpID: "", want: ErrOriginMismatch},
		{name: "sibling subdomain", origin: "https://example.com", origins: []string{"https://example.com"}, rpID: "other.test", want: ErrRPIDMismatch},
	}
	for _, test := range cases {
		t.Run(test.name, func(t *testing.T) {
			raw := mustMarshal(t, &ClientData{Type: ClientDataTypeGet, Challenge: b64(challenge), Origin: test.origin})
			options := ClientDataVerifyOptions{
				Type:      ClientDataTypeGet,
				Challenge: challenge,
				Origins:   test.origins,
				RPID:      test.rpID,
			}
			_, err := VerifyClientData(raw, options)
			if test.want == nil {
				if err != nil {
					t.Fatalf("VerifyClientData: %v", err)
				}
				return
			}
			if !errors.Is(err, test.want) {
				t.Fatalf("error = %v, want %v", err, test.want)
			}
		})
	}
}

func TestVerifyClientDataCrossOrigin(t *testing.T) {
	challenge := []byte("challenge-bytes")
	raw := mustMarshal(t, &ClientData{
		Type:        ClientDataTypeGet,
		Challenge:   b64(challenge),
		Origin:      testOrigin,
		CrossOrigin: true,
		TopOrigin:   "https://embed.example",
	})
	options := clientDataOptions(challenge)
	if _, err := VerifyClientData(raw, options); !errors.Is(err, ErrOriginMismatch) {
		t.Fatalf("disabled cross-origin error = %v", err)
	}
	options.AllowCrossOrigin = true
	if _, err := VerifyClientData(raw, options); !errors.Is(err, ErrOriginMismatch) {
		t.Fatalf("unlisted top origin error = %v", err)
	}
	options.AllowedTopOrigins = []string{"https://embed.example"}
	if _, err := VerifyClientData(raw, options); err != nil {
		t.Fatalf("allowed top origin: %v", err)
	}
	withoutTop := mustMarshal(t, &ClientData{
		Type:        ClientDataTypeGet,
		Challenge:   b64(challenge),
		Origin:      testOrigin,
		CrossOrigin: true,
	})
	if _, err := VerifyClientData(withoutTop, options); !errors.Is(err, ErrOriginMismatch) {
		t.Fatalf("missing top origin error = %v", err)
	}
	unexpectedTop := mustMarshal(t, &ClientData{
		Type:      ClientDataTypeGet,
		Challenge: b64(challenge),
		Origin:    testOrigin,
		TopOrigin: "https://embed.example",
	})
	if _, err := VerifyClientData(unexpectedTop, clientDataOptions(challenge)); !errors.Is(err, ErrInvalidClientData) {
		t.Fatalf("topOrigin without crossOrigin error = %v", err)
	}
}

func TestVerifyClientDataAndroid(t *testing.T) {
	challenge := []byte("challenge-bytes")
	cases := []struct {
		name    string
		origin  string
		pkg     string
		instant bool
		wantErr bool
	}{
		{name: "valid", origin: "android:apk-key-hash:abcdef", pkg: "com.example.app"},
		{name: "instant valid", origin: "android:apk-key-hash:abcdef", pkg: "com.example.app", instant: true},
		{name: "missing package", origin: "android:apk-key-hash:abcdef", wantErr: true},
		{name: "instant missing package", origin: "android:apk-key-hash:abcdef", instant: true, wantErr: true},
		{name: "package on non-android", origin: testOrigin, pkg: "com.example.app", wantErr: true},
	}
	for _, test := range cases {
		t.Run(test.name, func(t *testing.T) {
			raw := mustMarshal(t, &ClientData{
				Type:               ClientDataTypeGet,
				Challenge:          b64(challenge),
				Origin:             test.origin,
				AndroidPackageName: test.pkg,
				AndroidInstant:     test.instant,
			})
			options := ClientDataVerifyOptions{
				Type:      ClientDataTypeGet,
				Challenge: challenge,
				Origins:   []string{test.origin},
			}
			_, err := VerifyClientData(raw, options)
			if test.wantErr {
				if !errors.Is(err, ErrInvalidClientData) {
					t.Fatalf("error = %v, want ErrInvalidClientData", err)
				}
				return
			}
			if err != nil {
				t.Fatalf("VerifyClientData: %v", err)
			}
		})
	}
}

func TestVerifyClientDataTokenBinding(t *testing.T) {
	challenge := []byte("challenge-bytes")
	build := func(binding *TokenBinding) []byte {
		return mustMarshal(t, &ClientData{
			Type:         ClientDataTypeGet,
			Challenge:    b64(challenge),
			Origin:       testOrigin,
			TokenBinding: binding,
		})
	}
	options := clientDataOptions(challenge)
	options.TokenBindingID = "bound-id"
	if _, err := VerifyClientData(build(&TokenBinding{Status: "present", ID: "bound-id"}), options); err != nil {
		t.Fatalf("present binding: %v", err)
	}
	if _, err := VerifyClientData(build(&TokenBinding{Status: "present", ID: "other"}), options); !errors.Is(err, ErrTokenBindingMismatch) {
		t.Fatalf("mismatched binding error = %v", err)
	}
	if _, err := VerifyClientData(build(&TokenBinding{Status: "present", ID: "bound-id"}), clientDataOptions(challenge)); !errors.Is(err, ErrTokenBindingMismatch) {
		t.Fatalf("unconfigured binding error = %v", err)
	}
	if _, err := VerifyClientData(build(&TokenBinding{Status: "supported"}), options); err != nil {
		t.Fatalf("supported binding: %v", err)
	}
	if _, err := VerifyClientData(build(&TokenBinding{Status: "supported", ID: "x"}), options); !errors.Is(err, ErrTokenBindingMismatch) {
		t.Fatalf("supported binding with ID error = %v", err)
	}
	if _, err := VerifyClientData(build(&TokenBinding{Status: "not-supported"}), options); err != nil {
		t.Fatalf("not-supported binding: %v", err)
	}
	if _, err := VerifyClientData(build(&TokenBinding{Status: "weird"}), options); !errors.Is(err, ErrTokenBindingMismatch) {
		t.Fatalf("unknown binding status error = %v", err)
	}
	required := clientDataOptions(challenge)
	required.RequireTokenBinding = true
	if _, err := VerifyClientData(build(nil), required); !errors.Is(err, ErrTokenBindingMismatch) {
		t.Fatalf("missing required binding error = %v", err)
	}
}

func TestNormalizeOrigin(t *testing.T) {
	valid := map[string]string{
		" HTTPS://Example.COM:443/ ": "https://example.com",
		"http://example.com:80":      "http://example.com",
		"https://example.com:8443":   "https://example.com:8443",
		"android:apk-key-hash:AbC":   "android:apk-key-hash:AbC",
		"https://[::1]:443":          "https://[::1]",
	}
	for input, want := range valid {
		got, err := normalizeOrigin(input)
		if err != nil {
			t.Fatalf("normalizeOrigin(%q): %v", input, err)
		}
		if got != want {
			t.Fatalf("normalizeOrigin(%q) = %q, want %q", input, got, want)
		}
	}
	invalid := []string{
		"",
		"ftp://example.com",
		"https://user:pass@example.com",
		"https://example.com/path",
		"https://example.com?query",
		"https://example.com#fragment",
		"https://",
		"android:",
	}
	for _, input := range invalid {
		if _, err := normalizeOrigin(input); !errors.Is(err, ErrOriginMismatch) {
			t.Fatalf("normalizeOrigin(%q) error = %v", input, err)
		}
	}
}

func TestOriginMatchesRPID(t *testing.T) {
	cases := []struct {
		origin string
		rpID   string
		want   bool
	}{
		{origin: "https://example.com", rpID: "example.com", want: true},
		{origin: "https://login.example.com", rpID: "example.com", want: true},
		{origin: "https://example.com.evil.test", rpID: "example.com", want: false},
		{origin: "https://other.test", rpID: "example.com", want: false},
		{origin: "android:apk-key-hash:abc", rpID: "example.com", want: true},
		{origin: "https://[::1]", rpID: "::1", want: true},
	}
	for _, test := range cases {
		if got := originMatchesRPID(test.origin, test.rpID); got != test.want {
			t.Fatalf("originMatchesRPID(%q, %q) = %v, want %v", test.origin, test.rpID, got, test.want)
		}
	}
}

func TestNormalizeRPID(t *testing.T) {
	if got, err := normalizeRPID("Example.COM"); err != nil || got != "example.com" {
		t.Fatalf("normalizeRPID = %q, %v", got, err)
	}
	for _, input := range []string{"", " Example.COM", "https://example.com", "example.com:443", "example.com/path", ".example.com", "example.com.", "a..b", "exa mple.com"} {
		if _, err := normalizeRPID(input); !errors.Is(err, ErrInvalidConfig) {
			t.Fatalf("normalizeRPID(%q) error = %v", input, err)
		}
	}
}
