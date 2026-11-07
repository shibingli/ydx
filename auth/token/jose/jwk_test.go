package jose

import (
	"bytes"
	"crypto/ecdh"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"errors"
	"strings"
	"sync"
	"testing"

	"github.com/shibingli/ydx/json"
)

// rfc7638RSAJWK is the worked example of RFC 7638 section 3.1. | rfc7638RSAJWK 是 RFC 7638 第
// 3.1 节的示例。
const rfc7638RSAJWK = `{"kty":"RSA","n":"0vx7agoebGcQSuuPiLJXZptN9nndrQmbXEps2aiAFbWhM78LhWx4cbbfAAtVT86zwu1RK7aPFFxuhDR1L6tSoc_BJECPebWKRXjBZCiFV4n3oknjhMstn64tZ_2W-5JsGY4Hc5n9yBXArwl93lqt7_RN5w6Cf0h4QyQ5v-65YGjQR0_FDW2QvzqY368QQMicAtaSqzs8KJZgnYb9c7d0zgdAZHzu6qMQvRL5hajrn1n91CbOpbISD08qNLyrdkt-bFTWhAI4vMQFh6WeZu0fM4lFd2NcRwr3XPksINHaQ-G_xBniIqbw0Ls1jF44-csFCur-kEgU8awapJzKnqDKgw","e":"AQAB","alg":"RS256","kid":"2011-04-29"}`

var (
	sharedRSAOnce sync.Once
	sharedRSAKey  *Key
	sharedRSAErr  error
)

// testRSAKey returns a shared RSA key bound to RS256. Generating a 2048-bit key is expensive, so
// every test shares one instance. | testRSAKey 返回绑定 RS256 的共享 RSA 密钥。生成 2048 位密钥
// 开销较大，因此所有测试共享同一实例。
func testRSAKey(t *testing.T) *Key {
	t.Helper()
	sharedRSAOnce.Do(func() {
		sharedRSAKey, sharedRSAErr = GenerateKey("RS256", 2048)
	})
	if sharedRSAErr != nil {
		t.Fatalf("GenerateKey(RS256) failed: %v", sharedRSAErr)
	}
	return sharedRSAKey
}

// testUnboundRSAKey returns a shared RSA key without an algorithm binding. | testUnboundRSAKey 返回
// 不带算法绑定的共享 RSA 密钥。
func testUnboundRSAKey(t *testing.T) *Key {
	t.Helper()
	priv, err := testRSAKey(t).PrivateKey()
	if err != nil {
		t.Fatalf("RSA PrivateKey failed: %v", err)
	}
	k, err := FromPrivateKey("rsa-test", priv)
	if err != nil {
		t.Fatalf("FromPrivateKey(RSA) failed: %v", err)
	}
	return k
}

func TestThumbprintRFC7638(t *testing.T) {
	k, err := ParseKey([]byte(rfc7638RSAJWK))
	if err != nil {
		t.Fatalf("ParseKey failed: %v", err)
	}
	if err := k.Validate(); err != nil {
		t.Fatalf("Validate failed: %v", err)
	}
	const want = "NzbLsXh8uDCcd-6MNwXF4W_7noWXFZAfHkxZsRGC9Xs"
	got, err := k.Thumbprint()
	if err != nil {
		t.Fatalf("Thumbprint failed: %v", err)
	}
	if got != want {
		t.Fatalf("Thumbprint = %q, want %q", got, want)
	}
	renamed := k.Clone()
	renamed.Kid = "rotated"
	renamed.Alg = ""
	renamed.Use = "enc"
	again, err := renamed.Thumbprint()
	if err != nil {
		t.Fatalf("Thumbprint after metadata change failed: %v", err)
	}
	if again != want {
		t.Fatalf("Thumbprint changed with metadata: %q, want %q", again, want)
	}
}

func TestParseKeyRSAMaterial(t *testing.T) {
	k, err := ParseKey([]byte(rfc7638RSAJWK))
	if err != nil {
		t.Fatalf("ParseKey failed: %v", err)
	}
	raw, err := k.PublicKey()
	if err != nil {
		t.Fatalf("PublicKey failed: %v", err)
	}
	pub, ok := raw.(*rsa.PublicKey)
	if !ok {
		t.Fatalf("PublicKey type = %T, want *rsa.PublicKey", raw)
	}
	if pub.N.BitLen() != 2048 {
		t.Fatalf("modulus bit length = %d, want 2048", pub.N.BitLen())
	}
	if pub.E != 65537 {
		t.Fatalf("exponent = %d, want 65537", pub.E)
	}
	if _, err := k.PrivateKey(); !errors.Is(err, ErrNotPrivateKey) {
		t.Fatalf("PrivateKey error = %v, want ErrNotPrivateKey", err)
	}
	pubOnly := k.Public()
	if pubOnly.D != "" || pubOnly.P != "" || pubOnly.Q != "" || pubOnly.DP != "" || pubOnly.DQ != "" || pubOnly.QI != "" {
		t.Fatalf("Public retained private members: %+v", pubOnly)
	}
	if err := pubOnly.Validate(); err != nil {
		t.Fatalf("public Validate failed: %v", err)
	}
	want, _ := k.Thumbprint()
	got, err := pubOnly.Thumbprint()
	if err != nil {
		t.Fatalf("public Thumbprint failed: %v", err)
	}
	if got != want {
		t.Fatalf("public Thumbprint = %q, want %q", got, want)
	}
}

func TestParseKeyRejectsMalformed(t *testing.T) {
	cases := []struct {
		name string
		jwk  string
	}{
		{"empty input", ""},
		{"not json", "{"},
		{"no kty", `{"n":"AQAB"}`},
		{"rsa missing n", `{"kty":"RSA","e":"AQAB"}`},
		{"rsa bad exponent", `{"kty":"RSA","n":"AQAB","e":"AA"}`},
		{"oct missing k", `{"kty":"oct"}`},
		{"oct bad base64", `{"kty":"oct","k":"%%%"}`},
		{"ec short coordinate", `{"kty":"EC","crv":"P-256","x":"AQ","y":"AQ"}`},
		{"ec unknown curve", `{"kty":"EC","crv":"P-999","x":"AQ","y":"AQ"}`},
		{"okp short x", `{"kty":"OKP","crv":"Ed25519","x":"AQ"}`},
		{"unknown kty", `{"kty":"weird","k":"AQ"}`},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			k, err := ParseKey([]byte(tc.jwk))
			if err == nil {
				err = k.Validate()
			}
			if !errors.Is(err, ErrInvalidKey) {
				t.Fatalf("error = %v, want ErrInvalidKey", err)
			}
		})
	}
}

func TestGenerateKeyRoundTrips(t *testing.T) {
	cases := []struct {
		alg  string
		bits int
		kty  string
		crv  string
	}{
		{"RS256", 2048, KeyTypeRSA, ""},
		{"ES256", 0, KeyTypeEC, CurveP256},
		{"ES384", 0, KeyTypeEC, CurveP384},
		{"ES512", 0, KeyTypeEC, CurveP521},
		{"EdDSA", 0, KeyTypeOKP, CurveEd25519},
		{"HS256", 0, KeyTypeOct, ""},
		{"ECDH-ES", 256, KeyTypeEC, CurveP256},
		{"ECDH-ES+A128KW", 384, KeyTypeEC, CurveP384},
	}
	for _, tc := range cases {
		t.Run(tc.alg, func(t *testing.T) {
			k, err := GenerateKey(tc.alg, tc.bits)
			if err != nil {
				t.Fatalf("GenerateKey failed: %v", err)
			}
			if k.Kty != tc.kty || k.Crv != tc.crv || k.Alg != tc.alg {
				t.Fatalf("key = kty %q crv %q alg %q, want %q %q %q", k.Kty, k.Crv, k.Alg, tc.kty, tc.crv, tc.alg)
			}
			if err := k.Validate(); err != nil {
				t.Fatalf("Validate failed: %v", err)
			}
			if _, err := k.PrivateKey(); err != nil {
				t.Fatalf("PrivateKey failed: %v", err)
			}
			if _, err := k.PublicKey(); err != nil {
				t.Fatalf("PublicKey failed: %v", err)
			}
			encoded, err := json.Marshal(k)
			if err != nil {
				t.Fatalf("Marshal failed: %v", err)
			}
			parsed, err := ParseKey(encoded)
			if err != nil {
				t.Fatalf("ParseKey failed: %v", err)
			}
			if err := parsed.Validate(); err != nil {
				t.Fatalf("parsed Validate failed: %v", err)
			}
			want, err := k.Thumbprint()
			if err != nil {
				t.Fatalf("Thumbprint failed: %v", err)
			}
			got, err := parsed.Thumbprint()
			if err != nil {
				t.Fatalf("parsed Thumbprint failed: %v", err)
			}
			if got != want {
				t.Fatalf("round-trip Thumbprint = %q, want %q", got, want)
			}
			pub := k.Public()
			if pub.Kty != k.Kty || pub.Crv != k.Crv {
				t.Fatalf("Public changed key identity: %+v", pub)
			}
			if k.Kty == KeyTypeOct {
				if _, err := pub.PrivateKey(); err != nil {
					t.Fatalf("oct Public should retain k: %v", err)
				}
			} else if _, err := pub.PrivateKey(); !errors.Is(err, ErrNotPrivateKey) {
				t.Fatalf("Public PrivateKey error = %v, want ErrNotPrivateKey", err)
			}
		})
	}
}

func TestGenerateKeyRejects(t *testing.T) {
	cases := []struct {
		alg  string
		bits int
		want error
	}{
		{"none", 0, ErrAlgNotAllowed},
		{"RS256", 1024, ErrWeakKey},
		{"HS256", 64, ErrWeakKey},
		{"ECDH-ES", 123, ErrInvalidConfig},
		{"", 0, ErrAlgNotAllowed},
	}
	for _, tc := range cases {
		if _, err := GenerateKey(tc.alg, tc.bits); !errors.Is(err, tc.want) {
			t.Fatalf("GenerateKey(%q, %d) error = %v, want %v", tc.alg, tc.bits, err, tc.want)
		}
	}
}

func TestFromStandardKeys(t *testing.T) {
	rsaPriv, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("rsa.GenerateKey failed: %v", err)
	}
	ecPriv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("ecdsa.GenerateKey failed: %v", err)
	}
	edPub, edPriv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("ed25519.GenerateKey failed: %v", err)
	}
	xPriv, err := ecdh.X25519().GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("X25519 GenerateKey failed: %v", err)
	}
	secret := bytes.Repeat([]byte{0x42}, 32)

	privCases := []struct {
		name string
		priv any
		kty  string
		crv  string
	}{
		{"rsa", rsaPriv, KeyTypeRSA, ""},
		{"ecdsa", ecPriv, KeyTypeEC, CurveP256},
		{"ed25519", edPriv, KeyTypeOKP, CurveEd25519},
		{"x25519", xPriv, KeyTypeOKP, CurveX25519},
		{"oct", secret, KeyTypeOct, ""},
	}
	for _, tc := range privCases {
		t.Run("private/"+tc.name, func(t *testing.T) {
			k, err := FromPrivateKey("kid-"+tc.name, tc.priv)
			if err != nil {
				t.Fatalf("FromPrivateKey failed: %v", err)
			}
			if k.Kty != tc.kty || k.Crv != tc.crv || k.Kid != "kid-"+tc.name || k.Alg != "" {
				t.Fatalf("key = %+v", k)
			}
			if err := k.Validate(); err != nil {
				t.Fatalf("Validate failed: %v", err)
			}
			if _, err := k.PrivateKey(); err != nil {
				t.Fatalf("PrivateKey failed: %v", err)
			}
			pub := k.Public()
			if err := pub.Validate(); err != nil {
				t.Fatalf("public Validate failed: %v", err)
			}
			want, _ := k.Thumbprint()
			got, err := pub.Thumbprint()
			if err != nil {
				t.Fatalf("public Thumbprint failed: %v", err)
			}
			if got != want {
				t.Fatalf("public Thumbprint = %q, want %q", got, want)
			}
		})
	}

	pubCases := []struct {
		name string
		pub  any
	}{
		{"rsa", &rsaPriv.PublicKey},
		{"ecdsa", &ecPriv.PublicKey},
		{"ed25519", edPub},
		{"x25519", xPriv.PublicKey()},
		{"oct", secret},
	}
	for _, tc := range pubCases {
		t.Run("public/"+tc.name, func(t *testing.T) {
			k, err := FromPublicKey("pub-"+tc.name, tc.pub)
			if err != nil {
				t.Fatalf("FromPublicKey failed: %v", err)
			}
			if err := k.Validate(); err != nil {
				t.Fatalf("Validate failed: %v", err)
			}
			if _, err := k.PublicKey(); err != nil {
				t.Fatalf("PublicKey failed: %v", err)
			}
			if _, err := k.PrivateKey(); tc.name != "oct" && !errors.Is(err, ErrNotPrivateKey) {
				t.Fatalf("PrivateKey error = %v, want ErrNotPrivateKey", err)
			}
		})
	}

	if _, err := FromPrivateKey("bad", 42); !errors.Is(err, ErrInvalidKey) {
		t.Fatalf("FromPrivateKey(42) error = %v, want ErrInvalidKey", err)
	}
	if _, err := FromPublicKey("bad", 42); !errors.Is(err, ErrInvalidKey) {
		t.Fatalf("FromPublicKey(42) error = %v, want ErrInvalidKey", err)
	}
	if _, err := FromHMAC("bad", nil); !errors.Is(err, ErrInvalidKey) {
		t.Fatalf("FromHMAC(nil) error = %v, want ErrInvalidKey", err)
	}
}

func TestKeyNilSafety(t *testing.T) {
	var k *Key
	if k.Public() != nil || k.Clone() != nil {
		t.Fatal("nil key copy methods returned non-nil")
	}
	if !errors.Is(k.Validate(), ErrInvalidKey) {
		t.Fatal("nil Validate should fail with ErrInvalidKey")
	}
	if _, err := k.Thumbprint(); !errors.Is(err, ErrInvalidKey) {
		t.Fatal("nil Thumbprint should fail with ErrInvalidKey")
	}
	if _, err := k.PrivateKey(); !errors.Is(err, ErrInvalidKey) {
		t.Fatal("nil PrivateKey should fail with ErrInvalidKey")
	}
	if _, err := k.PublicKey(); !errors.Is(err, ErrInvalidKey) {
		t.Fatal("nil PublicKey should fail with ErrInvalidKey")
	}
}

func TestMarshalPublicKeyOmitsPrivateMembers(t *testing.T) {
	k := testRSAKey(t)
	out, err := k.Public().MarshalJSON()
	if err != nil {
		t.Fatalf("MarshalJSON failed: %v", err)
	}
	text := string(out)
	if !strings.Contains(text, `"kty":"RSA"`) || !strings.Contains(text, `"n":`) || !strings.Contains(text, `"e":`) {
		t.Fatalf("public JWK lacks required members: %s", text)
	}
	for _, member := range []string{`"d":`, `"p":`, `"q":`, `"dp":`, `"dq":`, `"qi":`, `"oth":`} {
		if strings.Contains(text, member) {
			t.Fatalf("public JWK retains %s: %s", member, text)
		}
	}
	if _, err := ParseKey(out); err != nil {
		t.Fatalf("ParseKey(public) failed: %v", err)
	}
}
