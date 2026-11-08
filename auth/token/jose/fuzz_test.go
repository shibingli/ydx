package jose

import (
	"testing"
)

// FuzzVerifyNeverPanics checks that malformed compact JWS input never panics verification. |
// FuzzVerifyNeverPanics 校验非法紧凑 JWS 输入不会使验签 panic。
func FuzzVerifyNeverPanics(f *testing.F) {
	key, err := FromHMAC("fuzz", []byte("0123456789abcdef0123456789abcdef"))
	if err != nil {
		f.Fatalf("FromHMAC: %v", err)
	}
	valid, err := Sign([]byte(`{"sub":"fuzz"}`), key, SignOptions{Alg: "HS256"})
	if err != nil {
		f.Fatalf("Sign seed: %v", err)
	}
	for _, seed := range []string{
		"",
		".",
		"..",
		"e30.e30.",
		"eyJhbGciOiJub25lIn0.e30.",
		"eyJhbGciOiJIUzI1NiJ9.W10.",
		valid,
	} {
		f.Add(seed)
	}
	resolver := KeySetResolver(&KeySet{Keys: []*Key{key}})
	f.Fuzz(func(t *testing.T, token string) {
		if len(token) > DefaultMaxTokenSize+1 {
			return
		}
		_, _ = Verify(token, resolver, VerifyOptions{})
	})
}

// FuzzDecryptNeverPanics checks that malformed compact JWE input never panics decryption. |
// FuzzDecryptNeverPanics 校验非法紧凑 JWE 输入不会使解密 panic。
func FuzzDecryptNeverPanics(f *testing.F) {
	base, err := FromHMAC("fuzz", []byte("0123456789abcdef0123456789abcdef"))
	if err != nil {
		f.Fatalf("FromHMAC: %v", err)
	}
	key := base.Clone()
	key.Alg = ""
	key.Use = ""
	key.KeyOps = nil
	valid, err := Encrypt([]byte("fuzz plaintext"), key, EncryptOptions{Alg: AlgDir, Enc: EncA256GCM})
	if err != nil {
		f.Fatalf("Encrypt seed: %v", err)
	}
	for _, seed := range []string{
		"",
		".",
		"..",
		"e30.e30.e30.e30.e30",
		valid,
	} {
		f.Add(seed)
	}
	f.Fuzz(func(t *testing.T, token string) {
		if len(token) > DefaultMaxTokenSize+1 {
			return
		}
		_, _ = Decrypt(token, key, DecryptOptions{})
	})
}

// FuzzParseKeyNeverPanics checks that arbitrary JSON never panics JWK/JWKS parsing. |
// FuzzParseKeyNeverPanics 校验任意 JSON 不会使 JWK/JWKS 解析 panic。
func FuzzParseKeyNeverPanics(f *testing.F) {
	for _, seed := range [][]byte{
		nil,
		[]byte(`{}`),
		[]byte(`{"kty":"oct","k":"AA"}`),
		[]byte(`{"keys":[]}`),
		[]byte(`{"kty":"RSA","n":"","e":""}`),
		[]byte(`{"kty":"EC","crv":"P-256","x":"AA","y":"AA"}`),
	} {
		f.Add(seed)
	}
	f.Fuzz(func(t *testing.T, data []byte) {
		if len(data) > DefaultMaxTokenSize+1 {
			return
		}
		_, _ = ParseKey(data)
		_, _ = ParseKeySet(data)
	})
}
