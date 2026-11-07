package webauthn

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"errors"
	"math/big"
	"testing"
)

func TestCOSEKeyEC2RoundTrip(t *testing.T) {
	signer := newECSigner(t)
	key := signer.coseKey(t)
	encoded, err := key.Encode()
	if err != nil {
		t.Fatalf("Encode: %v", err)
	}
	parsed, err := ParseCOSEKey(encoded)
	if err != nil {
		t.Fatalf("ParseCOSEKey: %v", err)
	}
	if parsed.Kty != KeyTypeEC2 || parsed.Alg != AlgES256 || parsed.Crv != CurveP256 {
		t.Fatalf("parsed key = %#v", parsed)
	}
	if parsed.Algorithm() != AlgES256 {
		t.Fatalf("Algorithm = %d", parsed.Algorithm())
	}
	publicKey, err := parsed.PublicKey()
	if err != nil {
		t.Fatalf("PublicKey: %v", err)
	}
	ecKey, ok := publicKey.(*ecdsa.PublicKey)
	if !ok || !ecKey.Equal(&signer.key.PublicKey) {
		t.Fatalf("public key = %#v", publicKey)
	}
	message := []byte("hello webauthn")
	signature := signer.sign(t, message)
	if err := parsed.Verify(AlgES256, message, signature); err != nil {
		t.Fatalf("Verify: %v", err)
	}
	if err := parsed.Verify(AlgES384, message, signature); !errors.Is(err, ErrAlgorithmMismatch) {
		t.Fatalf("algorithm mismatch error = %v", err)
	}
	if err := parsed.Verify(AlgES256, []byte("other"), signature); err == nil {
		t.Fatal("signature verified over a different message")
	}
	if err := parsed.Verify(AlgES256, message, signature[:len(signature)-1]); err == nil {
		t.Fatal("truncated signature verified")
	}
}

func TestCOSEKeyEd25519RoundTrip(t *testing.T) {
	signer := newEdSigner(t)
	key := signer.coseKey(t)
	encoded, err := key.Encode()
	if err != nil {
		t.Fatalf("Encode: %v", err)
	}
	parsed, err := ParseCOSEKey(encoded)
	if err != nil {
		t.Fatalf("ParseCOSEKey: %v", err)
	}
	if parsed.Kty != KeyTypeOKP || parsed.Crv != CurveEd25519 || parsed.Alg != AlgEdDSA {
		t.Fatalf("parsed key = %#v", parsed)
	}
	publicKey, err := parsed.PublicKey()
	if err != nil {
		t.Fatalf("PublicKey: %v", err)
	}
	edKey, ok := publicKey.(ed25519.PublicKey)
	if !ok || !edKey.Equal(signer.key.Public()) {
		t.Fatalf("public key = %#v", publicKey)
	}
	message := []byte("ed25519 message")
	if err := parsed.Verify(AlgEdDSA, message, signer.sign(t, message)); err != nil {
		t.Fatalf("Verify: %v", err)
	}
	if err := parsed.Verify(AlgES256, message, signer.sign(t, message)); !errors.Is(err, ErrAlgorithmMismatch) {
		t.Fatalf("algorithm mismatch error = %v", err)
	}
}

func TestCOSEKeyRSA(t *testing.T) {
	privateKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("generate RSA key: %v", err)
	}
	key := &COSEKey{
		Kty: KeyTypeRSA,
		Alg: AlgRS256,
		N:   privateKey.N.Bytes(),
		E:   big.NewInt(int64(privateKey.PublicKey.E)).Bytes(),
	}
	encoded, err := key.Encode()
	if err != nil {
		t.Fatalf("Encode: %v", err)
	}
	parsed, err := ParseCOSEKey(encoded)
	if err != nil {
		t.Fatalf("ParseCOSEKey: %v", err)
	}
	publicKey, err := parsed.PublicKey()
	if err != nil {
		t.Fatalf("PublicKey: %v", err)
	}
	rsaKey, ok := publicKey.(*rsa.PublicKey)
	if !ok || !rsaKey.Equal(&privateKey.PublicKey) {
		t.Fatalf("public key = %#v", publicKey)
	}
	message := []byte("rsa message")
	digest := sha256.Sum256(message)
	signature, err := rsa.SignPKCS1v15(rand.Reader, privateKey, crypto.SHA256, digest[:])
	if err != nil {
		t.Fatalf("sign: %v", err)
	}
	if err := parsed.Verify(AlgRS256, message, signature); err != nil {
		t.Fatalf("Verify RS256: %v", err)
	}
	if err := parsed.Verify(AlgPS256, message, signature); !errors.Is(err, ErrAlgorithmMismatch) {
		t.Fatalf("algorithm mismatch error = %v", err)
	}
	pssSignature, err := rsa.SignPSS(rand.Reader, privateKey, crypto.SHA256, digest[:],
		&rsa.PSSOptions{SaltLength: rsa.PSSSaltLengthEqualsHash, Hash: crypto.SHA256})
	if err != nil {
		t.Fatalf("sign PSS: %v", err)
	}
	if err := parsed.Verify(AlgPS256, message, pssSignature); err == nil {
		t.Fatal("key algorithm RS256 accepted a PS256 request")
	}
	pssKey := &COSEKey{Kty: KeyTypeRSA, Alg: AlgPS256, N: key.N, E: key.E}
	if err := pssKey.Verify(AlgPS256, message, pssSignature); err != nil {
		t.Fatalf("Verify PS256: %v", err)
	}
}

func TestCOSEKeyP384AndP521(t *testing.T) {
	for _, test := range []struct {
		name  string
		curve elliptic.Curve
		crv   int
		alg   int
		size  int
	}{
		{name: "P-384", curve: elliptic.P384(), crv: CurveP384, alg: AlgES384, size: 48},
		{name: "P-521", curve: elliptic.P521(), crv: CurveP521, alg: AlgES512, size: 66},
	} {
		t.Run(test.name, func(t *testing.T) {
			privateKey, err := ecdsa.GenerateKey(test.curve, rand.Reader)
			if err != nil {
				t.Fatalf("generate key: %v", err)
			}
			uncompressed, err := privateKey.PublicKey.Bytes()
			if err != nil {
				t.Fatalf("encode public key: %v", err)
			}
			key := &COSEKey{
				Kty: KeyTypeEC2,
				Alg: test.alg,
				Crv: test.crv,
				X:   leftPad(uncompressed[1:1+test.size], test.size),
				Y:   leftPad(uncompressed[1+test.size:], test.size),
			}
			encoded, err := key.Encode()
			if err != nil {
				t.Fatalf("Encode: %v", err)
			}
			parsed, err := ParseCOSEKey(encoded)
			if err != nil {
				t.Fatalf("ParseCOSEKey: %v", err)
			}
			publicKey, err := parsed.PublicKey()
			if err != nil {
				t.Fatalf("PublicKey: %v", err)
			}
			ecKey, ok := publicKey.(*ecdsa.PublicKey)
			if !ok || !ecKey.Equal(&privateKey.PublicKey) {
				t.Fatalf("public key = %#v", publicKey)
			}
		})
	}
}

func TestCOSEKeyRejectsInvalidKeys(t *testing.T) {
	signer := newECSigner(t)
	valid := *signer.coseKey(t)

	t.Run("unsupported curve", func(t *testing.T) {
		key := valid
		key.Crv = 99
		if _, err := key.PublicKey(); !errors.Is(err, ErrUnsupportedKey) {
			t.Fatalf("error = %v", err)
		}
	})
	t.Run("curve algorithm mismatch", func(t *testing.T) {
		key := valid
		key.Alg = AlgES384
		if _, err := key.PublicKey(); !errors.Is(err, ErrAlgorithmMismatch) {
			t.Fatalf("error = %v", err)
		}
	})
	t.Run("coordinate length", func(t *testing.T) {
		key := valid
		key.X = key.X[:31]
		if _, err := key.PublicKey(); !errors.Is(err, ErrInvalidCOSEKey) {
			t.Fatalf("error = %v", err)
		}
	})
	t.Run("point not on curve", func(t *testing.T) {
		key := valid
		key.X = make([]byte, 32)
		key.Y = make([]byte, 32)
		if _, err := key.PublicKey(); !errors.Is(err, ErrInvalidCOSEKey) {
			t.Fatalf("error = %v", err)
		}
	})
	t.Run("unsupported key type", func(t *testing.T) {
		key := valid
		key.Kty = 42
		if _, err := key.PublicKey(); !errors.Is(err, ErrUnsupportedKey) {
			t.Fatalf("error = %v", err)
		}
	})
	t.Run("private EC parameter", func(t *testing.T) {
		encoded, err := Encode(NewMap(
			Pair{Key: NewInt(1), Value: NewInt(KeyTypeEC2)},
			Pair{Key: NewInt(3), Value: NewInt(AlgES256)},
			Pair{Key: NewInt(-1), Value: NewInt(CurveP256)},
			Pair{Key: NewInt(-2), Value: NewBytes(valid.X)},
			Pair{Key: NewInt(-3), Value: NewBytes(valid.Y)},
			Pair{Key: NewInt(-4), Value: NewBytes(make([]byte, 32))},
		))
		if err != nil {
			t.Fatalf("encode: %v", err)
		}
		if _, err := ParseCOSEKey(encoded); !errors.Is(err, ErrUnsupportedKey) {
			t.Fatalf("error = %v", err)
		}
	})
	t.Run("OKP with y parameter", func(t *testing.T) {
		encoded, err := Encode(NewMap(
			Pair{Key: NewInt(1), Value: NewInt(KeyTypeOKP)},
			Pair{Key: NewInt(3), Value: NewInt(AlgEdDSA)},
			Pair{Key: NewInt(-1), Value: NewInt(CurveEd25519)},
			Pair{Key: NewInt(-2), Value: NewBytes(make([]byte, 32))},
			Pair{Key: NewInt(-3), Value: NewBytes(make([]byte, 32))},
		))
		if err != nil {
			t.Fatalf("encode: %v", err)
		}
		if _, err := ParseCOSEKey(encoded); !errors.Is(err, ErrInvalidCOSEKey) {
			t.Fatalf("error = %v", err)
		}
	})
	t.Run("RSA with EC label", func(t *testing.T) {
		encoded, err := Encode(NewMap(
			Pair{Key: NewInt(1), Value: NewInt(KeyTypeRSA)},
			Pair{Key: NewInt(3), Value: NewInt(AlgRS256)},
			Pair{Key: NewInt(-2), Value: NewBytes(make([]byte, 32))},
			Pair{Key: NewInt(-1), Value: NewBytes(make([]byte, 32))},
			Pair{Key: NewInt(-3), Value: NewBytes(make([]byte, 32))},
		))
		if err != nil {
			t.Fatalf("encode: %v", err)
		}
		if _, err := ParseCOSEKey(encoded); !errors.Is(err, ErrInvalidCOSEKey) {
			t.Fatalf("error = %v", err)
		}
	})
	t.Run("duplicate label", func(t *testing.T) {
		value := NewMap(
			Pair{Key: NewInt(1), Value: NewInt(KeyTypeEC2)},
			Pair{Key: NewInt(3), Value: NewInt(AlgES256)},
			Pair{Key: NewInt(3), Value: NewInt(AlgES256)},
			Pair{Key: NewInt(-1), Value: NewInt(CurveP256)},
			Pair{Key: NewInt(-2), Value: NewBytes(valid.X)},
			Pair{Key: NewInt(-3), Value: NewBytes(valid.Y)},
		)
		if _, err := ParseCOSEKeyValue(value); !errors.Is(err, ErrInvalidCOSEKey) {
			t.Fatalf("error = %v", err)
		}
	})
	t.Run("empty map", func(t *testing.T) {
		if _, err := ParseCOSEKey(mustEncodeCBOR(t, NewMap())); !errors.Is(err, ErrInvalidCOSEKey) && !errors.Is(err, ErrUnsupportedKey) {
			t.Fatalf("error = %v", err)
		}
	})
	t.Run("not a map", func(t *testing.T) {
		if _, err := ParseCOSEKey(mustEncodeCBOR(t, NewUint(1))); !errors.Is(err, ErrInvalidCOSEKey) {
			t.Fatalf("error = %v", err)
		}
	})
	t.Run("private RSA parameter", func(t *testing.T) {
		key := &COSEKey{Kty: KeyTypeRSA, Alg: AlgRS256, N: valid.X, E: []byte{1, 0, 1}}
		encoded, err := Encode(NewMap(
			Pair{Key: NewInt(1), Value: NewInt(KeyTypeRSA)},
			Pair{Key: NewInt(3), Value: NewInt(AlgRS256)},
			Pair{Key: NewInt(-1), Value: NewBytes(key.N)},
			Pair{Key: NewInt(-2), Value: NewBytes(key.E)},
			Pair{Key: NewInt(-4), Value: NewBytes(make([]byte, 16))},
		))
		if err != nil {
			t.Fatalf("encode: %v", err)
		}
		if _, err := ParseCOSEKey(encoded); !errors.Is(err, ErrUnsupportedKey) {
			t.Fatalf("error = %v", err)
		}
	})
}

func TestCOSEAlgorithmHelpers(t *testing.T) {
	if name := AlgorithmName(AlgES256); name != "ES256" {
		t.Fatalf("AlgorithmName(ES256) = %q", name)
	}
	if name := AlgorithmName(9999); name != "" {
		t.Fatalf("AlgorithmName(9999) = %q", name)
	}
	if hash, ok := HashForAlgorithm(AlgES384); !ok || hash != crypto.SHA384 {
		t.Fatalf("HashForAlgorithm(ES384) = %v, %v", hash, ok)
	}
	if _, ok := HashForAlgorithm(9999); ok {
		t.Fatal("HashForAlgorithm accepted an unknown algorithm")
	}
	if len(DefaultAlgorithms()) == 0 {
		t.Fatal("DefaultAlgorithms returned nothing")
	}
	for _, alg := range DefaultAlgorithms() {
		if _, ok := HashForAlgorithm(alg); !ok && alg != AlgEdDSA {
			t.Fatalf("default algorithm %s has no hash", AlgorithmName(alg))
		}
	}
}

func leftPad(value []byte, size int) []byte {
	if len(value) >= size {
		return append([]byte(nil), value...)
	}
	out := make([]byte, size)
	copy(out[size-len(value):], value)
	return out
}
