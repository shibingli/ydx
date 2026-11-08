package jose

import (
	"bytes"
	"crypto/ecdh"
	"crypto/rand"
	"crypto/rsa"
	"encoding/hex"
	"errors"
	"strings"
	"testing"
)

// testOctKey returns an oct key of exactly n bytes. | testOctKey 返回恰好 n 字节的 oct 密钥。
func testOctKey(t *testing.T, n int) *Key {
	t.Helper()
	k, err := FromHMAC("sym", bytes.Repeat([]byte{0x5a}, n))
	if err != nil {
		t.Fatalf("FromHMAC failed: %v", err)
	}
	return k
}

// testECDHKey returns an unbound EC key on the requested curve. | testECDHKey 返回指定曲线上的未绑定
// EC 密钥。
func testECDHKey(t *testing.T, bits int) *Key {
	t.Helper()
	k, err := GenerateKey(AlgECDHES, bits)
	if err != nil {
		t.Fatalf("GenerateKey(ECDH-ES) failed: %v", err)
	}
	priv, err := k.PrivateKey()
	if err != nil {
		t.Fatalf("ECDH PrivateKey failed: %v", err)
	}
	unbound, err := FromPrivateKey("ecdh", priv)
	if err != nil {
		t.Fatalf("FromPrivateKey(ECDH) failed: %v", err)
	}
	return unbound
}

// jweTestKey returns a key-management key for alg. | jweTestKey 返回 alg 的密钥管理密钥。
func jweTestKey(t *testing.T, alg string) *Key {
	t.Helper()
	switch alg {
	case AlgRSAOAEP, AlgRSAOAEP256, AlgRSA15:
		return testUnboundRSAKey(t)
	case AlgA128KW:
		return testOctKey(t, 16)
	case AlgA192KW:
		return testOctKey(t, 24)
	case AlgA256KW:
		return testOctKey(t, 32)
	default:
		return testECDHKey(t, 256)
	}
}

// dummyJWE builds a five-segment JWE with the given protected header. | dummyJWE 使用给定受保护
// 头部构造五段 JWE。
func dummyJWE(header string) string {
	return EncodeSegment([]byte(header)) + ".AAAA.AAAA.AAAA.AAAA"
}

// TestAESKeyWrapRFC3394 checks the worked examples of RFC 3394 section 4. | TestAESKeyWrapRFC3394
// 校验 RFC 3394 第 4 节的示例。
func TestAESKeyWrapRFC3394(t *testing.T) {
	plain := mustHex(t, "00112233445566778899AABBCCDDEEFF")
	cases := []struct {
		kek  string
		want string
	}{
		{"000102030405060708090A0B0C0D0E0F", "1FA68B0A8112B447AEF34BD8FB5A7B829D3E862371D2CFE5"},
		{"000102030405060708090A0B0C0D0E0F1011121314151617", "96778B25AE6CA435F92B5B97C050AED2468AB8A17AD84E5D"},
		{"000102030405060708090A0B0C0D0E0F101112131415161718191A1B1C1D1E1F", "64E8C3F9CE0F5BA263E9777905818A2A93C8191E7D6E8AE7"},
	}
	for _, tc := range cases {
		kek := mustHex(t, tc.kek)
		wrapped, err := aesKeyWrap(kek, plain)
		if err != nil {
			t.Fatalf("aesKeyWrap failed: %v", err)
		}
		if got := hex.EncodeToString(wrapped); !strings.EqualFold(got, tc.want) {
			t.Fatalf("wrapped = %s, want %s", got, tc.want)
		}
		unwrapped, err := aesKeyUnwrap(kek, wrapped)
		if err != nil {
			t.Fatalf("aesKeyUnwrap failed: %v", err)
		}
		if !bytes.Equal(unwrapped, plain) {
			t.Fatalf("unwrapped = %x, want %x", unwrapped, plain)
		}
		tampered := append([]byte(nil), wrapped...)
		tampered[0] ^= 0x01
		if _, err := aesKeyUnwrap(kek, tampered); !errors.Is(err, ErrDecryptionFailed) {
			t.Fatalf("tampered unwrap error = %v, want ErrDecryptionFailed", err)
		}
	}
}

func TestJWERoundTripMatrix(t *testing.T) {
	encs := []string{EncA128CBCHS256, EncA192CBCHS384, EncA256CBCHS512, EncA128GCM, EncA192GCM, EncA256GCM}
	algs := []string{
		AlgRSAOAEP, AlgRSAOAEP256, AlgRSA15,
		AlgA128KW, AlgA192KW, AlgA256KW,
		AlgDir,
		AlgECDHES, AlgECDHESA128KW, AlgECDHESA192KW, AlgECDHESA256KW,
	}
	plaintext := []byte("The true sign of intelligence is not knowledge but imagination.")
	for _, enc := range encs {
		enc := enc
		p, _ := encParamsFor(enc)
		for _, alg := range algs {
			alg := alg
			t.Run(alg+"/"+enc, func(t *testing.T) {
				var key, encKey *Key
				if alg == AlgDir {
					key = testOctKey(t, p.cekLen)
					encKey = key
				} else {
					key = jweTestKey(t, alg)
					if alg == AlgRSAOAEP || alg == AlgRSAOAEP256 || alg == AlgRSA15 || strings.HasPrefix(alg, AlgECDHES) {
						encKey = key.Public()
					} else {
						encKey = key
					}
				}
				opts := EncryptOptions{
					Alg:         alg,
					Enc:         enc,
					Kid:         "jwe-" + alg,
					Typ:         "JWE",
					Cty:         "text/plain",
					AllowRSA1_5: alg == AlgRSA15,
				}
				if strings.HasPrefix(alg, AlgECDHES) {
					opts.APU = []byte("alice")
					opts.APV = []byte("bob")
				}
				token, err := Encrypt(plaintext, encKey, opts)
				if err != nil {
					t.Fatalf("Encrypt failed: %v", err)
				}
				parts := strings.Split(token, ".")
				if len(parts) != 5 {
					t.Fatalf("token has %d segments, want 5", len(parts))
				}
				if alg == AlgECDHES && parts[1] != "" {
					t.Fatalf("ECDH-ES encrypted key is not empty: %q", parts[1])
				}
				if alg != AlgECDHES && alg != AlgDir && parts[1] == "" {
					t.Fatal("encrypted key segment is empty")
				}
				got, err := Decrypt(token, key, DecryptOptions{AllowRSA1_5: alg == AlgRSA15})
				if err != nil {
					t.Fatalf("Decrypt failed: %v", err)
				}
				if !bytes.Equal(got, plaintext) {
					t.Fatalf("plaintext = %q, want %q", got, plaintext)
				}
			})
		}
	}
}

func TestJWEEmptyAndLongPlaintext(t *testing.T) {
	encs := []string{EncA128CBCHS256, EncA256CBCHS512, EncA128GCM, EncA256GCM}
	for _, enc := range encs {
		t.Run(enc, func(t *testing.T) {
			p, _ := encParamsFor(enc)
			key := testOctKey(t, p.cekLen)
			for _, plaintext := range [][]byte{{}, bytes.Repeat([]byte("A"), 4096)} {
				token, err := Encrypt(plaintext, key, EncryptOptions{Alg: AlgDir, Enc: enc})
				if err != nil {
					t.Fatalf("Encrypt failed: %v", err)
				}
				got, err := Decrypt(token, key, DecryptOptions{})
				if err != nil {
					t.Fatalf("Decrypt failed: %v", err)
				}
				if !bytes.Equal(got, plaintext) {
					t.Fatalf("plaintext length = %d, want %d", len(got), len(plaintext))
				}
			}
		})
	}
}

func TestJWEZipDEF(t *testing.T) {
	plaintext := bytes.Repeat([]byte("compress me please "), 256)
	for _, enc := range []string{EncA128CBCHS256, EncA256CBCHS512, EncA128GCM, EncA256GCM} {
		t.Run(enc, func(t *testing.T) {
			p, _ := encParamsFor(enc)
			key := testOctKey(t, p.cekLen)
			compressed, err := Encrypt(plaintext, key, EncryptOptions{Alg: AlgDir, Enc: enc, Zip: ZipDEF})
			if err != nil {
				t.Fatalf("Encrypt(zip=DEF) failed: %v", err)
			}
			plain, err := Encrypt(plaintext, key, EncryptOptions{Alg: AlgDir, Enc: enc})
			if err != nil {
				t.Fatalf("Encrypt failed: %v", err)
			}
			if len(compressed) >= len(plain) {
				t.Fatalf("compressed token %d bytes is not smaller than %d bytes", len(compressed), len(plain))
			}
			got, err := Decrypt(compressed, key, DecryptOptions{})
			if err != nil {
				t.Fatalf("Decrypt(zip=DEF) failed: %v", err)
			}
			if !bytes.Equal(got, plaintext) {
				t.Fatal("zip round trip changed the plaintext")
			}
			if _, err := Decrypt(compressed, key, DecryptOptions{MaxDecompressedSize: int64(len(plaintext)) / 2}); !errors.Is(err, ErrDecompressionLimit) {
				t.Fatalf("decompression limit error = %v, want ErrDecompressionLimit", err)
			}
			if _, err := Decrypt(compressed, key, DecryptOptions{MaxDecompressedSize: int64(len(plaintext))}); err != nil {
				t.Fatalf("Decrypt with exact limit failed: %v", err)
			}
		})
	}
}

func TestJWEHeaderAndAgreement(t *testing.T) {
	key := testECDHKey(t, 256)
	apu := []byte("alice")
	apv := []byte("bob")
	for _, alg := range []string{AlgECDHES, AlgECDHESA128KW, AlgECDHESA192KW, AlgECDHESA256KW} {
		t.Run(alg, func(t *testing.T) {
			token, err := Encrypt([]byte("agreed"), key.Public(), EncryptOptions{
				Alg: alg, Enc: EncA128GCM, APU: apu, APV: apv,
			})
			if err != nil {
				t.Fatalf("Encrypt failed: %v", err)
			}
			parts := strings.Split(token, ".")
			raw, err := DecodeSegment(parts[0])
			if err != nil {
				t.Fatalf("DecodeSegment failed: %v", err)
			}
			h, err := parseJWEHeader(raw)
			if err != nil {
				t.Fatalf("parseJWEHeader failed: %v", err)
			}
			if h.Alg != alg || h.Enc != EncA128GCM {
				t.Fatalf("header = %+v", h)
			}
			if h.EPK == nil || h.EPK.D != "" || h.EPK.Kty != KeyTypeEC || h.EPK.Crv != CurveP256 {
				t.Fatalf("epk = %+v", h.EPK)
			}
			gotAPU, err := decodeOptionalB64(h.APU)
			if err != nil {
				t.Fatalf("decode apu failed: %v", err)
			}
			gotAPV, err := decodeOptionalB64(h.APV)
			if err != nil {
				t.Fatalf("decode apv failed: %v", err)
			}
			if !bytes.Equal(gotAPU, apu) || !bytes.Equal(gotAPV, apv) {
				t.Fatalf("apu/apv = %q/%q", gotAPU, gotAPV)
			}
			plaintext, err := Decrypt(token, key, DecryptOptions{})
			if err != nil {
				t.Fatalf("Decrypt failed: %v", err)
			}
			if string(plaintext) != "agreed" {
				t.Fatalf("plaintext = %q", plaintext)
			}
		})
	}

	t.Run("p521", func(t *testing.T) {
		k := testECDHKey(t, 521)
		token, err := Encrypt([]byte("p521"), k.Public(), EncryptOptions{Alg: AlgECDHES, Enc: EncA256GCM})
		if err != nil {
			t.Fatalf("Encrypt failed: %v", err)
		}
		parts := strings.Split(token, ".")
		raw, _ := DecodeSegment(parts[0])
		h, err := parseJWEHeader(raw)
		if err != nil {
			t.Fatalf("parseJWEHeader failed: %v", err)
		}
		if h.EPK == nil || h.EPK.Crv != CurveP521 {
			t.Fatalf("epk = %+v", h.EPK)
		}
		got, err := Decrypt(token, k, DecryptOptions{})
		if err != nil {
			t.Fatalf("Decrypt failed: %v", err)
		}
		if string(got) != "p521" {
			t.Fatalf("plaintext = %q", got)
		}
	})

	t.Run("x25519", func(t *testing.T) {
		priv, err := ecdh.X25519().GenerateKey(rand.Reader)
		if err != nil {
			t.Fatalf("X25519 GenerateKey failed: %v", err)
		}
		k, err := FromPrivateKey("x25519", priv)
		if err != nil {
			t.Fatalf("FromPrivateKey failed: %v", err)
		}
		token, err := Encrypt([]byte("x"), k.Public(), EncryptOptions{Alg: AlgECDHES, Enc: EncA256GCM})
		if err != nil {
			t.Fatalf("Encrypt failed: %v", err)
		}
		parts := strings.Split(token, ".")
		raw, _ := DecodeSegment(parts[0])
		h, err := parseJWEHeader(raw)
		if err != nil {
			t.Fatalf("parseJWEHeader failed: %v", err)
		}
		if h.EPK == nil || h.EPK.Crv != CurveX25519 || h.EPK.Kty != KeyTypeOKP {
			t.Fatalf("epk = %+v", h.EPK)
		}
		got, err := Decrypt(token, k, DecryptOptions{})
		if err != nil {
			t.Fatalf("Decrypt failed: %v", err)
		}
		if string(got) != "x" {
			t.Fatalf("plaintext = %q", got)
		}
	})
}

func TestJWERSA1_5OptIn(t *testing.T) {
	key := testUnboundRSAKey(t)
	opts := EncryptOptions{Alg: AlgRSA15, Enc: EncA128GCM}
	if _, err := Encrypt([]byte("x"), key, opts); !errors.Is(err, ErrAlgNotAllowed) {
		t.Fatalf("Encrypt without opt-in error = %v, want ErrAlgNotAllowed", err)
	}
	opts.AllowRSA1_5 = true
	token, err := Encrypt([]byte("x"), key, opts)
	if err != nil {
		t.Fatalf("Encrypt with opt-in failed: %v", err)
	}
	if _, err := Decrypt(token, key, DecryptOptions{}); !errors.Is(err, ErrAlgNotAllowed) {
		t.Fatalf("Decrypt without opt-in error = %v, want ErrAlgNotAllowed", err)
	}
	got, err := Decrypt(token, key, DecryptOptions{AllowRSA1_5: true})
	if err != nil {
		t.Fatalf("Decrypt with opt-in failed: %v", err)
	}
	if string(got) != "x" {
		t.Fatalf("plaintext = %q", got)
	}
}

func TestJWEConfigurationErrors(t *testing.T) {
	rsaKey := testUnboundRSAKey(t)
	sym := testOctKey(t, 32)
	cases := []struct {
		name string
		key  *Key
		opts EncryptOptions
		want error
	}{
		{"nil key", nil, EncryptOptions{Alg: AlgDir, Enc: EncA256GCM}, ErrInvalidKey},
		{"unknown alg", sym, EncryptOptions{Alg: "none", Enc: EncA256GCM}, ErrAlgNotAllowed},
		{"unknown enc", sym, EncryptOptions{Alg: AlgDir, Enc: "A512GCM"}, ErrUnsupportedEnc},
		{"bad zip", sym, EncryptOptions{Alg: AlgDir, Enc: EncA256GCM, Zip: "GZ"}, ErrInvalidConfig},
		{"dir short key", testOctKey(t, 16), EncryptOptions{Alg: AlgDir, Enc: EncA256GCM}, ErrWeakKey},
		{"kw wrong length", testOctKey(t, 16), EncryptOptions{Alg: AlgA256KW, Enc: EncA128GCM}, ErrWeakKey},
		{"key alg binding", mustGenerate(t, "HS256"), EncryptOptions{Alg: AlgA256KW, Enc: EncA128GCM}, ErrAlgNotAllowed},
		{"rsa in ecdh", rsaKey, EncryptOptions{Alg: AlgECDHES, Enc: EncA128GCM}, ErrKeyTypeMismatch},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if _, err := Encrypt([]byte("x"), tc.key, tc.opts); !errors.Is(err, tc.want) {
				t.Fatalf("error = %v, want %v", err, tc.want)
			}
		})
	}
	if _, err := Decrypt("a.b.c.d.e", rsaKey, DecryptOptions{}); !errors.Is(err, ErrMalformed) {
		t.Fatalf("malformed header error = %v, want ErrMalformed", err)
	}
	if _, err := Decrypt(dummyJWE(`{"alg":"dir","enc":"A256GCM"}`), nil, DecryptOptions{}); !errors.Is(err, ErrInvalidKey) {
		t.Fatalf("nil key error = %v, want ErrInvalidKey", err)
	}
	for _, token := range []string{"", "a.b.c", "a.b.c.d", "." + "AAAA.AAAA.AAAA.AAAA"} {
		if _, err := Decrypt(token, sym, DecryptOptions{}); err == nil {
			t.Fatalf("Decrypt(%q) succeeded, want error", token)
		}
	}
}

func TestJWERSAMinimumKeySize(t *testing.T) {
	small, err := rsa.GenerateKey(rand.Reader, 1024)
	if err != nil {
		t.Fatalf("rsa.GenerateKey failed: %v", err)
	}
	key, err := FromPrivateKey("small", small)
	if err != nil {
		t.Fatalf("FromPrivateKey failed: %v", err)
	}
	if _, err := Encrypt([]byte("x"), key, EncryptOptions{Alg: AlgRSAOAEP, Enc: EncA128GCM}); !errors.Is(err, ErrWeakKey) {
		t.Fatalf("error = %v, want ErrWeakKey", err)
	}
}

func TestJWEHeaderRejections(t *testing.T) {
	key := testOctKey(t, 32)
	cases := []struct {
		name   string
		header string
		want   error
	}{
		{"none alg", `{"alg":"none","enc":"A256GCM"}`, ErrAlgNotAllowed},
		{"unknown enc", `{"alg":"dir","enc":"A512GCM"}`, ErrUnsupportedEnc},
		{"unknown zip", `{"alg":"dir","enc":"A256GCM","zip":"GZ"}`, ErrInvalidHeader},
		{"crit", `{"alg":"dir","enc":"A256GCM","crit":["exp"]}`, ErrUnsupportedCrit},
		{"duplicate", `{"alg":"dir","alg":"dir","enc":"A256GCM"}`, ErrInvalidHeader},
		{"epk without ecdh", `{"alg":"dir","enc":"A256GCM","epk":{"kty":"EC"}}`, ErrInvalidHeader},
		{"epk private material", `{"alg":"ECDH-ES","enc":"A256GCM","epk":{"kty":"EC","crv":"P-256","d":"AQ"}}`, ErrInvalidHeader},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if _, err := Decrypt(dummyJWE(tc.header), key, DecryptOptions{}); !errors.Is(err, tc.want) {
				t.Fatalf("error = %v, want %v", err, tc.want)
			}
		})
	}

	valid, err := Encrypt([]byte("x"), key, EncryptOptions{Alg: AlgDir, Enc: EncA256GCM})
	if err != nil {
		t.Fatalf("Encrypt failed: %v", err)
	}
	parts := strings.Split(valid, ".")
	parts[1] = EncodeSegment([]byte{0x01})
	if _, err := Decrypt(strings.Join(parts, "."), key, DecryptOptions{}); !errors.Is(err, ErrDecryptionFailed) {
		t.Fatalf("dir with encrypted key error = %v, want ErrDecryptionFailed", err)
	}

	ec := testECDHKey(t, 256)
	ecToken, err := Encrypt([]byte("x"), ec.Public(), EncryptOptions{Alg: AlgECDHES, Enc: EncA256GCM})
	if err != nil {
		t.Fatalf("Encrypt failed: %v", err)
	}
	parts = strings.Split(ecToken, ".")
	parts[1] = EncodeSegment([]byte{0x01})
	if _, err := Decrypt(strings.Join(parts, "."), ec, DecryptOptions{}); !errors.Is(err, ErrDecryptionFailed) {
		t.Fatalf("ECDH-ES with encrypted key error = %v, want ErrDecryptionFailed", err)
	}
}

func TestJWETampering(t *testing.T) {
	cbcKey := testOctKey(t, 32)
	gcmKey := testOctKey(t, 32)
	rsaKey := testUnboundRSAKey(t)

	t.Run("cbc ciphertext", func(t *testing.T) {
		token, err := Encrypt([]byte("secret"), cbcKey, EncryptOptions{Alg: AlgDir, Enc: EncA128CBCHS256})
		if err != nil {
			t.Fatalf("Encrypt failed: %v", err)
		}
		expectDecryptFailed(t, tamperJWESegment(t, token, 3), cbcKey)
	})
	t.Run("cbc tag", func(t *testing.T) {
		token, _ := Encrypt([]byte("secret"), cbcKey, EncryptOptions{Alg: AlgDir, Enc: EncA128CBCHS256})
		expectDecryptFailed(t, tamperJWESegment(t, token, 4), cbcKey)
	})
	t.Run("cbc iv", func(t *testing.T) {
		token, _ := Encrypt([]byte("secret"), cbcKey, EncryptOptions{Alg: AlgDir, Enc: EncA128CBCHS256})
		expectDecryptFailed(t, tamperJWESegment(t, token, 2), cbcKey)
	})
	t.Run("gcm ciphertext", func(t *testing.T) {
		token, _ := Encrypt([]byte("secret"), gcmKey, EncryptOptions{Alg: AlgDir, Enc: EncA256GCM})
		expectDecryptFailed(t, tamperJWESegment(t, token, 3), gcmKey)
	})
	t.Run("gcm tag", func(t *testing.T) {
		token, _ := Encrypt([]byte("secret"), gcmKey, EncryptOptions{Alg: AlgDir, Enc: EncA256GCM})
		expectDecryptFailed(t, tamperJWESegment(t, token, 4), gcmKey)
	})
	t.Run("aad", func(t *testing.T) {
		token, _ := Encrypt([]byte("secret"), gcmKey, EncryptOptions{Alg: AlgDir, Enc: EncA256GCM})
		parts := strings.Split(token, ".")
		parts[0] = EncodeSegment([]byte(`{"alg":"dir","enc":"A256GCM","kid":"attacker"}`))
		expectDecryptFailed(t, strings.Join(parts, "."), gcmKey)
	})
	t.Run("rsa encrypted key", func(t *testing.T) {
		token, err := Encrypt([]byte("secret"), rsaKey.Public(), EncryptOptions{Alg: AlgRSAOAEP256, Enc: EncA128GCM})
		if err != nil {
			t.Fatalf("Encrypt failed: %v", err)
		}
		expectDecryptFailed(t, tamperJWESegment(t, token, 1), rsaKey)
	})
	t.Run("ecdh wrapped key", func(t *testing.T) {
		ec := testECDHKey(t, 256)
		token, err := Encrypt([]byte("secret"), ec.Public(), EncryptOptions{Alg: AlgECDHESA128KW, Enc: EncA128GCM})
		if err != nil {
			t.Fatalf("Encrypt failed: %v", err)
		}
		expectDecryptFailed(t, tamperJWESegment(t, token, 1), ec)
	})
	t.Run("protected header", func(t *testing.T) {
		token, _ := Encrypt([]byte("secret"), gcmKey, EncryptOptions{Alg: AlgDir, Enc: EncA256GCM})
		parts := strings.Split(token, ".")
		parts[0] = tamperSegment(t, parts[0])
		if _, err := Decrypt(strings.Join(parts, "."), gcmKey, DecryptOptions{}); err == nil {
			t.Fatal("tampered protected header was accepted")
		}
	})
}

// expectDecryptFailed asserts that token fails with ErrDecryptionFailed. | expectDecryptFailed 断言
// token 以 ErrDecryptionFailed 失败。
func expectDecryptFailed(t *testing.T, token string, key *Key) {
	t.Helper()
	_, err := Decrypt(token, key, DecryptOptions{})
	if !errors.Is(err, ErrDecryptionFailed) {
		t.Fatalf("error = %v, want ErrDecryptionFailed", err)
	}
}

// tamperJWESegment flips the last byte of the numbered segment. | tamperJWESegment 翻转指定序号段的
// 最后一个字节。
func tamperJWESegment(t *testing.T, token string, index int) string {
	t.Helper()
	parts := strings.Split(token, ".")
	if len(parts) != 5 {
		t.Fatalf("token has %d segments, want 5", len(parts))
	}
	parts[index] = tamperSegment(t, parts[index])
	return strings.Join(parts, ".")
}

// mustHex decodes a hexadecimal test vector. | mustHex 解码十六进制测试向量。
func mustHex(t *testing.T, s string) []byte {
	t.Helper()
	out, err := hex.DecodeString(s)
	if err != nil {
		t.Fatalf("hex.DecodeString(%q) failed: %v", s, err)
	}
	return out
}

// TestDecodeOptionalB64RejectsNonZeroPadBits pins that apu and apv are validated as canonical
// base64url even when they are absent or empty. | TestDecodeOptionalB64RejectsNonZeroPadBits 固定
// 「apu 与 apv 即使可缺省也按规范 base64url 校验」。
func TestDecodeOptionalB64RejectsNonZeroPadBits(t *testing.T) {
	if got, err := decodeOptionalB64(""); err != nil || len(got) != 0 {
		t.Fatalf("decodeOptionalB64(empty) = %v, %v", got, err)
	}
	if _, err := decodeOptionalB64("AB"); err == nil {
		t.Fatal("decodeOptionalB64(AB) accepted non-zero trailing bits")
	}
}

// TestJWEEnforcesKeyUse pins that use=enc allows JWE key management while use=sig is refused for
// both encryption and decryption. | TestJWEEnforcesKeyUse 固定「use=enc 允许 JWE 密钥管理，
// 而 use=sig 在加密与解密两侧都会被拒绝」。
func TestJWEEnforcesKeyUse(t *testing.T) {
	key := testOctKey(t, 32)
	plaintext := []byte("jwe key use")
	token, err := Encrypt(plaintext, key, EncryptOptions{Alg: "dir", Enc: EncA256GCM})
	if err != nil {
		t.Fatalf("Encrypt with unbound key failed: %v", err)
	}
	if _, err := Decrypt(token, key, DecryptOptions{}); err != nil {
		t.Fatalf("Decrypt with unbound key failed: %v", err)
	}

	encKey := key.Public()
	encKey.Use = "enc"
	token, err = Encrypt(plaintext, encKey, EncryptOptions{Alg: "dir", Enc: EncA256GCM})
	if err != nil {
		t.Fatalf("Encrypt(use=enc) failed: %v", err)
	}
	if got, err := Decrypt(token, encKey, DecryptOptions{}); err != nil || !bytes.Equal(got, plaintext) {
		t.Fatalf("Decrypt(use=enc) = %q, %v", got, err)
	}

	sigKey := key.Public()
	sigKey.Use = "sig"
	if _, err := Encrypt(plaintext, sigKey, EncryptOptions{Alg: "dir", Enc: EncA256GCM}); !errors.Is(err, ErrInvalidKey) {
		t.Errorf("Encrypt(use=sig) err = %v, want ErrInvalidKey", err)
	}
	if _, err := Decrypt(token, sigKey, DecryptOptions{}); !errors.Is(err, ErrInvalidKey) {
		t.Errorf("Decrypt(use=sig) err = %v, want ErrInvalidKey", err)
	}

	decOps := key.Public()
	decOps.KeyOps = []string{"decrypt"}
	if got, err := Decrypt(token, decOps, DecryptOptions{}); err != nil || !bytes.Equal(got, plaintext) {
		t.Fatalf("Decrypt(key_ops=[decrypt]) = %q, %v", got, err)
	}
	signOps := key.Public()
	signOps.KeyOps = []string{"sign"}
	if _, err := Decrypt(token, signOps, DecryptOptions{}); !errors.Is(err, ErrInvalidKey) {
		t.Errorf("Decrypt(key_ops=[sign]) err = %v, want ErrInvalidKey", err)
	}
}

// TestDecryptTokenSizeLimit covers the pre-decode input bound: the exact limit passes, one byte over
// fails with ErrTokenTooLarge, and a zero option selects DefaultMaxTokenSize. |
// TestDecryptTokenSizeLimit 覆盖解码前的输入上限：恰好等于上限通过，超出 1 字节返回
// ErrTokenTooLarge，选项为零时使用 DefaultMaxTokenSize。
func TestDecryptTokenSizeLimit(t *testing.T) {
	key := testOctKey(t, 32)
	token, err := Encrypt([]byte("payload"), key, EncryptOptions{Alg: "dir", Enc: EncA256GCM})
	if err != nil {
		t.Fatalf("Encrypt failed: %v", err)
	}
	if got, err := Decrypt(token, key, DecryptOptions{MaxTokenSize: len(token)}); err != nil || string(got) != "payload" {
		t.Fatalf("Decrypt at exact limit = %q, %v", got, err)
	}
	if _, err := Decrypt(token, key, DecryptOptions{MaxTokenSize: len(token) - 1}); !errors.Is(err, ErrTokenTooLarge) {
		t.Fatalf("Decrypt one byte over limit err = %v, want ErrTokenTooLarge", err)
	}
	if _, err := Decrypt(token, key, DecryptOptions{}); err != nil {
		t.Fatalf("Decrypt under default limit failed: %v", err)
	}
	huge := strings.Repeat("A", DefaultMaxTokenSize+1)
	if _, err := Decrypt(huge, key, DecryptOptions{}); !errors.Is(err, ErrTokenTooLarge) {
		t.Fatalf("Decrypt over default limit err = %v, want ErrTokenTooLarge", err)
	}
}
