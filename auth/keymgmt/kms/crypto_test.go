package kms

import (
	"bytes"
	"context"
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"testing"

	"github.com/shibingli/ydx/json"
)

func TestServiceEncryptDecryptAlgorithms(t *testing.T) {
	ctx := context.Background()
	service, _ := newServiceForTest(t, Config{})
	cases := []struct {
		name string
		typ  KeyType
		bits int
	}{
		{"AES-128", KeyTypeAES, 128},
		{"AES-192", KeyTypeAES, 192},
		{"AES-256", KeyTypeAES, 0},
		{"ChaCha20", KeyTypeChaCha20, 0},
		{"SM4", KeyTypeSM4, 0},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			key := createKeyForTest(t, service, CreateKeyRequest{Type: tc.typ, Bits: tc.bits}, true)
			plaintext := []byte("secret payload for " + tc.name)
			aad := []byte("tenant=acme")
			ciphertext, err := service.Encrypt(ctx, key.ID, plaintext, aad)
			if err != nil {
				t.Fatalf("Encrypt: %v", err)
			}
			if !bytes.HasPrefix(ciphertext, cipherMagic) {
				t.Fatalf("ciphertext magic = %q", ciphertext[:4])
			}
			parsed, err := parseCipherEnvelope(cipherMagic, ciphertext)
			if err != nil {
				t.Fatalf("parseCipherEnvelope: %v", err)
			}
			if parsed.keyID != key.ID || parsed.version != 1 || len(parsed.nonce) != gcmNonceSize {
				t.Fatalf("parsed header = %+v", parsed)
			}
			decrypted, err := service.Decrypt(ctx, key.ID, ciphertext, aad)
			if err != nil || !bytes.Equal(decrypted, plaintext) {
				t.Fatalf("Decrypt = %q, %v", decrypted, err)
			}
			if _, err := service.Decrypt(ctx, key.ID, ciphertext, []byte("tenant=other")); !errors.Is(err, ErrAuthentication) {
				t.Fatalf("wrong AAD err = %v, want ErrAuthentication", err)
			}
			tampered := append([]byte(nil), ciphertext...)
			tampered[len(tampered)-1] ^= 0xff
			if _, err := service.Decrypt(ctx, key.ID, tampered, aad); !errors.Is(err, ErrAuthentication) {
				t.Fatalf("tampered ciphertext err = %v, want ErrAuthentication", err)
			}
			if _, err := service.Decrypt(ctx, key.ID, ciphertext[:10], aad); !errors.Is(err, ErrInvalidCiphertext) {
				t.Fatalf("truncated ciphertext err = %v, want ErrInvalidCiphertext", err)
			}
			other := createKeyForTest(t, service, CreateKeyRequest{Type: tc.typ, Bits: tc.bits}, true)
			if _, err := service.Decrypt(ctx, other.ID, ciphertext, aad); !errors.Is(err, ErrInvalidCiphertext) {
				t.Fatalf("wrong key err = %v, want ErrInvalidCiphertext", err)
			}
			first, err := service.Encrypt(ctx, key.ID, plaintext, aad)
			if err != nil {
				t.Fatalf("second Encrypt: %v", err)
			}
			if bytes.Equal(first, ciphertext) {
				t.Fatal("two encryptions produced identical ciphertexts")
			}
			empty, err := service.Encrypt(ctx, key.ID, nil, nil)
			if err != nil {
				t.Fatalf("Encrypt empty: %v", err)
			}
			if out, err := service.Decrypt(ctx, key.ID, empty, nil); err != nil || len(out) != 0 {
				t.Fatalf("Decrypt empty = %q, %v", out, err)
			}
		})
	}
}

func TestServiceEncryptRejectsAsymmetricKeys(t *testing.T) {
	ctx := context.Background()
	service, _ := newServiceForTest(t, Config{})
	key := createKeyForTest(t, service, CreateKeyRequest{Type: KeyTypeRSA, Bits: 2048}, true)
	if _, err := service.Encrypt(ctx, key.ID, []byte("data"), nil); !errors.Is(err, ErrUsageNotAllowed) {
		t.Fatalf("Encrypt with RSA err = %v, want ErrUsageNotAllowed", err)
	}
}

func TestServiceSignVerifyAlgorithms(t *testing.T) {
	ctx := context.Background()
	service, _ := newServiceForTest(t, Config{})
	cases := []struct {
		name string
		typ  KeyType
		bits int
		opts []SignOption
	}{
		{"RSA-PKCS1v15", KeyTypeRSA, 2048, nil},
		{"RSA-PSS", KeyTypeRSA, 2048, []SignOption{WithPSS()}},
		{"ECDSA-P256", KeyTypeECDSA, 256, nil},
		{"ECDSA-P384", KeyTypeECDSA, 384, nil},
		{"Ed25519", KeyTypeEd25519, 0, nil},
		{"SM2", KeyTypeSM2, 0, nil},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			key := createKeyForTest(t, service, CreateKeyRequest{Type: tc.typ, Bits: tc.bits}, true)
			message := []byte("message signed with " + tc.name)
			signature, err := service.Sign(ctx, key.ID, message, tc.opts...)
			if err != nil {
				t.Fatalf("Sign: %v", err)
			}
			if len(signature) == 0 {
				t.Fatal("empty signature")
			}
			valid, err := service.Verify(ctx, key.ID, message, signature, tc.opts...)
			if err != nil || !valid {
				t.Fatalf("Verify = %v, %v", valid, err)
			}
			valid, err = service.Verify(ctx, key.ID, []byte("tampered message"), signature, tc.opts...)
			if err != nil || valid {
				t.Fatalf("Verify tampered message = %v, %v", valid, err)
			}
			tamperedSignature := append([]byte(nil), signature...)
			tamperedSignature[len(tamperedSignature)-1] ^= 0xff
			valid, err = service.Verify(ctx, key.ID, message, tamperedSignature, tc.opts...)
			if err != nil && !errors.Is(err, ErrNotSupported) {
				t.Fatalf("Verify tampered signature error: %v", err)
			}
			if valid {
				t.Fatal("tampered signature verified")
			}
		})
	}
}

func TestServiceSignUsageAndDigestOptions(t *testing.T) {
	ctx := context.Background()
	service, _ := newServiceForTest(t, Config{})
	aesKey := createKeyForTest(t, service, CreateKeyRequest{Type: KeyTypeAES}, true)
	if _, err := service.Sign(ctx, aesKey.ID, []byte("data")); !errors.Is(err, ErrUsageNotAllowed) {
		t.Fatalf("Sign with AES err = %v, want ErrUsageNotAllowed", err)
	}
	rsaKey := createKeyForTest(t, service, CreateKeyRequest{Type: KeyTypeRSA, Bits: 2048}, false)
	if _, err := service.Sign(ctx, rsaKey.ID, []byte("data")); !errors.Is(err, ErrKeyNotUsable) {
		t.Fatalf("Sign pre-active err = %v, want ErrKeyNotUsable", err)
	}
	ecdsaKey := createKeyForTest(t, service, CreateKeyRequest{Type: KeyTypeECDSA, Bits: 256}, true)
	message := []byte("digest signed message")
	digest := sha256.Sum256(message)
	signature, err := service.Sign(ctx, ecdsaKey.ID, digest[:], WithDigest())
	if err != nil {
		t.Fatalf("Sign digest: %v", err)
	}
	valid, err := service.Verify(ctx, ecdsaKey.ID, digest[:], signature, WithDigest())
	if err != nil || !valid {
		t.Fatalf("Verify digest = %v, %v", valid, err)
	}
	if _, err := service.Sign(ctx, ecdsaKey.ID, digest[:], WithDigest(), WithHash(crypto.SHA384)); err != nil {
		t.Fatalf("Sign SHA-384 digest: %v", err)
	}
	if _, err := service.Sign(ctx, ecdsaKey.ID, []byte("data"), WithHash(0)); err != nil {
		t.Fatalf("default hash option: %v", err)
	}
	edKey := createKeyForTest(t, service, CreateKeyRequest{Type: KeyTypeEd25519}, true)
	if _, err := service.Sign(ctx, edKey.ID, []byte("data"), WithDigest()); !errors.Is(err, ErrNotSupported) {
		t.Fatalf("Ed25519 digest err = %v, want ErrNotSupported", err)
	}
	smKey := createKeyForTest(t, service, CreateKeyRequest{Type: KeyTypeSM2}, true)
	if _, err := service.Sign(ctx, smKey.ID, []byte("data"), WithDigest()); !errors.Is(err, ErrNotSupported) {
		t.Fatalf("SM2 digest err = %v, want ErrNotSupported", err)
	}
}

func TestServiceWrapGenerateDataKeyAndDerive(t *testing.T) {
	ctx := context.Background()
	service, _ := newServiceForTest(t, Config{MaxDataKeyLength: 64})
	key := createKeyForTest(t, service, CreateKeyRequest{Type: KeyTypeAES, Bits: 256}, true)
	material := []byte("material to wrap")
	aad := []byte("wrap context")
	wrapped, err := service.WrapKey(ctx, key.ID, material, aad)
	if err != nil {
		t.Fatalf("WrapKey: %v", err)
	}
	if !bytes.HasPrefix(wrapped, wrappedMagic) {
		t.Fatalf("wrapped magic = %q", wrapped[:4])
	}
	unwrapped, err := service.UnwrapKey(ctx, key.ID, wrapped, aad)
	if err != nil || !bytes.Equal(unwrapped, material) {
		t.Fatalf("UnwrapKey = %q, %v", unwrapped, err)
	}
	if _, err := service.UnwrapKey(ctx, key.ID, wrapped, []byte("wrong")); !errors.Is(err, ErrAuthentication) {
		t.Fatalf("UnwrapKey wrong AAD err = %v, want ErrAuthentication", err)
	}
	if _, err := service.WrapKey(ctx, key.ID, nil, nil); !errors.Is(err, ErrInvalidRequest) {
		t.Fatalf("WrapKey empty err = %v, want ErrInvalidRequest", err)
	}

	dataKey, err := service.GenerateDataKey(ctx, key.ID, 0, aad)
	if err != nil {
		t.Fatalf("GenerateDataKey: %v", err)
	}
	if len(dataKey.Plaintext) != 32 || dataKey.KeyID != key.ID || dataKey.KeyVersion != 1 || !bytes.HasPrefix(dataKey.Wrapped, wrappedMagic) {
		t.Fatalf("data key = %+v", dataKey)
	}
	recovered, err := service.UnwrapKey(ctx, key.ID, dataKey.Wrapped, aad)
	if err != nil || !bytes.Equal(recovered, dataKey.Plaintext) {
		t.Fatalf("UnwrapKey(data key) = %q, %v", recovered, err)
	}
	if _, err := service.GenerateDataKey(ctx, key.ID, 65, nil); !errors.Is(err, ErrInvalidRequest) {
		t.Fatalf("oversize GenerateDataKey err = %v, want ErrInvalidRequest", err)
	}

	salt := []byte("hkdf salt")
	first, err := service.DeriveKey(ctx, key.ID, 32, "encryption", salt)
	if err != nil {
		t.Fatalf("DeriveKey: %v", err)
	}
	second, err := service.DeriveKey(ctx, key.ID, 32, "encryption", salt)
	if err != nil || !bytes.Equal(first, second) {
		t.Fatalf("DeriveKey not deterministic: %q, %q, %v", first, second, err)
	}
	other, err := service.DeriveKey(ctx, key.ID, 32, "authentication", salt)
	if err != nil {
		t.Fatalf("DeriveKey other info: %v", err)
	}
	if bytes.Equal(first, other) {
		t.Fatal("different HKDF info produced the same key")
	}
	if _, err := service.DeriveKey(ctx, key.ID, 65, "too long", nil); !errors.Is(err, ErrInvalidRequest) {
		t.Fatalf("oversize DeriveKey err = %v, want ErrInvalidRequest", err)
	}
	rsaKey := createKeyForTest(t, service, CreateKeyRequest{Type: KeyTypeRSA, Bits: 2048}, true)
	if _, err := service.DeriveKey(ctx, rsaKey.ID, 32, "x", nil); !errors.Is(err, ErrUsageNotAllowed) {
		t.Fatalf("DeriveKey with RSA err = %v, want ErrUsageNotAllowed", err)
	}

	rotated, err := service.Rotate(ctx, key.ID)
	if err != nil || rotated.Version != 2 {
		t.Fatalf("Rotate = %+v, %v", rotated, err)
	}
	if legacy, err := service.UnwrapKey(ctx, key.ID, wrapped, aad); err != nil || !bytes.Equal(legacy, material) {
		t.Fatalf("UnwrapKey legacy version = %q, %v", legacy, err)
	}
	fresh, err := service.WrapKey(ctx, key.ID, material, aad)
	if err != nil {
		t.Fatalf("WrapKey after rotation: %v", err)
	}
	parsed, err := parseCipherEnvelope(wrappedMagic, fresh)
	if err != nil || parsed.version != 2 {
		t.Fatalf("fresh wrapped version = %+v, %v", parsed, err)
	}
}

func TestEnvelopeEncryption(t *testing.T) {
	ctx := context.Background()
	service, _ := newServiceForTest(t, Config{})
	key := createKeyForTest(t, service, CreateKeyRequest{Type: KeyTypeAES, Bits: 256}, true)
	plaintext := []byte("bulk payload encrypted with a data key")
	aad := []byte("object=42")
	envelope, err := service.EncryptEnvelope(ctx, key.ID, plaintext, aad)
	if err != nil {
		t.Fatalf("EncryptEnvelope: %v", err)
	}
	if envelope.KeyID != key.ID || envelope.KeyVersion != 1 || len(envelope.Nonce) != gcmNonceSize || !bytes.HasPrefix(envelope.WrappedKey, wrappedMagic) || len(envelope.Ciphertext) < 16 {
		t.Fatalf("envelope = %+v", envelope)
	}
	blob, err := envelope.MarshalBinary()
	if err != nil {
		t.Fatalf("MarshalBinary: %v", err)
	}
	if !bytes.HasPrefix(blob, envelopeMagic) {
		t.Fatalf("envelope magic = %q", blob[:4])
	}
	parsed, err := ParseEnvelope(blob)
	if err != nil {
		t.Fatalf("ParseEnvelope: %v", err)
	}
	if parsed.KeyID != envelope.KeyID || parsed.KeyVersion != envelope.KeyVersion || !bytes.Equal(parsed.WrappedKey, envelope.WrappedKey) || !bytes.Equal(parsed.Nonce, envelope.Nonce) || !bytes.Equal(parsed.Ciphertext, envelope.Ciphertext) {
		t.Fatalf("parsed envelope = %+v", parsed)
	}
	decrypted, err := service.DecryptEnvelope(ctx, parsed, aad)
	if err != nil || !bytes.Equal(decrypted, plaintext) {
		t.Fatalf("DecryptEnvelope = %q, %v", decrypted, err)
	}
	if _, err := service.DecryptEnvelope(ctx, parsed, []byte("object=43")); !errors.Is(err, ErrAuthentication) {
		t.Fatalf("wrong envelope AAD err = %v, want ErrAuthentication", err)
	}
	tampered := parsed.Clone()
	tampered.Ciphertext[len(tampered.Ciphertext)-1] ^= 0xff
	if _, err := service.DecryptEnvelope(ctx, tampered, aad); !errors.Is(err, ErrAuthentication) {
		t.Fatalf("tampered envelope err = %v, want ErrAuthentication", err)
	}
	if _, err := ParseEnvelope(blob[:12]); !errors.Is(err, ErrInvalidCiphertext) {
		t.Fatalf("ParseEnvelope truncated err = %v, want ErrInvalidCiphertext", err)
	}
	if _, err := (&Envelope{}).MarshalBinary(); !errors.Is(err, ErrInvalidRequest) {
		t.Fatalf("MarshalBinary invalid err = %v, want ErrInvalidRequest", err)
	}
	if _, err := service.DecryptEnvelope(ctx, nil, nil); !errors.Is(err, ErrInvalidRequest) {
		t.Fatalf("DecryptEnvelope nil err = %v, want ErrInvalidRequest", err)
	}

	rotated, err := service.Rotate(ctx, key.ID)
	if err != nil || rotated.Version != 2 {
		t.Fatalf("Rotate = %+v, %v", rotated, err)
	}
	legacy, err := service.DecryptEnvelope(ctx, parsed, aad)
	if err != nil || !bytes.Equal(legacy, plaintext) {
		t.Fatalf("DecryptEnvelope legacy = %q, %v", legacy, err)
	}
	newEnvelope, err := service.EncryptEnvelope(ctx, key.ID, plaintext, aad)
	if err != nil || newEnvelope.KeyVersion != 2 {
		t.Fatalf("EncryptEnvelope after rotation = %+v, %v", newEnvelope, err)
	}
}

func TestServiceExportPolicyAndFormats(t *testing.T) {
	ctx := context.Background()
	service, _ := newServiceForTest(t, Config{})
	symmetric := createKeyForTest(t, service, CreateKeyRequest{Type: KeyTypeAES, Bits: 256, Exportable: true}, true)
	if _, err := service.ExportKey(ctx, symmetric.ID, ExportRequest{Format: ExportFormatRaw, Private: true}); !errors.Is(err, ErrExportDenied) {
		t.Fatalf("default policy private export err = %v, want ErrExportDenied", err)
	}
	if _, err := service.ExportKey(ctx, symmetric.ID, ExportRequest{Format: ExportFormatRaw}); !errors.Is(err, ErrExportDenied) {
		t.Fatalf("symmetric public export err = %v, want ErrExportDenied", err)
	}
	asymmetric := createKeyForTest(t, service, CreateKeyRequest{Type: KeyTypeRSA, Bits: 2048}, true)
	exported, err := service.ExportKey(ctx, asymmetric.ID, ExportRequest{Format: ExportFormatPEM})
	if err != nil {
		t.Fatalf("public PEM export: %v", err)
	}
	if exported.Private || exported.Version != 1 || !bytes.Contains(exported.PublicMaterial, []byte("BEGIN PUBLIC KEY")) {
		t.Fatalf("public PEM export = %+v", exported)
	}
	block, _ := pem.Decode(exported.PublicMaterial)
	if block == nil {
		t.Fatal("public PEM did not decode")
	}
	if _, err := x509.ParsePKIXPublicKey(block.Bytes); err != nil {
		t.Fatalf("parse exported public key: %v", err)
	}
	jwk, err := service.ExportKey(ctx, asymmetric.ID, ExportRequest{Format: ExportFormatJWK})
	if err != nil {
		t.Fatalf("public JWK export: %v", err)
	}
	var fields map[string]any
	if err := json.Unmarshal(jwk.PublicMaterial, &fields); err != nil {
		t.Fatalf("JWK JSON: %v", err)
	}
	if fields["kty"] != "RSA" {
		t.Fatalf("JWK kty = %v", fields["kty"])
	}
	sm2Key := createKeyForTest(t, service, CreateKeyRequest{Type: KeyTypeSM2}, true)
	if _, err := service.ExportKey(ctx, sm2Key.ID, ExportRequest{Format: ExportFormatJWK}); !errors.Is(err, ErrNotSupported) {
		t.Fatalf("SM2 JWK export err = %v, want ErrNotSupported", err)
	}
	if exported, err := service.ExportKey(ctx, sm2Key.ID, ExportRequest{Format: ExportFormatPEM}); err != nil || !bytes.Contains(exported.PublicMaterial, []byte("BEGIN PUBLIC KEY")) {
		t.Fatalf("SM2 PEM export = %+v, %v", exported, err)
	}

	open, _ := newServiceForTest(t, Config{ExportPolicy: ExportPolicy{AllowPrivate: true}})
	exportable := createKeyForTest(t, open, CreateKeyRequest{Type: KeyTypeAES, Bits: 256, Exportable: true}, true)
	private, err := open.ExportKey(ctx, exportable.ID, ExportRequest{Format: ExportFormatRaw, Private: true})
	if err != nil {
		t.Fatalf("private export with policy: %v", err)
	}
	if !private.Private || len(private.Material) != 32 {
		t.Fatalf("private export = %+v", private)
	}
	locked := createKeyForTest(t, open, CreateKeyRequest{Type: KeyTypeAES, Bits: 256}, true)
	if _, err := open.ExportKey(ctx, locked.ID, ExportRequest{Format: ExportFormatRaw, Private: true}); !errors.Is(err, ErrExportDenied) {
		t.Fatalf("non-exportable private export err = %v, want ErrExportDenied", err)
	}
	if _, err := open.ExportKey(ctx, exportable.ID, ExportRequest{Format: ExportFormatPEM, Private: true}); !errors.Is(err, ErrNotSupported) {
		t.Fatalf("symmetric PEM private export err = %v, want ErrNotSupported", err)
	}
}

func TestServiceImportKey(t *testing.T) {
	ctx := context.Background()
	service, _ := newServiceForTest(t, Config{ExportPolicy: ExportPolicy{AllowPrivate: true}})
	privateKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("generate ECDSA: %v", err)
	}
	privateDER, err := x509.MarshalPKCS8PrivateKey(privateKey)
	if err != nil {
		t.Fatalf("marshal private: %v", err)
	}
	publicDER, err := x509.MarshalPKIXPublicKey(&privateKey.PublicKey)
	if err != nil {
		t.Fatalf("marshal public: %v", err)
	}
	imported, err := service.ImportKey(ctx, ImportKeyRequest{
		CreateKeyRequest: CreateKeyRequest{Type: KeyTypeECDSA, Alias: "imported-signer", Bits: 256},
		Material:         privateDER,
	})
	if err != nil {
		t.Fatalf("ImportKey: %v", err)
	}
	if imported.State != StatePreActive || imported.Version != 1 || imported.Material != nil || len(imported.PublicMaterial) == 0 {
		t.Fatalf("imported key = %+v", imported)
	}
	if _, err := service.Sign(ctx, imported.ID, []byte("data")); !errors.Is(err, ErrKeyNotUsable) {
		t.Fatalf("Sign imported pre-active err = %v, want ErrKeyNotUsable", err)
	}
	if _, err := service.Activate(ctx, imported.ID); err != nil {
		t.Fatalf("Activate imported: %v", err)
	}
	message := []byte("imported key signature")
	signature, err := service.Sign(ctx, imported.ID, message)
	if err != nil {
		t.Fatalf("Sign imported: %v", err)
	}
	valid, err := service.Verify(ctx, imported.ID, message, signature)
	if err != nil || !valid {
		t.Fatalf("Verify imported = %v, %v", valid, err)
	}

	publicOnly, err := service.ImportKey(ctx, ImportKeyRequest{
		CreateKeyRequest: CreateKeyRequest{Type: KeyTypeECDSA, Alias: "public-verifier"},
		PublicMaterial:   publicDER,
	})
	if err != nil {
		t.Fatalf("ImportKey public-only: %v", err)
	}
	if publicOnly.UsageMask != MaskVerify {
		t.Fatalf("public-only usage = %d, want MaskVerify", publicOnly.UsageMask)
	}
	if _, err := service.Activate(ctx, publicOnly.ID); err != nil {
		t.Fatalf("Activate public-only: %v", err)
	}
	valid, err = service.Verify(ctx, publicOnly.ID, message, signature)
	if err != nil || !valid {
		t.Fatalf("Verify public-only = %v, %v", valid, err)
	}

	raw := bytes.Repeat([]byte{0x42}, 32)
	symmetric, err := service.ImportKey(ctx, ImportKeyRequest{
		CreateKeyRequest: CreateKeyRequest{Type: KeyTypeAES, Bits: 256, Exportable: true},
		Material:         raw,
	})
	if err != nil {
		t.Fatalf("ImportKey symmetric: %v", err)
	}
	if _, err := service.Activate(ctx, symmetric.ID); err != nil {
		t.Fatalf("Activate symmetric: %v", err)
	}
	ciphertext, err := service.Encrypt(ctx, symmetric.ID, []byte("import"), nil)
	if err != nil {
		t.Fatalf("Encrypt imported symmetric: %v", err)
	}
	if plain, err := service.Decrypt(ctx, symmetric.ID, ciphertext, nil); err != nil || string(plain) != "import" {
		t.Fatalf("Decrypt imported symmetric = %q, %v", plain, err)
	}
	exported, err := service.ExportKey(ctx, symmetric.ID, ExportRequest{Format: ExportFormatRaw, Private: true})
	if err != nil || !bytes.Equal(exported.Material, raw) {
		t.Fatalf("export imported symmetric = %+v, %v", exported, err)
	}

	if _, err := service.ImportKey(ctx, ImportKeyRequest{
		CreateKeyRequest: CreateKeyRequest{Type: KeyTypeAES, Bits: 256},
		Material:         []byte{1, 2, 3},
	}); !errors.Is(err, ErrInvalidMaterial) {
		t.Fatalf("bad symmetric import err = %v, want ErrInvalidMaterial", err)
	}
	if _, err := service.ImportKey(ctx, ImportKeyRequest{
		CreateKeyRequest: CreateKeyRequest{Type: KeyTypeEd25519, RotationInterval: -1},
		PublicMaterial:   publicDER,
	}); !errors.Is(err, ErrInvalidMaterial) {
		t.Fatalf("mismatched public import err = %v, want ErrInvalidMaterial", err)
	}
}

func TestServiceImportPublicOnlyRejectsPrivateUsage(t *testing.T) {
	ctx := context.Background()
	service, _ := newServiceForTest(t, Config{})
	privateKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("generate ECDSA: %v", err)
	}
	publicDER, err := x509.MarshalPKIXPublicKey(&privateKey.PublicKey)
	if err != nil {
		t.Fatalf("marshal public: %v", err)
	}
	_, err = service.ImportKey(ctx, ImportKeyRequest{
		CreateKeyRequest: CreateKeyRequest{Type: KeyTypeECDSA, Usage: []KeyUsage{UsageSign}},
		PublicMaterial:   publicDER,
	})
	if !errors.Is(err, ErrUsageNotAllowed) {
		t.Fatalf("public-only sign usage err = %v, want ErrUsageNotAllowed", err)
	}
	if _, err := service.ImportKey(ctx, ImportKeyRequest{
		CreateKeyRequest: CreateKeyRequest{Type: KeyTypeAES},
	}); !errors.Is(err, ErrInvalidMaterial) {
		t.Fatalf("empty symmetric import err = %v, want ErrInvalidMaterial", err)
	}
}

func TestValidateMaterialRejectsMismatchedPublicKey(t *testing.T) {
	privateKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("generate ECDSA P-256: %v", err)
	}
	privDER, err := x509.MarshalPKCS8PrivateKey(privateKey)
	if err != nil {
		t.Fatalf("marshal private: %v", err)
	}
	otherCurveKey, err := ecdsa.GenerateKey(elliptic.P384(), rand.Reader)
	if err != nil {
		t.Fatalf("generate ECDSA P-384: %v", err)
	}
	otherCurveDER, err := x509.MarshalPKIXPublicKey(&otherCurveKey.PublicKey)
	if err != nil {
		t.Fatalf("marshal P-384 public: %v", err)
	}
	if _, _, _, err := ValidateMaterial(KeyTypeECDSA, 0, privDER, otherCurveDER); !errors.Is(err, ErrInvalidMaterial) {
		t.Fatalf("P-256 private with P-384 public err = %v, want ErrInvalidMaterial", err)
	}

	otherKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("generate second ECDSA P-256: %v", err)
	}
	otherDER, err := x509.MarshalPKIXPublicKey(&otherKey.PublicKey)
	if err != nil {
		t.Fatalf("marshal second public: %v", err)
	}
	if _, _, _, err := ValidateMaterial(KeyTypeECDSA, 0, privDER, otherDER); !errors.Is(err, ErrInvalidMaterial) {
		t.Fatalf("P-256 private with unrelated P-256 public err = %v, want ErrInvalidMaterial", err)
	}

	publicKey := privateKey.PublicKey
	matchingDER, err := x509.MarshalPKIXPublicKey(&publicKey)
	if err != nil {
		t.Fatalf("marshal matching public: %v", err)
	}
	_, returnedPublic, bits, err := ValidateMaterial(KeyTypeECDSA, 0, privDER, matchingDER)
	if err != nil {
		t.Fatalf("matching private and public err = %v", err)
	}
	if bits != 256 {
		t.Fatalf("bits = %d, want 256", bits)
	}
	if !bytes.Equal(returnedPublic, matchingDER) {
		t.Fatalf("returned public material changed")
	}

	if _, _, _, err := ValidateMaterial(KeyTypeECDSA, 0, privDER, nil); err != nil {
		t.Fatalf("derive public from private err = %v", err)
	}
}
