package kms

import (
	"bytes"
	"context"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/sha256"
	"encoding/binary"
	"errors"
	"testing"

	"golang.org/x/crypto/pbkdf2"
)

// legacyBlobForTest builds material in the first KMSM1 at-rest format. | legacyBlobForTest 构建首个
// KMSM1 静态格式的材料。
func legacyBlobForTest(t *testing.T, keyBytes []byte, keyID string, version uint32, material []byte) []byte {
	t.Helper()
	block, err := aes.NewCipher(keyBytes)
	if err != nil {
		t.Fatalf("legacy aes.NewCipher: %v", err)
	}
	aead, err := cipher.NewGCM(block)
	if err != nil {
		t.Fatalf("legacy cipher.NewGCM: %v", err)
	}
	nonce := make([]byte, aead.NonceSize())
	if _, err := rand.Read(nonce); err != nil {
		t.Fatalf("legacy nonce: %v", err)
	}
	out := append([]byte(nil), legacyAtRestMagic...)
	out = append(out, nonce...)
	return aead.Seal(out, nonce, material, atRestAAD(keyID, version))
}

// TestAtRestVersionedFormatRandomSalt verifies that passphrase wrappers store random salts and
// explicit KDF parameters. | TestAtRestVersionedFormatRandomSalt 校验口令包装器保存随机盐与显式
// KDF 参数。
func TestAtRestVersionedFormatRandomSalt(t *testing.T) {
	ctx := context.Background()
	wrapper, err := newAtRestWrapper(nil, "random salt passphrase")
	if err != nil {
		t.Fatalf("newAtRestWrapper: %v", err)
	}
	raw, ok := wrapper.(*atRestWrapper)
	if !ok {
		t.Fatal("unexpected wrapper type")
	}
	first, err := raw.Wrap(ctx, "key-1", 3, []byte("material"))
	if err != nil {
		t.Fatalf("Wrap first: %v", err)
	}
	second, err := raw.Wrap(ctx, "key-1", 3, []byte("material"))
	if err != nil {
		t.Fatalf("Wrap second: %v", err)
	}
	if bytes.Equal(first, second) {
		t.Fatal("passphrase wraps reused salt or nonce")
	}
	firstParams, err := parseAtRestHeader(first)
	if err != nil {
		t.Fatalf("parse first: %v", err)
	}
	secondParams, err := parseAtRestHeader(second)
	if err != nil {
		t.Fatalf("parse second: %v", err)
	}
	if firstParams.kdf != atRestKDFPBKDF2 || firstParams.iterations != pbkdf2Iterations || firstParams.keyLen != 32 {
		t.Fatalf("unexpected KDF parameters: %+v", firstParams)
	}
	if len(firstParams.salt) != atRestSaltSize || bytes.Equal(firstParams.salt, secondParams.salt) {
		t.Fatalf("salts = %x / %x, want distinct %d-byte salts", firstParams.salt, secondParams.salt, atRestSaltSize)
	}
	for name, blob := range map[string][]byte{"first": first, "second": second} {
		plain, err := raw.Unwrap(ctx, "key-1", 3, blob)
		if err != nil || string(plain) != "material" {
			t.Fatalf("Unwrap %s = %q, %v", name, plain, err)
		}
	}

	rootWrapper, err := newAtRestWrapper(&Key{Type: KeyTypeAES, Material: []byte("0123456789abcdef")}, "")
	if err != nil {
		t.Fatalf("newAtRestWrapper root: %v", err)
	}
	rootBlob, err := rootWrapper.Wrap(ctx, "key-2", 1, []byte("material"))
	if err != nil {
		t.Fatalf("root Wrap: %v", err)
	}
	rootParams, err := parseAtRestHeader(rootBlob)
	if err != nil {
		t.Fatalf("parse root: %v", err)
	}
	if rootParams.kdf != atRestKDFDirect || rootParams.iterations != 0 || len(rootParams.salt) != 0 || rootParams.keyLen != 16 {
		t.Fatalf("unexpected direct KDF parameters: %+v", rootParams)
	}
}

// TestAtRestLegacyCompatibility verifies that KMSM1 material still decrypts for root-key and
// passphrase wrappers and through Service storage. | TestAtRestLegacyCompatibility 校验根密钥与口令
// 包装器以及 Service 存储仍可解密 KMSM1 材料。
func TestAtRestLegacyCompatibility(t *testing.T) {
	ctx := context.Background()
	rootBytes := []byte("0123456789abcdef")
	rootWrapper, err := newAtRestWrapper(&Key{Type: KeyTypeAES, Material: rootBytes}, "")
	if err != nil {
		t.Fatalf("root wrapper: %v", err)
	}
	legacy := legacyBlobForTest(t, rootBytes, "legacy-key", 2, []byte("legacy secret"))
	plain, err := rootWrapper.Unwrap(ctx, "legacy-key", 2, legacy)
	if err != nil || string(plain) != "legacy secret" {
		t.Fatalf("legacy root Unwrap = %q, %v", plain, err)
	}
	if _, err := rootWrapper.Unwrap(ctx, "legacy-key", 3, legacy); !errors.Is(err, ErrInvalidMaterial) {
		t.Fatalf("legacy wrong version err = %v", err)
	}

	passphrase := "legacy passphrase"
	passWrapper, err := newAtRestWrapper(nil, passphrase)
	if err != nil {
		t.Fatalf("passphrase wrapper: %v", err)
	}
	legacyKey := pbkdf2.Key([]byte(passphrase), []byte(legacyAtRestSalt), pbkdf2Iterations, 32, sha256.New)
	legacyPass := legacyBlobForTest(t, legacyKey, "legacy-pass", 1, []byte("old material"))
	plain, err = passWrapper.Unwrap(ctx, "legacy-pass", 1, legacyPass)
	if err != nil || string(plain) != "old material" {
		t.Fatalf("legacy passphrase Unwrap = %q, %v", plain, err)
	}

	store := NewMemoryStore()
	service, err := New(Config{Store: store, RootKey: &Key{Type: KeyTypeAES, Material: rootBytes}, Clock: newTestClock().Now, ExportPolicy: ExportPolicy{AllowPrivate: true}})
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	key := createKeyForTest(t, service, CreateKeyRequest{Type: KeyTypeAES, Bits: 256, Exportable: true}, true)
	loaded, err := service.loadKey(ctx, mustStoredKey(t, store, key.ID))
	if err != nil {
		t.Fatalf("loadKey: %v", err)
	}
	raw, err := store.GetKey(ctx, key.ID)
	if err != nil {
		t.Fatalf("GetKey: %v", err)
	}
	raw.Material = legacyBlobForTest(t, rootBytes, raw.ID, raw.Version, loaded.Material)
	for _, version := range raw.Versions {
		version.Material = legacyBlobForTest(t, rootBytes, raw.ID, version.Version, loaded.Material)
	}
	if err := store.UpdateKey(ctx, raw); err != nil {
		t.Fatalf("UpdateKey legacy: %v", err)
	}
	ciphertext, err := service.Encrypt(ctx, key.ID, []byte("legacy roundtrip"), nil)
	if err != nil {
		t.Fatalf("Encrypt legacy: %v", err)
	}
	decrypted, err := service.Decrypt(ctx, key.ID, ciphertext, nil)
	if err != nil || string(decrypted) != "legacy roundtrip" {
		t.Fatalf("Decrypt legacy = %q, %v", decrypted, err)
	}
}

// mustStoredKey loads a stored key or fails the test. | mustStoredKey 加载存储的密钥或使测试失败。
func mustStoredKey(t *testing.T, store *MemoryStore, id string) *Key {
	t.Helper()
	key, err := store.GetKey(context.Background(), id)
	if err != nil {
		t.Fatalf("GetKey(%s): %v", id, err)
	}
	return key
}

// TestAtRestParameterTamperingRejected verifies that edits to authenticated KDF parameters fail. | TestAtRestParameterTamperingRejected
// 校验对已认证 KDF 参数的修改会失败。
func TestAtRestParameterTamperingRejected(t *testing.T) {
	ctx := context.Background()
	wrapper, err := newAtRestWrapper(nil, "tamper passphrase")
	if err != nil {
		t.Fatalf("newAtRestWrapper: %v", err)
	}
	wrapped, err := wrapper.Wrap(ctx, "tamper-key", 1, []byte("protected"))
	if err != nil {
		t.Fatalf("Wrap: %v", err)
	}
	cases := map[string]func([]byte) []byte{
		"kdf byte": func(in []byte) []byte {
			out := append([]byte(nil), in...)
			out[len(atRestMagic)] = 9
			return out
		},
		"iterations below minimum": func(in []byte) []byte {
			out := append([]byte(nil), in...)
			binary.BigEndian.PutUint32(out[len(atRestMagic)+1:], 1)
			return out
		},
		"iterations changed": func(in []byte) []byte {
			out := append([]byte(nil), in...)
			binary.BigEndian.PutUint32(out[len(atRestMagic)+1:], pbkdf2Iterations-1)
			return out
		},
		"key length": func(in []byte) []byte {
			out := append([]byte(nil), in...)
			binary.BigEndian.PutUint16(out[len(atRestMagic)+5:], 15)
			return out
		},
		"salt length": func(in []byte) []byte {
			out := append([]byte(nil), in...)
			out[len(atRestMagic)+7] = atRestMaxSaltSize + 1
			return out
		},
		"salt byte": func(in []byte) []byte {
			out := append([]byte(nil), in...)
			out[atRestFixedHeaderSize] ^= 0xff
			return out
		},
		"ciphertext": func(in []byte) []byte {
			out := append([]byte(nil), in...)
			out[len(out)-1] ^= 0xff
			return out
		},
		"truncated header": func(in []byte) []byte {
			return append([]byte(nil), in[:atRestFixedHeaderSize-1]...)
		},
		"truncated salt": func(in []byte) []byte {
			return append([]byte(nil), in[:atRestFixedHeaderSize]...)
		},
		"truncated nonce": func(in []byte) []byte {
			return append([]byte(nil), in[:len(atRestMagic)+atRestFixedHeaderSize+atRestSaltSize]...)
		},
		"truncated ciphertext": func(in []byte) []byte {
			header := len(atRestMagic) + atRestFixedHeaderSize + atRestSaltSize
			return append([]byte(nil), in[:header+gcmNonceSize]...)
		},
	}
	for name, mutate := range cases {
		if _, err := wrapper.Unwrap(ctx, "tamper-key", 1, mutate(wrapped)); !errors.Is(err, ErrInvalidMaterial) {
			t.Fatalf("%s: err = %v, want ErrInvalidMaterial", name, err)
		}
	}
}

// TestAtRestRewrapRotation verifies helper-level rewrap and service-wide passphrase rotation. | TestAtRestRewrapRotation
// 校验助手级重新包装与服务级口令轮换。
func TestAtRestRewrapRotation(t *testing.T) {
	ctx := context.Background()
	oldWrapper, err := newAtRestWrapper(nil, "old passphrase")
	if err != nil {
		t.Fatalf("old wrapper: %v", err)
	}
	newWrapper, err := newAtRestWrapper(nil, "new passphrase")
	if err != nil {
		t.Fatalf("new wrapper: %v", err)
	}
	blob, err := oldWrapper.Wrap(ctx, "rotate-key", 4, []byte("rotate me"))
	if err != nil {
		t.Fatalf("old Wrap: %v", err)
	}
	rewrapped, err := Rewrap(ctx, oldWrapper, newWrapper, "rotate-key", 4, blob)
	if err != nil {
		t.Fatalf("Rewrap: %v", err)
	}
	plain, err := newWrapper.Unwrap(ctx, "rotate-key", 4, rewrapped)
	if err != nil || string(plain) != "rotate me" {
		t.Fatalf("new Unwrap = %q, %v", plain, err)
	}
	if _, err := oldWrapper.Unwrap(ctx, "rotate-key", 4, rewrapped); !errors.Is(err, ErrInvalidMaterial) {
		t.Fatalf("old wrapper unwrapped rotated blob: %v", err)
	}
	if _, err := Rewrap(ctx, nil, newWrapper, "k", 1, blob); !errors.Is(err, ErrInvalidConfig) {
		t.Fatalf("nil source err = %v", err)
	}
	if _, err := Rewrap(ctx, oldWrapper, nil, "k", 1, blob); !errors.Is(err, ErrInvalidConfig) {
		t.Fatalf("nil target err = %v", err)
	}
	if out, err := Rewrap(ctx, oldWrapper, newWrapper, "k", 1, nil); err != nil || out != nil {
		t.Fatalf("empty Rewrap = %v, %v", out, err)
	}

	store := NewMemoryStore()
	oldService, err := New(Config{Store: store, Passphrase: "old passphrase", Clock: newTestClock().Now})
	if err != nil {
		t.Fatalf("New old: %v", err)
	}
	first := createKeyForTest(t, oldService, CreateKeyRequest{Type: KeyTypeAES, Bits: 256}, true)
	second := createKeyForTest(t, oldService, CreateKeyRequest{Type: KeyTypeChaCha20}, true)
	plaintext := []byte("rotated envelope")
	ciphertext, err := oldService.Encrypt(ctx, second.ID, plaintext, nil)
	if err != nil {
		t.Fatalf("old Encrypt: %v", err)
	}
	updated, err := oldService.RewrapAtRest(ctx, newWrapper)
	if err != nil {
		t.Fatalf("RewrapAtRest: %v", err)
	}
	if updated != 2 {
		t.Fatalf("RewrapAtRest updated %d keys, want 2", updated)
	}
	if recovered, err := oldService.Decrypt(ctx, second.ID, ciphertext, nil); err != nil || !bytes.Equal(recovered, plaintext) {
		t.Fatalf("rotated service Decrypt = %q, %v", recovered, err)
	}
	stale, err := New(Config{Store: store, Passphrase: "old passphrase", Clock: newTestClock().Now})
	if err != nil {
		t.Fatalf("New stale: %v", err)
	}
	if _, err := stale.Decrypt(ctx, second.ID, ciphertext, nil); !errors.Is(err, ErrInvalidMaterial) {
		t.Fatalf("old passphrase decrypt after rotation err = %v", err)
	}

	fresh, err := New(Config{Store: store, Passphrase: "new passphrase", Clock: newTestClock().Now})
	if err != nil {
		t.Fatalf("New fresh: %v", err)
	}
	decrypted, err := fresh.Decrypt(ctx, second.ID, ciphertext, nil)
	if err != nil || !bytes.Equal(decrypted, plaintext) {
		t.Fatalf("fresh Decrypt = %q, %v", decrypted, err)
	}
	if _, err := fresh.DeriveKey(ctx, first.ID, 16, "rotation", nil); err != nil {
		t.Fatalf("fresh DeriveKey: %v", err)
	}
	if _, err := fresh.RewrapAtRest(ctx, nil); !errors.Is(err, ErrInvalidConfig) {
		t.Fatalf("nil next err = %v", err)
	}
	plainService, _ := newServiceForTest(t, Config{})
	if _, err := plainService.RewrapAtRest(ctx, newWrapper); !errors.Is(err, ErrInvalidConfig) {
		t.Fatalf("no wrapper err = %v", err)
	}
}
