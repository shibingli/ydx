package kms

import (
	"context"
	"errors"
	"testing"
)

// TestDeriveKeySymmetricOnly verifies that DeriveKey rejects asymmetric key records with a clear
// type error and still derives from every symmetric family. | TestDeriveKeySymmetricOnly 校验
// DeriveKey 以明确的类型错误拒绝非对称密钥记录，并仍可从所有对称密钥族派生。
func TestDeriveKeySymmetricOnly(t *testing.T) {
	ctx := context.Background()
	service, _ := newServiceForTest(t, Config{})
	cases := []struct {
		name    string
		keyType KeyType
		bits    int
	}{
		{"RSA", KeyTypeRSA, 2048},
		{"ECDSA", KeyTypeECDSA, 256},
		{"Ed25519", KeyTypeEd25519, 0},
		{"SM2", KeyTypeSM2, 0},
	}
	for _, tc := range cases {
		key := createKeyForTest(t, service, CreateKeyRequest{Type: tc.keyType, Bits: tc.bits}, true)
		stored, err := service.store.GetKey(ctx, key.ID)
		if err != nil {
			t.Fatalf("%s GetKey: %v", tc.name, err)
		}
		// Force the derive usage on the stored record to exercise the type guard; normal
		// creation rejects derive for asymmetric families. | 在存储记录上强制加入派生用途以覆盖类型
		// 守卫；正常创建会拒绝非对称族的派生用途。
		stored.UsageMask |= MaskDeriveKey
		if err := service.store.UpdateKey(ctx, stored); err != nil {
			t.Fatalf("%s UpdateKey: %v", tc.name, err)
		}
		if _, err := service.DeriveKey(ctx, key.ID, 32, "test", nil); !errors.Is(err, ErrInvalidKeyType) {
			t.Fatalf("%s DeriveKey err = %v, want ErrInvalidKeyType", tc.name, err)
		}
	}
	symmetric := []struct {
		name    string
		keyType KeyType
	}{
		{"AES", KeyTypeAES},
		{"ChaCha20", KeyTypeChaCha20},
		{"SM4", KeyTypeSM4},
	}
	for _, tc := range symmetric {
		key := createKeyForTest(t, service, CreateKeyRequest{Type: tc.keyType}, true)
		out, err := service.DeriveKey(ctx, key.ID, 16, "test", []byte("salt"))
		if err != nil || len(out) != 16 {
			t.Fatalf("%s DeriveKey = %d bytes, %v", tc.name, len(out), err)
		}
	}
}
