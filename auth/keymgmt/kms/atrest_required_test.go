package kms

import (
	"bytes"
	"context"
	"errors"
	"testing"
)

// recordingWrapper records the buffers passed to Wrap and Unwrap so tests can verify
// zeroization after the service returns. | recordingWrapper 记录传给 Wrap 与 Unwrap 的
// 缓冲区，使测试能在服务返回后校验归零。
type recordingWrapper struct {
	wrapInputs   [][]byte
	unwrapInputs [][]byte
}

// Wrap records material and returns a reversible prefixed copy. | Wrap 记录 material 并返回
// 可逆的前缀副本。
func (w *recordingWrapper) Wrap(_ context.Context, _ string, _ uint32, material []byte) ([]byte, error) {
	w.wrapInputs = append(w.wrapInputs, material)
	out := append([]byte("WKMS:"), material...)
	return out, nil
}

// Unwrap records wrapped and returns the original material. | Unwrap 记录 wrapped 并返回原始材料。
func (w *recordingWrapper) Unwrap(_ context.Context, _ string, _ uint32, wrapped []byte) ([]byte, error) {
	w.unwrapInputs = append(w.unwrapInputs, wrapped)
	if !bytes.HasPrefix(wrapped, []byte("WKMS:")) {
		return nil, ErrInvalidMaterial
	}
	return append([]byte(nil), wrapped[len("WKMS:"):]...), nil
}

// allZero reports whether every captured buffer has been overwritten with zeroes. |
// allZero 报告每个捕获的缓冲区是否已被零覆盖。
func allZero(buffers [][]byte) bool {
	for _, buffer := range buffers {
		for _, value := range buffer {
			if value != 0 {
				return false
			}
		}
	}
	return true
}

// TestRequireAtRestEncryptionModes verifies required and optional at-rest configurations.
// TestRequireAtRestEncryptionModes 校验必需与可选的静态加密配置。
func TestRequireAtRestEncryptionModes(t *testing.T) {
	root := &Key{Type: KeyTypeAES, Material: bytes.Repeat([]byte{3}, 32)}
	cases := []struct {
		name    string
		config  Config
		wantErr bool
		enabled bool
	}{
		{"required without protection", Config{RequireAtRestEncryption: true}, true, false},
		{"required with root key", Config{RequireAtRestEncryption: true, RootKey: root}, false, true},
		{"required with passphrase", Config{RequireAtRestEncryption: true, Passphrase: "fixed test passphrase"}, false, true},
		{"required with wrapper", Config{RequireAtRestEncryption: true, Wrapper: &recordingWrapper{}}, false, true},
		{"optional without protection", Config{}, false, false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			tc.config.Store = NewMemoryStore()
			service, err := New(tc.config)
			if tc.wantErr {
				if !errors.Is(err, ErrInvalidConfig) {
					t.Fatalf("New err = %v, want ErrInvalidConfig | New 错误 = %v，期望 ErrInvalidConfig", err, err)
				}
				if service != nil {
					t.Fatalf("service = %+v, want nil | 服务 = %+v，期望 nil", service, service)
				}
				return
			}
			if err != nil {
				t.Fatalf("New: %v | New：%v", err, err)
			}
			if got := service.AtRestEnabled(); got != tc.enabled {
				t.Fatalf("AtRestEnabled = %v, want %v | AtRestEnabled = %v，期望 %v", got, tc.enabled, got, tc.enabled)
			}
		})
	}

	var nilService *Service
	if nilService.AtRestEnabled() {
		t.Fatal("nil service reports at-rest encryption | 空服务报告静态加密")
	}
	if _, err := NewService(Config{Store: NewMemoryStore(), RequireAtRestEncryption: true}); !errors.Is(err, ErrInvalidConfig) {
		t.Fatalf("NewService required err = %v, want ErrInvalidConfig | NewService 必需错误 = %v，期望 ErrInvalidConfig", err, err)
	}
	alias, err := NewService(Config{Store: NewMemoryStore(), RequireAtRestEncryption: true, RootKey: root})
	if err != nil {
		t.Fatalf("NewService with root: %v | 带根密钥的 NewService：%v", err, err)
	}
	if !alias.AtRestEnabled() {
		t.Fatal("NewService did not enable at-rest wrapping | NewService 未启用静态包装")
	}
}

// TestRequiredAtRestEnvelopeAndZeroization verifies envelope encryption through required
// at-rest protection and that intermediate buffers are zeroized. |
// TestRequiredAtRestEnvelopeAndZeroization 校验必需静态保护下的信封加密以及中间缓冲区归零。
func TestRequiredAtRestEnvelopeAndZeroization(t *testing.T) {
	ctx := context.Background()
	wrapper := &recordingWrapper{}
	service, _ := newServiceForTest(t, Config{RequireAtRestEncryption: true, Wrapper: wrapper})
	key := createKeyForTest(t, service, CreateKeyRequest{Type: KeyTypeAES, Bits: 256}, true)

	plaintext := []byte("at-rest envelope payload")
	aad := []byte("envelope-aad")
	envelope, err := service.EncryptEnvelope(ctx, key.ID, plaintext, aad)
	if err != nil {
		t.Fatalf("EncryptEnvelope: %v | EncryptEnvelope：%v", err, err)
	}
	if !bytes.HasPrefix(envelope.WrappedKey, wrappedMagic) {
		t.Fatalf("wrapped key = %x, want KMSW prefix | 包装密钥 = %x，期望 KMSW 前缀", envelope.WrappedKey, envelope.WrappedKey)
	}
	encoded, err := envelope.MarshalBinary()
	if err != nil || !bytes.HasPrefix(encoded, envelopeMagic) {
		t.Fatalf("MarshalBinary = %x, %v | MarshalBinary = %x，%v", encoded, err, encoded, err)
	}
	decrypted, err := service.DecryptEnvelope(ctx, envelope, aad)
	if err != nil || !bytes.Equal(decrypted, plaintext) {
		t.Fatalf("DecryptEnvelope = %q, %v | DecryptEnvelope = %q，%v", decrypted, err, decrypted, err)
	}
	if _, err := service.DecryptEnvelope(ctx, envelope, []byte("wrong-aad")); !errors.Is(err, ErrAuthentication) {
		t.Fatalf("wrong AAD err = %v, want ErrAuthentication | 错误 AAD 错误 = %v，期望 ErrAuthentication", err, err)
	}

	if len(wrapper.wrapInputs) == 0 || !allZero(wrapper.wrapInputs) {
		t.Fatal("persistKey did not zeroize wrapper inputs | persistKey 未归零包装输入")
	}
	if len(wrapper.unwrapInputs) == 0 || !allZero(wrapper.unwrapInputs) {
		t.Fatal("loadKey did not zeroize wrapped material | loadKey 未归零包装材料")
	}
}

// TestRequiredAtRestStoredMaterialWrapped verifies imported plaintext never appears in
// the backing store and remains readable through the service. |
// TestRequiredAtRestStoredMaterialWrapped 校验导入的明文绝不出现在存储中，且仍可经服务读取。
func TestRequiredAtRestStoredMaterialWrapped(t *testing.T) {
	ctx := context.Background()
	store := NewMemoryStore()
	service, err := New(Config{
		Store:                   store,
		RequireAtRestEncryption: true,
		RootKey:                 &Key{Type: KeyTypeAES, Material: bytes.Repeat([]byte{9}, 32)},
	})
	if err != nil {
		t.Fatalf("New: %v | New：%v", err, err)
	}
	material := bytes.Repeat([]byte{0x5a}, 32)
	key, err := service.ImportKey(ctx, ImportKeyRequest{
		CreateKeyRequest: CreateKeyRequest{ID: "imported", Type: KeyTypeAES, Bits: 256},
		Material:         material,
	})
	if err != nil {
		t.Fatalf("ImportKey: %v | ImportKey：%v", err, err)
	}
	raw, err := store.GetKey(ctx, key.ID)
	if err != nil {
		t.Fatalf("raw GetKey: %v | 原始 GetKey：%v", err, err)
	}
	if !bytes.HasPrefix(raw.Material, atRestMagic) {
		t.Fatalf("stored material = %x, want at-rest magic | 存储材料 = %x，期望静态魔数", raw.Material, raw.Material)
	}
	if bytes.Contains(raw.Material, material) {
		t.Fatal("stored material contains the imported plaintext | 存储材料包含导入明文")
	}
	if len(raw.Versions) != 1 || !bytes.HasPrefix(raw.Versions[0].Material, atRestMagic) {
		t.Fatal("stored version material is not wrapped | 存储版本材料未包装")
	}
	loaded, err := service.loadKey(ctx, raw)
	if err != nil {
		t.Fatalf("loadKey: %v | loadKey：%v", err, err)
	}
	if !bytes.Equal(materialForVersion(loaded, 1), material) {
		t.Fatal("unwrapped key material does not match the import | 解包密钥材料与导入不一致")
	}
}
