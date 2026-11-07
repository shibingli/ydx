package otp

import (
	"errors"
	"strings"
	"testing"
)

// TestGenerateRecoveryCodes checks count, length, alphabet and uniqueness. | TestGenerateRecoveryCodes 检查数量、长度、字母表与唯一性。
func TestGenerateRecoveryCodes(t *testing.T) {
	t.Parallel()
	if len(RecoveryCodeAlphabet) != 32 {
		t.Fatalf("alphabet length = %d, want 32 for uniform five-bit sampling | 字母表长度必须为 32",
			len(RecoveryCodeAlphabet))
	}
	codes, err := GenerateRecoveryCodes(16, 12)
	if err != nil {
		t.Fatalf("GenerateRecoveryCodes: %v | 生成恢复码失败", err)
	}
	if len(codes) != 16 {
		t.Fatalf("len(codes) = %d, want 16 | 恢复码数量不匹配", len(codes))
	}
	seen := make(map[string]struct{}, len(codes))
	for _, code := range codes {
		if len(code) != 12 {
			t.Errorf("code %q length = %d, want 12 | 恢复码长度不匹配", code, len(code))
		}
		for _, r := range code {
			if !strings.ContainsRune(RecoveryCodeAlphabet, r) {
				t.Errorf("code %q contains %q outside the alphabet | 恢复码含字母表外字符", code, r)
			}
		}
		if _, exists := seen[code]; exists {
			t.Errorf("duplicate code %q | 恢复码重复", code)
		}
		seen[code] = struct{}{}
	}
}

// TestGenerateRecoveryCodesInvalid checks the bounds. | TestGenerateRecoveryCodesInvalid 检查边界。
func TestGenerateRecoveryCodesInvalid(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name   string
		count  int
		length int
	}{
		{"zero count", 0, 10},
		{"negative count", -1, 10},
		{"count too large", MaxRecoveryCodes + 1, 10},
		{"length too small", 1, MinRecoveryCodeLength - 1},
		{"length too large", 1, MaxRecoveryCodeLength + 1},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			if _, err := GenerateRecoveryCodes(tt.count, tt.length); !errors.Is(err, ErrInvalidConfig) {
				t.Errorf("GenerateRecoveryCodes error = %v, want ErrInvalidConfig | 错误应为 ErrInvalidConfig", err)
			}
		})
	}
}

// TestNormalizeRecoveryCode checks user-typed formatting tolerance. | TestNormalizeRecoveryCode 检查用户输入格式容忍。
func TestNormalizeRecoveryCode(t *testing.T) {
	t.Parallel()
	tests := map[string]string{
		"ABCD-EFGH":    "ABCDEFGH",
		" abcd efgh ":  "ABCDEFGH",
		"AB\tCD\nEFGH": "ABCDEFGH",
		"":             "",
		"---":          "",
	}
	for input, want := range tests {
		if got := NormalizeRecoveryCode(input); got != want {
			t.Errorf("NormalizeRecoveryCode(%q) = %q, want %q | 规范化结果不匹配", input, got, want)
		}
	}
}

// TestHashRecoveryCode checks unkeyed hashing and verification. | TestHashRecoveryCode 检查无密钥哈希与校验。
func TestHashRecoveryCode(t *testing.T) {
	t.Parallel()
	hash := HashRecoveryCode("abcd-efgh")
	if !strings.HasPrefix(hash, "sha256:") {
		t.Fatalf("HashRecoveryCode = %q, want sha256 prefix | 哈希前缀不正确", hash)
	}
	if got := HashRecoveryCode("ABCD EFGH"); got != hash {
		t.Errorf("normalized hash = %q, want %q | 规范化哈希不一致", got, hash)
	}
	if !VerifyRecoveryCode("ABCD EFGH", hash) {
		t.Error("VerifyRecoveryCode rejected a matching code | 匹配的恢复码被拒绝")
	}
	if VerifyRecoveryCode("ABCD-EFGX", hash) {
		t.Error("VerifyRecoveryCode accepted a mismatched code | 不匹配的恢复码被接受")
	}
	if VerifyRecoveryCode("", hash) {
		t.Error("VerifyRecoveryCode accepted an empty code | 空恢复码被接受")
	}
	if VerifyRecoveryCode("ABCDEFGH", "") {
		t.Error("VerifyRecoveryCode accepted an empty hash | 空哈希被接受")
	}
	if HashRecoveryCode("") != "" {
		t.Error("HashRecoveryCode(\"\") is not empty | 空代码哈希非空")
	}
	if VerifyRecoveryCode("ABCDEFGH", "hmac-sha256:deadbeef") {
		t.Error("VerifyRecoveryCode accepted a different scheme | 接受了不同方案的哈希")
	}
}

// TestRecoveryCodeHasher checks keyed hashing, pepper isolation and nil safety. | TestRecoveryCodeHasher 检查带键哈希、pepper 隔离与 nil 安全。
func TestRecoveryCodeHasher(t *testing.T) {
	t.Parallel()
	if _, err := NewRecoveryCodeHasher(nil); !errors.Is(err, ErrInvalidConfig) {
		t.Errorf("empty pepper error = %v, want ErrInvalidConfig | 空 pepper 错误应为 ErrInvalidConfig", err)
	}
	if _, err := NewRecoveryCodeHasher([]byte{}); !errors.Is(err, ErrInvalidConfig) {
		t.Errorf("empty slice pepper error = %v, want ErrInvalidConfig | 空切片 pepper 错误应为 ErrInvalidConfig", err)
	}
	pepper := []byte("correct horse battery staple")
	hasher, err := NewRecoveryCodeHasher(pepper)
	if err != nil {
		t.Fatalf("NewRecoveryCodeHasher: %v", err)
	}
	hash := hasher.Hash("abcd-efgh")
	if !strings.HasPrefix(hash, "hmac-sha256:") {
		t.Fatalf("Hash = %q, want hmac-sha256 prefix | 哈希前缀不正确", hash)
	}
	if !hasher.Verify("ABCD EFGH", hash) {
		t.Error("Verify rejected a matching code | 匹配的恢复码被拒绝")
	}
	if hasher.Verify("ABCD-EFGX", hash) {
		t.Error("Verify accepted a mismatched code | 不匹配的恢复码被接受")
	}
	if hasher.Hash("") != "" {
		t.Error("Hash(\"\") is not empty | 空代码哈希非空")
	}
	if hasher.Verify("", "") {
		t.Error("Verify accepted empty values | 接受了空值")
	}
	other, err := NewRecoveryCodeHasher([]byte("different pepper"))
	if err != nil {
		t.Fatalf("NewRecoveryCodeHasher: %v", err)
	}
	if other.Verify("ABCDEFGH", hash) {
		t.Error("a different pepper verified the hash | 不同 pepper 通过了校验")
	}
	if hasher.Hash("ABCDEFGH") == other.Hash("ABCDEFGH") {
		t.Error("different peppers produced the same hash | 不同 pepper 产生相同哈希")
	}
	// The constructor must copy the pepper.
	pepper[0] = 'X'
	if !hasher.Verify("ABCDEFGH", hash) {
		t.Error("mutating the caller pepper changed the hasher | 修改调用方 pepper 影响了哈希器")
	}
	var nilHasher *RecoveryCodeHasher
	if nilHasher.Hash("ABCDEFGH") != "" {
		t.Error("nil hasher Hash is not empty | nil 哈希器 Hash 非空")
	}
	if nilHasher.Verify("ABCDEFGH", hash) {
		t.Error("nil hasher Verify accepted a code | nil 哈希器接受了恢复码")
	}
}
