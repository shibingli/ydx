package auth

import (
	"testing"
	"time"

	"github.com/pquerna/otp"
	"github.com/pquerna/otp/totp"
	ydotp "github.com/shibingli/ydx/auth/mfa/otp"
)

// testOTPSecret is the RFC 6238 SHA-1 test secret ("12345678901234567890") in base32. |
// testOTPSecret 是 RFC 6238 SHA-1 测试密钥（"12345678901234567890"）的 base32 形式。
const testOTPSecret = "GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ"

// testOTPTime is the RFC 6238 T=59 window. | testOTPTime 是 RFC 6238 的 T=59 时间窗口。
var testOTPTime = time.Unix(59, 0).UTC()

// BenchmarkTOTPGenerate compares TOTP generation with pquerna/otp. | BenchmarkTOTPGenerate 对比
// TOTP 生成与 pquerna/otp。
func BenchmarkTOTPGenerate(b *testing.B) {
	cfg := ydotp.Config{Algorithm: ydotp.SHA1, Digits: 6, Period: 30 * time.Second}
	b.Run("ydx", func(b *testing.B) {
		b.ReportAllocs()
		for i := 0; i < b.N; i++ {
			if _, err := ydotp.TOTP(testOTPSecret, testOTPTime, cfg); err != nil {
				b.Fatal(err)
			}
		}
	})
	b.Run("pquerna", func(b *testing.B) {
		b.ReportAllocs()
		for i := 0; i < b.N; i++ {
			if _, err := totp.GenerateCode(testOTPSecret, testOTPTime); err != nil {
				b.Fatal(err)
			}
		}
	})
}

// BenchmarkTOTPValidate compares TOTP validation with pquerna/otp. | BenchmarkTOTPValidate 对比
// TOTP 校验与 pquerna/otp。
func BenchmarkTOTPValidate(b *testing.B) {
	cfg := ydotp.Config{Algorithm: ydotp.SHA1, Digits: 6, Period: 30 * time.Second, Skew: 1}
	code, err := ydotp.TOTP(testOTPSecret, testOTPTime, cfg)
	if err != nil {
		b.Fatal(err)
	}
	opts := totp.ValidateOpts{Period: 30, Skew: 1, Digits: otp.DigitsSix, Algorithm: otp.AlgorithmSHA1}
	b.Run("ydx", func(b *testing.B) {
		b.ReportAllocs()
		for i := 0; i < b.N; i++ {
			if _, ok, err := ydotp.ValidateTOTP(testOTPSecret, code, testOTPTime, cfg); err != nil || !ok {
				b.Fatalf("ok=%v err=%v", ok, err)
			}
		}
	})
	b.Run("pquerna", func(b *testing.B) {
		b.ReportAllocs()
		for i := 0; i < b.N; i++ {
			if ok, err := totp.ValidateCustom(code, testOTPSecret, testOTPTime, opts); err != nil || !ok {
				b.Fatalf("ok=%v err=%v", ok, err)
			}
		}
	})
}

// TestTOTPInteropWithPquerna checks that both implementations accept each other's codes. |
// TestTOTPInteropWithPquerna 检查两个实现互相接受对方生成的口令。
func TestTOTPInteropWithPquerna(t *testing.T) {
	cfg := ydotp.Config{Algorithm: ydotp.SHA1, Digits: 6, Period: 30 * time.Second}
	ours, err := ydotp.TOTP(testOTPSecret, testOTPTime, cfg)
	if err != nil {
		t.Fatalf("ydx TOTP: %v", err)
	}
	theirs, err := totp.GenerateCode(testOTPSecret, testOTPTime)
	if err != nil {
		t.Fatalf("pquerna TOTP: %v", err)
	}
	if ours != theirs {
		t.Fatalf("codes differ: ydx %q, pquerna %q | 两个实现的口令不一致", ours, theirs)
	}
	opts := totp.ValidateOpts{Period: 30, Skew: 1, Digits: otp.DigitsSix, Algorithm: otp.AlgorithmSHA1}
	if ok, err := totp.ValidateCustom(ours, testOTPSecret, testOTPTime, opts); err != nil || !ok {
		t.Fatalf("pquerna rejected ydx code: ok=%v err=%v | pquerna 拒绝了 ydx 口令", ok, err)
	}
	if _, ok, err := ydotp.ValidateTOTP(testOTPSecret, theirs, testOTPTime, cfg); err != nil || !ok {
		t.Fatalf("ydx rejected pquerna code: ok=%v err=%v | ydx 拒绝了 pquerna 口令", ok, err)
	}
}
