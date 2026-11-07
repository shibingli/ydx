package otp

import (
	"crypto/hmac"
	"crypto/sha1"
	"encoding/base32"
	"encoding/binary"
	"errors"
	"strings"
	"testing"
	"time"
)

// TestSteamCode checks length, alphabet, determinism and validation. | TestSteamCode 检查长度、字母表、确定性与校验。
func TestSteamCode(t *testing.T) {
	t.Parallel()
	secret := testSecret("12345678901234567890")
	at := time.Unix(1234567890, 0).UTC()
	code, err := SteamCode(secret, at)
	if err != nil {
		t.Fatalf("SteamCode: %v | SteamCode 失败", err)
	}
	if len(code) != SteamCodeLength {
		t.Fatalf("SteamCode length = %d, want %d | Steam 口令长度不匹配", len(code), SteamCodeLength)
	}
	for _, r := range code {
		if !strings.ContainsRune(SteamAlphabet, r) {
			t.Errorf("code %q contains %q outside the Steam alphabet | Steam 口令含字母表外字符", code, r)
		}
	}
	again, err := SteamCode(secret, at.Add(29*time.Second))
	if err != nil {
		t.Fatalf("SteamCode: %v", err)
	}
	if again != code {
		t.Errorf("codes within one step differ: %q vs %q | 同一时间步内口令不一致", code, again)
	}
	step, ok, err := ValidateSteamCode(secret, code, at, 0)
	if err != nil || !ok {
		t.Fatalf("ValidateSteamCode = (%d, %v, %v), want (step, true, nil) | Steam 校验失败", step, ok, err)
	}
	if want := TimeStep(at, SteamPeriod); step != want {
		t.Errorf("step = %d, want %d | Steam 时间步不匹配", step, want)
	}
	if _, ok, err := ValidateSteamCode(secret, strings.ToLower(code), at, 0); err != nil || !ok {
		t.Errorf("lowercase ValidateSteamCode = (%v, %v), want (true, nil) | 小写 Steam 口令被拒绝", ok, err)
	}
	if _, ok, err := ValidateSteamCode(secret, code, at.Add(SteamPeriod), 0); err != nil || ok {
		t.Errorf("next-step ValidateSteamCode = (%v, %v), want (false, nil) | 下一步口令被接受", ok, err)
	}
	if _, ok, err := ValidateSteamCode(secret, code, at.Add(SteamPeriod), 1); err != nil || !ok {
		t.Errorf("skewed ValidateSteamCode = (%v, %v), want (true, nil) | 容差内 Steam 口令被拒绝", ok, err)
	}
	if _, ok, err := ValidateSteamCode(secret, code, at.Add(-SteamPeriod), 1); err != nil || !ok {
		t.Errorf("previous-step ValidateSteamCode = (%v, %v), want (true, nil) | 上一步 Steam 口令被拒绝", ok, err)
	}
}

// TestSteamCodeReference compares SteamCode with a direct standard-library implementation.
// | TestSteamCodeReference 用标准库直接实现对照 SteamCode。
func TestSteamCodeReference(t *testing.T) {
	t.Parallel()
	raw := "12345678901234567890"
	secret := testSecret(raw)
	for _, unix := range []int64{0, 59, 1234567890, 2000000000} {
		at := time.Unix(unix, 0).UTC()
		got, err := SteamCode(secret, at)
		if err != nil {
			t.Fatalf("SteamCode: %v", err)
		}
		if want := steamReference(t, raw, at); got != want {
			t.Errorf("SteamCode(%d) = %q, want %q | Steam 参考实现不一致", unix, got, want)
		}
	}
}

// TestSteamCodeInvalid checks malformed input handling. | TestSteamCodeInvalid 检查非法输入处理。
func TestSteamCodeInvalid(t *testing.T) {
	t.Parallel()
	secret := testSecret("12345678901234567890")
	at := time.Unix(1234567890, 0).UTC()
	if _, err := SteamCode("", at); !errors.Is(err, ErrInvalidSecret) {
		t.Errorf("empty secret error = %v, want ErrInvalidSecret | 空密钥错误应为 ErrInvalidSecret", err)
	}
	if _, _, err := ValidateSteamCode(secret, "ABCDE", at, -1); !errors.Is(err, ErrInvalidConfig) {
		t.Errorf("negative skew error = %v, want ErrInvalidConfig | 负容差错误应为 ErrInvalidConfig", err)
	}
	if _, _, err := ValidateSteamCode(secret, "ABCDE", at, MaxSkew+1); !errors.Is(err, ErrInvalidConfig) {
		t.Errorf("large skew error = %v, want ErrInvalidConfig | 过大容差错误应为 ErrInvalidConfig", err)
	}
	if _, _, err := ValidateSteamCode("", "ABCDE", at, 0); !errors.Is(err, ErrInvalidSecret) {
		t.Errorf("empty secret error = %v, want ErrInvalidSecret | 空密钥错误应为 ErrInvalidSecret", err)
	}
	current, err := SteamCode(secret, at)
	if err != nil {
		t.Fatalf("SteamCode: %v", err)
	}
	mismatch := []byte(current)
	if mismatch[0] != '2' {
		mismatch[0] = '2'
	} else {
		mismatch[0] = '3'
	}
	for _, code := range []string{"", "ABCD", "ABCDEF", "ABCD0", "abcde1", string(mismatch)} {
		_, ok, err := ValidateSteamCode(secret, code, at, 0)
		if err != nil {
			t.Errorf("ValidateSteamCode(%q) error = %v, want nil | 非法格式不应报错", code, err)
		}
		if ok {
			t.Errorf("ValidateSteamCode(%q) accepted a malformed code | 非法 Steam 口令被接受", code)
		}
	}
}

// steamReference recomputes a Steam Guard code with the standard library directly. | steamReference
// 直接用标准库重新计算 Steam Guard 口令。
func steamReference(t *testing.T, rawSecret string, at time.Time) string {
	t.Helper()
	key, err := base32.StdEncoding.WithPadding(base32.NoPadding).DecodeString(testSecret(rawSecret))
	if err != nil {
		t.Fatalf("decode reference secret: %v | 参考密钥解码失败", err)
	}
	mac := hmac.New(sha1.New, key)
	var message [8]byte
	binary.BigEndian.PutUint64(message[:], uint64(at.Unix()/int64(SteamPeriod/time.Second)))
	if _, err := mac.Write(message[:]); err != nil {
		t.Fatalf("write reference MAC: %v | 参考 MAC 写入失败", err)
	}
	sum := mac.Sum(nil)
	offset := sum[len(sum)-1] & 0x0f
	value := (uint64(sum[offset])&0x7f)<<24 |
		uint64(sum[offset+1])<<16 |
		uint64(sum[offset+2])<<8 |
		uint64(sum[offset+3])
	alphabet := "23456789BCDFGHJKMNPQRTVWXY"
	var builder strings.Builder
	for i := 0; i < SteamCodeLength; i++ {
		builder.WriteByte(alphabet[value%uint64(len(alphabet))])
		value /= uint64(len(alphabet))
	}
	return builder.String()
}
