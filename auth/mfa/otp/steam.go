package otp

import (
	"strings"
	"time"

	"github.com/shibingli/ydx/errs"
)

// The Steam Guard parameters. | Steam Guard 参数。
const (
	// SteamPeriod is Steam Guard's fixed 30-second time step. | SteamPeriod 是 Steam Guard 固定的 30 秒时间步。
	SteamPeriod = 30 * time.Second
	// SteamCodeLength is Steam Guard's five-character code length. | SteamCodeLength 是 Steam Guard 五字符口令长度。
	SteamCodeLength = 5
	// SteamAlphabet is Steam Guard's 26-character output alphabet. | SteamAlphabet 是 Steam Guard 的 26 字符输出字母表。
	SteamAlphabet = "23456789BCDFGHJKMNPQRTVWXY"
)

// SteamCode returns the Steam Guard code for the time step containing at. Steam Guard is Valve's
// proprietary five-character TOTP variant: HMAC-SHA-1 over 30-second steps, rendered in a
// 26-character alphabet instead of decimal digits. It is not an RFC standard. | SteamCode 返回 at
// 所在时间步的 Steam Guard 口令。Steam Guard 是 Valve 专有的五字符 TOTP 变体：以 30 秒为步长做
// HMAC-SHA-1，并用 26 字符字母表而非十进制数字渲染。它不是 RFC 标准。
func SteamCode(secret string, at time.Time) (string, error) {
	key, err := decodeSecret(secret)
	if err != nil {
		return "", err
	}
	return steamCode(key, TimeStep(at, SteamPeriod)), nil
}

// ValidateSteamCode reports whether code matches secret anywhere in the Steam Guard time-step
// window [step-skew, step+skew] and returns the matched step. A malformed code is a non-match and
// yields (0, false, nil). | ValidateSteamCode 报告 code 是否匹配 secret 在 Steam Guard 时间步窗口
// [step-skew, step+skew] 内的任意值，并返回命中的时间步。格式非法的口令视为不匹配并返回
// (0, false, nil)。
func ValidateSteamCode(secret, code string, at time.Time, skew int) (int64, bool, error) {
	if skew < 0 || skew > MaxSkew {
		return 0, false, errs.Detail(ErrInvalidConfig,
			"skew %d outside [0,%d] | 容差 %d 超出 [0,%d]", skew, MaxSkew, skew, MaxSkew)
	}
	key, err := decodeSecret(secret)
	if err != nil {
		return 0, false, err
	}
	code = strings.ToUpper(strings.TrimSpace(code))
	if len(code) != SteamCodeLength {
		return 0, false, nil
	}
	for i := 0; i < len(code); i++ {
		if !strings.ContainsRune(SteamAlphabet, rune(code[i])) {
			return 0, false, nil
		}
	}
	step := TimeStep(at, SteamPeriod)
	if step < 0 {
		step = 0
	}
	window := int64(skew)
	start := step - window
	if start < 0 {
		start = 0
	}
	end := step + window
	if end < step {
		end = maxInt64
	}
	for current := start; ; current++ {
		if constantTimeEqual(steamCode(key, current), code) {
			return current, true, nil
		}
		if current == end {
			break
		}
	}
	return 0, false, nil
}

// steamCode renders one Steam Guard code from an already decoded key and step. | steamCode 从已解码
// 密钥与时间步渲染一个 Steam Guard 口令。
func steamCode(key []byte, step int64) string {
	value := dynamicTruncate(key, uint64(step), SHA1)
	var builder strings.Builder
	builder.Grow(SteamCodeLength)
	for i := 0; i < SteamCodeLength; i++ {
		builder.WriteByte(SteamAlphabet[value%uint64(len(SteamAlphabet))])
		value /= uint64(len(SteamAlphabet))
	}
	return builder.String()
}
