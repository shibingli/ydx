package otp

import (
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/hex"
	"strings"

	"github.com/shibingli/ydx/errs"
)

// The recovery-code alphabet and bounds. | 恢复码字母表与边界。
const (
	// RecoveryCodeAlphabet is the 32-character ambiguity-free alphabet used by
	// GenerateRecoveryCodes: it omits 0, 1, I and O. | RecoveryCodeAlphabet 是 GenerateRecoveryCodes
	// 使用的 32 字符无歧义字母表：省略 0、1、I 与 O。
	RecoveryCodeAlphabet = "23456789ABCDEFGHJKLMNPQRSTUVWXYZ"
	// MinRecoveryCodeLength is the shortest generated recovery code, ten characters or 50 bits.
	// | MinRecoveryCodeLength 是最短生成恢复码长度，十个字符即 50 位。
	MinRecoveryCodeLength = 10
	// MaxRecoveryCodeLength is the longest generated recovery code. | MaxRecoveryCodeLength 是最长生成恢复码长度。
	MaxRecoveryCodeLength = 128
	// MaxRecoveryCodes is the largest batch GenerateRecoveryCodes produces. | MaxRecoveryCodes 是 GenerateRecoveryCodes 单次生成的上限。
	MaxRecoveryCodes = 1000
)

// GenerateRecoveryCodes returns count cryptographically random recovery codes of exactly length
// characters from RecoveryCodeAlphabet. Codes are returned without separators; use
// NormalizeRecoveryCode before hashing so spaces, hyphens and lower case are tolerated. | Generate
// RecoveryCodes 返回 count 个由 RecoveryCodeAlphabet 中恰好 length 个字符组成的密码学随机恢复码。
// 返回的恢复码不含分隔符；哈希前请使用 NormalizeRecoveryCode，以容忍空格、连字符与小写。
func GenerateRecoveryCodes(count, length int) ([]string, error) {
	if count < 1 || count > MaxRecoveryCodes {
		return nil, errs.Detail(ErrInvalidConfig,
			"recovery code count %d outside [1,%d] | 恢复码数量 %d 超出 [1,%d]",
			count, MaxRecoveryCodes, count, MaxRecoveryCodes)
	}
	if length < MinRecoveryCodeLength || length > MaxRecoveryCodeLength {
		return nil, errs.Detail(ErrInvalidConfig,
			"recovery code length %d outside [%d,%d] | 恢复码长度 %d 超出 [%d,%d]",
			length, MinRecoveryCodeLength, MaxRecoveryCodeLength,
			length, MinRecoveryCodeLength, MaxRecoveryCodeLength)
	}
	random := make([]byte, count*length)
	if _, err := rand.Read(random); err != nil {
		return nil, errs.Wrap(err, ErrRandomSource)
	}
	codes := make([]string, count)
	var builder strings.Builder
	builder.Grow(length)
	for i := 0; i < count; i++ {
		builder.Reset()
		for j := 0; j < length; j++ {
			// The alphabet has exactly 32 entries, so the low five bits are uniform.
			builder.WriteByte(RecoveryCodeAlphabet[random[i*length+j]&0x1f])
		}
		codes[i] = builder.String()
	}
	return codes, nil
}

// NormalizeRecoveryCode uppercases code and removes spaces, tabs, newlines and hyphens so a
// user-typed recovery code matches the stored hash. | NormalizeRecoveryCode 把 code 转为大写并移除
// 空格、制表符、换行与连字符，使用户输入的恢复码与存储的哈希匹配。
func NormalizeRecoveryCode(code string) string {
	var builder strings.Builder
	builder.Grow(len(code))
	for _, r := range strings.ToUpper(strings.TrimSpace(code)) {
		switch r {
		case ' ', '\t', '\r', '\n', '-':
			continue
		}
		builder.WriteRune(r)
	}
	return builder.String()
}

// HashRecoveryCode returns an unkeyed SHA-256 hash of the normalized code in the form
// "sha256:<hex>". An empty code yields an empty string. Unkeyed hashing is only appropriate for
// high-entropy codes; prefer RecoveryCodeHasher, which uses a server-side pepper. | HashRecoveryCode
// 返回规范化后代码的无密钥 SHA-256 哈希，形式为 "sha256:<hex>"。空代码返回空字符串。无密钥哈希
// 只适用于高熵代码；优先使用带服务端 pepper 的 RecoveryCodeHasher。
func HashRecoveryCode(code string) string {
	normalized := NormalizeRecoveryCode(code)
	if normalized == "" {
		return ""
	}
	sum := sha256.Sum256([]byte(normalized))
	return "sha256:" + hex.EncodeToString(sum[:])
}

// VerifyRecoveryCode reports whether code matches encoded. The comparison is constant time.
// | VerifyRecoveryCode 报告 code 是否匹配 encoded。比较使用常量时间。
func VerifyRecoveryCode(code, encoded string) bool {
	expected := HashRecoveryCode(code)
	if expected == "" || encoded == "" {
		return false
	}
	return subtle.ConstantTimeCompare([]byte(expected), []byte(encoded)) == 1
}

// RecoveryCodeHasher hashes and verifies recovery codes with a caller-supplied pepper. It is
// immutable after construction and safe for concurrent use. | RecoveryCodeHasher 使用调用方提供的
// pepper 哈希与校验恢复码。构造后不可变，可安全并发使用。
//
// The construction is HMAC-SHA-256 rather than a slow password KDF: generated recovery codes are
// random values with at least 50 bits of entropy, so stretching adds latency without changing the
// offline-guessing bound, while the pepper keeps an attacker who only stole the hashes from
// testing guesses at all. | 该实现使用 HMAC-SHA-256 而非慢速口令 KDF：生成的恢复码是至少 50 位
// 熵的随机值，拉伸只会增加延迟而不改变离线猜测上界；pepper 则让仅窃取哈希的攻击者无法测试猜测。
//
// # One-time semantics | 一次性语义
//
// A recovery code must be consumable exactly once. Verify only answers whether encoded matches;
// it does not remove anything. After a successful Verify the caller MUST atomically delete that
// hash from the user's remaining-code set (for example with a compare-and-delete in the store)
// before granting access, otherwise the same code can be replayed. | 恢复码必须只能消费一次。
// Verify 只回答 encoded 是否匹配，并不会删除任何内容。成功 Verify 后，调用方必须在授予访问前从
// 用户剩余恢复码集合中原子删除该哈希（例如存储层 compare-and-delete），否则同一恢复码可被重放。
type RecoveryCodeHasher struct {
	pepper []byte
}

// NewRecoveryCodeHasher returns a hasher keyed by pepper. The pepper is copied. An empty pepper
// is rejected because it removes the protection an attacker with a database dump would otherwise
// lack; use at least 16 random bytes. | NewRecoveryCodeHasher 返回以 pepper 为键的哈希器。pepper
// 会被复制。空 pepper 会被拒绝，因为它会让仅拿到数据库转储的攻击者失去唯一屏障；请使用至少
// 16 个随机字节。
func NewRecoveryCodeHasher(pepper []byte) (*RecoveryCodeHasher, error) {
	if len(pepper) == 0 {
		return nil, errs.Detail(ErrInvalidConfig, "recovery code pepper is empty | 恢复码 pepper 为空")
	}
	return &RecoveryCodeHasher{pepper: append([]byte(nil), pepper...)}, nil
}

// Hash returns "hmac-sha256:<hex>" for the normalized code. An empty code or a nil hasher yields
// an empty string. | Hash 返回规范化代码的 "hmac-sha256:<hex>"。空代码或 nil 哈希器返回空字符串。
func (h *RecoveryCodeHasher) Hash(code string) string {
	normalized := NormalizeRecoveryCode(code)
	if h == nil || len(h.pepper) == 0 || normalized == "" {
		return ""
	}
	mac := hmac.New(sha256.New, h.pepper)
	_, _ = mac.Write([]byte(normalized))
	return "hmac-sha256:" + hex.EncodeToString(mac.Sum(nil))
}

// Verify reports whether code matches encoded in constant time. A nil hasher, an empty code or an
// empty encoded value yields false. | Verify 以常量时间报告 code 是否匹配 encoded。nil 哈希器、
// 空代码或空 encoded 返回 false。
func (h *RecoveryCodeHasher) Verify(code, encoded string) bool {
	expected := h.Hash(code)
	if expected == "" || encoded == "" {
		return false
	}
	return subtle.ConstantTimeCompare([]byte(expected), []byte(encoded)) == 1
}
