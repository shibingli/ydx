package auth

import (
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/binary"
	"strings"
	"time"

	"github.com/shibingli/ydx/base64"
	"github.com/shibingli/ydx/errs"
)

// ErrRandomSource reports that the operating system random source failed. | ErrRandomSource 表示操作系统随机源失败。
var ErrRandomSource = errs.New("auth: random source failed | auth：随机源失败")

// RandomToken returns n cryptographically random bytes encoded as unpadded base64url. | RandomToken
// 返回 n 个密码学随机字节的免填充 base64url 编码。
//
// The result is suitable as a bearer secret, CSRF nonce, authorization code, refresh token or
// one-time verification token. Callers should use at least 32 bytes for bearer values. | 结果可用作
// 承载密钥、CSRF nonce、授权码、刷新令牌或一次性验证令牌。承载类取值建议至少 32 字节。
func RandomToken(n int) (string, error) {
	if n <= 0 {
		return "", errs.Detail(ErrInvalidRequest, "token length %[1]d | 令牌长度 %[1]d", n)
	}
	buf := make([]byte, n)
	if _, err := rand.Read(buf); err != nil {
		return "", errs.Wrap(err, ErrRandomSource)
	}
	return base64.RawURLEncoding.EncodeToString(buf), nil
}

// HashToken returns the SHA-256 digest of token encoded as unpadded base64url. | HashToken 返回 token
// 的 SHA-256 摘要，编码为免填充 base64url。
//
// Stores should persist this value instead of the raw bearer secret, so a database disclosure does
// not hand out usable sessions, codes or refresh tokens. | 存储应保存该值而不是原始承载密钥，这样
// 数据库泄露不会直接交出可用的会话、授权码或刷新令牌。
func HashToken(token string) string {
	sum := sha256.Sum256([]byte(token))
	return base64.RawURLEncoding.EncodeToString(sum[:])
}

// TokenHashMatches reports whether raw hashes to storedHash in constant time. | TokenHashMatches 以常量时间报告 raw 的哈希是否等于 storedHash。
func TokenHashMatches(storedHash, raw string) bool {
	if storedHash == "" || raw == "" {
		return false
	}
	want := HashToken(raw)
	return subtle.ConstantTimeCompare([]byte(storedHash), []byte(want)) == 1
}

// SecureEqual compares two strings in constant time. | SecureEqual 以常量时间比较两个字符串。
func SecureEqual(a, b string) bool {
	return subtle.ConstantTimeCompare([]byte(a), []byte(b)) == 1
}

// NewID returns a random identifier with the given prefix. | NewID 返回带指定前缀的随机标识。
//
// The identifier is 128 random bits encoded as base32hex-like lowercase base64url; it is not a
// sequential or guessable value. | 标识由 128 位随机数编码为小写 base64url，不是顺序或可猜测的值。
func NewID(prefix string) string {
	var raw [16]byte
	if _, err := rand.Read(raw[:]); err != nil {
		// rand.Read on the platform CSPRNG is documented never to fail after Go 1.24; if it does,
		// returning a value that could collide is unacceptable, so fall back to a timestamp mix that
		// still includes the process identity. The caller cannot see an error from an ID helper. | Go 1.24
		// 之后平台 CSPRNG 的 rand.Read 文档保证不失败；若真失败，返回可能碰撞的值不可接受，因此回退到
		// 仍包含进程身份的时间戳混合值。调用方无法从 ID 辅助函数看到错误。
		binary.BigEndian.PutUint64(raw[:8], uint64(time.Now().UnixNano()))
		binary.BigEndian.PutUint64(raw[8:], uint64(time.Now().UnixNano()>>1))
	}
	id := base64.RawURLEncoding.EncodeToString(raw[:])
	if prefix == "" {
		return id
	}
	return prefix + "_" + id
}

// normalizePhone returns the canonical lookup key of a phone number. | normalizePhone 返回手机号的规范化查询键。
//
// The key contains digits only. A leading plus or 00 international prefix is dropped, the accepted
// separators (ASCII spaces, tabs, line breaks, hyphens, parentheses and the ideographic space) are
// removed, and the Chinese country code 86 is folded into the 11-digit local mobile form so that
// "+86 138-0013-8000", "0086 13800138000", "8613800138000" and "13800138000" share one key. Values
// containing any other character or fewer than five digits are rejected. | 键只含数字。去掉前导加号或
// 00 国际前缀，移除接受的分隔符（ASCII 空格、制表符、换行、连字符、圆括号与全角空格），并把中国
// 国家码 86 折叠为 11 位本地手机号形式，使 "+86 138-0013-8000"、"0086 13800138000"、
// "8613800138000" 与 "13800138000" 共用一个键。包含其它字符或有效数字少于五位的取值会被拒绝。
func normalizePhone(phone string) (string, bool) {
	var b strings.Builder
	b.Grow(len(phone))
	for _, r := range phone {
		switch {
		case r >= '0' && r <= '9':
			b.WriteRune(r)
		case r == '+' && b.Len() == 0:
		case r == ' ' || r == '\t' || r == '\r' || r == '\n' || r == '-' ||
			r == '(' || r == ')' || r == '　':
		default:
			return "", false
		}
	}
	digits := b.String()
	if strings.HasPrefix(digits, "00") {
		digits = digits[2:]
	}
	if len(digits) == 13 && strings.HasPrefix(digits, "86") && digits[2] == '1' {
		digits = digits[2:]
	}
	if len(digits) < 5 {
		return "", false
	}
	return digits, true
}

// SanitizeIdentifier lowercases and trims an identifier for case-insensitive comparison. | SanitizeIdentifier 对标识做小写与去空白，用于大小写不敏感比较。
func SanitizeIdentifier(s string) string {
	out := make([]byte, 0, len(s))
	for i := 0; i < len(s); i++ {
		c := s[i]
		switch {
		case c >= 'A' && c <= 'Z':
			c += 'a' - 'A'
			out = append(out, c)
		case c == ' ' || c == '\t' || c == '\r' || c == '\n':
			continue
		default:
			out = append(out, c)
		}
	}
	return string(out)
}
