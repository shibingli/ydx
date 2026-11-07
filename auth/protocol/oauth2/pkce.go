package oauth2

import (
	"crypto/sha256"
	"crypto/subtle"
	"strings"

	"github.com/shibingli/ydx/auth"
	"github.com/shibingli/ydx/base64"
	"github.com/shibingli/ydx/errs"
)

// PKCE methods. | PKCE 方法。
const (
	// PKCES256 is the SHA-256 code-challenge method required by OAuth 2.1. | PKCES256 是 OAuth 2.1 要求的 SHA-256 挑战方法。
	PKCES256 = "S256"
	// PKCEPlain is the deprecated plain verifier method, kept for compatibility. | PKCEPlain 是已弃用的明文校验方法，仅为兼容保留。
	PKCEPlain = "plain"
)

// ErrPKCE reports a malformed or mismatched PKCE verifier. | ErrPKCE 表示 PKCE 校验器格式非法或不匹配。
var ErrPKCE = errs.New("oauth2: invalid PKCE verifier | oauth2：PKCE 校验器无效")

// GenerateCodeVerifier returns a 43-character high-entropy PKCE verifier. | GenerateCodeVerifier 返回 43 字符的高熵 PKCE 校验器。
func GenerateCodeVerifier() (string, error) {
	return auth.RandomToken(32)
}

// CodeChallengeS256 returns the S256 challenge for verifier. | CodeChallengeS256 返回 verifier 的 S256 挑战。
func CodeChallengeS256(verifier string) string {
	sum := sha256.Sum256([]byte(verifier))
	return base64.RawURLEncoding.EncodeToString(sum[:])
}

// ValidCodeVerifier reports whether verifier satisfies RFC 7636 §4.1. | ValidCodeVerifier 报告 verifier 是否满足 RFC 7636 §4.1。
func ValidCodeVerifier(verifier string) bool {
	if len(verifier) < 43 || len(verifier) > 128 {
		return false
	}
	for i := 0; i < len(verifier); i++ {
		c := verifier[i]
		if (c >= 'A' && c <= 'Z') || (c >= 'a' && c <= 'z') || (c >= '0' && c <= '9') ||
			c == '-' || c == '.' || c == '_' || c == '~' {
			continue
		}
		return false
	}
	return true
}

// ValidCodeChallenge reports whether challenge and method are a legal pair. | ValidCodeChallenge 报告 challenge 与 method 是否为合法组合。
func ValidCodeChallenge(challenge, method string) error {
	if challenge == "" {
		return errs.Detail(ErrPKCE, "code_challenge is empty | code_challenge 为空")
	}
	if len(challenge) < 43 || len(challenge) > 128 {
		return errs.Detail(ErrPKCE, "code_challenge length %[1]d | code_challenge 长度 %[1]d", len(challenge))
	}
	for i := 0; i < len(challenge); i++ {
		c := challenge[i]
		if (c >= 'A' && c <= 'Z') || (c >= 'a' && c <= 'z') || (c >= '0' && c <= '9') ||
			c == '-' || c == '.' || c == '_' || c == '~' {
			continue
		}
		return errs.Detail(ErrPKCE, "code_challenge contains an illegal character | code_challenge 含非法字符")
	}
	switch strings.ToUpper(method) {
	case "":
		return nil
	case PKCES256, PKCEPlain:
		return nil
	default:
		return errs.Detail(ErrPKCE, "unsupported code_challenge_method %[1]q | 不支持的 code_challenge_method %[1]q", method)
	}
}

// VerifyPKCE reports whether verifier matches challenge under method. | VerifyPKCE 报告 verifier 在 method 下是否匹配 challenge。
func VerifyPKCE(verifier, challenge, method string) bool {
	if !ValidCodeVerifier(verifier) || challenge == "" {
		return false
	}
	switch strings.ToUpper(method) {
	case "", PKCEPlain:
		return subtle.ConstantTimeCompare([]byte(verifier), []byte(challenge)) == 1
	case PKCES256:
		want := CodeChallengeS256(verifier)
		return subtle.ConstantTimeCompare([]byte(want), []byte(challenge)) == 1
	default:
		return false
	}
}

// NormalizePKCEMethod returns the canonical method name. | NormalizePKCEMethod 返回规范方法名。
func NormalizePKCEMethod(method string) string {
	if method == "" {
		return PKCEPlain
	}
	return strings.ToUpper(method)
}
