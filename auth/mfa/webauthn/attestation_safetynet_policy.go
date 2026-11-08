package webauthn

import (
	"encoding/hex"
	"strings"
	"time"

	"github.com/shibingli/ydx/errs"
)

// DefaultSafetyNetTimestampTolerance is the default accepted difference between the SafetyNet
// attestation timestamp and the verification clock. | DefaultSafetyNetTimestampTolerance 是 SafetyNet
// 认证时间戳与校验时钟之间默认接受的最大偏差。
const DefaultSafetyNetTimestampTolerance = time.Minute

// SafetyNetPolicy tightens the built-in android-safetynet verification beyond the mandatory
// ctsProfileMatch, nonce and signature checks. The zero value keeps the baseline behavior:
// ctsProfileMatch must be true, the nonce and JWS signature are verified, and the timestamp must be
// within DefaultSafetyNetTimestampTolerance. Every non-zero field adds a stricter requirement. |
// SafetyNetPolicy 在强制的 ctsProfileMatch、nonce 与签名校验之外收紧内置 android-safetynet 校验。
// 零值保持基线行为：ctsProfileMatch 必须为 true，nonce 与 JWS 签名必须有效，时间戳必须落在
// DefaultSafetyNetTimestampTolerance 内。每个非零字段都会增加更严格的要求。
//
// A custom SafetyNetVerifier replaces the built-in JWS checks and therefore owns this policy as
// well; SafetyNetPolicy is used only by the built-in path. | 自定义 SafetyNetVerifier 会替换内置
// JWS 校验，因此也自行负责该策略；SafetyNetPolicy 仅用于内置校验路径。
type SafetyNetPolicy struct {
	// RequireBasicIntegrity requires the payload basicIntegrity member to be true. | RequireBasicIntegrity
	// 要求载荷中的 basicIntegrity 成员为 true。
	RequireBasicIntegrity bool
	// AllowedAPKCertificateDigests pins the APK signing certificate SHA-256 digests reported in
	// apkCertificateDigestSha256. Entries are hexadecimal (64 characters) or standard base64. When
	// non-empty, the payload must report at least one digest and every reported digest must be
	// listed. | AllowedAPKCertificateDigests 固定 apkCertificateDigestSha256 中报告的 APK 签名证书
	// SHA-256 摘要。条目为十六进制（64 个字符）或标准 base64。非空时载荷必须至少报告一个摘要，且
	// 每个报告的摘要都必须在列表中。
	AllowedAPKCertificateDigests []string
	// AllowedEvaluationTypes restricts the payload evaluationType values. An empty list disables the
	// restriction; when set, the payload value must match one entry exactly. | AllowedEvaluationTypes
	// 限制载荷 evaluationType 的取值。空列表关闭限制；非空时载荷值必须与某一项完全匹配。
	AllowedEvaluationTypes []string
	// AllowedVersions restricts the attestation statement "ver" value. An empty list disables the
	// restriction. | AllowedVersions 限制认证声明 "ver" 字段的取值。空列表关闭限制。
	AllowedVersions []string
	// TimestampTolerance is the accepted absolute difference between timestampMs and the
	// verification clock. Zero means DefaultSafetyNetTimestampTolerance; negative values are
	// rejected as invalid configuration. | TimestampTolerance 是 timestampMs 与校验时钟之间可接受的
	// 绝对偏差。零值表示 DefaultSafetyNetTimestampTolerance；负值会作为非法配置被拒绝。
	TimestampTolerance time.Duration
}

// validate reports whether the policy is well formed. | validate 报告策略是否格式合法。
func (p SafetyNetPolicy) validate() error {
	if p.TimestampTolerance < 0 {
		return errs.Detail(ErrInvalidConfig, "SafetyNet timestamp tolerance %s is negative | SafetyNet 时间戳容忍度为负值 %s",
			p.TimestampTolerance, p.TimestampTolerance)
	}
	if _, err := decodePinnedDigests(p.AllowedAPKCertificateDigests, "SafetyNet APK certificate"); err != nil {
		return err
	}
	for _, evaluationType := range p.AllowedEvaluationTypes {
		if strings.TrimSpace(evaluationType) == "" {
			return errs.Detail(ErrInvalidConfig, "SafetyNet evaluation type allowlist contains an empty entry | SafetyNet evaluationType 允许列表包含空项")
		}
	}
	for _, version := range p.AllowedVersions {
		if strings.TrimSpace(version) == "" {
			return errs.Detail(ErrInvalidConfig, "SafetyNet version allowlist contains an empty entry | SafetyNet ver 允许列表包含空项")
		}
	}
	return nil
}

// timestampTolerance returns the configured tolerance or the default. | timestampTolerance 返回配置的
// 容忍度或默认值。
func (p SafetyNetPolicy) timestampTolerance() time.Duration {
	if p.TimestampTolerance > 0 {
		return p.TimestampTolerance
	}
	return DefaultSafetyNetTimestampTolerance
}

// verifySafetyNetJWSPolicy verifies the JWS and then applies the payload policy. | verifySafetyNetJWSPolicy
// 先校验 JWS，再应用载荷策略。
func verifySafetyNetJWSPolicy(jws *safetyNetJWS, expectedNonce []byte, policy SafetyNetPolicy) error {
	if err := verifySafetyNetJWS(jws, expectedNonce); err != nil {
		return err
	}
	if policy.RequireBasicIntegrity && !jws.payload.BasicIntegrity {
		return errs.Detail(ErrInvalidAttestation, "SafetyNet basicIntegrity is false | SafetyNet basicIntegrity 为 false")
	}
	if len(policy.AllowedEvaluationTypes) > 0 && !containsString(policy.AllowedEvaluationTypes, jws.payload.EvaluationType) {
		return errs.Detail(ErrInvalidAttestation, "SafetyNet evaluationType %q is not allowed | SafetyNet evaluationType %q 不在允许列表",
			jws.payload.EvaluationType, jws.payload.EvaluationType)
	}
	return verifySafetyNetDigests(jws.payload.APKCertificateDigestSHA, policy.AllowedAPKCertificateDigests)
}

// verifySafetyNetDigests enforces the APK certificate digest allowlist. | verifySafetyNetDigests 强制
// APK 证书摘要允许列表。
func verifySafetyNetDigests(reported []string, allowed []string) error {
	if len(allowed) == 0 {
		return nil
	}
	allowedDigests, err := decodePinnedDigests(allowed, "SafetyNet APK certificate")
	if err != nil {
		return err
	}
	if len(reported) == 0 {
		return errs.Detail(ErrInvalidAttestation, "SafetyNet payload reports no APK certificate digests | SafetyNet 载荷未报告 APK 证书摘要")
	}
	for index, digest := range reported {
		decoded, err := decodeStandardBase64(digest)
		if err != nil {
			return errs.WrapDetail(err, ErrInvalidAttestation,
				"SafetyNet APK certificate digest %d is not base64 | SafetyNet APK 证书摘要 %d 不是 base64", index, index)
		}
		if !containsDigest(allowedDigests, decoded) {
			return errs.Detail(ErrInvalidAttestation, "SafetyNet APK certificate digest %d is not allowed | SafetyNet APK 证书摘要 %d 不在允许列表",
				index, index)
		}
	}
	return nil
}

// decodePinnedDigests decodes hexadecimal or standard base64 digest entries. A 64-character
// hexadecimal value is the canonical representation of a SHA-256 digest; every other value is
// decoded as padded or unpadded standard base64. | decodePinnedDigests 解码十六进制或标准 base64 摘要条目。
// 64 个字符的十六进制值是 SHA-256 摘要的规范表示；其它值按带填充或无填充标准 base64 解码。
func decodePinnedDigests(values []string, label string) ([][]byte, error) {
	out := make([][]byte, 0, len(values))
	for index, value := range values {
		trimmed := strings.TrimSpace(value)
		if trimmed == "" {
			return nil, errs.Detail(ErrInvalidConfig, "%s digest %d is empty | %s 摘要 %d 为空", label, index, label, index)
		}
		decoded, err := hex.DecodeString(trimmed)
		if err != nil {
			decoded, err = decodeStandardBase64(trimmed)
		}
		if err != nil || len(decoded) == 0 {
			return nil, errs.Detail(ErrInvalidConfig, "%s digest %d is neither hexadecimal nor base64 | %s 摘要 %d 既不是十六进制也不是 base64",
				label, index, label, index)
		}
		out = append(out, decoded)
	}
	return out, nil
}

// containsDigest reports whether digests contains want. | containsDigest 报告 digests 是否包含 want。
func containsDigest(digests [][]byte, want []byte) bool {
	for _, digest := range digests {
		if constantTimeEqual(digest, want) {
			return true
		}
	}
	return false
}
