package webauthn

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/rsa"
	"crypto/x509"
	"strings"

	"github.com/shibingli/ydx/errs"
)

// Keymaster verified boot states used by the Android key attestation root of trust. | Android 密钥
// 认证信任根使用的 Keymaster 验证启动状态。
const (
	// androidVerifiedBootVerified is KM_VERIFIED_BOOT_VERIFIED. | androidVerifiedBootVerified 是
	// KM_VERIFIED_BOOT_VERIFIED。
	androidVerifiedBootVerified = 0
)

// AndroidKeyPolicy tightens the built-in android-key KeyDescription checks beyond the mandatory
// origin, signing purpose, attestationApplicationId, package and allApplications checks. The zero
// value keeps the baseline behavior exactly; every non-zero field adds a stricter requirement. |
// AndroidKeyPolicy 在强制的 origin、签名用途、attestationApplicationId、包名与 allApplications
// 校验之外收紧内置 android-key KeyDescription 校验。零值完全保持基线行为；每个非零字段都会增加
// 更严格的要求。
//
// The declared keySize, ecCurve and digest values are also compared with the actual certificate
// public key, so a KeyDescription cannot claim stronger properties than the key it certifies. A
// custom AndroidKeyVerifier adds checks; a non-zero AndroidKeyPolicy is still enforced after it
// returns, so a custom verifier cannot silently disable configured policy. | 声明的 keySize、ecCurve
// 与 digest 值还会与实际证书公钥比较，因此 KeyDescription 不能声称比其认证密钥更强的属性。自定义
// AndroidKeyVerifier 只增加校验；非零 AndroidKeyPolicy 会在其返回后继续执行，因此自定义校验器不能
// 静默关闭已配置策略。
type AndroidKeyPolicy struct {
	// RequireVerifiedBoot requires a rootOfTrust field whose verifiedBootState is Verified (0). |
	// RequireVerifiedBoot 要求存在 rootOfTrust 字段且 verifiedBootState 为 Verified（0）。
	RequireVerifiedBoot bool
	// MinOSVersion is the minimum accepted osVersion (for example 202401). Zero disables the
	// check; a positive value requires the field and rejects lower values. | MinOSVersion 是可接受的
	// 最低 osVersion（例如 202401）。零值关闭校验；正值要求该字段存在并拒绝更低的值。
	MinOSVersion int
	// MinOSPatchLevel is the minimum accepted osPatchLevel (for example 202401). Zero disables the
	// check; a positive value requires the field and rejects lower values. | MinOSPatchLevel 是
	// 可接受的最低 osPatchLevel（例如 202401）。零值关闭校验；正值要求该字段存在并拒绝更低的值。
	MinOSPatchLevel int
	// MinKeySize is the minimum accepted key size in bits. Zero disables the check. The size comes
	// from the certificate public key, which must also match any declared keySize. | MinKeySize 是
	// 可接受的最低密钥位数。零值关闭校验。位数来自证书公钥，且必须与声明的 keySize 一致。
	MinKeySize int
	// AllowedECCurves restricts EC keys to the listed field sizes in bits (224, 256, 384 or 521).
	// Empty disables the restriction. When non-empty, non-EC keys are rejected. | AllowedECCurves
	// 把 EC 密钥限制为列出的字段位数（224、256、384 或 521）。空值关闭限制；非空时非 EC 密钥会被拒绝。
	AllowedECCurves []int
	// AllowedDigests restricts the digest algorithm names declared in the AuthorizationList.
	// Accepted names are "none", "md5", "sha1", "sha224", "sha256", "sha384" and "sha512". Empty
	// disables the restriction; a non-empty list requires at least one declared digest and rejects
	// any declared digest outside the list. | AllowedDigests 限制 AuthorizationList 声明的摘要算法名称。
	// 可接受名称为 "none"、"md5"、"sha1"、"sha224"、"sha256"、"sha384" 与 "sha512"。空值关闭限制；
	// 非空时要求至少声明一个摘要，并拒绝列表之外的任何已声明摘要。
	AllowedDigests []string
	// AllowedApplicationDigests pins the AttestationApplicationId signature digests. Entries are
	// hexadecimal or standard base64. Empty disables the check; a non-empty list requires an
	// attestationApplicationId with at least one signature digest, and every reported digest must
	// be listed. This is the package digest consistency check. | AllowedApplicationDigests 固定
	// AttestationApplicationId 签名摘要。条目为十六进制或标准 base64。空值关闭校验；非空时要求存在
	// attestationApplicationId 且至少包含一个签名摘要，并且每个报告的摘要都必须在列表中。这就是包摘要
	// 一致性校验。
	AllowedApplicationDigests []string
	// AllowAllApplications permits the allApplications authorization. The default false keeps the
	// baseline rejection. When true, package binding is still enforced if a package name is
	// required. | AllowAllApplications 允许 allApplications 授权。默认 false 保持基线拒绝行为。设为
	// true 时，如果要求包名，包名绑定仍会被强制校验。
	AllowAllApplications bool
}

// isZero reports whether no optional policy field is set. | isZero 报告是否未设置任何可选策略字段。
func (p AndroidKeyPolicy) isZero() bool {
	return !p.RequireVerifiedBoot &&
		p.MinOSVersion == 0 &&
		p.MinOSPatchLevel == 0 &&
		p.MinKeySize == 0 &&
		len(p.AllowedECCurves) == 0 &&
		len(p.AllowedDigests) == 0 &&
		len(p.AllowedApplicationDigests) == 0 &&
		!p.AllowAllApplications
}

// validate reports whether the policy is well formed. | validate 报告策略是否格式合法。
func (p AndroidKeyPolicy) validate() error {
	if p.MinOSVersion < 0 || p.MinOSPatchLevel < 0 || p.MinKeySize < 0 {
		return errs.Detail(ErrInvalidConfig, "Android key policy minima are negative | Android 密钥策略下限为负值")
	}
	for _, curve := range p.AllowedECCurves {
		if _, ok := androidCurveEnum(curve); !ok {
			return errs.Detail(ErrInvalidConfig, "Android key policy curve %d is not 224, 256, 384 or 521 | Android 密钥策略曲线 %d 不是 224、256、384 或 521",
				curve, curve)
		}
	}
	for index, name := range p.AllowedDigests {
		if _, ok := androidDigestEnum(name); !ok {
			return errs.Detail(ErrInvalidConfig, "Android key policy digest %d is %q, want none, md5, sha1, sha224, sha256, sha384 or sha512 | Android 密钥策略摘要 %d 为 %q，需要 none、md5、sha1、sha224、sha256、sha384 或 sha512",
				index, name, index, name)
		}
	}
	if _, err := decodePinnedDigests(p.AllowedApplicationDigests, "Android application"); err != nil {
		return err
	}
	return nil
}

// androidDigestNames maps Keymaster digest enums to policy names. | androidDigestNames 把 Keymaster
// 摘要枚举映射为策略名称。
var androidDigestNames = map[int]string{
	0: "none",
	1: "md5",
	2: "sha1",
	3: "sha224",
	4: "sha256",
	5: "sha384",
	6: "sha512",
}

// androidDigestEnum maps a policy digest name to its Keymaster enum. | androidDigestEnum 把策略摘要
// 名称映射为 Keymaster 枚举。
func androidDigestEnum(name string) (int, bool) {
	normalized := strings.ToLower(strings.TrimSpace(name))
	for value, candidate := range androidDigestNames {
		if candidate == normalized {
			return value, true
		}
	}
	return 0, false
}

// androidCurveBits maps a Keymaster EC curve enum to its field size in bits. | androidCurveBits 把
// Keymaster EC 曲线枚举映射为字段位数。
func androidCurveBits(curve int) (int, bool) {
	switch curve {
	case 0:
		return 224, true
	case 1:
		return 256, true
	case 2:
		return 384, true
	case 3:
		return 521, true
	default:
		return 0, false
	}
}

// androidCurveEnum maps a field size in bits to its Keymaster EC curve enum. | androidCurveEnum 把字段
// 位数映射为 Keymaster EC 曲线枚举。
func androidCurveEnum(bits int) (int, bool) {
	switch bits {
	case 224:
		return 0, true
	case 256:
		return 1, true
	case 384:
		return 2, true
	case 521:
		return 3, true
	default:
		return 0, false
	}
}

// androidKeyProperties describes the strength of an attested public key. | androidKeyProperties
// 描述被认证公钥的强度。
type androidKeyProperties struct {
	// kind is "rsa", "ec" or "other". | kind 为 "rsa"、"ec" 或 "other"。
	kind string
	// bits is the modulus or field size in bits. | bits 是模数或字段位数。
	bits int
}

// androidKeyPropertiesOf reads the strength of a certificate public key. | androidKeyPropertiesOf
// 读取证书公钥的强度。
func androidKeyPropertiesOf(publicKey crypto.PublicKey) androidKeyProperties {
	switch key := publicKey.(type) {
	case *rsa.PublicKey:
		return androidKeyProperties{kind: "rsa", bits: key.N.BitLen()}
	case *ecdsa.PublicKey:
		properties := androidKeyProperties{kind: "ec"}
		if key.Curve != nil && key.Curve.Params() != nil {
			properties.bits = key.Curve.Params().BitSize
		}
		return properties
	default:
		return androidKeyProperties{kind: "other"}
	}
}

// verifyAndroidKeyPolicy applies the configured strength and platform policy. | verifyAndroidKeyPolicy
// 应用配置的强度与平台策略。
func verifyAndroidKeyPolicy(cert *x509.Certificate, software, tee androidAuthorizationList, policy AndroidKeyPolicy) error {
	properties := androidKeyPropertiesOf(cert.PublicKey)
	if err := verifyAndroidKeyStrength(properties, software, tee, policy); err != nil {
		return err
	}
	if err := verifyAndroidKeyDigests(software, tee, policy); err != nil {
		return err
	}
	if err := verifyAndroidKeyPlatform(software, tee, policy); err != nil {
		return err
	}
	return verifyAndroidApplicationDigests(software, tee, policy)
}

// verifyAndroidKeyStrength compares declared keySize and ecCurve values with the actual key. |
// verifyAndroidKeyStrength 把声明的 keySize 与 ecCurve 值和实际密钥比较。
func verifyAndroidKeyStrength(properties androidKeyProperties, software, tee androidAuthorizationList, policy AndroidKeyPolicy) error {
	if policy.MinKeySize > 0 {
		if properties.bits <= 0 || properties.bits < policy.MinKeySize {
			return errs.Detail(ErrInvalidAttestation, "Android key size %d is below the required %d bits | Android 密钥位数 %d 低于要求的 %d 位",
				properties.bits, policy.MinKeySize, properties.bits, policy.MinKeySize)
		}
	}
	declaredSizes := append(append([]int(nil), software.keySizes...), tee.keySizes...)
	for _, declared := range declaredSizes {
		if properties.bits <= 0 || declared != properties.bits {
			return errs.Detail(ErrInvalidAttestation, "Android declared keySize %d does not match the %d-bit certificate key | Android 声明的 keySize %d 与 %d 位证书密钥不一致",
				declared, properties.bits, declared, properties.bits)
		}
	}
	if len(policy.AllowedECCurves) > 0 {
		if properties.kind != "ec" || !containsInt(policy.AllowedECCurves, properties.bits) {
			return errs.Detail(ErrInvalidAttestation, "Android key curve %d bits is not allowed | Android 密钥曲线 %d 位不在允许列表",
				properties.bits, properties.bits)
		}
	}
	declaredCurves := append(append([]int(nil), software.ecCurves...), tee.ecCurves...)
	for _, declared := range declaredCurves {
		bits, ok := androidCurveBits(declared)
		if !ok {
			return errs.Detail(ErrInvalidAttestation, "Android ecCurve %d is unknown | Android ecCurve %d 未知", declared, declared)
		}
		if properties.kind != "ec" || bits != properties.bits {
			return errs.Detail(ErrInvalidAttestation, "Android declared ecCurve %d does not match the certificate key | Android 声明的 ecCurve %d 与证书密钥不一致",
				declared, declared)
		}
	}
	return nil
}

// verifyAndroidKeyDigests enforces the declared digest algorithm allowlist. | verifyAndroidKeyDigests
// 强制已声明摘要算法允许列表。
func verifyAndroidKeyDigests(software, tee androidAuthorizationList, policy AndroidKeyPolicy) error {
	if len(policy.AllowedDigests) == 0 {
		return nil
	}
	declared := append(append([]int(nil), software.digests...), tee.digests...)
	if len(declared) == 0 {
		return errs.Detail(ErrInvalidAttestation, "Android key attestation declares no digest algorithm | Android 密钥认证未声明摘要算法")
	}
	allowed := make([]string, 0, len(policy.AllowedDigests))
	for _, name := range policy.AllowedDigests {
		value, ok := androidDigestEnum(name)
		if !ok {
			return errs.Detail(ErrInvalidConfig, "Android key policy digest %q is unknown | Android 密钥策略摘要 %q 未知", name, name)
		}
		allowed = append(allowed, androidDigestNames[value])
	}
	for _, digest := range declared {
		name, ok := androidDigestNames[digest]
		if !ok || !containsString(allowed, name) {
			return errs.Detail(ErrInvalidAttestation, "Android key digest %d is not allowed | Android 密钥摘要 %d 不在允许列表", digest, digest)
		}
	}
	return nil
}

// verifyAndroidKeyPlatform enforces verified boot, OS version and patch-level policy. |
// verifyAndroidKeyPlatform 强制验证启动、OS 版本与补丁级别策略。
func verifyAndroidKeyPlatform(software, tee androidAuthorizationList, policy AndroidKeyPolicy) error {
	if policy.RequireVerifiedBoot {
		verified := (software.hasVerifiedBootState && software.verifiedBootState == androidVerifiedBootVerified) ||
			(tee.hasVerifiedBootState && tee.verifiedBootState == androidVerifiedBootVerified)
		if !verified {
			return errs.Detail(ErrInvalidAttestation, "Android key attestation does not report a verified boot state | Android 密钥认证未报告已验证的启动状态")
		}
	}
	if policy.MinOSVersion > 0 {
		values, present := androidOSValues(software, tee, false)
		if !present {
			return errs.Detail(ErrInvalidAttestation, "Android key attestation lacks osVersion | Android 密钥认证缺少 osVersion")
		}
		for _, value := range values {
			if value < policy.MinOSVersion {
				return errs.Detail(ErrInvalidAttestation, "Android osVersion %d is below the required %d | Android osVersion %d 低于要求的 %d",
					value, policy.MinOSVersion, value, policy.MinOSVersion)
			}
		}
	}
	if policy.MinOSPatchLevel > 0 {
		values, present := androidOSValues(software, tee, true)
		if !present {
			return errs.Detail(ErrInvalidAttestation, "Android key attestation lacks osPatchLevel | Android 密钥认证缺少 osPatchLevel")
		}
		for _, value := range values {
			if value < policy.MinOSPatchLevel {
				return errs.Detail(ErrInvalidAttestation, "Android osPatchLevel %d is below the required %d | Android osPatchLevel %d 低于要求的 %d",
					value, policy.MinOSPatchLevel, value, policy.MinOSPatchLevel)
			}
		}
	}
	return nil
}

// androidOSValues returns the declared OS version or patch level values. | androidOSValues 返回声明的
// OS 版本或补丁级别值。
func androidOSValues(software, tee androidAuthorizationList, patch bool) ([]int, bool) {
	var values []int
	present := false
	if patch {
		if software.hasOSPatchLevel {
			values = append(values, software.osPatchLevel)
			present = true
		}
		if tee.hasOSPatchLevel {
			values = append(values, tee.osPatchLevel)
			present = true
		}
	} else {
		if software.hasOSVersion {
			values = append(values, software.osVersion)
			present = true
		}
		if tee.hasOSVersion {
			values = append(values, tee.osVersion)
			present = true
		}
	}
	return values, present
}

// verifyAndroidApplicationDigests enforces the AttestationApplicationId signature digest allowlist.
// | verifyAndroidApplicationDigests 强制 AttestationApplicationId 签名摘要允许列表。
func verifyAndroidApplicationDigests(software, tee androidAuthorizationList, policy AndroidKeyPolicy) error {
	if len(policy.AllowedApplicationDigests) == 0 {
		return nil
	}
	allowed, err := decodePinnedDigests(policy.AllowedApplicationDigests, "Android application")
	if err != nil {
		return err
	}
	reported := append(append([][]byte(nil), software.applicationDigests...), tee.applicationDigests...)
	if len(reported) == 0 {
		return errs.Detail(ErrInvalidAttestation, "Android key attestation reports no application signature digests | Android 密钥认证未报告应用签名摘要")
	}
	for index, digest := range reported {
		if !containsDigest(allowed, digest) {
			return errs.Detail(ErrInvalidAttestation, "Android application signature digest %d is not allowed | Android 应用签名摘要 %d 不在允许列表",
				index, index)
		}
	}
	return nil
}
