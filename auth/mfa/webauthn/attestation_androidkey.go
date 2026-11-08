package webauthn

import (
	"context"
	"crypto/x509"
	"encoding/asn1"

	"github.com/shibingli/ydx/errs"
)

// androidKeyAttestationOID is the Android key attestation certificate extension. | androidKeyAttestationOID 是 Android 密钥认证证书扩展。
var androidKeyAttestationOID = asn1.ObjectIdentifier{1, 3, 6, 1, 4, 1, 11129, 2, 1, 17}

// Keymaster values used by the Android key attestation extension. | Android 密钥认证扩展使用的 Keymaster 值。
const (
	kmOriginGenerated = 0
	kmPurposeSign     = 2
)

// Android AuthorizationList tags inspected by the verifier. | 校验器检查的 Android AuthorizationList 标签。
const (
	androidTagPurpose                  = 1
	androidTagKeySize                  = 3
	androidTagDigest                   = 5
	androidTagECCurve                  = 10
	androidTagAllApplications          = 600
	androidTagOrigin                   = 702
	androidTagRootOfTrust              = 704
	androidTagOSVersion                = 705
	androidTagOSPatchLevel             = 706
	androidTagAttestationApplicationID = 709
)

// androidKeyDescription is the parsed Android KeyDescription structure. | androidKeyDescription 是解析后的 Android KeyDescription 结构。
type androidKeyDescription struct {
	// AttestationVersion is the attestation record version. | AttestationVersion 是认证记录版本。
	AttestationVersion int
	// AttestationSecurityLevel is the security level that produced the attestation. | AttestationSecurityLevel 是产生认证声明的安全级别。
	AttestationSecurityLevel asn1.Enumerated
	// KeymasterVersion is the Keymaster or KeyMint version. | KeymasterVersion 是 Keymaster 或 KeyMint 版本。
	KeymasterVersion int
	// KeymasterSecurityLevel is the security level holding the key. | KeymasterSecurityLevel 是保存密钥的安全级别。
	KeymasterSecurityLevel asn1.Enumerated
	// AttestationChallenge is the client data hash bound into the attestation. | AttestationChallenge 是绑定进认证声明的客户端数据哈希。
	AttestationChallenge []byte
	// UniqueID is the optional key unique identifier. | UniqueID 是可选密钥唯一标识。
	UniqueID []byte
	// SoftwareEnforced is the software-enforced AuthorizationList. | SoftwareEnforced 是软件强制的 AuthorizationList。
	SoftwareEnforced asn1.RawValue
	// TEEEnforced is the TEE or hardware-enforced AuthorizationList. | TEEEnforced 是 TEE 或硬件强制的 AuthorizationList。
	TEEEnforced asn1.RawValue
}

// androidAuthorizationList carries the security-relevant fields of an AuthorizationList. | androidAuthorizationList 携带 AuthorizationList 的安全相关字段。
type androidAuthorizationList struct {
	purposes             []int
	packageNames         []string
	applicationDigests   [][]byte
	keySizes             []int
	digests              []int
	ecCurves             []int
	origin               int
	verifiedBootState    int
	osVersion            int
	osPatchLevel         int
	hasOrigin            bool
	hasAllApplications   bool
	hasApplicationID     bool
	hasRootOfTrust       bool
	hasVerifiedBootState bool
	hasOSVersion         bool
	hasOSPatchLevel      bool
}

// verifyAndroidKey implements the android-key attestation format. | verifyAndroidKey 实现 android-key 认证声明格式。
func (o *AttestationObject) verifyAndroidKey(ctx context.Context, result *AttestationResult, clientDataHash []byte, opts AttestationOptions) error {
	alg, err := attestationStatementInt(o.AttStmt, "alg")
	if err != nil {
		return err
	}
	if _, ok := HashForAlgorithm(alg); !ok {
		return errs.Detail(ErrUnsupportedAlgorithm, "android-key attestation algorithm %d | android-key 认证声明算法 %d", alg, alg)
	}
	signature, err := attestationStatementBytes(o.AttStmt, "sig")
	if err != nil {
		return err
	}
	x5c, present, err := attestationStatementX5C(o.AttStmt)
	if err != nil {
		return err
	}
	if !present {
		return errs.Detail(ErrInvalidAttestation, "android-key attestation lacks x5c | android-key 认证声明缺少 x5c")
	}
	certs, err := parseX5C(x5c)
	if err != nil {
		return err
	}
	leaf := certs[0]
	key, err := attestationCredentialPublicKey(o.AuthData)
	if err != nil {
		return err
	}
	credentialPublicKey, err := key.PublicKey()
	if err != nil {
		return err
	}
	if !samePublicKey(leaf.PublicKey, credentialPublicKey) {
		return errs.Detail(ErrInvalidAttestation, "android-key certificate public key differs from the credential key | android-key 证书公钥与凭据密钥不一致")
	}
	signed := signedAttestationData(o.AuthDataRaw, clientDataHash)
	if err := VerifySignature(alg, leaf.PublicKey, signed, signature); err != nil {
		return errs.WrapDetail(err, ErrSignatureInvalid, "android-key attestation signature is invalid | android-key 认证声明签名无效")
	}
	expectedPackage := opts.expectedAndroidPackageName()
	if opts.AndroidKeyVerifier != nil {
		trustVerified, err := opts.AndroidKeyVerifier.VerifyAndroidKey(ctx, certs, AndroidKeyVerifyOptions{
			ClientDataHash:      append([]byte(nil), clientDataHash...),
			AuthData:            append([]byte(nil), o.AuthDataRaw...),
			ExpectedPackageName: expectedPackage,
		})
		if err != nil {
			return errs.WrapDetail(err, ErrUntrustedAttestation, "custom android-key verifier rejected the attestation | 自定义 android-key 校验器拒绝了认证声明")
		}
		// A custom verifier adds checks; a non-zero policy still applies afterwards so configured
		// policy cannot be silently disabled. | 自定义校验器只增加校验；非零策略随后仍会执行，因此已配置
		// 策略不能被静默关闭。
		if !opts.AndroidKeyPolicy.isZero() {
			if err := verifyAndroidKeyExtensionWithPolicy(leaf, clientDataHash, expectedPackage, opts.AndroidKeyPolicy); err != nil {
				return err
			}
		}
		result.Type = AttestationTypeBasic
		result.TrustPath = certs
		result.TrustVerified = trustVerified
		return nil
	}
	if err := verifyAndroidKeyExtensionWithPolicy(leaf, clientDataHash, expectedPackage, opts.AndroidKeyPolicy); err != nil {
		return err
	}
	verified, err := verifyCertificateChain(certs, opts.withAndroidKeyRoots())
	if err != nil {
		return err
	}
	result.Type = AttestationTypeBasic
	result.TrustPath = certs
	result.TrustVerified = verified
	return nil
}

// verifyAndroidKeyExtension checks the Android key attestation certificate extension with the
// baseline policy. | verifyAndroidKeyExtension 使用基线策略校验 Android 密钥认证证书扩展。
func verifyAndroidKeyExtension(cert *x509.Certificate, clientDataHash []byte, expectedPackage string) error {
	return verifyAndroidKeyExtensionWithPolicy(cert, clientDataHash, expectedPackage, AndroidKeyPolicy{})
}

// verifyAndroidKeyExtensionWithPolicy checks the Android key attestation certificate extension and
// applies policy after the baseline checks. | verifyAndroidKeyExtensionWithPolicy 校验 Android 密钥
// 认证证书扩展，并在基线校验后应用 policy。
func verifyAndroidKeyExtensionWithPolicy(cert *x509.Certificate, clientDataHash []byte, expectedPackage string, policy AndroidKeyPolicy) error {
	if err := policy.validate(); err != nil {
		return err
	}
	value, ok := certificateExtension(cert, androidKeyAttestationOID)
	if !ok {
		return errs.Detail(ErrInvalidAttestation, "certificate lacks the Android key attestation extension | 证书缺少 Android 密钥认证扩展")
	}
	var description androidKeyDescription
	rest, err := asn1.Unmarshal(value, &description)
	if err != nil || len(rest) != 0 {
		return errs.Detail(ErrInvalidAttestation, "Android key attestation extension is malformed | Android 密钥认证扩展格式非法")
	}
	if !constantTimeEqual(description.AttestationChallenge, clientDataHash) {
		return errs.Detail(ErrInvalidAttestation, "Android key attestation challenge mismatch | Android 密钥认证挑战不匹配")
	}
	software, err := parseAndroidAuthorizationList(description.SoftwareEnforced)
	if err != nil {
		return err
	}
	tee, err := parseAndroidAuthorizationList(description.TEEEnforced)
	if err != nil {
		return err
	}
	if (software.hasAllApplications || tee.hasAllApplications) && !policy.AllowAllApplications {
		return errs.Detail(ErrInvalidAttestation, "Android key attestation allows all applications | Android 密钥认证允许所有应用")
	}
	if !software.hasOrigin && !tee.hasOrigin {
		return errs.Detail(ErrInvalidAttestation, "Android key attestation lacks an origin | Android 密钥认证缺少 origin")
	}
	if software.hasOrigin && software.origin != kmOriginGenerated {
		return errs.Detail(ErrInvalidAttestation, "Android key origin %d is not KM_ORIGIN_GENERATED | Android 密钥 origin %d 不是 KM_ORIGIN_GENERATED",
			software.origin, software.origin)
	}
	if tee.hasOrigin && tee.origin != kmOriginGenerated {
		return errs.Detail(ErrInvalidAttestation, "Android key origin %d is not KM_ORIGIN_GENERATED | Android 密钥 origin %d 不是 KM_ORIGIN_GENERATED",
			tee.origin, tee.origin)
	}
	if !containsInt(software.purposes, kmPurposeSign) && !containsInt(tee.purposes, kmPurposeSign) {
		return errs.Detail(ErrInvalidAttestation, "Android key is not authorized for signing | Android 密钥未授权用于签名")
	}
	if expectedPackage != "" {
		if !software.hasApplicationID && !tee.hasApplicationID {
			return errs.Detail(ErrInvalidAttestation, "Android key attestation lacks an attestationApplicationId for package %q | Android 密钥认证缺少包 %q 的 attestationApplicationId",
				expectedPackage, expectedPackage)
		}
		if !containsString(software.packageNames, expectedPackage) && !containsString(tee.packageNames, expectedPackage) {
			return errs.Detail(ErrInvalidAttestation, "Android key attestation application ID does not match package %q | Android 密钥认证应用 ID 与包 %q 不匹配",
				expectedPackage, expectedPackage)
		}
	}
	return verifyAndroidKeyPolicy(cert, software, tee, policy)
}

// parseAndroidAuthorizationList parses the security-relevant fields of an AuthorizationList. |
// parseAndroidAuthorizationList 解析 AuthorizationList 的安全相关字段。
//
// The AOSP schema declares every field EXPLICIT, so origin [702] wraps an INTEGER and
// attestationApplicationId [709] wraps an OCTET STRING. Legacy implicit encodings produced by
// earlier versions of this package are still accepted. | AOSP 模式把每个字段声明为 EXPLICIT，
// 因此 origin [702] 包裹 INTEGER，attestationApplicationId [709] 包裹 OCTET STRING。本包早期版本
// 产生的旧式隐式编码仍会被接受。
func parseAndroidAuthorizationList(raw asn1.RawValue) (androidAuthorizationList, error) {
	var list androidAuthorizationList
	if len(raw.FullBytes) == 0 {
		return list, nil
	}
	elements, err := derElements(raw.Bytes)
	if err != nil {
		return list, errs.WrapDetail(err, ErrInvalidAttestation, "Android authorization list is malformed | Android 授权列表格式非法")
	}
	for _, element := range elements {
		if element.class != derClassContext {
			continue
		}
		switch element.tag {
		case androidTagPurpose:
			purposes, err := parseAndroidPurposes(element.content)
			if err != nil {
				return list, err
			}
			list.purposes = append(list.purposes, purposes...)
		case androidTagKeySize:
			keySize, err := parseAndroidExplicitInt(element.content, "keySize")
			if err != nil {
				return list, err
			}
			list.keySizes = append(list.keySizes, keySize)
		case androidTagDigest:
			digests, err := parseAndroidEnumSet(element.content, "digest")
			if err != nil {
				return list, err
			}
			list.digests = append(list.digests, digests...)
		case androidTagECCurve:
			curve, err := parseAndroidExplicitInt(element.content, "ecCurve")
			if err != nil {
				return list, err
			}
			list.ecCurves = append(list.ecCurves, curve)
		case androidTagAllApplications:
			list.hasAllApplications = true
		case androidTagOrigin:
			origin, err := parseAndroidExplicitInt(element.content, "origin")
			if err != nil {
				return list, err
			}
			list.hasOrigin = true
			list.origin = origin
		case androidTagRootOfTrust:
			root, err := parseAndroidRootOfTrust(element.content)
			if err != nil {
				return list, err
			}
			list.hasRootOfTrust = true
			if root.hasVerifiedBootState {
				list.hasVerifiedBootState = true
				list.verifiedBootState = root.verifiedBootState
			}
		case androidTagOSVersion:
			version, err := parseAndroidExplicitInt(element.content, "osVersion")
			if err != nil {
				return list, err
			}
			list.hasOSVersion = true
			list.osVersion = version
		case androidTagOSPatchLevel:
			patchLevel, err := parseAndroidExplicitInt(element.content, "osPatchLevel")
			if err != nil {
				return list, err
			}
			list.hasOSPatchLevel = true
			list.osPatchLevel = patchLevel
		case androidTagAttestationApplicationID:
			content := element.content
			if inner, ok := explicitAndroidElement(content, derTagOctetString); ok {
				content = inner.content
			}
			applicationID, err := parseAndroidAttestationApplicationIDFull(content)
			if err != nil {
				return list, err
			}
			list.hasApplicationID = true
			list.packageNames = append(list.packageNames, applicationID.packageNames...)
			list.applicationDigests = append(list.applicationDigests, applicationID.signatureDigests...)
		}
	}
	return list, nil
}

// explicitAndroidElement unwraps the single universal element of an EXPLICIT context-specific
// field. It reports false when content is not exactly one element with the wanted tag. |
// explicitAndroidElement 解包 EXPLICIT 上下文特定字段中的单个通用元素。content 不是恰好一个指定
// 标签的元素时返回 false。
func explicitAndroidElement(content []byte, tag int) (derElement, bool) {
	inner, rest, err := parseDERElement(content)
	if err != nil || len(rest) != 0 || inner.class != derClassUniversal || inner.tag != tag {
		return derElement{}, false
	}
	return inner, true
}

// parseAndroidExplicitInt parses an INTEGER wrapped in an EXPLICIT context-specific field, while
// still accepting the legacy implicit encoding. | parseAndroidExplicitInt 解析 EXPLICIT 上下文特定字段
// 包裹的 INTEGER，同时仍接受旧式隐式编码。
func parseAndroidExplicitInt(content []byte, field string) (int, error) {
	if inner, ok := explicitAndroidElement(content, derTagInteger); ok {
		content = inner.content
	}
	value, err := parseDERPositiveInt(content)
	if err != nil {
		return 0, errs.WrapDetail(err, ErrInvalidAttestation, "Android authorization %s is malformed | Android 授权 %s 格式非法", field, field)
	}
	return value, nil
}

// parseAndroidPurposes parses the SET OF INTEGER in the purpose field. | parseAndroidPurposes 解析 purpose 字段中的 SET OF INTEGER。
func parseAndroidPurposes(content []byte) ([]int, error) {
	return parseAndroidEnumSet(content, "purpose")
}

// parseAndroidEnumSet parses a SET OF INTEGER in an AuthorizationList field. | parseAndroidEnumSet
// 解析 AuthorizationList 字段中的 SET OF INTEGER。
func parseAndroidEnumSet(content []byte, field string) ([]int, error) {
	set, rest, err := parseDERElement(content)
	if err != nil || len(rest) != 0 || set.class != derClassUniversal || set.tag != derTagSet {
		return nil, errs.Detail(ErrInvalidAttestation, "Android %s is not a SET | Android %s 不是 SET", field, field)
	}
	elements, err := derElements(set.content)
	if err != nil {
		return nil, errs.WrapDetail(err, ErrInvalidAttestation, "Android %s SET is malformed | Android %s SET 格式非法", field, field)
	}
	values := make([]int, 0, len(elements))
	for _, element := range elements {
		if element.class != derClassUniversal || element.tag != derTagInteger {
			return nil, errs.Detail(ErrInvalidAttestation, "Android %s entry is not an INTEGER | Android %s 条目不是 INTEGER", field, field)
		}
		value, err := parseDERPositiveInt(element.content)
		if err != nil {
			return nil, errs.WrapDetail(err, ErrInvalidAttestation, "Android %s entry is negative or malformed | Android %s 条目为负数或格式非法", field, field)
		}
		values = append(values, value)
	}
	return values, nil
}

// androidRootOfTrust carries the parsed rootOfTrust fields used by the policy. | androidRootOfTrust
// 携带策略使用的已解析 rootOfTrust 字段。
type androidRootOfTrust struct {
	verifiedBootState    int
	hasVerifiedBootState bool
}

// parseAndroidRootOfTrust parses an EXPLICIT RootOfTrust sequence. The AOSP schema is
// SEQUENCE { verifiedBootKey OCTET STRING, deviceLocked BOOLEAN, verifiedBootState ENUMERATED,
// verifiedBootHash OCTET STRING OPTIONAL }. | parseAndroidRootOfTrust 解析 EXPLICIT RootOfTrust 序列。
// AOSP 模式为 SEQUENCE { verifiedBootKey OCTET STRING, deviceLocked BOOLEAN, verifiedBootState
// ENUMERATED, verifiedBootHash OCTET STRING OPTIONAL }。
func parseAndroidRootOfTrust(content []byte) (androidRootOfTrust, error) {
	var root androidRootOfTrust
	if inner, ok := explicitAndroidElement(content, derTagSequence); ok {
		content = inner.content
	}
	elements, err := derElements(content)
	if err != nil || len(elements) < 3 || len(elements) > 4 {
		return root, errs.Detail(ErrInvalidAttestation, "Android rootOfTrust is malformed | Android rootOfTrust 格式非法")
	}
	if elements[0].class != derClassUniversal || elements[0].tag != derTagOctetString ||
		elements[1].class != derClassUniversal || elements[1].tag != derTagBoolean || len(elements[1].content) != 1 ||
		elements[2].class != derClassUniversal || elements[2].tag != derTagEnumerated {
		return root, errs.Detail(ErrInvalidAttestation, "Android rootOfTrust fields are malformed | Android rootOfTrust 字段格式非法")
	}
	if len(elements) == 4 &&
		(elements[3].class != derClassUniversal || elements[3].tag != derTagOctetString) {
		return root, errs.Detail(ErrInvalidAttestation, "Android rootOfTrust hash is malformed | Android rootOfTrust 哈希格式非法")
	}
	state, err := parseDERPositiveInt(elements[2].content)
	if err != nil {
		return root, errs.WrapDetail(err, ErrInvalidAttestation, "Android rootOfTrust verifiedBootState is malformed | Android rootOfTrust verifiedBootState 格式非法")
	}
	root.verifiedBootState = state
	root.hasVerifiedBootState = true
	return root, nil
}

// parseAndroidAttestationApplicationID parses the package names in an AttestationApplicationId. |
// parseAndroidAttestationApplicationID 解析 AttestationApplicationId 中的包名。
func parseAndroidAttestationApplicationID(content []byte) ([]string, error) {
	applicationID, err := parseAndroidAttestationApplicationIDFull(content)
	if err != nil {
		return nil, err
	}
	return applicationID.packageNames, nil
}

// androidAttestationApplicationID carries the parsed package names and signature digests. |
// androidAttestationApplicationID 携带已解析的包名与签名摘要。
type androidAttestationApplicationID struct {
	packageNames     []string
	signatureDigests [][]byte
}

// parseAndroidAttestationApplicationIDFull parses an AttestationApplicationId. |
// parseAndroidAttestationApplicationIDFull 解析 AttestationApplicationId。
//
// The DER structure is SEQUENCE { SEQUENCE OF PackageInfo, SEQUENCE OF OCTET STRING }, where
// PackageInfo is SEQUENCE { packageName OCTET STRING, version INTEGER }. | DER 结构为
// SEQUENCE { SEQUENCE OF PackageInfo, SEQUENCE OF OCTET STRING }，其中 PackageInfo 为
// SEQUENCE { packageName OCTET STRING, version INTEGER }。
func parseAndroidAttestationApplicationIDFull(content []byte) (androidAttestationApplicationID, error) {
	var applicationID androidAttestationApplicationID
	sequence, rest, err := parseDERElement(content)
	if err != nil || len(rest) != 0 || sequence.class != derClassUniversal || sequence.tag != derTagSequence {
		return applicationID, errs.Detail(ErrInvalidAttestation, "Android attestationApplicationId is not a SEQUENCE | Android attestationApplicationId 不是 SEQUENCE")
	}
	fields, err := derElements(sequence.content)
	if err != nil {
		return applicationID, errs.WrapDetail(err, ErrInvalidAttestation, "Android attestationApplicationId is malformed | Android attestationApplicationId 格式非法")
	}
	if len(fields) != 2 ||
		fields[0].class != derClassUniversal || fields[0].tag != derTagSequence ||
		fields[1].class != derClassUniversal || fields[1].tag != derTagSequence {
		return applicationID, errs.Detail(ErrInvalidAttestation, "Android attestationApplicationId lacks package infos or signature digests | Android attestationApplicationId 缺少包信息或签名摘要")
	}
	infoElements, err := derElements(fields[0].content)
	if err != nil {
		return applicationID, errs.WrapDetail(err, ErrInvalidAttestation, "Android attestationApplicationId package infos are malformed | Android attestationApplicationId 包信息格式非法")
	}
	if len(infoElements) == 0 {
		return applicationID, errs.Detail(ErrInvalidAttestation, "Android attestationApplicationId has no package infos | Android attestationApplicationId 没有包信息")
	}
	applicationID.packageNames = make([]string, 0, len(infoElements))
	for _, info := range infoElements {
		if info.class != derClassUniversal || info.tag != derTagSequence {
			return applicationID, errs.Detail(ErrInvalidAttestation, "Android package info is not a SEQUENCE | Android 包信息不是 SEQUENCE")
		}
		parts, err := derElements(info.content)
		if err != nil {
			return applicationID, errs.WrapDetail(err, ErrInvalidAttestation, "Android package info is malformed | Android 包信息格式非法")
		}
		if len(parts) != 2 ||
			parts[0].class != derClassUniversal || parts[0].tag != derTagOctetString ||
			parts[1].class != derClassUniversal || parts[1].tag != derTagInteger {
			return applicationID, errs.Detail(ErrInvalidAttestation, "Android package info lacks a name or version | Android 包信息缺少名称或版本")
		}
		if len(parts[0].content) == 0 {
			return applicationID, errs.Detail(ErrInvalidAttestation, "Android package name is empty | Android 包名为空")
		}
		if _, err := parseDERPositiveInt(parts[1].content); err != nil {
			return applicationID, errs.WrapDetail(err, ErrInvalidAttestation, "Android package version is malformed | Android 包版本格式非法")
		}
		applicationID.packageNames = append(applicationID.packageNames, string(parts[0].content))
	}
	digests, err := derElements(fields[1].content)
	if err != nil {
		return applicationID, errs.WrapDetail(err, ErrInvalidAttestation, "Android signature digests are malformed | Android 签名摘要格式非法")
	}
	for _, digest := range digests {
		if digest.class != derClassUniversal || digest.tag != derTagOctetString || len(digest.content) == 0 {
			return applicationID, errs.Detail(ErrInvalidAttestation, "Android signature digest is not a non-empty OCTET STRING | Android 签名摘要不是非空 OCTET STRING")
		}
		applicationID.signatureDigests = append(applicationID.signatureDigests, append([]byte(nil), digest.content...))
	}
	return applicationID, nil
}

// containsString reports whether values contains want. | containsString 报告 values 是否包含 want。
func containsString(values []string, want string) bool {
	for _, value := range values {
		if value == want {
			return true
		}
	}
	return false
}
