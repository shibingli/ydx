package webauthn

import (
	"context"
	"crypto/sha256"
	"crypto/x509"
	"strings"
	"time"

	"github.com/shibingli/ydx/base64"
	"github.com/shibingli/ydx/errs"
	"github.com/shibingli/ydx/json"
)

// verifyAndroidSafetyNet implements the android-safetynet attestation format. | verifyAndroidSafetyNet 实现 android-safetynet 认证声明格式。
func (o *AttestationObject) verifyAndroidSafetyNet(ctx context.Context, result *AttestationResult, clientDataHash []byte, opts AttestationOptions) error {
	version, err := attestationStatementText(o.AttStmt, "ver")
	if err != nil {
		return err
	}
	response, err := attestationStatementBytes(o.AttStmt, "response")
	if err != nil {
		return err
	}
	jws, err := parseSafetyNetJWS(response)
	if err != nil {
		return err
	}
	expectedNonce := sha256.Sum256(signedAttestationData(o.AuthDataRaw, clientDataHash))
	if opts.SafetyNetVerifier != nil {
		if err := opts.SafetyNetVerifier.VerifySafetyNet(ctx, response, expectedNonce[:]); err != nil {
			return errs.WrapDetail(err, ErrUntrustedAttestation, "SafetyNet verifier rejected the response | SafetyNet 校验器拒绝了响应")
		}
		verified, err := verifySafetyNetTrust(jws.certs, opts)
		if err != nil {
			return err
		}
		result.Type = AttestationTypeBasic
		result.TrustPath = jws.certs
		result.TrustVerified = verified
		return nil
	}
	policy := opts.SafetyNetPolicy
	if err := policy.validate(); err != nil {
		return err
	}
	if err := verifySafetyNetJWSPolicy(jws, expectedNonce[:], policy); err != nil {
		return err
	}
	if len(policy.AllowedVersions) > 0 && !containsString(policy.AllowedVersions, version) {
		return errs.Detail(ErrInvalidAttestation, "SafetyNet version %q is not allowed | SafetyNet ver %q 不在允许列表", version, version)
	}
	expectedPackage := opts.expectedAndroidPackageName()
	if expectedPackage != "" && jws.payload.APKPackageName != expectedPackage {
		return errs.Detail(ErrInvalidAttestation, "SafetyNet APK package %q does not match expected package %q | SafetyNet APK 包名 %q 与期望包名 %q 不匹配",
			jws.payload.APKPackageName, expectedPackage, jws.payload.APKPackageName, expectedPackage)
	}
	now := opts.currentTime()
	attested := time.UnixMilli(jws.payload.TimestampMs)
	window := policy.timestampTolerance()
	if attested.Before(now.Add(-window)) || attested.After(now.Add(window)) {
		return errs.Detail(ErrInvalidAttestation, "SafetyNet timestamp is outside the %s window | SafetyNet 时间戳超出 %s 窗口", window, window)
	}
	verified, err := verifyCertificateChain(jws.certs, opts.withSafetyNetRoots())
	if err != nil {
		return err
	}
	result.Type = AttestationTypeBasic
	result.TrustPath = jws.certs
	result.TrustVerified = verified
	return nil
}

// verifySafetyNetTrust chains the JWS certificates when a SafetyNet or generic root pool is
// configured. A custom SafetyNetVerifier replaces the built-in JWS checks but never silently
// discards configured trust anchors. | verifySafetyNetTrust 在配置 SafetyNet 或通用信任池时校验 JWS
// 证书链。自定义 SafetyNetVerifier 替换内置 JWS 校验，但绝不静默丢弃已配置的信任锚。
func verifySafetyNetTrust(certs []*x509.Certificate, opts AttestationOptions) (bool, error) {
	if opts.SafetyNetRoots == nil && opts.Roots == nil {
		return false, nil
	}
	return verifyCertificateChain(certs, opts.withSafetyNetRoots())
}

// safetyNetPayload is the JWS payload of an Android SafetyNet response. | safetyNetPayload 是 Android SafetyNet 响应的 JWS 载荷。
type safetyNetPayload struct {
	// Nonce is the base64-encoded nonce echoed from the request. | Nonce 是请求回显的 base64 编码 nonce。
	Nonce string `json:"nonce"`
	// TimestampMs is the attestation time in Unix milliseconds. | TimestampMs 是 Unix 毫秒表示的认证时间。
	TimestampMs int64 `json:"timestampMs"`
	// APKPackageName is the package whose integrity was attested. | APKPackageName 是被认证完整性的包名。
	APKPackageName string `json:"apkPackageName"`
	// APKCertificateDigestSHA holds the SHA-256 certificate digests of the APK. | APKCertificateDigestSHA 保存 APK 证书的 SHA-256 摘要。
	APKCertificateDigestSHA []string `json:"apkCertificateDigestSha256"`
	// CTSProfileMatch reports whether the device passed CTS compatibility testing. | CTSProfileMatch 报告设备是否通过 CTS 兼容性测试。
	CTSProfileMatch bool `json:"ctsProfileMatch"`
	// BasicIntegrity reports whether the device passed the basic integrity check. | BasicIntegrity 报告设备是否通过基本完整性检查。
	BasicIntegrity bool `json:"basicIntegrity"`
	// EvaluationType is the SafetyNet evaluation type. | EvaluationType 是 SafetyNet 评估类型。
	EvaluationType string `json:"evaluationType"`
}

// safetyNetJWS is a parsed SafetyNet JWS. | safetyNetJWS 是解析后的 SafetyNet JWS。
type safetyNetJWS struct {
	header      safetyNetHeader
	payload     safetyNetPayload
	certs       []*x509.Certificate
	signedInput []byte
	signature   []byte
}

// safetyNetHeader is the JWS protected header of a SafetyNet response. | safetyNetHeader 是 SafetyNet 响应的 JWS 保护头。
type safetyNetHeader struct {
	// Alg is the JWS signature algorithm name. | Alg 是 JWS 签名算法名称。
	Alg string `json:"alg"`
	// X5C is the base64 certificate chain. | X5C 是 base64 证书链。
	X5C []string `json:"x5c"`
}

// parseSafetyNetJWS parses the compact JWS of a SafetyNet response. | parseSafetyNetJWS 解析 SafetyNet 响应的紧凑 JWS。
func parseSafetyNetJWS(response []byte) (*safetyNetJWS, error) {
	parts := strings.Split(string(response), ".")
	if len(parts) != 3 {
		return nil, errs.Detail(ErrInvalidAttestation, "SafetyNet response is not a compact JWS | SafetyNet 响应不是紧凑 JWS")
	}
	headerBytes, err := base64.RawURLEncoding.DecodeString(parts[0])
	if err != nil {
		return nil, errs.WrapDetail(err, ErrInvalidAttestation, "SafetyNet JWS header is not base64url | SafetyNet JWS 头不是 base64url")
	}
	var header safetyNetHeader
	if err := json.Unmarshal(headerBytes, &header); err != nil {
		return nil, errs.WrapDetail(err, ErrInvalidAttestation, "SafetyNet JWS header is not JSON | SafetyNet JWS 头不是 JSON")
	}
	if header.Alg == "" {
		return nil, errs.Detail(ErrInvalidAttestation, "SafetyNet JWS header lacks alg | SafetyNet JWS 头缺少 alg")
	}
	payloadBytes, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		return nil, errs.WrapDetail(err, ErrInvalidAttestation, "SafetyNet JWS payload is not base64url | SafetyNet JWS 载荷不是 base64url")
	}
	var payload safetyNetPayload
	if err := json.Unmarshal(payloadBytes, &payload); err != nil {
		return nil, errs.WrapDetail(err, ErrInvalidAttestation, "SafetyNet JWS payload is not JSON | SafetyNet JWS 载荷不是 JSON")
	}
	signature, err := base64.RawURLEncoding.DecodeString(parts[2])
	if err != nil {
		return nil, errs.WrapDetail(err, ErrInvalidAttestation, "SafetyNet JWS signature is not base64url | SafetyNet JWS 签名不是 base64url")
	}
	certs := make([]*x509.Certificate, 0, len(header.X5C))
	if len(header.X5C) == 0 || len(header.X5C) > maxAttestationCertificates {
		return nil, errs.Detail(ErrInvalidAttestation, "SafetyNet JWS has %d certificates | SafetyNet JWS 包含 %d 张证书", len(header.X5C), len(header.X5C))
	}
	for i, encoded := range header.X5C {
		der, err := base64.StdEncoding.DecodeString(encoded)
		if err != nil {
			return nil, errs.WrapDetail(err, ErrInvalidAttestation, "SafetyNet x5c entry %d is not base64 | SafetyNet x5c 第 %d 项不是 base64", i, i)
		}
		cert, err := x509.ParseCertificate(der)
		if err != nil {
			return nil, errs.WrapDetail(err, ErrInvalidAttestation, "SafetyNet x5c entry %d is not a certificate | SafetyNet x5c 第 %d 项不是证书", i, i)
		}
		certs = append(certs, cert)
	}
	return &safetyNetJWS{
		header:      header,
		payload:     payload,
		certs:       certs,
		signedInput: []byte(parts[0] + "." + parts[1]),
		signature:   signature,
	}, nil
}

// verifySafetyNetJWS verifies the JWS signature and the SafetyNet verdict. | verifySafetyNetJWS 校验 JWS 签名与 SafetyNet 判定。
func verifySafetyNetJWS(jws *safetyNetJWS, expectedNonce []byte) error {
	alg, ok := jwsAlgorithm(jws.header.Alg)
	if !ok {
		return errs.Detail(ErrUnsupportedAlgorithm, "SafetyNet algorithm %q | SafetyNet 算法 %q", jws.header.Alg, jws.header.Alg)
	}
	if err := VerifySignature(alg, jws.certs[0].PublicKey, jws.signedInput, jws.signature); err != nil {
		return errs.WrapDetail(err, ErrSignatureInvalid, "SafetyNet JWS signature is invalid | SafetyNet JWS 签名无效")
	}
	nonce, err := decodeStandardBase64(jws.payload.Nonce)
	if err != nil {
		return errs.WrapDetail(err, ErrInvalidAttestation, "SafetyNet nonce is not base64 | SafetyNet nonce 不是 base64")
	}
	if !constantTimeEqual(nonce, expectedNonce) {
		return errs.Detail(ErrInvalidAttestation, "SafetyNet nonce mismatch | SafetyNet nonce 不匹配")
	}
	if !jws.payload.CTSProfileMatch {
		return errs.Detail(ErrInvalidAttestation, "SafetyNet ctsProfileMatch is false | SafetyNet ctsProfileMatch 为 false")
	}
	return nil
}

// jwsAlgorithm maps a JWS alg name to a COSE algorithm. | jwsAlgorithm 把 JWS alg 名称映射为 COSE 算法。
func jwsAlgorithm(name string) (int, bool) {
	switch name {
	case "RS256":
		return AlgRS256, true
	case "RS384":
		return AlgRS384, true
	case "RS512":
		return AlgRS512, true
	case "PS256":
		return AlgPS256, true
	case "PS384":
		return AlgPS384, true
	case "PS512":
		return AlgPS512, true
	case "ES256":
		return AlgES256, true
	case "ES384":
		return AlgES384, true
	case "ES512":
		return AlgES512, true
	default:
		return 0, false
	}
}

// decodeStandardBase64 decodes padded or unpadded standard base64. | decodeStandardBase64 解码带填充或无填充的标准 base64。
func decodeStandardBase64(s string) ([]byte, error) {
	out, err := base64.StdEncoding.DecodeString(s)
	if err == nil {
		return out, nil
	}
	return base64.RawStdEncoding.DecodeString(s)
}
