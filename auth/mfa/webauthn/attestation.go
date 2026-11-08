package webauthn

import (
	"context"
	"crypto"
	"crypto/sha256"
	"crypto/x509"
	"encoding/asn1"
	"strings"
	"time"

	"github.com/shibingli/ydx/errs"
)

// Attestation statement format identifiers defined by WebAuthn. | WebAuthn 定义的认证声明格式标识。
const (
	// FormatNone is the none attestation format. | FormatNone 是 none 认证声明格式。
	FormatNone = "none"
	// FormatPacked is the packed attestation format. | FormatPacked 是 packed 认证声明格式。
	FormatPacked = "packed"
	// FormatFIDOU2F is the fido-u2f attestation format. | FormatFIDOU2F 是 fido-u2f 认证声明格式。
	FormatFIDOU2F = "fido-u2f"
	// FormatAndroidKey is the android-key attestation format. | FormatAndroidKey 是 android-key 认证声明格式。
	FormatAndroidKey = "android-key"
	// FormatAndroidSafetyNet is the android-safetynet attestation format. | FormatAndroidSafetyNet 是 android-safetynet 认证声明格式。
	FormatAndroidSafetyNet = "android-safetynet"
	// FormatTPM is the tpm attestation format. | FormatTPM 是 tpm 认证声明格式。
	FormatTPM = "tpm"
	// FormatApple is the apple attestation format. | FormatApple 是 apple 认证声明格式。
	FormatApple = "apple"
	// FormatECDA is the ecdaa attestation format. | FormatECDA 是 ecdaa 认证声明格式。
	FormatECDA = "ecdaa"
)

// AttestationType classifies the trust conveyed by an attestation statement. | AttestationType 对认证声明承载的信任进行分类。
type AttestationType string

// The attestation types defined by WebAuthn. | WebAuthn 定义的认证声明类型。
const (
	// AttestationTypeNone conveys no attestation information. | AttestationTypeNone 不承载认证声明信息。
	AttestationTypeNone AttestationType = "none"
	// AttestationTypeSelf is self attestation by the credential key. | AttestationTypeSelf 是由凭据密钥完成的自认证。
	AttestationTypeSelf AttestationType = "self"
	// AttestationTypeBasic is attestation by an authenticator certificate. | AttestationTypeBasic 是由认证器证书完成的认证。
	AttestationTypeBasic AttestationType = "basic"
	// AttestationTypeAttCA is attestation by an attestation CA. | AttestationTypeAttCA 是由认证声明 CA 完成的认证。
	AttestationTypeAttCA AttestationType = "attca"
	// AttestationTypeAnonCA is attestation backed by an anonymization CA. | AttestationTypeAnonCA 是由匿名化 CA 支撑的认证。
	AttestationTypeAnonCA AttestationType = "anonca"
)

// maxAttestationCertificates bounds the x5c chain length. | maxAttestationCertificates 限制 x5c 链长度。
const maxAttestationCertificates = 8

// SafetyNetVerifier verifies an Android SafetyNet response with caller-supplied policy. | SafetyNetVerifier 使用调用方策略校验 Android SafetyNet 响应。
//
// This package never performs network requests. Supply a verifier when the JWS must be checked
// against Google's online attestation service; expectedNonce is SHA-256(authenticatorData ||
// clientDataHash). | 本包从不发起网络请求。若需要用 Google 在线认证服务校验 JWS，请提供实现；
// expectedNonce 为 SHA-256(authenticatorData || clientDataHash)。
type SafetyNetVerifier interface {
	// VerifySafetyNet verifies response against expectedNonce. | VerifySafetyNet 使用 expectedNonce 校验 response。
	VerifySafetyNet(ctx context.Context, response, expectedNonce []byte) error
}

// SafetyNetVerifierFunc adapts a function to SafetyNetVerifier. | SafetyNetVerifierFunc 把函数适配为 SafetyNetVerifier。
type SafetyNetVerifierFunc func(ctx context.Context, response, expectedNonce []byte) error

// VerifySafetyNet implements SafetyNetVerifier. | VerifySafetyNet 实现 SafetyNetVerifier。
func (f SafetyNetVerifierFunc) VerifySafetyNet(ctx context.Context, response, expectedNonce []byte) error {
	return f(ctx, response, expectedNonce)
}

// AndroidKeyVerifier overrides the built-in android-key KeyDescription and trust checks. |
// AndroidKeyVerifier 覆盖内置 android-key KeyDescription 与信任校验。
//
// The package still verifies the attestation signature and that the leaf certificate public key
// equals the credential key before calling the verifier. The verifier owns the Android Key
// extension checks (challenge, origin, purpose, package name) and any certificate-chain decision;
// its trustVerified result is copied to AttestationResult.TrustVerified, and a non-nil error
// rejects the attestation. | 调用校验器前，本包仍校验认证声明签名以及叶证书公钥是否等于凭据公钥。
// 校验器负责 Android 密钥扩展校验（挑战、origin、purpose、包名）以及任意证书链判定；其
// trustVerified 结果会复制到 AttestationResult.TrustVerified，非空错误会拒绝该认证声明。
type AndroidKeyVerifier interface {
	// VerifyAndroidKey verifies certs and reports whether they were trusted. | VerifyAndroidKey 校验 certs 并报告是否受信任。
	VerifyAndroidKey(ctx context.Context, certs []*x509.Certificate, opts AndroidKeyVerifyOptions) (trustVerified bool, err error)
}

// AndroidKeyVerifierFunc adapts a function to AndroidKeyVerifier. | AndroidKeyVerifierFunc 把函数适配为 AndroidKeyVerifier。
type AndroidKeyVerifierFunc func(ctx context.Context, certs []*x509.Certificate, opts AndroidKeyVerifyOptions) (bool, error)

// VerifyAndroidKey implements AndroidKeyVerifier. | VerifyAndroidKey 实现 AndroidKeyVerifier。
func (f AndroidKeyVerifierFunc) VerifyAndroidKey(ctx context.Context, certs []*x509.Certificate, opts AndroidKeyVerifyOptions) (bool, error) {
	return f(ctx, certs, opts)
}

// AndroidKeyVerifyOptions carries the inputs a custom android-key verifier needs. |
// AndroidKeyVerifyOptions 携带自定义 android-key 校验器所需的输入。
type AndroidKeyVerifyOptions struct {
	// ClientDataHash is the SHA-256 of the client data JSON. | ClientDataHash 是客户端数据 JSON 的 SHA-256。
	ClientDataHash []byte
	// AuthData is the raw authenticator data. | AuthData 是原始认证器数据。
	AuthData []byte
	// ExpectedPackageName is the configured APK package name, empty when none is configured. |
	// ExpectedPackageName 是配置的 APK 包名，未配置时为空。
	ExpectedPackageName string
}

// AttestationOptions tune attribution verification. | AttestationOptions 调整认证声明校验。
type AttestationOptions struct {
	// Roots is the caller-supplied trust anchor pool. When nil, certificate chains are parsed but
	// not chained to a trust anchor. | Roots 是调用方提供的信任锚池。为空时解析证书链但不做信任锚校验。
	Roots *x509.CertPool
	// SafetyNetRoots overrides Roots for android-safetynet certificate chains. Nil falls back to
	// Roots. | SafetyNetRoots 为 android-safetynet 证书链覆盖 Roots。为空时回退到 Roots。
	SafetyNetRoots *x509.CertPool
	// AndroidKeyRoots overrides Roots for android-key certificate chains. Nil falls back to Roots.
	// | AndroidKeyRoots 为 android-key 证书链覆盖 Roots。为空时回退到 Roots。
	AndroidKeyRoots *x509.CertPool
	// AndroidKeyVerifier overrides the built-in android-key extension and trust checks. | AndroidKeyVerifier
	// 覆盖内置 android-key 扩展与信任校验。
	AndroidKeyVerifier AndroidKeyVerifier
	// AndroidPackageName is the APK package name required from android-safetynet and android-key
	// attestations. Empty falls back to ClientData.AndroidPackageName. Neither format carries a
	// hostname, so RP ID and origin binding come from the verified client data. | AndroidPackageName
	// 是 android-safetynet 与 android-key 认证声明要求的 APK 包名。为空时回退到
	// ClientData.AndroidPackageName。两种格式都不携带主机名，因此 RP ID 与来源绑定来自已校验的
	// 客户端数据。
	AndroidPackageName string
	// CurrentTime is the verification time; the zero value means time.Now. | CurrentTime 是校验时间；零值表示当前时间。
	CurrentTime time.Time
	// SafetyNetVerifier overrides the built-in SafetyNet JWS checks. | SafetyNetVerifier 覆盖内置 SafetyNet JWS 校验。
	SafetyNetVerifier SafetyNetVerifier
	// SafetyNetPolicy tightens the built-in android-safetynet checks. It is ignored when
	// SafetyNetVerifier is set. The zero value keeps the baseline ctsProfileMatch, nonce, signature
	// and one-minute timestamp checks. | SafetyNetPolicy 收紧内置 android-safetynet 校验。设置
	// SafetyNetVerifier 时忽略本字段。零值保持基线 ctsProfileMatch、nonce、签名与一分钟时间戳校验。
	SafetyNetPolicy SafetyNetPolicy
	// AndroidKeyPolicy tightens the built-in android-key KeyDescription checks. It is ignored when
	// AndroidKeyVerifier is set. The zero value keeps the baseline origin, purpose,
	// attestationApplicationId, package and allApplications checks. | AndroidKeyPolicy 收紧内置
	// android-key KeyDescription 校验。设置 AndroidKeyVerifier 时忽略本字段。零值保持基线 origin、
	// purpose、attestationApplicationId、包名与 allApplications 校验。
	AndroidKeyPolicy AndroidKeyPolicy
	// ClientData carries the verified client data when available. | ClientData 在可用时携带已校验的客户端数据。
	ClientData *ClientData
}

func (o AttestationOptions) currentTime() time.Time {
	if o.CurrentTime.IsZero() {
		return time.Now()
	}
	return o.CurrentTime
}

// withSafetyNetRoots returns opts using SafetyNetRoots when configured. | withSafetyNetRoots 在配置时返回使用 SafetyNetRoots 的 opts。
func (o AttestationOptions) withSafetyNetRoots() AttestationOptions {
	if o.SafetyNetRoots != nil {
		o.Roots = o.SafetyNetRoots
	}
	return o
}

// withAndroidKeyRoots returns opts using AndroidKeyRoots when configured. | withAndroidKeyRoots 在配置时返回使用 AndroidKeyRoots 的 opts。
func (o AttestationOptions) withAndroidKeyRoots() AttestationOptions {
	if o.AndroidKeyRoots != nil {
		o.Roots = o.AndroidKeyRoots
	}
	return o
}

// expectedAndroidPackageName returns the configured package name with client data as fallback. |
// expectedAndroidPackageName 返回配置的包名，并以客户端数据作为回退。
func (o AttestationOptions) expectedAndroidPackageName() string {
	if name := strings.TrimSpace(o.AndroidPackageName); name != "" {
		return name
	}
	if o.ClientData != nil {
		return strings.TrimSpace(o.ClientData.AndroidPackageName)
	}
	return ""
}

// AttestationObject is a decoded WebAuthn attestation object. | AttestationObject 是解码后的 WebAuthn 认证声明对象。
type AttestationObject struct {
	// Format is the attestation statement format identifier. | Format 是认证声明格式标识。
	Format string
	// AttStmt is the attestation statement map. | AttStmt 是认证声明映射。
	AttStmt *Value
	// AuthData is the parsed authenticator data. | AuthData 是解析后的认证器数据。
	AuthData *AuthenticatorData
	// AuthDataRaw is the exact authenticator data bytes. | AuthDataRaw 是认证器数据的原始字节。
	AuthDataRaw []byte
	// Raw is the complete attestation object CBOR. | Raw 是认证声明对象的完整 CBOR。
	Raw []byte
}

// AttestationResult is the verified outcome of an attestation statement. | AttestationResult 是认证声明校验后的结果。
type AttestationResult struct {
	// Type classifies the attestation. | Type 对认证声明分类。
	Type AttestationType
	// Format is the attestation statement format identifier. | Format 是认证声明格式标识。
	Format string
	// TrustPath is the attestation certificate chain, leaf first. | TrustPath 是认证声明证书链，叶证书在前。
	TrustPath []*x509.Certificate
	// TrustVerified reports that TrustPath was chained to a caller-supplied trust anchor
	// (AttestationOptions.Roots, SafetyNetRoots or AndroidKeyRoots). Custom AndroidKeyVerifier
	// implementations report their own value. | TrustVerified 表示 TrustPath 已链到调用方提供的信任锚
	// （AttestationOptions.Roots、SafetyNetRoots 或 AndroidKeyRoots）。自定义 AndroidKeyVerifier 报告
	// 其自身的值。
	TrustVerified bool
	// AAGUID identifies the authenticator model. | AAGUID 标识认证器型号。
	AAGUID [16]byte
	// SignCount is the authenticator signature counter. | SignCount 是认证器签名计数器。
	SignCount uint32
	// CredentialID is the raw credential identifier. | CredentialID 是原始凭据标识。
	CredentialID []byte
	// CredentialPublicKey is the parsed credential public key. | CredentialPublicKey 是解析后的凭据公钥。
	CredentialPublicKey *COSEKey
	// AuthData is the parsed authenticator data. | AuthData 是解析后的认证器数据。
	AuthData *AuthenticatorData
	// EKActivation is the verified TPM endorsement-key credential activation bound to a tpm
	// attestation, when Config.TPMEKActivation is enabled and registration supplied evidence. |
	// EKActivation 是绑定到 tpm 认证声明的已校验 TPM 背书密钥凭据激活；仅在启用
	// Config.TPMEKActivation 且注册提供证据时设置。
	EKActivation *TPMEKActivationResult
}

// ParseAttestationObject decodes a CBOR attestation object and its authenticator data. | ParseAttestationObject 解码 CBOR 认证声明对象及其认证器数据。
func ParseAttestationObject(raw []byte) (*AttestationObject, error) {
	if len(raw) == 0 {
		return nil, errs.Detail(ErrInvalidAttestation, "empty attestation object | 认证声明对象为空")
	}
	v, err := Decode(raw, DecodeOptions{MaxDepth: DefaultMaxCBORDepth, MaxBytes: DefaultMaxCBORBytes})
	if err != nil {
		return nil, errs.WrapDetail(err, ErrInvalidAttestation, "attestation object is not valid CBOR | 认证声明对象不是合法 CBOR")
	}
	if v.Kind != KindMap {
		return nil, errs.Detail(ErrInvalidAttestation, "attestation object is not a map | 认证声明对象不是映射")
	}
	o := &AttestationObject{Raw: append([]byte(nil), raw...)}
	formatValue, ok := v.MapGetText("fmt")
	if !ok || formatValue.Kind != KindText || formatValue.Text == "" {
		return nil, errs.Detail(ErrInvalidAttestation, "attestation object lacks a fmt text string | 认证声明对象缺少 fmt 文本串")
	}
	o.Format = formatValue.Text
	stmt, ok := v.MapGetText("attStmt")
	if !ok || stmt.Kind != KindMap {
		return nil, errs.Detail(ErrInvalidAttestation, "attestation object lacks an attStmt map | 认证声明对象缺少 attStmt 映射")
	}
	o.AttStmt = stmt
	authDataValue, ok := v.MapGetText("authData")
	if !ok {
		return nil, errs.Detail(ErrInvalidAttestation, "attestation object lacks authData | 认证声明对象缺少 authData")
	}
	authDataBytes, ok := authDataValue.AsBytes()
	if !ok {
		return nil, errs.Detail(ErrInvalidAttestation, "authData is not a byte string | authData 不是字节串")
	}
	authData, err := ParseAuthenticatorData(authDataBytes)
	if err != nil {
		return nil, errs.WrapDetail(err, ErrInvalidAttestation, "attestation authData is invalid | 认证声明的 authData 非法")
	}
	o.AuthData = authData
	o.AuthDataRaw = authData.Raw
	return o, nil
}

// Verify verifies the attestation statement over clientDataHash. | Verify 校验针对 clientDataHash 的认证声明。
//
// clientDataHash must be the SHA-256 of the client data JSON. Signature verification is performed
// for every supported format; certificate chains are verified only when the caller supplies a root
// pool. SafetyNetRoots and AndroidKeyRoots select per-format pools and fall back to Roots. | clientDataHash
// 必须是客户端数据 JSON 的 SHA-256。所有支持的格式都会校验签名；仅当调用方提供信任锚池时校验证书链。
// SafetyNetRoots 与 AndroidKeyRoots 选择按格式的信任池并回退到 Roots。
func (o *AttestationObject) Verify(ctx context.Context, clientDataHash []byte, opts AttestationOptions) (*AttestationResult, error) {
	if o == nil || o.AuthData == nil || o.AttStmt == nil {
		return nil, errs.Detail(ErrInvalidAttestation, "nil or incomplete attestation object | 认证声明对象为空或不完整")
	}
	if len(clientDataHash) != sha256.Size {
		return nil, errs.Detail(ErrInvalidRequest, "client data hash is %d bytes, want %d | 客户端数据哈希为 %d 字节，期望 %d",
			len(clientDataHash), sha256.Size, len(clientDataHash), sha256.Size)
	}
	if !o.AuthData.Flags.AttestedCredentialData() {
		return nil, errs.Detail(ErrInvalidAttestation, "attestation object has no attested credential data | 认证声明对象缺少认证凭据数据")
	}
	result := &AttestationResult{
		Format:              o.Format,
		AAGUID:              o.AuthData.AAGUID,
		SignCount:           o.AuthData.SignCount,
		CredentialID:        append([]byte(nil), o.AuthData.CredentialID...),
		CredentialPublicKey: o.AuthData.CredentialPublicKey,
		AuthData:            o.AuthData,
	}
	var err error
	switch o.Format {
	case FormatNone:
		err = o.verifyNone(result)
	case FormatPacked:
		err = o.verifyPacked(result, clientDataHash, opts)
	case FormatFIDOU2F:
		err = o.verifyFIDOU2F(result, clientDataHash, opts)
	case FormatAndroidKey:
		err = o.verifyAndroidKey(ctx, result, clientDataHash, opts)
	case FormatAndroidSafetyNet:
		err = o.verifyAndroidSafetyNet(ctx, result, clientDataHash, opts)
	case FormatTPM:
		err = o.verifyTPM(result, clientDataHash, opts)
	case FormatApple:
		err = o.verifyApple(result, clientDataHash, opts)
	case FormatECDA:
		err = errs.Detail(ErrUnsupportedAttestation, "ecdaa attestation is not supported | 不支持 ecdaa 认证声明")
	default:
		err = errs.Detail(ErrUnsupportedAttestation, "unknown attestation format %q | 未知认证声明格式 %q", o.Format, o.Format)
	}
	if err != nil {
		return nil, err
	}
	return result, nil
}

func (o *AttestationObject) verifyNone(result *AttestationResult) error {
	if len(o.AttStmt.Pairs) != 0 {
		return errs.Detail(ErrInvalidAttestation, "none attestation has a non-empty attStmt | none 认证声明的 attStmt 非空")
	}
	result.Type = AttestationTypeNone
	return nil
}

// signedAttestationData returns authenticatorData || clientDataHash. | signedAttestationData 返回 authenticatorData || clientDataHash。
func signedAttestationData(authData, clientDataHash []byte) []byte {
	out := make([]byte, 0, len(authData)+len(clientDataHash))
	out = append(out, authData...)
	out = append(out, clientDataHash...)
	return out
}

// attestationStatementBytes reads a required byte-string member. | attestationStatementBytes 读取必需的字节串成员。
func attestationStatementBytes(stmt *Value, name string) ([]byte, error) {
	v, ok := stmt.MapGetText(name)
	if !ok {
		return nil, errs.Detail(ErrInvalidAttestation, "attestation statement lacks %q | 认证声明缺少 %q", name, name)
	}
	b, ok := v.AsBytes()
	if !ok {
		return nil, errs.Detail(ErrInvalidAttestation, "attestation statement member %q is not a byte string | 认证声明成员 %q 不是字节串", name, name)
	}
	return b, nil
}

// attestationStatementInt reads a required integer member. | attestationStatementInt 读取必需的整数成员。
func attestationStatementInt(stmt *Value, name string) (int, error) {
	v, ok := stmt.MapGetText(name)
	if !ok {
		return 0, errs.Detail(ErrInvalidAttestation, "attestation statement lacks %q | 认证声明缺少 %q", name, name)
	}
	n, ok := v.AsInt64()
	if !ok {
		return 0, errs.Detail(ErrInvalidAttestation, "attestation statement member %q is not an integer | 认证声明成员 %q 不是整数", name, name)
	}
	return int(n), nil
}

// attestationStatementText reads a required text member. | attestationStatementText 读取必需的文本成员。
func attestationStatementText(stmt *Value, name string) (string, error) {
	v, ok := stmt.MapGetText(name)
	if !ok {
		return "", errs.Detail(ErrInvalidAttestation, "attestation statement lacks %q | 认证声明缺少 %q", name, name)
	}
	s, ok := v.AsText()
	if !ok || s == "" {
		return "", errs.Detail(ErrInvalidAttestation, "attestation statement member %q is not a text string | 认证声明成员 %q 不是文本串", name, name)
	}
	return s, nil
}

// attestationStatementX5C reads the optional x5c array. | attestationStatementX5C 读取可选的 x5c 数组。
func attestationStatementX5C(stmt *Value) (*Value, bool, error) {
	v, ok := stmt.MapGetText("x5c")
	if !ok {
		return nil, false, nil
	}
	if v.Kind != KindArray {
		return nil, false, errs.Detail(ErrInvalidAttestation, "x5c is not an array | x5c 不是数组")
	}
	if len(v.Array) == 0 || len(v.Array) > maxAttestationCertificates {
		return nil, false, errs.Detail(ErrInvalidAttestation, "x5c has %d certificates | x5c 包含 %d 张证书", len(v.Array), len(v.Array))
	}
	return v, true, nil
}

// parseX5C parses an x5c array into certificates. | parseX5C 把 x5c 数组解析为证书。
func parseX5C(v *Value) ([]*x509.Certificate, error) {
	if v == nil || v.Kind != KindArray || len(v.Array) == 0 {
		return nil, errs.Detail(ErrInvalidAttestation, "empty x5c | 空 x5c")
	}
	if len(v.Array) > maxAttestationCertificates {
		return nil, errs.Detail(ErrInvalidAttestation, "x5c has too many certificates | x5c 证书过多")
	}
	certs := make([]*x509.Certificate, 0, len(v.Array))
	for i := range v.Array {
		der, ok := v.Array[i].AsBytes()
		if !ok {
			return nil, errs.Detail(ErrInvalidAttestation, "x5c entry %d is not a byte string | x5c 第 %d 项不是字节串", i, i)
		}
		cert, err := x509.ParseCertificate(der)
		if err != nil {
			return nil, errs.WrapDetail(err, ErrInvalidAttestation, "x5c entry %d is not a certificate | x5c 第 %d 项不是证书", i, i)
		}
		certs = append(certs, cert)
	}
	return certs, nil
}

// verifyCertificateChain chains certs to opts.Roots when roots are supplied. | verifyCertificateChain 在提供根证书时把 certs 链到 opts.Roots。
func verifyCertificateChain(certs []*x509.Certificate, opts AttestationOptions) (bool, error) {
	if len(certs) == 0 {
		return false, errs.Detail(ErrInvalidAttestation, "empty attestation certificate chain | 认证声明证书链为空")
	}
	now := opts.currentTime()
	leaf := certs[0]
	if now.Before(leaf.NotBefore) || now.After(leaf.NotAfter) {
		return false, errs.Detail(ErrUntrustedAttestation, "attestation certificate is not valid at the verification time | 认证声明证书在校验时间无效")
	}
	if opts.Roots == nil {
		return false, nil
	}
	intermediates := x509.NewCertPool()
	for _, cert := range certs[1:] {
		intermediates.AddCert(cert)
	}
	_, err := leaf.Verify(x509.VerifyOptions{
		Roots:         opts.Roots,
		Intermediates: intermediates,
		CurrentTime:   now,
		KeyUsages:     []x509.ExtKeyUsage{x509.ExtKeyUsageAny},
	})
	if err != nil {
		return false, errs.WrapDetail(err, ErrUntrustedAttestation, "attestation certificate chain is not trusted | 认证声明证书链不受信任")
	}
	return true, nil
}

// samePublicKey reports whether two public keys have the same PKIX encoding. | samePublicKey 报告两个公钥的 PKIX 编码是否相同。
func samePublicKey(a, b crypto.PublicKey) bool {
	if a == nil || b == nil {
		return false
	}
	aDER, err := x509.MarshalPKIXPublicKey(a)
	if err != nil {
		return false
	}
	bDER, err := x509.MarshalPKIXPublicKey(b)
	if err != nil {
		return false
	}
	return constantTimeEqual(aDER, bDER)
}

// fidoAAGUIDOID is the id-fido-gen-ce-aaguid certificate extension. | fidoAAGUIDOID 是 id-fido-gen-ce-aaguid 证书扩展。
var fidoAAGUIDOID = asn1.ObjectIdentifier{1, 3, 6, 1, 4, 1, 45724, 1, 1, 4}

// verifyAAGUIDExtension checks the optional FIDO AAGUID certificate extension. | verifyAAGUIDExtension 校验可选的 FIDO AAGUID 证书扩展。
func verifyAAGUIDExtension(cert *x509.Certificate, aaguid [16]byte) error {
	for i := range cert.Extensions {
		ext := &cert.Extensions[i]
		if !ext.Id.Equal(fidoAAGUIDOID) {
			continue
		}
		if ext.Critical {
			return errs.Detail(ErrInvalidAttestation, "AAGUID extension is critical | AAGUID 扩展被标记为关键")
		}
		var extensionAAGUID []byte
		rest, err := asn1.Unmarshal(ext.Value, &extensionAAGUID)
		if err != nil || len(rest) != 0 {
			return errs.Detail(ErrInvalidAttestation, "AAGUID extension is not an OCTET STRING | AAGUID 扩展不是 OCTET STRING")
		}
		if len(extensionAAGUID) != 16 || !constantTimeEqual(extensionAAGUID, aaguid[:]) {
			return errs.Detail(ErrInvalidAttestation, "AAGUID extension does not match authenticator data | AAGUID 扩展与认证器数据不匹配")
		}
		return nil
	}
	return nil
}

// attestationCredentialPublicKey returns the parsed credential public key or an error. | attestationCredentialPublicKey 返回解析后的凭据公钥或错误。
func attestationCredentialPublicKey(authData *AuthenticatorData) (*COSEKey, error) {
	if authData == nil || authData.CredentialPublicKey == nil {
		return nil, errs.Detail(ErrInvalidAttestation, "authenticator data lacks a credential public key | 认证器数据缺少凭据公钥")
	}
	return authData.CredentialPublicKey, nil
}
