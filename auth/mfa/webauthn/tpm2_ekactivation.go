package webauthn

import (
	"context"
	"crypto/ecdsa"
	"crypto/rsa"
	"crypto/x509"
	"encoding/asn1"
	"strings"
	"time"

	"github.com/shibingli/ydx/errs"
)

// TPM endorsement-key credential activation defaults and limits. | TPM 背书密钥凭据激活的默认值与限制。
const (
	// DefaultTPMEKActivationTimeout is the default lifetime of an EK activation challenge. |
	// DefaultTPMEKActivationTimeout 是 EK 激活挑战的默认生命周期。
	DefaultTPMEKActivationTimeout = 2 * time.Minute
	// DefaultTPMEKActivationPending is the default maximum number of pending EK activation challenges. |
	// DefaultTPMEKActivationPending 是待处理 EK 激活挑战的默认最大数量。
	DefaultTPMEKActivationPending = 64
	// DefaultTPMEKMinKeyBits is the default minimum RSA endorsement-key size. |
	// DefaultTPMEKMinKeyBits 是默认的最小 RSA 背书密钥位数。
	DefaultTPMEKMinKeyBits = 2048
	// maxTPMEKActivationCredential bounds the credential bytes carried by one activation. |
	// maxTPMEKActivationCredential 限制一次激活携带的凭据字节数。
	maxTPMEKActivationCredential = 64
	// maxTPMEKActivationChallengeID bounds the encoded challenge identifier. |
	// maxTPMEKActivationChallengeID 限制编码后的挑战标识长度。
	maxTPMEKActivationChallengeID = 128
)

// tcgKpEKCertOID is the TCG endorsement-key certificate extended key usage. |
// tcgKpEKCertOID 是 TCG 背书密钥证书扩展密钥用途。
var tcgKpEKCertOID = asn1.ObjectIdentifier{2, 23, 133, 8, 1}

// TPMEKActivationConfig configures optional TPM endorsement-key credential activation. |
// TPMEKActivationConfig 配置可选的 TPM 背书密钥凭据激活。
//
// The zero value enables the protocol with no trust anchors: certificates are parsed and their
// profile is checked, but TrustVerified stays false. Set EKRoots (or Config.AttestationRoots) to
// chain EK certificates to vendor roots. The built-in profile, certificate-chain and AAGUID checks
// always run before Verifier, so a custom verifier can add constraints but cannot bypass them. |
// 零值启用协议但不提供信任锚：证书会被解析并检查配置，但 TrustVerified 保持 false。设置 EKRoots（或
// Config.AttestationRoots）把 EK 证书链到厂商根。内置配置、证书链与 AAGUID 校验始终在 Verifier 之前
// 执行，因此自定义校验器只能增加约束，不能绕过它们。
type TPMEKActivationConfig struct {
	// EKRoots is the trust anchor pool for endorsement-key certificate chains. Nil falls back to
	// Config.AttestationRoots in a Service. | EKRoots 是背书密钥证书链的信任锚池。Service 中为空时
	// 回退到 Config.AttestationRoots。
	EKRoots *x509.CertPool
	// RequireTrustedEKChain rejects activation unless the EK certificate chains to a configured root.
	// | RequireTrustedEKChain 要求 EK 证书链到已配置的根，否则拒绝激活。
	RequireTrustedEKChain bool
	// AllowedAAGUIDs restricts activation to the listed authenticator models. Empty disables the
	// restriction. | AllowedAAGUIDs 把激活限制为列出的认证器型号。空值关闭限制。
	AllowedAAGUIDs [][16]byte
	// AllowedEKManufacturers restricts the TCG manufacturer attribute in the EK certificate
	// subjectAltName. Empty disables the restriction. Values are compared case-insensitively after
	// trimming whitespace. | AllowedEKManufacturers 限制 EK 证书 subjectAltName 中的 TCG 制造商属性。
	// 空值关闭限制。去除空白后按大小写不敏感比较。
	AllowedEKManufacturers []string
	// MinEKKeyBits is the minimum RSA EK modulus size. Zero means DefaultTPMEKMinKeyBits. |
	// MinEKKeyBits 是最小 RSA EK 模数位数。零值表示 DefaultTPMEKMinKeyBits。
	MinEKKeyBits int
	// ChallengeTTL is the lifetime of a pending activation challenge. Zero means
	// DefaultTPMEKActivationTimeout; negative values are rejected. | ChallengeTTL 是待处理激活挑战的
	// 生命周期。零值表示 DefaultTPMEKActivationTimeout；负值会被拒绝。
	ChallengeTTL time.Duration
	// MaxPendingChallenges bounds the pending challenge store. Zero means
	// DefaultTPMEKActivationPending; negative values are rejected. The oldest challenge is evicted
	// when the bound is reached. | MaxPendingChallenges 限制待处理挑战存储。零值表示
	// DefaultTPMEKActivationPending；负值会被拒绝。达到上限时淘汰最旧的挑战。
	MaxPendingChallenges int
	// RequiredForTPMAttestation makes FinishRegistration reject a tpm attestation that does not
	// carry TPMEKActivation evidence. It has no effect outside a Service. | RequiredForTPMAttestation
	// 使 FinishRegistration 拒绝未携带 TPMEKActivation 证据的 tpm 认证声明。在 Service 之外无效果。
	RequiredForTPMAttestation bool
	// Verifier runs after every built-in check and may only add constraints. A non-nil error rejects
	// the activation. | Verifier 在全部内置校验之后运行，只能增加约束。非空错误会拒绝激活。
	Verifier TPMEKActivationVerifier
}

// TPMEKActivationVerifier adds caller-specific checks after the built-in EK activation checks. |
// TPMEKActivationVerifier 在内置 EK 激活校验之后增加调用方特定校验。
//
// The verification value and result are read-only snapshots; mutating them has no effect. Returning
// an error rejects the activation. | verification 与 result 是只读快照，修改它们不会产生效果。返回错误
// 会拒绝激活。
type TPMEKActivationVerifier interface {
	// VerifyTPMEKActivation checks a verified activation. | VerifyTPMEKActivation 校验已完成的激活。
	VerifyTPMEKActivation(ctx context.Context, verification TPMEKActivationVerification, result TPMEKActivationResult) error
}

// TPMEKActivationVerifierFunc adapts a function to TPMEKActivationVerifier. |
// TPMEKActivationVerifierFunc 把函数适配为 TPMEKActivationVerifier。
type TPMEKActivationVerifierFunc func(ctx context.Context, verification TPMEKActivationVerification, result TPMEKActivationResult) error

// VerifyTPMEKActivation implements TPMEKActivationVerifier. | VerifyTPMEKActivation 实现
// TPMEKActivationVerifier。
func (f TPMEKActivationVerifierFunc) VerifyTPMEKActivation(ctx context.Context, verification TPMEKActivationVerification, result TPMEKActivationResult) error {
	return f(ctx, verification, result)
}

// TPMEKActivationRequest starts an endorsement-key credential activation. |
// TPMEKActivationRequest 启动背书密钥凭据激活。
type TPMEKActivationRequest struct {
	// EKCertificates is the DER endorsement-key certificate chain, leaf first. At least one
	// certificate is required. | EKCertificates 是 DER 背书密钥证书链，叶证书在前。至少需要一张证书。
	EKCertificates [][]byte
	// EKPublic is the raw TPMT_PUBLIC endorsement-key area without its TPM2B length prefix. |
	// EKPublic 是不带 TPM2B 长度前缀的原始 TPMT_PUBLIC 背书密钥区域。
	EKPublic []byte
	// AKPublic is the raw TPMT_PUBLIC attestation-key area without its TPM2B length prefix. |
	// AKPublic 是不带 TPM2B 长度前缀的原始 TPMT_PUBLIC 认证密钥区域。
	AKPublic []byte
	// AAGUID identifies the authenticator model requesting activation. | AAGUID 标识请求激活的认证器型号。
	AAGUID [16]byte
	// UserID optionally binds the challenge to one account. FinishRegistration enforces the binding.
	// | UserID 可选地把挑战绑定到一个账号。FinishRegistration 会强制该绑定。
	UserID string
}

// TPMEKActivationChallenge is the server response to TPMEKActivationRequest. |
// TPMEKActivationChallenge 是服务器对 TPMEKActivationRequest 的响应。
//
// CredentialBlob and EncryptedSecret are the exact TPM2B_ID_OBJECT and TPM2B_ENCRYPTED_SECRET
// parameter contents to pass to TPM2_ActivateCredential. | CredentialBlob 与 EncryptedSecret 是传给
// TPM2_ActivateCredential 的 TPM2B_ID_OBJECT 与 TPM2B_ENCRYPTED_SECRET 参数内容。
type TPMEKActivationChallenge struct {
	// ID is the opaque single-use challenge identifier. | ID 是不透明的一次性挑战标识。
	ID string
	// CredentialBlob is the credential ID object. | CredentialBlob 是凭据 ID 对象。
	CredentialBlob []byte
	// EncryptedSecret is the encrypted credential seed. | EncryptedSecret 是加密的凭据种子。
	EncryptedSecret []byte
	// AKName is the TPM Name of the attestation key. | AKName 是认证密钥的 TPM Name。
	AKName []byte
	// AAGUID is the requested authenticator model. | AAGUID 是请求的认证器型号。
	AAGUID [16]byte
	// ExpiresAt is the challenge deadline. | ExpiresAt 是挑战期限。
	ExpiresAt time.Time
}

// TPMEKActivationVerification is the evidence checked by VerifyEKActivation. |
// TPMEKActivationVerification 是 VerifyEKActivation 校验的证据。
type TPMEKActivationVerification struct {
	// EKCertificates is the DER endorsement-key certificate chain, leaf first. |
	// EKCertificates 是 DER 背书密钥证书链，叶证书在前。
	EKCertificates [][]byte
	// EKPublic is the raw TPMT_PUBLIC endorsement-key area. | EKPublic 是原始 TPMT_PUBLIC 背书密钥区域。
	EKPublic []byte
	// AKPublic is the raw TPMT_PUBLIC attestation-key area. | AKPublic 是原始 TPMT_PUBLIC 认证密钥区域。
	AKPublic []byte
	// AAGUID identifies the authenticator model. | AAGUID 标识认证器型号。
	AAGUID [16]byte
	// Credential is the server-generated secret bound into the credential blob. |
	// Credential 是绑定进凭据 blob 的服务器生成秘密。
	Credential []byte
	// CredentialBlob is the TPM2B_ID_OBJECT parameter content. | CredentialBlob 是 TPM2B_ID_OBJECT
	// 参数内容。
	CredentialBlob []byte
	// EncryptedSecret is the TPM2B_ENCRYPTED_SECRET parameter content. | EncryptedSecret 是
	// TPM2B_ENCRYPTED_SECRET 参数内容。
	EncryptedSecret []byte
	// CertInfo is the TPM2B_ATTEST response content from TPM2_ActivateCredential. | CertInfo 是
	// TPM2_ActivateCredential 返回的 TPM2B_ATTEST 内容。
	CertInfo []byte
	// Now is the verification time. Zero means time.Now. | Now 是校验时间。零值表示 time.Now。
	Now time.Time
}

// TPMEKActivationResult is the verified outcome of EK credential activation. |
// TPMEKActivationResult 是 EK 凭据激活的校验结果。
type TPMEKActivationResult struct {
	// AAGUID is the verified authenticator model. | AAGUID 是已校验的认证器型号。
	AAGUID [16]byte
	// AKName is the verified attestation-key Name. | AKName 是已校验的认证密钥 Name。
	AKName TPM2BName
	// EKPublic is the verified endorsement-key public area. | EKPublic 是已校验的背书密钥公钥区域。
	EKPublic TPM2BPublic
	// EKCertificates is the parsed endorsement-key chain. | EKCertificates 是已解析的背书密钥证书链。
	EKCertificates []*x509.Certificate
	// TrustVerified reports whether the EK chain chained to a configured root. |
	// TrustVerified 报告 EK 证书链是否链到已配置的根。
	TrustVerified bool
	// VerifiedAt is the verification time. | VerifiedAt 是校验时间。
	VerifiedAt time.Time
}

// normalizeTPMEKActivationConfig validates config and fills defaults. | normalizeTPMEKActivationConfig
// 校验 config 并填充默认值。
func normalizeTPMEKActivationConfig(config *TPMEKActivationConfig, fallbackRoots *x509.CertPool) (*TPMEKActivationConfig, error) {
	if config == nil {
		return nil, nil
	}
	out := *config
	if out.EKRoots == nil && fallbackRoots != nil {
		out.EKRoots = fallbackRoots.Clone()
	}
	if out.RequireTrustedEKChain && out.EKRoots == nil {
		return nil, errs.Detail(ErrInvalidConfig, "TPM EK activation requires a trusted chain but no EK roots are configured | TPM EK 激活要求受信任证书链，但未配置 EK 根")
	}
	if out.MinEKKeyBits == 0 {
		out.MinEKKeyBits = DefaultTPMEKMinKeyBits
	}
	if out.MinEKKeyBits < DefaultTPMEKMinKeyBits {
		return nil, errs.Detail(ErrInvalidConfig, "minimum EK key size %d is below %d bits | 最小 EK 密钥位数 %d 低于 %d 位",
			out.MinEKKeyBits, DefaultTPMEKMinKeyBits, out.MinEKKeyBits, DefaultTPMEKMinKeyBits)
	}
	if out.ChallengeTTL == 0 {
		out.ChallengeTTL = DefaultTPMEKActivationTimeout
	}
	if out.ChallengeTTL < 0 {
		return nil, errs.Detail(ErrInvalidConfig, "TPM EK activation challenge TTL is negative | TPM EK 激活挑战生命周期为负值")
	}
	if out.MaxPendingChallenges == 0 {
		out.MaxPendingChallenges = DefaultTPMEKActivationPending
	}
	if out.MaxPendingChallenges < 0 {
		return nil, errs.Detail(ErrInvalidConfig, "TPM EK activation pending limit is negative | TPM EK 激活待处理上限为负值")
	}
	out.AllowedAAGUIDs = append([][16]byte(nil), config.AllowedAAGUIDs...)
	out.AllowedEKManufacturers = make([]string, 0, len(config.AllowedEKManufacturers))
	for _, manufacturer := range config.AllowedEKManufacturers {
		trimmed := strings.TrimSpace(manufacturer)
		if trimmed == "" {
			return nil, errs.Detail(ErrInvalidConfig, "TPM EK manufacturer allowlist contains an empty entry | TPM EK 制造商允许列表包含空项")
		}
		out.AllowedEKManufacturers = append(out.AllowedEKManufacturers, trimmed)
	}
	return &out, nil
}

// VerifyEKActivation verifies a complete TPM endorsement-key credential activation. |
// VerifyEKActivation 校验完整的 TPM 背书密钥凭据激活。
//
// The function checks the EK certificate profile, optional vendor trust chain, the EK public area
// against the leaf certificate, the AK public area and Name, the credential blob and encrypted
// secret shape, and the TPM2_ActivateCredential certInfo. Every built-in check runs before
// Config.Verifier, so a custom verifier cannot bypass the configured policy. |
// 本函数检查 EK 证书配置、可选的厂商信任链、EK 公钥区域与叶证书是否一致、AK 公钥区域与 Name、凭据
// blob 与加密秘密的结构，以及 TPM2_ActivateCredential certInfo。所有内置校验都在 Config.Verifier
// 之前运行，因此自定义校验器不能绕过已配置策略。
func VerifyEKActivation(ctx context.Context, verification *TPMEKActivationVerification, config *TPMEKActivationConfig) (*TPMEKActivationResult, error) {
	if verification == nil {
		return nil, errs.Detail(ErrEKActivation, "nil EK activation verification | EK 激活校验为空")
	}
	if ctx == nil {
		ctx = context.Background()
	}
	policy, err := normalizeTPMEKActivationConfig(config, nil)
	if err != nil {
		return nil, err
	}
	if policy == nil {
		policy = &TPMEKActivationConfig{
			MinEKKeyBits:         DefaultTPMEKMinKeyBits,
			ChallengeTTL:         DefaultTPMEKActivationTimeout,
			MaxPendingChallenges: DefaultTPMEKActivationPending,
		}
	}
	now := verification.Now
	if now.IsZero() {
		now = time.Now()
	}
	now = now.UTC()

	ekPublic, akName, certs, trusted, err := verifyTPMEKActivationMaterial(
		verification.EKPublic, verification.AKPublic, verification.EKCertificates, verification.AAGUID, policy, now)
	if err != nil {
		return nil, err
	}
	if err := validateTPMEKActivationChallenge(&ekPublic.Public, akName, verification.Credential, verification.CredentialBlob, verification.EncryptedSecret); err != nil {
		return nil, err
	}
	if err := VerifyActivationCertInfo(TPM2BAttest{Buffer: append([]byte(nil), verification.CertInfo...)}, verification.Credential, akName); err != nil {
		return nil, err
	}
	result := &TPMEKActivationResult{
		AAGUID:         verification.AAGUID,
		AKName:         TPM2BName{Name: append([]byte(nil), akName.Name...)},
		EKPublic:       TPM2BPublic{Public: ekPublic.Public, Raw: append([]byte(nil), verification.EKPublic...)},
		EKCertificates: append([]*x509.Certificate(nil), certs...),
		TrustVerified:  trusted,
		VerifiedAt:     now,
	}
	if policy.Verifier != nil {
		snapshot := *verification
		check := *result
		if err := policy.Verifier.VerifyTPMEKActivation(ctx, snapshot, check); err != nil {
			return nil, errs.WrapDetail(err, ErrEKActivation, "custom TPM EK activation verifier rejected the activation | 自定义 TPM EK 激活校验器拒绝了激活")
		}
	}
	return result, nil
}

// verifyTPMEKActivationMaterial validates the EK and AK public areas, the EK certificate profile and
// the optional EK trust chain. | verifyTPMEKActivationMaterial 校验 EK 与 AK 公钥区域、EK 证书配置与
// 可选的 EK 信任链。
func verifyTPMEKActivationMaterial(ekRaw, akRaw []byte, chain [][]byte, aaguid [16]byte, policy *TPMEKActivationConfig, now time.Time) (*TPM2BPublic, TPM2BName, []*x509.Certificate, bool, error) {
	ekPublic, err := parseTPMEKPublic(ekRaw)
	if err != nil {
		return nil, TPM2BName{}, nil, false, err
	}
	_, akName, err := parseTPMEKActivationAK(akRaw)
	if err != nil {
		return nil, TPM2BName{}, nil, false, err
	}
	if err := verifyTPMEKPublicStrength(&ekPublic.Public, policy.MinEKKeyBits); err != nil {
		return nil, TPM2BName{}, nil, false, err
	}
	certs, err := parseTPMEKCertificateChain(chain)
	if err != nil {
		return nil, TPM2BName{}, nil, false, err
	}
	attributes, err := verifyTPMEKCertificateProfile(certs[0], now, policy.MinEKKeyBits)
	if err != nil {
		return nil, TPM2BName{}, nil, false, err
	}
	if err := verifyTPMEKManufacturer(attributes, policy.AllowedEKManufacturers); err != nil {
		return nil, TPM2BName{}, nil, false, err
	}
	ekKey, err := ekPublic.Public.PublicKey()
	if err != nil {
		return nil, TPM2BName{}, nil, false, err
	}
	if !samePublicKey(ekKey, certs[0].PublicKey) {
		return nil, TPM2BName{}, nil, false, errs.Detail(ErrEKCertificate, "endorsement-key public area differs from the leaf certificate | 背书密钥公钥区域与叶证书不一致")
	}
	if !containsAAGUID(policy.AllowedAAGUIDs, aaguid) {
		return nil, TPM2BName{}, nil, false, errs.Detail(ErrEKActivation, "AAGUID %x is not allowed for EK activation | AAGUID %x 不在允许的 EK 激活列表", aaguid, aaguid)
	}
	trusted, err := verifyTPMEKCertificateChain(certs, policy.EKRoots, now, policy.RequireTrustedEKChain)
	if err != nil {
		return nil, TPM2BName{}, nil, false, err
	}
	return ekPublic, akName, certs, trusted, nil
}

// parseTPMEKPublic parses an exact raw TPMT_PUBLIC endorsement-key area. | parseTPMEKPublic 解析恰好一个
// 原始 TPMT_PUBLIC 背书密钥区域。
func parseTPMEKPublic(raw []byte) (*TPM2BPublic, error) {
	public, err := ParseTPMTPublic(raw)
	if err != nil {
		return nil, err
	}
	if !public.IsRestrictedDecrypt() {
		return nil, errs.Detail(ErrEKActivation, "endorsement key lacks restricted decrypt attributes | 背书密钥缺少 restricted decrypt 属性")
	}
	if _, err := public.StorageSymmetric(); err != nil {
		return nil, err
	}
	return &TPM2BPublic{Public: *public, Raw: append([]byte(nil), raw...)}, nil
}

// parseTPMEKActivationAK parses an AK public area and computes its Name. | parseTPMEKActivationAK 解析
// AK 公钥区域并计算其 Name。
func parseTPMEKActivationAK(raw []byte) (*TPMTPublic, TPM2BName, error) {
	public, err := ParseTPMTPublic(raw)
	if err != nil {
		return nil, TPM2BName{}, err
	}
	if public.ObjectAttributes&TPMASign == 0 {
		return nil, TPM2BName{}, errs.Detail(ErrEKActivation, "attestation key lacks the sign attribute | 认证密钥缺少 sign 属性")
	}
	name, err := public.Name(raw)
	if err != nil {
		return nil, TPM2BName{}, err
	}
	akName := TPM2BName{Name: append([]byte(nil), name...)}
	if err := akName.Validate(); err != nil {
		return nil, TPM2BName{}, err
	}
	return public, akName, nil
}

// verifyTPMEKPublicStrength enforces the minimum RSA EK size and supported ECC curves. |
// verifyTPMEKPublicStrength 强制最小 RSA EK 位数与支持的 ECC 曲线。
func verifyTPMEKPublicStrength(public *TPMTPublic, minBits int) error {
	switch public.Type {
	case TPMAlgRSA:
		if int(public.KeyBits) < minBits {
			return errs.Detail(ErrEKCertificate, "endorsement RSA key is %d bits, minimum %d | 背书 RSA 密钥为 %d 位，最小 %d",
				public.KeyBits, minBits, public.KeyBits, minBits)
		}
	case TPMAlgECC:
		if _, err := tpmECCCurve(public.CurveID); err != nil {
			return errs.WrapDetail(err, ErrEKCertificate, "unsupported endorsement ECC curve | 不支持的背书 ECC 曲线")
		}
	default:
		return errs.Detail(ErrEKCertificate, "endorsement key type %#04x is not RSA or ECC | 背书密钥类型 %#04x 不是 RSA 或 ECC",
			public.Type, public.Type)
	}
	return nil
}

// parseTPMEKCertificateChain parses a bounded DER certificate chain. | parseTPMEKCertificateChain 解析
// 有界 DER 证书链。
func parseTPMEKCertificateChain(raw [][]byte) ([]*x509.Certificate, error) {
	if len(raw) == 0 {
		return nil, errs.Detail(ErrEKCertificate, "endorsement-key certificate chain is empty | 背书密钥证书链为空")
	}
	if len(raw) > maxAttestationCertificates {
		return nil, errs.Detail(ErrEKCertificate, "endorsement-key certificate chain has %d certificates, limit %d | 背书密钥证书链包含 %d 张证书，上限 %d",
			len(raw), maxAttestationCertificates, len(raw), maxAttestationCertificates)
	}
	certs := make([]*x509.Certificate, 0, len(raw))
	for index, der := range raw {
		if len(der) == 0 {
			return nil, errs.Detail(ErrEKCertificate, "endorsement-key certificate %d is empty | 背书密钥证书 %d 为空", index, index)
		}
		cert, err := x509.ParseCertificate(der)
		if err != nil {
			return nil, errs.WrapDetail(err, ErrEKCertificate, "endorsement-key certificate %d is malformed | 背书密钥证书 %d 格式非法", index, index)
		}
		certs = append(certs, cert)
	}
	return certs, nil
}

// verifyTPMEKCertificateProfile checks the EK certificate profile and returns its SAN attributes. |
// verifyTPMEKCertificateProfile 检查 EK 证书配置并返回其 SAN 属性。
func verifyTPMEKCertificateProfile(cert *x509.Certificate, now time.Time, minBits int) (map[string]string, error) {
	if cert == nil {
		return nil, errs.Detail(ErrEKCertificate, "nil endorsement-key certificate | 背书密钥证书为空")
	}
	if cert.Version != 3 {
		return nil, errs.Detail(ErrEKCertificate, "endorsement-key certificate is not X.509 v3 | 背书密钥证书不是 X.509 v3")
	}
	if now.Before(cert.NotBefore) || now.After(cert.NotAfter) {
		return nil, errs.Detail(ErrEKCertificate, "endorsement-key certificate is not valid at the verification time | 背书密钥证书在校验时间无效")
	}
	if cert.BasicConstraintsValid && cert.IsCA {
		return nil, errs.Detail(ErrEKCertificate, "endorsement-key certificate is a CA | 背书密钥证书是 CA")
	}
	if cert.KeyUsage != 0 && cert.KeyUsage&(x509.KeyUsageDigitalSignature|x509.KeyUsageKeyEncipherment|x509.KeyUsageKeyAgreement|x509.KeyUsageEncipherOnly|x509.KeyUsageDecipherOnly) == 0 {
		return nil, errs.Detail(ErrEKCertificate, "endorsement-key certificate key usage is not usable for EK operations | 背书密钥证书密钥用途不能用于 EK 操作")
	}
	if len(cert.ExtKeyUsage) > 0 || len(cert.UnknownExtKeyUsage) > 0 {
		if !containsOID(cert.UnknownExtKeyUsage, tcgKpEKCertOID) && !containsExtKeyUsage(cert.ExtKeyUsage, x509.ExtKeyUsageAny) {
			return nil, errs.Detail(ErrEKCertificate, "endorsement-key certificate lacks the TCG EK certificate EKU | 背书密钥证书缺少 TCG EK 证书 EKU")
		}
	}
	switch key := cert.PublicKey.(type) {
	case *rsa.PublicKey:
		if key.N == nil || key.N.BitLen() < minBits {
			return nil, errs.Detail(ErrEKCertificate, "endorsement certificate RSA key is smaller than %d bits | 背书证书 RSA 密钥小于 %d 位",
				minBits, minBits)
		}
	case *ecdsa.PublicKey:
		if key.Curve == nil || key.Curve.Params() == nil ||
			(key.Curve.Params().BitSize != 256 && key.Curve.Params().BitSize != 384 && key.Curve.Params().BitSize != 521) {
			return nil, errs.Detail(ErrEKCertificate, "endorsement certificate ECC curve is not supported | 背书证书 ECC 曲线不受支持")
		}
	default:
		return nil, errs.Detail(ErrEKCertificate, "endorsement certificate key type %T is not RSA or ECC | 背书证书密钥类型 %T 不是 RSA 或 ECC",
			cert.PublicKey, cert.PublicKey)
	}
	value, ok := certificateExtension(cert, subjectAltNameOID)
	if !ok {
		return map[string]string{}, nil
	}
	attributes, err := parseDirectoryNameAttributes(value)
	if err != nil {
		return nil, errs.WrapDetail(err, ErrEKCertificate, "endorsement-key certificate subjectAltName is malformed | 背书密钥证书 subjectAltName 格式非法")
	}
	return attributes, nil
}

// verifyTPMEKManufacturer enforces the manufacturer allowlist. | verifyTPMEKManufacturer 强制制造商允许列表。
func verifyTPMEKManufacturer(attributes map[string]string, allowed []string) error {
	if len(allowed) == 0 {
		return nil
	}
	manufacturer := strings.TrimSpace(attributes[tpmManufacturerOID.String()])
	if manufacturer == "" {
		return errs.Detail(ErrEKCertificate, "endorsement-key certificate lacks a manufacturer attribute | 背书密钥证书缺少制造商属性")
	}
	for _, candidate := range allowed {
		if strings.EqualFold(strings.TrimSpace(candidate), manufacturer) {
			return nil
		}
	}
	return errs.Detail(ErrEKCertificate, "endorsement-key manufacturer %q is not allowed | 背书密钥制造商 %q 不在允许列表",
		manufacturer, manufacturer)
}

// verifyTPMEKCertificateChain chains EK certificates to the configured roots. |
// verifyTPMEKCertificateChain 把 EK 证书链到已配置的根。
func verifyTPMEKCertificateChain(certs []*x509.Certificate, roots *x509.CertPool, now time.Time, required bool) (bool, error) {
	if roots == nil {
		if required {
			return false, errs.Detail(ErrEKCertificate, "EK activation requires a trusted chain but no roots are configured | EK 激活要求受信任证书链，但未配置根")
		}
		return false, nil
	}
	intermediates := x509.NewCertPool()
	for _, cert := range certs[1:] {
		intermediates.AddCert(cert)
	}
	if _, err := certs[0].Verify(x509.VerifyOptions{
		Roots:         roots,
		Intermediates: intermediates,
		CurrentTime:   now,
		KeyUsages:     []x509.ExtKeyUsage{x509.ExtKeyUsageAny},
	}); err != nil {
		return false, errs.WrapDetail(err, ErrEKCertificate, "endorsement-key certificate chain is not trusted | 背书密钥证书链不受信任")
	}
	return true, nil
}

// validateTPMEKActivationChallenge checks the credential blob and encrypted secret shapes. |
// validateTPMEKActivationChallenge 检查凭据 blob 与加密秘密的结构。
func validateTPMEKActivationChallenge(ek *TPMTPublic, akName TPM2BName, credential, credentialBlob, encryptedSecret []byte) error {
	if len(credential) == 0 || len(credential) > maxTPMEKActivationCredential {
		return errs.Detail(ErrEKActivation, "credential is %d bytes, limit %d | 凭据为 %d 字节，上限 %d",
			len(credential), maxTPMEKActivationCredential, len(credential), maxTPMEKActivationCredential)
	}
	hash, ok := TPMHash(ek.NameAlg)
	if !ok {
		return errs.Detail(ErrUnsupportedAlgorithm, "endorsement key name algorithm %#04x | 背书密钥名称算法 %#04x", ek.NameAlg, ek.NameAlg)
	}
	digestSize := hash.Size()
	if len(credential) > digestSize {
		return errs.Detail(ErrEKActivation, "credential is %d bytes, name algorithm needs %d | 凭据为 %d 字节，名称算法需要 %d",
			len(credential), digestSize, len(credential), digestSize)
	}
	integrity, ciphertext, err := parseIDObject(TPM2BIDObject{Buffer: append([]byte(nil), credentialBlob...)})
	if err != nil {
		return err
	}
	if len(integrity) != digestSize {
		return errs.Detail(ErrEKActivation, "credential integrity HMAC is %d bytes, need %d | 凭据完整性 HMAC 为 %d 字节，需要 %d",
			len(integrity), digestSize, len(integrity), digestSize)
	}
	if len(ciphertext) < 2 || len(ciphertext) > digestSize+2 {
		return errs.Detail(ErrEKActivation, "credential ciphertext is %d bytes, limit %d | 凭据密文为 %d 字节，上限 %d",
			len(ciphertext), digestSize+2, len(ciphertext), digestSize+2)
	}
	switch ek.Type {
	case TPMAlgRSA:
		if len(encryptedSecret) != int(ek.KeyBits/8) {
			return errs.Detail(ErrEKActivation, "RSA encrypted secret is %d bytes, modulus needs %d | RSA 加密秘密为 %d 字节，模数需要 %d",
				len(encryptedSecret), ek.KeyBits/8, len(encryptedSecret), ek.KeyBits/8)
		}
	case TPMAlgECC:
		curve, err := tpmECCCurve(ek.CurveID)
		if err != nil {
			return err
		}
		reader := &tpm2Reader{data: encryptedSecret}
		x, err := reader.sized(maxTPMECCParameterSize)
		if err != nil {
			return err
		}
		y, err := reader.sized(maxTPMECCParameterSize)
		if err != nil {
			return err
		}
		if !reader.done() {
			return errs.Detail(ErrTPMStructure, "encrypted secret has %d trailing bytes | 加密秘密有 %d 个多余字节",
				reader.remaining(), reader.remaining())
		}
		if err := (TPMSEccPoint{X: x, Y: y}).validate(curve); err != nil {
			return err
		}
	default:
		return errs.Detail(ErrEKCertificate, "endorsement key type %#04x is not RSA or ECC | 背书密钥类型 %#04x 不是 RSA 或 ECC",
			ek.Type, ek.Type)
	}
	return akName.Validate()
}

// containsAAGUID reports whether allowed is empty or contains want. | containsAAGUID 报告 allowed 是否为空
// 或包含 want。
func containsAAGUID(allowed [][16]byte, want [16]byte) bool {
	if len(allowed) == 0 {
		return true
	}
	for _, candidate := range allowed {
		if candidate == want {
			return true
		}
	}
	return false
}

// containsExtKeyUsage reports whether usages contains want. | containsExtKeyUsage 报告 usages 是否包含
// want。
func containsExtKeyUsage(usages []x509.ExtKeyUsage, want x509.ExtKeyUsage) bool {
	for _, usage := range usages {
		if usage == want {
			return true
		}
	}
	return false
}
